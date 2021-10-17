/**
 * Copyright 2020 Tobias Gierke <tobias.gierke@code-sourcery.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.codesourcery.keepass.webapp;

import de.codesourcery.keepass.core.MergeHelper;
import de.codesourcery.keepass.core.crypto.Credential;
import de.codesourcery.keepass.core.fileformat.Database;
import de.codesourcery.keepass.core.fileformat.XmlPayloadView;
import de.codesourcery.keepass.core.util.IResource;
import de.codesourcery.keepass.core.util.Serializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.wicket.extensions.markup.html.repeater.data.table.DefaultDataTable;
import org.apache.wicket.extensions.markup.html.repeater.data.table.IColumn;
import org.apache.wicket.extensions.markup.html.repeater.data.table.LambdaColumn;
import org.apache.wicket.extensions.markup.html.repeater.util.SortableDataProvider;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.form.upload.FileUploadField;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.request.IRequestCycle;
import org.apache.wicket.request.handler.resource.ResourceStreamRequestHandler;
import org.apache.wicket.request.resource.ContentDisposition;
import org.apache.wicket.util.resource.FileResourceStream;
import org.apache.wicket.util.resource.IResourceStream;
import org.apache.wicket.util.time.Duration;
import org.danekja.java.util.function.serializable.SerializableFunction;

import javax.crypto.BadPaddingException;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import static de.codesourcery.keepass.core.util.Logger.Level.INFO;
import static de.codesourcery.keepass.core.util.Logger.Level.SUCCESS;

/**
 * The one and only web page.
 *
 * @author tobias.gierke@code-sourcery.de
 */
@Protected
public class HomePage extends WebPage
{
    private static final Logger LOG = LogManager.getLogger( HomePage.class );

    private static final DateTimeFormatter DF = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssZ");

    public static final ConcurrentHashMap<String,Integer> delayPerClient = new ConcurrentHashMap<>();

    private enum Column implements SerializableFunction<AuditLogEntry,Object>
    {
        TIMESTAMP( "Timestamp", x -> DF.format( x.creationTime() ) ),
        CLIENT_IP( "Client IP", AuditLogEntry::clientIP),
        LEVEL( "Level", AuditLogEntry::level),
        MESSAGE( "Message", AuditLogEntry::message);

        public final IModel<String> colLabel;
        public final Function<AuditLogEntry,Object> func;

        Column(String colLabel, Function<AuditLogEntry, Object> func)
        {
            this.colLabel = Model.of(colLabel);
            this.func = func;
        }

        public LambdaColumn<AuditLogEntry,Column> lambdaColumn(){
            return new LambdaColumn<>(colLabel, this);
        }

        @Override
        public Object apply(AuditLogEntry auditLogEntry)
        {
            return func.apply(auditLogEntry);
        }
    }

    private final Configuration configuration;
    private final AuditLogManager auditLog;

    private final FeedbackPanel feedback = (FeedbackPanel) new FeedbackPanel("feedback").setOutputMarkupPlaceholderTag(true);
    private final PasswordTextField password = new PasswordTextField("password", Model.of((String) null));

    private final SortableDataProvider<AuditLogEntry,Column> dataProvider = new SortableDataProvider<>()
    {
        private ResultPage<AuditLogEntry> result;

        @Override
        public void detach()
        {
            result = null;
        }

        @Override
        public Iterator<? extends AuditLogEntry> iterator(long first, long count)
        {
            return data((int) first, (int) count).results().iterator();
        }

        private ResultPage<AuditLogEntry> data(int offset, int count)
        {
            if (result == null || result.offset() != offset)
            {
                result = auditLog.getPage(offset, count);
            }
            return result;
        }

        @Override
        public long size()
        {
            return data(0, 10).totalCount();
        }

        @Override
        public IModel<AuditLogEntry> model(AuditLogEntry object)
        {
            return Model.of(object);
        }
    };

    public HomePage() throws IOException
    {
        configuration = Configuration.getInstance();
        auditLog = new AuditLogManager(configuration);
        if ( ! auditLog.testConnectivity() ) {
            throw new IOException("DB connection failed");
        }
    }

    private String getRemoteIP() {
        final HttpServletRequest request = (HttpServletRequest) getRequestCycle().getRequest().getContainerRequest();
        return request.getRemoteAddr();
    }

    @Override
    protected void onInitialize()
    {
        super.onInitialize();

        final List<IColumn<AuditLogEntry, Column>> columns = List.of(Column.TIMESTAMP.lambdaColumn(),
            Column.CLIENT_IP.lambdaColumn(), Column.LEVEL.lambdaColumn(), Column.MESSAGE.lambdaColumn());

        final DefaultDataTable<AuditLogEntry,Column> table =
            new DefaultDataTable<>("auditLog", columns, dataProvider,15);

        final Form<Void> uploadForm = new Form<>("uploadForm");
        uploadForm.setMultiPart(true);

        password.setRequired(true);

        final Button downloadLink = new Button("downloadLink") {
            @Override public void onSubmit() {
                try
                {
                    sendVault();
                } catch(Exception ex) {
                    LOG.error( "Caught ", ex );
                    error("Something went wrong: "+ex.getMessage());
                }
            }
        };

        final FileUploadField upload = new FileUploadField("fileUpload");
        final Button uploadButton = new Button("uploadButton") {
            @Override public void onSubmit() {
                try
                {
                    mergeFiles( upload );
                } catch(Exception e) {
                    LOG.error( "Caught ", e );
                    error("Something went wrong: "+e.getMessage());
                }
            }
        };
        queue(downloadLink, password, uploadForm, upload, uploadButton, feedback, table );
    }

    private void mergeFiles(FileUploadField upload)
    {
        final List<FileUpload> uploads = upload.getFileUploads();
        if ( uploads.isEmpty() ) {
            feedback.error("You need to upload at least one file");
            return;
        }

        final List<Credential> credentials = List.of(Credential.password(password.getModelObject().toCharArray()));
        try
        {
            final List<Database> databases = new ArrayList<>();
            for ( FileUpload up : uploads )
            {
                LOG.info("onSubmit(): Trying to open " + up.getClientFileName());
                final IResource r = IResource.inputStream(up::getInputStream,up.getClientFileName());
                final Database d = Database.read(credentials, r );
                databases.add(d);
                LOG.info("onSubmit(): Successfully opened " + up.getClientFileName());
            }
            final File original = configuration.getMergeTarget();

            LOG.info("onSubmit(): Opening local file " + original.getAbsolutePath());
            final Database originalDb = Database.read(credentials, IResource.file( original ) );
            LOG.info("onSubmit(): Successfully opened local file " + original.getAbsolutePath());
            databases.add(originalDb);

            LOG.info("onSubmit(): Performing vault merge for "+getRemoteIP());
            MailHelper.getInstance().sendMail("Performing vault merge for " + getRemoteIP(), "<no body>");

            final de.codesourcery.keepass.core.util.Logger feedbackLogger = (level, msg, t) ->
            {
                switch(level)
                {
                    case TRACE,DEBUG -> feedback.debug(msg);
                    case INFO -> feedback.info(msg);
                    case SUCCESS -> feedback.success(msg);
                    case WARNING -> feedback.warn(msg);
                    case ERROR -> feedback.error(msg);
                }
            };
            final MergeHelper.MergeResult updatedDatabase = MergeHelper.combine(databases, feedbackLogger);
            if ( updatedDatabase.mergedDatabaseChanged() || ! updatedDatabase.mergedDatabase().resource.isSame(originalDb.resource) )
            {
                performMerge(credentials, configuration, original, updatedDatabase.mergedDatabase(), feedbackLogger);
                feedback.success("Databases merged successfully.");
                auditLog.write( getRemoteIP(), logger ->
                {
                    final String msg = databases.stream().map(x->x.resource.toString()).collect(Collectors.joining(","));
                    logger.log(SUCCESS, HomePage.class, "Successful merge: "+msg);
                });
            } else {
                auditLog.write( getRemoteIP(), logger ->
                {
                    final String msg = databases.stream().map(x->x.resource.toString()).collect(Collectors.joining(","));
                    logger.log(SUCCESS, HomePage.class, "No-op merge: "+msg);
                });
                feedback.success("Merging produced no changes as destination was already up-to-date.");
            }
        }
        catch (Exception e)
        {
            MailHelper.getInstance().sendMail("Vault merge failed for "+getRemoteIP(), "Exception: "+e.getMessage());
            LOG.error("onSubmit(): "+e.getMessage(),e);
            feedback.error("Something went wrong: "+e.getMessage());
        }
    }

    private static synchronized void performMerge(List<Credential> credentials, Configuration config,
                                                  File original,
                                                  Database updatedDatabase,
                                                  de.codesourcery.keepass.core.util.Logger progressLogger) throws IOException
    {
        final File tmpOut = File.createTempFile("tmp_keepassx", ".kdbx", config.getTempFolder());
        try ( OutputStream out = new FileOutputStream(tmpOut) )
        {
            updatedDatabase.write(credentials, new Serializer(out),
                config.getMinKeyDerivationTime().orElse(null), progressLogger);
        }
        final ZonedDateTime now = ZonedDateTime.now();
        final String extension = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssZ").format(now);
        final File backup = new File(original.getAbsolutePath() + "_" + extension );
        if ( backup.exists() && ! backup.delete() ) {
            throw new IOException("Failed to delete old backup file");
        }

        if ( ! original.renameTo(backup) ) {
            tmpOut.delete();
            throw new IOException("Failed to rename original file");
        }
        if ( ! tmpOut.renameTo(original) ) {
            tmpOut.delete();
            if ( ! backup.renameTo(original) ) {
                LOG.fatal("onSubmit() Failed to restore original file");
            }
            throw new IOException("Failed to rename " + tmpOut.getAbsolutePath() + " -> " + original.getAbsolutePath());
        }
        // make sure we're able to decrypt the new file properly
        final Database test;
        try
        {
            test = Database.read(credentials, IResource.file(original));
            new XmlPayloadView(test).getGroups();
        }
        catch(IOException e) {
            LOG.error("onSubmit(): Failed to read merge file",e);
            original.delete();
            if ( ! backup.renameTo(original) ) {
                LOG.error("onSubmit(): Failed to restore original file " + original.getAbsolutePath());
            }
            throw e;
        }
        catch (BadPaddingException e)
        {
            throw new RuntimeException(e);
        }
        LOG.info("Merging databases completed successfully.");
    }

    private void sendVault()
    {
        final File file = configuration.getMergeTarget();
        final String remoteIP = getRemoteIP();
        try
        {
            final List<Credential> credentials = List.of(Credential.password(password.getModelObject().toCharArray()));
            new Database().read(credentials, IResource.file(file));
            delayPerClient.remove(remoteIP);
        }
        catch (IOException e)
        {
            MailHelper.getInstance().sendMail("Failed to transfer vault to " + remoteIP, "Exception: " + e.getMessage());
            LOG.error("onSubmit(): Failed to transfer vault", e);
            feedback.error("Internal error");
            return;
        }
        catch (BadPaddingException e)
        {
            LOG.error("Wrong password ? Failed to decrypt database", e);
            final Integer delaySeconds =
                delayPerClient.compute(remoteIP,
                    (ip, previousDelay) -> previousDelay == null ? 1 : previousDelay * 2);

            final String msg = "WRONG PASSWORD ENTERED BY " + remoteIP+" - Delay is now " + delaySeconds + " seconds";
            auditLog.write(getRemoteIP(),log -> log.log(de.codesourcery.keepass.core.util.Logger.Level.ERROR, HomePage.class,msg) );
            MailHelper.getInstance().sendMail("WRONG PASSWORD ENTERED BY " + remoteIP, "Delay is now " + delaySeconds + " seconds");
            try
            {
                Thread.sleep(delaySeconds * 1000);
            }
            catch (InterruptedException interruptedException)
            {
                Thread.currentThread().interrupt();
            }
            feedback.error("Wrong password");
            return;
        }
        LOG.info("onSubmit(): Transferring vault to " + remoteIP);
        MailHelper.getInstance().sendMail("Transferred vault to " + remoteIP, "<no body>");

        final IResourceStream resourceStream = new FileResourceStream(new org.apache.wicket.util.file.File(file));
        getRequestCycle().scheduleRequestHandlerAfterCurrent(
            new ResourceStreamRequestHandler(resourceStream)
            {
                @Override
                public void respond(IRequestCycle requestCycle)
                {
                    auditLog.write( getRemoteIP(), logger ->  logger.log(INFO, HomePage.class, "User downloaded " + file.getName()));
                    super.respond(requestCycle);
                }
            }.setFileName("merged_vault.kdbx")
                .setContentDisposition(ContentDisposition.ATTACHMENT)
                .setCacheDuration(Duration.NONE));
    }
}