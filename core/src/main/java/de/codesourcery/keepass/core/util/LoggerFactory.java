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
package de.codesourcery.keepass.core.util;

import org.apache.commons.lang3.Validate;

import java.text.MessageFormat;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ConcurrentHashMap;

public class LoggerFactory
{
    public static Logger.Level currentLevel = Logger.Level.INFO;

    public static final LogAppender CONSOLE = new ConsoleLogAppender();

    private static final ThreadLocal<LogAppender> APPENDER = ThreadLocal.withInitial(() -> CONSOLE);

    private static final ConcurrentHashMap<Class<?>, Logger> LOGGERS = new ConcurrentHashMap<>();

    public interface LogAppender extends AutoCloseable
    {
        default void log(Logger.Level lvl, Class<?> clazz, String msg) {
            log(lvl,clazz,msg,null);
        }

        @Override
        default void close()
        {
        }

        void log(Logger.Level lvl, Class<?> clazz, String msg, Throwable t);
    }

    public static class ConsoleLogAppender implements LogAppender {

        public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssZ");

        @Override
        public void log(Logger.Level lvl, Class<?> clazz, String msg, Throwable t)
        {
            if ( lvl.severity >= currentLevel.severity )
            {
                doLog(lvl, clazz, msg, t);
            }
        }

        protected void doLog(Logger.Level lvl, Class<?> clazz, String msg, Throwable t)
        {
            System.out.println(createLogMessage(lvl, clazz, msg));
            if ( t != null ) {
                t.printStackTrace(System.out);
            }
        }

        protected final String createLogMessageNoTimestamp(Logger.Level lvl, Class<?> clazz, String msg)
        {
            final String formatString = "{0} - {1} - {2}";
            return MessageFormat.format(formatString,
                lvl.name,
                clazz.getName(),
                msg);
        }

        protected final String createLogMessage(Logger.Level lvl, Class<?> clazz, String msg)
        {
            final ZonedDateTime now = ZonedDateTime.now();
            final String time = DATE_TIME_FORMATTER.format(now);
            final String formatString = "{0} - {1}";
            return MessageFormat.format(formatString,
                time,
                createLogMessageNoTimestamp(lvl,clazz,msg) );
        }
    }

    public static Logger getLogger(Class<?> clazz)
    {
        return LOGGERS.computeIfAbsent(clazz,cl -> (level,msg,t) -> APPENDER.get().log(level,clazz,msg,t) );
    }

    public static void setLogAppender(LogAppender appender)
    {
        Validate.notNull(appender, "appender must not be null");
        APPENDER.set( appender );
    }

    public static void resetLogAppender()
    {
        setLogAppender(CONSOLE);
    }
}