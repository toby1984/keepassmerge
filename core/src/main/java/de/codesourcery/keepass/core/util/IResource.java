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

import java.io.*;

public interface IResource
{
    final class ClasspathResource implements IResource
    {
        private final String path;

        public ClasspathResource(String path)
        {
            Validate.notBlank( path, "path must not be null or blank");
            this.path = path;
        }

        @Override
        public boolean isSame(IResource other)
        {
            return other instanceof ClasspathResource res && res.path.equals(this.path);
        }

        @Override
        public InputStream createInputStream() throws IOException
        {
            InputStream in = getClass().getResourceAsStream(path);
            if ( in == null ) {
                throw new FileNotFoundException("Failed to load "+this);
            }
            return in;
        }

        @Override
        public OutputStream createOutputStream(boolean overwrite) throws IOException
        {
            throw new UnsupportedOperationException("Not supported for classpath resources");
        }

        @Override
        public String toString()
        {
            return "classpath:"+path;
        }
    }

    final class FileResource implements IResource
    {
        private final File file;

        public FileResource(File file)
        {
            Validate.notNull(file, "file must not be null");
            this.file = file;
        }

        @Override
        public boolean isSame(IResource other)
        {
            return other instanceof FileResource res && this.file.equals( res.file );
        }

        @Override
        public InputStream createInputStream() throws IOException
        {
            return new FileInputStream(file);
        }

        @Override
        public OutputStream createOutputStream(boolean overwrite) throws IOException
        {
            if ( ! overwrite && file.exists() ) {
                throw new IOException("Refusing to overwrite existing file "+file.getAbsolutePath());
            }
            return new FileOutputStream(file);
        }

        @Override
        public String toString()
        {
            return "file:"+file.getAbsolutePath();
        }
    }

    InputStream createInputStream() throws IOException;

    OutputStream createOutputStream(boolean overwrite) throws IOException;

    boolean isSame(IResource other);

    @FunctionalInterface
    public interface InputStreamSupplier {
        InputStream get() throws IOException;
    }

    static IResource inputStream(InputStreamSupplier supplier, String description) {
        return new IResource()
        {
            @Override
            public InputStream createInputStream() throws IOException
            {
                return supplier.get();
            }

            @Override
            public OutputStream createOutputStream(boolean overwrite) throws IOException
            {
                throw new UnsupportedOperationException("Method createOutputStream not implemented");
            }

            @Override
            public boolean isSame(IResource other)
            {
                return false;
            }

            @Override
            public String toString()
            {
                return "input stream: " +description;
            }
        };
    }
    static IResource classpath(String path)
    {
        return new ClasspathResource(path);
    }

    static IResource file(File file) {
        return new FileResource(file);
    }
}
