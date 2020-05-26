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

import javax.mail.internet.InternetAddress;
import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Properties;

/**
 * Abstract helper class (for subtyping only) that simplifies parsing configuration properties.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public abstract class ConfigHelper
{
    // data types
    protected static final ConfigHelper.PropertyType<Boolean> BOOLEAN_TYPE = ConfigHelper.PropertyType.of("boolean", value -> {
        final List<String> trueChoices = List.of("true","yes","on","1");
        if ( trueChoices.stream().anyMatch(value::equalsIgnoreCase)) {
            return true;
        }
        final List<String> falseChoices = List.of("false","no","off","0");
        if ( falseChoices.stream().anyMatch(value::equalsIgnoreCase)) {
            return false;
        }
        throw new RuntimeException("Invalid boolean literal '"+value+"'");
    });
    protected static final ConfigHelper.PropertyType<Integer> INTEGER_TYPE = ConfigHelper.PropertyType.of("boolean", Integer::parseInt);
    protected static final ConfigHelper.PropertyType<String> STRING_TYPE = ConfigHelper.PropertyType.of("string", x->x);
    protected static final ConfigHelper.PropertyType<Duration> DURATION_SECONDS_TYPE = ConfigHelper.PropertyType.of("duration (seconds)", x->Duration.ofSeconds(Long.parseLong(x)));
    protected static final ConfigHelper.PropertyType<Duration> DURATION_MILLIS_TYPE = ConfigHelper.PropertyType.of("duration (millis)", x->Duration.ofMillis(Long.parseLong(x)));
    protected static final ConfigHelper.PropertyType<InternetAddress[]> EMAIL_TYPE = ConfigHelper.PropertyType.of("email addresses",InternetAddress::parse);
    protected static final ConfigHelper.PropertyType<File> DIRECTORY_TYPE = ConfigHelper.PropertyType.of("directory", x -> {
        final File file = new File(x);
        if ( ! file.exists() ) {
            if ( ! file.mkdirs() ) {
                throw new IOException("Failed to create folder '"+x+"'");
            }
        } else if ( file.exists() && ! file.isDirectory() ) {
            throw new RuntimeException("Expected a directory but '"+x+"' was not");
        }
        return file;
    });

    protected static final ConfigHelper.PropertyType<File> FILE_TYPE = ConfigHelper.PropertyType.of("file", x -> {
        final File file = new File(x);
        if ( ! file.exists() ) {
            throw new RuntimeException("File does not exist: '"+x+"'");
        }
        if ( ! file.isFile() ) {
            throw new RuntimeException("Expected a file but '"+x+"' was not");
        }
        return file;
    });

    protected record PropertiesWithLocation(Properties properties, String location) {}

    protected interface Converter<T>
    {
        T convert(String input) throws Exception;
    }

    protected static abstract class PropertyType<T>
    {
        public final String name;

        public PropertyType(String name)
        {
            this.name = name;
        }

        public abstract T convert(String value) throws Exception;

        @Override public String toString() { return name; }

        public static <T> PropertyType<T> of(String name, Converter<T> func)
        {
            return new PropertyType<T>(name) {
                @Override public T convert(String value) throws Exception { return func.convert(value); }
            };
        }
    }

    protected static final class ConfigProperty<T>
    {
        public final String key;
        public final PropertyType<T> conversion;
        public final boolean optional;
        public final T defaultValue;

        private ConfigProperty(String key, PropertyType<T> conversion,boolean optional,T defaultValue)
        {
            this.key = key;
            this.conversion = conversion;
            this.defaultValue = defaultValue;
            this.optional = optional;
        }

        public static <T> ConfigProperty<T> of(String key, PropertyType<T> conversion) {
            return new ConfigProperty<>(key,conversion,false,null);
        }

        public static <T> ConfigProperty<T> of(String key, PropertyType<T> conversion,T defaultValue) {
            return new ConfigProperty<>(key,conversion,true,defaultValue);
        }

        public T readFrom(PropertiesWithLocation wrapper)
        {
            String input = wrapper.properties.getProperty(key);
            if ( input == null )
            {
                if ( ! optional )
                {
                    throw new RuntimeException("Configuration is lacking value for mandatory key '" + key + "', location: " + wrapper.location);
                }
                return defaultValue;
            }
            try
            {
                return conversion.convert(input.trim());
            }
            catch (Exception e)
            {
                throw new RuntimeException("While parsing configuration key '"+key+"' of type '"+conversion+"', location "+wrapper.location+": "+e.getMessage(),e);
            }
        }
    }
}