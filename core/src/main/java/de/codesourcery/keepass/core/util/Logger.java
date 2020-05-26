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

public interface Logger
{
    public static final Logger NOP = (level, msg, t) -> { };

    enum Level
    {
        TRACE(1, "TRACE"),
        DEBUG(2, "DEBUG"),
        INFO(3, "INFO"),
        SUCCESS(3, "SUCCESS"),
        WARNING(4, "WARN"),
        ERROR(5, "ERROR");

        public final int severity;
        public final String name;

        Level(int severity, String name)
        {
            this.severity = severity;
            this.name = name;
        }
    }

    default void log(Level level, String msg) { log(level,msg,null); }
    void log(Level level, String msg, Throwable t);

    default void trace(String msg) { log(Level.TRACE,msg); }
    default void trace(String msg,Throwable t) { log(Level.TRACE,msg,t); }

    default void debug(String msg) { log(Level.DEBUG,msg); }
    default void debug(String msg,Throwable t) { log(Level.DEBUG,msg,t); }

    default void info(String msg) { log(Level.INFO,msg); }
    default void info(String msg,Throwable t) { log(Level.INFO,msg,t); }

    default void success(String msg) { log(Level.SUCCESS,msg); }
    default void success(String msg,Throwable t) { log(Level.SUCCESS,msg,t); }

    default void warn(String msg) { log(Level.WARNING,msg); }
    default void warn(String msg,Throwable t) { log(Level.WARNING,msg,t); }

    default void error(String msg) { log(Level.ERROR,msg); }
    default void error(String msg,Throwable t) { log(Level.ERROR,msg,t); }
}
