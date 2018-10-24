-- Copyright (C) 2012 by Konstantin Ryabitsev and contributors
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
-- 02111-1307, USA.
--

-- CHANGE THE PASSWORDS, OBVIOUSLY!
CREATE USER totpcgi       WITH PASSWORD 'wakkawakka';
CREATE USER totpcgi_admin WITH PASSWORD 'bokkabokka';

CREATE SEQUENCE users_userid_seq;

GRANT UPDATE ON users_userid_seq TO totpcgi;
GRANT UPDATE ON users_userid_seq TO totpcgi_admin;

-- Used by all backends

CREATE TABLE users (
	userid   INTEGER NOT NULL PRIMARY KEY DEFAULT nextval('users_userid_seq'),
	username VARCHAR(255) NOT NULL,
    CONSTRAINT users_uniq UNIQUE (username)
);
GRANT SELECT, INSERT         ON users TO totpcgi;
GRANT SELECT, INSERT, DELETE ON users TO totpcgi_admin;

-- Used by the state backend

CREATE TABLE timestamps (
	userid    INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
	success   BOOLEAN NOT NULL,
	timestamp INTEGER NOT NULL
);
GRANT SELECT, INSERT, DELETE ON timestamps TO totpcgi;
GRANT SELECT, INSERT, DELETE ON timestamps TO totpcgi_admin;

CREATE TABLE used_scratch_tokens (
	userid INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
	token  INTEGER NOT NULL
);
GRANT SELECT, INSERT, DELETE ON used_scratch_tokens TO totpcgi;
GRANT SELECT, INSERT, DELETE ON used_scratch_tokens TO totpcgi_admin;

CREATE TABLE counters (
	userid  INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
	counter INTEGER NOT NULL,
	CONSTRAINT counters_uniq UNIQUE (userid, counter)
);
GRANT SELECT, INSERT, DELETE ON counters TO totpcgi;
GRANT SELECT, INSERT, DELETE ON counters TO totpcgi_admin;

-- Used by the secrets backend

CREATE TABLE secrets (
    userid             INTEGER      NOT NULL REFERENCES users ON DELETE CASCADE,
    secret             VARCHAR(255) NOT NULL,
    rate_limit_times   INTEGER DEFAULT 3,
    rate_limit_seconds INTEGER DEFAULT 30,
    window_size        INTEGER DEFAULT 0,
    CONSTRAINT secrets_uniq UNIQUE (userid)
);
GRANT SELECT                         ON secrets TO totpcgi;
GRANT SELECT, INSERT, UPDATE, DELETE ON secrets TO totpcgi_admin;

CREATE TABLE scratch_tokens (
    userid INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    token  INTEGER
);
GRANT SELECT                 ON scratch_tokens TO totpcgi;
GRANT SELECT, INSERT, DELETE ON scratch_tokens TO totpcgi_admin;

-- Used by the pincodes backend

CREATE TABLE pincodes (
    userid INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    pincode VARCHAR(1024) NOT NULL,
    CONSTRAINT pincodes_uniq UNIQUE (userid)
);
GRANT SELECT                         ON pincodes TO totpcgi;
GRANT SELECT, INSERT, UPDATE, DELETE ON pincodes TO totpcgi_admin;

