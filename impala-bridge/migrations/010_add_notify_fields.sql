-- Add optional notification contact/destination fields to the notify table
ALTER TABLE notify ADD COLUMN mobile VARCHAR(50);
ALTER TABLE notify ADD COLUMN wa VARCHAR(50);
ALTER TABLE notify ADD COLUMN signal VARCHAR(50);
ALTER TABLE notify ADD COLUMN tel VARCHAR(50);
ALTER TABLE notify ADD COLUMN email VARCHAR(255);
ALTER TABLE notify ADD COLUMN url VARCHAR(2048);
ALTER TABLE notify ADD COLUMN app VARCHAR(255);
