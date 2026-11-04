package keyring

// Unlock is the three steps a caller without a lock to mind takes in one go.
func (c *Collection) Unlock(password []byte) error {
	if c.key != nil {
		return nil
	}
	o, err := c.BeginUnlock()
	if err != nil {
		return err
	}
	opened, err := o.Open(password, Argon2id)
	if err != nil {
		return err
	}
	return c.FinishUnlock(opened)
}

// ChangePassword is NewRekey and ChangeKey in one go.
func (c *Collection) ChangePassword(password []byte, kdf KDF) error {
	if c.key == nil {
		return ErrLocked
	}
	r, err := NewRekey(password, kdf, Argon2id)
	if err != nil {
		return err
	}
	return c.ChangeKey(r)
}
