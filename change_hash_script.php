/**
	 * This function is used if there is a need to migrate from an old hash type to a new one.
	 * Will migrate the hash to a newly specified hash type.
	 * 
 	 * @param required string $thePassword - password entered by the user in the login form.
	 * @param optional string $oldHashType - This is the hash type to migrate from (Sha1, Simple, or Blowfish)
 	 * @return Failure - boolean false
	 * @return Success - array $theUser['User']. If $theUser['badpass'] is returned, the user entered password did
	 * 	not match the old hashed password value.
	 */
		
		public function autoRehash($theUser=array(), $plainPassword=null, $oldHashType='Sha1'){
			if((empty($theUser)) || (empty($plainPassword))){
				CakeLog::write('error', 'User or password not specified [Model->User.php->checkHash()]');
				return false;
			}
		/**
		 * Check to see if the provided password matches the currently indicated oldHashType.  If not, then a bad password was supplied.
		 * Return 'badpass' = true.  Otherwise, continue.
		 */
		 	if(!parent::_checkHash($plainPassword, $theUser['User']['password'], $oldHashType)){
		 		$message = $theUser['User']['username'].': Supplied password did not match stored password hash.  Password not migrated. [Model->User.php->checkHash()]';
		 		CakeLog::write('audit', $message);
				$theUser['badpass'] = true;
				return $theUser;
			}
		/**
		 * Check to make sure the old password being migrated matches the systems current password security policy.  If not, reset the user
		 * and have them create a new password.  Return false.  Otherwise continue.
		 */
			if(!$this->__validatePassword($plainPassword)){
				$message = $theUser['User']['username'].': Unable to migrate old password.  Password was not up to current security requirements. [Model->User.php->checkHash()]';
				CakeLog::write('audit', $message);
				if($this->resetUser($theUser)){
					$theUser['reset'] = true;
					return $theUser;
				}
				else{
					return false;
				}
			}
		/**
		 * Passed all previous tests and password need to be migrated.  Save plain-text password to password field so system can automatically
		 * hash the password with the new system defined hash type.
		 */
			$theUser['User']['password'] = $thePassword;
			$theUser['User']['hash_migration'] = false;
			if($this->save($theUser)){
				CakeLog::write('audit', $theUser['User']['username'].': Password hash was automatically updated by the system. [Model->User.php->checkHash()]');
				return $theUser;
			}
		/**
		 * Something was wrong with the save function.  Failed validation or other error.
		 */
			else{
				CakeLog::write('error', $theUser['User']['username'].': There was a problem saving the new password hash.  [Model->User.php->checkHash()]');
				return false;
			}
			return false;
		}
