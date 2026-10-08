/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package org.springframework.security.web.webauthn.management;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.TestBytes;
import org.springframework.security.web.webauthn.api.TestCredentialRecords;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Reproduces the stale owner-index behavior when save is called with an existing
 * credential id and a different owner.
 */
class MapUserCredentialRepositoryReproductionTests {

	@Test
	void saveExistingCredentialIdWithDifferentOwnerLeavesStaleIndex() {
		MapUserCredentialRepository repository = new MapUserCredentialRepository();
		CredentialRecord oldRecord = TestCredentialRecords.userCredential().build();
		Bytes oldOwnerId = oldRecord.getUserEntityUserId();
		Bytes newOwnerId = TestBytes.get();
		CredentialRecord newRecord = ImmutableCredentialRecord.fromCredentialRecord(oldRecord)
			.userEntityUserId(newOwnerId)
			.label("new-owner")
			.build();

		repository.save(oldRecord);
		repository.save(newRecord);

		List<CredentialRecord> oldOwnerRecords = repository.findByUserId(oldOwnerId);
		System.out.println("1 old owner records after overwrite: " + oldOwnerRecords);
		assertThat(oldOwnerRecords).containsExactly(newRecord);

		Bytes credentialIdFromOldOwner = oldOwnerRecords.get(0).getCredentialId();
		CredentialRecord recordFromMainIndex = repository.findByCredentialId(credentialIdFromOldOwner);
		System.out.println("2 main index lookup from old owner credentialId: " + recordFromMainIndex);
		assertThat(recordFromMainIndex).isEqualTo(newRecord);

		repository.delete(credentialIdFromOldOwner);
		System.out.println("3 new owner records after delete: " + repository.findByUserId(newOwnerId));
		assertThat(repository.findByUserId(newOwnerId)).isEmpty();

		Throwable failure = null;
		try {
			repository.findByUserId(oldOwnerId);
		}
		catch (Throwable ex) {
			failure = ex;
		}
		System.out.println("4 old owner lookup after delete: " + failure);
		assertThat(failure).isInstanceOf(NullPointerException.class);
	}

}
