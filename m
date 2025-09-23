Return-Path: <kasan-dev+bncBDB3VRFH7QKRBVN3ZPDAMGQEIJNFTSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DB64B971C4
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:50:33 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-32eddb7e714sf5528447a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:50:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649813; cv=pass;
        d=google.com; s=arc-20240605;
        b=DRIhKqJPVy2ZBsQ6VDdiRD0MVK1eMb0ky36NhMDqEsgAkXG49VlPGPgmP+2sUwF5CH
         fQzSm5TPTnV/+vx6g9deNz4ufBdVSvNTmqHdOpk2yHsefMcBioqDF8wayXjRx/SfGPe+
         IrGCq/IJ6INvRiKZLg/Nb+mgeJkwfsk3v4F1IOkJ3MfOMkdEpl6azgHhIMOkvaU0bEtV
         eeTv+PR0H+yLVHytTLIodfGQ5g1wQ2QdJFqXCLU7OmexF3YVLANau7gwEEbjW1HTVgfD
         rGJlqe//WapyZjV+fRePHcLczcL5zPvjfpZ+Y6nzTdbvdQg/CExJI+PsbXndI5qA5jzC
         9/Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uovJmzOKqYjgZ3LTBAEm1QXGLWdA/kIP3jPvhNJkmA0=;
        fh=syXFtVER4sltCABX3WOaUR+9kFmgcS7M2YQ5j0er7Mw=;
        b=TM0QLZjFoBaKf1HQqO7w8TsNIujx1XvA/HZYWBRrmgV0DZWX6k/UJiZd2U4VXZy/s7
         YcvzvrffG7VsVak9/vGs/aj2BNbvki4n712Ayk/+1UhUxPzrQCjLgqRHsOiPwPavqoAu
         fTaRAm0zqECyfPNIVdk8Bfm0QLyZ1fMZ7uejZ/bRvXVFyZkrmnJ2GbQDYAu4Ix/+Fh1H
         ye0RlPnr/gyfEdP9Hi/V2tJF6Udc12mNJz66dsdEaw/nOwGDycstzD0fP644w6VB2DtY
         6yP1//a7jQGn5OIKrLf4QV31uB203+nIrxnM57kgfSBuvxKfePq3O+NXrCslPw74JbKm
         RyeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649813; x=1759254613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uovJmzOKqYjgZ3LTBAEm1QXGLWdA/kIP3jPvhNJkmA0=;
        b=eUE8FgDH93mzbgl5/QQKBz+gi9oOFV3Ej4PTuTTk0DZV1PKXPs/dKDuSI+8Wm4auek
         ZH2BGRoQ8elYmy2SJ6XwHcy3XKBGsuzJLuS9sf47LzMTyh5W7e5a+TCU8fYj7p4YNdZ+
         afrJwdky/Af6CZwsDvP9zADbTtQqDePVaQ8TPqgM73aUj9Hiq2EmSI7qlb+6BRtJtDHa
         neOFIJx9N1oM9XFWUP3TgyyXXeb89p5BNwlsf0I76RhBaAgqUP4OBpg52XwCgBf+dPUf
         Ar+DB3Fl1cd+s6z0rCh0gYGaI7gfK94MsnxICX5vAjtADDojc3blmAzoFJf0IQmstJBg
         EtZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649813; x=1759254613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uovJmzOKqYjgZ3LTBAEm1QXGLWdA/kIP3jPvhNJkmA0=;
        b=VdNipTauXt9wPedU2fCWC1rRqYz9urncnXy9MgP1W3L206Gu0oYriYR7At2wBmpwyX
         rbbWyobkazsV+lWATLGXrhQ6SyfKsuzPhvnzLXSVvkM9h1ZKwgAHwb8sx/wCZZq99C7C
         iyOLpKqqREmTPMRVfOIzpcoeVP2q3mdApvJEYAp6SpkU+l5jCmfx0u9PGdMvhRlL5NHQ
         gA9T+T3QspisOXf/GIMeRcYNHU92P4BvQcrkRrO96sEiysYqJ5zYIPHEFGY+kzXF4wYX
         pKYFxYSzu8oROObaBNoZL9wU2QKA4QR6cPs+JFnNT2Qx6Qa3OiIiduT26xeu3LRuNQNd
         rg3g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXnO6Z0P8LxHAVRq5PUyib+rVcimrfW0/KJeT9jA0S5kjESX3F5B/tLqDSyDxvHfGe3SxQTKQ==@lfdr.de
X-Gm-Message-State: AOJu0YyrYuBypuuvPZTlIKwXWQvIWxDkFXv24K/MD4IgYlCEH1to96V0
	mQzH2jRcbQUhl1sPtDRTRfQDNDaeavzodo7kxcCbpZhkZVX3LKnk7TjE
X-Google-Smtp-Source: AGHT+IG4TSVvAxeztHFCCWkn+nUnwoLXZwB/Y4667sZTrHA64zv4klVZ6UIo3otjgUbFsTLhFGpokg==
X-Received: by 2002:a17:90b:3d4e:b0:330:48d1:f90a with SMTP id 98e67ed59e1d1-332a9909737mr4040103a91.27.1758649813444;
        Tue, 23 Sep 2025 10:50:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd64VTzkGwrfRmyAyGthURE1ds7TEPXUWwU1JbawkDFDKA==
Received: by 2002:a17:90b:1949:b0:32e:a86f:3430 with SMTP id
 98e67ed59e1d1-3306527e8eels4758335a91.2.-pod-prod-01-us; Tue, 23 Sep 2025
 10:50:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXu9M8b1D+GNsaTuNCeq6/M2LPbZy2HQ74fJzIH5PlRaJIQMC4tVoNI3zSkMepo3pE1uXToEpfeRB8=@googlegroups.com
X-Received: by 2002:a17:90b:1fd0:b0:32e:f1c:e778 with SMTP id 98e67ed59e1d1-332a95445d8mr4382641a91.3.1758649812113;
        Tue, 23 Sep 2025 10:50:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649812; cv=none;
        d=google.com; s=arc-20240605;
        b=KN1fJQEFRVAeVel27wg5E2yZvV0AspdxHjWJM4o1ICrfupXcUqivhXhuuTU+3A38WH
         zI3SASSbx6vfO+evRsll2gvZffNiEncVvM8o15r5CyIY2yN1j7rK8iB0vogwlnGG0xq5
         sreQlBPQI4aRWppz3up9GM7fYXU8PDz9NzOTB93HWVp6LUPSz3YYecet0glUlHYei/NY
         1fNj7YHNIX/tnkuv1Hrx3rP/Ug2G1guLgoN8XZTELr60OZ1Kbpz6tP8FMaV2tjEz4MUa
         8rIF+zJjKoCKdU3t1Dii7SPX2TNz/SSed/V1eJViSRMlwszj8gFDPOWUyWlWkUESRs29
         C0sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=lZyHqDirOg8h1xFyA+fm0sCoxyLJfpze86+oaD8OVwo=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=gfNvQxG3s/E4Ef4lJ/OA/lXLmcsb0bZTGMXO7hvBSNJxAvFXfNEfWvx9UoTw+tciYo
         DbnLF2yMO7e4fyKrzPXv+h2vZl866cdKizQ6UkcGjY46v48J1zhVuXniYirZ3IKJxlnz
         bkXxWzjlL2fiTo563Ng/3QxLEjlIdcN8oyGrBeazgNj91Q+8/GCf6DM52gk3+11I7Wr5
         ZbgpapKZWMFwoBKPj52V7v/Wcbbw6PzErgrHuHdnSzVc2w5y6wR6jkIrzES8BkwVXxKl
         yI1h6KpMZqeeo3V8xzNaF7GAcLuR85WE9vEF0LvAfxHtPJOBIbOLKKtCy75EPdUbfmjy
         RrLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-3306070f7d4si677029a91.2.2025.09.23.10.50.12
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:50:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 60DD1497;
	Tue, 23 Sep 2025 10:50:03 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id D65E03F5A1;
	Tue, 23 Sep 2025 10:50:07 -0700 (PDT)
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Joey Gouly <joey.gouly@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Ada Couprie Diaz <ada.coupriediaz@arm.com>
Subject: [RFC PATCH 14/16] arm64/insn: always inline aarch64_insn_encode_ldst_size()
Date: Tue, 23 Sep 2025 18:49:01 +0100
Message-ID: <20250923174903.76283-15-ada.coupriediaz@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250923174903.76283-1-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
MIME-Version: 1.0
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

The type and instruction checks cannot be made at compile time,
as they are dynamically created. However, we can remove the error print
as it should never appear in normal operation and will still lead to
a fault BRK.

This makes `aarch64_insn_encode_ldst_size()` safe for inlining
and usage from patching callbacks.

This is a change of visiblity, as previously the function was private to
lib/insn.c.
However, in order to inline more `aarch64_insn_` functions and make
patching callbacks safe, it needs to be accessible by those functions.
As it is more accessible than before, add a check so that only loads
or stores can be affected by the size encoding.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 24 ++++++++++++++++++++++++
 arch/arm64/lib/insn.c         | 19 +------------------
 2 files changed, 25 insertions(+), 18 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index 44435eede1f3..46d4d452e2e2 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -717,6 +717,30 @@ static __always_inline u32 aarch64_insn_encode_immediate(
 
 	return insn;
 }
+
+extern const u32 aarch64_insn_ldst_size[];
+static __always_inline u32 aarch64_insn_encode_ldst_size(
+					 enum aarch64_insn_size_type type,
+					 u32 insn)
+{
+	u32 size;
+
+	if (type < AARCH64_INSN_SIZE_8 || type > AARCH64_INSN_SIZE_64) {
+		return AARCH64_BREAK_FAULT;
+	}
+
+	/* Don't corrput the top bits of other instructions which aren't a size. */
+	if (!aarch64_insn_is_ldst(insn)) {
+		return AARCH64_BREAK_FAULT;
+	}
+
+	size = aarch64_insn_ldst_size[type];
+	insn &= ~GENMASK(31, 30);
+	insn |= size << 30;
+
+	return insn;
+}
+
 static __always_inline u32 aarch64_insn_encode_register(
 				 enum aarch64_insn_register_type type,
 				 u32 insn,
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 71df4d72ac81..63564d236235 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -42,30 +42,13 @@ u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
 	return (insn >> shift) & mask;
 }
 
-static const u32 aarch64_insn_ldst_size[] = {
+const u32 aarch64_insn_ldst_size[] = {
 	[AARCH64_INSN_SIZE_8] = 0,
 	[AARCH64_INSN_SIZE_16] = 1,
 	[AARCH64_INSN_SIZE_32] = 2,
 	[AARCH64_INSN_SIZE_64] = 3,
 };
 
-static u32 aarch64_insn_encode_ldst_size(enum aarch64_insn_size_type type,
-					 u32 insn)
-{
-	u32 size;
-
-	if (type < AARCH64_INSN_SIZE_8 || type > AARCH64_INSN_SIZE_64) {
-		pr_err("%s: unknown size encoding %d\n", __func__, type);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	size = aarch64_insn_ldst_size[type];
-	insn &= ~GENMASK(31, 30);
-	insn |= size << 30;
-
-	return insn;
-}
-
 static inline long label_imm_common(unsigned long pc, unsigned long addr,
 				     long range)
 {
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-15-ada.coupriediaz%40arm.com.
