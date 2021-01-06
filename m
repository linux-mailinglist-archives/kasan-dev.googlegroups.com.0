Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB7WK237QKGQECWTJ4WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C1BB2EBD5C
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 12:56:48 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id z6sf1379416oop.10
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 03:56:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609934206; cv=pass;
        d=google.com; s=arc-20160816;
        b=szOqnZK3vkGJH6w745z26wxNQDNbGBwxAE5IEUS26FX7P4kIpFE81ELmEF4N5kLB19
         b+tgU+UZvqWwH9HKZEVY1X7vGjnzxADyxkqenRXbiNXfiHWG4rL1ZjkrSDfPuN33vzk7
         rp1dAsQn7MvW31GuYI7cWfuXlp5nWQZ7pEW9E+J2AfDI2T2AKeENUY4E/2ctF+6xJbxZ
         GGsjQE80ySGD0hn9QS08PCOJXpvIxPb20pwpKeehaSaCpizcgAxHWP1BHZI75pwercLC
         OyXNSX9eTwkKZTj+LrlMpNHs0p6QUqgpdw4o4sR64krQCKsYSiEZiAPBeABb7Da/nmB2
         COXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qv04S8bPBd96FNqIwcSIUabz2xC2Ydzm88qYz3ixfjo=;
        b=vJOd6FtpuKaBNGinGPYu8VhzVrjWFtvG9un+k1EHrZadJg9iIWpxwacFTtyRF2N3DE
         qIDBTjYuMFtj3G0fJL48NQXDQSAyOj6KNecNrrmz8wbOc9otslIjYqsSko+0b7OwOc6W
         AqPLRMg/7r05pS26QntFnnPsklQRzIvaB+991j9+4WGkc1ufL1suGKWIK11vx3rxJNvk
         ai5qcw4EDHdjhH7ECZCwCTQogHgKSHZ6CoGLdnAAhJug61M57b+TfJSGNRiB/rrM1B3a
         zJ9TtYrotu8cTWUykrnhhqsJAURQeNZeU0OdctckUEDXKI4Crs8V9jn9SSP45n3lR5vV
         boow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qv04S8bPBd96FNqIwcSIUabz2xC2Ydzm88qYz3ixfjo=;
        b=UMJO940a0I14zGyM5RDF3Pd90aMBi4Ns+veODTiwxOa8l89JHxZXKHkb+65DlB9Z1a
         /NRAq3flKJ4joSU9cIzBqNa2rSmrnlcHt4czeFZkh8lGwgySQFRf58AKW60miy5Q4y3M
         t2obbi6b7o7/T1SO7oSzmFVtIxs0NHigo9BRETxPwwx0QX3t954iJ/2+H0jGyQ+tJspv
         /pXU6v5IS47urzti13M/YZSpOf8eQ8ZghFUU7pWqqaxpG9TO+D7SmY6BrYQ7IpMcLgRG
         iYyAOVOsq7dJj/EYxWwEEm+jUhNbAL+GmqK8A++6E7o23sGs7HKj3fPhZRhngAxBZuEV
         7j1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qv04S8bPBd96FNqIwcSIUabz2xC2Ydzm88qYz3ixfjo=;
        b=juYVmMf3wVund9CF3ayeDP2dxbLFSjmyEobXKU7em4XYlIdod6GflZ0B5O/aP+RKm9
         wg8nLlQm1bV5miEOTTJqhbEdfoQeCIBqgQzb+2gz6dy320r+PpBhDokoF6aLS1wCLInv
         auyviTNx1viZ8TYZxIrMott0FmSoeRDAvzboDzcDsz2M15ISWSvTyOfwOCbM9GOOHlPh
         tNN9aWfE/chG4MBh0aCMR3FouWPLtwkUNJYkzyHKzlcjL713FuyNwkczvMZzDv5cn++v
         O6A4F20n/lXlkHRVtl1+yDubyrePmz1T8mxUPI0G94a4uV7AWfFZPlpSdcQV9RLhyB7g
         zzmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532iuEEKWEk6bnMuysLBOd6SoqXXy6jzmiGKvDLfc0ABto/Z7vGK
	St3rVF9YS5YONsUhOJU/Hzs=
X-Google-Smtp-Source: ABdhPJwCAXlbjBpPV7OALSci1G0QH5+Eg1hFArizTylR7APprdojv0tRmIcNkpTz4KVvftkVKwqDbg==
X-Received: by 2002:aca:eb44:: with SMTP id j65mr2834424oih.19.1609934206777;
        Wed, 06 Jan 2021 03:56:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3d36:: with SMTP id a51ls733136otc.3.gmail; Wed, 06 Jan
 2021 03:56:46 -0800 (PST)
X-Received: by 2002:a9d:3d64:: with SMTP id a91mr2838242otc.144.1609934206477;
        Wed, 06 Jan 2021 03:56:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609934206; cv=none;
        d=google.com; s=arc-20160816;
        b=EtK5Jc2Ar6+6R+BcMiboDs/YRPpuSS7vycV0YBkuCabr0Pn/T+vYgjjxzLbhLeu1cs
         z5BkPPqYPUzoleSvHCr7i3PrVXIX4NCOGNhfrvLP6eqV97MuWD/dirqYKzIxPmMhvWJf
         JlQPhN8AUctscSSNtMHiV84VSwGGeBhh8yNZj4fsh9eUCLV4ZcZEC7gJYciYCxeJQSpI
         F4rsE6aa1XaJcnuV1Fvj2yZi6gYrcRf006akAOQ8DtUrmfw/A/kyf2YtIQOOGbbeQ0xh
         /7oXTq6U1WvptvnD3Z+Y/pyYraWRjJQldB1TZjBPwS7DQ1zZ9ublenR4qOLqK6kWKHJA
         vXBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=wzBsRAmTaPPuVzyMv1+iFfPgfurqCFgQKEqsxtwaJmM=;
        b=tZqzTSj7sB2MEem4e8ltfKfM1Ps/Rv8cMRuzy4p1nlrFQ/Jui18awMtEvzAIi8d+gC
         0ZiMKxDFz2iJmTbKmhTYB+X7r2Ik/n14h8yD69tMsRt8WmjOV4yv5ZwSv1w+wJXnFK6y
         qGDBzPqrLvxEVS8+Qv8oqkym4+h4F2dsEQ6iCZLj3NYzB4nVXUmyhQI7417P54pS14Be
         Pghne2vPCAAtbVOhL5MaG1kYNkiv4uga/If2Oml6fuoS0zrGw3t7pR1esjM1TUPbIGLo
         WPc71zyeeYFqmEZmHHOsbApUJzlrDmQLuQxcA/BM6WZTQdAb/AsLjISRc0J94m4qrLjk
         DcAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l19si147990oib.3.2021.01.06.03.56.46
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Jan 2021 03:56:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 514EF12FC;
	Wed,  6 Jan 2021 03:56:46 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A66AA3F70D;
	Wed,  6 Jan 2021 03:56:44 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 4/4] arm64: mte: Optimize mte_assign_mem_tag_range()
Date: Wed,  6 Jan 2021 11:55:19 +0000
Message-Id: <20210106115519.32222-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.29.2
In-Reply-To: <20210106115519.32222-1-vincenzo.frascino@arm.com>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

mte_assign_mem_tag_range() is called on production KASAN HW hot
paths. It makes sense to optimize it in an attempt to reduce the
overhead.

Optimize mte_assign_mem_tag_range() based on the indications provided at
[1].

[1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
 arch/arm64/lib/mte.S         | 15 ---------------
 2 files changed, 25 insertions(+), 16 deletions(-)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index c757ff756e09..ac134a74e1a1 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -50,7 +50,31 @@ long get_mte_ctrl(struct task_struct *task);
 int mte_ptrace_copy_tags(struct task_struct *child, long request,
 			 unsigned long addr, unsigned long data);
 
-void mte_assign_mem_tag_range(void *addr, size_t size);
+static inline void mte_assign_mem_tag_range(void *addr, size_t size)
+{
+	u64 _addr = (u64)addr;
+	u64 _end = _addr + size;
+
+	/*
+	 * This function must be invoked from an MTE enabled context.
+	 *
+	 * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
+	 * size must be non-zero and MTE_GRANULE_SIZE aligned.
+	 */
+	do {
+		/*
+		 * 'asm volatile' is required to prevent the compiler to move
+		 * the statement outside of the loop.
+		 */
+		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
+			     :
+			     : "r" (_addr)
+			     : "memory");
+
+		_addr += MTE_GRANULE_SIZE;
+	} while (_addr < _end);
+}
+
 
 #else /* CONFIG_ARM64_MTE */
 
diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
index 9e1a12e10053..a0a650451510 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -150,18 +150,3 @@ SYM_FUNC_START(mte_restore_page_tags)
 	ret
 SYM_FUNC_END(mte_restore_page_tags)
 
-/*
- * Assign allocation tags for a region of memory based on the pointer tag
- *   x0 - source pointer
- *   x1 - size
- *
- * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
- * size must be non-zero and MTE_GRANULE_SIZE aligned.
- */
-SYM_FUNC_START(mte_assign_mem_tag_range)
-1:	stg	x0, [x0]
-	add	x0, x0, #MTE_GRANULE_SIZE
-	subs	x1, x1, #MTE_GRANULE_SIZE
-	b.gt	1b
-	ret
-SYM_FUNC_END(mte_assign_mem_tag_range)
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106115519.32222-5-vincenzo.frascino%40arm.com.
