Return-Path: <kasan-dev+bncBDQ27FVWWUFRBYWGXTXQKGQEJ3OEWXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E90B117F1A
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 05:47:32 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id x9sf8466008plv.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 20:47:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575953251; cv=pass;
        d=google.com; s=arc-20160816;
        b=R5KDikhN7+Ob6JR4dSsvkpYAIuZGQvQsyjeJ6dp9FFiGwLI2wTrm6hclb66fEdrs3I
         8rrFJeFOmn7Wqd3uZURTZPjXWKhDtutMKj+Hl9HV+P1/DLcbEvBX69akygsWQEhzrO6u
         pDz/cqZU4ayzzFWRLYxU+Rpv2BRwnQD1EZiEjRf0fAqhcBzNnJlTu/+W3PbjDCBKSySQ
         h3wQOnn+vmtv/M0eWs3VltmQkDxe0Xy5h8TQ7VkFbn1SKunyJWr1km7rDi4sc6sUcLZ0
         5VcLXlcONySZHkbq8NZmBev4koJgT1nfukXF7Vx1pe6L6Yw2UfYw+JNh9NtrcL40773+
         jjAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=N45ctuQ3tW1l75i2V5lnoC4TfQv/WReFku3HlN9YKrA=;
        b=QgkXaaQB3Bw+FugbfaoAffNm7AB6KVJUwm63VnxXFC938tUdql3t5+Bs09qib4XcGF
         qhGNXV7C7kR9MGHMsupG8wNbu3Bzf5B1DhvTJZLaF0WW5ZH6mTguRMYo1YLESbpB+NPC
         4IAyJkaqVQfjZ0cZQnkHh1WUJjEACUJjQnmGKxVsgm+eEX6xdAOnKcOOyglZhukmGRUS
         VEgpIUA+aUQkVG2tkqhj09pSlGKddN71L4bCgQgYJw1ukvGScbesPcU8+cyxB/l9jviK
         7RyeSa7T00D0pAczzTrkurswN0kURH386ALa4owfiAKYMcZpm1OzBqxwnu3ZE85Ga+Li
         /qig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=O5nCdYx2;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N45ctuQ3tW1l75i2V5lnoC4TfQv/WReFku3HlN9YKrA=;
        b=mcFrXcG/NzvaEmxARflItOr6RszZ9lsx6bwcaZ+Fbron07brl6c68uoTvoauBnLLK+
         odTMNCOJcnW8jTIJTClsv7iNqXEYXcpqYGO1PlsN7eyh3V99pfl/n9PU2/EJgXff4Xxn
         INYWfitNYc0pJLZmA7vwhl2OOVjVCoibjonzCwJkjwEgAMsf9hbzF6ZgcHij/HlREWX/
         ekBSZOICbzVk7NrNAcGHhSSTpbb98TC5OUIk9VKgzBxocL2WZkHD6W/11f+Yxqce43hX
         uyP5kmljjVyUTDtbeG1sbBCbR4XInVoga/y95IXLDa0y1JaYacgYka9mBNwGv5k93BbP
         DpFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N45ctuQ3tW1l75i2V5lnoC4TfQv/WReFku3HlN9YKrA=;
        b=d2hoPs05zW+QuYa/sciILl9KSLxAv19johJDK3FaB1TS139wFkSw/PQb8AP6dprXHj
         ATuqsaCppkjOB2ItGxKvoCb/9MoSqtL6ZP2QFdwNoG2b+Ookz49JNyP5TUO+ROIarmpd
         odw/9GFblcMkiW7m2lKnto0jZpaVybIRFAIuyoOKNmDrgzoy79IwNDVLWgcoW5cDN9m9
         ytruhTAmIAeuk56hk28/0p7Ds11/YyDQt4/D1H3eTxTTtRijkJSUc8xGjexP8YwBBTsn
         B/LB/+6kAalVbaIJSDtGENT1DWt8fWbX7fPmMsFSjae1BdSzLg/MBVAMOxdPvXVPny7b
         EycQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV4AJWQHe6wmxy8Pd/RucNe0UUDwWm/plj6+O1+ur9hIg2FbBCO
	PxSNrFBHA85hMEPvv5qjk3s=
X-Google-Smtp-Source: APXvYqy8H478szh6OOwuruMtakv1ZPTRRasPWjB0e7ME/2+/va/5yA6SX7s/M3Un4fNLIiXc9S8vAw==
X-Received: by 2002:a63:7311:: with SMTP id o17mr21534957pgc.29.1575953250786;
        Mon, 09 Dec 2019 20:47:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8048:: with SMTP id y8ls4146993pfm.10.gmail; Mon, 09 Dec
 2019 20:47:30 -0800 (PST)
X-Received: by 2002:a65:46c6:: with SMTP id n6mr22621257pgr.15.1575953250148;
        Mon, 09 Dec 2019 20:47:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575953250; cv=none;
        d=google.com; s=arc-20160816;
        b=NzmWGxzXmj3fmsw2azn5wHfxJec0VxVDq22dNPqnyMB+eTvtEyINNPOj2nPmw1r52U
         k364qb57EUHvVeKhehdPcEUgEO5fLHN4ITfSIxPBm1R/n5t/FI0hwQRohCXveSWqPaXh
         kiHnVzOY6eDyQSBHuqRpaSdFYMU6jjJVwqaygE8Wg+OWr72PavSC8lRkFE7SaOtzh9ij
         MKBzAXcHHq098D8DKfFZu5eSywMw58p8/rLZF+CMt6hpKwL6F1Ul4lQxvoRUpfibpbP6
         ADfJUoF8ZrUIskPbnM84rK9TNTabDlPJeaRsgTPAFvqilcvW4XRvbdy41lU4eNRqmR+R
         lylQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Qz4EMw+QBJw2XWxTbQKVczK3wuv6III+QMaefXi4B1g=;
        b=LR8xRo8+HTsLGk/ngr1Pht9D/UbMiJmUGKilbjglHbEwcuz0ichHHkpkAHrw80ccyS
         HM+RPMRdh28MjdbC8AoFpHCnDtg82yJsm8NIwjp9Ppp4VeN/C/vdtOR58nQ8hgi0tXmY
         3NAtsLqUU7XctGZR/nw0ovri+ewmRSDb4MjpOpp+pc2hu4U4qoRzpau110KHw+7DRlW9
         1xIJs1MBdN0PekdvrRTJib0WSHVNpaeAB7yt+bPqjwYZeUcf9gCzaJJo55DR66YDB90q
         8fqX9BEvixsVVDf88BSG+e0sti3ErXaFPUIcWkSnp9E8vxTRbi1JEyjX+0GCvumKm663
         OOaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=O5nCdYx2;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id q207si69560pfc.5.2019.12.09.20.47.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 20:47:30 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id x17so1502989pln.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 20:47:30 -0800 (PST)
X-Received: by 2002:a17:90a:374f:: with SMTP id u73mr3243246pjb.22.1575953249787;
        Mon, 09 Dec 2019 20:47:29 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-e460-0b66-7007-c654.static.ipv6.internode.on.net. [2001:44b8:1113:6700:e460:b66:7007:c654])
        by smtp.gmail.com with ESMTPSA id a14sm1176178pfn.22.2019.12.09.20.47.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Dec 2019 20:47:29 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	linux-arch@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v2 1/4] mm: define MAX_PTRS_PER_{PTE,PMD,PUD}
Date: Tue, 10 Dec 2019 15:47:11 +1100
Message-Id: <20191210044714.27265-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191210044714.27265-1-dja@axtens.net>
References: <20191210044714.27265-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=O5nCdYx2;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

powerpc has boot-time configurable PTRS_PER_PTE, PMD and PUD. The
values are selected based on the MMU under which the kernel is
booted. This is much like how 4 vs 5-level paging on x86_64 leads to
boot-time configurable PTRS_PER_P4D.

So far, this hasn't leaked out of arch/powerpc. But with KASAN, we
have static arrays based on PTRS_PER_*, so for powerpc support must
provide constant upper bounds for generic code.

Define MAX_PTRS_PER_{PTE,PMD,PUD} for this purpose.

I have configured these constants:
 - in asm-generic headers
 - on arches that implement KASAN: x86, s390, arm64, xtensa and powerpc

I haven't wired up any other arches just yet - there is no user of
the constants outside of the KASAN code I add in the next patch, so
missing the constants on arches that don't support KASAN shouldn't
break anything.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/arm64/include/asm/pgtable-hwdef.h       | 3 +++
 arch/powerpc/include/asm/book3s/64/hash.h    | 4 ++++
 arch/powerpc/include/asm/book3s/64/pgtable.h | 7 +++++++
 arch/powerpc/include/asm/book3s/64/radix.h   | 5 +++++
 arch/s390/include/asm/pgtable.h              | 3 +++
 arch/x86/include/asm/pgtable_types.h         | 5 +++++
 arch/xtensa/include/asm/pgtable.h            | 1 +
 include/asm-generic/pgtable-nop4d-hack.h     | 9 +++++----
 include/asm-generic/pgtable-nopmd.h          | 9 +++++----
 include/asm-generic/pgtable-nopud.h          | 9 +++++----
 10 files changed, 43 insertions(+), 12 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
index d9fbd433cc17..485e1f3c5c6f 100644
--- a/arch/arm64/include/asm/pgtable-hwdef.h
+++ b/arch/arm64/include/asm/pgtable-hwdef.h
@@ -41,6 +41,7 @@
 #define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
 
 #define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
+#define MAX_PTRS_PER_PTE	PTRS_PER_PTE
 
 /*
  * PMD_SHIFT determines the size a level 2 page table entry can map.
@@ -50,6 +51,7 @@
 #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
 #define PMD_MASK		(~(PMD_SIZE-1))
 #define PTRS_PER_PMD		PTRS_PER_PTE
+#define MAX_PTRS_PER_PMD	PTRS_PER_PMD
 #endif
 
 /*
@@ -60,6 +62,7 @@
 #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
 #define PUD_MASK		(~(PUD_SIZE-1))
 #define PTRS_PER_PUD		PTRS_PER_PTE
+#define MAX_PTRS_PER_PUD	PTRS_PER_PUD
 #endif
 
 /*
diff --git a/arch/powerpc/include/asm/book3s/64/hash.h b/arch/powerpc/include/asm/book3s/64/hash.h
index 2781ebf6add4..fce329b8452e 100644
--- a/arch/powerpc/include/asm/book3s/64/hash.h
+++ b/arch/powerpc/include/asm/book3s/64/hash.h
@@ -18,6 +18,10 @@
 #include <asm/book3s/64/hash-4k.h>
 #endif
 
+#define H_PTRS_PER_PTE		(1 << H_PTE_INDEX_SIZE)
+#define H_PTRS_PER_PMD		(1 << H_PMD_INDEX_SIZE)
+#define H_PTRS_PER_PUD		(1 << H_PUD_INDEX_SIZE)
+
 /* Bits to set in a PMD/PUD/PGD entry valid bit*/
 #define HASH_PMD_VAL_BITS		(0x8000000000000000UL)
 #define HASH_PUD_VAL_BITS		(0x8000000000000000UL)
diff --git a/arch/powerpc/include/asm/book3s/64/pgtable.h b/arch/powerpc/include/asm/book3s/64/pgtable.h
index b01624e5c467..209817235a44 100644
--- a/arch/powerpc/include/asm/book3s/64/pgtable.h
+++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
@@ -231,6 +231,13 @@ extern unsigned long __pmd_frag_size_shift;
 #define PTRS_PER_PUD	(1 << PUD_INDEX_SIZE)
 #define PTRS_PER_PGD	(1 << PGD_INDEX_SIZE)
 
+#define MAX_PTRS_PER_PTE	((H_PTRS_PER_PTE > R_PTRS_PER_PTE) ? \
+				  H_PTRS_PER_PTE : R_PTRS_PER_PTE)
+#define MAX_PTRS_PER_PMD	((H_PTRS_PER_PMD > R_PTRS_PER_PMD) ? \
+				  H_PTRS_PER_PMD : R_PTRS_PER_PMD)
+#define MAX_PTRS_PER_PUD	((H_PTRS_PER_PUD > R_PTRS_PER_PUD) ? \
+				  H_PTRS_PER_PUD : R_PTRS_PER_PUD)
+
 /* PMD_SHIFT determines what a second-level page table entry can map */
 #define PMD_SHIFT	(PAGE_SHIFT + PTE_INDEX_SIZE)
 #define PMD_SIZE	(1UL << PMD_SHIFT)
diff --git a/arch/powerpc/include/asm/book3s/64/radix.h b/arch/powerpc/include/asm/book3s/64/radix.h
index d97db3ad9aae..4f826259de71 100644
--- a/arch/powerpc/include/asm/book3s/64/radix.h
+++ b/arch/powerpc/include/asm/book3s/64/radix.h
@@ -35,6 +35,11 @@
 #define RADIX_PMD_SHIFT		(PAGE_SHIFT + RADIX_PTE_INDEX_SIZE)
 #define RADIX_PUD_SHIFT		(RADIX_PMD_SHIFT + RADIX_PMD_INDEX_SIZE)
 #define RADIX_PGD_SHIFT		(RADIX_PUD_SHIFT + RADIX_PUD_INDEX_SIZE)
+
+#define R_PTRS_PER_PTE		(1 << RADIX_PTE_INDEX_SIZE)
+#define R_PTRS_PER_PMD		(1 << RADIX_PMD_INDEX_SIZE)
+#define R_PTRS_PER_PUD		(1 << RADIX_PUD_INDEX_SIZE)
+
 /*
  * Size of EA range mapped by our pagetables.
  */
diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgtable.h
index 7b03037a8475..3b491ce52ed2 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -342,6 +342,9 @@ static inline int is_module_addr(void *addr)
 #define PTRS_PER_PGD	_CRST_ENTRIES
 
 #define MAX_PTRS_PER_P4D	PTRS_PER_P4D
+#define MAX_PTRS_PER_PUD	PTRS_PER_PUD
+#define MAX_PTRS_PER_PMD	PTRS_PER_PMD
+#define MAX_PTRS_PER_PTE	PTRS_PER_PTE
 
 /*
  * Segment table and region3 table entry encoding
diff --git a/arch/x86/include/asm/pgtable_types.h b/arch/x86/include/asm/pgtable_types.h
index ea7400726d7a..82d523db133b 100644
--- a/arch/x86/include/asm/pgtable_types.h
+++ b/arch/x86/include/asm/pgtable_types.h
@@ -257,6 +257,11 @@ enum page_cache_mode {
 # include <asm/pgtable_64_types.h>
 #endif
 
+/* There is no runtime switching of these sizes */
+#define MAX_PTRS_PER_PUD PTRS_PER_PUD
+#define MAX_PTRS_PER_PMD PTRS_PER_PMD
+#define MAX_PTRS_PER_PTE PTRS_PER_PTE
+
 #ifndef __ASSEMBLY__
 
 #include <linux/types.h>
diff --git a/arch/xtensa/include/asm/pgtable.h b/arch/xtensa/include/asm/pgtable.h
index 27ac17c9da09..5d6aa16ceae6 100644
--- a/arch/xtensa/include/asm/pgtable.h
+++ b/arch/xtensa/include/asm/pgtable.h
@@ -55,6 +55,7 @@
  * we don't really have any PMD directory physically.
  */
 #define PTRS_PER_PTE		1024
+#define MAX_PTRS_PER_PTE	1024
 #define PTRS_PER_PTE_SHIFT	10
 #define PTRS_PER_PGD		1024
 #define PGD_ORDER		0
diff --git a/include/asm-generic/pgtable-nop4d-hack.h b/include/asm-generic/pgtable-nop4d-hack.h
index 829bdb0d6327..6faa23f9e0b4 100644
--- a/include/asm-generic/pgtable-nop4d-hack.h
+++ b/include/asm-generic/pgtable-nop4d-hack.h
@@ -14,10 +14,11 @@
  */
 typedef struct { pgd_t pgd; } pud_t;
 
-#define PUD_SHIFT	PGDIR_SHIFT
-#define PTRS_PER_PUD	1
-#define PUD_SIZE	(1UL << PUD_SHIFT)
-#define PUD_MASK	(~(PUD_SIZE-1))
+#define PUD_SHIFT		PGDIR_SHIFT
+#define MAX_PTRS_PER_PUD	1
+#define PTRS_PER_PUD		1
+#define PUD_SIZE		(1UL << PUD_SHIFT)
+#define PUD_MASK		(~(PUD_SIZE-1))
 
 /*
  * The "pgd_xxx()" functions here are trivial for a folded two-level
diff --git a/include/asm-generic/pgtable-nopmd.h b/include/asm-generic/pgtable-nopmd.h
index 0d9b28cba16d..4a860f47f3e6 100644
--- a/include/asm-generic/pgtable-nopmd.h
+++ b/include/asm-generic/pgtable-nopmd.h
@@ -17,10 +17,11 @@ struct mm_struct;
  */
 typedef struct { pud_t pud; } pmd_t;
 
-#define PMD_SHIFT	PUD_SHIFT
-#define PTRS_PER_PMD	1
-#define PMD_SIZE  	(1UL << PMD_SHIFT)
-#define PMD_MASK  	(~(PMD_SIZE-1))
+#define PMD_SHIFT		PUD_SHIFT
+#define MAX_PTRS_PER_PMD	1
+#define PTRS_PER_PMD		1
+#define PMD_SIZE  		(1UL << PMD_SHIFT)
+#define PMD_MASK  		(~(PMD_SIZE-1))
 
 /*
  * The "pud_xxx()" functions here are trivial for a folded two-level
diff --git a/include/asm-generic/pgtable-nopud.h b/include/asm-generic/pgtable-nopud.h
index d3776cb494c0..1aef1b18edbc 100644
--- a/include/asm-generic/pgtable-nopud.h
+++ b/include/asm-generic/pgtable-nopud.h
@@ -18,10 +18,11 @@
  */
 typedef struct { p4d_t p4d; } pud_t;
 
-#define PUD_SHIFT	P4D_SHIFT
-#define PTRS_PER_PUD	1
-#define PUD_SIZE  	(1UL << PUD_SHIFT)
-#define PUD_MASK  	(~(PUD_SIZE-1))
+#define PUD_SHIFT		P4D_SHIFT
+#define MAX_PTRS_PER_PUD	1
+#define PTRS_PER_PUD		1
+#define PUD_SIZE  		(1UL << PUD_SHIFT)
+#define PUD_MASK  		(~(PUD_SIZE-1))
 
 /*
  * The "p4d_xxx()" functions here are trivial for a folded two-level
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191210044714.27265-2-dja%40axtens.net.
