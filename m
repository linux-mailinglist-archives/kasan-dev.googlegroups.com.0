Return-Path: <kasan-dev+bncBCZP5TXROEIJL5FTXADBUBERNN2I4@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 82B2C99C7EE
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 13:01:43 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-6e38fabff35sf12253047b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 04:01:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728903702; cv=pass;
        d=google.com; s=arc-20240605;
        b=j1lB1ovDcHqZGdj9FUqJq+bV9b8hIbqJdiZwcsTpoZZXb/AM7K9Gku/SS2Rjo57P3R
         sh8vKiGEJ3m5X+7oLzPKE3byf9FUqzEIXohO/k+EJLpV02VA+Lxg3tU9YHwPCEfNGnDt
         zM7SFUskbBghy9Bg2msExcVEy/JT2HmTXmWP3W7de4DBf/igFcuWZzntom1JLxm9rYkG
         l1qX1xfrtbE37TCBu08TDMWTiBhcybQSwqVsStMDs2DISFifFUyu/2G/6lGEihiHwhHD
         +KE8J5O3Ce8EN+F6F4oPBmhqjRbxoJ5Zb9l55ylxKYqEkVUh2bBmE8OLTORWkAYn9ZKT
         vndQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SXTHr4iA0UEQaKHir136JkF+0Lc2/b57Y3F78H95K1I=;
        fh=po6FG4xLyPoPJ8H4/VimnexPEG6pWo5nvWAeDkC3pMk=;
        b=RCEs8LskkCLEzToWmwohaZKawPjZbYoCYegwPjZSfXRv8qopR0vJ6uy/ez7vKncNqa
         THYNbN+C8w08FB+381AJwAlQTHBoqJp2NEfVVlbNaL8c4jvFwQLGPhLZrdQS3MKVhjxM
         t158RMjP+EmL2P3HRwoWJ7r37KbBLHXaT4gOrrhtEVERsQpL1Xp4TnhE+JrP8ttoqg28
         A7mt5zplaQRSuPhOs1nqYeiDZTFx8vrMhoWK3is0GIfOKzpqgZL62YKM+d4PBbJOM27m
         cVpkIBCXAoTPorVJ43ZcEW4CP4ppJ6cu5NFDjSUeSBD0uytMNHVqLcCZnIzVn81qWOwq
         92hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728903702; x=1729508502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SXTHr4iA0UEQaKHir136JkF+0Lc2/b57Y3F78H95K1I=;
        b=CoLzKiPmy9Fhg/IU6s+OTdAuyIXhMvv1jZcxbgmaCUqhkx/UvgPVEPlJjX7gutVjrJ
         Dw6snIjJ7hCvlNi02hvYCKqaokquy/gxONlIhbqUR+J0DhlyNTQkepPXfT+SnLdnuTux
         ICy0ZGEafXZmsy8R+BDj8sDGPyGLfDaZ9+gJ8sJsver9y5yEqDGyN3etGel1hlMzIpxs
         eR/lB4D6LBRpgtFJUXPear0KpAdpupkITKfsDZGVZuWIDngDQfSeKmHAGau3r+Q3BFMr
         1SZax4SFuv7c+IqdyOfoxgS+svPSjrO+FiUbq/poXV+LlEL+gBZIWCMZ6mJrpYzOzVbV
         ENaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728903702; x=1729508502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SXTHr4iA0UEQaKHir136JkF+0Lc2/b57Y3F78H95K1I=;
        b=r+WZL/Oks6bYsobEFdfXE/4F01mPx0vRrozG4c+VVrpeOnhVUh9eRK/yBFn0qhB+Wo
         VJFmBNpF36zi+KIHsLfOSQLJDIlHPHCEzckCcC2aVLYmzBcDyrFXOlTg8uys1HtFfWcT
         ljvRpeiv3BbtqU8QdswfKXYK4OswqIuXoc6a2+sDHPX6c29114/fFDaOALo5uwWssdsK
         cCpRq1v++nOylCt1Hdo74LXzdMzRAUFa75BWXp9+POqOVKv3wrkxCqntXzF4NEByu3vR
         1ETWtZ4OZvcpeNJ8m16qad+A9ClDLCANGBlB4K29Nj+CB5C6KmYk4vMctY5KpoGqi9jy
         Zuqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWz+A36DNlzn56vfuB4yjF1YNkPJMiNEj5+0AAyzL+uC6H1fMCpcrB4seOJCYZLEuYdz7COvA==@lfdr.de
X-Gm-Message-State: AOJu0Yxxj6HDm9raueSoRF9Q65gXdX4v4lxcwdHqxC5kRE1SRuzeSh5u
	Oyu5Cyi9kqL2iG+4xLu3rv8C2qhciwGMAYUJlJaXev9GJyryDf2U
X-Google-Smtp-Source: AGHT+IEt1HsjHq53di5hfXrCaLs/TvQh8M4yVPOwRICea79PQ1xEoWwOPjPHVmvdj1oUz9MCA/iX5Q==
X-Received: by 2002:a05:6902:1549:b0:e28:b864:e97f with SMTP id 3f1490d57ef6-e2919dfb274mr6818893276.46.1728903701881;
        Mon, 14 Oct 2024 04:01:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1885:b0:e29:2d4a:f757 with SMTP id
 3f1490d57ef6-e292d4afb2fls197175276.1.-pod-prod-09-us; Mon, 14 Oct 2024
 04:01:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUSZxcNKH2agjJ6puCDbqVRW/1ibTdyzpjoQCHrxJVixfj/KeW/psXD0h9695pId+s4pfDEldTjjxw=@googlegroups.com
X-Received: by 2002:a05:6902:18d2:b0:e29:5540:7f85 with SMTP id 3f1490d57ef6-e2955407fb6mr1580695276.1.1728903701127;
        Mon, 14 Oct 2024 04:01:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728903701; cv=none;
        d=google.com; s=arc-20240605;
        b=C9SJr5UZvusInZAA/Yanitr9hs9HTmzYYevCRrg0Nl0QoFmjDqKOQ3maHVUSwkJ1lQ
         3Xhr0HxR5ikpCR2DWUtgK+/4IYE5Oof436a6mktFdpcWx8NXFHS+oxwCbWzyVh3BfiXh
         FbptJJ6/oi3KaGXU0OT8Qj5UKC1rUtBnJb8czhluzOnf+c0yLSAN1KEQ761TDK1fI6l3
         JUBFo0L760dbO4MFrNLZWj56cNsQm1Hi8+ekI5e8mrIjbmP6UvN0J/L6zjSxoJBIsHuk
         Zhv0dp3AheyG3iUb/UIRD0KDQ2jhtgPB/FCOxmCURFy6zxWrlgzPpwFln6CZEAtpyihI
         HzSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=r9v3S3hMjuiCiaBUIv6jmo6gDiOvZ9WOws2YRMMwzI8=;
        fh=Vb509HLg/3ySrrOxXcquN2XcIGgJcKs2ocI33Tn4UJo=;
        b=KkKAjMteWjeP5/Coqdtr4NOWqePi6XIXeoxPTWmMmgm9KGyDhf78uMU1Rub4cWzHfS
         6nF2jbmEx94CcjqFWInwHk9C85F23eFzr0YHFofr0S+B0JnIEzGu+wPUVMXuPrPS3kKc
         1xzhBhbCcrjayEuy3aMs+x0JxPSuaV7NUne6X7mA+wkStnPQnbaqKy8NEK9iGTwDDw1M
         PIQIgvjLoj47cW/CYdBXIliHkn9BuW76+H78DK1h0aSAIYN08w/gOibMmgeTE4bEcZmQ
         ZpoxdgKogu1DLM/UUIxVn5IDl8hc5v4esuTHhsEkVpR71IEKW0yN/6LnyqV9u/HcItn2
         Ynzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 3f1490d57ef6-e290ef44a09si507803276.2.2024.10.14.04.01.40
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2024 04:01:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C1414175D;
	Mon, 14 Oct 2024 04:02:09 -0700 (PDT)
Received: from e125769.cambridge.arm.com (e125769.cambridge.arm.com [10.1.196.27])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2811C3F51B;
	Mon, 14 Oct 2024 04:01:37 -0700 (PDT)
From: Ryan Roberts <ryan.roberts@arm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	David Hildenbrand <david@redhat.com>,
	Greg Marsden <greg.marsden@oracle.com>,
	Ivan Ivanov <ivan.ivanov@suse.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	Marc Zyngier <maz@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthias Brugger <mbrugger@suse.com>,
	Miroslav Benes <mbenes@suse.cz>,
	Oliver Upton <oliver.upton@linux.dev>,
	Thomas Gleixner <tglx@linutronix.de>,
	Will Deacon <will@kernel.org>
Cc: Ryan Roberts <ryan.roberts@arm.com>,
	kasan-dev@googlegroups.com,
	kvmarm@lists.linux.dev,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [RFC PATCH v1 43/57] arm64: Clean up simple cases of CONFIG_ARM64_*K_PAGES
Date: Mon, 14 Oct 2024 11:58:50 +0100
Message-ID: <20241014105912.3207374-43-ryan.roberts@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20241014105912.3207374-1-ryan.roberts@arm.com>
References: <20241014105514.3206191-1-ryan.roberts@arm.com>
 <20241014105912.3207374-1-ryan.roberts@arm.com>
MIME-Version: 1.0
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
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

There are a number of places that define macros conditionally depending
on which of the CONFIG_ARM64_*K_PAGES macros are defined. But in
preparation for supporting boot-time page size selection, we will no
longer be able to make these decisions at compile time.

So let's refactor the code to check the size of PAGE_SIZE using the
ternary operator. This approach will still resolve to compile-time
constants when configured for a compile-time page size, but it will also
work when we turn PAGE_SIZE into a run-time value. Additionally,
IS_ENABLED(CONFIG_ARM64_*K_PAGES) instances are also converted to test
the size of PAGE_SIZE.

Additionally modify ARM64_HAS_VA52 capability detection to use a custom
match function, which chooses which feature register and field to check
based on PAGE_SIZE. The compiler will eliminate the other page sizes
when selecting a compile time page size, but will also now cope with
seting page size at boot time.

Signed-off-by: Ryan Roberts <ryan.roberts@arm.com>
---

***NOTE***
Any confused maintainers may want to read the cover note here for context:
https://lore.kernel.org/all/20241014105514.3206191-1-ryan.roberts@arm.com/

 arch/arm64/include/asm/kvm_arm.h     | 21 ++++-------
 arch/arm64/include/asm/kvm_pgtable.h |  6 +---
 arch/arm64/include/asm/memory.h      |  7 ++--
 arch/arm64/include/asm/processor.h   | 10 +++---
 arch/arm64/include/asm/sparsemem.h   | 11 ++----
 arch/arm64/include/asm/sysreg.h      | 54 ++++++++++++++++++----------
 arch/arm64/kernel/cpufeature.c       | 43 +++++++++++++---------
 arch/arm64/mm/fixmap.c               |  2 +-
 arch/arm64/mm/init.c                 | 20 +++++------
 arch/arm64/mm/kasan_init.c           |  8 ++---
 arch/arm64/mm/mmu.c                  |  2 +-
 drivers/irqchip/irq-gic-v3-its.c     |  2 +-
 12 files changed, 94 insertions(+), 92 deletions(-)

diff --git a/arch/arm64/include/asm/kvm_arm.h b/arch/arm64/include/asm/kvm_arm.h
index d81cc746e0ebd..08155dc17ad17 100644
--- a/arch/arm64/include/asm/kvm_arm.h
+++ b/arch/arm64/include/asm/kvm_arm.h
@@ -189,22 +189,13 @@
  * Entry_Level = 4 - Number_of_levels.
  *
  */
-#ifdef CONFIG_ARM64_64K_PAGES
+#define VTCR_EL2_TGRAN							\
+	(PAGE_SIZE == SZ_64K ?						\
+		VTCR_EL2_TG0_64K :					\
+		(PAGE_SIZE == SZ_16K ? VTCR_EL2_TG0_16K : VTCR_EL2_TG0_4K))
 
-#define VTCR_EL2_TGRAN			VTCR_EL2_TG0_64K
-#define VTCR_EL2_TGRAN_SL0_BASE		3UL
-
-#elif defined(CONFIG_ARM64_16K_PAGES)
-
-#define VTCR_EL2_TGRAN			VTCR_EL2_TG0_16K
-#define VTCR_EL2_TGRAN_SL0_BASE		3UL
-
-#else	/* 4K */
-
-#define VTCR_EL2_TGRAN			VTCR_EL2_TG0_4K
-#define VTCR_EL2_TGRAN_SL0_BASE		2UL
-
-#endif
+#define VTCR_EL2_TGRAN_SL0_BASE						\
+	(PAGE_SIZE == SZ_64K ? 3UL : (PAGE_SIZE == SZ_16K ? 3UL : 2UL))
 
 #define VTCR_EL2_LVLS_TO_SL0(levels)	\
 	((VTCR_EL2_TGRAN_SL0_BASE - (4 - (levels))) << VTCR_EL2_SL0_SHIFT)
diff --git a/arch/arm64/include/asm/kvm_pgtable.h b/arch/arm64/include/asm/kvm_pgtable.h
index 19278dfe79782..796614bf59e78 100644
--- a/arch/arm64/include/asm/kvm_pgtable.h
+++ b/arch/arm64/include/asm/kvm_pgtable.h
@@ -20,11 +20,7 @@
  *  - 16K (level 2):	32MB
  *  - 64K (level 2):	512MB
  */
-#ifdef CONFIG_ARM64_4K_PAGES
-#define KVM_PGTABLE_MIN_BLOCK_LEVEL	1
-#else
-#define KVM_PGTABLE_MIN_BLOCK_LEVEL	2
-#endif
+#define KVM_PGTABLE_MIN_BLOCK_LEVEL	(PAGE_SIZE == SZ_4K ? 1 : 2)
 
 #define kvm_lpa2_is_enabled()		system_supports_lpa2()
 
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 54fb014eba058..6aa97fa22dc30 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -188,11 +188,8 @@
 #define MT_S2_FWB_NORMAL_NC	5
 #define MT_S2_FWB_DEVICE_nGnRE	1
 
-#ifdef CONFIG_ARM64_4K_PAGES
-#define IOREMAP_MAX_ORDER	(PUD_SHIFT)
-#else
-#define IOREMAP_MAX_ORDER	(PMD_SHIFT)
-#endif
+#define IOREMAP_MAX_ORDER						\
+	(PAGE_SIZE == SZ_4K ? PUD_SHIFT : PMD_SHIFT)
 
 /*
  *  Open-coded (swapper_pg_dir - reserved_pg_dir) as this cannot be calculated
diff --git a/arch/arm64/include/asm/processor.h b/arch/arm64/include/asm/processor.h
index f77371232d8c6..444694a4e6733 100644
--- a/arch/arm64/include/asm/processor.h
+++ b/arch/arm64/include/asm/processor.h
@@ -55,15 +55,15 @@
 #define TASK_SIZE_MAX		(UL(1) << VA_BITS)
 
 #ifdef CONFIG_COMPAT
-#if defined(CONFIG_ARM64_64K_PAGES) && defined(CONFIG_KUSER_HELPERS)
+#if defined(CONFIG_KUSER_HELPERS)
 /*
- * With CONFIG_ARM64_64K_PAGES enabled, the last page is occupied
- * by the compat vectors page.
+ * With 64K pages in use, the last page is occupied by the compat vectors page.
  */
-#define TASK_SIZE_32		UL(0x100000000)
+#define TASK_SIZE_32							\
+	(PAGE_SIZE == SZ_64K ? UL(0x100000000) : (UL(0x100000000) - PAGE_SIZE))
 #else
 #define TASK_SIZE_32		(UL(0x100000000) - PAGE_SIZE)
-#endif /* CONFIG_ARM64_64K_PAGES */
+#endif /* CONFIG_KUSER_HELPERS */
 #define TASK_SIZE		(test_thread_flag(TIF_32BIT) ? \
 				TASK_SIZE_32 : TASK_SIZE_64)
 #define TASK_SIZE_OF(tsk)	(test_tsk_thread_flag(tsk, TIF_32BIT) ? \
diff --git a/arch/arm64/include/asm/sparsemem.h b/arch/arm64/include/asm/sparsemem.h
index 8a8acc220371c..a05fdd54014f7 100644
--- a/arch/arm64/include/asm/sparsemem.h
+++ b/arch/arm64/include/asm/sparsemem.h
@@ -11,19 +11,12 @@
  * Section size must be at least 512MB for 64K base
  * page size config. Otherwise it will be less than
  * MAX_PAGE_ORDER and the build process will fail.
- */
-#ifdef CONFIG_ARM64_64K_PAGES
-#define SECTION_SIZE_BITS 29
-
-#else
-
-/*
+ *
  * Section size must be at least 128MB for 4K base
  * page size config. Otherwise PMD based huge page
  * entries could not be created for vmemmap mappings.
  * 16K follows 4K for simplicity.
  */
-#define SECTION_SIZE_BITS 27
-#endif /* CONFIG_ARM64_64K_PAGES */
+#define SECTION_SIZE_BITS	(PAGE_SIZE == SZ_64K ? 29 : 27)
 
 #endif
diff --git a/arch/arm64/include/asm/sysreg.h b/arch/arm64/include/asm/sysreg.h
index 4a9ea103817e8..cbcf861bbf2a6 100644
--- a/arch/arm64/include/asm/sysreg.h
+++ b/arch/arm64/include/asm/sysreg.h
@@ -10,10 +10,12 @@
 #define __ASM_SYSREG_H
 
 #include <linux/bits.h>
+#include <linux/sizes.h>
 #include <linux/stringify.h>
 #include <linux/kasan-tags.h>
 
 #include <asm/gpr-num.h>
+#include <asm/page-def.h>
 
 /*
  * ARMv8 ARM reserves the following encoding for system registers:
@@ -913,24 +915,40 @@
 #define ID_AA64MMFR0_EL1_PARANGE_MAX	ID_AA64MMFR0_EL1_PARANGE_48
 #endif
 
-#if defined(CONFIG_ARM64_4K_PAGES)
-#define ID_AA64MMFR0_EL1_TGRAN_SHIFT		ID_AA64MMFR0_EL1_TGRAN4_SHIFT
-#define ID_AA64MMFR0_EL1_TGRAN_LPA2		ID_AA64MMFR0_EL1_TGRAN4_52_BIT
-#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MIN	ID_AA64MMFR0_EL1_TGRAN4_SUPPORTED_MIN
-#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MAX	ID_AA64MMFR0_EL1_TGRAN4_SUPPORTED_MAX
-#define ID_AA64MMFR0_EL1_TGRAN_2_SHIFT		ID_AA64MMFR0_EL1_TGRAN4_2_SHIFT
-#elif defined(CONFIG_ARM64_16K_PAGES)
-#define ID_AA64MMFR0_EL1_TGRAN_SHIFT		ID_AA64MMFR0_EL1_TGRAN16_SHIFT
-#define ID_AA64MMFR0_EL1_TGRAN_LPA2		ID_AA64MMFR0_EL1_TGRAN16_52_BIT
-#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MIN	ID_AA64MMFR0_EL1_TGRAN16_SUPPORTED_MIN
-#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MAX	ID_AA64MMFR0_EL1_TGRAN16_SUPPORTED_MAX
-#define ID_AA64MMFR0_EL1_TGRAN_2_SHIFT		ID_AA64MMFR0_EL1_TGRAN16_2_SHIFT
-#elif defined(CONFIG_ARM64_64K_PAGES)
-#define ID_AA64MMFR0_EL1_TGRAN_SHIFT		ID_AA64MMFR0_EL1_TGRAN64_SHIFT
-#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MIN	ID_AA64MMFR0_EL1_TGRAN64_SUPPORTED_MIN
-#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MAX	ID_AA64MMFR0_EL1_TGRAN64_SUPPORTED_MAX
-#define ID_AA64MMFR0_EL1_TGRAN_2_SHIFT		ID_AA64MMFR0_EL1_TGRAN64_2_SHIFT
-#endif
+#define ID_AA64MMFR0_EL1_TGRAN_SHIFT					\
+	(PAGE_SIZE == SZ_4K ?						\
+		ID_AA64MMFR0_EL1_TGRAN4_SHIFT :				\
+		(PAGE_SIZE == SZ_16K ?					\
+			ID_AA64MMFR0_EL1_TGRAN16_SHIFT :		\
+			ID_AA64MMFR0_EL1_TGRAN64_SHIFT))
+
+#define ID_AA64MMFR0_EL1_TGRAN_LPA2					\
+	(PAGE_SIZE == SZ_4K ?						\
+		ID_AA64MMFR0_EL1_TGRAN4_52_BIT :			\
+		(PAGE_SIZE == SZ_16K ?					\
+			ID_AA64MMFR0_EL1_TGRAN16_52_BIT :		\
+			-1))
+
+#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MIN				\
+	(PAGE_SIZE == SZ_4K ?						\
+		ID_AA64MMFR0_EL1_TGRAN4_SUPPORTED_MIN :			\
+		(PAGE_SIZE == SZ_16K ?					\
+			ID_AA64MMFR0_EL1_TGRAN16_SUPPORTED_MIN :	\
+			ID_AA64MMFR0_EL1_TGRAN64_SUPPORTED_MIN))
+
+#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MAX				\
+	(PAGE_SIZE == SZ_4K ?						\
+		ID_AA64MMFR0_EL1_TGRAN4_SUPPORTED_MAX :			\
+		(PAGE_SIZE == SZ_16K ?					\
+			ID_AA64MMFR0_EL1_TGRAN16_SUPPORTED_MAX :	\
+			ID_AA64MMFR0_EL1_TGRAN64_SUPPORTED_MAX))
+
+#define ID_AA64MMFR0_EL1_TGRAN_2_SHIFT					\
+	(PAGE_SIZE == SZ_4K ?						\
+		ID_AA64MMFR0_EL1_TGRAN4_2_SHIFT :			\
+		(PAGE_SIZE == SZ_16K ?					\
+			ID_AA64MMFR0_EL1_TGRAN16_2_SHIFT :		\
+			ID_AA64MMFR0_EL1_TGRAN64_2_SHIFT))
 
 #define CPACR_EL1_FPEN_EL1EN	(BIT(20)) /* enable EL1 access */
 #define CPACR_EL1_FPEN_EL0EN	(BIT(21)) /* enable EL0 access, if EL1EN set */
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 646ecd3069fdd..7705c9c0e7142 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1831,11 +1831,13 @@ static bool has_nv1(const struct arm64_cpu_capabilities *entry, int scope)
 		  is_midr_in_range_list(read_cpuid_id(), nv1_ni_list)));
 }
 
-#if defined(ID_AA64MMFR0_EL1_TGRAN_LPA2) && defined(ID_AA64MMFR0_EL1_TGRAN_2_SUPPORTED_LPA2)
 static bool has_lpa2_at_stage1(u64 mmfr0)
 {
 	unsigned int tgran;
 
+	if (PAGE_SIZE == SZ_64K)
+		return false;
+
 	tgran = cpuid_feature_extract_unsigned_field(mmfr0,
 					ID_AA64MMFR0_EL1_TGRAN_SHIFT);
 	return tgran == ID_AA64MMFR0_EL1_TGRAN_LPA2;
@@ -1845,6 +1847,9 @@ static bool has_lpa2_at_stage2(u64 mmfr0)
 {
 	unsigned int tgran;
 
+	if (PAGE_SIZE == SZ_64K)
+		return false;
+
 	tgran = cpuid_feature_extract_unsigned_field(mmfr0,
 					ID_AA64MMFR0_EL1_TGRAN_2_SHIFT);
 	return tgran == ID_AA64MMFR0_EL1_TGRAN_2_SUPPORTED_LPA2;
@@ -1857,10 +1862,26 @@ static bool has_lpa2(const struct arm64_cpu_capabilities *entry, int scope)
 	mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
 	return has_lpa2_at_stage1(mmfr0) && has_lpa2_at_stage2(mmfr0);
 }
-#else
-static bool has_lpa2(const struct arm64_cpu_capabilities *entry, int scope)
+
+#ifdef CONFIG_ARM64_VA_BITS_52
+static bool has_va52(const struct arm64_cpu_capabilities *entry, int scope)
 {
-	return false;
+	const struct arm64_cpu_capabilities entry_64k = {
+		ARM64_CPUID_FIELDS(ID_AA64MMFR2_EL1, VARange, 52)
+	};
+	const struct arm64_cpu_capabilities entry_16k = {
+		ARM64_CPUID_FIELDS(ID_AA64MMFR0_EL1, TGRAN16, 52_BIT)
+	};
+	const struct arm64_cpu_capabilities entry_4k = {
+		ARM64_CPUID_FIELDS(ID_AA64MMFR0_EL1, TGRAN4, 52_BIT)
+	};
+
+	if (PAGE_SIZE == SZ_64K)
+		return has_cpuid_feature(&entry_64k, scope);
+	else if (PAGE_SIZE == SZ_16K)
+		return has_cpuid_feature(&entry_16k, scope);
+	else
+		return has_cpuid_feature(&entry_4k, scope);
 }
 #endif
 
@@ -2847,20 +2868,10 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 	},
 #ifdef CONFIG_ARM64_VA_BITS_52
 	{
+		.desc = "52-bit Virtual Addressing",
 		.capability = ARM64_HAS_VA52,
 		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
-		.matches = has_cpuid_feature,
-#ifdef CONFIG_ARM64_64K_PAGES
-		.desc = "52-bit Virtual Addressing (LVA)",
-		ARM64_CPUID_FIELDS(ID_AA64MMFR2_EL1, VARange, 52)
-#else
-		.desc = "52-bit Virtual Addressing (LPA2)",
-#ifdef CONFIG_ARM64_4K_PAGES
-		ARM64_CPUID_FIELDS(ID_AA64MMFR0_EL1, TGRAN4, 52_BIT)
-#else
-		ARM64_CPUID_FIELDS(ID_AA64MMFR0_EL1, TGRAN16, 52_BIT)
-#endif
-#endif
+		.matches = has_va52,
 	},
 #endif
 	{
diff --git a/arch/arm64/mm/fixmap.c b/arch/arm64/mm/fixmap.c
index de1e09d986ad2..15ce3253ad359 100644
--- a/arch/arm64/mm/fixmap.c
+++ b/arch/arm64/mm/fixmap.c
@@ -82,7 +82,7 @@ static void __init early_fixmap_init_pud(p4d_t *p4dp, unsigned long addr,
 		 * share the top level pgd entry, which should only happen on
 		 * 16k/4 levels configurations.
 		 */
-		BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES));
+		BUG_ON(PAGE_SIZE != SZ_16K);
 	}
 
 	if (p4d_none(p4d))
diff --git a/arch/arm64/mm/init.c b/arch/arm64/mm/init.c
index 9b5ab6818f7f3..42eb246949072 100644
--- a/arch/arm64/mm/init.c
+++ b/arch/arm64/mm/init.c
@@ -73,13 +73,10 @@ phys_addr_t __ro_after_init arm64_dma_phys_limit;
  * (64k granule), or a multiple that can be mapped using contiguous bits
  * in the page tables: 32 * PMD_SIZE (16k granule)
  */
-#if defined(CONFIG_ARM64_4K_PAGES)
-#define ARM64_MEMSTART_SHIFT		PUD_SHIFT
-#elif defined(CONFIG_ARM64_16K_PAGES)
-#define ARM64_MEMSTART_SHIFT		CONT_PMD_SHIFT
-#else
-#define ARM64_MEMSTART_SHIFT		PMD_SHIFT
-#endif
+#define ARM64_MEMSTART_SHIFT						\
+	(PAGE_SIZE == SZ_4K ?						\
+		PUD_SHIFT :						\
+		(PAGE_SIZE == SZ_16K ? CONT_PMD_SHIFT : PMD_SHIFT))
 
 /*
  * sparsemem vmemmap imposes an additional requirement on the alignment of
@@ -87,11 +84,10 @@ phys_addr_t __ro_after_init arm64_dma_phys_limit;
  * has a direct correspondence, and needs to appear sufficiently aligned
  * in the virtual address space.
  */
-#if ARM64_MEMSTART_SHIFT < SECTION_SIZE_BITS
-#define ARM64_MEMSTART_ALIGN	(1UL << SECTION_SIZE_BITS)
-#else
-#define ARM64_MEMSTART_ALIGN	(1UL << ARM64_MEMSTART_SHIFT)
-#endif
+#define ARM64_MEMSTART_ALIGN						\
+	(ARM64_MEMSTART_SHIFT < SECTION_SIZE_BITS ?			\
+		(1UL << SECTION_SIZE_BITS) :				\
+		(1UL << ARM64_MEMSTART_SHIFT))
 
 static void __init arch_reserve_crashkernel(void)
 {
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b65a29440a0c9..9af897fb3c432 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -178,10 +178,10 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
 	} while (pgdp++, addr = next, addr != end);
 }
 
-#if defined(CONFIG_ARM64_64K_PAGES) || CONFIG_PGTABLE_LEVELS > 4
+#if CONFIG_PGTABLE_LEVELS > 4
 #define SHADOW_ALIGN	P4D_SIZE
 #else
-#define SHADOW_ALIGN	PUD_SIZE
+#define SHADOW_ALIGN	(PAGE_SIZE == SZ_64K ? P4D_SIZE : PUD_SIZE)
 #endif
 
 /*
@@ -243,8 +243,8 @@ static int __init root_level_idx(u64 addr)
 	 * not implemented. This means we need to index the table as usual,
 	 * instead of masking off bits based on vabits_actual.
 	 */
-	u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
-							: vabits_actual;
+	u64 vabits = PAGE_SIZE == SZ_64K ? VA_BITS
+					 : vabits_actual;
 	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
 
 	return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index d4d30eaefb4cd..a528787c1e550 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -1179,7 +1179,7 @@ int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
 {
 	WARN_ON((start < VMEMMAP_START) || (end > VMEMMAP_END));
 
-	if (!IS_ENABLED(CONFIG_ARM64_4K_PAGES))
+	if (PAGE_SIZE != SZ_4K)
 		return vmemmap_populate_basepages(start, end, node, altmap);
 	else
 		return vmemmap_populate_hugepages(start, end, node, altmap);
diff --git a/drivers/irqchip/irq-gic-v3-its.c b/drivers/irqchip/irq-gic-v3-its.c
index fdec478ba5e70..b745579b4b9f3 100644
--- a/drivers/irqchip/irq-gic-v3-its.c
+++ b/drivers/irqchip/irq-gic-v3-its.c
@@ -2323,7 +2323,7 @@ static int its_setup_baser(struct its_node *its, struct its_baser *baser,
 	baser_phys = virt_to_phys(base);
 
 	/* Check if the physical address of the memory is above 48bits */
-	if (IS_ENABLED(CONFIG_ARM64_64K_PAGES) && (baser_phys >> 48)) {
+	if (PAGE_SIZE == SZ_64K && (baser_phys >> 48)) {
 
 		/* 52bit PA is supported only when PageSize=64K */
 		if (psz != SZ_64K) {
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014105912.3207374-43-ryan.roberts%40arm.com.
