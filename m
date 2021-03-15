Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIF6XWBAMGQEBTN3JAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A476E33B3B1
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:33 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id o124sf4194955oia.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814432; cv=pass;
        d=google.com; s=arc-20160816;
        b=pU+Mvenc/pr8VuOV0AjJsYIVgozt1TPq9lZK9xcANgnxMyypbqM6v/gFjOGdrK+Teh
         To+4IDLkwn4TRfA8FvNN23KUfttkv87EnpYAM99ympe6r0ICN0tkq1mbA+iajHEJoilI
         rXQtRS/tkp117jbtoOdaSFMeqZuKDLXcJWL/x9lBeEfouWXd/7D7SSQkmutjFqHKv3Ri
         07xdyuA/Qn97yVkstKmAEJlgAGfng11p2jPO5dhBFPc4AMZXjEdjKEdOtt7u1UQgFNR+
         ysP2k6e61OeAM7NQgNvOLTubrIcnLNIYDf0U2l8w+Q+U3KxzYLJiPmueWgQTui2wLf5I
         X3hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NofscBDEeDVOVnaVmxgtTCaacFO80KRiTvcyi2LwHb8=;
        b=ov0OkRoUSi0UJnqP307ckMNrSY1ank9AGjoyN4I+Q6wzXYKayPYeFLz5dLWfxRx+IL
         W3khotybQfA5TisGZf8TCNZGHbipNWpoIwA7Vi1Lco40CZX8zOMOJmALAapzU5santXp
         EY6VeeFaD84S9KivbfiRxDN1r6uV/KAv1sKqsT0JkPAMXZO0f0v0V5hOWxKxKxHupIQG
         rJz5euQhdAH3d531jJKxSYDLO0kHvPiff4ibQMdawg4K2JNtV9TNXXrAR8HLgEzVfqNI
         LA3hM7O502GActlNwoTx6HRCzH5zaJ/3PuA9qWB9YXcBntH2aEKArhcvLv9MGtMHyFjs
         c8OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NofscBDEeDVOVnaVmxgtTCaacFO80KRiTvcyi2LwHb8=;
        b=kfhLaposamTCYK+TkyzNcTPEN4qlBuGwR6A9676T16Ur2PrpxKeTLXV/SJkfuJBlzn
         4mwQ9V1Y6PBCdYfQk9EplEMx4TNYNkIyDozTwf6187zqodaiAq29dBpsMj70Pxy/WB2q
         w+yb96lUUs3B9GXY4YJhGAX3wWc4wB5dOod6+tpybqshdRf0jbIro7mj3NDKXfhz37w/
         p5/7mnUeNGYdG16+FxnJllsP8IiX89GEyzEYg6qYJDTK80+aNerRv9bNoq4xG/2Nvp3n
         X8opjMc++ONzEYs4U7/QzbAnoC1g6phoIMqFLwwIi8h4XRGEHsOO81T1/DwoIvzQhzRv
         Z2HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NofscBDEeDVOVnaVmxgtTCaacFO80KRiTvcyi2LwHb8=;
        b=QBLzGZJTHAYPg+iC3Q/CZCKRo4rqlmhDqlZwbyHm47ewkkZeciMoYNZlR/NgMs/NkR
         d2j3erkI9kK4E7MSRUA4y9wdWlNKiuUtRk0Nz81Nm3A4zvDeXzs/qa3pWRwcDlJWvVKg
         gnYqZ7OG9NWjbP8uGsyLIKAq4LBVrkg5wrhOlPZ7B5VEGi32ELUWkjmCK58xSGuAdWkp
         puE4D+Vv/Jkek8DJFiSuhrBQNDwB20ej+89CykzhK4NU4bx3pj0KxwZCHclFfQoQ44FK
         5vYJrcAw/0HZa0CVMOSb7s7QGVdiiwVJZb67Q1M+FT+IZFUC59JTjiJytcBJab2DkkE+
         EhzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530sEBieDrmVV+Jb1vKlifMw1h1NwnZ+GbR9fy0fScT9qiH7bHJt
	YezC/HjdTnNBPe1kJyH07Ks=
X-Google-Smtp-Source: ABdhPJyTZLnRZUlJE8iUy8UnvgyKVImeNo0+wnXXaQSZwCKhGAfAsuZy1FSmOOWOeX+7xN+zbqU1VQ==
X-Received: by 2002:a9d:370:: with SMTP id 103mr13875123otv.232.1615814432643;
        Mon, 15 Mar 2021 06:20:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4390:: with SMTP id u16ls4000840oiv.9.gmail; Mon, 15 Mar
 2021 06:20:32 -0700 (PDT)
X-Received: by 2002:a54:4196:: with SMTP id 22mr18237070oiy.30.1615814431528;
        Mon, 15 Mar 2021 06:20:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814431; cv=none;
        d=google.com; s=arc-20160816;
        b=z+rzRRJ1Tioyq0phGOZUDM/tXAZSkoKUEeaa+TRc1sOlJXRMpM3jPfDkQjMaieEtV9
         TRV9gcdh78sVEKKeU8+0GIgi2oXL+o19GyCKEq2ucOprlW0zO/gCmnaEb8fUNfElDzoR
         3Njx9WNlwYcbDecGiad3mQWfshYb2wbk2Mfe2wsMrroVJIL5XVGpy1RxeYpqzkS7Mawk
         M3sCCLvqYfKdrKtd3H6IXhLu0dxbWI925xD8riZLhC3nYvTxxKAWhEBi1448Qlb7q/P2
         JCkDv+PXtk/mwIFftCwleRvN2GG0KVp1AZjbq4x1uTA2GQcbbugHAbmZoBZb1cvxK46C
         hVmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=xQasdjR0iwoNuHHV01Ezti6UWXmzBcE46JdRRmOGf1o=;
        b=tB9gX2k7W4ZyrZVi5miryQc2QxrxwG8a9m+0+ahs3IGQxrfuNtjaBwDT5QJJPwiCSJ
         wkrHcwVq/Wt2jqHQYJoIsnWzbcaZIw1K+RyZil8ulez7ElFATapw8d0y+oE9ha3ZfTOu
         KBajB6mrLC2gkUOs95Dg6LkV08iXCIIWGxKhpfiPg3Fl4i6LkpP48gui/+pxMKqcPdz1
         wCz2lBl1Hd4DnvHic0vXmOmQeHbYRsUvwTaX1p4xfepBGYFRGZVCN5jsQIwfbll0VwkS
         Q8viOMoNg6z9EhAdtOrsRJ7pq7mfzDG5gV/16WVhnPnKI6wWoMo/9wpqcF+bC5hNcwIV
         Wphw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a4si250283oiw.5.2021.03.15.06.20.31
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 44263ED1;
	Mon, 15 Mar 2021 06:20:31 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 603BB3F792;
	Mon, 15 Mar 2021 06:20:29 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v16 1/9] arm64: mte: Add asynchronous mode support
Date: Mon, 15 Mar 2021 13:20:11 +0000
Message-Id: <20210315132019.33202-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
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

MTE provides an asynchronous mode for detecting tag exceptions. In
particular instead of triggering a fault the arm64 core updates a
register which is checked by the kernel after the asynchronous tag
check fault has occurred.

Add support for MTE asynchronous mode.

The exception handling mechanism will be added with a future patch.

Note: KASAN HW activates async mode via kasan.mode kernel parameter.
The default mode is set to synchronous.
The code that verifies the status of TFSR_EL1 will be added with a
future patch.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  4 +++-
 arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
 arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
 3 files changed, 24 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index d98a7bda0d0d..f6d1ae69ffb3 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -243,7 +243,9 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
+#define arch_enable_tagging_async()		mte_enable_kernel_async()
+#define arch_enable_tagging()			arch_enable_tagging_sync()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 570af3e99296..ddd4d17cf9a0 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -87,7 +87,8 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size,
 	}
 }
 
-void mte_enable_kernel(void);
+void mte_enable_kernel_sync(void);
+void mte_enable_kernel_async(void);
 void mte_init_tags(u64 max_tag);
 
 void mte_set_report_once(bool state);
@@ -115,7 +116,11 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size,
 {
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel_sync(void)
+{
+}
+
+static inline void mte_enable_kernel_async(void)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index b3c70a612c7a..fa755cf94e01 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -107,11 +107,23 @@ void mte_init_tags(u64 max_tag)
 	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
 }
 
-void mte_enable_kernel(void)
+static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 {
 	/* Enable MTE Sync Mode for EL1. */
-	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
 	isb();
+
+	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
+}
+
+void mte_enable_kernel_sync(void)
+{
+	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
+}
+
+void mte_enable_kernel_async(void)
+{
+	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
 }
 
 void mte_set_report_once(bool state)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-2-vincenzo.frascino%40arm.com.
