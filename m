Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNHORT6QKGQEKIU2DBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id ACC8F2A713F
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:20 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 205sf100083lfb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532020; cv=pass;
        d=google.com; s=arc-20160816;
        b=LfK05zWe3m3ZUb7enLPtp159iIRXvyj/RV7iPF8occ0Fo/VEiK5PFr4TgaLZNCwrYF
         7KE96iznalZF0Uz5lDAgnRRKaJfMDHtugNAhQlpLSdVcT6/6I742fQWvH/AbhjWA0vfD
         apm7abVVeXGz/57D+7CsyGEU0Lj0N9amwp/yIFQ1rorPRELL3km8JCqgbgOmBoowGlef
         qGmJEmUHOEmotEZ28cnxEpZxz/Y6cO0BxGZUsKCExaVLIppXV/XIYGJ50kflUUUXbsXq
         +xU93bYGxgDw3v6zMHfZLOAdOkZfJ7monpsWorTqSYchzgb85HyD9BFxrAXEj0hIwQDN
         xdHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6b4yF0BFIFu9dizWP78qkREbqs2iwuCp2kuUZK/Y+OI=;
        b=Kzyv8CfyMBEoKpu3CBS/fwcrG+lEcd+dMx9rUgfnQTdsEw1Kq/uILXTxwejVhA7eAZ
         VeLn13Ssc0pAn/iHaGZIQr+7jYl3QlisviooSOocBoZhaf3yu/xNKyJX0KPkexhtu/O9
         jGBpiUGUfvJKTMVM8edRfDEfzzSW7wr4vQRP/nWsJJFM9iUGbbq+vFNL/9hu1KST03zp
         Zeh135dxmQ2rkIdy5TB1OPb2VquUT2wSPzIrLyRXBx4lq9cljqW7bhAsF5ULGCvRUsRZ
         gGuNtqBGddEO63kw1kZwQC1AmCAo71ogZyd/5deptBz/spXgMk2Xgi+/iuPeRS0cy3ft
         0pEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RkNt0KlM;
       spf=pass (google.com: domain of 3mjejxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3MjejXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6b4yF0BFIFu9dizWP78qkREbqs2iwuCp2kuUZK/Y+OI=;
        b=fxRUy/QFpz34xMR/lWHuy+5HKOupDdRKveMBfnzrhbWoaYJ9kC9/TRXRwk57CkmGYy
         tmqrUAwisHlvYailHk7iPv3h/qEYUzib0hQLnxWSRUf9yAXL24oWP5ssMXv8zsfbJnTM
         K9sDiouc5TX9FyCuVplJddEwGGl/NH7n2uTzetOUOKC3H0vSNQkJTgLqkIbOU/BG2SzX
         U5VRGzkUlFS+h5FI2sYajRiK6zX8UXRF7G+pyAn6v1qPzE8xYnMymxZ2tm6AOdrQqEy4
         E/dsNcZZeYwdrWsynCWpJMjTri/E5Mvm9xLK7Zwxh8ERsCOOk8+NJhMASGdOuMJNLJYz
         kuig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6b4yF0BFIFu9dizWP78qkREbqs2iwuCp2kuUZK/Y+OI=;
        b=hTOL3T51C1Fgg1bBQiGiooWS+oY319uMvwPfALlkNdcBxAZbZTsLGmGXGvveDJ8X6T
         o/8JK9ECN9AzVpxRdb+4KNtVSD/XJEFSkqe1qJqKBtbXegLVKl8DNmtnTUcsrorxqmQr
         5Ll8ZzHWcbGG5WXxeoEuiDH7nAT7tOKeIlXZAJEUeUry6EJfKw8JSYn58317ftXDSJMy
         Dlh/7c/lBEg/jQNZ2hZD2SrEWz9LHJE3OOhVnERTiEmj73BUNU/jPOcl8g8LTOQgEcG2
         mZNwewnfOon5tmyrXKhxIjAzbMADBilMvZkMJUSzmeCc+BsEQCzDTgteNxjajSqUstkN
         i77Q==
X-Gm-Message-State: AOAM532xiJzGocKb7yGbt6shu3adecYQTKb0JrqK70oQXSCXYxSjNXWZ
	j7R5A08b8Len3bc+b48n//k=
X-Google-Smtp-Source: ABdhPJyVgsaTZr0sKYUQ+BVi66vh5Y2wl3p1KAAZWwyvvHpat5HXb7XoxrCFiGrlIIWIOLMwi+gKMg==
X-Received: by 2002:a05:651c:238:: with SMTP id z24mr121098ljn.408.1604532020284;
        Wed, 04 Nov 2020 15:20:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls644961lfa.2.gmail; Wed, 04 Nov
 2020 15:20:19 -0800 (PST)
X-Received: by 2002:a05:6512:210f:: with SMTP id q15mr30462lfr.78.1604532019407;
        Wed, 04 Nov 2020 15:20:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532019; cv=none;
        d=google.com; s=arc-20160816;
        b=mcyhiozEs1AX06On9PV5KW4vZNDyZPRiWU7fXSEgJIVybqzcQ+MatyNSP7PO328LUO
         NrCuSF1Rdp7yU6mHUIx9gXmcE9+Qkbo3YyQ91uPOH/Cz+B8ViwnQAihXNyyOLmIi14ZW
         gv4CrwgEpVvZyNxVIoK3UTWP8eey1yL0l3RS+ZenJMVRzLyhpugZ4pBHdTnni1XkcDRV
         M9SXZiFRHXrhAugpcE7X1RbEZADenzTFx7UJ4yKmHRVmcPdp1rRgGxwGsuccZ7oXWO9Y
         Yg0R20cvecsqKHYOMqHcK+K1tcl00pS8HyjkMy0CQAN2n5OmhiXBDUlfE3ghvzk3uWm8
         fZsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MtscXzxM87FBM4U9jZNGOq87ComGejjIMcvAPHhplUo=;
        b=WLfkQRnPJ1OrWruyN++nhS8c6s2WaREWxZ/qF6iGIq0LoyieVzSxprCF/4gcRvqe9H
         ETazLHwXCF/1KzuqpuIAi7DxyMW112eBJ+11JP4fa8UcFZ3Bq06rKr00Molt5w1B54EH
         yFs9mI01Jb+M3buid5P286iiw9FOr0dhFukBq7pO2tDruQY3J9DxlUO81+TuON/9wu8Z
         EE+2kbXsQAPHUQrbFhTcuTgH/wotgen0qMGlcUjF7eXsH4HwJ2ezFSABDdplTQxWlGFX
         Gt1YomFI9aTNMN85tkHv9DPq2UqE+/DHbr4ZH0ZdC9a80CHAJLb/JBIEPoqvsVFQLmDB
         qo1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RkNt0KlM;
       spf=pass (google.com: domain of 3mjejxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3MjejXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id l28si126770lfp.11.2020.11.04.15.20.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mjejxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f11so39535wro.15
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:19 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2803:: with SMTP id
 o3mr59728wmo.97.1604532018890; Wed, 04 Nov 2020 15:20:18 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:45 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RkNt0KlM;       spf=pass
 (google.com: domain of 3mjejxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3MjejXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
feature and requires it to be enabled. MTE supports

This patch adds a new mte_init_tags() helper, that enables MTE in
Synchronous mode in EL1 and is intended to be called from KASAN runtime
during initialization.

The Tag Checking operation causes a synchronous data abort as
a consequence of a tag check fault when MTE is configured in
synchronous mode.

As part of this change enable match-all tag for EL1 to allow the
kernel to access user pages without faulting. This is required because
the kernel does not have knowledge of the tags set by the user in a
page.

Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
similar way as TCF0 affects EL0.

MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
enable it as part of this patch as well.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
---
 arch/arm64/include/asm/mte-kasan.h |  6 ++++++
 arch/arm64/kernel/mte.c            |  7 +++++++
 arch/arm64/mm/proc.S               | 23 ++++++++++++++++++++---
 3 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3a70fb1807fd..ae75feaea2d4 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
+void __init mte_init_tags(u64 max_tag);
+
 #else /* CONFIG_ARM64_MTE */
 
 static inline u8 mte_get_ptr_tag(void *ptr)
@@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
+static inline void mte_init_tags(u64 max_tag)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 06ba6c923ab7..fcfbefcc3174 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -121,6 +121,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return ptr;
 }
 
+void __init mte_init_tags(u64 max_tag)
+{
+	/* Enable MTE Sync Mode for EL1. */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	isb();
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 23c326a06b2d..7c3304fb15d9 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -40,9 +40,15 @@
 #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
 
 #ifdef CONFIG_KASAN_SW_TAGS
-#define TCR_KASAN_FLAGS TCR_TBI1
+#define TCR_KASAN_SW_FLAGS TCR_TBI1
 #else
-#define TCR_KASAN_FLAGS 0
+#define TCR_KASAN_SW_FLAGS 0
+#endif
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1 | TCR_TBI1
+#else
+#define TCR_KASAN_HW_FLAGS 0
 #endif
 
 /*
@@ -427,6 +433,10 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x5, MAIR_EL1_SET
 #ifdef CONFIG_ARM64_MTE
+	mte_tcr	.req	x20
+
+	mov	mte_tcr, #0
+
 	/*
 	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
 	 * (ID_AA64PFR1_EL1[11:8] > 1).
@@ -447,6 +457,9 @@ SYM_FUNC_START(__cpu_setup)
 	/* clear any pending tag check faults in TFSR*_EL1 */
 	msr_s	SYS_TFSR_EL1, xzr
 	msr_s	SYS_TFSRE0_EL1, xzr
+
+	/* set the TCR_EL1 bits */
+	mov_q	mte_tcr, TCR_KASAN_HW_FLAGS
 1:
 #endif
 	msr	mair_el1, x5
@@ -456,7 +469,11 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
 			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
-			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
+			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
+#ifdef CONFIG_ARM64_MTE
+	orr	x10, x10, mte_tcr
+	.unreq	mte_tcr
+#endif
 	tcr_clear_errata_bits x10, x9, x5
 
 #ifdef CONFIG_ARM64_VA_BITS_52
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl%40google.com.
