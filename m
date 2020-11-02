Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGW4QD6QKGQE2RVAWDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id B479A2A2EFB
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:43 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id 144sf2926619pfv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333082; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwjIU3TprIgN+hG985veVTHL7AyC3S4jAq9+Xo/eDAcGRWahqk6qM5UOm2np6W1vX2
         TOEvYf1nCIvteZEXroKAONjMPdhZS4o+oyKtv5LkMdTGqM3Tf+Xn4TiFJ4Q39qTgBoGL
         8SSNrs4NnpVJ9rmQeJhcyNRFVaIosCxzNdKk8kXZ5jDYwKBA1B1FWzWQgLUKpsQwh0JK
         6jYg03wgnGwQDT+XCqYoKfP+0cBP1l+42vkO5azW5LtHltYfQkgGhM9PFBYV5L8eZymM
         Yj3ANMwph5NvzbON/IfDa3H0JLvP5NePHzNbit7bL3Tu9lMa2nd5X/8lJY4MsYobF4Mv
         qA+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=TxzXo5U2w+Q+vpTk5C8/Un7wJTZMbdUY7vugxB3J6+w=;
        b=fCBVOWpkGEOjsFhGD+zxXFqtZvr1JOP+0iyP24a9lILwAdp2rhp51PKRMjbJePiK+E
         +ek6fjBbRvdcB84RnMg4hoDUgl84gei+5oQzqATrUx4Gf1OOv7CZ5Mk8ly+FEmQ4Lms0
         tVvLdavzO0UfyDA8/kSMzkd7tmvC2wDmHiI0PTm60jpTTwyZWb47KIfUP4nRZen8p2lB
         3RBbavc9b44UJYApULY3B3kLZa2CT7qiUiQZYKk6s/e8NxCL/Y8oaQXl8FWLg+4NW0IT
         6dB733jt5BnY7LrOVmSuLtudG2kpWJ1sWb6iTVPEjMp+/o2YXaZCDtQvfah7EZf3REyz
         FWHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="M1egA/6R";
       spf=pass (google.com: domain of 3gs6gxwokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GS6gXwoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TxzXo5U2w+Q+vpTk5C8/Un7wJTZMbdUY7vugxB3J6+w=;
        b=A88XRIldwfVFQUWeUtveSUzFv5eodu32nEHtje8dmIRtXLClwqpTIJVdTkATG9Ut9L
         XCr8641VccFdKT5FGokbL1NXaxv8sgsZ+CoacC/VrkQXnp1gfBpjnm/w1bMyuDaczHC7
         OfNZZB6CLXfkUBQ+bx77fKNc5+MfhRI9S2qMWwMwvNh3WjDtewU62stvY4MKqkbH5VxT
         GF4+k7LUE+v457akqgzUHOlVH1a5xg62o0YyWqxh7C/QkI5lUPfQn1D5viYCbbDrl0Ml
         /099DtLNReLIWqVNGVSvKVfJGdidpTGlS6TXQA7h5IFSLRzafP4uzYrXkB/uy1GJCB+X
         d0eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TxzXo5U2w+Q+vpTk5C8/Un7wJTZMbdUY7vugxB3J6+w=;
        b=sY7qTDVIiNF7zqRxaCXZgiQ6OTpDWs5PEil8T/FRYvxXts/NwgwUIDg9MPX9K9j21B
         VZpW9EDQeFs+im9JhQpuExBMITLvoG22ArzvTkr55nXYpCFUy7HOsWWlEfX8IcPIdlQN
         we/WbIRg3vQA/SPPo/YrjAkaPrIw+q7pAT1SLTB+QJVHX7yl4j5Pp74tLY2WPJ+qGW19
         Gjh61BsgRmbqfI09V2+ytxVcZ/RY7l4vAD9EpyuIXWdI2psO2Gn2KFwk5z4bCWv4PUzg
         LzLlMAVLxvS/+be0Od14iDRA/MLb6JLECyypyrMJX/eaIWXKufepTV3rrGhf8LjcceGn
         OHOg==
X-Gm-Message-State: AOAM531ea0vWuAA7GYQDjA7K82G9tRPkxuXUvI4vqYShMKLqO87YPDw5
	3U+p3nO9Fo0OiWiYJCGy114=
X-Google-Smtp-Source: ABdhPJyfHzosEJACDtAJ+QnjsURE3jwKgpIKuRCYMORqBkUK1HpHcr4NZqWCMI88jfyLLyn+2gLw/w==
X-Received: by 2002:a17:902:9890:b029:d5:e447:6b32 with SMTP id s16-20020a1709029890b02900d5e4476b32mr21340968plp.51.1604333082473;
        Mon, 02 Nov 2020 08:04:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a107:: with SMTP id s7ls6674119pjp.1.canary-gmail;
 Mon, 02 Nov 2020 08:04:42 -0800 (PST)
X-Received: by 2002:a17:90a:c7c4:: with SMTP id gf4mr13018235pjb.18.1604333081935;
        Mon, 02 Nov 2020 08:04:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333081; cv=none;
        d=google.com; s=arc-20160816;
        b=ynJzCfUxwLAE2Ricof/GLlesjz85vikzjYMxi24sbOMm6ogS3dHP3RMAMZ3DC7bx9x
         Y87gfCsTyHmSXNV07EOG7za88MCs7e7ouhWNIyakGwOTxCNmIe48X4unVNPtulueowIt
         TYV84ezOMBIxGS1ICJO10hFEGNxIHWCEpbLEDcObXnzWA1Dtc9iSvfioAoGNBePXepVm
         0xoTKzVo7m4i+bpuJh/hkd/4mYMONfP4djl6UpTN5YE25FRxAlgWfi00LgumjC1pbabA
         2JgUJFST+3yLs9PTZoH5/EequdGAGL5Rsiy0JhD3mlZWi7FRC3mQDtoq8WU8nRrLiiFc
         uxng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VsN8c2WI1TMox3v/PYtKI3bTw78pIVnf1hcHZhXvdoM=;
        b=UT+ErzeIl8+p9OJC58qkb9+frL8gs7YfQCYgaDpSvqJDkZCTTixFyJScWhpIXFTO+V
         1T2JLbtZGTklc1hK1ozEm+aZMsvBFsHk5i+h68SFeSQWt2zs0o5L2EGnkFgyC+fP8u97
         OAyfwdv7j1utti1XEF8nOclKyQYFzyIkI8dntSr2cqxe5IZDNYT7qL3mrqgm134GqWmN
         +6icLq4yAlDoBVi5U0jSzyykunYlP2PJaO3TYRg5xt2f9HLwmvP3PHXnK4RlNqX0ijLF
         Dvnv0Xzwq9xR6UhyM7swZNIBsAQZWw02og+Dgvb2cbwIclQLX1N98FQdyuWaDfWtd/xW
         rhIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="M1egA/6R";
       spf=pass (google.com: domain of 3gs6gxwokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GS6gXwoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id d2si1089533pfr.4.2020.11.02.08.04.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gs6gxwokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id es11so8449509qvb.10
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:41 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:baa2:: with SMTP id
 x34mr22633076qvf.23.1604333081018; Mon, 02 Nov 2020 08:04:41 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:46 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <29259e315987b3cff3c6bf2ebac9cc089b7413a0.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 06/41] arm64: kasan: Enable in-kernel MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="M1egA/6R";       spf=pass
 (google.com: domain of 3gs6gxwokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GS6gXwoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
feature and requires it to be enabled.

The Tag Checking operation causes a synchronous data abort as
a consequence of a tag check fault when MTE is configured in
synchronous mode.

Enable MTE in Synchronous mode in EL1 to provide a more immediate
way of tag check failure detection in the kernel.

As part of this change enable match-all tag for EL1 to allow the
kernel to access user pages without faulting. This is required because
the kernel does not have knowledge of the tags set by the user in a
page.

Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
similar way as TCF0 affects EL0.
MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
enable it as part of this patch as well.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
---
 arch/arm64/kernel/cpufeature.c |  7 +++++++
 arch/arm64/mm/proc.S           | 23 ++++++++++++++++++++---
 2 files changed, 27 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index dcc165b3fc04..c61f201042b2 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1704,6 +1704,13 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 		cleared_zero_page = true;
 		mte_clear_page_tags(lm_alias(empty_zero_page));
 	}
+
+	/* Enable in-kernel MTE only if KASAN_HW_TAGS is enabled */
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {
+		/* Enable MTE Sync Mode for EL1 */
+		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+		isb();
+	}
 }
 #endif /* CONFIG_ARM64_MTE */
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29259e315987b3cff3c6bf2ebac9cc089b7413a0.1604333009.git.andreyknvl%40google.com.
