Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNXORT6QKGQE3TXGYGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BEDE2A7141
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:23 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id j22sf114862lfh.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532022; cv=pass;
        d=google.com; s=arc-20160816;
        b=DG4bGElFxJ6WZ09d61cgw2scOCYMToWOYzqPsynNnAAd5TfiBDtIf8yGiwvBQ/xQsw
         +HP54nn3GnDQueKeO1kTO3VFhHMD5Yv9o03ajGqDzn5iOAdyC5tQPa/W5aSy+fU5l/op
         fpKzk+ACtkjirm9qPrpPS0nyLUHGAHJbm0GGFo5HsRwdctuJvDGwkrkzxhkFogjBFsnK
         371lekvCSEaFAOorKZo/jIXi0X4T2tV2/3uROwjlNUjfTuuh+Pwvfyg9tK9FVmwHhhdD
         guzLxkX75DZ/LYMdb3kmdlk6WHnXFirxtdLm7GFNRIpChw9UpCo215NBpyLFhbhRfYo1
         gFSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4+UwcqADm9y+N4FKrvZPB87KkWr6LHAV5Z/roHZlVTE=;
        b=bHSCVt6mCHbyOREHng/avbhgvr2efGQ9Lqr5aH5yjw2sHiq/ljcAZoOqYS1gmcyUaQ
         oK6nRfmhvxLbUdZ0OKuOpt9Wms3LJpLU1NBErBoJdWNIkUCBIWP2gVPbM0bFe24F6fOt
         MfOrKYWs8KN++93zHpwnJDf1ivegaSY4HkSpNQAG3ozB5LMp3jKq3+owkaTZmkJmo7gM
         ic1DsW48mroaLcvlGm1/GAUnQzoLm/7a41BhROQyHpB7nErkp7Aen6cg49Z059npm1KB
         WjxQjoG9ugXtd+Iq/CjJcRIouoTv77YaRKglrmVkSK50ddlWmfdF2s3Xsp69sBu+1lgK
         5ZNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="q/Ff3ASA";
       spf=pass (google.com: domain of 3ntejxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3NTejXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4+UwcqADm9y+N4FKrvZPB87KkWr6LHAV5Z/roHZlVTE=;
        b=Y73hsyY3LI5dZ1su5Zdi9LFHRvH9KRIqWoDfeNzRhtJ5JHN2ox3YHJYp/flzhcggD5
         o7VYZFRGK5/CWk8RR4Fk79GC6H6kRXLUVHp5gEM5oFuNUDUCgCJcITP81nX9XYAx5Ufm
         UXe9dedxQNDyIkDutKbqjrIB+HvTrGkqnLpkYo3XKypNrlbNwCI4cD93p73F4y38p5rM
         t5NkDzC5j2DpfDUEkO9pkQR3J3lU8OyJ4k0BbLnNRSa0JXE2UQ9HsdvRVwfuyPDKtTb2
         92D7j4WqJ8rxz7vyDEnkILIzWHpprF50b+/0frGjTy6qURkcJQxqrfIabHEdrE/iUxOK
         1F7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4+UwcqADm9y+N4FKrvZPB87KkWr6LHAV5Z/roHZlVTE=;
        b=rjW2UKdbwiiAIvg7hIPNu1qeKwW343mq5F/lHhlwBPGZf8hbLjZ2PF/IWkrVicF668
         fyUSLcsWBHBWHfBLRYe2pEdH5m/G0905GyYqRtwbcl1bvLeBVoMw++qEoLLf/gHDncNS
         ihlgTgS7vz6NWfMyzOH9MfuSMKWQRHQ4jEGjHpvHx3elDLctvDJdRR6SjMtk8AMH5InF
         d2IMGhVCoS3Dt57bpJxy+/XO7ul7vXtzTWNUWbgbkPEoohdwhSvyzf6cJ0oqbaohLIWv
         g0MxvXQh1Z8QUZUcoNGTDWPKcO+s1iWIPehQp1bfgDb200HSOYf+o5TaxzOwiLLJkxif
         WRsQ==
X-Gm-Message-State: AOAM533pPTwLcoX5RV6uPQalW8SSlZ80OT4Jb6uZ2/8Uq4WjQKr/+Enp
	L2pPnon87tAi97MWyfZvTXA=
X-Google-Smtp-Source: ABdhPJy0a5Ox2oaF8woRmEmaIMdTekOCXleI+bzwfKsIH25YFAtZ81o2OmNDGLgXaLvUoy6wHgqvBA==
X-Received: by 2002:a19:24d4:: with SMTP id k203mr25562lfk.548.1604532022677;
        Wed, 04 Nov 2020 15:20:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls2256251lff.1.gmail; Wed, 04 Nov
 2020 15:20:21 -0800 (PST)
X-Received: by 2002:a19:6b1a:: with SMTP id d26mr28738lfa.162.1604532021755;
        Wed, 04 Nov 2020 15:20:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532021; cv=none;
        d=google.com; s=arc-20160816;
        b=SFMdPqTaghK4ydMN7OxaLSFJZFYIOlU1r4ArN7Fui5Eru4WeBzKmolbB0aFgSUf++Y
         ZO++/P69s8BRa7PpDRMH6Uf0ze8yg9a37qZTxf+47aWG5KezD66oLkmj2WmqVD4L0GtI
         ezyLbHBPTAU2u3sFWPyPq4RYEGIm55wXz44IIN0zErhMgieUG2joB+QJoa9OkjdZCgOb
         Sp1nw34VsZTuuCUlIphE0ZZsW22z01PX1ETM8hA1kqiwAvR7A4bbADIALGutI0z5W8oM
         mcWV18yJ85KH8heC/bn4vWKHrHkP+C2SijrCYZsvRVRIat2+qUFhseg2o3t0FIQVTjDG
         +BrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=sU5rZNeX083+m80V53yNOXDsSYa9T2iypaGHB0m7hOE=;
        b=DgMK83ktmBL6psBtITqrMdkSJj9flwVWss6Hel95Pz6szsb86LL5H0/Jd/9nBr1aTR
         JW4rvbi8uRr12aOrmRTOI4SS2LimKI/+XspTzhgnIq52zoST+5n+YDgWeJjx1vMckbY4
         PZqgZGbNx39jRGxSsqxYyjxBY9FCXopMgLwCcIaCXZYHw+zDDsMl6xLB+1lI+Z3AVDV9
         OysflvBYNtX9jnLFwP9RWSi1/RIF6dv2yOo9tUpD2sFK3tWCMsItH928bTCFqqVgMnWt
         DXS/hUrQivFaaj7aklLur+SsWe79wJ7Jw2GFVQgKOFLj9r5aZOBSdS3ZKRNrExfXwvib
         jgig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="q/Ff3ASA";
       spf=pass (google.com: domain of 3ntejxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3NTejXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id l28si126770lfp.11.2020.11.04.15.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ntejxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f11so39535wro.15
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:21 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2ec6:: with SMTP id
 u189mr57375wmu.85.1604532021347; Wed, 04 Nov 2020 15:20:21 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:46 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <b0ad51df00dc72fc3ae1c392e1e66a4ffdbb35f7.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 31/43] arm64: mte: Convert gcr_user into an exclude mask
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
 header.i=@google.com header.s=20161025 header.b="q/Ff3ASA";       spf=pass
 (google.com: domain of 3ntejxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3NTejXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

The gcr_user mask is a per thread mask that represents the tags that are
excluded from random generation when the Memory Tagging Extension is
present and an 'irg' instruction is invoked.

gcr_user affects the behavior on EL0 only.

Currently that mask is an include mask and it is controlled by the user
via prctl() while GCR_EL1 accepts an exclude mask.

Convert the include mask into an exclude one to make it easier the
register setting.

Note: This change will affect gcr_kernel (for EL1) introduced with a
future patch.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: Id15c0b47582fb51594bb26fb8353d78c7d0953c1
---
 arch/arm64/include/asm/processor.h |  2 +-
 arch/arm64/kernel/mte.c            | 29 +++++++++++++++--------------
 2 files changed, 16 insertions(+), 15 deletions(-)

diff --git a/arch/arm64/include/asm/processor.h b/arch/arm64/include/asm/processor.h
index fce8cbecd6bc..e8cfc41a92d4 100644
--- a/arch/arm64/include/asm/processor.h
+++ b/arch/arm64/include/asm/processor.h
@@ -154,7 +154,7 @@ struct thread_struct {
 #endif
 #ifdef CONFIG_ARM64_MTE
 	u64			sctlr_tcf0;
-	u64			gcr_user_incl;
+	u64			gcr_user_excl;
 #endif
 };
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index fcfbefcc3174..14b0c19a33e3 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -148,23 +148,22 @@ static void set_sctlr_el1_tcf0(u64 tcf0)
 	preempt_enable();
 }
 
-static void update_gcr_el1_excl(u64 incl)
+static void update_gcr_el1_excl(u64 excl)
 {
-	u64 excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
 
 	/*
-	 * Note that 'incl' is an include mask (controlled by the user via
-	 * prctl()) while GCR_EL1 accepts an exclude mask.
+	 * Note that the mask controlled by the user via prctl() is an
+	 * include while GCR_EL1 accepts an exclude mask.
 	 * No need for ISB since this only affects EL0 currently, implicit
 	 * with ERET.
 	 */
 	sysreg_clear_set_s(SYS_GCR_EL1, SYS_GCR_EL1_EXCL_MASK, excl);
 }
 
-static void set_gcr_el1_excl(u64 incl)
+static void set_gcr_el1_excl(u64 excl)
 {
-	current->thread.gcr_user_incl = incl;
-	update_gcr_el1_excl(incl);
+	current->thread.gcr_user_excl = excl;
+	update_gcr_el1_excl(excl);
 }
 
 void flush_mte_state(void)
@@ -179,7 +178,7 @@ void flush_mte_state(void)
 	/* disable tag checking */
 	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
 	/* reset tag generation mask */
-	set_gcr_el1_excl(0);
+	set_gcr_el1_excl(SYS_GCR_EL1_EXCL_MASK);
 }
 
 void mte_thread_switch(struct task_struct *next)
@@ -190,7 +189,7 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_incl);
+	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -198,13 +197,14 @@ void mte_suspend_exit(void)
 	if (!system_supports_mte())
 		return;
 
-	update_gcr_el1_excl(current->thread.gcr_user_incl);
+	update_gcr_el1_excl(current->thread.gcr_user_excl);
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
 {
 	u64 tcf0;
-	u64 gcr_incl = (arg & PR_MTE_TAG_MASK) >> PR_MTE_TAG_SHIFT;
+	u64 gcr_excl = ~((arg & PR_MTE_TAG_MASK) >> PR_MTE_TAG_SHIFT) &
+		       SYS_GCR_EL1_EXCL_MASK;
 
 	if (!system_supports_mte())
 		return 0;
@@ -225,10 +225,10 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
 
 	if (task != current) {
 		task->thread.sctlr_tcf0 = tcf0;
-		task->thread.gcr_user_incl = gcr_incl;
+		task->thread.gcr_user_excl = gcr_excl;
 	} else {
 		set_sctlr_el1_tcf0(tcf0);
-		set_gcr_el1_excl(gcr_incl);
+		set_gcr_el1_excl(gcr_excl);
 	}
 
 	return 0;
@@ -237,11 +237,12 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
 long get_mte_ctrl(struct task_struct *task)
 {
 	unsigned long ret;
+	u64 incl = ~task->thread.gcr_user_excl & SYS_GCR_EL1_EXCL_MASK;
 
 	if (!system_supports_mte())
 		return 0;
 
-	ret = task->thread.gcr_user_incl << PR_MTE_TAG_SHIFT;
+	ret = incl << PR_MTE_TAG_SHIFT;
 
 	switch (task->thread.sctlr_tcf0) {
 	case SCTLR_EL1_TCF0_NONE:
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b0ad51df00dc72fc3ae1c392e1e66a4ffdbb35f7.1604531793.git.andreyknvl%40google.com.
