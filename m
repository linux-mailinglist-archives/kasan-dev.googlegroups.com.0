Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHG4QD6QKGQE3WIIXWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7223F2A2EFC
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:45 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id c204sf3504167wmd.5
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333084; cv=pass;
        d=google.com; s=arc-20160816;
        b=aBZAw8Q8xWTZJbPYL7bhNPt8zd+bColj3QsWBmKqiCdk+Tn9TefMMkIoQAe9toftLa
         Qi0sdG12JESZuTEXarY7BaOW3xrt6TbZkxXgThJ3EChBnj6n+bPiFnn1avF2Gy6xWmlN
         RvsHodcSF8ClLSaW+2ec5Hyg5nYkU3yMIi+5RqGXZ1glbhcVA4IYzEReYgSpzSAGjD+m
         zq3tmqM+MxT5h7FwVo3WqLG/CwvbyIiY4aTEZP52BZDHqE5nEWBTioEjNsb0gxszZoJt
         ntnLOva9/DAbLQuOaz/Y5AwmhCUBKDmhfAp20tEVNsDBECdFTvS0nXoBplmY4XJr/IZY
         gSiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=g+t3/nhaYqKgN2wB0zVxHt7VqQtF6kNGu0DMhihRwCg=;
        b=G75yZmP5iyrbwNnNAydx4Oqv80fUcHLAvBXhMy1U43A2craurMe+vuNBwUazeB/4Uf
         7Xv0UFVL+pAHHULRZZEiT3Mtl5d27Pf+aXHUF7mnz2M4jqwfQXKNibgR9hasbB8z8lhg
         kfTM4D/sAt1O9Z8hjIe89SuxUjlh7YxNYp9PHB7lW1Ye2hOfo3X0dMkkgV88A7HnnDNk
         0gybwfgjSNU6iOdNJ5yjLNULgFIlcZQOrRB4p5ArRHIZEg7SPmuO/7wsOjhD2VJUfpkU
         XDCnzbXeSqWTDhEsTYukieWLOmj/Vrsh4FvhI2WG+d6Xo1eG8Mco8CIdVJFmVNfzFmHy
         afPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nzqwEq4v;
       spf=pass (google.com: domain of 3gy6gxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Gy6gXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g+t3/nhaYqKgN2wB0zVxHt7VqQtF6kNGu0DMhihRwCg=;
        b=SjuPhGohsIb+/6pGFRJQlDFVqLxMAPGQJgE71Dz7RJpuNhoKJCZDWbONuer3LKDxKt
         7F6X53SWVv4WK5t81zBbjObKO6BtWqFCQB9t/njO0+NztPttJ0yC4S1FnXTe8PzslNXs
         h0b58mmZw3+MQazMrAotBe8p//pLV46ahSUEjHwuGH9+HGRIYn2W10uTB/NLqTfWSZR2
         ylFEHRqVZtH4t1BTimEteIMM2xixCFB6AF7rtg4ND29MQKSwWEw+75CaPOCjWQlr0PSH
         vDe1Vz9S6ngrb/4xD9YyJCbclYlUo3Y/i4bt1KQsxQdI85zc9ytattcUIiITj/K+m387
         NEqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g+t3/nhaYqKgN2wB0zVxHt7VqQtF6kNGu0DMhihRwCg=;
        b=K50mn+JtMN7DqI65aQhNSt/f3kgTKpG37Th9dSsJ1pQ2Ubub44TMocD9LanyGhfV2j
         d8T70qdLBn4oBbFFQK1fVpa/TuDQgXuniDV4cxZ0ZLAG3nj59FZwUmgqH5rDY7N8T4k1
         J4ur+ieKXRcvMXpHUcm34Zvit6276+SZU8XDK86Fzuj7iXF78e6hS633ZvHCRshTdL2G
         UylpnQbwBtD0nMotg7OSVOXoi8zlRFtr7Ih93PP5dttDTA/ArDBQ15nFvc3aJocH2N4U
         bNSdX0WutSTCeUOgf7TouhVoZrC6kU4xfXZEVCxOm+4N4qUq5G8HlHVLsy8OIZv+h6kb
         GRig==
X-Gm-Message-State: AOAM533tSY8OvmO4Z55ncQgelMCt4JgrLiVGGnuhYojdNeTxC6skFI7y
	nYHUHDS/K1hg6Zx8kYqtl48=
X-Google-Smtp-Source: ABdhPJxAV7FS1jZdtyX+XuZOFGbBzXxcasaAGuEEh6TI3/UzLMBhzPYhuot9wjtIul1RPKE4YNjWNg==
X-Received: by 2002:a5d:6110:: with SMTP id v16mr22717467wrt.219.1604333084719;
        Mon, 02 Nov 2020 08:04:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:cd8c:: with SMTP id q12ls8865119wrj.0.gmail; Mon, 02 Nov
 2020 08:04:43 -0800 (PST)
X-Received: by 2002:adf:8484:: with SMTP id 4mr21556123wrg.334.1604333083858;
        Mon, 02 Nov 2020 08:04:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333083; cv=none;
        d=google.com; s=arc-20160816;
        b=QcaFgHmsxL58msukHzUPFcbl4ZerKRwI6rEQ3JMEm5mfmCX2NCP3+S/JxS1+FjHKIt
         oohg2w4eGp1QcDqx6L9zF2iULcFXR7PfekInYSziOWvfMVivjqDkoTO61Tc+IHCILPqI
         Yc8m4Kahnih3ppAyLPGFvlpDMyNwPgTXO1zcpGvps9nUy2/afWEt39/y4DtZvxwpLoOV
         dd2iJ6kChzDbfB4zod3IumdkIoPJz0dzNIZ9ybFYFxQ+SX0NvmEk5Yzmmd+Bu1ONGtYu
         xo2k3bUaQL96iyjPwZMIa2OYP97Fk4uRPDjZu9PhJw7NMk20HfyxCrGGEnuJvaWp2GCY
         hQsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LscJFjoJLVax370bbjjUkdBy9lfnLd5L4hR3aqcqMxs=;
        b=ahDAhJAxPesuGWj9ZCqAYsHSr78Ato2lvUJTgfGDRyAgd3l3s/emL9WHJp8X1NeLxd
         x1xzzAePS2rT+qXYnw3Wy9jYM5pyVx17uND7o11FTv+r/zafE9z1rlfJxhXB6w5c9+n/
         X7mThak07e8d85sqpFboZg8YxRWuewtEwUbi3m4VYFfd5Q5r4MpyQc5khkGh5qAMmDgk
         SFrb90CGmGKZ0WkQEnkI9SlHdWhWOiosbHOvk5vUDUUuT060aUh6ENwktsSIyVzUo8YS
         Ekeg1j8+3jy7JaKgZHiDXzTUPT6XM7Vs8328GgpF3v/d4G3zeKI6tYYVHVuubLq3Z28i
         /56A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nzqwEq4v;
       spf=pass (google.com: domain of 3gy6gxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Gy6gXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f131si294687wme.1.2020.11.02.08.04.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gy6gxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id q15so6596414wrw.8
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:43 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e345:: with SMTP id
 a66mr16954306wmh.188.1604333083509; Mon, 02 Nov 2020 08:04:43 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:47 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <b7b3e826a7969fc9de79fef466dd9307950a9521.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 07/41] arm64: mte: Convert gcr_user into an exclude mask
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
 header.i=@google.com header.s=20161025 header.b=nzqwEq4v;       spf=pass
 (google.com: domain of 3gy6gxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Gy6gXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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
index 06ba6c923ab7..a9f03be75cef 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -141,23 +141,22 @@ static void set_sctlr_el1_tcf0(u64 tcf0)
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
@@ -172,7 +171,7 @@ void flush_mte_state(void)
 	/* disable tag checking */
 	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
 	/* reset tag generation mask */
-	set_gcr_el1_excl(0);
+	set_gcr_el1_excl(SYS_GCR_EL1_EXCL_MASK);
 }
 
 void mte_thread_switch(struct task_struct *next)
@@ -183,7 +182,7 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_incl);
+	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -191,13 +190,14 @@ void mte_suspend_exit(void)
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
@@ -218,10 +218,10 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
 
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
@@ -230,11 +230,12 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b7b3e826a7969fc9de79fef466dd9307950a9521.1604333009.git.andreyknvl%40google.com.
