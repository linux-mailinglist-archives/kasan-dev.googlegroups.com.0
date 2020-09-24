Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEOGWT5QKGQEXQ4JUEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id CF150277BED
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:02 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id ic18sf385764pjb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987921; cv=pass;
        d=google.com; s=arc-20160816;
        b=zsxz34wNzqzvYJB0pkR2v93QeKkxJ/sP78jvkdxaBJ91ypNwt1i/3YX+r5ag9rOptu
         H4TjKZ2772PC+4x81qXGkAsbsuH+ZHvIrSZsly1YawhxTJGkI9i/UgwyEMx3e6EUmTO5
         +/NrcO8EoZ3s4Lbg9hSW2Zk0yggK3dCqlafKsZ5u57WDhi5BEpBTYHmgRvs7HL0ykRvn
         YkKseRahCZAnfDSFVxdVtGcY/maiMrZ2GoQ92TGd/yhaxUnr8TQIcLKtchUjSEb7ibXw
         3ncn1nw1gNj2eIQxOs93+Lqtb6rfWpbEUX2Fa1wf4r2y3IfzWkvKSKj+MIz6LUtqeLCK
         t/0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=AZbu0/6xVnUQ9OR8P9DmcqpKLFZo10GoD0dLv2OZFrc=;
        b=fxUgPr09FcljzuHejEMORmU50RYrVBiD9Vi417THKMYVs2Z7T74zvADXeiRA5DhdIm
         aryLr0GcKvXqZK990UU8K6OGcMABsMaC9xrpy19RzMMwJLW6h/y51Ezl8iHV4GWD5Lj+
         8lLf4Z74GEr9XuoNfYrPaw7pE0B9On2o035e9mcY9d+Aia8a+k/z+jx3AJaVWwP3KgzP
         LnVoLBwgQP0gMT/RXS6xqA+3m+vOUEEhda2GTMoTLxBY88z2RaNdPEo3IiQ3LQZWnL4k
         Y/ehoaOpih/bjq/W26k2HQWwE0YEHc8650tudT6YfPeLoFxgqwEIssTIYal/d4PTa2kH
         OrSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z8L7kQ44;
       spf=pass (google.com: domain of 3ecntxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ECNtXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AZbu0/6xVnUQ9OR8P9DmcqpKLFZo10GoD0dLv2OZFrc=;
        b=Nj3Nquftr/bko8ckU6OWSByvdnNRys5vst3IPs59/aGuDq4SGifkDGdsjSlU4LWt8T
         43BGqS/ZkCkBy7nai52lDV+St2jEtxNrL5ybgeGWJE5v76Bt1Y9UcC7H/Bq5SkTJSpfc
         zeD049Yyf2lRo6VuCWZuIfj14n4mamCsKjOM1zzgfeTgyalKzVxuDhrUlwFdITqteFtG
         odJIiurIr9TmbVZeTrDN2EnNlaaf80DqZsLw6OjHYCu2HIU7N0bTwRSmfC6fbxZBMzEo
         hvpERxqyDx0XSXdAgX2HZDZxeRKNEcW3cTDtwBEhjiBcyKahIbi/CJ1m0u4GMpB/ReUt
         gmMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AZbu0/6xVnUQ9OR8P9DmcqpKLFZo10GoD0dLv2OZFrc=;
        b=EsCNtcU8kfFVRzd9NPvN7bQT8iWOS//FLzeidZA2URn/N3yV0Z9rnDGrpPjfaRryUI
         lah/q3vlV8kx3JivxivPF/VNijqq5siGhx6bCu0c3JXl74epQw7UBflZVsNwPuHlQWYX
         Klikqfu1NjW6mi61Y6oy4JQq29yvbMjYziT5dnZAmhL08509QdYacPoGXg+eQDvoqBlw
         2pTVdRX7TWYS8L4xB+FFZuAyK0qr+hlHiyaT+npwsA+DKalrNtSnUhHw9gQa6bQHS+f0
         tjfRTEMMWEooIEylKVndftGA51/PSe2saJMcSAARIttcUDDbusdujhjbvXZetVMS5TWu
         hCfw==
X-Gm-Message-State: AOAM530v9OsgTCnahJrfrJEbc4aCDOj+0rwR0iJ0xZj507xMIldgEQpg
	yTKw1zRxQ0LHtHliots06eo=
X-Google-Smtp-Source: ABdhPJzt0w8Esl8kbrTPUMmiySrCVGcTfibz1hGwYO6Fo4PVLaLa1gWJPnu0bu5iHqw2ye4iekIVvg==
X-Received: by 2002:a17:90a:ca82:: with SMTP id y2mr1011146pjt.233.1600987921520;
        Thu, 24 Sep 2020 15:52:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ead1:: with SMTP id p17ls405595pld.2.gmail; Thu, 24
 Sep 2020 15:52:01 -0700 (PDT)
X-Received: by 2002:a17:902:b686:b029:d1:e5e7:be0e with SMTP id c6-20020a170902b686b02900d1e5e7be0emr1357753pls.65.1600987920951;
        Thu, 24 Sep 2020 15:52:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987920; cv=none;
        d=google.com; s=arc-20160816;
        b=CmErb3vn3DxphCFZd1JWU6bi9+TWp/+GvqIrBv/RRhkrr5ifav7xdDQE2ci+UnohMB
         lsXjpwxjtoUQv23r1FREOlkaIO0u3DmH3JuO7pxMv6KmE09wvoXwx+++9C51oa6DCJD2
         CTqisMezZuh0V5XxKEE6NooMynWnhbMiYqi+xYKmG0aGLIpjcnIP3i94U1/PXULekYj7
         jquKkb55iTv5pFyAg8Qj+cyhJ33Ef9cyx0HvnNEoOJvH29MhJ786gl5Qp97m+G0wT47U
         w26RkFgFeGHFHhHvUC1yQ2pJPPsIgEJBYjzYPD2wwp/9UFKYp2Y5kmO/bF2BFOHS+OI7
         vmMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=2ZNxfm3ay5zbZVAoyeFT7OvnOs6QmAy2d7QmbFd4VOE=;
        b=VHGL9oiNRU33fekCjmgzROqGObidUwCS9bU4fB4f9i5rdWDj7jGm84Adur5H7YEWKJ
         lKUHWujRru+Dh4DIZQroYMvvL18xNnZ5Ft+UYHX/dlOqVA9kBqRbCt0JQRBmdpWgAL8e
         D3LtzMmqR07s3CNqQZ+QSGK6WTAOoZR17qa3Tef2O7nBxYeDR4EZ3uBGsgMgkJXk/pLB
         WwdAYwK0KlvNkT0mV9MQUapw+eaWWbnMkXpHlRi3RUzYxy+XHnRTO4NQHHrf52vJMKT7
         C5kYiXgqT9C5F8rSwzaXXp9Lxxmz4n/KYvXvnWz2ImfBaQbatHcO8kTc2mtZWMkHh+zr
         fgSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z8L7kQ44;
       spf=pass (google.com: domain of 3ecntxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ECNtXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id t16si82609pgu.1.2020.09.24.15.52.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ecntxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id 99so505136qva.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:00 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:58aa:: with SMTP id
 ea10mr1648526qvb.58.1600987920066; Thu, 24 Sep 2020 15:52:00 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:35 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <27e272bfd203cc0ff32181f07db588363ef3776b.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 28/39] arm64: mte: Convert gcr_user into an exclude mask
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Z8L7kQ44;       spf=pass
 (google.com: domain of 3ecntxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ECNtXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
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
index fec204d28fce..ed9efa5be8eb 100644
--- a/arch/arm64/include/asm/processor.h
+++ b/arch/arm64/include/asm/processor.h
@@ -153,7 +153,7 @@ struct thread_struct {
 #endif
 #ifdef CONFIG_ARM64_MTE
 	u64			sctlr_tcf0;
-	u64			gcr_user_incl;
+	u64			gcr_user_excl;
 #endif
 };
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 833b63fdd5e2..393d0c794be4 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -136,23 +136,22 @@ static void set_sctlr_el1_tcf0(u64 tcf0)
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
@@ -167,7 +166,7 @@ void flush_mte_state(void)
 	/* disable tag checking */
 	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
 	/* reset tag generation mask */
-	set_gcr_el1_excl(0);
+	set_gcr_el1_excl(SYS_GCR_EL1_EXCL_MASK);
 }
 
 void mte_thread_switch(struct task_struct *next)
@@ -178,7 +177,7 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_incl);
+	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -186,13 +185,14 @@ void mte_suspend_exit(void)
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
@@ -213,10 +213,10 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
 
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
@@ -225,11 +225,12 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/27e272bfd203cc0ff32181f07db588363ef3776b.1600987622.git.andreyknvl%40google.com.
