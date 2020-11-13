Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5ULXT6QKGQEF2WI6JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 34EB52B2823
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:27 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id f15sf1376280ljm.20
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305846; cv=pass;
        d=google.com; s=arc-20160816;
        b=RJobiCOxLKFcKkDADl/NIqGvNI6wXFG4n3SxZpyaXnGIci8nLHZJbFfdaKHO8Fx4vB
         8Y0xSrVGve3QayMlDHyIhJp3B3rCZBgjpnHbJb8k9pPcrZQp1KnPwytUjGmOpYbHkJiu
         B9uJMDz4T9MuHcXSGJtGjqsVqSAss4/TPM4Uzg41zlVg/oyKBbj2jSFr6c4f7HxDvP3F
         FkyZv/6EAfSd4mIlD+jpw3bZUqw2T9d/APWTZNDiw6QeNRAYaWXs1u8xId8jB5DtkxtK
         hrLJAntkeqKhSQcHKYigcPa9/qFgNVPI3ljLTJ+AO+Nt1Etx0MjuLusfIouVtp0O2FCm
         cAcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=2CV6K0A1K86NTGILzBvKEnznW0F9dzqq3E1F5xjkFpY=;
        b=VDGUaAkS6/7cMz/DO+Ji2ce+Q93VlVJaXACVGzwW/ORlFvWSCJZNg1mFG1xzeexsTA
         lS0Fd9v3uewEFAjyO5E5lsQaODTC9d7NuE/d49G+PPa7f6PuyZkfw32OLC0kT6Q5SBDa
         OG3phgtwdn9Adng+aCXRiXDmEf42tpUDGyHpJpaXX25HWlgi/vIP6e1AXsdtD/q6Ay6i
         icaI3Fys4355iTaP10LtFj5qANoWQUAPvzYvM1ntHGJSUkGmHgRP9O2dI4afk9bqT/Jj
         2HnEInYenucd12yTyBPfMg/PZ5VWtcOIS8kLsoOnpjWYG3/tGCrK+o49SeAcfDO09rAj
         KV9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bplSDuCY;
       spf=pass (google.com: domain of 39qwvxwokccagtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39QWvXwoKCcAgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2CV6K0A1K86NTGILzBvKEnznW0F9dzqq3E1F5xjkFpY=;
        b=edsmvmngr3dT/4zpzBziSRhtOu8OrszOyq7meWXqP0Kpozisom8X15ucp0OMrvLUOH
         WJY0KGVYN/f/pPYMyHwp8DYDGet9CH6RTPlg1IbV2T2eKJiPYJq3TdQ7J2kR4CZOWNnU
         k8KMxx+I3vbF5EiVWCsnjkwH8suTXKcasUWKWqZUwlK1N9bmJOVhxd+PIqAPfK3HoK0I
         SEwN7Hy1CNBHEWZsC6FEoNBFaio5yYkgOm35OFKQ8hO3II5N54tIAchSiZzrN/abtc7T
         2nvEKm7j+l27lZdj8HJdvgYXTZ9T+cbDbO3SjebXyuqqxYbMqSMvQZ6nc3edPfSTRuPd
         rotA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2CV6K0A1K86NTGILzBvKEnznW0F9dzqq3E1F5xjkFpY=;
        b=bXfNiq8qu1xFYC0cgh1DW4YDJW08FvD94h+V4SuS7jOEHHj9AdPiWp3N6xDmy72U0v
         Yr4RrAFG6mZARdWeNEvGBBz0llGEetCSdOQQfAqIo+BqDKAVD9/8nX/8kilpHjyQ5JQ3
         /3xdS42XW5DkuKXpwWlDYyzm7KsJmAh0+pqI+I5BAVheo5OFO4PXZmj6KzcSqXe+6m2t
         9U5nCPjmLW1UJEE3XdG7P6GSg2h9CTfCaow68fP0h8dgmzRx5XX3tbYZ9kRcs+htPABp
         nUusbW8VzHPIxnSJoF5ppzJsCUyGODK4jvSQ1P4QGIsoGcwdFMTOmdwAnl1+2tQjzPAi
         snVw==
X-Gm-Message-State: AOAM532JjuLdd3n+DHnLD9vtyGRKzUlZzVKS/P28maSEUCqybMM3AeFm
	w3D88GhreldStnLcvBP3mj8=
X-Google-Smtp-Source: ABdhPJyeYcMNyjgY3bVkm/w4uP3ag2U89N8KFKvvK1OYxHbVJw2ECMkybKAXEIJep17itIK0CpzNng==
X-Received: by 2002:a05:6512:3587:: with SMTP id m7mr1835799lfr.149.1605305846773;
        Fri, 13 Nov 2020 14:17:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls5523153lfn.0.gmail; Fri, 13 Nov
 2020 14:17:25 -0800 (PST)
X-Received: by 2002:ac2:4211:: with SMTP id y17mr1794177lfh.133.1605305845875;
        Fri, 13 Nov 2020 14:17:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305845; cv=none;
        d=google.com; s=arc-20160816;
        b=zJ9TkjLVdmVJ11uXkQmKnD5tjNwUm16c1lkDypex2yu6R+KO2wMU8jjoLFCD/H6pOp
         9pnIMCnIReVvUIFz2Go0hVO6L0Pb7S1R5fbRMq91lXSafTscucC/ZGF8SsE1u7Tp52Gb
         z4K43AWIDFbNemnpQvD8kThzcY6atpMQkFeVsc63G7kXBL8iDzvS5tUikqOyULmdbzwx
         4pX4RwzU3G1zJ7t9KHZHxrXYRNo3TEcMFB4b0+MPyK4ddDiYinDyScs1Yh88ct7Ref/A
         5adDO7IlKH8BTNaypASTZ5UIGnKVdGEBPhmqlrr3V6TQ7B/wH+pehHiHzIDdIE6fAqCe
         sr/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=towGrnACjVFWXBLIg9UmlGyfIuoY75eHqBtKUJMwnvM=;
        b=XYvQbFCoIL1CbFRe8HCyye7O4D5AR2rWBXTUFFTafap1OJoSFamWO7zZzFxZUojayh
         rHJIdYM9AeAxGhQGWHw6u11t6NibJlPQbACZl1EL0xg5N0l3Xv2QvXoNPE/JBezXv3r6
         B/5eqTvi5iA8kTLZ1VOBMzw+LulN8sMwvYUzncDt8Ztv1ST+TAPtMyLBv6dDILjl2BOR
         xyhZmZp2fJWclrYk+rlla3W3IAUQOgx4p5ullolPcna09bCG7FCVKuSGmo5y2YqV2epA
         5tKlm5khf55KKjodxH8GVskodvIxrUVWl+csanIrzifvfKOH4eWJW7jjLf8Og54EoYWi
         bUlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bplSDuCY;
       spf=pass (google.com: domain of 39qwvxwokccagtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39QWvXwoKCcAgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f28si339178ljp.3.2020.11.13.14.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 39qwvxwokccagtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w17so4630748wrp.11
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:25 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:de05:: with SMTP id
 b5mr5951444wrm.131.1605305845232; Fri, 13 Nov 2020 14:17:25 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:57 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <1d853f7f1e9284af23023fb4ce628a26b9b3752e.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 29/42] arm64: mte: Convert gcr_user into an exclude mask
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bplSDuCY;       spf=pass
 (google.com: domain of 39qwvxwokccagtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39QWvXwoKCcAgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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
index 7899e165f30a..6a7adb986b52 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -156,23 +156,22 @@ static void set_sctlr_el1_tcf0(u64 tcf0)
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
@@ -187,7 +186,7 @@ void flush_mte_state(void)
 	/* disable tag checking */
 	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
 	/* reset tag generation mask */
-	set_gcr_el1_excl(0);
+	set_gcr_el1_excl(SYS_GCR_EL1_EXCL_MASK);
 }
 
 void mte_thread_switch(struct task_struct *next)
@@ -198,7 +197,7 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_incl);
+	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -206,13 +205,14 @@ void mte_suspend_exit(void)
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
@@ -233,10 +233,10 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
 
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
@@ -245,11 +245,12 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d853f7f1e9284af23023fb4ce628a26b9b3752e.1605305705.git.andreyknvl%40google.com.
