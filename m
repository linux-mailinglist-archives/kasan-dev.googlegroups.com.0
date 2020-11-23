Return-Path: <kasan-dev+bncBDX4HWEMTEBRBANO6D6QKGQE3FUOQ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD142C1557
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:37 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id f16sf6516418lfk.7
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162177; cv=pass;
        d=google.com; s=arc-20160816;
        b=tzeh6ylD9v0+OxQrXsH5j9fK+8yyh23vkbwS6neInZKRFX80OlhsUhN651M3cOIlXU
         m7d5uHaGdufkJwFH75yAXpho8JnCaD8NRpqFaALOVwqPMumn3jObGmmAywHveni4IoiI
         PkYC7l6sX2WDT4JS3KDqLIymlj4B91xglAc/yVnXPHLuJWTL9x0jpNgjA07RUEr1AcKp
         2qygrcUMBazOqLsryNgLv8CJ8beFRhdbyGrOe9hNvlxko/NPW+wVMU1Y4FqWqENSqPLC
         GbNPXaX34g3ylDaBwePIQG1FgITWTC4DqRO/06PWSKK6Ko/hn0w4Nx8kQvDUInowXAh8
         CqyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=aJJXH0B0yjhYg1dyRCL6Cl7bpmU2lVPKi6ASbTPxmKY=;
        b=HEYOSI2o7E7Ji/EHlduWfhInQjbYHijRiWeYKWbn8zhNodqO7gtWwee8jWUrsZIp6w
         sxUp9vkkMc8Fe3OrnsbALaCc1bmYIN56Uq6RpVaS3ENtCOLI8DGDdBPiqUzwQiSXVQqX
         N48haNbmMZfJaG3gnjneBsyhOOJ1XHZXF2l5C3GpYfiIXlIbKk2R2xcuQMJxHsmjVuve
         TlBOQfVoOXwnBNZqQoTgaAkSJMNP6C87u2lGZP4DUwL1/ZtR4vrwnLm6YW8wqP7EdBs1
         WXGULppw86jaVai4ix/xAB24MLZRM3KJBzsvm49SleFD0URW7Z/NQ0yTCKnTUI2k7/E/
         T3ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oLbVI8QD;
       spf=pass (google.com: domain of 3_xa8xwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_xa8XwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aJJXH0B0yjhYg1dyRCL6Cl7bpmU2lVPKi6ASbTPxmKY=;
        b=o+Uc9J/R9bHJU+OKk5HdBCnYNzchWSbdHIhVI2Dn0NGvBnbF2FA1rAgyT0sn8dCXm6
         cwIBwc0++yvVzuuxJ1ziRp2dupc4GaOb5+yDHc62G0wPiH3qYvPBBXSLKcLnDvikHXM6
         se7QjRt3zuNfgaNzOtsRz1iYUd/fwMeh9lMbswMjo1GC1PvfJUjxLE0ykxlDJPLvhfpr
         HStxlUI/ioi5NZYYEh8vDf8SYr2DzRZE3YfGvCwbIlqWD3Gn1SLD7e4RiRjF6ffi+6M3
         kJFfOvX15xmQECis2gglazHzheks49yDtylkV+QUoCo5qkpNagQ/lLJNlOJr0l9AlGdE
         X0iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aJJXH0B0yjhYg1dyRCL6Cl7bpmU2lVPKi6ASbTPxmKY=;
        b=Dei+iwdQvQnxBp8Xjz4ojIxHFW6K2nIjfQniugh0I7ajKLTHR3JdE9yd1E5i1z8t+p
         tz1e+wOpjxL4iqvg0nYcSY86RnwY6rw0QT146R83Z5FOp6QHQq8LF22M7sFppjxabmrV
         kw3W8aRFPFO/CtMJScgBtOsgUnHqZ35RdwxQQINa0Ne1bq1lNxwofLOHLAD5FNXh+yej
         axjhhEfSD9jB0p04l3iYSptUUorWz0g/2RLWgqZo6YbfxwYWeg2fDu8s7pBlNSmjKWhT
         zVuIKBQJr5+8ne5njEjL0XucTQ0SqRlY4Dc4/DPpUsySPFvCSqC07uH7BEu8E5KXlHV9
         YHwA==
X-Gm-Message-State: AOAM5303h6C17w3RArMnLxXvmcOaTRL/M1Kk8dz7k0EqMORSTQqIml3P
	KV4jHflWRd9ntoCJ5sorMpk=
X-Google-Smtp-Source: ABdhPJwNYoY/EU6151XaZueXYLpgCjiIyKqxUDydnDs/H1/1YlKc5CoXD0KO3hdyCv4QeFi2vPWW6g==
X-Received: by 2002:a2e:6c07:: with SMTP id h7mr468435ljc.464.1606162177275;
        Mon, 23 Nov 2020 12:09:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls3987452lfg.3.gmail; Mon, 23
 Nov 2020 12:09:36 -0800 (PST)
X-Received: by 2002:a05:6512:528:: with SMTP id o8mr349019lfc.374.1606162176219;
        Mon, 23 Nov 2020 12:09:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162176; cv=none;
        d=google.com; s=arc-20160816;
        b=m8B4nYoGkJnXZwNvB84a3ENdjZaC4U/rSQqVlxED7QUG67iktxaIoF5mu9qzg73C3i
         2ckCvYw3m5PAy1qrsmUBYw/+F83ibh3hEgkbB4e2goQTcYKpfMmvhVFvNiXSKOvNILrr
         JTm5M9QPPu+Z/2Z2MRUUii53uG+FUWQTg4dftIf+cOjKxJ1j9SZjQ3J7SS57NOslvlrx
         m0iVF4Of2PEtiAM4O+IR0ziQtayJlboUj7eo1iZvoCKUoB5yRGtxqn7UfZqz1JTf8MzP
         0u18DJ0pTecyjQ9dd7FwfVXrI0YMk30lEVnvaLW6B2GUrkaOeEEVsMjclFOndN5xcAcM
         TDdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=AHP0QRUHAmMZJhpT2581AIFhhHxpaXNp9zbm2PJOXII=;
        b=eXxs2TGPBmY4x4e5UMEEXgFde08n/opwlOsv+Se9q64Oobkkl+sg4NDjc1ggFQKqfP
         jNTfboNkyPYNeUh9DFePoDn/6Y82E0QShvHndXIuXCr7HtuaQJ4ac1OzvAPOK1ITX3/f
         x3mFjuOnKDM/jBAe8/MtZ1TCIULQXavRLE2dLsueCa3944ZWsRVrtsu6jKPkQsamd+9Q
         MiLs42GD6udYnesODWzQEabhMXC2pckFmJhjUX2VmJR5JQGufA7DYgx4gmxVy9+96MQz
         TGAlJFaa1plE7DYXa8gonkTK01L8/07sDc/GvUdpDvXq/aC97oUe3/xjSPdFLd+ZSVco
         MVqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oLbVI8QD;
       spf=pass (google.com: domain of 3_xa8xwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_xa8XwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p13si32454lji.4.2020.11.23.12.09.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_xa8xwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id c8so6240629wrh.16
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:36 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:a343:: with SMTP id
 d3mr1391165wrb.91.1606162175513; Mon, 23 Nov 2020 12:09:35 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:53 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <946dd31be833b660334c4f93410acf6d6c4cf3c4.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 29/42] arm64: mte: Convert gcr_user into an exclude mask
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
 header.i=@google.com header.s=20161025 header.b=oLbVI8QD;       spf=pass
 (google.com: domain of 3_xa8xwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_xa8XwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/946dd31be833b660334c4f93410acf6d6c4cf3c4.1606161801.git.andreyknvl%40google.com.
