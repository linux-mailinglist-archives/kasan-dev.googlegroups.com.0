Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZW6QT5QKGQES2355TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 638F226AF65
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:28 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id r8sf2635624pgh.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204647; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kfba2yY3RGRJOfhVATVgztBIbGpl96BMkRrG4GNJolY2RD1nD3ERdEZ86zJJMRBJgZ
         DdeHJi5BIUf91QUW//wzIHVlS4hFP6FA1eOGsjKCo45YVZhNxB9mQP8osKStIEAkNzOp
         QeFZOUKYQGEoUZ1wgttOFskRpDQ/th+iqsMr9pYBXhOZZ6gJiOawiGrkGCmN/O6rXUsu
         1U8ue+VxWBfhE6IFa0bpIjyNMn/wbHT55S+DdhxuPjqRjgVmPa0JIPvK4HPcmjx5tnDV
         Oj+QspZ65sXQuYcmbVnVwdUuK3N2tmjQcR9V6o270SGyVrLxG30iVutduBUIS40ccRyM
         FNUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Ye3PB2eZ2mt58cE4bkzKkztAyT11mGbtTHOyQhWWbIw=;
        b=aWo7DUKhMtVTKsGJrj1TQmsmCW9z/mBvsN9rSqtVslDm06BKS80f2WjerMDdCr/D2K
         njIiGtcP1jQcDyDOgguLgQpvA4d3MOF/rbwcfzcx/83UiugcEFGfJK9wbH3CDgJIdv1N
         sDvTpIMLichdAlt99vMzfEPj8nSEIzAPpQ+5DOuM4kD6FIjwqDPFFGJzLxHJrCtyX/b8
         L6/kW7lewLJ575kgG0c61ZVvodSZawA7DIMtyDYK6BYECcezGUrCmDWah/Yh3zIpijG+
         0EgDpplqg5l1P6XhK9lnt6Kz56ip9h2dUTDwiY6KqzAcaKYX4pF8SF/wpwxs9eIOGCH2
         VSew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OPHSGMgy;
       spf=pass (google.com: domain of 3zs9hxwokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ZS9hXwoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ye3PB2eZ2mt58cE4bkzKkztAyT11mGbtTHOyQhWWbIw=;
        b=DjY8B2F7UcNv0WZ+munT+I8knvZXFxuQbgGCythtLaIQ/63CYiNASQMqA5lJ/a4ANe
         oJpQBtuNED4nixUN0uRdvd0DXhhutS3YXlZztkNNI+wBFURLK3MO7c7QErzJj58XOX2n
         k9p1a9JNnxui+JZx/LmmJaUl+uwqp2hx1kEE0ic4pGuswrrLF9F4apIHeft4FlmapDcU
         ZoCHK8gGgQtebVBwQpQPiemNzuSlhWyexfsrRh/Fbwk4sqBE7S+R6RM2d8lMHUSXrhBb
         lKXK+khqk3SdmdL7nDyrGkh5in/IdXISnfHE47XxWS/s2jpyj3cvSnVjpD8gO2zevDqy
         oEZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ye3PB2eZ2mt58cE4bkzKkztAyT11mGbtTHOyQhWWbIw=;
        b=nHtbXwr3jhtcQiTte06wW+dxcjbiVkHp4KEYfEvY3xfOFcHn3YmLMBaJXbuqwFd3Tw
         w6WH6nPRH78eHqWGtBmRGGOOlMRVD9vH+G2p6vgOYPFn82WYQtOBUnvCxMOMpTw1Kd+i
         CKEUCdbdr7P9bZTRbGnqPuFeQTOSWDa5vxAFkUtDun3zu6iY9IfrxBqqf62jWrEKXlWA
         k68TgpzYAWjX20bPaGf1V8O2rGMpxjOsFv2kS2wS1EMs7wuyhjAb90PsH0Zie6SHvHi1
         SqyTRQ/6wWqdbh/t+poLmDM2KiY1YzpF/E/598xKmezORybErdWqZXICNCIrMeQjVHKa
         yomw==
X-Gm-Message-State: AOAM531ZYCiJOCOs7SbnK2CFhsAZX1FGX2XdWR4uConaEBlDrTh2RZWI
	pHA0ExXkJAI3kSwkMBoLtjw=
X-Google-Smtp-Source: ABdhPJzdENPfvTwh0fwlHcPle3sA7SyZpem1SmELc/iL4w/YjsmOqryvONH2vFyy431E/ynaREaYYQ==
X-Received: by 2002:a63:a70d:: with SMTP id d13mr16098973pgf.65.1600204647039;
        Tue, 15 Sep 2020 14:17:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb49:: with SMTP id i9ls156562pli.10.gmail; Tue, 15
 Sep 2020 14:17:26 -0700 (PDT)
X-Received: by 2002:a17:90a:a58d:: with SMTP id b13mr1110222pjq.49.1600204646475;
        Tue, 15 Sep 2020 14:17:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204646; cv=none;
        d=google.com; s=arc-20160816;
        b=UQ/N8TMEkfcCEOhvTnFoAXIT7Y2IoolBXj0jrONffk2YbBAlxurBnUGjMyPrbIMcEZ
         pBx9vEzC0JgobbQwSLtalnWGPUn6iwOEBI2siMefan2bIaSYobVibSjgTonOBumMWA07
         Yb1+DIYLzMl4tBpOVuHC17hNOt+QcI6bi8OrDOQv6FJws1UuB7PU8jpJm9rwD9BE3x3u
         NSqiwAPQxE3a2hQPPvne963rp5tct1TEhKnk1Tvxhw2JKVG832i2FuzIxbw3CEXpwQGH
         DfSrSFuwupVBQznFazImGp3pnM6bVhzKF8xg68GAYL5ExTpbPi9DjifnBNyb9cxyIWsW
         GmcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LoMLrgCJ4NCLa6lDkl4/AfQRlbckNXKPTR9s0h+8nto=;
        b=ZTmdellow5XqjyLgqRcjjvmM406HkeY2T+m1O4W6MobNv4+68ZqschiXC/3HBLGw6g
         PmT2F8GhrDlXnYyr6s7fl/Ftat/W5VV2blLJRgO2qKyBbugivIV5HLftbCG8Oai6neDT
         K7JE3zzE2r2mERquvfbj+jiMTI97SoskltUujCQxn9fuQP3AoOilWzeCi0nEuBUbk6QU
         yT3/I4naORSR4js4QP9Oktlotfac4jXqg0OU66hlV1aUS58Z2usPQmCEt8TrMLVjj7tN
         hE3BCS0BmY3TClKLdvrDQ+T/urBl+w6hdeRmeshmpVLo+UVpd1wdYg69I57cRLL5cvQA
         kPUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OPHSGMgy;
       spf=pass (google.com: domain of 3zs9hxwokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ZS9hXwoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id z13si747302pgl.5.2020.09.15.14.17.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zs9hxwokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id x191so4118517qkb.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:26 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b21b:: with SMTP id
 x27mr20134857qvd.12.1600204645596; Tue, 15 Sep 2020 14:17:25 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:08 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <dbe7d509102cbbefe0bafb38e9367b5b323bfebd.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 26/37] arm64: mte: Convert gcr_user into an exclude mask
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
 header.i=@google.com header.s=20161025 header.b=OPHSGMgy;       spf=pass
 (google.com: domain of 3zs9hxwokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ZS9hXwoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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
index e238ffde2679..858e75cfcaa0 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -140,23 +140,22 @@ static void set_sctlr_el1_tcf0(u64 tcf0)
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
@@ -171,7 +170,7 @@ void flush_mte_state(void)
 	/* disable tag checking */
 	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
 	/* reset tag generation mask */
-	set_gcr_el1_excl(0);
+	set_gcr_el1_excl(SYS_GCR_EL1_EXCL_MASK);
 }
 
 void mte_thread_switch(struct task_struct *next)
@@ -182,7 +181,7 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_incl);
+	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -190,13 +189,14 @@ void mte_suspend_exit(void)
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
@@ -217,10 +217,10 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
 
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
@@ -229,11 +229,12 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dbe7d509102cbbefe0bafb38e9367b5b323bfebd.1600204505.git.andreyknvl%40google.com.
