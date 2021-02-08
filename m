Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBSO2QWAQMGQEDRW2B6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FD7B313A30
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:56:42 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id u17sf897393ybi.10
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:56:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612803401; cv=pass;
        d=google.com; s=arc-20160816;
        b=qLjUZENHWv5etaGcorDLc2lZSX1Rmfw3Ym1pNBqvb1I39b7CVP6jy7mCX0aK34y2x6
         0lXiulndpm9l5RtzmqteeRmGpxG03a+hBn36drw/5FVFJV+lTZMS1uzUabH3VTQZIaEV
         YiP5kMWt1UK4DQ9u0hLxrd8aVbTyuj2VGn2P8G2jfyEho6Tunop9kQSt2Yfq/rnGRwWZ
         vceguMUIYmtTv/xJqT+SYsVKR7FU5Xq5OgDsQoH/Mcc1I1nRZpP5wjTSHf6pd1r4ww8u
         gEZjXcmFV6ZnB8tVp3sUOImnaRuzEdqMgIjJCLS6eNBEijFFxBw4n8E9nsPICV29Hm88
         BKXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dNakC+VK4mMwu+O4xMzF+GF9aGiRX40N82DdVzqRqf4=;
        b=WRv5FSb39ewSCbM8FjEnA6QL22rpK/jsJfd9mZIiaEYQMBJbxyF9EF891XgF6ibdNU
         SZMR1Fjl8OLUzR81QQwS72u3cHefpdcmt0WkQINMdx5CRzYc8LMAK6JPxQ/SUl+kwYcx
         MNhXE1scRhej9QDr53CSbFT+WwGKNlZkPjPdgh4COR7afFC7MUil0m2LNyb8oPiVMnP+
         IbImNOeIkmYvTyAIJeJoqbNQgamOQa7lECIOhi+rwQVCNiV93VncQtbZD62yRrUNqrsj
         gn7hFEYIA+x8x1PKH2NyXK5VB1as0qa9qqBSXbBTn+onqGQKv1VKXJUmG+YFlz3XrkSy
         2VlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dNakC+VK4mMwu+O4xMzF+GF9aGiRX40N82DdVzqRqf4=;
        b=NMEBkaxs4Ozkaczrh9BMvYeuTkNDdMy3EM9wyj8eH7XBr/mettN32E38n0654smUgx
         2i3ILMZeA55jSJMG0mT9NNDXJ+7vO/DofkVK7i6Jd6gDvwwoqRkb7JtTBetu2ruLIk4C
         Kgb1m92NP56+RnTck9vkjez0rNAejlkojjQ8L4R0/GCIYR7x92os/O6L9qfAjKQw9NoA
         zMY2FqQJJzK3yJNuWaZa1jZIiSsveUhCRQmnWCtCyRGgnOqZuRqyXOdGA2kmH7puYSAs
         nSMs9Gg3QwSL1KW0y1/6OYfxBYoB53Owrsnj5soIINgOzkfnCdUIfSrC7a1dJ/En2RWN
         cY4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dNakC+VK4mMwu+O4xMzF+GF9aGiRX40N82DdVzqRqf4=;
        b=h0QnhaqChPA0S2yn/m/KqM1h5KmPlMsUHq8sRUjQLwj2Z1gNAfrSvwexIlmMjH3GX5
         yyGF7jmUhEbfWXUKY5SxKGY3dLgdEXOywxAq7K0rmPjDqIeSkDNNUxXznfGICpU5uklr
         Fp5d1gNnm2VoD51oaq98Z532rJiUnp+uwGVYvb208xgHwPnLEw7awqDD8btkSxXrcgfa
         bqAM2N0JkR+d3tWY0SqcwHOy9ZS/BvCHDF0/V+1vQ/rl8xTKG+iE5opLxaN/t48SiquQ
         vQLFSckzk0jDCqC8L/Wnf15m39O5M3BvejHhO+RcVmukPGsi09ngxxW7yMWkgXpf1Oph
         ZZ7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VoseujV6GXmGLKLqsX5NDUNjjqvkNUUlSCrf6PkUIogpJ3pxa
	lqGNah3Ws3977TiLQ92wD8Q=
X-Google-Smtp-Source: ABdhPJyZi0RyF1KNZ7SYqyw9GEcq3Cr6rWw33eFpJXgncQocSY7YcUOcsOj5J3Dbq7zkvQOA+reR+w==
X-Received: by 2002:a25:d4d2:: with SMTP id m201mr25835954ybf.1.1612803401289;
        Mon, 08 Feb 2021 08:56:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bc4c:: with SMTP id d12ls1762089ybk.0.gmail; Mon, 08 Feb
 2021 08:56:41 -0800 (PST)
X-Received: by 2002:a25:b3c2:: with SMTP id x2mr25844459ybf.304.1612803400909;
        Mon, 08 Feb 2021 08:56:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612803400; cv=none;
        d=google.com; s=arc-20160816;
        b=aAeb/c/I0wLVaflWgxytQiP7vTfcKBorfbe6UVsamErPf4PO+Uor5mSXCPdUxerEpy
         byakcmc9pep97uTPNV84Ye3eIvVQniO/JhC2YZGUyLlZTd78PDT0aIEZzicLkqDczmsH
         Lmdn3LWiAeKa4o/InQiIygkRd0Yv/x9OErlOLNlsmPtdQ96L+TLu7fNigmXtBlLZdpmH
         8d5T62f2LcR3RbqcSj8xI2fTRlRRFweRL/5dA7OgYVbGy7+JPzyDPo5Y7wZDKD3eR1zo
         qlxwphDZYb00J0Js5b4c9n/0J2gqnITtVbNLwXfJFbGAQHgTUFWb898+GixKmTIoLOTJ
         jwUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=SzlTJN9dRjGybl/zN+5jaH18pYsboQ5xx2VzgOMBgeM=;
        b=YEeHr34frhuPLhk+GNEeT2VkAXjg52qwYZQ3aLWMiFtVlAp+kUWpI0uqbu5PZY1FyD
         kP/zEYCSrv/3ySafP4EwESxiHa369egqzsVrWbBjGmuIzux20YKqFUVgn9DSSkZV25GK
         7ACaUw2xUeu0ATb/EteE8APDcGehQzGdxOWdZ4EWkepnqWjNarMCkwMoz3OwgJ6Y5jwG
         Xa1MfhD2k91RUelUj1xSNaGXpI8aZEgT6fyKGVD9/W2VJ0FnfWJfscZiy4LUsSQ8Sqcz
         Mycsb11aq4yNH9SjlyraagmxplP2ralSieH+ZNt2w29Z2DWIKiZ0G2BMKd9V3BkyewOg
         cIgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e143si320995ybb.5.2021.02.08.08.56.40
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 08:56:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1972613A1;
	Mon,  8 Feb 2021 08:56:40 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 37BF63F719;
	Mon,  8 Feb 2021 08:56:38 -0800 (PST)
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
Subject: [PATCH v12 6/7] arm64: mte: Save/Restore TFSR_EL1 during suspend
Date: Mon,  8 Feb 2021 16:56:16 +0000
Message-Id: <20210208165617.9977-7-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210208165617.9977-1-vincenzo.frascino@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
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

When MTE async mode is enabled TFSR_EL1 contains the accumulative
asynchronous tag check faults for EL1 and EL0.

During the suspend/resume operations the firmware might perform some
operations that could change the state of the register resulting in
a spurious tag check fault report.

Save/restore the state of the TFSR_EL1 register during the
suspend/resume operations to prevent this to happen.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h |  4 ++++
 arch/arm64/kernel/mte.c      | 22 ++++++++++++++++++++++
 arch/arm64/kernel/suspend.c  |  3 +++
 3 files changed, 29 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 237bb2f7309d..2d79bcaaeb30 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -43,6 +43,7 @@ void mte_sync_tags(pte_t *ptep, pte_t pte);
 void mte_copy_page_tags(void *kto, const void *kfrom);
 void flush_mte_state(void);
 void mte_thread_switch(struct task_struct *next);
+void mte_suspend_enter(void);
 void mte_suspend_exit(void);
 long set_mte_ctrl(struct task_struct *task, unsigned long arg);
 long get_mte_ctrl(struct task_struct *task);
@@ -68,6 +69,9 @@ static inline void flush_mte_state(void)
 static inline void mte_thread_switch(struct task_struct *next)
 {
 }
+static inline void mte_suspend_enter(void)
+{
+}
 static inline void mte_suspend_exit(void)
 {
 }
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 3332aabda466..5c440967721b 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -25,6 +25,7 @@
 
 u64 gcr_kernel_excl __ro_after_init;
 
+static u64 mte_suspend_tfsr_el1;
 static bool report_fault_once = true;
 
 /* Whether the MTE asynchronous mode is enabled. */
@@ -295,12 +296,33 @@ void mte_thread_switch(struct task_struct *next)
 	mte_check_tfsr_el1();
 }
 
+void mte_suspend_enter(void)
+{
+	if (!system_supports_mte())
+		return;
+
+	/*
+	 * The barriers are required to guarantee that the indirect writes
+	 * to TFSR_EL1 are synchronized before we save the state.
+	 */
+	dsb(nsh);
+	isb();
+
+	/* Save SYS_TFSR_EL1 before suspend entry */
+	mte_suspend_tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
+}
+
 void mte_suspend_exit(void)
 {
 	if (!system_supports_mte())
 		return;
 
 	update_gcr_el1_excl(gcr_kernel_excl);
+
+	/* Resume SYS_TFSR_EL1 after suspend exit */
+	write_sysreg_s(mte_suspend_tfsr_el1, SYS_TFSR_EL1);
+
+	mte_check_tfsr_el1();
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index a67b37a7a47e..16caa9b32dae 100644
--- a/arch/arm64/kernel/suspend.c
+++ b/arch/arm64/kernel/suspend.c
@@ -91,6 +91,9 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
 	unsigned long flags;
 	struct sleep_stack_data state;
 
+	/* Report any MTE async fault before going to suspend. */
+	mte_suspend_enter();
+
 	/*
 	 * From this point debug exceptions are disabled to prevent
 	 * updates to mdscr register (saved and restored along with
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208165617.9977-7-vincenzo.frascino%40arm.com.
