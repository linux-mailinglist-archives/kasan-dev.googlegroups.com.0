Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB7E4SWAQMGQEGTVCAMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D9FB318EB7
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:34:22 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id v23sf4526748pfe.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:34:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613057661; cv=pass;
        d=google.com; s=arc-20160816;
        b=AgSFzXH4CyamMy8rhAlcQyGqTaimw+XqqUbBX6cN3hYGawcn8OTF4vscMsZTl+TgeX
         0f3ar0b+o1X8hxh0jivdcXWlK+7slY2MtP2dYz4uQcFwxb4hy6poDZvt2Eejyae5O4PF
         l0HA4vniM0KgjjbkE7OBkadqiAIP062kj0RP//QHT49iD6holbhOhpiDJv8vQixM8jAy
         mK2sdzYXY2+6+YkjAFWroNot2IUoI4yajVdf5KS6x4/xLMTpkioMjMmfnvHZYSSxDm0z
         EIbuCM/AJJ1BihNK0M+FfyDB9dE9VCFPI2L2femxFUnG7Kmqr+CK6jgpkrhH9cQduoO+
         rg5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LTfxVzTBbgXAoFnxJ0uywM9yqRHXzrTbVO8+mwoll/E=;
        b=rysoX1H5DHNusVBgTDB4kImghBsixrxEOvwMfdYXi0W9q+JRtU3ArNhiOlL7r5BVQR
         h6N5vCMm9yai0JmCjr2IUyYixo8X7fQ7zxlMy/PBq0kWfLhVa0gkNgLy8slrYLOVAfFy
         D+78q3C1GfwYKHoMg6sjrovpUkSnTttYy2KoYQ6UfJpd2xEDAsUx0DZoisgkQZJXgHSA
         E7pZcRJeOPmINci5IETH+L3V0lBKzFfU5+4AtCCb9ytjl3JyqqtnRJPMBbeav9tY0zb0
         xBwNSdxN/qQ7T914SewS+Uaq7Jh8w42fz5FljXK2fPO7WcKDVcwHNNsp+Ejg3Hr5nv+J
         o/Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LTfxVzTBbgXAoFnxJ0uywM9yqRHXzrTbVO8+mwoll/E=;
        b=q3O0LfZTkzlI0UdlpawKdbXCxygO/d+UMKLsyn9x4BemrzzhtGElWCVDEEoZ72LtqB
         GufMH+reOeK9lpaRwWDX64C7HzslutT60hGsrcxnpOTnNCnBdAiBPPxhUO19j7XsrJbU
         YePvKwjT4ttx5SHztegN/V21aXpO1ho9qa+AfBZ91BEmGM6CK1pvVpSAaGvsiFZYUcxQ
         EHMLA7KEXdDRXLr2vwGG+tj7OAY52HLiTLBDbGukvPphGNpkRnkK6Pz4P76nsZGu5aAm
         UNfHbka/CbgnsCbPKHhNHFcFgk5FiziVYiM+4gryRFwiOAerr+TrA5ul8tk/ViOQNLUY
         dv2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LTfxVzTBbgXAoFnxJ0uywM9yqRHXzrTbVO8+mwoll/E=;
        b=HqHbX49k6MmKmgW+KNdKFt34lSjOLqxukhqtvSqGgSsvLd+x1B3DnTLY4e60EHLlr8
         EZyK7RxtYbfGHd9Zpb0AbkvvsF9LkFaIZnrOY3ZKEYfkQ7Xe2kMdwR2kO0N/4lzeQYXA
         TZQnCUe2FfafjHSBZFa/EgEu9YrzKsykqYOLpB++mkCxAyzB1z1zQEhgbBXsFftJ4vo8
         VQKmiAUGg93vfAL7YBow6G1Feax0j8H8RZEjjOvSvD1tp6K7NnSF4UI85mAG6bwEkwzv
         4QG2VdcTcdckC1uBjRBM3FZeDx0rKjwcQ3G/XjItAi5KyzEfmqP7H8epAHvJlDwsSKT5
         X3AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532deajAZeFms1Slr8CJB5L7KhB5I8xJL+kH0ik/cu5hamOIiTUZ
	rAdtOlQupqM7TYTL0q8Y588=
X-Google-Smtp-Source: ABdhPJxtTmucXjbUiJwppojHXMoQoNnXYTfq1OshbDIhjGQ42+VznyLrALTKrnTgdy7ZfBPsZh8uTA==
X-Received: by 2002:a63:7947:: with SMTP id u68mr8474641pgc.451.1613057660983;
        Thu, 11 Feb 2021 07:34:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls2297554pgu.6.gmail; Thu, 11 Feb
 2021 07:34:20 -0800 (PST)
X-Received: by 2002:a63:1965:: with SMTP id 37mr8672129pgz.349.1613057660295;
        Thu, 11 Feb 2021 07:34:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613057660; cv=none;
        d=google.com; s=arc-20160816;
        b=sc8L/JtJhaviy1mwFN/fp9DLlDXme9uYuPYcDIb8IumV47bkJE2eUqyEjmSK57N0WQ
         /ducmF7WVxApf7nK5PShc9bzQTH6LEqBmCRSiNDPhVin802n85oJu4aFQ8biwRBFc8dM
         VP6wgFRbFnFcdmhcaJGOx9Df66cTHGUgIVIeAZnzvc3Pt5CXSgSyLdbADhf/hmQhMmG2
         YC1Z9W7GrZGD8D7Mhh8X8TclLprFNvl9+6+TnbuWTbw7k4lAmgHcCuMjwjEoXSTW/wg2
         /uABqF+aczX9yqNpC99XWFTXtI83maXCrlLz+vx9ZaNG/wPabu7agS6cdsyD+bZWWEIV
         NK1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=rt6rtnGmcfdzYQBNI/0F2yHk/lSQpALJc8beWEoRpWc=;
        b=SlEz94Y55JuRxXYzRIycc2aI5dkZnXJp1HIcwdcfwuMHfVvS+dVUEkMvRmcJwcdbgO
         GaWM92k7LVRMQosDTZmHU1xl/DXRG5Korlu3uKxtEt48osk623P4W9wYsG2ZzrJHrYCW
         ugmMDfWdBs+m/atWcvZBDhqIYSkM+Zs3rcr4veQVDRzX6OVLHO6rj5/L/my9XzX/FRe2
         XKJB4soBH25drq4ZOu2fThefubaqjW50xJNxgHFGa+Vi7hkiEQX8nj54UnUDAfWsdxI2
         nsr6pIlH+9D6roNWfBTMwMgLldEkX9s7ReKBjSe96kLNegh33V5nKU3vpq983QwsGeSu
         SyTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f24si547571pju.1.2021.02.11.07.34.20
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:34:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 41EC71435;
	Thu, 11 Feb 2021 07:34:19 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 564053F73D;
	Thu, 11 Feb 2021 07:34:17 -0800 (PST)
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
Subject: [PATCH v13 6/7] arm64: mte: Report async tag faults before suspend
Date: Thu, 11 Feb 2021 15:33:52 +0000
Message-Id: <20210211153353.29094-7-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210211153353.29094-1-vincenzo.frascino@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
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

Report asynchronous tag faults before suspend and clear the TFSR_EL1
register after resume to prevent this to happen.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h |  4 ++++
 arch/arm64/kernel/mte.c      | 20 ++++++++++++++++++++
 arch/arm64/kernel/suspend.c  |  3 +++
 3 files changed, 27 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 43169b978cd3..33e88a470357 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -41,6 +41,7 @@ void mte_sync_tags(pte_t *ptep, pte_t pte);
 void mte_copy_page_tags(void *kto, const void *kfrom);
 void flush_mte_state(void);
 void mte_thread_switch(struct task_struct *next);
+void mte_suspend_enter(void);
 void mte_suspend_exit(void);
 long set_mte_ctrl(struct task_struct *task, unsigned long arg);
 long get_mte_ctrl(struct task_struct *task);
@@ -66,6 +67,9 @@ static inline void flush_mte_state(void)
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
index f5aa5bea6dfe..de905102245a 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -258,12 +258,32 @@ void mte_thread_switch(struct task_struct *next)
 	mte_check_tfsr_el1();
 }
 
+void mte_suspend_enter(void)
+{
+	if (!system_supports_mte())
+		return;
+
+	/*
+	 * The barriers are required to guarantee that the indirect writes
+	 * to TFSR_EL1 are synchronized before we report the state.
+	 */
+	dsb(nsh);
+	isb();
+
+	/* Report SYS_TFSR_EL1 before suspend entry */
+	mte_check_tfsr_el1();
+}
+
 void mte_suspend_exit(void)
 {
 	if (!system_supports_mte())
 		return;
 
 	update_gcr_el1_excl(gcr_kernel_excl);
+
+	/* Clear SYS_TFSR_EL1 after suspend exit */
+	write_sysreg_s(0, SYS_TFSR_EL1);
+
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index a67b37a7a47e..25a02926ad88 100644
--- a/arch/arm64/kernel/suspend.c
+++ b/arch/arm64/kernel/suspend.c
@@ -91,6 +91,9 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
 	unsigned long flags;
 	struct sleep_stack_data state;
 
+	/* Report any MTE async fault before going to suspend */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211153353.29094-7-vincenzo.frascino%40arm.com.
