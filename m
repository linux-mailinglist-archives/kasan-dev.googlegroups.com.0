Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDU3TGBAMGQEIR2ETKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EA3133131F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:15:11 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id q23sf5426490oot.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:15:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220110; cv=pass;
        d=google.com; s=arc-20160816;
        b=ORxzP+QpMUa+iR1u1/GCyXt/7ro8mN531ZBvHpFMorZPncx8JG3o1pvupKghH0Yivr
         AaR7Ua8Ui8nLimxQDHnfe/xx+Bos1QIFbt9yfUcaFlJmM3h+RtT1VlMqTHzPdKWNiOF0
         ZbNtOhlzDrrplkWMZCW7s2fh4elxFapMQMj5upQKINHIli9Hr6U1bQ97fhjrQPJFqiH7
         wyKS9yUjvoB4vv2rnZ5gfPkcH5XjV66jAVtD8cI6ewCXJrr2zDMcAnHRHvIbeqvD5NBq
         3GmdMHwSOPMtn9nmnMYWhYvI7oqbvIgxJXx/oOkApfLd0lgGnwSHZeqCiDav/HtK4sqO
         WF+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9ZQbtCzuYrYLZYrskNsoym3CGXYRru5m0WdYuTDKgz0=;
        b=CY06i1hfQWYkJZ8rZPqte9+bC+fAgWbC7r03yUMYz2LgPBqnbhYhkj33DDntmnUTBm
         gHO39XEqx209bzM4ueXTRMjCTz/I60ZwzN7ufjagzGJ5ApUdYZiHwvZUwF1xK9Yd9OvG
         wLbucQZZiTz2k66vkDneHGhuCK0+JLnrTqR3T5BnAANfmAQmuIuXRZrE20ViE5aiDEUo
         eJO1WLwDshkj8ihXwE5OlA9xgRK4cUeYtJ75Wql7LYoZGVnd0dHpfEfOAshy/KX/8dN3
         aF9J8A2oxPvNCybWfaf/1eQGbTFuZ0a19L6/OErvI7wMQiYz2XDnU/qd3GNfb8mi/Mey
         MUlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ZQbtCzuYrYLZYrskNsoym3CGXYRru5m0WdYuTDKgz0=;
        b=oX2TYUt2Sd5V8nT5CPMiKioQ5wyPfyzyptjg3QHh/PaQuTA+UBc+uIAzpOZVy0eUe6
         Frr1eBYT0KncgqQt4UCPu0X1xMqJH+mIrmDwExmtkcgfrdhc5e0pliWVt7IKx5QQ7+YZ
         EjdfrV2CI3uBFOW6yJ3MYtjKkd3MUBmrrlXy0uxyOiiZkSCrVviPKe8Fh/uyeJ7EZeHb
         G2fgKhrG3W2S5KxzgSpVSOk8YxXtfo1tJMVdAfv9/DeTBhmpDOcdnMK+3UqyYWX6TNPW
         V2CxNpzTInrM3xE8pGPkwJp3Mg3PxWBZDI/PufoyNBWY/WsWZxzuI3yBJGmaGm0bLRYE
         AmSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ZQbtCzuYrYLZYrskNsoym3CGXYRru5m0WdYuTDKgz0=;
        b=RPs/G++EQzLf6bzMoX6KlMt+LoXx5zIxMKCGJGcgxIh7XBZHUV9aTBtO9eUvj3DpkE
         8GgYWDS+/3lga2J2i9g/fzb3DEfrKAgn6IGgE2ofU2LX8yFXj8PSrKTw4RW/dHuzsxXl
         t8kv4RhknFICu9pG+s3RVy/+faf9Zm7mv8tXCurq1nLvX+wzWrb6topvjDqKqoZ0COje
         p0KvwuPudeWdmQ4hx6ck7QFozdltFq5FLpSNiTj1WZ9N1tjX790JfNC6WC09mjdKrGxb
         HwZtzHqUqMXXlFuoApJp0nN84NOWYOtk/+EOjTgf2qCSNB2rUK/Di8jz70nAMO6UvHOv
         aXdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53131OfjuWJ5cjNxaVhSAFPQUU5Jw5baw7ylW7B+LzFDT/k4RZzu
	NoWjatBdfFhy1Qwl1iWoJ0E=
X-Google-Smtp-Source: ABdhPJy9LoCiFD30jX8czIKFlCRtocgR8WVtkn02LnQL0ZmWAVaklCwlbqvmF+utBdLq0HbAWfLlUQ==
X-Received: by 2002:aca:aa84:: with SMTP id t126mr15253011oie.50.1615220110313;
        Mon, 08 Mar 2021 08:15:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c650:: with SMTP id w77ls4483698oif.1.gmail; Mon, 08 Mar
 2021 08:15:10 -0800 (PST)
X-Received: by 2002:a54:4708:: with SMTP id k8mr14311089oik.22.1615220109987;
        Mon, 08 Mar 2021 08:15:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220109; cv=none;
        d=google.com; s=arc-20160816;
        b=ajb8/yRYa9UfTvkJ2DlkalYLOKRTs3l+sPwz+fRP8fHdPmfG5m0PpzSe0Ht0NfEPcM
         xDuHPVL7eJP6daOrzkuAzApp2AU6ria/NhwC7+qs1See2OqBTKwet+i1ZxyBj4S6IVS9
         y04I6RhrFnXeZ+EhnO8G1BweKTCQ2FF6V2Kryk3Dalgycnv6vHGwgZtI3vOIYZ4PL3cD
         8otifoyiAq7zE1x8g9VM5/NsA+k05Usc2oBxePn1YxBoc5oEW7p7ap2LnEnolA4YC6XC
         SuVDOKtLUfaV5kGTkcssc8QydWZPMYemFN+ySF+RKKNiPO4scESaGX6RxjYIbcPONuyb
         LrOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GLxOue4aGUUAb+u+O1lnWSd/PqS3vEEL9EE/e1JMAQs=;
        b=CHLnwF6wp8QCjdE+2VC3qHP6gqpGAhsHTI+gkRdtJpJlwbrezyJoxRN/DPMXGiz3ZF
         pfiFfmF+ppm1ChCnh/ruZ+Qgfps/hwFIfIBdcUzQCNjRvsG8IS+vKnkHy5paj55FeViB
         R7Uq6BPCklQtsS+OkQWnWSgvV9JUkzH4N4LrZe4t3l9Ng7nK7s795pfl9U0JJbmKAZyp
         IQ1MhGQVYVrXgQQGr4hGwTPCAaTCJuAofyzcCwzTdylMEmIjadetHUtX8TX1NXdth+YP
         L7gLRI1wLW9Y45inozOIxp/nYDFzKfommKMDJuwuWziHxLqCgeo2YsiXoWEh6Md3f5FG
         Pwdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s7si656520ois.0.2021.03.08.08.15.09
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:15:09 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A4DB713A1;
	Mon,  8 Mar 2021 08:15:09 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C33DB3F73C;
	Mon,  8 Mar 2021 08:15:07 -0800 (PST)
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
Subject: [PATCH v14 7/8] arm64: mte: Report async tag faults before suspend
Date: Mon,  8 Mar 2021 16:14:33 +0000
Message-Id: <20210308161434.33424-8-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h |  4 ++++
 arch/arm64/kernel/mte.c      | 16 ++++++++++++++++
 arch/arm64/kernel/suspend.c  |  3 +++
 3 files changed, 23 insertions(+)

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
index d6456f2d2306..1979bd9ad09b 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -261,6 +261,22 @@ void mte_thread_switch(struct task_struct *next)
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
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index d7564891ffe1..6fdc8292b4f5 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-8-vincenzo.frascino%40arm.com.
