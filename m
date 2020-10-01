Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOGE3H5QKGQEJMSBFWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1502A280B16
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:53 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id t10sf37188wmi.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593912; cv=pass;
        d=google.com; s=arc-20160816;
        b=IGv7FchOB0MOT7PCbmhP2iFjaiwpTP7Kf6hcTi27tzKTHokrijr3Dlfc/hd6mayBfN
         vY9QEeS+A85bNhozcvCai0aI8Q9vWLrzCxQLmpJgGzPinIvqHGwwe4yVDJsGtewhDO3I
         tStEhW2vzyxWIENjsF++yBItlqg4iJRqLdqGun2H8DJsyrF+pLYQ9/uRH0D6cOv07cfG
         tNWiUuzrJfg7XrkSu+oDKdX6hPn4BqmwlAFn12lbuy1yvtI0UO39mFRpxkV6WntmLQ3X
         r48XDpMC+HIznVKThLv9IQY30132Ad4tcixARpoabyZJvrwVJi5yBh0zA8Xr3H9Y0jw4
         l3Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5gFOV1ZkBsFj2kxaL0XlZbg46r514o3vCdNJzN7oXyA=;
        b=SNEVAOIB0/aJoMCY+iGAtGEVYjlS5v11llaUlkaTFBsIlZyHRkpyECQDzV24aFV20+
         wuID/cSiaeQbWyoqEnkQ6wku1g/UYwSi3rV4hLBu0Jq31azkNnQQXDMmcULsmx8FVPl5
         tDXsxyIduGhEPqnWioPdOj+5dKnEPExZfZm+NpHxKPg4qWHpYNbZZyfsMR+2Qn9F10Tc
         1prU16mZs8BEHScaMaBK2XXopPDrKZOwg+s3fOSvjns3t72eAddoVdtL5MoM4i0/+Gsp
         SVBDVYKoOmZIBHbX3YueoyuE3tahuj0Zad5dXyhnKk8jlA9/OE+W0/UqmCQhRBb+lGBP
         oTNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qB85PTWw;
       spf=pass (google.com: domain of 3n2j2xwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3N2J2XwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5gFOV1ZkBsFj2kxaL0XlZbg46r514o3vCdNJzN7oXyA=;
        b=JMKwKvudbeSz5iaBM9yU6eFmfQPUMisxYTCnvk+F1ST9Up8UfHmWsWbBhR3NmE8M1X
         CBpMP3D3g+HGnZyXFt6K0BpR6im4u7IwF+jCwyBktL3SBenoS1VDE6F6U6YNlVOhxULx
         XAa2LbewkXm7rl7Xvzsw4W73eHfqUpP15eQLf551oIpvdXogxNIGMguGLTXvG8kMi9rT
         ho7HE5BD0edrp8ifaLCVaZui1c15aO28vY1hZK/4rId0Za3V1AV34Vmozv+j9T/3EzaV
         b6/zMst4R963W4uIxqxiemy7txR9zLuYjZjje7AbtAwr9A6pvWt0HHebJfdIgtT8yGx+
         qL5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5gFOV1ZkBsFj2kxaL0XlZbg46r514o3vCdNJzN7oXyA=;
        b=aFAmbT0lpPfcKGGDTzkQx60TiKUll8eFa9j1MyT9qRFZvPgW3XVwUs9jEp73P7b1RC
         y9HF6E79JG2M08pf50qFw3AYcVfg4LK7RpOLUwKpT5MAx83dajXiqo4GhXWr/cHa0mMB
         MONSAHZT3s9iJAy2h5Efekw+KQljfYoxc+xLhNHQpkmExYfpqlCl3uqVaq5R6xBHytL2
         MfOy/cLU326u7xaYuwx9ASUaR4T6XtZEDhZz3PwjmlKGoas91z4THg2cESdUFCSvAobL
         kujatlRgvT10HmwU2Atkq6AlEodU6q6VB7SJX0qTc8wmwquHxAPKa0lKz6rWu5/ROT6m
         6ihw==
X-Gm-Message-State: AOAM530c86ngUXiNO4OxBQp/TKbHjqtTv92j6ndtDfb5VBgDGVcoG9Th
	uJM7jiUpS/V1Y0DydXTRFHc=
X-Google-Smtp-Source: ABdhPJzMoraOCVGFRhTA4IWq3zz9yy4aiyj4+Fos5UAcm5B3V+qwFpCqOFHwcvWBoScHdl2vgzhxvw==
X-Received: by 2002:adf:91c2:: with SMTP id 60mr12388992wri.292.1601593912866;
        Thu, 01 Oct 2020 16:11:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls8626119wrm.1.gmail; Thu, 01 Oct
 2020 16:11:52 -0700 (PDT)
X-Received: by 2002:adf:a49d:: with SMTP id g29mr12255102wrb.219.1601593912187;
        Thu, 01 Oct 2020 16:11:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593912; cv=none;
        d=google.com; s=arc-20160816;
        b=oPH7DmdFF+wFcg1GRrOkynvJyCB8wRTZ3BqsgmdmcMNiGC9Ugyn7jXuZIVBbVsvRf1
         8DJ6XFMIBvSl4luLiH7s+rPW6jk8yuCNqHWmjzQ46DiCkJNQtsQHkk8g/lh0hwYVDWoF
         FbB53x2KTIYnMSNxo/bgVXCh3xp+1ymqTkMk2LldDz9Imv5m8OpB8aeSRQPopP6qqD8l
         7rwrHpWUKTKlX6OXI54BsqUo4D7jOns9S9S/FTTMBOzS5xmNpods7ShiTK6gzlOYDlbk
         JJTgmFFUA5xUxvU713Ox53bPILza7wlmSWTIfA52d0RigTuu8DKkPQuzBtLOSas40oZA
         /NjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ju5gjpNN1q5eXNRLUzsJquEOFzdpbcw+xVgzFDXZ9W8=;
        b=FiAGYsnoFdcDpRtfhJaxkCDUgEn7t5Mi4niVtRoRjX7HmG62CmZ4gWUtiKAEnAIu28
         Iv63qA7hdx6JsBL9ItBSZHHDfyFI+o30PtMnnJTWAy4bw+gaNktRlZ+wdYvnhXduekYw
         w01DlQMXmhn5fVNkWD7NnlSQBv1Y1cABbLt0m3UyT7iLgnL1Nubw7RfJvaIu0eS8eKFu
         +5tcNfqyTjodV1JmOAv5vXWKfSmosJ2SwBzeSPWstKfaDhCnxqzpAtUVmUh8p3wi2g/v
         +w6FDT8F5FXQKNaG5IJ8br6Uig4NwgMhyOewBI1CmfIECrqQXGV4PqSkTC9sYAev1zsz
         ekHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qB85PTWw;
       spf=pass (google.com: domain of 3n2j2xwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3N2J2XwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id v5si173883wrs.0.2020.10.01.16.11.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3n2j2xwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id d13so111645wrr.23
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:52 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4e16:: with SMTP id
 g22mr2156826wmh.99.1601593911698; Thu, 01 Oct 2020 16:11:51 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:29 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <83f7e87c25ace381acdd5846775e1949f695158a.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 28/39] arm64: mte: Convert gcr_user into an exclude mask
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
 header.i=@google.com header.s=20161025 header.b=qB85PTWw;       spf=pass
 (google.com: domain of 3n2j2xwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3N2J2XwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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
index 8f99c65837fd..7c67ac6f08df 100644
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/83f7e87c25ace381acdd5846775e1949f695158a.1601593784.git.andreyknvl%40google.com.
