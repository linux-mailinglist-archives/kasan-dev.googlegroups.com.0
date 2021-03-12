Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLXSVWBAMGQEPQGFXYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id BFC9C338FC0
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:39 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id r18sf14217874pfc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558958; cv=pass;
        d=google.com; s=arc-20160816;
        b=EEZpbpbd4Ey+yxZWzVnV9f6au/VLyiFoifGkylv+JdYOLKJytccELkVWkBPzf05egi
         WWfFuQsW3bvQCxcHiPzpkymJMlSwgbEhy+e49Kx/tFWQc2qfQhlOdwrKAzjVbw9Wf75d
         rhwnr26MiTdGioyvLDMSNWtwL/oUCur+pDCaEDMpjlJrhzfwpxQeGFzOCp6jmBBWXiv2
         4krJi8+BK8F6jSmTy2pQlpF2ipsFiA+UiNoA17N7ABlbt/J+PFWJZycnHbwgxY+9nbbs
         aTF3atBo/RNMtzaLWUWOgu9B+pO6ZosseETWbZ7s1YyfOVedEi9Z5OSUcYCNkSLXEBD0
         1BpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5v/k7UT5X9IvlG6OrUX2rTqICeJ/kPq2wuALkmCcUBU=;
        b=lC/hrZYlJ+08+bkhbh0lUstDXd8j/oA8QXdKJtqoIiELnF96L2qvSKpiWkyeOmxFlV
         QOJQlWpO0zE7M13V+NekLFre6+V2olQZhWzyBxTAjxk97uemHRFzf9I5Zh3Zfd+nndbV
         yQo0vFaYmAAodJ8MfgmS4n2LMSDW8WwfYJtMch53eTsVjtdJzvy7uhpvU6dWOCgXItN8
         5m4sK0UQPbPul7hP0UWmpujwJg+2U5HwU2xtq0DkxwMav899ViTHKBWQ3NZvHU8NV03j
         cjTHPDkYDtPT9ypN1SASYtJuU6MQ8o6tiUe0trvwxMgTbGBXQTiEfok3czFxgb6gxvze
         IaFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5v/k7UT5X9IvlG6OrUX2rTqICeJ/kPq2wuALkmCcUBU=;
        b=EJZ23wzt7IIihTgBZrE6KVhB3aBjiahGGCsW8AP2+7o0v+iXkjqWajoVMnEgX5Fdrw
         sEZa9OzeK7EPDmeLyOfZCRi0pYWpKIl93Fk5zuO16zoj/aOhe6sjv4kzDfSOgtVDEYfF
         0HbvpkKpv0eCQtsFxJGsWjTPm6YNm2sWEBnSKCUL4u681qKq/XGRl7sjOU0N5oGXTRG5
         K7TxVLCEmDbdUT+2IRRE8moEGO98WzbXn3WGHkYPqkWeNSTpEhLnHm2CpyWt6xEZSCnG
         0q2eBTxUljQRLIQw9nJvpF8K9VaLc9VxAPhAjELiomsQBCBeZcsSsUBxnjzfOBtkIT5+
         NOEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5v/k7UT5X9IvlG6OrUX2rTqICeJ/kPq2wuALkmCcUBU=;
        b=RfpWu8DbaFunHG2T6Q92yxvj88lEBe55dDxOorf8glyZ8m5riby0Azj01rl8ICkBRN
         a//lyqQosqZTWqXjvQTgpqxZFE1OJ7g8vTOAZtLMOXA14GEUoO02QiFcwgK0oK+ydZBF
         mtnC6mt2SWsoN8558zwzCzxkRrpBEWI6T2wXjx1I03GARVQMlcjsvV7w/NsR7aNsI7I2
         ziJ8Si9poH4Wbkkvj2cd6e22z/rATm0R4ZRjOVeQrke1Tx8jTSovp7IM26moBIafpBd1
         FpkxoE21tROLhDPkQK5FFcJjYiJWJIJfKYaR4G+ZKPc6K+3yWKUHQlqxoMvhK49wqSgU
         UBKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305qkDMSafY5D2f3NLxkoTJyanQJSIcasLTwOE3Eer/3fF8OEbp
	POfEfgt9b7EUjrU7KFunwvY=
X-Google-Smtp-Source: ABdhPJw58tthgdmm4Ok03TSciV0dIsnqyRIKrWYl22sRuTvUl0+H5rWajkWJZIblztz/GnFiITldVg==
X-Received: by 2002:a17:90a:3902:: with SMTP id y2mr14581263pjb.202.1615558958471;
        Fri, 12 Mar 2021 06:22:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cb0b:: with SMTP id z11ls5302213pjt.2.canary-gmail;
 Fri, 12 Mar 2021 06:22:38 -0800 (PST)
X-Received: by 2002:a17:902:d905:b029:e4:64d6:bdb0 with SMTP id c5-20020a170902d905b02900e464d6bdb0mr13607985plz.7.1615558957969;
        Fri, 12 Mar 2021 06:22:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558957; cv=none;
        d=google.com; s=arc-20160816;
        b=DuEfnOuJ8Sbt9cEfnNpu6nFiCqXxiqWGSzfIExiBd6sSrbmF2WsWJXH4RTimyiHC1j
         XJCiTB1BloPYqlcZ1udYfGrHtXdsjyN3fjWWFes3yx64bl3ZUrP0B6+PS0M5F1l2Atm3
         E+eVVkprfMJg/44piv60B0f3N/IEGwXYZ6LA4Wbz3kz7O4fBELJ0kHz4/wMc3VUfcu2w
         t6AFE5Kd2koFZ2pyqSfsBoGCoqfdv5OfUKIE+3T6U30idYa/6vxNF/zbaPhaX6T/nBrL
         raS6W7selUnBsZjNOLkQj+2Bxko7h4zDxc6612Veor/sb5lJPa2qGTfqOu6Ja8jLCiBc
         0HSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=LcFWiN089xX3UZFTc493tMMbqN0zg/JUnok0ZEf1ZR8=;
        b=EJjUKd05Ogd7y2m5c49llixyew5UO99BwYKnXc+5uq5KEDeOisIiPAcdWHDJQel7TO
         kROejBYxcXvW7xPbj5fwRgYnHnSpEoZMs5gjBCjfMhC+Xb1UljtjetU+JpLiOWODPYGh
         51Chi3nkKdd+426ft1ZiAzRTZz9bYsjU7PAcVx9UM1yfwyReGdKBC9Hb2SrRIsqPsIpn
         O78J0URmLVb2PObmQux2aketrPr+wwW61xIekuaYCzLaMaLHQr+Hsc8HwWq2MfLH4xKT
         1/X4frwTU1K916xqteQ++8nvm1TeA25UFS05lpu2L22515A0yW6AOGU/YeTA3ir62ET2
         G+lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e8si284295pgl.0.2021.03.12.06.22.37
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9D8C51063;
	Fri, 12 Mar 2021 06:22:37 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B9D9B3F793;
	Fri, 12 Mar 2021 06:22:35 -0800 (PST)
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
Subject: [PATCH v15 7/8] arm64: mte: Report async tag faults before suspend
Date: Fri, 12 Mar 2021 14:22:09 +0000
Message-Id: <20210312142210.21326-8-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210312142210.21326-1-vincenzo.frascino@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
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
index 9a929620ca5d..a38abc15186c 100644
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
index ef6664979533..5d3205878236 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-8-vincenzo.frascino%40arm.com.
