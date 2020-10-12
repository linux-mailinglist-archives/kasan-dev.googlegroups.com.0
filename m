Return-Path: <kasan-dev+bncBDX4HWEMTEBRBV4ASP6AKGQE5MU23DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7905E28C2EA
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:12 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id a6sf12679649plm.5
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535511; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZL9o2GYI7nrn4AkmwlO4abH3aOXJW/FExTJ2jITsuBrF+QL+1U/XxIc3U6tt5U5fei
         xUlg0/uSw9JiUy0kBR4CnftLmBQGgQBe+nBukdsbZz0Z+YANc2raAk1Im0uZmgF/yrqF
         zhgM3u3/8M6nQzIH9lf+JFfp0BtUYnM1LSjQJe5diqWVKi0eH3FtxsJKCa8J5wCcS70o
         ZNP0IHKYEZewrajR5bW6pLCwP1loFsCJEff4cZu+k6nA3iklRYrj/wdA1RB4ii1Ghayc
         LdnRNxO0PYVQ/WN3tBcWykNFh8EDsJ8JGtN5ywHR9hFBKwFn2Ab94Z++uUQ6KDwvaEIl
         gsoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=QA0kEZW0tPtEcGLp2yUEBWmVOap3Hv/qSaPIcs5vGds=;
        b=tbebSdSNQxex/64wNjMI3nMpqU/UbYy8azyXukbS51kvMdF2IuhTSCzFck7pRlHPJs
         do/lDSusg1cOVfwkjmLQWuPWsLkWIBjo0e7VMmfOK7ERahBOhvMhV8aBZgm+aUO7uTfT
         xeC1a+lZGD7ps620ZKtyNzSJPXMJUQkE+tkdaNENezYIe5R1x4nnVJvWLdg6+h4FeUJM
         GEiJ5MMWMDCNW4jNCoBtajTiKVj3xSdnDdHdfZc69dcr7eGVNO6lRVtm6qyAxpv8t56K
         oK7aMI8gseDF3dY8K5bXECaukRM1wcqbyfnmtRxzTnkZjyKhuVXjB0v7Z+e0/jJfD8P0
         rO3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YWuI+NoC;
       spf=pass (google.com: domain of 3vccexwokceomzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VcCEXwoKCeoMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QA0kEZW0tPtEcGLp2yUEBWmVOap3Hv/qSaPIcs5vGds=;
        b=FPOHC4l0slbTf1hdi9qs+4HbBQY6KYv8LbBdYvX8TH3v4OHiRKcbvtFVmhbPW07xaH
         v3elnJalmA+CNXdnbSIbBeaJU57QTjriAMDJzcXvUwUyWG6jrD33iT/eoIRfUx7CdxF0
         qIrmBZF6E/SxyxJMk9jMBnelB5JTGLeAZSvaKhvGBa1PFCqfVTi+X5prl9LB5hg3bxMw
         3ZxGpt5q/SmfJKebeePj9Rxj8gYGgWetA5aoVOINGRWLKL+4dEHly7ubcH1yRvQsmT0/
         tUrsz1qqPydu6P2UZJvjIcn+oTQRMQenk6STFvDdTUVmRrEGs5R5xQV361PbHealuTsO
         /VQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QA0kEZW0tPtEcGLp2yUEBWmVOap3Hv/qSaPIcs5vGds=;
        b=dGdjoRfQnovJ08kAMMVa/9x3+3vxG+XVWVuasU/mhnH1u8OaBMK/ER9N9oaa18LkJa
         rk8f56NVyg2Kpec7uzncrN4vFurmtgCw6NuetrG15edAP1BARPqWCNGB1Gpnz4kdmiEP
         wVae5UgWrA4kcWVt3h/T2ZZfvaI09AmgggpNQFR9uUhG5VYmCCqdgXMhg3itBoNypzd9
         0Cu1SfDsMacyEMvad/RQGh0k02xj5hL74zKZWNw5n2g4a8wLAewhT7wz4Ei26Q8pArMJ
         +0rJoGfmAHCd/aTXLbz/2+XGAHR56jkj+zqI+0m12qMFdB2aTmjbInlZct6sURa6d9si
         mfgw==
X-Gm-Message-State: AOAM5321xFlypJHQtpKXjwCq6ruk7WDue6h/xemOCj6XwUkK2ytQoPrc
	JVeN9VwqbJSFcl2aBdowqT4=
X-Google-Smtp-Source: ABdhPJzzyfH6Q4fPAKyxd1OE0+3Fog0MkmPc1zJP/qjpoSdtfdVED+PvbtUjYV+imtElJs6v5jD2OA==
X-Received: by 2002:a62:54c3:0:b029:152:127a:afe with SMTP id i186-20020a6254c30000b0290152127a0afemr24359111pfb.79.1602535511204;
        Mon, 12 Oct 2020 13:45:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ba81:: with SMTP id k1ls8095622pls.5.gmail; Mon, 12
 Oct 2020 13:45:10 -0700 (PDT)
X-Received: by 2002:a17:90a:bb81:: with SMTP id v1mr21597369pjr.62.1602535510665;
        Mon, 12 Oct 2020 13:45:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535510; cv=none;
        d=google.com; s=arc-20160816;
        b=orwr2HfSEHleD/zz9WY3Hay0KTXOnkIVAX3dDgZCXH1Dbey52yeCe/OXdBqPHcDPEQ
         iM8xUpkY96rX9u0hKPj0/qmMU7wVBv/1A0UX6py2UJZn3yPadWsgcWKV8h0/wXvwV4CW
         HvSLDAwu1RDlFxlYuUgQgFvMcVfOgZ2crRTYOR41ipe6yL8OHSit8FQ1Paa0cOvtkIn7
         XnaVDHZwgpqU2XmgUV+rJAnxGECrUsQkHJOpMWphbKvHiw+kv/UHs1I1zi3Pr60To9wj
         2Kqxz2XCifNFuvqhRqPrzlCtGbJIe1KAM/rOy3kFSSuMWEn4B0eh0gNf5bngiTdCTZIm
         03iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=P3WrMaTmC/8Awoz0WCiVL24+THxtheuZV6C/x998Isc=;
        b=yy+zAT5WQQ8oxPKOAIjFPMtpiwXK/IQgErvwu/jE7kKibDKAXBWCGtivsKWpXJY2j4
         9zc6f+nFO0snBW0lD1Y4Do9WdRwscDe4JH7KnRjZ9CvFsQD8s11pa4aS3u0NhaNYVBQa
         s90etRcB83Or7pxy3e5YBmU61xgdCxDpvLdQiyrf+j6mRFUGxNGOm+lUjroYBTBO74bt
         PovC76IgmEeRusXYk4OS33GTcnxXSvGkzPwltyHdn7GAUSJ3Udbdfvkly7ZZAolYQvJQ
         7gYNkAyRr4f6v2wvZRU/yTc6Y18JiI0DTVyMMhul+XRhOb8gLAPH4cT1+0kgO2cHpIXH
         6GnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YWuI+NoC;
       spf=pass (google.com: domain of 3vccexwokceomzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VcCEXwoKCeoMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id c6si905778pjo.0.2020.10.12.13.45.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vccexwokceomzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id z9so5218332qvo.20
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:10 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f442:: with SMTP id
 h2mr14581132qvm.55.1602535509722; Mon, 12 Oct 2020 13:45:09 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:13 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <61abc8f917bb161cff39ada051a88ff20ba3f7ac.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 07/40] arm64: mte: Convert gcr_user into an exclude mask
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
 header.i=@google.com header.s=20161025 header.b=YWuI+NoC;       spf=pass
 (google.com: domain of 3vccexwokceomzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VcCEXwoKCeoMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/61abc8f917bb161cff39ada051a88ff20ba3f7ac.1602535397.git.andreyknvl%40google.com.
