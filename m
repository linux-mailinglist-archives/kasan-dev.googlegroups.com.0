Return-Path: <kasan-dev+bncBDX4HWEMTEBRBM4T3P4QKGQEUROMPZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D47F0244DD3
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:19 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id k204sf3426024wmb.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426099; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ph9h/9u80aXMOa9sy1ybYZJcsIZvlRMyxRFTJmjNZEUEu8uoQic/OFv1zzdeofDG/Y
         pl+OlRaTXyIlxGJvU1ezIPWDaQmOZ7NNhSvWL6JAGS/DjVkzrZBmy4+H8znt/hb7kO60
         A38uMCNsvSQChveVYjdrcE6tcluoPUyuJWBuvZ++8Kc7j2+yBtP1RDUkA2IpQaP4SD48
         MaTKXTHASQRYgSpzDmmp05DYxPL3T/2yeG8F3gUVWTtnhEacrzuQG2HNpjTwmXr+yR94
         sH7GhBr/f5iP2QGv2MbNd7gqr2C/KbntOCInjhx8vQyY6tHBuhPHTM8HuvRhwFphxmNz
         CjLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=w0o5KPICN+7BZ/HlpRqs8s8+5zSpWQcTWtiMCm2GmVI=;
        b=PyrHK6/GeU4bQ2RqOPxb1gTwaTEmy4WYY/TEYoWsE25M8awO4NIgv75BR2qQETQ4CJ
         Bn+Z7nJp/BFINw8UOO/MNihwdrBW9V0yCkmcDv9MOoulVzUgqgY532+e8wflvFaikxaf
         T9yi5/KaKonfEKT6YjQ4SFg7mEmS/d79rxmU4NysQaBZUyHsDuDfnHPBYm28LaZI8jdR
         vDoSA1Ku4jWU4QNCVTg2T+LTr42lazmUNshGxtmoN9pLhEuLctY8+DZAdVZTh2YPt9C7
         BYVHQEpcQsKWZQbP4O1tiv03oZXB9bMsOOaGfr1j5HO1a+VMmFr0E2ePiUu9egy9Sp5C
         70cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wLdpPUJw;
       spf=pass (google.com: domain of 3ssk2xwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ssk2XwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w0o5KPICN+7BZ/HlpRqs8s8+5zSpWQcTWtiMCm2GmVI=;
        b=EGVx7Dg4/Q5lE5TZJ4UvyA3uQE2G10r8yeyqtx1W2KeMMhnlCpgugRICCIRxgXOrLI
         5YiFsPjECnnOOONxs+H04ciQCHNgPHaoGben581/CT/F3h68WJUawZbnhUjF2SFCtpJk
         n5L6b9Ako6MtrVt/J02ID3Sb0ik9jDELd1kgzIr/yOIjQgxV8cId4IUXD3BsIjP7WOuH
         kQ3JV50yAIY+6sIYcZAfCOEBsiuz72C5rj4d/Ssf/tz2GlZhZDPYPkOirR7iO3pG5vRe
         TAqkpsrbacNKtqMwENk9DV3e1ksk5LKOegKpMTZvk1TJj17CI9bH4QkWXSEDspSWIfY0
         Sqhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w0o5KPICN+7BZ/HlpRqs8s8+5zSpWQcTWtiMCm2GmVI=;
        b=osxp8uFEJuNv8HneSmZ6tb+nEvZD112xgHFAS5MqcQv1f4HSQI9xpsPs4/rHqyVeHR
         BZrY2gNVhT8rKvg9GvUYd1o/i8Gc2zdOlQqlphPuy9W/MC6pO9NfHLfJRaSRvUeSz0PS
         MaxLa7/XB/aoKwTFVeft5ZNCJCThTP132h5Bvu0qwJX7GwlEbvX/im4KF69i7A2o1iZ0
         Y9FyWZ1J0u6t3W89omjpiIeFYRjaTOx4RpMINonu2C2Wjawx8clCrF05/cBl3NH8diEi
         E5K0ecmkHys3mVSsItaLss7Tiiz8P9PBUb4EsWikke8QJZUeY9+uP+uYCs0q4f11gMcu
         H5Kg==
X-Gm-Message-State: AOAM533xjERaHarMaZ3OuS6OoCBEiV2lGryxodzHhNkPPUDBJDDpL3Cp
	A6lJ3lZPiF3OM+g7wmfpTo4=
X-Google-Smtp-Source: ABdhPJwr5E3dEhyFP4qh6+9NRMy+JewMJo6VUBHZWjIpE3mo62mUS/trVTVf8VNBAqJhfDeWoproAg==
X-Received: by 2002:a1c:b4c1:: with SMTP id d184mr3608280wmf.26.1597426099574;
        Fri, 14 Aug 2020 10:28:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:b1cf:: with SMTP id r15ls707990wra.3.gmail; Fri, 14 Aug
 2020 10:28:19 -0700 (PDT)
X-Received: by 2002:a05:6000:c:: with SMTP id h12mr3511458wrx.49.1597426099053;
        Fri, 14 Aug 2020 10:28:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426099; cv=none;
        d=google.com; s=arc-20160816;
        b=BPXIJgMam0YQcBeYYraKAxK6XUlk3z6h5V7F+El7L4lTmoVhNBpg70YcY5tXVbPhZB
         NS/Eeez/PyHCu8J1bkDEY9YgKYX5Mv9CrKaFyBKZIrsz1bXYp3YZ/EkC2cg/7N9CRnB1
         iyufwEtAppS2VcTv1fkfZdqPYT6NpsKio6CW+9mKW9nAGHSV/JtGtE/5uhIvOGnZH24t
         jnANH7NTTCC4bOu3H0wHS3Zs+Ge+wfRxlf9SPsn8JRGkNRoAJP1UYc44QiZubq5BBdwf
         5wzkh+bKWrSjorsM4nE4hFQC1oJR9fIg/moAKYwH76LlX6Gp51DSJZ0mfY649RoOMkVO
         3T6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZkzH9bOmKLetwfTAc91nMyZnzSTKk7nABhSXX08ok80=;
        b=l7d0LwTcipL4o49YANSgClorhb27N+feiYNY6EzKqwH8PQp5lObG68p+XBZ6FaIIQA
         dScYduODnMMmKix6OJSBhc2Oisoo8/1sof0SppBLusehV3Qogd5cB6CZWRTJMB3M2Zgd
         +dCXYlVGsFwgy/c8DjaGxzDut6xnNYHgYiCFq4fk8Yc6nKUQq/UOuHZg07WOAPrsbWXZ
         vHJhQ1MJa46E9vj9ZuWI2Mq04WuGlZHSQIGbL5vV80/7CPntBp5ae00DnuaHZoyuB1/M
         7DchoNuHCNDQcCBz70+Y/MZlFmtHWicZazwecdOMp3f3v+lf7Bepn6T4OF/7oiIXwvyn
         rDdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wLdpPUJw;
       spf=pass (google.com: domain of 3ssk2xwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ssk2XwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f134si833086wme.4.2020.08.14.10.28.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ssk2xwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id b13so3605472wrq.19
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:19 -0700 (PDT)
X-Received: by 2002:a05:6000:1085:: with SMTP id y5mr3627507wrw.100.1597426098448;
 Fri, 14 Aug 2020 10:28:18 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:05 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <bf88a783f1c9b6643a96648dac88b4edc8d464d2.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 23/35] arm64: mte: Convert gcr_user into an exclude mask
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wLdpPUJw;       spf=pass
 (google.com: domain of 3ssk2xwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ssk2XwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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
index e2d708b4583d..7717ea9bc2a7 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -135,23 +135,22 @@ static void set_sctlr_el1_tcf0(u64 tcf0)
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
@@ -166,7 +165,7 @@ void flush_mte_state(void)
 	/* disable tag checking */
 	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
 	/* reset tag generation mask */
-	set_gcr_el1_excl(0);
+	set_gcr_el1_excl(SYS_GCR_EL1_EXCL_MASK);
 }
 
 void mte_thread_switch(struct task_struct *next)
@@ -177,7 +176,7 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_incl);
+	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -185,13 +184,14 @@ void mte_suspend_exit(void)
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
@@ -212,10 +212,10 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
 
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
@@ -224,11 +224,12 @@ long set_mte_ctrl(struct task_struct *task, unsigned long arg)
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bf88a783f1c9b6643a96648dac88b4edc8d464d2.1597425745.git.andreyknvl%40google.com.
