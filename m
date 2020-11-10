Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRNAVT6QKGQE5MRLPSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A7332AE2D5
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:23 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id l14sf6479ioj.17
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046342; cv=pass;
        d=google.com; s=arc-20160816;
        b=j0SDbIMeJddCDtL3m+mtdGQJCC8skFKLtBy7pdHP0gF0fVYerolUcHFqnhDdyOUAgL
         yiKqtLIbPMKgTKiRAuECUP54/SDqQqEFiIY9o0ZVD1puoMX4W2mfINTn+f3X4l9l/hIC
         7vNmW79nO/N9coes9mE/6bCJmMwmhBl3A+2w1aZIs4U43N5jHVeBkhugOYSmJoz65mrb
         G22JAZek9S/EsUS9vZ9ozOzIkhb8ZassdfROcRd2Ssjgi+jJuOAqewt3ZV5u6l4FLyZn
         Fws7diMr/0F4Al3jEPJDl61fhiewjjpXVbGYF2rLpEB1I/L7nL8ufceQzQssIwq/mOAc
         OK3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=xnQ7O0jxx601kkt5FT486TIeXeyT1geVkCxXJWDvltk=;
        b=V6GgDwGEVWtUzaC2H+3DFH3Pxbc3cj8rW4amu594Q9j8sxfefU8ZGXF2EP7YtcFAEw
         q+rw1pLDHbJoarqFjhYM30Et7wJWpAIkUV6GQQB8WFNcl/zM+s2W6jSeAipHWE5PYm+j
         FfFaFNXj4JdVDrj+0NOU4E3i3STpYb3Eun/07sB8kly3OZ8hCjFNEtIXIzBWKO2o9+Km
         jEnoJU7b2p++tVDFP2A+e7sBHGyFojAz41z0eVL3/4Qox9Jwu26YfiUJdvCbwxOA5Q5b
         P/Cj8BFfp17UNu0odGUjIMG9KMUF3ppzb5fpNfmNyost0mVxP4PfiCoYchRAbF3H2aJh
         nBdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fbHtSPL9;
       spf=pass (google.com: domain of 3rbcrxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3RBCrXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xnQ7O0jxx601kkt5FT486TIeXeyT1geVkCxXJWDvltk=;
        b=EPwIROjiqxtAHDM57EmAEisV11k1It0l5Avzr/Z1JYdTxpybiKJ744q18lSiqQ00MA
         i+7jJz3UFnCCT5GHNYrmoiVqhwMyfu5MD54JLH+abqvE9J4GRIBWe0GnRkgFQg3CL/pT
         SHBjac75fODxuBkdom4XmHnyn4DVo6tceJSMFDtM5+JOnK5NVG694zSP/VdHlKpdBdZk
         0Wp8EONLYi+I7zn/HoTUfX4U/fDlIsIfWGdJlrTrUC6nnlyZyecjSUCqc2LFmJyN4Ipt
         sgwf60fuWO3uO/9M1Ne25vuhlBeM9Onh/xBDLTED40w1fF+WwE+xb3C0j/kuQKUpg9Yg
         GXrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xnQ7O0jxx601kkt5FT486TIeXeyT1geVkCxXJWDvltk=;
        b=O3qiIrVLGPaHvMfS71u/OGYAgJFi1PvGp/1Qxc1ObIoi9aVZsfv33dTr/LW+b/MLss
         lbPS8t7jl78P5GM6fNGkcxnwz75njnR4ITZSbfbAqpysXou/iWScXLO0AGoCaO/ckdRz
         ux9gSxaZFBHop5cLs4E1rSJ+uVzeZJLVxyKMLVo2Tf4AwbaYNylUykNFn2ecX9SEGKfR
         xR4VlqM+/OIArrQfswBTctippYTAOY0Rt2ep7GxP7nD+Wue0WxcXiF4iLrdtkwpLVJ+7
         yOhlUGJCVjGVuuU4gYGmyka4Grux8SQ1mHmKvKAeLE8MYweVvxmIw2yYn908+/oF9IFV
         +RRA==
X-Gm-Message-State: AOAM532Z0RuBTDdmIG5/dQhXyqL1qAuJzTko1Qdj4u+715OxZsKoZLlO
	A+48/ujUiCHw/QAl0iMksZw=
X-Google-Smtp-Source: ABdhPJz1ILxQMXa4wu0y/bdKi02ZaNjxcKcInHzboL2KHUPv+UYju6o5prcIo1y8adN1iPgxERFyPQ==
X-Received: by 2002:a05:6e02:931:: with SMTP id o17mr16418651ilt.273.1605046342008;
        Tue, 10 Nov 2020 14:12:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2681:: with SMTP id o1ls1523763jat.3.gmail; Tue, 10
 Nov 2020 14:12:21 -0800 (PST)
X-Received: by 2002:a02:5b09:: with SMTP id g9mr16501242jab.89.1605046341624;
        Tue, 10 Nov 2020 14:12:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046341; cv=none;
        d=google.com; s=arc-20160816;
        b=ljt214dwZUX/KUVvn2xC09LVGabb31hsyAxOBHu0l8ODVAsHDL1MJ0dGyGGwl7J/Dp
         LJA/5LRZVuk4EAc12vrm2dnk9IEVi++QuR27kVPtfGCCX2843feWoF2EE10hID2Aztxx
         8wE4PFweB68GXNuMpcXOKbwYqY43RwIWH4NfWmr2s7EJYYgRlyvhOlGVs7FJDn0py7l1
         Padwr8UEkRecEuX6ZToCHJr8yvQIJQDcn32OfaWbBxpCwPOuVEI/aNYRCGGx8fEqZtdw
         P2EDHyQT3naTfuHOsiQTo6En2/fBL9zyP3L9sIAJhxfu2ylidqNmfjY43mi3fJt4tp0M
         NHoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=aitQWhpaEU/uSCKzI+XDauotlYTbLDgdJFQ9/bCU7Gw=;
        b=kzQNPZ4DmXjcLj4ZAe7ETi7LOw7XVTsdgzlvmeybzrBpyp9Bj4mmfeMyUZCMRyrsNH
         C1tlOEejiQY71D8LlhVF05cVg3AdrZl4KmVPLhxE5N1S9dEcrSBri2bx+jR0krfZs5Si
         Vb5S+irQQx72elR42wuv1I4KSJp8gzF+j7o1aErwM6IfTpjmvQW60Da/owVr38csVzsP
         whgI6M6Om59Tci48UaPl+w7y1rNW/VYZJJIbmizfHpojdnGORBXB9FvPz+L4O0bz+k/u
         K8XYYDZh5tpy9DEPXd3M6UyV78DEmSMvGyAcd9EMiok95O+hsH0TywSwUtgJw6mzU0Xt
         YxPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fbHtSPL9;
       spf=pass (google.com: domain of 3rbcrxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3RBCrXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id y16si5464ilk.4.2020.11.10.14.12.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rbcrxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i14so8447232qtq.18
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:21 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4e34:: with SMTP id
 dm20mr22011918qvb.40.1605046340982; Tue, 10 Nov 2020 14:12:20 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:28 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <a5242d8eaa3c305c068aa531755eb78d0be5ffd3.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 31/44] arm64: mte: Convert gcr_user into an exclude mask
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fbHtSPL9;       spf=pass
 (google.com: domain of 3rbcrxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3RBCrXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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
index 7f477991a6cf..664c968dc43c 100644
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a5242d8eaa3c305c068aa531755eb78d0be5ffd3.1605046192.git.andreyknvl%40google.com.
