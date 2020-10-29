Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYNO5T6AKGQEMSS62UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EBCB29F4E4
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:27 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id f128sf2701522ioa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999586; cv=pass;
        d=google.com; s=arc-20160816;
        b=LSbOYwDk4fKIPImh2U2pdDWlQOvIthqeYzFq6bxTqD8lNC7xvXE/dWPlD5jC+ArLlB
         bBnMIWTu3NfimxLtCzyGn/C64wa2fIkx8Ck6Furqt8y4TMSvTHmyF5/w95X140cDRXP+
         t5t9mlzqppen0NRTg+LSgnzizgYj9oLZnTpYuSxamdbdE4HD4sYSLyGwszKsQvZh64B9
         jzn5Pa3/fjSefoVk1GyFxBFjgQmfe46HXvLqVcgBoDiv9Ei/5Bbk2oc55w3OiLgwQgeB
         +1ENJtcAef3t3s/0+F2mwrFQ6IbwoS0FxAfCfVX45iZ4PU96heSjbBE/ZVOKPH8UuSiy
         nOQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=S2U8Sx3RVQAu19ecWQxJkMKPEdiNPxmnK+ygkqEh+oU=;
        b=wDcis+ul+WG+vcTMWdWi7UD9HnZym08PMrPTAfzGvY9hnELdBMLAhGvteFxq27XQoA
         iqscnBk0z8MwS3wbGa8MH8P/TcNSH6ez9ZnPPYEjSQCY0jt3dg9HNvRAJnl75Ht41mPw
         rXF85C+7HlitagZVtSaNKFx5M7va5zTcwK7dsLcj38ciTpQOBwnTahDuqeRZY6JpgK/N
         UU2B3WIN5dcNgK2opSYQbyolTjFKsLAWOIum9qQBOpikJYnRCeXa9HOULXSPNFStTsS+
         lpmB73JXBql5VCJ1yxKWBI7B7bD4DuyGRRitON3iqLzETKSx8R5RmO/rgczhvizRd4By
         5AJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sj1oPCpa;
       spf=pass (google.com: domain of 3ybebxwokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YBebXwoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S2U8Sx3RVQAu19ecWQxJkMKPEdiNPxmnK+ygkqEh+oU=;
        b=Qdb8E1VlfP4k2Kq42aWoTrtPMloO15D5ny5IGEpplwSP5LWkwecJYaS/Lr0Fis5laV
         0p7IQYFcCOA/SuxEzAyibGWTQc248NKMpXNx3Rh8jXa5zOhEPxjAhmXtFYSjKsnRwTdR
         vimdaMebykjsLzcI0HnAT0hfl+NJMLjfahXFbI2e8GqRVVXP8i4hcWZtb967Hh62OV3K
         IwSmCQ+CuAnxBIlza10sXpDjabp7oSL4cYRN1kaFIed4pihnogdGQ7/4MU8RMYrubN9h
         +mOOJrUMfmPhXSLQ2XGS4rHC8frace7ILD99IjAZv2tBvPZZSCPuDHAwYbwxPddy5aw7
         Ok7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S2U8Sx3RVQAu19ecWQxJkMKPEdiNPxmnK+ygkqEh+oU=;
        b=hCo7flFGaRDTChBmPqSeKK7qWrIz3AAs086UrfP8UqYiekc9uNAM71eaBSXerpW4xX
         jPxOo6B/M4dZ5Y4dHpQ/nrTmU5tzO3yQBzPW8eYF03NPbGChAh/b2kmvAG4J/kOhiudX
         jq7PrsaK5njrRFA0IkojlUMUOaPai3JBVO75R2nXI/Z4oqTE6l1yuAERdkCE6tQSeF8+
         PZ9P+rZb9w5KEzZ2mil/+eXHw/lt9DVk5YqtOXltLpXoun21MvRr6ltOep+VYDldv4Db
         dHqEJRuT8g3xrMaqKBw0VZFjN3xnoaa+nxeuZ04UrGXRfLEyV4xYflFEjpyAAdge2tMJ
         bLoQ==
X-Gm-Message-State: AOAM531/xzivETMC3BmJt0AOlYwcrNGFag+AmBo2EJDdCKaCX6BT7EOU
	svNUydVoRZdnPaNBmB8HVFk=
X-Google-Smtp-Source: ABdhPJysVgCgEnI1uTr2Dg3yEBhqycZLq69QRO3B0FLVcH22Idl4H+qKahH+SMEMb407xgsnQqIKxA==
X-Received: by 2002:a5e:9319:: with SMTP id k25mr4758250iom.153.1603999585315;
        Thu, 29 Oct 2020 12:26:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f41:: with SMTP id y1ls945210ilj.2.gmail; Thu, 29
 Oct 2020 12:26:25 -0700 (PDT)
X-Received: by 2002:a92:1f19:: with SMTP id i25mr4695547ile.198.1603999584949;
        Thu, 29 Oct 2020 12:26:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999584; cv=none;
        d=google.com; s=arc-20160816;
        b=Wm2Iis2lRsjKBslTczPYreeNqQF4mnBeL+9n++e9VpqvHtcfKkY1inhPuU4bskJCAe
         d8yCWvy0+zJjIucencXmNRiCggkVQI7JLYJ23JQrVXL+OFkz4M47f6kDGQlO+zUP8pJl
         2RdMvkFDvfdShjRo/j0QNdnNONFOg7KxSMNvweNm7MG3F/N+OMMDRwl6hiKn+r3eccxJ
         +0Gf/VHzHgn4OvaF/fxqkHkB7pOVSzzmzLmXc+tihtS+FmzYnkEB1Sac4sUzZ9x297to
         fcFzxvfTt5iMLeNCe267p/ZyWMwrXmzgUOEBqcKrinZGo2+A5T0KslASoa1+ZaZAlkon
         iWQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LscJFjoJLVax370bbjjUkdBy9lfnLd5L4hR3aqcqMxs=;
        b=bQP+p6fDMJPmE9qxxn0cDunf3nn3oLQ1SXLuv6vT2IA7XDj/pjlbjmOfma1eh5NV8x
         h+nE2326+7UpfkzAPxpbSPei+Kba8Qjvd68FXmaWN87d5kZYUaPtCj17jZIO6hHnYn44
         JKb5qbwXGkUjGFqJ9DZKO3x/h5kjUgyCObSns6H/jbZz3VQqWWp+X+HR7+gXewRvvDdK
         bO8H+V4LZRnOKIbzBXQFPWQ6yGuj81m2tcAMk9OVok1oZJ1EDjL6Arm7Uf48pbRfJy3z
         KasnecmgxJYTLxNtNFrzDcM4h65VSj5UYxnrikgCf5Gy2pBs6Vo/Z1REYaO3G1KHVuIP
         fFKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sj1oPCpa;
       spf=pass (google.com: domain of 3ybebxwokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YBebXwoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id l1si157746ili.0.2020.10.29.12.26.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ybebxwokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id a81so2430728qkg.10
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:24 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:17d3:: with SMTP id
 cu19mr6192488qvb.12.1603999584322; Thu, 29 Oct 2020 12:26:24 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:28 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <360a5b6b49a3511e116896fa6d775c276f150842.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 07/40] arm64: mte: Convert gcr_user into an exclude mask
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
 header.i=@google.com header.s=20161025 header.b=sj1oPCpa;       spf=pass
 (google.com: domain of 3ybebxwokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YBebXwoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/360a5b6b49a3511e116896fa6d775c276f150842.1603999489.git.andreyknvl%40google.com.
