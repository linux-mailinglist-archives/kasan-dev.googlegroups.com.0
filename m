Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDGGWT5QKGQEJHXUFCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D72F277BE7
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:57 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id a6sf324897ljk.11
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987916; cv=pass;
        d=google.com; s=arc-20160816;
        b=pOb3jNlzBHC3jwBBdWK6vPf+yqPyMpN6SdeM4h3K9an6iYLcYi3vNRaWh+DFOmgRl7
         HRY0vMmCuz9FFRpsObY+/zHiXaNwYdQt1TRZ2GOlX78h4uEX4GtVlkFLa0rFUilyWE/H
         8DguFr4l0VN33D40Lz8A5yzpjQg0/PYCkVx50cY1jbYFHW/Mb+cFULdAVXNF27YOizlC
         bPCiJITu/ITGgdHfPnYSYT+PFtXCxm9JaCajG/qzu1cRm6s60SPI9FkTa+w3kK2ZRK4+
         IWRC06by01iVoSnx/qHl/VLP2wbeeYv3y311MHRK7dOUoGnwFagkGNvC/mRIrV2L4zyc
         ds0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=y6ReU/yQbMmhmfPYPgQAE7YvqQiR0AR8VeoVn4CJRYM=;
        b=nWB+J4ymX/76rUUqaq41LjvskraLrv0ekD2ldUiPeyReSmvZ5TKtTbi6RrIz5JdyvJ
         GOw8eAoZyxye2fSHhXSkuFg4jDMXhhUSGVOKVKr7G3Qs74Q6NDvj7785df1mSaPVNBHZ
         9QPEE3aHN7VG9Lak2CaZqR9XhEoYf90JTfvIU/td/beMM6lSeormCJVtd66nk/8DkeJT
         gJPlbDl/JCEuv/Blrg8iW1lMLcr2E4voYHi6b2UEmZg2AvXlFx3LG8Lz9jqi7dBX15QE
         8FpwMK3USEvXCT33A4qBDMHYpWQf9vjCMRS0ZERI24S5SFoUXn7kg80BjyI+GkLXV0pP
         zE9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fnWeMmJQ;
       spf=pass (google.com: domain of 3cintxwokcqchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CiNtXwoKCQchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y6ReU/yQbMmhmfPYPgQAE7YvqQiR0AR8VeoVn4CJRYM=;
        b=qlBXtzpAHbPkqDTPSy31WVXmRqOc/yOhAtnIvOSIkrDQjHEen4YTDOu4nmI5BgTP1E
         /YQoVzglvGih8phGD2AB1D+0DjVVL7JGQQSS9p7dVgrZjos6gR6zTf0MCFt/z4t5e5mJ
         83VoJQqud4v1FeoKmJ9SK3ThpvqjFGm4sjwMT8AtGRq+rn9dZRXcVwYG6PoM+SA/7gWZ
         SBPb+ZmEWGDvFwF9/qV4TGREEEjUoZD1sh+fA2mE1+kGFZuJMtzkQuOjm4cWYvSMUmzP
         V7M4iH2K6f9OV/lZpsyQReDuFjOABBgNGFAdCUnAiXawg71mLRu8xb3CZzJHJ+LIO5P/
         CUsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y6ReU/yQbMmhmfPYPgQAE7YvqQiR0AR8VeoVn4CJRYM=;
        b=nIE0+hqKcq5EugOlQG9G8EzHVMR7Cj3jcSExMM44W7+iSSkpWXAAAg6hC3lnrMlPK4
         A01iMdVfikVSiDr4NXAfDn3Bd1S2fjAYzUlE/5EsPmt/MXurozgoqB2xLoaNO3314QF9
         r2FNB2ZF6pPC9oCFK5wNOIiLtihiTqBnj8RsNFTgR/osN/scLXzq4wVJIZaplQl6bHOl
         lhxp3ASweM4q2aZ5o5ELRiolcNf8yQ67Yb9BMqFy4t9R7q7FVvay5g+HWXy6s2kREkP+
         JPpL3w1cnIvTi67hcFHyEqeCtKVSAxhGatflPcFXIlt0RZq5nqSYyKpghN2abyY5Qvni
         HEMA==
X-Gm-Message-State: AOAM530CBGJSe98BRmghIuSAQs5dNpacrXT3og7VhY46eSbE6AwxzNfP
	p3MmCCiCxchRKzVQGVGbxL8=
X-Google-Smtp-Source: ABdhPJxaleMUMIQhbYKCfU0mFC643kch+Sj7RBkwu6A+QACFRvzosIaVYd9Z4AMnbqTzbeWQtWrQgQ==
X-Received: by 2002:a2e:80c3:: with SMTP id r3mr409358ljg.167.1600987916791;
        Thu, 24 Sep 2020 15:51:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:93:: with SMTP id 19ls93576ljq.4.gmail; Thu, 24 Sep
 2020 15:51:55 -0700 (PDT)
X-Received: by 2002:a05:651c:1352:: with SMTP id j18mr356149ljb.343.1600987915772;
        Thu, 24 Sep 2020 15:51:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987915; cv=none;
        d=google.com; s=arc-20160816;
        b=OpXAu3XmF8D2saqFll/BtBVksZmm4Vpft9jFgWO13lGwkbQpzabbFHMxfjSyNwpS2M
         DzhwW+fDNCeVBdMaI/DLrTcqzPxRpbkBg1fmWyUTniki8WojmchCB5qaUmSplevv2gjM
         dZ9igvFFxOKzz3lJK9TFtAWVIOcZmqzB/pJ2TDbCvDeGg4DIjjM2YeYR1gyMiZLU3lmv
         iWnphdj22dCd21D7en+d/Qa2ilO7Z39ToS7qEQhV2gFXhbVxpupz3nxXufGVbbfYvipq
         hn/k2xf32WOEPX8tm2mWjQDup9/ZyIW4OvtTzBQhpK/HssfLvN4lHE8S0lPAFsV04ftU
         pvzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DwY0XJ+mNp8uQtCgvLTc+GHO/ICbiZZuKiMqQmp5BSw=;
        b=vfIdVadY7B52ciWV2Yhqr9Ho/kFB1ZmfoUZpUg/ghN+eaFj3BEVTR6936xzArc2HcV
         G8U69fA8yXtFDqV1hYg3Cf/b6Wv+97YbPjDY93L3om3qg9e+SJU3YFVxRKUDj/o0VfRU
         WTg6iCEvCRbR0MJ/cq8zhK6e20NBNb8i+ZHygU3ggg4u3bGyEyJyq2n79P8auhYK4/s2
         iKa00hVMPnmmVbxyxuoe+jsETjI1gRB8yy9XfOvM6mcD/S/Q3mJvnLIEZt0YohE+GFab
         Wnt2jR1JT2mGZkeNCUxgdouhILUJOOjUchi970/MNxGcSfzBbabosVxqCPZdd8iKSj3i
         fL1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fnWeMmJQ;
       spf=pass (google.com: domain of 3cintxwokcqchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CiNtXwoKCQchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id x74si18829lff.12.2020.09.24.15.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cintxwokcqchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id a12so286051wrg.13
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:55 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c14f:: with SMTP id
 z15mr113wmi.1.1600987914792; Thu, 24 Sep 2020 15:51:54 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:33 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 26/39] arm64: mte: Add in-kernel tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=fnWeMmJQ;       spf=pass
 (google.com: domain of 3cintxwokcqchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CiNtXwoKCQchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
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

Add the implementation of the in-kernel fault handler.

When a tag fault happens on a kernel address:
* MTE is disabled on the current CPU,
* the execution continues.

When a tag fault happens on a user address:
* the kernel executes do_bad_area() and panics.

The tag fault handler for kernel addresses is currently empty and will be
filled in by a future commit.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I9b8aa79567f7c45f4d6a1290efcf34567e620717
---
 arch/arm64/include/asm/uaccess.h | 23 +++++++++++++++++++
 arch/arm64/mm/fault.c            | 38 +++++++++++++++++++++++++++++++-
 2 files changed, 60 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 991dd5f031e4..c7fff8daf2a7 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -200,13 +200,36 @@ do {									\
 				CONFIG_ARM64_PAN));			\
 } while (0)
 
+/*
+ * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
+ * affects EL0 and TCF affects EL1 irrespective of which TTBR is
+ * used.
+ * The kernel accesses TTBR0 usually with LDTR/STTR instructions
+ * when UAO is available, so these would act as EL0 accesses using
+ * TCF0.
+ * However futex.h code uses exclusives which would be executed as
+ * EL1, this can potentially cause a tag check fault even if the
+ * user disables TCF0.
+ *
+ * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
+ * and reset it in uaccess_disable().
+ *
+ * The Tag check override (TCO) bit disables temporarily the tag checking
+ * preventing the issue.
+ */
 static inline void uaccess_disable(void)
 {
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+
 	__uaccess_disable(ARM64_HAS_PAN);
 }
 
 static inline void uaccess_enable(void)
 {
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+
 	__uaccess_enable(ARM64_HAS_PAN);
 }
 
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index a3bd189602df..d110f382dacf 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -33,6 +33,7 @@
 #include <asm/debug-monitors.h>
 #include <asm/esr.h>
 #include <asm/kprobes.h>
+#include <asm/mte.h>
 #include <asm/processor.h>
 #include <asm/sysreg.h>
 #include <asm/system_misc.h>
@@ -294,6 +295,11 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+static void report_tag_fault(unsigned long addr, unsigned int esr,
+			     struct pt_regs *regs)
+{
+}
+
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
@@ -641,10 +647,40 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
 	return 0;
 }
 
+static void do_tag_recovery(unsigned long addr, unsigned int esr,
+			   struct pt_regs *regs)
+{
+	static bool reported = false;
+
+	if (!READ_ONCE(reported)) {
+		report_tag_fault(addr, esr, regs);
+		WRITE_ONCE(reported, true);
+	}
+
+	/*
+	 * Disable MTE Tag Checking on the local CPU for the current EL.
+	 * It will be done lazily on the other CPUs when they will hit a
+	 * tag fault.
+	 */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_NONE);
+	isb();
+}
+
+
 static int do_tag_check_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
-	do_bad_area(addr, esr, regs);
+	/*
+	 * The tag check fault (TCF) is per EL, hence TCF0 affects
+	 * EL0 and TCF affects EL1.
+	 * TTBR0 address belong by convention to EL0 hence to correctly
+	 * discriminate we use the is_ttbr0_addr() macro.
+	 */
+	if (is_ttbr0_addr(addr))
+		do_bad_area(addr, esr, regs);
+	else
+		do_tag_recovery(addr, esr, regs);
+
 	return 0;
 }
 
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl%40google.com.
