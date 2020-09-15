Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYO6QT5QKGQERUA5GKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id BD36226AF63
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:22 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id f8sf3335233iow.7
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204641; cv=pass;
        d=google.com; s=arc-20160816;
        b=kO4lL9bmq3pPx2+nNuwMune5k5/BoQVCYbXVp58/c7qhrjb34qje+PgeORQnccXbsr
         bzA92o4T/zVCwGSC5Bm0xOIhpyiJkVrjQnVSPnn/Reagkb0I9XrrAKQYoAN4MpWVOz1+
         sf63N4KKgPoBGgQl2qXjpJ57ZHi8XtZPr1yinY2yGtb7ohHaZWZjCoNmC9gqzj33PhsW
         Woun0O3UcR5AFCiWBMGcYLEGtvxlSE5zEvDH52AI33GJkyZzAOraf+3i5f51p3YiT1lN
         pNN/pDx7KG6yYR6Kv9QMZN46lK5eTfMDg8tX7XuH3YAZ0kVnsItknUA4hBraZ2slUN8C
         Jo5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=WQY0uovbTh4VxoXkIieFn5eWRJw/v7ECKJ5psKSOe9k=;
        b=AFQjrWG56hc5snJoW/nacm6h7QbONd/cSJ9ESFoo9+DxpXNGVuBuA+XNwm05mPw3oa
         58yo52uzV9epVQVtT9Ust7sTWOpJiCA1JDokRpTJlr3pM6BtmCgxP9kRSp5xaIcE85ss
         CCV2wyg6VWl0Kg5qgKzhUxsiccH9skcUncIYFB0Brz99C7C6ona0aRFyjjvL6U5LrkS8
         WY8/tjhoUla3dztio1tBvZvjbxU9YoPMFlerM07j1nLdWP1CVA/MK+xKhyLse11t3jj+
         JfJITJ5Mfn9piCQrHrJJUP5lrsSQpMqhP4Gnw13HXeNCf5q4idkC1TDLy9aittuRB3fV
         nWTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vmOgCDX4;
       spf=pass (google.com: domain of 3yc9hxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YC9hXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WQY0uovbTh4VxoXkIieFn5eWRJw/v7ECKJ5psKSOe9k=;
        b=m00Nl8teEAptskfk6D80e2ICuwllnIcY0FvgeJMig3MI+8PpFSjbo5AcaCD9C9Rpw4
         HfZ9MeokzZWYH0PjsDPPbUGLqkd84zYAUOMUAzephU3Qf5vNGmRA4ePzM8L4MjI3I1Qe
         zs5nM+xG2dPbVXZD9b7gpwSY7FM2kBQyguaJRmqfoV3OkltuVY52GRtayonKovBob9rk
         vTC4k6NLfIgUmJ5fhCcroDvdwqQe8I7R0N8vTZQ/ztYVyJLfqangDyHbgOd3WsXEAiVJ
         fNh5iYn6WeG+JSIyaqJusWwYzAJFlly/zao6Ps4GSgWL81Q3sKoyPse7QNM/5hIY+HGw
         j6Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WQY0uovbTh4VxoXkIieFn5eWRJw/v7ECKJ5psKSOe9k=;
        b=rkh1Kbx24SXfdHu8MRxNdodbwPmL+nQvWUg1X1crXxsGjlrXjdU3bAKP2k4qUjpTD8
         qVNSoeUOF0ihBzrsyFfP/pOssnEPrwlFDhQ/wWMlurluvZqKv2kTy+0iQs3zf4HXhk1y
         YHJc46WI6zGhHGUlz0r9rKp9iQ+ZbnDB0ew3ziv3wZHRuhi7DRouUNZBXWdO1d3cYLv0
         0d81HOkCcxzkPX0PS/c/pD3AmS7BFa0vQPdBO60AYsjr4v++5MnfgemUWPbSCNgR29K/
         FX+/CarDQ3T+7pi84gVho5j305B56Em13AKDiL6Jwyn2D6fRtGqmxGBjNW2NYR24Zzf8
         xvDQ==
X-Gm-Message-State: AOAM532oi+lDDfP+3ff1F84cXIS/fleq7vsBEs3iwowOhy+B2FfKonae
	yrjDh6w9F+aFrNp4s45U2MI=
X-Google-Smtp-Source: ABdhPJwYFOK908I6wNbKVMahxesniwCbW6VTghLdZsgF9ODKgmFWVS4Kwcrku9SsiziC/tXVUFkkaw==
X-Received: by 2002:a05:6602:2043:: with SMTP id z3mr16286849iod.93.1600204641734;
        Tue, 15 Sep 2020 14:17:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2ac2:: with SMTP id m2ls63509iov.7.gmail; Tue, 15
 Sep 2020 14:17:21 -0700 (PDT)
X-Received: by 2002:a5e:9b0e:: with SMTP id j14mr16928548iok.112.1600204641303;
        Tue, 15 Sep 2020 14:17:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204641; cv=none;
        d=google.com; s=arc-20160816;
        b=jvPbJogueoZuGHFYT5WwPTDPd8iwXMNw7zoe7vVDg4nu1Fyw6I8VGNfE+jBI8DX8CX
         w3Mo3VOxgJUg32SysVXLtsgzyCv5EJWoXtm7EUOYK3ld/cWdjVR/tLTB2UmS00WUGYjc
         vrnPDq/4vOYNgN8uV/OTBwemdjNY8F2vjK0N4i5oJB2Mp4vBECrs1vKbnyQzDHIefnbp
         e9bdiBleiWm7U9UWfWqqAZynNIFBD5+8dZH1tJhjGy+CPEAzuMok8Tl2x5h3G+mbs2xW
         evzN9QPryPc7reFApyhRCIyOeQkZJ6l+q/kdsMAU9IdwDNQjC0E8NtRprXSk7bdQECl3
         WnHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=8gCy5LzCrZ4Ippif5C2Kr6pI1Q8A3vPTLrXylwHP5Is=;
        b=J4apQ/iyIuumZh86xT8nJYs2J2DQgiZzlaQpPFcyYL3FruftaI0+1LhLjvBONI9M/q
         jMMipvBmg1n+KD42vm7bQhxsHNNnSeV6CwN/dKW4STLDoC1pF8SEgi92NJD85rQPLAsr
         eZFQUTsVKFpQLXtDXArzZnOkzipP39AuX2WIpXTimanXQn6v3E6QkU0x1yYQ24SgkpI5
         lxnGnAmMPlR5C5RINEX/69YxeZ24CTWigGQDjjSzUYBCFj4YnVJKRtmvr3YVPzeaHsyp
         a+As8grPoz/fsUF9IlQ8Hq/MLBrJdRyV+e99BG2OKj72K4fhQPNJewDmEp9LjGNWHvua
         uFFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vmOgCDX4;
       spf=pass (google.com: domain of 3yc9hxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YC9hXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id s185si1046916ilc.0.2020.09.15.14.17.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yc9hxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id m203so4056402qke.16
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:21 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5745:: with SMTP id
 q5mr19950252qvx.29.1600204640737; Tue, 15 Sep 2020 14:17:20 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:06 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <7866d9e6f11f12f1bad42c895bf4947addba71c2.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 24/37] arm64: mte: Add in-kernel tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=vmOgCDX4;       spf=pass
 (google.com: domain of 3yc9hxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YC9hXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
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
* a warning is logged,
* MTE is disabled on the current CPU,
* the execution continues.

When a tag fault happens on a user address:
* the kernel executes do_bad_area() and panics.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I9b8aa79567f7c45f4d6a1290efcf34567e620717
---
 arch/arm64/mm/fault.c | 36 +++++++++++++++++++++++++++++++++++-
 1 file changed, 35 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index a3bd189602df..cdc23662691c 100644
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
@@ -294,6 +295,18 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+static void report_tag_fault(unsigned long addr, unsigned int esr,
+			     struct pt_regs *regs)
+{
+	bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
+
+	pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
+	pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
+	pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
+			mte_get_ptr_tag(addr),
+			mte_get_mem_tag((void *)addr));
+}
+
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
@@ -641,10 +654,31 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
 	return 0;
 }
 
+static void do_tag_recovery(unsigned long addr, unsigned int esr,
+			   struct pt_regs *regs)
+{
+	report_tag_fault(addr, esr, regs);
+
+	/*
+	 * Disable Memory Tagging Extension Tag Checking on the local CPU
+	 * for the current EL.
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
+	/* The tag check fault (TCF) is per TTBR */
+	if (is_ttbr0_addr(addr))
+		do_bad_area(addr, esr, regs);
+	else
+		do_tag_recovery(addr, esr, regs);
+
 	return 0;
 }
 
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7866d9e6f11f12f1bad42c895bf4947addba71c2.1600204505.git.andreyknvl%40google.com.
