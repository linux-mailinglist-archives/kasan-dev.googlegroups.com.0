Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLUT3P4QKGQEZNBH2CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id CC64C244DD1
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:15 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id i185sf2546982vki.7
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426094; cv=pass;
        d=google.com; s=arc-20160816;
        b=rVzvBlsRBuFsh6TWzJGENHFxBO3Bm1NBGE4sk3kchk3H0cZJcuJjgYg7136tSLonJ1
         Wi6SZcm7O1YfgLIOHefiKrq+go9Vtm8Caay6w94wv9HpTMgy/b8eOigTlUAkeAZWK1op
         qg0/CM4C9k5sYWm0GcKZLqrVRco+HagKW8b8mo34NTuZbNe8fp7rdbVqcNrzGZ94uEa0
         AD8RXiFrGP+QdBw4zC60Su+F3svuXx0P5XSCqTNg4/RvtqGepuwTT088gDQxMqy3ECVb
         IB2ef6w7KCiSPAg75uizxenOgExdZ3Qh0Z4aX1babNS0gw97CCVQPf/wJb1QFGSNGfLE
         xK5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=kddKL29Mmw5jSZusfOBywzMMaiGM7rvk5cE0rukggA8=;
        b=botA1O/UiSgDPbir1coSdKeYSrVKbDNzZJsUZmyFIF0Z55ZtV/wvd+OjoVvDcJRBNG
         tuyybrxuw3/kj6exZS4j/+HVhnRTwCtgMCnftW0QiZlQga8a4wEaEPRWYqOZj3CbVgch
         9slBeY99RKwCrVl98UU5DeJ2enXSEfZPXsQtqZLrOzD1HrNVjKvDJfbM9hPkGYv0COGf
         mT+Ke+57nhw85cvnMtjwXFi676hVq9WVueb/q1yY8gX4I6fEQFJApLwFvEesM5Iu81Qn
         NWWhoKLNw0DhoxfY7U3Lyza6UG2tauAeSTo3A/aMwQBf6Ehx9sl3PwoExTb5DlyBWZ88
         E7Mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J0yRjS8w;
       spf=pass (google.com: domain of 3rck2xwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rck2XwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kddKL29Mmw5jSZusfOBywzMMaiGM7rvk5cE0rukggA8=;
        b=sJF4oDAVOg257sW6ZxMn6q/63tg9/UbSBrchZodMP1rK+UbBjML19YIAJPJgBgK7f1
         IRqEandZkmBzACA3A/+YBaqMqjh/IrXcXsrDlYfI8w7GF6FvCeANt2rxb8HZza6lAB1B
         B/7aiJAuTrLNTzTxvQOLqRPQ50T5eETz92LUf21gJSHclX2Hub29S8oHbJVBj/DxiPa2
         pvYGP3VfHj6MBpHppYLQngCMlBjnUQvUB19sel60p5H1lIuCWWdy8qKF2XgTvsHYynQu
         PjPE8Feuvt2RyH9nir/ZlqgD0UE2z8icJVoYCDSWZQv0+EOzyNWrwOJoIi8o0flXzmm+
         UBXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kddKL29Mmw5jSZusfOBywzMMaiGM7rvk5cE0rukggA8=;
        b=TmaVoINMCxNgcHu/dZOxe/te4f+Bac0RhCSj1u0J7m5Rj7QKKTTTHK7PdHc4HNqyFj
         sXcpqG5hKbbaVTtXDo5fFir2rtDYuqBqDj3C0v8EkruXM/P8fx4ay+XfnAqz5XnjLWCD
         TxfO6DvYj0GL1j/Qs3Tk16nEhVyW+YS8UQtfWUaUldV1ZD4hG68CgMan+sDWcWnDUcp+
         kNtiKqMhcgjAZBoX2RVTnNTQS0ffYhxiTRF2WfNkmocce5EyX7mUFCgm/NStSkhOQ2YF
         2Z2+KdwEBT/+xMT0Y2Vg+0cCoi0qUDeQwLN1tTNgpoeFya3KntysHxRDt79RS+/phPkg
         Icqw==
X-Gm-Message-State: AOAM531UCEALBmU8IDAbGJvQlMOuB6E5UxvkyXA9yKmSjX9Ta1w1+TAd
	Ja1fBFWwKymw0YRvLwIGIek=
X-Google-Smtp-Source: ABdhPJyeaTjE9O40Rj9CKKr8NmFE9/3wgcvtoQ12HT0wJRL/OZy3LT2qc9b+0ul9TgAwQ2B2PFQKWQ==
X-Received: by 2002:a1f:ab02:: with SMTP id u2mr2399808vke.80.1597426094706;
        Fri, 14 Aug 2020 10:28:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3110:: with SMTP id e16ls1180235vsh.2.gmail; Fri,
 14 Aug 2020 10:28:14 -0700 (PDT)
X-Received: by 2002:a67:43c7:: with SMTP id q190mr2238483vsa.193.1597426094338;
        Fri, 14 Aug 2020 10:28:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426094; cv=none;
        d=google.com; s=arc-20160816;
        b=ve1rgpDWxsqSffTuLrajiyyNvlWtvIVaGajR0kF6DmSEm+4Ae/K/TGCv7yW0eNNoNy
         dKFG+H/3i1U3HDZIIKWAALPsZKzgAbs+lFOJkmFNLz9Z7VRzewDBwX3tV6sMzSF5sU81
         eHgPF93NSQ+gtMxCRqMHFcHTKJx11nsntg7oxKvb8ZfcniEixiPctioN0jMutSNM8oix
         c36+ylOyGandAmM8caDSES+/YOkHe8sMklAEz1ADHqVkYteBYCc75Iz2hEZcFULnDilq
         YeY7pR3tLDGi9LhsdiIZckKucHkohXN1MozJV32Qdompee1yO/6uALbFcB1Hq3aUb7sh
         tmQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=E0RrGh1M0jqaaDoEOkU8MvQi4g07cx9su4pS9IT1SWw=;
        b=zyzvinNT5CU47yj3GXOAnFMPw+VI+M6p217VMPuV1PeMIj0Qw/QdCnAKCVg9MD4Zbc
         SOc+Ug2W2636+/QohQXiRUXm607HZUmqlJ7GDqLRPgsNA4I7XiGiWO27QHiKjeq4b+YW
         9i1vJH6qwAkRHAALKi0q1OjfSecf7Y4OxcmO34V6AJyWlExLDrVl2P3tm3zno787Ye4z
         Nl8xOijuNV7Fiqfct5FMaw2jpjwdvWYkwVNcGtyS8Ynxw8tEYdzDK/9Z6diwXZAXETso
         9Utpi926miaR5T3h0BSD5smHOTA6QE8IPt4G5ijTAVprTERYaaY0EmPnFVth2fKjdT3T
         yv/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J0yRjS8w;
       spf=pass (google.com: domain of 3rck2xwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rck2XwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id s126si558812vkd.1.2020.08.14.10.28.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rck2xwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id q12so6493715qvm.19
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:14 -0700 (PDT)
X-Received: by 2002:a0c:9a0c:: with SMTP id p12mr3610073qvd.75.1597426093874;
 Fri, 14 Aug 2020 10:28:13 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:03 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=J0yRjS8w;       spf=pass
 (google.com: domain of 3rck2xwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rck2XwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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
* the faulting instruction is skipped,
* the execution continues.

When a tag fault happens on a user address:
* the kernel executes do_bad_area() and panics.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/mm/fault.c | 50 ++++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 49 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 5e832b3387f1..c62c8ba85c0e 100644
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
@@ -222,6 +223,20 @@ int ptep_set_access_flags(struct vm_area_struct *vma,
 	return 1;
 }
 
+static bool is_el1_mte_sync_tag_check_fault(unsigned int esr)
+{
+	unsigned int ec = ESR_ELx_EC(esr);
+	unsigned int fsc = esr & ESR_ELx_FSC;
+
+	if (ec != ESR_ELx_EC_DABT_CUR)
+		return false;
+
+	if (fsc == ESR_ELx_FSC_MTE)
+		return true;
+
+	return false;
+}
+
 static bool is_el1_instruction_abort(unsigned int esr)
 {
 	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_CUR;
@@ -294,6 +309,18 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
@@ -317,12 +344,16 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			msg = "execute from non-executable memory";
 		else
 			msg = "read from unreadable memory";
+	} else if (is_el1_mte_sync_tag_check_fault(esr)) {
+		report_tag_fault(addr, esr, regs);
+		msg = "memory tagging extension fault";
 	} else if (addr < PAGE_SIZE) {
 		msg = "NULL pointer dereference";
 	} else {
 		msg = "paging request";
 	}
 
+
 	die_kernel_fault(msg, addr, esr, regs);
 }
 
@@ -658,10 +689,27 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
 	return 0;
 }
 
+static int do_tag_recovery(unsigned long addr, unsigned int esr,
+			   struct pt_regs *regs)
+{
+	report_tag_fault(addr, esr, regs);
+
+	/* Skip over the faulting instruction and continue: */
+	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
+
+	return 0;
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl%40google.com.
