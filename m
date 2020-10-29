Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXNO5T6AKGQEN6D6JMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id F202F29F4E2
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:21 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id h14sf1675054ljj.3
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999581; cv=pass;
        d=google.com; s=arc-20160816;
        b=bzG082UDg7s5yLISLpq6kyKa2K+fGfYgesRl4eEx4eajPrxgU6gTyOUqy0Kxpfi5aH
         cHWH6Zt5OS/UEQxD/JmuD8smTdoyKXPfd5eNmP3ruoTr3kqVYiXtjkY0j+UMt8AzMOj7
         V3RMbPs2GDIHf97YlrLB/PXN953Qoy2imLXdtsHf+HxY5ptwSfjrst5o2gqCofB7bBBF
         ZZgxZlhVCVZEq1awZghdhqTVKGjyeywlQ5V2y3cuHWDd1r9o3NUPlH7NiH+GDT5zWA/H
         q1cngL95wb8OpV/9TzNsYGHi5UA/rFAeHcZOCdkJN7NARO1xpTFET4PH+Wr/njiZMz+5
         pc6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=JKiLwusmRw6Cqj1iZN3uXW19bwtBzCAMhYJBaUD/Qww=;
        b=m8IKX0Vr2wpeqtKqdLWHmjKxEFjoag0nW5MtnFhm2hBl1tRPv5AJUfUrkRp3Xy74R/
         zw5EMuMVsM4YZn02UTnvOeuaOhiz5ekFqqbnx0ZHpC/4zL8esNjyPqm0ZArfFc7ALza+
         MxzqDYPqSBd0t58E7ablXZfy+Z7WNU+rIpGHKAsiC1RM7MlZGJ4CXzS0QBLR8b2ob2/M
         nkdluSkRsXecvzhFIa6UJzUf7UAKpQWU9JP4Q8evLeWP9saapyenyTMaGOnnRpWiCfsj
         ioE0mJNs5oS8rYdbMyjhVW+GnqgdXKMBdd9fseMzh7qv0NSp9MzHkAkn3zzJQjtO+dGG
         /lTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qO3xF8jJ;
       spf=pass (google.com: domain of 3whebxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhebXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JKiLwusmRw6Cqj1iZN3uXW19bwtBzCAMhYJBaUD/Qww=;
        b=FSftvTNW6oCl2XzqI1zORjyzjCVmYk6ZxHcuGDbhN27o4gu/nBlWtJq91ECLYZrLVr
         8iRSMJW1o4/wg7c3VaQ9arouRHOpUNJmy0XKjIj4TBSb+AnEL3gV0gE5LvW55xUVD2BM
         I7rivlWN6pND+6nA6IEcqYaXF8iGfJQAR+gbuAbiyDgYfs6/yanEUrigeByZ6CnuEpuW
         SbLj91FQbwIoF2sFAMTJUUyQC12sWPHHBvjxyQTBEWeknbPkkM4AmGSw7isIXnqxoklV
         PCyDtphSS7Ncwn4leQHDd41UYwRZxq1K6IUi/vy+suvsGKJJ6PQBpsSiyfFRVs768Enf
         9j/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JKiLwusmRw6Cqj1iZN3uXW19bwtBzCAMhYJBaUD/Qww=;
        b=aL3BwbwNpvGP9Gg3/brwHC/i+MxKs/5vZb7roDWH25kKKOzbZmtQoU5R16XzzB+X1z
         GIGgnbRUlKTtKSGkkLBRVGeSTzGG5DH2IP+Pmc+KY/VkgoUk0Yl97y3hj+D9qkpbO1rB
         ksZ9JeD3rIuufRH7cWh3n/oPEEqfcxqb62BVh+bR1yzg0cfzhRRcvQAH89kovWzLyPe+
         +fcgUUQB1C5xIJSVJbWAcAKrkCD6SPvaJ5E8meQlsmofSaPoe5TiRpx6Qvr9L4hIUSmg
         I9nhn5Xb4I1Yppj6UC7dsUs5CjVDtOaoFpvDTmgO1rK/sW8K+k8Y97zdCjj78RcEZuAz
         86ZQ==
X-Gm-Message-State: AOAM531tlm9FIpmIqhuIBDzRuYeHSKljDY3g4GRYkC/6bVqZ78EHdqRK
	g4LIlolgAgreilL/jICHNhY=
X-Google-Smtp-Source: ABdhPJw5I/9Xu8v7I0HUze87tUvlTu/EBa8nZQaMX0/5Ul0l3zWJqPSFWhuO+V9RNtjbOV/zUe6e+w==
X-Received: by 2002:a2e:920a:: with SMTP id k10mr2341952ljg.349.1603999581410;
        Thu, 29 Oct 2020 12:26:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:888a:: with SMTP id k10ls750342lji.10.gmail; Thu, 29 Oct
 2020 12:26:20 -0700 (PDT)
X-Received: by 2002:a2e:6e18:: with SMTP id j24mr2654824ljc.91.1603999580225;
        Thu, 29 Oct 2020 12:26:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999580; cv=none;
        d=google.com; s=arc-20160816;
        b=yDvnWeBXTI5cG3n7XZWpcKz/njmxUEQWlq5XqCWpr60cTvoa3U1wez2FU0vIheEwHN
         wZlHbUaieCnPZ2URQqgjcRuVMusVgHK0bXwUae2ue8yZLPtcMes7FV9lUJSCChNuSqcb
         zGQ6f/BiaGwbh4UIWgwOgRiv75uUM5PlDUZUntZFvrNyu2vy/ZBa4QDM5nSkhQTIEi77
         83dFaQ9Fln0GyFXDj4/76nodef2oFA5tAzIWytJ2MV11VvV71by0Mb4XDUinw3jAstq1
         /4aSGIVNYI4pnuSRwOsKqtt7i801rYD0guretCEGAnr7XFNdOsABm7f5gt+KkD8zOQ/S
         JNrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Xhi8/obcRMlNP7+SSdhpfrVDPTS3W5bEgvNhWzgL4po=;
        b=kT/7qEaAmXFh2yx7FND4/6RDud3AwlfOWMgFmTYRPAxfnQXTZUJ6u3W+4DeF0eGvdC
         R8HJqAfIpUbFonCx6g8VKM4N1ZDPIRva5DYVX+8gbOdc7D+EeP9eLtuZdeGibpGaviLk
         zRtaaEoGN531TYnYcYYIg0/HEXecED8cCZfxLdalaepSZSCN0aT6nlBeqyRBmDEIfIZB
         5nrOeNlt25J5oSEzK1YaJvYtQoihKRRcjbtu2gpDDxrPTtrSsjkDXl01nfDVmdkKfX/j
         1qGODjDCcGNLVCtIHQMrpxsNQbC35n1LJ+oWvkbSEKy/YBwsKYzDJchnp0lP92cnigio
         IaAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qO3xF8jJ;
       spf=pass (google.com: domain of 3whebxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhebXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o142si86578lff.6.2020.10.29.12.26.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3whebxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z62so972424wmb.1
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:20 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c149:: with SMTP id
 z9mr50488wmi.0.1603999578948; Thu, 29 Oct 2020 12:26:18 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:26 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <171f9481fe4d116c46cc25a4b1145622ee62440e.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 05/40] arm64: mte: Add in-kernel tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=qO3xF8jJ;       spf=pass
 (google.com: domain of 3whebxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhebXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/include/asm/uaccess.h | 23 ++++++++++++++++
 arch/arm64/mm/fault.c            | 45 ++++++++++++++++++++++++++++++++
 2 files changed, 68 insertions(+)

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
index 94c99c1c19e3..7be8f3f64285 100644
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
@@ -296,6 +297,44 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+static void report_tag_fault(unsigned long addr, unsigned int esr,
+			     struct pt_regs *regs)
+{
+}
+
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
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
@@ -312,6 +351,12 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	    "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
 		return;
 
+	if (is_el1_mte_sync_tag_check_fault(esr)) {
+		do_tag_recovery(addr, esr, regs);
+
+		return;
+	}
+
 	if (is_el1_permission_fault(addr, esr, regs)) {
 		if (esr & ESR_ELx_WNR)
 			msg = "write to read-only memory";
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/171f9481fe4d116c46cc25a4b1145622ee62440e.1603999489.git.andreyknvl%40google.com.
