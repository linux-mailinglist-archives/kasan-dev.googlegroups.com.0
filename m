Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ5P5T6AKGQEM5QETHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id F116A29F513
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:36 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id z18sf2701000ioz.6
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999656; cv=pass;
        d=google.com; s=arc-20160816;
        b=DmWdbklwnC/tgaAbHUY4lSanw9J7T7S6PYIfDaJtNnqlm7AqRFS+wBS9wPNX4RMorJ
         GbsqcxMP2WXPzQJR/YNVwFBTHXmln4M+mPzg5QjBLIpSmtNtnIXnoaOmoRjbAZH/zLEc
         +6j2vl8AP3weqhwr6Hr1IbxtX9c79wC0ZRcn+R5ymSJfJDVd7I2qVKhkBuh4mtL8y783
         1+8Ta2vh9286tS2/Dy0P7yh9gdEcdITE7PhHuzg5MU2ZHTrNioBz8WPW5uWUPrpm2/gD
         EizL2hs/5mDV5UzoYpLpbQdE/Gpr8OVcAq25FsBSuotjvig9nd/m0nnmMt+nG8Lfd1Yk
         qIOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=16rWnshHH0jIxgppKgOncw4FoKo1LrvN8sm6h3a2WPU=;
        b=kJGJX7GlXb5GoCZH5seWW8gCYk3lNDcbpeilTNF+jOOwVO1WreNyoi88F2QnspNU5k
         YaMmL4wqgB+FJJM+Tmp/Qd8JxN7Jcjp+srExAwfYQHJXPwvFcks+iwzDgRDp8k5XGF06
         ixHQGPKs37Um2xb3ULP4J4Pq+Vc+reboUq/JCS0CAYmfwU4eWsw3deZJWt2A17G1y0HR
         Pm1pSlgvkqV71dXLgANmfS6hM/gh2a8TLl0p2duNaU98Cg7W/BX19DFRssS+NrW7N/sT
         Edzm/O6JuX03UDCiqdNTFeNxMwty8OqGW7GsH/o8UQvZjoWyc0JV9Ek5i1El402Xxuf6
         nN2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fUnZ1HtL;
       spf=pass (google.com: domain of 3pxebxwokcuyivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3pxebXwoKCUYivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=16rWnshHH0jIxgppKgOncw4FoKo1LrvN8sm6h3a2WPU=;
        b=Uodjvg5BN3jDLGl8otrmocrfNnky+secKOsN/A2DD1V7cZXweRrM3ZCmIDXWB0YMRu
         cFBP3grfeGuL4WvbI8d8j/IPQZ/boBcbi3IHq89vkVjhuOdCtWO9W7s6BsAEfH6LN66r
         Ryu6F/vATXzdlDPGpMqwetDjb3osuafuGoIK6nSwdczhzhjfthrRaKkD85LitPgpHTv2
         N12K/5TGRhPi53c4LwQsG0SM/7A8+eOhGlauJYK6b/AwEhOCte2DCYx4HKfhq4sYY069
         KU3LSEBBfPtAklz9VRIW/uRC2PHQPOgqwkvGF45DLLHQIYKMAClAJp51CrpeM5P9bDe1
         Okwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=16rWnshHH0jIxgppKgOncw4FoKo1LrvN8sm6h3a2WPU=;
        b=bLWDtsAdmcWjtkJZamS22u+Mz/PoO+ZWniW2kNctsp+LmvjlvvbRiB7XYaMCn7x4eG
         uHic+mETwhfWvTCIrXTWXrFYvXhB/GkMl0lBPb2mxxVO9SCpcBInVyiLUzWF3c6KuLdi
         nJvM1PrqhqtXq78Es+OEaQ91+4RV/CTeTOtfzKA56C74/SUXJIdsPNBUvhAJxCjw7bbg
         clBsR+8nCHfpg33VhnI1m9/f451BwN/Wk/apZpYqBzSAsYybHDyU4mkJTsOY1DIPAdgu
         uOgVT1m1fpZmZyFskrQntyuGVlHvxu/LybwePaCy1n6sUeSrwd8s6XTZ1tvvA3BMg0eq
         VYqg==
X-Gm-Message-State: AOAM532YM/UAS/sq5Fxq/9wQ5RlPdhWtS2zu3dlRGNpxztcGl/Qi1Mto
	PWr8Dc/vHNS42fRZIJURvMA=
X-Google-Smtp-Source: ABdhPJyMPTIp+k8Tq10TcNALyU+oLECcMU8VbP8/uIac/QrMU35SYL0tgBmqkcv9THLLpvBy/6r95A==
X-Received: by 2002:a92:1911:: with SMTP id 17mr4456957ilz.129.1603999655990;
        Thu, 29 Oct 2020 12:27:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2d8e:: with SMTP id k14ls571650iow.3.gmail; Thu, 29
 Oct 2020 12:27:35 -0700 (PDT)
X-Received: by 2002:a6b:c8c1:: with SMTP id y184mr2507961iof.109.1603999655665;
        Thu, 29 Oct 2020 12:27:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999655; cv=none;
        d=google.com; s=arc-20160816;
        b=YbOiWRh56aoPAIxCqyr5iADlzLNf+x7dvmIP6QbWs3BUdOeQzulEniLCqW46YtABLR
         SMP1u7Zf4SUUq7rnEZLzghijExuRJ+2XF3juJ54pIrvy+zL2K00ujdqyUFZ3pnwEmGQ+
         ErRVmyh7mCjkNL5sdjFpkmrWfinKzzivA5eYNwadGT4YvjgELwFhQkgPiJsNsYwWypBn
         G9S/p/aDx4WSu6cDxP/Y/8DD+wgDV5jaghFqcG9HjUYaOgfnQgzaKZlQEWxbH/188TJq
         lbkh54VzkZkdZqM61CJOWAm1/NmW9xZ5DmydhPkCSRsLqDcIiprL9Si7n3KKYkqCFamL
         WixA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=A1ZDaKpC4XtGkLWbudlzWpby5nqFzQhbh548tIdxUT8=;
        b=OHHUxO1ymIOt/ROm+FjPn1q7asAihIBl7IaJgF0nuYynxIGWGydnN8dW3GixW1IkiR
         vSOWdA5Ql0YTsRiIiMolVHij+yCRxRozea0EWI7d+ggMHpdM7/TCzwjzDfk/uozL8Xfm
         EJ81sPJqU9JdrPxcLGMPJ/Pg+oCMgE4tG8IDiI613oSdEGRXf6O4iHUPDScKUAdoD2bN
         lsQft5iGwRiYdfe5rRnNpEJVWqDbFbggn0gNdqxwQ+383JhF/B8Z/61yr8e7ImriuLa7
         QkiQMWsEFClxmzW4fHeWSTrNa+Ll6YD7vXhPw21ue9mbfB+rbF9MPinwxuNMqHkNNFUG
         Qukg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fUnZ1HtL;
       spf=pass (google.com: domain of 3pxebxwokcuyivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3pxebXwoKCUYivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id s11si199880iot.1.2020.10.29.12.27.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pxebxwokcuyivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id k15so2406939qvx.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:35 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:40c6:: with SMTP id
 x6mr5883701qvp.20.1603999655065; Thu, 29 Oct 2020 12:27:35 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:57 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <d489548329132c789b86059e916c7996d07d3513.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 36/40] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=fUnZ1HtL;       spf=pass
 (google.com: domain of 3pxebxwokcuyivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3pxebXwoKCUYivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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

Add error reporting for hardware tag-based KASAN. When CONFIG_KASAN_HW_TAGS
is enabled, print KASAN report from the arm64 tag fault handler.

SAS bits aren't set in ESR for all faults reported in EL1, so it's
impossible to find out the size of the access the caused the fault.
Adapt KASAN reporting code to handle this case.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I3780fe7db6e075dff2937d3d8508f55c9322b095
---
 arch/arm64/mm/fault.c | 14 ++++++++++++++
 mm/kasan/report.c     | 11 ++++++++---
 2 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 7be8f3f64285..e1be919f7f55 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -14,6 +14,7 @@
 #include <linux/mm.h>
 #include <linux/hardirq.h>
 #include <linux/init.h>
+#include <linux/kasan.h>
 #include <linux/kprobes.h>
 #include <linux/uaccess.h>
 #include <linux/page-flags.h>
@@ -297,10 +298,23 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
 static void report_tag_fault(unsigned long addr, unsigned int esr,
 			     struct pt_regs *regs)
 {
+	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
+
+	/*
+	 * SAS bits aren't set for all faults reported in EL1, so we can't
+	 * find out access size.
+	 */
+	kasan_report(addr, 0, is_write, regs->pc);
 }
+#else
+/* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
+static inline void report_tag_fault(unsigned long addr, unsigned int esr,
+				    struct pt_regs *regs) { }
+#endif
 
 static void do_tag_recovery(unsigned long addr, unsigned int esr,
 			   struct pt_regs *regs)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8afc1a6ab202..ce06005d4052 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -62,9 +62,14 @@ static void print_error_description(struct kasan_access_info *info)
 {
 	pr_err("BUG: KASAN: %s in %pS\n",
 		get_bug_type(info), (void *)info->ip);
-	pr_err("%s of size %zu at addr %px by task %s/%d\n",
-		info->is_write ? "Write" : "Read", info->access_size,
-		info->access_addr, current->comm, task_pid_nr(current));
+	if (info->access_size)
+		pr_err("%s of size %zu at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read", info->access_size,
+			info->access_addr, current->comm, task_pid_nr(current));
+	else
+		pr_err("%s at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read",
+			info->access_addr, current->comm, task_pid_nr(current));
 }
 
 static DEFINE_SPINLOCK(report_lock);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d489548329132c789b86059e916c7996d07d3513.1603999489.git.andreyknvl%40google.com.
