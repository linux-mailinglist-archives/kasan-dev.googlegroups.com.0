Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSPORT6QKGQEKE5QTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 591CD2A714D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:42 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id m185sf188742oia.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532041; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rx2HqfniMQW013JADuQFTU//HBxhmDxTHTHLB0eWfVDW78ITbMGQi/Z6/fLe2+kOlm
         ntWvNQwyApeAbIfSkdpVck9eeV1KTey3EavsXkaJA2HOwRKggocQXhO4XbJ6Skxp2g3t
         DJmJ3c1zprzse+ZyHLL939zDyya6dSLRI4n4nloaRK2pMShAOHknxTwneZSbEJ2Rbt7j
         hxxZQAn8BOMEsB1zSw5BWc/xly78443I9zjmO3OWhzNrfzkHcJc5eWXAKdhNrunpGpJZ
         pPdv0i0naVWQvRS+0jPvCfMXIOken4vknxNwDwZ5edyQnVaBa6W+2lBS3DPWjvzR6Txx
         0VQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5UbPBnwYawLmKsCT94NjZq4es4x9X/j3uT2x23fHf98=;
        b=nAGX/H8xnGRL+na/kmxGK0o8jjtRVcvMpdqzixoADiqJTMVjcU2ToRTRHW+QJhYQ0G
         TGe+y7vSeHEj+HN1IK7jmQeB60vJSL2TcJ3VShsGDRb+cbTF/6DoOuhfitGQC5Lg5fD9
         oxNco3c4YMUCvg06f/SwHi6GzBKjrgL96aYDzVY24sPdkGTOZGz8bAVQxx9hi/qUP1y5
         VhniotfhPROn3LfRsbyrILI04aaxDKmcvCxXnGDjXJuOzdzJ5EdUKNadR0UjVeuPr1Sh
         5rjzEDMDHFIrAWohQffzQ724wZ9E1OItrWm3lkqCb0srdLDLMEhI91jCvXso+WozaEPD
         lGgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c0vkrlRI;
       spf=pass (google.com: domain of 3sdejxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3SDejXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5UbPBnwYawLmKsCT94NjZq4es4x9X/j3uT2x23fHf98=;
        b=q61jln4LWD4czNIszh31wmenlpTcY2Bwf1k7TSj9JUDvjiaNeVQDBIV4d29ar3V5rc
         TRl0h07DE/h4psB+5oFk6wIv9bXLtLNduZwbxosv0qGhTdX/u0cYKspYCeckjR719xXQ
         KfUMrbZZrRsFWG09aydSPCLgr4xfaUgejx38zpK7vhnlcPC4msLiCkMJp65j7Pr4rNgF
         DF0cOjAdiiYOqcgqESSHRqFzeDlArlOPJoq6mL0US7L9lryyIvmBzNDJaoGFhedVMNAk
         gOzVZiSDuiU+8IHfvW0DcAkvTSDshQDCP+dpP7F2rs4IZzUotaM03jaNZA5HJ0i97AOp
         zl/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5UbPBnwYawLmKsCT94NjZq4es4x9X/j3uT2x23fHf98=;
        b=RVmI8IQXRbUMNtGlDp90Qy/H1ykEUnOQHTihavyiyUQHmjbNCMI8ZB03xS2M37jsfw
         /sRU9tJU3yL3Q1TlF0W9BhjEOu20NGTozRB0ia/XxbRE4pVnQLb+v85WKkyJDJ5t1sjr
         XpkPO8TH/w0+GFqpt9nMWsKH1iZYNCjJEwyhjJTRkxFiEmPRqC0542ZLVrQM1x+vbRk3
         DvuwkWJvg4cWSSyL+Wx8atSK8E2F8og8MoFZcB4JqL7CLpUbtIdwtyNLmfhCL9BRGe3S
         pFpyzFHIBraj8zy+2Oyb+rTbPbISq8xV3SNVNbIFsm+dWWk3aJShiplY4461g6ejwzjg
         FNZg==
X-Gm-Message-State: AOAM532KFwjhXRhZ4SMRBeGtsTPxvvmNfkotJI8FWorDdrOi1d8RO9Cu
	9BMaFR0ZZcCO22ksYYHoT3o=
X-Google-Smtp-Source: ABdhPJxcFG+N5BFbIdXt+RxMHAIVjJrhv49s6oJajyA1e4qBSAQNDqM/0RIVmV10HLl5jeChVdmCDg==
X-Received: by 2002:a9d:731a:: with SMTP id e26mr58293otk.53.1604532041336;
        Wed, 04 Nov 2020 15:20:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:bb2:: with SMTP id 47ls906080oth.9.gmail; Wed, 04 Nov
 2020 15:20:41 -0800 (PST)
X-Received: by 2002:a9d:17c5:: with SMTP id j63mr66791otj.9.1604532041026;
        Wed, 04 Nov 2020 15:20:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532041; cv=none;
        d=google.com; s=arc-20160816;
        b=b1XsKglkDp7uJRuxBhsEPQM7A6bYg834IpE5fQAleILVfObK3nXRI+SaAy0OGUta73
         7MOpsUGu/SBKYMxVLf1tliMrWvppaHhp7UBTRjlbBJ+CJlqzLqDm9ICwaOj/nWO0+nyx
         RYhPcaCSNkYpdHpszoAascITF/gG23rcSrFI4Ajp59yuHKJ+D4ktyaYjcWrls6l+UEB6
         JscrWHw/94FMYkaT+43IcL38a8Hx+/efgeGF8v2i14yUib1sS34INjYaHLnrUmYQ4moH
         UMG96zcoGvGhNHCQE2G89MKeRVL23XEDEN2y6bdU0bXE7PIMqA+aVGhwWg/lE9qepDIR
         eMbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=35WbJzPGlJ32SG4OmkQQICRjm1+Un7MaGRWzBQ2gFy8=;
        b=DsN+/mkD8zMG/m2VDRXeTIgGuQ3Y8j0sazaW02YT5GqYhmSL0/+aXcM3u3QcmfooJr
         l3g04KFWm9zdnkdVB3NBMHoy/hVlwl78CkL5CBDkfN1Vb5rqadhbUZcNXCvjFclbALtg
         ntRC/xTSdcG8lojW8/FYOvvxZfAmtycR9adk1D5B0Oe3YbA+MRX9SX5AcFfqcnd6kqmX
         41oBYi9i8EjxtTimkEsbI7Zq9bJ/hTrEhbs/oBKG1LAzjV1MMTrOfFNF5shol8d5hENQ
         hL6EAiWCSe6TZpHHhGkBYlCzhYF28FxF1QoSvpziSIPpt/68ZpFMSI2w9lvOH5l2+Box
         8e/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c0vkrlRI;
       spf=pass (google.com: domain of 3sdejxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3SDejXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id n185si237735oih.3.2020.11.04.15.20.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sdejxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id l67so70363qte.6
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:40 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:55ea:: with SMTP id
 bu10mr283554qvb.28.1604532040493; Wed, 04 Nov 2020 15:20:40 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:54 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <4bde28cafd5ef30f4caf2bbeca90a9d7ccb73793.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 39/43] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=c0vkrlRI;       spf=pass
 (google.com: domain of 3sdejxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3SDejXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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
index fbceb14d93b1..7370e822e588 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4bde28cafd5ef30f4caf2bbeca90a9d7ccb73793.1604531793.git.andreyknvl%40google.com.
