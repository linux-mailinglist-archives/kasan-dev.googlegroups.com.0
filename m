Return-Path: <kasan-dev+bncBDX4HWEMTEBRBS6E3H5QKGQEDJ5TBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id CC82C280B22
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:12:12 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id ic18sf200136pjb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:12:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593931; cv=pass;
        d=google.com; s=arc-20160816;
        b=L1AiwfQRUmr0fz7P3kCzjvW1oWdrB7f320Aq3seHHev5i7qOkMr/JoBeMMN76Eqewv
         Wza9o2muKRqvNmUa6NIkVBDOsMAfugndBPBBjHZndXzPiavwHpJ13NblWYoCqh11oqXn
         cRGzm0/9RJ5pgstx8ZvdKnRWZCWnWoOwz7kCRopqVOXQkwFRjyhDMz2b5eE8tyWbYVaV
         XdzFho9vrs8xxUYR16ZowmEaxhNGEIdl6HyvIllB2i+QabBW8e43A/8opodqe1WrIzFw
         XN3z+kIlN4J8b1WEVlyegNvq1RaR6hsN0CQ06Aw95OotGkL8a5cqoA0p7dWWYPBegcnm
         3K2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Psbj5hk+ke7EI4ttQNiYguTPNPEh1+Z2t53W6gKL8x4=;
        b=bTlzo5dF9PGuegkjtGaWWM490xxUJtprzpqOE1+TknTgMEZV4cM6zfQzl/3FIVQ56t
         3v0W4HEUauldQF9pnJ6s+JL5tICBowlFhxTCbcuTKao7TOTH4oYTLmOr6Bme10i1OoN8
         srs44oRW88BN2PO2pLM7SfNPOkfK69FIk8p6Kc8DjLBIZ+NIJ+sp9B7KhRlyY3Y8d3Vm
         Kb1o9z8o3l9AiRiH715Tyupb5aQt/D2RJcXJ4ASKr6bAARdTsxcYXGlvkdIQa11p9HiG
         a8NagER1I52K13fhObicGXS1PVM7LKe5VyhDX0cif7h05dbHI7kSdi9+sE+FalNeUsLZ
         CPEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XXVH4kQG;
       spf=pass (google.com: domain of 3smj2xwokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3SmJ2XwoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Psbj5hk+ke7EI4ttQNiYguTPNPEh1+Z2t53W6gKL8x4=;
        b=kAqi4Ypnql3VWjgYcM9Ww95ftNx2zBFJLqIwD29ZAdpQMl/zBwja/8EWk8aDRhaxxn
         YKuVUMb45KYF83GKy2oSHUBY4T3qKTUFM01DS9P2P2YyreSFM92DLes8X14jkp1ySK11
         aFvSDKN+Wg6sfnxf7RB1X/oVPizWabUr4MHT5PwRTbU6IkTE471mx9jdWuDLfTWNUwys
         2vqueKq/XDSTfWbza4l0aHpor0bOeZFDfXya0y9pxNFIVfDsD21hgtwwpwp4k+tBYIrS
         OtQoM0h8UpW/lcY8G2WLXtS96X9DfzrBBDZDJHmuc49Dz2Gnogu9ZgVVeG3dIt9DvQOz
         nvWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Psbj5hk+ke7EI4ttQNiYguTPNPEh1+Z2t53W6gKL8x4=;
        b=i0gun6W37cRhsni6xATvC5d574FJYtdbG5Rl2fKb/jE0tOOdnpA9QXPPAZn6Z/IsI7
         X6ZrqjWciM/zast5W/29izEgTwruJD6xKZyOJ9ZSXbxDOpt950Flzxyv5jzuPe7EA1yU
         bm1K19tFBEMFy487JIM7RH6zTpSdEQZhp/ZJgc53xMI+wdsPfn/Jf3N8sCntVMkDV5/s
         1DK9rD0UkmCqcUQ4mj7a7VOtQL2OcOtwgcVBTOyE+e8AA1HNNgAfVU6ynG03bR5+APmp
         aKPZSP4ErxrIYQnUanx88d1W6r+s/oGMycywpbWQto14An7tO52rnS+dhqxrAlzGnlo2
         t7TQ==
X-Gm-Message-State: AOAM531wKwKab6qudl7SOHdnmATtKIH5r8DtkLaIEgps66fEuVyC4HD8
	KcjBpRBkNfYrNgwrrom+vJA=
X-Google-Smtp-Source: ABdhPJxw9u/o9TFUKSpvDpUERBcY7V5BnEgi5vjaGRf9ZkrVCjo7Ws/DGj6uvcVJT5DgSZjb5Jdraw==
X-Received: by 2002:a63:841:: with SMTP id 62mr8247825pgi.35.1601593931545;
        Thu, 01 Oct 2020 16:12:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:480c:: with SMTP id a12ls3023218pjh.3.gmail; Thu, 01
 Oct 2020 16:12:11 -0700 (PDT)
X-Received: by 2002:a17:90a:cf17:: with SMTP id h23mr1485996pju.201.1601593930940;
        Thu, 01 Oct 2020 16:12:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593930; cv=none;
        d=google.com; s=arc-20160816;
        b=Nj1r8IV+DgGTh1H4e9vYlKDMKOVZ+2NxR9tlBht4HEksTuPqGlQkGvHGOfqs+HNS66
         7M/s/b6zGvBr7LC0fk1xYsZk+Cmy9CpGmyb8aePURhfuL3KK03v4jmKbDC4CdV6ae0rK
         fexP8qjio60FaXmD7H/J0Tl2fVYgavRVLpMtDPpV67BubC0DFOnuCYvrBc776BOTQdKC
         av88qC1f6gH9KkpP33LAvcUu4DxrZ4ShLK3PYf4TdRJri1Bgo1bOSm+4HxT5Gz9TAcmR
         TNO4Dy3j2Z38UUB5UzPmlP1AjdpvhfhfnaWafsXqqkvVjxjfcu8+osD/2wzrssnc6Cqf
         bvYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=C+iBtL4ZEIj4wTVvYUlhj1NgYSWcn9LosnxdDa1AU0o=;
        b=jZAyae6uqB72LW+HDPSc4xHPFxulzN0CeiZpYTj2gQCKFnG/Ty1DeRJNKfJErnTjY9
         G8ziwFu4hMXvzlJ+QmRctMGWYcQK50krZDYo+LxeUPKfrGjwNU6wHjF5hWsSiJuszU+f
         xv/mMibBVIXMQUFQI6cpkfyPbs1chEVsj9rrf00jYWhpKnprBPPMSMp8/H6BcOs1dwWT
         jp3QTTns+Y1/n3b8/YT5n/wUdijyznL+ewyunFmASUQDLzFe1nYjShooXgH3FuCrrx1x
         rowv7Kaa1DqrNDHzwT9EZlTRC11hMefywF2krlCwr1GCnmN0BclXixI29B24+MwD2X5Z
         FZJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XXVH4kQG;
       spf=pass (google.com: domain of 3smj2xwokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3SmJ2XwoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id f6si393866pgk.3.2020.10.01.16.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:12:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3smj2xwokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id p20so252809qvl.4
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:12:10 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:8f2:: with SMTP id
 dr18mr10070980qvb.49.1601593930474; Thu, 01 Oct 2020 16:12:10 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:37 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <10120a10ca12074ff3172c90e63678c27224b024.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 36/39] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=XXVH4kQG;       spf=pass
 (google.com: domain of 3smj2xwokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3SmJ2XwoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
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
index d110f382dacf..1c314e6f7918 100644
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
@@ -295,10 +296,23 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
 
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3924127b4786..f8817d5685a7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -60,9 +60,14 @@ static void print_error_description(struct kasan_access_info *info)
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/10120a10ca12074ff3172c90e63678c27224b024.1601593784.git.andreyknvl%40google.com.
