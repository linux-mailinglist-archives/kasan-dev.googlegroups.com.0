Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6W6QT5QKGQETZBOUZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EAFC26AF6D
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:47 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id j8sf3328330iof.13
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204666; cv=pass;
        d=google.com; s=arc-20160816;
        b=yweBB1rgmG99NlpCPKed9HLLKqXQkIAzeZAQjGb5ozmowDsOPllaZTZixRkioYOWiy
         VlszLUlI37PoLfytgJfC1y5gM1zZSSnNgPX0lxUAbxPDBHUeSBfqsJY+BoPYj0dYOzhN
         wXJOppBTv5m1sK69vnY8EyjwjigcMsJZqLuf5j1qznaBgn9XwmRkOqBWPjpi7F0X01wr
         PBeAHjjbNCmTtc+mZvlKnM6/Pupgs3LfjudnGJgkyfGh7foy9HCrb2FmW3LahTo+EqUr
         Ubv1dQs3F1rNWrEUFC4wRxuaxaI23VgitSNw5jHZpIL77t4Dx5vO50hhO42MhYK1tVR2
         eAIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=NsaWJXNu8YL5U2gzqX0OAdv93ri20MyZqdu3BZQs0xo=;
        b=gmFHzvCSi/t2ps25uhiy22A7bUDIR7hxVTZiXaEIiqy6Qtc7YSilYm0aXZqvRRqcrG
         j+uWTYgcWAkBc2okuYO6dttxLiExZ9geR7lNGRyaLGRHMys7ykoBXsBdEa3VWnp3PnAZ
         KSh0ANQ9D10YRXFCbd06SFTC+MprID7nMMMMBlcwJv5cGwP50b4MA+mCofnkYvVdUfax
         ewNK1l1nXmyam+DDUvcke+hvFiIuaHcUm2HoG7cHrUyK32ArVW06XG7Zmc3cQFk3sZBp
         KsSXQpcgDX2/0rArBSb7R4g/MHqMcxyhc+nJZia7l8PmFV7YjuWioVqkvbS9yOhvFiPK
         0tNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JLHBY9Ag;
       spf=pass (google.com: domain of 3es9hxwokcv46j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3eS9hXwoKCV46J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NsaWJXNu8YL5U2gzqX0OAdv93ri20MyZqdu3BZQs0xo=;
        b=sb5iUWlYeXqcXcgaH+JNrkAunIASmIBalZyknX9ooQm9D6TNjjQcLWG3OVD9d1izgx
         vTF0PZXErrRUo7bI8ufEoMEQHTZmIfFFJP2gwj4VA+yVsWUHHq65dVBnfDKgtirVGKMG
         o/yYxjo2YdNPahnkvuv5O7Gv4Rp5T3L2N5sfYNqTm80PnCq9s/74Osste94T2WviHWtQ
         VDSxUzUyxtND9fiTn5NBg8RAJPvUhCxVSMCm2K2XyCFyt2VwqQqqPR98J7fr5cktRMgH
         AciRA/rphHikadP+by7vdr2XgCeHQHs4Ye1Hmdit8TQGsPTKDaWFoTUFfAErtJ7mr6Gp
         mYPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NsaWJXNu8YL5U2gzqX0OAdv93ri20MyZqdu3BZQs0xo=;
        b=SJ6V7vNoHIocn00vxdM7NIkcy5zPCbrpWeF0V3M56g9eIdD5YVEY6rDYmnHA3418A9
         fV1BwF7ENLiVArNoBRzSkCdIF7++Nm+ypK9Uuj1PuiJTpT02wYX/qJiXQJ1v0Fv+HRXI
         RKstKU+Siu4IekA0tpGBWd+P7Kfi3pGxn3+H1B/qq6LMgpEzyrfvXPsG7nKx8xA5Dy8x
         FA13a10+nhJDZI5kLcCA2/WwucmBV4aV+zksrL7kyJlvxLuo0RRlQKCi8YfAt9Hp3jun
         jiiOXJf9nY/K+0vjQ/U57ycEbqzMzgskMIGV5Fh9vBGnozAL36CABBH/d3drSBy6uHT0
         EibA==
X-Gm-Message-State: AOAM532dotgxa4YFsm1DdBKCeiwvjuYkq+2WM0tZDGvkFQyeTTMn6vGq
	FjkehHnH6z/5O8Nw0/2BuLw=
X-Google-Smtp-Source: ABdhPJzM0DrmhMsuTuKIuQ7rfag7/SPIRWWrYJQqqR8cYAs5r5MvRnqhENeie9974u0qtsRoVcaFAQ==
X-Received: by 2002:a92:cec4:: with SMTP id z4mr8391978ilq.270.1600204666502;
        Tue, 15 Sep 2020 14:17:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d848:: with SMTP id h8ls19805ilq.7.gmail; Tue, 15 Sep
 2020 14:17:46 -0700 (PDT)
X-Received: by 2002:a92:2001:: with SMTP id j1mr15769724ile.56.1600204666162;
        Tue, 15 Sep 2020 14:17:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204666; cv=none;
        d=google.com; s=arc-20160816;
        b=hf1uinUfMB00v3u3W1Bs210nIwGxI1P7sK7nqSVBBaGe1gQ/ZMjXGdlbbAlQOUVpZX
         bNYu0qPowOSdHr8CDWf8CMWgp1aZcPWKbQPhENr+7/Hyt6sYh4JdVXbVqGnEciJyUKpV
         1+r74vpX4AWNruz0E6/2rmWoRbjENO5uxFIaORENmQeaXYi/xEfZ9MJaK/kHs6Yu+X1J
         dWadAf4Rqfilz5WdWdf0KkSl/aCB9yD53W67F/RRDU7qpHjPm3PBNF4LzGBXMv9KdGT6
         0OR6E3t0QDaol7J0KZq6WhHzRhVbFIb+l2p5Vdk1vDHdf5hg/k8Q0lI1CrTqJoH6kDWX
         WsHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=D8sG/cEP7djDLTapvipoPil4TaVPwtS1uBYZ8/rqMfU=;
        b=HI/FK2+RJb3Mv2QTcrDEmcQqMQk6Orb0MTJi4N+Uw9GFuHuTQ4UjlGUz96N/lpMsil
         L5zlkE/Mbb1aA+wSgFlt1D8rjOs6Kxwc9HtzQIdA5U27yXDdmDsTlMyhVajCM1WTALiT
         CwTofv+njOsXJ0GQYNbOotqnsjsQRelZRt+0b7cEEBNwdsM5+sy1jEnwPOIMz5Nsmygz
         W/EuFddFNz4eKcVi9JyT3aMHtrXyjrL7/eh/1KIlAzn76wnCR8JrN8NOjEMWD+GStUgH
         GB+Ka1WhRQWnSdm8H2NNiz4OuMOnaRkURC+o76Tv5eawyof3Spu2Fl8I9wiNd+3hHfeY
         Zhyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JLHBY9Ag;
       spf=pass (google.com: domain of 3es9hxwokcv46j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3eS9hXwoKCV46J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id a13si1031118ios.2.2020.09.15.14.17.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3es9hxwokcv46j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id c19so4067247qkk.20
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:46 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:58e3:: with SMTP id
 di3mr3798476qvb.54.1600204665622; Tue, 15 Sep 2020 14:17:45 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:16 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <fb70dc86ccb3f0e062c25c81d948171d8534ee63.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 34/37] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=JLHBY9Ag;       spf=pass
 (google.com: domain of 3es9hxwokcv46j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3eS9hXwoKCV46J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I3780fe7db6e075dff2937d3d8508f55c9322b095
---
 arch/arm64/mm/fault.c | 19 +++++++++++++------
 mm/kasan/report.c     | 11 ++++++++---
 2 files changed, 21 insertions(+), 9 deletions(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index cdc23662691c..ac79819317f2 100644
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
@@ -295,17 +296,23 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
 static void report_tag_fault(unsigned long addr, unsigned int esr,
 			     struct pt_regs *regs)
 {
-	bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
+	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
 
-	pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
-	pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
-	pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
-			mte_get_ptr_tag(addr),
-			mte_get_mem_tag((void *)addr));
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
index c904edab33b8..34ef81736d73 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -65,9 +65,14 @@ static void print_error_description(struct kasan_access_info *info)
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fb70dc86ccb3f0e062c25c81d948171d8534ee63.1600204505.git.andreyknvl%40google.com.
