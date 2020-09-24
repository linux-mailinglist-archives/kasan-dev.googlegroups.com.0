Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJGGWT5QKGQEXYSFK2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E754277BFB
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:21 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id j134sf169478vke.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987940; cv=pass;
        d=google.com; s=arc-20160816;
        b=dVxYEJsXkq22O4Uj+N680OitEO0ni4CxDT4S3YuNMWX0mbruKcdzs6018y4ZY29aOQ
         XnGyoL1nz/4a/SiJu/3JqB218HqLrlGexgXCGjjQZsacFFPSEsG84akhPuLZdhTESjEE
         T0d8BkW5uYSI4d2u7t/TgF1ZTU3TMw+wtR18E8PFfxdQ3AhInjxvpyVtfegpZ521CtFR
         0n66F8JRybiK2jV4iYXN3SjeqZGZpW2jShVyhz70FGsuaIWuBB/fmX2N2hP7ZQCTkt5H
         ABz/ZWfIH4mdUYndpC+nVhSb+vhwvk6BhQimO/pKtJCHjA3RmyD0KjOxwJtr8l8zX30Y
         7Auw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=kAtWlTlfLvw6sOK0x1kTy67vRKRkaqUWD004+bgaQEg=;
        b=UTNEB8gt5fhZNSneB9BsWc3DKMvLkdfJR/boua/Qq+kIxw8091QS5qKnWzultYCfip
         9mTvK5ppWIwnq/gyEr1yTeKs3TFF6yQ3fUY012cHGJayqwa1A8FAnSn1ndblLd5UiPCZ
         6FjBeTdQn/nR2qF54VSTpG2BMdvhveNCsskW7L/6WZwgGwbMs1ie8qaSO1wA3GQqfxXH
         JL4EHSrEgLxjfcZgpNmhLDghiwn6zNlpm7wx0E3GJdiCNHbsTSbQVJVtXbWSiUAWVGUl
         aFvD7jjzjW4RiF4NX/coVXfV+65WfbpFXF/2EhkL/1ern/ztX+/cEnklh5IzQ7Hlg1h5
         c7KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jrGnJ+BL;
       spf=pass (google.com: domain of 3iyntxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3IyNtXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kAtWlTlfLvw6sOK0x1kTy67vRKRkaqUWD004+bgaQEg=;
        b=q0yvkJgZA63MmAOmPwjvi0B8Jjti49SyT8pbkeEDWXtzzDAGeqQE4tR84/5hE+sAvu
         qZuF+6ciCDdNnOcWV8skI0Qij02egF2QWZcJHDw9BYA9P525w5H6AS6TjPJ4T/bi1U3d
         /BlrzZAhlR3Ai0dNLQk5Ra/d2kceb/cZWPKzdzfzvWLwgvWbH4B8ZRw54moVx5eQ4+s3
         4lFgm4SDji2HIPTEk3dtIEHOmkAw9DJolzjpMI0aCB9qKlPh0fehOyfYxh86yHK/y9S1
         CyPhKTCXCjVFvp015cFTPWtxhnAhwJJyIPe3pjtq/tHMoqwLfzH7u7k9ap4zrKT+3uiA
         WBMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kAtWlTlfLvw6sOK0x1kTy67vRKRkaqUWD004+bgaQEg=;
        b=flFM8zA2Lbs5i39TBiP7d2uY1P1E7a9D+nOCc/zaGN8zWFzJ6ZTQkrz6fUlNSetQZe
         6I3NWzycf5nlfjPyZxSnltbkbDRelk10azoTTCbo9x2FqCE+P3rCxVgEsKdqsW2gAjC/
         v/JpudszcNDgZZeNpE3QE0TnLXhSk7lWlrCIgSOYNjrAUXvjYPXlw/m29j7VCf528ZrU
         9C9dBapsnMh1BqCQAhC82zoSKMwPCT8VP7QEjx07JdRdhL14Ac+VECK84URF/yGLj/4N
         +aOV0b1GRyzsYPmAS8AmyBuhjV+mHzn8fezkF5awc41rc07xr6oeC/ZmQmGB5qflrkL8
         VNhg==
X-Gm-Message-State: AOAM532QRi95qQoQRf62fOR0Y8nfip0bGhQNdFqkP0Y3QjUxIK4Wkymp
	5dv2jCE+VqWouzLl3bc4hX8=
X-Google-Smtp-Source: ABdhPJwZnxFGeNvdKQK9eeNkL0LU9gtnn4H9je+fZ5hnwPXu1KoOOPMDDDCQ+fEo1iWVBEGYptEJUQ==
X-Received: by 2002:a67:18c5:: with SMTP id 188mr1310651vsy.30.1600987940254;
        Thu, 24 Sep 2020 15:52:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2e6:: with SMTP id j6ls136096vsj.1.gmail; Thu, 24
 Sep 2020 15:52:19 -0700 (PDT)
X-Received: by 2002:a67:383:: with SMTP id 125mr1267014vsd.9.1600987939820;
        Thu, 24 Sep 2020 15:52:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987939; cv=none;
        d=google.com; s=arc-20160816;
        b=TkPwC1NjCnlKeS+9QP1DHs2GFTdIWHQfyeFO4dGnJlxlFVWY6ghR3BEtAEH8+RXG/O
         gYOAmhXLGoGIt1IuhszoOk89JL+mZno4pr8ltp+Hssti+HLbx03IkLq3RKZHCYod1gaX
         ZacftuXOawLU9tO8ZEhQO1CV2YpduRDOo1Tg9r72ANy9NPqvHqpRAO5QYFWvxw5gNIfI
         BLmkYQFtJcck78TwKMEby8UsjIhjOZKsaRKkLdKprHdrDAWvchYbNDYiG3K/ijC8sVH/
         LFh4yOTsZ2m8B+qyUZHnkFpgyu7guEhp198b88TfWUlABHY44qZFENkzZlmq3Q8Y32oU
         Z9Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IS9ZsYB9v/N3vPDTIy5S5K93CUEmQWaPqYVbAcaV4Fc=;
        b=VMoP2TaDrMuBCOqVD92suwDfGA/zOCupey6kwtEwQ7n1xf9WlXE4Xahm5sEkm0S20h
         8W7ltFxBzteuIUAoxETRyWG5G77HGyIIIClxtBo5IFSQGVw9WYzfeVMOF4cjyzQLm/+1
         4kKDK/3/yduZzL/e6EiZ3RL4RIN6kTrHfZt3ph5HZqEURVGpx0g+1wdUxD4iFlXqJAuy
         QkpS8hGpn7y4hohOYktv3oXsMh60uL0Kc52w4V66WHUie0Q+yj4lHLEW9yjnwt8cZB64
         WI8DoCnnvsuCktWtLTYTTn2EebBSfShqXYsoJezVOt+0Y3iB1ljG7ZW74SKdmcHOQJLZ
         uSKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jrGnJ+BL;
       spf=pass (google.com: domain of 3iyntxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3IyNtXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id p129si53048vkg.3.2020.09.24.15.52.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iyntxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id w3so40632qtn.16
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:19 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b31c:: with SMTP id
 s28mr1643871qve.17.1600987939311; Thu, 24 Sep 2020 15:52:19 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:43 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <6296d106e480eed388f86e3c8fce10a14bead75a.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 36/39] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=jrGnJ+BL;       spf=pass
 (google.com: domain of 3iyntxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3IyNtXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6296d106e480eed388f86e3c8fce10a14bead75a.1600987622.git.andreyknvl%40google.com.
