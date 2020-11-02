Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZO4QD6QKGQEMRCR2DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C9AFC2A2F2B
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:57 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id m11sf5967802ljp.21
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333157; cv=pass;
        d=google.com; s=arc-20160816;
        b=y3nD/LAc/aGA5bHS1czH1nnWmgBu0yGHRS/yEy9e6tbtt75osfhcpsrPTC3XENsCG7
         rpnzY6Y11rmSDn5QviKgdp9Nym1lcwhQMIcjEOoqzRf58GqxbtmSGWP6hutCgSzF8KHb
         gzvNHNEM9HLAS19XTzIeksn0p5sxjX7GTqAdVrh2DnSd9ri1gkNn4aYCRZ0A2vTgz8/R
         0COp0j2AADbIxig8v2giuL5y6Lcc4qw7uztPNldSgAyVMUNMbuDCK/NbzTQuiCNlLw8s
         wxuQGLIs+Jm1iT3KUwKNJi/V9VoR1/VwMqoZVKlPslFXySuTFm+envEJyytSNXHYdtq2
         urmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=maUItNuMhFM5jYL7lqGY028ffYSDIA9474P9lSDnpjQ=;
        b=qoxgVzZn9r2YZGQpcdBGbVT5qBAUFH1xK0DGA7HbmOZhCcE3cE6OD61FKkP6/KmFZb
         VrO+UJ7j3OK8PQ1PqnAtVfxYMTcdlSXGwPHdAGhu0CnF9nw8Tuz5Vrr483vyWsHn3bah
         9xsGvHn48OMXzHZlsPpZ71+4oU4k6Lu4OOxSwu49kZSgFV/kZN3oSZDqtJDPzRZ2r/QI
         gJiB2StL6hAqtBH3jdeZGyvZ0jWRjMJePTyj4C+Bpj7fSbHgvBx62CItZ4wfHAOqaCDZ
         s5u5x5viTn2Q4LM9qmsb2b+rge9DloRP6jWfOycIJxpqrN30nqoKw6GSIbOcDEV+hQiy
         rg5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ReVmikUf;
       spf=pass (google.com: domain of 3zc6gxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ZC6gXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=maUItNuMhFM5jYL7lqGY028ffYSDIA9474P9lSDnpjQ=;
        b=hOeiNIVLylJO+4GjEhKRyAosWYnCy6Dv/3AOKD91NJ2IPCGXQXgYxBeVkmtPZhI00s
         xgcTRhzCwF6sYCMlmuteDH2eVYexjay2T3I12Pncl4HjXNttEbz7P9Fb+4J0bcvT6L/U
         YtUVKG7YduaDYwJlvEhKshO0B0sY2le4dsqIlDpNTs2IJHuO3FoLyHZzNg9LiRO3Qk2r
         pa4Nx4s6k7tdRagFJfd2tVyBYDAQ/vC6rp90wMUem/UQfCpgvJ7etfVK1EXZCf1GEspK
         LNwPqMw961RaCj98AHUz/MiH9QAoDq/DY1ZPOjKhDe6afvEpS79ARUX2Y+tAkuhIyiJh
         yxog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=maUItNuMhFM5jYL7lqGY028ffYSDIA9474P9lSDnpjQ=;
        b=MCohIzZmp1+c2RsTDyHCNvF5EKtexX7WqrOG6Gk5aZeiT/bDqfuyhlvebKfJ8TwzqH
         rQmjycluwPAUdbpnznp5YlWVLWweIP0kK3rqEUMINUYQymXTZSNH3b5PyH9Vo1rcRgBj
         dxGVKcxauHZte4bQigJ90dRfc6NACxVo5GZyZD6tmpNuCXSjSKEMGC8jbWgNT1D044B2
         s4MQ60Vf/5YCNkKwARSoasNy56R4pIx05JzZZ2llyVydopJ88XlzJiJGU3XUT+kEMtCE
         KWOmyYj4dD4xQl8uIOjHh4qZzaxf8NLEH0rdEbM0QOtdSjFQslP3xc5GXc0CPRY4Rh0c
         J+IA==
X-Gm-Message-State: AOAM530nwMpW0MSwcjugy0wdqTt+6/AXT/B5Zu6U0Dj4C6QLae25SibX
	2SYWsZXB8Cenn5ZsqQnRoUU=
X-Google-Smtp-Source: ABdhPJxjIWo5Ko4lep00j9mh41NDNrXGnM/sEG/TSuSeW5G94D2IT+FO8CeAqD6zbCiriGspQjY7TA==
X-Received: by 2002:a2e:8945:: with SMTP id b5mr7445191ljk.220.1604333157387;
        Mon, 02 Nov 2020 08:05:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls1376383lff.1.gmail; Mon, 02 Nov
 2020 08:05:56 -0800 (PST)
X-Received: by 2002:ac2:4195:: with SMTP id z21mr6690572lfh.259.1604333156516;
        Mon, 02 Nov 2020 08:05:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333156; cv=none;
        d=google.com; s=arc-20160816;
        b=cArekGq0K4gnCC0yxDM8pcYM+l2ApnteOjHHmji3l7835wrfJiIMW45ocrXZdvISAj
         ECs08j7GxP4SIxnV0VKOY/I36pG83CnIVREkWaDdiEJ7Nokguh0Habntun2fYQTLEs+U
         CHZH4sb+S5XDi39PXaqYdEObA+uhU5rF+6LikcIetwAHsCpUP9K9crMOzeA5xh+BRnEF
         V5eDro7bb2PHswrQU59W41DTKGhqj6IiTEHf4eMPMWsD+am61hQXMQpq6KjTrwYnpCS8
         wiR+GQSVO1zO5XwIhNWZslsS4KxJknuVlRVIoGNOY5ZWNFgARjI1VpAACskdIv7rg18+
         N97Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=35WbJzPGlJ32SG4OmkQQICRjm1+Un7MaGRWzBQ2gFy8=;
        b=b6TXXEMtN5c6ZOITNeAgfHAHwL21U4nFHa27UnmYaRzw4ygmghG2/xuNhF7qCHm5uq
         HWrwrj3G/yDRAIu3QFb+lJhyI86ej8WPE7OsH1dZrjLLdp9RXOvkdOMXCeDAFrkXhNeX
         mDrlFg2bTbhX1DDrEGgxR0VB3f8p0YbLPSybwLfNU5LkDazsx/aEsev6yvvwzbb7RghG
         u4tOnf78zPFUqxA9cpRboOTkYNSynqZFjUHoTTezBKYsI5QcBj1RvOuOhIhvhybTLO70
         2Oj5SpAk8yrsIWsULiQnUbRMAyxHUZlkvTW2LiZ6kiH13p0qdvZxTivHYA+syIgZq0cm
         Aj6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ReVmikUf;
       spf=pass (google.com: domain of 3zc6gxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ZC6gXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id i16si462565ljj.3.2020.11.02.08.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zc6gxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j13so6655291wrn.4
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:56 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c845:: with SMTP id
 c5mr7825433wml.135.1604333156027; Mon, 02 Nov 2020 08:05:56 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:17 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <f31c5b0e68d839382d3dfb8c879ffb34cf5457fb.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 37/41] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=ReVmikUf;       spf=pass
 (google.com: domain of 3zc6gxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ZC6gXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f31c5b0e68d839382d3dfb8c879ffb34cf5457fb.1604333009.git.andreyknvl%40google.com.
