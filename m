Return-Path: <kasan-dev+bncBDX4HWEMTEBRBC4MXT6QKGQEZE234FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 951012B2830
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:48 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id b185sf4421682lfg.10
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305868; cv=pass;
        d=google.com; s=arc-20160816;
        b=jowNub2bO7YQcV9ZMoqT3p6gMt+PiSXFvrZrwJYKmaRKBpg1Dx+niw12hdyYI4+bP7
         7u3mqc8mPjrl4ElCoiqgwkcOX5ZcJy/AUc9vyAD2CMp8Bl84BIZPS50rWbqa0HTdyvQC
         za39gRpW/9aB5/qj+3yWvBGOwUWxHJZS8CEralq7E8F/e4aAh41dHfmPQBSCNeiaRSFf
         JRXHxxFJjUpZUKJqLK6AWhJpatTdbHCGpZed12QIArPo5WDfIbxcVJR6uw/e7xiLT9sL
         ESmZGZAcAhve3zourlXIjkbp5jjXeKDQuTDHKwHSNYgLxK1soqA1FsmWttnsYOZx8L0I
         404g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=u3grXBjCMCaCUo9NGiMlqAaQg89gb2BJZIY0IRK7yIk=;
        b=c6bEryjRcRSiu1UHQnaZAWQlJNa7iJo1z9lkEvpqxDkDwR0EKbLipKLMP31CYV+h1X
         rtR5g0xUamds+yliEYuwz58hVYSqdg2soEdIhR9gAM7IXGmbZ17ljO+W+se5rXAjEgx4
         A4cdZve0JdlGHCHUAcjjJUUWv4IkXTZyd6ZzydtItRYLznx5j/q+7YS0QaKi5HuF9Tcs
         2NepZlEbRfEHUGMdnrILNp0/d7SR7YOEf5hxgqyeGxEICXgYi/z15DQJDjKyoXPEFxuQ
         2+xWyVcb71NPAdvZigh2P1P/kWSppphDyNbGkvdC0l9ngVcBiAlqshqkEVYIV2mjxFWP
         J2Wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CWWbP+Cr;
       spf=pass (google.com: domain of 3cgavxwokcdu1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CgavXwoKCdU1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u3grXBjCMCaCUo9NGiMlqAaQg89gb2BJZIY0IRK7yIk=;
        b=VSMqNraj+UgA1qd9pfjUpBQPOSCf8xrgXSp4iYk6FAWOOsj150oqPNl42W8zpWKaUn
         xSltp8H6qlw4XxeAsSCaEldBzBI2bfjALgMUfs73xcHMPoetvNl/qXmZff0fDQ96tQUU
         AjBYK//Vkz5OmF10a2HM7u8PSx7mHNSmwtZ1/QQNeLmIw0FZFtnM0Y6U+BGMeRb3mH+e
         RIUF3ywIc1nKw3dBZUTct110rcT65EX2Ek5VtBtp25/QwG3pZNI4w0yV97fYDSTUSnfC
         LlQvR1x8hSmjxl0ik2vHuu6JS79VFriG5OEKtI7Ra7cBFKpQvsqMPSri9TsCPeDa6UJ1
         3sQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u3grXBjCMCaCUo9NGiMlqAaQg89gb2BJZIY0IRK7yIk=;
        b=FFKxLqzAx+TT3b67HgK/r04tB7xNbEQTuKn/FPTk0dUYh8xlCRkFlf4h7LX+4yyzSk
         qmRg0Sutyv7b+bsXYkB61E7onEZWyHMQJ6jd8Y8Qgj17URi/lZfNi5rugr+zNq3vqTN3
         FhWE72hFqzTnBikYEvDa6fLW0kmy9BJI4DZTzRHvcVQ78bYmF6ae+/M+ZIUuHv2tCk+b
         1KOHlqLOAlX+N/4Xthr7RE+XYeLQlgVIP2oaU+QY1NWviVbqo4wXN3rsSStROk3wdDiV
         iaPJZTv/2f9uIPcwTXVae8Ah7JeypFLU6Ksr3+gGeukxDg87tnPBsuZsOWQwN5UEDjxt
         rGcA==
X-Gm-Message-State: AOAM5329N0OANFKqSWiIUnVpElMYLileBSoAHlNJyMsoRsYjYvYoUH0S
	Z7u87qibRJsj29NZDg0ZC5k=
X-Google-Smtp-Source: ABdhPJzoFlBlUMk01Tc11u0qRWMhKlVxifd7CBvyvScejBzjiyStbkBxz55Ejcp1+jsdtvO1qpQCAA==
X-Received: by 2002:a2e:1607:: with SMTP id w7mr1926175ljd.419.1605305868178;
        Fri, 13 Nov 2020 14:17:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:90b:: with SMTP id 11ls1496946ljj.0.gmail; Fri, 13 Nov
 2020 14:17:47 -0800 (PST)
X-Received: by 2002:a2e:855a:: with SMTP id u26mr2002473ljj.0.1605305867277;
        Fri, 13 Nov 2020 14:17:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305867; cv=none;
        d=google.com; s=arc-20160816;
        b=oDHgE75u58MWMvu0Acbr+vF6YGZHrTLmue6FRV4Br3O/GBaLRjXO7pyTKe1W1VgqQz
         7VD3i2bJH2LAploeOuSII9xaTlUOU4fQdc/nImBcA6yOdBgKvbaUayU8F3GCx2b8hXE2
         Ve8l/QdV8bWh6VDwcBygmp0B6KFyxsKa+0NWG2Sipi3XdwPwNIewURuRjcCJFsbIFhHy
         6n/o5nd+R/2Sf25PFrIIl3aP4oa5BGRfyLbIScDJAViRC2/fiKQoSo4UCXPUfL5qMLlZ
         AyIrcxbUSSyD3D7ylUzlgZ5CJUyggoPdOsQL1JhLZX/20hZYR90zspGT+id95mP44Lo2
         IdbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=xaa+VV69xly6NtD9oDw0a4fgTp58XYd2+h3RtuHf6eE=;
        b=iLspUcKndsdQoyH2VaPClWXOKnyqycWv/RMQiez3Woh9+emzrOLY/gDSM1usJ6fvTF
         LyxfwLJ1sTnb8db03oB/n23/q5NDcXJ+P4FrJt5ExzTKbIdcp19vBRPxanV47SWKhvWm
         CNRT4SDsPPTWfBEBrPzzYdus5NPp9Jmrtn00+VNhtdBOAD4D8c0Jtf4o0XPdEbS5mt0w
         YtmwNnVFXQXfv1bDcGM22905cq26Ra0Pag35+gROR7xbkdXUJDvAwJBUXzoAEMHewNhC
         m/5XuddXzu4Koy1YZAVCiDTExq4ooIjwm9zkZHy9smlYsrYm08faVxiBlI4kwPZzGKE+
         FZgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CWWbP+Cr;
       spf=pass (google.com: domain of 3cgavxwokcdu1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CgavXwoKCdU1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y11si376341lfg.7.2020.11.13.14.17.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cgavxwokcdu1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h11so4647013wrq.20
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:47 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:e983:: with SMTP id
 h3mr5834862wrm.382.1605305866774; Fri, 13 Nov 2020 14:17:46 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:06 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <53055673bff17607e42bc518dd31b56cb3e2a3af.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 38/42] kasan, arm64: print report from tag fault handler
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CWWbP+Cr;       spf=pass
 (google.com: domain of 3cgavxwokcdu1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CgavXwoKCdU1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I3780fe7db6e075dff2937d3d8508f55c9322b095
---
 arch/arm64/mm/fault.c | 14 ++++++++++++++
 mm/kasan/report.c     | 11 ++++++++---
 2 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 1e4b9353c68a..3aac2e72f81e 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -15,6 +15,7 @@
 #include <linux/mm.h>
 #include <linux/hardirq.h>
 #include <linux/init.h>
+#include <linux/kasan.h>
 #include <linux/kprobes.h>
 #include <linux/uaccess.h>
 #include <linux/page-flags.h>
@@ -298,10 +299,23 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
index 2c503b667413..a69c2827a125 100644
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/53055673bff17607e42bc518dd31b56cb3e2a3af.1605305705.git.andreyknvl%40google.com.
