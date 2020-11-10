Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXFAVT6QKGQEZDMFEHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0472A2AE2E7
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:45 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id j66sf77716lfj.9
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046364; cv=pass;
        d=google.com; s=arc-20160816;
        b=gcAm8S+VqqY1s0kFjyWS6tzr9eWwR6fK/2rkKUP3XL8hTz5vzbsc6WqX1XdhlPidCk
         ii71DPuWltC5xAHiNQsm36LxlIBDjIN88jZ9LOsu8OjirnMRGoZykvo+ckXIIZb18Ela
         7W8Ny0gfu5IkEHT4ZRTv8PBylHMHDppLuWmA1/QF3TuPbI3i/onfGlj53KeGmLAzyRMG
         iOSrwnpbFGwuR94vHtyHH5bOKv4hMKg9V6c8wtYoM+3R0Wbf7uBXgWxWfSfN/g3P9ql4
         lrKpMTxO5nAu4+Lp8j3F88pLxwzcNxAuggkrcdp7apgdMQrg6v5NuuN97bt6X2vXB7Bv
         LNzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ItzRPKDC6GREhN6KHzwzsWK6/5+TrwE0hW3+GQnzMD0=;
        b=elnU8f7ibQJSa8V+6Sgj59ABTBHtxF+af5RfjQ2tVBYsrA5u2GTKFzSlJTbhj7QcXE
         eOk8yE6wXsWvO8o1tXhsiMPB8OFINUSq5n3z8y55166mzxyfitXWg9u14tIgf2u1Xjpc
         42xUOo+Pm6d8xNIRJIlMVDlz0o46kdgwIwclA7ivW/YEJgxTZa/ekVIP2PgfKwb4zm1Z
         ldysC3a9EC8QgmtHtONFcu+F1qgp7EQqnWTZLrlDcUakCLFsFJUGvy9fRM4BM5Y5NcHb
         HcYiK7SAYfFoKkhzrQ2qIAMrgMBmCBQ/d/JBPH2aPQ5fHKcsb04i2U3ynYQpg65ABUpQ
         bNBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Y/jR1dsz";
       spf=pass (google.com: domain of 3whcrxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhCrXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ItzRPKDC6GREhN6KHzwzsWK6/5+TrwE0hW3+GQnzMD0=;
        b=bYjY7fzBzajxvUY+N8sWrgWELFsA33TJlL1hMoztpx9JYOG/bLUylkkLgbTiSedrCr
         R4OeHclNcZohFfKWvpPZLh4FoOBu8iVY4CVTZvtLp8qWQCoA6mJbfLXCAPAtNZFeV629
         KB1RiSkgNloBE3lool2aP2Zm79i6Goe5Hwh2hsSIZVA7hm0sYHxO116jJDpFnLe431I5
         K4LpaSb9LqbyesPY6zK2MCqjIcaOF4N37/T+7q35PfTVifVjZDal0U5o5g3/ILpiUS7e
         pZwJk363UhqVnDIdgDOnEOFcHFfbbBVS0KOVZLByfAnHjWbiqTvGQ3VIXcChc8aDgD//
         jgFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ItzRPKDC6GREhN6KHzwzsWK6/5+TrwE0hW3+GQnzMD0=;
        b=Swvn7fjfHYiVltVbM5Mkz5easak01NDADgb9A5Jv21aol2rvSN2EsiApuzzvdrNORn
         2Gu5zN/s5VODMV2eXbYkb7Sot55kICBEG1wIWDzzS8roGkSAgyv/Y3GGx7mzi+cuY4fP
         z5GGvi+B8uPT6qp1DRdrt9LkTLq/AnfGEt1FZ4XErnR6LpXYlHD8Y0fAOvAbGahkVAbC
         SWuHgopTTgBNXJvqDaVm7+Sd5weiQ00v5N2MQUwT7X17dwz/Nj0AbLjEooUjzebCRFL9
         UMnMO1j+DP4j3j3FdUG152Lo20rWnhaq0FNme54t8pCwFHTZ7SWRsmJj86xK0C88LG3T
         w8sA==
X-Gm-Message-State: AOAM533EvUhLLuDhF4j5/H6MPYWG+0FqXobKbnjDeFJclkeG1jnUKShn
	1xKdDKFfzBXsB8xeqjxE1/o=
X-Google-Smtp-Source: ABdhPJzeBZQl9Ron+EMeQohJZZrcnhadkN/S612vwkYSQ8RpTj1zAK51zaEzZJERPeDC+KDx/hn5Sg==
X-Received: by 2002:a2e:b701:: with SMTP id j1mr9586462ljo.242.1605046364486;
        Tue, 10 Nov 2020 14:12:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls1295208lfg.3.gmail; Tue, 10
 Nov 2020 14:12:43 -0800 (PST)
X-Received: by 2002:a19:484f:: with SMTP id v76mr6592698lfa.142.1605046363461;
        Tue, 10 Nov 2020 14:12:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046363; cv=none;
        d=google.com; s=arc-20160816;
        b=NhwTwlxKUE7BxYTX9BtRHKQTsESDXphQ+UvyfsqdO4pk/mG0OGj7WLWCAGc34WAQtK
         C9R/Q0kkliSl2vvmeAAh2Sm5s29ONftbzhsX+zXKPnP3WuBuDhpy/btXW4SQD4JPBOXe
         f3X7JkUKeNkbsp4cAvH8eHBp3lOVOIL4d0cTgV4xS4Fw6/WZzWYNysDCUVJsahszCGQl
         n8d1Ia8e97UL6ss1rsMG4Gdso/r8fCzDQKiMofBb0QeFCcsCui+AbRpLG4XZQDI1y3io
         Uv7ruUXYsDtHRyd4DRTyVZ0Vc1INqRp2e4ouvfNYk1r58fB5QohhZf9MpHmHCn6MfnG3
         iLsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=/sxzdyvi8KkfW5gspThP8KvseoTY7ROsnu5nrXDzCag=;
        b=WT2tGtxmJT5dTsv2Zn1r3T//ln9Zf6vtmGxJDjpOxR9ufTJSMZ6rbICstK1lajP1iz
         PKHhuI5JYkUT/fUJF09H/tFvfvB4HhLIwxWUGzpReiblz4eR2aKGpBmUL9Nbg+7CoCLw
         Nj/+RKkf5lA/Llv44SogQiXqADtgfL0xsBKLyfGlS+CdhFF6mGTqv7mZrFhHKwwh0VJ+
         bxtuivJSz8UasJRhpfVTnJGZ1A1Cu6IYelpn8yc3HAPwZTftbUKei31ozp7sWrKiqu70
         p97Eu2TgobroNVn780poubxvafCV4gvzN97cY8Ogy/56PK+QN8mGxTYS3yr93znrQYdh
         h2UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Y/jR1dsz";
       spf=pass (google.com: domain of 3whcrxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhCrXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id y11si6257lfg.7.2020.11.10.14.12.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3whcrxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z62so1669085wmb.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:43 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:109:: with SMTP id
 o9mr25232534wrx.240.1605046362785; Tue, 10 Nov 2020 14:12:42 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:37 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <fe78d723ba64456d68754a944fa93fe4a25c730f.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 40/44] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b="Y/jR1dsz";       spf=pass
 (google.com: domain of 3whcrxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhCrXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe78d723ba64456d68754a944fa93fe4a25c730f.1605046192.git.andreyknvl%40google.com.
