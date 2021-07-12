Return-Path: <kasan-dev+bncBDL5H3OYYEEBB75ZWGDQMGQEUC6XTCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 639A63C5EF0
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jul 2021 17:17:20 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id e14-20020ab037ce0000b029029e1110eeaasf7530754uav.12
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jul 2021 08:17:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626103039; cv=pass;
        d=google.com; s=arc-20160816;
        b=kiUYA8oEF/uDnEQZ5P+t+W/LKTg2gQCdWXP1Ni34CwP/d+/DVacQ50Vheb71mGi7oo
         9c5o9OzC/LyEhBivpKVtYbIDCVwdsVrLwVMFAi1SqedBiestPq9APuVCGOnJrYLlsP2I
         TNfYQBhl5hpsWtibNtRxWrBM9ExAgDudjBhJhKMEykHyZuXOM401u+mcYWmbuDmnFz94
         lZ4SdJBpfs1cG/6yTxkgVXHFQDiKl3e7hCQtcueaTGW6hjiqpS/oH5Vip+bsEfVeEKAC
         pd8CArxPqf9SJM1sW+hy2IluoQCL5IGsDaivwaEd7dCuRY/mdlFVediwbPMsw4fEiPjO
         F9ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ZOxFM9eEsxIbNfhaeESZlhedi21ST+Z5FVtbT8o0DHY=;
        b=i0O7LIPqMNWbmN3ycQTfn8IphALAyaljvxpjE87vqVwZNsIilkCsNpjmU9ntbW5qSC
         dn0sHX4GFKL972ghuRvm1DU0xF2v4vs3KVtlZyUFzRLZ8w0WzcBQWJ5PCw8Twzi+Dlk3
         lcbkpG3AL+waoHpkukze4rS68+SQrGddR3ptwVDlq08pNkV/bU8tRrozeS1CIiDbzDsN
         Wmf91hwHe7iXO1s5ApJGNygpFiuNveeIGmhmorE7SQqI6NVoR3jA64YFOE9WOO8QjJbu
         gAzza4Pk/k3VqpgFu2E4osl0M738Vdf3zKjqjy6x3KsvqjW3tceoCcBBIcSH/RVCU6cf
         VGbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f0JkJ7lv;
       spf=pass (google.com: domain of 3_lzsyagkcxcrjjytgdibjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--woodylin.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_lzsYAgKCXcrjjYtgdibjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--woodylin.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZOxFM9eEsxIbNfhaeESZlhedi21ST+Z5FVtbT8o0DHY=;
        b=UWIwtYElyshdJ1WpyE3T3n/XRxXk57OdmGCBYqhqchJMf6g1mvYEvOEtJE0P2HwU7P
         81gkqgtmnMEBtBOfUOAoeEKpzbhuCMscYlpYldwZMTJo9PAVpY5hY8y3w/NUUOjjNBgL
         fmfJxQ4vI0TaQEyL5R8C6IOLhewC4+6BKzn9OMQ0TG18Siwppkhe0ROKD1SI7yWtWhAs
         P6N5ijK/IHNv0hxbKZe9Q1v1m8gz6DHa6JfAV3WMONkaCGcbCvFpdvinrRMFr2iwKRZJ
         U0SMqaTFyaASPqQS1Egq3FPJWFU7VvZz1oh9/awQPycVYnFEh25PkkUtFDSUmdshgbMJ
         sdNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZOxFM9eEsxIbNfhaeESZlhedi21ST+Z5FVtbT8o0DHY=;
        b=uZY8FG6XiVE4ZASDBwG6aHmOdnxvRnUJQuvLYCpaLws+jw2YGJeQKYQgx60kUHomvR
         axogFaufGG5yQ2DKc2c0wmmc7sPscvTVGKAD5DnjN3gW1As5YEawyqwd8MfainKUV8cW
         zc2cOynA6zX0X9Mf7Zc/8GsrF0RJdopucTcG9qJdClIpIzkGUlYFfDdCsbAD+bm6lg1G
         oydJQI4KK7/xY7L3Fc1snsY/ga4UBROwHUVySfQAkmLhhMdu2VT6B0LEjS1bRfx3A6N+
         6IeQj+94d9QKf3ZuPG257VBVX/J4706+TCGhROETSfCobKnn/tZXNjciBz6x8skZJFHV
         VsAQ==
X-Gm-Message-State: AOAM531RNzPHveTdFjP+bKujXbWQwrE1iyvXyObf2mag7YjNIPy8vi6b
	eJJ8tf7ufl3fHPWaMH+7qxw=
X-Google-Smtp-Source: ABdhPJx13o+NYpTfrm5Re/ioybeltjVmwKEIB5bHlayhuS/rKiMN9nX4DHQS9Dq2A9gS26ezpZtapQ==
X-Received: by 2002:a67:1482:: with SMTP id 124mr2796675vsu.11.1626103039468;
        Mon, 12 Jul 2021 08:17:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9116:: with SMTP id t22ls1595915vkd.9.gmail; Mon, 12 Jul
 2021 08:17:19 -0700 (PDT)
X-Received: by 2002:a1f:9c54:: with SMTP id f81mr43082150vke.11.1626103038891;
        Mon, 12 Jul 2021 08:17:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626103038; cv=none;
        d=google.com; s=arc-20160816;
        b=dVJkZ7A0Aq8sG32sA+ZAG+tM9czJcKO3eBdItG+3xmk42MLgrH/9pOGGyIBIWqxIVw
         Gp4WB4ojCL/xokMqOpou6I5BZXjKHnjF+PXK5UMKJlLwM/6F3/7F/pLJ1avy712R+f5z
         NYFeT32gWoPEzgSt8tk8vTjpkWnjtr8IkZ2pWuoiWY57katTBzWwhhnemUSW/kkkQzLh
         Z3EAoE+6J7uRV7LXs+ata9iKxE7g2hlIUD9eHFOLKwfPZq7Rwwz/BuhqYN2h9t7h6tIj
         4XBJWQJj+OXxWV2rMRRDjH4VXwoGkQEiqEKbdFSYs3KZoKtSszele6RDsoK9GiOqk7Ak
         uWKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=F183fJF48DpZvlb4sVM7Y2bwjFLi2q0xYlbUr8FWRkE=;
        b=gWbVtLhoqNamTvxhaD2XEQj/elm6F0f2SIXWIqjQ9gf9yiK4rrBI2M4s3L1IoySqrS
         0sf/0TGSALfSr9dbv1VE/u2+0IsptOa0+jSc++2pYXKszrUjjWJBlg8xlOWOKQSDKnkF
         tYVp/+oB2fIwvoB4AhDcgWHUAsCfatb5ZleVyfM4QYjC5vo6SlyrpPIJ2gEELjXZWbIh
         MddkzBloBQdc72OXRWpLdkFerZB3iwLRlSqZayCPO2d7tGcQPK9kLATk0ok/o3ArINxd
         e7EOWpGRjNAMpIGaPMdI60BhnTKKf7QCsZCypz2R/L3estz2V+CI63XOKIS6dTYFEt2w
         wQnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f0JkJ7lv;
       spf=pass (google.com: domain of 3_lzsyagkcxcrjjytgdibjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--woodylin.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_lzsYAgKCXcrjjYtgdibjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--woodylin.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id f4si1329439uap.1.2021.07.12.08.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jul 2021 08:17:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_lzsyagkcxcrjjytgdibjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--woodylin.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id o11-20020a056902110bb029055b266be219so22672430ybu.13
        for <kasan-dev@googlegroups.com>; Mon, 12 Jul 2021 08:17:18 -0700 (PDT)
X-Received: from woodylin.ntc.corp.google.com ([2401:fa00:fc:202:8c53:eec1:7238:4b4e])
 (user=woodylin job=sendgmr) by 2002:a25:6046:: with SMTP id
 u67mr62050233ybb.6.1626103038450; Mon, 12 Jul 2021 08:17:18 -0700 (PDT)
Date: Mon, 12 Jul 2021 23:16:18 +0800
Message-Id: <20210712151618.1549371-1-woodylin@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH] mm/kasan: move kasan.fault to mm/kasan/report.c
From: "'Woody Lin' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Woody Lin <woodylin@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: woodylin@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f0JkJ7lv;       spf=pass
 (google.com: domain of 3_lzsyagkcxcrjjytgdibjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--woodylin.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_lzsYAgKCXcrjjYtgdibjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--woodylin.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Woody Lin <woodylin@google.com>
Reply-To: Woody Lin <woodylin@google.com>
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

Move the boot parameter 'kasan.fault' from hw_tags.c to report.c, so it
can support all KASAN modes - generic, and both tag-based.

Signed-off-by: Woody Lin <woodylin@google.com>
---
 Documentation/dev-tools/kasan.rst |  2 ++
 mm/kasan/hw_tags.c                | 43 -------------------------------
 mm/kasan/report.c                 | 29 ++++++++++++++++++---
 3 files changed, 28 insertions(+), 46 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 83ec4a556c19..ab8e27d45632 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -203,6 +203,8 @@ boot parameters that allow disabling KASAN or controlling its features.
   report or also panic the kernel (default: ``report``). The panic happens even
   if ``kasan_multi_shot`` is enabled.
 
+  Note: The boot parameter 'kasan.fault' is supported by all KASAN modes.
+
 Implementation details
 ----------------------
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 4ea8c368b5b8..51903639e55f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -37,16 +37,9 @@ enum kasan_arg_stacktrace {
 	KASAN_ARG_STACKTRACE_ON,
 };
 
-enum kasan_arg_fault {
-	KASAN_ARG_FAULT_DEFAULT,
-	KASAN_ARG_FAULT_REPORT,
-	KASAN_ARG_FAULT_PANIC,
-};
-
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
-static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 
 /* Whether KASAN is enabled at all. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
@@ -59,9 +52,6 @@ EXPORT_SYMBOL_GPL(kasan_flag_async);
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
-/* Whether to panic or print a report and disable tag checking on fault. */
-bool kasan_flag_panic __ro_after_init;
-
 /* kasan=off/on */
 static int __init early_kasan_flag(char *arg)
 {
@@ -113,23 +103,6 @@ static int __init early_kasan_flag_stacktrace(char *arg)
 }
 early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
 
-/* kasan.fault=report/panic */
-static int __init early_kasan_fault(char *arg)
-{
-	if (!arg)
-		return -EINVAL;
-
-	if (!strcmp(arg, "report"))
-		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
-	else if (!strcmp(arg, "panic"))
-		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
-	else
-		return -EINVAL;
-
-	return 0;
-}
-early_param("kasan.fault", early_kasan_fault);
-
 /* kasan_init_hw_tags_cpu() is called for each CPU. */
 void kasan_init_hw_tags_cpu(void)
 {
@@ -197,22 +170,6 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
-	switch (kasan_arg_fault) {
-	case KASAN_ARG_FAULT_DEFAULT:
-		/*
-		 * Default to no panic on report.
-		 * Do nothing, kasan_flag_panic keeps its default value.
-		 */
-		break;
-	case KASAN_ARG_FAULT_REPORT:
-		/* Do nothing, kasan_flag_panic keeps its default value. */
-		break;
-	case KASAN_ARG_FAULT_PANIC:
-		/* Enable panic on report. */
-		kasan_flag_panic = true;
-		break;
-	}
-
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8fff1825b22c..884a950c7026 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -39,6 +39,31 @@ static unsigned long kasan_flags;
 #define KASAN_BIT_REPORTED	0
 #define KASAN_BIT_MULTI_SHOT	1
 
+enum kasan_arg_fault {
+	KASAN_ARG_FAULT_DEFAULT,
+	KASAN_ARG_FAULT_REPORT,
+	KASAN_ARG_FAULT_PANIC,
+};
+
+static enum kasan_arg_fault kasan_arg_fault __ro_after_init = KASAN_ARG_FAULT_DEFAULT;
+
+/* kasan.fault=report/panic */
+static int __init early_kasan_fault(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "report"))
+		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
+	else if (!strcmp(arg, "panic"))
+		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.fault", early_kasan_fault);
+
 bool kasan_save_enable_multi_shot(void)
 {
 	return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
@@ -102,10 +127,8 @@ static void end_report(unsigned long *flags, unsigned long addr)
 		panic_on_warn = 0;
 		panic("panic_on_warn set ...\n");
 	}
-#ifdef CONFIG_KASAN_HW_TAGS
-	if (kasan_flag_panic)
+	if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
 		panic("kasan.fault=panic set ...\n");
-#endif
 	kasan_enable_current();
 }
 
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210712151618.1549371-1-woodylin%40google.com.
