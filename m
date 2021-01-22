Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBAW7VOAAMGQE2FVGJRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 755A930073F
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:30:11 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id k66sf2274111oia.6
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:30:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611329410; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZEJqhHHHIjjMIrXpDZhWWnb8bY/NZRpd/qM2uLWM5AKGIOtUOLxxZhFfqjJy1SK2ZP
         bA46yKrATYyZ91NKmV0P6i0eDg/6HgtxwOXsrZ4SNWeOQ1MMQqRCwuzPAzPNBnFqM8K8
         pYHvlEbH+FziOffGbsXxMSMknU0eQxhOoPL+0AD/mxcSniUqduTFmwD9TPLwOR8n6uOv
         KRbbPi81GWztGwwlR6ughhR6Q2fWohy8Du2lSmLnscMH+dTin7DtZ5LTUZhBiCLPyC01
         AvdVSBSQuy9Wz3NXGFwcwYu4MZWrv8XprPh8Rul7OiqBIMcHWNdJnvmuiA14ml9LtlOi
         EeSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PrDRNFOlJv/MlxB/TiyXXEpveuoj9t+sPPrSiFboa8c=;
        b=YPhwHhK9toTX3Dx2U3d8Ysak3WUMfJ6G7IrCxzihRvEaaZYpnNEMJrMp0BUSuFUg/w
         XCsfstGQxkNIduWMHVcvdAsO3eng23Bsd2lNvR0uSNvNzX3TD5uPP3JbmUthtDgpXY0o
         MJyhEsWobQQjTRuOryyKKupEVw8aby4DwgLFZ6qiF+LayfuFofySukxc/q5cHEXEzyc3
         2myKeBT3oHPfC9tvvYcQk/2YNbqy7HIERhIDthIC4Y27EfCHJR82HCeEJxEnBrPQ2+th
         mxdOHy90JtbxYPniXfKl/rXHxPkEN0FkZnVPeVxUMN4EDS1dclaskOih/v93gc/ruaxZ
         QLuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PrDRNFOlJv/MlxB/TiyXXEpveuoj9t+sPPrSiFboa8c=;
        b=NHGYq+qE0M4bjcsMp/ZeY5AAfBidHtvIY3ZYKRAudTCSlz4ODkc6ndbaDLM2sBnVap
         likQZ/hj2JjuOyxswfToCLnbq742ghiwP6WDn7BR+rqhdKTqmoJEMJG/8XNXzolNl11d
         di2ivMeQCg/2uLKlYMmnCb9KclgacssDL8hoSxb601GBxySzn+tco8LsisSDSO+5h24m
         AMpyWkVQ5FQnXdxUNLYrUiSoTGE04ga+/c1dJo5Z3DlA6OcDjPkiggsPT7UFMYttCqvI
         uva5hzwRx4yI9Pw3+/K3+xaa7An9v4yDoXegQ4mI48CWUTb3gtPcU6a0GhG7E6nqjtmt
         1f3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PrDRNFOlJv/MlxB/TiyXXEpveuoj9t+sPPrSiFboa8c=;
        b=D5nXi3+lw82ZPMJ8UVh5+jCtdaH0dDn2g842q1NBXIl54H63SbDkp54FYm2egmkcR/
         8DYWcLfrhb/wBlWAwgkRpBg0fzslCX2dWqBZVzPH7RyP9T+sARkVDnk94gczPCJAfCYW
         ZQp7PnM9IJO1HW0DIv5ujine8WxiP49M+UXtWGnz4CIytBgRH/hE0f16DdqtcAk/z4MA
         Rxr5101HgPKihNm/BgUdrkxkEUyvbr5P0jHOda2nCjswnZG7WMqTvhubIpHejMF+ZTLY
         eAzBVM7lVX03ytldGiGK3mh0KpzPRP/L2fSFMYq5cqAVDLVzrI3mRqFXLE20xuPzafIn
         3pyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Kq5zyJ1UeckJjXJwy1nq1GuwwBGNCgiSHfrh4MlyDmOXHK/eE
	HIltXuDsYt5frUtjan50LXo=
X-Google-Smtp-Source: ABdhPJxjwZxgmuCrENz7Ve8ZQJjVzVSOLgTON5HmLX4TNTHcTDlPEf8dI52zwu5KoLJ14DJatl6ZaA==
X-Received: by 2002:a9d:6e10:: with SMTP id e16mr3652717otr.211.1611329410468;
        Fri, 22 Jan 2021 07:30:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7290:: with SMTP id t16ls912376otj.11.gmail; Fri, 22 Jan
 2021 07:30:10 -0800 (PST)
X-Received: by 2002:a9d:7a4:: with SMTP id 33mr3745506oto.217.1611329410133;
        Fri, 22 Jan 2021 07:30:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611329410; cv=none;
        d=google.com; s=arc-20160816;
        b=z9zRq6IpvVdAR9aN+7b1sOH1MOO7lfLQmDzIjzUycBUUb59wzU2c7Dm0cYGrt7q6tq
         MlxirfQW5AcnQceAzbcJptPHjMdrvl3Wox9IpQnoyX7oRozpR+wQ9LSX0wl+u05QUB95
         ACwnBjeRDy1Cjk5/WZHOWYPJNlFmB3IIjdcHDZSeaYtiS1Rkt813Asv2QSUnBvv1PdQC
         JAajy/hBokc+67FWZI/uVXiQNu3z57ijER7rXgc9wuzzTTiBdJ7nhHd5DvliMu3VUvMR
         PkUc6g9AaB8VpoymRoC3sMJ0t/C91ND84S8dFxud8nJ3pWdBL1gSJdqCgWz6icAxFslW
         ybmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=q/AYBenmg/d6TpfIR/o7FemVL4ezE8KGYZoOX5Xb97s=;
        b=F0onbrxbDGhhD65MaNdUkKk688aDVlQlLX3k/lLwngpyD/BvJHhvQm2BTGx7BwZvYi
         0tGi6CFEAw5HvOMeuwESxqT8pB7QnFf3+GCE0Mj5rl58SQ9QNKHTm3FdetJFLGtq2N59
         uBZ/Vl7IfMGI0dmgo2EiPJWx0LJvbE+pg37gLq987CXNZd6/S7tyUp47r3EadDGDGep6
         inVg9tbgzK5u3qdOvwAKHM1pbFG3K0/F/8ND5taD/9mPWjFN/3BoTF3yTmh3FBa3LkiG
         JwRnirIcB4DiBC5C2c4RY9buGc2Y0SqXpkPGrTYkBerY8swEb47aWro7iDmyRP9hmQfT
         fH4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s139si697215oih.5.2021.01.22.07.30.10
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:30:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A87F01570;
	Fri, 22 Jan 2021 07:30:09 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EB5663F66E;
	Fri, 22 Jan 2021 07:30:07 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v8 2/4] kasan: Add KASAN mode kernel parameter
Date: Fri, 22 Jan 2021 15:29:54 +0000
Message-Id: <20210122152956.9896-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122152956.9896-1-vincenzo.frascino@arm.com>
References: <20210122152956.9896-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

Architectures supported by KASAN_HW_TAGS can provide a sync or async mode
of execution. On an MTE enabled arm64 hw for example this can be identified
with the synchronous or asynchronous tagging mode of execution.
In synchronous mode, an exception is triggered if a tag check fault occurs.
In asynchronous mode, if a tag check fault occurs, the TFSR_EL1 register is
updated asynchronously. The kernel checks the corresponding bits
periodically.

KASAN requires a specific kernel command line parameter to make use of this
hw features.

Add KASAN HW execution mode kernel command line parameter.

Note: This patch adds the kasan.mode kernel parameter and the
sync/async kernel command line options to enable the described features.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 Documentation/dev-tools/kasan.rst |  9 +++++++++
 lib/test_kasan.c                  |  2 +-
 mm/kasan/hw_tags.c                | 32 ++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h                  |  6 ++++--
 4 files changed, 45 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e022b7506e37..e3dca4d1f2a7 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -161,6 +161,15 @@ particular KASAN features.
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
+- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
+  synchronous or asynchronous mode of execution (default: ``sync``).
+  Synchronous mode: a bad access is detected immediately when a tag
+  check fault occurs.
+  Asynchronous mode: a bad access detection is delayed. When a tag check
+  fault occurs, the information is stored in hardware (in the TFSR_EL1
+  register for arm64). The kernel periodically checks the hardware and
+  only reports tag faults during these checks.
+
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
   ``off``).
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index d16ec9e66806..7285dcf9fcc1 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -97,7 +97,7 @@ static void kasan_test_exit(struct kunit *test)
 			READ_ONCE(fail_data.report_found));	\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
 		if (READ_ONCE(fail_data.report_found))		\
-			hw_enable_tagging();			\
+			hw_enable_tagging_sync();		\
 		migrate_enable();				\
 	}							\
 } while (0)
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index e529428e7a11..308a879a3798 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -25,6 +25,12 @@ enum kasan_arg {
 	KASAN_ARG_ON,
 };
 
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_DEFAULT,
+	KASAN_ARG_MODE_SYNC,
+	KASAN_ARG_MODE_ASYNC,
+};
+
 enum kasan_arg_stacktrace {
 	KASAN_ARG_STACKTRACE_DEFAULT,
 	KASAN_ARG_STACKTRACE_OFF,
@@ -38,6 +44,7 @@ enum kasan_arg_fault {
 };
 
 static enum kasan_arg kasan_arg __ro_after_init;
+static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 
@@ -68,6 +75,21 @@ static int __init early_kasan_flag(char *arg)
 }
 early_param("kasan", early_kasan_flag);
 
+/* kasan.mode=sync/async */
+static int __init early_kasan_mode(char *arg)
+{
+	/* If arg is not set the default mode is sync */
+	if ((!arg) || !strcmp(arg, "sync"))
+		kasan_arg_mode = KASAN_ARG_MODE_SYNC;
+	else if (!strcmp(arg, "async"))
+		kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.mode", early_kasan_mode);
+
 /* kasan.stacktrace=off/on */
 static int __init early_kasan_flag_stacktrace(char *arg)
 {
@@ -115,7 +137,15 @@ void kasan_init_hw_tags_cpu(void)
 		return;
 
 	hw_init_tags(KASAN_TAG_MAX);
-	hw_enable_tagging();
+
+	/*
+	 * Enable async mode only when explicitly requested through
+	 * the command line.
+	 */
+	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
+		hw_enable_tagging_async();
+	else
+		hw_enable_tagging_sync();
 }
 
 /* kasan_init_hw_tags() is called once on boot CPU. */
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 07ef7fc742ad..3923d9744105 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -294,7 +294,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
 #endif
 
-#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_enable_tagging_sync()		arch_enable_tagging_sync()
+#define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
 #define hw_get_random_tag()			arch_get_random_tag()
@@ -303,7 +304,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-#define hw_enable_tagging()
+#define hw_enable_tagging_sync()
+#define hw_enable_tagging_async()
 #define hw_set_tagging_report_once(state)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122152956.9896-3-vincenzo.frascino%40arm.com.
