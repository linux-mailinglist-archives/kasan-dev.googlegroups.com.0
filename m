Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBHF2VOAAMGQER266W7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id EEF5A3004F2
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:11:41 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id u14sf5464299ybu.9
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:11:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324701; cv=pass;
        d=google.com; s=arc-20160816;
        b=rgbC3FpGarz+/58KYHVub18FXztlgVJ9826vdjC/3NNfgtOcdQhqDEcktCtt2nfU1t
         h5+406hmfLXeYh7pkc9EEe4t0UdZGyg7DF0E8tS2oa0M/cppRfT440bC3C0OQZCsMDjT
         mjP/Z+WrkIsHPyoBhGeh6B4u6Lshi0xM1gZ3+TjAqRiU3SJQuxWeCkDwE2AU+PyAeMcw
         MyXAnVk2SEgh1vrB9+51w7TQ6+fFgI2DJdyw8NzCYiHCe3kPZCfrDkrL0YnCRhT+rX7l
         gK+Ib4mTfvM0KKIcH6fHo71r4X6+GjzmS+rPPu16LhkLg/MGbScDrCbUcIP7Bukb9WZ3
         fW7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FuEDBBLW2xWzlcZy9kXtklwzX1woUts7VRMkseag3Ck=;
        b=vs0f1TY1oyt8GHAgAgAt7pK0Pl7KQ3KPIUifTGgWl+qdKO0dwlK+3ed3EDg3Pb08oX
         nSBMry0mmhYVZdcUnlgKkOiEAZZHkOW8NuvoXQhn5d7zJts2q4vKlgZkZ2uWVdNRpNCX
         jHiKIY7LovF2Xqrx3iB5y9tNZNO+VXSysuiypVDoiVDsqibeybir4kSzIyYCJRJj8Siz
         P8Z7vh+bY4qstrWw+6sJbnjtXL4rQRLweKFacksyR4EIhxQa6SOsSd9GTFSAV9mx3Y8C
         JxVSwVq0PSwnllBIBOMJz6o2yQ2lkQ/3w8DPWtcqeeBYODDN9xOnZkqeuirb1ydtGZ3Y
         gU6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FuEDBBLW2xWzlcZy9kXtklwzX1woUts7VRMkseag3Ck=;
        b=Lb1fr/G5ysuIFTJVbMXuKKS8hkdhIsGJNnH8NUnr/egYQJO7hvqfC+Ukvl+O4VxFqD
         z1CmpI8fGK/s3sYDEL63Nu9s+H+BaebM6hTFVD6lG56lPHfnLJKQ2p62raJjFBPj8ec5
         dapTUByL453t9IR/0a3XBWZr1q99bs6mP4xZ6/+3RtZJF1DsIWkpY95GTioyGXIKopDV
         Y2nQYGR5flV+3N7FHWA9bXb0e6fUBLrpSiwEsDbGbpIZ41O/EUc75sTTpgPtvsTqF+aR
         TD+NCE7RV8/ToQ3kqqcyhjXKuYf4YtBK2RqIJPX6hE4f3QmYPp03V6kHpfEqW9G3yFqf
         BlXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FuEDBBLW2xWzlcZy9kXtklwzX1woUts7VRMkseag3Ck=;
        b=c1MPyQpJ4vORyqD80WvEh1VsRRR1+EiG77xDxMjDPsOIdsMnpDH3govkJ3ydbfY50V
         1f7Ky547KisLh8aUJbqvNbSl8YPPwIn+9VL31HyXDnmlMzhAHloayWFrABJ9ejLftG52
         oeGhynFWYWwBzqCQ6kBNhbK8Rpg9eaeYbLT2i6gbU/jVS36998bmQNUoauMqrEDLKRxH
         3DL8bLVYUlvEj8cfRAWS6EOD37uAf60zS2TIqv3jnZ6rmizqRGRVCoR9lwftXxHUs8LF
         UZLmewVaGBAMfbWIyRsh6J9NJTqiDh/mvT1YMZoCGPrzUvB+xE6ota6idK1v6PEsAKMl
         BIjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lnY9yKQ48zLeDEXTXfTnXmy13dYbS6I4zKPLv8a0/9LZkwXvB
	YN0GV+hj7G7cRCr9iu+yjV8=
X-Google-Smtp-Source: ABdhPJz04YZfFdzDzbdlNehsuAKKlXH54J9trA/D5qGCG9K1S2s9wJAcWOAgjDKDfaT3Gu3h2BJ2Kg==
X-Received: by 2002:a25:ba0e:: with SMTP id t14mr6500314ybg.203.1611324700352;
        Fri, 22 Jan 2021 06:11:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2f84:: with SMTP id v126ls3026032ybv.11.gmail; Fri, 22
 Jan 2021 06:11:39 -0800 (PST)
X-Received: by 2002:a25:7704:: with SMTP id s4mr6948724ybc.523.1611324699889;
        Fri, 22 Jan 2021 06:11:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324699; cv=none;
        d=google.com; s=arc-20160816;
        b=OWo3+SalQKtQM2NpY1r1dE5h3sn5EQBnSMMuCjG4efcmcyJ7V9a5ptNcxffdvyEQXp
         MDlP5jZkBNqbzqTCgKnHpFA6dqEacbiCXTMmIaqWAHVGLhdtO4eOrpM+cMJ8H/clMrDC
         i94mqWZtHB8XWAq5i8UI0+jHQsG0AEuSBzQvtuN/xPjU2iyCNJPvLBEbCdo0Z0459Xnf
         N5iaHaXBr8rop0Og88Xrb/6tIVodl7QG4JT9xs8nphebkvcdXMo4/RMGU/2LhAFqo86Y
         yoTgDie4CgpCcNPERlhLwqlxXPk16XLOZ+2ylfagoDSNvRavUpQuiXOJOxenjSXr5pod
         /FrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=bT/eY64hTk8N8T7E6ls2cetFLFpcd1hei82NbuE+bx4=;
        b=d8e/SeG0iFjb1R5StuRUcEHY9K0uOTfmfDtfJ0vfjGQNVA3hNn97Sp9mK7oo4QmBbE
         F5BTuZp5byZ/qRGJl8oxZ8OOqX0aRIOJlQz3kaTzAivSIehcqQousxg1zhq/BehjU8+/
         gIlUs9+xvIEFC3tFeerw8SfmbTECnaSHHCLgZwsG5MTJ4fRap5mM/7Avt5e8VAigCt+o
         Yux8Os8kXMDR4PivD0r9h+Tbwu9+m4j7MD4SZHjzTAxCOUNaox2VSk6jHQ5cjVacZ2uQ
         rM96kQQUlPqpaWJtiFx2wbCLJlzUlsQEIku81txfZ0+8Fjg9UtgwLeQcMGfHlME6gyH7
         DT7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x18si619703ybe.0.2021.01.22.06.11.39
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:11:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5220A1509;
	Fri, 22 Jan 2021 06:11:39 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A5B753F66E;
	Fri, 22 Jan 2021 06:11:37 -0800 (PST)
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
Subject: [PATCH v7 2/4] kasan: Add KASAN mode kernel parameter
Date: Fri, 22 Jan 2021 14:11:23 +0000
Message-Id: <20210122141125.36166-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122141125.36166-1-vincenzo.frascino@arm.com>
References: <20210122141125.36166-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122141125.36166-3-vincenzo.frascino%40arm.com.
