Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBXO4U2AAMGQEIBJGZ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id A3C6B2FF093
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 17:39:58 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id m21sf1835511qtp.6
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 08:39:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611247197; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hj7Wsf9aOkPmXQnV0qlZhR7dvVGjIN1hp9U4AbjbTqCJeJJeuiWBd7/akR3PNfwYH9
         WzOilgv8GwbqYt0JAM5aPNMHfRpt22b8zrPZTg2W4SkhRjRvfuqnUNu/+rCBFau3Ujlm
         4DgLJhCHhmq/YtSWvHGmq0C0rSSi+QnsRQnAkpEMlADIOcvEmWTAeqnhNwnOlrv9Ob6+
         uSVkCyMIxbUIufGt0ZEWfYa8mCgW1eY1RB9C56Y3/pwWjxjLEKqk2t7CJDC9CtkmoYe3
         qZiaqb1atCs0mm/LMUZmTPkF7Kq2bFXI3HAuYM/CX9BLh+t8YjpzQdFwMRf7K24hapiY
         hiNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SuruEzbS7RBp55thyLgpDIvLuLV3rIRCxsnFk7P2e3s=;
        b=IfUo/I6bYdFmjBnaW+wBsWvJnBLal7ORDkdDMSbWm/bdk7YMbaO5pPZyBO5CKcDu2n
         SngBuC0Q/3UJ52BJBTnjWJkbJHXHgOdJd5JK528eOnAGWhug03HYgGqD3ugTe8/qzGVY
         O4WyaO6zfy6ccg5XhuCmqgpV0dMFfA9BJqXB267FNqYwlzAVWse54ZmZzxNtlLfVQkcZ
         viCREooe5pbLyG2hwrzCUhB5ZKFH+dtsOwz1vCRHUlId3oJKEn7Rp5Q127DVHIIY06FW
         m91XNNcopqt9xGfSv/3QScTre2fVV9/kwxG2Pz8GmJ+jAHa5IASo3fWTX8gsyQNJfRok
         ThAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SuruEzbS7RBp55thyLgpDIvLuLV3rIRCxsnFk7P2e3s=;
        b=G7sgl3VPb9gDpSZhCqmsTcRQeOLWHEUZYtPgPM7KJW4UqQ0kDi8dGl/xgfy/jM3ykc
         1/dLFWOKbsSR3D1OdEhq+PbtSyUoGiMKZYLMdXG+vO6s6aNLhkDXu1bBos3Hk1YRCrYt
         e7fBT6F5Cs3u5bW0Wd3ORTg16tHLqhvqMztdz/rB87HBxx7eUkWeZTkTRWtyPCgOGyoO
         SIJMLaLM7+UCafRIr8kDYXpneDs1B//3BHKfvGrjkpfJYOPXhcOho/PAolhjJKO4o7DH
         l+dbASnm3u5v0O6qekeFX0heCZfX5Qz+0UskynInnEUYLbhfHSUSqM2rWx/AXkjpJyDa
         roqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SuruEzbS7RBp55thyLgpDIvLuLV3rIRCxsnFk7P2e3s=;
        b=omrd/lpuO76z8gQhpLPui+/ooJUjAJN3zhl6EDpid2U1KMfge1XBXgJ53V/PxtUTf0
         qMEKdWcg8LG0/AiWwxsTJt9IGmYw37V91d7Re83Y+5520VJ3CBFL/RmG+fo8ybARbt+E
         u8q/zoSDkRlS6/FAe/UcEvMKzLgQuWl6i+74MzVYk5fJf1cyOqC27krdykcB6x7aXNZX
         qks8Fi/C2cVcK2XycyaucKkcAZKdQ/m5Pnkmc6iV1os5OmK6jeXMxCTI63fOHYQYRbud
         BT+ENE4bmQFGou2UOyBQ1uwU6LeGUaEL0GAmOiEODwCbk5oWLZXeXRtVxAG3S0fAo0AC
         tgTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vM1md1mPusmDC6lSXHPMs/hOCGHC46HjfnQ1rO440prGkBiiq
	cgVVJSYywf2IIfUjSAYOOWk=
X-Google-Smtp-Source: ABdhPJyloThxXvXz/BUwO5ssl6Ol/VvAbea6Nz9QqWrhP8b6Nq9eokSRCRXBm+0htZkv+JzSs9IPOw==
X-Received: by 2002:a05:620a:8cb:: with SMTP id z11mr552668qkz.411.1611247197801;
        Thu, 21 Jan 2021 08:39:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b590:: with SMTP id g16ls703442qve.2.gmail; Thu, 21 Jan
 2021 08:39:57 -0800 (PST)
X-Received: by 2002:a0c:eed3:: with SMTP id h19mr351300qvs.18.1611247197372;
        Thu, 21 Jan 2021 08:39:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611247197; cv=none;
        d=google.com; s=arc-20160816;
        b=gP5uoize6I5QOgLQsAW8cO6AVxg/HsBChoATqH01ibW2ycqOJgEE2+o79y0Rw7ykvX
         dMuCfobk81qvnBa4ERxNRrt8nCPDEqNXpzt+i9YO2WwVLIyPtdjghxffSqQaAdTAjA/Z
         MAX0E/EFsyFkBedyCjQnIYinM1BV+/DFNVaFcidHPeZKUXRqfZ3z1OpNA6wiqwtjOYnM
         nM+batZp97uzqXaRlH5WP/ta2oQ+R8JKeo5D5HzBaIM48S5NdIXL/bK5IDqhX+qSnFrz
         Rw+uT2YRVgfkIia3Dt/3QPdl3YR5rrKtWY11UWacAJiEseNgZWc9dWQJT4VYsfKx3SRX
         TmxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ilRJSXgjvPfL4yo26MbclT7ZNFxSL9VYY5WV1FAs+34=;
        b=uckTQN2gY5HY02E/+tn3eBXHPWvxdjmKkTxfXMpSxyCql5hE7HAthCAlfcvpciDiq1
         JmZtFWZsq3RK61bTcmAH654VXzffqzlKuB8p9PhtegHcTTevs4u3czzNmbHyjFApnzQD
         qL0Jjhr2mJmqpy7hbaYTsUwVg2MTemjWeFF1BmoyfTqLaYy298OSqmlXwEqbFsX5g1uw
         6zb+LTdZpCUFD/Y4nfJUFiTv6ep8UbsJ2y+RarFBj5HYDE9azjJc6R2Bld/BjpR8kAeS
         Y7znFa/Lh0G15EspvmjdxxDjB2+KVr+nwvWUgRWe919m+f2plLfdk4yviDALoY6LF6t/
         ZpZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p6si571992qti.1.2021.01.21.08.39.57
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 08:39:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8D9B714FF;
	Thu, 21 Jan 2021 08:39:56 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E24C73F68F;
	Thu, 21 Jan 2021 08:39:54 -0800 (PST)
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
Subject: [PATCH v5 2/6] kasan: Add KASAN mode kernel parameter
Date: Thu, 21 Jan 2021 16:39:39 +0000
Message-Id: <20210121163943.9889-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210121163943.9889-1-vincenzo.frascino@arm.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
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
 Documentation/dev-tools/kasan.rst |  7 +++++++
 lib/test_kasan.c                  |  2 +-
 mm/kasan/hw_tags.c                | 27 ++++++++++++++++++++++++++-
 mm/kasan/kasan.h                  |  6 ++++--
 4 files changed, 38 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e022b7506e37..7e4a6e0c9f57 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -161,6 +161,13 @@ particular KASAN features.
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
+- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
+  synchronous or asynchronous mode of execution (default: ``sync``).
+  ``synchronous mode``: an exception is triggered if a tag check fault occurs.
+  ``asynchronous mode``: if a tag check fault occurs, the information is stored
+  asynchronously in hardware (e.g. in the TFSR_EL1 register for arm64). The kernel
+  checks the hardware location and reports an error if the fault is detected.
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
index e529428e7a11..224a2187839c 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -25,6 +25,11 @@ enum kasan_arg {
 	KASAN_ARG_ON,
 };
 
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_SYNC,
+	KASAN_ARG_MODE_ASYNC,
+};
+
 enum kasan_arg_stacktrace {
 	KASAN_ARG_STACKTRACE_DEFAULT,
 	KASAN_ARG_STACKTRACE_OFF,
@@ -38,6 +43,7 @@ enum kasan_arg_fault {
 };
 
 static enum kasan_arg kasan_arg __ro_after_init;
+static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 
@@ -68,6 +74,21 @@ static int __init early_kasan_flag(char *arg)
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
@@ -115,7 +136,11 @@ void kasan_init_hw_tags_cpu(void)
 		return;
 
 	hw_init_tags(KASAN_TAG_MAX);
-	hw_enable_tagging();
+
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121163943.9889-3-vincenzo.frascino%40arm.com.
