Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB64Q7SEQMGQE3S3RHYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 54CD940863A
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 10:14:52 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id a23-20020a19fc17000000b003f0973fa819sf2921815lfi.11
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 01:14:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631520892; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4R+2n3A5i1f+WMc1ZHm2fsf/HK/ruRG40lWjjpFMdOi03zZ3K63sfw8oPlWPvCn89
         Kygw6XIFHW3dyXN9w4uQlw7qzewKwrpHPXvBxF3BdyUjxYFuZ0OGeEoztE//Wnbl+MWc
         oHhu8mN441EngS5TsMzWRr1W87nBJFjagbLfrVYFFFjnVndjE02YQYZpQWdnaxKfD/GS
         wDBzEa9lUctf2s//XRKWAz7zR03lTahxiSunVEg2MCpqtpRYlb0TpCRXz56hQg6pE5OU
         1ZKzwEG2DzOP/81zqVTCp7zB3pi0J+aEVnBAgPj3w0LUDmqxZvdZRRBvygOxxqiUcBVt
         4Dng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ckBaJA4qv+Bg+oM9FV2dm3lDmnZcN4X9bEPFkYkhvsY=;
        b=yc9t6OgFFPYZXZYsVMSn6qY0XL301JzMyyUnhutGi+U5bsB8IdqR7iLKgfpv5Fc+8k
         0THXejDi9HMFWe/+GAaRY1UIuREATOyju4b01AiiojJjklNy5AtBYso683glSMkuKElb
         DoCUvrOciyfqPH2Dws3WaMPdW4Km+RZAR4IuttsV6vSOkI18AsHM3QlnJ2RMsPyHRnYZ
         UoejGBlC6oNSN85u8I45KyBGZYiV7CEJqQQQ6nXaf6CZz6es76f4QGG3uNPG/D+1NwkM
         n2twbD4/Q+NgJggyLFLqgxbvfMNh/G8kfeh3mBzMru5HzC6YUYiCrElV1XpG7WVTwU3S
         sG9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ckBaJA4qv+Bg+oM9FV2dm3lDmnZcN4X9bEPFkYkhvsY=;
        b=jZCTF6CpeO7MHaaiB+IHCrf9bFNe5HILfTQ0fwK5E3IpplA45NI5gmT0j0XU8BdiGH
         TijpRr8UkhA+9tGsmKXC+vpAuGX6th2ROcsyzybVlVIIFA06HlAqmE311GdCn+w0dmUl
         8xICjFhhMi2Ff26Yi++vuWg7NCYpa17KhRvuxqTloYJULzOCCGAZWsw+xSnpJmY81x9c
         CWKvT1DrlMLlpA9v/wcisouDn1y6ZpQAs2T9kK1dVCaAtwC4oTp7bnxaxWmM8ESihouc
         GyR+7sw9Frc4fQbj0GoPs3itzhKW5fXsdxzvYSdG+5YBqeuT0Q4yeov/DbkthHyi27F5
         Egiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ckBaJA4qv+Bg+oM9FV2dm3lDmnZcN4X9bEPFkYkhvsY=;
        b=DgxDwLUCJON5HBy73ZpQuSEGiB/xhcmw6JaMEDb+yvg5BxIx1fV7Z2GAXx7Vl4LeHp
         ViFKZxATRwnfREPQv5YRGMgBevnaEqmWzlXPiLeqivxUK6VhOXa+J3XmJXlCGVxfR+z3
         gam4r89konWkqDmeq82xbaVWbeGda4LLNrjiHQPOzDuuLVQSuBMW7SvHFCa1hqDQC0UE
         LkOODa6Hw2ayMGmIMPfG1eIUEbx6yUIcMTEf5ChnLkJ6bMt+Fuml6zyCjKS1szveENVu
         n3G91fMUOi4BpQGMZ9acfVVrJXQ/2t3h8dWsLSPXTpdusKi0flHZntYDRE27An0sk+YH
         FupQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332+f61T+EcQHM1Y5JnfU/Ewi4oBRFpDCSY5LcgWqOO7Oy5ufGO
	O/nHMK83ujHXa4nG1Eog438=
X-Google-Smtp-Source: ABdhPJy4maxf0eTMmQCc1ohjXIFtyruVBWFZJMtHG7S1BQ0p5WU6WfVok/e/kalGNEF1XcdqLL+Qnw==
X-Received: by 2002:a2e:b014:: with SMTP id y20mr9295923ljk.311.1631520891877;
        Mon, 13 Sep 2021 01:14:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls908545lfi.2.gmail; Mon, 13 Sep
 2021 01:14:51 -0700 (PDT)
X-Received: by 2002:a05:6512:169a:: with SMTP id bu26mr7746536lfb.357.1631520891042;
        Mon, 13 Sep 2021 01:14:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631520891; cv=none;
        d=google.com; s=arc-20160816;
        b=OUotl/VyNT7sC9irzWFkOh7U3cWuXID0GGJPzZhFIgUkYQPX9E88mTMn440RX/Y6dO
         npZK9H2kRb01nzsG1oBWfkcRtbxn4v/Zc4foDL0CLEgVftI0q1Q3cwvnDhg9Pc4K90qB
         2REs79CE8eG/rYJkAC+LL1KFk0h9d8/0AgvIKHO8loK8yxvboeWcx7YrSy0PnicOeLwp
         qn1c6XnHqQgB9cpGSW9y19oMf3MYYHKtV0bUxL0WyXTlBDHFeTteRLkN6Qiplzkjxfs/
         HvUxLd3MKWc1mChnIanzGrQjHtUX17w0puzyLGHCx4bG1ey1haiW3+ySMA2w78lPaJO5
         Zo2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ZkJMXyMbBMFdDJC0EKgCpYng1573sti2jdzVSVrAHN4=;
        b=o8HCfwYfEnYyQz5rgOQv7Irb71yGeZdjVpcYv65cmWl4yOk+YBXpfHqTi2z7kYDQfn
         h0kl7O8pcvdQUwOayP3X65r4JT5Zbx0fhcwDNm8kez6yfIK84oY74uTC/Wj0e6YIij24
         tErno/qZhggWvpBc7xrWb/XiY1MwwSS4o8ka+IcMNPwNx6hGyINrz9n94WvIY8/137xi
         wWYraZnIyVfz05ax2TiRFY/lUxZJyqRgopOAeGx0vwzYq2T8aXu9TGmZkCk+iArxa1jv
         9+2gdZ9bSyGu8c9Zyklyc0oxbSuG2iu1EbKLwKCMnKCs1XirryLN25TC7BRGfusi7hl5
         lw0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z26si653388lfu.6.2021.09.13.01.14.50
        for <kasan-dev@googlegroups.com>;
        Mon, 13 Sep 2021 01:14:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 090D11042;
	Mon, 13 Sep 2021 01:14:50 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 24CC53F5A1;
	Mon, 13 Sep 2021 01:14:48 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH 5/5] kasan: Extend KASAN mode kernel parameter
Date: Mon, 13 Sep 2021 09:14:24 +0100
Message-Id: <20210913081424.48613-6-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20210913081424.48613-1-vincenzo.frascino@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
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

Architectures supported by KASAN_HW_TAGS can provide an asymmetric mode
of execution. On an MTE enabled arm64 hw for example this can be
identified with the asymmetric tagging mode of execution. In particular,
when such a mode is present, the CPU triggers a fault on a tag mismatch
during a load operation and asynchronously updates a register when a tag
mismatch is detected during a store operation.

Extend the KASAN HW execution mode kernel command line parameter to
support asymmetric mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 Documentation/dev-tools/kasan.rst | 10 ++++++++--
 mm/kasan/hw_tags.c                | 27 ++++++++++++++++++++++-----
 mm/kasan/kasan.h                  |  5 +++++
 3 files changed, 35 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 21dc03bc10a4..7f43e603bfbe 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -194,14 +194,20 @@ additional boot parameters that allow disabling KASAN or controlling features:
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
-- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
-  synchronous or asynchronous mode of execution (default: ``sync``).
+- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
+  is configured in synchronous, asynchronous or asymmetric mode of
+  execution (default: ``sync``).
   Synchronous mode: a bad access is detected immediately when a tag
   check fault occurs.
   Asynchronous mode: a bad access detection is delayed. When a tag check
   fault occurs, the information is stored in hardware (in the TFSR_EL1
   register for arm64). The kernel periodically checks the hardware and
   only reports tag faults during these checks.
+  Asymmetric mode: a bad access is detected immediately when a tag
+  check fault occurs during a load operation and its detection is
+  delayed during a store operation. For the store operations the kernel
+  periodically checks the hardware and only reports tag faults during
+  these checks.
 
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 05d1e9460e2e..87eb7aa13918 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -29,6 +29,7 @@ enum kasan_arg_mode {
 	KASAN_ARG_MODE_DEFAULT,
 	KASAN_ARG_MODE_SYNC,
 	KASAN_ARG_MODE_ASYNC,
+	KASAN_ARG_MODE_ASYMM,
 };
 
 enum kasan_arg_stacktrace {
@@ -49,6 +50,10 @@ EXPORT_SYMBOL(kasan_flag_enabled);
 bool kasan_flag_async __ro_after_init;
 EXPORT_SYMBOL_GPL(kasan_flag_async);
 
+/* Whether the asymmetric mode is enabled. */
+bool kasan_flag_asymm __ro_after_init;
+EXPORT_SYMBOL_GPL(kasan_flag_asymm);
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
@@ -69,7 +74,7 @@ static int __init early_kasan_flag(char *arg)
 }
 early_param("kasan", early_kasan_flag);
 
-/* kasan.mode=sync/async */
+/* kasan.mode=sync/async/asymm */
 static int __init early_kasan_mode(char *arg)
 {
 	if (!arg)
@@ -79,6 +84,8 @@ static int __init early_kasan_mode(char *arg)
 		kasan_arg_mode = KASAN_ARG_MODE_SYNC;
 	else if (!strcmp(arg, "async"))
 		kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
+	else if (!strcmp(arg, "asymm"))
+		kasan_arg_mode = KASAN_ARG_MODE_ASYMM;
 	else
 		return -EINVAL;
 
@@ -116,11 +123,13 @@ void kasan_init_hw_tags_cpu(void)
 		return;
 
 	/*
-	 * Enable async mode only when explicitly requested through
-	 * the command line.
+	 * Enable async or asymm modes only when explicitly requested
+	 * through the command line.
 	 */
 	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
 		hw_enable_tagging_async();
+	else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
+		hw_enable_tagging_asymm();
 	else
 		hw_enable_tagging_sync();
 }
@@ -143,16 +152,24 @@ void __init kasan_init_hw_tags(void)
 	case KASAN_ARG_MODE_DEFAULT:
 		/*
 		 * Default to sync mode.
-		 * Do nothing, kasan_flag_async keeps its default value.
+		 * Do nothing, kasan_flag_async and kasan_flag_asymm keep
+		 * their default values.
 		 */
 		break;
 	case KASAN_ARG_MODE_SYNC:
-		/* Do nothing, kasan_flag_async keeps its default value. */
+		/*
+		 * Do nothing, kasan_flag_async and kasan_flag_asymm keep
+		 * their default values.
+		 */
 		break;
 	case KASAN_ARG_MODE_ASYNC:
 		/* Async mode enabled. */
 		kasan_flag_async = true;
 		break;
+	case KASAN_ARG_MODE_ASYMM:
+		/* Asymm mode enabled. */
+		kasan_flag_asymm = true;
+		break;
 	}
 
 	switch (kasan_arg_stacktrace) {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3639e7c8bb98..a8be62058d32 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -287,6 +287,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #ifndef arch_enable_tagging_async
 #define arch_enable_tagging_async()
 #endif
+#ifndef arch_enable_tagging_asymm
+#define arch_enable_tagging_asymm()
+#endif
 #ifndef arch_force_async_tag_fault
 #define arch_force_async_tag_fault()
 #endif
@@ -302,6 +305,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #define hw_enable_tagging_sync()		arch_enable_tagging_sync()
 #define hw_enable_tagging_async()		arch_enable_tagging_async()
+#define hw_enable_tagging_asymm()		arch_enable_tagging_asymm()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
@@ -312,6 +316,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #define hw_enable_tagging_sync()
 #define hw_enable_tagging_async()
+#define hw_enable_tagging_asymm()
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913081424.48613-6-vincenzo.frascino%40arm.com.
