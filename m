Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLN2YCAAMGQEGD5T7XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 306C6303F25
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:46:22 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id q2sf1199617otf.22
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:46:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668781; cv=pass;
        d=google.com; s=arc-20160816;
        b=nTI7aGyWXguWaic0PaVOi5VCrzfUDa40N/w5V+452YVwICpuQKBzr9Bga5ICdiNzkL
         pw+XUwd+MVtp+wcrWr4FGJ/3hR8HBLOx2N/48TRtZbTBnD263akQgFwKc8PtwwcRXx1+
         pQLIyhJzEROg70G0npBth4w2YBWp1uSxy3pd0k4xv/gW9wMBuK79W0Y2MTuekW37Bx4a
         kguZjQSRUUj+ApRmhjVkPN0MWHTJ4CHWfmIgAyIfSv3SJno8lfo4It7t71gXGEa1UTBN
         rYOdAoMxpbZajQjNPTfYvaD6Y/V16n0vqEuKOMEJzUVijUH/S3sQbEWR3prSsAZErKMs
         tozQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=skmDjkLooMO0LC70iDFEITUPBj8Wke5TK+qyhOT7O5A=;
        b=rHjOq+q6hbiGzZe0PVz9hW2nW6rtgmvtmy2lHgClNPzugFyilum47FBLMAc5kzpVrN
         eYrLDOeJW6z6oD9sImH/l/HknVurUUncGwQqOk80UtkxY3khpjx1tsEXRk28Ek4ieZey
         9EtqgV5erYzNRlm6sdZS2PJ7IfkpNWEO7f1QG06PFeqBMY8zkHqxtYUfAKC3wjR5DUa8
         vvJpTXUSsBSqDYObSoDSq2sYfajRl5sXeB9YStmmzGvBleRgAKPexbcTcb+qvOFYnk7r
         K+h+J0N0Bf3j7tSXnBmeNZWA3LMtFoQoOZOKtAn44irXbA9ozYARFgG5VXRk4QT2wHmN
         PZIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=skmDjkLooMO0LC70iDFEITUPBj8Wke5TK+qyhOT7O5A=;
        b=Da9FXGAJ7cOxZjHKlk1vneYftC91JwXEdrLaX/HtBWkbWqOfNlK5qqV17EDvbBCKOf
         EtZuS13p3JgU2WXnxo6HP4q02UhoXeVoE56JvCEzcXXytJWZUx3qDWqRZ9y3iVnGvN9G
         C3fW1CNJxvlnPnyBXVfPh8atzZvCAepwJ2Cb3Zflo/S5HbuGnaWessq/wvc0otU3MBUf
         cLMyu98NbWUS3odoY2UctchrdtoX5KE0+zFflujnlZ8iMc4YsKrTHFpEuOlVATGBOFv2
         smLM6+NXnRdLPS7cYiUoUU96eivlisr0tbQkekkh+3ly2CFx+AA3qYaRGr7plzwAzyjw
         YuZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=skmDjkLooMO0LC70iDFEITUPBj8Wke5TK+qyhOT7O5A=;
        b=YrVGM831Uy1e60pAr+JvFroOpiD8gXQaBpMmYlcS/SDQlWNJkQ7rZ/dNCkSfeWvBtc
         1DISv7ZXVYYbOcK1mIQtRpGeH+9hLsQivShoyl/pGrks56QTnNPOJ1j7uJ2BiiB7D/iQ
         hA/ljAl6Fp2/Js+6UoK4ydQemXQSvOoCWgtiw9tGCiHv7osCuZlRjkoNwBLjR4ikDd13
         yc+Dy14e8iFtziwrSw+HTn8GF0Zjnmtrn/PH3CSsw801sDXNIVdftMLeIxry69FcWQzx
         0vaZqI9iLRG6JqR1zy8MELP6SmBzI5oovol1v45gjKOTEaLk0AvT3sVAw7sPxPr8yQ2K
         kuDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ubgwhB5wmErebCFWoT97sn85rurhV4VAKYCD+EqN2lu2EsOhh
	95VtKKY/Aq4KU9baguk/4L4=
X-Google-Smtp-Source: ABdhPJwS2IR5xy0DpzEa31LsDmYSeQwQolOdWV/ekzB+jWs3mBwOkB3ATGAsyA1cx9801rC0DABVGQ==
X-Received: by 2002:a9d:7cd5:: with SMTP id r21mr3701628otn.57.1611668781196;
        Tue, 26 Jan 2021 05:46:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f0d:: with SMTP id u13ls3489730otg.8.gmail; Tue,
 26 Jan 2021 05:46:20 -0800 (PST)
X-Received: by 2002:a9d:19aa:: with SMTP id k39mr3959959otk.28.1611668780865;
        Tue, 26 Jan 2021 05:46:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668780; cv=none;
        d=google.com; s=arc-20160816;
        b=hmcqGFSVwwfYWfeRFu9Tt966MBvGY61V8Ln2sZ8hmDQUszXUdL5guVCDNDvu3heE7u
         4pC8TYMdhPERFMxhGewRuy8DNxF4ffBsCKsZ5UVJtbe0mUyRsWOvnZ38Bs7y4FEPDrh4
         CgYzrvYhQYnJODAextSiay+OYldLbwUnBF54q3eRjMIcayNExzgSpVgzQCW1xNz+qtLQ
         OFiTK9wjMo2Sat5fdmRTRflNui6azT+TdpfB44cWxXKFVyDtImGK/gLzBOFJhhzYdcYp
         6fcSFOhl5Cpfp908G+J3+wWkOoWRDip8RPk31EJkylibJ62WDQKiFOj0ZsEO03uB5iJ2
         wdMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=q/AYBenmg/d6TpfIR/o7FemVL4ezE8KGYZoOX5Xb97s=;
        b=m+clEGaC1HNOQt1fJd0dKBCMuvaKIj7gfzyE7OsCjnQ1aE/kFt2KMUyhoblvn3IfhI
         qMjSsHWVPDZV1aJ8PEcaiz5sCZB9TTkQTw3v/TqumY4iWcjeG9gwZpQjXzfWCTUSXi9K
         iy/nxBUYPynP7ydOWs2UlJUKvH21+9/mdBV48U/wSfXUgRSMppEk5BpbP9X/ekMjFzVc
         lU3/EbdqBx7FMZyN08aGKN5Y4XvWvbemR0YxBDGuW1mWGv+3FzbRpKaSUTxkz5uvoeQ1
         FFOdv3GbFhQriQTaQsixDReub8cA8r5zY0n96D5WdoMGjnnURMya498MbONRf9OOq5VU
         azbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s139si1454986oih.5.2021.01.26.05.46.20
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:46:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8990D113E;
	Tue, 26 Jan 2021 05:46:20 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C1A0B3F68F;
	Tue, 26 Jan 2021 05:46:18 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v9 2/4] kasan: Add KASAN mode kernel parameter
Date: Tue, 26 Jan 2021 13:46:01 +0000
Message-Id: <20210126134603.49759-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210126134603.49759-1-vincenzo.frascino@arm.com>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134603.49759-3-vincenzo.frascino%40arm.com.
