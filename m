Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLVOZCTAMGQEJE2AYBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E3BF773998
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 12:21:35 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4fe32caefd8sf5199859e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 03:21:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691490095; cv=pass;
        d=google.com; s=arc-20160816;
        b=MNk+GScjc6Y6F3O/ae1nnV/XGqkh5HOE0cERb3cZLxzZ473f+xtcdxQ8/7nYwBhjnB
         kaqcyncvbNL0Ch7LOKMsHYZjtfrQ+urdspC2AcVIvQlYlLloTOS95iw4zCG2yDndsELa
         wmN43/3YbO9JeMJe3gUniz3cl+V83BxaVLDRrvon2X0oyf12yS/V6RsgVaTz/KtjU3NG
         TfUAJgBa32vqt7ijosN27ZdeCoRX0BbK6pxxXdnXSPq4PV/tb3EZ85ylWcQn+oem53pa
         PSdeUa0zmo0fTMntzbZ5bWtqFIEauqrCwDL2cLFKIUOkCaHJTn4g5WnFAthWjJzWYan1
         5DtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=kzgpeLwTYsd3AzU7hMu2q3JgGNwLeiLlc5U3K934PPM=;
        fh=0+1A2GTyPkIZP1JqAjZ2aq5svYM3vBrC3jkZRiGb8LI=;
        b=L76cdnI7pDXvMS8uPGOPEcytryXUjWBOZlQsAhsjIY353ZA2VhjZgVWy2ASHWhOfWS
         6ewRF2miJJGDdYB7asMLVq9fwYxcJ4u2lpwgSAtqtgSqhsd8kghNKZwXuWdcqimS+9yD
         8DhURNRwFY6Pi0jnbnIr2TbtPl0ojKeO9KLsi1wnyHVaKjbM6DBhlXsHgzbWYPx6DNA6
         56u9uQuDd70DLI1P9F7YOG86db3B4mG7puqITKdHky/VrvjASqxEeR8eHD+vUDGE7Hoy
         /o16u2k2ntdx+s/L17Wb0tmhvglncxkmVDPhGtoi2Elg3mw1nayEcV11Yo1yhkATATVf
         pS2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Mudnf9IB;
       spf=pass (google.com: domain of 3kxfszaukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3KxfSZAUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691490095; x=1692094895;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kzgpeLwTYsd3AzU7hMu2q3JgGNwLeiLlc5U3K934PPM=;
        b=F2HcWp0oPr/gc1uB4hqbDLEDtpwPpRNYXL12nKiigX3UHSWC3UXPxBY/vjN2uyZjNJ
         zjO0qOzoVzvVApvzBWgBF/O9Qn2HpyHKQRjV0ZYs/gQGiF5ERFVanTmzeS+W2GCW0NeP
         3tuMnldRppovo/txkSdgimILO1HIVJrmPJZfLEUE9TvS0bZihMCmrgK36D4huHM9f6sf
         x3D5oJ2ibbTbzDfGzpPqyVsS3Aa5hHyNwriVYH+t6mEfTk07Hf5s+7ll+Lt0H1n5LctO
         zuMSQBYj9OGuIL1TWIxIr3HagZ1VI6EIhrYOCsDOlXWVv/ROVpsCApmfx7EIE1nR/sXr
         mW8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691490095; x=1692094895;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kzgpeLwTYsd3AzU7hMu2q3JgGNwLeiLlc5U3K934PPM=;
        b=eIi/t9XgybDc7sKom7PsTpi4zCs86OaVJ/HK6xvulDkUmroxpi7UCGJ9ir39wshQtG
         fRfQr9/0miPpGZo5CYyLJqVE+3jX3AknAwdgUdoXpT+IT/WtAmUVhsTOQmD8LZ7ECgbA
         qhm/QcoI1VuIz51cUEvz3hehPr2yl2RhmeRepCji/50/0Fv6trPdLVaT4lW+ZluknWjX
         J1vpBEDlYe0saqHEPs+cLsN8sBVqc9rmpO6UHTIvRCLsxdUBhZRfWkgoHV6yQyvj/7C8
         w4IoANQvFp6cYPI3F3U4useElnUYrnrEhbhn27qx4BHYd8GoOxyYf38TXlpFLJvMswdF
         Ms7w==
X-Gm-Message-State: AOJu0Yz0impl3hI+RZXutE2LQh+bo5LW6Ga5o1UkeYbOOeq4rGqYW8cv
	N3Qk6PY+L8s/nKrTdenmPe0=
X-Google-Smtp-Source: AGHT+IEEzp/6mmkH4J8nmwKZ4yYfTx9Nfw8a3frHE72mJaObvxVV99z71rCTarSSNE2kwyDVUjxmkQ==
X-Received: by 2002:a2e:9e0c:0:b0:2b9:a6a1:f12 with SMTP id e12-20020a2e9e0c000000b002b9a6a10f12mr8038497ljk.43.1691490094448;
        Tue, 08 Aug 2023 03:21:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6016:b0:3fe:2d78:7ffa with SMTP id
 az22-20020a05600c601600b003fe2d787ffals615322wmb.2.-pod-prod-03-eu; Tue, 08
 Aug 2023 03:21:32 -0700 (PDT)
X-Received: by 2002:a5d:4a81:0:b0:317:5b76:826 with SMTP id o1-20020a5d4a81000000b003175b760826mr6760190wrq.0.1691490092582;
        Tue, 08 Aug 2023 03:21:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691490092; cv=none;
        d=google.com; s=arc-20160816;
        b=Z5jEkgN6/8KoGyacyIi5vjyfmr9GI6aq1Cf/LY+IeD2S1A6RyDiUTqNxUZ7HPrvylq
         9qE+Y80CTCT8HMgGFQBxQLNL1g9Btod0S2KyG2UFU41TGxjtNM+TizheQ+CY/C2F4i/e
         Zge1KuAWK+/irDkaBtX6/P7aCoQVoMiAVgxTGSwZNPq8/a+wAWrpEUvOe0MoREEB/DEL
         Is7/HeZsd10fRLCA6+LSfX+0723NhTU2VF9EuZoOtdtJS6ixEWeXAqklQrMeIXd65tvS
         tFOYffyEovuuWrtDaVvu8fbCJreJXFwSAtQ3VeIWh64F2Q5p5zMkkAd5SMXICpPJh9L6
         59uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=8CDlzc3vfWuiyArBAiXe26CLSydTdANPU8OF+/ikf0k=;
        fh=21lXPMSK2yK/sEXDyQrJ/fRnyJ9/L86+gRgt0otc1Cc=;
        b=sel2QygBFUtkv/LFWMJjLIGYUeE70/EivNsiZKm1vBKN9GR9s8Rj8gAn/cizqXLR6f
         0qJ8iuj6+cGwkyQOnEbO9ghcsA2LgHYfa9edN70OvKWaZYRQq0sXHfmBX2xGn8uco57J
         WWx0ZIx2UfOeD7M0ZZUXjRweLsDA2aHSIQqmZjjSZWukNlG6KmBxQuN6H8YmK6qnT3BH
         jAUSnHV/Rmc9Dv8ympTjz5naH5eEFyM3t6PslrMpi53Wo4y+un12whqFiClkS2vRIh5+
         WUCZ+2dh85mpbiVoPVhQjHKbVcs9KyE9z6LBTjRrIsb/FHBhj7RZYPO+AXZ9AAELngV0
         meoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Mudnf9IB;
       spf=pass (google.com: domain of 3kxfszaukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3KxfSZAUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id bn18-20020a056000061200b00317478f49dbsi852366wrb.0.2023.08.08.03.21.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Aug 2023 03:21:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kxfszaukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-3fe1dadb5d2so29914275e9.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Aug 2023 03:21:32 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:39c0:833d:c267:7f64])
 (user=elver job=sendgmr) by 2002:a5d:66c6:0:b0:317:cc33:106 with SMTP id
 k6-20020a5d66c6000000b00317cc330106mr78663wrw.11.1691490091926; Tue, 08 Aug
 2023 03:21:31 -0700 (PDT)
Date: Tue,  8 Aug 2023 12:17:27 +0200
In-Reply-To: <20230808102049.465864-1-elver@google.com>
Mime-Version: 1.0
References: <20230808102049.465864-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.640.ga95def55d0-goog
Message-ID: <20230808102049.465864-3-elver@google.com>
Subject: [PATCH v3 3/3] list_debug: Introduce CONFIG_DEBUG_LIST_MINIMAL
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Mudnf9IB;       spf=pass
 (google.com: domain of 3kxfszaukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3KxfSZAUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Numerous production kernel configs (see [1, 2]) are choosing to enable
CONFIG_DEBUG_LIST, which is also being recommended by KSPP for hardened
configs [3]. The feature has never been designed with performance in
mind, yet common list manipulation is happening across hot paths all
over the kernel.

Introduce CONFIG_DEBUG_LIST_MINIMAL, which performs list pointer
checking inline, and only upon list corruption delegates to the
reporting slow path.

To generate optimal machine code with CONFIG_DEBUG_LIST_MINIMAL:

  1. Elide checking for pointer values which upon dereference would
     result in an immediate access fault -- therefore "minimal" checks.
     The trade-off is lower-quality error reports.

  2. Use the newly introduced __preserve_most function attribute
     (available with Clang, but not yet with GCC) to minimize the code
     footprint for calling the reporting slow path. As a result,
     function size of callers is reduced by avoiding saving registers
     before calling the rarely called reporting slow path.

     Note that all TUs in lib/Makefile already disable function tracing,
     including list_debug.c, and __preserve_most's implied notrace has
     no effect in this case.

  3. Because the inline checks are a subset of the full set of checks in
     ___list_*_valid(), always return false if the inline checks failed.
     This avoids redundant compare and conditional branch right after
     return from the slow path.

As a side-effect of the checks being inline, if the compiler can prove
some condition to always be true, it can completely elide some checks.

Running netperf with CONFIG_DEBUG_LIST_MINIMAL (using a Clang compiler
with "preserve_most") shows throughput improvements, in my case of ~7%
on average (up to 20-30% on some test cases).

Link: https://r.android.com/1266735 [1]
Link: https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/blob/main/config [2]
Link: https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings [3]
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Rename ___list_*_valid() to __list_*_valid_or_report().
* More comments.

v2:
* Note that lib/Makefile disables function tracing for everything and
  __preserve_most's implied notrace is a noop here.
---
 arch/arm64/kvm/hyp/nvhe/list_debug.c |  2 +
 include/linux/list.h                 | 64 +++++++++++++++++++++++++---
 lib/Kconfig.debug                    | 15 +++++++
 lib/list_debug.c                     |  2 +
 4 files changed, 77 insertions(+), 6 deletions(-)

diff --git a/arch/arm64/kvm/hyp/nvhe/list_debug.c b/arch/arm64/kvm/hyp/nvhe/list_debug.c
index 16266a939a4c..46a2d4f2b3c6 100644
--- a/arch/arm64/kvm/hyp/nvhe/list_debug.c
+++ b/arch/arm64/kvm/hyp/nvhe/list_debug.c
@@ -26,6 +26,7 @@ static inline __must_check bool nvhe_check_data_corruption(bool v)
 
 /* The predicates checked here are taken from lib/list_debug.c. */
 
+__list_valid_slowpath
 bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 				struct list_head *next)
 {
@@ -37,6 +38,7 @@ bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 	return true;
 }
 
+__list_valid_slowpath
 bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
diff --git a/include/linux/list.h b/include/linux/list.h
index 130c6a1bb45c..066fe33e99bf 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -39,38 +39,90 @@ static inline void INIT_LIST_HEAD(struct list_head *list)
 }
 
 #ifdef CONFIG_DEBUG_LIST
+
+#ifdef CONFIG_DEBUG_LIST_MINIMAL
+# define __list_valid_slowpath __cold __preserve_most
+#else
+# define __list_valid_slowpath
+#endif
+
 /*
  * Performs the full set of list corruption checks before __list_add().
  * On list corruption reports a warning, and returns false.
  */
-extern bool __list_add_valid_or_report(struct list_head *new,
-				       struct list_head *prev,
-				       struct list_head *next);
+extern bool __list_valid_slowpath __list_add_valid_or_report(struct list_head *new,
+							     struct list_head *prev,
+							     struct list_head *next);
 
 /*
  * Performs list corruption checks before __list_add(). Returns false if a
  * corruption is detected, true otherwise.
+ *
+ * With CONFIG_DEBUG_LIST_MINIMAL set, performs minimal list integrity checking
+ * (that do not result in a fault) inline, and only if a corruption is detected
+ * calls the reporting function __list_add_valid_or_report().
  */
 static __always_inline bool __list_add_valid(struct list_head *new,
 					     struct list_head *prev,
 					     struct list_head *next)
 {
-	return __list_add_valid_or_report(new, prev, next);
+	bool ret = true;
+
+	if (IS_ENABLED(CONFIG_DEBUG_LIST_MINIMAL)) {
+		/*
+		 * In the minimal config, elide checking if next and prev are
+		 * NULL, since the immediate dereference of them below would
+		 * result in a fault if NULL.
+		 *
+		 * With the minimal config we can afford to inline the checks,
+		 * which also gives the compiler a chance to elide some of them
+		 * completely if they can be proven at compile-time. If one of
+		 * the pre-conditions does not hold, the slow-path will show a
+		 * report which pre-condition failed.
+		 */
+		if (likely(next->prev == prev && prev->next == next && new != prev && new != next))
+			return true;
+		ret = false;
+	}
+
+	ret &= __list_add_valid_or_report(new, prev, next);
+	return ret;
 }
 
 /*
  * Performs the full set of list corruption checks before __list_del_entry().
  * On list corruption reports a warning, and returns false.
  */
-extern bool __list_del_entry_valid_or_report(struct list_head *entry);
+extern bool __list_valid_slowpath __list_del_entry_valid_or_report(struct list_head *entry);
 
 /*
  * Performs list corruption checks before __list_del_entry(). Returns false if a
  * corruption is detected, true otherwise.
+ *
+ * With CONFIG_DEBUG_LIST_MINIMAL set, performs minimal list integrity checking
+ * (that do not result in a fault) inline, and only if a corruption is detected
+ * calls the reporting function __list_del_entry_valid_or_report().
  */
 static __always_inline bool __list_del_entry_valid(struct list_head *entry)
 {
-	return __list_del_entry_valid_or_report(entry);
+	bool ret = true;
+
+	if (IS_ENABLED(CONFIG_DEBUG_LIST_MINIMAL)) {
+		struct list_head *prev = entry->prev;
+		struct list_head *next = entry->next;
+
+		/*
+		 * In the minimal config, elide checking if next and prev are
+		 * NULL, LIST_POISON1 or LIST_POISON2, since the immediate
+		 * dereference of them below would result in a fault.
+		 */
+		if (likely(prev->next == entry && next->prev == entry))
+			return true;
+		ret = false;
+	}
+
+	ret &= __list_del_entry_valid_or_report(entry);
+	return ret;
 }
 #else
 static inline bool __list_add_valid(struct list_head *new,
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index fbc89baf7de6..e72cf08af0fa 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1680,6 +1680,21 @@ config DEBUG_LIST
 
 	  If unsure, say N.
 
+config DEBUG_LIST_MINIMAL
+	bool "Minimal linked list debug checks"
+	default !DEBUG_KERNEL
+	depends on DEBUG_LIST
+	help
+	  Only perform the minimal set of checks in the linked-list walking
+	  routines to catch corruptions that are not guaranteed to result in an
+	  immediate access fault.
+
+	  This trades lower quality error reports for improved performance: the
+	  generated code should be more optimal and provide trade-offs that may
+	  better serve safety- and performance- critical environments.
+
+	  If unsure, say Y.
+
 config DEBUG_PLIST
 	bool "Debug priority linked list manipulation"
 	depends on DEBUG_KERNEL
diff --git a/lib/list_debug.c b/lib/list_debug.c
index 2def33b1491f..0ff547910dd0 100644
--- a/lib/list_debug.c
+++ b/lib/list_debug.c
@@ -17,6 +17,7 @@
  * attempt).
  */
 
+__list_valid_slowpath
 bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 				struct list_head *next)
 {
@@ -39,6 +40,7 @@ bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 }
 EXPORT_SYMBOL(__list_add_valid_or_report);
 
+__list_valid_slowpath
 bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
-- 
2.41.0.640.ga95def55d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230808102049.465864-3-elver%40google.com.
