Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN7CVGTAMGQE43EYZDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 788B876D10A
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Aug 2023 17:07:37 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-786a6443490sf607241639f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Aug 2023 08:07:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690988856; cv=pass;
        d=google.com; s=arc-20160816;
        b=S6M89p2KCWj5EcXyZBgzgV5qmP2jT8+nSeNoxZDYT7FRqwVISOZeZ9ushuKyAg+Lhx
         enQusEutdJnV3NBlGir2nIw90Rr3dRG2aXvdmigDsWl9qw80dE7gk7Zvc56Ki3xxBciD
         VyBecpGLQF8G7ErGjwjHDlyyo6GvSYGrE7WLVp6iw3s2dgHGZLE7TFrY/R9bKfjWa92p
         SVKnkPhQgJBCDh4cjf5xqfJhEDsCC4S82C/Z+lQ/uCvIjgH/fUwUj1u9VO1h9Cgg5+sY
         wHT3bTx6UTovFMNEzO2+I9tOBi04QBHJ7yk8bH+u/YAok2781wvnxDBLOo9Gz3vguqKf
         QseA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7v1V5p4GxLE75bKYt4d3MM8we89UHV9L1tKAW4kW6C0=;
        fh=uAQSQbJ2uPOh1U3Yr1sxvPhVEW4wvg6y/uAlAwy6j5c=;
        b=rLNzc2koBGXfV1Xi3gB6cRsPQmPNxG5gPyhQZ/7WbuBkwMeN3EMQ4cwMgkF0KNwP34
         HWddM17dByVSdHooO/byZywGRX7EpxIKfHN5vkRYi3WsVGEhd8gL3xa1w411quSIe03a
         Y2Y4E1MDlU7V5YoRfz2AyjL+PLrgt04vSVYCAyV+dm+bu2nJfd72640HL8M3v4ByiA6c
         kEulw4H1cNCvoaDrgXpe7UbqB4xj2q7+FVGhfJFw+Hemu7i7vDXTTGYE8qF2iDZelL0t
         N/XInlVFaaRpNmgewXhkr10ttAPxw1W0RNGnp2Tzdmq5Zn2uFuhiZPBG3yTIyLrbbwW4
         N20g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4ZYamtVu;
       spf=pass (google.com: domain of 3nnhkzaukcw8ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3NnHKZAUKCW8RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690988856; x=1691593656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7v1V5p4GxLE75bKYt4d3MM8we89UHV9L1tKAW4kW6C0=;
        b=OkFv11BD44xs0qYC5OHwA5jsxQBwNanLJdH+ziBn8Xw5VQBjOakopZ2hMZPz61Dbvp
         z3cEq4rJ9V5nawdrui/6Sh4OQFfpjrF2MwOy7BrguJge1bDE3KwSSUrqBfoQJG+dPYqF
         qw2o9BCJsfqsCKxeNGEDCRrv4qQQLiAWWx2/XHhRfNmmXLoVs/BiPuVo20J8ke7Vfkvq
         6z5d4gI4grqjhga7sAIK3iBD0maVD+QVkzPpLj/NqQ4/ZRIuntZmSBOKtstb3E7q/BaO
         FpxJCyymRc6CIwk1CROvONDlkiTQd9l3DVeNb1qeokBdjHi2RD6pFn0V5EEER94OPNX6
         lvkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690988856; x=1691593656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7v1V5p4GxLE75bKYt4d3MM8we89UHV9L1tKAW4kW6C0=;
        b=Zd/vE3/JrkV0T+x4A2DrrODCEeaiBajWyz7YwNycY4ZesJo0T8EI7k32RJnySwvKdG
         ZhZ7ENf5gDvGxmcHRR6CxuH9jPHsg5uP1or22mkp19IpfbomYt5Q6GCR1dTO+4UbTMsI
         T89QBW6lw4wg7fi+y9hLs7KyQYp7I1qbTD++dtZbPusy0//BfM1IKA+sd6L8nZmW7tDf
         8BJU+d+bSORulPfNzN8JEtrl5bB1rQUF2M6Qsq/muQk+3/CVyt/gM1yT4NHlLuTn43vh
         l2rRXi69Lrlzjhm+N0tn2TUzahhlB5MUOY44esA+e/ii6D1Y1ni+GYTFNQ9ohgJPwI53
         1TSw==
X-Gm-Message-State: ABy/qLZetXq7jeJCoZJ30v8b6G75Z13tazb3VUczUt4h+u5+c5/UmWRc
	fefQISAvtILC7kHmT+9mWok=
X-Google-Smtp-Source: APBJJlEAr9hbBMbSwmk5QJFBfGd3IBDuPtOikFGJN4upgyy17lOZVKYKCmPpofL0jasTjSiHea21TQ==
X-Received: by 2002:a05:6e02:1286:b0:346:6afb:8351 with SMTP id y6-20020a056e02128600b003466afb8351mr14232840ilq.9.1690988856061;
        Wed, 02 Aug 2023 08:07:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:a048:0:b0:349:7b9:7d22 with SMTP id b8-20020a92a048000000b0034907b97d22ls3604622ilm.1.-pod-prod-03-us;
 Wed, 02 Aug 2023 08:07:35 -0700 (PDT)
X-Received: by 2002:a05:6602:2568:b0:790:8e84:8747 with SMTP id dj8-20020a056602256800b007908e848747mr15289010iob.17.1690988855220;
        Wed, 02 Aug 2023 08:07:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690988855; cv=none;
        d=google.com; s=arc-20160816;
        b=PtPUJzBJC/6NPo0JrbB0HmWSn7egpMIEFXnhdOnpkdkPlm9vvReUt9YPb7w2X5me16
         oC4oUmdFJZ0eSW0emeeeSHLyLqvH6qMa139sm1pgEwk4m22Exl0o9RvEXzkAj76FOfXX
         ECTPHq3XGtqVO4beKv3P+M73KxMjCdab6iuKEqo6+I+oZWg0e18xB3+G3ysmJEeJkik6
         Ydh3Zbg8LocsmsXUf+OzFLG2NCT2lPIb8HRozhHbldA5mU9t/QqkMfloM83dBiLvxhLe
         oOONhZpBanL7qcvMDfXBWsJeLtEVOnzaCW7kOQhSmFGBoKLQQ//RQo3Gg7e0sQKPZnTb
         09tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QsQzCCvgsUc29iN0t+r4OrRLxcOlAg596pNmSZ7559A=;
        fh=lNGG3jUJkf8aHp9vpCSrpIUZatSpkge/xU1iDADXpuE=;
        b=xVLC7YVUIAPs+dUIBbWFIYKHYa3zmGrrvuhPPgbKppa3yjgwtUByjO3EN+XwbEkYTW
         I9Bp90hFZHwVTIWabOLtYipPT4I2AT/pud1AkUmpjg0ky3rge0GiISla9q2a6+hiTObG
         A7WVJ6+YZBSGeHhg44kXIQAUUdqOrkAvy9qZD6WI+tR5yA5v8/pwCJoRvrhUQlRYvJWL
         1n25xldWc/23/kafpX8IjTEaDjqCnq6RUSoNsptiU3Dy5jpqgER6PwTUMtD7G+2b0Z/a
         sM4JiQePePcV9Oxtsxn8sHfYhZE0cgXf5o78H+c84Y0hFSwrXL3NTk/fhwA/CDJx1Maz
         ksRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4ZYamtVu;
       spf=pass (google.com: domain of 3nnhkzaukcw8ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3NnHKZAUKCW8RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id y20-20020a056602049400b0078360746879si1521296iov.0.2023.08.02.08.07.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Aug 2023 08:07:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nnhkzaukcw8ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5847479b559so81356307b3.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Aug 2023 08:07:35 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:5f73:1fc0:c9fd:f203])
 (user=elver job=sendgmr) by 2002:a81:b50d:0:b0:586:4e84:26d2 with SMTP id
 t13-20020a81b50d000000b005864e8426d2mr79140ywh.3.1690988854773; Wed, 02 Aug
 2023 08:07:34 -0700 (PDT)
Date: Wed,  2 Aug 2023 17:06:39 +0200
In-Reply-To: <20230802150712.3583252-1-elver@google.com>
Mime-Version: 1.0
References: <20230802150712.3583252-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.585.gd2178a4bd4-goog
Message-ID: <20230802150712.3583252-3-elver@google.com>
Subject: [PATCH 3/3] list_debug: Introduce CONFIG_DEBUG_LIST_MINIMAL
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=4ZYamtVu;       spf=pass
 (google.com: domain of 3nnhkzaukcw8ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3NnHKZAUKCW8RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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
 arch/arm64/kvm/hyp/nvhe/list_debug.c |  2 +
 include/linux/list.h                 | 56 +++++++++++++++++++++++++---
 lib/Kconfig.debug                    | 15 ++++++++
 lib/list_debug.c                     |  2 +
 4 files changed, 69 insertions(+), 6 deletions(-)

diff --git a/arch/arm64/kvm/hyp/nvhe/list_debug.c b/arch/arm64/kvm/hyp/nvhe/list_debug.c
index 589284496ac5..df718e29f6d4 100644
--- a/arch/arm64/kvm/hyp/nvhe/list_debug.c
+++ b/arch/arm64/kvm/hyp/nvhe/list_debug.c
@@ -26,6 +26,7 @@ static inline __must_check bool nvhe_check_data_corruption(bool v)
 
 /* The predicates checked here are taken from lib/list_debug.c. */
 
+__list_valid_slowpath
 bool ___list_add_valid(struct list_head *new, struct list_head *prev,
 		       struct list_head *next)
 {
@@ -37,6 +38,7 @@ bool ___list_add_valid(struct list_head *new, struct list_head *prev,
 	return true;
 }
 
+__list_valid_slowpath
 bool ___list_del_entry_valid(struct list_head *entry)
 {
 	struct list_head *prev, *next;
diff --git a/include/linux/list.h b/include/linux/list.h
index e0b2cf904409..a28a215a3eb1 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -39,20 +39,64 @@ static inline void INIT_LIST_HEAD(struct list_head *list)
 }
 
 #ifdef CONFIG_DEBUG_LIST
-extern bool ___list_add_valid(struct list_head *new,
-			      struct list_head *prev,
-			      struct list_head *next);
+
+#ifdef CONFIG_DEBUG_LIST_MINIMAL
+# define __list_valid_slowpath __cold __preserve_most
+#else
+# define __list_valid_slowpath
+#endif
+
+extern bool __list_valid_slowpath ___list_add_valid(struct list_head *new,
+						    struct list_head *prev,
+						    struct list_head *next);
 static __always_inline bool __list_add_valid(struct list_head *new,
 					     struct list_head *prev,
 					     struct list_head *next)
 {
-	return ___list_add_valid(new, prev, next);
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
+	ret &= ___list_add_valid(new, prev, next);
+	return ret;
 }
 
-extern bool ___list_del_entry_valid(struct list_head *entry);
+extern bool __list_valid_slowpath ___list_del_entry_valid(struct list_head *entry);
 static __always_inline bool __list_del_entry_valid(struct list_head *entry)
 {
-	return ___list_del_entry_valid(entry);
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
+	ret &= ___list_del_entry_valid(entry);
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
index fd69009cc696..daad32855f0d 100644
--- a/lib/list_debug.c
+++ b/lib/list_debug.c
@@ -17,6 +17,7 @@
  * attempt).
  */
 
+__list_valid_slowpath
 bool ___list_add_valid(struct list_head *new, struct list_head *prev,
 		       struct list_head *next)
 {
@@ -39,6 +40,7 @@ bool ___list_add_valid(struct list_head *new, struct list_head *prev,
 }
 EXPORT_SYMBOL(___list_add_valid);
 
+__list_valid_slowpath
 bool ___list_del_entry_valid(struct list_head *entry)
 {
 	struct list_head *prev, *next;
-- 
2.41.0.585.gd2178a4bd4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230802150712.3583252-3-elver%40google.com.
