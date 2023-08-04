Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMP7WKTAMGQEKNMI3SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id D4CA876FCDE
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 11:06:59 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-68790b952bbsf832284b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 02:06:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691140018; cv=pass;
        d=google.com; s=arc-20160816;
        b=sQMge13i0zJ2UDfiJ18sQU2fDVz0+g/2T97xlAGIycixn7NwWH/daLpTKBdN7yBxDV
         izZIF+MEDzcY136E9728t2NJKxpxz3jZXiu3H2wuQBD2bpqcPMmBRzNc5zHqNDuXzLeg
         PJm65E1aPKBLenC0tzV6ZCF2Qy/rNPcrDIMBXcfyf/GD2EFvh7b7T2Q91nAH8F/ASFSO
         El6vNM2344DQPT2yj97cPrj1/UR1uHfCszNeUyob1P3IqZQQXj1K0PW2cEyH7IazwW+j
         PyY7E1mqzuVqTbQmi3jINMnBdRyuMkmlAyNblnlM1icz3+y624j/UPwgPMMPF/Mb28CA
         Adwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=RHXycKexvO1wi9h78dkvc0y16WN6hnfVrzMoqBKf5js=;
        fh=3EsCV1kjHdS/GYEZbaUoPw6fO/lAfz1JWLpP8sfLAPw=;
        b=ByqkyOWFDCLTHElkCbIpsrdY0gb/1s4TjCMP2q8J4KOQFmYJcMgXTsPMRmiXF7eqn+
         T/Cnoq89Zfcki2rVOxr0R4nB0WIUO5Rxmn+Td3GMKjowLxZLxvJfNbpL0xXUDe+nARYv
         lJ2tVtS1ASfWDqe60KGNmhVk1621lbQdASqB5sT3WbAN2TT5WJyjv6hFLAsuwSV4uRTb
         EUET6cP0rgTksrmmTerpJVSPnbQzOwjbbUnfMZwOTS+AePdiRso/GKo3xnMIntZ1tQVz
         GdCH0EyZtIWAuwyrLrkBo+TIATE8OHKSlTQiKC8pksRmnEQQKfI6HlPvBBt/+FHFpU4Q
         IzLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=X1qQHJBN;
       spf=pass (google.com: domain of 3r7_mzaukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3r7_MZAUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691140018; x=1691744818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RHXycKexvO1wi9h78dkvc0y16WN6hnfVrzMoqBKf5js=;
        b=JrJflvkCHsXZ9fap7UR7qK4UqE638NTcY/RK0SSKZjLzo09SD+AvlhH8ogptfNKvpQ
         6ISKI4cSTb4F54NSBXvXTBF/CPDlaQWnAtucauMfK8A6w51+zCm+WSGxs/0gfA8LLnUe
         uk8LFLhuCg6KcwFmOR5e9uPuGedhsirz1UDUbIee+sVDJyu6aRFkW7/low8U69j+uaDw
         RS1e5rzBsPsQD8PGGRx76bK1LKLjK6cSWgZZuLfi3AbsV7u3rUSFpGcGleFhPGvS+wde
         Hkh97Sbu7OGyFVYuVpnA6PPA9X4eY8V9omgKwUIRTpk8mSOD5kDBZdoESI8b19ifv0/l
         qQrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691140018; x=1691744818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RHXycKexvO1wi9h78dkvc0y16WN6hnfVrzMoqBKf5js=;
        b=LWUK9ObVnCfndPC4OI2Leb4CklzhmSBPhKIPgkymy3IJBaLBLdu8T0d6pPi3fjJuls
         eflN42kCN6WDDJqcflyWR1k74Uq9oQQNm/8LQEV+jyXGi/E9jlLirA8ckZMXBEx/BnBZ
         9SxJLHbnGb+Zf0Rw/pmfszzkgLDIDL4cO3Y4b6LXXQgPByI3I+Of6wzO1SG7f0JZhuu7
         VTiQCR/k81l/2Tg9RKfHvc5GV5R+sRma1INQNzfy2TVnxAR/0OSQ6o/nWJ8swn0Jdpk0
         DwSxY1fJuQo07bWh3s78C/vkjEd6sFH4fHhVigLMfQCPo0we8ccaQvM80WNNc906iWJq
         3bHQ==
X-Gm-Message-State: AOJu0YyNTeExfBUUZMTJ+9ofqQXYC9x6QaZ1fvrjnF5eV51N+SbW3oNf
	SyzYfq0+W9f78MUIgWvuU8E=
X-Google-Smtp-Source: AGHT+IH523roQa9VWXUO7lRubplmx9oJptC8RdJDovkBNiR3wJBeKEoCHU9rAw3l59bHvirfJuh41Q==
X-Received: by 2002:a05:6a21:328a:b0:131:b3fa:eaaa with SMTP id yt10-20020a056a21328a00b00131b3faeaaamr1117657pzb.61.1691140017747;
        Fri, 04 Aug 2023 02:06:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9aea:0:b0:686:c224:d01f with SMTP id y10-20020aa79aea000000b00686c224d01fls5135051pfp.2.-pod-prod-09-us;
 Fri, 04 Aug 2023 02:06:56 -0700 (PDT)
X-Received: by 2002:aa7:88c9:0:b0:687:35ab:d21f with SMTP id k9-20020aa788c9000000b0068735abd21fmr1330917pff.22.1691140016468;
        Fri, 04 Aug 2023 02:06:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691140016; cv=none;
        d=google.com; s=arc-20160816;
        b=KOSVGtmX5h7ya1HZrZJWXEIO/yXJx6S2vjT5S/+Uy+x5gaRInB/UyumqRYlhG/r4Fi
         P41QXvhuCIQFsyqnjwSgjO9O14fCMI+a+FSLX58tls0PZPK5KJSlnDpxg1pqs9uuwpDO
         zClk6AXb3krOaUA8cocV77+2HRStnwl0vPECraH0JxtILlPUF69vlkNtdca/hPXapuk3
         fUMMXB5nfmBbmIXnlqup5PVbARgwvrjWs28jDDCOG9xLhuyGdBuIZKZj3xT5BR3BBxIn
         vo5JNbVZWbOgjqL739aiyLlYfJO0GZkHsTuI21CI3MlEsqPakqsLaHjP5hIo+mNcctA6
         +XOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=MzWCD4HwKY1r1A6RBU3efg4gsiTlnVjc3j6YbCfBqUM=;
        fh=J68g6MH/W7wOt124Z8Lp4h64rxBVPLWDnNTMQSSfdjs=;
        b=sin/MYBUp1kq6fFzxUcH5XIkZJolEps8z/0zY3KPNk0P2Lyn0msqu7bU55J1yPRr/n
         p+NTGSVBcZb/NsL2cbjI0NYRa0i/PorMM8bB66yeoJ+gyCdPpnJsl0SvsML3L7YmlmH0
         rlM/Hauvjlh4rxUriqT2iahh3742m0i9ywjoXwonFgE0PW5y/Y4qjsY5ztzQJtH+0Pon
         kZynH+SxWq9ICSaKDtMfsf5EwOQst+T7lVTXvkfWuVt3QIZCr8Eo4lcxAdDPq6zfW+YQ
         8nkMe5cuUkG8LrWFJ4KhmGbSksbQp90yNKJE8Alx+z4cf9XMpyFeBGokOZPl0R6d6d+N
         q/lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=X1qQHJBN;
       spf=pass (google.com: domain of 3r7_mzaukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3r7_MZAUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id q17-20020a056a00085100b0068718e461fcsi103525pfk.1.2023.08.04.02.06.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 02:06:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r7_mzaukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-583f048985bso22167077b3.2
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 02:06:56 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:2ebf:f3ea:4841:53b6])
 (user=elver job=sendgmr) by 2002:a81:af41:0:b0:573:8316:8d04 with SMTP id
 x1-20020a81af41000000b0057383168d04mr7391ywj.4.1691140015704; Fri, 04 Aug
 2023 02:06:55 -0700 (PDT)
Date: Fri,  4 Aug 2023 11:02:58 +0200
In-Reply-To: <20230804090621.400-1-elver@google.com>
Mime-Version: 1.0
References: <20230804090621.400-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.640.ga95def55d0-goog
Message-ID: <20230804090621.400-3-elver@google.com>
Subject: [PATCH v2 3/3] list_debug: Introduce CONFIG_DEBUG_LIST_MINIMAL
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
	Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=X1qQHJBN;       spf=pass
 (google.com: domain of 3r7_mzaukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3r7_MZAUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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
v2:
* Note that lib/Makefile disables function tracing for everything and
  __preserve_most's implied notrace is a noop here.
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
2.41.0.640.ga95def55d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804090621.400-3-elver%40google.com.
