Return-Path: <kasan-dev+bncBCCMH5WKTMGRBB6DUCJQMGQECWBULJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id D468D5103ED
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:55 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id h65-20020a1c2144000000b0038e9ce3b29csf1495701wmh.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991495; cv=pass;
        d=google.com; s=arc-20160816;
        b=rm8nrUA+542HsgVLjzM8hXopszEjx2jNLM6dRuvc0rlH82S1ZB855kcFvBcdqt3oXB
         ZZOVxxFKTDTVwXtEIyR6Tmtb3MSX1TWRe/tiS/BPLPyzBAqaI6wGbxNAzMlAXQ1Z4cs9
         iY/UhpdwS+Su8HM3qWIjjfU2hGK0K8yty+ryfztLhSPfway8Pdy8vdik35Cl3npdlhlw
         hCYrNNWufHWVmNLdOWRr7PtJ6IQbUznnS1E3X3xw7BJOwv2cakF8ZDSOu7DI+wcixMEI
         vc4545hFoDpW7lXd/u8VL09C6GmIyUNpk3GQnCL749hmoEW0bzVbqTlAeHvAHZ8MPtnj
         VM1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=v1nlK9gFRJTvUfoxPGhhbcG5C/ih67Jvm47xM8BzccU=;
        b=rN9IawTkmA5nYHlJFtu0NrswDqTpIdYaWqjrdsxuGBwnpe31qFkuhQ4OlqloS/03DF
         iXBjVg5nvRFdnlTGWq4nzcGZo6HGuox12OpTDy5TBa5YTl+vriHH31wcJZygem7noEp9
         D+1MNARn9VZMSG06I4BmQK7l6UkBPUgMh4ozfDVLF13yzQLqFKq1OBrYShF4zEkF9fEY
         qSKi3jmhg845u1sJWBpCML4z3D6WE/p24TLnKa8h574V5Hc3VpkxH57We6unwTHBQdM9
         HpTjp2DCk3uDs23yBi/Lkd4SSDBrOuLv4FXzxWUi8/+fOutA6CDqHgpPR4H57DidZq62
         MdsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BgZrayGS;
       spf=pass (google.com: domain of 3hifoygykcymnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hiFoYgYKCYMnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1nlK9gFRJTvUfoxPGhhbcG5C/ih67Jvm47xM8BzccU=;
        b=C97QlrQ4QpdbxGTK0OH7ASLAtQlgBvKedbYpv2HMfILhcu5uV9ot+enrPfao1CrU4l
         OZzgz5eKrSJCMfKPOkdIg54iaKwIwqDnSsjE1n+PVN0LzExWvTjwwrYt9uwAXYtV4XFE
         N38xj1Ks+LMrC82PGlTyntQyIDrQp4LJyRA9YJtRlam66LA7fll54L8yJ2VoaRs9zwKn
         wWW/kRA8wS2Fz3xy3yL9L4W8SiOSBzz1aIdUNtaFtBVtHWvx+RdKz0SzaQfuA/JJFwYK
         GqlQsdiNFj3YWBCDT2R12fX5QiNty7JQFX1Z2IL59mZO1pVldkcDBkMj5cmL20U+vTHb
         FxfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1nlK9gFRJTvUfoxPGhhbcG5C/ih67Jvm47xM8BzccU=;
        b=OGD5j7LR1L8uSLs0hDE7YFYnyibqnwpPjZpDCNA6Ttjlp71qUpMwKszAL8p54WEo6M
         +2O7WyKtG5hm1yEGuAgcWq7vNbywhksP2I3AjzHLSZIcTKe4OBV63oz25NZVn3te7gjJ
         5tU3qOFMiGLvPigRApGd5HRRpdWKuE17vzQN4hHfm/6kwsrVZq4c3Cu5gMsBesE2oeAs
         tDdJLF0A/cHGJmwxE8F0sm9/+kg3SWLNFJaii8PKXmoLv3ezCy8tLyt2ISxpdsRyWRu+
         p84O19vus9Yt9gcrnKUYCGEhoUbRoRuzY42iMRaADdWhtv8ZG2RT7wMa6aQd0rXipksD
         ikJw==
X-Gm-Message-State: AOAM5317xJhL1Kro/52JK5MboXTx2o/XCvwa5HCnx5BqqOWrozafRNfe
	BxTbc3rx5NLlwz4cf7j1DS8=
X-Google-Smtp-Source: ABdhPJyJ5YqYSJ7tdSBfblrZNotdzjuXsYKZ1cKq9WTE//iwFLgO1uwQ5ViHAhHiGnnmb1VDHlTnng==
X-Received: by 2002:a05:600c:34c7:b0:392:8d86:b148 with SMTP id d7-20020a05600c34c700b003928d86b148mr33093197wmq.117.1650991495550;
        Tue, 26 Apr 2022 09:44:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1447:b0:20a:dc13:2578 with SMTP id
 v7-20020a056000144700b0020adc132578ls1003245wrx.1.gmail; Tue, 26 Apr 2022
 09:44:54 -0700 (PDT)
X-Received: by 2002:a5d:4441:0:b0:20a:d7b5:483 with SMTP id x1-20020a5d4441000000b0020ad7b50483mr11149585wrr.636.1650991494604;
        Tue, 26 Apr 2022 09:44:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991494; cv=none;
        d=google.com; s=arc-20160816;
        b=tQD0E9tswK0kL3DVhb2jeF/w8J7FswL4RhqUAxqZVK/iKF8r/eoeaxmjOHJl1Eo8b/
         XqaAOG3X2+SIwxsOLBuVsU+87tnllV29wfXCTDeScQdcIZCqNvjPiiCjb6f5A5rsqDfu
         Qgx5p6kybN8Gonfm4SU6C59c4AY06hxPDGhXXd9aPeaFgCwIFUGSLxKpmRrCXBXSS/Ai
         nHBVbSwdad4eIdU9h2LbJuwSKXlz5pvVNUmSodBu2lLaLBcyzu7al/uRlj2datv53YbT
         +go0smUHIimGKJcU9bGNtOMCKNZ70C09cMx0UurhTjQOD4urFDtJL1pwpwKwCQKbWxGn
         s1DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=W9bLVQHqrvNNLkakI5+eXR9eCGhjUZBWMw6dTDyY1eM=;
        b=ABfZReYraXAIDB1lbQyDCrkEBiibivvapUShCYE3UiBpdEtlUmsJq34glwQyui6WoK
         3HRcYsyl+SPd6WtD1j3l2Zesgs9AoZ5KT5EsAmX/pWvXlRp/X7Pm2DKXWgwj+d3O3Bqm
         aMBO+v7kQXx+pfp41Tp8BMOghfubpYuqoYzx8QADVOm8VlaOpl//mfM3101MS+1k1/cl
         ZiemSyjrDxBaS1ru4S71KDRG7L3CJ8rN7p/K9o3WCbiwev/OTXDB4CAXSdXWIpMrr3KO
         C5nI0ksJsU4F+zTDgUHGqlACLsaD/VMIt8Tsuv/XzAEY/7QDofhSElmKqgEZCjy9Cxpt
         RZHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BgZrayGS;
       spf=pass (google.com: domain of 3hifoygykcymnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hiFoYgYKCYMnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id b6-20020adfd1c6000000b0020ae37338dcsi176164wrd.8.2022.04.26.09.44.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hifoygykcymnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id r30-20020a50d69e000000b00425e1e97671so3850205edi.18
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:54 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:84a:b0:423:fe99:8c53 with SMTP id
 b10-20020a056402084a00b00423fe998c53mr25379562edz.195.1650991494081; Tue, 26
 Apr 2022 09:44:54 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:42 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-14-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 13/46] kmsan: implement kmsan_init(), initialize READ_ONCE_NOCHECK()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BgZrayGS;       spf=pass
 (google.com: domain of 3hifoygykcymnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hiFoYgYKCYMnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

kmsan_init() is a macro that takes a possibly uninitialized value and
returns an initialized value of the same type. It can be used e.g. in
cases when a value comes from non-instrumented code to avoid false
positive reports.

In particular, we use kmsan_init() in READ_ONCE_NOCHECK() so that it
returns initialized values. This helps defeat false positives e.g. from
leftover stack contents accessed by stack unwinders.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Icd1260073666f944922f031bfb6762379ba1fa38
---
 include/asm-generic/rwonce.h |  5 +++--
 include/linux/kmsan-checks.h | 40 ++++++++++++++++++++++++++++++++++++
 mm/kmsan/Makefile            |  5 ++++-
 mm/kmsan/annotations.c       | 28 +++++++++++++++++++++++++
 4 files changed, 75 insertions(+), 3 deletions(-)
 create mode 100644 mm/kmsan/annotations.c

diff --git a/include/asm-generic/rwonce.h b/include/asm-generic/rwonce.h
index 8d0a6280e9824..7cf993af8e1ea 100644
--- a/include/asm-generic/rwonce.h
+++ b/include/asm-generic/rwonce.h
@@ -25,6 +25,7 @@
 #include <linux/compiler_types.h>
 #include <linux/kasan-checks.h>
 #include <linux/kcsan-checks.h>
+#include <linux/kmsan-checks.h>
 
 /*
  * Yes, this permits 64-bit accesses on 32-bit architectures. These will
@@ -69,14 +70,14 @@ unsigned long __read_once_word_nocheck(const void *addr)
 
 /*
  * Use READ_ONCE_NOCHECK() instead of READ_ONCE() if you need to load a
- * word from memory atomically but without telling KASAN/KCSAN. This is
+ * word from memory atomically but without telling KASAN/KCSAN/KMSAN. This is
  * usually used by unwinding code when walking the stack of a running process.
  */
 #define READ_ONCE_NOCHECK(x)						\
 ({									\
 	compiletime_assert(sizeof(x) == sizeof(unsigned long),		\
 		"Unsupported access size for READ_ONCE_NOCHECK().");	\
-	(typeof(x))__read_once_word_nocheck(&(x));			\
+	kmsan_init((typeof(x))__read_once_word_nocheck(&(x)));		\
 })
 
 static __no_kasan_or_inline
diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index a6522a0c28df9..ecd8336190fc0 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -14,6 +14,44 @@
 
 #ifdef CONFIG_KMSAN
 
+/*
+ * Helper functions that mark the return value initialized.
+ * See mm/kmsan/annotations.c.
+ */
+u8 kmsan_init_1(u8 value);
+u16 kmsan_init_2(u16 value);
+u32 kmsan_init_4(u32 value);
+u64 kmsan_init_8(u64 value);
+
+static inline void *kmsan_init_ptr(void *ptr)
+{
+	return (void *)kmsan_init_8((u64)ptr);
+}
+
+static inline char kmsan_init_char(char value)
+{
+	return (u8)kmsan_init_1((u8)value);
+}
+
+#define __decl_kmsan_init_type(type, fn) unsigned type : fn, signed type : fn
+
+/**
+ * kmsan_init - Make the value initialized.
+ * @val: 1-, 2-, 4- or 8-byte integer that may be treated as uninitialized by
+ *       KMSAN.
+ *
+ * Return: value of @val that KMSAN treats as initialized.
+ */
+#define kmsan_init(val)                                                        \
+	(							\
+	(typeof(val))(_Generic((val),				\
+		__decl_kmsan_init_type(char, kmsan_init_1),	\
+		__decl_kmsan_init_type(short, kmsan_init_2),	\
+		__decl_kmsan_init_type(int, kmsan_init_4),	\
+		__decl_kmsan_init_type(long, kmsan_init_8),	\
+		char : kmsan_init_char,				\
+		void * : kmsan_init_ptr)(val)))
+
 /**
  * kmsan_poison_memory() - Mark the memory range as uninitialized.
  * @address: address to start with.
@@ -48,6 +86,8 @@ void kmsan_check_memory(const void *address, size_t size);
 
 #else
 
+#define kmsan_init(value) (value)
+
 static inline void kmsan_poison_memory(const void *address, size_t size,
 				       gfp_t flags)
 {
diff --git a/mm/kmsan/Makefile b/mm/kmsan/Makefile
index a80dde1de7048..73b705cbf75b9 100644
--- a/mm/kmsan/Makefile
+++ b/mm/kmsan/Makefile
@@ -1,9 +1,11 @@
-obj-y := core.o instrumentation.o hooks.o report.o shadow.o
+obj-y := core.o instrumentation.o hooks.o report.o shadow.o annotations.o
 
 KMSAN_SANITIZE := n
 KCOV_INSTRUMENT := n
 UBSAN_SANITIZE := n
 
+KMSAN_SANITIZE_kmsan_annotations.o := y
+
 # Disable instrumentation of KMSAN runtime with other tools.
 CC_FLAGS_KMSAN_RUNTIME := -fno-stack-protector
 CC_FLAGS_KMSAN_RUNTIME += $(call cc-option,-fno-conserve-stack)
@@ -11,6 +13,7 @@ CC_FLAGS_KMSAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
 
 CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)
 
+CFLAGS_annotations.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_core.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_hooks.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_instrumentation.o := $(CC_FLAGS_KMSAN_RUNTIME)
diff --git a/mm/kmsan/annotations.c b/mm/kmsan/annotations.c
new file mode 100644
index 0000000000000..8ccde90bcd12b
--- /dev/null
+++ b/mm/kmsan/annotations.c
@@ -0,0 +1,28 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KMSAN annotations.
+ *
+ * The kmsan_init_SIZE functions reside in a separate translation unit to
+ * prevent inlining them. Clang may inline functions marked with
+ * __no_sanitize_memory attribute into functions without it, which effectively
+ * results in ignoring the attribute.
+ *
+ * Copyright (C) 2017-2022 Google LLC
+ * Author: Alexander Potapenko <glider@google.com>
+ *
+ */
+
+#include <linux/export.h>
+#include <linux/kmsan-checks.h>
+
+#define DECLARE_KMSAN_INIT(size, t)                                            \
+	__no_sanitize_memory t kmsan_init_##size(t value)                      \
+	{                                                                      \
+		return value;                                                  \
+	}                                                                      \
+	EXPORT_SYMBOL(kmsan_init_##size)
+
+DECLARE_KMSAN_INIT(1, u8);
+DECLARE_KMSAN_INIT(2, u16);
+DECLARE_KMSAN_INIT(4, u32);
+DECLARE_KMSAN_INIT(8, u64);
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-14-glider%40google.com.
