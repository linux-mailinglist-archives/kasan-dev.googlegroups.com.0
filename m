Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3FWWGFAMGQEZQIH67A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 183B9415C32
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 12:48:14 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id u19-20020a0568301f1300b005472c85a1fesf2754151otg.12
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 03:48:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632394092; cv=pass;
        d=google.com; s=arc-20160816;
        b=uFuYiR5hqKFRusd9Mxp9Pj3y3LboJdWA5ybkU5U+TvmM69StuNK3wdkQeiHGWzeIeQ
         D7424Pg81ItviWhAyBB/FaF2teA+IYqxk8bSoHBfskCcer40egyQ5y7YSu2JulboP/r7
         iOs12o5sPHwCGOjxDhQ1/c9O5s2Ja3MgCs4Q0npumEtUJSQVJDAIUyw7G+j+9pzxDfIu
         438H3NvbANbB3HE+kwZ5SrCT2iUTOb2kPacyJ2jHefgRW/47sYZtrhAvV7tAqpZiLpVU
         GHFIybtUXyPRHbd4JclXw2W2devo/i5wvMTlIhMCOSru+r0wQdq+CGqqP3Cfzf6ir0DX
         DFYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=2uPB7m5+rUiKJSxr4PRd7fx9W/eMLCzzBUzWMdL4atc=;
        b=n7w2Hb6eqLgF3wKe9KSw7JdXF7omA/OV6mw64fKXUuHdO2JSb487zdMMJoOiiXcFH/
         RHgNXf4gRsqDhpd/aZHlba6fdTlhXu/pgXNiO4snbMfbfe9NrGGvgwZrvDQOGVaIfsi4
         AvAZuZxWiWdt/J46+9vnDecoxPHSyxesUmn8YSglqElahKILfHum8T28ZTTm3/okcOiZ
         9Bzy3VJoOxFhb/JhhbKcgTZetU5E0s1vDsCA/ZFR3k5WcTLX4+rsHi1Le7sQDLX68v8Y
         PdnGRQQOGwecMdz9x0hPx84YiOnMTv9CzsanSDPMRgm/zGVsFxCDh9AL61UWCAx1J2ML
         sbEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rz5x5gdF;
       spf=pass (google.com: domain of 3a1tmyqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3a1tMYQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2uPB7m5+rUiKJSxr4PRd7fx9W/eMLCzzBUzWMdL4atc=;
        b=fE9e/yLLmvZU5q3U2bd9uw+XM8QwxdsSCQIvAt6Y1wyeZwbB9KQmx6ngeIYximvPvE
         X/otnRFphe4NOt+1Z8OkBn8kjo7KAy30Y1L5PWB4ZXpgoh23Uwz9nr4eYvP5VYn6cxzb
         cl9Y/pBUfS9j0Z8DUZ9jwHJKDnYRRZfJEwiEb3ysaF7lhq5bFBrT/I3SJ/ebcH1iy+UQ
         NDZyLppLOTC81Wrsue/rC/tdOQf5uK7nqpa/pt+dJlNvSu+6Zx86sZsLzmjUxNaGte3L
         G7XuMVJMqZHyqiW6n0aPMTU/WYI9npuPER698o+kXI8Gq+wUerUB2xr2dUCvvgwuPYfq
         K7eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2uPB7m5+rUiKJSxr4PRd7fx9W/eMLCzzBUzWMdL4atc=;
        b=r4ELRsUwPBRgFG9s+/1d+obMdpJiG5UxLNt/KKdy4Dg1sHyd3Hqxzsi6GRtnjsUUQv
         BN2qAMrhHdbC3mgAVI5icYer/uno78FNQ+dfCs+FpotayM2ySbIUEomePNcF2I+Dad4m
         0/SqwgXLkpeh3Ihtxv+UqBuUy9lAZqGWVu9NsRss1ZuhJqORZHsGLXRAb1aUGDdWpubR
         011NQD8NgOaFfUhwRaTGtFLflpoJ+o795/O2Gr0P8PnmStWEdPQhENOlPR5CtOlouxcC
         F4IIqXJ/aVRAvdr0hiWYon20H+6VhCJJ3a98jOw6NJWqW7i1KXM2GqNvHiz4Zh7U0gQs
         vRWg==
X-Gm-Message-State: AOAM5317YBldE4fkG2JHzAadOgshJ1htzWh+V2fRXp08KmiaFHGEKjUs
	etgGcLegmpJeXWgRuziF4H0=
X-Google-Smtp-Source: ABdhPJwWgOVSo4VUByiNQ0ep1WgIrewZwe4VMJBYCSaTCIWZU6EzDyvTDFwH10uVTW4e4QaDZsL8zA==
X-Received: by 2002:a9d:384:: with SMTP id f4mr3629101otf.94.1632394092771;
        Thu, 23 Sep 2021 03:48:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:c002:: with SMTP id v2ls374140oop.8.gmail; Thu, 23 Sep
 2021 03:48:12 -0700 (PDT)
X-Received: by 2002:a4a:e499:: with SMTP id s25mr3180115oov.46.1632394092404;
        Thu, 23 Sep 2021 03:48:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632394092; cv=none;
        d=google.com; s=arc-20160816;
        b=xt6FDHE/dD1EUBuz4ug2lAV3cofWfAZ2Rf+Og3HVOxoeFo88HlHMuhG+/Pb+eJ4r0u
         cnyO/dFjiDS8+QsDHwanXnt2i41irIuJQPNysZh76PdWRcsCVEDf2jRxUw4KDG6kHKOg
         4S0qbiBWpyaGGRQpTPWhojurK2uLwmzoDgZYT2ON5P4YoN1Kjv08/BotBfaKDIFQrh/Q
         msmvW1TO++8kf1nptvtURuz3ifRplnBWQvK2Qx36brNdWFQBpUgWEn9fjhBfcaMPrgIX
         N+AscL7s9KZpgIwTiKVkIkaoUyhc7H5GbHRv1jmGKL+/Olyhsp2LHHBUhfW/twOuk7t3
         yUkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=T9tewya8iK1bzbkFhOsP6uZciKvGiqobRhQCuQcyJJA=;
        b=oCCmpq7t8UPuEF6A41xl/0hf4d6Cjn3cIWrwaESU8U4yZoaxEp9586m6AKOvM/64vU
         ga8XRkjkOy/SwQDC/5qi0dmLA9OUOuwsrl9oBr16QWApoN589anI58Pa3AHkCB2UfdSD
         mi87QA47RfGx5NJgkf/rSQqDFkesBe3YIOpzZIJ4eliJTNelN4Cz553AWAs2r/rrkodV
         g12Q+363sIkMxRfj+wWJ+CBEsupYbopSG8oNixPTiDk2R2ZJ6aASJ5jnc/kRQBBbL8vC
         v2nRr0WLcbqzGJeTNEsu0ZzlRZV6bfByBQ+tKb+pkCEa4NWe0WQ1xJyQVntPV3iuFkYZ
         49cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rz5x5gdF;
       spf=pass (google.com: domain of 3a1tmyqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3a1tMYQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id d24si364302ote.2.2021.09.23.03.48.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 03:48:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3a1tmyqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 70-20020aed20cc000000b002a69b3ea30aso16373805qtb.15
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 03:48:12 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:bd72:fd35:a085:c2e3])
 (user=elver job=sendgmr) by 2002:a05:6214:4c9:: with SMTP id
 ck9mr3692117qvb.52.1632394091933; Thu, 23 Sep 2021 03:48:11 -0700 (PDT)
Date: Thu, 23 Sep 2021 12:47:59 +0200
Message-Id: <20210923104803.2620285-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v3 1/5] stacktrace: move filter_irq_stacks() to kernel/stacktrace.c
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rz5x5gdF;       spf=pass
 (google.com: domain of 3a1tmyqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3a1tMYQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

filter_irq_stacks() has little to do with the stackdepot implementation,
except that it is usually used by users (such as KASAN) of stackdepot to
reduce the stack trace.

However, filter_irq_stacks() itself is not useful without a stack trace
as obtained by stack_trace_save() and friends.

Therefore, move filter_irq_stacks() to kernel/stacktrace.c, so that new
users of filter_irq_stacks() do not have to start depending on
STACKDEPOT only for filter_irq_stacks().

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
v3:
* Rebase to -next due to conflicting stackdepot changes.

v2:
* New patch.
---
 include/linux/stackdepot.h |  2 --
 include/linux/stacktrace.h |  1 +
 kernel/stacktrace.c        | 30 ++++++++++++++++++++++++++++++
 lib/stackdepot.c           | 24 ------------------------
 4 files changed, 31 insertions(+), 26 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index ee03f11bb51a..c34b55a6e554 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -30,8 +30,6 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 
 void stack_depot_print(depot_stack_handle_t stack);
 
-unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries);
-
 #ifdef CONFIG_STACKDEPOT
 int stack_depot_init(void);
 #else
diff --git a/include/linux/stacktrace.h b/include/linux/stacktrace.h
index 9edecb494e9e..bef158815e83 100644
--- a/include/linux/stacktrace.h
+++ b/include/linux/stacktrace.h
@@ -21,6 +21,7 @@ unsigned int stack_trace_save_tsk(struct task_struct *task,
 unsigned int stack_trace_save_regs(struct pt_regs *regs, unsigned long *store,
 				   unsigned int size, unsigned int skipnr);
 unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);
+unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries);
 
 /* Internal interfaces. Do not use in generic code */
 #ifdef CONFIG_ARCH_STACKWALK
diff --git a/kernel/stacktrace.c b/kernel/stacktrace.c
index 9f8117c7cfdd..9c625257023d 100644
--- a/kernel/stacktrace.c
+++ b/kernel/stacktrace.c
@@ -13,6 +13,7 @@
 #include <linux/export.h>
 #include <linux/kallsyms.h>
 #include <linux/stacktrace.h>
+#include <linux/interrupt.h>
 
 /**
  * stack_trace_print - Print the entries in the stack trace
@@ -373,3 +374,32 @@ unsigned int stack_trace_save_user(unsigned long *store, unsigned int size)
 #endif /* CONFIG_USER_STACKTRACE_SUPPORT */
 
 #endif /* !CONFIG_ARCH_STACKWALK */
+
+static inline bool in_irqentry_text(unsigned long ptr)
+{
+	return (ptr >= (unsigned long)&__irqentry_text_start &&
+		ptr < (unsigned long)&__irqentry_text_end) ||
+		(ptr >= (unsigned long)&__softirqentry_text_start &&
+		 ptr < (unsigned long)&__softirqentry_text_end);
+}
+
+/**
+ * filter_irq_stacks - Find first IRQ stack entry in trace
+ * @entries:	Pointer to stack trace array
+ * @nr_entries:	Number of entries in the storage array
+ *
+ * Return: Number of trace entries until IRQ stack starts.
+ */
+unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries)
+{
+	unsigned int i;
+
+	for (i = 0; i < nr_entries; i++) {
+		if (in_irqentry_text(entries[i])) {
+			/* Include the irqentry function into the stack. */
+			return i + 1;
+		}
+	}
+	return nr_entries;
+}
+EXPORT_SYMBOL_GPL(filter_irq_stacks);
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 69c8c9b0d8d7..b437ae79aca1 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -20,7 +20,6 @@
  */
 
 #include <linux/gfp.h>
-#include <linux/interrupt.h>
 #include <linux/jhash.h>
 #include <linux/kernel.h>
 #include <linux/mm.h>
@@ -417,26 +416,3 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
-
-static inline int in_irqentry_text(unsigned long ptr)
-{
-	return (ptr >= (unsigned long)&__irqentry_text_start &&
-		ptr < (unsigned long)&__irqentry_text_end) ||
-		(ptr >= (unsigned long)&__softirqentry_text_start &&
-		 ptr < (unsigned long)&__softirqentry_text_end);
-}
-
-unsigned int filter_irq_stacks(unsigned long *entries,
-					     unsigned int nr_entries)
-{
-	unsigned int i;
-
-	for (i = 0; i < nr_entries; i++) {
-		if (in_irqentry_text(entries[i])) {
-			/* Include the irqentry function into the stack. */
-			return i + 1;
-		}
-	}
-	return nr_entries;
-}
-EXPORT_SYMBOL_GPL(filter_irq_stacks);
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923104803.2620285-1-elver%40google.com.
