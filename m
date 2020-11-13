Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVULXT6QKGQEYZATNBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id CC86E2B280C
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:55 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id v2sf7208690pgv.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305814; cv=pass;
        d=google.com; s=arc-20160816;
        b=nEvMmLWPtYz5QBpoY+pNabDTTdK9Aif8d5TcdI6iruvjpW7nRwKb63Se51MC4at3xT
         J+Mdbojlnu6SYzPaxRiTihrmlXdd/rQjuzkJTrwEDq9wEu81TXod7BGEgTl/+5U47+rN
         913Fx5dBKAYcIfY5ku2Fvru37cJyn/Uqen/OJx7vc+yON+HfUcW/MRcBPlkFh1jjL/VV
         SkkD4IT46k/C+LXwupbeCXF72NJ72utGeR1A7+F6D9TPqJZlweu71Gjq4U2pfVs47lCM
         LgIYphXwVD0ILErYPrG1AZTLh/0ae4zdlZeHtD8ZhanizFY2OeJwdg+xCv1cNKcYN5HO
         mQrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=7YNemfH+QKlPjgqo6b6K5EzWx4QA52amJqytPJm/UdQ=;
        b=Vm4sWRCL1Ah140v1WeN8BxPbdzp1dluFNn8iE1uqXqH6dk642GPHNk9gd27nFLbWk4
         6Ba06YKMnE81nIg+z+lAeSCw0aGrrkVwdMKMc9PwL5j4I4cEE2w/b4TOqNnc8SOjfrBl
         P6ZnLG4DZnp5xSE983Ai1d7NbkETL6kbXxBr7Xq/R/8Z1XvhqBuAmHd0w0OtS7nFSC6x
         +TMjGo+lQ8fg7sBYDim1pEITvNA+3+a+UxCNtJGyJ/Z67tw1e0+lROT7oWZ3yKCPl4bP
         fiJW3WKAdWBb0LkM6Gos+CU2A3eTUR2hbkqaQDbfQW5N7s0+30RHhsEG+Dp8YSnf2mmb
         xrJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LT5CFhYH;
       spf=pass (google.com: domain of 31qwvxwokcaaandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=31QWvXwoKCaAANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7YNemfH+QKlPjgqo6b6K5EzWx4QA52amJqytPJm/UdQ=;
        b=WmY+qbSmAhz4Ui4gCU4LhMEUS3zEV6cfafNNi/fIWPYoBc80sNiYRdlPMn1pKA2/KM
         KPkl4czeWQvajZ2dmsWA+YqOl22aoWuhkayOhn2vQVWBQgI5bzIfiQsoJWFPJHYk5v8b
         SJPXZsHF7zBY0CJvGVra43OwOXxtwumHILXoNkbeDXjThfYEmfgpyWa02y5oGej5Lyhk
         MthyaJhZn6KrQ9bo8LbAQf/27jfx3I9qOqFQgz4ENTb4ZKaalh6GnEZAa//9RjE44axe
         m8tZX2ASIQB4yF6yP18zdjb46rmYNe45wPrVezmTt0F4IqSHcbN+6Y3myZ0RnHu7dgF5
         4pHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7YNemfH+QKlPjgqo6b6K5EzWx4QA52amJqytPJm/UdQ=;
        b=Ch8aTk2KvKzITUqX1ubbQRIJLiXB5mG25YZbwRjT5ndnU8rO0O5ZhCPGa5Rybwm81E
         5aEFWGw8P8HnKPogs3yWICPt0liC+NlyFrPhg/uSxu4X5xXeQKXD2XctNdXZ0aFozegi
         XHpXzjWnFW7PErCQ3LzT/qWBO5dBaAQtrnwO/ggwegpAY9NP21ZIYUpaOzV9FBNOC6YG
         Add75BtHKTpulp52TBxoaVr/icQgo3NpID9Y/qpGIseOd/LWc8nR9tDs4PvD/q2N6lCE
         Dz5jFRK4KtTDw6umHQ8zoI2xplf/vkUtQhX4RJBzYZjO1a/urHJeILmUo84PCDvxKwKq
         slSw==
X-Gm-Message-State: AOAM532jYfxAF0tDDfgKa0BGQ4I9BXzxjWZV5um/y1aaywE960P1nAc9
	i4hLESOHovomoBMVj68wNXc=
X-Google-Smtp-Source: ABdhPJyjQmmZvEECknd016l+sg02NZbblyMxmCdHzrqU3YJTWXoiG+6AOg0jRavL2R8u/Vh8Tf72kQ==
X-Received: by 2002:a17:90a:4816:: with SMTP id a22mr5326094pjh.228.1605305814541;
        Fri, 13 Nov 2020 14:16:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:483:: with SMTP id 125ls2701076pfe.6.gmail; Fri, 13 Nov
 2020 14:16:54 -0800 (PST)
X-Received: by 2002:a62:d114:0:b029:18a:e114:1eb4 with SMTP id z20-20020a62d1140000b029018ae1141eb4mr3789037pfg.41.1605305814023;
        Fri, 13 Nov 2020 14:16:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305814; cv=none;
        d=google.com; s=arc-20160816;
        b=eFzUdMVWlYD6AA61hnQhILm969WqJjXY+vMWdoa9a7FrfWvl/Y1hjyC2F/gidOi2fL
         RlhLfeGL95arKcIcekc7gf8ZVCObimG8mFIwBAyhnI07UlwIyndN5tmfTTKDC96VWTk/
         VvcA2SRXIKTyqjuVQwrX9MxfowM/OKEGt/4WusG3c6BbtIekVS6YrZkJWUpawHs8F2g2
         m8xgPOHkFPXLS4eYHjPWDWjDk3IFka4h4b2o8F+fDY2WSeNQIBNZm9hdOLQO5eR7eMu9
         dJyEtOQ/5fDWSjmH2RMX7WZA0W/MtolTmwXtAMJjgD4Fcj4Wc6xyN45rOGMkFepPSud8
         wVRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=9CcY7cnQj8/ZsaLGH95ZEDucryFMFL6l1gyKldTtU/U=;
        b=M2cjTSaSQ5d8kOWqxeeuhMQvLe2iNYNHTy4aQCkVgULyWly8WFWvP7gEjHNyfSF/Gk
         1qjiaeZj+EyxAn4HvaAeuba/JuKp43/izY/5cnRp63pQMMarxTB8lqV6RFZSm46MygYf
         6k5uKUwiM/d/C651U1iHiGbZIPi698On5YltAxSjz1O0fiqAY8c0ClVZAEx/oxnod2Zm
         JDKrihvCa+m6xoCJw/Rd/xAS8eC155Cq9U4/SloeQw2Vu1QaVkcAYn5BrfGK/SexaQpg
         gVJjJaBBdfyWpYPsLTixuFFdsZwK0iR0jF0UqbacYPrGxVnUzNehw0otdTTDLb020Ebd
         cUGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LT5CFhYH;
       spf=pass (google.com: domain of 31qwvxwokcaaandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=31QWvXwoKCaAANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id f14si520391pfe.3.2020.11.13.14.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 31qwvxwokcaaandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s8so2713455qvr.20
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ec4e:: with SMTP id
 n14mr4382317qvq.7.1605305813183; Fri, 13 Nov 2020 14:16:53 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:44 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <031e7a7e501534c0ec5d77f6733d63ac56513d1f.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 16/42] kasan, arm64: move initialization message
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LT5CFhYH;       spf=pass
 (google.com: domain of 31qwvxwokcaaandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=31QWvXwoKCaAANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Software tag-based KASAN mode is fully initialized with kasan_init_tags(),
while the generic mode only requires kasan_init(). Move the
initialization message for tag-based mode into kasan_init_tags().

Also fix pr_fmt() usage for KASAN code: generic.c doesn't need it as it
doesn't use any printing functions; tag-based mode should use "kasan:"
instead of KBUILD_MODNAME (which stands for file name).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Iddca9764b30ff0fab1922f26ca9d4f39b6f22673
---
 arch/arm64/include/asm/kasan.h |  9 +++------
 arch/arm64/mm/kasan_init.c     | 13 +++++--------
 mm/kasan/generic.c             |  2 --
 mm/kasan/sw_tags.c             |  4 +++-
 4 files changed, 11 insertions(+), 17 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index f7ea70d02cab..0aaf9044cd6a 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -12,14 +12,10 @@
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
 
-#ifdef CONFIG_KASAN
-void kasan_init(void);
-#else
-static inline void kasan_init(void) { }
-#endif
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
+void kasan_init(void);
+
 /*
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
  * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresses,
@@ -43,6 +39,7 @@ void kasan_copy_shadow(pgd_t *pgdir);
 asmlinkage void kasan_early_init(void);
 
 #else
+static inline void kasan_init(void) { }
 static inline void kasan_copy_shadow(pgd_t *pgdir) { }
 #endif
 
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 5172799f831f..e35ce04beed1 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -278,17 +278,14 @@ static void __init kasan_init_depth(void)
 	init_task.kasan_depth = 0;
 }
 
-#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
-
-static inline void __init kasan_init_shadow(void) { }
-
-static inline void __init kasan_init_depth(void) { }
-
-#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-
 void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
+#if defined(CONFIG_KASAN_GENERIC)
+	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
 	pr_info("KernelAddressSanitizer initialized\n");
+#endif
 }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 67642acafe92..da3608187c25 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -9,8 +9,6 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 64540109c461..9445cf4ccdc8 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -6,7 +6,7 @@
  * Author: Andrey Konovalov <andreyknvl@google.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+#define pr_fmt(fmt) "kasan: " fmt
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
@@ -41,6 +41,8 @@ void kasan_init_tags(void)
 
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
+
+	pr_info("KernelAddressSanitizer initialized\n");
 }
 
 /*
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/031e7a7e501534c0ec5d77f6733d63ac56513d1f.1605305705.git.andreyknvl%40google.com.
