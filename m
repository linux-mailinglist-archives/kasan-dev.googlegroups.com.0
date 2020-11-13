Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOELXT6QKGQEMNNYTJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id A378B2B27FC
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:25 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id 93sf1003516uav.7
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305784; cv=pass;
        d=google.com; s=arc-20160816;
        b=sH6Phbg1ZgFEwJXP5S7FX2bRpQolCvQ9/ZkEiB7RRctLD4ijkEjZPU94CnbMtKFN5U
         SSlPK0chIfPGssd+P4cb14vW9+Ykt6MhoMQpCtDoZeTgAEAz8buqxw8u25NopA4w0n4s
         iPCc+k6i91G+5IP0xIuepWdFEWuQGIFnV5lCZ8ZHSZrCAr4mDUxoeg78VQli4qs1yxeY
         SkyKLw8MeH04Rc2O1gPc2yOZiqh+8BUIa7EQgKnRb38OU4HGfVIj/2ogz7fwOBnCslj1
         UVF+61EwXREDoSjhim2dHfF3FHM465ywBki1f+cb84fcxRRIefgm/sphuKuZBWmtGjfh
         L2IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=/9p3RxxF3sivaTgIfGgJ2ik5V97DT2UjYtpv2QXdikc=;
        b=e7p6QeBeeaZGQZlm32wR17SpYM6I8ne+z9tf7leA1JmNANSJeSL8cX6B1nzkXf7Z1s
         03h+dkKvKCv6bVae1kCAtm+9aaSMfhGEuAJXq9I/tHolraLTrScmDQeXrFzjLqr4ZTso
         042X6B+B2nh6MB3TuKTrc2gzZQQYloJRE5xdf+oxCR0ytu5IkHO20pxCfpmW88NuXAAr
         K1YzoOVM/8Qdj7jrY8xYKVPDS5/o5IZMqtWzqiu10lay9GUg6TGfSkUz/RWE6H6vKhoR
         eu5b3bhCIdqFYP7WO4keUSCpQv64RiDrRFCk2EDhu4CfbmSPkOCINXVN1VOgpH3xVWSy
         USXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Sdo5xec8;
       spf=pass (google.com: domain of 3twwvxwokcyigtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3twWvXwoKCYIgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/9p3RxxF3sivaTgIfGgJ2ik5V97DT2UjYtpv2QXdikc=;
        b=Yrmj9ZuSH/RC5M6jaAqhDRsXqiZuQDkI6hv1mEOiFtatV3YcHs6531uXuNZeXq9zyu
         i+oAsVg1mkcXdKIjVm5cVzatcOFkko445xAHHZnaS8RU0JrvS3ldERJrSHNXyNER7Di2
         8wZ05aFZEtXobQ7cnKi0av4vJXw6YGjekdiF0fsRAFedWy7X4CFS6mxvDOt7qsyrd+QB
         u3vLuzYPvoRRMOeb+HZarz6bQ3ktaB6lxdvzxJad/Q73PMtbuMETKfRkNhutHozDPwkg
         oHjJxspWAJIBPJ22s+U9IX13DXhTEJYVDEdYV8kCptzBMAetKmMeospCISG9W56QKfQd
         gQTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/9p3RxxF3sivaTgIfGgJ2ik5V97DT2UjYtpv2QXdikc=;
        b=aYeiGGt82oWzngZ5l9gSKSDxEZUHHcSiUsUl9Ewzh+mA0DMPU2BUaUCUOE4W1W3yLS
         TXGKMYvqlpZGtTN1ESicidr963giCnv+5wX4hlPA5FTM+81EcEFVhNarzd9FW93Lhws/
         4jzl/xote3d9GwHZywX3aNkiRAiFDfUdiNWreERGTfXw4RPpISNLq9oRl+jDc4s3XX0O
         L8NE9ImPskNc/j+DmHo+WOaSA45kyqi6hIVjkaxBPcEfieKw0tXbnn6mdAqML68wt5my
         z3eYTForbv1l+ohbaTi/F+7myZMr/bNKS1JH37Lm6bcflrfT0tBRq8fpcZszREe8V87Z
         ov4w==
X-Gm-Message-State: AOAM531lYYRiaH0TEM6TiwtwChPpUGgVVZgfxjW7LNJjniSosEp0POMV
	CXigPNYtNEfrpk1cTLwEykw=
X-Google-Smtp-Source: ABdhPJymZ3T3nYWoJGX1tHOR+3VnXmb8Rt55g3eYOLZUCGpoxxVs7QJjUgPp8dXLSVFEbiJd0uMF8w==
X-Received: by 2002:ab0:758c:: with SMTP id q12mr3119413uap.75.1605305784714;
        Fri, 13 Nov 2020 14:16:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5adb:: with SMTP id x27ls589746uae.1.gmail; Fri, 13 Nov
 2020 14:16:24 -0800 (PST)
X-Received: by 2002:ab0:69c5:: with SMTP id u5mr2623806uaq.45.1605305784231;
        Fri, 13 Nov 2020 14:16:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305784; cv=none;
        d=google.com; s=arc-20160816;
        b=Vs6GBL3J1eiLwNtGRKsQbKVxajMrGwNuVMCWnjGpeKbudKs048jrsKOiDRmRi1Zaoi
         TUG8R8WXAXXK+OJpKLS0vhPAj3taugyXvGeyyj2MFN1rsxb5+HxtxyrqdnkVKHhnMbIh
         NdYpEpkUGspkZUjPD0Mn1Ja+cYwMFOIIrNWsNrPcUAodQnt/ekSSD6LxVooLCTcQY7Z0
         TBmQ51/7fEsRMbsdAkRF0P5dto9SZIYEtRUU9lpJ5/6K2si3wLhZ+OmJm0nZDPvStAIy
         9PVaQ2LZeE22MHMHhD+CbryDXvnS4zkcS8ZRQz+IY7Mccj+Zx9rb59EDwzlClPLuSqkH
         urrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=dmp1Ztz+z0/5ouydww+9T91eTtvP6ouU0pc5TkOOGLA=;
        b=kWdxYhaOcMjkKwPsSDwJv3/l3ZwgCE9AKpTwymqKeslAMK8T9FKIP6n6Zt/nQfLh8T
         hV+GizpPZbIVXzrDr5FXmrvockM5F+w05RkiKqjtEr2V4Nb5++FDXgprCJdtN9O0Y12S
         kp8n+PC3TEaKhr8GBrDtwMNhbZtAQoNCBY7w0INg4bPIe/3fm+HzEFu0TIkfpg1dExrF
         ckrCqkM2jG0C4XtmGWahRO08tHFjV1+xTY+3T45UijiekD7i/yZ6ZOqjHaFHNeGOzrgV
         lY1IrDk9VLQXgC0YwG0v36sJQlBXxGPDH+3y2AhNnJviGvMBGRYbDx/ot9gCIs4JdyaU
         x4ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Sdo5xec8;
       spf=pass (google.com: domain of 3twwvxwokcyigtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3twWvXwoKCYIgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id j77si640350vkj.1.2020.11.13.14.16.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3twwvxwokcyigtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id t13so7044314qvm.14
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:24 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5387:: with SMTP id
 i7mr4558075qvv.43.1605305783806; Fri, 13 Nov 2020 14:16:23 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:32 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <df8daed599225910d82a752b8717b70911816772.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 04/42] kasan: shadow declarations only for software modes
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
 header.i=@google.com header.s=20161025 header.b=Sdo5xec8;       spf=pass
 (google.com: domain of 3twwvxwokcyigtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3twWvXwoKCYIgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Group shadow-related KASAN function declarations and only define them
for the two existing software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
---
 include/linux/kasan.h | 47 ++++++++++++++++++++++++++++---------------
 1 file changed, 31 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 59538e795df4..26f2ab92e7ca 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -11,7 +11,6 @@ struct task_struct;
 
 #ifdef CONFIG_KASAN
 
-#include <linux/pgtable.h>
 #include <asm/kasan.h>
 
 /* kasan_data struct is used in KUnit tests for KASAN expected failures */
@@ -20,6 +19,20 @@ struct kunit_kasan_expectation {
 	bool report_found;
 };
 
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
+#include <linux/pgtable.h>
+
+/* Software KASAN implementations use shadow memory. */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_INIT 0xFF
+#else
+#define KASAN_SHADOW_INIT 0
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
@@ -35,6 +48,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 		+ KASAN_SHADOW_OFFSET;
 }
 
+int kasan_add_zero_shadow(void *start, unsigned long size);
+void kasan_remove_zero_shadow(void *start, unsigned long size);
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline int kasan_add_zero_shadow(void *start, unsigned long size)
+{
+	return 0;
+}
+static inline void kasan_remove_zero_shadow(void *start,
+					unsigned long size)
+{}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_KASAN
+
 /* Enable reporting bugs after kasan_disable_current() */
 extern void kasan_enable_current(void);
 
@@ -75,9 +105,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -143,14 +170,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline int kasan_add_zero_shadow(void *start, unsigned long size)
-{
-	return 0;
-}
-static inline void kasan_remove_zero_shadow(void *start,
-					unsigned long size)
-{}
-
 static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
@@ -158,8 +177,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -174,8 +191,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/df8daed599225910d82a752b8717b70911816772.1605305705.git.andreyknvl%40google.com.
