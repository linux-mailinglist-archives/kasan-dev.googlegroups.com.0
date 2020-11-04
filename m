Return-Path: <kasan-dev+bncBDX4HWEMTEBRB57NRT6QKGQENYZ56ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 78AB52A7114
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:20 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id j1sf113030lfg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531960; cv=pass;
        d=google.com; s=arc-20160816;
        b=QqSqvckM3EZkzWm8ULPWfm2Gsb8CcGS4huzaCAV76GrSVuIHucF1uQGZhG+sFC+Ac+
         vkjfvLOTGZPJjq9H9HzXzl5r2xbyHs4SAi4jtLRocr1m+3eo/E7HFPinpJ9q36AYX0GE
         riuhifyYOfJAnRneZcCj1m43wvJSECuOuvlQ4pycK77zvgSKzQytlbCb41ymuyIclZnC
         CVG3FK7jQz2njO5a+ClxXNdq5BSuLc3mmL6h8jo1yFlXhvtS+QRolQyUV5tAUONvz6Rf
         j+gpJnaOuh8MhWJaA+A10Ppcd6m4whvbOXKIZ673JLA0C/ZVv/AuHl32tmvAxYI+FkJ/
         eQ2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+i8tATml4CfM6dBECmiC35KhsU0cuVQgYU7zdZpoN84=;
        b=bXm7q/w+Y2ysB+mVKbGR8XTCLW56KVq3HhbBTPuOv+4hdNDMIhsOI6tQkNuyaiVXn6
         USSJFp1FacJ8yDvIip+mF1O/KGcDBWm/tItA/VtF39YWwnpKhLa/wUxmYAhcdtlrmS2+
         hFyY5PqvjPCTrjYepWWIyR4xRYoYbY4Irj71twE00WtnbM7EVzlI1gXmJ4vLXHO8UYW9
         Nn8R4wUC7+JIzft5gW4BZW1v6jtrpJ2W4LqCFRjWXQqzcAzvfZHt5iBVvRhrWjpSKKfg
         q3IocfM9VJ0FZGw8VyTM6kWApysf+2bRN+NSuG3PImODA345QrXNc9Fueopkb7WaqDFo
         zAMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dgN/w1am";
       spf=pass (google.com: domain of 39jajxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39jajXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+i8tATml4CfM6dBECmiC35KhsU0cuVQgYU7zdZpoN84=;
        b=FuZESpmnD0aI2bfMrfi4kVdGvMxrTgstehyBv6rAAO+lewmCHe1bF4iVvxTVXAS7Ul
         OGrxJYZlBhW0b2WOS7BZZ73JK+S654soH4FxnO5/idDWBrK2+XRgi1J0IsEGAsL0sS+h
         oBhp4rGIGDN2BvDW/TJAYBL6imUO60A/ZdJd6xdqMo7bMNVo8PPRp/8GuobMCMIV1hUV
         CjylcBHEZus81m6jOIbr9uvoAAYPcm+b5rJWaht9BZ13YKa9xEw/Ngp5HzIa0jBqxrRz
         /QI3e31qHI+Gy+DD4+QlWwqIBPqKAC+5TRfdfDKx3GDDm+Jz88zTZEuu4ltU3naOJBgo
         odeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+i8tATml4CfM6dBECmiC35KhsU0cuVQgYU7zdZpoN84=;
        b=j5w/Mk+DljbXuRuYXERgPAKRSzGczuYzaX/PrN6C3E6Z7PARVo/NQ9zwM/7sGGDwnr
         yDw5X0u6w2oI4YM4iQSYXcI5LGSpw0J4ljhPBSm0r20QhZOHssSw4x1/bEzJ2hzD5ubD
         g6H9cFLDJYxgRz7MTAMWIY/xETF/Dr78zbIu29upyQQzWr2udedUWXz+Zq3J/UiM99Ex
         8nSbpCxJpX/4ztYOpnvleOf8uE2THp+Qj0nKL7OEFeFylcYXUnqzVB+rRDm+KuaTDuY+
         N7KsTea/WZSuO1AhSM0sUS4/V16bIuQM0iEJkZByLU2bbn2PHnvrKDwHEYCcMnAXmF3d
         A22Q==
X-Gm-Message-State: AOAM531VRUjPkNdN6EWhQnGywTD4DiIAIm53nOMKQOyvupgizkcurfxW
	qngO12+AtOmxeq6a4n7Bp3I=
X-Google-Smtp-Source: ABdhPJw8bDjzsWFSs3KXEAiVbQqf7iYvjSdy0MnjDIFd9QwEQitRNTlRq6imIIPbv7D7A0YTru5YUQ==
X-Received: by 2002:a05:651c:3d1:: with SMTP id f17mr132021ljp.80.1604531960001;
        Wed, 04 Nov 2020 15:19:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b5b7:: with SMTP id f23ls673274ljn.2.gmail; Wed, 04 Nov
 2020 15:19:19 -0800 (PST)
X-Received: by 2002:a2e:984e:: with SMTP id e14mr128087ljj.110.1604531958877;
        Wed, 04 Nov 2020 15:19:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531958; cv=none;
        d=google.com; s=arc-20160816;
        b=QIEN9jL8DgwEA8rzTfy0FyVxbU47yGZ7agmVX0KQ5avZ2wQJUhOrZCmmZwpz5KRVMz
         Q5B4r4EqGtrTDBe8A5KHLVTlGmCiFlJTe7knD05lx/PbQmkXU72aGRhfeZiW9mPwVUlD
         m+djw+nNmazKjszqQcmgbJfZPOKtJiGd6Rbl4U3AuoSKxNFQDNFL3gl+8bt4WmsKs+Vk
         jbQGNjimeXpm1VJVvpbfCcbzKjdqk7NBQ23gfco5Bj9wSXWNGoGPZZj7kFuZjcWLHOUp
         AFHi1JctFMaCWVcvYR2r9o59WwqEq8bxWijHUCUEgTnvyo/A/LaU5dl29DcR6WyObK59
         g3Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=nboRM2CFBpQGYkXl6uRGVt4iydoGbxyL4XKrxiXLpKY=;
        b=LUkTjX1XPKQ0nGKAGlTNJCGBpI1H0kyqCSTxQFbXAuzIvIAdX6J5Bw3kgdZznX6GLL
         vaCT9iSV4zOpiUY8qPLkzunmMEY6+HRz873hRf0ZUyqfqC+BohRaoInjcjKdFyf8apzS
         XcVHyk/1B4dLdu7TpDn+lNjLK/tRXTBIQgU6p7h4fJA+kNNF9CCzxXOquWflI2PvkOjL
         joOgehhknyB1bumPkGCjI+rtPH57sVo2WQ2wXLVo5zd2P3qGHydUfS/nnoiAKC0EjV23
         Qu48SO425LcS6ogqLGx80PapzLbZEXMDGtp4p05us5kMmxYhgVDFt9FwU9j8+D/oVV7+
         HoJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dgN/w1am";
       spf=pass (google.com: domain of 39jajxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39jajXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id w28si101838lfq.3.2020.11.04.15.19.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 39jajxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id a130so1721744wmf.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:18 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4957:: with SMTP id
 w84mr86567wma.84.1604531958343; Wed, 04 Nov 2020 15:19:18 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:20 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <36545c406b0aea73f636fa25e85de6a86a349775.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 05/43] kasan: shadow declarations only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="dgN/w1am";       spf=pass
 (google.com: domain of 39jajxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39jajXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
---
 include/linux/kasan.h | 45 ++++++++++++++++++++++++++++---------------
 1 file changed, 29 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 59538e795df4..45345dd5cfd6 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -10,9 +10,20 @@ struct vm_struct;
 struct task_struct;
 
 #ifdef CONFIG_KASAN
+#include <asm/kasan.h>
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 #include <linux/pgtable.h>
-#include <asm/kasan.h>
+
+/* Software KASAN implementations use shadow memory. */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_INIT 0xFF
+#else
+#define KASAN_SHADOW_INIT 0
+#endif
 
 /* kasan_data struct is used in KUnit tests for KASAN expected failures */
 struct kunit_kasan_expectation {
@@ -35,6 +46,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
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
 
@@ -75,9 +103,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -143,14 +168,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
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
 
@@ -158,8 +175,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -174,8 +189,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/36545c406b0aea73f636fa25e85de6a86a349775.1604531793.git.andreyknvl%40google.com.
