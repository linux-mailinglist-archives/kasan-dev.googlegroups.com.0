Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLO4QD6QKGQE2TSAWHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id F29F32A2F03
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:01 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id o27sf1109103lfc.23
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333101; cv=pass;
        d=google.com; s=arc-20160816;
        b=x7S7qFTozmhymrP9tgSaD/pkU+rjcNbebEPk48v9LJpioXtvqAU9NqM9NO3bA9LS/+
         KaFzOVI2WnkuFJaSY7ZOPGXvqTMFgSNjXXQiuesZF70W4rJufXqm4SM36/OE5K0GnRru
         HeJyJs10F7EVgpPtPs8mhSrXPs9EQz5O5Me7q/Bwi0pBo6WC2Rc0lsrnWXd/U8EW9uAP
         Gj0XcjIgyVYgFp9mvzj9MK6Lt9/v+HiUz1OEBd5X4PdFvD2tb+v0TcFufepbOEhRZ9Pf
         GEQnaXx+yPmx3D1kjk+qfbN0EABHTQNtD5ppnYshvJEDw/26TfBON+32HthrVZ1fZsO3
         hr1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=F/w1/0fcgXSiD5AtYwAe+NAqrH96+gELq8Cxcs9RpqI=;
        b=jzdXUBn5t6+uNoB8KY/Zrqq5noQYoX9wF6lfnHY8S0LYPyj5qA2cJWC/AynLj/Yntb
         qHq11xxu9yoC2zjNjjJ/EKWAXCSeRIm0HWms6c194KzLh+g8k06D5OAOuI9L2yUMDA0E
         hFPpzBL/sWIiKqijwWI6EdPszJ8o3n5mwpbojMDNU0r+B8hbtwqa8F6qvC2OH52jUrKh
         61C+4RpTlP291xkwSJ4EuQ6Xh5e9P2iqMb9qqxSCHUN2/SjIDjF7AV9Oj3it424+Bkhq
         9DXtE3u2aYrwMm5a9woDQCud51MT+uYl70VokydXs1Fp/nhpOCEFewo+YnnR5DLUJM88
         ejSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JHfhNMMW;
       spf=pass (google.com: domain of 3ky6gxwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Ky6gXwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=F/w1/0fcgXSiD5AtYwAe+NAqrH96+gELq8Cxcs9RpqI=;
        b=oxxmct1o4rca5PWlqJkARqNK3irwF/a0Hg/GSrdRCHhomI7h1XggP5RsA/PrVhwoyl
         ehK/iKF4LXmvOQjx1s8ijafCqHyxMqd4Ezuik4gjnc1Bcmz/SPNuXbdHPg5oyhXFgSbV
         TBcfSeEbraw8b3vQdixWa56WM+Sl0aPossaHnUI/y7TkqkZ9h8p/pYrGWSD4UTw5Ve/B
         GQk7h0Kcm+HYMcYU+F3RxgGQ7rzysiii9t3H/Q+T6UqwI/w6NxDU7rABLvFsvFqw+sM3
         ykj1bZmMM7x1O9LAVVEQ4LcOVlfUtTdD2+i2kWtlUoTaOEPR0RpRJGNEi11QPV64J3kw
         82MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F/w1/0fcgXSiD5AtYwAe+NAqrH96+gELq8Cxcs9RpqI=;
        b=idW3yFHfofRF06y21HqT1BfwJjqAZzcxciVsl28bX9fcovSPWAcDepoYUeucDlJolz
         xBhuXsNcPeDsahhD4aDHVfXHioxDYm0qLUlQg3b9JdZy4KIorGhgCbE0JDX8XeH893L4
         MBhNLW2hIuURV7fODRc3wtznvSTY1BzDCHP3Nrjjo1+lhG6qma7/4kSaBzE3sWesCBsQ
         CveWJoiNO28MxYb8cPkp3el+GxhSnoNZMYM+t89AcfUPRdJ7sA36t1VXdQq97G9Gs15e
         n/JSKg/0Det+VkSlxl2RqFOKXdgWY63okI+ACqpfo7Th9TRfqIRFnUdA01dN2aPMc1Vi
         suXQ==
X-Gm-Message-State: AOAM5333/92EK09KumNGMiwEUEJ0O3iGtmNyo1mzesgQCtd5l4F+7sjE
	onAmYTR4yG++Tk6zK1Lvr5M=
X-Google-Smtp-Source: ABdhPJx2o199Tvj9F4BlcRBzQfQdB7zgKw9ZHYxR8N9oRnFU6qjoWl8iOkfA+wzePdmhaLjrLnvKeg==
X-Received: by 2002:a05:6512:612:: with SMTP id b18mr6605168lfe.209.1604333101525;
        Mon, 02 Nov 2020 08:05:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls1374722lff.1.gmail; Mon, 02 Nov
 2020 08:05:00 -0800 (PST)
X-Received: by 2002:a19:4a16:: with SMTP id x22mr6586596lfa.66.1604333100506;
        Mon, 02 Nov 2020 08:05:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333100; cv=none;
        d=google.com; s=arc-20160816;
        b=fuqez3Aro9l2GB7ow5ESeqB4dX2QnFEgl1ctDQ520OFcQNKLUCVItsG11/P26fQp9P
         vSiKqUybheAFO+HtGLj55Rwi05EqYlKa4ZYWE1/aLiQWSQo9K5wo8L7J4fUbCEU+1gaK
         JiYY6NyJiwKi9RxDGcA36Jp7sfzys4jvGpNU0mw4ov8nts+YikbmVn1LVbRzZyzu3dQ4
         yR3kech+1fD+dGNonA6puuqtXtQzUmzpZfHZqJ62I2OWB6XqcadRRfDmBA1PDDs+N64u
         AYLuG/aEOj513dPbqdPZ6RHxl/QqCR9XyA5/aEs4mONMrWPGL86vgTwEUxuPty0HZ1M1
         1dug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=nboRM2CFBpQGYkXl6uRGVt4iydoGbxyL4XKrxiXLpKY=;
        b=v5gV0QpjyW/5swp7i2nkj0P93cmGOhugFBBPFSQVPVXsxSWH4DxuIvbtQ41kRGd66H
         TLaE65greW4YWpFdXrBjGGYj0QX2RZAGrjgkoqgXcnqqMo59N16IUoml29l/kmEylm7g
         spfS2WvPix56AZqydmvHOAggeLkfmnUwTF7weqwhTy/gjjG8MsRLvmZMSahzccB9jNG8
         CQjRXei6JYjkAjpFrh6QV12B1LkPfF02eT8C/oFxcAn+DubS6zdzmdNmd+aaB/Ul8r2f
         qa4rH2uSCZU/OQs0P7LYMtXqwkRHE7UfwadBfSSj/rIy8mlAmP7KUNkaak4YjTcJZS/r
         3DMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JHfhNMMW;
       spf=pass (google.com: domain of 3ky6gxwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Ky6gXwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id a1si473008lff.2.2020.11.02.08.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ky6gxwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id c10so2652969wmh.6
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:00 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:21c4:: with SMTP id
 x4mr18287235wmj.74.1604333099942; Mon, 02 Nov 2020 08:04:59 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:54 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <d292b4aefdd9b5d0d52bfde8a353aae4e3cb5d5d.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 14/41] kasan: shadow declarations only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JHfhNMMW;       spf=pass
 (google.com: domain of 3ky6gxwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Ky6gXwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d292b4aefdd9b5d0d52bfde8a353aae4e3cb5d5d.1604333009.git.andreyknvl%40google.com.
