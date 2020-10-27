Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVGX4D6AKGQECA3KQFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 109E729B022
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 15:16:53 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id b11sf826517wrm.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:16:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603808212; cv=pass;
        d=google.com; s=arc-20160816;
        b=lCbWQ83v064R/7/SD+xAA1IY/clxJZWvecWEMCc/IHJ+LFD+yC4N0MMz5zp4t4LJ2q
         VuNvV9M37qndI/zErLMi2WxvNw77LryIxKALhorVIIcA7YHDiQ7s6bAWmCxn9jZGLqkC
         DFYWW3yDqNIhWUyy/OVn6e+c+1fpgiJEahvuRF9x/4S0EQ1K2Z4zbp552swZH1PfGdiG
         uiZDELhGirwWnqjnE6Z7u7+4sGdqNXUsJ/BzDR6eX5/gIEi6tkelqeDLjo1wLGIXHJn2
         o4MeGOBxlWp7AQUxtwaxE/khjx/WtCNO/eLKwzU6NHl7GKL4R7jJDvF0kZI+OMxIBcXY
         AQqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=BRkeb7kA3lwLAQoFxVJ/bsRn3IFaoCytHY72Gkoag74=;
        b=vUN/xdr4MBhjvwdwzGmLTro0PKqw1UXI8hqFsq0L1Rnp5Ls0WjirSB6oOBbYD0rCz1
         B/ju4nu7lAkKdHAVvYkQZoFMmsBVOkaTUOA3VAehO0qNpbXqy7GfD0nzzHr8/z24JWKQ
         Jqj8t7xoGv9d9XRKnRIMhpGi0XyHjAgSHAmNPHM4ggK2DMr7q7XOrem8LxPGYwvfbmdE
         Vna7G7MFyjsA3HE5TB1gFZqt9N7AjNqWBKH9zHU2XeftAij4Brc/kmwNA2BmBRTltU8O
         CgwOxlxMmERQnEn+5rKjPcuOLT+/gqEXkGpqjYc4YSphx95u3dZZYMLwpqukksTDtOv7
         /mow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WvM8gQFb;
       spf=pass (google.com: domain of 30yuyxwukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30yuYXwUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BRkeb7kA3lwLAQoFxVJ/bsRn3IFaoCytHY72Gkoag74=;
        b=Rk1ovd0uGLxCFWSXWL1ph9cY0nXEPmj2wATe8ZqrWc+Hxo1aE3DmIJk4qkR/ocgK17
         1aEWWAylcRWDjmybLBy5bj5QpwD5M0gqBuxVp8VZxjU1pZohODk61Vdun3we5xfKmDHe
         qSObShUJ0xf+KkjI4STN6r3i3DT5CZCWJxkygf6FxRXuOXOm09f0EbY3XWOWHnVIHjG6
         HzADP7LlS93dRdVzKECvzNIBtteM1G6X7KFIZeMfIujyLS4ssQNleXqIxpB+U91GOEcQ
         7o3tXH3peht9gpI9gTJLLE7aq+mcUVqUEWzGwUm+Yzncg3UIJ20xnFokYRXKuMHdOGv5
         8gDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BRkeb7kA3lwLAQoFxVJ/bsRn3IFaoCytHY72Gkoag74=;
        b=CepjJFyQpHP4KjBVzcwDCofepwZFx86s2nv4xWccqrgJFy/EWqz+o9bZE8nwtljRI/
         wZq0VvDJtVXC4BWq9BJUJfzQ0jZ23P2Wq5vFZOOQeFrjt4ej7XpB6I+vKEbyMMHHeLJI
         rC6IJwG3JykDhL2o81S+sD6a0391509jxTGQVRi+m6SeTfK+J6JRposRs57HmZhLCJxd
         1UgVVzTw9zwH9W49GpFW1vfW1evQQVd7FocSoiIf16OF/cCPQQ8VKl2rd/mWNNEiBoe8
         gIpSPYJp81VDmxt0mZsS6d/ZRGFHXH9F4HIFJJp3kf80dcRJ+tshGMDb1YP5v0bfcOuI
         2TFw==
X-Gm-Message-State: AOAM531HMIZ+zf/L9pVBpR5LImFrzqwn7cGxbj7WZIMkUBV/vsgXvUm7
	swnD3dmWEpc9q76RktOmBTE=
X-Google-Smtp-Source: ABdhPJxY77J0WhKMDIGPrVh4W5Et4WR25hs9gYtnV1HNqwsovsZ6ml5DUHDAI8Eb0IItihJaE+x3xw==
X-Received: by 2002:adf:f247:: with SMTP id b7mr3425992wrp.56.1603808212755;
        Tue, 27 Oct 2020 07:16:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7d02:: with SMTP id y2ls945502wmc.2.canary-gmail; Tue,
 27 Oct 2020 07:16:51 -0700 (PDT)
X-Received: by 2002:a1c:9c51:: with SMTP id f78mr3134100wme.189.1603808211728;
        Tue, 27 Oct 2020 07:16:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603808211; cv=none;
        d=google.com; s=arc-20160816;
        b=ujBthAzy7p9L93BGhb0Y8rDDM5ze+2yFZIWZ49K6lGKmUm7rQJz+nUQ826/EvLtj2r
         sYAbM6tvCFCtyTc7iq93gM83zIosESwYi1poHsm8QUI9GcyKJnPIXg44g4J45Wa0HU7a
         zJU3MEM40EOY1gpP/mNgkv2VXAmfwREpVkRKTXHJSdQxO0p6eiqjUvA9c5duQ7DalEn/
         CND3suwFOGuS1ApFXJkPxDAQQ6NN7HI6nEWEIH/Ew0odrANv07/gV8ZFyQwgII1l/9Yx
         zH/jMy2yG44rg1tvPptmL9JZ8iGFUMxidtt2fq7PTztjj9xRRRosig3xO2D/Y97pEq/C
         0ORA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oPFfGVLWPpZQZIz4b/Fi+mHq5Y/nLTEYGP5aTsEDf08=;
        b=duEeu5Pp00w9xYjBwTCPpL58NIblRAez1pVIyk9RpEdI8nCw6ePk1GddczUyKCZd17
         573BZ2YgbQCqIVINs4Ea4BZ8LGlEWC7Ako58zPGUPwPjRJbj2iRtzWFDiMJhuzqafaPk
         9kt+tCKkOME6jCjK9vdFyn1l08cGXlQqikHIyvRez8N4veB8f8MXJWMp/M+rPNBh3yNN
         /gLrMP1zcMjezy1KrmpwMvMUVA1U2F2nCvQayS0yMKMKaptfsMvngfGNMd5YfszV7wyZ
         u4xkwXE9ZZmDEoLeVLoedVs60KX3EKjDz2k+2h1AyujpZK1tseL0upYodcaEyvfpUeYm
         yMdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WvM8gQFb;
       spf=pass (google.com: domain of 30yuyxwukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30yuYXwUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 16si54298wmi.3.2020.10.27.07.16.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 07:16:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30yuyxwukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id l23so384091wmg.6
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 07:16:51 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c4cb:: with SMTP id g11mr2986340wmk.88.1603808211201;
 Tue, 27 Oct 2020 07:16:51 -0700 (PDT)
Date: Tue, 27 Oct 2020 15:16:03 +0100
In-Reply-To: <20201027141606.426816-1-elver@google.com>
Message-Id: <20201027141606.426816-7-elver@google.com>
Mime-Version: 1.0
References: <20201027141606.426816-1-elver@google.com>
X-Mailer: git-send-email 2.29.0.rc2.309.g374f81d7ae-goog
Subject: [PATCH v5 6/9] kfence, kasan: make KFENCE compatible with KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WvM8gQFb;       spf=pass
 (google.com: domain of 30yuyxwukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30yuYXwUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

From: Alexander Potapenko <glider@google.com>

We make KFENCE compatible with KASAN for testing KFENCE itself. In
particular, KASAN helps to catch any potential corruptions to KFENCE
state, or other corruptions that may be a result of freepointer
corruptions in the main allocators.

To indicate that the combination of the two is generally discouraged,
CONFIG_EXPERT=y should be set. It also gives us the nice property that
KFENCE will be build-tested by allyesconfig builds.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v5:
* Also guard kasan_unpoison_shadow with is_kfence_address(), as it may
  be called from SL*B internals, currently ksize().
* Make kasan_record_aux_stack() compatible with KFENCE, which may be
  called from outside KASAN runtime.
---
 lib/Kconfig.kfence |  2 +-
 mm/kasan/common.c  | 15 +++++++++++++++
 mm/kasan/generic.c |  3 ++-
 3 files changed, 18 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index d24baa3bce4a..639b48cc75d4 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -5,7 +5,7 @@ config HAVE_ARCH_KFENCE
 
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
-	depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
+	depends on HAVE_ARCH_KFENCE && (!KASAN || EXPERT) && (SLAB || SLUB)
 	depends on JUMP_LABEL # To ensure performance, require jump labels
 	select STACKTRACE
 	help
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..ac1d404fb41e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -18,6 +18,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
@@ -141,6 +142,14 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	 */
 	address = reset_tag(address);
 
+	/*
+	 * We may be called from SL*B internals, such as ksize(): with a size
+	 * not a multiple of machine-word size, avoid poisoning the invalid
+	 * portion of the word for KFENCE memory.
+	 */
+	if (is_kfence_address(address))
+		return;
+
 	kasan_poison_shadow(address, size, tag);
 
 	if (size & KASAN_SHADOW_MASK) {
@@ -396,6 +405,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	tagged_object = object;
 	object = reset_tag(object);
 
+	if (is_kfence_address(object))
+		return false;
+
 	if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
 	    object)) {
 		kasan_report_invalid_free(tagged_object, ip);
@@ -444,6 +456,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (unlikely(object == NULL))
 		return NULL;
 
+	if (is_kfence_address(object))
+		return (void *)object;
+
 	redzone_start = round_up((unsigned long)(object + size),
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..1069ecd1cd55 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -21,6 +21,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
@@ -332,7 +333,7 @@ void kasan_record_aux_stack(void *addr)
 	struct kasan_alloc_meta *alloc_info;
 	void *object;
 
-	if (!(page && PageSlab(page)))
+	if (is_kfence_address(addr) || !(page && PageSlab(page)))
 		return;
 
 	cache = page->slab_cache;
-- 
2.29.0.rc2.309.g374f81d7ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027141606.426816-7-elver%40google.com.
