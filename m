Return-Path: <kasan-dev+bncBAABBPMQUWVAMGQERUCWUNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 95B027E2DBB
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:10:38 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4095fcbba0asf31120925e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:10:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301438; cv=pass;
        d=google.com; s=arc-20160816;
        b=afMu8mb0JQJWFKtb97Is4p2BFPHTKZNBuH5ugt1zSaSC6tKMSq1O3j0ic7RyayYfHm
         2HWS5SHYSakfYMrczCQjNzpkQUlMrPWC3rnaseHxaISOqyLE9jtYqDobNV3uJm62WBfo
         KqFVnPLq3HGMLM7EPqqXAeFuAceKMaHqjIg4bf7Yof6De377kwvACnh/gD3oBhjz9cps
         UYuvA9Ly/++E7Yw44YeE5GiC0HyJzd9GgiQ5jM5wruefWQSYaSRAa9kNEzFmjsMyk1WW
         U5l4coWpCXVj8KNryJTymTXiGtlkPS5Gh1rvWRuqmMqRWPxN1yRwyJ1SlxJsW9Fu8pNw
         CHeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/P4DXh8QGAJQxFmSaUtQOouwtNScP06yIPjhsojumoI=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=cdTG7/jYFQgyOKTioheuomhw7HqEmfM8qXmpGWAA5ciqtDgSa31T9UWnS5NCrD8Yyg
         2dBm98/CN+J7E5IKzeTM+P9wgst3kCKuHd78V6EU+6HrjeZejGDvi3BsxljbNkOq29B+
         nDnm2syfVgfNm/+T0ih6Jkdtn7LVkwO31P4gZ7A7SLpMcOqbNX5vmlAExP4BL85L81cI
         ENmQCQyTdch5T9Gm2456gV5Z0XXuerEkE3Ppbcv6+gRvkrquH1+xbTKaSrUj2M8yW0Dp
         iSkZhGGKokqIjh8cTrbpdH+9ueInum2KVUTuUS84nidPP9X3iU2x975zcgdiQQpvS4e0
         DWNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mSKMvKXc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301438; x=1699906238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/P4DXh8QGAJQxFmSaUtQOouwtNScP06yIPjhsojumoI=;
        b=nAjib4fvLQuSFZI9vHHRntHSdVjmJb+t3SUSOwMLXBR9TPMtlFGZ2p5Cloq6jMJXhV
         IT0EtSM5ggxdQTQ6WbLmIz4hKxSbt4QMGWGuifQXYuRiziuWxS81M8JiBo0t0vrsqmZ6
         Z/p8AMPBki40uZMaMX6fQB8IhCq3LXxiKziH7MCWoHoG0rzczOgdaqWFBFHlATDuy6WI
         SEEPq/ayedMBF4z19jXjdWi+KENH2SPurypxfzGqhY8/NDxdfqap6JCHtpKsZwoWy7lM
         m5IoH1IdC+6fCZ4w9JG9jisp3q7w3m4CwaISBJxgHXltwiJRx3NCcTHpbMYPyyUbYCDo
         IxWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301438; x=1699906238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/P4DXh8QGAJQxFmSaUtQOouwtNScP06yIPjhsojumoI=;
        b=Y0jk3J8ZBRVeDP9SYHD18tUmN3FA/q01XM9Vhy5LFvyDJKBbtznsneoqg+IPwRtU7Z
         MD2uEMcX7vGlT5TeDUpPboaA+cq1w4CbGIR0uu0Zyz0kFJyqaPK4rFHno+rx3CZyierD
         aS90Cf3wPA1oT4O6chfp310vANSZZVIjpEaCho0/V70izU6NFJePONSRpyFw68yE9Alx
         JWvKmG89ejDESlJoc6gbnI2Y66Fp9ZWzZz4m7BXAnbeL3gM5QTIsFOynw94wCHLUGQ/z
         Y+IRSgVOOgemF7CEHtlKP/dzB60SRKt0Dp5TUzneeu199n1kFXRD2abzkbFRm5nDRitv
         fpPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwqDL0A9EH6oIBdIZdhPDI4ZKKwCVKIqPdgnVJiy+i2jEutJEzW
	z3E/DLZ/om4zs4BdRRU5nYU=
X-Google-Smtp-Source: AGHT+IF4BjgSdykcqQmiKs68BYo5srBP7G56rqtQTRRtSCnPx9qEPshOD6LS5U1vp+8JVhn1BUKO1w==
X-Received: by 2002:a05:600c:470e:b0:406:54e4:359c with SMTP id v14-20020a05600c470e00b0040654e4359cmr631518wmo.19.1699301437950;
        Mon, 06 Nov 2023 12:10:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b95:b0:3fe:cf02:f33b with SMTP id
 n21-20020a05600c3b9500b003fecf02f33bls2234959wms.2.-pod-prod-07-eu; Mon, 06
 Nov 2023 12:10:36 -0800 (PST)
X-Received: by 2002:a05:600c:4f16:b0:405:3885:490a with SMTP id l22-20020a05600c4f1600b004053885490amr655788wmq.0.1699301436555;
        Mon, 06 Nov 2023 12:10:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301436; cv=none;
        d=google.com; s=arc-20160816;
        b=AET149r/kJh5sQr3qaCabpplCK0liXu6uUdJIU6X9iiNbEzGunEPnl4mfzLQs2/mIe
         ET6fCz2szjls1lcdXeoCRLUINRlVj3aSY351ypVYPWSYspgfUldKFXtVuMYEZbX/y3f0
         KJbTAo356WHkf36OZc2+hFzcVN762Uq/MWOb/+5NUZeyn5DDiWthhfJy6Gvra8R4aiZv
         8zrfLDl2nCqz/TAOu5hnyJDcxNAiDMVOkGg0Owu4GMDHTVkx+3816gkBlPrNJFGSxDoH
         GFX0Bc1sFofhmx8VAnjj3f6EGuZOKIVQyTqRjD8pBH/cqvyW0KxcO1k6jwlChnGdI4d8
         k6+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Hi9wxEG5hyOM24yVF5pvgyGm+UDfsaiMZW2KqzysWxs=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=E6j1aNT/Ch1+RPNVcB100ri2D1uZtzsVvKwvYAl12PneL3KoAHstIIJO1ralGXg5Cb
         p8d9U3iZ/wn4kP9N+PE6kmnocMjSDW55yx5LipOkB2ytzgC2kcB+1DF2z8uAWmIrfIU8
         JAcY3ygM5rSQj3qNuy70sVYGeXVHrVNrO5pDMY2vm14q8XMpRNLX2JTKLKepRqEIbtHv
         n4vErVrFsObchTwJGA24IyttCL2maQHX/p2CGiTFIT3kL5kAHyUsNuAQSEmVSLEABygG
         bAtVrWdh4u8JndkYMpWKhjFFiNsWkjkL1MMUSu5fop8Qp0Buji0IK79wdDFgQ7XeXFNb
         L/fQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mSKMvKXc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [2001:41d0:203:375::ac])
        by gmr-mx.google.com with ESMTPS id o18-20020a05600c511200b0040a1fd44348si87505wms.1.2023.11.06.12.10.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:10:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) client-ip=2001:41d0:203:375::ac;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 04/20] kasan: add return value for kasan_mempool_poison_object
Date: Mon,  6 Nov 2023 21:10:13 +0100
Message-Id: <673406599a04fc9ea0111dac01ae9c84f9a01524.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mSKMvKXc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Add a return value for kasan_mempool_poison_object that lets the caller
know whether the allocation is affected by a double-free or an
invalid-free bug. The caller can use this return value to stop operating
on the object.

Also introduce a check_page_allocation helper function to improve the
code readability.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 ++++++++++++-----
 mm/kasan/common.c     | 21 ++++++++++-----------
 2 files changed, 22 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bbf6e2fa4ffd..33387e254caa 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -212,7 +212,7 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
-void __kasan_mempool_poison_object(void *ptr, unsigned long ip);
+bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
 /**
  * kasan_mempool_poison_object - Check and poison a mempool slab allocation.
  * @ptr: Pointer to the slab allocation.
@@ -225,16 +225,20 @@ void __kasan_mempool_poison_object(void *ptr, unsigned long ip);
  * without putting it into the quarantine (for the Generic mode).
  *
  * This function also performs checks to detect double-free and invalid-free
- * bugs and reports them.
+ * bugs and reports them. The caller can use the return value of this function
+ * to find out if the allocation is buggy.
  *
  * This function operates on all slab allocations including large kmalloc
  * allocations (the ones returned by kmalloc_large() or by kmalloc() with the
  * size > KMALLOC_MAX_SIZE).
+ *
+ * Return: true if the allocation can be safely reused; false otherwise.
  */
-static __always_inline void kasan_mempool_poison_object(void *ptr)
+static __always_inline bool kasan_mempool_poison_object(void *ptr)
 {
 	if (kasan_enabled())
-		__kasan_mempool_poison_object(ptr, _RET_IP_);
+		return __kasan_mempool_poison_object(ptr, _RET_IP_);
+	return true;
 }
 
 /*
@@ -293,7 +297,10 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_mempool_poison_object(void *ptr) {}
+static inline bool kasan_mempool_poison_object(void *ptr)
+{
+	return true;
+}
 static inline bool kasan_check_byte(const void *address)
 {
 	return true;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69f4c66f0da3..087f93629132 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -244,7 +244,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	return ____kasan_slab_free(cache, object, ip, true, init);
 }
 
-static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
+static inline bool check_page_allocation(void *ptr, unsigned long ip)
 {
 	if (!kasan_arch_is_ready())
 		return false;
@@ -259,17 +259,14 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 		return true;
 	}
 
-	/*
-	 * The object will be poisoned by kasan_poison_pages() or
-	 * kasan_mempool_poison_object().
-	 */
-
 	return false;
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
-	____kasan_kfree_large(ptr, ip);
+	check_page_allocation(ptr, ip);
+
+	/* The object will be poisoned by kasan_poison_pages(). */
 }
 
 void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
@@ -419,7 +416,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 		return ____kasan_kmalloc(slab->slab_cache, object, size, flags);
 }
 
-void __kasan_mempool_poison_object(void *ptr, unsigned long ip)
+bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 {
 	struct folio *folio;
 
@@ -432,13 +429,15 @@ void __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
 	 */
 	if (unlikely(!folio_test_slab(folio))) {
-		if (____kasan_kfree_large(ptr, ip))
-			return;
+		if (check_page_allocation(ptr, ip))
+			return false;
 		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
+		return true;
 	} else {
 		struct slab *slab = folio_slab(folio);
 
-		____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);
+		return !____kasan_slab_free(slab->slab_cache, ptr, ip,
+						false, false);
 	}
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/673406599a04fc9ea0111dac01ae9c84f9a01524.1699297309.git.andreyknvl%40google.com.
