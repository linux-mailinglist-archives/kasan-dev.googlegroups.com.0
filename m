Return-Path: <kasan-dev+bncBAABBO5SRCWAMGQEWEBVCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 35D0381937F
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:29:16 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-54da74116d5sf2484a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:29:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703024956; cv=pass;
        d=google.com; s=arc-20160816;
        b=YtWEyPJxMskwz0Fb83wBDYMsvHrurzPJhHN4hkejYfjvMWS06O+m+YOndhhyh8U8o/
         0bUidqgzUSgNh/qIoW+NX/6ivbbnWmSigdCdCTAk0YITO52aBRUdgVxqWUzpEWJAFFQT
         HkN3GfvZIt1eCXfe3uVL7oNh0Sbo5cEhAtjhtP0G4W3nvcmrOiq3fVzEYCsSzTeFcQhy
         xU+m+fAMY1Yp2Xrvbh+A6JPovSlbV95lT+xOrDeLMVdzBooCewegHRfBxd2BS3O0F9Zy
         G4yKOWPbpOqHnlN+o1IlCG7HNZwd1HkoRJEZQi/lh5q+ImiGNuiGA6Frw8uFL5BzDWDS
         oE2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gnCWbcHXewu3GqSsPKndU1MTEs9cLqLOKZ10siCwTEQ=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=RxWttk1KC4d7CmLgDPcM6m7a2iIx7A2ixP9YrqogkJgNyju1MEOHsAolbQg/kjiYE1
         lpgM+SqphBKyzCFRXF4eQLxeSy4b6bkG3HYKCZL3xVDMA1b99cy0eNv3AbHl8QTt9Gxc
         3RBRv/+LqdEXPXZaXEEeOziakNy80O1ssswVPt8yDoyRq6emQ1FQ8kV4a/v5g14QSJgp
         U/wQnYC9l93n9wM3cA25NgBVbrh1tM/arUZVYeb+HyCt/VsENIjgppuMKWxewfRPYKl6
         wZE3P3NRcflsaQTtxvZIgmJKI54d1rnZMqiu6/wFZbpGXrlB1iNZI/x1oZG9/pSf6hIl
         DH0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UmTZEubK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703024956; x=1703629756; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gnCWbcHXewu3GqSsPKndU1MTEs9cLqLOKZ10siCwTEQ=;
        b=SmCk10I9oU2Bj/KSyAbVEbMDUczmipy38fHxDMc0tXNlT6w8eoZCpf+ZI0j83yTL3r
         WLAWLD0JcLILk/rspXiqeSFp8q65m7Z1S+i2xgKfffI1mjc8skCS5SawEiUP8xxD3Vxa
         Bpb7KZN/YbB6YCNSC8Otb7+dNw8xXQ5A0tLRx85Bgz/tUyd1q5uz07rNm8iU9B9l7SN8
         bkVybppLAWeVT501e68d14vSV5R+ESdbO9GjpEOl/kF9i9gHFVogq6CBwv7JKtVNasrI
         vF2vjkCE2H2K1sdsp2cKs9URistniNmPlsll4IwiBTEuE93hA7KmW86q+dg3RoLRB7w1
         B/Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703024956; x=1703629756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gnCWbcHXewu3GqSsPKndU1MTEs9cLqLOKZ10siCwTEQ=;
        b=abgk6/GF8FkOJqnhW2lLtBztehlc1haL1NoTIpjrKhatMUqtT+Hh6vXUY2F3UWnCnT
         yCEfezFUIfvoFVqnS+6nX+QRvZZ5w7ssNW1O5fWIxcsOX3lmHli/nMfNsO/tlEr5ZHCf
         0R7wBkS2ZzqLF5+DeL3GsXvi6xLhNM85m114urbO0/Gyl44cM8iA9zfygEVmyPX9ZoiN
         2lFJoI2nzx3TqzE2wtclLkfnxwfLTC23PytyYKrSeE8hLzQx/LfxsJrBgpgcvePfKmwi
         kT50v/RvPVjXQodevGZQ7hCM7IwNCCnH5murGHqOyBcowp/Pg5DjzO7wFhcxdcg9okC/
         Ul8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YySgC2KX7ByK/XS1kUQV/+uC5rTHiA3ilucYg+OfY1rErQXSaaq
	oLseo/lspl21Fne51HaGFk8=
X-Google-Smtp-Source: AGHT+IHEsew+g0ZKjYJAlVI/pLNhgK2WmFw2kEJ66ynDy/BzeDJdDGalS+9vHM3hAip9vAwp2Z8eUA==
X-Received: by 2002:a50:9e09:0:b0:553:62b4:5063 with SMTP id z9-20020a509e09000000b0055362b45063mr47650ede.4.1703024955636;
        Tue, 19 Dec 2023 14:29:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a07:b0:2cc:5337:489c with SMTP id
 by7-20020a05651c1a0700b002cc5337489cls842078ljb.0.-pod-prod-03-eu; Tue, 19
 Dec 2023 14:29:14 -0800 (PST)
X-Received: by 2002:a05:651c:1a1f:b0:2cc:7445:bbc2 with SMTP id by31-20020a05651c1a1f00b002cc7445bbc2mr2421074ljb.32.1703024953884;
        Tue, 19 Dec 2023 14:29:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703024953; cv=none;
        d=google.com; s=arc-20160816;
        b=Ir3LaKhOpWFnx2qkDvMaKkH1/h1ZLIwBMtVGwqzqByY6tObG9AlWn+BuFmXElrXAn9
         AJvsli5e2QWMtIeqUCXOU4msI+qUJiomDGEUWuwoVhjRNo6xQN3UeoikWvzxKgkO+HR9
         gjfgNL+oO3rKY//A2aSTOCIdUB5Y7ggZsQYJsi07d8U/g39AEsbmnAwh/OfPe1uCQily
         YyQb6eiqZOF8JYtWxKsiGhw9oW1Koyrfcyr6+MP93MLo0QSMn9cnHKoy7mEpBxF6IXMh
         0xDNhcbHF4bLpVX8w52LCkZKrF9GodpulIFH8L2peAHsHI57B0G+AqDAbxn84p9TWnSn
         eO1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UD/Zwt/pPZV96U3h6ZFDRBLd7zSWBzdFKqeEs3HVWEE=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=gMWCZoulTS3QocvdHeTZlZghR1hODChukozbpH9ehteatqc33GWb4r72VG/ralr/7f
         2esokQyFAD+ntS5xYhVi1v6GgPfp3m6vzctthuMTefR22loIpkgDW2Bcg1oRNoLrwMp5
         weOq70zrtz8penwX+ZS4brMff0vA40dZVoxqhV8Qh+Gxh4RJdoaVToQSLalCtOrWVWUz
         gdaxdE+ANwU7dpAVuScFL1aqx4mquVmsoVqGLHOS3QzOWfodamSJOpyLr6sHIrTQhOV3
         qNK4ud+Vj2hM2CmuKvie39cQqWcnGhySwLfrCWf4eaNWO9hXVi9onKRfiUeY4iA/tGZ7
         CWDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UmTZEubK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [95.215.58.173])
        by gmr-mx.google.com with ESMTPS id u26-20020a2ea17a000000b002cc5d3ea655si418966ljl.8.2023.12.19.14.29.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:29:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) client-ip=95.215.58.173;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 02/21] kasan: move kasan_mempool_poison_object
Date: Tue, 19 Dec 2023 23:28:46 +0100
Message-Id: <23ea215409f43c13cdf9ecc454501a264c107d67.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UmTZEubK;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Move kasan_mempool_poison_object after all slab-related KASAN hooks.

This is a preparatory change for the following patches in this series.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 16 +++++++--------
 mm/kasan/common.c     | 46 +++++++++++++++++++++----------------------
 2 files changed, 31 insertions(+), 31 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6310435f528b..0d1f925c136d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -172,13 +172,6 @@ static __always_inline void kasan_kfree_large(void *ptr)
 		__kasan_kfree_large(ptr, _RET_IP_);
 }
 
-void __kasan_mempool_poison_object(void *ptr, unsigned long ip);
-static __always_inline void kasan_mempool_poison_object(void *ptr)
-{
-	if (kasan_enabled())
-		__kasan_mempool_poison_object(ptr, _RET_IP_);
-}
-
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
 				       void *object, gfp_t flags, bool init);
 static __always_inline void * __must_check kasan_slab_alloc(
@@ -219,6 +212,13 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
+void __kasan_mempool_poison_object(void *ptr, unsigned long ip);
+static __always_inline void kasan_mempool_poison_object(void *ptr)
+{
+	if (kasan_enabled())
+		__kasan_mempool_poison_object(ptr, _RET_IP_);
+}
+
 /*
  * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
  * the hardware tag-based mode that doesn't rely on compiler instrumentation.
@@ -256,7 +256,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init
 	return false;
 }
 static inline void kasan_kfree_large(void *ptr) {}
-static inline void kasan_mempool_poison_object(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags, bool init)
 {
@@ -276,6 +275,7 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
+static inline void kasan_mempool_poison_object(void *ptr) {}
 static inline bool kasan_check_byte(const void *address)
 {
 	return true;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index e0394d0ee7f1..fc7f711607e1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -282,29 +282,6 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 	____kasan_kfree_large(ptr, ip);
 }
 
-void __kasan_mempool_poison_object(void *ptr, unsigned long ip)
-{
-	struct folio *folio;
-
-	folio = virt_to_folio(ptr);
-
-	/*
-	 * Even though this function is only called for kmem_cache_alloc and
-	 * kmalloc backed mempool allocations, those allocations can still be
-	 * !PageSlab() when the size provided to kmalloc is larger than
-	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
-	 */
-	if (unlikely(!folio_test_slab(folio))) {
-		if (____kasan_kfree_large(ptr, ip))
-			return;
-		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
-	} else {
-		struct slab *slab = folio_slab(folio);
-
-		____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);
-	}
-}
-
 void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 					void *object, gfp_t flags, bool init)
 {
@@ -452,6 +429,29 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 		return ____kasan_kmalloc(slab->slab_cache, object, size, flags);
 }
 
+void __kasan_mempool_poison_object(void *ptr, unsigned long ip)
+{
+	struct folio *folio;
+
+	folio = virt_to_folio(ptr);
+
+	/*
+	 * Even though this function is only called for kmem_cache_alloc and
+	 * kmalloc backed mempool allocations, those allocations can still be
+	 * !PageSlab() when the size provided to kmalloc is larger than
+	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
+	 */
+	if (unlikely(!folio_test_slab(folio))) {
+		if (____kasan_kfree_large(ptr, ip))
+			return;
+		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
+	} else {
+		struct slab *slab = folio_slab(folio);
+
+		____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);
+	}
+}
+
 bool __kasan_check_byte(const void *address, unsigned long ip)
 {
 	if (!kasan_byte_accessible(address)) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23ea215409f43c13cdf9ecc454501a264c107d67.1703024586.git.andreyknvl%40google.com.
