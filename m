Return-Path: <kasan-dev+bncBAABBPEQUWVAMGQEZID7E7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 96F077E2DB9
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:10:37 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-40901b5acb6sf92005e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:10:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301437; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRI9Kq4gT49Rp7lIUGfux6NStSWXVb+bEqyTEf/ruYBpRx4FS2VrDz81XWI0VMllXC
         KIHp72WsQuRlFnsTlBRzwZEOSjN6d7k5QrcWLXVv9F/p+V4B/T6xvMXMDlgNf46Xg6BQ
         5kASGQgodVj+ZwPG7mt1773cp3EQFdgE67z/NhHjUgzY6z0WvuY68LaS4g305Ix90h9q
         xe0EllVvPo1z61iZsFaOCyzTMyWlfq05CRNW3bYa2NyECyXUUqZ1w5wWUnhQ0LazZHYj
         /ijDGMS8OWUINxHCLrnLdncIH7ngE4xUssNeiGT09qgEV/v4yCbZ4B8dHUFmdaWo9qkb
         sSgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Ep5zctXoszeTy0H3vZoIUkxVwhmcxuBgtqOaElv+CoY=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=ns4lOMPHsiO2UfFY12873AcHfS+3W8Tt4LmsOhR2DtzF2q+D4gEkUke0vz9Yc67UaP
         PFoTp9MTns+F91JqGSMaBdRSsdxrCcBmcCW/vEJMA+bb03VzhEECuKyHLcHf4/V7rTY6
         OfinYmcqgZTD4hfc6nkYdTsjifq8arOzEQ+t5DCuFvJSUFijTnTqbYz9959UATQRb4wV
         Le3TscwtTnNUSC9io3Q2N/L8rTblRTjh5QXEaOQ7YyZwxPK+ZbhMBumDjIgDLZyKJyMQ
         1N1riMCB2lCVKXBpD9Tn9kzUMATCCR9DJQw5RogdZ+8pVuLtDbkSBwPmLTuQk4JEDW+B
         Dm5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aaX6KV+U;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.182 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301437; x=1699906237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ep5zctXoszeTy0H3vZoIUkxVwhmcxuBgtqOaElv+CoY=;
        b=Ph5m764SAsVk3imzOgJ9CYJI6CkvexLTM2KOk1TlFfKFk9JGmeQVANU/WwlY08wFKJ
         dBI6luZVn7zDd9zIhf4pi2a9JSYqDukhzzolqGnlyZ8k7UcBlJqoA+lB2brNSR7+c6FE
         mC2ooFdqbyOJp9UR4bPK4FoK0PezIGf+IgyQW/Zy0koX+7MF6X7dFwF+1cfY0/gBBOsW
         9Ol9DC2PEExSzL0zPldrYqXopxL2vArOHSKtdeSSmCMiSjyIs6sZCu6FCNl4UfrYHCkx
         03rb+5Rwo34iZfvIoxEcNKy4mWnkT5KdHHKl1J2F9NgS8WhU3BFBXRG6aLXQm1p1sWhh
         RJNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301437; x=1699906237;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ep5zctXoszeTy0H3vZoIUkxVwhmcxuBgtqOaElv+CoY=;
        b=NKaMcgPENNtLDtAeaYfIIE/twKB7HDYTkbdy1mF4nW119toGuRXM7mFp7WdbCpPNJs
         g2kOZmTwc5WR9sIxfsO/vMndbtI7p3dUdgB3hk408ii42n5zBVig8v9o2ZyK7VmQDWsm
         4KqA6G8fDWFHZuGYYjksYtY9lNZiC/0s+ZMZ1o8k0t0w1fKuX9w6CVzy6+mfizxr4pSW
         wR8Aavxq2ysShL+LHrNehuR/GJNKup8ulaBZYnLCLV/YQ88dr9N4wUe9c5orAFTywy5Q
         996VMYfecqqq2Bd9B13K6CR+iwNJL3WfrWJo5kBceLynBrFsEyuUCTI+BMcbvyQUsfb4
         tpPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyUv00CGkkf2/lEsirkd/tO1KOdHXzXvApSztZ/D456oxiZzVWy
	RUGY+JSBQorN1jGORQ98q+0=
X-Google-Smtp-Source: AGHT+IHOCTs8SGt/kNmMYyQHnf1RC0TrrHfh5EGrpSm3li0o844WuOodLKcfwsI4FRJ+3rP+hhd9aw==
X-Received: by 2002:a05:600c:5192:b0:408:3e63:f457 with SMTP id fa18-20020a05600c519200b004083e63f457mr37242wmb.2.1699301436745;
        Mon, 06 Nov 2023 12:10:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b10:b0:406:6882:6832 with SMTP id
 m16-20020a05600c3b1000b0040668826832ls1904937wms.2.-pod-prod-09-eu; Mon, 06
 Nov 2023 12:10:35 -0800 (PST)
X-Received: by 2002:a5d:588f:0:b0:32f:7e4e:535d with SMTP id n15-20020a5d588f000000b0032f7e4e535dmr23505322wrf.15.1699301435311;
        Mon, 06 Nov 2023 12:10:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301435; cv=none;
        d=google.com; s=arc-20160816;
        b=j3KhuwDB8dIFZSQe10vCPpLmJ+7zL3wGvq+kz+au/VyXUFCq0q+9gV3MqxXZPuTE88
         yaFMyWQ2IifDz2VuQyrYYuW9/RaXD7PCimCMWxWxYqMAty+3G4DWBg1pIlVUbIoiLV+z
         voDGad8CB7OnaenLs3M6rX1RexPQl7l+idz/GhJEhK0lCRXV0rDUVzTen4pCcfUw0XfB
         HpHg6tgokyZjE9YeH2wlhRauAL6gBdks/QTu/INj/r6evEgw06Mzu8jEh6XiHE98r3uB
         jbNzALabG2H8I9n6P761hTHJUAyzDGm3EIC1o9PObMCxbbw84NKTk5jHkIameBtr3CSS
         QnVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=t/Tz91brdE21dTNWs0et2BZxKBCaFAccIIB/OCqkFS0=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=GBsw9e3DkPhMX5cRryBlhyy+0UmtQSglTLnAXGKvrk6vBSxN5mw+0MvmMwb7LnEfey
         8t8Qa0Ivil98Gmm5sJ4kif3AuUYU0A1x8Ziqf71Ni0PApAmFajyzhiEscA2gW42yGrpX
         IDFbMJ7j6lG1Um38YOOM52VPGNuH4cVD9bx7hz4XiWds42Gxsy1/kB6R8xXm7Fjo1JUo
         WgevjYGek/UixbzwCVIJ/W7l50q1fldL83tT4fPaB0W1A0sF0kw65SqlqjctlZFRrjZV
         l7KJSgSSdhZaB5qyCslUR2JHTnTWZRv/goi5JkS1a64zxxcDcw7q2/IGaD8PPe4k/m9l
         jisg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aaX6KV+U;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.182 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-182.mta1.migadu.com (out-182.mta1.migadu.com. [95.215.58.182])
        by gmr-mx.google.com with ESMTPS id x9-20020adfffc9000000b0032fccc15b58si29156wrs.2.2023.11.06.12.10.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:10:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.182 as permitted sender) client-ip=95.215.58.182;
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
Subject: [PATCH RFC 02/20] kasan: move kasan_mempool_poison_object
Date: Mon,  6 Nov 2023 21:10:11 +0100
Message-Id: <8bf615539d11dba005e01a65267be1c0298887bc.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=aaX6KV+U;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.182 as
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
index e42d6f349ae2..69f4c66f0da3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -272,29 +272,6 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
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
@@ -442,6 +419,29 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8bf615539d11dba005e01a65267be1c0298887bc.1699297309.git.andreyknvl%40google.com.
