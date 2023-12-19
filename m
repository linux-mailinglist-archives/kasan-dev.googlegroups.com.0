Return-Path: <kasan-dev+bncBAABBO5SRCWAMGQEWEBVCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 949EF819381
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:29:17 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-50beaf48be3sf3715292e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:29:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703024957; cv=pass;
        d=google.com; s=arc-20160816;
        b=FuS8RQt+G50MYh8Axt0cWho4ymMOjhAx8080M5fOGjdQ9+s8KXp3XDWm/Ccaf7K24B
         NC6bR9m4UGMRpyL/SmHyPSYtg57YVFTcm4CekdincbZzerh7fZv+lsELvEQK2mRSemxY
         X1nroUgoFMeefx19PjRBx6ok33k+TtNNpzzQIhMCE8IMBdi+DLbg0KoNM6ib9KNZW6wd
         0Q9nbn4dxZoFSkY/bKIY4H5LDfJ9+eFjADSOih/X9v03GJNE8VjkJCvZLvdzSwnJF2X7
         vSQbhtaIf1Ddr8xozzgorX6n6e5WkK+kH9qOx0Mp3v4129oZogYjrcrZkmXdYTHt3knX
         oEaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qY63KN0TwAaz1ysh1KAuNDCSOunH2QemrC+irVlfN8g=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=tVi14mPcxeJUmSxJIFhvBFtK2J1CvwhasWHfvSSdk92pgWBvBpZ7M3bKTazWVUTkQV
         bZKHAMonxvYB6VBMtaKDtsfw5G/IacDe4HrPilbaUxkVLaJ7+ioEprdhxCnvyfOkhCkb
         jhRSCW9pK+kPRH2XurEXu93NFYabZ6cXmfnBdBPPwjc7eFciKYEFoWqIMQad4UtvEF0e
         Til9yMwZUFy++KIN65+VB8oWddk0fEBSeosekehdNFgvqAtD5V7nJe5VkQzJxaTLRw2C
         esSQtv+0KwVd6K8o2eN30LOS0AjRLx6IXJi76pnX3Zcb/KDttIDR75F+2oNnSOaiixLA
         x1Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dzo5xM0U;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703024957; x=1703629757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qY63KN0TwAaz1ysh1KAuNDCSOunH2QemrC+irVlfN8g=;
        b=DdJIkGhMt78jF33Qb0wHulGEIuaBgzYsRRUuX0WaPE8kWPKWc4/ikti2y8dNNtibAn
         Xe+zzsb8s7M/Navq9CcUzg4/9xMIiMBWyK2nKoIldXpnwKtyrKnnxcVRQ1CONVpYoJUy
         RIVrigdQLnfjDJz44NRJBNfQwTpEX5HlNqOH0PLRlWOZsBnlJEs22AVwpfGhCGC9+cM3
         CMdv3coz6dnCjYfpZanConLaqgNhkkWHcDHY4EfUlCZjJNF+zbsQJ6qrWaa27MEsDdrN
         AVwxsE1HgZoPDkNrbycNgQYd70lrNZAyv9TEAn4yYV2JGyo95MrcoDtpiuF2d67mf4Rx
         osEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703024957; x=1703629757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qY63KN0TwAaz1ysh1KAuNDCSOunH2QemrC+irVlfN8g=;
        b=jP+B2tjumh7WTyt5MKa5w/JKugIBuoqA4v2Jt+R+RbL3By/8j0G8mK+BCsB15U4Ar0
         aXuuGtOqnCFsizRn9jnbMZxQ9j6ZtWNonCEkbxskV7PGbU1spuytjjyfIYdb8HVcupSh
         LNEUgNq0gKzHGe2DWQ9ZY42Tw23RwwIfactg4VMJnnY9275wfb2qRBe1eWMabZgmS1Zc
         7A3j4jJiTXcqcbGwhJsS1jKjoKKGSBMDiBkDhwhF3w0BAyO2KEUuHUqXMUkMps6POyoC
         JJQY1MlBc2XkpvZMVZZxAZSDfR4wwpL+Lv47wTglqvE9zqrzgBHUOlNX9C7/veXVLvWc
         bzhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwJSq9J1UH9jo2UorXRvpTKqfyK4RRlDRdf2iHQvs31Fo5WTdJM
	jBsVj2LHKUKxeopvl0mTVWk=
X-Google-Smtp-Source: AGHT+IEGCcrPfPgcY2Hsi1D58F5/bpkpzeetsgnc3AAPqHNPy1cZGnNJpOOSvRIki8LC9aZLIQvlgw==
X-Received: by 2002:a05:6512:1241:b0:50e:34a1:faf5 with SMTP id fb1-20020a056512124100b0050e34a1faf5mr2109946lfb.144.1703024956103;
        Tue, 19 Dec 2023 14:29:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:27c8:b0:553:b64a:dd8b with SMTP id
 c8-20020a05640227c800b00553b64add8bls161418ede.1.-pod-prod-02-eu; Tue, 19 Dec
 2023 14:29:14 -0800 (PST)
X-Received: by 2002:a50:8a9e:0:b0:553:727e:3b65 with SMTP id j30-20020a508a9e000000b00553727e3b65mr1176924edj.59.1703024954535;
        Tue, 19 Dec 2023 14:29:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703024954; cv=none;
        d=google.com; s=arc-20160816;
        b=Ig+OF2SHiwEruJPQ7mZmbTyKfM5s72+ikhVvB2WAuX4Ibju2LMybqL/ITqVDt6a0oJ
         Oq4rhl6SyyLxEr8Lr7pwLjfYmgIfiyGmJ6+Wtd9Kmj2WW1VG7Sc/i76n4IE88Kj5IRKo
         la98aXAmSBbHgEkC6jD1FJ2VdLZ43clJGcXQXPA6IBmmw8u51SRPUPrUyeEO8YuZzuGc
         12et5nMjQOSxmLN5gowgOxcK6fmhBCR1JGQ2K5CCsDP8wUEjAeFibcOADTK8f7Ap4oRN
         hYhzKkACPxcD+9ubvAbc26qd9lpIP0NkXNvEQgyymmKD5+5COkOmCUA/G9X3MgJnrCEd
         wENQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=W+GO4UdeS5AdNTnDLBObG20S1KoxsxGlKzUPAgkpjho=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=a37NJ9EHlEvOKlOXNsIoZReoxWVuyMTVodjL4RCakM3bN/JbG1oZVTwWOKW2LrT4aA
         C2E2kJq90p1U6gbnaQx8Y3cXxIpfZ5yfOUQl4Trmfu7VLIKu0AdDqO1cTMOxFGI+yfEb
         s89dXviWWr5ploEsueVeULu/nppe8PkAL26E7HDprSA1Z0Nw5ditPCE3OVlEdTRBcZpu
         UC2PyoUD26KlnZzlXBHhqNngr89dSkQae5fMf3Cq0Grhl9PxXhYrLeh8NQcMJBgNOx2/
         zkkK1wA1aH3dMMjXw1Ekuo7N5nOl6GxIgscMzC0Bc0bYh8kTIyj9Nb7Biug5jtGTTjuH
         TR3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dzo5xM0U;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [2001:41d0:203:375::ac])
        by gmr-mx.google.com with ESMTPS id u4-20020a50eac4000000b0054cb5798047si1072023edp.3.2023.12.19.14.29.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:29:14 -0800 (PST)
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
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 04/21] kasan: add return value for kasan_mempool_poison_object
Date: Tue, 19 Dec 2023 23:28:48 +0100
Message-Id: <618af65273875fb9f56954285443279b15f1fcd9.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dzo5xM0U;       spf=pass
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
index fc7f711607e1..2b4869de4985 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -254,7 +254,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	return ____kasan_slab_free(cache, object, ip, true, init);
 }
 
-static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
+static inline bool check_page_allocation(void *ptr, unsigned long ip)
 {
 	if (!kasan_arch_is_ready())
 		return false;
@@ -269,17 +269,14 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
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
@@ -429,7 +426,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 		return ____kasan_kmalloc(slab->slab_cache, object, size, flags);
 }
 
-void __kasan_mempool_poison_object(void *ptr, unsigned long ip)
+bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 {
 	struct folio *folio;
 
@@ -442,13 +439,15 @@ void __kasan_mempool_poison_object(void *ptr, unsigned long ip)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/618af65273875fb9f56954285443279b15f1fcd9.1703024586.git.andreyknvl%40google.com.
