Return-Path: <kasan-dev+bncBAABBM6J3GMAMGQEKZIJ3NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id E147A5ADA88
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:05:55 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id qw34-20020a1709066a2200b00730ca5a94bfsf2636143ejc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:05:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662411955; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZBbr9d9bUuUehfAv8Qz+/dx9zucDCV22ZNva77DQpGoAYcxqwvnSWG+XDho/hjgjsh
         pMHQiiqdlWSdlleJqceT4pP2Yd2DKpSd034Img8Mlh1HTv6mNvKLArpKlPrcBrqrn4Y7
         TW1bCWmx37KhgirQ9gQnFpynoj207xbIGsraeYHQ0/hQQHFP+PLr8FX4oJ8KMeB0j+9K
         f4g4o6MXF13zlTI1xUm9XgQjQgi86m47/aC4UDpHOVUMR9hAKL9VD4wniaZobSoGmviV
         gzIkrSwYyf20Yau/BKwWT/KYFEx4QI45XQyLFy+RaoFB41N17BW5Dm/oAyJfRFc8JjeZ
         +WKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Mb/yhA0hUbVQwHLwyh+6C2J6ScRqoXVplR3noU+lxEE=;
        b=m5Xg4dEfusrdZaPo4M9YgghYo8rkYuaiShu6h0jOyC6ta1PXLM4lSkI1GcyAXWStuc
         Z8oQPX3i4aXqoYJGEvMLBtNXNY84lx5pxuTVPR+PZCMqYKOOKOJgzcDc7IarJPCUOsuE
         aJwZXjlBJEAh3lpho3EqaLw6DkZUwhVKBBHOsjB+XarywJFnfEVzmkrm+HkuXT8a9VqG
         wQCcjmFQn4RWOrSr9vzkTBRjGIC9WZ2+FnFDhalbBHT22b3Rp/PFUaY4JAGnxLEPEVYS
         G82JVcqsL9dCVs5r7CgZjUq4EM4FUUOXzF/78367SLuYiLZH1/ufT9iDXrOaek9nKnWh
         fO6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="o/wYk110";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=Mb/yhA0hUbVQwHLwyh+6C2J6ScRqoXVplR3noU+lxEE=;
        b=qVtlodVVZnoyX10dqWaBT5bzCCDFOdHk8qeP4+TfoPMtoaX1A4ykWS79uWieSWFHiX
         xLMWcQJlyZGsVk4tC/BSIgv/mW1WfX0w576hO8HURcUVvSpui5rC4t76P/2ud6KhY+bu
         skF82LY9yCunaxHqjwUT9vUWXc+Nr5kLWo7lO/FWFaQY05exNkUOO+tjp7vtKB1RCrM1
         06nvecWV4El74Jod1VTegyDtTlt948Iqsbx1CqsvblkYDAn0ZQ4XuEQ9yCTdIeFn9O5x
         P+qnJfc1cWRsdp/X/WjUyf6pNMAfGjQFBjKexP11rg8/ywAlfey0yngi1xAE5xcFzHvG
         GeKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Mb/yhA0hUbVQwHLwyh+6C2J6ScRqoXVplR3noU+lxEE=;
        b=rejDLlSQ4HaM2mtPz5FiC+dcg6udm7GMbX9mn0i65LKyu6gAyWSYbYvBgYm4UgizhZ
         Vr2J65HrHZkQLRweU3foDklmh0LJOeU0dtZ0H/UpzSlhrIyW8gUQLVVwCr+0hehY0K1F
         MjGgSZ3AOaHR/u5fMhlXyW4NqgjodH25QW8w3gGkQZEYajirXgXR7wCeSc8EhICVhrf7
         kDzJG0u6oCG9wVAudf6qiU4WtjbmSULxC6RyzBjjYt/VJbt//miv3YAQYjdbwp1CcEsT
         4FUcxc8RPSlhB6hPIbjoiHZvrVYuJzYpdGa4fE4b847+ksoMuJthJR4msNBb6ASXiXa7
         JsvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2Q/MvfcYNWbOnDCnSlmBkVELZ5vjUq4CPXMQQ9bTUQ1Fzgq90C
	Hr4t6xY8bG7GgmHBFnp7tqc=
X-Google-Smtp-Source: AA6agR51FNUVhqa/pEBIjibFAjtYB5UyFpk2F9/SbzuHjGigsk73fYrgrU/kRVIE0fbdsvbmwf37sA==
X-Received: by 2002:a05:6402:1044:b0:44d:925c:41bb with SMTP id e4-20020a056402104400b0044d925c41bbmr9562884edu.245.1662411955631;
        Mon, 05 Sep 2022 14:05:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c8:b0:448:77f2:6859 with SMTP id
 x8-20020a05640226c800b0044877f26859ls7996405edd.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:05:54 -0700 (PDT)
X-Received: by 2002:a05:6402:1ccf:b0:447:2a20:254f with SMTP id ds15-20020a0564021ccf00b004472a20254fmr44321389edb.114.1662411954934;
        Mon, 05 Sep 2022 14:05:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662411954; cv=none;
        d=google.com; s=arc-20160816;
        b=eXcYSVyd9RFaOAqqEOmG95+HbX8k2zvnnmGUoLFvuBNbLSb68NvigWGI7/KQxOjY/U
         JdDdmuEprfeVV5jIjhQnae0oPVbKUPJWOEVWmAXZ/nCeIxv9hedX0aj40djFqXLG6hJb
         DQFFud+G7qabtsZtYbUxXlNu2bGlP4Yp3vjdKMZXsyyujVP8e64unI8y1fJSNzOnno6S
         lkFd7ZR3XAZit/2UOChhdD1WM4VuDok2T1B07MjTLPaCP0T0abb+WAAuG0G7FcCE45ru
         3vLBFifmeVFVd1usH9Km6ZIlEeLjO1fo94CINX56ZmrJaiRD2rKW9g5JWblxwjvzA7R0
         E6Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sMNzQ3fOnw2gnA7sk+p5VzcTC4OOC9AXjNxA2irzgT8=;
        b=KgKrGgzfQOzLnchd3fWUwXjYNS50VYN1YgmlaVahuJNnaJwfjJw/qIFmFwGCgFNtf3
         mPOtzjDUoOXJKORaXfn6HalhdLZMU6WPwV6Yqsdh4lOlYZnWRxgYOQx/5wehCMrDGQSh
         BOw4WbnK2Lq2EfM4lxi0gIva+mqUT23xI8w/iSOP1GuElpc60AQBBHFr3oF+DCrOj/kW
         7679cFamLJjBvtaJhN8CkyiDE+GXvqF9RURJMurSLj3+RpISrK7D3vFl86urlBo85QGr
         oZRl8P9NFOJjzpz86/IRap8rPrLYr/aPHkTXYBfyCSpuPpJtYdp59uhNZjvp7pXgY0nt
         Y+vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="o/wYk110";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id q5-20020aa7d445000000b0044db0bb77bdsi275034edr.5.2022.09.05.14.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:05:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 02/34] kasan: rename kasan_set_*_info to kasan_save_*_info
Date: Mon,  5 Sep 2022 23:05:17 +0200
Message-Id: <9f04777a15cb9d96bf00331da98e021d732fe1c9.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="o/wYk110";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Rename set_alloc_info() and kasan_set_free_info() to save_alloc_info()
and kasan_save_free_info(). The new names make more sense.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 8 ++++----
 mm/kasan/generic.c | 2 +-
 mm/kasan/kasan.h   | 2 +-
 mm/kasan/tags.c    | 2 +-
 4 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f6a6c7d0d8b8..90b6cadd2dac 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -365,7 +365,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return false;
 
 	if (kasan_stack_collection_enabled())
-		kasan_set_free_info(cache, object, tag);
+		kasan_save_free_info(cache, object, tag);
 
 	return kasan_quarantine_put(cache, object);
 }
@@ -424,7 +424,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void set_alloc_info(struct kmem_cache *cache, void *object,
+static void save_alloc_info(struct kmem_cache *cache, void *object,
 				gfp_t flags, bool is_kmalloc)
 {
 	struct kasan_alloc_meta *alloc_meta;
@@ -468,7 +468,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags, false);
+		save_alloc_info(cache, (void *)object, flags, false);
 
 	return tagged_object;
 }
@@ -514,7 +514,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	 * This also rewrites the alloc info when called from kasan_krealloc().
 	 */
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags, true);
+		save_alloc_info(cache, (void *)object, flags, true);
 
 	/* Keep the tag that was set by kasan_slab_alloc(). */
 	return (void *)object;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 437fcc7e77cf..03a3770cfeae 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -358,7 +358,7 @@ void kasan_record_aux_stack_noalloc(void *addr)
 	return __kasan_record_aux_stack(addr, false);
 }
 
-void kasan_set_free_info(struct kmem_cache *cache,
+void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_free_meta *free_meta;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 01c03e45acd4..bf16a74dc027 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -285,7 +285,7 @@ struct slab *kasan_addr_to_slab(const void *addr);
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
-void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
+void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag);
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 8f48b9502a17..b453a353bc86 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,7 +17,7 @@
 
 #include "kasan.h"
 
-void kasan_set_free_info(struct kmem_cache *cache,
+void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9f04777a15cb9d96bf00331da98e021d732fe1c9.1662411799.git.andreyknvl%40google.com.
