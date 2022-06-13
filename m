Return-Path: <kasan-dev+bncBAABBXNVT2KQMGQE2I3NKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7ACC6549EAF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:15:26 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id a9-20020a17090682c900b0070b513b9dc4sf2180758ejy.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:15:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151326; cv=pass;
        d=google.com; s=arc-20160816;
        b=kjoe6+fC6kOTtrjZRha8HsgJb8ryh9Jbzqn8o2Vx+isisupcTTO5sRfAkE/mjM5zji
         QJ8I0exZ/9F/1fmZkD5RUf5TwMVvNq9lrMfmzzM8aldWh4Q1xDU0zHdHJZeFOmpsxZnm
         UIT0JT7BBgkxr5fY0vJ8R+pus988QkyOZGENAKnSQwCQXXfU9VKzVuNh3/hrrGdJAI01
         0X/OLpOOxxLviTn+pNRUIPnJUlCcMdKkvPB08P3hU44lFYX5plCcSDphidOBWOkkFnX8
         7/dc2t1ZMmlFXHhXdZf16XxJMhzmZXS5Verf+i/RpPdFsQJmdunBVodKjS4ehRW3vbCa
         ctlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jk4/GBReunowCNe5M1Mm2Tn30bmzl0tzC6olb8Q3xFU=;
        b=LHZgpnaf28mH86lr7uF+HlZBHS/iQ1aKiDnrdZfbRoBWKOLNlnPQQ+BvBaWzAPEVTr
         zjdFtId4e+hgK4bF5pHutl/Lr88DJVYbw2s+JMPnsEl3tQ9wOr0RMReMgslQVyBlwfY6
         haXGwuBGu7haJyG63buJknszwNmI3YqXCLLFDUs+2Wx5TOPws7xOfLiEV0om0cPMFxbL
         QOAFs4P/c50WFFn5R5shSnjxJcat3l6zBU+GKcGI9Mp3J+NePK9xj9VPwi49uu293+tB
         7Sg2GX5fO71unwoNU6DwMkQEzvAFwvtmcmJ78cc+oxze11PlX3jkVqEmvTjNiM87WYrn
         bDOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B7wM0RDK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jk4/GBReunowCNe5M1Mm2Tn30bmzl0tzC6olb8Q3xFU=;
        b=P3zIIuYBGgU/oxDLNmBTZDGmVofYXTZmTwkJN0bywDI7/JsUdtN0eLDI0EyVxEMuNb
         5GcYnNZiqKDzItmqdc54HaHTU3eqFleW0EzD6WAGzEXySDyNExOMMJtp2zM6tPADQdRR
         YAYvzTNVm1YCuvat4eUPkl0UPdURo5jED20Qu7T5EQ9s6p/28tvCBVn9t0C0SygqcBH8
         ipU80y13I4abzGFbd65PP0TeQxqVOPtS9LnnqwEg9yxhwD18myhIQM0Ta1GY3nLNUueL
         sB+Lj0vyKcWHL24Uoyu7G/kdY4RAifq/sjXMGJyCoVI1eEQq16NZjSTAeVjm88KvfTdD
         XrDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jk4/GBReunowCNe5M1Mm2Tn30bmzl0tzC6olb8Q3xFU=;
        b=6y1vYuiWOEKLNQfsn7evTQ7F8/hh360/d35eEXA7xWTrQxwsl5FfQtsRBiV7fNtmjp
         QWnrscclO1BcnBknFuUlsY40sEK5kGyEmzrsH6lzShrnkPh3yf8/ypydtj23FI/+bkPF
         9Mw0BKlDXub8v49j3MuZbpUthQMYykyA0ah+TTLnTa7B05yUMg0C/PEycjagrmO+HBZr
         0FSQyottZoxQK/wgHJCAf5W+YDnGv1zhozAxyqhTgmSnFGbx+j3qs2zoYB2I9WC0ElYe
         l6DkfBhreUvbxZ75wyPM+q5RgebTKoOOmHviuG0AAK7suOHBAq33bV8dn8QWNmCCVGUQ
         jgEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5307TTRG+C71GGOn0J1Z2g0fLensTrByosGA6q8pJ4fsUmDvwr9n
	vYA2IRHKkELH7a07z67qNUU=
X-Google-Smtp-Source: ABdhPJwcKSiyPffaj0wnC/dCjF63ub2/h2edEMdz9sUh+STI6woVZ+BfiyE3mfRK9AOjinXohIdg1g==
X-Received: by 2002:aa7:d303:0:b0:42d:d192:4c41 with SMTP id p3-20020aa7d303000000b0042dd1924c41mr1740217edq.178.1655151325967;
        Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5ac1:b0:6ff:ab8:e8f with SMTP id x1-20020a1709065ac100b006ff0ab80e8fls142532ejs.6.gmail;
 Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
X-Received: by 2002:a17:906:748b:b0:712:2a23:7395 with SMTP id e11-20020a170906748b00b007122a237395mr1297632ejl.666.1655151325251;
        Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151325; cv=none;
        d=google.com; s=arc-20160816;
        b=F4jYiCJ9W3d9wCZtLB32j3pMbYWrSC38mjxaqoONEcaeQmbmLBE6v5hdhSQeHLOyn0
         LYpISVbk49i5LWTDbEiDkkGLphJ0yeDgHuwiUdvwcYAI7/3GtNDMAgBYbdVL1ROn8F4w
         oMGbdgqLOxFFNav1EtelD+oZZtc7NOVKNJ79u23zS25vlSwpEXGC0gHafklyBn39DW2/
         7jIkc/OmTGr5SxWT63z1JFmkRgPE0xa2Rwp2pCCQwBN5PKzGFDMATvyL1pdHYJU7l88C
         SxqwQjCRVVodDMhe+hxT0ThtUss8xrAE5Pc9+SOP4LIxkQ/MiqXpO7y2EAIZGycr/f5B
         XEWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=j0yWL0nsrOMOMqm9cWej2oW3wFadR2W9VWyegnjYrXA=;
        b=hX01Xy1y3GjeX4YnxKRs3c9cvfD3XgqE+1aryBPnbFLTm04SbwzNL+sz32TFxaySso
         WIizHL6UOl26XzKXgxB1nT+Ugb6Aw4R/GNsAqSCetMMZi12l+OMEdJWpfK9I2B+IVNFR
         MVWzerE5iPeP1Sn1N5h2Yb8sSNm5xYhzxKpEdGGcmMqGvfBzgYEiX5b9uRDKzhaDUXh8
         YkSYBM02fKIdoa9HJGlXDIwDzTjVRCyv27AebBMr443A9YC9e3iKy9UNo91MMsjEbB5a
         gJREZQ14RU1++5P2PZE6Jz72i88666vE8efluTk1ot0mVXpizqvhGMqp9SI8OEeAXWoN
         qS6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B7wM0RDK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id j8-20020a170906430800b00711d2027db1si310241ejm.0.2022.06.13.13.15.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 02/32] kasan: rename kasan_set_*_info to kasan_save_*_info
Date: Mon, 13 Jun 2022 22:13:53 +0200
Message-Id: <50cdd8e8d696a8958b7b59c940561c6ed8042436.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=B7wM0RDK;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 8 ++++----
 mm/kasan/generic.c | 2 +-
 mm/kasan/kasan.h   | 2 +-
 mm/kasan/tags.c    | 2 +-
 4 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 968d2365d8c1..753775b894b6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -364,7 +364,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return false;
 
 	if (kasan_stack_collection_enabled())
-		kasan_set_free_info(cache, object, tag);
+		kasan_save_free_info(cache, object, tag);
 
 	return kasan_quarantine_put(cache, object);
 }
@@ -423,7 +423,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void set_alloc_info(struct kmem_cache *cache, void *object,
+static void save_alloc_info(struct kmem_cache *cache, void *object,
 				gfp_t flags, bool is_kmalloc)
 {
 	struct kasan_alloc_meta *alloc_meta;
@@ -467,7 +467,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags, false);
+		save_alloc_info(cache, (void *)object, flags, false);
 
 	return tagged_object;
 }
@@ -513,7 +513,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
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
index 610d60d6e5b8..6df8d7b01073 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -284,7 +284,7 @@ struct slab *kasan_addr_to_slab(const void *addr);
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/50cdd8e8d696a8958b7b59c940561c6ed8042436.1655150842.git.andreyknvl%40google.com.
