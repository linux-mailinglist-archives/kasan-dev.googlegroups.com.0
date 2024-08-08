Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB3452S2QMGQENKJCF7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8462294C457
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2024 20:31:12 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-42816096cb8sf15242205e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2024 11:31:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723141872; cv=pass;
        d=google.com; s=arc-20160816;
        b=SfROj1nj5/TWFQAwMu1Zglc36U0ulJE4lmfeNKYzz7Osbb+n2Uk1q/YXGJEb9ksspO
         8p0rX7wpRUlM8O+4kwSSC5ThIt8st7xEGq/uzmWKgy89R7HcsyTzW6Wt18YOzJdCGldZ
         R4KHRZE+8ZHd3yShuVX8ZJF7fk6iv/PCiLrj+5Dt2ZvqWAOh6gsZf3ceAegetjJ8wsYy
         SntrdzXbL9h60+wc6n2lIDnhjFOBh+9+8MvmnlXjKBcqXzuPQuZXzM3KViq+HisFN0ep
         rfOr4etg7a3f6kE+egFdfEzVj8ibgVH6liJe5poec0rDpIiEUM/vfPHvWPAqbhukqg96
         dlmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=aYLd7HSwJ4TBONMiAj/czBIcDx/U2MAuic1g3hES+54=;
        fh=B5KgVFX5V7QQ2ZprfuBuRxVcarn2mZDQys6P3k/JCWU=;
        b=e/JDaYxmCxDzJQG/0BTokGiFrLEwm++XmPvkyEgl/iXGrITHhIbJswhIdXipIeE+JT
         tO0x37O/ezKmQiRAxhb6EO6J4LeEEwwq0SKT2QMrpe3b6j6E6B7Nq9iiGmexu5sWmoNX
         h5p4Hthldp09MFXJXLtTuerfKRd4myZyF8m2MxaruGYgO35TqGQpLydPjQWWDPQaRNwZ
         WGGSuxTUei5qgpLcO/jh1+I2aeR1ADu9bwhrtw5ywr8Ln9yAUeUI13xHWbTE0aacFjwl
         kdX3kakd9zwaJkXfUB/Su8aRZlUkGOUFRUHStugEuEbmhZq3+Y5QF+KqLAtfIVjup1Po
         5Mbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dHIrzxi3;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723141872; x=1723746672; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aYLd7HSwJ4TBONMiAj/czBIcDx/U2MAuic1g3hES+54=;
        b=R/xFPlvNtLjyftJxHKMdMhJqCz1381oBznfBNHrFREJq3BEKb4M2GTy4okUCEsrkXd
         bwNPLwNydahnDaXqF0OI1D1zDQPmlpNsBk1ykaiuCZ8vrmTF5GK0Kz9S52tZbXRc8RSo
         WWp30wQIjRAjO3bQXUpA4bp44/G1c3I1grDICxVHLBqDI+w4eewN4Ez+3fEJPFgbY59J
         m4wF88ND8H1jBo1KdG+cMxj3KRQNgzR7VPVpBuIEGQofoD+MNRz1pU9/lVPKvrUVuvY6
         KMfc60DkX5ijQwDcJi/kUNiwievwkv2oEJ/Y5c4lym+NrF7SynspotoD8jXsGNpNa+O4
         tM0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723141872; x=1723746672;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aYLd7HSwJ4TBONMiAj/czBIcDx/U2MAuic1g3hES+54=;
        b=uqHspXMPbMHRYDeh35y2IIe1v/ijQZdBBHbQ7IHlUE5tQZBy3iBby0N/OXXDe/PLmK
         3yVGmolP/hx1f6NKFDn45lh25hnx1wvDaQXOggxPiu/qUv+nstP2U2Dco9YARd3q6U50
         i117t34Hfc4xfWFBShMnnjr9OrFl+FKmhFR/a0Hp8OOHW8218lxlW4T7nvF5/S+5MCqY
         KKX7ROoJcdtm1m4lM58x1woLgReup/xjE7tnAetJQgzqrWAXmZp+sTEQaELcDrwbENHm
         vgT/Vn85ELSVHgLE7kC1M8K3C0xXQ4Xnr1fVIxNvWQICGl/+c6FuToVsH6718mEU6MWu
         RGrQ==
X-Forwarded-Encrypted: i=2; AJvYcCXYaL+K/LIpkQI6pADGOhQJGA6Am/Yppg9zLyYtP5SsFn1CecRpXEYoHza4mU+udmBNxcVAIw==@lfdr.de
X-Gm-Message-State: AOJu0YxPP9PVzktvQ2gqQg2r6M5Ys90rdSs88DAFpFqJfyOHZGboIH/a
	qcQGKS61j8TEJ8KY3Tnm28r2C0aB6oT5cENKGWxcwLcBdUHhz96M
X-Google-Smtp-Source: AGHT+IGru13wM8tqATiX2ENmemLaWf65Bs0qe4XFY29o2wa+fzT8jfNBcJUAfrAbS/dIMm1OimlxeA==
X-Received: by 2002:a05:600c:5010:b0:426:5b44:2be7 with SMTP id 5b1f17b1804b1-4290aeee04fmr26889495e9.10.1723141871367;
        Thu, 08 Aug 2024 11:31:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1991:b0:427:9669:d780 with SMTP id
 5b1f17b1804b1-4290909cb86ls8010745e9.0.-pod-prod-05-eu; Thu, 08 Aug 2024
 11:31:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXOMINNHoc8tMaUNC9RrYh74p22VOr44tqaFVju4TMj5TQO6DgAqfoBRIychdNjcLNjt9kkB+FwiVQ=@googlegroups.com
X-Received: by 2002:a05:600c:1914:b0:426:5f09:cf53 with SMTP id 5b1f17b1804b1-4290af002f6mr29609195e9.15.1723141868879;
        Thu, 08 Aug 2024 11:31:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723141868; cv=none;
        d=google.com; s=arc-20160816;
        b=rKmoZtDPfio8yGe/LfPaOGaN4fEKsXcheKVtsd9n6DX8WfCtb1dd+x8SM8G7ALwMeA
         jyvQTUd6/MRfHdfmzYE/E4CQwuu9/ZMOrns6N+5a21aG0TYr4W3ZJ5wTDcz4kvqiNfNP
         sr3OEvoFAOoYcAWqAUUw6ACgpHaJng1oixY1qwuGVNYN7nYLa3lTIokxncte9Gp4vBrM
         N2ZZGeRam797OobcUZJfkzogBsKb6ThCqwHwuqnMthwM6xXLS0FNQWCJ8y1hf+TooLNS
         k86UulY8CuB7xzDA0x8chYEwnufPuMVWdPzggu3QLgifW4wbn4W3DAzQe6zHSUa0kVK5
         c8Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=04hH29wKOUh4zO671E3nNC0Fq21jgPwt4FhdP1F+2dI=;
        fh=yfd2GNOy6XruwGPMV+0O3F3nfXaoLwwePFnSZYDU9WE=;
        b=jFZI/1MjGnCNOiuocGhszq52NkU+F0H8IXtkJqYayJfwHrYqUYOOdhTIW25uOHfEmg
         LFiWPG3f+Wt3dbpa1IwnN0j+l1EvROKKS1bWQ0EV1mMbAbSOW/Nnb4jLmadtZGVcY4P1
         zxoKcKne63y3gWaEg2jYRMg3MWeWr85Ssjaf808WTgvCDsVgFtgmwamhkZPbQKRZy8B2
         L9tgXXHu1jMm1oDJqme2i+COeLNcUHXda0Yt+p7Eery29PS0IIPh0vFPFo9oCOa0CoCv
         oENJ0uNv0QwVFUb964XdIiws0w7cUU6dIN8HQhETSQQsqSTNGGu9BefUBVF6p8GXxVnT
         615A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dHIrzxi3;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429057ade71si2227185e9.1.2024.08.08.11.31.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Aug 2024 11:31:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-428063f4d71so1475e9.1
        for <kasan-dev@googlegroups.com>; Thu, 08 Aug 2024 11:31:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW5Pd4q63FKVWKNO+TIFzB0wUTc7hQ7IpIzA68yKy3BX5XMx9F40Q4g6JFgYT/a6wqG0UStshaNa5U=@googlegroups.com
X-Received: by 2002:a05:600c:1d8b:b0:428:e6eb:134b with SMTP id 5b1f17b1804b1-429c17158eamr150835e9.4.1723141867568;
        Thu, 08 Aug 2024 11:31:07 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:fc0e:258b:99ae:88ba])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-36d2716cab8sm2740602f8f.33.2024.08.08.11.31.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Aug 2024 11:31:07 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 08 Aug 2024 20:30:45 +0200
Subject: [PATCH v7 1/2] kasan: catch invalid free before SLUB reinitializes
 the object
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240808-kasan-tsbrcu-v7-1-0d0590c54ae6@google.com>
References: <20240808-kasan-tsbrcu-v7-0-0d0590c54ae6@google.com>
In-Reply-To: <20240808-kasan-tsbrcu-v7-0-0d0590c54ae6@google.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
 David Sterba <dsterba@suse.cz>, Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1723141862; l=8980;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=6bMIRMeh/1RVCY2STakwRPDtPkfm0ed8OAz2i9tHk/A=;
 b=Bz96GJnEDgJC0OQe3Qvv/I4NeAbS0M2d7kU5ie23XurhDcPE734xeSMNC41OBmyWhVoZJdBL/
 lpaO+mpyAHSD2BQyWV8a/5H+3kMUvHChi9BvLG4uKYJzdlI5KEVtYbp
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=dHIrzxi3;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Currently, when KASAN is combined with init-on-free behavior, the
initialization happens before KASAN's "invalid free" checks.

More importantly, a subsequent commit will want to RCU-delay the actual
SLUB freeing of an object, and we'd like KASAN to still validate
synchronously that freeing the object is permitted. (Otherwise this
change will make the existing testcase kmem_cache_invalid_free fail.)

So add a new KASAN hook that allows KASAN to pre-validate a
kmem_cache_free() operation before SLUB actually starts modifying the
object or its metadata.

Inside KASAN, this:

 - moves checks from poison_slab_object() into check_slab_allocation()
 - moves kasan_arch_is_ready() up into callers of poison_slab_object()
 - removes "ip" argument of poison_slab_object() and __kasan_slab_free()
   (since those functions no longer do any reporting)

Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h | 54 ++++++++++++++++++++++++++++++++++++++++++---
 mm/kasan/common.c     | 61 ++++++++++++++++++++++++++++++---------------------
 mm/slub.c             |  7 ++++++
 3 files changed, 94 insertions(+), 28 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 70d6a8f6e25d..1570c7191176 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -172,19 +172,61 @@ static __always_inline void * __must_check kasan_init_slab_obj(
 {
 	if (kasan_enabled())
 		return __kasan_init_slab_obj(cache, object);
 	return (void *)object;
 }
 
-bool __kasan_slab_free(struct kmem_cache *s, void *object,
-			unsigned long ip, bool init);
+bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
+			unsigned long ip);
+/**
+ * kasan_slab_pre_free - Check whether freeing a slab object is safe.
+ * @object: Object to be freed.
+ *
+ * This function checks whether freeing the given object is safe. It may
+ * check for double-free and invalid-free bugs and report them.
+ *
+ * This function is intended only for use by the slab allocator.
+ *
+ * @Return true if freeing the object is unsafe; false otherwise.
+ */
+static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
+						void *object)
+{
+	if (kasan_enabled())
+		return __kasan_slab_pre_free(s, object, _RET_IP_);
+	return false;
+}
+
+bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
+/**
+ * kasan_slab_free - Poison, initialize, and quarantine a slab object.
+ * @object: Object to be freed.
+ * @init: Whether to initialize the object.
+ *
+ * This function informs that a slab object has been freed and is not
+ * supposed to be accessed anymore, except for objects in
+ * SLAB_TYPESAFE_BY_RCU caches.
+ *
+ * For KASAN modes that have integrated memory initialization
+ * (kasan_has_integrated_init() == true), this function also initializes
+ * the object's memory. For other modes, the @init argument is ignored.
+ *
+ * This function might also take ownership of the object to quarantine it.
+ * When this happens, KASAN will defer freeing the object to a later
+ * stage and handle it internally until then. The return value indicates
+ * whether KASAN took ownership of the object.
+ *
+ * This function is intended only for use by the slab allocator.
+ *
+ * @Return true if KASAN took ownership of the object; false otherwise.
+ */
 static __always_inline bool kasan_slab_free(struct kmem_cache *s,
 						void *object, bool init)
 {
 	if (kasan_enabled())
-		return __kasan_slab_free(s, object, _RET_IP_, init);
+		return __kasan_slab_free(s, object, init);
 	return false;
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr)
 {
@@ -368,12 +410,18 @@ static inline void kasan_poison_new_object(struct kmem_cache *cache,
 					void *object) {}
 static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 				const void *object)
 {
 	return (void *)object;
 }
+
+static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
+{
+	return false;
+}
+
 static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
 {
 	return false;
 }
 static inline void kasan_kfree_large(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 85e7c6b4575c..f26bbc087b3b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -205,59 +205,65 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
 	object = set_tag(object, assign_tag(cache, object, true));
 
 	return (void *)object;
 }
 
-static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
-				      unsigned long ip, bool init)
+/* Returns true when freeing the object is not safe. */
+static bool check_slab_allocation(struct kmem_cache *cache, void *object,
+				  unsigned long ip)
 {
-	void *tagged_object;
-
-	if (!kasan_arch_is_ready())
-		return false;
+	void *tagged_object = object;
 
-	tagged_object = object;
 	object = kasan_reset_tag(object);
 
 	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) != object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
 	}
 
-	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
-		return false;
-
 	if (!kasan_byte_accessible(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_DOUBLE_FREE);
 		return true;
 	}
 
+	return false;
+}
+
+static inline void poison_slab_object(struct kmem_cache *cache, void *object,
+				      bool init)
+{
+	void *tagged_object = object;
+
+	object = kasan_reset_tag(object);
+
+	/* RCU slabs could be legally used after free within the RCU period. */
+	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+		return;
+
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
 	if (kasan_stack_collection_enabled())
 		kasan_save_free_info(cache, tagged_object);
+}
 
-	return false;
+bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
+				unsigned long ip)
+{
+	if (!kasan_arch_is_ready() || is_kfence_address(object))
+		return false;
+	return check_slab_allocation(cache, object, ip);
 }
 
-bool __kasan_slab_free(struct kmem_cache *cache, void *object,
-				unsigned long ip, bool init)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init)
 {
-	if (is_kfence_address(object))
+	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 
-	/*
-	 * If the object is buggy, do not let slab put the object onto the
-	 * freelist. The object will thus never be allocated again and its
-	 * metadata will never get released.
-	 */
-	if (poison_slab_object(cache, object, ip, init))
-		return true;
+	poison_slab_object(cache, object, init);
 
 	/*
 	 * If the object is put into quarantine, do not let slab put the object
 	 * onto the freelist for now. The object's metadata is kept until the
 	 * object gets evicted from quarantine.
 	 */
@@ -501,17 +507,22 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		if (check_page_allocation(ptr, ip))
 			return false;
 		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
 		return true;
 	}
 
-	if (is_kfence_address(ptr))
-		return false;
+	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
+		return true;
 
 	slab = folio_slab(folio);
-	return !poison_slab_object(slab->slab_cache, ptr, ip, false);
+
+	if (check_slab_allocation(slab->slab_cache, ptr, ip))
+		return false;
+
+	poison_slab_object(slab->slab_cache, ptr, false);
+	return true;
 }
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 {
 	struct slab *slab;
 	gfp_t flags = 0; /* Might be executing under a lock. */
diff --git a/mm/slub.c b/mm/slub.c
index 3520acaf9afa..0c98b6a2124f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2223,12 +2223,19 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
 	if (kfence_free(x))
 		return false;
 
+	/*
+	 * Give KASAN a chance to notice an invalid free operation before we
+	 * modify the object.
+	 */
+	if (kasan_slab_pre_free(s, x))
+		return false;
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_free and initialization memset's must be
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * The initialization memset's clear the object and the metadata,

-- 
2.46.0.76.ge559c4bf1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240808-kasan-tsbrcu-v7-1-0d0590c54ae6%40google.com.
