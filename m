Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSUT3P4QKGQEO2STCHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id CA9B7244DE0
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:42 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id j2sf3610994wrr.14
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426122; cv=pass;
        d=google.com; s=arc-20160816;
        b=BXr535LO/Zsfaq/RbMvRfStpg6eZ/R8JwyzX6yvqPs/C/TaV26tcJz5hWGJZLegBC8
         qRrgmBUikaIvXCAdFiPFopybJFnDOIeHdN8ynTA+X+TUXTKXE9PkzApqgATdYGPFbXRt
         8wAw+CZAOqZqFfP8OSvttYMJRpfnRjv+VY79gf19vX2Z5o5ghL0S2EGyAldPzAGY6lpx
         eOAUqodzYC193Xl0bhuLsWwv0We83KpQYl5KIZW1bkRJHKvHU3McSO5z7YS81U8q0sWJ
         ETkPiHRt/c1ENecFKbFdHXjvBrwWopE0wrheE3obd9x5WLWq2f29VkKpcWhygwXfz/Gq
         OYug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=+1wuw/GkrSVjsFmBELBuobKsrddT1yJ5tWd1q2ViwuY=;
        b=NZ7LhvlRMUZ9gobaVg3OyBJeTlXu0TOlXXwv6TaoQ9OeOBZewAnmRele004t06Ap+4
         SxbBTeK+vaoYuJIk9M3ekQiqkUTngHwyB07E5M8PQLyLGv+iD0yGTMMNu0UCW1K/TBbR
         ICKwvDjhB1KUQZr6tjiOph/8vpDUI75aXefhu/4WnhCJX5dsQyXa+v9BgqSIgGzXRLxw
         I+AVUysvqdn/KSi0zvNo/z93tsmVzv3LEz3YSRhbgZtEQJUGpgf+TI6ut78pDby4fNqS
         dxe+63U4KYgqlI5uaOCNzri7PvzOD+ZI1DW2ZTJqI3oJVth60u2ghlGn1FzQSe7TcXQR
         cDVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I7BFJRn9;
       spf=pass (google.com: domain of 3yck2xwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yck2XwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+1wuw/GkrSVjsFmBELBuobKsrddT1yJ5tWd1q2ViwuY=;
        b=axDmlS7fW6nRDACYBJjfBiC7MbY3RtQF9DyR1dZlVam7k6YJD7+BG0WTY53afAq5h2
         Sn0cjyBanej6IuMKrgMykIgOFZmSQ0QMKqgOeUmPeKXZqz5Z8InlUt+7+E3Jpsxnquxy
         yqWsZ+UWAY/sF07O/r62VajCyO01BcEnmwJKNFb11OFysRkZ6em51u+WDZRMiAbuGrl6
         80wLMZ9pzfI0vBJU+NZriZShpURXd9VFKs+v+t3Tr7LPqFXX74lX33REtWjXSiGBgh0B
         juZ7RKXyQRnXa+hLfOEZVcZmUtslK2H6H0JOj+MtcqG0GE46AjjcqFcAhDNJAeFB295g
         xxJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+1wuw/GkrSVjsFmBELBuobKsrddT1yJ5tWd1q2ViwuY=;
        b=fNCECX0SAMyKDWPzOqoW0ZgJFAOw46wY8S9qBX8GYxrzcIxNZPwyNMYPm72dNWKsfe
         AAuQfExMwBtQ4oNQKHuPApyuWbWEGMAG8CFQXvYQkuU1hegnqw+7h0/9H2p4TxlidaHS
         IHurqPCJxMob3eP5az6JSYHmt7YOtCj9OTazHQTA4aRZ017m0YPDpsuzfxKZ7dgfvIi2
         3FNAS0jG4F2fvJVYmjuVC6klKMtQPidEHZpP+8FQknYYitIHfcghmKEBuRwu0mMs9QTm
         b3AfpwCex80F9LeNno4kkxDMWszLWWn3lsSFPcgKKKdd+t/u0ixHP4IcAVUHF4kKCWwb
         0gfA==
X-Gm-Message-State: AOAM533ko83/IOHISChZ9zu/rYOZIb97jbbH84AxR/rjd2aannnCLGyy
	dKNzilbZ9xVB3+EHb3GauD0=
X-Google-Smtp-Source: ABdhPJxp7dvooahWLLthlSOs/pYRriw4VHWRL8emjhAfae6kk+YLWcxSvWWbmP57moVCpVxSL7tuCQ==
X-Received: by 2002:a1c:4844:: with SMTP id v65mr3491242wma.149.1597426122577;
        Fri, 14 Aug 2020 10:28:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fa8e:: with SMTP id h14ls710374wrr.0.gmail; Fri, 14 Aug
 2020 10:28:42 -0700 (PDT)
X-Received: by 2002:adf:dc83:: with SMTP id r3mr3876958wrj.172.1597426122058;
        Fri, 14 Aug 2020 10:28:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426122; cv=none;
        d=google.com; s=arc-20160816;
        b=v/CqoSckdXFhzw5seK5jbGX8QMHkedZNBBGa/KG5W/3n+QLKLv7iyVWX5xYocqjJT5
         e+31iCgymhpLE3D8siK3AD4qXen2jpN5iYHa2WkS6tmglBRfruTC83hYVpBwgAXlqeAG
         mNu0IKumXhGpHNPf6SnhvekHkj2jo7LtsEuh/bhF1x75y9JNvaNVFcgRgmu/X8yD64BT
         IPPRg/mOt2c8FhnUYgnY7pjWknD7nDR3UVeyyGfScRKjSR8nY9FjNxHME2IIH4Qpeg0d
         t8vJXehiGxLvmusyuodN2lOF30mZ4vUhcSxlm0ATLlWASItte1hedkVOUl2Ee+KR9rrV
         RKCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=kJlHQlyHf1HvTYFCcN+LwDe0IIk6i9RqNd5dGciZ6Z0=;
        b=Usz342Ju1EGQ4p832MWM6qt95kZZRO+/aZyJPV1+bFnYoVn+KY7ateL8hQqt6dxZTT
         BZG+DwTPC7c0WLkaHO/oI2xvAgI7WN/gmTHCSkdMsA7lXhlWNbVpvPiU2LRxuk2S9F4O
         P2AsI5TdhDgWDVGGbq1v/Ovtd90zpw9xuZKFgGM6djmKTk/Dq9nAfOTOExv9zb5/m/0F
         yA/Xcaja8kT81cCI7XJGs2KAzPqa9vWac4oPvWeKmHtuFlMMrXJ+HH+3+R8bpNfDDboJ
         S2n6M+fzlxfeyMuxPu2+Kul00tTJz7BZA2TonHmxP3ZjVKjp6gK2NNcQeAhA9hngFKDC
         L0rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I7BFJRn9;
       spf=pass (google.com: domain of 3yck2xwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yck2XwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id m3si496533wme.0.2020.08.14.10.28.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yck2xwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id 5so3572989wrc.17
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:42 -0700 (PDT)
X-Received: by 2002:a1c:2e4e:: with SMTP id u75mr3382777wmu.134.1597426121790;
 Fri, 14 Aug 2020 10:28:41 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:15 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <8384a6b24203b5719ef4f3a0339f740ad3299e9c.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 33/35] kasan, slub: reset tags when accessing metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I7BFJRn9;       spf=pass
 (google.com: domain of 3yck2xwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yck2XwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
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

SLUB allocator accesses metadata for slab objects, that may lie
out-of-bounds of the object itself, or be accessed when an object is freed.
Handle this for Hardware tag-based KASAN by resetting tags when accessing
metadata.

Hardware tag-based KASAN doesn't rely on metadata_access_disable/enable(),
and therefore requires resetting tags in the sections of code guarded
by those annotations.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_poison.c |  2 +-
 mm/slub.c        | 25 ++++++++++++++-----------
 2 files changed, 15 insertions(+), 12 deletions(-)

diff --git a/mm/page_poison.c b/mm/page_poison.c
index 34b9181ee5d1..d90d342a391f 100644
--- a/mm/page_poison.c
+++ b/mm/page_poison.c
@@ -43,7 +43,7 @@ static void poison_page(struct page *page)
 
 	/* KASAN still think the page is in-use, so skip it. */
 	kasan_disable_current();
-	memset(addr, PAGE_POISON, PAGE_SIZE);
+	memset(kasan_reset_tag(addr), PAGE_POISON, PAGE_SIZE);
 	kasan_enable_current();
 	kunmap_atomic(addr);
 }
diff --git a/mm/slub.c b/mm/slub.c
index ef303070d175..a786e1cee095 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -249,7 +249,7 @@ static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
 {
 #ifdef CONFIG_SLAB_FREELIST_HARDENED
 	/*
-	 * When CONFIG_KASAN_SW_TAGS is enabled, ptr_addr might be tagged.
+	 * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tagged.
 	 * Normally, this doesn't cause any issues, as both set_freepointer()
 	 * and get_freepointer() are called with a pointer with the same tag.
 	 * However, there are some issues with CONFIG_SLUB_DEBUG code. For
@@ -275,6 +275,7 @@ static inline void *freelist_dereference(const struct kmem_cache *s,
 
 static inline void *get_freepointer(struct kmem_cache *s, void *object)
 {
+	object = kasan_reset_tag(object);
 	return freelist_dereference(s, object + s->offset);
 }
 
@@ -304,6 +305,7 @@ static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
 	BUG_ON(object == fp); /* naive detection of double free or corruption */
 #endif
 
+	freeptr_addr = (unsigned long)kasan_reset_tag((void *)freeptr_addr);
 	*(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
 }
 
@@ -546,8 +548,8 @@ static void print_section(char *level, char *text, u8 *addr,
 			  unsigned int length)
 {
 	metadata_access_enable();
-	print_hex_dump(level, text, DUMP_PREFIX_ADDRESS, 16, 1, addr,
-			length, 1);
+	print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
+			16, 1, addr, length, 1);
 	metadata_access_disable();
 }
 
@@ -578,7 +580,7 @@ static struct track *get_track(struct kmem_cache *s, void *object,
 
 	p = object + get_info_end(s);
 
-	return p + alloc;
+	return kasan_reset_tag(p + alloc);
 }
 
 static void set_track(struct kmem_cache *s, void *object,
@@ -591,7 +593,8 @@ static void set_track(struct kmem_cache *s, void *object,
 		unsigned int nr_entries;
 
 		metadata_access_enable();
-		nr_entries = stack_trace_save(p->addrs, TRACK_ADDRS_COUNT, 3);
+		nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
+						TRACK_ADDRS_COUNT, 3);
 		metadata_access_disable();
 
 		if (nr_entries < TRACK_ADDRS_COUNT)
@@ -755,7 +758,7 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct page *page,
 
 static void init_object(struct kmem_cache *s, void *object, u8 val)
 {
-	u8 *p = object;
+	u8 *p = kasan_reset_tag(object);
 
 	if (s->flags & SLAB_RED_ZONE)
 		memset(p - s->red_left_pad, val, s->red_left_pad);
@@ -785,7 +788,7 @@ static int check_bytes_and_report(struct kmem_cache *s, struct page *page,
 	u8 *addr = page_address(page);
 
 	metadata_access_enable();
-	fault = memchr_inv(start, value, bytes);
+	fault = memchr_inv(kasan_reset_tag(start), value, bytes);
 	metadata_access_disable();
 	if (!fault)
 		return 1;
@@ -881,7 +884,7 @@ static int slab_pad_check(struct kmem_cache *s, struct page *page)
 
 	pad = end - remainder;
 	metadata_access_enable();
-	fault = memchr_inv(pad, POISON_INUSE, remainder);
+	fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
 	metadata_access_disable();
 	if (!fault)
 		return 1;
@@ -1126,7 +1129,7 @@ void setup_page_debug(struct kmem_cache *s, struct page *page, void *addr)
 		return;
 
 	metadata_access_enable();
-	memset(addr, POISON_INUSE, page_size(page));
+	memset(kasan_reset_tag(addr), POISON_INUSE, page_size(page));
 	metadata_access_disable();
 }
 
@@ -2816,10 +2819,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 		stat(s, ALLOC_FASTPATH);
 	}
 
-	maybe_wipe_obj_freeptr(s, object);
+	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
 
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
-		memset(object, 0, s->object_size);
+		memset(kasan_reset_tag(object), 0, s->object_size);
 
 	slab_post_alloc_hook(s, gfpflags, 1, &object);
 
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8384a6b24203b5719ef4f3a0339f740ad3299e9c.1597425745.git.andreyknvl%40google.com.
