Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQWN52VAMGQE4KRUTMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id BD6237F1C75
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:43 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2c88814a48esf4789221fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505283; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nwo03xWYP2PS5qiGmH5cWgMJAvTsE6WxuzDkiOrdIJhC7SIOwgG3s58jnCdnRjciaf
         qq7LEQ+YdubZpiWrgodJAS0v7x2oafNuH3gseeS4ciRbh9RZcvlOrGDNJdVpoqmVTbFh
         y3juu0iBSe/4/cPsXM24u2z7qCCNtXuOPUIdfLqL6ShIQj4s2LBZqzKmVtklBb3oT1P/
         HZjSQwr2jy7CWwNqQlMYQp0hHrEvfWEJWgPdcWqDZQDGBy7oCeugqAxS+cNjg0LIEEil
         7IqO9z2dQnVOsh2+DgUSLQI5iUjW6dITY0LMfkZpUsyhh9jxBuJeQVPv6xQHiBnq7IpR
         pPGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=u+1hpyfg2yyvkllEdH+NtNgOB/ZRnQhT4wlr8V5Ltx0=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=TITZCD5Ep9XzdGRlDxH0/pA4s8i4NMhMOdo+4R4sb4JUGMuA3BHwxCkI0N6noiEzXU
         cbFMyTg5SZiLFcUZSVZbN1JygbxgfVueufGir3kZTWQT3jNQC4/nEn1XJpUhxKdhx5Q6
         YGNR1b9Y0DrH3y9Fblg+nYbecEQEVeVdE4VIch06+Ln3EcqeoS/T1+ggXVDHJja8UV6B
         jwS+hs0IttClrRm1YAIY+Z30ExGj+oYoszk07/DCC+JPi67AaNcCAkqzeGAM9vVVDaBm
         hr4Bb+N7UpiYXZBccjTKCPGiqdIhIvZtIYGrtvKchkMtWRhqTd3+OK2Yq6bCVCVQGkGc
         +LVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=A6pk4gEk;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505283; x=1701110083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u+1hpyfg2yyvkllEdH+NtNgOB/ZRnQhT4wlr8V5Ltx0=;
        b=eQsFSmVbyTgbrkzqyGEQ+Se9CGaS9tbFgkYZhYO+k0bX9/cu97+n5d3SXnJ2IID4XM
         SDrtXv+tOMYg4UW0cQzg7sdgXpK4kAaxx/rW6FQJzY7QllluRTSEzLXdxc6MqwLgCWhs
         if7Kgl71A+YyMt/cDi4z4WRLqarwnyxUQxoLlQVTOvXthnDTFYNzrZoeLcMCc8NZX0Gk
         gd+WMPzpIhjqglF2e1lCnF8+DMV032NMIbDMK7bi1y59XTtCYLsdQATuBBXdI2dbCJhb
         5TCLzAw3owBWDRgu+/UCVSHFjdPDvNsBAuXRjzfTgLLokif30kBFPSozirgmDI8/9zG4
         fO5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505283; x=1701110083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u+1hpyfg2yyvkllEdH+NtNgOB/ZRnQhT4wlr8V5Ltx0=;
        b=HhlOb8ixR/8Ku7SekyfnWWQhhuKaAGdFtrpe+JOVLvNw77JA+pDaxJAIj9RvcEr0Na
         dg3VzschpTDmbdcOsdYpJz++G3GIpkzXpoRBntkvEi7jXjmyx5taU9PYyOM1sxLQKwV4
         slmopwKD9LDIW/guCnJBUgbLfixa4ynYi6zJje32rkRDi9KwTIt4C9JlWpzf+tEYqh38
         ril3n5qihWTiuZ/7CmU43gF6sOsyf19te9djBo9FgQfSuwcNzX+vjCDucIJ4h8LFtQ/+
         B/oxxhNCfCKdWqaLp8rTBbQ01VKnqJuYY7qPMFfe/aQPvB0UbwAPs67Z5KBVlDyndSxn
         4NJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz8j4qDsNM8dr7zbgqzGUitPrjchiFSx+7Pcbx0L/MtBE96Lo8v
	5BgRb6Z7PjRFMpi9bTLhaIY=
X-Google-Smtp-Source: AGHT+IG/CLwRv7Orqave2tivBu4sllUT/MSuSlM0E0patd8yngN8Ywo+06Tu8F7fr5ScGkJpQew3oA==
X-Received: by 2002:a2e:9015:0:b0:2c8:3613:d071 with SMTP id h21-20020a2e9015000000b002c83613d071mr5656291ljg.36.1700505282827;
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c27:b0:409:5426:9d95 with SMTP id
 j39-20020a05600c1c2700b0040954269d95ls1014661wms.0.-pod-prod-04-eu; Mon, 20
 Nov 2023 10:34:41 -0800 (PST)
X-Received: by 2002:a05:600c:19cc:b0:3fe:dcd0:2e32 with SMTP id u12-20020a05600c19cc00b003fedcd02e32mr7145239wmq.19.1700505280942;
        Mon, 20 Nov 2023 10:34:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505280; cv=none;
        d=google.com; s=arc-20160816;
        b=thJpqYUdIVBNBOYlzuf4dVHqsM16h3otFLLqi7K5kaMMUbgol5XWsvmUm+BvjHXSzG
         x7GLYFnTi+z/V8e2wGx/njORVzxrOMigKN6FS6TlnfnR9KB868MRtBo2Tr5V1m8KiGsV
         Wx8jygFV9B9fzXsNi3cYFkVulgRdtS5OXoTcPLd1PVZHNGG+7yZNx6YMborkB8/OvShK
         3iS2MdUR7GaM7rA3pm2ypo5vYyVdz5Vzfqs52MrzXcayKZfkk+3pPbEkWREHiIBWBbvb
         jD8E9EdjyQaEQGKEAw+jwxhgyCbs685kA2snHymh4mx5PROrJnpvtYts46N4vKZZFFFC
         cQpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=vcj9xI8buQN1G/rc5/jIHh6rM1KaznuLIHKBfsphrRU=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=icDxvdWKjnMoNLI9tOH/V8l/UhmQK+DN1Sxx2VXwZ84jGA+nWBJ/Qoj9pR9uQnCq9v
         DJQZSllChx0XIY4KuKtRMfxEjIH7CmRJ2V2l5yRlsPq1QN/GDQJefdPw5HZw4aieJEHj
         531vbTtMwaHbZfrImdcMDbva4dpbSDeA1pyOChpkm/nqBVl6dZcmaBhv5N6iuRCI8HP4
         aeh+iXVRAGde6Hv8cioydEBT/p7btnVgVtZbPdFJfHHTqibmbekfv+yoeNIJm82tx+SS
         Z6lj8qnebXaGKUcNciq3kxFI3hEwkKEaUqNBRBWn0hn9/97UPncFtYFJ+u05/7QyUfHL
         r6dA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=A6pk4gEk;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id c6-20020a05600c0a4600b0040a441dd5e1si700332wmq.1.2023.11.20.10.34.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:40 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4693A21907;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 042B713499;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id OMF+AMCmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:40 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:14 +0100
Subject: [PATCH v2 03/21] KASAN: remove code paths guarded by CONFIG_SLAB
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: *
X-Spam-Score: 1.30
X-Spamd-Result: default: False [1.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 BAYES_SPAM(5.10)[100.00%];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=A6pk4gEk;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

With SLAB removed and SLUB the only remaining allocator, we can clean up
some code that was depending on the choice.

Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/kasan/common.c     | 13 ++-----------
 mm/kasan/kasan.h      |  3 +--
 mm/kasan/quarantine.c |  7 -------
 3 files changed, 3 insertions(+), 20 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 256930da578a..5d95219e69d7 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -153,10 +153,6 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
  * 2. A cache might be SLAB_TYPESAFE_BY_RCU, which means objects can be
  *    accessed after being freed. We preassign tags for objects in these
  *    caches as well.
- * 3. For SLAB allocator we can't preassign tags randomly since the freelist
- *    is stored as an array of indexes instead of a linked list. Assign tags
- *    based on objects indexes, so that objects that are next to each other
- *    get different tags.
  */
 static inline u8 assign_tag(struct kmem_cache *cache,
 					const void *object, bool init)
@@ -171,17 +167,12 @@ static inline u8 assign_tag(struct kmem_cache *cache,
 	if (!cache->ctor && !(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return init ? KASAN_TAG_KERNEL : kasan_random_tag();
 
-	/* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
-#ifdef CONFIG_SLAB
-	/* For SLAB assign tags based on the object index in the freelist. */
-	return (u8)obj_to_index(cache, virt_to_slab(object), (void *)object);
-#else
 	/*
-	 * For SLUB assign a random tag during slab creation, otherwise reuse
+	 * For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU,
+	 * assign a random tag during slab creation, otherwise reuse
 	 * the already assigned tag.
 	 */
 	return init ? kasan_random_tag() : get_tag(object);
-#endif
 }
 
 void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8b06bab5c406..eef50233640a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -373,8 +373,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object);
 
-#if defined(CONFIG_KASAN_GENERIC) && \
-	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
+#ifdef CONFIG_KASAN_GENERIC
 bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
 void kasan_quarantine_reduce(void);
 void kasan_quarantine_remove_cache(struct kmem_cache *cache);
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index ca4529156735..138c57b836f2 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -144,10 +144,6 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 {
 	void *object = qlink_to_object(qlink, cache);
 	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
-	unsigned long flags;
-
-	if (IS_ENABLED(CONFIG_SLAB))
-		local_irq_save(flags);
 
 	/*
 	 * If init_on_free is enabled and KASAN's free metadata is stored in
@@ -166,9 +162,6 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
 
 	___cache_free(cache, object, _THIS_IP_);
-
-	if (IS_ENABLED(CONFIG_SLAB))
-		local_irq_restore(flags);
 }
 
 static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-3-9c9c70177183%40suse.cz.
