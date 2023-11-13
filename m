Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBHLZGVAMGQETC5UOEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B7347EA361
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:14 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5079b9407aesf1116e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902853; cv=pass;
        d=google.com; s=arc-20160816;
        b=s1QTUxcT6DLvWYnaczus1uDGAm/UvqVbA0sCn5Kqq4Wm7IrPWL6/beQeCciYaU1LVO
         BiBjEM9BE6v6IxbUa2fe3i9M0/OsgEUYS7W43NB2heOUy7vrCUEI9NTSr35JknUZ4H8E
         D/b/7nr/9flysUEvl/ohBH8/wTzsVcYJiTmrcha6Z4PnwD+x/F0Eymtx/S0kUaU9MmtC
         Q3da1KX6nbJASadUABVaJMPzeN1Y2vkVfFn0RlbiU8bGPKLIq4Lr33Rh78pDkOvUMSjP
         dbt3pAqJ55wYzcFDgnhtm4ZDqPgWniZm5kAILsrV6DJuc8/Owr/LmxFiwh5myiUbZRtr
         aJ+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=656Yol7sdK80wysCA3fpYM01rs6fM1rR9xpVfpZsRRA=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=F5hkMKtrCaDjlo7W44vU8FQ8s8dt/2qDenAdRGcQtWKkDCFs1GvSuSDpO2S5lcetVA
         iQhmToodl313tnmGPM9VdfEL+p3vuO4ZbaMi/V6i3yYav5Bl/OzmASg9GDYlOuFXafaL
         ODOHoAr9GvDEBFt84vlQSyspv2o1oTUBKpIw2bGT0CTM/JsXue56jeu/JzW6R1n/eAbw
         B1Njxvn2Vk/T+cwAPsgcNr/Eze1RSzDTOib3Mo8BDBZ3D+OFFzamdxrjJN3qWuBUOhEn
         Guy5NraNmIO/l0StetTJyXPYKMARaSUs3G8Rm6JmtTJAzkuA1Db7K5CQk/mIeMGZzcjU
         5ZMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=X7VVhHyL;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902853; x=1700507653; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=656Yol7sdK80wysCA3fpYM01rs6fM1rR9xpVfpZsRRA=;
        b=u9FFN9Ir+sMWI8HFdDBvVj8swMRTXBm4j8MgpcXHtFnul5Wdkp7qi8u3iiMNKCs4mW
         +ELzYswt7LRD2P/KIfj4HnkaZUetXgoJc0PbhQL6ML2MnVuo03z7UKCLR+NVOE/bgNFQ
         zocJX4UAoPh75+uUGqAxUTEWZZX6U9F9ssBoGssQIM1sTnZrp0dKJBcYtmQ3uHHCu6/Y
         ukwK5xsVoHv47mVyk1t1MZlUC7KRvk3LrwSXno66oU1YjVu9vHSks2rf9jOzv6DEMv+Q
         q/smV0CEkjenpPevZNbaxdV2H1x8uhnlKoQ61SclK37Fy8kgKJmjZPzWB8uR++lz0PnY
         azFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902853; x=1700507653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=656Yol7sdK80wysCA3fpYM01rs6fM1rR9xpVfpZsRRA=;
        b=AVWm8nL/exyfE2/L/GB7Su5PH104k4w7GEcjh/NOhjQlfdZmD1dyuAQeiO4w36F/p1
         W0382nLhW2cAdF+nMI5Q6sRFxjCSyVsXnlL/RzIJCkZckqYVFoXEcgjUmAlYmWZnu4o1
         cma68K+jOS5y1EXLoWLpFOmEJvb4nbOiZmLTfrX5YPZVbt4Ml/bjM35zJxktK+CmDief
         febmtasxBzNaYFhrkQU9x1eKf3mji14FQ/ctxDEQZ9Zmf5P72oty/1gkkHcT4bendNw3
         Zkt3e22L5Z1NiVZMK4h4dnKH/c2pru6VhOsiAd87rGyCHmTJiQCu4PlcwOXqGlmAdg+3
         PwwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzDnsugQi+umqcjnXl0KHoMXxX18ZdBdaIEfYSo3e09pbd/pTuS
	9bYIzYn6ogOp5PHUxBIX4nk=
X-Google-Smtp-Source: AGHT+IF9qHtGGjcEXstLWk4mm6CRXAMeuvBWxAI6ZU8+pTSJ5WTMvibuWHamhc+juUlYSGqLUJk62A==
X-Received: by 2002:a05:6512:3d20:b0:509:48d1:698b with SMTP id d32-20020a0565123d2000b0050948d1698bmr17685lfv.4.1699902852601;
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1308:b0:507:cf9c:aa7e with SMTP id
 x8-20020a056512130800b00507cf9caa7els162658lfu.1.-pod-prod-07-eu; Mon, 13 Nov
 2023 11:14:11 -0800 (PST)
X-Received: by 2002:a05:6512:1047:b0:50a:760f:dd29 with SMTP id c7-20020a056512104700b0050a760fdd29mr5278660lfb.66.1699902850640;
        Mon, 13 Nov 2023 11:14:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902850; cv=none;
        d=google.com; s=arc-20160816;
        b=ZFdEJU83eve6KPJv1r/CxDfGMhTQUgBQ067HdARJ2GA5Ry1sdxSIDhSNpcHoXBThvU
         +yRxyKvmP8yVNS4VG7D7SF9B5J9GboiWD370dTEgtNSaP0nj946KtzXcfs2EY/Wap/rd
         vESW7KkIL6MWdIqV+LUkgBooBpfkebteVF+2a9bbjEceQlMfNBKSCUylVTKHgAZJp0jd
         5jf67pHvK5JMH79a8QZr7Ff6CkI0eFZXr3a7s9D6kAGOkF5BSQ00ehzXeChiZHbUtBRQ
         UxJHneb4Bv/zllBS1zZPLh/AnDMgARW33gB200ThbXVVw9EynRnmHif/k6HaByTsnULz
         vv1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=sRrsgxJwat5NXRr1zzXEwT9soXXRRzcekV8Be8tRJ7Y=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=zsGDTqml1tPxtCFGMt7reTrVxbngPQNU4IQf42kN/XVhLhnM8bXy+jDfPsPpELen7g
         VAvf691fENWYmq1wT83JeNQCvuJlTuLuZvKLSopujDf3V/mOPzqm2xa+fHwDTAQGUSjt
         F4FJm7Dj9Bz54S/SS96ZumLx3AK5lM2wHgQ6VXg5JaJujKg4K62UfJBKnrkjteFepULt
         7OJoiMydLf30h1AwpwSgHNuO89H/oLN1Kl2+Lzo0XxDlMjga6ftgdGwGxfUnpoRVr/Rz
         7VHRVqaNx0ei2q7C/ioVBvglslsgYzXnfHEVYGHcyq5jE14pr746SmtDtOan0ikQhQZl
         ImYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=X7VVhHyL;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id c18-20020a056512239200b0050a72e696casi192096lfv.6.2023.11.13.11.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0504B21906;
	Mon, 13 Nov 2023 19:14:10 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id A64FA13398;
	Mon, 13 Nov 2023 19:14:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 6DkBKIF1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 02/20] KASAN: remove code paths guarded by CONFIG_SLAB
Date: Mon, 13 Nov 2023 20:13:43 +0100
Message-ID: <20231113191340.17482-24-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=X7VVhHyL;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

With SLAB removed and SLUB the only remaining allocator, we can clean up
some code that was depending on the choice.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-24-vbabka%40suse.cz.
