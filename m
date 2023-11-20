Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRWN52VAMGQEZMRTXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 48F467F1C88
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:47 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-509901ca83esf5455478e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505286; cv=pass;
        d=google.com; s=arc-20160816;
        b=HdA36X0vMDDZzrplfqPXdno4BSpefJIstQhZzAY5qEeHJF5o7K+VRwM89y/DX2Y3JW
         MqtQ3B6PDxr2F0Y+lLxecIK4KCiPMjezVRgAgPiYCm3umxIpo1xPhe+RbHtshGYg3NkX
         8ppM4Se8/1fqiyR0bdZZjWqPB66ccoTtIqdLzybuE+rmll56D/YMDq3BM+nA4FTYcT3E
         tVrMRnjVWLyhjFZl9b6GggyQYzbAUyfbHl6KW3y593ZFdleNKRHLrscJqKpEYPAMjC0X
         5CPsg5sU6WUZ9fCVOvmkPBfUuMtYiW6eRyFJO2FfurDo9zPtBkke5DLkCq443EhcuyEN
         7cNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=DSfpWzvd2hEwgEVC19rH6zTT0xzsFco3v4l6CS4wOOw=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=Xs4KoS6sETS0YwRxTTJifixERstuYeIZV9TALCyxeipfTsJ+h2gFDalGPO11OLDEGQ
         ItlQeIj+KCwuVWUwFZAxmMmtudb9FKUadyvGHIpzMFI/XpoWzlELkQaodaw4iH/Lucoh
         GTT1juOsre64OCzVYoGQ0X9GyoELYZ5Og8qiu1emuNEg1qP4z361Tyx/+5FIyQd4YN0b
         2DuI22SHR73UlubMFpakB0ELgz/Ct5gHZy40V5PdTTXy8ljvGCbTwQTUfGhKzea1rwIx
         W0/dtIyK+n2s9CKLPBlYnZQu3cPFFJ6yTse1H9WDSz4ufOY5D9rl0qpsbhZTe/ph7wOd
         8Naw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lMWFwPye;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=2WYXGeth;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505286; x=1701110086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DSfpWzvd2hEwgEVC19rH6zTT0xzsFco3v4l6CS4wOOw=;
        b=lD83qQ6CIbBWw4xVEEiBbQLadGAsKndSp59vlg92d6QlerH9U1hOAbP69qb5vNn48f
         5Qwj/5t9pU8cwWuwOxUGQSkKS3jq0yrRSY2NfO9PJrfh/GUvz0UFyTABCIbvMZOKkNbb
         tbeaJkV0W8DU4FC5FH2/AZtcZ9CLt3O8GSvHRUOEV0ImoO6lidyRjNZpPjhYpZuAXlbG
         Sk/kIB8jQ9+9k3iIgJyCZ52YSsgCceAJEvh5pCLX9/RVf0mKV663u/pOu4I4PGO95ZDS
         ujcM6DEj2Iwfxd8ZkColGqweHNuC74NGfrlQsSJroR+2VcB+7FUxmNt/ig6pys0BOt3U
         SKWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505286; x=1701110086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DSfpWzvd2hEwgEVC19rH6zTT0xzsFco3v4l6CS4wOOw=;
        b=XdFp3akq35STinjWZG5TVQLOJJ6NGDsrdoy7ftff7HNkzvFqsvZoBqUn7H1P+XumCF
         7UCGh2Hia6zzFVKKq2EJShH24VRKkui8fZusk40r/QFU6QRFYfeh/B4wa5qanOiVyBka
         NpzAQTIXV3D7cZTV6jSoFnN/wFnkKJ9tzEGIit9rbziDyVYMH9NU/Up5slLKyP3nyNv7
         O4lO6oI87AygKMpKnbFRvQa1B4MyAzQxeU2kfPneS7O1QG1QuT7uqLAW48wTK/4LC0/1
         +7fofq7dkyTZyyYUJrduf/9rINN1SU6vWfaGqWn0dTF+Vn8lYZamNBrR3hwheZUrqeOW
         qvJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzIIH/pwvVnJp1dBps+W8ZZvrxvy53sB1FgBRQcqOSLnzxOe3O5
	iHQdI1PF/2Gmc7lgWVcy3Fk=
X-Google-Smtp-Source: AGHT+IF8b68NOkkQUtR+0wd0h+Ul+mW7YjZW+l/5NJIxdCAEySiC6UB8ooPRAvaUT8Tb7ZxvtuFBog==
X-Received: by 2002:ac2:5e81:0:b0:507:9996:f62b with SMTP id b1-20020ac25e81000000b005079996f62bmr6031717lfq.56.1700505286627;
        Mon, 20 Nov 2023 10:34:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1295:b0:50a:a571:5cda with SMTP id
 u21-20020a056512129500b0050aa5715cdals108190lfs.2.-pod-prod-02-eu; Mon, 20
 Nov 2023 10:34:45 -0800 (PST)
X-Received: by 2002:a2e:90c4:0:b0:2c7:b9b3:4ec1 with SMTP id o4-20020a2e90c4000000b002c7b9b34ec1mr5038001ljg.17.1700505284690;
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505284; cv=none;
        d=google.com; s=arc-20160816;
        b=PobqcNrAygB2J0BUX5X36nlIjMEsZ6OIpTP8KAbRtkN2ftsMopkl5e4dBVB1olCXYy
         QWesTrLkrSkrtTu3EfT19CuLuBfOfze6fwVci4Q/25byssb3ePH06AXN+cMvTpfK4pPJ
         ii542EO5IS+uFsKVx/eDQi8gw+DY+fURqzgF9xCDjrZT5PHBIrBnzWYy1sGZmKIpK0za
         OOMzMZ2sE4n3CenXFQulAyAgajOIu6xxXphPSaHPRyOE7JgPsZP0UySIhj0Ocu8WLgzI
         +al3uMnKCxQr1UiuSveFmTSi6Rx2hh61CTXXHJ/mEtAeEY1pBx885ooXP7RvWt/vqQoh
         3RzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=66Fcft8CxLuyGHKa/ns5P/AtbVP/SvETjQ6dsoMJ/dY=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=zk/wcmpBF7UejXK27D88qUCG/SamDWPJ8B2xqb8fo6sTDUk/b26FxjgdQzF8Kp9CYY
         a6vlPeVc8nH5mEv1QwW2FarJQlvlB+xj5hxOQ54zKJ5IqQoH+T6T7KrfTYUFyGo+AR5u
         47PJOgCCXkNr5V+LNV/Vl//9hRGFLPmJJJSoY8GSLYN/uXZPtUx7Cx0jC/e6vvf+qVgK
         JNrVpr9FJ15YxrjtBOjXxGrYk4hP/3/V7iU22Ts+T6MKu7Ch72b7gBzCqlPPUQA4AFO4
         u355RH2VuFFfDxtlFcnK2aiT8DpWQp2Qv//RL9j/uMCE6vH7UaQv74FbR+5tyzmON37A
         ejrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lMWFwPye;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=2WYXGeth;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id e16-20020a05651c151000b002c820f71e0bsi77182ljf.5.2023.11.20.10.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 150A71F8AB;
	Mon, 20 Nov 2023 18:34:44 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id C8DFC13912;
	Mon, 20 Nov 2023 18:34:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ULBvMMOmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:43 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:30 +0100
Subject: [PATCH v2 19/21] mm/slub: remove slab_alloc() and
 __kmem_cache_alloc_lru() wrappers
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-19-9c9c70177183@suse.cz>
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
 header.i=@suse.cz header.s=susede2_rsa header.b=lMWFwPye;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=2WYXGeth;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

slab_alloc() is a thin wrapper around slab_alloc_node() with only one
caller.  Replace with direct call of slab_alloc_node().
__kmem_cache_alloc_lru() itself is a thin wrapper with two callers,
so replace it with direct calls of slab_alloc_node() and
trace_kmem_cache_alloc().

This also makes sure _RET_IP_ has always the expected value and not
depending on inlining decisions.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 25 +++++++++----------------
 1 file changed, 9 insertions(+), 16 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d6bc15929d22..5683f1d02e4f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3821,33 +3821,26 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
 	return object;
 }
 
-static __fastpath_inline void *slab_alloc(struct kmem_cache *s, struct list_lru *lru,
-		gfp_t gfpflags, unsigned long addr, size_t orig_size)
-{
-	return slab_alloc_node(s, lru, gfpflags, NUMA_NO_NODE, addr, orig_size);
-}
-
-static __fastpath_inline
-void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
-			     gfp_t gfpflags)
+void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
 {
-	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
+	void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE, _RET_IP_,
+				    s->object_size);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
 
 	return ret;
 }
-
-void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
-{
-	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
-}
 EXPORT_SYMBOL(kmem_cache_alloc);
 
 void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 			   gfp_t gfpflags)
 {
-	return __kmem_cache_alloc_lru(s, lru, gfpflags);
+	void *ret = slab_alloc_node(s, lru, gfpflags, NUMA_NO_NODE, _RET_IP_,
+				    s->object_size);
+
+	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
+
+	return ret;
 }
 EXPORT_SYMBOL(kmem_cache_alloc_lru);
 

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-19-9c9c70177183%40suse.cz.
