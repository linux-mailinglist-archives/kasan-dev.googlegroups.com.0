Return-Path: <kasan-dev+bncBAABBYEVTSVQMGQERZN5UVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9725A7FD35D
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:50 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-285a20a12cfsf6385545a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251809; cv=pass;
        d=google.com; s=arc-20160816;
        b=mqY9cCwTtuLUhRaIw1zET/C9naxxp2pVs1OcnOMzhKWPheEB4Pj9RkwCDclqEaWEfZ
         PCeaX2NkZiZamxwKvwtu8/XNF2npiwDGQDAqNuNTRzKI7LdZvt1RtLH76IrbiiqxUN/8
         d/0MmB49woAK8nZvpPQQgHGHTA0Q1SjM3aT504ZdUWxZrUz9pYbb/TKkTErE80WqnGbQ
         lXfBAEm9qgtTLkqWsSmpQ0LvCNuSzZab6hsBb7NzaaKnikoSEUM0dlg6HtM81pCQO7ER
         HVeLc7rAeVMn/eNCaRvvFaX9X2UagF6dwjCT+jPzzu/nWhZ18RJ02enBaSbNsSUATi+M
         yPCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=LEk/daCW8KnGpxJ5cHy/uhXO3HzavkjBEJXl/+dDtac=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=cGX7waC58wXnq8sy5w4bzkM9ZtHpWIrmycyXHKMA7yol6FrkCD8WWqOB1pmoc7dVpQ
         I/gUE66aYYmWP5UrJPGz6pf5sfhuMpWOHkLn0VSmjtPstl0Un/sKgrYe9rE4A/aTtGB9
         mzaIw9+5ngKITlkIsIWS9cv8At80wDPUl5k+9VpzVZ1p4OrP/bYDfgtylDwy6v40aLxd
         SKBvW/KpGouMYQgXNZkxtiVAwAQhBKesOn3tQyFfBXV4lcNAKxTmJS1iYeDhtZwgAmlG
         SjQU+anzLGElSahYlD2zWMmzsWAzgJzJR5MeGFN/WulXnRvh/+8rpZ3YgCgOqOub7vXx
         fVRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251809; x=1701856609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LEk/daCW8KnGpxJ5cHy/uhXO3HzavkjBEJXl/+dDtac=;
        b=Vvr0mWBA63cHeu9Hzz7wvTChkwFGRlbsrCAV+VUG9TX1xewQH/4wmmU1x+hHDCtkOU
         5FzjjciYkk+bUYuMJlbObQsPcIVry6c7685cMFOL5RbogaGWRGHgBuDkHuNrUZwJgEPF
         7otiWT8vEGQxOULORPHAmjUEbs7B/+xFg4u+eIGHKMyQxPAoFiAYrI8LjNE5lRT+N+W6
         4IR+henEft70j0DmfilYa2UIV76KfPj6rXhT8zdI8guqcwHVpyB4OGSx14+UiliiWC1L
         jNaxrLKSroOzTWcV6MdS9SYJB9LSXQXpEuFtGqzufte6rXH3JXa/u4ImXuB64TYiXo+r
         h0VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251809; x=1701856609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LEk/daCW8KnGpxJ5cHy/uhXO3HzavkjBEJXl/+dDtac=;
        b=JeaZlR+hchBo/VNEVuPkBHO4BC2lJv5eu1CnXmyh2QmZfcAFvZXbyrJnljHQD/ZFsu
         q48d7YSPekxWOqyY7H1F6zxqtS/w+S4IbmEmQ6zxyL5Cujw63OPsYQkT/NnH8DkSDrpK
         wyNw4fhlxnGM2pYwvqWso459Z/ca0wM+7Wdsv3xhSCYqmioM/1yhHuZVB0lmYP0ujn9a
         rHO7azRp5xQXHNAWnQg1uTn6AFMQV4Luq1WkPMtYShiWlMAH8Rc6t/apXiwYptccxz6v
         pm7P/cJfagFlRyaOJT542rH6oeY1eMFxLkLjdXIU1RCaaPDXhyhz3d/r//q2/Vw4t0M5
         ipjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxdE8E/ZUmLZBUzdgREg1rok59SkRtHE5W99tDhEtBH+wPECvSA
	lrU7kjKKnOuq3qw+VIiQNfo=
X-Google-Smtp-Source: AGHT+IEWUFfVc2CpTSZbZhgJjuX2BoAS4ez3vydpKEZ68E5YSWAV/mVTX1juKbetDT7HHMyH8Fu1bQ==
X-Received: by 2002:a17:90b:314a:b0:285:ada5:94e with SMTP id ip10-20020a17090b314a00b00285ada5094emr13673590pjb.32.1701251808873;
        Wed, 29 Nov 2023 01:56:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c293:b0:280:878:8539 with SMTP id
 f19-20020a17090ac29300b0028008788539ls52633pjt.2.-pod-prod-07-us; Wed, 29 Nov
 2023 01:56:48 -0800 (PST)
X-Received: by 2002:a17:90b:190a:b0:280:990b:3c29 with SMTP id mp10-20020a17090b190a00b00280990b3c29mr3630991pjb.1.1701251808272;
        Wed, 29 Nov 2023 01:56:48 -0800 (PST)
Received: by 2002:a05:620a:191d:b0:77b:cc25:607f with SMTP id af79cd13be357-77d63f5307cms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:a2e:a58d:0:b0:2c9:99ca:1317 with SMTP id m13-20020a2ea58d000000b002c999ca1317mr8018843ljp.24.1701251618767;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=GuyxKt4yvsmjplmoOWKwHyEnS2vqkHpNQdOKEZmPa4UgJ+R1I0lQLNbsSL3Ws9zSER
         rpAovodQDIXmXxItn3G7BkeBODp9Hnu3SXKtc6H2JduxkxG3h6cYb7fOWA/5mXhEEDBC
         MtuKSEo/VAlTPU866tPuoXWCjbkXvxOJcrnBfgNcIP7Xsbq06lIp1A3Anuyz4ATs/1l6
         /XWnyTOo01SwRAC/kfsEeAILRQ/UxHRVvIryN4yurwqIlOfRhqEyW183kxUpY8iOYXQf
         vkrFsBPEDq6QZZ+uSsBVZBzBjFvvkfbEQvsJMouzNHlZdhsr9cnnzc2PZd3u+l60NDat
         y35g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=r0ZIwChSWj55C5ZofQebA+Ysb/A45+GXttFMd4vVFZY=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=p0NV51nP39zBJw2F2TvOVOYCE8K8WHiZEVBJge8OyTc2UnecWdZt3F76U5RwpfMdPw
         HxOUmqMvgyCIdZfhmBJlbI6qifdrxs50dqPeA0wV70RT0OV6pSiVRLtDMTXXhtcZ2SWv
         VUma/V608BNnBAclBrre3OsW8YUOgYJwYiXrtGdcUAsYb9sBSihmQxok34iHdqQWO+q5
         An2m15Hz7cL86Obm5PycH6e9a+LHiapX9OqleCYEolB5lz9d1lp1qoTqAJV5eL8f3YWb
         fpaEhLk6TX4XojsnShwQzToYdm4cUSZTcm00yFGAV7Ylvj15yYr0kKkDxGUOtynHayHH
         JLxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id a17-20020a05600c2d5100b0040b54466ee8si34868wmg.2.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0AF1221991;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E23D613A97;
	Wed, 29 Nov 2023 09:53:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id AGjyNiAKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:27 +0100
Subject: [PATCH RFC v3 2/9] mm/slub: introduce __kmem_cache_free_bulk()
 without free hooks
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-2-6bcf536772bc@suse.cz>
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
In-Reply-To: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Matthew Wilcox <willy@infradead.org>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, maple-tree@lists.infradead.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spamd-Bar: +++++++++++++++++
X-Spam-Score: 17.13
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: 0AF1221991
X-Spam-Flag: NO
X-Spam-Level: *****************
X-Spamd-Result: default: False [17.13 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_SPAM(5.09)[99.98%];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_SPF_SOFTFAIL(4.60)[~all:c];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 R_DKIM_NA(2.20)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 NEURAL_SPAM_LONG(2.85)[0.813];
	 RCPT_COUNT_TWELVE(0.00)[17];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,lists.infradead.org,googlegroups.com,suse.cz];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Currently, when __kmem_cache_alloc_bulk() fails, it frees back the
objects that were allocated before the failure, using
kmem_cache_free_bulk(). Because kmem_cache_free_bulk() calls the free
hooks (kasan etc.) and those expect objects processed by the post alloc
hooks, slab_post_alloc_hook() is called before kmem_cache_free_bulk().

This is wasteful, although not a big concern in practice for the very
rare error path. But in order to efficiently handle percpu array batch
refill and free in the following patch, we will also need a variant of
kmem_cache_free_bulk() that avoids the free hooks. So introduce it first
and use it in the error path too.

As a consequence, __kmem_cache_alloc_bulk() no longer needs the objcg
parameter, remove it.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 33 ++++++++++++++++++++++++++-------
 1 file changed, 26 insertions(+), 7 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index f0cd55bb4e11..16748aeada8f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3919,6 +3919,27 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
 	return same;
 }
 
+/*
+ * Internal bulk free of objects that were not initialised by the post alloc
+ * hooks and thus should not be processed by the free hooks
+ */
+static void __kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
+{
+	if (!size)
+		return;
+
+	do {
+		struct detached_freelist df;
+
+		size = build_detached_freelist(s, size, p, &df);
+		if (!df.slab)
+			continue;
+
+		do_slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
+			     _RET_IP_);
+	} while (likely(size));
+}
+
 /* Note that interrupts must be enabled when calling this function. */
 void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 {
@@ -3940,7 +3961,7 @@ EXPORT_SYMBOL(kmem_cache_free_bulk);
 
 #ifndef CONFIG_SLUB_TINY
 static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-			size_t size, void **p, struct obj_cgroup *objcg)
+					  size_t size, void **p)
 {
 	struct kmem_cache_cpu *c;
 	unsigned long irqflags;
@@ -4004,14 +4025,13 @@ static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 
 error:
 	slub_put_cpu_ptr(s->cpu_slab);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
-	kmem_cache_free_bulk(s, i, p);
+	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 
 }
 #else /* CONFIG_SLUB_TINY */
 static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-			size_t size, void **p, struct obj_cgroup *objcg)
+				   size_t size, void **p)
 {
 	int i;
 
@@ -4034,8 +4054,7 @@ static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 	return i;
 
 error:
-	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
-	kmem_cache_free_bulk(s, i, p);
+	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
 #endif /* CONFIG_SLUB_TINY */
@@ -4055,7 +4074,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	if (unlikely(!s))
 		return 0;
 
-	i = __kmem_cache_alloc_bulk(s, flags, size, p, objcg);
+	i = __kmem_cache_alloc_bulk(s, flags, size, p);
 
 	/*
 	 * memcg and kmem_cache debug support and memory initialization.

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-2-6bcf536772bc%40suse.cz.
