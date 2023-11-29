Return-Path: <kasan-dev+bncBAABBV4VTSVQMGQEKUEBUAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id F2A377FD358
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:40 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-5c5dd157f5csf3368976a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251799; cv=pass;
        d=google.com; s=arc-20160816;
        b=bXV99l/eg26lsFjofPr0GhaZZJLq9fN3FrTa/CmS949ApC6npzNLea2zk/I8k+0nKl
         cheA972jv1JpLFQp0m9FnCkqEMZmfkAgSgX+FF7P1l/4QrXdpxp5bkhfxMrre3Cb1opT
         QaB9EBUH2Gob4SL6aZFFxc9T1O1BiUiqk8X7mfQ21XDuAvFogP5ewHyVBe+uiUcIrJj7
         P2F51vPRjvddYwjHzQ23P2fens57+C3L/jjo5dWiLUptKYSrOxqS+N0Oyty2DNZ25ajF
         weWI5wVxwnp5bFodH9cPsv67gC1tdu+9RPGfqDGBjI+qwwYYzIoE9AGFf7SAidxs3E1B
         mgiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=5u8cqiJLXcRsss+/ewhdNC0LW3gInvZ5ZPErNnFSTAU=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=NkciahDgPQmtMiTgx/gujRStn64vwq5bgn6/dmK3jiwBxG0CtabPlgQaKrLUVaX7v0
         6pc6DnrhNLkwzLk0gaVM9jPUAmk7VhhCJttBgcrbU1MQI6yeXePJ2S4k2KFVpTtIYOZ/
         jV1voyu7hDsrC/TSbp8v+jOE19kXf9FJZdsNyfL6CpZWfEgXSxNw6GLHuA2iH+3oHBXA
         JzLW1/WTNOSPTji2DThBiA4V9OjLfK9pqbB1oXA34wIRGpoRW09sMohxTMKcqxa3T8Ad
         C2l87gQzgtKei3VyWN6H/3TGpKQaAw2QdF3dDjCxUjoxIEPsL+6SKvRd6zsSF8ki5POs
         EeNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251799; x=1701856599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5u8cqiJLXcRsss+/ewhdNC0LW3gInvZ5ZPErNnFSTAU=;
        b=BFVvKSQ+77dzLp+W1t8N7c8dz7nL7kvkXir53FUFdr9LhbRZMeyBBdHJwgSufLq1KK
         xk036OWSc4acuTDanvugU6WbLgyOQmIeS1mEPuidIJcJTZMNcwE9TnUuWSAyGD+Vs92i
         9A53yK2/jFxned5W9oeF/UxqfayYM+/Gv5smXIvJP/mV5RY9h3WOaZ9pcfisOVOVewyL
         qJve/OGqlpv47n73hySt1Os5OK+Ih+O5v45D2E9vVfhvBC0y//QnLjxm6q32c7VAWWsY
         TVjfy7A/PatmB9cJVps9/lx8ysNlnkxsrG8vAsWq64ZZtWeVOskCL5t4PO61XMr4ILVJ
         qk4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251799; x=1701856599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5u8cqiJLXcRsss+/ewhdNC0LW3gInvZ5ZPErNnFSTAU=;
        b=kD4fTKfevldOZqkuh4zBo1cN5tsYgMXUiajhuC5K7NWHRfhj9mzKK7xfEnJnXikOhb
         Qi7iWVUYS9NcVM0Om9r876N3k1iDMuNrsKICkpvwgRH3LbEc/xCdHj99pRytHudTRfq3
         2gBq5fIjCTQv4YTclaSJ7pVQAe3ayy15zyZ6sEZU0PcypWEpJTHvvNFi2aRX0wgVShME
         CxGUViQ28iKZFZesVEhYgc1WJe5DivpiXw8uk2NQb8z8DaNz2ovz/83xt3jZR4CraC7B
         R1KgKtq+Xy8+vOBK9SGovpvuQZskIRqX8tesCC33YSyOyLO9rso8vBXtDa3hMh4Nwz3/
         MsCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywop0y3G7nM5xMwUyVgWo0xQu2rBPimVPfxsUpXLNPLMyPKCQyd
	8P9BiVyGh7G8O31dLLId7no=
X-Google-Smtp-Source: AGHT+IGdXobTnyHByaNdN2ZuR0jzadbMYXTTdRk92YjzUWSKNFs6chkyD2fg98ahO0M8Ak1ktvTvQg==
X-Received: by 2002:a05:6a20:c189:b0:187:ce5a:2a87 with SMTP id bg9-20020a056a20c18900b00187ce5a2a87mr18920224pzb.12.1701251799179;
        Wed, 29 Nov 2023 01:56:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8c11:b0:690:ffcd:3bfd with SMTP id
 ih17-20020a056a008c1100b00690ffcd3bfdls4730229pfb.2.-pod-prod-00-us; Wed, 29
 Nov 2023 01:56:38 -0800 (PST)
X-Received: by 2002:a05:6a00:acd:b0:6c6:9f26:3a00 with SMTP id c13-20020a056a000acd00b006c69f263a00mr5456915pfl.2.1701251798610;
        Wed, 29 Nov 2023 01:56:38 -0800 (PST)
Received: by 2002:a05:620a:191d:b0:77b:cc25:607f with SMTP id af79cd13be357-77d63f5307cms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:a05:600c:a04:b0:408:369a:dad1 with SMTP id z4-20020a05600c0a0400b00408369adad1mr4364223wmp.4.1701251618568;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=TPudFCLsOa0ubYnHDkeoL07zF990Kfok5eKL0puWI7EJEVYI2K+3WSlaG7k5c8wDix
         6KRqPEdiA45pBcx+FE7CAc3NkOXpvIoGqc2p6zY3jolkUgj5nmgDWw1IomNevZvfw+xj
         kn01UlMskzHHkudRCjVs8VRwF5RSrN6jYjPXPw0U8wBSciSRuhIgtuq+nXIDGOjwecDL
         /JoKu2+s1OVxmQ22PRPJcogaus8bDRvm2PkllX+Igil3vDaoSzwCRL3xpBz4B+Ib48EC
         /B2IUEpKZVZf+4gIlilR+PgwH5DwHwuBqM/Ewd3CJfHLgHhsgt3daGELqJ+9shDeMAiV
         AGiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=DUPnHPdnAWU/UCFeEX1tNeDnCcnIMYmNivE3br+UPhg=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=Y0Ec/Z0sTXbpVwwT6j/staleE6zEgzltgabKLx3cUnN+AluH9hQBSts4xxwK3cyOwK
         AQ4ybCt9rVxKwYeQLExIMfkUeKkC/m/+aqE4ZvZZ9t+IEo1SF/arczUY1lI9jUa9reyY
         0M/8hE8M5LxK98BojN/yDMXcB4FZV9EvRknB5sBaiIRZOd6i7hcnE808IN7Ht1NEo+0p
         doRQtWXj3eWpV2UIIdxVxiBxoigY/ZlSrwds8IjFKzvqICwaoXA1vkugt0PnJJ07CJBP
         Q2uTU0nSTa3y0qCtD1pIlsW6I4kWLbx2KYMkO2pVTR+hc3iT5+d2wK+h15AMOAlfnHqd
         Sj9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id p35-20020a05600c1da300b0040b4055397csi82159wms.1.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E3FEA21990;
	Wed, 29 Nov 2023 09:53:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C819013A96;
	Wed, 29 Nov 2023 09:53:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id wISPMCAKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:26 +0100
Subject: [PATCH RFC v3 1/9] mm/slub: fix bulk alloc and free stats
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-1-6bcf536772bc@suse.cz>
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
X-Spamd-Bar: ++++++++++++
X-Spam-Score: 12.03
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: E3FEA21990
X-Spam-Flag: NO
X-Spam-Level: ************
X-Spamd-Result: default: False [12.03 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_SPAM(0.00)[18.74%];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_SPF_SOFTFAIL(4.60)[~all];
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
	 NEURAL_SPAM_LONG(2.84)[0.812];
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

The SLUB sysfs stats enabled CONFIG_SLUB_STATS have two deficiencies
identified wrt bulk alloc/free operations:

- Bulk allocations from cpu freelist are not counted. Add the
  ALLOC_FASTPATH counter there.

- Bulk fastpath freeing will count a list of multiple objects with a
  single FREE_FASTPATH inc. Add a stat_add() variant to count them all.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 11 ++++++++++-
 1 file changed, 10 insertions(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index 63d281dfacdb..f0cd55bb4e11 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -341,6 +341,14 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
 #endif
 }
 
+static inline void stat_add(const struct kmem_cache *s, enum stat_item si, int v)
+{
+#ifdef CONFIG_SLUB_STATS
+	raw_cpu_add(s->cpu_slab->stat[si], v);
+#endif
+}
+
+
 /*
  * Tracks for which NUMA nodes we have kmem_cache_nodes allocated.
  * Corresponds to node_state[N_NORMAL_MEMORY], but can temporarily
@@ -3784,7 +3792,7 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 
 		local_unlock(&s->cpu_slab->lock);
 	}
-	stat(s, FREE_FASTPATH);
+	stat_add(s, FREE_FASTPATH, cnt);
 }
 #else /* CONFIG_SLUB_TINY */
 static void do_slab_free(struct kmem_cache *s,
@@ -3986,6 +3994,7 @@ static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 		c->freelist = get_freepointer(s, object);
 		p[i] = object;
 		maybe_wipe_obj_freeptr(s, p[i]);
+		stat(s, ALLOC_FASTPATH);
 	}
 	c->tid = next_tid(c->tid);
 	local_unlock_irqrestore(&s->cpu_slab->lock, irqflags);

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-1-6bcf536772bc%40suse.cz.
