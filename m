Return-Path: <kasan-dev+bncBDXYDPH3S4OBBC44VHFQMGQEERM6RVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 55344D32C8D
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:41:16 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4801c105717sf17109145e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:41:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574475; cv=pass;
        d=google.com; s=arc-20240605;
        b=afs+Nx0c2J0ekj26aKeAbq72oVkzb0uf0oC8pxtrWIDoucuK+8U5QRFH/YUCShgZxx
         UjALtcMwz3TGiuLa07AHhC6XCeyPO3H65sNOitRpF/CdIllcTBdAaG+pHQYpDYuF+Zup
         R7b61FtBC/c1pEsJNC+eKUdCSITebfitqS6Wr0p/BopXYaXeYEJ0VPQOnKhCWMgOksdP
         Xlae0lHKlVYUWSTDuIvj/Xxd9gtjfC9/jK33P5wlgXeQBJRth0zRRR/E/hCq3le40pKD
         1M/D96X65/KBksVu4sfcrc2X4JO6QGkWrdKlRUdDW4aoHbjm+AH+Zj7uhogBdWjFGx/r
         wiow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=3f4VAQxa+2il1/PGSQ20S2d18R4WRDZ/bcd2K0CKHFM=;
        fh=SWTEgntJJ6kqiyRbeR0Q75h9EOeR+0frkAKya6Lvih8=;
        b=I2CsdUOItpgvzRLJB+MX+JMvmmlmNWh7QlPp1lSYieb81T35bTtPnoPgIFZuS44zT9
         AximK1hqPFlGQeeJry+72s+lzBuHP76V6W10jahq81ZTKYMfXyOebWr8+qD0l2j1kaFr
         B+bHecfnWP4tEjIIx56VDwIZqrDn1Lcc0eTMGd8qN3CT1/dBpcccbXtfnnRZI8kWl3pa
         JwfURkrwfnyLgG1yTCdyONxcu1oetq3XYDQv36k95+CJ41prgJwqdbgDUaAQpDZvmIvR
         smlraIeHnLSNoGajySWcRpCeLXfwfQNAurnAkp8+ABnXs0cI2hM4sPml7HRawVfcntiR
         dcUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="XZ/eqAuB";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="XZ/eqAuB";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574475; x=1769179275; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3f4VAQxa+2il1/PGSQ20S2d18R4WRDZ/bcd2K0CKHFM=;
        b=OdKtELj2YdGfkrz4YMRkxBkc1i6rfKd9lox/NoY9yjhra4YvmtLPYdpG1GM66JOxim
         we4g9gpi/2UuXkkjNtUyEOB193jHWhz89/8QumzCPbdf1zn69h4zapXBIg7TtfQtf/2j
         od9+7t2XmtdJRspGjEQtRJeQrYLC/rUy/IpOHsdoR/fDtl7ZIjS07MvMX0UHCH+PLksA
         FbM5xJVxe3MWn2dDZpZEhiWRTfVaXeHpcziwSiRWcu7anV/3ZNOlsmH1bjHInjwusJjB
         EJxyXE4LNuSCaSnhJErobAxOwVHdv6Yqcxc27nrM+T0mH8DO/bba3R+SPQvWNoLqxUgp
         AIJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574475; x=1769179275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3f4VAQxa+2il1/PGSQ20S2d18R4WRDZ/bcd2K0CKHFM=;
        b=GA1xB3NWdPUC5fJF26uc2MHmVsMiCW+jtNFmn72m9W9hDJPi1kO21sqL1g4w0zp5th
         4AsM6SWRMquWWWEV4okX6masduXLPwuS6D/ZnFVyLtbtkvKLDFRbQTRstsyPibC8DYkm
         LdjfI5ZuVTVlAZnIzO07kOyXEye+8R1efxK6ifuCvn1tdKVesaPBf9mBt8mga4UiWVru
         mh3QFIPF5tLAzOmkRmyGU2sqLgUP5jDc9cNawa1+jnRK2f+knNL+/Wtf4ZwClZLBOfJ6
         o98d2oGeZVLj0zoqPGGbOTSbS0DD5XauOoggaXqwnJrMe/ZfJu9c3wMKinYJK1B30v1E
         A12g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1cUIEfijG59dluCkcXU4Bay5gnxknaIZs8rRsS2HvylvarXymqCkEY6P0VoZegWUP4/2wZw==@lfdr.de
X-Gm-Message-State: AOJu0Yw4sGILjwLAUm/5NaSWE8b5XydOWIAX74LZUBMy6LZFv5qTWlYv
	0fHNJNJCEaF+exsIawnmomVeTduI8xK8vrLYKqBsorlb+ZNEzyj//nLy
X-Received: by 2002:a05:600c:6990:b0:47e:c562:a41f with SMTP id 5b1f17b1804b1-4801e334361mr39903025e9.18.1768574475595;
        Fri, 16 Jan 2026 06:41:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E0ssXyYQERj3QSJR0VWwPqi+9ZpkCmzFyxJfrSic6m7w=="
Received: by 2002:a05:600c:3510:b0:47a:74d9:db with SMTP id
 5b1f17b1804b1-47fb730a4a5ls11244055e9.1.-pod-prod-02-eu; Fri, 16 Jan 2026
 06:41:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUhmpT0Tgc56THlTFmO+y+Vl8PMZMjxV8LzLeOGCbHvtcV4S2TdAEbzc1CC5ISkPR1D1Mf9GVComcw=@googlegroups.com
X-Received: by 2002:a05:600c:6994:b0:47d:3690:7490 with SMTP id 5b1f17b1804b1-4801e2fd5c9mr36446855e9.9.1768574473346;
        Fri, 16 Jan 2026 06:41:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574473; cv=none;
        d=google.com; s=arc-20240605;
        b=HXVUGlotW7ijMgQHwESigZ9sHsv3tO71HDaK2Befz+nYnFmJrQFM2cc7c/D9srh4CW
         EIu5s8rCNlbtD02AhexuplFObtAgqHbxMzsScoIwQA6hFVhRtMK3DV/kBkyHxtbAGEkE
         phT/zn4zOXKjQTkJ4evlISSaXvtyc7KiAW3Ok0IFBpT1epK4hIaJtbjRJxYqRrZ0cq4j
         Nl1QwPF70XAUz3c7x3QONVmoXFUvpE6lQXzwaEn5x5duc4asX8m0NS9dk1ViizCdI9VH
         5ul6lCIzgh5Vfbicgg3Q0Z8cyRnkqbAsMVhpoEoK7Zx++6rkZcq1+kcIYpHXACNz+VV1
         vlvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=yKwoNuW0XcCU6x7RZ8PJjscrQbHgYsoJBCDr/kRfhfw=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=IdJ99+fwReLr7km1o5yOJ9FdmelTcqJMfxIdzt9a5+lQUI/AN4p6eCHXaHgxAoOxg2
         yy6ej+s3a0cMQ/g5nAIO4cVwCLUJ8KO6YCTfoSJcNfsvflLmRAJXnMGPa2Z/JS00I/2h
         4XOgs8osfCPq1zRqPXBAJTKJYLn0M3kOK5E1G/ybwxZgf2aGu99wrJXfNef4vF5DW2bs
         p5/TSuG+g+EYXcWMN+gSPnJ9aV5f7tr54Ywkq58X1jnYgSd1RulzBjQnXTQGE59cfMK1
         5oDz/r4UQG6RuLLsn8FwkH9tMsRfc95QGI0KwyHsnFyO307PDgeCDlcuZYCaehXi6zfr
         qYFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="XZ/eqAuB";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="XZ/eqAuB";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4802602e1aesi2645e9.2.2026.01.16.06.41.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:41:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E35B9337FD;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B7D313EA65;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id SOyZLOZNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:40 +0100
Subject: [PATCH v3 20/21] mm/slub: remove DEACTIVATE_TO_* stat items
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-20-5595cb000772@suse.cz>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.999];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc),to(RL941jgdop1fyjkq8h4)]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="XZ/eqAuB";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="XZ/eqAuB";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as
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

The cpu slabs and their deactivations were removed, so remove the unused
stat items. Weirdly enough the values were also used to control
__add_partial() adding to head or tail of the list, so replace that with
a new enum add_mode, which is cleaner.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 31 +++++++++++++++----------------
 1 file changed, 15 insertions(+), 16 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 7ec7049c0ca5..c12e90cb2fca 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -324,6 +324,11 @@ static void debugfs_slab_add(struct kmem_cache *);
 static inline void debugfs_slab_add(struct kmem_cache *s) { }
 #endif
 
+enum add_mode {
+	ADD_TO_HEAD,
+	ADD_TO_TAIL,
+};
+
 enum stat_item {
 	ALLOC_PCS,		/* Allocation from percpu sheaf */
 	ALLOC_FASTPATH,		/* Allocation from cpu slab */
@@ -343,8 +348,6 @@ enum stat_item {
 	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
 	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
 	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
-	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
-	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
 	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
 	DEACTIVATE_BYPASS,	/* Implicit deactivation */
 	ORDER_FALLBACK,		/* Number of times fallback was necessary */
@@ -3268,10 +3271,10 @@ static inline void slab_clear_node_partial(struct slab *slab)
  * Management of partially allocated slabs.
  */
 static inline void
-__add_partial(struct kmem_cache_node *n, struct slab *slab, int tail)
+__add_partial(struct kmem_cache_node *n, struct slab *slab, enum add_mode mode)
 {
 	n->nr_partial++;
-	if (tail == DEACTIVATE_TO_TAIL)
+	if (mode == ADD_TO_TAIL)
 		list_add_tail(&slab->slab_list, &n->partial);
 	else
 		list_add(&slab->slab_list, &n->partial);
@@ -3279,10 +3282,10 @@ __add_partial(struct kmem_cache_node *n, struct slab *slab, int tail)
 }
 
 static inline void add_partial(struct kmem_cache_node *n,
-				struct slab *slab, int tail)
+				struct slab *slab, enum add_mode mode)
 {
 	lockdep_assert_held(&n->list_lock);
-	__add_partial(n, slab, tail);
+	__add_partial(n, slab, mode);
 }
 
 static inline void remove_partial(struct kmem_cache_node *n,
@@ -3375,7 +3378,7 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
 	if (slab->inuse == slab->objects)
 		add_full(s, n, slab);
 	else
-		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		add_partial(n, slab, ADD_TO_HEAD);
 
 	inc_slabs_node(s, nid, slab->objects);
 	spin_unlock_irqrestore(&n->list_lock, flags);
@@ -3996,7 +3999,7 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
 			n = get_node(s, slab_nid(slab));
 			spin_lock_irqsave(&n->list_lock, flags);
 		}
-		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		add_partial(n, slab, ADD_TO_HEAD);
 		spin_unlock_irqrestore(&n->list_lock, flags);
 	}
 
@@ -5064,7 +5067,7 @@ static noinline void free_to_partial_list(
 			/* was on full list */
 			remove_full(s, n, slab);
 			if (!slab_free) {
-				add_partial(n, slab, DEACTIVATE_TO_TAIL);
+				add_partial(n, slab, ADD_TO_TAIL);
 				stat(s, FREE_ADD_PARTIAL);
 			}
 		} else if (slab_free) {
@@ -5184,7 +5187,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	 * then add it.
 	 */
 	if (unlikely(was_full)) {
-		add_partial(n, slab, DEACTIVATE_TO_TAIL);
+		add_partial(n, slab, ADD_TO_TAIL);
 		stat(s, FREE_ADD_PARTIAL);
 	}
 	spin_unlock_irqrestore(&n->list_lock, flags);
@@ -6564,7 +6567,7 @@ __refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int mi
 				continue;
 
 			list_del(&slab->slab_list);
-			add_partial(n, slab, DEACTIVATE_TO_HEAD);
+			add_partial(n, slab, ADD_TO_HEAD);
 		}
 
 		spin_unlock_irqrestore(&n->list_lock, flags);
@@ -7031,7 +7034,7 @@ static void early_kmem_cache_node_alloc(int node)
 	 * No locks need to be taken here as it has just been
 	 * initialized and there is no concurrent access.
 	 */
-	__add_partial(n, slab, DEACTIVATE_TO_HEAD);
+	__add_partial(n, slab, ADD_TO_HEAD);
 }
 
 static void free_kmem_cache_nodes(struct kmem_cache *s)
@@ -8719,8 +8722,6 @@ STAT_ATTR(FREE_SLAB, free_slab);
 STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
 STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
 STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
-STAT_ATTR(DEACTIVATE_TO_HEAD, deactivate_to_head);
-STAT_ATTR(DEACTIVATE_TO_TAIL, deactivate_to_tail);
 STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
 STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
 STAT_ATTR(ORDER_FALLBACK, order_fallback);
@@ -8823,8 +8824,6 @@ static struct attribute *slab_attrs[] = {
 	&cpuslab_flush_attr.attr,
 	&deactivate_full_attr.attr,
 	&deactivate_empty_attr.attr,
-	&deactivate_to_head_attr.attr,
-	&deactivate_to_tail_attr.attr,
 	&deactivate_remote_frees_attr.attr,
 	&deactivate_bypass_attr.attr,
 	&order_fallback_attr.attr,

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-20-5595cb000772%40suse.cz.
