Return-Path: <kasan-dev+bncBAABBZUVTSVQMGQEUFXMYJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 62EA67FD35F
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:56 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-5c5e6089750sf1879341a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251815; cv=pass;
        d=google.com; s=arc-20160816;
        b=pmOcutdAOJUSiZfQxovCa3ALvSAFhmKw/64cmHnfsIUsNxasxf3xIedVZzLUKCWcEQ
         yETtiPQiYBhBA5l1IZbzWh2ajBdcYgz62c18lc0nAJq1ejfRUh6d4vTefeBeb7zYuf/q
         gwQ1s8SlwpFip/PIox7TfYLKFG4M3HIN8cFUgCXsUWN21uwVSNANXcO2DpJdJb3LQg5h
         7Ux6JJjXZFzvUzmpSJ5x9l48cFgh7TOkAp6xFmVfdEfTp89n519zoa65a+mDkd7fGgMb
         pyxJ6ChBowgqDOj5CXuLl2+v9n7bWkcVlfjKJksh/8sLKKlg2n+2vEdFeXM+hXpnHpTA
         p3Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=2dOWKjQuEaeWqelAuV1cdMCzHjtbBiBaCfchCxL13pI=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=X1DDcCOV9ky4F2GQpUtWPpGHcnoBzgeXmNqP7MmctECcrgkj0YUkBGXznOrXta7XhS
         EaCte2/WC06JX3wPSPuTUvdyjbhl5sbLxpH9+/FpiOHxI1XZStZoRMwJDT8CT/rHbJpD
         YadiYQK0pBNX9+D1N1rmqVa8rwXtxpd7aFDgnUyYuMSntHY0dFWKshI6p1qWm3xTSyUJ
         VZUqTYINRajIfi/6R7PDZUqRKvTXqBQi10IS0dCW2j0GP5P6mvb1sGsvIyhlBUwhGW1I
         6ycR+oVXPa1nqLmlCkUWuJkfgH2QqoWDajs8RqkdTm0PfiKCfOXPcbIJG30kLINdgGN1
         PO9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251815; x=1701856615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2dOWKjQuEaeWqelAuV1cdMCzHjtbBiBaCfchCxL13pI=;
        b=rTVxyAD47zBwV7Ju7TlbkzsCL1ikcru52RNt89/3MWClRzNEBW02cXPKTwyBLfV02u
         viUq7FI5mgOYSWfDxdvLrHtWpTrD9dbo+gfZiQ/bvvw5056SmVyIBbAWqoJzZD6lCZnZ
         eOQ936KqY4Rr2v4fCTm+Tq/ip36tA5aR1dwhcfFm8GCo44K9KjCno5FMnriU7rx9nxJe
         MnbSb2rL0YhK1pS0T5tvJQq8Mhx2Y25X4vRO0DdO+pw1XHvgolZbBkh5C7++Ao5tchc7
         MwyGjCm/3DzIMMFzO3xbEYycz8uTDHvBDr1jBAgIt71XfhS7yahLItuS8KxgQWYjx9f3
         QoUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251815; x=1701856615;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2dOWKjQuEaeWqelAuV1cdMCzHjtbBiBaCfchCxL13pI=;
        b=Cz36UL1tkXOTDRcuEH/ghqeH8VgmbaS0FVp/Bcv6+gz8U09XcGHVzTVAtM3XfwYF+Q
         QK9DxyAmMlV9pdFaeEnT8pZ6YdaXkrD53aEGKAIfXXGoaHQaiGbgTc/9dD6PhPeJ9lBh
         ulBNeEUfrWSCVHXg6HL5jaKc/gwhnkhskZexP26P64w3Dk2miu3pbJyAIVuhgsHhveju
         rruGP8dnpnyoIt4Nx6ViTzHlsF0Z/IBefjvtGElc9mRyQpyCPDzGIwZNO2/YDXTXYqOZ
         HbRhk131plY6ioXDjMs5iGuiDsXpLZsPP1EZV0RGLqQuFX0G8W884s4mdRZom6nCxv6p
         jwuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzAmn0XalhR8riDjxMzzse7M3Hy5AueBPc5WQMI1LIva65kcDhE
	OGQkBHjIqTCm50G0m3j2+AU=
X-Google-Smtp-Source: AGHT+IEMwalW2udIIec0NcTsMtZ31NGuPUo/kpAuoSSyczSCBA2Jker3mtk8RvrfQO8ew3v8eClKeg==
X-Received: by 2002:a05:6a20:729e:b0:18a:f5df:5f88 with SMTP id o30-20020a056a20729e00b0018af5df5f88mr19571239pzk.62.1701251814779;
        Wed, 29 Nov 2023 01:56:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:44c6:b0:6cb:76bd:cb70 with SMTP id
 cv6-20020a056a0044c600b006cb76bdcb70ls9161pfb.0.-pod-prod-01-us; Wed, 29 Nov
 2023 01:56:54 -0800 (PST)
X-Received: by 2002:a63:5942:0:b0:5c1:7391:f21c with SMTP id j2-20020a635942000000b005c17391f21cmr3036289pgm.8.1701251814201;
        Wed, 29 Nov 2023 01:56:54 -0800 (PST)
Received: by 2002:a05:620a:2410:b0:778:a9dc:3cb2 with SMTP id af79cd13be357-77d641b56c2ms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:a05:651c:1a23:b0:2c5:1c6:80dc with SMTP id by35-20020a05651c1a2300b002c501c680dcmr7550070ljb.15.1701251619166;
        Wed, 29 Nov 2023 01:53:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251619; cv=none;
        d=google.com; s=arc-20160816;
        b=a83HCSWainWCqjygqaLOAPrH6f0IAr85BtkLvdmGy9ZBOt31wml8bc2PwzQiowCqlw
         awtQGXc22yfQAJIloXvmQPMzVzrcUZgtWm3aIo7iynZkrqLNctUo0Qr4gCVKRBj3hlRD
         +QreFCvnNiRihTpmqGObQJp8XS5HOrlVhCbqMkGcjurpf2/O6Z1uC9KtnZwDw1RT45lq
         hglTSM+2d0ubjtSuDXzgTpAgRohWuRb8lxZWI4JP9h+XhOsheSiAIxAz6+Ys4ZYq0mrS
         F87Fg1y66MjtuYc1o7aWWlPajQFzbc3IUnJoN/u5fFB2l2PuYeWfBUzJxilEbkk7mCkR
         FAWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=P2ukcSj2GFDFWZJr5dQPgX+igAnhpGokILF+Ev+OXuM=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=LoRchc0z31mzqNJJiyx900dOUR1psnx3z/0CdZ9IDImWO+yEKWO0R7wd1YrtPWUkqW
         7EMHWTT9w0oZHasrE7BEQkdOsgiApwI0SdCJ+RCV99Ba2jLnEJdn4EB5LBtTbsibD4kV
         W9XCy036+MwKakvGuXdELapwVdWeMdJs6AtXM3o/j1ug5mCh2NjcO2MqQ00/bAvFStY/
         j117XHvgX6blXPWQqbksZIH7ZpOMKT/QnC38Oi+2Ygjz98UldKXe41IDfcTS7cwJWi+i
         ki/SGUaQ6TIs7nYHIUYVwZziOdPzjv9Hlwo2loVOP+e6e2loINoWOSInIaHl3wtErQpS
         OdmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id s17-20020a2e81d1000000b002c9bcb68addsi67375ljg.8.2023.11.29.01.53.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2B8351F8B3;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 08AC613A98;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id qLDSASEKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:28 +0100
Subject: [PATCH RFC v3 3/9] mm/slub: handle bulk and single object freeing
 separately
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-3-6bcf536772bc@suse.cz>
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
X-Spamd-Bar: +++++++++
X-Spam-Score: 9.03
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: 2B8351F8B3
X-Spam-Flag: NO
X-Spam-Level: *********
X-Spamd-Result: default: False [9.03 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
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
	 BAYES_HAM(-3.00)[100.00%];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 NEURAL_SPAM_LONG(2.84)[0.810];
	 RCPT_COUNT_TWELVE(0.00)[17];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,lists.infradead.org,googlegroups.com,suse.cz];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

Until now we have a single function slab_free() handling both single
object freeing and bulk freeing with neccessary hooks, the latter case
requiring slab_free_freelist_hook(). It should be however better to
distinguish the two scenarios for the following reasons:

- code simpler to follow for the single object case

- better code generation - although inlining should eliminate the
  slab_free_freelist_hook() in case no debugging options are enabled, it
  seems it's not perfect. When e.g. KASAN is enabled, we're imposing
  additional unnecessary overhead for single object freeing.

- preparation to add percpu array caches in later patches

Therefore, simplify slab_free() for the single object case by dropping
unnecessary parameters and calling only slab_free_hook() instead of
slab_free_freelist_hook(). Rename the bulk variant to slab_free_bulk()
and adjust callers accordingly.

While at it, flip (and document) slab_free_hook() return value so that
it returns true when the freeing can proceed, which matches the logic of
slab_free_freelist_hook() and is not confusingly the opposite.

Additionally we can simplify a bit by changing the tail parameter of
do_slab_free() when freeing a single object - instead of NULL we can set
equal to head.

bloat-o-meter shows small code reduction with a .config that has KASAN
etc disabled:

add/remove: 0/0 grow/shrink: 0/4 up/down: 0/-118 (-118)
Function                                     old     new   delta
kmem_cache_alloc_bulk                       1203    1196      -7
kmem_cache_free                              861     835     -26
__kmem_cache_free                            741     704     -37
kmem_cache_free_bulk                         911     863     -48

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 57 ++++++++++++++++++++++++++++++++++-----------------------
 1 file changed, 34 insertions(+), 23 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 16748aeada8f..7d23f10d42e6 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1770,9 +1770,12 @@ static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
 /*
  * Hooks for other subsystems that check memory allocations. In a typical
  * production configuration these hooks all should produce no code at all.
+ *
+ * Returns true if freeing of the object can proceed, false if its reuse
+ * was delayed by KASAN quarantine.
  */
-static __always_inline bool slab_free_hook(struct kmem_cache *s,
-						void *x, bool init)
+static __always_inline
+bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 {
 	kmemleak_free_recursive(x, s->flags);
 	kmsan_slab_free(s, x);
@@ -1805,7 +1808,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
 		       s->size - s->inuse - rsize);
 	}
 	/* KASAN might put x into memory quarantine, delaying its reuse. */
-	return kasan_slab_free(s, x, init);
+	return !kasan_slab_free(s, x, init);
 }
 
 static inline bool slab_free_freelist_hook(struct kmem_cache *s,
@@ -1815,7 +1818,7 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 
 	void *object;
 	void *next = *head;
-	void *old_tail = *tail ? *tail : *head;
+	void *old_tail = *tail;
 
 	if (is_kfence_address(next)) {
 		slab_free_hook(s, next, false);
@@ -1831,7 +1834,7 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
+		if (slab_free_hook(s, object, slab_want_init_on_free(s))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -1846,9 +1849,6 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		}
 	} while (object != old_tail);
 
-	if (*head == *tail)
-		*tail = NULL;
-
 	return *head != NULL;
 }
 
@@ -3743,7 +3743,6 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 				struct slab *slab, void *head, void *tail,
 				int cnt, unsigned long addr)
 {
-	void *tail_obj = tail ? : head;
 	struct kmem_cache_cpu *c;
 	unsigned long tid;
 	void **freelist;
@@ -3762,14 +3761,14 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 	barrier();
 
 	if (unlikely(slab != c->slab)) {
-		__slab_free(s, slab, head, tail_obj, cnt, addr);
+		__slab_free(s, slab, head, tail, cnt, addr);
 		return;
 	}
 
 	if (USE_LOCKLESS_FAST_PATH()) {
 		freelist = READ_ONCE(c->freelist);
 
-		set_freepointer(s, tail_obj, freelist);
+		set_freepointer(s, tail, freelist);
 
 		if (unlikely(!__update_cpu_freelist_fast(s, freelist, head, tid))) {
 			note_cmpxchg_failure("slab_free", s, tid);
@@ -3786,7 +3785,7 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 		tid = c->tid;
 		freelist = c->freelist;
 
-		set_freepointer(s, tail_obj, freelist);
+		set_freepointer(s, tail, freelist);
 		c->freelist = head;
 		c->tid = next_tid(tid);
 
@@ -3799,15 +3798,27 @@ static void do_slab_free(struct kmem_cache *s,
 				struct slab *slab, void *head, void *tail,
 				int cnt, unsigned long addr)
 {
-	void *tail_obj = tail ? : head;
-
-	__slab_free(s, slab, head, tail_obj, cnt, addr);
+	__slab_free(s, slab, head, tail, cnt, addr);
 }
 #endif /* CONFIG_SLUB_TINY */
 
-static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
-				      void *head, void *tail, void **p, int cnt,
-				      unsigned long addr)
+static __fastpath_inline
+void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
+	       unsigned long addr)
+{
+	bool init;
+
+	memcg_slab_free_hook(s, slab, &object, 1);
+
+	init = !is_kfence_address(object) && slab_want_init_on_free(s);
+
+	if (likely(slab_free_hook(s, object, init)))
+		do_slab_free(s, slab, object, object, 1, addr);
+}
+
+static __fastpath_inline
+void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
+		    void *tail, void **p, int cnt, unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, p, cnt);
 	/*
@@ -3821,13 +3832,13 @@ static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
-	do_slab_free(cache, virt_to_slab(x), x, NULL, 1, addr);
+	do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
 }
 #endif
 
 void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller)
 {
-	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, caller);
+	slab_free(s, virt_to_slab(x), x, caller);
 }
 
 void kmem_cache_free(struct kmem_cache *s, void *x)
@@ -3836,7 +3847,7 @@ void kmem_cache_free(struct kmem_cache *s, void *x)
 	if (!s)
 		return;
 	trace_kmem_cache_free(_RET_IP_, x, s);
-	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, _RET_IP_);
+	slab_free(s, virt_to_slab(x), x, _RET_IP_);
 }
 EXPORT_SYMBOL(kmem_cache_free);
 
@@ -3953,8 +3964,8 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 		if (!df.slab)
 			continue;
 
-		slab_free(df.s, df.slab, df.freelist, df.tail, &p[size], df.cnt,
-			  _RET_IP_);
+		slab_free_bulk(df.s, df.slab, df.freelist, df.tail, &p[size],
+				df.cnt, _RET_IP_);
 	} while (likely(size));
 }
 EXPORT_SYMBOL(kmem_cache_free_bulk);

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-3-6bcf536772bc%40suse.cz.
