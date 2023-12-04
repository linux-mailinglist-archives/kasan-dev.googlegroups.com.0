Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXWTXCVQMGQETX5C26Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id BCB33803E75
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Dec 2023 20:34:56 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40b3519a03asf41529715e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Dec 2023 11:34:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701718496; cv=pass;
        d=google.com; s=arc-20160816;
        b=x5Kd6TksOUFC9gk7CzIojGnI7C3BM6V8I8o2U411+ffaFUGYupNXEITPuLMZ4vEeuF
         A2ZSbz3f3ZxoP9aRbhPgAbpcED6po8Cgs40U1wqpXbUkTQLacWVZSqTwdixt3QN9CQlr
         HbOQnJZHIp4Xpxf031EeCjmCy99HDvGWT+mzhHX5kvWvRFjQHCxQDh013tLAOp7tc715
         fR6T8JnzOXeHU+UPoygNApmkrOQZ1AjGK/KgIHQogUKZ0cFw790Ph2vJb4+gzShRJAfe
         OFHkPguNQObzPiwcYw/W83linKTASNrK3bkc8uIzKme4i0De7O7L10z/gHiOkq81QTqk
         MODQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=LHjrgc2vBctqYXI8JsAuDJb+gdwplQhQ+E0JJ7hqjSg=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=McpXdE9Pk7IdYAuIsDC8RJh91MBwiyg+tgjCdserYe4r13CDIGwijV6gmVRSVlBouy
         L1iiR8x8feAuDI5vt17Njwtm91UniCwjNXX4636m2Kv0ti85JpHGoCcNHm9siW8UUVQ5
         2C1XGBvQLMrmehCoJV2Bk7iToKv1p1mt1IOSngctpebsU0ftO4SGA9CONWeDRhSgqLMq
         bb9jwj6gyYHz74fPxMpBsZykdeIqD+8QYlttLWLp8qwjL5+NVS67vhXOUf+QKuInmNPp
         ZeE16q30ktuxEscUgyI4gdV2CM6KSFJ1QZB/jXAgfJaQXbAH0XqL7DP+0ygHM9Tj+MCt
         trLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=heFvZSEq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701718496; x=1702323296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LHjrgc2vBctqYXI8JsAuDJb+gdwplQhQ+E0JJ7hqjSg=;
        b=Zbu7D55KQvqTxhtwJsiT4E+VLTbOlhFNlIvdk+sE1yL+0TakbV2/ikjyOW3fCLonCP
         6m3eZLNJ1jCPkb6+C7gy8I303LoFfKMC6HCN9cAG0c/1fjhwonMjOgErRYHteJbD5mFy
         bfqSR2YaIXhE3SCo9DeemsYuP+XCQikqKbm97AAsbKKIMfURJVEhm7pc0F3pqvV7eZ8h
         VNLf4/1qn0c5bymCHfJdnqgJiYcXE45MmgrLkBPnTaCb0R1OmEySciacxvgt3c/VFZAq
         BcjUnrHoTZI838XaSDwBc2NpERN1BABR/IFCMWpDSLCPAt3kYdRjRslMyrw5D72bV7ci
         yUhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701718496; x=1702323296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LHjrgc2vBctqYXI8JsAuDJb+gdwplQhQ+E0JJ7hqjSg=;
        b=mdSsHj/uoRmlSsA30TpRp2grogE8cEo1Tv5RSUMfEk1u7ol5LBGqD6NIS5Xt5elC4x
         iEekSuGU6jVeGhY1gn3I/AhguUJgc8FYftztuzCVka55hQnDLMR7SHAcSAHA7PYKjccx
         9+IpJMww/toVnJqGjt5NQC6S6KucJnPsK1peI8OKBN0gWxR1IJri2YxADoHoj+CKp5xu
         dN9Z3tOGGITrFaoz2cCe6VOYbW83rYCxBo9+zQEf4y8Y++M2GG1jaq/o6mkKLlwOCmZR
         PRZzPBuPN4+8/jXLbNl2YJbkyQzVEpQDX6I0aT7MExUZ8z5iU9t5Bx5agpXz9T0BDbm3
         kBGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy34EQmJukGsPFv5T7CZh+jf14x80BBaoPo+eC8RwPJPqRCarec
	hw+jjwKRI1jBEEtInwkoHN0=
X-Google-Smtp-Source: AGHT+IFEGZvB19xkA+WwRzHfxJd1zYxqj0slTMPuRl4pE4/uQFGDbTGbX2ik54dkTh5UMup6H4SXaQ==
X-Received: by 2002:a05:600c:45d0:b0:40b:4b1a:57f with SMTP id s16-20020a05600c45d000b0040b4b1a057fmr2863898wmo.24.1701718495172;
        Mon, 04 Dec 2023 11:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f16:b0:40b:3977:87e3 with SMTP id
 l22-20020a05600c4f1600b0040b397787e3ls362002wmq.0.-pod-prod-05-eu; Mon, 04
 Dec 2023 11:34:53 -0800 (PST)
X-Received: by 2002:a05:600c:8607:b0:40b:5e59:ccd3 with SMTP id ha7-20020a05600c860700b0040b5e59ccd3mr2689550wmb.180.1701718493482;
        Mon, 04 Dec 2023 11:34:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701718493; cv=none;
        d=google.com; s=arc-20160816;
        b=yN3im0FSaf4d43xZrrP2+zNEsUXV7y63aKA8odq6P0tMyP8DGBGeSew1FYxDddyMPP
         SpgExH/bTml8w22ZWNTiFlQX25vBfEwKl8BAM6JIOml4wmi8EVy6K4S5BCQiA2IOfAvh
         TCIpqXjSegBreeX+XB2VlTJxHt6jDRUhLDHvf84cvSzF2W/dVDBV6+dI4pATuXmrSj+W
         O4YwO9u+gIJrcYEek53U4Uj0fBVy+INxXi9oDL7zXPLb+LM9qDsVMNMIE8rrxW3dsmjj
         5xhOMlqveEOv2elA+FEuoOlPMG67k+tVgyJ7CBYAxHiO6n3dQARFW7X5ZuPbtv+SZpjP
         NqSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=oMJ38qh2PsFVzYJdgL9aE/PQtVEO5BW0t1lp5LOzGhE=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=0YatOFOL4yChtx9DQyK3B++gIBKbQFccKnVtHg792c5cBHlKT5ZsZ2uCk+3ofZa+lv
         cBwaqMFJQAvdkCwNX+eua4gomylykSk2ZweXYzf+S8Hrz/Ae6p0d8eO/i+yB1rhO8j8q
         /qGuM6bO0iQ1qVKeR960zqwVGQiMrDI3Phc1zed6Js38f/eKs81pFiKzgh1Z6eB/28le
         cPDlWM95kdurN/diS5i+cmrUq835Nz3PZCsFeUm7gBQn2U7/lc5ZEbo/pRcoKeSZG3s1
         pa58eTbKuqH1pD2htSe1fQKHDZywKTZQfHXSSz6+y6pybFeUTguQ0QeSkF8fKVopNYpu
         QACQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=heFvZSEq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id fa20-20020a05600c519400b0040a25ec1ce5si772199wmb.0.2023.12.04.11.34.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 11:34:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id BDC741FE6F;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A101E13AC1;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 6Gn/JtwpbmUPMwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 04 Dec 2023 19:34:52 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 04 Dec 2023 20:34:42 +0100
Subject: [PATCH 3/4] mm/slub: handle bulk and single object freeing
 separately
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231204-slub-cleanup-hooks-v1-3-88b65f7cd9d5@suse.cz>
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
In-Reply-To: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: 
X-Spam-Score: -2.60
X-Spamd-Result: default: False [-2.60 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RLtz7ce9b89hw8xzamye9qeynd)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[14];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_TLS_ALL(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=heFvZSEq;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

Currently we have a single function slab_free() handling both single
object freeing and bulk freeing with necessary hooks, the latter case
requiring slab_free_freelist_hook(). It should be however better to
distinguish the two use cases for the following reasons:

- code simpler to follow for the single object case

- better code generation - although inlining should eliminate the
  slab_free_freelist_hook() for single object freeing in case no
  debugging options are enabled, it seems it's not perfect. When e.g.
  KASAN is enabled, we're imposing additional unnecessary overhead for
  single object freeing.

- preparation to add percpu array caches in near future

Therefore, simplify slab_free() for the single object case by dropping
unnecessary parameters and calling only slab_free_hook() instead of
slab_free_freelist_hook(). Rename the bulk variant to slab_free_bulk()
and adjust callers accordingly.

While at it, flip (and document) slab_free_hook() return value so that
it returns true when the freeing can proceed, which matches the logic of
slab_free_freelist_hook() and is not confusingly the opposite.

Additionally we can simplify a bit by changing the tail parameter of
do_slab_free() when freeing a single object - instead of NULL we can set
it equal to head.

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
 mm/slub.c | 59 +++++++++++++++++++++++++++++++++++------------------------
 1 file changed, 35 insertions(+), 24 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 0742564c4538..ed2fa92e914c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2037,9 +2037,12 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
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
@@ -2072,7 +2075,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
 		       s->size - s->inuse - rsize);
 	}
 	/* KASAN might put x into memory quarantine, delaying its reuse. */
-	return kasan_slab_free(s, x, init);
+	return !kasan_slab_free(s, x, init);
 }
 
 static inline bool slab_free_freelist_hook(struct kmem_cache *s,
@@ -2082,7 +2085,7 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 
 	void *object;
 	void *next = *head;
-	void *old_tail = *tail ? *tail : *head;
+	void *old_tail = *tail;
 
 	if (is_kfence_address(next)) {
 		slab_free_hook(s, next, false);
@@ -2098,8 +2101,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (likely(!slab_free_hook(s, object,
-					   slab_want_init_on_free(s)))) {
+		if (likely(slab_free_hook(s, object,
+					  slab_want_init_on_free(s)))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -2114,9 +2117,6 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		}
 	} while (object != old_tail);
 
-	if (*head == *tail)
-		*tail = NULL;
-
 	return *head != NULL;
 }
 
@@ -4227,7 +4227,6 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 				struct slab *slab, void *head, void *tail,
 				int cnt, unsigned long addr)
 {
-	void *tail_obj = tail ? : head;
 	struct kmem_cache_cpu *c;
 	unsigned long tid;
 	void **freelist;
@@ -4246,14 +4245,14 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
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
@@ -4270,7 +4269,7 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 		tid = c->tid;
 		freelist = c->freelist;
 
-		set_freepointer(s, tail_obj, freelist);
+		set_freepointer(s, tail, freelist);
 		c->freelist = head;
 		c->tid = next_tid(tid);
 
@@ -4283,15 +4282,27 @@ static void do_slab_free(struct kmem_cache *s,
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
@@ -4305,7 +4316,7 @@ static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
-	do_slab_free(cache, virt_to_slab(x), x, NULL, 1, addr);
+	do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
 }
 #endif
 
@@ -4349,7 +4360,7 @@ void kmem_cache_free(struct kmem_cache *s, void *x)
 	if (!s)
 		return;
 	trace_kmem_cache_free(_RET_IP_, x, s);
-	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, _RET_IP_);
+	slab_free(s, virt_to_slab(x), x, _RET_IP_);
 }
 EXPORT_SYMBOL(kmem_cache_free);
 
@@ -4395,7 +4406,7 @@ void kfree(const void *object)
 
 	slab = folio_slab(folio);
 	s = slab->slab_cache;
-	slab_free(s, slab, x, NULL, &x, 1, _RET_IP_);
+	slab_free(s, slab, x, _RET_IP_);
 }
 EXPORT_SYMBOL(kfree);
 
@@ -4512,8 +4523,8 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 		if (!df.slab)
 			continue;
 
-		slab_free(df.s, df.slab, df.freelist, df.tail, &p[size], df.cnt,
-			  _RET_IP_);
+		slab_free_bulk(df.s, df.slab, df.freelist, df.tail, &p[size],
+			       df.cnt, _RET_IP_);
 	} while (likely(size));
 }
 EXPORT_SYMBOL(kmem_cache_free_bulk);

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231204-slub-cleanup-hooks-v1-3-88b65f7cd9d5%40suse.cz.
