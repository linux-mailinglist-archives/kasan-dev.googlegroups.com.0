Return-Path: <kasan-dev+bncBDXYDPH3S4OBB6VVZTFQMGQEKQ65ASA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id aHaSAvwac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB6VVZTFQMGQEKQ65ASA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:48 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E6FD87136E
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:47 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-47fff4fd76dsf14007035e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151227; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rohjsn8bA9gy+k6rB6l3h4iXiFtQPQa8k90kaToFTjFZrKx2xWORuqW+Z4S14AgCVD
         zH+Ercg579S8SefbDScAbkLszSzZglumYMV6Wds5K+ymkKu8bzJ6V7EHX7M1XRhAh0Zp
         TrVr7r4D9UxlAO5ZDsAO8ujK6kf85mIJ9BRiBCAUZm7lMXirC6bHIFRB1TsZAkhy7jC3
         4q6u/6x1cOQaENGgOdssZjRBsLIz17Cp3i/gUXx7zIlfrKcLrspIb3F2zH1iAMtGOtLl
         DwGSs0MemKDvZilHx2m/vw0fx1okR+TgnJUv0n1Pq8HJq1PDn+cyQbzsZWYj7H1pxXJj
         vXlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=JcfUsNWDwOf+oxmnsq1xThepQgwvKuSRnjTDiftUJz4=;
        fh=oAmCKgI+bUUi9/lQJJfBAM7HMIldvjWvtpW6PlwPWZc=;
        b=DyXfrJlKoLonKlYO7QTKPK53Qu0r29OYCg8D6lPy+gWzzjlSuti53MtPM2WCYY41Ec
         oImvfOohWiEJU/O61LD7nPm1yBl4ZF5qRgEqPpMvXfx0p8FILawWgsTzkSQn7+7XfcSN
         ++ZfQ4xoNdWReNDLiwu8RmWqvs/iW+HnW4TCPB67W/5+2cr7a76nuySyr+3Y+DcyZ2Xf
         CpH3qOovai3eC0rwgtayNja1XvCNunvA2S12xCbaNZOywAel6g/hmwjIl9IFcJCRukwx
         tQiEGqJL5PqHsX1Ot20DegUUvxYqhNkt3O4i8bjB9PJSjYocn26bZ8jnvAF8S6XwN5iM
         F5NA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151227; x=1769756027; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JcfUsNWDwOf+oxmnsq1xThepQgwvKuSRnjTDiftUJz4=;
        b=OlrybD0g5QBGuXAuGiFGsY0ivf2a50be+FHLYcRA9lDHdcPu6R9EQLDwfszR0fbx74
         1ukhLqA2AG1UvKtL63Bl7Jgam/a7AfVL6qkYgmA2PjTpeiSK9k/V/3N+0sqIlFbRxgao
         EJfZLhb1frKGt8VGl9XEUCQWt9HOJutyV3W1+dGHAUYLOp+5OxxB97o31DQedfL7xyCu
         oi0pgCgSTEC5G4PFdvixT5XgpbJPVU44EHZ9tVCAXneWbmoDbBH7EOQ0LtlqiCYeXskt
         MRusREgJBjsJCB7k6FJxG8hchKXx70UiyCH/pA5J0X+Ms2D/HVJGvLkdRzvVcsEEGo0T
         wzXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151227; x=1769756027;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JcfUsNWDwOf+oxmnsq1xThepQgwvKuSRnjTDiftUJz4=;
        b=OzpznFZocKadGXJdAKRA1irvIzXtndRwDj1GZ7jNn6mzAAZ3Qgv3CBl+jgW47aIeTM
         P2gAotxo+SNt9b6ckmz6y76QpMLGqKzrzS4SIzVnsDY822UBgBchWDTeVul9fGTEAMyl
         yQzdSplD8TZ6vpM6RTMVmmgeo7pCnBtn9ewr5VS33OEntzMAZzWXy7KV74iGBO1wZBjn
         Z2IOW+oHQ4wrNkAooLnopV0ufSEn5k7nE1/nM7TfaD1jZJeDlWtqqnSTjPqdkSDZTbvI
         6UKF+hOAqR8WNOoNgNLc0JwdZ/LokvZku01cyIOB8WSsTkPoLGy13LcWHN77r/t54gtt
         E8QQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyMAudyne15o6I3bedv1HW5yoIsj6M7mzkzePiy5m/dVdkgp5GibnYi+iNCpBzelcAJO3Hdw==@lfdr.de
X-Gm-Message-State: AOJu0YzHwW8D6l0ORXQj3y7csHvkV0pjz3ktm0vq2sdl0WEo42UTFzNC
	T716L4oH6EuQ2/v7PKvoRw26Ktz6McKTsObNVt4Gsp3b0zRKUfVnWRG0
X-Received: by 2002:a05:600c:8b64:b0:47e:e72b:1fce with SMTP id 5b1f17b1804b1-4805126793bmr4365205e9.37.1769151227412;
        Thu, 22 Jan 2026 22:53:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GzzHj7/IDCssFep/kMDr+Xk33PBQriF4fwzsAq38f9Mg=="
Received: by 2002:a05:600c:1c02:b0:477:5d33:983b with SMTP id
 5b1f17b1804b1-48046fc241dls11897075e9.2.-pod-prod-01-eu; Thu, 22 Jan 2026
 22:53:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVykY88XLPHFGiH4r88NV4jjG1cc5GqWiinQE+cCso5r+Srge8ihgQ7ib22PC8pviHx1k7XbeI1HDE=@googlegroups.com
X-Received: by 2002:a05:600c:34ca:b0:480:4a4f:c366 with SMTP id 5b1f17b1804b1-48051249cdcmr5236225e9.20.1769151225160;
        Thu, 22 Jan 2026 22:53:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151225; cv=none;
        d=google.com; s=arc-20240605;
        b=HdFm2Fz49e4mUNA1/nOQGEBJsWgQBh0NJR56rKHhMXO6IxHWTNxcNZRRtdQlmoyaBW
         EvRoklF3Y6dW7Ds4w0bSs+TzleAUfzN60bgh6auFdYR186lktoTbud8yZ0DTdPfDHG7m
         EDdRtSwJ1yyzZNXx3k8fqY9NIgxQnvCy1r8eNCQGlgAaxvmP9wG/aIg1N3NncOPOI7GI
         bgUHTBB1QiolZIBX3uki170x9++/tGSqtqKGSy3cAful2KYucKC89y2/tNR34T2xI4+X
         MerPmjNT7BfiI478ml3/OqfxYpo401hvD7/FE+7z4Z5HoDxNXgAfM0I0l+SEdRwxwnQG
         4y/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=o+ybqgoZwawPF95TqOAOO7y+1weufOIC06TusY9kl9k=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=AkXVTKfogGpil6JCb6t3qJ+ncfSzs2vNhrHlsnYOJhrsLPyrF858QszZXwCYBGngA+
         Rc2EzCxW0KqyclE/dNdA78o2I/ZvQt4bAP6QJel4j6be4LcXywcFe66oNJYmLwj96Fww
         RnZ0Xo/ESsa0RaI6PzC9YBk+ovNQFu+nRebcPbPGiQeoCNMw6jrFyClaPlJ20YY2oQLO
         zKur8eI60N1rbFE4aVn8kdRNRn1E6zKS+OYaG5/I8JFYqY0knXdyGG3OiN2nxBsJi9VE
         CeL1F54L8Uix+BXUrNX4iBrAuN6E1ZormNMHW/jyIB8ZJv0t7W1cek+8j9ASxqwhxfYw
         YmfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4804db54901si93065e9.2.2026.01.22.22.53.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:45 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7B7DE5BCD8;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 52B08139E8;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id EMnqE9cac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:11 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:59 +0100
Subject: [PATCH v4 21/22] mm/slub: remove DEACTIVATE_TO_* stat items
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-21-041323d506f7@suse.cz>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
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
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB6VVZTFQMGQEKQ65ASA];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.973];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: E6FD87136E
X-Rspamd-Action: no action

The cpu slabs and their deactivations were removed, so remove the unused
stat items. Weirdly enough the values were also used to control
__add_partial() adding to head or tail of the list, so replace that with
a new enum add_mode, which is cleaner.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Hao Li <hao.li@linux.dev>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 31 +++++++++++++++----------------
 1 file changed, 15 insertions(+), 16 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 3009eb7bd8d2..369fb9bbdb75 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -329,6 +329,11 @@ static void debugfs_slab_add(struct kmem_cache *);
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
@@ -348,8 +353,6 @@ enum stat_item {
 	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
 	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
 	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
-	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
-	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
 	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
 	DEACTIVATE_BYPASS,	/* Implicit deactivation */
 	ORDER_FALLBACK,		/* Number of times fallback was necessary */
@@ -3270,10 +3273,10 @@ static inline void slab_clear_node_partial(struct slab *slab)
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
@@ -3281,10 +3284,10 @@ __add_partial(struct kmem_cache_node *n, struct slab *slab, int tail)
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
@@ -3377,7 +3380,7 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
 	if (slab->inuse == slab->objects)
 		add_full(s, n, slab);
 	else
-		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		add_partial(n, slab, ADD_TO_HEAD);
 
 	inc_slabs_node(s, nid, slab->objects);
 	spin_unlock_irqrestore(&n->list_lock, flags);
@@ -3999,7 +4002,7 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
 			n = get_node(s, slab_nid(slab));
 			spin_lock_irqsave(&n->list_lock, flags);
 		}
-		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		add_partial(n, slab, ADD_TO_HEAD);
 		spin_unlock_irqrestore(&n->list_lock, flags);
 	}
 
@@ -5070,7 +5073,7 @@ static noinline void free_to_partial_list(
 			/* was on full list */
 			remove_full(s, n, slab);
 			if (!slab_free) {
-				add_partial(n, slab, DEACTIVATE_TO_TAIL);
+				add_partial(n, slab, ADD_TO_TAIL);
 				stat(s, FREE_ADD_PARTIAL);
 			}
 		} else if (slab_free) {
@@ -5190,7 +5193,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	 * then add it.
 	 */
 	if (unlikely(was_full)) {
-		add_partial(n, slab, DEACTIVATE_TO_TAIL);
+		add_partial(n, slab, ADD_TO_TAIL);
 		stat(s, FREE_ADD_PARTIAL);
 	}
 	spin_unlock_irqrestore(&n->list_lock, flags);
@@ -6592,7 +6595,7 @@ __refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int mi
 				continue;
 
 			list_del(&slab->slab_list);
-			add_partial(n, slab, DEACTIVATE_TO_HEAD);
+			add_partial(n, slab, ADD_TO_HEAD);
 		}
 
 		spin_unlock_irqrestore(&n->list_lock, flags);
@@ -7059,7 +7062,7 @@ static void early_kmem_cache_node_alloc(int node)
 	 * No locks need to be taken here as it has just been
 	 * initialized and there is no concurrent access.
 	 */
-	__add_partial(n, slab, DEACTIVATE_TO_HEAD);
+	__add_partial(n, slab, ADD_TO_HEAD);
 }
 
 static void free_kmem_cache_nodes(struct kmem_cache *s)
@@ -8751,8 +8754,6 @@ STAT_ATTR(FREE_SLAB, free_slab);
 STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
 STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
 STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
-STAT_ATTR(DEACTIVATE_TO_HEAD, deactivate_to_head);
-STAT_ATTR(DEACTIVATE_TO_TAIL, deactivate_to_tail);
 STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
 STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
 STAT_ATTR(ORDER_FALLBACK, order_fallback);
@@ -8855,8 +8856,6 @@ static struct attribute *slab_attrs[] = {
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-21-041323d506f7%40suse.cz.
