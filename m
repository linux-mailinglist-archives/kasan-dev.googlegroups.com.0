Return-Path: <kasan-dev+bncBDXYDPH3S4OBB2VVZTFQMGQEOZQ7VJI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eJWqGuwac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB2VVZTFQMGQEOZQ7VJI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2131171306
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:32 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-59ddd48f30dsf1147724e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151211; cv=pass;
        d=google.com; s=arc-20240605;
        b=aUoU2QVGQeeocIDF1uHnYMqyIIlODCMSZa9mBuRHuX0GvvR3Lum0Rb6Nl1W4eng2kb
         Bpnir7/9B40gR8A0vboIUPycaOCqG9tRFTe++J8Gck9gzE8yLfDO8U7BhN8Q1BotlHrA
         2o15eTj6c0gvKmwqKklaBIOMH/1+QnTcGT51H5+c87/78yV61FAyUSy5FhSZ8cEsLG3k
         svxfoKGYG/SgCZcUqEnZiUwZNCn4Q24AoVZALhD9wsi1GQ7XhLu/iBXAyJPuEYzCwYIz
         xt3Y8uBiCt/NN3GINlcdzYi+1kNATGPhM4J93VlVeElLOs+JGCyNPkfChFQMTYjP/FNw
         Bx0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=tUgpjfsqTvRKZjXKzBT5tXl1eJ5WH5yI/XBi0PUTR64=;
        fh=Lx8b5rp4JBPtT3SrMHtJpr31LjFzfM/qaSufAcm45cM=;
        b=jQ8ZpRUh20C4vlRhvOYZo0UnGSHYDScKTRCNEBQSBet56BV3L5DxzTt0biMG4ybTyr
         yFAiZolKqfrbYTa1ZL/CiNGD/4rSuQn6nAsTBSEt0khf4snncz8Ab/L7c/xMFE1Olq87
         ZS12b1WQRCkS8FEGPX7j9osRmm+DuJncVn/f/jvouFxK10JJ1rnUZiDPvz5UqcqUBI0I
         pHsYUBdhtm+piGOdC65cm1YZIhZ5IB+FEy2sJ7hA48e/gMm7Ey5CT/O4gHY/18c/UgwI
         5ZZf8qQDih6CKu6qXyxqaoVLrYe92c2hQjQadLlcenEFk8M6bD7j8xuX42jrGO4U7fA7
         aoRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151211; x=1769756011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tUgpjfsqTvRKZjXKzBT5tXl1eJ5WH5yI/XBi0PUTR64=;
        b=mReJi0TlHmoh17XyrcLc3ihZv3ucqXth3z7dMPH+srmnf0vQwFrQFxFtRW7xy1Q0Nd
         /Paw0YNB9CMcPsqJTsgezyGHLz6t2AGWgq80WxRbkZanwXDWfkXI495HbevivWUl6v66
         VMZYNCgnFWMRKGQzMhUL1cDKRZkFw+3IiPrBtJVzYb7EYhBkKW1m8erB49BnQKEU956J
         3UjgLQodtBriankDnAqDNE779nhWatKA/OPU58asOhLRC1KflzHEuvnjBb8rPSEe+Tfg
         J4M6QMejI2Msj1cMtEC/HxZbH02JXoHSRrrdkiizFc8s//o0OrYYv7Au6F/NIZXYf+Dd
         GGXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151211; x=1769756011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tUgpjfsqTvRKZjXKzBT5tXl1eJ5WH5yI/XBi0PUTR64=;
        b=GC1TGQqPYUgeJQ+ytVhMBFlOT6+WvJstPNwOqf6dL5XdQI6pjb1+j/lGdEbjTzb8XC
         NHjGBBcb1ATpSb5ldnejFu7eJC3R3nRxwKPiue7qRyjYg9Hhk7GyfM9SKXzYXaXSlaL7
         EhWTTe5HloC+whf5dsFQES0e3MndQUj+cDXUXSC3XaTrYbFO0TYEIc3BOlrGZL7mFXvQ
         JmK8vDAVz3+r64XYs2n0htbmLLAw7AC9aY52iB0InQvLoSV+zrlMQZjp31Hyas49JoG7
         cXeDOo4qt56oIBKPfdVWoeYOyQ6mYXstNP/VSQuik4eKLozsjtLrtFStVOVvgrgTJGOG
         m32w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsT4MVTfQLqWAq1HK0FFKIVNTi1wa7bkcicYm3/9wwxlruMS+hF2HIzoTXrE0Wjmq9ZXC4iQ==@lfdr.de
X-Gm-Message-State: AOJu0YyxzCqBxGXUmOCF9RJu6L1kbxHmvoSP5vEd9Ry6B58ZSQ1NaKUC
	0CFlu+bDI4dwRIm3Kx/+eiM+CCkfHFnFiEMtLL9PRMD6VIddY/NUaCB7
X-Received: by 2002:a05:6512:ba5:b0:59d:e3bc:4c96 with SMTP id 2adb3069b0e04-59de816c7b5mr147020e87.43.1769151211222;
        Thu, 22 Jan 2026 22:53:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GRCaSIma8EosVE6lMq+8fjozYYrZOTZ6hITKVABPnNeg=="
Received: by 2002:a05:6512:2313:b0:59b:a3bb:9e0f with SMTP id
 2adb3069b0e04-59dd797f506ls670631e87.2.-pod-prod-01-eu; Thu, 22 Jan 2026
 22:53:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUTnYw0+Gn2rnEBB++ZDh0vtmorMy5VU11X8GO4f6nnKX8xCKIh7x3oV+kt5Ii3zmlByqmfoICxpKo=@googlegroups.com
X-Received: by 2002:a05:6512:2389:b0:59d:e65e:b38d with SMTP id 2adb3069b0e04-59de816f8ffmr141406e87.45.1769151208267;
        Thu, 22 Jan 2026 22:53:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151208; cv=none;
        d=google.com; s=arc-20240605;
        b=QowKhFo31L8EEIUSP3y4BsHaK2wHZ2FuypKvCY/ylDmTDWQEkYfhDtfHvclj5mK8ey
         YOG2GMZ1E478bIxahquG8MIzuD+ZoFxWj6hQsZBAA5AeQ455wsqRhdW3+TGAXi9V92JX
         iXTuihsdqSTGjmfWzCSCuoVzJZo3I+bYUYxlwklTOw1d58QOba8gWoVYQMTK5y3s9lbl
         xwMS1u8ZZbaPBqdlE8+SW/sxqkvks3l9negZ1mLTpYIhLd6hirdx8j6WFMqWQRgn/b9Q
         24ObSQXcMtzPhk9kBea2h+PNM82hG96ir8C3iNPYRwtJ0v/hx5PxCTxo0eyWdjWP0HLm
         tUhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=pd9NhgTxEwmbln0uzdMB8QcqXtQLYyQ8wYbEE2RoEbc=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=e40VkvC5GFyyA9L/FhhWHvzQq0v0THlUZMCCaGQAisJtZ6D20jI/iAxCZPIF7KfMX+
         lcIceEw0wxseUla8jQH5hfKt8AEYReglu4Exq4OpvGmY7E4XQRqM9x0Zjll8BGoXHzBo
         slMrK/AnZqlDG9tXC+I08YQq9UMk5OHWrlnPq8cF6V9YAjR8JBnZN2Jgd7nQmjT5cWa2
         oYE0wf5L6PwhETwRY/aZ/1zCjl4LONmB6MXwLL9r9XADQJSj69gbuTrd65LXhIOfVa+W
         bx5wZwGNLZn4+WAWHOSc8f5rV1afUMB3U0qar79vnbH5VA4Ru8Hygx4if1l0yxON3HYu
         v7EQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385da117ea3si291521fa.7.2026.01.22.22.53.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:28 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id D7A6733778;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 62858139F3;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CDDJF9Yac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:50 +0100
Subject: [PATCH v4 12/22] slab: remove SLUB_CPU_PARTIAL
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-12-041323d506f7@suse.cz>
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
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB2VVZTFQMGQEOZQ7VJI];
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
	NEURAL_HAM(-0.00)[-0.976];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,suse.cz:mid,suse.cz:email,mail-lf1-x13b.google.com:helo,mail-lf1-x13b.google.com:rdns]
X-Rspamd-Queue-Id: 2131171306
X-Rspamd-Action: no action

We have removed the partial slab usage from allocation paths. Now remove
the whole config option and associated code.

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Reviewed-by: Hao Li <hao.li@linux.dev>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/Kconfig |  11 ---
 mm/slab.h  |  29 ------
 mm/slub.c  | 321 ++++---------------------------------------------------------
 3 files changed, 19 insertions(+), 342 deletions(-)

diff --git a/mm/Kconfig b/mm/Kconfig
index bd0ea5454af8..08593674cd20 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -247,17 +247,6 @@ config SLUB_STATS
 	  out which slabs are relevant to a particular load.
 	  Try running: slabinfo -DA
 
-config SLUB_CPU_PARTIAL
-	default y
-	depends on SMP && !SLUB_TINY
-	bool "Enable per cpu partial caches"
-	help
-	  Per cpu partial caches accelerate objects allocation and freeing
-	  that is local to a processor at the price of more indeterminism
-	  in the latency of the free. On overflow these caches will be cleared
-	  which requires the taking of locks that may cause latency spikes.
-	  Typically one would choose no for a realtime system.
-
 config RANDOM_KMALLOC_CACHES
 	default n
 	depends on !SLUB_TINY
diff --git a/mm/slab.h b/mm/slab.h
index a20a6af6e0ef..0fbe13bec864 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -77,12 +77,6 @@ struct slab {
 					struct llist_node llnode;
 					void *flush_freelist;
 				};
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-				struct {
-					struct slab *next;
-					int slabs;	/* Nr of slabs left */
-				};
-#endif
 			};
 			/* Double-word boundary */
 			struct freelist_counters;
@@ -188,23 +182,6 @@ static inline size_t slab_size(const struct slab *slab)
 	return PAGE_SIZE << slab_order(slab);
 }
 
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-#define slub_percpu_partial(c)			((c)->partial)
-
-#define slub_set_percpu_partial(c, p)		\
-({						\
-	slub_percpu_partial(c) = (p)->next;	\
-})
-
-#define slub_percpu_partial_read_once(c)	READ_ONCE(slub_percpu_partial(c))
-#else
-#define slub_percpu_partial(c)			NULL
-
-#define slub_set_percpu_partial(c, p)
-
-#define slub_percpu_partial_read_once(c)	NULL
-#endif // CONFIG_SLUB_CPU_PARTIAL
-
 /*
  * Word size structure that can be atomically updated or read and that
  * contains both the order and the number of objects that a slab of the
@@ -228,12 +205,6 @@ struct kmem_cache {
 	unsigned int object_size;	/* Object size without metadata */
 	struct reciprocal_value reciprocal_size;
 	unsigned int offset;		/* Free pointer offset */
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	/* Number of per cpu partial objects to keep around */
-	unsigned int cpu_partial;
-	/* Number of per cpu partial slabs to keep around */
-	unsigned int cpu_partial_slabs;
-#endif
 	unsigned int sheaf_capacity;
 	struct kmem_cache_order_objects oo;
 
diff --git a/mm/slub.c b/mm/slub.c
index 3a78cee811cf..914b51aedb25 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -268,15 +268,6 @@ void *fixup_red_left(struct kmem_cache *s, void *p)
 	return p;
 }
 
-static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
-{
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	return !kmem_cache_debug(s);
-#else
-	return false;
-#endif
-}
-
 /*
  * Issues still to be resolved:
  *
@@ -431,9 +422,6 @@ struct freelist_tid {
 struct kmem_cache_cpu {
 	struct freelist_tid;
 	struct slab *slab;	/* The slab from which we are allocating */
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	struct slab *partial;	/* Partially allocated slabs */
-#endif
 	local_trylock_t lock;	/* Protects the fields above */
 #ifdef CONFIG_SLUB_STATS
 	unsigned int stat[NR_SLUB_STAT_ITEMS];
@@ -666,29 +654,6 @@ static inline unsigned int oo_objects(struct kmem_cache_order_objects x)
 	return x.x & OO_MASK;
 }
 
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-static void slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
-{
-	unsigned int nr_slabs;
-
-	s->cpu_partial = nr_objects;
-
-	/*
-	 * We take the number of objects but actually limit the number of
-	 * slabs on the per cpu partial list, in order to limit excessive
-	 * growth of the list. For simplicity we assume that the slabs will
-	 * be half-full.
-	 */
-	nr_slabs = DIV_ROUND_UP(nr_objects * 2, oo_objects(s->oo));
-	s->cpu_partial_slabs = nr_slabs;
-}
-#elif defined(SLAB_SUPPORTS_SYSFS)
-static inline void
-slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
-{
-}
-#endif /* CONFIG_SLUB_CPU_PARTIAL */
-
 /*
  * If network-based swap is enabled, slub must keep track of whether memory
  * were allocated from pfmemalloc reserves.
@@ -3476,12 +3441,6 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
 	return object;
 }
 
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-static void put_cpu_partial(struct kmem_cache *s, struct slab *slab, int drain);
-#else
-static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
-				   int drain) { }
-#endif
 static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
 
 static bool get_partial_node_bulk(struct kmem_cache *s,
@@ -3894,131 +3853,6 @@ static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
 #define local_unlock_cpu_slab(s, flags)	\
 	local_unlock_irqrestore(&(s)->cpu_slab->lock, flags)
 
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-static void __put_partials(struct kmem_cache *s, struct slab *partial_slab)
-{
-	struct kmem_cache_node *n = NULL, *n2 = NULL;
-	struct slab *slab, *slab_to_discard = NULL;
-	unsigned long flags = 0;
-
-	while (partial_slab) {
-		slab = partial_slab;
-		partial_slab = slab->next;
-
-		n2 = get_node(s, slab_nid(slab));
-		if (n != n2) {
-			if (n)
-				spin_unlock_irqrestore(&n->list_lock, flags);
-
-			n = n2;
-			spin_lock_irqsave(&n->list_lock, flags);
-		}
-
-		if (unlikely(!slab->inuse && n->nr_partial >= s->min_partial)) {
-			slab->next = slab_to_discard;
-			slab_to_discard = slab;
-		} else {
-			add_partial(n, slab, DEACTIVATE_TO_TAIL);
-			stat(s, FREE_ADD_PARTIAL);
-		}
-	}
-
-	if (n)
-		spin_unlock_irqrestore(&n->list_lock, flags);
-
-	while (slab_to_discard) {
-		slab = slab_to_discard;
-		slab_to_discard = slab_to_discard->next;
-
-		stat(s, DEACTIVATE_EMPTY);
-		discard_slab(s, slab);
-		stat(s, FREE_SLAB);
-	}
-}
-
-/*
- * Put all the cpu partial slabs to the node partial list.
- */
-static void put_partials(struct kmem_cache *s)
-{
-	struct slab *partial_slab;
-	unsigned long flags;
-
-	local_lock_irqsave(&s->cpu_slab->lock, flags);
-	partial_slab = this_cpu_read(s->cpu_slab->partial);
-	this_cpu_write(s->cpu_slab->partial, NULL);
-	local_unlock_irqrestore(&s->cpu_slab->lock, flags);
-
-	if (partial_slab)
-		__put_partials(s, partial_slab);
-}
-
-static void put_partials_cpu(struct kmem_cache *s,
-			     struct kmem_cache_cpu *c)
-{
-	struct slab *partial_slab;
-
-	partial_slab = slub_percpu_partial(c);
-	c->partial = NULL;
-
-	if (partial_slab)
-		__put_partials(s, partial_slab);
-}
-
-/*
- * Put a slab into a partial slab slot if available.
- *
- * If we did not find a slot then simply move all the partials to the
- * per node partial list.
- */
-static void put_cpu_partial(struct kmem_cache *s, struct slab *slab, int drain)
-{
-	struct slab *oldslab;
-	struct slab *slab_to_put = NULL;
-	unsigned long flags;
-	int slabs = 0;
-
-	local_lock_cpu_slab(s, flags);
-
-	oldslab = this_cpu_read(s->cpu_slab->partial);
-
-	if (oldslab) {
-		if (drain && oldslab->slabs >= s->cpu_partial_slabs) {
-			/*
-			 * Partial array is full. Move the existing set to the
-			 * per node partial list. Postpone the actual unfreezing
-			 * outside of the critical section.
-			 */
-			slab_to_put = oldslab;
-			oldslab = NULL;
-		} else {
-			slabs = oldslab->slabs;
-		}
-	}
-
-	slabs++;
-
-	slab->slabs = slabs;
-	slab->next = oldslab;
-
-	this_cpu_write(s->cpu_slab->partial, slab);
-
-	local_unlock_cpu_slab(s, flags);
-
-	if (slab_to_put) {
-		__put_partials(s, slab_to_put);
-		stat(s, CPU_PARTIAL_DRAIN);
-	}
-}
-
-#else	/* CONFIG_SLUB_CPU_PARTIAL */
-
-static inline void put_partials(struct kmem_cache *s) { }
-static inline void put_partials_cpu(struct kmem_cache *s,
-				    struct kmem_cache_cpu *c) { }
-
-#endif	/* CONFIG_SLUB_CPU_PARTIAL */
-
 static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
 {
 	unsigned long flags;
@@ -4056,8 +3890,6 @@ static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
 		deactivate_slab(s, slab, freelist);
 		stat(s, CPUSLAB_FLUSH);
 	}
-
-	put_partials_cpu(s, c);
 }
 
 static inline void flush_this_cpu_slab(struct kmem_cache *s)
@@ -4066,15 +3898,13 @@ static inline void flush_this_cpu_slab(struct kmem_cache *s)
 
 	if (c->slab)
 		flush_slab(s, c);
-
-	put_partials(s);
 }
 
 static bool has_cpu_slab(int cpu, struct kmem_cache *s)
 {
 	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
 
-	return c->slab || slub_percpu_partial(c);
+	return c->slab;
 }
 
 static bool has_pcs_used(int cpu, struct kmem_cache *s)
@@ -5652,13 +5482,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		return;
 	}
 
-	/*
-	 * It is enough to test IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) below
-	 * instead of kmem_cache_has_cpu_partial(s), because kmem_cache_debug(s)
-	 * is the only other reason it can be false, and it is already handled
-	 * above.
-	 */
-
 	do {
 		if (unlikely(n)) {
 			spin_unlock_irqrestore(&n->list_lock, flags);
@@ -5683,26 +5506,19 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		 * Unless it's frozen.
 		 */
 		if ((!new.inuse || was_full) && !was_frozen) {
+
+			n = get_node(s, slab_nid(slab));
 			/*
-			 * If slab becomes non-full and we have cpu partial
-			 * lists, we put it there unconditionally to avoid
-			 * taking the list_lock. Otherwise we need it.
+			 * Speculatively acquire the list_lock.
+			 * If the cmpxchg does not succeed then we may
+			 * drop the list_lock without any processing.
+			 *
+			 * Otherwise the list_lock will synchronize with
+			 * other processors updating the list of slabs.
 			 */
-			if (!(IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && was_full)) {
-
-				n = get_node(s, slab_nid(slab));
-				/*
-				 * Speculatively acquire the list_lock.
-				 * If the cmpxchg does not succeed then we may
-				 * drop the list_lock without any processing.
-				 *
-				 * Otherwise the list_lock will synchronize with
-				 * other processors updating the list of slabs.
-				 */
-				spin_lock_irqsave(&n->list_lock, flags);
-
-				on_node_partial = slab_test_node_partial(slab);
-			}
+			spin_lock_irqsave(&n->list_lock, flags);
+
+			on_node_partial = slab_test_node_partial(slab);
 		}
 
 	} while (!slab_update_freelist(s, slab, &old, &new, "__slab_free"));
@@ -5715,13 +5531,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 			 * activity can be necessary.
 			 */
 			stat(s, FREE_FROZEN);
-		} else if (IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && was_full) {
-			/*
-			 * If we started with a full slab then put it onto the
-			 * per cpu partial list.
-			 */
-			put_cpu_partial(s, slab, 1);
-			stat(s, CPU_PARTIAL_FREE);
 		}
 
 		/*
@@ -5750,10 +5559,9 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 
 	/*
 	 * Objects left in the slab. If it was not on the partial list before
-	 * then add it. This can only happen when cache has no per cpu partial
-	 * list otherwise we would have put it there.
+	 * then add it.
 	 */
-	if (!IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && unlikely(was_full)) {
+	if (unlikely(was_full)) {
 		add_partial(n, slab, DEACTIVATE_TO_TAIL);
 		stat(s, FREE_ADD_PARTIAL);
 	}
@@ -6419,8 +6227,8 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 		if (unlikely(!allow_spin)) {
 			/*
 			 * __slab_free() can locklessly cmpxchg16 into a slab,
-			 * but then it might need to take spin_lock or local_lock
-			 * in put_cpu_partial() for further processing.
+			 * but then it might need to take spin_lock
+			 * for further processing.
 			 * Avoid the complexity and simply add to a deferred list.
 			 */
 			defer_free(s, head);
@@ -7734,39 +7542,6 @@ static int init_kmem_cache_nodes(struct kmem_cache *s)
 	return 1;
 }
 
-static void set_cpu_partial(struct kmem_cache *s)
-{
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	unsigned int nr_objects;
-
-	/*
-	 * cpu_partial determined the maximum number of objects kept in the
-	 * per cpu partial lists of a processor.
-	 *
-	 * Per cpu partial lists mainly contain slabs that just have one
-	 * object freed. If they are used for allocation then they can be
-	 * filled up again with minimal effort. The slab will never hit the
-	 * per node partial lists and therefore no locking will be required.
-	 *
-	 * For backwards compatibility reasons, this is determined as number
-	 * of objects, even though we now limit maximum number of pages, see
-	 * slub_set_cpu_partial()
-	 */
-	if (!kmem_cache_has_cpu_partial(s))
-		nr_objects = 0;
-	else if (s->size >= PAGE_SIZE)
-		nr_objects = 6;
-	else if (s->size >= 1024)
-		nr_objects = 24;
-	else if (s->size >= 256)
-		nr_objects = 52;
-	else
-		nr_objects = 120;
-
-	slub_set_cpu_partial(s, nr_objects);
-#endif
-}
-
 static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
 					     struct kmem_cache_args *args)
 
@@ -8627,8 +8402,6 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 	s->min_partial = min_t(unsigned long, MAX_PARTIAL, ilog2(s->size) / 2);
 	s->min_partial = max_t(unsigned long, MIN_PARTIAL, s->min_partial);
 
-	set_cpu_partial(s);
-
 	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
 	if (!s->cpu_sheaves) {
 		err = -ENOMEM;
@@ -8992,20 +8765,6 @@ static ssize_t show_slab_objects(struct kmem_cache *s,
 			total += x;
 			nodes[node] += x;
 
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-			slab = slub_percpu_partial_read_once(c);
-			if (slab) {
-				node = slab_nid(slab);
-				if (flags & SO_TOTAL)
-					WARN_ON_ONCE(1);
-				else if (flags & SO_OBJECTS)
-					WARN_ON_ONCE(1);
-				else
-					x = data_race(slab->slabs);
-				total += x;
-				nodes[node] += x;
-			}
-#endif
 		}
 	}
 
@@ -9140,12 +8899,7 @@ SLAB_ATTR(min_partial);
 
 static ssize_t cpu_partial_show(struct kmem_cache *s, char *buf)
 {
-	unsigned int nr_partial = 0;
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	nr_partial = s->cpu_partial;
-#endif
-
-	return sysfs_emit(buf, "%u\n", nr_partial);
+	return sysfs_emit(buf, "0\n");
 }
 
 static ssize_t cpu_partial_store(struct kmem_cache *s, const char *buf,
@@ -9157,11 +8911,9 @@ static ssize_t cpu_partial_store(struct kmem_cache *s, const char *buf,
 	err = kstrtouint(buf, 10, &objects);
 	if (err)
 		return err;
-	if (objects && !kmem_cache_has_cpu_partial(s))
+	if (objects)
 		return -EINVAL;
 
-	slub_set_cpu_partial(s, objects);
-	flush_all(s);
 	return length;
 }
 SLAB_ATTR(cpu_partial);
@@ -9200,42 +8952,7 @@ SLAB_ATTR_RO(objects_partial);
 
 static ssize_t slabs_cpu_partial_show(struct kmem_cache *s, char *buf)
 {
-	int objects = 0;
-	int slabs = 0;
-	int cpu __maybe_unused;
-	int len = 0;
-
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	for_each_online_cpu(cpu) {
-		struct slab *slab;
-
-		slab = slub_percpu_partial(per_cpu_ptr(s->cpu_slab, cpu));
-
-		if (slab)
-			slabs += data_race(slab->slabs);
-	}
-#endif
-
-	/* Approximate half-full slabs, see slub_set_cpu_partial() */
-	objects = (slabs * oo_objects(s->oo)) / 2;
-	len += sysfs_emit_at(buf, len, "%d(%d)", objects, slabs);
-
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	for_each_online_cpu(cpu) {
-		struct slab *slab;
-
-		slab = slub_percpu_partial(per_cpu_ptr(s->cpu_slab, cpu));
-		if (slab) {
-			slabs = data_race(slab->slabs);
-			objects = (slabs * oo_objects(s->oo)) / 2;
-			len += sysfs_emit_at(buf, len, " C%d=%d(%d)",
-					     cpu, objects, slabs);
-		}
-	}
-#endif
-	len += sysfs_emit_at(buf, len, "\n");
-
-	return len;
+	return sysfs_emit(buf, "0(0)\n");
 }
 SLAB_ATTR_RO(slabs_cpu_partial);
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-12-041323d506f7%40suse.cz.
