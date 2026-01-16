Return-Path: <kasan-dev+bncBDXYDPH3S4OBB6M3VHFQMGQE5N2RHLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 64BA6D32C6E
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:58 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-655b10ed8d1sf646473a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574458; cv=pass;
        d=google.com; s=arc-20240605;
        b=kBMnD2X1Po8Zrm7hU+MNi9FO9Q+Nd2imG2aXkO9IUIEyE946yqQohl3T2vwjk1CoYz
         x/NN/8ztmaXL4wTp+b68dEqXVQLt93OPnoEZ5ifS74bdjWEHW30WqUu0yvu9g4W5RBu1
         0Tjd7/RjEARfwV0dBHcZYmbhuCxPXQx2w/MPPMT+9+TU86WxoKPRpHtJ1Gve2E8rKgOj
         Zg+/UHYARJpSBuSAE3MPrttLI8pYKP2iKtVhlsGcqzC/ldRQFd0yGZR1j77w6aLwAvBT
         gi1jr0tmoY9x4perDN6Grgne6Mb0R4ACONBp8CADfcpfGHaVqXi6ZARkSLw3e5KEpudq
         AszA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=iRl++cT3ucLhLrZj3n84ZOu7i9UydZMjJ3c1yPsBnM0=;
        fh=tuQ9eJbcBmi5fRqnbXaa6WxZXd4TVk75DWJCenLiJCM=;
        b=PVfc3ZCXF8qfyLqpPkZEl+3eVoXJvX4bZK4w3QFWgQl5ZL6tZeJxAIdvEIQ8QVPgUo
         f+mnR5Zy+XPAktceWgzCk7D4ZlHaDKCBkLY4+B1ZEUBHljB+5/NJXbM/yciv+IDzfyzM
         rq5kseoM+L+Gbl+uX9zjbX/IwI+3d9obQcKY0pjxpCAMJiBL711vpVrydHrdqXg0oZ8c
         kXbMJiO9OMkMcPmbgwMUH4TPS1rfrg5Zi7b38JABUFo82FeFQ5z+BxMYXMK5wdj7ykxB
         7l+miGPvmh5gWVX2CXC1/7C0NupF5olthSNAFVqAym7x7ysVMLwy1g9A69S6Y/WjHr9Y
         AvuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WuCIu3ap;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WuCIu3ap;
       dkim=neutral (no key) header.i=@suse.cz header.b=GRQGqbgi;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574458; x=1769179258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iRl++cT3ucLhLrZj3n84ZOu7i9UydZMjJ3c1yPsBnM0=;
        b=LtZOCwdF5lyvBGOBtzQShuOfoqEHMkfBBYL1hzi9u1KwX6UQ7v3HmaHPtY9wgFtZQV
         qQR/BL9sRQDWNCnonenI1TBq5S0LymepcjEkcmj+VvbTtOCIXJcPdZzEBVUY//iZQqq6
         hvHt8FDlk4uM2dEMJyT8HNtxfNg/MgNe6xO1zLSNypfHOIoSk2ibgZk17s4FpmDFWoRi
         MutevDs2SgwsLiu0cihzfV883GZr//0HvFwb7koU2Ec9OjaQjHW07kIm4yMxnX7BHa89
         ofiLzwyuwLajrJTgJqHyytWvKjR7FO4l0t8xG4Nn83bn8ims8tVAoGSkbC1G4JsJvlZ0
         v+rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574458; x=1769179258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iRl++cT3ucLhLrZj3n84ZOu7i9UydZMjJ3c1yPsBnM0=;
        b=SeeEO5GtlmO14KkwUkbjutsV6Aa46Kh3f/cbCEG7SYVNZXOKwpd68/ybiyf13wmfCW
         eW+OGLQ2bcc1gl2wKczEBLPKAB3Lo7euIr63Fj13CbpQ9VMC3cIKz9YHSJ8Du52LFfeU
         RspfC3hvE0Du1T4MnybJIoB11j6+AGClswU2dslpRfZjg86jo3VQYCGeJsvJMkX/DEvW
         5UZIyZuZ8uuF/M1XTPYoE0Tht9INJuOdHD+LNROS8mgU0UtIBoK0FCRPSa/eKR6C3o66
         jqbBvYAGTrHD8Fh6ezOxNhq/enwwC6tr2+8652I11ryLzG3NneK3BdnhL/+tRPAAO/D3
         1etw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQn4l0pgkImmN6Woh+VOrOTwKzMObYQNkxni4w7Eiu28sdiK6j6H2bMkmAnI30fTlVBW/DNw==@lfdr.de
X-Gm-Message-State: AOJu0YzFKmvn9EBfYGhh9tLdd7+89pBdSBDQTqB5ICQ6Wa1qq58JyGot
	D+pkVdo1aFzCYHcnl7axzoSsgaodmLFf9Su1paFrie837+mHRuwNRe9c
X-Received: by 2002:a05:6402:52:b0:649:19bf:bba1 with SMTP id 4fb4d7f45d1cf-654132928ccmr3932471a12.17.1768574457623;
        Fri, 16 Jan 2026 06:40:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HMN59XlRuZ6V4I7FJWuU6U3I1OygW19YAp9WNAFjx9mw=="
Received: by 2002:a05:6402:3256:20b0:64b:6e67:b69c with SMTP id
 4fb4d7f45d1cf-653ea29b65cls2028932a12.2.-pod-prod-00-eu-canary; Fri, 16 Jan
 2026 06:40:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7MYpO8JbR4qZfqvia/V19ECHUDdj/J9911jazvfObf/Q65tmvUwD8zKZrg968yklPWgExHLvyQvk=@googlegroups.com
X-Received: by 2002:a17:907:7854:b0:b80:1403:764c with SMTP id a640c23a62f3a-b8777c1a340mr394635866b.24.1768574455298;
        Fri, 16 Jan 2026 06:40:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574455; cv=none;
        d=google.com; s=arc-20240605;
        b=TGdsoMVUzhsQny86sdS6FJVYP5U+XRXPO4Ub3bcI/h6JpjuZXlD14pZo9JfgwyqO4Y
         CTVZ3xr5+x3XEoXTn6ZiIsndoyy/81eYgQJ83SRVvQOR6zKbcXD2I3A/Z0lEVf39PGfO
         4ThMXjv2iATDHrY4pss2tTRc6DTmoT5iHQGf2ORx0xbgdbZbX6dCqTPywWbf5recSuEM
         gs5HE59MRlXagrUPs5eEBBwI2hcQ4xhcL6KNCOL4ha+bQHohXdzBOMp4LKmOJOgr2DJ/
         MbwfuVufRSDCADPYRaD1Nxi/I4KoEzHgYfbIHwjMj5pVlwMsraGohZ3g73RVHhbsAnHP
         Ww0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=s+NEFIplY8DiruHyzDBaJMFyS25WmDkj2WChHn+qGs4=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=cTln9cI+a9Lr35GcRC75ZrWGiU/00efWGFvPqw48Buy9GFnlco6lpT5j6pBi91z2RO
         90znLrdN889GqAPSf7o/nWk7TrDn9qX+JWls7QqvrYeX2KAl0WXKRTzPCm2ND3EYNX/0
         YSZO0AdtMh/pQMbhZVBynQFkYaZEb+YDsZsEFMOHHY5xv8Bz/c/472Yz7759Hlmo9QU7
         E++M2McL+QyYWjNych9gHz8zjfnmfldZvlnJflxk1FMZWxbYsEwNiIPpj4kxcCNLI7GB
         LmujdEtQiNq9SCZSbqnWVAZk1As4owflAifsBqgJ1t7SgW/bU5W+pXIbkNBX2oi7cldz
         wGSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WuCIu3ap;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WuCIu3ap;
       dkim=neutral (no key) header.i=@suse.cz header.b=GRQGqbgi;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65452cca91fsi40106a12.2.2026.01.16.06.40.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:55 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id D2084337F9;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B4ADB3EA65;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id wB3TK+VNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:31 +0100
Subject: [PATCH v3 11/21] slab: remove SLUB_CPU_PARTIAL
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz>
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
X-Spam-Score: -4.51
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: D2084337F9
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=WuCIu3ap;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=WuCIu3ap;       dkim=neutral (no key)
 header.i=@suse.cz header.b=GRQGqbgi;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

We have removed the partial slab usage from allocation paths. Now remove
the whole config option and associated code.

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
index cb48ce5014ba..e77260720994 100644
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
index 698c0d940f06..6b1280f7900a 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -263,15 +263,6 @@ void *fixup_red_left(struct kmem_cache *s, void *p)
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
@@ -426,9 +417,6 @@ struct freelist_tid {
 struct kmem_cache_cpu {
 	struct freelist_tid;
 	struct slab *slab;	/* The slab from which we are allocating */
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	struct slab *partial;	/* Partially allocated slabs */
-#endif
 	local_trylock_t lock;	/* Protects the fields above */
 #ifdef CONFIG_SLUB_STATS
 	unsigned int stat[NR_SLUB_STAT_ITEMS];
@@ -673,29 +661,6 @@ static inline unsigned int oo_objects(struct kmem_cache_order_objects x)
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
@@ -3474,12 +3439,6 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
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
@@ -3898,131 +3857,6 @@ static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
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
@@ -4060,8 +3894,6 @@ static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
 		deactivate_slab(s, slab, freelist);
 		stat(s, CPUSLAB_FLUSH);
 	}
-
-	put_partials_cpu(s, c);
 }
 
 static inline void flush_this_cpu_slab(struct kmem_cache *s)
@@ -4070,15 +3902,13 @@ static inline void flush_this_cpu_slab(struct kmem_cache *s)
 
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
@@ -5646,13 +5476,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
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
@@ -5677,26 +5500,19 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
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
@@ -5709,13 +5525,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
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
@@ -5744,10 +5553,9 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 
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
@@ -6396,8 +6204,8 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
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
@@ -7707,39 +7515,6 @@ static int init_kmem_cache_nodes(struct kmem_cache *s)
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
 
@@ -8595,8 +8370,6 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 	s->min_partial = min_t(unsigned long, MAX_PARTIAL, ilog2(s->size) / 2);
 	s->min_partial = max_t(unsigned long, MIN_PARTIAL, s->min_partial);
 
-	set_cpu_partial(s);
-
 	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
 	if (!s->cpu_sheaves) {
 		err = -ENOMEM;
@@ -8960,20 +8733,6 @@ static ssize_t show_slab_objects(struct kmem_cache *s,
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
 
@@ -9108,12 +8867,7 @@ SLAB_ATTR(min_partial);
 
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
@@ -9125,11 +8879,9 @@ static ssize_t cpu_partial_store(struct kmem_cache *s, const char *buf,
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
@@ -9168,42 +8920,7 @@ SLAB_ATTR_RO(objects_partial);
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-11-5595cb000772%40suse.cz.
