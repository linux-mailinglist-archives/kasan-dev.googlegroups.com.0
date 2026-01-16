Return-Path: <kasan-dev+bncBDXYDPH3S4OBB443VHFQMGQEFXUNUQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C22AD32C62
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:58 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-59b6c274d69sf1987676e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574452; cv=pass;
        d=google.com; s=arc-20240605;
        b=HAynTdMIiXUSS0DYK21nKw9KrTXqSB+7WGMvwATpl95KH6FvZ7RegCbodRDBSFenPO
         D/0kkLS7oouW0xK9hZgbJACfcBqbLDFJlybB+F+Yk7FBXNQfF/gLwcdiUXChLaNqIxjT
         nwJRNxusC9z+B8H8SW4fWF9JueRsw+849yNbFWQl6PHsGarR1/9/0iVMYZ+MYwbndBW+
         7sfjcJ5aLg1b8uzd85LLxDYMTrRSEmgJuD+HWkKdlLew17tf8mvsq7a9S2ac0pMCMBjt
         QNmBo4YlLGPirYVO9zztuqo9febPvZwRGhLfTzGqq+fJ7MJHdjwfsqd/6FTpbyX7e/GM
         fRxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=6WcofxG4jCFemFXgB/Su6BR1zo13NNxgfqKZYft7E7s=;
        fh=GVAXZoF2+kTzLKG9lfqhSFhB26dYB4/2vRYIhAyzEg0=;
        b=LixGhA7LiuG4XLqffMVuThddwGQivaRnK5eNraK1B+6po0MuQgJ52ly4t6TdGFf7uf
         cQbGJikBRDgIHFrmheD6QnbPeRUGut5/CM447tXyXc+lD5PwnpKByZ9nIga9IiecEEf0
         lwkj1TTasZz3M8AWiZmH5Opl1q7SNQu0bsFMwoCbCoItSFyYhtggvoYuHC+7ijO++j0C
         R8uxKzDJuYy2Yii2wXInvJ7ULUPI691DD2v8H/REwjK5kABfPU1E3prTK6YSjW5LpKlt
         XC90OpbIM9t1n0exotSEp3ZWCFa5U+g7cgpyMO4R4mNTiH0Qo2de/cTeZXi42S7xNIGK
         ZIAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k6hRjn02;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k6hRjn02;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574452; x=1769179252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6WcofxG4jCFemFXgB/Su6BR1zo13NNxgfqKZYft7E7s=;
        b=fiyFL9/2Hioq5LruiIVfggIS8I3f5NTct8Kl19yH+sVPIm5Hp7N5AkD31C+th7fE5e
         uXU5i1xbgtV9wQOLYX/419Q8bMTMfBmpqeRpkEROK738eySpH70GzLBDK1EHkXnzi6ES
         N54bi2KB+La2Q4Q6Ekp9zbjFiJu30Y8rrWAQixpW07isjYrGlUYblLBgulg3jRgRmdPx
         PSRux0PbOLKC2OcJvWWdTkDmMjOS1suv+WurnirYWbhxNUc3eRCZ2M8YKhB/dWwmWEAN
         gNs31pbhXED1rWl3RzKfO9xoWe2DmNHz2TUwDBJ1mwS/1hjN8xKlAi0pbFEI4NSkoJJT
         jVtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574452; x=1769179252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6WcofxG4jCFemFXgB/Su6BR1zo13NNxgfqKZYft7E7s=;
        b=VASO17kPbwwES4HtsAP2JjYQDGgaHEO1jh5o6Li47N+6K11yuxWazKA6P9mfpa2PvZ
         s5Nzgu6AATNXKAVnnGBAQV+BUftmLb2EX2xyZk9cO9akeZ82mQORJuDuYuK88wrTp+6B
         UD7GJdp7rT68qgmeFcY0DbkS27jvj/9nShZ/WbqBTpch4cLgAczXSTo5Dz9vKp1liOoD
         Ehvp/dz0yfg6tMJyl2EJ3X34zLZidji2QK/y7I9/EprdIVp6Pvn2/gEhx++PgGAtsI3+
         nKyldT+jnejkPX9ijAZ8tX63InLA690PuVFbuJs8h/CDyu7aW2RCQT94t2jDEdkbOUR2
         mhEQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmxnNscqINeWeuTMXw9IuUU9GNJ72BqvNGsZ0GIaddSxH6hr/ksIApopJoFc/hnflQZ1M11Q==@lfdr.de
X-Gm-Message-State: AOJu0YzC5QOFN9NbP2TX0r5y2pIi4kTXPNOkkNLrY/FkUNxsa5ZsplS4
	zomtOK8ceAld+Fk6cpDHxXxFRRArUvyVZGmYl8RK3s3Tuj1TAOvDtQt/
X-Received: by 2002:a05:6512:2512:b0:59b:b0e4:87ea with SMTP id 2adb3069b0e04-59bb0e48a07mr844317e87.8.1768574452305;
        Fri, 16 Jan 2026 06:40:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GC1bc5UOhxk3fwJ1UX3jx3BK1LeyDE5/flYabSYW3zjw=="
Received: by 2002:a05:6512:63cf:20b0:595:77b7:5e39 with SMTP id
 2adb3069b0e04-59ba056abd2ls203979e87.0.-pod-prod-00-eu-canary; Fri, 16 Jan
 2026 06:40:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX6VnAiP42pLA8X9lHYOmV+GQDKJnN81Bfg5pugr53SA5FnsbYFLRSVaDYFYtGEz0tu1bxhI7WEjOQ=@googlegroups.com
X-Received: by 2002:a05:651c:2357:20b0:383:227:2891 with SMTP id 38308e7fff4ca-3836ef603efmr18723831fa.4.1768574449572;
        Fri, 16 Jan 2026 06:40:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574449; cv=none;
        d=google.com; s=arc-20240605;
        b=Vd0hDiQOo4k9BP8vcZ4k7qSRoSgIGKjCRKaI226AICT5gaZNKNGaHc9r/23wp1IrQg
         qzAtlIVayx7d8cBt0JFX+vHEFlOoVftupbzdq2DW1tGydXEIMXKy/gV593LRgp5C2MQV
         bNlVGuf4LKqYQDB+JvjFQ5WsWpSwUu1Ui0B2VhW78CqmC/HLAtUJySqAKQzVv+oGP6Tk
         gVUacKeXPeJfoivZNH7B3MChG/AFhN1+VwGaHznjXMTe5wdQ6fOkVUmsnN58LLhVGq9t
         ElEo6C9ebTPwBoUxFRgucGq2Z0J2MjHz6zsu+QLvElrtlbSinT/1rx0p8U/wImoCLb56
         LMFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=en/PV8L5vRbZ1mp+m0UL7Z3JJuIYQSFGAs1yxFq9ZMM=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=Hs7wkrWYyTv5zGcXftyDJtI5o1mJ4tmnIO2FNy0xbj9DcJQYYGM+WMV8D9ndLIqV9e
         /ugSTpJZvMiZqJrM4AtyWF1bDi/ZRDNJ7ZSmB+a1DmytyON3qvxa2WOJZHfHddKzLxfk
         qGOPT4g3zrC/OeI1uF0GgkYAl9n0APs1KTIbQxvGnhMM/sdvle7zT3lqHb0xHBb3uDMG
         5bMoKxPpTAu7mZiEza9rQRA75ILHC/PtE8igSiSjnlUeQWWeMZ+WQ3J+NR7CWp5h3f2F
         Kkjcc358OlZmnmyQLfM3IM0wwuOTXpIi8mq8qZRYXTWuEhiUrmx6BnlEwjd0Vm6ubzNN
         kxhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k6hRjn02;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k6hRjn02;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d0ff47si558381fa.1.2026.01.16.06.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:49 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7CFEA337F4;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5F6B03EA65;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id iCQFF+VNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:28 +0100
Subject: [PATCH v3 08/21] slab: handle kmalloc sheaves bootstrap
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-8-5595cb000772@suse.cz>
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
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=k6hRjn02;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=k6hRjn02;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Enable sheaves for kmalloc caches. For other types than KMALLOC_NORMAL,
we can simply allow them in calculate_sizes() as they are created later
than KMALLOC_NORMAL caches and can allocate sheaves and barns from
those.

For KMALLOC_NORMAL caches we perform additional step after first
creating them without sheaves. Then bootstrap_cache_sheaves() simply
allocates and initializes barns and sheaves and finally sets
s->sheaf_capacity to make them actually used.

Afterwards the only caches left without sheaves (unless SLUB_TINY or
debugging is enabled) are kmem_cache and kmem_cache_node. These are only
used when creating or destroying other kmem_caches. Thus they are not
performance critical and we can simply leave it that way.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 88 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++---
 1 file changed, 84 insertions(+), 4 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index b385247c219f..9bea8a65e510 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2605,7 +2605,8 @@ static void *setup_object(struct kmem_cache *s, void *object)
 	return object;
 }
 
-static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
+static struct slab_sheaf *__alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp,
+					      unsigned int capacity)
 {
 	struct slab_sheaf *sheaf;
 	size_t sheaf_size;
@@ -2623,7 +2624,7 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
 	if (s->flags & SLAB_KMALLOC)
 		gfp |= __GFP_NO_OBJ_EXT;
 
-	sheaf_size = struct_size(sheaf, objects, s->sheaf_capacity);
+	sheaf_size = struct_size(sheaf, objects, capacity);
 	sheaf = kzalloc(sheaf_size, gfp);
 
 	if (unlikely(!sheaf))
@@ -2636,6 +2637,12 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
 	return sheaf;
 }
 
+static inline struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s,
+						   gfp_t gfp)
+{
+	return __alloc_empty_sheaf(s, gfp, s->sheaf_capacity);
+}
+
 static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
 {
 	kfree(sheaf);
@@ -8119,8 +8126,11 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
 	if (s->flags & SLAB_RECLAIM_ACCOUNT)
 		s->allocflags |= __GFP_RECLAIMABLE;
 
-	/* kmalloc caches need extra care to support sheaves */
-	if (!is_kmalloc_cache(s))
+	/*
+	 * For KMALLOC_NORMAL caches we enable sheaves later by
+	 * bootstrap_kmalloc_sheaves() to avoid recursion
+	 */
+	if (!is_kmalloc_normal(s))
 		s->sheaf_capacity = calculate_sheaf_capacity(s, args);
 
 	/*
@@ -8615,6 +8625,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
 	return s;
 }
 
+/*
+ * Finish the sheaves initialization done normally by init_percpu_sheaves() and
+ * init_kmem_cache_nodes(). For normal kmalloc caches we have to bootstrap it
+ * since sheaves and barns are allocated by kmalloc.
+ */
+static void __init bootstrap_cache_sheaves(struct kmem_cache *s)
+{
+	struct kmem_cache_args empty_args = {};
+	unsigned int capacity;
+	bool failed = false;
+	int node, cpu;
+
+	capacity = calculate_sheaf_capacity(s, &empty_args);
+
+	/* capacity can be 0 due to debugging or SLUB_TINY */
+	if (!capacity)
+		return;
+
+	for_each_node_mask(node, slab_nodes) {
+		struct node_barn *barn;
+
+		barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
+
+		if (!barn) {
+			failed = true;
+			goto out;
+		}
+
+		barn_init(barn);
+		get_node(s, node)->barn = barn;
+	}
+
+	for_each_possible_cpu(cpu) {
+		struct slub_percpu_sheaves *pcs;
+
+		pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
+
+		pcs->main = __alloc_empty_sheaf(s, GFP_KERNEL, capacity);
+
+		if (!pcs->main) {
+			failed = true;
+			break;
+		}
+	}
+
+out:
+	/*
+	 * It's still early in boot so treat this like same as a failure to
+	 * create the kmalloc cache in the first place
+	 */
+	if (failed)
+		panic("Out of memory when creating kmem_cache %s\n", s->name);
+
+	s->sheaf_capacity = capacity;
+}
+
+static void __init bootstrap_kmalloc_sheaves(void)
+{
+	enum kmalloc_cache_type type;
+
+	for (type = KMALLOC_NORMAL; type <= KMALLOC_RANDOM_END; type++) {
+		for (int idx = 0; idx < KMALLOC_SHIFT_HIGH + 1; idx++) {
+			if (kmalloc_caches[type][idx])
+				bootstrap_cache_sheaves(kmalloc_caches[type][idx]);
+		}
+	}
+}
+
 void __init kmem_cache_init(void)
 {
 	static __initdata struct kmem_cache boot_kmem_cache,
@@ -8658,6 +8736,8 @@ void __init kmem_cache_init(void)
 	setup_kmalloc_cache_index_table();
 	create_kmalloc_caches();
 
+	bootstrap_kmalloc_sheaves();
+
 	/* Setup random freelists for each cache */
 	init_freelist_randomization();
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-8-5595cb000772%40suse.cz.
