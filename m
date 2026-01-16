Return-Path: <kasan-dev+bncBDXYDPH3S4OBB243VHFQMGQE2BX35OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F939D32C4B
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:44 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-382f31b01basf11043741fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574444; cv=pass;
        d=google.com; s=arc-20240605;
        b=XlcOFVwSlEZfedPwRQIM+DArIeXQr9P6+orhUsgNav15YW+iMug1cobQm1P29IFyXM
         R/rg9X+gOVAAoYrXDWSz/n0BkhQopiBCa6RbaF9SyCpFZfIMcvgJ24biF/i2yEOurSGA
         e01Q6yKXTrqA6ND3EtVea0aNSFkJ1UbbP/2RpbN7+B9qX4iwmsq6P45mqPJOEmaOk6KR
         agoWsPhIQWYUtZgmXcrfGx/iFOLe8LczokFWcGYoTheEFwFdpXp5Ivyz9/SSAofqjxQw
         156E9oagVqyQp6c6/YrqzkPjyC1tY62RcH5kiQ03t1dzggTshZ2j94Pb5NShWPPpwG2g
         Mk+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=i0zmQhPXa9qVDteKvW5b9ZddwTZMOZO+xpCaak25Szs=;
        fh=bT342Wrkxy6k7vK8LLDsGRksa7IG+hdl+FEuyb1bD7k=;
        b=FlZD3w8NPkUAerseFVwutT5LgHllkn3P/utanWuLzOXCeBHjkni5Rxe/gZXnIrA8dq
         lXpNwPIEkk+26vjr6JErBeeUm1+kRwhhxs0CZxGt/yClzGYO2sH7HveeGbMi4a/vVDBd
         ySjumDUiLoT/3LmvqKzdeq83bKUVZLn1HotpTe+Z9d5usY7t0pxc/GZ1VlaRv6XrigbI
         xiplwjRtSGihVyN9TrbhJtpPEqTVtmdno+E9+xpP9LPlj7xXFhIH19bJn0W5hq6oGkIc
         Huq5DsvhXvVb4xHe2sCU9YBNXd0xjjkFG6ZPhHnCGUspTYvE+S15ryIvIguTewFu062H
         eJpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aRo74MpM;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aRo74MpM;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574444; x=1769179244; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i0zmQhPXa9qVDteKvW5b9ZddwTZMOZO+xpCaak25Szs=;
        b=J3PCsBs9MojbWC1edFsz8e1BWvZjZoP6xwt0qD12tUza+VArqwqIhXdO7YW6k1kUcR
         9QAwfsu07IeEUvFnFxd/N5xcx0l2TQNAOBFKgiEnEFtdIO+BrM2Iiox0Redv06a0iKNr
         1QSqR6OWX3fqgUXYP1LNwEsBOjL6u6N69/953wAG9vRQOiXJdewqcFQyMoWA41h3Mqyx
         gXfVDiS6fg4Nd0Tb2J9I0OojkfWoZEeOwiifq9A0olZBBvI+6UIQO4rC6nJfRQIXFnum
         2lmD99aDFhUTorGuB0vHKl2Ln+u44Jok9jws0j7ocW6OLHrY9zX7NCt+Ufo8yNhT8BT1
         daDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574444; x=1769179244;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i0zmQhPXa9qVDteKvW5b9ZddwTZMOZO+xpCaak25Szs=;
        b=p94e7dbFCcOJZ9wLeZ4S8KO7tGage6whsU5iK2qCdzz6AccK06kET0r21Oic6kbou/
         eW/zcBX/vqssce71fIYFThlcSx/lSDCjLrvEUU27ml/oqNy24AmlVmTwIsKvbK6v4ebJ
         i39kINFe99p3+c7jG6pAfVIIYEIKIoyf4Yjs397hdmuWEQCMbWvsnKrSWnz9X8hcoEYF
         7wJiENFqQBb1azdmg8zrtW987H+G2fPc8YUdgs1zYsLEFgW3lwi+2sv6FOpD7fVRp0sO
         wXlS6QwBOuVT+KC4JbPVXaaR4Mht9yLhD859XxW2JT8SsvOgbH8EmplR+j7bTS30cSsO
         vl+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvqmGT2V4KdKK2/W9XQx62GXLlFyfplj2xkTy5bxDWraDGXoZtKulVCBsSoX/D61Z89fGnRg==@lfdr.de
X-Gm-Message-State: AOJu0Yz/foULzm/z2g/IPdrth5UONztlu3CsqdUhkA8PPUv3RbjHGPDa
	yIkChgYSOqECe1TaZa1ibxvwXnAmtQnUQ1cv1Qnp+81JgFTE36Aaz9XK
X-Received: by 2002:a05:651c:1542:b0:382:88f2:fe25 with SMTP id 38308e7fff4ca-3838434633emr8917051fa.45.1768574443721;
        Fri, 16 Jan 2026 06:40:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HUPe/LijuvTfDz4C9RErq9K9HAznkcJ3CPL9bGHg7+cw=="
Received: by 2002:a2e:6e0b:0:b0:382:fcc7:93e4 with SMTP id 38308e7fff4ca-3836ee724b9ls5441651fa.2.-pod-prod-08-eu;
 Fri, 16 Jan 2026 06:40:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFaU5HeRRLcLR/TqIf5b/w5/E0YErCuc7am0krSNYI9hMs6OEM01ZKxVDOh2RTTVGXwZrw0FJvtto=@googlegroups.com
X-Received: by 2002:a05:651c:41c9:b0:37a:2dca:cfaf with SMTP id 38308e7fff4ca-3838427cc0amr10617051fa.20.1768574440743;
        Fri, 16 Jan 2026 06:40:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574440; cv=none;
        d=google.com; s=arc-20240605;
        b=a/cdm7nO3V2htp1vvqA9VIprmW8fnx5nJlcjOCCvCULLRlKll3qt95MPO3VvyIdX2H
         vKDIi/JrdwJm/8YPKyloD3TLgJGKBQ7x0os63P8CMbNE3p8FgzIsn3b4hi+TRpFT9+sP
         UWw/FKoak7uDKFs4G1L9I8aNoSN9TGM/b+e6YhVTtmADXjOmuKdvKSmWQ1vbt++xvQlu
         PwA882iivniTK85EJCi1rjgmL8J5PXOz69TExI8QN0AAq582pP4fvy/Ilh5yfzLLqVcs
         oInAPnkfxLKol3APwmVikb5MD0BSQnkkU7n+gFdp5nfd3cutZ/V4/ty0ZNz//44+MKck
         /PXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=8dPdlHB0y/PWoX5RbcXdAl7xKUlthHXOgepwL2HcwIA=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=IhzrDQURQK6kU9M5BLIAAHTmPtX4V56tTT5Y+dMthL1v4cZP1N3alhhn6bIkNowAnX
         e9Ax4Hdqo3cJ0zI2Udt153r6pkQwgpF8Yb4ib/bkPTx59ABw1JOVf1Gn7pWcZ1Y8m0qh
         sBBbV+IvlkVYHTax/KWvWbI9V/cmaItvgZWYVM1Y+GS6pFydc7peCrmm2TeMrwZuOdkw
         0SD4G/Mf20/oAWBYTyG8N6ANCD2v0EJ8fwnjJfn4iHMM0Ryu8VYT+Vhbpfi9owPsPJ6h
         QL+8fB7BWUZ0e4wwM401oUL4tSfNPmYUJ/muTeJz80y5JJVZsbf8zIEkOfOpDV9m2MCH
         A8cQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aRo74MpM;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aRo74MpM;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d0ff47si558341fa.1.2026.01.16.06.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 297EC5BE82;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0B5F43EA65;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OOSBAuVNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:25 +0100
Subject: [PATCH v3 05/21] slab: add sheaves to most caches
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-5-5595cb000772@suse.cz>
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
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=aRo74MpM;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=aRo74MpM;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

In the first step to replace cpu (partial) slabs with sheaves, enable
sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
and calculate sheaf capacity with a formula that roughly follows the
formula for number of objects in cpu partial slabs in set_cpu_partial().

This should achieve roughly similar contention on the barn spin lock as
there's currently for node list_lock without sheaves, to make
benchmarking results comparable. It can be further tuned later.

Don't enable sheaves for bootstrap caches as that wouldn't work. In
order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
even for !CONFIG_SLAB_OBJ_EXT.

This limitation will be lifted for kmalloc caches after the necessary
bootstrapping changes.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h |  6 ------
 mm/slub.c            | 51 +++++++++++++++++++++++++++++++++++++++++++++++----
 2 files changed, 47 insertions(+), 10 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 2482992248dc..2682ee57ec90 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -57,9 +57,7 @@ enum _slab_flag_bits {
 #endif
 	_SLAB_OBJECT_POISON,
 	_SLAB_CMPXCHG_DOUBLE,
-#ifdef CONFIG_SLAB_OBJ_EXT
 	_SLAB_NO_OBJ_EXT,
-#endif
 	_SLAB_FLAGS_LAST_BIT
 };
 
@@ -238,11 +236,7 @@ enum _slab_flag_bits {
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
 /* Slab created using create_boot_cache */
-#ifdef CONFIG_SLAB_OBJ_EXT
 #define SLAB_NO_OBJ_EXT		__SLAB_FLAG_BIT(_SLAB_NO_OBJ_EXT)
-#else
-#define SLAB_NO_OBJ_EXT		__SLAB_FLAG_UNUSED
-#endif
 
 /*
  * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
diff --git a/mm/slub.c b/mm/slub.c
index 2dda2fc57ced..edf341c87e20 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -7863,6 +7863,48 @@ static void set_cpu_partial(struct kmem_cache *s)
 #endif
 }
 
+static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
+					     struct kmem_cache_args *args)
+
+{
+	unsigned int capacity;
+	size_t size;
+
+
+	if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
+		return 0;
+
+	/* bootstrap caches can't have sheaves for now */
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return 0;
+
+	/*
+	 * For now we use roughly similar formula (divided by two as there are
+	 * two percpu sheaves) as what was used for percpu partial slabs, which
+	 * should result in similar lock contention (barn or list_lock)
+	 */
+	if (s->size >= PAGE_SIZE)
+		capacity = 4;
+	else if (s->size >= 1024)
+		capacity = 12;
+	else if (s->size >= 256)
+		capacity = 26;
+	else
+		capacity = 60;
+
+	/* Increment capacity to make sheaf exactly a kmalloc size bucket */
+	size = struct_size_t(struct slab_sheaf, objects, capacity);
+	size = kmalloc_size_roundup(size);
+	capacity = (size - struct_size_t(struct slab_sheaf, objects, 0)) / sizeof(void *);
+
+	/*
+	 * Respect an explicit request for capacity that's typically motivated by
+	 * expected maximum size of kmem_cache_prefill_sheaf() to not end up
+	 * using low-performance oversize sheaves
+	 */
+	return max(capacity, args->sheaf_capacity);
+}
+
 /*
  * calculate_sizes() determines the order and the distribution of data within
  * a slab object.
@@ -7997,6 +8039,10 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
 	if (s->flags & SLAB_RECLAIM_ACCOUNT)
 		s->allocflags |= __GFP_RECLAIMABLE;
 
+	/* kmalloc caches need extra care to support sheaves */
+	if (!is_kmalloc_cache(s))
+		s->sheaf_capacity = calculate_sheaf_capacity(s, args);
+
 	/*
 	 * Determine the number of objects per slab
 	 */
@@ -8601,15 +8647,12 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 
 	set_cpu_partial(s);
 
-	if (args->sheaf_capacity && !IS_ENABLED(CONFIG_SLUB_TINY)
-					&& !(s->flags & SLAB_DEBUG_FLAGS)) {
+	if (s->sheaf_capacity) {
 		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
 		if (!s->cpu_sheaves) {
 			err = -ENOMEM;
 			goto out;
 		}
-		// TODO: increase capacity to grow slab_sheaf up to next kmalloc size?
-		s->sheaf_capacity = args->sheaf_capacity;
 	}
 
 #ifdef CONFIG_NUMA

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-5-5595cb000772%40suse.cz.
