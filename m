Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXWTXCVQMGQETX5C26Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3154E803E73
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Dec 2023 20:34:56 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-54c6e10230esf2436a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Dec 2023 11:34:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701718495; cv=pass;
        d=google.com; s=arc-20160816;
        b=WfS7UMm01z/kN/5KHRYbJXFpDD/61+XlJ9FF1He4xMj49lYpvZ/LITAV0OrCuqVz2v
         e0G5J+Q3DtO8cB89u7jlYT+FiX0CdqIHw27+LDxfPb5x0WWakRTGot8NCsiIeVOa05vz
         qKOvMicUfzLFlKGht7lstvk2KU04zTj8T0buZMYTQamyiElVbHInZY4y40PJewvpDxSS
         e2XG/RlBg7IKLodbsmUZ5LGSOpKY2aJpZevQmll9rqi5DnbgHMMWT1MdE68/p2wSjv3O
         gzLGpo9nQmcYpoC6It20zHMXTjBsREULw4voomGfj4s+GfhGMxkw5kPD3s0NMQUZ10My
         kTig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=WuIO1ZcA9qjBUieLKNR4NydqRbkN2Y9Mrw2MbCRgZRU=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=Hg4SVM8yKs6F5r9oda6UtCY0YNEJrmX+EpwJnd5pEOICyEDNnguLFkry7H75ORv6Ru
         zuKhS+5TJt2lQRTOxPUBlEOfbGnyCl1AR/v3pZPmVihUE4ZC2pmxwGVnkDO9kWZImmGx
         xmxLgAQPP9nO4ltwXVXlmAEiFO4UXkFXYTG/uUhVmSAu+NtN82YjIHPUkXvTpjSRekFP
         oW1CZxTrF+tEWcD9FoYfov+G1tbNOUnR4k8OFoWU0bsACj+j+Z47VyR/mLIc2AOc4WNc
         9qMPiD1nH1n1eTgDj0rkzHAshUmNTukq19vTs2XKSOZEcs6HzSzpd5MiQ9NOFvfOkS4E
         pnyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cYuegURd;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701718495; x=1702323295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WuIO1ZcA9qjBUieLKNR4NydqRbkN2Y9Mrw2MbCRgZRU=;
        b=cqh6WoiUmK8kg5InYmBlnObyNAHa74soQ8keEmnP5pVFw8Gjm0BEnPhs0mlc5y7+U4
         w5uvH/FoMHzoRD7NeCi21MjZrZVNL+9WDnW7rLlOqYI/Iuj6dISmpt7r0l7RbIxfpCpS
         3p+kZdGAdCw4QyY97tTQL1xBn5ZwgS+x9yCjr8fN9jVcanzpuZhZKmLvRn7wvBab2x96
         ngSm/sUtRKSNDKBBRp3AWwRAN8cbXiiUeE+kD3gfkxw9ZpIdM3v8YYlb9cufkmOxBUkS
         V9YHg47rdsA8PZH+fyk6GAPPUAIUhj8ahhePY31bC4hP4oO7k5z5Tj6A0twsPApCyFHf
         Woiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701718495; x=1702323295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WuIO1ZcA9qjBUieLKNR4NydqRbkN2Y9Mrw2MbCRgZRU=;
        b=botsnjTBKLic7nUi9QmYchxvEdcBm9sLMQ4K39mFi7C/34WX0G5um2CY78s5S8KWRV
         jMj48yFxj2Sg5njmRwIrO2mWLOHumqZN81MJMaPfnbK0H8+cTBzaMwFEOpcssEL2N9Nr
         i3SIKE9IU8LazcPeAsg08ySs/1/roIClsERZcmb2S6I5CLfgWCrhLsh4osiZIJGo/mFb
         pQNt97OK9GLsFiDBnhBxL2P1/JyQslKMNRKmaJg995kcotaWvdMQtPrb6lAEwqLwYrIE
         GXPv8nUk4yOCUnh62ILHkXFcLMUUSFCFGZRz8oWIcJYcVi9J5FYCYNoKR1S8kPwtKeTt
         13Dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywnv0ryPdSlTtuCHKHKza9LTvDD0t1ngxvxOipMxkMGB4RTp+LF
	gcbDGMKl0nwLsv3DwqnwzAU=
X-Google-Smtp-Source: AGHT+IHfaGPaF+1ys5k6XMQ3SbGa1W2RXrErPPjZxmV6NRIf7Vbz0+L1oQGqODtsxKzCHZQAze+ppQ==
X-Received: by 2002:a50:aacf:0:b0:54b:321:ef1a with SMTP id r15-20020a50aacf000000b0054b0321ef1amr356338edc.6.1701718495114;
        Mon, 04 Dec 2023 11:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:712:b0:333:33e9:2565 with SMTP id
 bs18-20020a056000071200b0033333e92565ls276794wrb.0.-pod-prod-06-eu; Mon, 04
 Dec 2023 11:34:53 -0800 (PST)
X-Received: by 2002:adf:e344:0:b0:333:46fe:d92e with SMTP id n4-20020adfe344000000b0033346fed92emr1632550wrj.118.1701718493349;
        Mon, 04 Dec 2023 11:34:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701718493; cv=none;
        d=google.com; s=arc-20160816;
        b=ED0k+gcmi15/u5nmebynry4gVjq01aDCJLM3+PItxKQg2xooYXAUnNI1k6UTT2hK9I
         tY8e0kbgB8fUXkA8jxwobt5VqGP+Z78ECtt0F3/0MDQTd8OMY7v16u5NmC1Bw8Tp/F9u
         mHE0QJQJgfnVN//+LMYHJOcaUtQ7+BY9fY7Z8wX9SE7uj+/Imsz8aXP71i7hWBrMZASF
         lU6wEV1C6vBB/ZwfTsAMuxfCQ55yXdMfTu9xX1Clsb5BWwqR8PydSClXzYaP6o3qukMb
         Z4XEVcongMRZGlFExn8x840qB2w9HDQugixBU32pwZol/7zj1ZahQcMI7b7SEtwImY5O
         gzcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=4fSahCwhPLa3fIglvL1TRmtTOqYm3xhkbDoawZHdw9A=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=iOlcwbjnbomsbBLZCOxOsNzE17mkL/MfW35Kz+N4xZ7ljdV80MxcgLHFIhOXb0XBJ6
         8ujpPuY12zaKRZ64BawjLrvffaryOVuqXH3uRQlwEoIwiaOQre5OEBy9iXpHiNeOBqMC
         64QfNGXGLaJxGkg3sPHAQOD+OV4CqQTEGv0gmCAnjkUFsxWiIkNIfpyrDh2mG4pQq2HW
         AElGT5bdRcsvr633Gz8J4iyMeoWO7LHKMoaqDrKzrP3pBRt3M6SmU+A1n4PxwLMC94Lj
         //bOfWRMdN+FT9qyGjbdLsuGs0XWldmkivXBJ3cO6wdTMS3Ks0dcuF63AqVDpcmXK1xc
         7WWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cYuegURd;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id m18-20020adffa12000000b00333498a276csi161293wrr.4.2023.12.04.11.34.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 11:34:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A51611FE6E;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8875313AC2;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OCn7INwpbmUPMwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 04 Dec 2023 19:34:52 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 04 Dec 2023 20:34:41 +0100
Subject: [PATCH 2/4] mm/slub: introduce __kmem_cache_free_bulk() without
 free hooks
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231204-slub-cleanup-hooks-v1-2-88b65f7cd9d5@suse.cz>
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
X-Spam-Level: ***
X-Spam-Score: 3.33
X-Spamd-Result: default: False [3.33 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_SPAM(2.93)[93.30%];
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
 header.i=@suse.cz header.s=susede2_rsa header.b=cYuegURd;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Currently, when __kmem_cache_alloc_bulk() fails, it frees back the
objects that were allocated before the failure, using
kmem_cache_free_bulk(). Because kmem_cache_free_bulk() calls the free
hooks (KASAN etc.) and those expect objects that were processed by the
post alloc hooks, slab_post_alloc_hook() is called before
kmem_cache_free_bulk().

This is wasteful, although not a big concern in practice for the rare
error path. But in order to efficiently handle percpu array batch refill
and free in the near future, we will also need a variant of
kmem_cache_free_bulk() that avoids the free hooks. So introduce it now
and use it for the failure path.

As a consequence, __kmem_cache_alloc_bulk() no longer needs the objcg
parameter, remove it.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 33 ++++++++++++++++++++++++++-------
 1 file changed, 26 insertions(+), 7 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d7b0ca6012e0..0742564c4538 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4478,6 +4478,27 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
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
@@ -4499,7 +4520,7 @@ EXPORT_SYMBOL(kmem_cache_free_bulk);
 
 #ifndef CONFIG_SLUB_TINY
 static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-			size_t size, void **p, struct obj_cgroup *objcg)
+					  size_t size, void **p)
 {
 	struct kmem_cache_cpu *c;
 	unsigned long irqflags;
@@ -4563,14 +4584,13 @@ static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 
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
 
@@ -4593,8 +4613,7 @@ static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 	return i;
 
 error:
-	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
-	kmem_cache_free_bulk(s, i, p);
+	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
 #endif /* CONFIG_SLUB_TINY */
@@ -4614,7 +4633,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231204-slub-cleanup-hooks-v1-2-88b65f7cd9d5%40suse.cz.
