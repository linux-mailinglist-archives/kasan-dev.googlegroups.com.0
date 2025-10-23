Return-Path: <kasan-dev+bncBDXYDPH3S4OBBW7G5DDQMGQEPXUCBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 471E6C01906
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:32 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-471168953bdsf7115835e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227612; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bz0iIS6G0QwHvbgTqfLZGCB76Zr6tt9gDo6zQu0cB/55ADmyjsj0yw/jSiCOjyiNtl
         ijJ5RYY2xGBaXvZ9sGGDOOV9+2Go15m+5hkMumJiXHPXC5YnUVkUzymxLSeMd/FZZK6M
         rNkgXqwcoR5+C29KjzRBRH2q6TARoh5BdA/+atJh8MHjb4IusZWGweCRlfhWGqqQSBca
         QPt+9RJvaVwsgyGqr1093pKF3lV7fT8iXx314/Z+KTcZJaeCdNgqe6NUqY2m4ZzkokTh
         bZslDsT5ddGHYQ6awumDjM+XRXez1h3XrRT67GWHxQLR1yPbfQUOaah43EQ9PayLeygW
         9Jyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=+epPcha1S8bTsbvsWELCyUdzWhx37ws1i/33WAOhuxI=;
        fh=H3anM+VqiirDG6+hHzFZRrUDyieB7PGNUzjnmg+1FvI=;
        b=gATEzoOuvLTWgaJ49v9+PnLIB7c89U6XPBZDsFQqnSEXM/I5YVWoHN59KI0Ppw2i23
         gDqSz6NaUDdikPjdpU7V1A0kbCNFwxFylAF+CaD9B+IAD8PaPk6cth3u/Xz3vTJ0XzXk
         1MzhME64fGcvBd/zCSHswi7Z59dEjknPP4miyvWfqCC0CouNpHGx7oJ96Zl+GUwWrBPk
         4FtuBHxymbNtMH2ToC2zx0YZ3B7jPi/AW0H4mfIqsJuidUOPbv4Yj/HqIWSast5ufyBS
         Af5q1fPkd7xpc5rtJWV7sykJoiwTN63MtduDrGvZxfntQx5wnbIy7I4W1KFYBZbOsWuZ
         +uDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g2RqqKtb;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=a5zjqizc;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227612; x=1761832412; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+epPcha1S8bTsbvsWELCyUdzWhx37ws1i/33WAOhuxI=;
        b=CBtxXH6ZGgl2rLaneKGKWs4PnLPmN9sjnYHCWPg/jN4dhcD7oDwRhfHwssfojjtxlc
         c700xCudyhnhkL0Cl5KedD7mOb0i2r0m0/H2O7eMUpXiIkyVxI5txBj8q7XBAN3mF4RN
         9D3sMPVkEbSW7TuT/xvveGq1+swAre8E7dCIovEz9c6xLquYYCU1hpYkIogTxeCFyeBP
         ylu7DUVfkpau4mz0WQDeTN2kp7a8UyyFMK/N8AOXBkqCAMpvr03ELmcTjnDKKI2KUlC5
         +YA0x/kLFBuu5Jt9QnbUKlllYnp+z3aWb3rC4VWMl1XspYWS/R5jTBzYLTpp6eABI+M3
         itPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227612; x=1761832412;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+epPcha1S8bTsbvsWELCyUdzWhx37ws1i/33WAOhuxI=;
        b=poAZ7keu5lTtP6SZLQ3W8VWYnQxaYHmF1H96GQ6mKwr59HNsA+l+LyLn9WxsoM3pXr
         J5BwVKcxv1DzOdVX9bNlUkgJjsnrqePuWt9rXKTXSDqnP1J+RzB06ylMSBUE+7l/yNnl
         ZjvIPI42sUVT9oY/MSJWk0B0Bpp8G4hROTAGdYK9jd7WYB0afEW/X4x0+gIXicN1oA5k
         kQRN5CMqtHL562K/znZ+nuDko3GQD3ByuXdDahCdjHnQ/fb4R7EMlG0rqN1zTXo7HZCZ
         J4/LiRBX4GHd4QlCYFR3qgXvMPHIq8q/l4s/Hdq6f/+aQGCGQB/aix9iddt4h/ncge9d
         VxKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULEqYdrAyroEHEa2f87nawf5oMnjO4ovD8bLQQrBIpw3ZdlNK7pazeAKvwIKEnrHXkFzrz2Q==@lfdr.de
X-Gm-Message-State: AOJu0YwK2TnlPSAcZl/VDayDSMxa6V+h4u90y7FY3MgzaTtloEBUWb5H
	ryLW64lQocOYAUkxUOUBEsYRSwqBcVNCspCMol8Hxd20vNhzXuLVxI9L
X-Google-Smtp-Source: AGHT+IF3ed2uWSZK9m4inTqHrVt8giLk928RecV2Vfio0izzL5/9GrnqZ4nBPU76TN7xo9jt4tPuUA==
X-Received: by 2002:a05:600c:3f10:b0:46e:6339:79c5 with SMTP id 5b1f17b1804b1-475c3fa1f3emr60575585e9.5.1761227611790;
        Thu, 23 Oct 2025 06:53:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7QowWjtV4XyAko3R0INXq0Y7PanUsMOkqcH1u6WupjKg=="
Received: by 2002:a7b:cd98:0:b0:471:ab2:13e0 with SMTP id 5b1f17b1804b1-475caa16beals1597905e9.1.-pod-prod-00-eu;
 Thu, 23 Oct 2025 06:53:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxvbqxyGqEksdqJ5ijQoHF0ltR30LUsZyiQ+7gdSMLdnFehX4hGjoDt5UnS1cPBo5tAzgbUxN2QsA=@googlegroups.com
X-Received: by 2002:a05:600c:6995:b0:46e:33ed:bca4 with SMTP id 5b1f17b1804b1-475c6f68f4dmr37439855e9.15.1761227609200;
        Thu, 23 Oct 2025 06:53:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227609; cv=none;
        d=google.com; s=arc-20240605;
        b=JpMAu8LZDv2QW77MQvUL/ccotrJ/pQMitwLx5dbZp5z7BE8z7fQt0Pdjv+av6CQpxY
         qgfsMw8KhdMmqIVHsSAf+gEPuoCtKaDoWk2cBWx9qjmc1pL96GVItiL5xdFMS3QytaGx
         QpPH30GVGWup1ltohfUi4AhYuihIaOUhdDuQvMUGPG7ZzdTiN2gsGwt/xqfPusfUhs9u
         FMfvYpd/xyqfMnAgci/qty3P0JGf3EswKh3ScBl/69uGHnn/fVpNUZgLkL/BmdLPaITt
         UgjFCh+OzdxDmy92utU6bqcojE/iStRQlbwWf3hW4CTftEhPBc8+r2hMihwGQhuLURpn
         H0tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=bwEJAB2u9ltAgWYDeLEgZcAvDMG4WKRh64HkDQCHmoQ=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=MjsamoCGGLDdHFYOhTHsRWtpe5+haiybrGsgNba/YZvy/xhiu5fsSA5U5AZ40Ie0M4
         TV/jZv2nQTsoGtp77yrLy7RUAotCy88m0Ah1VL1RCEcHd3u9FPdZW1EG5jreh8sO5fx+
         Aj4SrYLpOPSavxH2Ss0dH1oJPaj7db7TccMh0dg/Npvf+9VZgP15au8rDPCNWLMrbCgJ
         Iz1cLIh55SE3zhgEoq2WDW5E5fol63ESMsgfj7BuqRh4rW0K/GzMkM+8r8fuOb/NavV4
         VGw+nSSnBnCSYpM2XYE/7WHBbrFHRUxEyXHFEfbYmULc+D1k2p/W27653g96TRywTlXZ
         6WVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g2RqqKtb;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=a5zjqizc;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-475c41c92f4si537885e9.0.2025.10.23.06.53.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 799841F788;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C4B1713B06;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id KE6+LzUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:30 +0200
Subject: [PATCH RFC 08/19] slab: handle kmalloc sheaves bootstrap
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-8-6ffa2c9941c0@suse.cz>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spamd-Result: default: False [-8.30 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	ARC_NA(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=g2RqqKtb;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=a5zjqizc;       dkim=neutral (no key)
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

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 88 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++---
 1 file changed, 84 insertions(+), 4 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 5d0b2cf66520..a84027fbca78 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2588,7 +2588,8 @@ static void *setup_object(struct kmem_cache *s, void *object)
 	return object;
 }
 
-static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
+static struct slab_sheaf *__alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp,
+					      unsigned int capacity)
 {
 	struct slab_sheaf *sheaf;
 	size_t sheaf_size;
@@ -2606,7 +2607,7 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
 	if (s->flags & SLAB_KMALLOC)
 		gfp |= __GFP_NO_OBJ_EXT;
 
-	sheaf_size = struct_size(sheaf, objects, s->sheaf_capacity);
+	sheaf_size = struct_size(sheaf, objects, capacity);
 	sheaf = kzalloc(sheaf_size, gfp);
 
 	if (unlikely(!sheaf))
@@ -2619,6 +2620,12 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
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
@@ -8064,8 +8071,11 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
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
@@ -8549,6 +8559,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
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
@@ -8592,6 +8670,8 @@ void __init kmem_cache_init(void)
 	setup_kmalloc_cache_index_table();
 	create_kmalloc_caches();
 
+	bootstrap_kmalloc_sheaves();
+
 	/* Setup random freelists for each cache */
 	init_freelist_randomization();
 

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-8-6ffa2c9941c0%40suse.cz.
