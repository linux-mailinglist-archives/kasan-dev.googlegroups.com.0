Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZVVZTFQMGQE2LJQJSY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id qCEnHucac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBZVVZTFQMGQE2LJQJSY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:27 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id ED365712E9
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:26 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-65805f976cdsf2595994a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151206; cv=pass;
        d=google.com; s=arc-20240605;
        b=bFRQx3WeDNKPkqS8BFVchb0qfbzhuaU1ozFA/27zDxGNDr/A1oMSExKYCQriI0e2B2
         GOgI8YXGfyaMEeq+Wu+GliqA+iyBZQ2ahZyUZqB0XB7zMS75W57L4Ssu5fk40XSbef/S
         NYl1W/1TZkvLXQO6yUSOFMwlkKMFZi6NC552GBP6Rgl8zLBFhjMsyMQSDb3D0jnTajCX
         8lDOniZiO9gw3wrEcuFl83mncolMvkXyTb7AOrQwdnZ7ubSRsn8QWBeO/5DWIe9LLYFf
         1hhxeikKPYLF1n38HXIi4PtRCLuQwTVKKNOVTy+w0fQfQl8wnWzTbKVrjTh4vaHucMEO
         vc6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=dtdg+1RXstVY7m4dZFdOnPa2eiy3IQsDjbdqzV5vBjI=;
        fh=tWrwGyZ0sXXgNDzTjNs5C7fCrlUCoSisMfWELJgv8ms=;
        b=bjk2QJvs50JCv/iZkyuW8lWMu88+dFnrK9O8i+7QtS6adbmpPH/badJ9OMh3Z2jm3U
         1924syB538iXpxvujPAdxKh1DMbkm8Ul3VriimK4oBrzX/3MGRIaRLOe3ImLPEw5hsye
         hDdWwof5NM2x6twWjVmI/JW1vb2fYirc/3RAPmnW6WAdIuMVEeXStuftoltBwDK0EaF2
         RNLyAaPxFzsdZb6iRWFMK6sKDIMwg3IIHAekGfnktLmW5yvKIZkWwsU0PgFpkEPbGbi2
         9zOZsT0lJC5w8sRB4RHgtGRVzMpmQ3kg1cDcLKdXiXdBfyA9MiaSg35WM8ZKHKsBFADL
         9YRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151206; x=1769756006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dtdg+1RXstVY7m4dZFdOnPa2eiy3IQsDjbdqzV5vBjI=;
        b=OOzdHgD2UoBjJITSPxbuQN0ClXynWCG0BcK7ZZjshSSFlAegYMpx6NtZWsg7lTGkoR
         eaKVgOAGsUhqe9mLPUSYLDXbwSbBB4QfS3bkNJPSb6z+CMTu1+HsuoPOC0dGk6NAgMmH
         aAn/NQWxq3OwbCL9zzvbe9et5nnpdh/wiRAUexKXSm8mm6GT2vplRwdEEdTG4nkIviUa
         W9mdO3FILh4tgFK4ZUAR8LQNyPedlYoJEPM3+kSx8kTabKZiu58nixEhqOoLF6y5Wbyw
         VvjN+Qd4MND1h0lvsYjIaV3+IeZXWl+potQgzdin+wm0tZ+YSHYON/jFqvDfY2djWbt6
         BTHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151206; x=1769756006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dtdg+1RXstVY7m4dZFdOnPa2eiy3IQsDjbdqzV5vBjI=;
        b=mX5HNfLec1LEqBzSGddCqmcHxpcTFxNsSOSWrP2G0wr058SjhPPzjVZZPSguSSQjKy
         eVJnN08XmB728I+LNMkjOt0zG4Qb8niW/wMYnqLHf6pSu/5CiUkKz0WzWTw/R6ScDGee
         uAeu4529WT28vAUqeS0cIFIP13THIy0MJNMzUABVT/4Dy71hKvcX/uLcu4Q+sAxAp00B
         PNG4nc1YxRNW7p9SHfX7KsJFUwUNP8VAhodSfSk5m4/uXtGbp+yervyWCXYg0C32m1Cu
         p29YltxVcaUpL9lm2nkN2qFHe4uKecJ6MDMOOG8v/Wj3fLNkjDH/Ihc7NnehE4YZxI4N
         aTqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4f73Ekc2rel6YNxDpGdik36Fl+qVqfwIbSzJLgq+tw8ZmH2IvFz5taWTSz+fG9bMgEfFyEw==@lfdr.de
X-Gm-Message-State: AOJu0YyBWC3lOAWVPFd4nfl+WQ4bswtROK2ZX0lx9ILnVsepEYlwsKce
	Zx1Y4uuL4HDeS06Unm4Jl7fHGhPmdEs3/RtIgrqx8qnZhC0vObM1VNlu
X-Received: by 2002:a05:6402:2116:b0:64b:58df:cf24 with SMTP id 4fb4d7f45d1cf-6584b1a38c0mr1182877a12.11.1769151206475;
        Thu, 22 Jan 2026 22:53:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HcK4i9lzQ1EI44toOZBlgvYFCom489azfNJhFkeN157g=="
Received: by 2002:aa7:d817:0:b0:64b:aa45:7bfa with SMTP id 4fb4d7f45d1cf-65813470ecfls1409833a12.1.-pod-prod-00-eu-canary;
 Thu, 22 Jan 2026 22:53:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVDtZTfqQrHYFSnNbQpc4XdHSQEFNx3OMmHyvMhFpfxsdVUB8Z9IfCxG3/Pm6YA0hDcJblZCz4N+Bc=@googlegroups.com
X-Received: by 2002:a17:906:c109:b0:b88:4224:815b with SMTP id a640c23a62f3a-b885a262cacmr149555866b.3.1769151204367;
        Thu, 22 Jan 2026 22:53:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151204; cv=none;
        d=google.com; s=arc-20240605;
        b=YZv6VeXFsBM6s0qJRMgp2FWYUjgF8DqV4Jo6/pbS3tP6ll+EsWqOoYcLG9sufBleDI
         KpozFtlS5SJb8xmRfhTAS583gcWYPx8wxe30DiwVj230OjAA7N7QtEKTcADVKr7EyHdC
         Ag+3Rvs1X7M/J4qpQ8fMDJ8ZHweyKe60BLqrLvk8KyN3cJG6UQe/s7yxDM4yP9W5dQFc
         YWWDUFJIFoZVnAjS5YBS9Bg7H3vELmTo+0CTNIWMXvzE3vqEqcHhxj+rGBAOm+yYwWvp
         SIiG/xuquPinlFBQv2SSiVsmmSgi284t0cyJ7z161vj5102QI8oBbW3Ja50nQeSEBshu
         UzTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=R3tMPeH9Ipw8jVs85e3Pd4lK1yV/xqf8NCU0KSfX1vE=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=V1TLbAwmTk+4E0saARzv9t/7m7j1DbQyb6t7Y7MExgYx8x4JCVKSL+RwAcV8aDo4LU
         jVZbKz0Pk0xCt86xso8cojBw9qw5V39m6v7VFfzYEGORu+3a5SX880FTfa9Q3eKpISph
         pQ/pdTRNvu/wym37kCgF9DlTlJ4Exwn3IhERtaPTQ7rPyHK+LvnFsBIw4gxA+Q8cESlM
         eOE1go/SmFWSLFh0XYPhglAR90YeiP6XoleF1yvt+B8CdLp/dxq5b9rMWkkWSlG0W48N
         +irDEK+yKfi5/b983VxXTF9pi5/q1+RMDXmwtVNZ5Etx+/M38Zx/EWRXVVJah2mS+KkQ
         Lw3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b885b7076d7si1962466b.3.2026.01.22.22.53.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id D0DD833775;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0FF1D139F0;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CKtxA9Yac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:47 +0100
Subject: [PATCH v4 09/22] slab: handle kmalloc sheaves bootstrap
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-9-041323d506f7@suse.cz>
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
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Spam-Flag: NO
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBZVVZTFQMGQE2LJQJSY];
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
	NEURAL_HAM(-0.00)[-0.975];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-ed1-x53e.google.com:helo,mail-ed1-x53e.google.com:rdns,oracle.com:email,suse.cz:mid,suse.cz:email]
X-Rspamd-Queue-Id: ED365712E9
X-Rspamd-Action: no action

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

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Reviewed-by: Hao Li <hao.li@linux.dev>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 88 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++---
 1 file changed, 84 insertions(+), 4 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 4ca6bd944854..22acc249f9c0 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2593,7 +2593,8 @@ static void *setup_object(struct kmem_cache *s, void *object)
 	return object;
 }
 
-static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
+static struct slab_sheaf *__alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp,
+					      unsigned int capacity)
 {
 	struct slab_sheaf *sheaf;
 	size_t sheaf_size;
@@ -2611,7 +2612,7 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
 	if (s->flags & SLAB_KMALLOC)
 		gfp |= __GFP_NO_OBJ_EXT;
 
-	sheaf_size = struct_size(sheaf, objects, s->sheaf_capacity);
+	sheaf_size = struct_size(sheaf, objects, capacity);
 	sheaf = kzalloc(sheaf_size, gfp);
 
 	if (unlikely(!sheaf))
@@ -2624,6 +2625,12 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
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
@@ -8144,8 +8151,11 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
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
@@ -8640,6 +8650,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
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
@@ -8683,6 +8761,8 @@ void __init kmem_cache_init(void)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-9-041323d506f7%40suse.cz.
