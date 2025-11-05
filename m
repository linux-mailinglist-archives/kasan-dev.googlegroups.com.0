Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXNGVTEAMGQE3PELIDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 46ACCC34AC1
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 10:05:35 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-640ed3ad89bsf2249188a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 01:05:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762333535; cv=pass;
        d=google.com; s=arc-20240605;
        b=KCC8bpOK6OKsN3b97Ww+4JoaO1HwQZj8cAAoOVu/fcmmllyvNYw13k0b8sQbaiEk4u
         h5L6OFvGNjmF6z+PrvI/Cn9rixXAC2OMdSf0dVmeluDwS7EbRaTPgXF1Kmz3aDkCIE1W
         FixbqZevytrtWS+5vqr6naF3bkpgQUfhSMNgbDgwIHeTUZ+3Pq11Lv5vNUR7FrfXTT5Z
         yaq4WUdpTyRx4JTX3IeQe7Exs30A9Sj1E5wuWI5eIICVrjLuZghFK5DlgZC0kllaCckk
         PkEyC12XxQ4bkIXBYxbkfZP9fCEmXOTop9fbikaAlcwZ7Qx6E7R93ymuIenqT7lMjPKy
         pdIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=a+7hmYN7cBBDvnuhWkYMmjOhRrauTHSG8+w1PuzNk6E=;
        fh=6jrEzAyQWa/sgd9vJndaJXQ+3ayMHQp6gixdcn90w1w=;
        b=V3WDL0DYLX+NCQ4OtdtQun/U01ewL47bIIfCR+impUkrMJM7sVweod/vmQyHgyum5w
         poLlrwaprACJeQ1X/0Q1KjeMxjzJAiMnqI38YcsjJ/HrjJVUq4U+fWviQLgqqVw0kowl
         s2hGO+5Ex5GdR86ya/ParumxodqWbP5v7DdJ6TqfRRBFt5iYOqiKZgTcnLRsH3Ze55DF
         w3xyo5Lfte57Y9wuHw5YikgTtdorxu/nPflYc/b5xcD6uVCyvJrfhH17LsJMD3PRyd+p
         0SwZ587Ks8aAYiev/jUXqgvKA8Dto2l/3EGimf6tn+xT3uVx1wGTgICzyAFZ0RhaSIH0
         1XMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JqN8C7wL;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JqN8C7wL;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762333535; x=1762938335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a+7hmYN7cBBDvnuhWkYMmjOhRrauTHSG8+w1PuzNk6E=;
        b=laFYsRAiVIIZHSlgqUmFYaZsNSXldyltrnHgzAU9OFJMY59G3oJ0TX44GdkahWkkaq
         G9brKezZcR9bs9IiEadSxqdv6bPJS0DJuqpYTuIssIC/g26NXfH84DZ/i7iG5AE80Jrd
         2u3PdNL6sgs5jxxSZLhhXUlHwvgdKxPKKescY0FUXS1c9SNe2/wEZ91m+wziYxm9s5W7
         k01pb/pYuiEddtnl9At5IPLVb8uWFiBq1G3r8/ciFtS9/oIVzLDt8T/tuCaN5rzHLgDW
         E74MApjq3B9xuvHZlp77PupPyFf46NAp93PPx9N9c5sYoTZlx6LmnFNP4HSryS/6MNck
         TPXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762333535; x=1762938335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a+7hmYN7cBBDvnuhWkYMmjOhRrauTHSG8+w1PuzNk6E=;
        b=TV4PLYOrinTLjoUztlo2A7Mv15zWEP2Wbcn0+g51IZDUPYcYxEDXT9aW1kMqFvONWb
         CKmSM2Zejtt9+fJCLgVJI0NS3GkJXUMC8cSUp0bFKBKeBxm3v0NuaTnvWi7iAgerpV6f
         dIC10SBdZagxHbvyjdLWw5su2FpV4LgFKakFwd2gpbS1hW8pYSfyZpq+VqaTqasAdq4I
         +hw63XP6dosdehrxCZIAsLetjkoXSwKMPT+T0kEhZq4LVHXHBTcWEZIAuSF7jrOccHnh
         +PWFGlfTx25pdSPIF5BGpCsDZ5fYQaGs1nVYcGbhf8DPFlJhs5EO6ssdehRb2pIt5Fc1
         0wIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVEGdlhOYNuSpYMYjNy/sCmwxkaqKou9+PiiSfno55PFRnHbP6ugoJbl8q8ZnVgpO4k1Zxk5A==@lfdr.de
X-Gm-Message-State: AOJu0YxubbroKkNfFcO9KxgShUs1z4i4aAi2EoH9T/FnYGjd7bL3kQPY
	t8JSsA6sH1f8obucy0TawzOjKE9MYmIHz7gy2UHmjtBf0HJXqr9DUqzq
X-Google-Smtp-Source: AGHT+IHY/PgAEGXMKCH3InQ6AlyWgymEdVi1z9mQnCxBoqbdEb7gwLFkfpDLtDT6wa67R52OfIy4hQ==
X-Received: by 2002:a05:6402:2105:b0:640:c497:3d7b with SMTP id 4fb4d7f45d1cf-64105b6fb96mr2019582a12.28.1762333534670;
        Wed, 05 Nov 2025 01:05:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZtNyI3kz14KB9TAwzgvPYop4t8AhQVnLcSBuNYsMIiZA=="
Received: by 2002:a05:6402:2081:20b0:640:8bd2:b646 with SMTP id
 4fb4d7f45d1cf-6408bd2c1a2ls4563354a12.1.-pod-prod-06-eu; Wed, 05 Nov 2025
 01:05:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVz7uuMUnpVa/VW+Kj8dlMOD8BK+HabReSPTWqCV1P8I+kKwlglspd2cmrbBA9dnWRsWTJpUjfKhsk=@googlegroups.com
X-Received: by 2002:a05:6402:84d:b0:640:a9b1:870b with SMTP id 4fb4d7f45d1cf-641058b9ffamr1900388a12.14.1762333531421;
        Wed, 05 Nov 2025 01:05:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762333531; cv=none;
        d=google.com; s=arc-20240605;
        b=Z2LMysPb2stjGOmfx5AwL0IAo6Gx0Eeq0d4B7xs9ntuS2Hnog2atV0kHjBwhTdQlhN
         n9rEm1bHKF1PP0svfbF7N5ttwSq+57oa93l6oF/dIppu/rKWJ2SMI9HyU9EcU/It4lnS
         W5efqd07PVi7mBSgaR3uwdbIXVbzroXtXQ2nWxfiXF4CdAWfGboenHeTXOnWZeTTmIcc
         9qZQCLTP/YBTTMaDytDu229hl9/7+lNPDmy4zs2ummh1+/O37WRRwWzp0t1TekgaqnsI
         1EQo2E39Lr/3/pendVME4jvbDItyuevaKgInGm3UBDnCqHLuzgUuEexFh5P7ZtpyTesA
         Lcbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=dS0i3Iby0OJwb+mg8PeOF13C4McpBxa53amtQoTdGRo=;
        fh=0VZDZxBGXWy41l171YBh+BdY6cJG+AzAPMWnSIJmIok=;
        b=hV6SlUUDAHT3SNdV3vtW1y2orF8+5nwLMP9go+G1XDURvd6dZ4F50VVWOsyL55Oe/j
         ZX4NUk/CMn9bZxe07f5WTzkR2+kKmGHXNZlYeIbhgKjUeuH2xAgsO7IOrNsJlSD93GyD
         pBX73aHOsymlFK0t2iSqdpz2sjf42uslQNfkHnjtdVndZZBKpXf57ks5BFKbsXY9cuSN
         9Zfd1+FkqRBZOyxvA0FwZnOX5Nzeri83Vqx8Lg6cg5ZM5LHLEqxbOokN6P2sDIddj7aP
         1LvIFyCBZahCfLZEbzsj4zmep0XGsdo3ppC+PeskrUwCpMaav9fm+eNAjFxsRTzoTkYo
         Gcfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JqN8C7wL;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JqN8C7wL;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-640e6806b2asi157939a12.2.2025.11.05.01.05.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 01:05:31 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id B87E921181;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9A87613A91;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id AEN5JVoTC2lSBAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 05 Nov 2025 09:05:30 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 05 Nov 2025 10:05:30 +0100
Subject: [PATCH 2/5] slab: move kfence_alloc() out of internal bulk alloc
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251105-sheaves-cleanups-v1-2-b8218e1ac7ef@suse.cz>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
In-Reply-To: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, bpf@vger.kernel.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>
X-Mailer: b4 0.14.3
X-Rspamd-Queue-Id: B87E921181
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:email,suse.cz:mid,suse.cz:dkim];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=JqN8C7wL;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=JqN8C7wL;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

SLUB's internal bulk allocation __kmem_cache_alloc_bulk() can currently
allocate some objects from KFENCE, i.e. when refilling a sheaf. It works
but it's conceptually the wrong layer, as KFENCE allocations should only
happen when objects are actually handed out from slab to its users.

Currently for sheaf-enabled caches, slab_alloc_node() can return KFENCE
object via kfence_alloc(), but also via alloc_from_pcs() when a sheaf
was refilled with KFENCE objects. Continuing like this would also
complicate the upcoming sheaf refill changes.

Thus remove KFENCE allocation from __kmem_cache_alloc_bulk() and move it
to the places that return slab objects to users. slab_alloc_node() is
already covered (see above). Add kfence_alloc() to
kmem_cache_alloc_from_sheaf() to handle KFENCE allocations from
prefilled sheafs, with a comment that the caller should not expect the
sheaf size to decrease after every allocation because of this
possibility.

For kmem_cache_alloc_bulk() implement a different strategy to handle
KFENCE upfront and rely on internal batched operations afterwards.
Assume there will be at most once KFENCE allocation per bulk allocation
and then assign its index in the array of objects randomly.

Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 44 ++++++++++++++++++++++++++++++++++++--------
 1 file changed, 36 insertions(+), 8 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 074abe8e79f8..0237a329d4e5 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5540,6 +5540,9 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, gfp_t gfp,
  *
  * The gfp parameter is meant only to specify __GFP_ZERO or __GFP_ACCOUNT
  * memcg charging is forced over limit if necessary, to avoid failure.
+ *
+ * It is possible that the allocation comes from kfence and then the sheaf
+ * size is not decreased.
  */
 void *
 kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *s, gfp_t gfp,
@@ -5551,7 +5554,10 @@ kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *s, gfp_t gfp,
 	if (sheaf->size == 0)
 		goto out;
 
-	ret = sheaf->objects[--sheaf->size];
+	ret = kfence_alloc(s, s->object_size, gfp);
+
+	if (likely(!ret))
+		ret = sheaf->objects[--sheaf->size];
 
 	init = slab_want_init_on_alloc(gfp, s);
 
@@ -7399,14 +7405,8 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	local_lock_irqsave(&s->cpu_slab->lock, irqflags);
 
 	for (i = 0; i < size; i++) {
-		void *object = kfence_alloc(s, s->object_size, flags);
-
-		if (unlikely(object)) {
-			p[i] = object;
-			continue;
-		}
+		void *object = c->freelist;
 
-		object = c->freelist;
 		if (unlikely(!object)) {
 			/*
 			 * We may have removed an object from c->freelist using
@@ -7487,6 +7487,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 				 void **p)
 {
 	unsigned int i = 0;
+	void *kfence_obj;
 
 	if (!size)
 		return 0;
@@ -7495,6 +7496,20 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 	if (unlikely(!s))
 		return 0;
 
+	/*
+	 * to make things simpler, only assume at most once kfence allocated
+	 * object per bulk allocation and choose its index randomly
+	 */
+	kfence_obj = kfence_alloc(s, s->object_size, flags);
+
+	if (unlikely(kfence_obj)) {
+		if (unlikely(size == 1)) {
+			p[0] = kfence_obj;
+			goto out;
+		}
+		size--;
+	}
+
 	if (s->cpu_sheaves)
 		i = alloc_from_pcs_bulk(s, size, p);
 
@@ -7506,10 +7521,23 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 		if (unlikely(__kmem_cache_alloc_bulk(s, flags, size - i, p + i) == 0)) {
 			if (i > 0)
 				__kmem_cache_free_bulk(s, i, p);
+			if (kfence_obj)
+				__kfence_free(kfence_obj);
 			return 0;
 		}
 	}
 
+	if (unlikely(kfence_obj)) {
+		int idx = get_random_u32_below(size + 1);
+
+		if (idx != size)
+			p[size] = p[idx];
+		p[idx] = kfence_obj;
+
+		size++;
+	}
+
+out:
 	/*
 	 * memcg and kmem_cache debug support and memory initialization.
 	 * Done outside of the IRQ disabled fastpath loop.

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251105-sheaves-cleanups-v1-2-b8218e1ac7ef%40suse.cz.
