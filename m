Return-Path: <kasan-dev+bncBDXYDPH3S4OBBX6TXCVQMGQETKF745Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EE80803E72
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Dec 2023 20:34:56 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5444a9232a9sf3703837a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Dec 2023 11:34:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701718495; cv=pass;
        d=google.com; s=arc-20160816;
        b=atLnu1jjvT5BChwM2MbHMNo+u4Q4p6n7mFauWbRd1SYl7OykX+iz0ji0aE78ZDbqbz
         +ltgH87Coy7Inab6LXuPJ4ED1IQ37TiVUh+jvGp66XZFZ1++TXh8n7fJe2zgswHT5NrA
         Dp3TCP+asZGV4vkNygQZM9Gd3zGmqCN32ByGr3J7LBQFAOf5/qSNJ6e4i5wBRGNiC76m
         gIfwrhGeAu/ilNcoX+yUOBOtC05ZTKsHtU2o88TTv31Vo4xMA/bJwPN2Pyns6yw4g8mY
         /gpY5850dlTpsxUezxLJNr/2dlZyasYeOn9GytR3rxkPxYJqx8Xf3tEfKlX/Q37ku/gE
         P38Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=0kA/dEsCTPO5Cfog9AD64s1AP3n3o49OFxhHW2YxGlM=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=aEuoPl0NgWzoM1dS3Niqehm3KhW9p941lulP8E1tWsO4ekBHrJ2vQmGVUuDF0KcbXD
         ZEL8/4IYjRUwE4uT1EQBbzC0sXX0o6n7DQP3Q46O6iX+OxcA8VknAuTIXa8jalY1ZKBN
         ll9isNQSd0B+rXUywNfN2pSG5jwQncU3Nw2w5iXhUgy6FV1lYvcarhfzqyKzsNIOpJAq
         wF4qBZj+LBo1NIIMjb3wz/VLHmH9RUKiA2ElPrrqTS1L59ZV8EnHRy8ZvRHbBBTgclGS
         O8bRrd9H42hDJAcNxygiiAFPtxpQ97atPtwZhSAEdjheAUmk6qUSQ4FoAoNAWQeMgly3
         eCMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701718495; x=1702323295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0kA/dEsCTPO5Cfog9AD64s1AP3n3o49OFxhHW2YxGlM=;
        b=o8Gdw8M0bG6EyMqeOgicg0f072w4yT/QRH0Jz+i2lJBXurwYNUiJ4Zkbw50AtGAvmP
         NXZmgIr9Z7fwgtD8WhMQHYlUGlUGDa6DIVKro+NIiVRFwOGPUc/FM2vg6XmrRo6J0nYC
         sfKMHjk8ZrsJmSWQXpFlTMjlxMPutYREyyZHqZQqd1eq+/ykQOnJBik5d3svBvu74pPd
         vIUi0aXMv1lxiYkjE3LxXdp+5p85zm4WV3INOj+RmCW6XtAsE9ixXG4NNNT1c7VadrJW
         5RvE9pNSRMQmiT0/fxEdzkasH9pGrQzVsmdxNtDIDMR11G8cge6/GiqZPCxSq60hi06a
         5AEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701718495; x=1702323295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0kA/dEsCTPO5Cfog9AD64s1AP3n3o49OFxhHW2YxGlM=;
        b=BP9LVR7v8NsiAaNgIzHaN4s2H2uZACJ/mfWQhyzrvKZJ2hm24Z+c+cViOJ8672Jat6
         wZQLYzXMqYjVpFbYn/LUHhIxiCD7rmEXsuB3d4VQYbMMWSw0Q30aCOa2g+tykrwYAMVl
         g8M6OfcVJPgNOorT592Z3pHDLq8sMt+H6CzQbMND81esbeUopZB6OFUEyPOOAfipj2H8
         A1vButx5zk47KV11cmhuN2G10FQ14D0adEJl/Dosl3aBiLT1On+bhQgHbJecmDK8vu13
         A1MjDR82gWCFZN/H/DVeYVaEUSOpxwMeriAhg2fbk1C7Sk80L2L+m+3zNF3auq2Zt2UO
         qcHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw8Y6Da9Z/ZTPRl/vZ2eQ/thNQCcViNhUDyJgDcmKrEDfjFWq28
	qcZKEUfJh94lMKxef7cXxh4=
X-Google-Smtp-Source: AGHT+IEBTvyLua7Aann56LIHFQo7nJxNAgEP6LTFQojKec+GVyb6Jfc+qCdR/I1a0sIeoijaKGq/hA==
X-Received: by 2002:a05:6402:2927:b0:54c:fc8e:55ef with SMTP id ee39-20020a056402292700b0054cfc8e55efmr189003edb.167.1701718495275;
        Mon, 04 Dec 2023 11:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:17c9:b0:54c:c484:563b with SMTP id
 s9-20020a05640217c900b0054cc484563bls193486edy.1.-pod-prod-08-eu; Mon, 04 Dec
 2023 11:34:53 -0800 (PST)
X-Received: by 2002:aa7:d387:0:b0:54a:ff96:2cb7 with SMTP id x7-20020aa7d387000000b0054aff962cb7mr1667592edq.41.1701718493513;
        Mon, 04 Dec 2023 11:34:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701718493; cv=none;
        d=google.com; s=arc-20160816;
        b=A06wDa6dsKqt7P6DMcB352HV8BZdteHeY18LGpU44rlwdCD0/7jK0rUuawhslntCwi
         zKBJMRkeR8g+W6cD8a8+f+KrE2DL3L7qou/AavidDA+gs639hzONV2JHo4o76XaMhBYr
         U12+w9p2WZNEgPRV11l0PPKuYUzH6FXPVSn86RkDSRRVMdHOsX07y7wdqx6OKyz+YRpl
         pEVlhpjaPvLZTcpVP3NtGU5Zwcz9AYAC7RfUfAmAOcYXHaLfIjM/HkvnarCgQGJwNVZB
         aSTsUG0vNBXorTlUFtUJpyOq0/bpyPP702bsT6hOHkTp1TWOpd3Fa7FlsFqP4RE3TSow
         tCSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=l0vu8j+/9A2K31W5hfz2IyO5NKbuonHh7Yjg+JM4QPY=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=AXkktkcfnJ3pzNxAsNJMQ4hiWow11S4LBV5ohufNw7lQV3NjzwoXfYvHjcCoebqSri
         c31rR7DSzC6bJyeYUcmZEjDQPfbMzYEVqek4VvcmFJTpp18LlSeWaAtbx3nUqdbfv4zi
         kvdrc44iMu7kQn4E1NVCtvMo/qTR7v3BTLtDMJovjNy7kB2/1iy7YPE4T30gkc4xBDOQ
         8xC+aDCGP6eegloRHZcLKrHug8NMNk+vrce3YBzfxEFcEe/TLA8XK45/8ibXd5j7teBE
         7hfIRG+Y4qOG8KXlC1EHyPANXNO08TgjhBbFK1V1r0QCuXZ9hSVRsTejk9/zic7wEIZf
         BjRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ec20-20020a0564020d5400b0054cc15d3b56si15666edb.5.2023.12.04.11.34.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 11:34:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D710B1FE70;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B9C9B139AA;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id KLwRLdwpbmUPMwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 04 Dec 2023 19:34:52 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 04 Dec 2023 20:34:43 +0100
Subject: [PATCH 4/4] mm/slub: free KFENCE objects in slab_free_hook()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz>
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
X-Spam-Level: *****
X-Spamd-Bar: +++++
X-Rspamd-Server: rspamd2
X-Spamd-Result: default: False [5.39 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_SPF_SOFTFAIL(4.60)[~all:c];
	 R_RATELIMIT(0.00)[to_ip_from(RLhc4kaujr6ihojcnjq7c1jwbi)];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 FROM_EQ_ENVFROM(0.00)[];
	 R_DKIM_NA(2.20)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-3.00)[100.00%];
	 MID_RHS_MATCH_FROM(0.00)[];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[14];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 5.39
X-Rspamd-Queue-Id: D710B1FE70
X-Spam-Flag: NO
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

When freeing an object that was allocated from KFENCE, we do that in the
slowpath __slab_free(), relying on the fact that KFENCE "slab" cannot be
the cpu slab, so the fastpath has to fallback to the slowpath.

This optimization doesn't help much though, because is_kfence_address()
is checked earlier anyway during the free hook processing or detached
freelist building. Thus we can simplify the code by making the
slab_free_hook() free the KFENCE object immediately, similarly to KASAN
quarantine.

In slab_free_hook() we can place kfence_free() above init processing, as
callers have been making sure to set init to false for KFENCE objects.
This simplifies slab_free(). This places it also above kasan_slab_free()
which is ok as that skips KFENCE objects anyway.

While at it also determine the init value in slab_free_freelist_hook()
outside of the loop.

This change will also make introducing per cpu array caches easier.

Tested-by: Marco Elver <elver@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 22 ++++++++++------------
 1 file changed, 10 insertions(+), 12 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index ed2fa92e914c..e38c2b712f6c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2039,7 +2039,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
  * production configuration these hooks all should produce no code at all.
  *
  * Returns true if freeing of the object can proceed, false if its reuse
- * was delayed by KASAN quarantine.
+ * was delayed by KASAN quarantine, or it was returned to KFENCE.
  */
 static __always_inline
 bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
@@ -2057,6 +2057,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
+	if (kfence_free(kasan_reset_tag(x)))
+		return false;
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_free and initialization memset's must be
@@ -2086,23 +2089,25 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 	void *object;
 	void *next = *head;
 	void *old_tail = *tail;
+	bool init;
 
 	if (is_kfence_address(next)) {
 		slab_free_hook(s, next, false);
-		return true;
+		return false;
 	}
 
 	/* Head and tail of the reconstructed freelist */
 	*head = NULL;
 	*tail = NULL;
 
+	init = slab_want_init_on_free(s);
+
 	do {
 		object = next;
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (likely(slab_free_hook(s, object,
-					  slab_want_init_on_free(s)))) {
+		if (likely(slab_free_hook(s, object, init))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -4103,9 +4108,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 
 	stat(s, FREE_SLOWPATH);
 
-	if (kfence_free(head))
-		return;
-
 	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 		free_to_partial_list(s, slab, head, tail, cnt, addr);
 		return;
@@ -4290,13 +4292,9 @@ static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
-	bool init;
-
 	memcg_slab_free_hook(s, slab, &object, 1);
 
-	init = !is_kfence_address(object) && slab_want_init_on_free(s);
-
-	if (likely(slab_free_hook(s, object, init)))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
 		do_slab_free(s, slab, object, object, 1, addr);
 }
 

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5%40suse.cz.
