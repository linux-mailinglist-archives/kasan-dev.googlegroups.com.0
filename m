Return-Path: <kasan-dev+bncBDXYDPH3S4OBB7FVZTFQMGQE422LSHI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WHNVIP0ac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB7FVZTFQMGQE422LSHI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:49 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BACC71378
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:49 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4801ad6e51csf18354785e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151228; cv=pass;
        d=google.com; s=arc-20240605;
        b=XDpmS96Sp2i7YoYns/va/Zd1gZV6pLkkIWjd8cJkOfhyB6BKBbyWXdKTIMZI0l3lR8
         gUJquH2IAVeQCSHVREmMHw4ODUI+ctzoItarZkx6b58zPPw5aJz3aESq0AZtG5pd6//p
         6wDQbxEGAlhBR1wAKHZjMl2c+wqtpsfcNqtAz46Z9gLfvcs8hST84USJdWD4zIbTLqp1
         sLkrMnRJ5AdOx/u0mRgAcidLliNCK4vB4zRVWt6igKZgeL9CfaC1F4YzxM074FBt5dLb
         sY3F0Aa6PBjhrOefDhWiVN6so+79I+eWABKdDn26SRh9418Brcz17UiIY6xxtBtyQUnV
         pULg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=sTdFjzcss4GCrI9vR1Wq1R6MXmuvoq8CsEd+XdR705o=;
        fh=SXTHvOJOkcWQt8wVuWGP4O/qxD0FJ2Px2zh1qR4F/HA=;
        b=g4MntQZDAxGWoFrhY6+uAGhAlqr0Ypxe8B4f1OPuILdV9hxNTYPW1KiYEIXG6/nk8R
         eUXxY2A3tv6dDzl7Rl3Hl1mhX9E060qPYIDkAhUHfRLygsNkKSyJbSiYpcIJgTAdWpbz
         gMHGFkRxKQS8+7VrMw0Xz12zNVo7UpdE0a0EQL5zlJ4R9SGCVKu+EGhnLmZuLsECfmYC
         ebrn/Wm4k/OuHMLsXKJxuvpKbR3wkh96HJLKMpV0KZUXVXiQij019derTSxbrbuApxvu
         IKEyCX++yvlWhju9P5BTIgcrYrqS8r/duW3CBbKKrTIw63SZc22vE79I+fdcMiEZbTUD
         MgXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151228; x=1769756028; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sTdFjzcss4GCrI9vR1Wq1R6MXmuvoq8CsEd+XdR705o=;
        b=wqZWw+AELboK5IoMGKE6VC6H6yVZ3jHsB+NznKA9O5VGwTnGclUK0P8JtzHZJ6Rqz3
         aro1/DsLdDJYtYV2oh8cIcGfktO63EfH/wDD2Z9aAM6nfXYdft3mqbgGHAKU2sH+jzvO
         0PbxpkAHpF8zcsXUx/NEdwJBsM9J0v4b5aB4JCUYhDNE1GLNvn+dx4j9rg4ZHv+ZNbkj
         AMtCS1BwRAx+cBY8k8B+IqC7wjlnTCeD4tzmnNJbahgg5ZYAztlZAf+qA561UBUCkdsZ
         zebg6EYmrDeDpjejgMmxM+Vrhekthn0taGYqgnHcHBbBb6NVTpO9RcuFvgzD5QatuQOe
         f6jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151228; x=1769756028;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sTdFjzcss4GCrI9vR1Wq1R6MXmuvoq8CsEd+XdR705o=;
        b=HVwm6uVf5JQsqOaPqtr3Jrfcru04+ydJAF+GqAfrifKwKxq5S3sG8UqL5BpmRhrC2/
         ROue8AiU7bsQa2ERvqhR8lVfSJVZ+EhZuLRUNrLv4dwVfH71yYsB5s0TP1PZMNq9Y7Fp
         zaI+3/5zQdebAhtG5sN0y1s23QuhpdCzM4yARzY5GjpFM7KQtMfvDVGbLbsgIk0qIDSt
         IC0QqgDvZMrWmD8RDGrr6+AI9US6SoWI16oVmy+JGCyYGEN48COB+oc5unkGruUWXVeo
         NtTqI/bDfEqEMOe2cv1wEuPNNq4nWoJQLndQFw787//vWeJMUZmyTffKDZp+fi3PKHXB
         sTbg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVwRz1doSfzJTiHLwJai79xjnUesGguVUFA9en33KfKXNNOgfaEyCWC7VnTjzv8BqUn4j0Hw==@lfdr.de
X-Gm-Message-State: AOJu0YzTHO4TMm9x5SiCv/pGIFtHqIddA71mdZglyJlLyvovQjW5dQpL
	lcHRS9RlZdbSGbIJfm5oF7quRf8TN0np4O+AT8sm/v4ERwI9TGUaxiQD
X-Received: by 2002:a05:600c:83c5:b0:477:7bca:8b2b with SMTP id 5b1f17b1804b1-4804c95e234mr33327965e9.15.1769151228662;
        Thu, 22 Jan 2026 22:53:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GsLx9uIGbHpezei0cLv+4bCAN6SworP1Tpo0rysoTc8w=="
Received: by 2002:a05:600c:4f14:b0:479:10b7:a7cb with SMTP id
 5b1f17b1804b1-48046fcd8dcls14128075e9.2.-pod-prod-02-eu; Thu, 22 Jan 2026
 22:53:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWh7+EqKdXMZr6VjWhNx516guug9vJQgs8grFgVSSfArvdMVxUlxjmPLdU6IyUMymlom+Kzs+hXpKE=@googlegroups.com
X-Received: by 2002:a05:600c:4f45:b0:480:32da:f338 with SMTP id 5b1f17b1804b1-4804c95ca8emr34959185e9.14.1769151226218;
        Thu, 22 Jan 2026 22:53:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151226; cv=none;
        d=google.com; s=arc-20240605;
        b=VxAbPNioFxb9A7KTgwxhimt79UZsqTmZ7dsrd5MkNMxKu/4Wwj7eWLWxzI4z74EbGf
         wy5di5BgC1iKf0EaRM9pguskE58TP4IAGrEewLdSG2JrKc6LC5MCOlBlCc4If21/K3bA
         hQNj5DtPSv8qiGmpE1WgNGXQcdBPfVUhZVkX9n1rGst5QWcLYcEGGBgssR2Oi3fYvBXf
         xx/ZueIi5DSEIL49Dzd74OP0To5k465I5iiUn4nFhi6NcP5z/zHKjk2x2WgMN2a29Vpn
         PeAxLNqd3HpXAZI2bGfKAqCK4ptFCVC9StmzczzNhvdM5d90mIG4bzAy2wFfHpElZ45u
         4cDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=LyTlh10iWYr/4gY9DIKeM0qSfHRXAHnQQi23jLibfLc=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=JIdvGoMlP6d2dhK3/Cu2W2Mkgwc0TslaOiQxJzKNuxnFE+xdGQaiVsw+NGQ4aMFsKD
         XhZZxA9mf+sEUVZJCZ1BTOVjDMhDsBRnHdX9Zf+z/fUcNuJIfgQrAu2krqgkXijzeCMZ
         3LHa8JUjTGiF6at9N02py/0BdE4WWD/rPaSiFzIdD9dxQMWMgk2Wsq/EUrXgbj+/iIXO
         LvPRSUw7Ka0j+CXE0E34J26YtE/tJjYnjNq5tGUJEO/iv1FRtxCW8B+vB9hg+w55wk3d
         2e6DQMng63vLYTQFO3HrseryRr4mFYuqufsEEIOYWWHcPneS06AJNwNDCfbDw9Q4T1Lf
         yOJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4804d5f2db1si111675e9.1.2026.01.22.22.53.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 92DD43377C;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6BECD139E9;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id EHITGtcac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:11 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:53:00 +0100
Subject: [PATCH v4 22/22] mm/slub: cleanup and repurpose some stat items
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-22-041323d506f7@suse.cz>
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
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB7FVZTFQMGQE422LSHI];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email,linux.dev:email,mail-wm1-x33a.google.com:helo,mail-wm1-x33a.google.com:rdns]
X-Rspamd-Queue-Id: 2BACC71378
X-Rspamd-Action: no action

A number of stat items related to cpu slabs became unused, remove them.

Two of those were ALLOC_FASTPATH and FREE_FASTPATH. But instead of
removing those, use them instead of ALLOC_PCS and FREE_PCS, since
sheaves are the new (and only) fastpaths, Remove the recently added
_PCS variants instead.

Change where FREE_SLOWPATH is counted so that it only counts freeing of
objects by slab users that (for whatever reason) do not go to a percpu
sheaf, and not all (including internal) callers of __slab_free(). Thus
sheaf flushing (already counted by SHEAF_FLUSH) does not affect
FREE_SLOWPATH anymore. This matches how ALLOC_SLOWPATH doesn't count
sheaf refills (counted by SHEAF_REFILL).

Reviewed-by: Hao Li <hao.li@linux.dev>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 83 ++++++++++++++++++++-------------------------------------------
 1 file changed, 26 insertions(+), 57 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 369fb9bbdb75..b07a27a3ca28 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -335,33 +335,19 @@ enum add_mode {
 };
 
 enum stat_item {
-	ALLOC_PCS,		/* Allocation from percpu sheaf */
-	ALLOC_FASTPATH,		/* Allocation from cpu slab */
-	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
-	FREE_PCS,		/* Free to percpu sheaf */
+	ALLOC_FASTPATH,		/* Allocation from percpu sheaves */
+	ALLOC_SLOWPATH,		/* Allocation from partial or new slab */
 	FREE_RCU_SHEAF,		/* Free to rcu_free sheaf */
 	FREE_RCU_SHEAF_FAIL,	/* Failed to free to a rcu_free sheaf */
-	FREE_FASTPATH,		/* Free to cpu slab */
-	FREE_SLOWPATH,		/* Freeing not to cpu slab */
+	FREE_FASTPATH,		/* Free to percpu sheaves */
+	FREE_SLOWPATH,		/* Free to a slab */
 	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
 	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
-	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
-	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
-	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
-	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
+	ALLOC_SLAB,		/* New slab acquired from page allocator */
+	ALLOC_NODE_MISMATCH,	/* Requested node different from cpu sheaf */
 	FREE_SLAB,		/* Slab freed to the page allocator */
-	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
-	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
-	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
-	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
-	DEACTIVATE_BYPASS,	/* Implicit deactivation */
 	ORDER_FALLBACK,		/* Number of times fallback was necessary */
-	CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
 	CMPXCHG_DOUBLE_FAIL,	/* Failures of slab freelist update */
-	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
-	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
-	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
-	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
 	SHEAF_FLUSH,		/* Objects flushed from a sheaf */
 	SHEAF_REFILL,		/* Objects refilled to a sheaf */
 	SHEAF_ALLOC,		/* Allocation of an empty sheaf */
@@ -4350,8 +4336,10 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 	 * We assume the percpu sheaves contain only local objects although it's
 	 * not completely guaranteed, so we verify later.
 	 */
-	if (unlikely(node_requested && node != numa_mem_id()))
+	if (unlikely(node_requested && node != numa_mem_id())) {
+		stat(s, ALLOC_NODE_MISMATCH);
 		return NULL;
+	}
 
 	if (!local_trylock(&s->cpu_sheaves->lock))
 		return NULL;
@@ -4374,6 +4362,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 		 */
 		if (page_to_nid(virt_to_page(object)) != node) {
 			local_unlock(&s->cpu_sheaves->lock);
+			stat(s, ALLOC_NODE_MISMATCH);
 			return NULL;
 		}
 	}
@@ -4382,7 +4371,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat(s, ALLOC_PCS);
+	stat(s, ALLOC_FASTPATH);
 
 	return object;
 }
@@ -4454,7 +4443,7 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat_add(s, ALLOC_PCS, batch);
+	stat_add(s, ALLOC_FASTPATH, batch);
 
 	allocated += batch;
 
@@ -5117,8 +5106,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	unsigned long flags;
 	bool on_node_partial;
 
-	stat(s, FREE_SLOWPATH);
-
 	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 		free_to_partial_list(s, slab, head, tail, cnt, addr);
 		return;
@@ -5422,7 +5409,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat(s, FREE_PCS);
+	stat(s, FREE_FASTPATH);
 
 	return true;
 }
@@ -5687,7 +5674,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat_add(s, FREE_PCS, batch);
+	stat_add(s, FREE_FASTPATH, batch);
 
 	if (batch < size) {
 		p += batch;
@@ -5709,10 +5696,12 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 	 */
 fallback:
 	__kmem_cache_free_bulk(s, size, p);
+	stat_add(s, FREE_SLOWPATH, size);
 
 flush_remote:
 	if (remote_nr) {
 		__kmem_cache_free_bulk(s, remote_nr, &remote_objects[0]);
+		stat_add(s, FREE_SLOWPATH, remote_nr);
 		if (i < size) {
 			remote_nr = 0;
 			goto next_remote_batch;
@@ -5766,6 +5755,7 @@ static void free_deferred_objects(struct irq_work *work)
 		set_freepointer(s, x, NULL);
 
 		__slab_free(s, slab, x, x, 1, _THIS_IP_);
+		stat(s, FREE_SLOWPATH);
 	}
 }
 
@@ -5807,6 +5797,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	}
 
 	__slab_free(s, slab, object, object, 1, addr);
+	stat(s, FREE_SLOWPATH);
 }
 
 #ifdef CONFIG_MEMCG
@@ -5829,8 +5820,10 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
 	 */
-	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
+	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt))) {
 		__slab_free(s, slab, head, tail, cnt, addr);
+		stat_add(s, FREE_SLOWPATH, cnt);
+	}
 }
 
 #ifdef CONFIG_SLUB_RCU_DEBUG
@@ -5855,8 +5848,10 @@ static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
 		return;
 
 	/* resume freeing */
-	if (slab_free_hook(s, object, slab_want_init_on_free(s), true))
+	if (slab_free_hook(s, object, slab_want_init_on_free(s), true)) {
 		__slab_free(s, slab, object, object, 1, _THIS_IP_);
+		stat(s, FREE_SLOWPATH);
+	}
 }
 #endif /* CONFIG_SLUB_RCU_DEBUG */
 
@@ -5864,6 +5859,7 @@ static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
 	__slab_free(cache, virt_to_slab(x), x, x, 1, addr);
+	stat(cache, FREE_SLOWPATH);
 }
 #endif
 
@@ -6733,6 +6729,7 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 		i = refill_objects(s, p, flags, size, size);
 		if (i < size)
 			goto error;
+		stat_add(s, ALLOC_SLOWPATH, i);
 	}
 
 	return i;
@@ -8736,33 +8733,19 @@ static ssize_t text##_store(struct kmem_cache *s,		\
 }								\
 SLAB_ATTR(text);						\
 
-STAT_ATTR(ALLOC_PCS, alloc_cpu_sheaf);
 STAT_ATTR(ALLOC_FASTPATH, alloc_fastpath);
 STAT_ATTR(ALLOC_SLOWPATH, alloc_slowpath);
-STAT_ATTR(FREE_PCS, free_cpu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
 STAT_ATTR(FREE_FASTPATH, free_fastpath);
 STAT_ATTR(FREE_SLOWPATH, free_slowpath);
 STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
 STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
-STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
 STAT_ATTR(ALLOC_SLAB, alloc_slab);
-STAT_ATTR(ALLOC_REFILL, alloc_refill);
 STAT_ATTR(ALLOC_NODE_MISMATCH, alloc_node_mismatch);
 STAT_ATTR(FREE_SLAB, free_slab);
-STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
-STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
-STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
-STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
-STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
 STAT_ATTR(ORDER_FALLBACK, order_fallback);
-STAT_ATTR(CMPXCHG_DOUBLE_CPU_FAIL, cmpxchg_double_cpu_fail);
 STAT_ATTR(CMPXCHG_DOUBLE_FAIL, cmpxchg_double_fail);
-STAT_ATTR(CPU_PARTIAL_ALLOC, cpu_partial_alloc);
-STAT_ATTR(CPU_PARTIAL_FREE, cpu_partial_free);
-STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
-STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
 STAT_ATTR(SHEAF_FLUSH, sheaf_flush);
 STAT_ATTR(SHEAF_REFILL, sheaf_refill);
 STAT_ATTR(SHEAF_ALLOC, sheaf_alloc);
@@ -8838,33 +8821,19 @@ static struct attribute *slab_attrs[] = {
 	&remote_node_defrag_ratio_attr.attr,
 #endif
 #ifdef CONFIG_SLUB_STATS
-	&alloc_cpu_sheaf_attr.attr,
 	&alloc_fastpath_attr.attr,
 	&alloc_slowpath_attr.attr,
-	&free_cpu_sheaf_attr.attr,
 	&free_rcu_sheaf_attr.attr,
 	&free_rcu_sheaf_fail_attr.attr,
 	&free_fastpath_attr.attr,
 	&free_slowpath_attr.attr,
 	&free_add_partial_attr.attr,
 	&free_remove_partial_attr.attr,
-	&alloc_from_partial_attr.attr,
 	&alloc_slab_attr.attr,
-	&alloc_refill_attr.attr,
 	&alloc_node_mismatch_attr.attr,
 	&free_slab_attr.attr,
-	&cpuslab_flush_attr.attr,
-	&deactivate_full_attr.attr,
-	&deactivate_empty_attr.attr,
-	&deactivate_remote_frees_attr.attr,
-	&deactivate_bypass_attr.attr,
 	&order_fallback_attr.attr,
 	&cmpxchg_double_fail_attr.attr,
-	&cmpxchg_double_cpu_fail_attr.attr,
-	&cpu_partial_alloc_attr.attr,
-	&cpu_partial_free_attr.attr,
-	&cpu_partial_node_attr.attr,
-	&cpu_partial_drain_attr.attr,
 	&sheaf_flush_attr.attr,
 	&sheaf_refill_attr.attr,
 	&sheaf_alloc_attr.attr,

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-22-041323d506f7%40suse.cz.
