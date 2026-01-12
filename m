Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCVBSTFQMGQEPS6OEZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 257A9D1390D
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:32 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b8720608e53sf114222066b.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231051; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pt70A2bCqTBk7CXe++47toO+jzfkYgRWb/Nm6zavgHNRWGLAnl0l/BfA11e/ZyKPxQ
         ubVqE4x3tNh2scAtvj11/KjJwAEzIXNjB6Qnhb44WKTOq3cXQpqgOIz6crr1l3aQWwdw
         ivGVoYVr+mCgABjXWnNkoQrrHpYrWMfFsmz4sSQh+9v+uTxGiuG5wIj0Jprt2iZhe2qe
         omv2YlTJN7sgdb51MDw9JNv0QrUA819Meq3TWzhOuJrrjEmyyw0wMWC8TQS9RuurxhVm
         ujslpjche0Ztooq8w0yiMvsJsngzTo9akBFdZvhO5IqP8ztgqpEI1O7s6ihDKusv9cdu
         L4UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=6NP9lnPxOdh/K0fgFk0GZ6jB1Nk5MK1dV4IQQGB1jw8=;
        fh=6/g5LFrGzmhUX6b/hoV4VYNWDHbjt6jlue7ssngZpqA=;
        b=VyWhmy8Js9E0OJsxoo0/Ep11rSWB2HwDLMZvrSxmlxPTYotBa4lr38p3g/Z3BC2uz8
         ibk3P0NJCyP2GsHmoOAQCWa543A4+3/dazPYRiSy9Z/0FUGkj1xJM+9n1iT5CLQfBmON
         2HVK1oNsKuiSizCoITwRjtPmitpuscLHa/4C32aMyWNNGy7fmQxICuLww+cowH1rQl7y
         gdwlU9jtzNOMAr0QyaraGf6HP5U0xjcjB3U1EhyQT/YE0mN4M8Odo3kQhlT/IjxYr6AX
         FRcPUzIKon8wMlQ/APkpMas5h9vKg9G1l+9QP3In9GSParygE8dtUTh2sMqTOAZPbOip
         tvDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=3Ha3gYTY;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=3Ha3gYTY;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231051; x=1768835851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6NP9lnPxOdh/K0fgFk0GZ6jB1Nk5MK1dV4IQQGB1jw8=;
        b=WIyTfAIML1lrPoGHPo94JgzbfyfIWicEqHWhI+qS/rL5LSKI6bFSSRqLRePD/oISUp
         DFLdYS9i0EldV3TlimtuafDaDjDBgNrPZuc1WGuSF9zxNT+3ffXxne+rZsqv0iJOJxmS
         o/0skKsf0d/OiI98Od6c2a+kBz3Cro1Ez0sTv+FAYULv+KF/yuQsgbPRD1Xq15xTN/18
         /bvhfVx13A9t+2b4CU7kFfOBSyKENlRka79J5C43rc4xzjUsoDEpozd6p7eLpgYwUrnO
         7BKH124LPn32cdlX2j2W1svuHuUzUcQqwu/wYMkwh44/cVR67Apwu+/CLmsBY8oF1A9z
         RYMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231051; x=1768835851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6NP9lnPxOdh/K0fgFk0GZ6jB1Nk5MK1dV4IQQGB1jw8=;
        b=cr88O8yL265t4V+zOqRajbKIb90r7o6zpzLvk69pEhFRv6AAMKl73midhRqiJwxUHk
         bNxbvPXnDqELxVZeE2MMEGciQaHG9YJ4VP4petr5yN5yat+JbVR/FNy1pHssVv0Zyzyw
         h3W0dc/kHo/mFyW/DH1kuBB58NcCeGC8Q6XwvYkD+2XPjZVgk5CAawGioQq9FJk03rsd
         KvDSQCssb8soOdd/dxRSmz00aGWUYBqaDIW8iEwi7Iwru2teYK3skqhUIoenSiw7lU+W
         yXre6GuRD/AJ2I8N5HCb+VQmfDy0rL8TRV/L0ZUFqOnIZhvoC6JPjL3NFKlsQnJr3Oca
         GKyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLZLvdSIyL3dp3UxSNwDXM/q7Y41I8lkuSyiWNKFZxkQR4nujTeLIUzzNn8WtCU0At54Z1Sw==@lfdr.de
X-Gm-Message-State: AOJu0YyjoLf/AocvJlEkILigIAMs+0twYHrzTgmwnnLCHZvTzBSd1bUT
	yHDfYdtfpgA5FF38I22jyQMLfynU08fBro0Tek7fxA+xiXYdynFw04+4
X-Google-Smtp-Source: AGHT+IF0dQJp/q1olsQOc8ClTZB9kp8unfSBTgR1yX3cnkj89z0liYjU1TphzMBi4sb9S4CgM8rSWw==
X-Received: by 2002:a17:906:fe42:b0:b72:a899:169f with SMTP id a640c23a62f3a-b8444c3fad9mr1930380766b.4.1768231051460;
        Mon, 12 Jan 2026 07:17:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HTeiEiosr+lAPZQ1QG/yVX7xJhe0GndQvNousTJ9qo2g=="
Received: by 2002:a05:6402:5356:20b0:644:f95b:b16f with SMTP id
 4fb4d7f45d1cf-6507443534cls4926005a12.0.-pod-prod-08-eu; Mon, 12 Jan 2026
 07:17:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU3ORLWwzYCflyDx2XNqVA6MjyoPm+ANUdj7bJkh3s/RFntnfE5TaoefEEFZ6fxOuhNEWwLlhgfxBA=@googlegroups.com
X-Received: by 2002:a05:6402:5110:b0:64d:1762:9ba2 with SMTP id 4fb4d7f45d1cf-65097df8435mr17430329a12.13.1768231049301;
        Mon, 12 Jan 2026 07:17:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231049; cv=none;
        d=google.com; s=arc-20240605;
        b=e4eYKxkisrYJ8Ygr7Mld9zFz5K7NPn6bp3fJ/W/d3dZPCI2eIEgMNME/0iiLEZ675G
         qlpxEsTb3VlvfWSbMBRmrOZftcKei73ZYY7yV15LSgV2o4Setb05DB3YCL7onoRdVQpk
         XLJlnKVVMEK+P6zsK0A4D3pD6BGkrdyHQnWSaug0/h8LS2Z4cUv5+WqRWwoZmEVfVfQW
         m1MEt97TFElKVOpN1QGt4tjWqvpqByb19WAr2tEcLrOoV0l3cqavGJkqZdNkWPkWCLVz
         Cg0KNJLdTF0yEgc+Gvj7M2BxaYwXmcJsaMqt87sKTm2ZQwVIw4jb5kEo+DoVvZ/KeIJ6
         G1QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=bcLFQc/ui+avkUrpYqgT4MBi/dIYNzGpd9WjmG235Uw=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=HWGYJOzLfy0tT7CU8b92SprBh1RrjRnaeXEDQSxYngK9eUQGcJ/zJAcVtQqyeiP6rO
         GCcNUOTaXt35iMJdXMqUeutg/fgPJwkwrsHvg7+rSz14TVgxdJWVMD3f8KLtSLXYTXEH
         zAAbEBG8FGxcD4jb12nSD65bYrdkXvFvSZ2PPjbMzS1RHoeeWhTNhT9P1+YuKV1RixZ1
         jG6kZSeQ2DK15VjDpHAesmbsIvzzLd9sIWXgSXVosVhevz09mPlfInfHGMVVcqrYGYg5
         ljJn2G9wI7temGmRP7ZQsxq2af/khJQxaAyuMQ2rQzeR8t78IAS2PzrAuV+fGf7uLKbg
         7AdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=3Ha3gYTY;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=3Ha3gYTY;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d723064si382452a12.7.2026.01.12.07.17.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:29 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8A5813369E;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6E0473EA63;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CHOXGmsQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:59 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:13 +0100
Subject: [PATCH RFC v2 19/20] mm/slub: remove DEACTIVATE_TO_* stat items
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-19-98225cfb50cf@suse.cz>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
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
X-Spamd-Result: default: False [-8.30 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	ARC_NA(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid,suse.cz:email]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=3Ha3gYTY;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=3Ha3gYTY;       dkim=neutral (no key)
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

The cpu slabs and their deactivations were removed, so remove the unused
stat items. Weirdly enough the values were also used to control
__add_partial() adding to head or tail of the list, so replace that with
a new enum add_mode, which is cleaner.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 31 +++++++++++++++----------------
 1 file changed, 15 insertions(+), 16 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 5b2d7c387646..a473fa29a905 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -324,6 +324,11 @@ static void debugfs_slab_add(struct kmem_cache *);
 static inline void debugfs_slab_add(struct kmem_cache *s) { }
 #endif
 
+enum add_mode {
+	ADD_TO_HEAD,
+	ADD_TO_TAIL,
+};
+
 enum stat_item {
 	ALLOC_PCS,		/* Allocation from percpu sheaf */
 	ALLOC_FASTPATH,		/* Allocation from cpu slab */
@@ -343,8 +348,6 @@ enum stat_item {
 	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
 	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
 	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
-	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
-	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
 	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
 	DEACTIVATE_BYPASS,	/* Implicit deactivation */
 	ORDER_FALLBACK,		/* Number of times fallback was necessary */
@@ -3253,10 +3256,10 @@ static inline void slab_clear_node_partial(struct slab *slab)
  * Management of partially allocated slabs.
  */
 static inline void
-__add_partial(struct kmem_cache_node *n, struct slab *slab, int tail)
+__add_partial(struct kmem_cache_node *n, struct slab *slab, enum add_mode mode)
 {
 	n->nr_partial++;
-	if (tail == DEACTIVATE_TO_TAIL)
+	if (mode == ADD_TO_TAIL)
 		list_add_tail(&slab->slab_list, &n->partial);
 	else
 		list_add(&slab->slab_list, &n->partial);
@@ -3264,10 +3267,10 @@ __add_partial(struct kmem_cache_node *n, struct slab *slab, int tail)
 }
 
 static inline void add_partial(struct kmem_cache_node *n,
-				struct slab *slab, int tail)
+				struct slab *slab, enum add_mode mode)
 {
 	lockdep_assert_held(&n->list_lock);
-	__add_partial(n, slab, tail);
+	__add_partial(n, slab, mode);
 }
 
 static inline void remove_partial(struct kmem_cache_node *n,
@@ -3360,7 +3363,7 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
 	if (slab->inuse == slab->objects)
 		add_full(s, n, slab);
 	else
-		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		add_partial(n, slab, ADD_TO_HEAD);
 
 	inc_slabs_node(s, nid, slab->objects);
 	spin_unlock_irqrestore(&n->list_lock, flags);
@@ -3979,7 +3982,7 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
 			n = get_node(s, slab_nid(slab));
 			spin_lock_irqsave(&n->list_lock, flags);
 		}
-		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		add_partial(n, slab, ADD_TO_HEAD);
 		spin_unlock_irqrestore(&n->list_lock, flags);
 	}
 
@@ -5054,7 +5057,7 @@ static noinline void free_to_partial_list(
 			/* was on full list */
 			remove_full(s, n, slab);
 			if (!slab_free) {
-				add_partial(n, slab, DEACTIVATE_TO_TAIL);
+				add_partial(n, slab, ADD_TO_TAIL);
 				stat(s, FREE_ADD_PARTIAL);
 			}
 		} else if (slab_free) {
@@ -5174,7 +5177,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	 * then add it.
 	 */
 	if (unlikely(was_full)) {
-		add_partial(n, slab, DEACTIVATE_TO_TAIL);
+		add_partial(n, slab, ADD_TO_TAIL);
 		stat(s, FREE_ADD_PARTIAL);
 	}
 	spin_unlock_irqrestore(&n->list_lock, flags);
@@ -6557,7 +6560,7 @@ __refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int mi
 				continue;
 
 			list_del(&slab->slab_list);
-			add_partial(n, slab, DEACTIVATE_TO_HEAD);
+			add_partial(n, slab, ADD_TO_HEAD);
 		}
 
 		spin_unlock_irqrestore(&n->list_lock, flags);
@@ -7025,7 +7028,7 @@ static void early_kmem_cache_node_alloc(int node)
 	 * No locks need to be taken here as it has just been
 	 * initialized and there is no concurrent access.
 	 */
-	__add_partial(n, slab, DEACTIVATE_TO_HEAD);
+	__add_partial(n, slab, ADD_TO_HEAD);
 }
 
 static void free_kmem_cache_nodes(struct kmem_cache *s)
@@ -8713,8 +8716,6 @@ STAT_ATTR(FREE_SLAB, free_slab);
 STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
 STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
 STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
-STAT_ATTR(DEACTIVATE_TO_HEAD, deactivate_to_head);
-STAT_ATTR(DEACTIVATE_TO_TAIL, deactivate_to_tail);
 STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
 STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
 STAT_ATTR(ORDER_FALLBACK, order_fallback);
@@ -8817,8 +8818,6 @@ static struct attribute *slab_attrs[] = {
 	&cpuslab_flush_attr.attr,
 	&deactivate_full_attr.attr,
 	&deactivate_empty_attr.attr,
-	&deactivate_to_head_attr.attr,
-	&deactivate_to_tail_attr.attr,
 	&deactivate_remote_frees_attr.attr,
 	&deactivate_bypass_attr.attr,
 	&order_fallback_attr.attr,

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-19-98225cfb50cf%40suse.cz.
