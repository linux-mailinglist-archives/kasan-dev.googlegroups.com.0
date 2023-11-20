Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQ6N52VAMGQEGGY4CLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 96FCE7F1C7B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:44 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40a48806258sf14871305e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505284; cv=pass;
        d=google.com; s=arc-20160816;
        b=l7dbct4ehANggBgLzt2oHWmF+otBOkY41NxiFCkPct5ltf+oszJtj7BwQJhutsSiCo
         LF96NKkjz/AJ6jBdOyWicULXxdtIMzYQj0P6Qz20l8Zffg6EAJ4z03GW1LgIZKIU3VI5
         Fdic2LqH+5iLWwVF5m83n5SLiMIeV2uXaLoHqEpmQK6xbF3JTqVs9edUDVsBimGyBTid
         AADZxoH8T1NBO8FLwxwp9MNm1A/VDWbLtAz/qquTgIgUs1+HWKzvbwsw9mI7AtdCKrRw
         Cja30HZtMhmaczGm+FslIBeLnOa31d+NWaYu3Cl8Hq+xBd7A7bplO4PwuLoAZc1hocrB
         uHsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=UTOJxt1ibfIe92vhfDHNbAweUQeVvBJlUHSTTRlc/lA=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=rVyzm+uL9Kc0nx6tJV+HpmJf12xefnetzk8xoqRRbSYnHpHprQgiJxN0rNpIAVlhmK
         qYYIOLDH2ZOqzUoYWoCr70fschpY3TCaBSVZp1A0yWKCggvS4vZQld1SrXRz5vr7q5wE
         CuV1Q9pyMs+vYpT5oUIUjS+LMcVMCFdxm+I40I4H7SEicZX7x5QPl4sPf94jwqNXxeGl
         KzN5LfV2bLwXtzseWjtPmP/qApWbvqajH5lV00l103YJqq8NuaYflmbjQJLPTjHKmJ3/
         /+USepBgLpdm/hIYYi3rLrZw7exP+aou01KGtmd4HtPUfo5x151ry7p7DyRckTLsglMz
         RyHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Xi8x2Mai;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505284; x=1701110084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UTOJxt1ibfIe92vhfDHNbAweUQeVvBJlUHSTTRlc/lA=;
        b=iLsyPfRrYwmLckWXVAwQ6Po86oIhEjNTqAGZHzqrsNC3OBdcV0YDzQmX4eVF791tHD
         8hxAiuvxqRKdLc55IzMQO6D51CAmxh2IBPIj0kWnYJR0J+SmTvTP81+RzlxyRp5r08Vm
         PvcsfjvWE4kgFUC9KcUJRaRBq5ndaPIOoYgMS/ij8QywBbE8qv2MpsEyFZO2gszV2XlM
         K4KEllcEyIQoWEL20LCla7CIijYnRnBNEERKIFyX4inHP2tHN8vXyKomP5cS68dLW5IF
         acjvL1RWHOIQnq/5xTTqr1kWqa4gB02RW1Cy95AdrxuqsWcQAAyN/Rby2ALBpevXBPuz
         bheg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505284; x=1701110084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UTOJxt1ibfIe92vhfDHNbAweUQeVvBJlUHSTTRlc/lA=;
        b=FU+NtdtnkM4KO+jvVzIDqX1uNCoPtN3n8SMJBueqNhpfqmLqmJESgZP7qwGBhuaB6G
         Cvfl6lRWyxU9t4/RUdsuCS7piuJlWIMDmJSdlISByv3lfDx4Yg9gHfIBUZayctRyUHpp
         yk3W0lWHwLy78GHqlSsijIessTS23ggfITPZ2YVQ62Vc+kxbzqRzznf0rBiwS0w+8pW5
         ZjnG6sflbueYcrLvhBOBUq0pQaAepW6YA8SnAOxQEbibXQwOUR4721Z0sjIao4BsVS6J
         6a1vf096OXYBc/nbutJkSSmJSSnRmsYwT7qnMbe7KXxkb3jrONRGG0LyrBUuj4vdhITe
         h8Cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz78fbG52ulNkeSrTb5+FT1rEaGX3kZpFJnxF2+XRoSbM/T8BW3
	imBHrYIaY2Z2xKRLjhnyHLM=
X-Google-Smtp-Source: AGHT+IGcvKU687LHcVy2EdkAknNHWcZiQZqTniQNd3Lw4iz2ocuDdYWOtXkfc78e8z8y40ykBfoHig==
X-Received: by 2002:a05:600c:511f:b0:409:677:31e7 with SMTP id o31-20020a05600c511f00b00409067731e7mr6248396wms.11.1700505283808;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d26:b0:409:3542:341d with SMTP id
 l38-20020a05600c1d2600b004093542341dls1097942wms.1.-pod-prod-08-eu; Mon, 20
 Nov 2023 10:34:42 -0800 (PST)
X-Received: by 2002:a05:600c:524a:b0:40a:5290:dcf9 with SMTP id fc10-20020a05600c524a00b0040a5290dcf9mr6017155wmb.33.1700505282188;
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505282; cv=none;
        d=google.com; s=arc-20160816;
        b=pc7c9jRebn46RX2fxte350/pyuwScwO3yVJ9JSnu7Fda3PZ0ZeBXSS8eioimLEnTQW
         2L0O+BmIkuh5dxrj77CtPZ1BjeJb3wYZ5EQvmq7qvHrMkdtdr4/equBr9waAFZ4WFzZy
         sQde4ExxJHtTBaToYnzuFNK14JI2QHeldNbKLSsI261bnqtg1yuC8RBJq1Ncl8D2YXcH
         uJZH4HNYpdpPDGpjdS3VIIm6GUXtWGSwZxMqi4ScaIsf7ZUjq79VtULvCUq27aZXk4R6
         Ypfg4Jta+Ko/P0sxn2RlEKrid4fxCUNQ+k+q8Bj7H1/A4GDfqAOK2nHb8NDCqI66XJoA
         1+iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=aVfRs6M7+9kPCQWxAD8DsCdbOnhN2KBENiJIM8UzvaI=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=fSq/Iis59TMHBhDHy+dcbAdgqNAuIyK12U2NQm7eoYvg+TDNGCJHJ2zzHiRSZ1umpe
         uxgoo7tycDLecqx1tsR1r4IDR3Qp+N1HTBGCqxvha8SUsdrf+fFwpsgTDSzQeqvQo6h4
         Gt+A2U/e+1yscE4U6COGf3siRJFHZBFTccIM5CAZyGkH3/gnI6mMNvJ8lGAyhPun7gR7
         5bi6xewNoc3fdK8f7KhXTDhZ1kuv0KFa7r+oZYumQ5egXOXwgsKoP+7qXejaZ91qEyTx
         FPo7qiuJWFF3HE/pq8Q1G0jkrjji6S3MwPm7MdWn3D8A+n44q9igs7AKGGcOCmGeP06U
         D7wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Xi8x2Mai;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id m18-20020a05600c3b1200b0040b26d7d202si19698wms.0.2023.11.20.10.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E026321923;
	Mon, 20 Nov 2023 18:34:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 9F8C013912;
	Mon, 20 Nov 2023 18:34:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id KDB8JsGmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:41 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:21 +0100
Subject: [PATCH v2 10/21] mm/slab: move struct kmem_cache_cpu declaration
 to slub.c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-10-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: *
X-Spam-Score: 1.30
X-Spamd-Result: default: False [1.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 BAYES_SPAM(5.10)[100.00%];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Xi8x2Mai;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted
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

Nothing outside SLUB itself accesses the struct kmem_cache_cpu fields so
it does not need to be declared in slub_def.h. This allows also to move
enum stat_item.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slub_def.h | 54 ------------------------------------------------
 mm/slub.c                | 54 ++++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 54 insertions(+), 54 deletions(-)

diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index deb90cf4bffb..a0229ea42977 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -12,60 +12,6 @@
 #include <linux/reciprocal_div.h>
 #include <linux/local_lock.h>
 
-enum stat_item {
-	ALLOC_FASTPATH,		/* Allocation from cpu slab */
-	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
-	FREE_FASTPATH,		/* Free to cpu slab */
-	FREE_SLOWPATH,		/* Freeing not to cpu slab */
-	FREE_FROZEN,		/* Freeing to frozen slab */
-	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
-	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
-	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
-	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
-	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
-	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
-	FREE_SLAB,		/* Slab freed to the page allocator */
-	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
-	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
-	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
-	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
-	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
-	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
-	DEACTIVATE_BYPASS,	/* Implicit deactivation */
-	ORDER_FALLBACK,		/* Number of times fallback was necessary */
-	CMPXCHG_DOUBLE_CPU_FAIL,/* Failure of this_cpu_cmpxchg_double */
-	CMPXCHG_DOUBLE_FAIL,	/* Number of times that cmpxchg double did not match */
-	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
-	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
-	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
-	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
-	NR_SLUB_STAT_ITEMS
-};
-
-#ifndef CONFIG_SLUB_TINY
-/*
- * When changing the layout, make sure freelist and tid are still compatible
- * with this_cpu_cmpxchg_double() alignment requirements.
- */
-struct kmem_cache_cpu {
-	union {
-		struct {
-			void **freelist;	/* Pointer to next available object */
-			unsigned long tid;	/* Globally unique transaction id */
-		};
-		freelist_aba_t freelist_tid;
-	};
-	struct slab *slab;	/* The slab from which we are allocating */
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	struct slab *partial;	/* Partially allocated frozen slabs */
-#endif
-	local_lock_t lock;	/* Protects the fields above */
-#ifdef CONFIG_SLUB_STATS
-	unsigned stat[NR_SLUB_STAT_ITEMS];
-#endif
-};
-#endif /* CONFIG_SLUB_TINY */
-
 #ifdef CONFIG_SLUB_CPU_PARTIAL
 #define slub_percpu_partial(c)		((c)->partial)
 
diff --git a/mm/slub.c b/mm/slub.c
index 3e01731783df..979932d046fd 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -330,6 +330,60 @@ static void debugfs_slab_add(struct kmem_cache *);
 static inline void debugfs_slab_add(struct kmem_cache *s) { }
 #endif
 
+enum stat_item {
+	ALLOC_FASTPATH,		/* Allocation from cpu slab */
+	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
+	FREE_FASTPATH,		/* Free to cpu slab */
+	FREE_SLOWPATH,		/* Freeing not to cpu slab */
+	FREE_FROZEN,		/* Freeing to frozen slab */
+	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
+	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
+	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
+	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
+	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
+	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
+	FREE_SLAB,		/* Slab freed to the page allocator */
+	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
+	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
+	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
+	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
+	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
+	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
+	DEACTIVATE_BYPASS,	/* Implicit deactivation */
+	ORDER_FALLBACK,		/* Number of times fallback was necessary */
+	CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
+	CMPXCHG_DOUBLE_FAIL,	/* Failures of slab freelist update */
+	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
+	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
+	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
+	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
+	NR_SLUB_STAT_ITEMS
+};
+
+#ifndef CONFIG_SLUB_TINY
+/*
+ * When changing the layout, make sure freelist and tid are still compatible
+ * with this_cpu_cmpxchg_double() alignment requirements.
+ */
+struct kmem_cache_cpu {
+	union {
+		struct {
+			void **freelist;	/* Pointer to next available object */
+			unsigned long tid;	/* Globally unique transaction id */
+		};
+		freelist_aba_t freelist_tid;
+	};
+	struct slab *slab;	/* The slab from which we are allocating */
+#ifdef CONFIG_SLUB_CPU_PARTIAL
+	struct slab *partial;	/* Partially allocated frozen slabs */
+#endif
+	local_lock_t lock;	/* Protects the fields above */
+#ifdef CONFIG_SLUB_STATS
+	unsigned int stat[NR_SLUB_STAT_ITEMS];
+#endif
+};
+#endif /* CONFIG_SLUB_TINY */
+
 static inline void stat(const struct kmem_cache *s, enum stat_item si)
 {
 #ifdef CONFIG_SLUB_STATS

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-10-9c9c70177183%40suse.cz.
