Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCHLZGVAMGQE6N3PIAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id EEA4A7EA36C
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:16 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4083717431esf33054145e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902856; cv=pass;
        d=google.com; s=arc-20160816;
        b=QpS4k2IXaI9CQSx1JQknlZL4sUoJxJAHJTv8OXWEJxqnSFQpNjyhEsob/xl4daZ4ZZ
         /qxQ9RD0tfs4ly1FhUFqwCj+Wu6c+mYFg0gvf1j+Y0S+Uy9uWjEaJYzhEj1AUJzdTpww
         Sr1ACKiktu/77hgGWd5sL28zm18eGfP1lZ2zdfEUgsd5ADaleoCpJBSAf6RDJFTOdQZO
         mS9EFnCMbh+9Kcnyvbdm4K9r03G/cY+J3n/qjIPA8CSJTn4boKjH751iJ0NU8bF7sYX0
         zi98i5aI/l8Fc9LmKgVi7t8FJfajE+vA0/EiuunVBtliQodKR5V9fD+LAV6HrwM62+kS
         rTKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BcyA4q0nxXWuO0CI8g99+pDF3IxUaGos+phRu2IZdY0=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=Az6btz1wIRQGbvuKf7Q/2O7nvZ0d3HWgcN6H3feSItcrhmACB2PTSVy7oXf0U2ZAsF
         RY4UzghDOa/W32rL+LvrMlRs3djKKyWxf2TVPwojQGRomhmY05pl2bLoLCG15fnQkjH1
         DazCb+DATYkxHe//lUoq1/85ReY2iBBd+aN6eFaNqoLdpmemHlqi2DL4REwgABstOkgy
         EQsYtNxswJ31DbFvyhxrXDywJvpbZp043M3ytJFbj0qyKIDQPdmpt6PBlHBt/llsSVwz
         zmdd2rNmY4BXrFo6tNpNzHC3JZgYbwU5yQfwXmErVFap1xoK7Njo2Z0o+la3cCj4CXql
         IC2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RpQWn4sN;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=J0Xb8K74;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902856; x=1700507656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BcyA4q0nxXWuO0CI8g99+pDF3IxUaGos+phRu2IZdY0=;
        b=mGOBj7ihbkM6Kp+DNYyS4SnqIPSNsdYt1Yb6M2cBIPZGVdpRiKhbtOw4XTtlbM56Im
         gTeEvWiksWBZcNMpkBpubCBfTag2ddrVT6Sk4UpPnUNNEPQ/9IA6fx2NZBCzrEboUbeB
         TetYSHd3MFLqdwjfJZkktyqjNPg/jdJfgYHi+B6Qhfv/km7Wir5o4JovTYpbvbvUwWKN
         8QfolMrYfzhD0BG95H+kOAm0+YFBZV0iK5h2T92IKbi16pTWzFQ+JRdTQs1m19BAsvuG
         FefRDfBoSZP+CqKQgE4RliVXKKPkb0+FGgYxcHHbc0TGtCjUvMerxorp3AaUemLqvc5R
         KH8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902856; x=1700507656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BcyA4q0nxXWuO0CI8g99+pDF3IxUaGos+phRu2IZdY0=;
        b=qFFW5XKlTRC3L4/iofB8ZYoCIANastQij5ImBH4x+QX439Uml+xjJcOag2ZayCH3NB
         SL3JfBuSAilFSCjlVAtmXm+mcBGVjkvxAAB2pV70tfIflhhoH//69gsd3DxK5fMNdlv9
         Mn0ek6q4sXbS7XE6TPiLD8caOrM2FMD85g1rwB+iAaOHx+hE4Tdi8wR3gLUgg26g3VpI
         FdL+QHfA8OFONYiegXBMmsCvkXPpuKYJJRBQznJ8nGAnvFIMnK8dYyidw4QvJv5/Wkjf
         96b5XkLpIUgfcWMHU+uN2VxoB0d+lF5IEqyr6j02a8Tky76YRMb+Q6O6kjFvtHQeOSvC
         e7LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxLLylkC9rx7PpBlwVYLcf4UTW7JPuZetEacy2RpuD4VUhr+Y/D
	iPb+FHFOIzaRkRM8v8wh6YI=
X-Google-Smtp-Source: AGHT+IGd0WWapu+MCPZzFmYter8O+a7TypefDLbvK3CaST1isjuYDnTWcONn86YhPND1mq+DuKnbmQ==
X-Received: by 2002:a05:600c:45c5:b0:40a:25f1:7a28 with SMTP id s5-20020a05600c45c500b0040a25f17a28mr6833883wmo.40.1699902856422;
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c1e:b0:406:6882:6832 with SMTP id
 j30-20020a05600c1c1e00b0040668826832ls1181163wms.2.-pod-prod-09-eu; Mon, 13
 Nov 2023 11:14:14 -0800 (PST)
X-Received: by 2002:a05:600c:4ec9:b0:409:2f7:d771 with SMTP id g9-20020a05600c4ec900b0040902f7d771mr6397841wmq.4.1699902854567;
        Mon, 13 Nov 2023 11:14:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902854; cv=none;
        d=google.com; s=arc-20160816;
        b=EjLXzWLA8P+bNsIyBIDAcy5mAzPaHdeBUf00xVmaOHqq8+e3t8KQILWxkaezMYSlJu
         BfBtsNeZU2qwGy4GO76w74yEp1ZlAhiH+arqwpABs4uk4GLg9qdtQ8bzBVsGfl3aIuMf
         bNmhsE00oDEvMcXG/cCWeb0DTxK38qp2H5sHQNTurECD1qFmkUi8l7+7ucAItw6whzZh
         GTx+ZmTPnl14PTiNLSk4r2AynHS7IJuausb3okGpJGbfipS8aaaPPQawguQPv/x5OHQb
         xodULRjO6bic8/hjHWz0N/01mk18WwDwo7okI+l0Ya71/Rmxn/Cb+102EzN/7+YkwI/0
         pKYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=uxDKJC7EaSr87DEKt16Pu1EQtaytOZJplZCJuXCflPQ=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=mAAJjJZqPKQP1it4H2z0i3zrSkCSWGLDOIy0zdn26t54BvR6TjDVA+5FqrXvKUIUBX
         RKQ7dOJKC4cfcS6DBC1bER0I6FOtaJ6M48A/MFdoSqxNGUW6gOHqefvIAiJydR1IY7xe
         W54J//L2dL2WMvfsMW6YYIntLTmh0ew1rqJwZ5FtG7o3zbGzrcN0k5iTICO1/sc7fhb+
         YF5kTbyA95ATgluu2MMjftE2zFNtY5jsvMCb4csYGeDYCYD/WYGU4qvIe1ehwG2wYYx2
         BnnPVL9MqwxmgdiYWLFWZEwxIlT630xlYM8GKV8hDIYCgj9MvNfPzZhCbVbakvxcvCTb
         Acaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RpQWn4sN;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=J0Xb8K74;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id p5-20020a05600c1d8500b003fc39e1582fsi523527wms.1.2023.11.13.11.14.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:14 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 43E4121921;
	Mon, 13 Nov 2023 19:14:14 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E25AE13398;
	Mon, 13 Nov 2023 19:14:13 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id QNKnNoV1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:13 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 14/20] mm/slab: move struct kmem_cache_node from slab.h to slub.c
Date: Mon, 13 Nov 2023 20:13:55 +0100
Message-ID: <20231113191340.17482-36-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=RpQWn4sN;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=J0Xb8K74;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

The declaration and associated helpers are not used anywhere else
anymore.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h | 29 -----------------------------
 mm/slub.c | 27 +++++++++++++++++++++++++++
 2 files changed, 27 insertions(+), 29 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 8de9780d345a..1b09fd1b4b04 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -587,35 +587,6 @@ static inline size_t slab_ksize(const struct kmem_cache *s)
 	return s->size;
 }
 
-
-/*
- * The slab lists for all objects.
- */
-struct kmem_cache_node {
-	spinlock_t list_lock;
-	unsigned long nr_partial;
-	struct list_head partial;
-#ifdef CONFIG_SLUB_DEBUG
-	atomic_long_t nr_slabs;
-	atomic_long_t total_objects;
-	struct list_head full;
-#endif
-};
-
-static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
-{
-	return s->node[node];
-}
-
-/*
- * Iterator over all nodes. The body will be executed for each node that has
- * a kmem_cache_node structure allocated (which is true for all online nodes)
- */
-#define for_each_kmem_cache_node(__s, __node, __n) \
-	for (__node = 0; __node < nr_node_ids; __node++) \
-		 if ((__n = get_node(__s, __node)))
-
-
 #ifdef CONFIG_SLUB_DEBUG
 void dump_unreclaimable_slab(void);
 #else
diff --git a/mm/slub.c b/mm/slub.c
index 25ff9d2d44a8..0dbb966e28a7 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -396,6 +396,33 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
 #endif
 }
 
+/*
+ * The slab lists for all objects.
+ */
+struct kmem_cache_node {
+	spinlock_t list_lock;
+	unsigned long nr_partial;
+	struct list_head partial;
+#ifdef CONFIG_SLUB_DEBUG
+	atomic_long_t nr_slabs;
+	atomic_long_t total_objects;
+	struct list_head full;
+#endif
+};
+
+static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
+{
+	return s->node[node];
+}
+
+/*
+ * Iterator over all nodes. The body will be executed for each node that has
+ * a kmem_cache_node structure allocated (which is true for all online nodes)
+ */
+#define for_each_kmem_cache_node(__s, __node, __n) \
+	for (__node = 0; __node < nr_node_ids; __node++) \
+		 if ((__n = get_node(__s, __node)))
+
 /*
  * Tracks for which NUMA nodes we have kmem_cache_nodes allocated.
  * Corresponds to node_state[N_NORMAL_MEMORY], but can temporarily
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-36-vbabka%40suse.cz.
