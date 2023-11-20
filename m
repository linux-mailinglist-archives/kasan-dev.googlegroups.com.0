Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRON52VAMGQEYH5G65Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 173A17F1C84
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:46 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5082705f6dfsf4306009e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505285; cv=pass;
        d=google.com; s=arc-20160816;
        b=A9UnI7JQVnb+4MIThvmjD60RwpTFKR1VJuhBRjYeuJmntiV0iUn44XQl/dzgWnjv+g
         IXZ+QAuwbXIJGKnGE8c2kL+hLwqxmEyr3yfixBKyauHZuD+1xYf3m5FwGRu+GIehpBUR
         kXYPtpE6vo2gJILYZyrr52MorfCPgm1cxZs9jZOOSsOYdGubzamIpL13HTD4K79nOmx5
         GD3lVTdguzAPrM6/x1xHB305TA4ctwBQ/bnaFRcZOUXq6yHqW8mfHW38TJKHWtYia2hE
         rv9RdEJLpv4vU5/A5iy+cnpWClCKTBHi96Ro8CCgRDfuASdVHfEMjdutlUqeIwujV4Ik
         zbIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=CPLnHtPpNZSSiQLFuyIDaw2p06PwqcDBFhKkIJWoZu4=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=JmWy3Z43orjwvnqOINDZrJAThwTCAunlqKYzB3Fnm4OUdPwM7cdjDvIsCqg8IrOIPX
         m8Dm5KLBossyuWgEYVXuaBBmUcC5xpvEsD0e0eyYXGTXYsSy3YTwWqEKnrSQ19MBVhmK
         d4csIKs95ALNYIGUxyyU/YH39OCod8SLl0OY0Ez2M9BkUmOla51jWm9FdC3PemJt5U2h
         qYwv5h3qvcjBHk1P/Y6V85nvW0zcJWv06fVXa9CLHcPmvPKJ9SF8668s7XiHe3FpRq8f
         Iu5RIG3GOYNZl3Zqp5ph0jrQJUvtuvDrJD65v1GPq9i0jYBhEIRAy1DB0xCniRsVdYSH
         SDVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TukUKNES;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="SR+5CH/H";
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505285; x=1701110085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CPLnHtPpNZSSiQLFuyIDaw2p06PwqcDBFhKkIJWoZu4=;
        b=beuFP9oYO4IJcdrkh0t4vmWnWFSjsrplZBAk7TKmnq/HAC2MyG5nOYROVyK2xyUKkX
         x91PV+mukSY4U/u8fFP0rUqZM3BdpOY2yDGfxtuG5iXJRBQBOYr9nrWsYHLK/VUlUYIn
         Q/lHmTw94epG8SpqYH23wolfiyGr0llg9zRJdfE7OHIbbo/fRFIt9OWHYV5xfGhiP0Y6
         io8kPTFUhYgdXoywTuk6Fory0hSV5B2I083ikTPvxDh760rr4EOk+/lya1lKi2Hns/Fr
         pr5Lti/msl8mfuhtWvmkhDaddTfXuoOqoRVGnyNy/8OBjSZAn65rXFaQKrTSFTQVZvKp
         QpaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505285; x=1701110085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CPLnHtPpNZSSiQLFuyIDaw2p06PwqcDBFhKkIJWoZu4=;
        b=AkvKBpcYrQ1NdiqtCevgxOWyjQI969Cy/0Q2skQTuIhIJ/LTOC3tcdTn32Up5OQjsE
         aBYtDuaLdW1kq0GHS96+6MatcF4h9tyxL2OkWCxuOTzCyIS1ZIYcUlOW8AzRZ+J+YOCD
         puZ1Po8Mx9KfvD+G79W80PnMj56OvOhIgH34wl2iJj/6wiaj6WJvhNeTTm2GkzSmb0SU
         bYfu4iJuSKqqiy14Htq2CihFafGTA4+ZjdiqDuGBuWOsgLyvHyBfvzas6eQSYdqT5/PP
         rax7iT8OifxOxNYYjeE8W8AyQOQAgu/GDysv1tEzMXXIXvwTWRtRDtwiTeHhfIu3jYfg
         NSUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwfIAh0JWrmAd/t1hqSvwW3QjQrRoK33YlMHhgeVrdWf7gyJ6Hx
	UCRzOh42HVJVyGL3tptpaJw=
X-Google-Smtp-Source: AGHT+IGQtwg6RLjfeBXdWQ8ToGZKDpL2FG0Kxdh4xOtc7wtwZZptQbTsp+Wd/GojrR+vUYViqwtGcw==
X-Received: by 2002:a19:5218:0:b0:50a:71ec:a4ee with SMTP id m24-20020a195218000000b0050a71eca4eemr6008759lfb.8.1700505285378;
        Mon, 20 Nov 2023 10:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d0f:b0:50a:aa99:28a8 with SMTP id
 d15-20020a0565123d0f00b0050aaa9928a8ls69465lfv.0.-pod-prod-01-eu; Mon, 20 Nov
 2023 10:34:43 -0800 (PST)
X-Received: by 2002:a2e:8042:0:b0:2c6:ef8d:b49d with SMTP id p2-20020a2e8042000000b002c6ef8db49dmr6136084ljg.24.1700505283550;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505283; cv=none;
        d=google.com; s=arc-20160816;
        b=feA6OLuptat5nS6c57ULFvt+8uD7EDQhoBQjtV5Kf+3pqKZiGL1IDOiapqYz4sqoEt
         mnohCeGkOJ99jbteshnl65sgyS41s0BMKx51m3B91uDi+VBeWEPACD8hVTx4WL4XYb0m
         dCBNoipOA/oysGdDtRoXeCJpsdRySCXMu21/do1WEcGOOC3hvEkV2r32uHgkPCIilSsr
         YvO+1ZKrGxJoxfSeVtfNGT6l40YNJ1VoAMIuNakDQ3EwBrDl257en4sANaU5jvD8wHGy
         Myiqger+fNEo+RY+SyEBf5JWL6pSnVtiLCptI4mTkfm0o6pI2Ex1/K7vXNMwoKEwcENg
         ENnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=YBNKkmC9oRR4moRDCZJShxotomqe2hJVkCMX0lOWDT0=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=a5WbdSuSt/WBD6AJmCnXz5d5QlXR3PBB0/EUnMOWfcHR/VYvMo5iqVrxgjk9+sVbWk
         r9SJbPNZhFpl+8ctzRQWRd8ao9KFrBVHbzF9if9DvSn9E1VWlRFdC76jNLHcsEVZbJDH
         8cFRAHaU0lDr4TcMJIY6azzJ2VXoVDdNk6IbpAtV1E6bIzHlu0S1hrVtdtpEF1a7oa/K
         Mg4KnoGbEPBw61t8IPJHfOocV/+DbE6CBhDGGVEJ/cmjevPC269KisbUOfR7XexheMas
         Q4TlW7XxNvavot3Z8o6rRt2q13cXC+n2dupTrvYCPF/7r0lov+BDp63elb5qfWyxT9OG
         +k8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TukUKNES;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="SR+5CH/H";
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id e21-20020a2e9855000000b002bced4ef910si344110ljj.3.2023.11.20.10.34.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EC4921F8B5;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BAB8F13912;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id eEMcLcKmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:42 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:26 +0100
Subject: [PATCH v2 15/21] mm/slab: move struct kmem_cache_node from slab.h
 to slub.c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-15-9c9c70177183@suse.cz>
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
X-Spam-Level: 
X-Spam-Score: -3.80
X-Spamd-Result: default: False [-3.80 / 50.00];
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
	 BAYES_SPAM(0.00)[16.07%];
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
 header.i=@suse.cz header.s=susede2_rsa header.b=TukUKNES;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="SR+5CH/H";
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h | 29 -----------------------------
 mm/slub.c | 27 +++++++++++++++++++++++++++
 2 files changed, 27 insertions(+), 29 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index a81ef7c9282d..5ae6a978e9c2 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -588,35 +588,6 @@ static inline size_t slab_ksize(const struct kmem_cache *s)
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
index 844e0beb84ee..cc801f8258fe 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-15-9c9c70177183%40suse.cz.
