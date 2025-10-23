Return-Path: <kasan-dev+bncBDXYDPH3S4OBBUHG5DDQMGQETWX66DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 03FA9C018EB
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:22 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-579e84da8a6sf530733e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227601; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ph5rBz5koKl8kjIfW90Y+O4lpPDcTWmCPE8oVlgMd1+M1w7F/yGjGxXjMDX5k3EhVN
         lim5avMFBgNc/mW4JrnDbse0n1K/TmyOyCFWmjcu8K/3avo70vhFR56roAUYwtRex+zB
         MMvdN36p9voEQ07Xy3xRh2dpSrDzim0nzgiEL8JuQ1CySoO6tifmaTgYsUmhNCKyAaB0
         Aib+wj98++5K0JEYr+o97hZTbJdQVZjkRoInDq37pC1+sp9OsIQZXD1Pbxg5ubJtY8m2
         TYFqFMbU6IQRyL7Bss0F/ehdtynpBeoUn4wCRd/OwQ/7HHrKcoa5c/PGzNMEVqLcSn6F
         qF1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=tcxoJjVSJCM/7tKm75V6G8JXETsDCIWiXKuLVotnwHQ=;
        fh=KFame3QAT//8H4N+ZnrNLPKkcBc9SrPz+w4ma/cn9Yc=;
        b=XS5BWqUbdPg3abSXl5SNzyLw7XlP/3qmlnHMZPjSQA9ENFV6f2LSLo25yn+5hZ9gnr
         OBwWOx3Rvv1zWBhG81Q6qYBweAxUnS1TkbnRB/ox8EYDww7VExuE1qRWED2oDrz2RIoF
         A6TuBkKe2UCgrhwZa+N4JFTBndz6BV70V2zlsxfLWzkJLkNkU4ZQBNKuU9SIUW56IHwV
         YP0CAFfP6X1Cxt3mwJqRv9zNtoIseYyusv5YsFcwY87XrSGdWOAQy4Q1MvwvDli5e+Wx
         U7LoSR0wl62NHlj191xTSmSvDyUjOWMvXJHX6I7dJoWqfQ4YBl6DKDmnKXtLf6WNNzAl
         /zZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MOGWAwma;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mOq003rK;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227601; x=1761832401; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tcxoJjVSJCM/7tKm75V6G8JXETsDCIWiXKuLVotnwHQ=;
        b=ilughRUFqwWw8z8vKwIE0IjcN3x/GtMxi2MZJk0oJjM4hL6jdYiVzJ4xFlqvGhS0uR
         V5fLGNk8Rj+WjIvV//2z9SidwSEAMMLgqpo8KO4YnwvW23YfS4lSDcTi6zzYubXtJnNL
         S6c6q2cVVGb95f21j4zs5zZBEmI7BvkgrbfnqOLw+biaQe4Ci9SrBj0TjFe2om4VQZRx
         rk6hmKlG5ZdLXiui0elQ4YPw33mQCxX7/EscMp/3mjMTo2AJ+qdHZHyDSyG6Q4Ij3i9y
         QpPirQvsx8vJ06s43Fzlg6UCLxir+hxuVkuiN+rU2jo/7/utjQ0tkphTdm+Di8afY9eA
         UXTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227601; x=1761832401;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tcxoJjVSJCM/7tKm75V6G8JXETsDCIWiXKuLVotnwHQ=;
        b=oEFDjCtWOWTTR6Qp3K/HYsNfqZQWTazUCq3ZhT/0rW53VR9jCQm5qGETDvNJMmKkpV
         sjXmc2pmfH5RHbLMYH8x+quADl9PhXUiGEern5om05U0ETwXjGMqbD3wADKVwpm+kQhE
         rmB/SR+7aZSQ40qvurIbr+VzDND5WOPJlczbSqQrTC60zQ5Y/UseqvOayMcG7g9K4f5P
         7Mz8MrNs4tu1UTICkFlXpx4+/iuXBHOhbgrTZV8FpXS72N8+DXOx43XiIKgV9T5lwkUX
         aSx4UG9chcpODHvIGyrTMQEhRzES1nhTsvP4ds7e22Dcf8AgiimE06Vf3tlpr4sodo3a
         STyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0cBl34khwXv2ZuRaFb5x4g7XXXl6d3uuLv5Z983pbwn6rzMS35uVtVpjNe+cHeSaMbfnLow==@lfdr.de
X-Gm-Message-State: AOJu0YzQk1mQB/qw9HqnaqwfSsuoHOoxr7NLdBVaIZVl1MiLBwhVio1A
	ajHmdROlUzc+ld0Bgr3g6uR6dMpCuA0YKpam64Oe0fZ1pmbNFgUxSHQt
X-Google-Smtp-Source: AGHT+IEeHyc+KH3KMuSA77Z/YguuENTOTiMOdgHPj66EQw8o9yY1hURO+ENqPc1S83lGYAvuhvybCw==
X-Received: by 2002:a05:6512:10d4:b0:591:eb9d:ac08 with SMTP id 2adb3069b0e04-592f5a5c5b3mr838621e87.37.1761227600860;
        Thu, 23 Oct 2025 06:53:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+akgVQxzXIBc/xaNkCclvaHFv8EYxlauFZnDK3xllT1ug=="
Received: by 2002:a05:6512:61b3:b0:591:ec1c:1dbe with SMTP id
 2adb3069b0e04-592f53bd677ls220631e87.1.-pod-prod-01-eu; Thu, 23 Oct 2025
 06:53:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdviMvzVkDmp1M82K93UA0AhgRdX3Dp/coY8mGx3AVISeWtGPSqI6YuLxcl3AoHuSnBuJNCeINx+c=@googlegroups.com
X-Received: by 2002:a05:6512:61b3:b0:591:eb0e:4c1 with SMTP id 2adb3069b0e04-592f59048a3mr796507e87.10.1761227597945;
        Thu, 23 Oct 2025 06:53:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227597; cv=none;
        d=google.com; s=arc-20240605;
        b=Mmr47Q30H6t+3w6YcvHrQ0QA3wAcMPsXICQQZe2H3XD1ZCTOVmkhqEKDLRu4ArHQmK
         mzzZBd8eKfmH7C4cbmj26LHWrHQXUhRi5FpgzrXfFQc5moAIobNJmU+LXxkTltcMkgTz
         kC0sQMyAJGWBci7Z/uOgxwhBtwUbhtmaj+z/L1VaOpdiWuqhgxnhi1kqEhDqX5CTh7ml
         JkgI/5MJZb+Z2yELLz7GOPfDnOOy2LDrMq4H+4iqXbHC7GcIlgM6+6jDxYqTR1XzvfD1
         BvdDTqsexMtH6bXTXcVKDqJY5Cc+nVI+LnEj0F1Ukq8qf4oJuL2lrIcGs8zx40Hh9Ian
         7hgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=CDkwJ98STTAq4ia+HrB8vgXHgqJB0sa+3LSjpxlnzDw=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=P6+LaWME+xmu23QZr/kKzQZ3igatMG4PJZejDLLNyO53L65VmTI4/wMrbU5+inPODB
         8KXS812KtrP3DzZ6N8qkuyCCeT2eaIZov/FmxEMMi/tYETM7wYf1412OSwxbtfzeeJJD
         UmDAuU5xJBvJB1guk3lJW8FmuRhtOghtz08r7XP+kr21VBQheE4UG6LQbXbC0wzKDCJy
         sz99UhNutKDObtH86HVssAmzGpX4C2VTFZD/TTbUnqtiXEbdFAMOb4tzlgFORTCQ/WmJ
         7pGgIgG2darDbGER+ujar9Y5VnmsiVEWnFkZS/pO4M8x0SKIAn04q1a9Y4uPKQByuVut
         qS/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MOGWAwma;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mOq003rK;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-592f4aa1a26si46214e87.0.2025.10.23.06.53.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7F26121254;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 61FE713AE7;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id aBahFzUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:26 +0200
Subject: [PATCH RFC 04/19] slab: prevent recursive kmalloc() in
 alloc_empty_sheaf()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-4-6ffa2c9941c0@suse.cz>
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
X-Spam-Level: 
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=MOGWAwma;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=mOq003rK;       dkim=neutral (no key)
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

We want to expand usage of sheaves to all non-boot caches, including
kmalloc caches. Since sheaves themselves are also allocated by
kmalloc(), we need to prevent excessive or infinite recursion -
depending on sheaf size, the sheaf can be allocated from smaller, same
or larger kmalloc size bucket, there's no particular constraint.

This is similar to allocating the objext arrays so let's just reuse the
existing mechanisms for those. __GFP_NO_OBJ_EXT in alloc_empty_sheaf()
will prevent a nested kmalloc() from allocating a sheaf itself - it will
either have sheaves already, or fallback to a non-sheaf-cached
allocation (so bootstrap of sheaves in a kmalloc cache that allocates
sheaves from its own size bucket is possible). Additionally, reuse
OBJCGS_CLEAR_MASK to clear unwanted gfp flags from the nested
allocation.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/gfp_types.h |  6 ------
 mm/slub.c                 | 36 ++++++++++++++++++++++++++----------
 2 files changed, 26 insertions(+), 16 deletions(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 65db9349f905..3de43b12209e 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -55,9 +55,7 @@ enum {
 #ifdef CONFIG_LOCKDEP
 	___GFP_NOLOCKDEP_BIT,
 #endif
-#ifdef CONFIG_SLAB_OBJ_EXT
 	___GFP_NO_OBJ_EXT_BIT,
-#endif
 	___GFP_LAST_BIT
 };
 
@@ -98,11 +96,7 @@ enum {
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
-#ifdef CONFIG_SLAB_OBJ_EXT
 #define ___GFP_NO_OBJ_EXT       BIT(___GFP_NO_OBJ_EXT_BIT)
-#else
-#define ___GFP_NO_OBJ_EXT       0
-#endif
 
 /*
  * Physical address zone modifiers (see linux/mmzone.h - low four bits)
diff --git a/mm/slub.c b/mm/slub.c
index 68867cd52c4f..f2b2a6180759 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2031,6 +2031,14 @@ static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
 }
 #endif /* CONFIG_SLUB_DEBUG */
 
+/*
+ * The allocated objcg pointers array is not accounted directly.
+ * Moreover, it should not come from DMA buffer and is not readily
+ * reclaimable. So those GFP bits should be masked off.
+ */
+#define OBJCGS_CLEAR_MASK	(__GFP_DMA | __GFP_RECLAIMABLE | \
+				__GFP_ACCOUNT | __GFP_NOFAIL)
+
 #ifdef CONFIG_SLAB_OBJ_EXT
 
 #ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
@@ -2081,14 +2089,6 @@ static inline void handle_failed_objexts_alloc(unsigned long obj_exts,
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
-/*
- * The allocated objcg pointers array is not accounted directly.
- * Moreover, it should not come from DMA buffer and is not readily
- * reclaimable. So those GFP bits should be masked off.
- */
-#define OBJCGS_CLEAR_MASK	(__GFP_DMA | __GFP_RECLAIMABLE | \
-				__GFP_ACCOUNT | __GFP_NOFAIL)
-
 static inline void init_slab_obj_exts(struct slab *slab)
 {
 	slab->obj_exts = 0;
@@ -2590,8 +2590,24 @@ static void *setup_object(struct kmem_cache *s, void *object)
 
 static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
 {
-	struct slab_sheaf *sheaf = kzalloc(struct_size(sheaf, objects,
-					s->sheaf_capacity), gfp);
+	struct slab_sheaf *sheaf;
+	size_t sheaf_size;
+
+	if (gfp & __GFP_NO_OBJ_EXT)
+		return NULL;
+
+	gfp &= ~OBJCGS_CLEAR_MASK;
+
+	/*
+	 * Prevent recursion to the same cache, or a deep stack of kmallocs of
+	 * varying sizes (sheaf capacity might differ for each kmalloc size
+	 * bucket)
+	 */
+	if (s->flags & SLAB_KMALLOC)
+		gfp |= __GFP_NO_OBJ_EXT;
+
+	sheaf_size = struct_size(sheaf, objects, s->sheaf_capacity);
+	sheaf = kzalloc(sheaf_size, gfp);
 
 	if (unlikely(!sheaf))
 		return NULL;

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-4-6ffa2c9941c0%40suse.cz.
