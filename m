Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZFGVTEAMGQEJQEQNZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 04E03C34AD6
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 10:05:42 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4775fcf67d8sf2010865e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 01:05:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762333541; cv=pass;
        d=google.com; s=arc-20240605;
        b=gRaGecoIoCBMpBc0UqqttHX1oeSzhiqmqyFmqQtI8fO6QJQUyk6qpgNaOr/Jh/nUBY
         CviloU/Wvu+TyIJ7q5E51w/LMQgbKUWLt9/TG/DxttdKqr3qk4+FfSPr0h52vzpLO5iw
         RMJVpJojyGl/z2aBXTWR+vf19xEN8s/4e2q5/5Nv1/7Cq2OINcjAs0gkt0xy2ER0UCbu
         DQtx+2fvMBltncV3E/14kzoGVJZLVvIoOH3U7Bjv9QmeF9XfoluyTtyyg2aXcdoaJlA+
         JcqvUWZH7y+UsHGi+Gu7V18emhMieCjT0uD2UWrpKFwXjZVhPOOGtk2tUd1c99RKrgd7
         eywA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=FBG/weCksGAZJR1sWdOq+wOlfwoAd7x6cRbUqYfrGZw=;
        fh=zqolgaAjN2CfX37MCD4Rh0kLv3U+9w3womPxfdr9skA=;
        b=cf50ytnrblkov1Sa7z0U0Up5BkXMxD35r62iObxHsW0L0AFNVrS2iOGrn1lMFdtU/c
         1+7QdgG1Y5QexbIW6IY5K7iTWgAkUuIeV++et2LCMuhpDGrDLdplmYxF7irjDe3wcNjj
         EDpuSBJInvO3HEqg2RjyRKEe6hPEi83aWzFOB+HA8xhavQw6CE49XZBF6YNdEIEHFXR1
         r9uSUokNQiBaoMB80qcwkqVQvrmXW9rZ8kqbPFY7iM1eKybXm9PId906e3vQ+rL3ha+Q
         1WuO4hZrK5Q3C2trdfDPWeAx9Xq8ecucqVCtTpAgqcT9kmouC20pRxH1RVZdav6XE3jG
         m2Dw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MDolg0SQ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MDolg0SQ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762333541; x=1762938341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:in-reply-to:references:message-id:mime-version
         :subject:date:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FBG/weCksGAZJR1sWdOq+wOlfwoAd7x6cRbUqYfrGZw=;
        b=kVySlepujyQWhTGWoVJvpgAmQaHaRb9jHfDEuIcVtu1tu7fCtDE1CgPzX4jGkcbDBi
         7zgV4naPXmumnLFlshLmr1q9/84dKvmegJUiyur6tm06vU1kA7ceZPWHhgltj1gDj6C/
         aXo/nAE+GbzjhlF569Tfblbc59yMSHw2IuDp9RUZQQX6kPxwuZZIPg5++7ReTk0iDxXY
         KTW2/qp3GPkJVeY0I+Kg7KbyClzjgSCZmQGE5UrfWmnRYhCgq14tH1gqikpxYATr+6xH
         pCkbXjsbyPlBUIuUOOrP1qLr8OiB1B3zQPwf+sJaWrAug6D6pmW+7U682ZG6g+K+IcMb
         5egQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762333541; x=1762938341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FBG/weCksGAZJR1sWdOq+wOlfwoAd7x6cRbUqYfrGZw=;
        b=JZtu6NrsYuYDv1qzIxeDuSpnfKscPCeNd4wief+PbIEizObqukuD7Nxghr5bpWV6YB
         NbrCri0gK7FjIulZtVGNiyMwehvFSQWKuwnYyVfYcTzOce6c1bbrmrEIsw2MmQ46q9YL
         kaAvlIXzdCfqj2b7HaE9REhLUxzm9TWCydGFRfCmL1tSIuTBKF3TM9/YUty9mbEL/cXl
         dPki5LJKNQZF2U3yYZ6VAzGcXla5YjhkjFf60Z+R16reKJMtr9m0rRQBJAdkNI8eXUzL
         zdIe5e9QmyO7Ciwjmsqa14fYQZENhXNVbfe0+r7WnN4o3ky5KdUo2NAvkEEGba98/mIT
         yAZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXruHJ2BX/phOXoqaBq5UJPudLdmOB6GeqnfSkw0uwi70blCKZxeIDNbweGTyKqz2MPJ+7Syg==@lfdr.de
X-Gm-Message-State: AOJu0YydfnojOIPvwTtNm4wIzwg2lHLd5vt0SG9ATWDxEUoquS4/v6aj
	yPLGk7YnRBP1s3KvrKNAu9axlQmwqtAK598K4fntBayXGYcVepRLRS26
X-Google-Smtp-Source: AGHT+IFH3AH0FZrj5VG4CI1zHW4iek9MnDoGNViLbL/9/G8R9FKfYRBuu2mxvQy3K3ay3C1lIOpa6A==
X-Received: by 2002:a05:600c:5488:b0:45b:9a46:69e9 with SMTP id 5b1f17b1804b1-4775ce14dd0mr19718345e9.31.1762333541332;
        Wed, 05 Nov 2025 01:05:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZkCn0BiifuTPlKKKlVUCLhkp1d+2B0ciw3T+6xRODLCQ=="
Received: by 2002:a05:6000:4305:b0:425:686d:544f with SMTP id
 ffacd0b85a97d-429b4da6ef7ls3821256f8f.1.-pod-prod-09-eu; Wed, 05 Nov 2025
 01:05:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX4H6Cxh1i6LlE1lXJ7odfSbvvmeOtR71ZPtyKfZFwdMZFnXOnXxTt0p+0ejWwaMxXsl5OOYkJTSmU=@googlegroups.com
X-Received: by 2002:a5d:5d09:0:b0:429:d66b:50ae with SMTP id ffacd0b85a97d-429e33130d0mr1929222f8f.57.1762333538072;
        Wed, 05 Nov 2025 01:05:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762333538; cv=none;
        d=google.com; s=arc-20240605;
        b=kK9rXxcdIMxuP7T0fM3Ap4OgGKBBXE/8F9ZLcOQS/gzkJCveDcLt8d1ktTn3k+3pOb
         ALYNdvCM9tZl3lTiCAEUo+Tj2D0AczlP0dXlDG17655UGlJlcckjn1aPz4LcDneZlo+s
         zTsMm96zKRks9/iCckjDFD4RVDS3GgWI00BnUpqf7xNsCbJqgkgSVwd7Nh9EcUxUGMw4
         i3zawxZfN8m2fgMIaamqJ4Wcdh9mzJzV8Bf9daxR4NwC1Ozf/q459IjrHbZTkaKt1Pdr
         UBcvDs0ZihwT167mhuAdbnQH5mx6BUFTHao3V36ibrUU6xQ1Iy6Wh4D6Aj9sskEMpkke
         g6wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=bv7EzbHF/HHIgUO7NDMRC4WExXuoyCIClo0HWu7ZlNQ=;
        fh=dklpSMYSEC41gVZaXcntr2MBCAntdHiJG8gGN2y0lZI=;
        b=OVuRCklImQDlylsjgry2V4VLM/4eUiGIpRn1Y1vBOHw+C0iMthNLzwlafvSwWIjm+y
         9NVydwi2FbmpvMJtPiGhVryxiAo5j1XH3AKUrlRGgmantXCZ1y1IX0kL2Ib6Vy2cdSmi
         QjwnyRUycC0yIY7weZ/ASxL40SEFft8GwoP+nqrv3iGBLzJE2D8aJilLXiXXIh3fj1Qp
         1SkJAxdPVojKSPIQ+iLYXWNqmeQPaLRK3ijqh/5Rx1m3yYdbYU+CzcgHZvJs02fOI1ON
         v6n53Ld6eaw/Q/rQUunMwfphP9AnGq2zU3YmR4dSMzAFMUOJQPkHVSxPMs9tjI1jm14S
         pRGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MDolg0SQ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MDolg0SQ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429dc18e831si98847f8f.1.2025.11.05.01.05.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 01:05:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0549E21195;
	Wed,  5 Nov 2025 09:05:31 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DDA6213C02;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id iPalNVoTC2lSBAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 05 Nov 2025 09:05:30 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 05 Nov 2025 10:05:33 +0100
Subject: [PATCH 5/5] slab: prevent recursive kmalloc() in
 alloc_empty_sheaf()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251105-sheaves-cleanups-v1-5-b8218e1ac7ef@suse.cz>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
In-Reply-To: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, bpf@vger.kernel.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spam-Level: 
X-Spam-Flag: NO
X-Rspamd-Queue-Id: 0549E21195
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
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
	RCPT_COUNT_TWELVE(0.00)[13];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Spam-Score: -4.51
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=MDolg0SQ;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=MDolg0SQ;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
index a7c6d79154f8..f729c208965b 100644
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
@@ -2596,8 +2596,24 @@ static void *setup_object(struct kmem_cache *s, void *object)
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251105-sheaves-cleanups-v1-5-b8218e1ac7ef%40suse.cz.
