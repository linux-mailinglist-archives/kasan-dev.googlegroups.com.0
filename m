Return-Path: <kasan-dev+bncBC7OD3FKWUERB6ND3GXAMGQE3XQ5IZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DA3685E78C
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:47 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf260375ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544506; cv=pass;
        d=google.com; s=arc-20160816;
        b=nKzin2LhNAfHkumNKSigujNf9tRhQKu5IcNBzEVYlcMSViARUFvgssRZjv8MQNVFap
         TfPgN/Lk9Y17+JSSUz0bht4lEVflJSJyK3jkgmPvxOTk6SJBl739I49P2q3QfZ0Qe7uj
         JOuczeuNPwuS3qIP87n/tiu92y+T8PbMs/4dNdUsgz3iMNQlLlh2kv7cRZPeZnTHMV1N
         eN4glvRjPS6PrG3L8il0T5DxdoPAkFqd99mgmCYleS7Cp2sKIZL3N7EeE1RJR5iTqWZM
         NLFVtaGqSXoNqvuNTtRK92zzfppdC//klSH7I7HQNzPZ2XjzH05BwuwjyL1HMAOI11GO
         kKDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=CiJetItL+i7BXkhdJG7mMpVWMFbIV54WTNSan93v+MM=;
        fh=/aHZOc7AMxagwMHqYssc+Hi/dEviiQcCUe14CEtqf1M=;
        b=xYL7BH9xKFy9S6+z0AITuiuE8oz2glMjmkqH25ERKDQhCr3A2cDlTl/wUoi7qfHh4t
         u7jHnYhLflnhAOPJ6ZCWqhzDFeRxgRyuijPR3kPiPqFoS7GIPeHy63aPc3AfraQpP04g
         ihFhkj0m33eI1t0y7UQLaA7ozA9dAYHOWZp9yUduBhkaVOwOaB0BV1ePPCZjZGZMevdm
         SwZY/6XhWmHLmDsBEcMLmwakf67WMzEUdCAghzLntgdlAkkDPwJIdPzJpKp8hSPoJ2Kl
         IjGCVUU0ot3pyj2sVyf91ZljyRkNFgeggRM16Zj69je4K/x1jy7/uXWEZcGT9QvNUO4K
         4aeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wf7vpLuw;
       spf=pass (google.com: domain of 3-fhwzqykcsszbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-FHWZQYKCSsZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544506; x=1709149306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CiJetItL+i7BXkhdJG7mMpVWMFbIV54WTNSan93v+MM=;
        b=j0GAQJq/AAyv3rPX4pRvMUX2bXGkfldUa0bSOyuowuaxbiC4NZ4oPvntVp5rgCuNJS
         3fE6COgQ2X/4lFpvNVanuxLHgUCs3cW/m/aEH2OIZKfXgYKE8HVGTP+TWTv5AkK4+KpR
         rIXZlfxOSwSWq90fH1m89IvenKZElbPcapPu/gqaYyum/evymHENXeZ5RSb8ePY63POf
         MoVOcFuwgwj3NTqoM0n/NrWQiIojo4WvKKHQoVtJ6Iu4sUAJCaD2Kd0fW0KnOyvcUMe5
         xtHjxFryCQxRHyJ15S0pat4cb6iyI4Un/cWBdCIwulApCk51YLPTttpvTrn+uh5gY0Nd
         jEWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544506; x=1709149306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CiJetItL+i7BXkhdJG7mMpVWMFbIV54WTNSan93v+MM=;
        b=lzX1k/owQOeK0QFCQ2mrJBxngJMR2rR28AS4E0qAewxdhRkFiXvfBxsXWWlQloUS+6
         xq/A36VK1gttL7c/LxgipiDvXoJ0yPszf0suGrsQ/Ep1KNOOP4HeIxkkMS2ATuczh6Sd
         q2bAYzhXWlxNmw3vRO/ojh2XO1zT3vINFMyjkgEM71P0cgHD9jULOvDqSCuLHyyur6YJ
         DTZ9mvfFU2cblaivqBvmNJi1sDrUI0UF7JMNT+KCJLPRzYD3ZvhMFwCqgp2HXgqUVZ2C
         1BOueeugovh8z3jqVCnkW0HnJFpjod0vF57Oq3t25zMGFtklXlfcWzFVkz6nSNKqXpFv
         6T0Q==
X-Forwarded-Encrypted: i=2; AJvYcCU3hd5ID9nW4YT64n1R+ApItWyCFhecHDEhYln+mBSyhmHLGW1X8GwoMkbbw8kDhO0RwS7qH/H6inGjGWID2owkPrDzyT4a4w==
X-Gm-Message-State: AOJu0Yyc9ajUXve8NQM6zNMQa77eO9DkP/u+XtoY0hsn4JRGefpD76q2
	CB5DxgMP/ozrO6Ya2dhtKZ5ogoqWdg51pBjEAyAwycOUMxzBLEpi
X-Google-Smtp-Source: AGHT+IEXWVRPJfQzKxl2vX2OWpB/uihh7BPzkdU8ymWbmwo2ymDC/cuoc93hQl36JO6WajRzohAOjw==
X-Received: by 2002:a17:903:26ce:b0:1db:f1e2:8517 with SMTP id jg14-20020a17090326ce00b001dbf1e28517mr262673plb.1.1708544506098;
        Wed, 21 Feb 2024 11:41:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:554f:0:b0:59a:6de0:e6f5 with SMTP id e76-20020a4a554f000000b0059a6de0e6f5ls5279381oob.0.-pod-prod-02-us;
 Wed, 21 Feb 2024 11:41:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUyCDO+DXe1IfLkSLyfaHNemqcymv3MNHmk5Rp/GSSVLl8g+BVNGdhTSpOgeCtWKu85GiMf3w9D3k6INKcpgo2jQjfj8PkY6JIsuQ==
X-Received: by 2002:a05:6808:1642:b0:3be:d38b:9cf1 with SMTP id az2-20020a056808164200b003bed38b9cf1mr24071617oib.35.1708544505294;
        Wed, 21 Feb 2024 11:41:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544505; cv=none;
        d=google.com; s=arc-20160816;
        b=LdFgb1IYeMxoXNiMTuDCi88diAZkniw3dNqtdzcm6cOLv3Msop+tla6JKdMsZzh7a8
         Bo57nC/nI5b+vBnVcvtAQKlhlmqM6tD5oI69Q5yEWL/6XPON30piXP5l2kQWk3JwvOij
         i4yjr9+m9dB47pzzwD5UoVQ9OcfvDodYF3zc0MpwgK+Ehb7HaR+fTH9vgcJVWMxxVJuP
         QoPFB2d83qYW0OHuJ2lweVNKiqAt7lQg9ugDtuC0XEf2eB9yrjf6qvqh5AG172BxWSlD
         q7QxlgDupe+QssWUNHC+ow9z340OBAd2PzBBHjpX98gcv11w8fYO373V20YdA46YHD2j
         2tEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=SFqjsc0WslhSBLDjO+3ojiIHoGv8W+Erk8fAgLgypEk=;
        fh=lOf6L+irVWJ6Dja+zNHErZy40Azi/T7h+dLYiLpXqSc=;
        b=GAF0u20cv46/DGLhs00JpDe0C6NU1jeFpehiKwiQ6BWH5KnZzJzlLOaJwrAujri+ib
         eAVAzAg6LP065+9DzPhKuI3Su6e6pXYYDlw0CUdHM/UDCKD49ciVCHAnlV//lKpy9l4B
         XsAWngK+lTvgKwR4UrzrUC9BfqmED1fKoutfXKdYav4fWArvjebU/9CFJPYiacSHX1XA
         H9nXTUXulT1XQlQpHYF/5beitTqhM1PqDDmzqucT+sHheOOlGJR4gdHTZfb5/3NWLNBQ
         D0q6LXYJZBZWaGswzqu1tST2UZU6XIBNdAQ9HCP/Q/DW3wF/Er24Oiq9FoMIXrkeiZam
         TcWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wf7vpLuw;
       spf=pass (google.com: domain of 3-fhwzqykcsszbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-FHWZQYKCSsZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id bj6-20020a056808198600b003c176bd214csi30439oib.5.2024.02.21.11.41.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-fhwzqykcsszbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-608405e0340so17681527b3.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWo9Q3Q7tzY7hZ9ZgfIqRS/WQdFX7uRvo+Zr73os0dDkcpbr3zTEx4enZ+2GX7T90sac6tAYLJDsAKxKxvjC5nTfExujmJ5fFjV4w==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a0d:e692:0:b0:608:6894:120 with SMTP id
 p140-20020a0de692000000b0060868940120mr1109228ywe.4.1708544504629; Wed, 21
 Feb 2024 11:41:44 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:35 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-23-surenb@google.com>
Subject: [PATCH v4 22/36] mm/slab: add allocation accounting into slab
 allocation and free paths
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wf7vpLuw;       spf=pass
 (google.com: domain of 3-fhwzqykcsszbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-FHWZQYKCSsZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

Account slab allocations using codetag reference embedded into slabobj_ext.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 mm/slab.h | 66 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
 mm/slub.c |  9 ++++++++
 2 files changed, 75 insertions(+)

diff --git a/mm/slab.h b/mm/slab.h
index 13b6ba2abd74..c4bd0d5348cb 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -567,6 +567,46 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 			gfp_t gfp, bool new_slab);
 
+static inline bool need_slab_obj_ext(void)
+{
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	if (mem_alloc_profiling_enabled())
+		return true;
+#endif
+	/*
+	 * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditionally
+	 * inside memcg_slab_post_alloc_hook. No other users for now.
+	 */
+	return false;
+}
+
+static inline struct slabobj_ext *
+prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
+{
+	struct slab *slab;
+
+	if (!p)
+		return NULL;
+
+	if (!need_slab_obj_ext())
+		return NULL;
+
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return NULL;
+
+	if (flags & __GFP_NO_OBJ_EXT)
+		return NULL;
+
+	slab = virt_to_slab(p);
+	if (!slab_obj_exts(slab) &&
+	    WARN(alloc_slab_obj_exts(slab, s, flags, false),
+		 "%s, %s: Failed to create slab extension vector!\n",
+		 __func__, s->name))
+		return NULL;
+
+	return slab_obj_exts(slab) + obj_to_index(s, slab, p);
+}
+
 #else /* CONFIG_SLAB_OBJ_EXT */
 
 static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
@@ -589,6 +629,32 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
 
 #endif /* CONFIG_SLAB_OBJ_EXT */
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+
+static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+					void **p, int objects)
+{
+	struct slabobj_ext *obj_exts;
+	int i;
+
+	obj_exts = slab_obj_exts(slab);
+	if (!obj_exts)
+		return;
+
+	for (i = 0; i < objects; i++) {
+		unsigned int off = obj_to_index(s, slab, p[i]);
+
+		alloc_tag_sub(&obj_exts[off].ref, s->size);
+	}
+}
+
+#else
+
+static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+					void **p, int objects) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING */
+
 #ifdef CONFIG_MEMCG_KMEM
 void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
 		     enum node_stat_item idx, int nr);
diff --git a/mm/slub.c b/mm/slub.c
index 5dc7beda6c0d..a69b6b4c8df6 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3826,6 +3826,7 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
 			  unsigned int orig_size)
 {
 	unsigned int zero_size = s->object_size;
+	struct slabobj_ext *obj_exts;
 	bool kasan_init = init;
 	size_t i;
 	gfp_t init_flags = flags & gfp_allowed_mask;
@@ -3868,6 +3869,12 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, init_flags);
 		kmsan_slab_alloc(s, p[i], init_flags);
+		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+		/* obj_exts can be allocated for other reasons */
+		if (likely(obj_exts) && mem_alloc_profiling_enabled())
+			alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
+#endif
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
@@ -4346,6 +4353,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, &object, 1);
+	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
 	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
 		do_slab_free(s, slab, object, object, 1, addr);
@@ -4356,6 +4364,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 		    void *tail, void **p, int cnt, unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, p, cnt);
+	alloc_tagging_slab_free_hook(s, slab, p, cnt);
 	/*
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-23-surenb%40google.com.
