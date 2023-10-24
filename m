Return-Path: <kasan-dev+bncBC7OD3FKWUERB5MV36UQMGQE2NJOGXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2250E7D525C
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:35 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-58204b077a3sf6720920eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155254; cv=pass;
        d=google.com; s=arc-20160816;
        b=A/NHl6oleaSYLVoZqzfmNVb8SfAXF3jxhHd2LV38gq9PG4OWFkZzP3/jU9LeCWPOwD
         sCpmCUs0SHSg93QNqMeFiyelHlXXW2Nq4iST2z8w+eFc1SI/9g5uQlCcuWNGpE8eWgbJ
         4Y1HPPYni6pBrEUs6iIZKh/e+djA0imfGMXGK4RgXeF+jR0gCTOjolqJ8ZHj4y7NQUJH
         kzzOX7awKw9ZB/ZFkYFw6DV38UGoPTGJ5Vx3Dj4VWyCQBoGMJKWrB3sQB+E9fBUdoDAv
         6fGu6dvnTXJ7c7Xn496gZJu99qS1TwxWwaizaq2FRvQISl8LS0gH6UehuAk6XAGb2iWy
         vH9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GIY6VDgKdAOv7JJ1sxHlJcOhBBlGhE63kVmYkx73g2U=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=ubD7hItbEyEf7vaHIpLOllRsCiPTN2rcO1z6yiJrxuI/NA20yl+6ReyGCt6Zb1bcZ+
         arJOMnTyatV+rE9nDFJl40wNOk3eO4UKL2RsF993pEIvHRMrMdeI/V8MkGE6x97LOc2S
         DcPmFppVFsAgp9ZzFd5DWCPtY1hZzFOG6HkenQ9FAT4YA8JGVpsEYl3AvL5gxEnp9wnn
         JpnN0K/pgUT7FcoSzEG5Ns3O8M5yekXEke62dPN4FwF8fFhSUkgM3jQsJcnW/7IKfSGV
         ZdrcWPUmG2tFcVdhiYbuTFt4v5+Da6n0ZxB8DlfuH7O/Lq2bE2NkZEMKmioffxUQVFa/
         lJHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=I9moOlFa;
       spf=pass (google.com: domain of 39mo3zqykczklnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39Mo3ZQYKCZkLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155254; x=1698760054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GIY6VDgKdAOv7JJ1sxHlJcOhBBlGhE63kVmYkx73g2U=;
        b=Cf+GJ0s73xAyRPh+DrOprmy95TiCuZLV43jlqWiCNO+7N3TPXzec2GfGYtbPiAXmiY
         Elkv7y18LE/OSHwBgtYcFf6CtO2vpDWDnxffs6RuqAKhAk6gHfJ9YCpyTzyypiMioZNY
         zDs8x4YSsItuJZRca+C65zxaiWipDghWRV+3Oz1wsoZB3buW8LevGyS/QvE+RA9yYI/d
         BwnfFrfArGZsOItx+HOLMrth3zbHzB/q1XMOOD9+Fr6klcfrk7k3Nm4v/xX/XgRSbSD+
         5bBdBdLMctSabFHz4JY3GyuqtLk4maV8cBHAZYV4K20MKoHW5M3yk6bbQcYPF5T03V8H
         Y1QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155254; x=1698760054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GIY6VDgKdAOv7JJ1sxHlJcOhBBlGhE63kVmYkx73g2U=;
        b=SHHm+vlgD1f6+04tQTIoNsVHVAAu0epHz59C/P6d2D1t3OPmcx6Y95VYdrJHsonMXL
         /zbQ4mUtwqiBqFqk4RWZyLhZwwMBt6l/GzM7wf11Bs7aZzWRvKwXB+LysYErVQ9OelH4
         tux5XF9CQ29A0J1VqLujv8bg0NOEjcOZrwhtwIJpBV+Fcw42GNk67ZiPeS0vJIlUTjQw
         vWiOvNK9LAMnrqLoMJfog+R8mU+n/TBC4kUnXd7WgHKCJ3m9DdgdzdHZs22l+SgRmaH1
         vni9cj7h5gsvaFzXacRro7uRjkMumjM+/Q6ExQpwZLqo0JCPxDiHaDqpW6YMpFjAYiya
         8JvA==
X-Gm-Message-State: AOJu0YzTt+pWuHlUyvCy38PMpxzl4cJfrldm9ilDtlVcAyfuOkRVG+BF
	w+QdBJqdZgScvua23Hxq24A=
X-Google-Smtp-Source: AGHT+IG2XfBjRdVWirg2krJoBYMCVKaz1LGHLRXsO8SqzCC8undqKSdDN56f1b4q45N5/ieo1OYCAA==
X-Received: by 2002:a05:6870:8088:b0:1db:70ee:efed with SMTP id q8-20020a056870808800b001db70eeefedmr13192040oab.18.1698155253888;
        Tue, 24 Oct 2023 06:47:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:971f:b0:1ea:d76a:4f02 with SMTP id
 n31-20020a056870971f00b001ead76a4f02ls2179561oaq.1.-pod-prod-03-us; Tue, 24
 Oct 2023 06:47:33 -0700 (PDT)
X-Received: by 2002:a05:6871:3147:b0:1e9:bb3a:9a89 with SMTP id lu7-20020a056871314700b001e9bb3a9a89mr15896137oac.47.1698155253359;
        Tue, 24 Oct 2023 06:47:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155253; cv=none;
        d=google.com; s=arc-20160816;
        b=SnA0DtaDjMl3Lh8c8i9FjKXAd6d9VUtnRgL8vroiN4KwpFpURPPW0YJ8kzhYa35jmg
         nCMLkiM7YCNxC/i8KVPU6aC0i2fNfDKZdUbdLgtSF0BtrBxSB3oRGKW2nnyMAbnNkuOa
         wkCEgV33W9Ojn2N0YNRKfejdwoJRUORXywKUFcoxLHzI90HMZ3PXaFih/IUv9BSRgkvP
         qVi8Ii2zlPWJtGMGseZf1qkRVzDnuN5479X86AjcLQisBLzDpZeHfKvRhQZtvwXCFHqK
         sSvVrBAo64IUWpdJrQspFd4bVsBttUMVQ9ZPNRJRidSuVKIFPK1SYZZim06NdA5IoTSN
         M9Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=jxcZ43bmgT/q64Ul96+yH7BdLzW8wJzWTibIuRMuFN0=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=UEdTmk981veKFD0djes4cU8xRcJ9xwn+hYaTHrqqGA4xiYexpyqH1MStU1b3Ht2iPP
         Ys/LQAPAAeUsZ7siCTBYaK/Yjj8fjNYk5ohMoiecqhGIO/EBZ7Ql5POFyIznzCetTBBt
         SYY2EGfXILeXVPnyU1g5oJLCLuxushzPwL72Fx4QOdPIdtNFt5/QOQ8LGU7wuGFS4lX5
         MkQiLBzqC+t5BhBTbIWNSKSVYVtDn26C76gG2knoKQ6WSuvO6k4DXnVLoaS22zkKmZQJ
         o+dLhOz0EZOWt98tYqLcD4fXl4ZYenof0Y1YGjXEn8jM4wruc/O6jM8pbdFfq69TKU5V
         EYMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=I9moOlFa;
       spf=pass (google.com: domain of 39mo3zqykczklnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39Mo3ZQYKCZkLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id l14-20020ac84a8e000000b0041812c64692si875059qtq.3.2023.10.24.06.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39mo3zqykczklnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-da03ef6fc30so674884276.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:33 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:d05:0:b0:d9a:5b63:a682 with SMTP id
 5-20020a250d05000000b00d9a5b63a682mr216305ybn.13.1698155252840; Tue, 24 Oct
 2023 06:47:32 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:20 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-24-surenb@google.com>
Subject: [PATCH v2 23/39] mm/slab: add allocation accounting into slab
 allocation and free paths
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
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
 header.i=@google.com header.s=20230601 header.b=I9moOlFa;       spf=pass
 (google.com: domain of 39mo3zqykczklnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39Mo3ZQYKCZkLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
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
---
 include/linux/slab_def.h |  2 +-
 include/linux/slub_def.h |  4 ++--
 mm/slab.c                |  4 +++-
 mm/slab.h                | 32 ++++++++++++++++++++++++++++++++
 4 files changed, 38 insertions(+), 4 deletions(-)

diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index a61e7d55d0d3..23f14dcb8d5b 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -107,7 +107,7 @@ static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *sla
  *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
  */
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct slab *slab, void *obj)
+					const struct slab *slab, const void *obj)
 {
 	u32 offset = (obj - slab->s_mem);
 	return reciprocal_divide(offset, cache->reciprocal_buffer_size);
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index deb90cf4bffb..43fda4a5f23a 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -182,14 +182,14 @@ static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *sla
 
 /* Determine object index from a given position */
 static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
-					  void *addr, void *obj)
+					  void *addr, const void *obj)
 {
 	return reciprocal_divide(kasan_reset_tag(obj) - addr,
 				 cache->reciprocal_size);
 }
 
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct slab *slab, void *obj)
+					const struct slab *slab, const void *obj)
 {
 	if (is_kfence_address(obj))
 		return 0;
diff --git a/mm/slab.c b/mm/slab.c
index cefcb7499b6c..18923f5f05b5 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3348,9 +3348,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	struct slab *slab = virt_to_slab(objp);
 	bool init;
 
-	memcg_slab_free_hook(cachep, virt_to_slab(objp), &objp, 1);
+	memcg_slab_free_hook(cachep, slab, &objp, 1);
+	alloc_tagging_slab_free_hook(cachep, slab, &objp, 1);
 
 	if (is_kfence_address(objp)) {
 		kmemleak_free_recursive(objp, cachep->flags);
diff --git a/mm/slab.h b/mm/slab.h
index 293210ed10a9..4859ce1f8808 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -533,6 +533,32 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
 
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
@@ -827,6 +853,12 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 					 s->flags, flags);
 		kmsan_slab_alloc(s, p[i], flags);
 		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+		/* obj_exts can be allocated for other reasons */
+		if (likely(obj_exts) && mem_alloc_profiling_enabled())
+			alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
+#endif
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-24-surenb%40google.com.
