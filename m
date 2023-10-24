Return-Path: <kasan-dev+bncBC7OD3FKWUERBBEW36UQMGQEKDJZQ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E3F1B7D526E
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:49 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-6927dfe8c75sf2965994b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155268; cv=pass;
        d=google.com; s=arc-20160816;
        b=JbmlRyFk1YHx3Y2JyfLnhDENl1NdALMpLZcExGvsBxE/OklJheuXn8TiX8n7zws5GQ
         4Bi9EtcjzO77PeJvKWj1dz5WJH/mU/ShO79C6faW4VOTPuqSlIHkawIaHrWwGuFvsI91
         ROm/oV1gGD7l21LiN4YWZDkOvWoHwk2AGgE3QEIF3lU7DGzbYrpEtRTbrhVD71SmRREe
         +muU7OpJIFsyqs4LZOD4euyt92bl8HF6E/NJFFeabSCKY8ZGrxR4sWVOAiVhX0BhF0aO
         kHKogGhEKsFdtlihdcAo56XPm+3rl5E9FTLeks4sliSsp/nZoCjIg85znfGlaSUE0mIk
         2nlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=I31FecP6ejvlwILHPkmaE6Z7dZmfA/k0BPR5u5m8NWg=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=cKgCr896K2tPmuuuwOVm8vWLfhA4jmaDXhg+GeuZLeb98ave70XB1JOUYr+pSjGsWy
         iLAiYiFxWKpwO7V4bidt/fDAKNGp47KETdE5DBCCUw/AH6S+lqRCTEZ1vThGepCtJcnH
         t4BKT2m6G+2e+FzN7Ecgd1sHCi32YQ+BsHTUkqkPsjJ95jZbn9+6cs0iYd4B2FBJuh/s
         3ChQ8wA4T3BSePAsf9o9rTuoy2Vzz9DkgZ0g9UM4gpjU4Fxou9ddd0UrAIfEd2WU3lo/
         eafXRW3DQvVZ4Yg8DvqKwF+hKMFNtZNy2uLni3eZIpF+lrUlBcDYIvXYAYrRYtErOKcM
         vVPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sVX8q9DT;
       spf=pass (google.com: domain of 3ass3zqykcaczbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ass3ZQYKCacZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155268; x=1698760068; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=I31FecP6ejvlwILHPkmaE6Z7dZmfA/k0BPR5u5m8NWg=;
        b=Q5PyBOxVlAt7mFqUG2+BspWp2gT2tc8UFf13iZUdAEV+LB32CfNvosyFKQ3hEn64gg
         ZoaUlmNNDFoTulOKz+9/ipiPLAj2kQJeyZu+TWCEOWpRgu5YB7Aw6A14BijI5fi8Wip/
         gZbkHdwKJamvCqYK0QnfV8eI4CgvFS1IHVsBZM1MrSPJ3xhMo7wvD+oiuYvwrl4a4Vt9
         FUlA97ReR44rnasH01n1XDgxLVMZnfPjzA0h+8qCje5NDkPRHHrn7b9uC65RGIgQU+U8
         +U71jOe1RDmhMWQc7ywAUufNBB0XoiYCkXvsZ8YXtKV3AvYL6/ujzlQw09GzkgdsaE8u
         x7ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155268; x=1698760068;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I31FecP6ejvlwILHPkmaE6Z7dZmfA/k0BPR5u5m8NWg=;
        b=ksiEChijbSkrPjGkLPFXw/E4Wuk4uKQG81GoIg4Q2NWZgFQUWH6y6PEN8hOXMutZgX
         oKUJ7rYfTcB8S9I/4OYYZh5AL5+fOJx9Mg0yRcnBEiWSk6zybkDVVdtEaabI7EP8MoDQ
         RjLbJKp2fHtDBIKVrah2DKcX671hHpxhlrnjB5kiTYalsV7WTSf/cr2Yk9UTEbhPeq0Q
         NqX0ctbr10IfCUWx+5KzNVSOWlji1bJ6C0DLpAuaNOSeMy/gDy9wtpkG5zZ4ko4wLNId
         8KSRvwk50joG1vt7Jsj3/PMMdMU2tRHyX8qbzVdkEXk5QyA36w2z5gojQEJJEfmAYdN1
         LmBQ==
X-Gm-Message-State: AOJu0YyxnLsieA07gB+zuhNtdJ2AgE7mbe+jsvxja94glPU1vT3k1Ux/
	nWi4b9xZyYM/MA/y+CRqQZo=
X-Google-Smtp-Source: AGHT+IHI8DoOzfMHUllMr4O5z0cDjxwNun03MyhInswAQIZp35SVnSywq0mvseqtdJhEmWGSkzlR0w==
X-Received: by 2002:aa7:9622:0:b0:68e:42c9:74e0 with SMTP id r2-20020aa79622000000b0068e42c974e0mr9923459pfg.3.1698155268344;
        Tue, 24 Oct 2023 06:47:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d08:b0:68f:e870:b81a with SMTP id
 a8-20020a056a001d0800b0068fe870b81als2095565pfx.0.-pod-prod-07-us; Tue, 24
 Oct 2023 06:47:47 -0700 (PDT)
X-Received: by 2002:a05:6a20:3d89:b0:17b:689e:c751 with SMTP id s9-20020a056a203d8900b0017b689ec751mr2775685pzi.5.1698155267180;
        Tue, 24 Oct 2023 06:47:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155267; cv=none;
        d=google.com; s=arc-20160816;
        b=SpV1zRP7RnC1gPimEOZdyEOZxcejUD6hVenk/O4mzVYTqxVtKAp08WG56M9Sx/nq4D
         Imd+imBlYRud/rgW1140xcchyeKIVqWqwdKRJpzrAEAeiVWz2xKqb/TcL8i9QrCOz1eS
         VXItyUyHq+r19C4hP9tK1p8N8lJyj/cViQPsrjwGTx7wxhNjnzR1aEf98eHSJX0GVIG3
         gv10fZmsNZQuG3PMI9pWLKPRiDtA/e+tI+5hvYFdLGh0xydhLU6/CFo+GLxJdIrh1eqN
         qg4MymSNSfKvAK+m0Aik+y+hOUIdegdcSETltyE6Btm1wcvEdxap0oS0/x0aVs0aQVgb
         L4Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QaUscnVR3A9ivKzFSXLwhZ9WVAKd01wEmSHK760WXQ8=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=hNG+T5Oz4ebZrLd8KB8XuZJFbZd8lft9A66oxIUEsb93v1UMmTHNcazmebzgGBkCjf
         AjkLh184HspEnvI/ArbsT6R8/pnDZ2i7951Wm4j01nBKPEMKkQOJCuSC+NJ6ctKoPNJe
         uszsV0n2hwcmCX8MmgpgMHbDnbHiqptKJ5PzNYNBuDT5WvKyjS9QV8eOU3mukkl94ZBh
         7WwZmrnFT8mUVmmtmNo4waFsSPCas9JYWq3Z3ilbcZnBflS3CbJ3ASRvJKgkMFlvpwru
         dKocz/yUqYPY+EAE8897YFk8/mYREXqm6aPeAfLV66Hmr5ZmLJSg6Okyse8M91y6mGF7
         MwOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sVX8q9DT;
       spf=pass (google.com: domain of 3ass3zqykcaczbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ass3ZQYKCacZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 76-20020a63024f000000b00569ee9c848fsi837385pgc.0.2023.10.24.06.47.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ass3zqykcaczbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d9a45e7e0f9so5267910276.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:47 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a05:6902:105:b0:da0:3da9:ce08 with SMTP id
 o5-20020a056902010500b00da03da9ce08mr35592ybh.10.1698155266214; Tue, 24 Oct
 2023 06:47:46 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:26 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-30-surenb@google.com>
Subject: [PATCH v2 29/39] mm: percpu: Introduce pcpuobj_ext
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
 header.i=@google.com header.s=20230601 header.b=sVX8q9DT;       spf=pass
 (google.com: domain of 3ass3zqykcaczbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ass3ZQYKCacZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
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

From: Kent Overstreet <kent.overstreet@linux.dev>

Upcoming alloc tagging patches require a place to stash per-allocation
metadata.

We already do this when memcg is enabled, so this patch generalizes the
obj_cgroup * vector in struct pcpu_chunk by creating a pcpu_obj_ext
type, which we will be adding to in an upcoming patch - similarly to the
previous slabobj_ext patch.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Dennis Zhou <dennis@kernel.org>
Cc: Tejun Heo <tj@kernel.org>
Cc: Christoph Lameter <cl@linux.com>
Cc: linux-mm@kvack.org
---
 mm/percpu-internal.h | 19 +++++++++++++++++--
 mm/percpu.c          | 30 +++++++++++++++---------------
 2 files changed, 32 insertions(+), 17 deletions(-)

diff --git a/mm/percpu-internal.h b/mm/percpu-internal.h
index cdd0aa597a81..e62d582f4bf3 100644
--- a/mm/percpu-internal.h
+++ b/mm/percpu-internal.h
@@ -32,6 +32,16 @@ struct pcpu_block_md {
 	int			nr_bits;	/* total bits responsible for */
 };
 
+struct pcpuobj_ext {
+#ifdef CONFIG_MEMCG_KMEM
+	struct obj_cgroup	*cgroup;
+#endif
+};
+
+#ifdef CONFIG_MEMCG_KMEM
+#define NEED_PCPUOBJ_EXT
+#endif
+
 struct pcpu_chunk {
 #ifdef CONFIG_PERCPU_STATS
 	int			nr_alloc;	/* # of allocations */
@@ -64,8 +74,8 @@ struct pcpu_chunk {
 	int			end_offset;	/* additional area required to
 						   have the region end page
 						   aligned */
-#ifdef CONFIG_MEMCG_KMEM
-	struct obj_cgroup	**obj_cgroups;	/* vector of object cgroups */
+#ifdef NEED_PCPUOBJ_EXT
+	struct pcpuobj_ext	*obj_exts;	/* vector of object cgroups */
 #endif
 
 	int			nr_pages;	/* # of pages served by this chunk */
@@ -74,6 +84,11 @@ struct pcpu_chunk {
 	unsigned long		populated[];	/* populated bitmap */
 };
 
+static inline bool need_pcpuobj_ext(void)
+{
+	return !mem_cgroup_kmem_disabled();
+}
+
 extern spinlock_t pcpu_lock;
 
 extern struct list_head *pcpu_chunk_lists;
diff --git a/mm/percpu.c b/mm/percpu.c
index a7665de8485f..5a6202acffa3 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1392,9 +1392,9 @@ static struct pcpu_chunk * __init pcpu_alloc_first_chunk(unsigned long tmp_addr,
 		panic("%s: Failed to allocate %zu bytes\n", __func__,
 		      alloc_size);
 
-#ifdef CONFIG_MEMCG_KMEM
+#ifdef NEED_PCPUOBJ_EXT
 	/* first chunk is free to use */
-	chunk->obj_cgroups = NULL;
+	chunk->obj_exts = NULL;
 #endif
 	pcpu_init_md_blocks(chunk);
 
@@ -1463,12 +1463,12 @@ static struct pcpu_chunk *pcpu_alloc_chunk(gfp_t gfp)
 	if (!chunk->md_blocks)
 		goto md_blocks_fail;
 
-#ifdef CONFIG_MEMCG_KMEM
-	if (!mem_cgroup_kmem_disabled()) {
-		chunk->obj_cgroups =
+#ifdef NEED_PCPUOBJ_EXT
+	if (need_pcpuobj_ext()) {
+		chunk->obj_exts =
 			pcpu_mem_zalloc(pcpu_chunk_map_bits(chunk) *
-					sizeof(struct obj_cgroup *), gfp);
-		if (!chunk->obj_cgroups)
+					sizeof(struct pcpuobj_ext), gfp);
+		if (!chunk->obj_exts)
 			goto objcg_fail;
 	}
 #endif
@@ -1480,7 +1480,7 @@ static struct pcpu_chunk *pcpu_alloc_chunk(gfp_t gfp)
 
 	return chunk;
 
-#ifdef CONFIG_MEMCG_KMEM
+#ifdef NEED_PCPUOBJ_EXT
 objcg_fail:
 	pcpu_mem_free(chunk->md_blocks);
 #endif
@@ -1498,8 +1498,8 @@ static void pcpu_free_chunk(struct pcpu_chunk *chunk)
 {
 	if (!chunk)
 		return;
-#ifdef CONFIG_MEMCG_KMEM
-	pcpu_mem_free(chunk->obj_cgroups);
+#ifdef NEED_PCPUOBJ_EXT
+	pcpu_mem_free(chunk->obj_exts);
 #endif
 	pcpu_mem_free(chunk->md_blocks);
 	pcpu_mem_free(chunk->bound_map);
@@ -1648,8 +1648,8 @@ static void pcpu_memcg_post_alloc_hook(struct obj_cgroup *objcg,
 	if (!objcg)
 		return;
 
-	if (likely(chunk && chunk->obj_cgroups)) {
-		chunk->obj_cgroups[off >> PCPU_MIN_ALLOC_SHIFT] = objcg;
+	if (likely(chunk && chunk->obj_exts)) {
+		chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].cgroup = objcg;
 
 		rcu_read_lock();
 		mod_memcg_state(obj_cgroup_memcg(objcg), MEMCG_PERCPU_B,
@@ -1665,13 +1665,13 @@ static void pcpu_memcg_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
 {
 	struct obj_cgroup *objcg;
 
-	if (unlikely(!chunk->obj_cgroups))
+	if (unlikely(!chunk->obj_exts))
 		return;
 
-	objcg = chunk->obj_cgroups[off >> PCPU_MIN_ALLOC_SHIFT];
+	objcg = chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].cgroup;
 	if (!objcg)
 		return;
-	chunk->obj_cgroups[off >> PCPU_MIN_ALLOC_SHIFT] = NULL;
+	chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].cgroup = NULL;
 
 	obj_cgroup_uncharge(objcg, pcpu_obj_full_size(size));
 
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-30-surenb%40google.com.
