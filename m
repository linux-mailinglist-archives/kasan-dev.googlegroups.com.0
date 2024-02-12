Return-Path: <kasan-dev+bncBC7OD3FKWUERBTNAVKXAMGQEHB47GCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id E9A85851FE9
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:30 +0100 (CET)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-6077e1e919bsf5743647b3.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774029; cv=pass;
        d=google.com; s=arc-20160816;
        b=K8bYzdEY6hk6SWoh9GdTJM9TNs1J5teCq/93oJHtDMczLyAiN3SRtM8FoPPuWRxEih
         tiyLidXCSnXIaaAk6RBvGimW9P5GiwdIZ8o453HxCpOWMYJvaEG5kQP5kXkixGbhgoip
         VJrqFvLBZgnTsB8eTHsP7S+qk+2MOg5spYi0UT87LlwypaIGEy0Qm/EUoVao83fZ3VQS
         TrtkicXVPw74G9swJQS7n7YI5EXJfHVYGsynZtmyb9kekgpRVi7sKUh0xHbZfazC2gxd
         6c4qvwwhXrQ0+kBtDTVtwObjPZv/wfbMAdwfCQgKXj/0E8Ul/Fhux8asQMwOwvg17IPV
         juPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=QJsx4eMEdbypPAHiuYIWtE4XgrrsQRHXno3UoHNP+h4=;
        fh=02rqpnhNbDyPsnJpEks0AHJJEOfOfng190HY+JR6FA4=;
        b=yEuQK7lnG20Ib4yWXGXSBjNVRm7MIQ5wZJ4JYTKJuWA1eNTe8ZfLTn27Hbenk7ljh9
         HhvTqF4gd3+fALzftHTcOw8zaToU7cDCTw/lTWxLTM5IYfyXjg+PpkpNV9atw+95B487
         iY8Zr4PbSwXmFDEyGf0Ms7LoPSJBZZauvxfjZGr6ajgTwKc8diF0XQCfaWtiT5i5zh13
         tcrttruXsmS/KGXCFtcXjPFa8mG8rV0ktZf6cS8X3/xSeuKEXft22aPzZeqXLWF/VAZg
         gW4uwaz98zUltOtgKkmFdRWIL/jxz9bvCug5i0Kdu8dvaDaWzX+Ujg/lk679+WywUtyN
         IwNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tju6f5NL;
       spf=pass (google.com: domain of 3tjdkzqykccs9b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3TJDKZQYKCcs9B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774029; x=1708378829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QJsx4eMEdbypPAHiuYIWtE4XgrrsQRHXno3UoHNP+h4=;
        b=BBT50EDGHUQB6opFCMFnp5cRtA4sNSl2qXLALz6uGmlTte3xjfemP8+NMbkXbcoXDW
         4RCc4CWY8sKyq2MngqhR1zCn9ep7HPLJjuH42124eInzwWSGDKY6Ly4tUmIbqWSHZ71q
         Ah5cThkvkHzIejQ1vFagtoj2f2R7UYJrZHIdtzhR2L83UabzlRZ0s0AzUY8Nrbp+HRYM
         q5Wkn+kdfY7rjzoqhIae4nAnR5YBM9MzPHjXb4Ec4wl8r1cuDfsGvbeAW9p8ogTLBsq5
         KSh+qwuWAoHQF7PJQ0nq05aYtnHyB9hnPlTRLxwB6xk/EOHeBDKpFSVIARHivpoWNXt1
         w92Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774029; x=1708378829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QJsx4eMEdbypPAHiuYIWtE4XgrrsQRHXno3UoHNP+h4=;
        b=pADj7YcaKjrnhxm1RXer/uySPRCKwbP2GsJzHqV4iPLMC7MtLRSTNk58OC8qlpJ87q
         nRWFAUHVTcUu9kmFwIMSA/SCRaPD3v1Q8x4/nEUqg2Pwlzkiy0HGXhnqVU4aHLxq/u72
         g1N+jdzAfSHUyYqh9RGWAXA+phINefGYnZQJHqIdulYBEWTi+BIb/WmeVHzhuYhTg0Am
         5O2KxT8AjT30PEvQdP7ZzflmZGBoIH9E2jxWy1PIjOmB428ZkoQK8fUc2FEJDp7ilVHn
         fP8WUqZ342DWx3ZdGy55tHvRArpMay67soOC8ZCCfEHR6pBQv7BAK5gOnh1nOT+0kgQ3
         NBVA==
X-Forwarded-Encrypted: i=2; AJvYcCVqKnzCJNVF0rHfVzErkqDf3AC91FAzx+AB0HutsVokAKGcxCijG6ArpU/lCrSxevi817BOLoFsvanv+Gs6eYXAAMYGAiWe7Q==
X-Gm-Message-State: AOJu0YxQskwUbGms0TURBJOvMb7Rsn9zd+AMZsFm8IjTLgNKr1BB6Z2y
	BWp/cognuS4B7NhDMxsWPC6j1lq3MZhxSHeP7Rl8+mKy+I8sA9Tx
X-Google-Smtp-Source: AGHT+IGOUJF75R92L/ofw60V9OFFqpM0WO4ixX2jjcNX/BFsWUgLynqKYeSSIuLR0lQACCmhUOCfsA==
X-Received: by 2002:a05:6902:2606:b0:dc6:9399:849e with SMTP id dw6-20020a056902260600b00dc69399849emr7080374ybb.11.1707774029723;
        Mon, 12 Feb 2024 13:40:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d657:0:b0:dc7:458f:32f with SMTP id n84-20020a25d657000000b00dc7458f032fls1227812ybg.1.-pod-prod-08-us;
 Mon, 12 Feb 2024 13:40:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVkiMy7ZzzlzxCZ7LjHo6wYUIBDLAkowqrHnbaGSSIHSZgo46tBmYtC6nFDw+tqX9nd3S5yIdXPhhH6wHbjfdZ8iRihXUYHrnhhbg==
X-Received: by 2002:a0d:f744:0:b0:604:926c:5347 with SMTP id h65-20020a0df744000000b00604926c5347mr5688947ywf.23.1707774028899;
        Mon, 12 Feb 2024 13:40:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774028; cv=none;
        d=google.com; s=arc-20160816;
        b=j7irBV+yn4tzQ2NJS4PEVTusJUczGo7ff4ELD5/fuCWVnDPGf79pyGfw4X/k9cIhUL
         8ln/uLv1zaaH9Wy/1CMb2F+5EREjREIcTqFRHVR8kMtn/K1Mu6cbTA88LjyabIyYADKC
         ItJ7pKXz3HkHZihpOW3Rus0pukYe/yZU6nU3HQWvBSGTHyumjdVQM8KkR663O9tUkfAH
         HzqEbTS01MptNzglOaZuWzOY0oPIC6M8rjNyVCqCJ8k1HpQUcRgzismw58SSiWIHicx7
         7KASor4sXUJ01sHVMdlgJ1kJZJ1T67jWOVuH6h+4eVNmOwpVecSnUX9Dy+50nWbTA7I+
         qvCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ATNLg2TqDpb+ESy76iaYpc/lOC/dJ7HcAs1g5FXdHcs=;
        fh=X6BwG49eKp+Pirvdck9SxN+BoFVOMis21LB64D7i99s=;
        b=0YgZMZ+KsDr/wchu1tjTaAw/dJYdTHQrkKgYQ8xubskYXkKJyXW1XkQiXt4DKph1LO
         BYGpd6+ywysOJ1PX3bVGeE833INbqL7y29GBU2yyBH2Tj9eCSUV3Juath7c1ZDcum/YA
         iY9Uq+EOUGZOFXFAd1VhTLhhe+q3NtUUVR0eMbJ9D9+AUT/81QYVGagumJS0KYfGgssP
         EXoXZd6PPlptzCeJzhjoRARd9bq6dOqZgKMq7QM/T8FlNdZ5I//jhXgvVIGpwSbfuNf3
         zuS+7OSKTdLnNrsssS8jZgpeFOyRjOSOHqbY+4g1SBlbp98VwA2XgtGj2aEEqk92pzhW
         pSDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tju6f5NL;
       spf=pass (google.com: domain of 3tjdkzqykccs9b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3TJDKZQYKCcs9B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCV6UH6i+3Ssi6ChdKStE06SSzBqhej1Ep04m05snOHzFdXO7I8dJVvt2E9NknapnrPXunAmc6HJBAH6s7VN4O8INU/sQY8e93Ud2A==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id d6-20020a0ddb06000000b006040f84d90bsi717420ywe.4.2024.02.12.13.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tjdkzqykccs9b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-604ab15463aso4583337b3.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWu1oz4GpuNjxhE4/MhV8CaxRb3gW6XN8PUmgFXm6lKo36/+f/9inCPVH8w3vab5RKCFyiwHsXpwf5JzO21AtDwU2pFYOoZr+Dt3g==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:690c:884:b0:604:d53e:4616 with SMTP id
 cd4-20020a05690c088400b00604d53e4616mr1398151ywb.6.1707774028573; Mon, 12 Feb
 2024 13:40:28 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:12 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-27-surenb@google.com>
Subject: [PATCH v3 26/35] mm: percpu: Introduce pcpuobj_ext
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=tju6f5NL;       spf=pass
 (google.com: domain of 3tjdkzqykccs9b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3TJDKZQYKCcs9B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
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
index 4e11fc1e6def..2e5edaad9cc3 100644
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
@@ -1646,9 +1646,9 @@ static void pcpu_memcg_post_alloc_hook(struct obj_cgroup *objcg,
 	if (!objcg)
 		return;
 
-	if (likely(chunk && chunk->obj_cgroups)) {
+	if (likely(chunk && chunk->obj_exts)) {
 		obj_cgroup_get(objcg);
-		chunk->obj_cgroups[off >> PCPU_MIN_ALLOC_SHIFT] = objcg;
+		chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].cgroup = objcg;
 
 		rcu_read_lock();
 		mod_memcg_state(obj_cgroup_memcg(objcg), MEMCG_PERCPU_B,
@@ -1663,13 +1663,13 @@ static void pcpu_memcg_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-27-surenb%40google.com.
