Return-Path: <kasan-dev+bncBC7OD3FKWUERBA5E3GXAMGQEZOPIMYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 83BEE85E792
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:56 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-21f3fb232a2sf1239414fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544515; cv=pass;
        d=google.com; s=arc-20160816;
        b=tS3gw9n66TWCKtc+IfubZeW5oxprxDWEpKngP9qsZMEPDEpeqeILWSax1DbiNyu/7C
         dvul/2hjGrMo5FvOXx3bD2EGDkKizz6MH+c7AGYmKj7aGM88jMy+TOmOZUhy2CJY774F
         TB94aLPFCo76tlBRWwUPD06Uq4uhyuK6DPFqw2TEH9jAb8I69kQbS/Be7s7ahFmHUIGW
         7OhduT+qZvJQF579oOZqKTTQPzwxG80SkQy3XXxqO1zHxKUzadAxCL8yMnzwL0WadpcO
         jmeMkydItYVCHnv6ytmYO8YvDthGqwJdzNEyYJaHIOJJ35+35BjvNXOy8SS25exXAUlQ
         X7Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=D2f9pNvhcyLc/PibYsTQquDg17laW3IxMWJKcWpeScI=;
        fh=5iER/9+vWjlDqnN1qMeyprHT2sWH1Knr68oxuj07nO4=;
        b=ooVYPuuGB/PGUQ3zW3nyvPz7ze0XxvsRTZuB1JNQ6qMgTQjwm4qe2T+b9+1Fl/gTKA
         4s4mNAF47+r2EZNeYikXJSuFHymukjDw35+kl+f2M1kQI2C8VzLWO/s2775HXciW/P+h
         AuGYEJhZwaK9GnmBJcalFY9/bui5isFHJ+6TF08Aokf+gcejrVPhn21THiWrYUKY+AZd
         pOtj6o1xER1g3r8xG/liRG542egtgxiaW/MmkSO9wBSM8MHLT8D1z7crt3fDnq8gvEyi
         VtgNAK5mWNo917Bwgr6EWYRRxUXh9Zjj/FKqZFXLC+FpBCHWSmi+yaQg99+Q3AdzT9yf
         QUeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nHsiP7p8;
       spf=pass (google.com: domain of 3avlwzqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3AVLWZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544515; x=1709149315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=D2f9pNvhcyLc/PibYsTQquDg17laW3IxMWJKcWpeScI=;
        b=UnKcSl/voYk6KUU9+GzcwrJYHUFvMcxT5O1ge2bw4EGPHswpUOhRuVVTU+QH+Q+pCg
         0tml7trcCbc1zcOqQjGABwgKXMep4byCgSBQ9Zaz1FbOoAGRbrdqkd80TMOcPZK4pWlw
         8XeytQv1p4KKb3vZ9aWTWM/MIbsB2G3MriLfJ4xNuhRiGSuhUW7Rw72RRK8WuDdG1tIe
         5f5FgCVfSn63dyVKsng+1KzmISf53/oi3XT9mqJL3Ci/iCKRo2FXaOSTdjqeOby5ohuv
         RWTd+Mu+qwcfj/+0QV8UJhc/dUIKTKlJ8ljv6tHDR+86toKrGBDOPUjMDTmeM4LfoVV7
         /E9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544515; x=1709149315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D2f9pNvhcyLc/PibYsTQquDg17laW3IxMWJKcWpeScI=;
        b=mOjvwAGGyHKny9uj40sOashsoyeNNtgaBX8YGMDgCuteRjE7TtHGEjyvWnyhK+9j1z
         k7LVF1QVdcthn2BbNcJf/ewT2mjMPHYI0N9tCdAFgZRAPiTUx6BOaC49XhnCMVb79xqm
         SJPiunUalq61E3a0nTo+Lh/fUzJeBBiPD2w6MXt/TK4SX9R9nQW2QSqmpGiiRqHXVCNQ
         GaciroNQ4R+rbtYIkhTPZpWMaJk3n3g9w3znNf4ZHyl8JEyPZGm1ywWOyAOxfBWB8/Sb
         ZrIaoO1fx9RdIN9INFrBHPTHWoQ83HLM+zefRxbzVmV9uJTe08uB2JTWOvzqGuT0dYS0
         tZBw==
X-Forwarded-Encrypted: i=2; AJvYcCWO6A4/Wz1fOSIQzQFxTxGgQHSb1jPOhnEbnmw8fs/MWolv4lpUPARprbSbgk/19gz7Sz4vxJu0NmvYrqe99OHPa31wa2+WDg==
X-Gm-Message-State: AOJu0YzO8Lw/Ccv1fvTQffdYBizW7COMDEBDOlhEcTls+pB0q+xe/1mi
	Mq0JccOOLPZDcTOzCFqn7q4sT5X3XjlGLPR/JhQeqOhoR9cuK1vA
X-Google-Smtp-Source: AGHT+IH3KLChBFV805vS5hEdT6fucPAfzPvBZcJ4S8q/yDi/KIfKPvk+iqKGi6ZY1BoYkB3YUkmYxQ==
X-Received: by 2002:a05:6870:44cf:b0:21e:e60a:4dab with SMTP id t15-20020a05687044cf00b0021ee60a4dabmr10191830oai.21.1708544515365;
        Wed, 21 Feb 2024 11:41:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:612a:b0:21e:2e1d:c177 with SMTP id
 s42-20020a056870612a00b0021e2e1dc177ls5996769oae.0.-pod-prod-07-us; Wed, 21
 Feb 2024 11:41:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVWmRyHTV16SsljsIRHs9Q6KNCZP9/Eydxq8F4QwnWL38QgUUbv5jglTQG1ncu+M1DzD4l5ULNzMB7HFiM++raIcU4OkD8yZlX99g==
X-Received: by 2002:a05:6870:1f0d:b0:21e:95d9:dc7b with SMTP id pd13-20020a0568701f0d00b0021e95d9dc7bmr14193187oab.30.1708544514273;
        Wed, 21 Feb 2024 11:41:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544514; cv=none;
        d=google.com; s=arc-20160816;
        b=pUgkrRadhESh8a0aPIEC9U0DQyq3gJKQyNq3jbYf4Scu8ADttBIuC6LijkV/RbVcgf
         ZvNZ4qqRZz8KcFNzOrfVoPUMrFiemQqSXUR9gsghxiegnnRrQJx4pfm9IzJmPOo+aPkf
         ARS69qUpFMq0pLtU17wQ8i7EZP1rQhA0sTVChVjpzmieHylA1P7oBoh7zb8i+klfs/h6
         pwCpq2WlTUXch12ihVaQUvu+ctZGdP7Cg+JisCOYF79gQjnmkzfzzb/BB6gMAhebmdp3
         URRLkalKA5wnxyY41ey8MT+lc+Lb7S8AJKXVL3lQpWsz9HZINPE/4ECXIk4gcxDQjgnk
         r2Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=SBIp7l6FYh66kLRcBRL71yRbl3V2EKRiwuHeAcwsTzw=;
        fh=vxLgQJ5H2LBgEs3aOSwb/zUz7RcHeFP7XEfEy5QUCUI=;
        b=Mg+6kLz2OL3iWn4qZDJOsdwP0sOrewc5OdR3/bHk7o7G99gWr1VoDy4Y8w9/gK0/TJ
         1pOpS5opRlvDWbA08G7d7DzYYXPpDsR5miTC6REGr/TbUfN+bOJiVMq/P0ED05lWbIy+
         0sST5FURjv6hilPOkOlzvVfUToiLfi3E96GNBUyJkmhj3BFxcTZMyO4tGsFG/wlUrivS
         /n4TiDr1NMmMRNnCjGsrwGtxsvlRavO/miKDTcUAeymVr3L0Mrm6XL/ARVPHWwREdEig
         ytWpi/etiv/mFhvdm+FTEDRqLmaWILdB7EBbw3XwjMdx96/OwNGztk5cAt4jiRY2AVhR
         D7cw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nHsiP7p8;
       spf=pass (google.com: domain of 3avlwzqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3AVLWZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id hb25-20020a056870781900b0021e5223aee5si919890oab.4.2024.02.21.11.41.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3avlwzqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5efe82b835fso156757017b3.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWUbewYlJ8PFdD8YvNxx72Z0iGpd0IdH860gea96VLCF+jaScj7rHxK1HlQzCi4EVJ7v8k8PWXCyQZQ6P0/FWC9GwlpsKSFB66IMg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:690c:3388:b0:608:40e4:d05e with SMTP id
 fl8-20020a05690c338800b0060840e4d05emr2214356ywb.7.1708544513792; Wed, 21 Feb
 2024 11:41:53 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:39 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-27-surenb@google.com>
Subject: [PATCH v4 26/36] mm: percpu: Introduce pcpuobj_ext
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
 header.i=@google.com header.s=20230601 header.b=nHsiP7p8;       spf=pass
 (google.com: domain of 3avlwzqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3AVLWZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-27-surenb%40google.com.
