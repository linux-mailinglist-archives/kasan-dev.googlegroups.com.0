Return-Path: <kasan-dev+bncBC7OD3FKWUERB4OE6GXQMGQEHI5C3KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2408E885DC5
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:11 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5a4d1d88494sf1428754eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039090; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Lrjh6TIjztbv0VsunYF/fiACtwoJkNXAr6aubtA60xuihmN1GuN7J+fjA08G+ZoIK
         jEZ2quDjc0jjG0Xzn8lMiFgSejqEkl0udZO4vxhWCCjvyXkuAkJEFTbDKzL5Ib7yk0+4
         fEoISg9XCxO/vCYJJ1s/4UTZFuw93hel4j+b3i/eQ3rUE9CH6mGdRAGQaG2wOoSLZPOk
         jEBjXjorA1hnaKJvszHow2iy79RNav4r/lS2Tn5PW5b8ROg/aRngt/MobmYPkXRLumtQ
         hCCVnw53uSM5x13KR4T9jT/seHJW060Eh/KCdcCKDNGy2Ja9dPZpultHExYa+1dAVuSy
         EAeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=e3cRwvmmxRQa9kkEVlr0+suM2734V2Z1NLgLjhrvhXE=;
        fh=gnNX1JNVgktfCKmEHgD4KB0DHTuG1ls9HYh4G+LwvYI=;
        b=o1Q0vRaciGqHvjp1U8A7FY/DIwG1Hh/Pr+kHk8gSrMUIE9T4Sp2wspOZSZDtpLs6gz
         MSTvwQZg/SbhnjnQR670n1k2/Zp3PAmkLgfelhOwXWPKo851B3NnTvvarvOw+5pf8WLK
         bk07yhyR7HwiwcC/PTQa7+jUoTEJh+LjBR5dKBKUslxNkGf6krqpADk1V+wwX6ZcFUVL
         cVjoTdsL43xuLOjAm0HRbTfHLNobpXwDgVTKkuwYeBxOnXO7AWqvCghZPtWbQm5+GZs+
         FHByPfx6aukG215ogy8BoCiPYYXmQR74Q3nc+hmYLKhlo1w1lJJI1WAa07ZLPejRBe2j
         juVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4xO3fFKM;
       spf=pass (google.com: domain of 3cgl8zqykcv0npm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3cGL8ZQYKCV0NPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039090; x=1711643890; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=e3cRwvmmxRQa9kkEVlr0+suM2734V2Z1NLgLjhrvhXE=;
        b=h0GtyrQ1tzmkED9lZZ4ekKhx1HpsoM3SXsksdaKBbprTjepo60U2cEvBfidSevf6Jv
         w5fxlZqghawVksopjnpVMXHiXPBjZK7IinitXCOMWiC99FGMeCIg6ntHtn3U1UPAvoE0
         Y/CRmulgIpOvPid1FO9zSodtpCkq+7qDbftZkwxRmhWgZIDC+yT+HWCsa+Lmv+nEtP68
         J/tqkweR97wCyF1RPN9lSOdPey+Sfymp6+FLwQtZOSWWwYX7EusdwUz1LG6itidrlX9c
         xSdzPHNQV8EL+CQd5/iAIgwfUNE1uPg2cml603KGmSRoU8CufwkQHd4HRDnaQITaEKQh
         3j3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039090; x=1711643890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e3cRwvmmxRQa9kkEVlr0+suM2734V2Z1NLgLjhrvhXE=;
        b=iH3jFmRRmzXL148awubus41dVTi3eWkCr1qiPo4SdAweLbYAsYUmcoHyDOXnQ3EmBr
         FR+rYJVQ9fy8t+kxfkVgIqZTG/2mO4NtTiMu5AwtzTRbqDXfnqh/gxcJu0A7TtOFbnbi
         7ZDzCO4bZl1FjQoeDSkMJiYa55skL/oJVukaU3lpTf6DNaVlYdA7omLebZcsS2ruIUKb
         CyTzuo/Taz47P9QeNXuQAiP9Sh2p9R629+HFjCfNfbRJrEA+aGcd5yGAyxuWSUi5vMJl
         5C5ZnzXHTtk/OxGO7TDMM8G/0TDZFPSuERdXsse86xdDSbsaD8h8qWMEjxhsto3zcB00
         Nz9g==
X-Forwarded-Encrypted: i=2; AJvYcCUpsPRaBwk+aJdzNwrVGzJT847J7m1VA3GxIwP+hPq49U/L5S9mUbrc7aleFTm5OtTZuk2utjNoAEJk8K6Cvbw8nm1yTKdueg==
X-Gm-Message-State: AOJu0YxzdEQBrrS1L7Ii71zVRwyewhIRGi1MtbCdJYmzYGi3bj/qxNS8
	V+Fi03puC2KZIJu0YyW7wkAgDjbsNRm/zSr9rryIuyaZgWVLKxno
X-Google-Smtp-Source: AGHT+IEp/xwFe0cgRJ2tGD+p4/UsRg5RigHAEMjdRQxlTKfo3x4/o/Z7BXsebb9L5eneUIDqSzS+Pw==
X-Received: by 2002:a05:6871:2895:b0:221:b40e:b841 with SMTP id bq21-20020a056871289500b00221b40eb841mr8368oac.28.1711039089991;
        Thu, 21 Mar 2024 09:38:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:330f:b0:222:6319:39ed with SMTP id
 nf15-20020a056871330f00b00222631939edls561429oac.2.-pod-prod-00-us; Thu, 21
 Mar 2024 09:38:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvJOwJRutGzYqZ/dC3MzUERzCoO2KoDAddiu8fdECWh9PkORdOFq29eyVe49BXj1zfwUk/jOalHCuTBjeClTcFT4JrnWMM6MtKfQ==
X-Received: by 2002:a05:6870:1b0c:b0:221:9495:4ee9 with SMTP id hl12-20020a0568701b0c00b0022194954ee9mr13157oab.22.1711039089235;
        Thu, 21 Mar 2024 09:38:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039089; cv=none;
        d=google.com; s=arc-20160816;
        b=j1F5fDHhvq4h7z80IKK3CYTOMGMsGlezsozfk5HUkbmkXVcxOuYpZLxZQoAh3uC6Sj
         1qw3XsAMso/XTu6q9BGBAfJsUIWHTlkjgZWuHWz+OEEV1lJ3ksbsVu2x9JVTAAFNbIom
         WhnF1UBLs/IjKPrkir0QilgQD06f9RuJcd8I2SPwCzwwgwnv9QTHaAW/t4RnvarG167p
         SCgaGQ1EED1CSDyiPFVurubLvs4tQ1S2b1rW1eriVzNkLk2w+YJBIUxtZEFoOmG+9Yir
         kseKtKvrx7n6k1f+iWm3AUuVVM/eTMx/uvPjKewOtrTpnYKWGTJONu29WPp8SL2rwyHy
         k7iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DhlVYTL0Ii8S3ZK2BTRjXFWA8z6FsoYkfvkLJwCmND0=;
        fh=M7hyRhaZPZ0xVt+KdwIxjFoD/Bgu750VqcKxCig2M2g=;
        b=oJeLhEczBXj1AqGMq5IvqS58PHqgHyM2kgj1nslYwyErYBYnHdZoRuN7uWPzLY57fH
         ZVSvo0by94XLXiwSyRVHzqYoaX8gM9/umbD6w4RBPThMClKZhP09LW2FtO2pIZ6mcMhV
         9OCDX8Yzhgq8T8WJ82i2Qf6bzqOHMcdH9UHdaOGE+irR3u050LNzM/wc++ZsDJMRtVt5
         etYBWrZpY08xntLF1dO9ucIaUEuvJShvrwdqUTTkySvUtGiNZQC2/r9UEMq5pS0KchOo
         QgvMKc+0dvOv8NXnza4vu8CZkWMR3x18FWfjDb2BeOC4VG/elLxSw1l9VakNPoHZCTGF
         ECZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4xO3fFKM;
       spf=pass (google.com: domain of 3cgl8zqykcv0npm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3cGL8ZQYKCV0NPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id ee14-20020a0568306f0e00b006e6839fcce8si29152otb.0.2024.03.21.09.38.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cgl8zqykcv0npm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60a0a5bf550so21850477b3.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWmlmF4Urs+kVA+05fcV7FJXXLQiAzYdlZTH4ZI5wt2vttxq1GLHDHDhR8B5cKr4w6v8CG3JPVAv4K9eTo4imk5kOL0TJ0DiYRTA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:2689:b0:dcb:e4a2:1ab1 with SMTP id
 dx9-20020a056902268900b00dcbe4a21ab1mr2382761ybb.11.1711039088572; Thu, 21
 Mar 2024 09:38:08 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:49 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-28-surenb@google.com>
Subject: [PATCH v6 27/37] mm: percpu: Introduce pcpuobj_ext
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
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4xO3fFKM;       spf=pass
 (google.com: domain of 3cgl8zqykcv0npm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3cGL8ZQYKCV0NPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-28-surenb%40google.com.
