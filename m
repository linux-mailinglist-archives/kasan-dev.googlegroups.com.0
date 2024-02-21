Return-Path: <kasan-dev+bncBC7OD3FKWUERBB5E3GXAMGQETWEGFRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 885FC85E795
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:42:00 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-68f992cd47bsf27968936d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:42:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544519; cv=pass;
        d=google.com; s=arc-20160816;
        b=ApYTvWQXOv6mnwCpFRUiFtNOGQys47+P13+sMcT680cBcTbZ3n6hfjhEjUF6/alS7O
         xr0j26aEaqATsw7dcVfjgPHzUPW4wgKQNbhZPHqMQrB/BWNfH7IqaCC6Z69MU1u5CKZ2
         YAnIkQ0GqClGyzQLICC3HgWMa7FaZPIgtJmd7+revRw6k8D5lIgsUv8YnswVZaHOLMhD
         I++hGT53YC6L7/m4/boMEnmlt2TZL0/caP58LHVrUVxMuUThwIWULI43cZr6eb6S8MTK
         M6amzflH88yA37JhbpwWCeC0XSN+H/4d+ktzIavLOT6aaOTmTNbhlJeodgNBjbkVeipq
         DkeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GFwjCRCAHWVjEaizgwseMHA1FuBanEZLMtUaSiPbero=;
        fh=vmlXqCyyCwFGgkbeW2zFh3U2dVTXa58bhI7yJvF+tTU=;
        b=ktfd1YsqMB1DgX4p0YXxZ0or/tFNTw5BemqX5Gzlf03aYAYhtHOF61//8OzXtMDLdE
         oGAzYT/0mj8veKVQ/RMtS0BLd4bxC1JhCQ4sfwCj666IT0vR3/uPMRFpjCSVI7UWTbLA
         mMzdhH9WfT81hKccbT1U/HfoLxlW0aMjZ6vJ2CnUVBa3w6QzGj9r5I8B2JK9ANcns8u5
         02dpAPYYx40lXr2LokcrTFYmDWRmLWy6298eoeauaFbL9PrLCr63krq2fYLZ8TGO43JM
         yfTKcXvZ9Y4MHRySYNDPXWMdUK7VUSo5SVJMGqrMw6R0DAv4EOpu2QIfdZmNkkITxRUn
         /Www==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tgJvMMZj;
       spf=pass (google.com: domain of 3bllwzqykctknpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3BlLWZQYKCTknpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544519; x=1709149319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GFwjCRCAHWVjEaizgwseMHA1FuBanEZLMtUaSiPbero=;
        b=GBrd7Nh1WJDVUCNDC5XkpAnmtXxsWJa4Vlk7KrsnXRllAVvDQG6MDE3u5cT2Vdv9M8
         f3Ly8vSQcJhQ56HCo+OOBPh5DDndCpDbRxsMjchlmh/sOwva1rvvBCJCxl7tejUFFfaB
         3/a1BEGVS4VzUwicQ9AFH3hxqMEApMY49fcmsKaXH8HUrB7AD4ydvIJhmYNJT83ks/+Q
         g8GTMENlN5xwpiNnj+hIzjQUVnViN4lewR1aHnX11iwnZhBCTfTfyfoL9Jt7KurrX+Xy
         ab1FoeNCkz+3PiHXaq1Csb8/qNVeWb6gcSnSoPZh/KkwuVdQ75HJx/SZNzp14AY4fdde
         8iyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544519; x=1709149319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GFwjCRCAHWVjEaizgwseMHA1FuBanEZLMtUaSiPbero=;
        b=Jla3KKvIylPUO0oHuntGf493nRlyqrg3gcM7+MnR/Yxe3wyZwv7AVp/CthryDu1Tes
         RBds2D1twlkIiAtGA6eKM6wFKtM5KAQlEDNPzQtqQsO7AYFW6hd7fsKxnjmEYHsozE6l
         VLoQiP/+QlB/yQi3hc1f2V6/qsJVT4sK95/k8Y8wV1K8CC3iIdAbRayGWBVKesea7iEk
         5uH3CrL5q/xR0o63r1B8jMmSsKeQo2hRfWi4qCX+JLmV89PNQhZDTqZf3oONW+5ra9On
         U4ZEBUSJydUa3RpKDDTemMiqmbf/O3nNmxkiR43/WcaYw//dyOUIEdRB5O71TOImBN5O
         7Q5Q==
X-Forwarded-Encrypted: i=2; AJvYcCUy3YTfDLNqQtCfYz+fM1SYLwbEkWLXWzYST8LJMPVfuodi73l+vOB8BoK74iGhDxACvEtGY36Ymdmum9uItJh96oje/sPrFQ==
X-Gm-Message-State: AOJu0YyHeM4GoVSTDlrpkWFeGaezCQ1mUwTCWZLFULWSf8JJ2uCKHpUN
	mGBpVEzb3lRL14QOGDVQXIBL6dZYbT6+unaG3xt0fNKqHbGfI7jl
X-Google-Smtp-Source: AGHT+IHkwH8KlKqJ+Qaz6W2EHvDdi/Hna+CCFRJOUyijtcNVOqsSVMJFJwxcY0WtMHF51thOXuRRcQ==
X-Received: by 2002:a05:6214:2624:b0:68f:52d7:e599 with SMTP id gv4-20020a056214262400b0068f52d7e599mr15806196qvb.8.1708544519208;
        Wed, 21 Feb 2024 11:41:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:e46:b0:68f:7606:3d7e with SMTP id
 o6-20020a0562140e4600b0068f76063d7els761773qvc.0.-pod-prod-09-us; Wed, 21 Feb
 2024 11:41:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUqcFqmQVPbhnD3zV9KgoOwfWwgWG1TTOpeFnKDHd4fut7+luq0Y/MPzEpeo/EsKbPO+t5Bi6Wh3PnqySCp1QqIhoWD2CMVPfe5+g==
X-Received: by 2002:a0c:ca0f:0:b0:68f:144f:4c4 with SMTP id c15-20020a0cca0f000000b0068f144f04c4mr22099902qvk.37.1708544518578;
        Wed, 21 Feb 2024 11:41:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544518; cv=none;
        d=google.com; s=arc-20160816;
        b=Af+bvGSIi+zf/LIaPxB+QBxultyrrA6XvrXqIPETZo8ZwIPzXK6BzT8rl0izTAdNnK
         i7AaFsabdrri44KFqVIjWOmOLb6AvSF5NkT5JmJiblouBmSqOiw4VuWu6AvpPUW0B/y9
         rnfx2MlqZvI794EbRbGmXBL86mVmfcgKIVKQEzLte8cz20wamrBijo18W2eX/XFOjhrP
         Cb2WCJ0WI2YP3QpRAlKayU7AD5yfRZTkRXmv3rKGAVG/n6pHeV3GH63ph7QVH3odKCsS
         IAINymlJoLO+j8Bj26OqZ2FB/I9+lZ14hzMJh4FB3VewHXgTSyyDaelnIv+CNi4dT8W+
         gICA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YEtQtrsg9A+6qi4G17OgAejNr2caNgy1uwZYQh9NpiY=;
        fh=eroKOJwGbAxu1HUiG19byKkHYd0nIRRcVntIPlIDcj8=;
        b=HYboiDQvWMcOcdwwEAVwoGKNmQsn2ugBgV+VhNSbbLIR3VeGJ2SDeHI4wFVmFsh5lo
         3OJ0kpwvAaP0JZwUJeOrmK/D57ZDZYDu+pyexJdHJfzxovKhFjmWDDyFyFJhmsXELKeq
         a4qjFQTK5YpehdNymDxZ0iSjyk4V0a5kgAOaX7fd85HHqyT/gKRGT4Pr90o/Ltw31WQj
         Byx0p/tu/0TzLqR2xSTtPFJKTYy97OraOMsQjIv1QeedxC/fZlDaE9aYpDqPuUqdla7E
         tM3hB0CTslCDS1hIuaj3QmyA8/Fm37BA49YFyuOqfOTmrM850LKGWj+AJz1BgTYII5+B
         Ltbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tgJvMMZj;
       spf=pass (google.com: domain of 3bllwzqykctknpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3BlLWZQYKCTknpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id z7-20020a0cfc07000000b0068f10446451si815871qvo.7.2024.02.21.11.41.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bllwzqykctknpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-608852fc324so16616377b3.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUkv04ZWh7JxA8uRNskwrE+CYJRP9l17vwYTIlN4FIHjtH2fkXUsKmYUYAqsPakVflV7b1DRR0BXNWbBFY8KOxpsSfIHoorFYsyng==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:690c:3388:b0:608:406d:6973 with SMTP id
 fl8-20020a05690c338800b00608406d6973mr2030736ywb.5.1708544518169; Wed, 21 Feb
 2024 11:41:58 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:41 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-29-surenb@google.com>
Subject: [PATCH v4 28/36] mm: percpu: enable per-cpu allocation tagging
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
 header.i=@google.com header.s=20230601 header.b=tgJvMMZj;       spf=pass
 (google.com: domain of 3bllwzqykctknpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3BlLWZQYKCTknpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
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

Redefine __alloc_percpu, __alloc_percpu_gfp and __alloc_reserved_percpu
to record allocations and deallocations done by these functions.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/percpu.h | 23 ++++++++++-----
 mm/percpu.c            | 64 +++++-------------------------------------
 2 files changed, 23 insertions(+), 64 deletions(-)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 62b5eb45bd89..e54921c79c9a 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -2,6 +2,7 @@
 #ifndef __LINUX_PERCPU_H
 #define __LINUX_PERCPU_H
 
+#include <linux/alloc_tag.h>
 #include <linux/mmdebug.h>
 #include <linux/preempt.h>
 #include <linux/smp.h>
@@ -9,6 +10,7 @@
 #include <linux/pfn.h>
 #include <linux/init.h>
 #include <linux/cleanup.h>
+#include <linux/sched.h>
 
 #include <asm/percpu.h>
 
@@ -125,7 +127,6 @@ extern int __init pcpu_page_first_chunk(size_t reserved_size,
 				pcpu_fc_cpu_to_node_fn_t cpu_to_nd_fn);
 #endif
 
-extern void __percpu *__alloc_reserved_percpu(size_t size, size_t align) __alloc_size(1);
 extern bool __is_kernel_percpu_address(unsigned long addr, unsigned long *can_addr);
 extern bool is_kernel_percpu_address(unsigned long addr);
 
@@ -133,14 +134,16 @@ extern bool is_kernel_percpu_address(unsigned long addr);
 extern void __init setup_per_cpu_areas(void);
 #endif
 
-extern void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp) __alloc_size(1);
-extern void __percpu *__alloc_percpu(size_t size, size_t align) __alloc_size(1);
-extern void free_percpu(void __percpu *__pdata);
+extern void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
+				   gfp_t gfp) __alloc_size(1);
 extern size_t pcpu_alloc_size(void __percpu *__pdata);
 
-DEFINE_FREE(free_percpu, void __percpu *, free_percpu(_T))
-
-extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
+#define __alloc_percpu_gfp(_size, _align, _gfp)				\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, false, _gfp))
+#define __alloc_percpu(_size, _align)					\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, false, GFP_KERNEL))
+#define __alloc_reserved_percpu(_size, _align)				\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, true, GFP_KERNEL))
 
 #define alloc_percpu_gfp(type, gfp)					\
 	(typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type),	\
@@ -149,6 +152,12 @@ extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
 	(typeof(type) __percpu *)__alloc_percpu(sizeof(type),		\
 						__alignof__(type))
 
+extern void free_percpu(void __percpu *__pdata);
+
+DEFINE_FREE(free_percpu, void __percpu *, free_percpu(_T))
+
+extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
+
 extern unsigned long pcpu_nr_pages(void);
 
 #endif /* __LINUX_PERCPU_H */
diff --git a/mm/percpu.c b/mm/percpu.c
index 578531ea1f43..2badcc5e0e71 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1726,7 +1726,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
 #endif
 
 /**
- * pcpu_alloc - the percpu allocator
+ * pcpu_alloc_noprof - the percpu allocator
  * @size: size of area to allocate in bytes
  * @align: alignment of area (max PAGE_SIZE)
  * @reserved: allocate from the reserved chunk if available
@@ -1740,7 +1740,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
  * RETURNS:
  * Percpu pointer to the allocated area on success, NULL on failure.
  */
-static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
+void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
 				 gfp_t gfp)
 {
 	gfp_t pcpu_gfp;
@@ -1907,6 +1907,8 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	pcpu_memcg_post_alloc_hook(objcg, chunk, off, size);
 
+	pcpu_alloc_tag_alloc_hook(chunk, off, size);
+
 	return ptr;
 
 fail_unlock:
@@ -1935,61 +1937,7 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	return NULL;
 }
-
-/**
- * __alloc_percpu_gfp - allocate dynamic percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- * @gfp: allocation flags
- *
- * Allocate zero-filled percpu area of @size bytes aligned at @align.  If
- * @gfp doesn't contain %GFP_KERNEL, the allocation doesn't block and can
- * be called from any context but is a lot more likely to fail. If @gfp
- * has __GFP_NOWARN then no warning will be triggered on invalid or failed
- * allocation requests.
- *
- * RETURNS:
- * Percpu pointer to the allocated area on success, NULL on failure.
- */
-void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
-{
-	return pcpu_alloc(size, align, false, gfp);
-}
-EXPORT_SYMBOL_GPL(__alloc_percpu_gfp);
-
-/**
- * __alloc_percpu - allocate dynamic percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- *
- * Equivalent to __alloc_percpu_gfp(size, align, %GFP_KERNEL).
- */
-void __percpu *__alloc_percpu(size_t size, size_t align)
-{
-	return pcpu_alloc(size, align, false, GFP_KERNEL);
-}
-EXPORT_SYMBOL_GPL(__alloc_percpu);
-
-/**
- * __alloc_reserved_percpu - allocate reserved percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- *
- * Allocate zero-filled percpu area of @size bytes aligned at @align
- * from reserved percpu area if arch has set it up; otherwise,
- * allocation is served from the same dynamic area.  Might sleep.
- * Might trigger writeouts.
- *
- * CONTEXT:
- * Does GFP_KERNEL allocation.
- *
- * RETURNS:
- * Percpu pointer to the allocated area on success, NULL on failure.
- */
-void __percpu *__alloc_reserved_percpu(size_t size, size_t align)
-{
-	return pcpu_alloc(size, align, true, GFP_KERNEL);
-}
+EXPORT_SYMBOL_GPL(pcpu_alloc_noprof);
 
 /**
  * pcpu_balance_free - manage the amount of free chunks
@@ -2328,6 +2276,8 @@ void free_percpu(void __percpu *ptr)
 	spin_lock_irqsave(&pcpu_lock, flags);
 	size = pcpu_free_area(chunk, off);
 
+	pcpu_alloc_tag_free_hook(chunk, off, size);
+
 	pcpu_memcg_free_hook(chunk, off, size);
 
 	/*
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-29-surenb%40google.com.
