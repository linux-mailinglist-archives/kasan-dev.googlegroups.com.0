Return-Path: <kasan-dev+bncBC7OD3FKWUERBWND3GXAMGQECQ4MQJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A2AD685E773
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:14 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-36424431577sf58998075ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544473; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMUejrtr34V6kGsuCr5HHWchTrUD59kCzi1RG80eVhzlEePetE5R1ASYcBC3IPE3H1
         KyldEEcCFUe6C2x88Dd8/fQbjNVvxLRDNvFkeHu9uX925C/CZ8gZMYT0zSWeJMnKtDJi
         veYtcDwsrZt0Ied7+QdDz/nbakCSr8dPla87bTLvs2/mSx4E0BqdoW2ZPJ6aoBLMTX6T
         ojiXC/hsT12v+eHpf16gXYJn8+kV4Q2EfUtYBOxsYqnPoyAMWRE4tMxPJuYs5wxTrTMh
         eFMKLd36MRHg2vmsnoMi4X5maGXUvJc2gO7azdB1nXo6xOLlpL+5gSn9qci1vcxGS3nZ
         h6ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=xC8ibVXKcy/CYTrYVUwyY8Hkt41kdbJTl0HQKYfw8LM=;
        fh=PV/2nDpb5A4cIUg9ip8XlPWx263Ayo+aCXzr2cQRHqw=;
        b=PvkthEqSh8lXdZ1/C0B4QTZNve7z0jMbHUvSobZtiXLPfmksTtcQSz7kkvclQzbOH9
         /U8u/5pQAroDfDYyOg5LN25O840i3JRv9Fp10RhvKR633gMM8MEivWWQzagfDc2qZbQU
         yju7bJhZFHCSW+64orG/zDkk1wPqrf2MLsU5UFV43k5kd/I5QFn9LGf8ifcseAnd1JvA
         UE0dYJSIDvYWlDxdFvQFhgRm0zvIKxhAXOCRA9hM/WGvMMNrpOq+CRVv2iHa2qMwcuch
         SWouxipQsGzJyZPFtWEmryZa4CcSeYGsWbWngEZ+51JKTFtAotsaWSk1VPoB3wNSnaKs
         OlNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KuNlz4FI;
       spf=pass (google.com: domain of 32fhwzqykcqs352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=32FHWZQYKCQs352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544473; x=1709149273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xC8ibVXKcy/CYTrYVUwyY8Hkt41kdbJTl0HQKYfw8LM=;
        b=vPJFAnatytdIVUiKaQfugmnRVEwjbYMOM84TbjxOSuKCCURXTcQcHq8g34EcP3tX9f
         U5E+QPU5hfk0RTbes5IcDjNy5QCEH9rxOQuaXJNpZbklQdwXH+5UVZtR4Z+LhCdSbd7z
         NOW8wPA/TU1f7Uapbyaix9LOkemCuc8zD1Xtl4GM+tS5P7DC6iR3Z1lwGp5Q48pAge+W
         PSGYTd+lysyPUy7YZJLQYQ6k1Htzimu67GvIEJhJaXBXw10vBlPaVrjVTLT2/EqsEITT
         W9zw4Qv+3io/rT7n0LJqVcUGQ6j492vfCM0jETAP4kshvFM+J4YNlfNHNQlvaLkDnwzu
         YwuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544473; x=1709149273;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xC8ibVXKcy/CYTrYVUwyY8Hkt41kdbJTl0HQKYfw8LM=;
        b=eUtAcovH5huSJZ6bQ2Foe/YjBsXD7RoN+y4byxkEOfImNGwHdWPoC/N4Uero4UoO9o
         aeLemx6wU6JUWt1VcoFAMoxBG0dQOflSOGj08Ps0bHQNDeGbo8qpkPzYKkOcPRu/UVa5
         tnds0AAT53+9EwtzH58UIvKF+SaTnHBPSErgRd+TfscohU3BR9ark4ogcckNjnIH390o
         rwan9dl9MHyd4Mp3IbBqe9gs7nRbpvn0wgRMsSLbIgiMa//2cJXsjtV2/l3heYOBAPqC
         tMRPg2pdzmTMtNjFoyd0KtykiAlXylG3KDSbWYsuTUlEgnDxcD0GGQrVJWqimJnbcCjg
         /+0g==
X-Forwarded-Encrypted: i=2; AJvYcCVSMFka2E8GTUpQhIbj7GA7zJo4nryl8r398FYKtKF+Ep5chcqDBCSz4Y8kme1cEZNw/POag5DZk6f8t8HBR7irmrSMbgGOwA==
X-Gm-Message-State: AOJu0YzsMfwfp3bgeV2+CwYuAy66DuWiQsyEIRoRuNBlU6a+IxcpfYpu
	4bhuOosVyYo/iyE9L+fNUrhjg6HgG5K+nwwVD9Eg+vUmZxPmxB6g
X-Google-Smtp-Source: AGHT+IFRBzZ1hZMJJPE/0vLvSZHVbG7CZ5V4/PfQ5+EJc3gBVqW6Szr7+rTvN93M2BNA5vFHTcceDQ==
X-Received: by 2002:a05:6e02:1d02:b0:365:1e8e:9c6c with SMTP id i2-20020a056e021d0200b003651e8e9c6cmr14985733ila.11.1708544473520;
        Wed, 21 Feb 2024 11:41:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c27:b0:363:d634:895a with SMTP id
 m7-20020a056e021c2700b00363d634895als3271237ilh.2.-pod-prod-03-us; Wed, 21
 Feb 2024 11:41:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWLLJ02vAKDsppfRbEJXtxZHujxV9m9/zsLjGV4ieAK8HAYgad/ptK24QjEUvJjfn+rVA1C0GNfCzpTDps9pQrmEyJ+GTf3DckaAA==
X-Received: by 2002:a92:d28a:0:b0:365:5dbd:aa34 with SMTP id p10-20020a92d28a000000b003655dbdaa34mr1398596ilp.12.1708544472837;
        Wed, 21 Feb 2024 11:41:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544472; cv=none;
        d=google.com; s=arc-20160816;
        b=z+OgEKRsGuZmxax818Hdu8DKqQiYUTxSB9CWpz/g0nVtsgXmd+lwIYBRFoAz0A2jld
         83H0WesGAcD87PxTJxQavaK2JqH8X0sCYdoNiUnjWkcdSKHU9wrKRtN96jBuKCvEvv6a
         j4tmq4Q040GEl5wHAzTv9XlY35t+LOpgqTEcpA4iHKv1f59tGrTQ66oitSs0BAKCSgbv
         AtH3/XfAbygTN73c3N9essInm2157LbUUldHXd/mT0KL3kVfxu+X6xipUKy4umt2dC9/
         R0kmcjzhGf/HO7HOwDdL8W96GO8s47Bb9x1CEffhRXCnAVqw5mjbNkInRQUgisH2Lyus
         Et6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=WxhfLGit1QGZvv88CDz2b9TMcGpnJbteJyGythFonXg=;
        fh=9Wou+ISfcbltwyzE/ONx1Yap1wTTkBraeQCII9uX5F0=;
        b=nyf2N5CkxAvhBpNfS0F2Bm+rZe05zHg+HD/juL6Fh368k4Oyjvxl9Ecz25d3+CxATF
         qlSfuy9xyFpYc8Sy2o1mAEcp/D7DVge4ApQZoBE34P9KsSDMhdx2dHWWJF1c1V6dEc8P
         npR7xcYggbhnsbezckOCdPbTtzAcMNWKrqNk8IYmsRubgNW3QtE2Ns1FlFD8p+MrNh6j
         jPQO9wLmR2D4beqPYjahWKCGiLvyyiJ3GR0i06nFyEwO+kmSBiAcmQZqP7zshIRUDsrD
         rHRz53ijnnx9kiQ8RTYeO+LbDRpoKzO18p6rq0gHy1k8C7XnrKbzEr1CN5bFV5UajPii
         d5Yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KuNlz4FI;
       spf=pass (google.com: domain of 32fhwzqykcqs352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=32FHWZQYKCQs352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id b10-20020a056e020c8a00b00363d9b5d963si972226ile.1.2024.02.21.11.41.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 32fhwzqykcqs352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc6b5d1899eso213214276.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV2zT1+qqC/3w3h9uFY8d4n+Qs6dI+h354TMCazDE/1PjZem24ej2KPaL11wVmkJmoO96Em1haCid/+zmRApFYehle8uaMPKxbUow==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:124b:b0:dc7:7655:46ce with SMTP id
 t11-20020a056902124b00b00dc7765546cemr24975ybu.2.1708544472027; Wed, 21 Feb
 2024 11:41:12 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:20 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-8-surenb@google.com>
Subject: [PATCH v4 07/36] mm: introduce slabobj_ext to support slab object extensions
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
 header.i=@google.com header.s=20230601 header.b=KuNlz4FI;       spf=pass
 (google.com: domain of 32fhwzqykcqs352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=32FHWZQYKCQs352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
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

Currently slab pages can store only vectors of obj_cgroup pointers in
page->memcg_data. Introduce slabobj_ext structure to allow more data
to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
to support current functionality while allowing to extend slabobj_ext
in the future.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/memcontrol.h |  20 +++++--
 include/linux/mm_types.h   |   4 +-
 init/Kconfig               |   4 ++
 mm/kfence/core.c           |  14 ++---
 mm/kfence/kfence.h         |   4 +-
 mm/memcontrol.c            |  56 +++----------------
 mm/page_owner.c            |   2 +-
 mm/slab.h                  |  62 +++++++++++++--------
 mm/slub.c                  | 109 +++++++++++++++++++++++++++----------
 9 files changed, 156 insertions(+), 119 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 20ff87f8e001..eb1dc181e412 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -348,8 +348,8 @@ struct mem_cgroup {
 extern struct mem_cgroup *root_mem_cgroup;
 
 enum page_memcg_data_flags {
-	/* page->memcg_data is a pointer to an objcgs vector */
-	MEMCG_DATA_OBJCGS = (1UL << 0),
+	/* page->memcg_data is a pointer to an slabobj_ext vector */
+	MEMCG_DATA_OBJEXTS = (1UL << 0),
 	/* page has been accounted as a non-slab kernel page */
 	MEMCG_DATA_KMEM = (1UL << 1),
 	/* the next bit after the last actual flag */
@@ -387,7 +387,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
 	unsigned long memcg_data = folio->memcg_data;
 
 	VM_BUG_ON_FOLIO(folio_test_slab(folio), folio);
-	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJCGS, folio);
+	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
 
 	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
@@ -408,7 +408,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
 	unsigned long memcg_data = folio->memcg_data;
 
 	VM_BUG_ON_FOLIO(folio_test_slab(folio), folio);
-	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJCGS, folio);
+	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
 
 	return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
@@ -505,7 +505,7 @@ static inline struct mem_cgroup *folio_memcg_check(struct folio *folio)
 	 */
 	unsigned long memcg_data = READ_ONCE(folio->memcg_data);
 
-	if (memcg_data & MEMCG_DATA_OBJCGS)
+	if (memcg_data & MEMCG_DATA_OBJEXTS)
 		return NULL;
 
 	if (memcg_data & MEMCG_DATA_KMEM) {
@@ -551,7 +551,7 @@ static inline struct mem_cgroup *get_mem_cgroup_from_objcg(struct obj_cgroup *ob
 static inline bool folio_memcg_kmem(struct folio *folio)
 {
 	VM_BUG_ON_PGFLAGS(PageTail(&folio->page), &folio->page);
-	VM_BUG_ON_FOLIO(folio->memcg_data & MEMCG_DATA_OBJCGS, folio);
+	VM_BUG_ON_FOLIO(folio->memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	return folio->memcg_data & MEMCG_DATA_KMEM;
 }
 
@@ -1633,6 +1633,14 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
 }
 #endif /* CONFIG_MEMCG */
 
+/*
+ * Extended information for slab objects stored as an array in page->memcg_data
+ * if MEMCG_DATA_OBJEXTS is set.
+ */
+struct slabobj_ext {
+	struct obj_cgroup *objcg;
+} __aligned(8);
+
 static inline void __inc_lruvec_kmem_state(void *p, enum node_stat_item idx)
 {
 	__mod_lruvec_kmem_state(p, idx, 1);
diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
index 8b611e13153e..9ff97f4e74c5 100644
--- a/include/linux/mm_types.h
+++ b/include/linux/mm_types.h
@@ -169,7 +169,7 @@ struct page {
 	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
 	atomic_t _refcount;
 
-#ifdef CONFIG_MEMCG
+#ifdef CONFIG_SLAB_OBJ_EXT
 	unsigned long memcg_data;
 #endif
 
@@ -306,7 +306,7 @@ struct folio {
 			};
 			atomic_t _mapcount;
 			atomic_t _refcount;
-#ifdef CONFIG_MEMCG
+#ifdef CONFIG_SLAB_OBJ_EXT
 			unsigned long memcg_data;
 #endif
 #if defined(WANT_PAGE_VIRTUAL)
diff --git a/init/Kconfig b/init/Kconfig
index 8426d59cc634..fe5f5e75bd3f 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -929,6 +929,9 @@ config NUMA_BALANCING_DEFAULT_ENABLED
 	  If set, automatic NUMA balancing will be enabled if running on a NUMA
 	  machine.
 
+config SLAB_OBJ_EXT
+	bool
+
 menuconfig CGROUPS
 	bool "Control Group support"
 	select KERNFS
@@ -962,6 +965,7 @@ config MEMCG
 	bool "Memory controller"
 	select PAGE_COUNTER
 	select EVENTFD
+	select SLAB_OBJ_EXT
 	help
 	  Provides control over the memory footprint of tasks in a cgroup.
 
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 8350f5c06f2e..964b8482275b 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -595,9 +595,9 @@ static unsigned long kfence_init_pool(void)
 			continue;
 
 		__folio_set_slab(slab_folio(slab));
-#ifdef CONFIG_MEMCG
-		slab->memcg_data = (unsigned long)&kfence_metadata_init[i / 2 - 1].objcg |
-				   MEMCG_DATA_OBJCGS;
+#ifdef CONFIG_MEMCG_KMEM
+		slab->obj_exts = (unsigned long)&kfence_metadata_init[i / 2 - 1].obj_exts |
+				 MEMCG_DATA_OBJEXTS;
 #endif
 	}
 
@@ -645,8 +645,8 @@ static unsigned long kfence_init_pool(void)
 
 		if (!i || (i % 2))
 			continue;
-#ifdef CONFIG_MEMCG
-		slab->memcg_data = 0;
+#ifdef CONFIG_MEMCG_KMEM
+		slab->obj_exts = 0;
 #endif
 		__folio_clear_slab(slab_folio(slab));
 	}
@@ -1139,8 +1139,8 @@ void __kfence_free(void *addr)
 {
 	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
 
-#ifdef CONFIG_MEMCG
-	KFENCE_WARN_ON(meta->objcg);
+#ifdef CONFIG_MEMCG_KMEM
+	KFENCE_WARN_ON(meta->obj_exts.objcg);
 #endif
 	/*
 	 * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index f46fbb03062b..084f5f36e8e7 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -97,8 +97,8 @@ struct kfence_metadata {
 	struct kfence_track free_track;
 	/* For updating alloc_covered on frees. */
 	u32 alloc_stack_hash;
-#ifdef CONFIG_MEMCG
-	struct obj_cgroup *objcg;
+#ifdef CONFIG_MEMCG_KMEM
+	struct slabobj_ext obj_exts;
 #endif
 };
 
diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 1ed40f9d3a27..7021639d2a6f 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -2977,13 +2977,6 @@ void mem_cgroup_commit_charge(struct folio *folio, struct mem_cgroup *memcg)
 }
 
 #ifdef CONFIG_MEMCG_KMEM
-/*
- * The allocated objcg pointers array is not accounted directly.
- * Moreover, it should not come from DMA buffer and is not readily
- * reclaimable. So those GFP bits should be masked off.
- */
-#define OBJCGS_CLEAR_MASK	(__GFP_DMA | __GFP_RECLAIMABLE | \
-				 __GFP_ACCOUNT | __GFP_NOFAIL)
 
 /*
  * mod_objcg_mlstate() may be called with irq enabled, so
@@ -3003,62 +2996,27 @@ static inline void mod_objcg_mlstate(struct obj_cgroup *objcg,
 	rcu_read_unlock();
 }
 
-int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
-				 gfp_t gfp, bool new_slab)
-{
-	unsigned int objects = objs_per_slab(s, slab);
-	unsigned long memcg_data;
-	void *vec;
-
-	gfp &= ~OBJCGS_CLEAR_MASK;
-	vec = kcalloc_node(objects, sizeof(struct obj_cgroup *), gfp,
-			   slab_nid(slab));
-	if (!vec)
-		return -ENOMEM;
-
-	memcg_data = (unsigned long) vec | MEMCG_DATA_OBJCGS;
-	if (new_slab) {
-		/*
-		 * If the slab is brand new and nobody can yet access its
-		 * memcg_data, no synchronization is required and memcg_data can
-		 * be simply assigned.
-		 */
-		slab->memcg_data = memcg_data;
-	} else if (cmpxchg(&slab->memcg_data, 0, memcg_data)) {
-		/*
-		 * If the slab is already in use, somebody can allocate and
-		 * assign obj_cgroups in parallel. In this case the existing
-		 * objcg vector should be reused.
-		 */
-		kfree(vec);
-		return 0;
-	}
-
-	kmemleak_not_leak(vec);
-	return 0;
-}
-
 static __always_inline
 struct mem_cgroup *mem_cgroup_from_obj_folio(struct folio *folio, void *p)
 {
 	/*
 	 * Slab objects are accounted individually, not per-page.
 	 * Memcg membership data for each individual object is saved in
-	 * slab->memcg_data.
+	 * slab->obj_exts.
 	 */
 	if (folio_test_slab(folio)) {
-		struct obj_cgroup **objcgs;
+		struct slabobj_ext *obj_exts;
 		struct slab *slab;
 		unsigned int off;
 
 		slab = folio_slab(folio);
-		objcgs = slab_objcgs(slab);
-		if (!objcgs)
+		obj_exts = slab_obj_exts(slab);
+		if (!obj_exts)
 			return NULL;
 
 		off = obj_to_index(slab->slab_cache, slab, p);
-		if (objcgs[off])
-			return obj_cgroup_memcg(objcgs[off]);
+		if (obj_exts[off].objcg)
+			return obj_cgroup_memcg(obj_exts[off].objcg);
 
 		return NULL;
 	}
@@ -3066,7 +3024,7 @@ struct mem_cgroup *mem_cgroup_from_obj_folio(struct folio *folio, void *p)
 	/*
 	 * folio_memcg_check() is used here, because in theory we can encounter
 	 * a folio where the slab flag has been cleared already, but
-	 * slab->memcg_data has not been freed yet
+	 * slab->obj_exts has not been freed yet
 	 * folio_memcg_check() will guarantee that a proper memory
 	 * cgroup pointer or NULL will be returned.
 	 */
diff --git a/mm/page_owner.c b/mm/page_owner.c
index 5634e5d890f8..262aa7d25f40 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -377,7 +377,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
 	if (!memcg_data)
 		goto out_unlock;
 
-	if (memcg_data & MEMCG_DATA_OBJCGS)
+	if (memcg_data & MEMCG_DATA_OBJEXTS)
 		ret += scnprintf(kbuf + ret, count - ret,
 				"Slab cache page\n");
 
diff --git a/mm/slab.h b/mm/slab.h
index 54deeb0428c6..7f19b0a2acd8 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -87,8 +87,8 @@ struct slab {
 	unsigned int __unused;
 
 	atomic_t __page_refcount;
-#ifdef CONFIG_MEMCG
-	unsigned long memcg_data;
+#ifdef CONFIG_SLAB_OBJ_EXT
+	unsigned long obj_exts;
 #endif
 };
 
@@ -97,8 +97,8 @@ struct slab {
 SLAB_MATCH(flags, __page_flags);
 SLAB_MATCH(compound_head, slab_cache);	/* Ensure bit 0 is clear */
 SLAB_MATCH(_refcount, __page_refcount);
-#ifdef CONFIG_MEMCG
-SLAB_MATCH(memcg_data, memcg_data);
+#ifdef CONFIG_SLAB_OBJ_EXT
+SLAB_MATCH(memcg_data, obj_exts);
 #endif
 #undef SLAB_MATCH
 static_assert(sizeof(struct slab) <= sizeof(struct page));
@@ -541,42 +541,60 @@ static inline bool kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t fla
 	return false;
 }
 
-#ifdef CONFIG_MEMCG_KMEM
+#ifdef CONFIG_SLAB_OBJ_EXT
+
 /*
- * slab_objcgs - get the object cgroups vector associated with a slab
+ * slab_obj_exts - get the pointer to the slab object extension vector
+ * associated with a slab.
  * @slab: a pointer to the slab struct
  *
- * Returns a pointer to the object cgroups vector associated with the slab,
+ * Returns a pointer to the object extension vector associated with the slab,
  * or NULL if no such vector has been associated yet.
  */
-static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
+static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 {
-	unsigned long memcg_data = READ_ONCE(slab->memcg_data);
+	unsigned long obj_exts = READ_ONCE(slab->obj_exts);
 
-	VM_BUG_ON_PAGE(memcg_data && !(memcg_data & MEMCG_DATA_OBJCGS),
+#ifdef CONFIG_MEMCG
+	VM_BUG_ON_PAGE(obj_exts && !(obj_exts & MEMCG_DATA_OBJEXTS),
 							slab_page(slab));
-	VM_BUG_ON_PAGE(memcg_data & MEMCG_DATA_KMEM, slab_page(slab));
+	VM_BUG_ON_PAGE(obj_exts & MEMCG_DATA_KMEM, slab_page(slab));
 
-	return (struct obj_cgroup **)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct slabobj_ext *)(obj_exts & ~MEMCG_DATA_FLAGS_MASK);
+#else
+	return (struct slabobj_ext *)obj_exts;
+#endif
 }
 
-int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
-				 gfp_t gfp, bool new_slab);
-void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
-		     enum node_stat_item idx, int nr);
-#else /* CONFIG_MEMCG_KMEM */
-static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
+int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
+			gfp_t gfp, bool new_slab);
+
+#else /* CONFIG_SLAB_OBJ_EXT */
+
+static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 {
 	return NULL;
 }
 
-static inline int memcg_alloc_slab_cgroups(struct slab *slab,
-					       struct kmem_cache *s, gfp_t gfp,
-					       bool new_slab)
+static inline int alloc_slab_obj_exts(struct slab *slab,
+				      struct kmem_cache *s, gfp_t gfp,
+				      bool new_slab)
 {
 	return 0;
 }
-#endif /* CONFIG_MEMCG_KMEM */
+
+static inline struct slabobj_ext *
+prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
+{
+	return NULL;
+}
+
+#endif /* CONFIG_SLAB_OBJ_EXT */
+
+#ifdef CONFIG_MEMCG_KMEM
+void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
+		     enum node_stat_item idx, int nr);
+#endif
 
 size_t __ksize(const void *objp);
 
diff --git a/mm/slub.c b/mm/slub.c
index d31b03a8d9d5..76fb600fbc80 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -683,10 +683,10 @@ static inline bool __slab_update_freelist(struct kmem_cache *s, struct slab *sla
 
 	if (s->flags & __CMPXCHG_DOUBLE) {
 		ret = __update_freelist_fast(slab, freelist_old, counters_old,
-				            freelist_new, counters_new);
+					    freelist_new, counters_new);
 	} else {
 		ret = __update_freelist_slow(slab, freelist_old, counters_old,
-				            freelist_new, counters_new);
+					    freelist_new, counters_new);
 	}
 	if (likely(ret))
 		return true;
@@ -710,13 +710,13 @@ static inline bool slab_update_freelist(struct kmem_cache *s, struct slab *slab,
 
 	if (s->flags & __CMPXCHG_DOUBLE) {
 		ret = __update_freelist_fast(slab, freelist_old, counters_old,
-				            freelist_new, counters_new);
+					    freelist_new, counters_new);
 	} else {
 		unsigned long flags;
 
 		local_irq_save(flags);
 		ret = __update_freelist_slow(slab, freelist_old, counters_old,
-				            freelist_new, counters_new);
+					     freelist_new, counters_new);
 		local_irq_restore(flags);
 	}
 	if (likely(ret))
@@ -1881,13 +1881,72 @@ static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
 		NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
 }
 
-#ifdef CONFIG_MEMCG_KMEM
-static inline void memcg_free_slab_cgroups(struct slab *slab)
+#ifdef CONFIG_SLAB_OBJ_EXT
+
+/*
+ * The allocated objcg pointers array is not accounted directly.
+ * Moreover, it should not come from DMA buffer and is not readily
+ * reclaimable. So those GFP bits should be masked off.
+ */
+#define OBJCGS_CLEAR_MASK	(__GFP_DMA | __GFP_RECLAIMABLE | \
+				__GFP_ACCOUNT | __GFP_NOFAIL)
+
+int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
+			gfp_t gfp, bool new_slab)
 {
-	kfree(slab_objcgs(slab));
-	slab->memcg_data = 0;
+	unsigned int objects = objs_per_slab(s, slab);
+	unsigned long obj_exts;
+	void *vec;
+
+	gfp &= ~OBJCGS_CLEAR_MASK;
+	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
+			   slab_nid(slab));
+	if (!vec)
+		return -ENOMEM;
+
+	obj_exts = (unsigned long)vec;
+#ifdef CONFIG_MEMCG
+	obj_exts |= MEMCG_DATA_OBJEXTS;
+#endif
+	if (new_slab) {
+		/*
+		 * If the slab is brand new and nobody can yet access its
+		 * obj_exts, no synchronization is required and obj_exts can
+		 * be simply assigned.
+		 */
+		slab->obj_exts = obj_exts;
+	} else if (cmpxchg(&slab->obj_exts, 0, obj_exts)) {
+		/*
+		 * If the slab is already in use, somebody can allocate and
+		 * assign slabobj_exts in parallel. In this case the existing
+		 * objcg vector should be reused.
+		 */
+		kfree(vec);
+		return 0;
+	}
+
+	kmemleak_not_leak(vec);
+	return 0;
 }
 
+static inline void free_slab_obj_exts(struct slab *slab)
+{
+	struct slabobj_ext *obj_exts;
+
+	obj_exts = slab_obj_exts(slab);
+	if (!obj_exts)
+		return;
+
+	kfree(obj_exts);
+	slab->obj_exts = 0;
+}
+#else /* CONFIG_SLAB_OBJ_EXT */
+static inline void free_slab_obj_exts(struct slab *slab)
+{
+}
+#endif /* CONFIG_SLAB_OBJ_EXT */
+
+#ifdef CONFIG_MEMCG_KMEM
 static inline size_t obj_full_size(struct kmem_cache *s)
 {
 	/*
@@ -1966,15 +2025,15 @@ static void __memcg_slab_post_alloc_hook(struct kmem_cache *s,
 		if (likely(p[i])) {
 			slab = virt_to_slab(p[i]);
 
-			if (!slab_objcgs(slab) &&
-			    memcg_alloc_slab_cgroups(slab, s, flags, false)) {
+			if (!slab_obj_exts(slab) &&
+			    alloc_slab_obj_exts(slab, s, flags, false)) {
 				obj_cgroup_uncharge(objcg, obj_full_size(s));
 				continue;
 			}
 
 			off = obj_to_index(s, slab, p[i]);
 			obj_cgroup_get(objcg);
-			slab_objcgs(slab)[off] = objcg;
+			slab_obj_exts(slab)[off].objcg = objcg;
 			mod_objcg_state(objcg, slab_pgdat(slab),
 					cache_vmstat_idx(s), obj_full_size(s));
 		} else {
@@ -1995,18 +2054,18 @@ void memcg_slab_post_alloc_hook(struct kmem_cache *s, struct obj_cgroup *objcg,
 
 static void __memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 				   void **p, int objects,
-				   struct obj_cgroup **objcgs)
+				   struct slabobj_ext *obj_exts)
 {
 	for (int i = 0; i < objects; i++) {
 		struct obj_cgroup *objcg;
 		unsigned int off;
 
 		off = obj_to_index(s, slab, p[i]);
-		objcg = objcgs[off];
+		objcg = obj_exts[off].objcg;
 		if (!objcg)
 			continue;
 
-		objcgs[off] = NULL;
+		obj_exts[off].objcg = NULL;
 		obj_cgroup_uncharge(objcg, obj_full_size(s));
 		mod_objcg_state(objcg, slab_pgdat(slab), cache_vmstat_idx(s),
 				-obj_full_size(s));
@@ -2018,16 +2077,16 @@ static __fastpath_inline
 void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
 			  int objects)
 {
-	struct obj_cgroup **objcgs;
+	struct slabobj_ext *obj_exts;
 
 	if (!memcg_kmem_online())
 		return;
 
-	objcgs = slab_objcgs(slab);
-	if (likely(!objcgs))
+	obj_exts = slab_obj_exts(slab);
+	if (likely(!obj_exts))
 		return;
 
-	__memcg_slab_free_hook(s, slab, p, objects, objcgs);
+	__memcg_slab_free_hook(s, slab, p, objects, obj_exts);
 }
 
 static inline
@@ -2038,15 +2097,6 @@ void memcg_slab_alloc_error_hook(struct kmem_cache *s, int objects,
 		obj_cgroup_uncharge(objcg, objects * obj_full_size(s));
 }
 #else /* CONFIG_MEMCG_KMEM */
-static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
-{
-	return NULL;
-}
-
-static inline void memcg_free_slab_cgroups(struct slab *slab)
-{
-}
-
 static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
 					     struct list_lru *lru,
 					     struct obj_cgroup **objcgp,
@@ -2314,7 +2364,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
 					 struct kmem_cache *s, gfp_t gfp)
 {
 	if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
-		memcg_alloc_slab_cgroups(slab, s, gfp, true);
+		alloc_slab_obj_exts(slab, s, gfp, true);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
 			    PAGE_SIZE << order);
@@ -2323,8 +2373,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
 static __always_inline void unaccount_slab(struct slab *slab, int order,
 					   struct kmem_cache *s)
 {
-	if (memcg_kmem_online())
-		memcg_free_slab_cgroups(slab);
+	free_slab_obj_exts(slab);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
 			    -(PAGE_SIZE << order));
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-8-surenb%40google.com.
