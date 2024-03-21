Return-Path: <kasan-dev+bncBC7OD3FKWUERBRGE6GXQMGQESPVBXZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id D4CB7885DA0
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:25 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5a486a8e1fdsf1009319eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039044; cv=pass;
        d=google.com; s=arc-20160816;
        b=VqGkZL3sCtWkWu3FSlIxGcPmD7pmHhABxw0oePKz07FpRppmd+N+4XWWK1CdQ1LEOA
         SOilCJ73Dril2eByRlaqq4kUO4KbiX2UhvjzU5JQ/SVpCCsAmsWZkIaFn9hoZQSvkXee
         u50pddW56b1Zo4n4AiYTi58xwBEcE5vx1nU7SVcRraifHERUR7ADZvFaAXh1bcrmbKh4
         E0LIK3MDym92eOpIFsyQBWKAbvON2/LOyo13rZ6pth1LBSOmC9HdtaCweqT3jwgQ4xnw
         rt4gHOYwDkKETWAAEZ5aYZCL3rC8OgZqser0AD0l7mTQzoHAOaiIdQBT66zp0CVdGQb2
         xQsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Cfw4rkyEgf53z5WXX4MVk4yz+50IgVbjgpWWzu1q//A=;
        fh=AtNHgfXPFHdJKrXDLoQE3JilO6/uZ+CSzyI8+QFA+x4=;
        b=RrE6X8hLG9H/1KnKEmJXKYrJXNGqTf+FUX8OuLVj4Abqc4tJmqtQuH+IcMl9KfEpa3
         uX8v/WedjNkRT3M0LmAdp25qHwqPQpdeZnZ6vMzgXLdBbB5Af40RgFkiwPLphPWVvomu
         fEfdb/sTGeqIKppdh7Mn8lobIhDcK6igF/dGdhefaKCzH63GUkP0JGs1ia1F2e3ZJTB7
         iq5M7cmhN0YgPKFgX8K6mp0M1ja+iFkwpq3XRFvam2qNptD77iFVZQGoKwoH+BCJwIl5
         /l6ezjUnNuR8Hlb67bY2eM2lE3tdzXp42c7JFd95WuQP6tZx05u7J/hylLV7Ek0UZC4M
         quMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CDVQCnU9;
       spf=pass (google.com: domain of 3q2l8zqykctaegdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Q2L8ZQYKCTAegdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039044; x=1711643844; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Cfw4rkyEgf53z5WXX4MVk4yz+50IgVbjgpWWzu1q//A=;
        b=iWSgkV99d564kyxflfNgjAVqf2aM4h/QiIGEHxOfk2vpG3ilMNO6AHexKzCBmXi85a
         hTXPQ30tefE2KB2u4YhcwU6A/iWifnunrO6ik4VN+C5A3ZR+adcMIDbsQ0/T4Ei1myCK
         +j4YdPxT8lGcWTcTx1sqiJMB2twwilPcOc2ApN+Jffot7eco0eRohZJPn+mtFcgUf1Vy
         +FaQtU+He0OoFQC1L/scEaDoHzxMobFJUVH3qT+pP7jzlC8nijdVzstxaOVfEq2Pka5g
         jHBL50wXRt/5YlufMzEgiDQnEBUw/pKqPB9chfyHnb4zOXOpG8+pdCPH5uAVBY5hoQyo
         pirA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039044; x=1711643844;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cfw4rkyEgf53z5WXX4MVk4yz+50IgVbjgpWWzu1q//A=;
        b=K6me8SNK5z9kVFtI95e5nYIzoi11dYpypWi/o1iQMaGoQbYBgaq6BhFFU3RJd7FgpW
         0QhjjJ0iBWVuvAcGirF0TOWyQgulMynXaWcOgBLlC7jkKvS5AhAkMOa6BDyjE7tnrM4Y
         lZiSqF3j06ozFk19qifD0RjDkgfEGDWuxdftKrWo4qJqHAaImAV5onfrui3dhnHp2I24
         E020S0oTuKsa+xot4BZG9W4mOaMLHHw6fWhdqYvDN5f0aSjWE8hGNtK2NTnXAxOeBMdK
         ioCuaPQgIgJ3Y6yLvGI8QK5HSVBKd7Kwaywk1xhoYikVnvCvrvzdxKDIGTkI4yV8nwFL
         W9Zw==
X-Forwarded-Encrypted: i=2; AJvYcCWCguPdAnQVHZV8s8VPWa9c/DSe5pmCGlPEZs1LAMhyKaVXRj98rI/0XgKMtK2PPVZcJY5tAy+dKiCgLCmvkD8XoVJreCdLsw==
X-Gm-Message-State: AOJu0YxMl63aSaA6zv3AA3xfzN4b1mXczcnGlNA2dRd3im7KwNXJ57Vq
	RQX15yuDr0fYH1t7XkvJ3kBXqO3Wz34T3TPAt/JgdtSChAUPT+BE
X-Google-Smtp-Source: AGHT+IHKloqpmeah07ekRNKtNKyKRTGY6YGWwjnuSyoISD9hW7DxA4Oj4d/KKno8v6lzI+6bzFBx1A==
X-Received: by 2002:a05:6820:987:b0:5a1:316c:2d88 with SMTP id cg7-20020a056820098700b005a1316c2d88mr96154oob.0.1711039044702;
        Thu, 21 Mar 2024 09:37:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b44b:0:b0:5a4:905d:743f with SMTP id h11-20020a4ab44b000000b005a4905d743fls1126695ooo.1.-pod-prod-05-us;
 Thu, 21 Mar 2024 09:37:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxrsaLmu0TlQGPxOlpNF6pmcB0qEuUGwOiCPUp8X0tTj5Ftj5jSbtOUQ2hkCvtFr5WuZZJgVFzuGkkg5pIgTTZujn0WpcUPZ9fcQ==
X-Received: by 2002:a9d:6e92:0:b0:6e5:78c:45d2 with SMTP id a18-20020a9d6e92000000b006e5078c45d2mr2849629otr.8.1711039043709;
        Thu, 21 Mar 2024 09:37:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039043; cv=none;
        d=google.com; s=arc-20160816;
        b=UQWy5fJzY1A1Z2ssKGrE6UXRR20YH2J6KFlwpD/+Ts1r0i9XKWP6BFG/LSVFSGypw+
         zhk9uWjqjUJKNjPJG0XBMdAreW7UdFEdyo4Q3Yo0WSFtZNoL9V/lDXQjn8meKmaSKlFi
         2UVLAUcSviQuPz0mwLcNE42rtlwRnpS8hKXKaU7ZPju+nq3ZghPoaXaFm00peVdk3eQG
         HySNJuXpY4hpeenN/lpykAwV93AouNiNYAcOcxh4gxbIrenGwY6LuZlHt7PzR3waBMmf
         tTe98M0S1thLL3TA37WrLhU5ErEgL39YH6onGwK3uN58EnE0ifhu8Jdz/CnKFOOp1JaD
         bD5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=v0oqySW4AkJKGPTAgvOI/D0yl/u4uQhGUVWc4LnGMQI=;
        fh=X1GvcHOUwQxmyNb5MXzBDImge72yO9MZCcOgmie8z4U=;
        b=DvL51s3EvQJYm/qOqbcbgh8LTvH8jy0py2ecxeOpEZ7+6rzR9aS6gX8mgW5xYjREDM
         Oy+pACCBAqByDsRZmrVHUhNDm9XkwdVzrZWzDVQQiWm5EvbE3H3p7rzJlLVMbU3YH5YS
         wjTuBoQNr9xfxmk1DdIL5cRqn8j8oNldGAfdjvaTSnA4uXYWnO8c9YblmKdvCGfxlWqm
         G6gWSFn+TTJ5HJQgWioWS6JiiBrpGtsfJCom0RIT6UO0/yt+/c5SjgdyGGvjUSJ7v4GD
         z7VWHKuOqZ7VzxkIyg7PgmBsDUuZ5jeJE0VPOaSlGbo4+IOBN3w47qOh/6F5JbOeU/SG
         2C3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CDVQCnU9;
       spf=pass (google.com: domain of 3q2l8zqykctaegdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Q2L8ZQYKCTAegdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id ee14-20020a0568306f0e00b006e6839fcce8si29022otb.0.2024.03.21.09.37.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3q2l8zqykctaegdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-608e4171382so19891137b3.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXUQhq16wVoG/VBcMY8Km8y9pPgrwKJVr5b9nwgQsU7DiXttJkVdVYKqe9AylP/6a5fOyi2Lx4cwxnmXYpmUTNO41t9WltnGHtUNA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:118f:b0:dc2:26f6:fbc8 with SMTP id
 m15-20020a056902118f00b00dc226f6fbc8mr979928ybu.7.1711039043023; Thu, 21 Mar
 2024 09:37:23 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:28 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-7-surenb@google.com>
Subject: [PATCH v6 06/37] mm: introduce slabobj_ext to support slab object extensions
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
 header.i=@google.com header.s=20230601 header.b=CDVQCnU9;       spf=pass
 (google.com: domain of 3q2l8zqykctaegdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Q2L8ZQYKCTAegdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
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
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/memcontrol.h |  20 +++++---
 include/linux/mm_types.h   |   4 +-
 init/Kconfig               |   4 ++
 mm/kfence/core.c           |  14 ++---
 mm/kfence/kfence.h         |   4 +-
 mm/memcontrol.c            |  56 +++-----------------
 mm/page_owner.c            |   2 +-
 mm/slab.h                  |  52 ++++++++++---------
 mm/slub.c                  | 101 +++++++++++++++++++++++++++++--------
 9 files changed, 145 insertions(+), 112 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index b6264796815d..99f423742324 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -349,8 +349,8 @@ struct mem_cgroup {
 extern struct mem_cgroup *root_mem_cgroup;
 
 enum page_memcg_data_flags {
-	/* page->memcg_data is a pointer to an objcgs vector */
-	MEMCG_DATA_OBJCGS = (1UL << 0),
+	/* page->memcg_data is a pointer to an slabobj_ext vector */
+	MEMCG_DATA_OBJEXTS = (1UL << 0),
 	/* page has been accounted as a non-slab kernel page */
 	MEMCG_DATA_KMEM = (1UL << 1),
 	/* the next bit after the last actual flag */
@@ -388,7 +388,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
 	unsigned long memcg_data = folio->memcg_data;
 
 	VM_BUG_ON_FOLIO(folio_test_slab(folio), folio);
-	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJCGS, folio);
+	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
 
 	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
@@ -409,7 +409,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
 	unsigned long memcg_data = folio->memcg_data;
 
 	VM_BUG_ON_FOLIO(folio_test_slab(folio), folio);
-	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJCGS, folio);
+	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
 
 	return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
@@ -506,7 +506,7 @@ static inline struct mem_cgroup *folio_memcg_check(struct folio *folio)
 	 */
 	unsigned long memcg_data = READ_ONCE(folio->memcg_data);
 
-	if (memcg_data & MEMCG_DATA_OBJCGS)
+	if (memcg_data & MEMCG_DATA_OBJEXTS)
 		return NULL;
 
 	if (memcg_data & MEMCG_DATA_KMEM) {
@@ -552,7 +552,7 @@ static inline struct mem_cgroup *get_mem_cgroup_from_objcg(struct obj_cgroup *ob
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
index 5240bd7bca33..4ae4684d1add 100644
--- a/include/linux/mm_types.h
+++ b/include/linux/mm_types.h
@@ -169,7 +169,7 @@ struct page {
 	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
 	atomic_t _refcount;
 
-#ifdef CONFIG_MEMCG
+#ifdef CONFIG_SLAB_OBJ_EXT
 	unsigned long memcg_data;
 #endif
 
@@ -331,7 +331,7 @@ struct folio {
 			};
 			atomic_t _mapcount;
 			atomic_t _refcount;
-#ifdef CONFIG_MEMCG
+#ifdef CONFIG_SLAB_OBJ_EXT
 			unsigned long memcg_data;
 #endif
 #if defined(WANT_PAGE_VIRTUAL)
diff --git a/init/Kconfig b/init/Kconfig
index f3ea5dea9c85..7a20d713010c 100644
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
index aab3f5473203..8f9984bf6fd2 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -2979,13 +2979,6 @@ void mem_cgroup_commit_charge(struct folio *folio, struct mem_cgroup *memcg)
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
@@ -3005,62 +2998,27 @@ static inline void mod_objcg_mlstate(struct obj_cgroup *objcg,
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
@@ -3068,7 +3026,7 @@ struct mem_cgroup *mem_cgroup_from_obj_folio(struct folio *folio, void *p)
 	/*
 	 * folio_memcg_check() is used here, because in theory we can encounter
 	 * a folio where the slab flag has been cleared already, but
-	 * slab->memcg_data has not been freed yet
+	 * slab->obj_exts has not been freed yet
 	 * folio_memcg_check() will guarantee that a proper memory
 	 * cgroup pointer or NULL will be returned.
 	 */
diff --git a/mm/page_owner.c b/mm/page_owner.c
index d17d1351ec84..5a77d792112a 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -484,7 +484,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
 	if (!memcg_data)
 		goto out_unlock;
 
-	if (memcg_data & MEMCG_DATA_OBJCGS)
+	if (memcg_data & MEMCG_DATA_OBJEXTS)
 		ret += scnprintf(kbuf + ret, count - ret,
 				"Slab cache page\n");
 
diff --git a/mm/slab.h b/mm/slab.h
index d2bc9b191222..1c16dc8344fa 100644
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
@@ -536,42 +536,44 @@ static inline bool kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t fla
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
+#else /* CONFIG_SLAB_OBJ_EXT */
+
+static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 {
 	return NULL;
 }
 
-static inline int memcg_alloc_slab_cgroups(struct slab *slab,
-					       struct kmem_cache *s, gfp_t gfp,
-					       bool new_slab)
-{
-	return 0;
-}
-#endif /* CONFIG_MEMCG_KMEM */
+#endif /* CONFIG_SLAB_OBJ_EXT */
+
+#ifdef CONFIG_MEMCG_KMEM
+void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
+		     enum node_stat_item idx, int nr);
+#endif
 
 size_t __ksize(const void *objp);
 
diff --git a/mm/slub.c b/mm/slub.c
index bc9f40889834..5c896c76812d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1871,13 +1871,78 @@ static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
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
+static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
+			       gfp_t gfp, bool new_slab)
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
+static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
+			       gfp_t gfp, bool new_slab)
+{
+	return 0;
+}
+
+static inline void free_slab_obj_exts(struct slab *slab)
+{
+}
+#endif /* CONFIG_SLAB_OBJ_EXT */
+
+#ifdef CONFIG_MEMCG_KMEM
 static inline size_t obj_full_size(struct kmem_cache *s)
 {
 	/*
@@ -1956,15 +2021,15 @@ static void __memcg_slab_post_alloc_hook(struct kmem_cache *s,
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
@@ -1985,18 +2050,18 @@ void memcg_slab_post_alloc_hook(struct kmem_cache *s, struct obj_cgroup *objcg,
 
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
@@ -2008,16 +2073,16 @@ static __fastpath_inline
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
@@ -2028,10 +2093,6 @@ void memcg_slab_alloc_error_hook(struct kmem_cache *s, int objects,
 		obj_cgroup_uncharge(objcg, objects * obj_full_size(s));
 }
 #else /* CONFIG_MEMCG_KMEM */
-static inline void memcg_free_slab_cgroups(struct slab *slab)
-{
-}
-
 static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
 					     struct list_lru *lru,
 					     struct obj_cgroup **objcgp,
@@ -2298,7 +2359,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
 					 struct kmem_cache *s, gfp_t gfp)
 {
 	if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
-		memcg_alloc_slab_cgroups(slab, s, gfp, true);
+		alloc_slab_obj_exts(slab, s, gfp, true);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
 			    PAGE_SIZE << order);
@@ -2308,7 +2369,7 @@ static __always_inline void unaccount_slab(struct slab *slab, int order,
 					   struct kmem_cache *s)
 {
 	if (memcg_kmem_online())
-		memcg_free_slab_cgroups(slab);
+		free_slab_obj_exts(slab);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
 			    -(PAGE_SIZE << order));
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-7-surenb%40google.com.
