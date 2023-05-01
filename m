Return-Path: <kasan-dev+bncBC7OD3FKWUERBIO6X6RAMGQEFXIH3VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B7F056F33E0
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:02 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-328f6562564sf42908795ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960161; cv=pass;
        d=google.com; s=arc-20160816;
        b=OTx1AW9SbUmjuDq6AfDVLdrTfezMXgviVLMETRBm3ZqeMqrxDErRHmbjGszq2uR6kj
         nVEe30wVb6d0+DvsxJdSMOgHIwQIn83pBXYr7f4ELKyfzdxdrPP+ERUXJKuuYzyjJ+mU
         yc9qiO+YxALUeZ+TIQgpe2zRzZLMP57RP/9dnPGzQEF7qI5j7x/k/KGCXgWkCaMBTD1A
         Iq7E3hidllsKnHUNc59p06vDSg9GAO56DAeQWrLfs/HFGjfptQj7STonNzSr4lYCQ+ml
         4X9pZXj+6hxDMcTbPJ2TUCgruHzf/bBJvV6cLllPc7S/cvqZP6sO5bTnV8VV3Pt1/0bS
         D+qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Uuu1/WtzOwyfJVzb5EPqO6tK8DsWEQs5xoaAskUwpJg=;
        b=shfcJ15ayeU4a1+zf/vFPJpRL8sef0LrWUCtsS/QmgN9l8JUyv4CQjEpJO2imPgppE
         XC/ONrSMRI8SBDbe6KBdNGijdGUvAZbDbDIuKnY6s8XIWhN5XT4JZdzQWxfgrayPQ4ys
         SbU2uikr6IuyMd9agJuTIHkcfb9lqIfStTT1Wanhcilf60MqwZjxBtONEgLmK9t08mys
         NNI06BrPWaFVgUE3785WSUaSb80+WOtiXf0BPzHYhHyz1AmjRMmrM34wZJhyEMtXoA3+
         xcyclv4Q6LdtBI8DOtk4pqeCrLiLriImgXg8uOeJGbPVe1jFENAmc29t+96N8dIDoWcN
         1I7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Nr4QXyj/";
       spf=pass (google.com: domain of 3io9pzaykcwcxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3IO9PZAYKCWcXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960161; x=1685552161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Uuu1/WtzOwyfJVzb5EPqO6tK8DsWEQs5xoaAskUwpJg=;
        b=HJh8cbwCnivXb8ZbpbFUywnoA60+uLdANYWrB5k1rZQqEagO7SFERvS/Bl20PZBsrB
         0xoC6neKZ2YQqgSNytAeyCfjSiSsvi3OtS7dNRzqTaauyqkLsOi0n6C7h6RngIRz21FT
         nPR0To0kRzOAdGdL6bd5sa08QYMJGwpdAqY892vh2D35QQwDw0dLZmJtdDiPM5hFYQ9N
         Vkwb23klG6ExbStSlx0ZaWYoIhdGapgoZqPisxXzjt+1ZL36sQhyhcwXbY1BtZvdLfRl
         YWXvH1y9y/OXSe3XP8u33MVOy8xMBWwb4RweBXNQrQFtKh2f8KM9uD/2r5L4/0sl7TuK
         lEqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960161; x=1685552161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Uuu1/WtzOwyfJVzb5EPqO6tK8DsWEQs5xoaAskUwpJg=;
        b=EWhqTug4D3FOT6XDpkoPOOQBQn7zTsTraUoPPvgr2YYWKA/mdkDraMsfUsz6z3uEUG
         z0XqaNBX40H50yHlO4TYxiAHrjmPZ8oEueCScvq299OmkEu3iftG9ZtuR1mIP/UvvXC/
         E+a1hJh/uz2iyu8FWb+k5lyYRPABX/0pjDKwXiSuo7odoE9xIl+miq+b/1M/gbNQzkSG
         8haa8CIjSfxi3PAhobLSuTtjWd+yC5ZOUeExUOtzhCDuM2igvprsUCpqd0UHp37TvEac
         ipQ5h2BOAkZ4e8NakwwGUDLAXdj5QL8xR9qoZ9zcE3kUpj5tv2qIP5NmMCHi2EXnqR7c
         HEvw==
X-Gm-Message-State: AC+VfDwE7zYmCT2LsDF5VP4wG+aV/+ghx1rZkvVpA8kVdzhq/Gr9dkYZ
	7fykmJuGQb5adwN3ZnkAov8=
X-Google-Smtp-Source: ACHHUZ7CWBZ6AIqKGON6e5SVNWHsdlu2ev8jEfnQTjX2iKJx0xlD6mN5E4pwrmT8Gnny3jsX2/ZU/Q==
X-Received: by 2002:a92:7303:0:b0:326:61cb:5f3b with SMTP id o3-20020a927303000000b0032661cb5f3bmr7696482ilc.3.1682960161640;
        Mon, 01 May 2023 09:56:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c265:0:b0:328:fee0:eb77 with SMTP id h5-20020a92c265000000b00328fee0eb77ls3408517ild.5.-pod-prod-gmail;
 Mon, 01 May 2023 09:56:01 -0700 (PDT)
X-Received: by 2002:a05:6e02:783:b0:328:5525:26b5 with SMTP id q3-20020a056e02078300b00328552526b5mr9437607ils.10.1682960161172;
        Mon, 01 May 2023 09:56:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960161; cv=none;
        d=google.com; s=arc-20160816;
        b=pFdmSef+SF0epSNvomgOYt8DWd/MGqmjE6jbs5V5hx92xaQY9f/rrc4coRY98C0Jej
         wQedj4mIob+87grosiq0RVzmGa4sVLtw0Sn3dEEWpiGeRO8j5Iq5f6T4qbNyUWG5PSYk
         y/PRUHj0eZ5P+w9hYdIMlFEYgZtkdbcEM6bAoexaXSL0KASCbL8k2/HpGhju9LwmLx46
         yGCLqrQHweg85hnk7mzJgwp4Siyhs5eeJFKHQLha/GeN8GfTEaC4Si1hj/ADVppDsjDS
         YJDSm6vO9trfybsUr+M0/oak3/FBFd15reeYxQWml00yvR3dmEcqcGedarqQb7JOCbcl
         8iOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3JQAU/dBFDp2j3prOKpx9pu61B2aRzHMn5ijo1mj0wk=;
        b=VaWmIb5dOnB6jMvsPhKTmvRXrNR1t2/FX1fOrgYHfVLtEWSeWzc+GTKr7+eBM4rxwD
         er4gkBLbUYuicRASDK4EfxcdsYu2o2+vAQ2HORHck7pyDqeY+71JV5RHM3FaQkH6VNR5
         wGMxghfp9j+iZgV9tynK/H6gkBcQoLiu8Gv2g3+zNqe7XeV45EUxc6lUJg04X+Ht623M
         EpwyOvz37ZO18CrIZtNEX0yjO6+hb6g2m0DGeD9OMaHQnfGTVeJ9BzBBndC0ZVWirZvD
         m6SDb8CpFAqtg8K3BscIDscUaBxSKM5qw2jdClnD3ByNI0xlOrM7p7gSsu+jRt/n6Pw4
         wz6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Nr4QXyj/";
       spf=pass (google.com: domain of 3io9pzaykcwcxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3IO9PZAYKCWcXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id d11-20020a056e021c4b00b00330a4a4c129si398447ilg.4.2023.05.01.09.56.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3io9pzaykcwcxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-b9a8023ccf1so5356916276.2
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:01 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:2484:0:b0:b95:e649:34b6 with SMTP id
 k126-20020a252484000000b00b95e64934b6mr8454589ybk.1.1682960160542; Mon, 01
 May 2023 09:56:00 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:33 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-24-surenb@google.com>
Subject: [PATCH 23/40] lib: add codetag reference into slabobj_ext
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
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="Nr4QXyj/";       spf=pass
 (google.com: domain of 3io9pzaykcwcxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3IO9PZAYKCWcXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
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

To store code tag for every slab object, a codetag reference is embedded
into slabobj_ext when CONFIG_MEM_ALLOC_PROFILING=y.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/memcontrol.h | 5 +++++
 lib/Kconfig.debug          | 1 +
 mm/slab.h                  | 4 ++++
 3 files changed, 10 insertions(+)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 5e2da63c525f..c7f21b15b540 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -1626,7 +1626,12 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
  * if MEMCG_DATA_OBJEXTS is set.
  */
 struct slabobj_ext {
+#ifdef CONFIG_MEMCG_KMEM
 	struct obj_cgroup *objcg;
+#endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	union codetag_ref ref;
+#endif
 } __aligned(8);
 
 static inline void __inc_lruvec_kmem_state(void *p, enum node_stat_item idx)
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index d3aa5ee0bf0d..4157c2251b07 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -968,6 +968,7 @@ config MEM_ALLOC_PROFILING
 	select CODE_TAGGING
 	select LAZY_PERCPU_COUNTER
 	select PAGE_EXTENSION
+	select SLAB_OBJ_EXT
 	help
 	  Track allocation source code and record total allocation size
 	  initiated at that code location. The mechanism can be used to track
diff --git a/mm/slab.h b/mm/slab.h
index bec202bdcfb8..f953e7c81e98 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -418,6 +418,10 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 
 static inline bool need_slab_obj_ext(void)
 {
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	if (mem_alloc_profiling_enabled())
+		return true;
+#endif
 	/*
 	 * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditionally
 	 * inside memcg_slab_post_alloc_hook. No other users for now.
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-24-surenb%40google.com.
