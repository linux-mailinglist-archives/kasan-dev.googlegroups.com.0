Return-Path: <kasan-dev+bncBC7OD3FKWUERBFNE3GXAMGQEQH2NE3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9047485E7A0
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:42:14 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-6e427f6974dsf5195143a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:42:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544533; cv=pass;
        d=google.com; s=arc-20160816;
        b=rp1b8a+I29k9ULXOh/92HMuN/Am7jpO/TWWyi25jtUpnsQHfTPfXNTqenm6PrKtHV6
         dB5N5+5PXHF5O8CaqhDOaEFTiqilflGvu54OTLmcMviyg3WACmUfiEiNcflFRaelRRcH
         fQTILV8deeNtVKYu3Uqh0WpWG7gOIAqMJQh6an1/nYuW/l1J+yyKzMCmijzSJxhISWFu
         QaViQQQwZwSdre5SvdzBX9hc250VVtCsIEBh9M0TdOZY43tAXQKj558md8s1ZUnDb1Tj
         I1miP3XkrxkZJxDWwnn5BY4B7lAfGSRd2P9FZzvcmyLeH8s0aFOl3zcT4rypwFJZ4f2h
         Su+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2cySL+dM20dHzeOMHx6KDT3KL0gzXxtzY0KU2qZPpsQ=;
        fh=29tWRzeD8/Fx6PuzAhdWlq8uRR1bj88Fa6ZDluNi2Do=;
        b=khi6urBMC5aKSuRgl8i1PvtXRNgELyoJWUpyxOvVCD8QLJmD6oYkce6G3w6Tjpje7i
         U2/Yj1K+yfFqQvUd2JcbYfMO0moq6Cm1tCYsJLOthucmLnDSkvhOz3mD8tW6H2dxHxt6
         It/iYfnyrCNW7EeGGOs3MVKOV1SMOcnedmuVxR8ODpsP3yGanwBdDvU5veUAKW9DJw+P
         IFQnHasAjfV4aKOExYtG3GQTDB3WPZ1QhvUH/FiJSu/1G0GFE7vcFfEFKJtuuTbBzv/O
         rYu5smARBuMfP1BqGo1uomUMgbDJzci1cCyNKbBP6SD3dRtu0cuTfGVAcge+B2EiLMkU
         rtEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="ZoT/lLMo";
       spf=pass (google.com: domain of 3e1lwzqykcuy02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3E1LWZQYKCUY02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544533; x=1709149333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2cySL+dM20dHzeOMHx6KDT3KL0gzXxtzY0KU2qZPpsQ=;
        b=ntdgXLLJBzKRaYRTIj7EkbNdb+R6Vt7z1Q0xgpM/bsPHk5Edafzi5dr3uHC1y6ym81
         MOMCU0w7NvniwWrPL+Zj0I8mpOnI46uvoaTOdAsLi+tFtfkXTLoTzcf8VLkP0Fl6gYGO
         Zt3osf8Daa1BAnWkGchTUbbcN6Zbyd6mFoOiea/4Um8c2tfas2ILnbdbH+wZymGApGak
         qrGuKmfNGXTIXLTz8m7Vtbmoh9fn2oVCOG1pvjyCeUaZcb3CdLG4RE1shsWUnwdbCzfn
         xWyd2dCoXkLfeN2Je/yZoTS1ACg8gu/FBDaKJ1jRmbeHTNtK8rsmzs/jPmqREiGUYpLf
         uIAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544533; x=1709149333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2cySL+dM20dHzeOMHx6KDT3KL0gzXxtzY0KU2qZPpsQ=;
        b=PPJW9EZyMnVCbJhpWw2YuomjK3YXWAq+6KBsiREN+O5HlLgDdsXbP70yQw51NfEsFB
         TS66YLf47yJ4J5lilpm5X3v4lPh4sXN1FvnhiIel2PlhttyBQM4lTmKvHy48jC4UN2Y9
         TLM8JSd35ug/Ishza8tNzqWR493FIszH6wfA6y6Ap+sEDRTAyBgol2iYPy7/ISAmaiGc
         sZ9rSleJS1arqeLa+F9uXHjKTLf+EzkrOSqj7Dke2DTuWdK5XF8/df27ZWghIeP542E6
         dnn8fuU/MrjD1X1uhq3LnPWqnoz6+cSMUnClhLEHUq0FI2bPVMwxrck8MmskSQ3dh5Hq
         5c9Q==
X-Forwarded-Encrypted: i=2; AJvYcCWthSWT/KTa5zEu1jhpK9HDYVqtq3BG6F5pmdsLfsoRRnZAGGp4tipvqtU9V/STsywY7+B/pww6iPBorKUPMJOp3ndNK4qFYA==
X-Gm-Message-State: AOJu0YwuveDOLMOlpmqYvN0+R6tTF5h4qzFbea9ZQlmlGdtwVqXS5gzf
	U3C/TH5mr+jvGe+AfLEKFWGm8XD4oacjQsYY+CuV2FkEZoPWgT9wnI8=
X-Google-Smtp-Source: AGHT+IEQAORFpVCl5m0H7JYvkUd6oH8uzVEsblSVoziFnKcfG7b2TLtuU6LoDiMfUpRndyVj56+WNg==
X-Received: by 2002:a9d:7983:0:b0:6e2:f0f9:eb77 with SMTP id h3-20020a9d7983000000b006e2f0f9eb77mr19029649otm.12.1708544533309;
        Wed, 21 Feb 2024 11:42:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5bce:0:b0:68c:e237:af38 with SMTP id t14-20020ad45bce000000b0068ce237af38ls1599303qvt.0.-pod-prod-04-us;
 Wed, 21 Feb 2024 11:42:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU7ga/c9RJ7kbAxomt7oza1BYmI7U07vMM5uZIinCIWBBQagye73b09VQqp2rvyOC6Pco5CiXn8it2xLOFqtGksdfWvNptl+Y6tKg==
X-Received: by 2002:a67:f54a:0:b0:470:3ade:af52 with SMTP id z10-20020a67f54a000000b004703adeaf52mr10889437vsn.6.1708544532649;
        Wed, 21 Feb 2024 11:42:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544532; cv=none;
        d=google.com; s=arc-20160816;
        b=RPhpR+AJwR3XySutAQmsm5oNxo8MGizLwS1+MQSezSrzS8r/4hgjGfhJMg3Yc7rm1k
         tNaF2SISnU26SqJrMPTgnqtrBYAZ6Ijb3aMmzkdgkD5q4sgQYVncHv4xTGwAaMP3XG26
         4m13JXI+HDL4cTa21xmB3IzxQdy+wnVIb0cSpTH6KP3+aI85cTUu94zz68fnUOjgFK5B
         6Vj8o7aqgMZys5RXVXv0/J3yrXLtcKj2kC2mH4xbcX3hUknHaDlFlUkjZGLWiVY8Moj1
         B1ezD7l1XfHwQCZC8RjaqZEaW2D27SsJGakemwhGEKL6i2WfksLW2gYKLSPwGrpJ0SU6
         NDTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BN4n4r+pGIOuiPq9+HuwMZ/LVswbQsC+381oXCoHOQk=;
        fh=+4+jgFnATm5Xl3IsNLmmgifMfPBqX92NKOxM52LEzAI=;
        b=gDVrsEP2A2J1xk6SFriJnUPkwdQRhfQfNp4CGoA+PZX2eqxrU4O4tnnBu7xr1eRytE
         g6trchXQdYOe6MG8e80tnplRLUj1QsCqzXlXdEx6wIilLAuAeBcjoeHzzcQmwGKWwiFw
         ynAX5e03DBdjwq8ijb4CG0eA6N4AUAmCH9EJXE/NCdFiZUwqgPsOdD61QEmiruitI6/z
         4RnwfsiuV/nSHv4+cMd4DczHwr+PghvArHdta+0wkfn2d4LQGHwrj/tZghmesGKZbjLs
         jGHeUsvcym77XMO9NY71D8MOMSrckFy5xGbZMepDwfC0rxYXp2Re+/R4BYliLDF5c3FP
         XKZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="ZoT/lLMo";
       spf=pass (google.com: domain of 3e1lwzqykcuy02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3E1LWZQYKCUY02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id jg16-20020a056102181000b0046d2507c9a2si808712vsb.2.2024.02.21.11.42.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:42:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3e1lwzqykcuy02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc3645a6790so12826430276.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:42:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWpXFSEhOX6zzgAZEklGMuyqqCc2ZpQKrj7BputtyMB0ETHpPBMWmS3WP5DvdoG5E3JsAj5VszA+wOnjaa+cTLdCi7r4XfKb6K9UA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a25:ab6f:0:b0:dcb:b9d7:2760 with SMTP id
 u102-20020a25ab6f000000b00dcbb9d72760mr67613ybi.13.1708544531841; Wed, 21 Feb
 2024 11:42:11 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:47 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-35-surenb@google.com>
Subject: [PATCH v4 34/36] codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark
 failed slab_ext allocations
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
 header.i=@google.com header.s=20230601 header.b="ZoT/lLMo";       spf=pass
 (google.com: domain of 3e1lwzqykcuy02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3E1LWZQYKCUY02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com;
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

If slabobj_ext vector allocation for a slab object fails and later on it
succeeds for another object in the same slab, the slabobj_ext for the
original object will be NULL and will be flagged in case when
CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled.
Mark failed slabobj_ext vector allocations using a new objext_flags flag
stored in the lower bits of slab->obj_exts. When new allocation succeeds
it marks all tag references in the same slabobj_ext vector as empty to
avoid warnings implemented by CONFIG_MEM_ALLOC_PROFILING_DEBUG checks.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/memcontrol.h |  4 +++-
 mm/slub.c                  | 46 ++++++++++++++++++++++++++++++++------
 2 files changed, 42 insertions(+), 8 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 2b010316016c..f95241ca9052 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -365,8 +365,10 @@ enum page_memcg_data_flags {
 #endif /* CONFIG_MEMCG */
 
 enum objext_flags {
+	/* slabobj_ext vector failed to allocate */
+	OBJEXTS_ALLOC_FAIL = __FIRST_OBJEXT_FLAG,
 	/* the next bit after the last actual flag */
-	__NR_OBJEXTS_FLAGS  = __FIRST_OBJEXT_FLAG,
+	__NR_OBJEXTS_FLAGS  = (__FIRST_OBJEXT_FLAG << 1),
 };
 
 #define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
diff --git a/mm/slub.c b/mm/slub.c
index 3e41d45f9fa4..43d63747cad2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1901,9 +1901,33 @@ static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
 	}
 }
 
+static inline void mark_failed_objexts_alloc(struct slab *slab)
+{
+	slab->obj_exts = OBJEXTS_ALLOC_FAIL;
+}
+
+static inline void handle_failed_objexts_alloc(unsigned long obj_exts,
+			struct slabobj_ext *vec, unsigned int objects)
+{
+	/*
+	 * If vector previously failed to allocate then we have live
+	 * objects with no tag reference. Mark all references in this
+	 * vector as empty to avoid warnings later on.
+	 */
+	if (obj_exts & OBJEXTS_ALLOC_FAIL) {
+		unsigned int i;
+
+		for (i = 0; i < objects; i++)
+			set_codetag_empty(&vec[i].ref);
+	}
+}
+
 #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
 static inline void mark_objexts_empty(struct slabobj_ext *obj_exts) {}
+static inline void mark_failed_objexts_alloc(struct slab *slab) {}
+static inline void handle_failed_objexts_alloc(unsigned long obj_exts,
+			struct slabobj_ext *vec, unsigned int objects) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
@@ -1919,29 +1943,37 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 			gfp_t gfp, bool new_slab)
 {
 	unsigned int objects = objs_per_slab(s, slab);
-	unsigned long obj_exts;
-	void *vec;
+	unsigned long new_exts;
+	unsigned long old_exts;
+	struct slabobj_ext *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
 	/* Prevent recursive extension vector allocation */
 	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
-	if (!vec)
+	if (!vec) {
+		/* Mark vectors which failed to allocate */
+		if (new_slab)
+			mark_failed_objexts_alloc(slab);
+
 		return -ENOMEM;
+	}
 
-	obj_exts = (unsigned long)vec;
+	new_exts = (unsigned long)vec;
 #ifdef CONFIG_MEMCG
-	obj_exts |= MEMCG_DATA_OBJEXTS;
+	new_exts |= MEMCG_DATA_OBJEXTS;
 #endif
+	old_exts = slab->obj_exts;
+	handle_failed_objexts_alloc(old_exts, vec, objects);
 	if (new_slab) {
 		/*
 		 * If the slab is brand new and nobody can yet access its
 		 * obj_exts, no synchronization is required and obj_exts can
 		 * be simply assigned.
 		 */
-		slab->obj_exts = obj_exts;
-	} else if (cmpxchg(&slab->obj_exts, 0, obj_exts)) {
+		slab->obj_exts = new_exts;
+	} else if (cmpxchg(&slab->obj_exts, old_exts, new_exts) != old_exts) {
 		/*
 		 * If the slab is already in use, somebody can allocate and
 		 * assign slabobj_exts in parallel. In this case the existing
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-35-surenb%40google.com.
