Return-Path: <kasan-dev+bncBC7OD3FKWUERBF4W36UQMGQEVUZIWDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 31B0D7D5287
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:48:08 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-41cd5077ffesf1511901cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:48:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155287; cv=pass;
        d=google.com; s=arc-20160816;
        b=h5+2ZVbUps0bpavAEMYl4Fy9WxmwA+PAwU/ykOH0v8RSmLKbh6DWALKfGE3pnSCYNU
         n3IILlUKykeNQBKVuUot4WNzz1/eGACgdzT3Da1VXS0BJxGNKFCwtkUsNt8rD599UJOh
         87SRnqboP3VQmtLFGMwLz47/WSVAmK/QekGRIIQH2SUQ7ItmUpC1PtomTqAihWXSWd4x
         S/7nHedS7GX9uXuDl7/bLu7EdhaFFMX4HqalxmsdQkn+nhibwXs54ufzVkMdlExY9Bdg
         EiG9xIGYBvUv7ENdBUyt89N5aq7PDny1OLyp+G5mMgUlhQb5HYVuE2kF7YTuAFP6W7et
         lqRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6dxCCCTg8w3O+abR0vaWjPvocQ6E3MmZLXnL7YIqWYk=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=A69xlKUylES4yf9fHNw+u0k4AM1muVUoEb2t3YKyzwR6XmcrkgRb0wLT+VEJnAu1/V
         gfFzIIGAOFndGW9H2oyS4KaAvq4+2qJOuxaujAff8tI/mhFQphkEoz7WKnCZG/N6MWPj
         6vKzRmRaKSBOe/hU05VHrZRdHOTih9Ac7Ereao/ThzNt614Z3g7qtSGcJctusQDVvpGm
         R83x6M32G0lGGUS1v/d+WIV9RJm7MyPbvw9BTTIspP8Y9fJyb8kMpxtJX79Ci5ecQp1P
         iuaoIVu3jpSwkXJvL6+3E5Gltmwj/cNrChc2L9zbb8VuX75czvPrHj66wYB1ux4iQZKR
         uohQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Z9HkA1sg;
       spf=pass (google.com: domain of 3fss3zqykcbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Fss3ZQYKCbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155287; x=1698760087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6dxCCCTg8w3O+abR0vaWjPvocQ6E3MmZLXnL7YIqWYk=;
        b=rq4YdbI8g4yK7+syNKg1X/R+VPSLQNfOfjl1F8NdjP37OFhomOJNE1QYJQQugFsL7W
         oSL+EHcDqRkXmuSPSeDNCk7/AI5NIICR78SJ6dhrkQYp2ZK9EZKij2AHIhcM41xlgxpd
         JNRLJ0SzGd4wcqfqULD2+1bQZf61kwyaXUHcPaukTdomthuUhvHTdP6WuNrQw7SnQbC+
         ohZD20zu6XoKGeQgfkQIA7cVJ4UAymE4wrhlbXQCEc+UILFHecJrbQiILK2ZB1yFJTBT
         vOAHcjkSyZjqMQRo9XeN/Q0Ze9Ikh+AMqspTe12E5dSRVbmV5wcLFkN3+sTvvWzNdQ1G
         Gm4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155287; x=1698760087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6dxCCCTg8w3O+abR0vaWjPvocQ6E3MmZLXnL7YIqWYk=;
        b=ipGDQo5Z6vYZI7+eMqGfeh29lArOgBGKgaokRp8cIgPBxfwqEqg6+sZ95iQgVjtG89
         GaaHm7HpytpZkKPCxHoPxZEWL3h1Nx63u4ADR+mebYOSurtIafRpLeV1yZvspukkIde9
         S/tXcsA8C5DSDhTq4XB5e5arU3+T5ICSBgdDTTogUqmHAjN514RSoySH1zS5+6f1ILfJ
         mLc8KVdrtyEDeL8WpbbVAtTqtabXV0FNmHMrrQd6Bl6B86aoyR58ljWevgV7LdPetruA
         7GHzh6Msk6kobJ7dXUg9p8HCHxG7dhvXn2Cw3W/DhBRaE2zi5+iUjJz1rv0U9EjKquN2
         A2Zw==
X-Gm-Message-State: AOJu0YxerBl38rqS6bDxL57d4BhguaaGf2ryVFqZ8UTkwQplMr7UbNku
	DeWA3os91vZdrV8h4Uf8He0=
X-Google-Smtp-Source: AGHT+IEBZstuna4KnolYNUCAPBPsMNv7AbJrtuo2mEXqr/VNwR0Pm0RmfukdrNqqtwTFS11s27gu3A==
X-Received: by 2002:ac8:4cdb:0:b0:403:ac9c:ac2f with SMTP id l27-20020ac84cdb000000b00403ac9cac2fmr225844qtv.17.1698155287231;
        Tue, 24 Oct 2023 06:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4188:b0:41b:5e46:aa61 with SMTP id
 cd8-20020a05622a418800b0041b5e46aa61ls400491qtb.1.-pod-prod-02-us; Tue, 24
 Oct 2023 06:48:06 -0700 (PDT)
X-Received: by 2002:a05:622a:44a:b0:41b:b7fc:bca9 with SMTP id o10-20020a05622a044a00b0041bb7fcbca9mr14061282qtx.45.1698155286598;
        Tue, 24 Oct 2023 06:48:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155286; cv=none;
        d=google.com; s=arc-20160816;
        b=vRMxyh1x6g+duTY2KKw++uH0FaB5Pr/Tq8KXD1Oz0EnQ9K6KXPypPRB9RjLmBpoVdd
         QrtI81qIP2PdqBaxzD9VQ25CtuczA+9h4/on/ovWG2ukWuyhh4MNwF8kDpib8ZxSIm60
         oLvKAFzQpAvNZ5xtEyskdsjj5QIPXmKZF9b8Iy70JZek4DjFToZPHtEUG+79Z6Ty0Ox3
         0dEsBN5D0cXjoIRhgZNE94QkexSH+4+caoy8LLR/GMGUP3/vYPtbZeBbbfw7+GvYjVXn
         KjuD/yRRNYJL6vgrBV5pVCKk0rp0uypiRaapFQmSgjlJI+7eLwJe3gdRVNMSiMpgTOTY
         eLCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nwLU1aU2LNAtecsch6dr14rd1yTTpsfUN6nYD0uWJEE=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=f4w85ZMRMWKidEt70zTduaJpS3zQx+ld1gtucXtQmrCgqYrIRuetgZ08Gkg3jedCwJ
         MxUiOfqgtYtLW+yG9PjgdHNdU4mZgpBwMR4U7IQslLhxvuaLlFrm+wKBP2HECNThNxNj
         boDRlrlI31QVY31gWTKBOy6sllNuc57V7zKegnUlqsoUTYvRHiYhhP0KPgPdedvan2Wx
         uYPFTaRWHO9Sd/NX6fLKOj4OtstJJiwD0Pzkie7e8VK5harM+ONR1matgyEYg3vr/Z5v
         R7LgR9VYAA+CxniyjsGEJhrbxKgfkS/J058j41oCdaFuLuS4KmwV9Z+0JvoReKJs870i
         PPcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Z9HkA1sg;
       spf=pass (google.com: domain of 3fss3zqykcbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Fss3ZQYKCbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id j5-20020ac874c5000000b00417048548c7si826996qtr.2.2023.10.24.06.48.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:48:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fss3zqykcbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d9a39444700so5323375276.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:48:06 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:d244:0:b0:d9a:4cc1:b59a with SMTP id
 j65-20020a25d244000000b00d9a4cc1b59amr317326ybg.1.1698155286109; Tue, 24 Oct
 2023 06:48:06 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:35 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-39-surenb@google.com>
Subject: [PATCH v2 38/39] codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark
 failed slab_ext allocations
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
 header.i=@google.com header.s=20230601 header.b=Z9HkA1sg;       spf=pass
 (google.com: domain of 3fss3zqykcbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Fss3ZQYKCbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
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
 mm/slab.h                  | 25 +++++++++++++++++++++++++
 mm/slab_common.c           | 22 +++++++++++++++-------
 3 files changed, 43 insertions(+), 8 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 853a24b5f713..6b680ca424e3 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -363,8 +363,10 @@ enum page_memcg_data_flags {
 #endif /* CONFIG_MEMCG */
 
 enum objext_flags {
+	/* slabobj_ext vector failed to allocate */
+	OBJEXTS_ALLOC_FAIL = __FIRST_OBJEXT_FLAG,
 	/* the next bit after the last actual flag */
-	__NR_OBJEXTS_FLAGS  = __FIRST_OBJEXT_FLAG,
+	__NR_OBJEXTS_FLAGS  = (__FIRST_OBJEXT_FLAG << 1),
 };
 
 #define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
diff --git a/mm/slab.h b/mm/slab.h
index 45216bad34b8..1736268892e6 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -474,9 +474,34 @@ static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
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
+
 #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
 static inline void mark_objexts_empty(struct slabobj_ext *obj_exts) {}
+static inline void mark_failed_objexts_alloc(struct slab *slab) {}
+static inline void handle_failed_objexts_alloc(unsigned long obj_exts,
+			struct slabobj_ext *vec, unsigned int objects) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index db2cd7afc353..cea73314f919 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -218,29 +218,37 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-39-surenb%40google.com.
