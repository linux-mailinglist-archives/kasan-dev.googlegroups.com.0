Return-Path: <kasan-dev+bncBC7OD3FKWUERBOXKUKXQMGQEZ6KXTMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B84E873EAA
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:26:04 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-7c49c867608sf5464039f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:26:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749563; cv=pass;
        d=google.com; s=arc-20160816;
        b=LKGPYyV6ObKCvlO/qmS3QPpy8rzlVpn9MAqs3PG/zMhqqBcD41dunoY1QyrJTJpB0y
         x6WJcsCRr+kq+NepjN+if32HRBU5T4pGZNfSvnxyqTUAJ3sB/dXYXDLz4S4fUmlXOlrS
         njKXhc3WjYlakGtqdN/5Y83nQzo7iYeaDtam/ItC2MZwbXh/FRDlyMLKnBET2WcQI/Ey
         AyCXWqGfiZeN3bGBgEuqeXe62NZWRgEYmTbFF2edK1lhOm8Glv+DrofNM7lYrlTUjYNV
         mRrnbRgj+ouXeWEk/6njVA7345Prgy98WDI1G/q3Eed1i3aAVapDnXPHNgAsInHsuwEJ
         TxCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZmtFBdVM5lINIEDVGOMpNCYKDyyoFvDedpLT5rz3fbY=;
        fh=e9+XC/Queb7wMRkbrppFPvzeBrCDMeJiq3GIeDgxqf4=;
        b=rCT44LobKbchUbX7hZKCXz1ej0xZ2rA/OOiBwtq0J9uuNHANrqTxwxkzhTcnjWW/PZ
         t2pGn/kT3GSY80r27O0Zpq2gSyL8/iIaN0KwhHTWPXM2YBpq0Yjz1JOoezKQdtHY1+FQ
         HpLE31WcgAMMre8Faf7G0fDYsYVdRRXEQP2q93mF2EA3jrGyMULqqmt4AvTkReulvzs0
         fGR8S+Zuzdh0sbndydXdeYjmMPW9bx0v6mgCBhjYxu5THzJkGhWhwQ1+q+O4HWg3EI/s
         dPwzYkZk7tTBj5JLG98a+KSTKzMUiS5tZBjMqD81+6GM8BC2vK3o5izgvulVfZgllOMu
         OgMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pdfO5fGy;
       spf=pass (google.com: domain of 3n7xozqykcxoqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3N7XoZQYKCXoqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749563; x=1710354363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZmtFBdVM5lINIEDVGOMpNCYKDyyoFvDedpLT5rz3fbY=;
        b=Wg0O1nvIsI4ssYOFyYIMJZ54jU14qvwHnrW2p5rTuL7bDsZeDeq0H0U/VpyHLyIqrw
         sTKp4iYD7PWD0DIY4uBa8CM7XtoEmtSZBun979y+XV0AAXdR3VdXEavjc6VOrtNKAaiS
         IJJWSQE86tNr/MB2iHuL8pOC1G72nwts9Wi10qAWzF1u2+4qrVS/VIYZfXhNpqUJsyq9
         rpQP8hawy51hOWlvQNyhXB8nfQPS0Wegi4Fi1jRl8mMr9JYhfvhdVJD+4q6k94SNurKj
         WmwDLsAVp53qrqkJqX6W8wvfgrL52JOqyeuGca8jQmzdSuDyhHmoBegVJUgSRLrP3EtV
         S7yQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749563; x=1710354363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZmtFBdVM5lINIEDVGOMpNCYKDyyoFvDedpLT5rz3fbY=;
        b=CQTvYXpD8Hyl8BA19SkVotKXOOxrM7n723A1L1F96ZssJMOD5a3lrnihfPB+gzyn4y
         ACWCpnu8qSTLkcOUQzxE4vrqcmgcw4S66HZD+8SGuo6cpQFghrEyXI3FZTD/kftPQ72T
         cLHAUl0MSDAcZKcrNRP26tCqYouX6obXm5hTQ3jNG1pKz9XtrmDnhZubiwGPVJC7Q0bE
         XePk64xseJfViEueMbYsA4vc2YAI1lFCRJ4bVu3uepo1kuD5OHq3WQJtpCFtlghYL3ZM
         5uFvrAw37LQFmkNouE+hCMWp0lA1AGkguw6SKVlA7eel0RoSlhZrqVQd2C252fNdbfrM
         keFA==
X-Forwarded-Encrypted: i=2; AJvYcCUFGYjposqT4dA+3n8Cm+2TvMB94yfpL9Cye2m3JYRm+yp4NajpQGeCFnh7zpOEmEC5ZmomwUNE98q6X9AAenQQgeaBsI5nWw==
X-Gm-Message-State: AOJu0YyBrfuCWEt4258g4YSZd0EZ6FFqQZKZ5Rho6CCLleBIANf5X7WE
	AnO17eAaRm+fARIwsRStg6F2bnlD5zAgVDj/3XK9pxELtDMLw92M
X-Google-Smtp-Source: AGHT+IFhERM42C2BpDdQU/drEHcj1OXOxKH89RhhrnMt0B8HCaK/aJcZWv3tZbtOUo/NQAi7u9ZhiQ==
X-Received: by 2002:a05:6e02:1242:b0:365:fe9f:8129 with SMTP id j2-20020a056e02124200b00365fe9f8129mr4338829ilq.13.1709749563057;
        Wed, 06 Mar 2024 10:26:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1524:b0:365:a699:418 with SMTP id
 i4-20020a056e02152400b00365a6990418ls83940ilu.2.-pod-prod-04-us; Wed, 06 Mar
 2024 10:26:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXpdC+T/eTVTkah6G3C9PSDzXAlPlGmWSZelijJgdDlyVRGRf9jzcTDdwOAgc0pwG8ocqp3Q01O7fFCsJvmeWMmn7BA37zkGweqBQ==
X-Received: by 2002:a6b:5909:0:b0:7c8:7d1f:9633 with SMTP id n9-20020a6b5909000000b007c87d1f9633mr1788608iob.3.1709749560502;
        Wed, 06 Mar 2024 10:26:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749560; cv=none;
        d=google.com; s=arc-20160816;
        b=O1QDaokQBwH2C8Xbo7YHy0iHg5SOsmpuGdkP5NvfFzrEEt1cXhIy4UoZXOdM9h/SY4
         Wp90JH1GrOoYR50lpvHNzjM3u9Av11gQxniqvnW85OqorC7dkjnG5xO++SIDpNvVwaAe
         kPB21SEHLxuHBo1uvPGO38/hL96hKPm9DC5mhJIh0BpBTYjNkXtAQoq86ZgBgaISsyYN
         9MPBeKBU6s5YeBqBLZLtWMhB+piHEr/IAR6W9hD7wIH+46tdEpIdAuBxNRt982yW8wVi
         6XNFrDPyG2AyzErWekcHpXWHHrHjEF00XdByo2XC9qjAEUlm3ZoyU6N9bKNLz16X3ZmP
         +2oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=j6JoLMysN5flVa9c5yM3pdaz8HR3taJXen1pd2wjpNc=;
        fh=619BW5+QdOLLgPTKfLbgOrOzBrH9lQEW/3qNDOCUmws=;
        b=w+8ZdId2mUuJTtQzI6KAdNlfADj3RquAYrviIpFJrxP+rBV6zAKJ1K2ToYkUqQ2FMV
         F9qJHd7nM+uHpLnzmSgoAJXHqCtO5XD1qE2phEWdHAY8Ks6UnMeVnKLQ94zgxDJolwb1
         BAKbAPWDo5O4y8WFUcms51+jM3tsi6LD+keYo8LOa/Ov381He8d63G9h07v5NjPf47Gm
         5jGwHtmw+OIBW39VNoJpJFIvsV5uAuvWl8TBXXVVxIFkIZec9c5cBTvTVz5jy9EeaBWK
         riwLZhcdBczQEjKeIIyYbZQC8jCcWagOxoI6OHdg2ZgGeOh8vc79LAgUCLLv3HWwWZUW
         zVwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pdfO5fGy;
       spf=pass (google.com: domain of 3n7xozqykcxoqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3N7XoZQYKCXoqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id e27-20020a056638021b00b004767a24d021si74277jaq.2.2024.03.06.10.26.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:26:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3n7xozqykcxoqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-608d6ffc64eso1784077b3.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:26:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXoYSUlTpy+fRmA/mUwsg1/YWHYIUWkw0cs6e5tu+HyF2PQ3LtAgDpth/OEgFgtHSaMcAA5A9cGVw/XdbI+9GDGhNqtAd4IekRhrg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a81:ae60:0:b0:609:3c49:d77a with SMTP id
 g32-20020a81ae60000000b006093c49d77amr1209593ywk.5.1709749559768; Wed, 06 Mar
 2024 10:25:59 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:33 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-36-surenb@google.com>
Subject: [PATCH v5 35/37] codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark
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
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=pdfO5fGy;       spf=pass
 (google.com: domain of 3n7xozqykcxoqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3N7XoZQYKCXoqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
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
index 33cdb995751e..3dfb69f97c67 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -366,8 +366,10 @@ enum page_memcg_data_flags {
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
index 4a396e1315ae..d85fbf9019fa 100644
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
 
@@ -1919,29 +1943,37 @@ static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-36-surenb%40google.com.
