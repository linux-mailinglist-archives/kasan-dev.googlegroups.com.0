Return-Path: <kasan-dev+bncBC7OD3FKWUERB67JUKXQMGQE5WWGLXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 824AD873E76
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:01 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1dd129acd2asf67855ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749500; cv=pass;
        d=google.com; s=arc-20160816;
        b=cm7Cxa8TfQmeJc/869mU+gdXoc7sFTKiyklHscPT+f8W4CbOrk1ugWR9SQ7aewTt/g
         2jOJfRxjiYsPpM3gE9s1C3u5unJS1rC9zQJSWxKRq2b+AtUZPAeZnDcqeGJE8wQoJLsH
         ViOQGgfkOA72cQ+zR9TldteANhUhBzJj6IJxIoG4nqhwKIEb0OGsSMaXV481goobX4k3
         81mGxRiEGp6TgtgOyuScxCZboFfDVgxiQceWqPQjgHqQvyqkXFOws8N81T3rhY/KwlN8
         /SECXOP6pKzCcfrBM2JEi7xqzH7utygmGZJQNtH7/p4izT3vtc//wzgy3ih4kTdUh81U
         vKsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=AdhnZnEdnbbarVf4whrGvCbwW+thm3wLlDmvyeMhKFA=;
        fh=ZRw10NTCuuHS0yyZT4jZ833t0N0Cr5kfrWg+aDeV1WM=;
        b=RfNUftPH934JPXvG5QYz87Yl1uhrddHzMMFLIR68TwFrcNFmHMqv7OHwe0/HQ5GbD+
         usgdCrO4TE0ZT9CO0knHYi98JsTzmMYod5ILX5afWIj7Q56VK3nkRDfuLKzHyb1npoLO
         xiB/vpuzGXrZIe5EI5rU/1QmaQsX2E3j4ZL94O50XwfLcQR63m14pOpFyuUU04Ly8vJV
         hmQVQZzMsXRU78oLbq8WCx+Tg/i/YH2ORzOaOqR84fmQBwRhdRXnX0u+gadBpDUX3jR5
         Q4JkrV9unKhRuAirio6goaaEp130O+3xTo7K31RyygC1EQnNsstQcdoGxhCiPG2ggDa+
         MUZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v6KEcDS8;
       spf=pass (google.com: domain of 3-btozqykctwqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-bToZQYKCTwqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749500; x=1710354300; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AdhnZnEdnbbarVf4whrGvCbwW+thm3wLlDmvyeMhKFA=;
        b=cfnLx123+rIFMg5YJjGmChw6C46on9uedsspKELElAUhYduqgUOrC6IusiwVZtF1Ml
         YWqHeVBfr+TeRHp7znBS6yctpbQQjAFRgo/mSSytD14e++R3Ckza8uAqgbvI2CvzCtA4
         FkCtamJ08ysE29OVSGifIBLYWrI6AOqCezjY4dftmaULs86j1LK/CXLCd0dRZKZfpfG9
         V47WFX/oFvHL0+UCYkRVpCZxOGQv2MPqgrNjhBi6tvAHrHGw+biQlf/r3eBItUuiHV+/
         YFVWpC2AzEW4VnLyyiAXfPAn48kL8aJVoxkSLK5scTULwHrR2I4cf8OEhv6ipoc4Y8Nx
         ACwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749500; x=1710354300;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AdhnZnEdnbbarVf4whrGvCbwW+thm3wLlDmvyeMhKFA=;
        b=cz3VKM5eKzPUasPxQBgcUYe7ILMK7ooX9v8LhmueVErDl+XvqStvsNR5RUCPDQJfB4
         A8jfHoYT/V5slmPk86riEKXXQ9KziBzTdb8kBAnAIa0xGfMpOBbL6NuZyjhB640yQisI
         Xh6TigSpeUmCctAfn/mvCXtx20S26ClWfQfXQAJVrGCX9DdOxYRTLC6rk8ZajTNpIaYh
         rWaYKlT/tX7c8UO9WplG3ZOj+QNcO6ApuH8EySP9bTFT9+Vl5M1F7K1kshCrrkDc9wfw
         wBpc6gLy7b49Ce73LaJ8XYUMYHzFw4Qo0QRARcnUigQcBn1soF6uPSt/9KxVf7rT07mb
         66ww==
X-Forwarded-Encrypted: i=2; AJvYcCW4EblnZ0YR41lewp/wMC3BcSBalZ98017trEg9PaFWYde2duhiA7W3sEBiJwmT3VsdotQ244g6gLGe/BxCY8065BuNAVUzxg==
X-Gm-Message-State: AOJu0Yzvyva+hQSGTfnrhILrTgvYWJ58/pDGu7Lj2IPD1Tjko0/WeHnZ
	X7RcI0ME8gCr1ALtbSE9HwHDgjI6KxwPRfowMo67QanxuLhcJk/B
X-Google-Smtp-Source: AGHT+IGamVHr542jODhjtx7/kBvEGF+ua0ERoh0EBySCgbMimGmDPoE7Hysy3YctuPV2TqqyM7/vOA==
X-Received: by 2002:a17:902:650e:b0:1dc:c8b8:3c9b with SMTP id b14-20020a170902650e00b001dcc8b83c9bmr5639728plk.12.1709749500012;
        Wed, 06 Mar 2024 10:25:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce84:b0:1db:3ede:8aa7 with SMTP id
 f4-20020a170902ce8400b001db3ede8aa7ls67313plg.1.-pod-prod-01-us; Wed, 06 Mar
 2024 10:24:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVmw3dKRzeyI4ZW5h1xuKns9RBFDfI+Fgb0b9YoJP+WZ3NN8JNDzz3Z5RXSFbJZSOMZ2aGJOM0Ra2E/gCdZfbRjQsPv0cNMYfca0Q==
X-Received: by 2002:a17:903:192:b0:1db:4746:5fdd with SMTP id z18-20020a170903019200b001db47465fddmr7642613plg.43.1709749498729;
        Wed, 06 Mar 2024 10:24:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749498; cv=none;
        d=google.com; s=arc-20160816;
        b=VpsPnC9DCW2ACX1WCbQ0D3cjPkv8yE1gats1Xr+AHGNX5lReiIG9gZQQADHG2yBrv4
         3I6M8FbmS+VW68yKjg89YmTvNwwQWwb2lhFjBmFicTiDN3RKNSvQ51hlmCxHjbl3Qe2r
         3o0q09l1K2I01cTZgRRMzUez4p3PVDfdhJ/5PSobvdfz5NfxnNB2aJsSMYpNJi4T4YVl
         VHaIZS6Di3jNILrJ4vDcLzZJXRbrJW53HZ4UhLn/2wnQCYoosQE2hH94JjJBZJwwEb9t
         cnnkAjWNYdL/I50Lo/82mftRcnTYBCiekH29Sar4boe2Yxfi61XzawKgZ/H3ZwRYy6j7
         N4Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=6JMcGt6EYvTroht8h7kHXMFTQxZQYrHbNcyZWU/g6ow=;
        fh=IayjIzPTTiKcCPSKzjZBJZnES05615DTutPTEnqOA/U=;
        b=Vy73mWvy35llZ58G804H1eSIZvgKIl36uqCX0VpzU17586Ofm7lZNGih8o7ZFfWP7O
         8vaN6dYb3SHLRqJWSvgZ7DnmvndqCRwTutADeNfl7iZswoYCWlPs5p4vHVQEgTYAbz7Z
         nebRr4dGJX6o+X9dNX/qvPCMYVI2ivQU5J7ndj+8iz8k9FLVTQDcNnnm5ejhHW0r5UtK
         hW/SbejxZ7oCzn8fCGu6tEWGM4MYCD7pOmPGews+I4Qj45kc/SLubehjAHMgeVjN8WG1
         HaLx8ni+BRMiAgB8+0jUm7MOzu2i/W49I5Wi+S5pkVWWUFo4JjlF4iFogsRIbDSp+Lef
         ggpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v6KEcDS8;
       spf=pass (google.com: domain of 3-btozqykctwqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-bToZQYKCTwqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 13-20020a170902c14d00b001d92eb54a56si784132plj.12.2024.03.06.10.24.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:24:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-btozqykctwqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-609d95434daso385007b3.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:24:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXreHqcgcBYBBChXdkgTPWh/r1TViMMQein3sD5Oufr06IqBJQzUU90mr8WbnN848vtlBbxYaWPgZlWsZJuzFdZNNWtTrgq5tCEvA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:722:b0:dcd:875:4c40 with SMTP id
 l2-20020a056902072200b00dcd08754c40mr4233991ybt.10.1709749497766; Wed, 06 Mar
 2024 10:24:57 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:04 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-7-surenb@google.com>
Subject: [PATCH v5 06/37] mm: introduce slabobj_ext to support slab object extensions
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
 header.i=@google.com header.s=20230601 header.b=v6KEcDS8;       spf=pass
 (google.com: domain of 3-btozqykctwqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-bToZQYKCTwqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
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
---
 include/linux/memcontrol.h |  20 ++++---
 include/linux/mm_types.h   |   4 +-
 init/Kconfig               |   4 ++
 mm/kfence/core.c           |  14 ++---
 mm/kfence/kfence.h         |   4 +-
 mm/memcontrol.c            |  56 +++-----------------
 mm/page_owner.c            |   2 +-
 mm/slab.h                  |  52 +++++++++---------
 mm/slub.c                  | 106 ++++++++++++++++++++++++++++---------
 9 files changed, 145 insertions(+), 117 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 394fd0a887ae..9a731523000d 100644
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
 
@@ -1632,6 +1632,14 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
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
index bee58f7468c3..d160ab591308 100644
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
index 138bcfa18234..f99c63d5e9f2 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -2980,13 +2980,6 @@ void mem_cgroup_commit_charge(struct folio *folio, struct mem_cgroup *memcg)
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
@@ -3006,62 +2999,27 @@ static inline void mod_objcg_mlstate(struct obj_cgroup *objcg,
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
@@ -3069,7 +3027,7 @@ struct mem_cgroup *mem_cgroup_from_obj_folio(struct folio *folio, void *p)
 	/*
 	 * folio_memcg_check() is used here, because in theory we can encounter
 	 * a folio where the slab flag has been cleared already, but
-	 * slab->memcg_data has not been freed yet
+	 * slab->obj_exts has not been freed yet
 	 * folio_memcg_check() will guarantee that a proper memory
 	 * cgroup pointer or NULL will be returned.
 	 */
diff --git a/mm/page_owner.c b/mm/page_owner.c
index 033e349f6479..d21d00a04e98 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -469,7 +469,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
 	if (!memcg_data)
 		goto out_unlock;
 
-	if (memcg_data & MEMCG_DATA_OBJCGS)
+	if (memcg_data & MEMCG_DATA_OBJEXTS)
 		ret += scnprintf(kbuf + ret, count - ret,
 				"Slab cache page\n");
 
diff --git a/mm/slab.h b/mm/slab.h
index 54deeb0428c6..0e61a5834c5f 100644
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
@@ -541,42 +541,44 @@ static inline bool kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t fla
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
index 0f3369f6188b..6ab9f8f38ac5 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1881,13 +1881,78 @@ static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
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
@@ -1966,15 +2031,15 @@ static void __memcg_slab_post_alloc_hook(struct kmem_cache *s,
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
@@ -1995,18 +2060,18 @@ void memcg_slab_post_alloc_hook(struct kmem_cache *s, struct obj_cgroup *objcg,
 
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
@@ -2018,16 +2083,16 @@ static __fastpath_inline
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
@@ -2038,15 +2103,6 @@ void memcg_slab_alloc_error_hook(struct kmem_cache *s, int objects,
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
@@ -2314,7 +2370,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
 					 struct kmem_cache *s, gfp_t gfp)
 {
 	if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
-		memcg_alloc_slab_cgroups(slab, s, gfp, true);
+		alloc_slab_obj_exts(slab, s, gfp, true);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
 			    PAGE_SIZE << order);
@@ -2324,7 +2380,7 @@ static __always_inline void unaccount_slab(struct slab *slab, int order,
 					   struct kmem_cache *s)
 {
 	if (memcg_kmem_online())
-		memcg_free_slab_cgroups(slab);
+		free_slab_obj_exts(slab);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
 			    -(PAGE_SIZE << order));
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-7-surenb%40google.com.
