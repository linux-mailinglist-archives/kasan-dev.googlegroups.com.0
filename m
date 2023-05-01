Return-Path: <kasan-dev+bncBC7OD3FKWUERBCO6X6RAMGQE2YHJW4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AA356F33CD
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:38 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-192712e375fsf3695552fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960137; cv=pass;
        d=google.com; s=arc-20160816;
        b=uy+E/eP6jMA9T+vbZQiLgjgdgYvLtf1Q817JuJAQR+wkM5QAC2uIxEBZOtJdW51Gpu
         F3QO6ca9fkokBIeUmKtox9ZKZ/0l/FwIjxjhuOA1Y4QLZhB1iQnfRGyQrY2Y98+Lzijq
         CGXEmBrb+bzegvW4L5F2a5LzDDQ++2hh6RDmp/PhFlwy0Ehij8FtuApyIuIlsyNItmCK
         uaLnEdJYlBri1HfrDSvV0zSF7RJCYYg1VLIsCAd4jT6ZvNu+cko5VFfTBWE0hvoc9pZY
         s5Qc7tlWzdrASiRR8j+lLJ0Brz9sHTOAhd34aN6KCRlolLn2K4+wYRQQWSnstTX3zsnu
         9Blg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=BAkUJz4r7//FKePX9HOzVAYqfP8eskVMRkUKt7w25HE=;
        b=oQPW7HQcNL1s1VSU0DI0RUhF2MQwDZYsyA6HdnBLIdCML7zgqAkkordwrbhT0Wd8Up
         vxliyBaQ4DHxKHTtDw0z+sMc45/0wI+uT3poD+n+w7lknmJPdmSPxKiFJaqDivir3Afc
         NsNLg2IILXDv/kaHuUjZz76RfKUvSqwYkinjzQgFasSB1OZRZRUB5zPRZ2So18ZoOstw
         CobW+b709g2QLBJHk1XWCNBgmxejudvSNL1m92I1pqj7159eK3VcfCDnXSbM6xCnIvEp
         ksCCQusrf3ZXkMSsPM+dEj1fwFc2ZMSy1sAS8OOyqDKROIRHQ34UboR2QBbyKCG01jIJ
         ew4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=lxWpRSi2;
       spf=pass (google.com: domain of 3b-9pzaykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3B-9PZAYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960137; x=1685552137;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BAkUJz4r7//FKePX9HOzVAYqfP8eskVMRkUKt7w25HE=;
        b=jihQVfIJCwi/QQjC+Csghv/ihaKzJtIX+F+Smk7D4fORdsbpX+NZN29jmRpK0RxEnH
         7XWQLuZUPsZ4NrJxvt3ry6F8pWAEKwpPZxZ8u8xx/6vjvVo7ZMOmpppt1b1oaLgMH91N
         +BhTddRQ+zhKJAE2Io2log+lVY22KieXbPCK0rOP10r9otmV3zjIJlFgBSYSY5G2KcFI
         o9v+FcY2Qj6mdJXga6HeZw9NRT9qjkTsu3pZsKK3J4GKGp4muhB2cmF+HU1sSPK+M9eH
         A9E5oVzcQbdGkF3w1IQSV+wWT0aCHSLVncWf6WViH9fBWLMzdkfaND73qAsppiBgOUpI
         cihQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960137; x=1685552137;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BAkUJz4r7//FKePX9HOzVAYqfP8eskVMRkUKt7w25HE=;
        b=K3+RtpzibDpqIr6zybRemaO/DOYHGVaUz1lo43YTTwfS2Gmnb/0HYycQZ18L6gm/o2
         C3Dcu9H6P0xPnbsYOC7t4LtjLPVIK2qItXV9upNPiCZ039w1kLwzMrxkOBHwYEg5pqCa
         KesfVrMn7RunMYBpmop5cW3REXc0FMPUhrogp7cZjvfBkazBWsupF/Y1xKhRgrvlyQT2
         cvw6iLVJjN5MO9i23fpXKIjQppWn3wMASnC59iVOUbPPl9jiGF74CERY2cov1mJNbto0
         ufy6PnSHDQHIS87Ss8bRxjRkpdGjcHXxArQojNmTKn5jfYDTFSQnQa75CSK3aiyTUG4r
         97ww==
X-Gm-Message-State: AC+VfDzYRYbGWBy7i9tBjI+On7IkYmxeY1coF06M4omVWLhAjyERzb+6
	BdZksS2shthgmmpTHTcUpvw=
X-Google-Smtp-Source: ACHHUZ5X3UHjC+w/muSsleMn5movsQ90xwwuvew+JYX1bll7ei6KRb5S4MJm5MzFccmIYw1sf8Qg7w==
X-Received: by 2002:a05:6808:22a2:b0:38e:8cf:b1d6 with SMTP id bo34-20020a05680822a200b0038e08cfb1d6mr6549680oib.3.1682960137320;
        Mon, 01 May 2023 09:55:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1414:b0:38c:6290:a68b with SMTP id
 w20-20020a056808141400b0038c6290a68bls2714582oiv.0.-pod-prod-gmail; Mon, 01
 May 2023 09:55:36 -0700 (PDT)
X-Received: by 2002:aca:180e:0:b0:38c:5c1e:48f5 with SMTP id h14-20020aca180e000000b0038c5c1e48f5mr6291669oih.2.1682960136726;
        Mon, 01 May 2023 09:55:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960136; cv=none;
        d=google.com; s=arc-20160816;
        b=QGZV/Vzuo7i3Y3MyjnMaWQniJKYLbCIzPE3BhxZ7h16LbLQhjD53fp5X9Q5Wm6cXkH
         yjYS3TY4uVLbJCvGwx0XxmaZsI3lg6B9R/e4x0Gc0aD+DF7Xgj9RsP0cEH8ACE3wb9iR
         BoHyVjCp8NK0yTwACqaE5miugRAujN50E4PqLIvkMIrRr7sXZUZZAYbU7J0H2I8uYPVC
         QfIGMWNJ/W+PIAwOMontCEJxfSg+Yg1XnWRvHSDb0lulwy+QY7tTjrvbOtNekYTodQ8d
         MSxSvY90vv/wCIuTkW5awqg0emIbVTMvyGomXZnNnAbtaR2dKwtjJvjwfdVAY8wiUrH3
         NctA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=xg9JlY7/fjt8XCrAgZEcEBdLHf1ezLwh/Q099RdQeBg=;
        b=e6rFQq9c+Cewv/XnKj667PZX0hJwJ+bxX94aR0qy1m6AEAmqFeMkMCwOmfFGyww+Gg
         rSsk8yTbzME8axo+O5zfx16A0i7eQrzufdaZVLv0QolDvhKegQ2HIkmUcIaN8RvH9HG/
         h4Qcv8N6FON134Auv5klLPzO4Xm7ZyEW/9pngjJTKvNEqGkUut2+GFd+zoF7KFdsWxqC
         CYIPBHdsVlb2IK489oJAYjXAhY9FpQUqCIKWIFoRdCNj4JKmFwICc3yEsho7YrOEDC1d
         kddsH32KFxRC/VPa39kANwSwZq23h2ZzZiJ3vX1mhedS7j9Tqf0JyilvXx4fi9jo6qXo
         398g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=lxWpRSi2;
       spf=pass (google.com: domain of 3b-9pzaykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3B-9PZAYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id es10-20020a056808278a00b0038c2f0e920bsi184345oib.4.2023.05.01.09.55.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b-9pzaykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id 98e67ed59e1d1-24e02410034so1197441a91.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:36 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a17:90a:2d7:b0:247:5ce:5bd7 with SMTP id
 d23-20020a17090a02d700b0024705ce5bd7mr3861119pjd.0.1682960135879; Mon, 01 May
 2023 09:55:35 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:22 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-13-surenb@google.com>
Subject: [PATCH 12/40] slab: objext: introduce objext_flags as extension to page_memcg_data_flags
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
 header.i=@google.com header.s=20221208 header.b=lxWpRSi2;       spf=pass
 (google.com: domain of 3b-9pzaykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3B-9PZAYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
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

Introduce objext_flags to store additional objext flags unrelated to memcg.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/memcontrol.h | 29 ++++++++++++++++++++++-------
 mm/slab.h                  |  4 +---
 2 files changed, 23 insertions(+), 10 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index b9fd9732a52b..5e2da63c525f 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -347,7 +347,22 @@ enum page_memcg_data_flags {
 	__NR_MEMCG_DATA_FLAGS  = (1UL << 2),
 };
 
-#define MEMCG_DATA_FLAGS_MASK (__NR_MEMCG_DATA_FLAGS - 1)
+#define __FIRST_OBJEXT_FLAG	__NR_MEMCG_DATA_FLAGS
+
+#else /* CONFIG_MEMCG */
+
+#define __FIRST_OBJEXT_FLAG	(1UL << 0)
+
+#endif /* CONFIG_MEMCG */
+
+enum objext_flags {
+	/* the next bit after the last actual flag */
+	__NR_OBJEXTS_FLAGS  = __FIRST_OBJEXT_FLAG,
+};
+
+#define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
+
+#ifdef CONFIG_MEMCG
 
 static inline bool folio_memcg_kmem(struct folio *folio);
 
@@ -381,7 +396,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -402,7 +417,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
 
-	return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct obj_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -459,11 +474,11 @@ static inline struct mem_cgroup *folio_memcg_rcu(struct folio *folio)
 	if (memcg_data & MEMCG_DATA_KMEM) {
 		struct obj_cgroup *objcg;
 
-		objcg = (void *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+		objcg = (void *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 		return obj_cgroup_memcg(objcg);
 	}
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -502,11 +517,11 @@ static inline struct mem_cgroup *folio_memcg_check(struct folio *folio)
 	if (memcg_data & MEMCG_DATA_KMEM) {
 		struct obj_cgroup *objcg;
 
-		objcg = (void *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+		objcg = (void *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 		return obj_cgroup_memcg(objcg);
 	}
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 static inline struct mem_cgroup *page_memcg_check(struct page *page)
diff --git a/mm/slab.h b/mm/slab.h
index b1c22dc87047..bec202bdcfb8 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -409,10 +409,8 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 							slab_page(slab));
 	VM_BUG_ON_PAGE(obj_exts & MEMCG_DATA_KMEM, slab_page(slab));
 
-	return (struct slabobj_ext *)(obj_exts & ~MEMCG_DATA_FLAGS_MASK);
-#else
-	return (struct slabobj_ext *)obj_exts;
 #endif
+	return (struct slabobj_ext *)(obj_exts & ~OBJEXTS_FLAGS_MASK);
 }
 
 int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-13-surenb%40google.com.
