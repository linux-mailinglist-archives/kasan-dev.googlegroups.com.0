Return-Path: <kasan-dev+bncBC7OD3FKWUERBAWF6GXQMGQEJ5EYRTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A3B2885DD3
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:28 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id ada2fe7eead31-4769925b023sf119330137.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039107; cv=pass;
        d=google.com; s=arc-20160816;
        b=ajUs/FRgDehU9ej6imBLbSsiRMoWycAl3bk2tt0+Y3CUAF4ganDJB7iQkbMJfvkfW+
         LIXbCfb5XNh7mf8X3aoSIvx7zapSb4fNQEUmwCpTV69A1FYPr/YaBE8iNV2w+SG4vJdl
         B7JEqRC7m0VYTmKVI5MCHyRyTwG5J37vMDoW5AEVWTcIqKSBkVMrcsay6NHf7SDiMRsS
         o1CHKiSw+HuukSCiV0qdltzuggmQJRnEZgZkgcKeobB6m40yHOPMKGVEdvki4ALbE1CN
         f9CXaDsF5F8yCDk2DUYez7hLS0+/VjCaKeWQIC6nFG1vh9TCM4Agtr9oFrUx5jj+JxnD
         i6VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NFElSzMfiHsqGzXVltN0p8sJ69L40rEzR6o1Ebh2GW4=;
        fh=nGDoXGKBvar1iw+vjN8j8SLeLjyPMoOPsjqKisqs/Do=;
        b=WZCJaOclX3Ny4y1uzCb/S1QybSTuc04TdN7XhHlTfe1CFXdWBynrXLC91r/DmBLEmS
         lyTKXl3NIzq1Mxmxqdd5Ile4bLuxqq8bGfUYj6SLPjreb9b6lT1HmNmTp3b1RkqEUVv9
         HOX9/OZefE1qm/KNEudnfNPl291GAvDS//4B9t01DOkT7d4sS546e1O98c7LCTZEW7sS
         P0d+CukPCu0Sb92aKhXj8IdQ09gVR0CjZZ/Gbb/0TgbILHSWp6tyKOCiqWHQdqMMQT7O
         NRmLLC/TGw+op3cEBmcwDc1QJt+4l8j69oJxUWNz8RRGpbzcjXERz8XIgMdX8MDfbtas
         CNbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KjO9yk9z;
       spf=pass (google.com: domain of 3gwl8zqykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3gWL8ZQYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039107; x=1711643907; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NFElSzMfiHsqGzXVltN0p8sJ69L40rEzR6o1Ebh2GW4=;
        b=EViY4rWGlzq5ePJ9O0ieHTnfNsn1+SEFXWIOO+uTHUaTjYqUqLRzzttenlV/ZLFiP/
         QG0IUnjuwWZlld2YfdAvxNb2ZG0fC1rXFZdSwRtZ28ZR+oTEMJGpj2/K34Wq2Ah81gnj
         VaTW94LXmYH591VGxr7V4eLF5mHTv3K+fCu2wdwLzmCIglTKYKQANN8gGGPVt0HHHVnA
         +IlyLend5MSFdE+5+vNfp9l2zYgz7qR16+WwaLO/dZk+Tg3m6GXiXMpqJ4S0Ja+CJ8mX
         OJ0VVJhRhUgeJQBVyslmfONwtaGnHCo7WcSsNS7C/wSt8ZoRccFDi1hQW6xhJb92M+PE
         zd/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039107; x=1711643907;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NFElSzMfiHsqGzXVltN0p8sJ69L40rEzR6o1Ebh2GW4=;
        b=m97OCHPI/7fdZ+AxuhH8BN6ec0kDIGsAIqD9G2/NLuxu62Y/pQY26y/AuU3+DCSWqW
         VrYIOh7k/TtlHvkgjQOUR1hEgAQUuNZKIQtJUjZm6rOwJ+SgyeDZRSwXGlHOaro4wfpW
         9aDpm6vBqtAkN4F+USg3rIbWTYNFZGuwqya8PcnjDV1vOMr4xN79QRVoosnir1wrc5fz
         OFM2xjBAq+mo2MVIrb84aVCbk7IXdLLIStvcvgXDJx/Hb4QlX7emwh4qpCZuuyQsqy2P
         NDnlVEkD/JL0BmVr3sYblN1hdAaxdrrGi7n3yFy8ZE3f4qCuaIKjOEjr58PrORxiEjEX
         QObg==
X-Forwarded-Encrypted: i=2; AJvYcCX94Dj2ruC6aunBDYRgMKw42OVrWtgSMSOIOxH1CVlkge6Jsq1kthXVjLBHiX8e9lEiEzEASaj9e+OPEoETz1Sskf4VrJBHrg==
X-Gm-Message-State: AOJu0YyqRgMEB9BtU5aqTh8iyzggbI3ePakWb3Ox8u+9Fd4Dz/m2eYkd
	pE5EhfXakw1JhJCmGyFDKOtgIeBWp+cGtGlUdmdxmT8lqNcM4Xq9
X-Google-Smtp-Source: AGHT+IEdpksSkWuMXFgfx6JXfOdjLtxxiGV7Pr/GGt48W6Qm3zsrX/wN4Zya7QPWkdt140W0GSqVJw==
X-Received: by 2002:a05:6122:333:b0:4cc:4cdd:3faa with SMTP id d19-20020a056122033300b004cc4cdd3faamr7954942vko.0.1711039106940;
        Thu, 21 Mar 2024 09:38:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2523:b0:68f:1312:8dd0 with SMTP id
 gg3-20020a056214252300b0068f13128dd0ls1732867qvb.2.-pod-prod-03-us; Thu, 21
 Mar 2024 09:38:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWp59nJSr1xA0Hhex4E4l5lfWs+6Zf227/mfGy0UfrivXBzsTm3dyG73DRHlkGRnfjNWyVMGLQCZT3jdyT6MsAlWASo/p3RD6irrA==
X-Received: by 2002:a05:6102:310:b0:476:bf60:9467 with SMTP id 16-20020a056102031000b00476bf609467mr47817vsa.6.1711039106308;
        Thu, 21 Mar 2024 09:38:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039106; cv=none;
        d=google.com; s=arc-20160816;
        b=x6045bAyvIC5PoDhMxDrocmd1Kk2dP9ymPNS+CM+pkfMbEgteR0uxQJ+I+L4Uap8/x
         dCVAh4UDaNXel6VjxsXh0aAs7PshJMI+xacSSGfQVcZgD2C5qxi4dSge8zHzY/vX1Cwb
         K8Q7vWlu17t/2uJ4Lgn1d9RM/PBFksBEqMZHn0l/OIdj1RP2V/wAdTi+LPQB1pBfshAV
         gEA2C4SYEvWrKZdq12ruiBbLctnaicxTYzJOrBHyeDQzdLpKqwzhhEaQBgpkP/6mBxxW
         DxsVwpx1sOIyul3A7rmQd4HDmgNd4Fx35VrBZThzsTSpKB93fm/CvJwm7Qc4l/JsuyKb
         4Usw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=f5LdsTMnIqabj8ROFrnDTgTazgUa7GmHleuFcbzHgo8=;
        fh=LDOCQAO/rRgDGurXQFQRnaC7Rj4/gjWmtR/ihutluUc=;
        b=W3G0W/WQ/ewCuyVwJWQyUAnCDleMKcWqQvg+qFq1lS0aiWzUEWAd3N4cfZlGFX7MDT
         O8grDozJ0yxAZWDBM02MwwzJgh4qQIejPcqKZpSg8OG1cy3nTFJmFYtgLrbj+iUoqGU0
         4nffUyiLlW/33MqU50eFZiPFesEZw+feqqi+e5+NzDYiHM0eK0/UyBMHZoKxrM3Tx/CC
         O8cwuKxOb3DpY+boUt2QFVRXFsxfvCsLHG705OiULb3dZwQPgHSL4yoBOwgHdbjDyPHD
         HevQ6AuK6WXKizPeGmS4kl5shjSsoLmx9qouAg1HCfQkaYX3EOMqOa8xykdwTkwuy2lj
         E9qA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KjO9yk9z;
       spf=pass (google.com: domain of 3gwl8zqykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3gWL8ZQYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id ib2-20020a0561022b8200b0047309ffd6fesi22753vsb.2.2024.03.21.09.38.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gwl8zqykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60ab69a9e6fso28869647b3.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX1EJtFg3yTWAW/3kS+yYUBBmMJ2nOZV/R+a+hXv9TtqFZRBtOZ8gVNaETCNGA23qTwYzpeadZphI1Q/wI6uRdYrfUMgRQaapE6Iw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a0d:cc41:0:b0:610:dc1b:8e57 with SMTP id
 o62-20020a0dcc41000000b00610dc1b8e57mr863711ywd.3.1711039105858; Thu, 21 Mar
 2024 09:38:25 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:57 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-36-surenb@google.com>
Subject: [PATCH v6 35/37] codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark
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
 header.i=@google.com header.s=20230601 header.b=KjO9yk9z;       spf=pass
 (google.com: domain of 3gwl8zqykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3gWL8ZQYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
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
index 24a6df30be49..8f332b4ae84c 100644
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
index de8171603269..7b68a3451eb9 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1891,9 +1891,33 @@ static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
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
 
@@ -1909,29 +1933,37 @@ static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-36-surenb%40google.com.
