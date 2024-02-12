Return-Path: <kasan-dev+bncBC7OD3FKWUERBX5AVKXAMGQEIOF62SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 74624851FF6
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:48 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-42c6d28d780sf38968841cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774047; cv=pass;
        d=google.com; s=arc-20160816;
        b=ANzH2e8uLlkaeqbnghIjqFLRnqq9bsCiM5LpkBxi96FkhD8arayyFzKBEOj2VhCHz+
         al2C7MXw2Y0qMlHSYUC85UUtHUVj2qNTwhbmIVweKnWje/wuYOQ2B+564M6u8GXvxoHs
         GHE9CG4HhLvxSfhLirtDgPiy6fwj+hvsVEe9ylrpWFVv2v9LQz6StRFwUXQN3jUAvZmt
         ANQHuL7Y9cAQUumRG/OG2M9Y4X21+YLBn194I6dD1dDRfsuq752TfdHDAUjyapQ9NsGi
         zjPHz4NEXNPwgiWAdnz4jQWXNrKQtQPX7ibGamg7/fSYuibBHdoS3kVGVH0WLF5mwIFL
         s9Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=sjOKckgXKTTnZPzfcCITFu4pwbsBftgkOv3yicceHQY=;
        fh=uZMcnS5ohJCIslTtZ/yqrC5PwEbsSm3lonYWTUWhcYE=;
        b=pr+agz/eAxmuFHTfLh8gFMPkDmkhOFt8nKe9a1ivBsRJHSauCw2DPnS2wLeQX9jIxV
         r2vU71f1UYsw55DoVMCYKsI1MVVzrzf9qgdpZniFIhAFIwWB7VVy8HiKLey4BfYhTf0O
         GiI6aY8YwgrqJogKS3Og5XhWysfTvM2gNl30vCDctKcudn9Ceu9irXjIZz3otzB2aDCw
         Hmdm3tSg8GLIQ5RPydLZNCCBgHr64kTtN4U0NrWwT+RJ5m7yrshhah4MnI1MXXjL9GHy
         dZ33vW2RSC5R13n/Qh7g+3C8jxz0y0cKEr3fDa4W2GDII17hmkidC1gcMkm3nFr1cDTB
         Lqyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k5YJniJT;
       spf=pass (google.com: domain of 3xpdkzqykcd0rtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XpDKZQYKCd0RTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774047; x=1708378847; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=sjOKckgXKTTnZPzfcCITFu4pwbsBftgkOv3yicceHQY=;
        b=A7snCUj3wa+vkKqgmsyy4F9d1zyJ+uGsIt2MtnlczjCSvkrdK3xjdmvK1v8C07gMzU
         MJZlEH056Oq3uE++qFEAOWkOLCUMRRw9B86iYZ+4I3uqyuJRXlKZjqcUc9MEImHeZNZ0
         Wf2Z0zUe5VYRohUqLFTRLiR560K4wAbmCw+YojXD7THU3jck3r/Mfgr9k/45mnMz0GT3
         8hDAyr2RwwcLSJ+LDPUDiMfzifsFCuaFKLrCfjZt3DIGzIVYcCdPvv2MLE5mux+CnMt5
         eW4CgsacMhEvw6VUz9hj8UKaK95wLb7fzxmlTw+/VJAgZwI3hIzsFO+cJCkjUJStTXWm
         SOKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774047; x=1708378847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sjOKckgXKTTnZPzfcCITFu4pwbsBftgkOv3yicceHQY=;
        b=DJetG00CWG8qM60eKIsFzOyMeqB+jFJZ9jAkR55AeB6SVGvKTz5rnovKA4oko0wEc4
         JRxFbBFMl238B91C4pa1Kl4xNQBHzzWF1jWl+I137B/l6BHvX/D7WuA8htFKS+jCkp9G
         KoHfjM8HskHfJGJ+L+b66D5i54SkQJHq3Y2VanYAADJNutjylZrWLNtuLwuFaZ8Bc5tJ
         v9vk9E4EbPqK+l6Im7YB194/n2/ZDjJtqjY0D49ZGhdHYwQHRxpQP6gXBit+x1gWSkzH
         LjsegTC4y7lQdNjbjtugc5BC7L27W3lOSBEMwVq9ZXWBfw5TfiHjHLr4SnY5r3jbfzEZ
         soFA==
X-Forwarded-Encrypted: i=2; AJvYcCWwdyKsPBghdwiyXvSU1ltLvC2zBLo2sKDkNM/IRkXYvqmKNYiQiO70ld4QpLFQMKrOQTiObTirVCQfk37sNl0IsLq6UMstOg==
X-Gm-Message-State: AOJu0YzqiHqVRgFB2MPSHZZHyWYXRgG2kRUfIG9s+3+qTFshFL574va9
	hAxYjrdzO/+o/VuGzwXWFMertCACHQ51tMP8CahlXXCFvRq2oJw2
X-Google-Smtp-Source: AGHT+IGoy75xz3vcpsNJFBQm18tz6AGISoP57qjk09Oqh6ZNJ/OX+O3nUXIXKEKpb07M/9VN90Cwwg==
X-Received: by 2002:ac8:44a3:0:b0:42c:53ec:a8f6 with SMTP id a3-20020ac844a3000000b0042c53eca8f6mr998192qto.28.1707774047366;
        Mon, 12 Feb 2024 13:40:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:92:b0:42d:a963:7ef8 with SMTP id
 o18-20020a05622a009200b0042da9637ef8ls676563qtw.0.-pod-prod-00-us; Mon, 12
 Feb 2024 13:40:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5/cE1PIOCmlUw041wdiSEyH2P7zh3wQspPZY60qG87p/pa0ZbHW+9rfPnO/tYh8FSdUOTFdZYsCAajMuFJ006b2Rh68yxxxqOuA==
X-Received: by 2002:a05:622a:15c9:b0:42c:3f57:1e0d with SMTP id d9-20020a05622a15c900b0042c3f571e0dmr1491783qty.10.1707774046790;
        Mon, 12 Feb 2024 13:40:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774046; cv=none;
        d=google.com; s=arc-20160816;
        b=B+UFkS/eihcqJIh7bj9W9098gORoaF8b89MbpQ2SBL3Tu//gr64/hQvzcFNOlF/1aH
         T8p0gQzIvVttVZ6pGnaiBhDHFlkgtcZe/ULyZ9GzivCSsZhW9/L49SBKMTILiM2ALTOb
         ug4mejuxXlZuyWDGmIIPlWqJ3PQRjSeAXBZUkYZCitT5yD78njH6sGy1ZMchoUemPUfr
         A3Xvrsn4rsHSW7kUuHwUjyc/jSZNqLGkSi5kRLfNhmNICDLTEaqKdjujCLWqrEofdwKg
         gzGmeHRV2Jqwaf4ccbWIovfYe4gcz1Ep8Z4qWYImOoSc/PeFNVkoKMjYC6XiLdd1KnZg
         2ebw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RjVDAYkVgDU7fuXLh0MJZ7V+qIVlVtuXoydpki6LzsY=;
        fh=gsgVVP7moDMe1uRGJ0QWGbZliw+3VKjF2z7Ig9jzoWQ=;
        b=uycwrkcd1P/NDeKm6kIW/ZdMbP7XK4IkWYNCuGpKOfk5eiDxlJAg2m7/nUL8CA4u3T
         4BAM7Y2cfm6ZlP225xXPHM9a8LL+frQ6uN3acrAJ9vwSiDwc3X6MwFYehps0JYM1MGBh
         Zkh21rA6bmq5QaLbQ5a35+cmNpPNP2e0JxSBK/ToVM3ciXvTLJQ0uy3JEBVy1zHUX09X
         gxtsH5N08Vq/c2nZIvigagZLdO+afjeLDIPUOy2WoJH2bay9PmHmlRU8B1C5zxCjKAH6
         rC00G3rG5z6WS1zvVCc4xJyJdp0uJPw7kdnlM2c37HdK8QfN3J11e3RtcJ4dAWHSUfXc
         oD1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k5YJniJT;
       spf=pass (google.com: domain of 3xpdkzqykcd0rtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XpDKZQYKCd0RTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCV0P9OPiaG6cB4YApU1qUFcpjhE2MTlhBU0GY70S3gwdAHCdPj01fClT09URVKvi6GdRJfr0pmMmJEF6hECvxnOu8hWh/dByPsMmA==
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id o3-20020ac87c43000000b0042da8da3d03si121683qtv.4.2024.02.12.13.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xpdkzqykcd0rtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-6047a047f4cso97759887b3.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV6ym9SN7Ympy2DRyZsx2/8wtfKEY8m7Cpn73EBnvnqUOW8Qt487YYDgjgfVUWSzCErOb7d6kuvaoOurJLeiGpb4B2OefRMYZ6AOA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:150d:b0:dc6:d678:371d with SMTP id
 q13-20020a056902150d00b00dc6d678371dmr2278885ybu.3.1707774046204; Mon, 12 Feb
 2024 13:40:46 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:20 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-35-surenb@google.com>
Subject: [PATCH v3 34/35] codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark
 failed slab_ext allocations
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=k5YJniJT;       spf=pass
 (google.com: domain of 3xpdkzqykcd0rtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XpDKZQYKCd0RTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
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
diff --git a/mm/slab.h b/mm/slab.h
index cf332a839bf4..7bb3900f83ef 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -586,9 +586,34 @@ static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
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
index d5f75d04ced2..489c7a8ba8f1 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -214,29 +214,37 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-35-surenb%40google.com.
