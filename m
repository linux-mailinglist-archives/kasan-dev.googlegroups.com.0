Return-Path: <kasan-dev+bncBC7OD3FKWUERBW5AVKXAMGQEPF72OEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D6C4851FF2
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:45 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-290a26e6482sf3552459a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774043; cv=pass;
        d=google.com; s=arc-20160816;
        b=UUjSgLu+76ZyB9ON5vMSN6P8tLBPynwKWXvFCtPOcg4O1gHYOLEAVbmv7a1RPweVsh
         JQfkeKM4zDLqaJ92/CxF3FCKVDsBYakiEzljIsb1rnNgj9rAXknuY0BkCeiZGOZvbacN
         FETA4PNAupNtmUj+dnaWwaaCd5pVb/YXO/vXK7pcaDMPvf7fR/fnUzQbOXe4a8N9PTdJ
         oPlNrWYayN03vHjXYc8mZE+m9OtD3Vn6nOe5U3xmKYWr//Vs+yyosq0JKipnQgIiTzR+
         SrSMwvmSfMsYynOQx5X3+/GSgSXJ4lA5f1DIJQpNN42YWGfDAl3CrUyuCNSQMQTZL0Ru
         wGIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/Da4HFBG7p2Rs71/izjDS7lVqFIF10hOVcwT+UTDB+k=;
        fh=8KIaUrG7ZzgbJXeZd/EVVILAjz+jwMEHFEeyDSOBb74=;
        b=CIL6DAhxF6deXgvSvs58GT1hF4h1qBAw911rDHN7TOSE0c6kVwFyqzf5yeuZHvNwaK
         QxtJIp0iFHARr3u7zWXFUA0o9edaD/NsCvBPBK+yNfPh59cQ48tzB8A8HPUl0AW464YM
         PGt4xCfxjF/B6DhdLXQB3ArwT+gkkw6NQhI1K/tYGgm+rMXrb7rIk8IjBuyXKrggyqSX
         2n9RIKhTcKX2NkHmqRRhL4XcIHtjKJdPYfM0vaAGCpJvPjdCwwSEeSOkEaDcVTjE8kYp
         azzspri7JDZ9icrVLTiDgpxrk/i1cJ31xBgkzt4yjR/vnDU1llngA9IJlB0wiTd6N4qY
         DyGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h5QoK81T;
       spf=pass (google.com: domain of 3wzdkzqykcdgmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3WZDKZQYKCdgMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774043; x=1708378843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/Da4HFBG7p2Rs71/izjDS7lVqFIF10hOVcwT+UTDB+k=;
        b=kbSVQSSPc6yTB5N40QSn+cHobg2lQIGOfkTAUOHnL7RjqY6XQdVtxVJC6unvuzgzOd
         PKtn0kCFNZVbYH/4fgnSpQM2ScGnOy7sl1BJ8mYyUrwwuDZ5wMUV+Ugr3qPaa4h5MKKX
         C1ngiYUpVJ/vHGL4+TjWOoPCgFoPj9dERSpX0VTI13uQXYyx5+1tcp0tQvlNG91Vp+rH
         kw5EKefgNcetcj/NRqMKxAdBC71UXO2t3FUhHxfFSK9Tt0figm7wmlieyaLGIHe4Xhil
         URi3X2Hf33ITSoNF9BEmEW6chl3JneWb5JkQzQNv6mzA8oaHI5sAX8sNzMeYAx2RL/9f
         hFfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774043; x=1708378843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/Da4HFBG7p2Rs71/izjDS7lVqFIF10hOVcwT+UTDB+k=;
        b=QMQH3up1Z4m+tnGQeQDmOyKspvJ0fa98muPajoXbZcldGpjxHrphTNVQXUReqW1iu8
         JqCLmlm4zB+kli2ElgZaOtPP4aTDEhOg2lqFw+jcTagrhvuQE3wE0MlSHFsFBgFPdXR/
         df1vmqPLkr9zwu5727T2a/+FEk/IcWdQHM1Z1SydqaqXrc8qgjecthwKLSROfQ4hH/iU
         qtmImdk+dau3Cz398ID9Up7T3xnKl/HV3pnSorqjbqrLWloLIUNc+lSVfNYuUhrJHMNR
         roiUpPAB6G0X7RLn93LsRJxcOtERdGfs/pOTui1ZPtOPaaACCyYnmDQdJ6FmooAEo+2v
         Zh6A==
X-Forwarded-Encrypted: i=2; AJvYcCWd594ffHruFld8rMwf2jD2rqu6gSfsNjdreeREZ5e1gOcQrZaWcCz1jXR2qqN/2zAZVKePs4G8JvUaVXp7TZJQkK0+edgv+A==
X-Gm-Message-State: AOJu0YybeMhS+lugcedpppEVyRa4BAzz50S12IF+qyvtmPYwsroe1m6I
	xfhNXlBUtYLPbz8rkAjpElsqwNZOHaD7fJh3iBvGbOLpvu9aB1IU
X-Google-Smtp-Source: AGHT+IFiSImdwvSn4e81R9IwCIBAeTxEcLHKVMF7LBQa6IcMlD6sObF/J7IW6JPme+lugcfbbNn2pA==
X-Received: by 2002:a17:90b:3781:b0:296:3edf:d48a with SMTP id mz1-20020a17090b378100b002963edfd48amr5118194pjb.3.1707774043689;
        Mon, 12 Feb 2024 13:40:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1848:b0:296:e236:c5e2 with SMTP id
 mf8-20020a17090b184800b00296e236c5e2ls2458766pjb.1.-pod-prod-03-us; Mon, 12
 Feb 2024 13:40:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWyTjx/eW9moBZ4Kzrc5rhBh9M3g+Gys1AX5UrVcvOQe4+F/N3Sw/WjrMHZs5bol8IzDpwHVmUgbxc4B7BeWEpIIxsitj843z8BCg==
X-Received: by 2002:a05:6a20:e68e:b0:1a0:5d43:83ae with SMTP id mz14-20020a056a20e68e00b001a05d4383aemr1281820pzb.61.1707774042681;
        Mon, 12 Feb 2024 13:40:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774042; cv=none;
        d=google.com; s=arc-20160816;
        b=LKJ1LLAOZwb2VnPDVBo7PbZvtM449txOxoG1Hi6DyFcWO80o3wzVP59NxLEXAjTjUO
         S3fnpmIeW2T2jDXVgFi09pfgIEXjYoK3bOIxociW1JybE61xizuedhBwQgM8Bsg1HdQm
         cWI/oGjylC2T+eGHpIaw4bZx4CB9nc4skWuFFAMup0Ka7LObBE7gIVJfRXToAalrOyUw
         H3kbQG351Kb4UVy8yi2eAov+0PnbW46uJvxmeKoEATYmm679IpC5siaNrM4IHwmJBD1V
         8Pd/Z03gWsXTdfX4CzXxNCxmzS3m7sTQPEwYNHB/654xAevPtRJg140obgY99Vii1D+4
         cKtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/sI0PWD0cr+RKARN01FIe/JdJLbOCpqo744sqtIKAHU=;
        fh=fOXGZv0pFdhJAU57pZQcPxLMimMHjgsPzBWWMrP5bw4=;
        b=YjHPpEnve44PGkySV1i3xWa3CBzJ7CSXOjpYOIKHof7JwjF8HoMOqoxkgGgJ4ryxOv
         QHbqZ4gKW7HfeSK5J8jpp2DUWp40piqZ2k35gHVKOW1ZrVbNWerlSYzu8Yl/hJHoEp+u
         cHrcUK4sYgc/JwXw4OyBQp0i8d7RIP4zR1AlfIPOKHhxuj1Ofu3Id+3mtKE/jeOuvxSr
         pjJcqTWBo0TlLbI5pN4IsWR3P/j7Jvnbl624Fz7hHdvYQeW5lYGQpoZsMRbhOWZandMt
         4/O4FpHjtiGZmIIBNAcrGFF1VzZkGnYSWQCSLLZqIrQKPiV3YkpLJJDdmq7uspHGARqc
         N+NQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h5QoK81T;
       spf=pass (google.com: domain of 3wzdkzqykcdgmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3WZDKZQYKCdgMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCV3C2ocP8wsiFjOjenlJrX4+hRqnPEzDHriqAZygPjUA+y/aTk7BKGN5CGUxWj/8RjVFrnIFt9UJZzlpRVxw3yspgEQtqlQ/zCHxQ==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p6-20020a625b06000000b006e06c8a8c7esi1189706pfb.1.2024.02.12.13.40.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wzdkzqykcdgmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dcc58cddb50so292849276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW+aJBZZSPIn7DGP0Hwqodn9XFRxN6up31GyR41dHKu0ltYOTT1D19eQ4xM2ke0REIB+U/AdEIwL1AfeghjsmoNuq3APB7yIa6nkw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:2186:b0:dc6:cafd:dce5 with SMTP id
 dl6-20020a056902218600b00dc6cafddce5mr2274526ybb.12.1707774041837; Mon, 12
 Feb 2024 13:40:41 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:18 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-33-surenb@google.com>
Subject: [PATCH v3 32/35] codetag: debug: skip objext checking when it's for
 objext itself
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
 header.i=@google.com header.s=20230601 header.b=h5QoK81T;       spf=pass
 (google.com: domain of 3wzdkzqykcdgmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3WZDKZQYKCdgMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
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

objext objects are created with __GFP_NO_OBJ_EXT flag and therefore have
no corresponding objext themselves (otherwise we would get an infinite
recursion). When freeing these objects their codetag will be empty and
when CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled this will lead to false
warnings. Introduce CODETAG_EMPTY special codetag value to mark
allocations which intentionally lack codetag to avoid these warnings.
Set objext codetags to CODETAG_EMPTY before freeing to indicate that
the codetag is expected to be empty.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/alloc_tag.h | 26 ++++++++++++++++++++++++++
 mm/slab.h                 | 25 +++++++++++++++++++++++++
 mm/slab_common.c          |  1 +
 mm/slub.c                 |  8 ++++++++
 4 files changed, 60 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 0a5973c4ad77..1f3207097b03 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -77,6 +77,27 @@ static inline struct alloc_tag_counters alloc_tag_read(struct alloc_tag *tag)
 	return v;
 }
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+
+#define CODETAG_EMPTY	(void *)1
+
+static inline bool is_codetag_empty(union codetag_ref *ref)
+{
+	return ref->ct == CODETAG_EMPTY;
+}
+
+static inline void set_codetag_empty(union codetag_ref *ref)
+{
+	if (ref)
+		ref->ct = CODETAG_EMPTY;
+}
+
+#else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
+
+static inline bool is_codetag_empty(union codetag_ref *ref) { return false; }
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
+
 static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
 {
 	struct alloc_tag *tag;
@@ -87,6 +108,11 @@ static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
 	if (!ref || !ref->ct)
 		return;
 
+	if (is_codetag_empty(ref)) {
+		ref->ct = NULL;
+		return;
+	}
+
 	tag = ct_to_alloc_tag(ref->ct);
 
 	this_cpu_sub(tag->counters->bytes, bytes);
diff --git a/mm/slab.h b/mm/slab.h
index c4bd0d5348cb..cf332a839bf4 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -567,6 +567,31 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 			gfp_t gfp, bool new_slab);
 
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+
+static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
+{
+	struct slabobj_ext *slab_exts;
+	struct slab *obj_exts_slab;
+
+	obj_exts_slab = virt_to_slab(obj_exts);
+	slab_exts = slab_obj_exts(obj_exts_slab);
+	if (slab_exts) {
+		unsigned int offs = obj_to_index(obj_exts_slab->slab_cache,
+						 obj_exts_slab, obj_exts);
+		/* codetag should be NULL */
+		WARN_ON(slab_exts[offs].ref.ct);
+		set_codetag_empty(&slab_exts[offs].ref);
+	}
+}
+
+#else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
+
+static inline void mark_objexts_empty(struct slabobj_ext *obj_exts) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
+
 static inline bool need_slab_obj_ext(void)
 {
 #ifdef CONFIG_MEM_ALLOC_PROFILING
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 21b0b9e9cd9e..d5f75d04ced2 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -242,6 +242,7 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 		 * assign slabobj_exts in parallel. In this case the existing
 		 * objcg vector should be reused.
 		 */
+		mark_objexts_empty(vec);
 		kfree(vec);
 		return 0;
 	}
diff --git a/mm/slub.c b/mm/slub.c
index 4d480784942e..1136ff18b4fe 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1890,6 +1890,14 @@ static inline void free_slab_obj_exts(struct slab *slab)
 	if (!obj_exts)
 		return;
 
+	/*
+	 * obj_exts was created with __GFP_NO_OBJ_EXT flag, therefore its
+	 * corresponding extension will be NULL. alloc_tag_sub() will throw a
+	 * warning if slab has extensions but the extension of an object is
+	 * NULL, therefore replace NULL with CODETAG_EMPTY to indicate that
+	 * the extension for obj_exts is expected to be NULL.
+	 */
+	mark_objexts_empty(obj_exts);
 	kfree(obj_exts);
 	slab->obj_exts = 0;
 }
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-33-surenb%40google.com.
