Return-Path: <kasan-dev+bncBC7OD3FKWUERBNPKUKXQMGQEEFMBVXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id C0656873EA3
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:58 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-5ce12b4c1c9sf5196536a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749557; cv=pass;
        d=google.com; s=arc-20160816;
        b=pcNzaajYO04XlFE/OIhGIKdrTg3SzrCkM85r3ml7oXq3k0AS42poLVK0HiFzMatBs5
         nivS+w5ylgs/XMEOeh0KZF1jeYYwYMQtpbgjPzF8ospEI9VX6S9dg6Tvpuv2CAs9gduW
         luTI7eSQPsYbHbn+FSLK0NdpSf5xxoyk92AN3TPJ947Y7nTxj2oMgrAytWrXnynSE0OM
         c1Sh4pghCLavV+KBct+1ChjDnQBv98RHG/xnaK+Ow3TreJI36RJEZoo/lDIETw/zXyn/
         Kst+QAPoVx3zfuw+I7nbCXgd4l35hWyi3Qqsr3gfuVV+3aQwJVk4zV/Ayq0xz8yDpz9B
         I+fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GwH+jgoeARURdxIq+1mbZ5g17o5CWkGnTZrq9Pbl/rA=;
        fh=dXgmsHxbIneWXmZQeWYHj0oueLiKP4Gt1vYT/IFvdgM=;
        b=OtTVjkSO5O7yaeVNecfuGLx4t97gzCLWYOL+tO0MG481xwUu+aMk4sHCd+xC9AwjOK
         bJAV0B3fk2HwlcROioCMSSuD9ERIrl34Nlj532nvhD5+5znnLADSEy3+tHH3Is/ItOr0
         MsanDW3e5LiJ2DL8qBbFo2EOccAzvkV5GYTbXXloz+bCO/RivGUueWrs6Fpottm56RwW
         gagtRLJmuykmo7upzH8a17H3LQQtMgewtDyH+wqNo9xVbyuHdsjDjGCTEV6AqpX1qRoi
         wjBy86rJejo1uvDZF7C1UM12X1Ry/zbHFEtFN8E0phkbQV9rrQEj4x54fzuOmd7zChK+
         ksiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VK3BsZyF;
       spf=pass (google.com: domain of 3m7xozqykcxymolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3M7XoZQYKCXYmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749557; x=1710354357; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GwH+jgoeARURdxIq+1mbZ5g17o5CWkGnTZrq9Pbl/rA=;
        b=kaPhoKctlWFmJvWgoJglVAdBoNbDod4vNxlcEk7HZUAF+YKez1o/eSirWi7oXzgleD
         rcVELVm8zF84hbtUIejh0dEhwPnEXvLTEL9C1L8uHtakjK785KSEcjTFl/VP0Qqzacko
         lM6xJ1tZBYO919XZE/Vs7/BGBnMGpqUeKkohzPlc3kuqgDLdgSMskCPh7YPeSJZLdder
         3DFdTidN69Ipni6X8ikyCOuyNeal48vy7Yjx+Q/c70h8Rzerx6yAyCBF+SQz/OFk4d65
         w+s4ulAXmCVMpWLPzNNCwT1pfmbtfpgdUJvZr/4JEWV2s49gm0tYeWpiOg2kqSxnoKmK
         ID8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749557; x=1710354357;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GwH+jgoeARURdxIq+1mbZ5g17o5CWkGnTZrq9Pbl/rA=;
        b=TBJ9ArGeAWw6BickHYH34gZgzkiQ5Gl62X1GIOaDCpvQEhLeDXZad+7gEHBhG9/rMh
         i413YUnCWxqgVJEb3Rridd10NrDNUUWydBKVFC4pWELAmRglphIYjeKRpu5xxDFBvX8l
         ICJx/IEyZFgwfr6fOiwC+OeKcKNNanz6O1LKNq5GjVjjjQMSHjKDp0/kFrfCyTiI8CTg
         xrx72WTAWNH8d9qG8VMxdEI9thW5lxoRahHFkJIhuhaoBjAjlxcWWKtAkB3e8tieESUc
         VQxQhpdMJilBAqYfc8IOBX7RKrR642Z4fGTtsyd8X67uuakjWaxiW21aJag0XCif1To/
         5row==
X-Forwarded-Encrypted: i=2; AJvYcCVk6sKIzSr/H4laUIKpcqg2htEzNvtMrmDKu3RkGq6qzysbS4vXQOTOh/MjfSgW21ZnYVdmgEp2AKw2hpH+xnq0cma6WwTbRw==
X-Gm-Message-State: AOJu0Yzp8UntGMxFmJxg5oaePeHNltOwP8PcDP2YrdR23aZFPrsWqj+z
	J+WS+Fdxf2U8NQgFR4z4CgatlWbytpH8Uzw3tpvWewOFypenaXMO
X-Google-Smtp-Source: AGHT+IGQecdvfgmcp8JT6LWisBfNgEM5U3XcngrMIKuST1gAhkNfg2uiS49JvoY9pavgQ4S3SlFD/Q==
X-Received: by 2002:a17:903:120e:b0:1dc:ca74:7018 with SMTP id l14-20020a170903120e00b001dcca747018mr6502177plh.36.1709749557411;
        Wed, 06 Mar 2024 10:25:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d1:b0:1db:2ca9:b5b8 with SMTP id
 y17-20020a17090322d100b001db2ca9b5b8ls81306plg.1.-pod-prod-07-us; Wed, 06 Mar
 2024 10:25:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVtDwoLQ9lV0lHwhvJHVIe6Z8hCaLpybiZFVKXoJpJ3sjwgZWZuj5ijdfYkFQjJjS9TW9bZcfphZ3rZJMmPris7GdkuJ/6k2FG03g==
X-Received: by 2002:a17:902:f682:b0:1dc:afd1:9c37 with SMTP id l2-20020a170902f68200b001dcafd19c37mr6431691plg.24.1709749556434;
        Wed, 06 Mar 2024 10:25:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749556; cv=none;
        d=google.com; s=arc-20160816;
        b=F9zsclR3Zax0atPmZ29ZImEDYqSiMDX3xTI1ll7iQy86OYsfSrxIgOuQPclQjVuucq
         N7BDEoMIVbDi7wnINuCHJzhKWyL5Dbe8Z5yt7dTaOufFMHMSOMgfsIFzxo/txieCq496
         GN/XdrdllbNRwxvvn3r+q7qzkDlNkd3cAzjqVdT0Xo/uTrLQXztmc3YEt+r6b+rqNJJ2
         Ypyw8RfFFRupTw+jzd9twOA+jA8QexaOIaz9zLhjzJQBAnrDagsZ4Hd8fkEjvtt1dE8D
         RNPdkQPvt3y4ydVEeIOU9/06pEBjuR1nM4vpb1KcfcdxRGm2zi2DEybkKuswvhx8gNFP
         cDgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=O0frA1qINx6EEpp9W3MZZMQxDt0vbebTSbODwHd6D+c=;
        fh=b8V71TsHmsOrVcsQZ1QjOe6P+eCmWrpYi/l9H2HPCxE=;
        b=oOuaoIQy+zZYamFs5om4qi/3xdf9iRskD1aplYP4KGg5J8XU7uOPHqT8zV8v6Swwt8
         vK/TT8p6+AXSLayjP3zTwgKHbDtVyQTKLg1H+AMfYWhsOgwHn3kSPHtrNFik37aMmIVt
         1eCuKBL9ynfZFczciaceoZyLQF13Hodlk1sftILSRMwblvYnzzEA/OQv5gXgcPfRepPC
         MSzLLvo6aVwp/en3V91/M2FeZsZoPFQPYbEZ4h0wrpxWyv40NfXn0o4d76ScMinz9xh5
         zQ9jRb11YQ2FdklHhzht1UHMsPVafMDctKnkFnZpqc+iRLOrOhiXpBTGgNcpYaO0HVmK
         Oy/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VK3BsZyF;
       spf=pass (google.com: domain of 3m7xozqykcxymolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3M7XoZQYKCXYmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id n21-20020a170903405500b001d93b23476dsi903791pla.13.2024.03.06.10.25.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3m7xozqykcxymolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dd0ae66422fso201039276.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWRvL4MtkX9xcezkLEk4ToDBFxue3f7lyJkP4Ib8Se3k6RYKkuPK6JPXjTSNzkBFkiKI64RuIq9jXIb0AzHsGwiZon2JRowGNLeJQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:705:b0:dbe:d0a9:2be3 with SMTP id
 k5-20020a056902070500b00dbed0a92be3mr1901493ybt.3.1709749555637; Wed, 06 Mar
 2024 10:25:55 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:31 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-34-surenb@google.com>
Subject: [PATCH v5 33/37] codetag: debug: skip objext checking when it's for
 objext itself
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
 header.i=@google.com header.s=20230601 header.b=VK3BsZyF;       spf=pass
 (google.com: domain of 3m7xozqykcxymolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3M7XoZQYKCXYmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
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
 mm/slub.c                 | 33 +++++++++++++++++++++++++++++++++
 2 files changed, 59 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index aefe3c81a1e3..c30e6c944353 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -28,6 +28,27 @@ struct alloc_tag {
 	struct alloc_tag_counters __percpu	*counters;
 } __aligned(8);
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+
+#define CODETAG_EMPTY	((void *)1)
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
 #ifdef CONFIG_MEM_ALLOC_PROFILING
 
 struct codetag_bytes {
@@ -140,6 +161,11 @@ static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
 	if (!ref || !ref->ct)
 		return;
 
+	if (is_codetag_empty(ref)) {
+		ref->ct = NULL;
+		return;
+	}
+
 	tag = ct_to_alloc_tag(ref->ct);
 
 	this_cpu_sub(tag->counters->bytes, bytes);
diff --git a/mm/slub.c b/mm/slub.c
index 5e6d68d05740..4a396e1315ae 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1883,6 +1883,30 @@ static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
 
 #ifdef CONFIG_SLAB_OBJ_EXT
 
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
 /*
  * The allocated objcg pointers array is not accounted directly.
  * Moreover, it should not come from DMA buffer and is not readily
@@ -1923,6 +1947,7 @@ static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 		 * assign slabobj_exts in parallel. In this case the existing
 		 * objcg vector should be reused.
 		 */
+		mark_objexts_empty(vec);
 		kfree(vec);
 		return 0;
 	}
@@ -1939,6 +1964,14 @@ static inline void free_slab_obj_exts(struct slab *slab)
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-34-surenb%40google.com.
