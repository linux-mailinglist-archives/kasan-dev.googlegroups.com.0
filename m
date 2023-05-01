Return-Path: <kasan-dev+bncBC7OD3FKWUERBQO6X6RAMGQEOCOZEVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B30D46F33FF
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:34 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id 71dfb90a1353d-44050696d40sf466185e0c.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960193; cv=pass;
        d=google.com; s=arc-20160816;
        b=I7V2eQSfPOEvqrQZOnivAkSVk73ThrK8Yv3R3i8BMSUHhc046S6uMEG0765vbvGQGg
         i+SFJJ6qRfSSL5zICeO54KoyJF3IJ96IZHX5OpJrKsLva3pUYwxYxBhKRLVEU24/jjV0
         prIu3csREw1YZ5BEVyw3xDhAjw7YVoAfTXDY1WVSzLBn3jc6SeTFelRIUwNpq5JftYg6
         m1LMFhhePYYMJIHLDe4ETau7bMi0uCkkjnLHXPF+I+Xslh5qla2O5y1doz1htLKdWWP3
         09/R3QLAxtodYYOXdRR9NROwTapQhpRqKK4rArh8gRm+ItM10NpcnNWgi0MzuWRDnye6
         ZTKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zB2G5nYLbCqRQuEmSUE224oo8hMoLP13/igf+Z642oo=;
        b=oZUVFYkECKvOw1Qs9F8Iheu9aHlaXAzxyNC13pnWVMEpUEYTfXKUH9mFh1v9FYkoyE
         KC7CK2QrIBrxg0hfoG4DZ+InKHBMKkckKqFeS2wono5VEpuSKS/vk/TkugSzfyOVQq37
         H0g7+cG65xzntTmB36K2h3q4st/7vvWzbprpM0/ZtlMrLndxAjI/CzhFnZbdDF+K65Mv
         quyUAsW+b+w2tNn0xXISfzlqlXILAZiBG/Qb+PgVbXAisL42KWJNqgK/MQ3VNCD+KKS7
         u1XLJrVdyoW0kjmj2zau0ra3bL+fGZueOTM9WKWFlqz/KDB7Cudvth3JJDoaL827jiKh
         PjFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=lLa+vy9Y;
       spf=pass (google.com: domain of 3qo9pzaykcyc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3QO9PZAYKCYc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960193; x=1685552193;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zB2G5nYLbCqRQuEmSUE224oo8hMoLP13/igf+Z642oo=;
        b=e4UyNz6oQQI/OcbS6eVYzwBWLlfv2OfKf4C/mZOJHAfkJLkkcAn2Ee1L4joJSe2Nc3
         dixs5Hv8IaXhHSR3deiRoodtaUGJsyPDhoXqwM4E9D49QhygauF8ifVRkwTdqC8uku0k
         ZDreRpprvjtGDzCZsTs1EiNHQo4EYjd6hO7dewbK7+doSw6wsS7YYOPvwRH05ZbH/cAu
         l8oC2kKQrCG2MBSDV/rqtL/q3WNATVEkgDH8iqiWYpBSx+FaUEqccrAYUpQ5yj1fgzmx
         SuqUQcW2HelGcNVbe10lnWpbcKe7AgN0kqoRCVXT+V4fR7p9nBDLTBhIsapdUDx53WZb
         DTDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960193; x=1685552193;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zB2G5nYLbCqRQuEmSUE224oo8hMoLP13/igf+Z642oo=;
        b=e23TUY2lSTbNBfP29MNFtGGq6USKZDDqA2SOJFVkmadZVZMtO0RSKJkdoeBzXn1Rb6
         v4hAM7/rk8/m2wdZdpuJDzVGzblZfYZHh8yWaBrBlld6LBQt8vCMVNRSY7pZWFg4Rtfm
         Ibz4DJGTydgmt0FP98l/mMGzeLxS7rMNRt46a1YkqmM2k/lJ+EXGKfn3PNdDPaTeiDQD
         3Uy+zk6xe8WCmUTUiAhsoFbjO0oUyAvTO7AEzPiXtW6taKCvRL0tIe7gX/6W7ttcgKAx
         ol+bvdYCJdy0xnftejulAjBK8QWANa1LlTtsAldk19PnS8GeT6pcLOm8CfUyI1EQh+ne
         +RUw==
X-Gm-Message-State: AC+VfDzc1zvYauO8fgsN/H5bs8plEQY+PAw5t5QacreVEmMw3BKFizmC
	gS0wq3zSKomADOKDs3uERQ0=
X-Google-Smtp-Source: ACHHUZ7KKnP6V/Y7slDf8rtxmdCTMS7/gY9AmlkT9bCqCAkGbW9J0JAM8ZRB7LZnvzvrBXwi2Kqk1A==
X-Received: by 2002:a1f:138a:0:b0:43c:aa3:bf3d with SMTP id 132-20020a1f138a000000b0043c0aa3bf3dmr6382496vkt.1.1682960193600;
        Mon, 01 May 2023 09:56:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:5c05:b0:42d:8b40:67a5 with SMTP id
 ds5-20020a0561025c0500b0042d8b4067a5ls2747246vsb.8.-pod-prod-gmail; Mon, 01
 May 2023 09:56:33 -0700 (PDT)
X-Received: by 2002:a67:ff8b:0:b0:42f:e97c:b0eb with SMTP id v11-20020a67ff8b000000b0042fe97cb0ebmr5248644vsq.4.1682960192919;
        Mon, 01 May 2023 09:56:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960192; cv=none;
        d=google.com; s=arc-20160816;
        b=0Nughg7g1CWZ8zQADAHnhtqVO860vFObWFTSaFSJva7qUss1Yd3ZmWmDYjSzI2EydL
         NgTwt+6+07zxFhhDAmdXcSO8VYl5+e4WCTiXJ0WHnJeYS6QaYzWWKGTBO5gVivOj2o6P
         chcZ+K53TUuKpvdtqhSD586vyMznXBgt2pIr/25lW1JtxVDRy+Mw2sz+ooMvH4KB4AtO
         bx24wvn6vrf/pcP3elo7aGAM4KmIpg4/mNCTGwTDn23h/Az/LLCBc4bE40iuWmUj99hg
         vDblmeNpBH+LHj29WVofMYeZk8m8vRK/kGHfiD68WE3rQs2P0HWLsI2vixIUPLOZKhAU
         A0IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nH88FGoAACjgZmQtkl43JvHLPN3RafkQwEsrc5bfN4s=;
        b=VAIp51dtYTJUXNNKkBifRiq8/9etDmDg3vKFpPBpc6oepwdwsFSVccp+WV9rcztQvm
         qOkUPuMTDci72UG/8zZk3Kd+YTpowp2g4N4REl6hen6zTFvCLVxWh9+1IVgX+B2EXXJj
         GR3hUE1uswia7GYdFQC+natZAJc8+oHjlfqmmmH8/FMfuAKQetev6Cfa/GfiByvux5pJ
         mhOiC9OfMZBSZzp+MKi7hblpnHTdFLu/g3ibxmSOs5F58shQOi6PUvDttH9dUKemT+/B
         gqbsGuBxbyMLc/as0ZlNzSpID0Gye3PKaO5Sg3ZwgH4dhSaeCUUnuQaQDxKTXzeAm0Ly
         6ESA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=lLa+vy9Y;
       spf=pass (google.com: domain of 3qo9pzaykcyc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3QO9PZAYKCYc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id i1-20020a0561023d0100b0042c41134c2asi1760830vsv.1.2023.05.01.09.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qo9pzaykcyc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-55a7d1f6914so10708187b3.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:32 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a81:4011:0:b0:54f:9e1b:971c with SMTP id
 l17-20020a814011000000b0054f9e1b971cmr8801791ywn.1.1682960192486; Mon, 01 May
 2023 09:56:32 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:47 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-38-surenb@google.com>
Subject: [PATCH 37/40] codetag: debug: skip objext checking when it's for
 objext itself
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
 header.i=@google.com header.s=20221208 header.b=lLa+vy9Y;       spf=pass
 (google.com: domain of 3qo9pzaykcyc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3QO9PZAYKCYc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
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
 include/linux/alloc_tag.h | 28 ++++++++++++++++++++++++++++
 mm/slab.h                 | 33 +++++++++++++++++++++++++++++++++
 mm/slab_common.c          |  1 +
 3 files changed, 62 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 190ab793f7e5..2c3f4f3a8c93 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -51,6 +51,28 @@ static inline bool mem_alloc_profiling_enabled(void)
 	return static_branch_likely(&mem_alloc_profiling_key);
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
+static inline void set_codetag_empty(union codetag_ref *ref) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
+
 static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes,
 				   bool may_allocate)
 {
@@ -65,6 +87,11 @@ static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes,
 	if (!ref || !ref->ct)
 		return;
 
+	if (is_codetag_empty(ref)) {
+		ref->ct = NULL;
+		return;
+	}
+
 	if (is_codetag_ctx_ref(ref))
 		alloc_tag_free_ctx(ref->ctx, &tag);
 	else
@@ -112,6 +139,7 @@ static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 #else
 
 #define DEFINE_ALLOC_TAG(_alloc_tag, _old)
+static inline void set_codetag_empty(union codetag_ref *ref) {}
 static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
 static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
 static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
diff --git a/mm/slab.h b/mm/slab.h
index f9442d3a10b2..50d86008a86a 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -416,6 +416,31 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
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
@@ -437,6 +462,14 @@ static inline void free_slab_obj_exts(struct slab *slab)
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
diff --git a/mm/slab_common.c b/mm/slab_common.c
index a05333bbb7f1..89265f825c43 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -244,6 +244,7 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 		 * assign slabobj_exts in parallel. In this case the existing
 		 * objcg vector should be reused.
 		 */
+		mark_objexts_empty(vec);
 		kfree(vec);
 		return 0;
 	}
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-38-surenb%40google.com.
