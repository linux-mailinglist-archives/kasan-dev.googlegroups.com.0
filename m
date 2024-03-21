Return-Path: <kasan-dev+bncBC7OD3FKWUERBAGF6GXQMGQEYM4KWII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C724885DD0
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:25 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5a486a8e1fdsf1009796eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039104; cv=pass;
        d=google.com; s=arc-20160816;
        b=xkx6J1ch9twx3nBbArJUu71gBLpQC+RPSvDmBGbg9yVqy5kPIXTkmUhNka5Pfi+rw1
         JSSSJ+LzsYYRWT/BgXrbEtEc3C4jZbNrOJ8JCgViFxXQVzJdA9fmmpbF0WTyWTIrQXsz
         OwAADTIp35xCCb2B1niaHxWjLMyZl+579lcZKXCiASWwKphy+JNaH53+dUsERdAMncdA
         i9zH27ZNwfmc6CV/0Tk/qwaPH/G2OYyLDhqO0HDXGZme8+g7VYkmZZ687bWL2IODBI8p
         QaE+OI1YAUdHp+K8cAxZ3NQVyxSKLStKlYfc7xrH4R+k5d++SxSVEgPFUkeSg7hwWVgx
         ukcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=lAvVdWTdGjn7BVQnnDFuHAbH3VdW27xi5Rjn+fOmcGM=;
        fh=BKFZuACwCQjBN8OPB/AugBik7xSmewDSrLncWHIoBrM=;
        b=J5jq5Siyf9+pznw7UFvzVsN7hnuBu5JEnUjm/2oIPqgpbrKO6lyXtykjbcfd3NRO+Y
         Q2K5pgu0BtMQuCbnoF/0+c5HavnUAlj5wfPnRUnoJfylFJ7q8bkZhDLxffNwJIdlTqXC
         6DU/eSDeLe4W3tR70nyk6iCbzvJh8kcvRP3nG/Hc+WfEjxLC3E7co59CnHFVWciuwlEa
         U7viTMzCXChanXtatQL7idPcM3GoFBMv7cuSihKnsiXoHJ6fzd5ZiDRDmYGiLI160JX5
         kauERNR43jz2mXKf7rcERCKYHBsd7jlt9vBpLt1CnI7ag9Gi/VSlCm8/xFGD3WelQmee
         WP+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kseJzDGb;
       spf=pass (google.com: domain of 3fwl8zqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3fWL8ZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039104; x=1711643904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lAvVdWTdGjn7BVQnnDFuHAbH3VdW27xi5Rjn+fOmcGM=;
        b=Uxk/DQsy13GoTXb45lYv0AEX0YUti38pI4b9r4Jgkq4cIT5dV23754fCsChbPx2Aos
         lZP8lFrk6MUoGyTzFhS9z+0M2lVouoJhapJuzyvimWF5JmkSKYDGGUumuiPZOecD4xiC
         cnggoHJ9V3RxIlFDgnwgQO6lmIcUoqkg0cbiwZtGA85TiQZmBnby1LG8Hl/qrM9yvej2
         sL9OeFkWX+bnpCooSRjrUqTZEFqgheOTAWlhR1j8QPCobDpewfU5upUGeYeU4HUYuLEo
         +7vKJM2z6EKQrOIOgl+KYIJkwzagJ5o9FxNdVm/YA0vUtC4ByYmg/0fXEXQN3IZWkhfr
         TIZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039104; x=1711643904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lAvVdWTdGjn7BVQnnDFuHAbH3VdW27xi5Rjn+fOmcGM=;
        b=QrcPG5ZFeaFRErVh6Ob2hEcvNM8rG7HfPtZvvQy0kYo+YMIDIa8NIt0umWXnRLlg/7
         83M2s54EHZQUceAIscMYMWy82ZWbHjdnASm9IAO6mKhnoXcUXsD/T9qFOnpY+QxURiQR
         uyccKFrift/6b8IVizLN0Wyueeacgn3UlgwdapKxk/Ym4FFP8w8MT1rYBwJU/36nY3y5
         o361TPx50H5HRZk/YemyYombD6JUM36bUlL5rCeoN+gR+XyHeTlOsb9JkdTFn6abCzlg
         2POJC3qg7ioBoWWihonhaCWkXsw2SQOcoaSudkZvZnRo0NMfAKN03RV+d4uY+WTyYell
         IXtQ==
X-Forwarded-Encrypted: i=2; AJvYcCUnxvn8PsAERsxRkq+mnv5cJYMFtfLz5ogOZU2rkVAb+OQp86cv/kS3EdxMAYWfAcGqTwNrrWGcfNjOWyKMwFvgPyTvPYaOng==
X-Gm-Message-State: AOJu0Yx8rTuj5+0THLWG5EsuISi8mroCPPWHUZ6WQKyk64+wxa8qG6RZ
	5oFYLCRvvNAt3qbyFjuKzI2q8Gn1c/mAE0W6TlAVCPeyOuLMPcKPtVI=
X-Google-Smtp-Source: AGHT+IECkQv2e5uUUDu6+5uZNI0SA56jN4JPwoSLYuC/33cpyQXO7TvgiOsgk7Mp9HQqHR4G0agL4w==
X-Received: by 2002:a05:6820:987:b0:5a1:316c:2d88 with SMTP id cg7-20020a056820098700b005a1316c2d88mr98916oob.0.1711039104385;
        Thu, 21 Mar 2024 09:38:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b44b:0:b0:5a4:905d:743f with SMTP id h11-20020a4ab44b000000b005a4905d743fls1128035ooo.1.-pod-prod-05-us;
 Thu, 21 Mar 2024 09:38:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUajuUHxNVjviUPfWnDf+dz90jW/KWoQeNukloX+RhOhil1UAJpEDf9Q01ivnBqMjp7LKZ1viATZpRfKHR3Y24hWiSPIUVAvwDsDQ==
X-Received: by 2002:a9d:7d8b:0:b0:6e4:dcca:aafa with SMTP id j11-20020a9d7d8b000000b006e4dccaaafamr2954117otn.12.1711039102175;
        Thu, 21 Mar 2024 09:38:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039102; cv=none;
        d=google.com; s=arc-20160816;
        b=QcXzoHKUiK9vLMZ9+aQOOFsJ/Owyof7tIVMLMMWSwj5l1nIONg3QUfRyBnmj+J4a2C
         M4Y+g5RSmxjWgoVZeHGVjUwpkUQfk4c1Kj4sCuu0jMj5vAzBOW0ImNI3pVuI14GYoSvW
         H4tRRHREjpbeoJavsNCMLh+tfsq9EeI0kXvcMErq5PXqBB2+kJ+iJVtgDaN9F0BwqSoS
         sJHfDnfzoYuyrP/zzPnzpZ3ImbzNrXDYJsq1wWY4XZVJGY6lOTtyD5gTe7BII72FU4OX
         qmZfKGpTyrb/ClnoP/XwpagWd32HptnMZ9pnqfJFjbg+Vwks/48haxQwlPX+UT6988+P
         R/Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=WqtLQxxTOcT4NwKA/wnlkHzJUMqCp8K/X9+cNXxjvBQ=;
        fh=zQ5EJMrs7B58qUDTJJsiQQwUdbAzam3dplQNWEBLiuQ=;
        b=e08x8FmmujU8sqjpyHtMYSg0yDjc0nb+/da7QSxK84aL4TdjFW+po6SFAm2AmF3scp
         oSPxNledYJ8IWR9tPwiUu7GYP95gwftvIpOj4KV+qzkgGpRZNYTcBNJe5QvNz3y+NRN6
         mefRWNraeA2Isl18H/nKpRkzeTKvZ0T1P2ng1k2HkGItEGcVhh1sH79kckQ7waGUTn2K
         YVT573jIlMRetGAEzW4qCzij9xKse9qIXlATxdudmYjssudEooaQ0qEnK09CiPKjhjXc
         EcM3pmLoUv9y6x/blXMMv09QaDY0/Y4uoJ+TBxf9fhw7B5Qd83eWFVNqN3zEZko4DOnn
         lraQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kseJzDGb;
       spf=pass (google.com: domain of 3fwl8zqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3fWL8ZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id ec1-20020a0568306e0100b006e6a1f0ac32si31547otb.1.2024.03.21.09.38.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fwl8zqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6ceade361so2071234276.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUekUg04/G/KcOz/Kd8AIW6t2XCcHOzIEaGGp5mgAxFwZ71RrQTWEWshJeRbx+TgtQ4zFyZ9HwIoeqWb68VKpfGZAVhks2dcrGVew==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:2408:b0:dc2:1f34:fac4 with SMTP id
 dr8-20020a056902240800b00dc21f34fac4mr5790745ybb.2.1711039101565; Thu, 21 Mar
 2024 09:38:21 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:55 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-34-surenb@google.com>
Subject: [PATCH v6 33/37] codetag: debug: skip objext checking when it's for
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
 header.i=@google.com header.s=20230601 header.b=kseJzDGb;       spf=pass
 (google.com: domain of 3fwl8zqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3fWL8ZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
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
index a05d4daf1efd..de8171603269 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1873,6 +1873,30 @@ static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
 
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
@@ -1913,6 +1937,7 @@ static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 		 * assign slabobj_exts in parallel. In this case the existing
 		 * objcg vector should be reused.
 		 */
+		mark_objexts_empty(vec);
 		kfree(vec);
 		return 0;
 	}
@@ -1929,6 +1954,14 @@ static inline void free_slab_obj_exts(struct slab *slab)
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-34-surenb%40google.com.
