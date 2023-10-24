Return-Path: <kasan-dev+bncBC7OD3FKWUERBEUW36UQMGQELJYQ5FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3775F7D5280
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:48:04 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-7a9618a6685sf175264439f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:48:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155282; cv=pass;
        d=google.com; s=arc-20160816;
        b=H82QbLCtM0jOR44BtR9DQo0yQah4XaOREaAUZX/RuRYvNkbKyHg8+MsSiy6ZPEizsn
         mLXCvX5Tbd9pfNXhtPvzrneUZTJuVg5fkxosZcIXiuSjd5zqc3smDMpEfpfVRDrzqMOu
         MazIwmcsUg6TLS+xdKe1bjBMmMTq6ftzdtvtekKqlE/CExk6eRJc58s0QonQ09QZsjMW
         9V+qpnxccssRqUH0kmDi+N79b+KDnNVJ4/G30RxjFSslbVx72GLY0G58mr5GFaDHsjZQ
         iHQg8JFn0srsTsUMjgDaOQzbsEZbD4/PWAwUEzKty6pkbCCxGw9u6vftd681hwSIEPQ2
         TKQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gJVdfVFgMHnhFI9iqZoG9ntwYIvlh+se4ZFsoOuAsVU=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=GqA5kCTbriFHiWPK5buRy3pi69ibBLnRFBLXVpknc4s13NUSAH14ac7GpvPsoJglAU
         CMT7IhZVZn+MR87x6RDO3x6zduyRNbFq4yfhPjnn80yJkDF2TYCgoAeSANN73z1EEhPq
         a66M7yo2Yo4PZud8/IojaI3cgLjE+/ipb6IIwdhp1HX/B69XfXtQyhrJhg0qEVOVUney
         ubkDWFsyUjvo0ds54TKbYRXdxUoJS5Uh5JRcL7YWsw+EcZA0A+9c4yRrYy0QyQv59TlF
         eJVVRfQJ1Y56BxFfso2ncRFwjiSP3yNQvPT4k9jb7bGF+L2ElshZYsFGmnyFtUuUOa3l
         9+Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SKxaYT1Y;
       spf=pass (google.com: domain of 3ecs3zqykcbyoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Ecs3ZQYKCbYoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155282; x=1698760082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gJVdfVFgMHnhFI9iqZoG9ntwYIvlh+se4ZFsoOuAsVU=;
        b=tWHpBuKqapjwHPvTYEIq7yFElLzdRiEs1oNEiK09orFIvaTGNBvyrwp7mgjka/Lbzf
         X2cWZ/eC8pgZVYeg1+l78osVaw1AnLZxCUA3Q46wbDwrpB2bn9WhT9IlcJ3qhymTNxDA
         g+rXICZn9veSfBIEcUvjoF7MMJ5rEKnU/KxF9IdeLlAdwQDUIp7GnEN7gnpgGRJnMtLN
         WXM/58SPxWoaKw4vNJfgvyw2xmWZSDG6d6MKKYTK7H/0z0K7XOvZUvcRd9QcQw497SQX
         nCg3gfMsMInxc7VhC8mppM+rLk/vp47cy8tVjJvxl+OcCWZqquvt0Yh4ezEy26fBuK8s
         /hlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155282; x=1698760082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gJVdfVFgMHnhFI9iqZoG9ntwYIvlh+se4ZFsoOuAsVU=;
        b=gZ2lZRxC3dh/FgouELWiUA5tYOoH/XIscT+ZBFmkS5Aqo0hX5TPNpFS3PsrnqbNTH8
         9sFTFW9ddvYOh7r9AUWtOdcBTdAXTcgHf1auuAlwevgjaoxsU5E0NbmiuxA3jd9wlw29
         +Qt07r68tJWMhaR8HqFg2dmh5k2RHpZCSG8Ga1D1/S2u5BxSQhUbG1+18x5hOtCuNimF
         2/Wg7UlGIgIbkVPYFV3VRDdhPwR6OQZByk1r0quI+lUGZM73jG2OO8ui0mK41h8xLah0
         7wK2O5BVMz0tr89YOYmyZ30yUTi1g/fMyE6FgLrFO5o5ULFiN5Uue50LRRbXKKEXk0Li
         gtMw==
X-Gm-Message-State: AOJu0Yzz9f3dYhDqN7BW6lfDebMTYDyCxKBgY85r/NnQ0Orj1DkDzJ4B
	EkDB4x5BMBKLE88H2jFbCzs=
X-Google-Smtp-Source: AGHT+IHR+/yK5DN0qjJYE+rG3Q9R0k0ezLFvI7pr15Ni+1fI9SOFxeTdzxAzFqVZQiBiht3Xnn8Yhg==
X-Received: by 2002:a92:dacb:0:b0:357:f41c:8bf6 with SMTP id o11-20020a92dacb000000b00357f41c8bf6mr300041ilq.17.1698155282798;
        Tue, 24 Oct 2023 06:48:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2613:0:b0:352:55ed:84bd with SMTP id n19-20020a922613000000b0035255ed84bdls2711776ile.0.-pod-prod-09-us;
 Tue, 24 Oct 2023 06:48:02 -0700 (PDT)
X-Received: by 2002:a05:6602:1696:b0:795:13ea:477a with SMTP id s22-20020a056602169600b0079513ea477amr17763357iow.8.1698155282185;
        Tue, 24 Oct 2023 06:48:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155282; cv=none;
        d=google.com; s=arc-20160816;
        b=bM1ehcNgn+T8ULovbNczUDPnBfjy2HseXHwllZZcRxFTbF5zKO2U7R+LzjZtRNRC1L
         J3Y/04qFrE0m175KjW1qEiw/yQIgo6LrQfMTg/DrocX05hOyQiRoa6+aZO010Sp2oIcd
         IbZ16+obkakuOLMp5lzbHYg4k1VUSaCZh9LYCrs84qQC+M2IlsTGxZT4jOrJ+mWKWwFi
         LgE9M6fL6isiV4mdb6a5mcx6ivf1e14gAugnMqfVynnl8XvGu+GKcKlwVwbMD7E6/vHV
         APOSGdTdtUkjWdKAwWHWnMzhyhUSzifrPjJG2g5Qmw8XRZgjyx6W0Fu6BIvoSpfzjnlf
         Q8hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+3jXXsjNPLXrWv+rf69UQa/6uvXnoVOikFRei2b/KT8=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=PrkjTcmWbE1N8yQaMecJ0icFtc/aOJnRbj92jHm6n/1DfTny6LeGkNKBDJlENZ6PR6
         BfaFKheBTNkhES7MVKDtD+kWfnZm4WTS6ILejgVKjJKchGa+UvSJL78c+0qa1TjGCkLP
         JE6rv04h2cIbJhi+KaYA2xeBYl08cUsc5kVSahBoE8fs6np3ib306S2U0mk4tAgpJ6Ip
         1nLlyTCcDNAQ6srAkWGS/ZKLTeUyj/AuiRRecigmkal8pxAEWpcO0blXJ8Uw0eKiZzcn
         BT7WpDF37wYQiuJZb25q+uTz61VI3B4r/en7Twe+90N4Z58Hhcz1vvbtfZT+NMG4XN+R
         aaPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SKxaYT1Y;
       spf=pass (google.com: domain of 3ecs3zqykcbyoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Ecs3ZQYKCbYoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id f10-20020a05660215ca00b0079f9c4f99absi735863iow.2.2023.10.24.06.48.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:48:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ecs3zqykcbyoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5a7be940fe1so59935067b3.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:48:02 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:d50c:0:b0:d9c:66d1:9597 with SMTP id
 r12-20020a25d50c000000b00d9c66d19597mr227720ybe.13.1698155281680; Tue, 24 Oct
 2023 06:48:01 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:33 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-37-surenb@google.com>
Subject: [PATCH v2 36/39] codetag: debug: skip objext checking when it's for
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
 header.i=@google.com header.s=20230601 header.b=SKxaYT1Y;       spf=pass
 (google.com: domain of 3ecs3zqykcbyoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Ecs3ZQYKCbYoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
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
 mm/slab.h                 | 33 +++++++++++++++++++++++++++++++++
 mm/slab_common.c          |  1 +
 3 files changed, 60 insertions(+)

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
index 4859ce1f8808..45216bad34b8 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -455,6 +455,31 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
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
@@ -476,6 +501,14 @@ static inline void free_slab_obj_exts(struct slab *slab)
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
index 8ef5e47ff6a7..db2cd7afc353 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -246,6 +246,7 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 		 * assign slabobj_exts in parallel. In this case the existing
 		 * objcg vector should be reused.
 		 */
+		mark_objexts_empty(vec);
 		kfree(vec);
 		return 0;
 	}
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-37-surenb%40google.com.
