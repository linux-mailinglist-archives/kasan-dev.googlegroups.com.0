Return-Path: <kasan-dev+bncBC7OD3FKWUERBENE3GXAMGQE2YPJSWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id CA31185E79D
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:42:10 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-6e4695cf7b2sf891303a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:42:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544529; cv=pass;
        d=google.com; s=arc-20160816;
        b=0gZukQKnJxO+PJUADxXiEKCh+yaEfuWXgbpwrb8j68fG2YJH0zSrtXcbb/dOsB2Bnc
         KtYvEYWvn1aEWFOaBgqdOFjxuSpyNIwV6efamadUTYLUtMwYhbMOdqkqLAdJGKvO3+OV
         lyOYD3PsxlBCA0ly+S+U1ufCBpjMSSXDqEBqjkgIyN4ct/az1ysEPzmSHFmBQieCmof1
         9fnAbk7eMTX04Sse8LRc8W8Unsy2fLEJ25t7ULY+B24IrmIXWmJjkoEBeYA8ePNA0fJQ
         9D3Ov7bWma1O45R3qaJXD9LclZPrPlIRyaqUO/J/iJdPmkazuq6eA05xsPZOr9jMbiuC
         FiLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=KJ/xHT+hya/Y6RZQhuhN+/oer21XiK+crOVM4uHaFGo=;
        fh=sd0C0kZlktcleNTLKmiC4KzXcQ9spWAHRX1Y5+RAMiQ=;
        b=Vh/35dqde0xldr5je254BJwolp4Plm1REUyS+TlHrCTafBCKHE8Z5Ri3Ke1k/tFQN5
         k5XgCovIJhrMJCD2Mu7x2EP+M52c+423WyaPWa4N1yCzFQDMv4W47uJuCVdTdiAlFQyI
         n302OimQupLZEZIWZS3xJ+h0ajIg6KXTkGAJxAErwJYaGjaFJ5bV9OSj9NXw8u358FNK
         JGDnvgiwpkExcCip271NzrIiHXhhTMPcoccGMJVw5EgLpDhWgGgZ19gISIe5N08069RP
         GOoMsyc0+gq1jNM95KCX3A0V/Yb0VwHYCocUvuuVe+IGDuX1Bq+EJb7MlHV7aA6Cg30h
         4IQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mQGWaJVV;
       spf=pass (google.com: domain of 3d1lwzqykcuiwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3D1LWZQYKCUIwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544529; x=1709149329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KJ/xHT+hya/Y6RZQhuhN+/oer21XiK+crOVM4uHaFGo=;
        b=hSofstTJ9Yf7qkjTMOqcWbv1BVVOejhh0BHeDBtugiySiJZpToRe3AQATy2zaGGwQ0
         02n/AtW6ELTx64bF8orAhKeJ5BftJIn33/UyzuVL8nUG5OmBKcr4kzyVmdFUSr0bqvUJ
         XQ/qX03+T3UU5i3eIim5yZ/zoeah0EUjwr5fqvcIYRi1t82KajAV3vSCL27NQsQ2L9S3
         CiHUFFBYIG8DUVOmEjaDCmOOO7/1aGQsfx8AA3W48dJyCWvqjq4jHXOR0zQmLlxKo8+w
         4ePNqvlzUbbmmX7Qi+/r3sx1Jhvauqxnb934ucCw5K/B6BuLQ7FIPrwU6jVee8gdw6qU
         /SbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544529; x=1709149329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KJ/xHT+hya/Y6RZQhuhN+/oer21XiK+crOVM4uHaFGo=;
        b=FbjhHonL33YM9baO6sJUSOn1HUYX5OssXgHTrcGYpoaAleUwaVhDwzbd/DYMvvAWmR
         d5H8j37Ic49CuUwGg3Hm83tr7U+O42XxY7NcLarzMFNnKMER9pmE4IwDSzWWy2+Gsb8d
         nDxh5iKD73/oAMZCFxrAYCmk70N4LHiH2gftEd3sD3ZVel81naQagJx0mtnGTMb7Gbpf
         VD5/yo+1pn4ofRC4BTJvUThgn2S3Om996PmhnIPP7O+k1l/4ridUYDZK0/G+tMU940E3
         b/etIPgqby2XEpsQtVKanoXKqj79x4NUrTh5Mz/G+mm7SqWXy9oPXtP2J/VtvuvBpJRz
         DhIA==
X-Forwarded-Encrypted: i=2; AJvYcCXBLSsfEIPsXx/8ce7krbX40IlgpukdZmRlmIc0cyL63NMr0k7QUuZEkg6Q0lqvlkXjVToUdn8icVZeyVYrRzm00LFyQSzqUA==
X-Gm-Message-State: AOJu0YyaLHF5eZAmC15wpxBQPwFt1Qqn40FviPUEzm0PfS36Zw5bxugf
	si/gd30JU8iHQxfZ0n7x8i3QmEMG/65oG4YwC7cmbLbT/nSNZKyd
X-Google-Smtp-Source: AGHT+IHFeVwdiWMHT24rhT/LIGGpqBl0Mk2Uc+fdpqEEZNL2OIJYbiCZUoNcdEb+at/MP3dwIEJvYg==
X-Received: by 2002:a05:6358:6f0b:b0:178:688e:fb21 with SMTP id r11-20020a0563586f0b00b00178688efb21mr21400928rwn.7.1708544529607;
        Wed, 21 Feb 2024 11:42:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4297:b0:6e4:c588:29f4 with SMTP id
 bx23-20020a056a00429700b006e4c58829f4ls140626pfb.1.-pod-prod-09-us; Wed, 21
 Feb 2024 11:42:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX/hcDP8C1rFnaEIxSAz1avkMP4zjhgfMMvsKOSJKH2xzKHR+AGsV6JABLR5iYPjKj53lDRL0RZXP4QuARGZ0aPXTaa4sILUjNbzg==
X-Received: by 2002:a17:90a:d48f:b0:299:9c40:c8e8 with SMTP id s15-20020a17090ad48f00b002999c40c8e8mr8863419pju.43.1708544528571;
        Wed, 21 Feb 2024 11:42:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544528; cv=none;
        d=google.com; s=arc-20160816;
        b=hR4BZXGRXLBzkZg9O62YHiViSwwmtSRr7e9q865R/Gg835rMKdU96PNnKTowNT2Ie1
         1/IeJBWDoLS8TqhTB0kNP+ZmlcaYsPotpYrywqh9AbhQsYkG+hlNQR4O2dr8f4DA6bFe
         QKGjmAG+Sb3P+gAzIWPxDxjeDoawcq+p01TuP8QIjYf39CLafm6jZcaVvg0VkdxTv6Mr
         e9/c9orFeq/NqMwkK+xEc4ug8yZDA44W/1KJcImRBkd27TnNdKDPUtMqAhvbsR4ePbjj
         0ftXhwyWu2wJHMkNgS8lZedHri/JNFnLilRWumeWz0aO2LEtqIP8emGlv6LnhSTJEy/M
         0CfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/f5EOcne7K32iqTM6gsyOYn4NQeb5Q9RrrPaWIBtzrU=;
        fh=AV8Lm/ih74f4p0Mz4DmeDsirhmurBR0I8gYY8qFapek=;
        b=F6EzbD1xaPeVdjfyL4N1PSkUK4fRRU4w0sQVAbRemyD3FlvAz5FRyYHR5vW1woZK4z
         m/wRqqHJ9Gx2azaV/DgWqWE0Jb1LcUq2vLAcz1oVKs5VwwOM8BsyI319q3TyELgsLMeM
         hogHgx+82so/0yKbN+StKl/kSh/jclMi/wxz2W9ageL7QCt/jscYF7sh6jm0XmgieBUk
         S0nCxcyZPSGYA5OYou6rnqP61geFXGN4RAsE0GvLVWS1vNQgsG8CtudNPZ3oZg1gg5Vc
         ylZCCQDWTlgvosWngnxJ5ZTCyhc0Hj5QVz2/Asz84mnJrWeU6lZUjM99DI+a8efOcr5v
         ROEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mQGWaJVV;
       spf=pass (google.com: domain of 3d1lwzqykcuiwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3D1LWZQYKCUIwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id a5-20020a17090ad80500b0029905bdb9edsi830884pjv.2.2024.02.21.11.42.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:42:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3d1lwzqykcuiwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc64b659a9cso12526004276.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:42:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUZVmMapWXhZISQp4mHpXYR00wbW5KRhuxSJt4oretrlkd6PFL35dAz8aIBv5T2tp/61fA5deHK9KlI4gpkooahDI0bVksne2nFjA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:134d:b0:dcb:e4a2:1ab1 with SMTP id
 g13-20020a056902134d00b00dcbe4a21ab1mr67096ybu.11.1708544527496; Wed, 21 Feb
 2024 11:42:07 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:45 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-33-surenb@google.com>
Subject: [PATCH v4 32/36] codetag: debug: skip objext checking when it's for
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
 header.i=@google.com header.s=20230601 header.b=mQGWaJVV;       spf=pass
 (google.com: domain of 3d1lwzqykcuiwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3D1LWZQYKCUIwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
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
index 85a24a027403..4a3fc865d878 100644
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
@@ -91,6 +112,11 @@ static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
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
index 920b24b4140e..3e41d45f9fa4 100644
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
@@ -1923,6 +1947,7 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-33-surenb%40google.com.
