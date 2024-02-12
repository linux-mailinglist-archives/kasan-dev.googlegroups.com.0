Return-Path: <kasan-dev+bncBC7OD3FKWUERBRFAVKXAMGQEGRFN7CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D2CA851FE2
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:22 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-6e0e62e5d41sf1464657b3a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774020; cv=pass;
        d=google.com; s=arc-20160816;
        b=GWi4+nxiQJhBIzTFwR0YDUlGEzFQA4jEdnKMQuxQZTEPhEPI4e/pbPcf0OzTYbyK6S
         1nKLYkTVOSiRrx1d0MsBzVbwVG/13X2kD8eOU244w0V+wZ+ySwWZqOhLwT8LUR9dWcHU
         Hn1a1nMhJBcXRB4yceFuKgCPbVTU1GXy7Y7WgGwuh3X4SZBDerGkDhWqtyAOovn3AKav
         V8uzmllDumV9Jj8LMyBu9Uc98Q/bdG8cjgh4l8g+FGjcTzixn5hxi7kT3YnlnSKZrtRM
         Xi3xI5STr01rt7uHmgLLdKpcM3NmN7bR+PR0daXV15p0NYxfZ9yWBiJImlOKCGZ6XCsa
         aRWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=EG6Nwgbn6TR5M25BHtaxROpYABmjPh4HrseV6osuOOo=;
        fh=toO9gkN/nKrqiV37QGdXixDdaGBqiv6DHiqjKDqt6No=;
        b=h7hzdl7rlNAf5A3TOClrueK1T3RnWAqRUg9MH4ql+FwuzkDm5ZnlAD07ZVAmslkw1S
         IWxNU6rEOjzvE1s8d0B5fJFCKuXfocZ7gWo5ObPaQw8XyHPv5BKxBbcBP0FwkkAUMtc7
         BxBxr1qILHwhgtMSwUR9MpFJ70CEzdCcNfbpyWgusSj4m1Fv21RtXbteRRTQ4tMGLpye
         kKXslQC/oqgqQFqYMT0WwAVk+TKkCbAaE3YZyYlcZ174PZ1Hj3txu1mrsj70I4p6+qIh
         KoyKh9lKF8kmAYRv31s8VnG/HbgdmGciwViirEHoJsydSt7tvKo6yoqwDE/bFShkGXBl
         A50g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jVlhq+3g;
       spf=pass (google.com: domain of 3qpdkzqykccez1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3QpDKZQYKCcEz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774020; x=1708378820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EG6Nwgbn6TR5M25BHtaxROpYABmjPh4HrseV6osuOOo=;
        b=FTEWghRhaj4LEw3r86Bc/KQvpfJYUF2vdxTBH9z804L1uDSwxtSsGJGdJPPGHAMR/H
         +AiuSGNBXZst3KIa16dzO5BY7ETQTFICdENLqGgS7VKQzspP5KHwgWCeq5v/8JLOYM3B
         vonDLsNQ/yUPROSSk8h6HQAk0KkEsb2EQYSoA2wuHbUIGcoFcZDmhktFvCuOr3QIXYAd
         snUY/HlGsrFEJnoApIg7lUzqJqs8wV2vcwrT7WV0lA0vbaj1rM7agJ7Lpnz880uCNDQ8
         AdlOUTr6FkDJvUZAAFm+YvUTVbmYeREdQceHMw78vm8iRRjdCKKygxIjtmo8zsTRNpeV
         5iyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774020; x=1708378820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EG6Nwgbn6TR5M25BHtaxROpYABmjPh4HrseV6osuOOo=;
        b=hSfHO8jVlAkQOaJphXdJ6NwsKbcMH6TgJJdjzvH0Bmx8Xx3c0sqpCaK6vt3oynC/X4
         0p4UBklPm52Ipemdys9aaeCcvoWz5zemU5BGFz5e3nJpBVWcTdnTkEU1koVj/Xf5wIK3
         7E2IYhxBen2tRb9IVOj8PPGbvtaPwaHwctdGgWCGaE77G2qqab2SNMWl9cYW0v8luoZL
         QdKI5G/j/Z1qUlD2PThHMnkmlNDf5VRFRiCxum7iJbTbMX9WzrxdgRtC0EOxMmmaoWL9
         Y2/U9+N/LCKlfUmxdRuZ+ubFn6IrOwPL1Zjrv8F+FZn2LHBylaAy0RKqbJB+8e9tkoKs
         c2jA==
X-Forwarded-Encrypted: i=2; AJvYcCXAFwMMXQ4lczLpFw/UUjhX2R7s1O25pg4jFwPZsSvjBzsurFVc5oRKmmUqJF+Xa4wvVEtW/kJgPvR+OD0aqgcLLYQNi57ObQ==
X-Gm-Message-State: AOJu0YxRF22V7/PnhLCa5xeBUMityt9jQ+hgOu74cFoIk9NMK/sUi8hK
	uWFVY772F08g+oN1j120+kVDz+e7t2YVmarQnepaxsNzzXrCY5pl
X-Google-Smtp-Source: AGHT+IE90OalJhsKBnoFzyiRFjUIf6GzcR5LRSa6Dod4iq2k4/mYlwg/kCTycPR0HarJTCCHUI+SjA==
X-Received: by 2002:aa7:8116:0:b0:6d9:9613:cb9e with SMTP id b22-20020aa78116000000b006d99613cb9emr9496881pfi.29.1707774020634;
        Mon, 12 Feb 2024 13:40:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4c16:b0:6e0:a33c:74ff with SMTP id
 ea22-20020a056a004c1600b006e0a33c74ffls2073833pfb.2.-pod-prod-03-us; Mon, 12
 Feb 2024 13:40:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUeufJUpG91N1QSewhb8Q7CEtUSg9WvYmXYqgN2RuGBWXXMAanCJSWYV1qzasFOigLbWcugX27uiisdGcxfnukHrN1JyfCxLNCsZg==
X-Received: by 2002:a05:6a20:9d8f:b0:19e:8ad2:c934 with SMTP id mu15-20020a056a209d8f00b0019e8ad2c934mr12019336pzb.14.1707774019485;
        Mon, 12 Feb 2024 13:40:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774019; cv=none;
        d=google.com; s=arc-20160816;
        b=qUeCT1ro2eZAxYh7rCrwdqFgYA1dhjvsKJ1I+RzS5NUVx2FbOGU50AFgk8aFAYEhlf
         yeBgR6Fy8zgH4Sb/5nlp7by1gSqoPjkg6UdoI8KJoVfAU7j3eRyLkFTBDIKDGeipvw+1
         SX5HfXAUTMgbU20E6i2HtrOhS2gYj6v19C9egj+ClpBcvBlEo4BWzE+zWnZO+wuw5dYL
         ga2n0slLLxqM6AA5S6Cwrwb584RSl1T30afz0wR7QBekeVOEW27dq8eR3is6SRWLp3Rz
         10HwrlSn+rkmKv4YbsN7HQ5GeTz6GTNcqvw3/0CgeV05XBCFcjfdQCTIZ1LhID68VCUt
         0QoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TxFmyXLHYuBt1ZmWD3OCbH5m3f76lMQsgX1qwMm0SnA=;
        fh=8B+Yck6mmEHxqBAEe/r75DXQhPla5LlfDT+KwzdjiY0=;
        b=gs/utRgAtYnuuZe2P8Z1vveMum2aaURaNTkLLRPle5+Qbbp81OKjZL2F1wC1Pl0u2u
         H/lD43laDFCxnbZ7dsQdPWjaPuSIIyM2v+cJ+cUDe0GXPjjI3nGTqyc3QxcSxSCsmJQh
         FKusEzUJdteq8XiORrmgbmHHok3eRfqsRwEvcI9KZzTnwYOyf5Wd71EehR3GzV4z8/Hh
         8gS9ugBOf9HxUlxkvrlBNXiIrv6GZ/WnOFF40auXZiUZKz9kyhkLGNkTIN3eWvY7KQek
         jS7dfI3bW2UYjqfck5vv+UzSioDFB8tbu8LUsYDHGicSpn4tPIXOyJFTcARmWAr5EngU
         3iUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jVlhq+3g;
       spf=pass (google.com: domain of 3qpdkzqykccez1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3QpDKZQYKCcEz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXXdghI8d1TAXeuvLvcFL9LVhvxhkMyJHYEhpX2o7WjymcCzzgYHwkcRBDSkNirD4W6Dq13yC+Ki5+TZ+D6zI/8UCAfons/aglJng==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p6-20020a625b06000000b006e06c8a8c7esi1189706pfb.1.2024.02.12.13.40.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qpdkzqykccez1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dcc58cddb50so292161276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWwxtRHBN2mQ8p1F/sml/kKvOpYkFBPxh0ZOXBGlTv8nv1lNSGBsjmo2wtMQG5u49qce24xBI3BcSgxT/rgW86TyXCMji1lo0cY+w==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:2291:b0:dcc:5a91:aee9 with SMTP id
 dn17-20020a056902229100b00dcc5a91aee9mr85473ybb.7.1707774018612; Mon, 12 Feb
 2024 13:40:18 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:07 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-22-surenb@google.com>
Subject: [PATCH v3 21/35] mm/slab: add allocation accounting into slab
 allocation and free paths
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
 header.i=@google.com header.s=20230601 header.b=jVlhq+3g;       spf=pass
 (google.com: domain of 3qpdkzqykccez1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3QpDKZQYKCcEz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
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

Account slab allocations using codetag reference embedded into slabobj_ext.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 mm/slab.h | 26 ++++++++++++++++++++++++++
 mm/slub.c |  5 +++++
 2 files changed, 31 insertions(+)

diff --git a/mm/slab.h b/mm/slab.h
index 224a4b2305fb..c4bd0d5348cb 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -629,6 +629,32 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
 
 #endif /* CONFIG_SLAB_OBJ_EXT */
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+
+static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+					void **p, int objects)
+{
+	struct slabobj_ext *obj_exts;
+	int i;
+
+	obj_exts = slab_obj_exts(slab);
+	if (!obj_exts)
+		return;
+
+	for (i = 0; i < objects; i++) {
+		unsigned int off = obj_to_index(s, slab, p[i]);
+
+		alloc_tag_sub(&obj_exts[off].ref, s->size);
+	}
+}
+
+#else
+
+static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+					void **p, int objects) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING */
+
 #ifdef CONFIG_MEMCG_KMEM
 void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
 		     enum node_stat_item idx, int nr);
diff --git a/mm/slub.c b/mm/slub.c
index 9fd96238ed39..f4d5794c1e86 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3821,6 +3821,11 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
 					 s->flags, init_flags);
 		kmsan_slab_alloc(s, p[i], init_flags);
 		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+		/* obj_exts can be allocated for other reasons */
+		if (likely(obj_exts) && mem_alloc_profiling_enabled())
+			alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
+#endif
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-22-surenb%40google.com.
