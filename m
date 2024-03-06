Return-Path: <kasan-dev+bncBC7OD3FKWUERBIHKUKXQMGQEDIGJ6OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id C7E05873E94
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:37 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-29b4becb184sf2526402a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749536; cv=pass;
        d=google.com; s=arc-20160816;
        b=rDS43BQQ+ktZk9KJq/nkEw9L6veB9FqGRWGFzYGrjSgsKGo7UoGZcVsu/RLdN0gwlg
         EfGCq6w9YsxDOzfQQarBfV4v41ioaUqFqQNizD9m0yYsja9FDtoUznv6GcrQmOGp/2R8
         2HKutr9OrkLvG3hHY7840yljhXs8Mta9F5BkW6kCZAt+R5DgX1WHBvWXJNLx9U1UgHYP
         WRB/+6Mb4WYnK/jQ3kHqOP+/DPw0V7tQ4BvkOgpXlSyqJ6m3WBVUlB/74xCj9R9HqleE
         AZaHI59nIzTIvzh5cYgyavfUAZsORflQqy/if7NTNH8dK9eYQjLTf0ZB5mQX8aGMf7qo
         MrtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tvGRIh00/8AcfWo5kiS+wCi9cMRjUDO+K00EYrME7oc=;
        fh=yO4yxCK39oNSzzgIzXBOxpG9vdE75y7jzwJLIn2x9hw=;
        b=dyPbNc6mW+WBbpIWsBFchxyOEiagiVwYefzQtNJ76JTrD2VjB/7ZmBlm3HMdDvstKK
         yYPS5IkulyVBmw62fj+gVFIOeY7taD6HMnhJ/eTkvdEzUpomX57rvmIIcjNNYHHE3G2z
         7fWC/emJe77+awmvRe9hET/hqNWBNCF1WcIzEFw59Ny33z2NoYF7NT3ZHNehmMnwnKhu
         ITNB3sEflchkMEZH6w2OGtr6BxBREGhZGMASQdeV8awLSrztgkee8UnokdM4c9sESEfc
         AOiPvR3UoEmBl7DtflP3kka+7ECu7WxB5C0SaKR4dfa4FnClmZWKOzDhBLAjCUWe335u
         epZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qmWlZt9j;
       spf=pass (google.com: domain of 3hrxozqykcwertqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HrXoZQYKCWERTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749536; x=1710354336; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tvGRIh00/8AcfWo5kiS+wCi9cMRjUDO+K00EYrME7oc=;
        b=uprsT+EddjD3xR03R+YEaqxkosc2Vrg1hbViLjc/Jpj3U91CjVGg0z8dYllcvTY2Dq
         mB8skpWMPVrq7SzKF/izSD8s9yPTdzcENFuR1VlIvbs+IpsTQR+tFermtcipNtTCauxX
         eWXOZGz7RX8KtaQtkY6V0XJQfRvjg0penKATMEzBnkM6vYo0rMmBTu67PhA8ytESiIgo
         a2zkKRcwo3bW3uhU4iBgRB9JSlywL/7OHlfRCDfA5cnzLAUGQ4kXrhXHAlRudLbdlnw4
         L6cvbk+JAAWBxkYyKqCdIGzvY6maDYqqskqsO+w0/64kPcJ9uuDcEYUXnj884Xkdbivr
         v40w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749536; x=1710354336;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tvGRIh00/8AcfWo5kiS+wCi9cMRjUDO+K00EYrME7oc=;
        b=vMQChiRE/avdf1Yu61z00zHr26dHeS1Q8MZUuodvNjvxFDvf9fpXMFC4u3FQsNuryc
         GteQHsrr9+srBfMEolFleLvn008/KksRXvsSLBq3WnStVT4/tvMNfgDoF46bK6z5f1pa
         q5B+yLEG4yciistoPWohY1B4v8iQgAA6VyICsp6EZBF20JegTtBNEqyoXURciPBMgqLD
         s0cDUrIfiFZPsUKtDg+5x7EJr3ENTe/6GUyCQszSVaBwSwNnl3EZZqrQbf/eE79UZAzU
         pQub1EKbkViH+pYbRVhMu5ku1vhb3wHpE7DIAfgCx1dpvUapRhF2CR+VxzAMZJmi/cni
         XnYQ==
X-Forwarded-Encrypted: i=2; AJvYcCVtlpS7s5lKEhbHsr3ducc+ZUkCOZ2BW1HHog+cdlt4AfjI0qHi2O69STIuiJzwAVme/0LA1615aemUcEoQ1F5iZ8NBLv51AA==
X-Gm-Message-State: AOJu0YzqA7hKh58e0SgMMOELNeJ2HBVcL2LanlolGLwidCc+AXhZsbYj
	9C+vYz+WFnbAbpNlvl9akNlLiC8sWS2MJ2ho9pQn+yfWBzrPqBcZ
X-Google-Smtp-Source: AGHT+IH8TiCOYK7CAPeXnypjrusK711j/WJ7rLrx5CadR7kxmLGpnIf3Ey1zorYNE5N4DkRXfz9sFQ==
X-Received: by 2002:a17:90b:1bd0:b0:29b:3d08:c644 with SMTP id oa16-20020a17090b1bd000b0029b3d08c644mr9805591pjb.9.1709749536480;
        Wed, 06 Mar 2024 10:25:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:394c:b0:29b:5530:e6a7 with SMTP id
 oe12-20020a17090b394c00b0029b5530e6a7ls54347pjb.1.-pod-prod-01-us; Wed, 06
 Mar 2024 10:25:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXh1MBcEuiIQgQp85HjwvR0PzjrtctGjKdPSee1nJF8CBcwrcHh3Itv+yb9QFacD0ALUTv5WciUxe7wCPhf+VbEu9sdAmx5VoIAPQ==
X-Received: by 2002:a17:90a:db91:b0:29b:2945:d51d with SMTP id h17-20020a17090adb9100b0029b2945d51dmr11243321pjv.27.1709749535375;
        Wed, 06 Mar 2024 10:25:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749535; cv=none;
        d=google.com; s=arc-20160816;
        b=ifzABMhwrzfb1AmsSWe0/gofhpMyMDAQ4lRxBroPNeOlCC01NrauDrKUwL+DdamiTL
         az2MXDFl0Oi5wSeJw6SrU0suGtd4vV7yaRy6hhGuRZo2Pynl+oCXtYXygb3AT6sBfl59
         70NmVbE7l6F9zGP7NAZ6i1phW+XOKO6tN/sA4iKgNgpf1Wj/xYeJ0jeyBD0aIODj6UET
         Kp7yiPCq3J7elziHKspg+wzNGeqdXQtGOx7rrAtZGS56x5A2ks+a6FydzilH2R3ycqR7
         1w/IKWsIRaOAPOcOpNa8HGdX/yLI9Zvd+SbBvqTFKEL6dL18VmsGw+sZgi27udeCJx+y
         I9fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=s15jajKF49lJj6S4Z8eIgzY9HreX5MNZRA5AU2XXX3Y=;
        fh=8Jj3bSEHBFql1u76723AaGAqoeVDaACeHz7EhGvyVgc=;
        b=Pj6SWjNnAGHPbPrpuEMuwoVV3pj3YH55XThqkaHcYk1dkIQQzK12t4igWlAPyI+ysG
         67cmBVIu0kOwPK5yQf0OMVgHlYWwBDYe5CzSw9HTM7xUzozT4DLHxMPJNtYCR+JijLTV
         Qgb76hdv/1ieBNKNAWFvTECB74J1wfDbDXbLFiKdBhDUhUtnjhXpmVacSen6KIUqJBa8
         I6tIpuAcW5oV9nLRkA/EleYxQ04gDydwqcM2WnpaD0WV6b3T9qFsVDKJ5pgrCAgv6Wto
         vORDojgEhZ+IFQ6tZav3OTBNENF127w8DPKfDSb+DrCLFLvj9wXOZ6gNhXPLp5bNcWHi
         Q4bg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qmWlZt9j;
       spf=pass (google.com: domain of 3hrxozqykcwertqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HrXoZQYKCWERTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w2-20020a17090abc0200b0029b2d7a777fsi5096pjr.2.2024.03.06.10.25.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hrxozqykcwertqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6096493f3d3so128167b3.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUpMbzivOs5sbuNEr6XZH2vr1i7VO6DZKrx/OfOZ6zmOdzk0Nz8+omdiqrgFM/rC4cymFCbLe/yZCZr8l9GTCfwtcXR2CfzvtkQhA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:82:b0:609:78d7:4e9 with SMTP id
 be2-20020a05690c008200b0060978d704e9mr3296801ywb.6.1709749534383; Wed, 06 Mar
 2024 10:25:34 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:21 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-24-surenb@google.com>
Subject: [PATCH v5 23/37] mm/slab: add allocation accounting into slab
 allocation and free paths
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
 header.i=@google.com header.s=20230601 header.b=qmWlZt9j;       spf=pass
 (google.com: domain of 3hrxozqykcwertqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HrXoZQYKCWERTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 mm/slub.c | 91 ++++++++++++++++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 90 insertions(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index e94d3cc1b270..ea122aeb89fc 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1942,7 +1942,69 @@ static inline void free_slab_obj_exts(struct slab *slab)
 	kfree(obj_exts);
 	slab->obj_exts = 0;
 }
+
+static inline bool need_slab_obj_ext(void)
+{
+	if (mem_alloc_profiling_enabled())
+		return true;
+
+	/*
+	 * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditionally
+	 * inside memcg_slab_post_alloc_hook. No other users for now.
+	 */
+	return false;
+}
+
+static inline struct slabobj_ext *
+prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
+{
+	struct slab *slab;
+
+	if (!need_slab_obj_ext())
+		return NULL;
+
+	if (!p)
+		return NULL;
+
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return NULL;
+
+	if (flags & __GFP_NO_OBJ_EXT)
+		return NULL;
+
+	slab = virt_to_slab(p);
+	if (!slab_obj_exts(slab) &&
+	    WARN(alloc_slab_obj_exts(slab, s, flags, false),
+		 "%s, %s: Failed to create slab extension vector!\n",
+		 __func__, s->name))
+		return NULL;
+
+	return slab_obj_exts(slab) + obj_to_index(s, slab, p);
+}
+
+static inline void
+alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
+			     int objects)
+{
+	struct slabobj_ext *obj_exts;
+	int i;
+
+	if (!mem_alloc_profiling_enabled())
+		return;
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
 #else /* CONFIG_SLAB_OBJ_EXT */
+
 static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 			       gfp_t gfp, bool new_slab)
 {
@@ -1952,6 +2014,24 @@ static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 static inline void free_slab_obj_exts(struct slab *slab)
 {
 }
+
+static inline bool need_slab_obj_ext(void)
+{
+	return false;
+}
+
+static inline struct slabobj_ext *
+prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
+{
+	return NULL;
+}
+
+static inline void
+alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
+			     int objects)
+{
+}
+
 #endif /* CONFIG_SLAB_OBJ_EXT */
 
 #ifdef CONFIG_MEMCG_KMEM
@@ -2381,7 +2461,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
 static __always_inline void unaccount_slab(struct slab *slab, int order,
 					   struct kmem_cache *s)
 {
-	if (memcg_kmem_online())
+	if (memcg_kmem_online() || need_slab_obj_ext())
 		free_slab_obj_exts(slab);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
@@ -3833,6 +3913,7 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
 			  unsigned int orig_size)
 {
 	unsigned int zero_size = s->object_size;
+	struct slabobj_ext *obj_exts;
 	bool kasan_init = init;
 	size_t i;
 	gfp_t init_flags = flags & gfp_allowed_mask;
@@ -3875,6 +3956,12 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, init_flags);
 		kmsan_slab_alloc(s, p[i], init_flags);
+		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+		/* obj_exts can be allocated for other reasons */
+		if (likely(obj_exts) && mem_alloc_profiling_enabled())
+			alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
+#endif
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
@@ -4353,6 +4440,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, &object, 1);
+	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
 	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
 		do_slab_free(s, slab, object, object, 1, addr);
@@ -4363,6 +4451,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 		    void *tail, void **p, int cnt, unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, p, cnt);
+	alloc_tagging_slab_free_hook(s, slab, p, cnt);
 	/*
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-24-surenb%40google.com.
