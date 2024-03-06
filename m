Return-Path: <kasan-dev+bncBC7OD3FKWUERB77JUKXQMGQE4CBNVUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B5F9873E79
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:05 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-36531d770d1sf75660615ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749504; cv=pass;
        d=google.com; s=arc-20160816;
        b=DNwm1RvMutWkOZ9x5Vim0j3dpt3jedm/8UdYlQgNjchuQr1iJXbEwyrTDPizNO4Dr+
         ejmQxIvggSWFnNo1XOO6qnXznQHyfJusktpjPqe1n01s0WtBGLKs/BqNgNtsqV+JLK4r
         96/IAzgPv4cJ78tNffIgj4Llev4+H6++AGSTA3aM3pdfEKstDqonO1gCUsdO54hcUZGr
         E+bHV887e4VzyEFBEZ2GRceWcRm6YS/vCBruFFDqtZ+13Fyy2RPaXkREMgcRmHRQi+CI
         eOuqMma9/NFLcj+3+pFYzJEes8kZmFm9F7Owb7GhJLCqW3O4p5ve27jGYpohhX5OIrAM
         TU0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=hQD4mIxJEFp3US5GkjZSah2cqvURPaFLBJ6SjWfbqHs=;
        fh=aI9dg8I06amuzs6lINoDzFwdzmP7U7vP3jT3k/PpFmg=;
        b=KCppKYemQDDditQmi7l10Std8p0CiUBGJlQVHosDEbbDNYqLCsRaI1vW4FsTjaaqH2
         2reCs0p30chLyIJYwgF0yDT23c673z7KT6r8Jt3c8sFquU2VAlWPfj1yrtrJkzJtIaM1
         aXupnMYaZofLwFrqfcbNdWjw0xqM0c7ipNLs/t3yKbKF91sJuyMVUMaZovnsGr3XtQk9
         Ul0KQmshPch7Dsbd9nJCzKMmaJdBgjcNBLTzy4EdJTN5vKmDP1DXvoUViEuotDdngihS
         iZhVfkmNbdWLW4RzlhL4tq1WPOHDn9LmQ1Wgf90XgPbe7wopLEDf/Yf0nPYrN9rajpdt
         x1Yg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A5CMu28t;
       spf=pass (google.com: domain of 3_rtozqykcuevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_rToZQYKCUEvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749504; x=1710354304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hQD4mIxJEFp3US5GkjZSah2cqvURPaFLBJ6SjWfbqHs=;
        b=Q55fiOCwhJPAkPBYXOH4nGVfwGxnj4FFciIUcH2F3y54A6LZH7njxXHgMokITwYbIJ
         ULYRdHzScriYTl+mXsR8cm7Sk342/SbwGr0XszOjCUJ2ah+KgmtpxiTdKrm7AqeCu264
         LK1C/SFaZK53Hyec2Vqu4jy8eaLLuRV9HEUkhv9j7DJeFXrzRJoG4y6dm68SpwGPGsSh
         co3VtXah4f3QoFk4j2V0EHIcN0Y8Ie/ttU/LfmOpxchxhjuSzi63HKomC5y1JCU2Uucr
         WtlJExWfTQziaYGfxTnvoj03neokTJJYiHq5sghq/FEMsY4j4EBm3nsfoZzFavQy/WjL
         pVVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749504; x=1710354304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hQD4mIxJEFp3US5GkjZSah2cqvURPaFLBJ6SjWfbqHs=;
        b=DyfTenIGDvjIubAZHhK9NsCn0DA0VQm/pVlpmq+SBjQkDf/mfE0zJV9ye1HrVJoEA1
         mul1DSHX9ZkFhvvGw2kKxYyZF7lY8wqQGFZNWpyKpDXRfRtkJO/ubZOlC6T1pRhrwy7R
         5+0D+cesQMIep7A/qhp81Zabz+EzRi4cMcyXv6s334M4W9rzr5xpAsqj+CbLuiZQUzYU
         tBubSYlhLSKPefXYI4rfPSpG5rcQzCQ0dRWQiahEmQmvrsOiBn1CSM2LxFdKLOVzQGEh
         OULmThHIcZWs1SbsJTrZ6PvPoltodPZfNSVCpdt5fbZ7VRodjDxu+4ZaO+Xz2dSQMux8
         wOvQ==
X-Forwarded-Encrypted: i=2; AJvYcCW4z+qHXd71GO6V8/j7c0vwHVDHF/e7q4b08dA/3nTRQUwcuKbMmguSCgkE7jCxGolivYb9gJBj5xTO3HIWf6Tr31YxzpOQWQ==
X-Gm-Message-State: AOJu0Yz9vofiW1w6Bf36wtWah976oAIS+pgbsCSs0Phwb/N6AcBF7gGP
	OGgpSd7cEhzfDVf0vJER26+dfcZ9kJhu6fLyFY7A9Iim8taNvS5W
X-Google-Smtp-Source: AGHT+IFhFzJYDG3LwRzkkk96Y5ykft9nx3b5XjrlToOezRuDgo05YBSkHzVW+3myncXOglJTZeoJtQ==
X-Received: by 2002:a92:c563:0:b0:365:46a0:dc84 with SMTP id b3-20020a92c563000000b0036546a0dc84mr20752883ilj.21.1709749503689;
        Wed, 06 Mar 2024 10:25:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d05:b0:365:a664:c570 with SMTP id
 i5-20020a056e021d0500b00365a664c570ls119881ila.1.-pod-prod-02-us; Wed, 06 Mar
 2024 10:25:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXpQsyRluKIGoQJdmBVbgZna9WkUUxFpYhf2XWicJMGxIMcdJlpiqWrnC+F1uGhVtqFGA8owS2WEV9Sy9ZWaCfMW8y+mkS2Jsmjvg==
X-Received: by 2002:a05:6602:e45:b0:7c8:28d0:e205 with SMTP id gq5-20020a0566020e4500b007c828d0e205mr17026708iob.4.1709749502811;
        Wed, 06 Mar 2024 10:25:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749502; cv=none;
        d=google.com; s=arc-20160816;
        b=O+IatrN3yUmDrlzQhky3O8wrVc+RAerfphfxZLazRPoPJnCIluExG/c2Prp3mDzKWB
         0fFGHa4ByGdCZ/m+HLsA+LzxEWSUKYHCqV61BckTXNjj02IEV9uoo8aBgyQE0Qf4u/YV
         I8AI1OcQiYrO3R3xqjDaFsankU0wGHshSY0ZSqkBfuD19xQcZSi3f/mGlUA1zjQDWbfh
         IJsBGBCwUZhO+Fui3PdLX5SlefTU6BqNR9kA5S+mzNQRz/HpD2myAu/qgkI/mETiV50N
         2dzNIF/VyJJ0O4eeSO5Zt8YjlF4YgD+me+3X2lJZbzccL7MFZGkociLbHKZZsWVee8FC
         KHBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=MWCYv1v0m9ThdSU1Yjo1XvUgYihcegNMceRH273060M=;
        fh=DX5Di9QYFXvorgfL7JtluI04KjfjEcV9d59h8L87m8c=;
        b=0zsNOgZk9E9VO0XN748GsAA4JSUj16BUenCe+eSW94eW9rVW/YiN26Otc3g1KfXTuc
         dYpHxBR/HGLmgOYa2teGIQFqOXEs0Fa2ohmISvfY7yrKfq+RTjfJBKNQoSAX+hQC7Qqp
         bZNWuaqDIsujgfG4xqOi5/jUjmlJVu8Df2Ifk43e7rsxiYDdLMF1hINPQVkqfH5x3rml
         uQlz9p0jUJQ2asDNpTCHAhM0z7a9KrFYLHrdXSP5ANqENzHNSigTMXbMIaVL0ViWpgti
         DM2/FVKkWT1BUe9m3ceb2sFdcu37My+AG9ISzHiSbysFSCgopU2x+wy4eD01vrvNLqfh
         7JHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A5CMu28t;
       spf=pass (google.com: domain of 3_rtozqykcuevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_rToZQYKCUEvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id y136-20020a6bc88e000000b007c877546a32si204598iof.1.2024.03.06.10.25.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_rtozqykcuevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dd0ae66422fso199142276.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU95/lFUaAG/K+GTiqbmleXrmnlHH69e2tzaUiDLogf0EkZnTL4lno4+aOzAhei1bICnRpGdA5S3A5IsZ0YMkVc7uZEgsQVcBE7gg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a5b:54c:0:b0:dc7:5925:92d2 with SMTP id
 r12-20020a5b054c000000b00dc7592592d2mr1248065ybp.1.1709749502066; Wed, 06 Mar
 2024 10:25:02 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:06 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-9-surenb@google.com>
Subject: [PATCH v5 08/37] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
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
 header.i=@google.com header.s=20230601 header.b=A5CMu28t;       spf=pass
 (google.com: domain of 3_rtozqykcuevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_rToZQYKCUEvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
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

Slab extension objects can't be allocated before slab infrastructure is
initialized. Some caches, like kmem_cache and kmem_cache_node, are created
before slab infrastructure is initialized. Objects from these caches can't
have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
caches and avoid creating extensions for objects allocated from these
slabs.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 6 ++++++
 mm/slub.c            | 5 +++--
 2 files changed, 9 insertions(+), 2 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index b5f5ee8308d0..58794043ab5b 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -28,6 +28,12 @@
  */
 /* DEBUG: Perform (expensive) checks on alloc/free */
 #define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
+/* Slab created using create_boot_cache */
+#ifdef CONFIG_SLAB_OBJ_EXT
+#define SLAB_NO_OBJ_EXT		((slab_flags_t __force)0x00000200U)
+#else
+#define SLAB_NO_OBJ_EXT		0
+#endif
 /* DEBUG: Red zone objs in a cache */
 #define SLAB_RED_ZONE		((slab_flags_t __force)0x00000400U)
 /* DEBUG: Poison objects */
diff --git a/mm/slub.c b/mm/slub.c
index 2ba5d7b2711d..e94d3cc1b270 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5704,7 +5704,8 @@ void __init kmem_cache_init(void)
 		node_set(node, slab_nodes);
 
 	create_boot_cache(kmem_cache_node, "kmem_cache_node",
-		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);
+			sizeof(struct kmem_cache_node),
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
 
@@ -5714,7 +5715,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 			offsetof(struct kmem_cache, node) +
 				nr_node_ids * sizeof(struct kmem_cache_node *),
-		       SLAB_HWCACHE_ALIGN, 0, 0);
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	kmem_cache = bootstrap(&boot_kmem_cache);
 	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-9-surenb%40google.com.
