Return-Path: <kasan-dev+bncBC7OD3FKWUERBUEV36UQMGQEWS3EN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 056137D5227
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:46:59 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-581ed663023sf6680323eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:46:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155217; cv=pass;
        d=google.com; s=arc-20160816;
        b=vEkE5gqmbE+2HAtZD1MhYqWb7JAfQonf2tMGJit496cpBcCLc+rMc3HJhRvc8PxD+T
         W3R7h9aw5weoVWH/rqvLnnJTVUirjHjdX3Ye0Qanl6HkiJy23DCYWyRWCChARdFmkiVM
         KlqSF1xX9Rvavdod8woaOXwobLZbNoLFYGzLi/6F3EaZWc3lWGYkNaavqNa9rFwLAVHB
         OsgFjVLcqzwOZ+SBGgUV/44kbozZpGfXt+pjlQG9HdggX9Qe9AUSdwwoQgwtXTlUHj4+
         rkC0YphzGEaeec7BYjCThaZiUsMLpVm3mEC9BQtfLvxrFUFSi7LbrMHh7+HFbXvOU/wQ
         y9bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BHbugWNuTHIWHufawTv8IObZ+5A+AcSt4RRwzvA5crI=;
        fh=Uc4NTkU4JpYTxnvS06tzSRaYxCh98zFxfZDlD3CFRKw=;
        b=YsgHQtr9jY0Gh6VMkM4FG1w5k6mBSxjX+iWQbXs+b9Gv8M1+32htvc04jvK6uATo0m
         WhLnbQNsOmgM3jW9PWD627bFwiGHKQaLidNIyZL6VUKEBfqneYLYnN60IvsiTgMoPFQa
         JRyjrkABBowYeTpddOXJpCX5rDB2sKvtnNCmvqDHIqT5qf9LjgamoW/1t+jx54uFHcRz
         6Dy8JLgCM8zZRRVSIlJ1t0yxs/iilODM/Ki6hoo81oaDHeVyDBcVX/ed7ZsEYXhGemmv
         W54L+LDPjFfN1ftsnnx4C/0FHODIKsAx5zb2ONn9pgDZlQEJCgQiXweIsXvnLoA9vL39
         CqoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZksBdUL2;
       spf=pass (google.com: domain of 3zso3zqykcxmjlivesxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3zso3ZQYKCXMjliVeSXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155217; x=1698760017; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BHbugWNuTHIWHufawTv8IObZ+5A+AcSt4RRwzvA5crI=;
        b=GyAgrf6DyWBVdkC2mmHV5IdBKNFP2Qg55cCZtsgccKtlYcNo+ftqnveENJHtZBA+XP
         bs7xu1ERYH+UShUrFb14SD6ugfBJfzAvsV60yXfcV0LsYEaefz+2ksPxrnP6e+kDsrl9
         Zu98ZZ8HXc2muLa+huGuo9GO8YBvgLGPhHOP2obDchxsPEZXS4KoJAzt9o/OsohDjY3x
         iWefFExDirNcRHNoG5lxheUuBalb2r+sBYzDUhang9bALi+gyrGGlWxXyGphSuTY57vH
         fe6d+hSa0VVjyycKbTgVWzRUw7Vu4kFDCwKpP7NdgltR+EjqvHZdH7DzRY+czP3c61IB
         XFPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155217; x=1698760017;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=BHbugWNuTHIWHufawTv8IObZ+5A+AcSt4RRwzvA5crI=;
        b=C5pSNjwuyTxUsij0Bf3XqS+9fCZdw7MzsodBl/sMbW5aF15mUxqEfiyIdFLtkf+pxp
         FWV10fUw57gd3fExdL4VaFAGNKgPilkCwvkP7HMkh1Nhfelb9be47TkqV9aoNCtecjz5
         vPpJprlPiz7EfDT9qPgFpU2kNTiidr2bZI791D4U5enVGzAWrFj27pDry6UTUR+nW/4z
         V3DkRsUHB5pn4W0OIJ1Q/Cydkdtk9DBvb9cxky3gtYYFu+QfWHADPFcFXGtWqzzTefJr
         m+30K0BiDH4d7CKSOq9iDFsyko9Hcn7xxcioeV6I3zmH0TXFnPpaFgVmFynb8uTSg8W3
         Sidw==
X-Gm-Message-State: AOJu0YyrwHV+0EMNO1bR5+kGoE1twVbiiNgDsZhPjjOggloMaTi4gNdh
	sSoq+3X2/Z/y/w8NDeeP3og=
X-Google-Smtp-Source: AGHT+IEmdFkcbFjhnrF5FeprJT2QwfsYMzXvBoc3/sI9Yrs3a9yiUIkFMTAFsfPNRr+BSggC66TXJw==
X-Received: by 2002:a05:6870:6719:b0:1ea:183d:ff65 with SMTP id gb25-20020a056870671900b001ea183dff65mr15825514oab.35.1698155216137;
        Tue, 24 Oct 2023 06:46:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2b0b:b0:41c:bf76:6740 with SMTP id
 ha11-20020a05622a2b0b00b0041cbf766740ls4656522qtb.2.-pod-prod-03-us; Tue, 24
 Oct 2023 06:46:55 -0700 (PDT)
X-Received: by 2002:a67:c190:0:b0:458:8ef9:a27d with SMTP id h16-20020a67c190000000b004588ef9a27dmr9015236vsj.20.1698155215267;
        Tue, 24 Oct 2023 06:46:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155215; cv=none;
        d=google.com; s=arc-20160816;
        b=K39TnY0gpgFetjofRDy7vp/I2o2Qfqa0Uv36YZ/Tg4t6lkdiw7nMGbMAMELhphP35f
         RrU0GBaHg7FkF+yWTPwoxh6fCPWa+TPUTO0SPujevoHYKpZJcLDdsoRVUTLkkBvsVdp/
         8MobBpqdCNRCkibuqoCNCahezCkUU6jEIXYJnYxN6UE7gjI1AaJSVkRG7HYka2BQXxVa
         Kk34iRE4hzPTj8dYcmGaNFZsFfzoshYGiaJO6bbpHGken0alC2xOpcdG5uLu+aKZhg9o
         FsNw1bIsO07Jp7hW2bYDbBGnbBlJq1s6RLR6cWoYqfOc5ZkkosCjRoOQaASUqRCBrdfR
         LmPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=X9FRyOcPx+PqvPwKi5hgMRq683fi1N6H4UQ0tqouPmU=;
        fh=Uc4NTkU4JpYTxnvS06tzSRaYxCh98zFxfZDlD3CFRKw=;
        b=hpTtLMdndN20UFQ5Gn9L6LYaHGeTN6YUzG8TrWaWqpxz7gRzQmIYKNJ8TdSFgbR9dv
         WGcvJXV84GQF0LlACJvsHkGQWXchlOabl/36dc10CWRPb3oz94WchmIrLof1GONL8sty
         lY50CbSOFv75gG+tJwMSM4Znwpy/QLyPrS4GC2JVGe3+vKG/ZYYECruaDwtlCbDMhHzu
         Vy7w92Ikfd8R9DqOoxgDdVqqqaP2tYrJvwey8w5Hd9OnxscR665zh91vOtkBPE5nrMNJ
         ieJUcY1b4IfOzq4o6hvK7QplvNpmeyn7mIjFZqlpH6PFVFvzv9GwK+zCnHPEu84vGF1S
         sIYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZksBdUL2;
       spf=pass (google.com: domain of 3zso3zqykcxmjlivesxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3zso3ZQYKCXMjliVeSXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id k20-20020ab07554000000b007b5fcda34aesi362329uaq.0.2023.10.24.06.46.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:46:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zso3zqykcxmjlivesxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5a7aa161b2fso57966907b3.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:46:55 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a0d:eb8a:0:b0:5a7:b496:5983 with SMTP id
 u132-20020a0deb8a000000b005a7b4965983mr249771ywe.9.1698155214761; Tue, 24 Oct
 2023 06:46:54 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:03 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-7-surenb@google.com>
Subject: [PATCH v2 06/39] mm: enumerate all gfp flags
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
	cgroups@vger.kernel.org, 
	"=?UTF-8?q?Petr=20Tesa=C5=99=C3=ADk?=" <petr@tesarici.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ZksBdUL2;       spf=pass
 (google.com: domain of 3zso3zqykcxmjlivesxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3zso3ZQYKCXMjliVeSXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--surenb.bounces.google.com;
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

Introduce GFP bits enumeration to let compiler track the number of used
bits (which depends on the config options) instead of hardcoding them.
That simplifies __GFP_BITS_SHIFT calculation.

Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/gfp_types.h | 90 +++++++++++++++++++++++++++------------
 1 file changed, 62 insertions(+), 28 deletions(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 6583a58670c5..3fbe624763d9 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -21,44 +21,78 @@ typedef unsigned int __bitwise gfp_t;
  * include/trace/events/mmflags.h and tools/perf/builtin-kmem.c
  */
=20
+enum {
+	___GFP_DMA_BIT,
+	___GFP_HIGHMEM_BIT,
+	___GFP_DMA32_BIT,
+	___GFP_MOVABLE_BIT,
+	___GFP_RECLAIMABLE_BIT,
+	___GFP_HIGH_BIT,
+	___GFP_IO_BIT,
+	___GFP_FS_BIT,
+	___GFP_ZERO_BIT,
+	___GFP_UNUSED_BIT,	/* 0x200u unused */
+	___GFP_DIRECT_RECLAIM_BIT,
+	___GFP_KSWAPD_RECLAIM_BIT,
+	___GFP_WRITE_BIT,
+	___GFP_NOWARN_BIT,
+	___GFP_RETRY_MAYFAIL_BIT,
+	___GFP_NOFAIL_BIT,
+	___GFP_NORETRY_BIT,
+	___GFP_MEMALLOC_BIT,
+	___GFP_COMP_BIT,
+	___GFP_NOMEMALLOC_BIT,
+	___GFP_HARDWALL_BIT,
+	___GFP_THISNODE_BIT,
+	___GFP_ACCOUNT_BIT,
+	___GFP_ZEROTAGS_BIT,
+#ifdef CONFIG_KASAN_HW_TAGS
+	___GFP_SKIP_ZERO_BIT,
+	___GFP_SKIP_KASAN_BIT,
+#endif
+#ifdef CONFIG_LOCKDEP
+	___GFP_NOLOCKDEP_BIT,
+#endif
+	___GFP_LAST_BIT
+};
+
 /* Plain integer GFP bitmasks. Do not use this directly. */
-#define ___GFP_DMA		0x01u
-#define ___GFP_HIGHMEM		0x02u
-#define ___GFP_DMA32		0x04u
-#define ___GFP_MOVABLE		0x08u
-#define ___GFP_RECLAIMABLE	0x10u
-#define ___GFP_HIGH		0x20u
-#define ___GFP_IO		0x40u
-#define ___GFP_FS		0x80u
-#define ___GFP_ZERO		0x100u
+#define ___GFP_DMA		BIT(___GFP_DMA_BIT)
+#define ___GFP_HIGHMEM		BIT(___GFP_HIGHMEM_BIT)
+#define ___GFP_DMA32		BIT(___GFP_DMA32_BIT)
+#define ___GFP_MOVABLE		BIT(___GFP_MOVABLE_BIT)
+#define ___GFP_RECLAIMABLE	BIT(___GFP_RECLAIMABLE_BIT)
+#define ___GFP_HIGH		BIT(___GFP_HIGH_BIT)
+#define ___GFP_IO		BIT(___GFP_IO_BIT)
+#define ___GFP_FS		BIT(___GFP_FS_BIT)
+#define ___GFP_ZERO		BIT(___GFP_ZERO_BIT)
 /* 0x200u unused */
-#define ___GFP_DIRECT_RECLAIM	0x400u
-#define ___GFP_KSWAPD_RECLAIM	0x800u
-#define ___GFP_WRITE		0x1000u
-#define ___GFP_NOWARN		0x2000u
-#define ___GFP_RETRY_MAYFAIL	0x4000u
-#define ___GFP_NOFAIL		0x8000u
-#define ___GFP_NORETRY		0x10000u
-#define ___GFP_MEMALLOC		0x20000u
-#define ___GFP_COMP		0x40000u
-#define ___GFP_NOMEMALLOC	0x80000u
-#define ___GFP_HARDWALL		0x100000u
-#define ___GFP_THISNODE		0x200000u
-#define ___GFP_ACCOUNT		0x400000u
-#define ___GFP_ZEROTAGS		0x800000u
+#define ___GFP_DIRECT_RECLAIM	BIT(___GFP_DIRECT_RECLAIM_BIT)
+#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)
+#define ___GFP_WRITE		BIT(___GFP_WRITE_BIT)
+#define ___GFP_NOWARN		BIT(___GFP_NOWARN_BIT)
+#define ___GFP_RETRY_MAYFAIL	BIT(___GFP_RETRY_MAYFAIL_BIT)
+#define ___GFP_NOFAIL		BIT(___GFP_NOFAIL_BIT)
+#define ___GFP_NORETRY		BIT(___GFP_NORETRY_BIT)
+#define ___GFP_MEMALLOC		BIT(___GFP_MEMALLOC_BIT)
+#define ___GFP_COMP		BIT(___GFP_COMP_BIT)
+#define ___GFP_NOMEMALLOC	BIT(___GFP_NOMEMALLOC_BIT)
+#define ___GFP_HARDWALL		BIT(___GFP_HARDWALL_BIT)
+#define ___GFP_THISNODE		BIT(___GFP_THISNODE_BIT)
+#define ___GFP_ACCOUNT		BIT(___GFP_ACCOUNT_BIT)
+#define ___GFP_ZEROTAGS		BIT(___GFP_ZEROTAGS_BIT)
 #ifdef CONFIG_KASAN_HW_TAGS
-#define ___GFP_SKIP_ZERO	0x1000000u
-#define ___GFP_SKIP_KASAN	0x2000000u
+#define ___GFP_SKIP_ZERO	BIT(___GFP_SKIP_ZERO_BIT)
+#define ___GFP_SKIP_KASAN	BIT(___GFP_SKIP_KASAN_BIT)
 #else
 #define ___GFP_SKIP_ZERO	0
 #define ___GFP_SKIP_KASAN	0
 #endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x4000000u
+#define ___GFP_NOLOCKDEP	BIT(___GFP_NOLOCKDEP_BIT)
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
-/* If the above are modified, __GFP_BITS_SHIFT may need updating */
=20
 /*
  * Physical address zone modifiers (see linux/mmzone.h - low four bits)
@@ -249,7 +283,7 @@ typedef unsigned int __bitwise gfp_t;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
=20
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT ___GFP_LAST_BIT
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
=20
 /**
--=20
2.42.0.758.gaed0368e0e-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20231024134637.3120277-7-surenb%40google.com.
