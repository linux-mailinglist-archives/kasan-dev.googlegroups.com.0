Return-Path: <kasan-dev+bncBC7OD3FKWUERBV5D3GXAMGQEYTACGFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9351085E770
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:12 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6e46fdd68a5sf3012629b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544471; cv=pass;
        d=google.com; s=arc-20160816;
        b=DVnuYvYexjEzvTlhzPG8pB1YalCZTo6TCzOOpTPyzmjFtSl69otQWg2W3wPhhp0HMq
         vSZ5jZ/H5ZXffWirhfrbNf65Yw5+Lk+ghzSNPRm3lseFqd+b31m/WZjn0QaIqzLleM9j
         JLY/7NspeW9gaN2eq2DRKsrpQ8EF30HyDqyjhdeLKFnFXaTs71iSwxtgiScago/mQDct
         ceMR3Gpcmvad0zwpMVDYgNmwdOqf9JoJ7ljRi1lbjmze75PngCPzsocI0wLT9mI9KcJI
         Cz6BtOLKzd16TsiArrOQ/whtnwFu7+iEkwqJbaXogeLrIAD8N+nbnLukSIEUwwZ7Qokp
         D3mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=t51LJl0YL0KWFuRDQJCnqUU0rcTCKFftETeoN6izzhQ=;
        fh=86qy/RCgsGWSS7WMNkSpAoru1x5al52htrjq5MaXBRY=;
        b=rcE0GGRgItn3m1mDeNMdILnpRYOit+30BiXtqQSmbzNVFUA/+vqgimzt7p2/S36GF6
         4WzbFRCH2KxLs/mTDPbPlH1af4HYyTZi/KaYA2pFvEgQey5d+VSCD1jMwGTlXbFobP0r
         zz6NQv6qSWY8+4Q2XifOO+jCM3Co+uGLLaw59ay5EmgDbQB3uPVAI0usNWfZgYKBddwl
         0NkAlk+LtwUSEooHlyE2FSdkNxA4BXJG+9lRNJ36YcrmRs8M/k2EYETcNLajl3KLnDxz
         gkTNxLPWhN3E8tOgLzNiu5PKl+EXkbUgmsR/cB242xKqPwNuHfNCn0TbbAFhT878Hjnr
         /QEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IVW68x11;
       spf=pass (google.com: domain of 31vhwzqykcqg02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=31VHWZQYKCQg02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544471; x=1709149271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=t51LJl0YL0KWFuRDQJCnqUU0rcTCKFftETeoN6izzhQ=;
        b=AXE2ej6ES7+SnR+VmgatJ5Ap0qKhqfsU/x5IIhLvuyTv0mOaQ/Ngr/jouFIoD3gC3o
         0ckWD7Vvy4Mu9nJHiUtdPuunO3HGfsriEL+xISocOV76Z1rUEgZzrVrn/nHHim4UgQLx
         3gWq4aFyWp4t7TCRTOZJq8ZMW+jpHQeB9TO2tFH2KHhfExXgjOBkho85JLd+7g3Kt2WV
         cvSQWgawRFJy27+XhvQZgLTObUzciqLtcI40qe4v6MYNAzcKw2ut4wGHmn02eWDtx2tE
         /gpXY6VsYCEwh9PFAW1k9Far1bN9CpByGc5Szp6zn6qbcDiWowkhrSTw/GmKzD9pDdrL
         tUTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544471; x=1709149271;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=t51LJl0YL0KWFuRDQJCnqUU0rcTCKFftETeoN6izzhQ=;
        b=w20l8blE2oSR+WSnKXGaDaXUMq+FbuZzAuGfUCkylXj1ogc0+iS4q8AVYrQnUMCt8+
         TrO1nK4d2+O4oRAjUYDp/ImvOMk82RigOMQXO6YwhRv2dw/VN9Oe0et32ieX805CNpnl
         dx19WpBh2dfFKz0RfxOOSppdcYnPIlUZWaeIeC8yxkC59fuc8FnLcGyX6YDoG4NjU8ba
         sIra59I4wwCbdqHCH0ODlHop58GuVWFKhiGbl3RfZmpWjdgOdiC+wXIgydUq8+TtWAwz
         sJfaopEsMNhDZtX9xP0TDUyKim2xJcF7Tk5BGWL5zKaiRVk2rapM4AJ2E50oSv3fGAbP
         dcxw==
X-Forwarded-Encrypted: i=2; AJvYcCXxJmUJn6OT0TULFnk5QWcW1XAi0O5uM2yHCmIX4klTQLGzEFqYxq8usIVB7MQGk5fs+p0XaYnbetKiu/h6LQjeji9AbVgwzg==
X-Gm-Message-State: AOJu0YwaRJhPV1Ya1HECDwDsNgR0YypSUJnQZG/3+dEB2hm/nQRCbtdq
	e5HPcEAGSnfUJj+hAhnh0QD1GkAYgImTwstmVhTOuBJwQmnPhdMQ
X-Google-Smtp-Source: AGHT+IGNI3sQNwpDBlZRdYODaqClIo2BIpabV51hCcnUge1mhr2uWMNto5gXXyKP3y4CSwoJNQAx4Q==
X-Received: by 2002:a05:6a20:d806:b0:1a0:94a8:400f with SMTP id iv6-20020a056a20d80600b001a094a8400fmr12864387pzb.18.1708544471171;
        Wed, 21 Feb 2024 11:41:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3309:b0:6e0:f00b:3ffe with SMTP id
 cq9-20020a056a00330900b006e0f00b3ffels2431262pfb.0.-pod-prod-01-us; Wed, 21
 Feb 2024 11:41:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW+Tp6D4crwhYLGD7BawLgL1Iwd61gYAzhx6xvxYLwywH+Ve2fJK+hBCa5ZJIWcO+NkyfKSSXObZSXpxpjr0uLIZ0VA/k9fDCGoww==
X-Received: by 2002:a05:6a20:d806:b0:1a0:94a8:400f with SMTP id iv6-20020a056a20d80600b001a094a8400fmr12864336pzb.18.1708544470171;
        Wed, 21 Feb 2024 11:41:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544470; cv=none;
        d=google.com; s=arc-20160816;
        b=kLORjfuLDUVmgCGYy4Y5fGTifBAcbK87L5AqjIjuCF22pZLlxfDXWOk1Eq//PtsnIH
         BJD0GIOAIXWTOxbDexkzFA770DSRg3j0cMNQLFux0oISRD87znFIYG4Kqh6yzNKsgL7P
         tLIsPSPXzizkW6bZr1Ik6xFPcf+Bs+SlJB2jLOZfH4L2ZEHNyMxnrF6bty75hDRxzhkb
         5DmwpIM8vHE7lp7u8mOOlBstgNGYA8e/+oOuiW/5hIZPsoMXucmNWnB0kD6DcajCbGq6
         PWrYrdsFGR5SohECQRKoyVyrd1+Nfd22ou9YVx0moOmAIhTLpmqAiR5kMeDlyaFmdMPW
         ylTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=QzsUMX2xNFk2gXovx8vmt7vEJ3oqQRqP0H0Mn26pLn0=;
        fh=TSAmkGGvt0PGr64l5TqWSdBTltCdI8GjecIPPfXCp0g=;
        b=ucOcK4L3tmfl394rWLB1BQrg7pZE0jOQSC2cOtRG6nQrzLnx5NdkynG+poLoKcUVx2
         vcm4WIuzTsDtxmVj0o6uxM6YViI4cUGWzh34JlkvjCxe4r+Rx3+eizoXJkU84yYhg7yo
         7XJSsUbNa2gkrBYQsyUBkNIW1ZS7h5OafIPy9ogjOnZMroUCdvnPtZ95UzCC4liedaWI
         6CqAP4fzd6XRAEr06VmQoxBhG1ISJ5s+nLG2NX9Xs0t9AJjeuST70Lew47wkzr8Xwvw5
         YJTnDtXns3OAkGqIZPZVX6LVifmiakywUYINqapZb2c9YnIRSD4KY8zekmY1xko58Fhn
         dJtA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IVW68x11;
       spf=pass (google.com: domain of 31vhwzqykcqg02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=31VHWZQYKCQg02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id p16-20020a056a000b5000b006e49fcb1e28si149430pfo.5.2024.02.21.11.41.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 31vhwzqykcqg02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6082ad43ca1so60768567b3.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWRPobTY6QWBERLX0lonMwIb7rqAUFPgjzdk/cJ267fjCFBSXpwNMF3J3HtxpmWnwSWEeo2frL429Aa5kvmWSAQRa3Ur/nW/GtFtA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a0d:e6c5:0:b0:608:801a:e66e with SMTP id
 p188-20020a0de6c5000000b00608801ae66emr474072ywe.3.1708544469656; Wed, 21 Feb
 2024 11:41:09 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:19 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-7-surenb@google.com>
Subject: [PATCH v4 06/36] mm: enumerate all gfp flags
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
	cgroups@vger.kernel.org, 
	"=?UTF-8?q?Petr=20Tesa=C5=99=C3=ADk?=" <petr@tesarici.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IVW68x11;       spf=pass
 (google.com: domain of 31vhwzqykcqg02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=31VHWZQYKCQg02zmvjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 include/linux/gfp_types.h | 90 +++++++++++++++++++++++++++------------
 1 file changed, 62 insertions(+), 28 deletions(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 1b6053da8754..868c8fb1bbc1 100644
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
2.44.0.rc0.258.g7320e95886-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240221194052.927623-7-surenb%40google.com.
