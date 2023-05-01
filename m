Return-Path: <kasan-dev+bncBC7OD3FKWUERBAO6X6RAMGQE3R6H6VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AE236F33C2
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:31 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-763da06581dsf149901139f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960130; cv=pass;
        d=google.com; s=arc-20160816;
        b=taryHweO+iJwaauWvIksnrT4IgDY8SJzEx8BvF/9YEzE5AEw1otmXYe1APgi/d0EVM
         t5fnKCrE/qarJUoi5IBYe99jFcj5uJeDq7xIkDa5IF2yaKY3zwaN51Ypxd0YneYEUMI2
         mgw427hJmgaL4owOmTDwvdTDVqbMlLIg5hd9p9UuQAXTIGrjtSBmoaoh5xnCgfxpALvu
         qUUCxcmz1EqsxqwLHKrykd/gwVYyETwbbTk+sRfPbOHuOt2v5r9TSAA5a3Olixo3zs80
         Dgz3Gv6wSzDajimoqGZ+gzVzPxP4viKOFHiG3yCK//OUX8Drvx6lnDaG7rCrQwAdm/1c
         0HuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2RimequBTDBZl1Itagf4I6ZH3NZk86vl8YD1Y60sfyI=;
        b=Q7mtUcSe/jLG3MbMVfTbY4zUempbtVNs6R9EX3FMCPPVH1Jjye4yskYRTJo/4gF7KP
         oI53ickn4U4N8wZcMuyaFrbGUjCm4ckf7RMj0JK7/af8rs0xUIwMVYP9l/8mi75SZFoV
         WH6qvufdbyA2cDxg4F04m9SMY48OP6lVkYaezRcXLra1KCbDVTJK0icQ5aSjrz+Ccwdp
         vJl7KFzdu036K5+IPGafmi0PBPPksUaP7fR09Tb/DezkzZyMFlj8FTQySx4CLV4K8UXv
         lxrnCnzJvSTLhZX0ViYgyS7a1r3z+QjHHIh3C4ZCdggZ0kCqi1LSJjUdKEVtoXZcsxE+
         KGLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=j+Kr4wFQ;
       spf=pass (google.com: domain of 3ao9pzaykcuc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3AO9PZAYKCUc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960130; x=1685552130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2RimequBTDBZl1Itagf4I6ZH3NZk86vl8YD1Y60sfyI=;
        b=EA2CT41XIwxJHs4Tr2f/zFxPAEw8uHG9zU8mbYjMs/3jJODxm7V+t9uX95UqWTxXrU
         TcO+H9GKkc6IHsLr7GZtUAnqvr1O5HivOlF7b/0qGkKcXhibYsNbXmXx9irwsQFHJ556
         Uxyc3hWCTzf/zJfxAqbhR7QTtma/Ff5xeZZNjaf1SUY/rtPAj5IGrcQNGw5MGxNikcZI
         2HWpu2FPDhKs6ZIKhL5QlP7F3O2nBOiYe2jeGHk1Fs5rxsncEKfV7B9lO46Lq8b6LzSR
         d3Ovilp+itGXIZgwm7FwhMipSt1a15bnJsXV29d0RgQsOnEceOhFS9XjQml67TA01RwM
         NQJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960130; x=1685552130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2RimequBTDBZl1Itagf4I6ZH3NZk86vl8YD1Y60sfyI=;
        b=NHYlD/JoJBnJprw6Gt5jDW0zdR/xYm3kRAvZdylFRgK83snnwKTod5noyuO8rPeQs7
         1U304kAytKK73Q12ilbKX9WSsL7ODxCpY8QBQ+5sjmoch+ro4i7u1b1gpMCPD1uYOYPf
         VNXUiycwZMaQDoLWEYqAaSr2LMh6EjUA9UVpuBHfJpvZcxYy5be70siB7DTiir9Q9w7m
         R2IRZnt5PAvArrVGgJhV+NqunuTzCGZ+m0gQ6UPoIKED3WLz4gmIoRjPkX+04OeFAI+j
         xzyUTApzy3qy+e//ZIgOB1crADY4Kge/ogVgKOn/Qz1QNAFHc/yWMLKrM1mOF1QzRWmo
         wYYA==
X-Gm-Message-State: AC+VfDxjx51ZoFIuqxB4dVK+0bXl0XTUOQSW2aXRoT6MA4IkrWlgz7A+
	DzdUDr4y+MEZ9QwNNWzlmac=
X-Google-Smtp-Source: ACHHUZ7sorp9BbYH2Qekep5V1zf+u4KKZtwliqqSGXx/6eBqiT/cBhjrUh3h8EByQv5zNw9QqBax/g==
X-Received: by 2002:a02:a154:0:b0:40f:7a52:d66c with SMTP id m20-20020a02a154000000b0040f7a52d66cmr6191777jah.5.1682960130000;
        Mon, 01 May 2023 09:55:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:15d6:b0:760:abd7:d605 with SMTP id
 f22-20020a05660215d600b00760abd7d605ls2156555iow.0.-pod-prod-gmail; Mon, 01
 May 2023 09:55:29 -0700 (PDT)
X-Received: by 2002:a6b:e40d:0:b0:758:7abd:959f with SMTP id u13-20020a6be40d000000b007587abd959fmr10895098iog.18.1682960129496;
        Mon, 01 May 2023 09:55:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960129; cv=none;
        d=google.com; s=arc-20160816;
        b=baVzBIH+W83n2A3ZxY6tOdJzRJKZbVr5/J7QQmSNx3jJF7NoeLFEitaARBLreK6zNn
         KYwpeMghlrarYASur87cAoDogMXqsYL+Joj4y3AgdqCMyhQeVRXB1Wfn/aLb7BaZ8STD
         cBZlI1oLI0GTV8h5laY80vpRWDULNGOtovQNV6MghjGdIfyXxirRr7h0Suxvesi4swSE
         VXGEWo3iPMEzMzuiVaBEnfJs6mIOkzZ+MOx5kCjrGkHag/c0BY2AvsXkxMlEcmEfZJbH
         90f3GIsCuay6BLZ+Ib8+8EZ7FGujjHqfMyht0MjnXOoyFjg5tvPSfauRKQXhGnCZ0DzK
         wEFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DK6/s7foZNj5EExVH4gZckioJVPcIxI52cq1C7FfTD8=;
        b=C9QpFSUTgg75xG/7dmdrjcr1pJ/5Hg70EEfTSLZp5ZWKHBGMwENQSejSAMqulRdGC9
         ZUpETjv/qgJTHe2MUPZLEr4ewsHoCRxMfgfKpNy1GgsVgs3/NlVWFbnq3YlRjteBr89r
         xaJKjK7uOuVJlVvf/aYjs87AoEP467U06VdAwU3POTOgcbFO1gUZry/mAMb/Wx2eviVB
         k6qooE7q1MehICDOF/XMoJby5RtQNIkcrW+sS3jjxJaftE0spsE/nViLct7zUmoVVz77
         w4sjkyJGKpPeTazlgECDQ+HnGEY0j3guHfYzD8QCI4y8unUmMun+WLaudf6zoDNp5+0Q
         +mSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=j+Kr4wFQ;
       spf=pass (google.com: domain of 3ao9pzaykcuc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3AO9PZAYKCUc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x64a.google.com (mail-pl1-x64a.google.com. [2607:f8b0:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bb9-20020a056602380900b00760f0b7ff47si2156084iob.3.2023.05.01.09.55.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ao9pzaykcuc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) client-ip=2607:f8b0:4864:20::64a;
Received: by mail-pl1-x64a.google.com with SMTP id d9443c01a7336-1aae803a5eeso10245605ad.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:29 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a17:902:6a84:b0:1a6:4543:d295 with SMTP id
 n4-20020a1709026a8400b001a64543d295mr4657171plk.5.1682960128744; Mon, 01 May
 2023 09:55:28 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:19 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-10-surenb@google.com>
Subject: [PATCH 09/40] mm: introduce __GFP_NO_OBJ_EXT flag to selectively
 prevent slabobj_ext creation
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
 header.i=@google.com header.s=20221208 header.b=j+Kr4wFQ;       spf=pass
 (google.com: domain of 3ao9pzaykcuc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3AO9PZAYKCUc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
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

Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocations
when allocating slabobj_ext on a slab.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/gfp_types.h | 12 ++++++++++--
 1 file changed, 10 insertions(+), 2 deletions(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 6583a58670c5..aab1959130f9 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -53,8 +53,13 @@ typedef unsigned int __bitwise gfp_t;
 #define ___GFP_SKIP_ZERO	0
 #define ___GFP_SKIP_KASAN	0
 #endif
+#ifdef CONFIG_SLAB_OBJ_EXT
+#define ___GFP_NO_OBJ_EXT       0x4000000u
+#else
+#define ___GFP_NO_OBJ_EXT       0
+#endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x4000000u
+#define ___GFP_NOLOCKDEP	0x8000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -99,12 +104,15 @@ typedef unsigned int __bitwise gfp_t;
  * node with no fallbacks or placement policy enforcements.
  *
  * %__GFP_ACCOUNT causes the allocation to be accounted to kmemcg.
+ *
+ * %__GFP_NO_OBJ_EXT causes slab allocation to have no object extension.
  */
 #define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
 #define __GFP_WRITE	((__force gfp_t)___GFP_WRITE)
 #define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
 #define __GFP_THISNODE	((__force gfp_t)___GFP_THISNODE)
 #define __GFP_ACCOUNT	((__force gfp_t)___GFP_ACCOUNT)
+#define __GFP_NO_OBJ_EXT   ((__force gfp_t)___GFP_NO_OBJ_EXT)
 
 /**
  * DOC: Watermark modifiers
@@ -249,7 +257,7 @@ typedef unsigned int __bitwise gfp_t;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-10-surenb%40google.com.
