Return-Path: <kasan-dev+bncBDKPDS4R5ECRB5HH76IQMGQEBJDYFEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id BB35F4E85E4
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:19:49 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id c6-20020a621c06000000b004fa7307e2e0sf6390320pfc.6
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Mar 2022 22:19:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648358388; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzkU4wuHGcPXllWmcANnxAdsCEF22IH9PI0n4BkKfyu0mXLAsCm2NJ5zoVgjf7qwsu
         /btvodZCxNEItn9hoqBFNITNndQ7cJs6ApHj7zxcjERjGG8Dsb9DDFKOUCTrkCsNJOUg
         MLexYFDdp+UN4Dwa8WdxKEvdtnNeClZGKWhDqpDYRgwOuESpbdjoLtq9qRk4f8JyhUD4
         EuxgAAC/qa+fQZsflJXuXrXcCeoTx+EuHDnBNKoUIOIMXFzJgbbHes1zHdVznzzYjBsQ
         OiWnjkGx1DHfUieTsUpL1VFrLC43H1yY1H1Wb7aSmLck4VE9NrhrYNPelC3CYmJxyb6Q
         EWVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b0J67aHwIsAk5pqWcNPvWrV38dogc6Hd7QhWYKYybpg=;
        b=u8PGXQQILeJagpCuezP24KoVWCehwVrfRjLE/NwRrm1E/4gmVVRmfjNCW8VcLZeWwk
         BW4GcNqRhnc5VBoLQnXP0IPZwxpLSTNyHJ1rlMlNXw48P6/0V8+m3YWFxFgvbKGl0FMp
         KIWcRZFnrbfaueXVewnjZz2tZe1v8BRlWeA5kQlTAEazj9Eb6ONNlJkssD66/cEVZabO
         O58HIcE3PYTVNX9TYZbVPAYOC0GJqyywZkyKjGIDpCFeOelwo7oAeEp7LyiQUeFfcbQK
         icunBq9L5ocu19tqRcl9/DkFmWUpEqEk/u827/twxuiv+5ncWv6ebPZdaD7bWVERsiIW
         JLhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=wBkFbXGM;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b0J67aHwIsAk5pqWcNPvWrV38dogc6Hd7QhWYKYybpg=;
        b=C5BoFC6OFJ0GPbxLfO7gj501R4upbmj8/OutYS1bYP+S70SNerhH0t1ODhHxKbpWIw
         GcQJgu2JMM+mO7grtG2ZCZBBldkg9iTFl1Wfpmb1IH5M/4CkudmWXRrX8nhmID1yWLU1
         mqtoK3/5nimbX1y+mO3PjgyEJZ3eGryWjUbmIvUtl1tLhtBJHw2UIcsYomkOrI6FHXTh
         gVDGbPrOLZVcoEos/n1MXfoLMk7qK8d3N+pFxjUqTcCK8pKNzgvg1P3bcpnrew8eNdlv
         +t0h/Y49xK5rQoFaXBEQ1U+PQrYJPzmwJ8Zm7A4wlVlEVyeTcOjdznC5ikUJcPeVMTcd
         K5RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b0J67aHwIsAk5pqWcNPvWrV38dogc6Hd7QhWYKYybpg=;
        b=XRGlAiKZy682dBzJ26IrBcqo0dlHnT9eOLx95dbWAgCoO5QuUYLnZAS++gg8/q5v6S
         S8PCUWvcegzfzLBhBDQVGsFeatOjFO5m+T0sQiDvyaAhhu5z7U4C4w0agH6KkZfYEflC
         DXlVcEgC4pCWZ2sKQv8vwrnfnfHZ8D4FaE+2TX4ENQgySiEMpfeGpuF4n6Nf+cUUM2LN
         vFqIUV4GiH0ugA26ApodV7NAvliDO2o7wpGiGUIj21p8p9/eqXkStRnDwMfE00LR7Pso
         RbjKNixMTghgeC2xWKbPu1xcRcHdjnTD78lbS2NsifYcjeSQ8Aht29SkfopxEMUicYTs
         D6iA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x9bIuD4Kd5e7ThI18JZdbX2s6SEl1SPi0MKEgE6puIsBiy+yQ
	TH6rJd/zmJiFqbqHOX6BdLw=
X-Google-Smtp-Source: ABdhPJyFPfN8pPul6Nk5wedk4HnR8dxwzfbZ0LRHBuFq3nH0qxPGL/Bfp+OT8yq7yI6gxl/Q+N34Uw==
X-Received: by 2002:a17:902:7089:b0:14f:c32d:f0c4 with SMTP id z9-20020a170902708900b0014fc32df0c4mr20046623plk.97.1648358388220;
        Sat, 26 Mar 2022 22:19:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:182:b0:154:42fe:624f with SMTP id
 z2-20020a170903018200b0015442fe624fls7529849plg.9.gmail; Sat, 26 Mar 2022
 22:19:47 -0700 (PDT)
X-Received: by 2002:a17:90b:1c8a:b0:1c3:22be:fe31 with SMTP id oo10-20020a17090b1c8a00b001c322befe31mr34564982pjb.195.1648358387612;
        Sat, 26 Mar 2022 22:19:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648358387; cv=none;
        d=google.com; s=arc-20160816;
        b=OZ+ToyTnt0V694QfA0/CPHMwLGWeyfpjvdy6u42dyoic9ES/XVh64UapDXqlB26Oz7
         goXMs4j9qZFqCoCEkKI0AtGRcSCtKSycf3dXoxg7T1tprvHVe0F1dCLLWqAEzR2niDDE
         cYkcGjKC2rp1ePcs9Nl10FPTD/ETb1IaRXQmXMxQc7aHMHvqTf1rWDff1VNz0yFQkTSO
         X92BbKnZHRBFbYSdkWljwqZfyS5st9EK8R2JbFnFjAzvgEVwxxsJ2hiB30iuY2vG0fkd
         tgJMea7NwBgld+11r7ywssI2DncQQJ1WNKzF2Li+hytiFy5UbivqISuorzMooGSOlcyi
         /Ujw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DjAjApw5OmSknfrnxGEwevfGU2mFpTwiMRTXvU9CZ2U=;
        b=eWS5dp7QPPhN3Pwvntb+NA7mnYf4fcdx913EMc/MMRwZSHTBGpQo+KMdwSqYcWUDAO
         lEpOujQh4PeH+hGqh7QRfd+2VAPE9fHSO/LX94JgjWRnwOlAeBGLbMj1Kz8LXncdjAC8
         eRCmmTlYUMusiU+idFVpvvLY/oCjWVSYxJ4tp1acbGO5cWVPNodtb4Po55cS8cliPBOw
         i5a3+b3G7QzwgHsDr8LCYCVkKjX1kDjGt5UQPkt5RTYshINZI8zip93pUfSbNPYiBx9J
         QJhAlAhVXE9GYjxv/bfCAKrvtnvi6hj65Y5pabRxnsFkYJ8GCridKKx3Pbn6HAR7m0DD
         F5kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=wBkFbXGM;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id u13-20020a170903124d00b0015428b8fcf6si658992plh.10.2022.03.26.22.19.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Mar 2022 22:19:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id x31so3222124pfh.9
        for <kasan-dev@googlegroups.com>; Sat, 26 Mar 2022 22:19:47 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a91:b0:4fa:b21d:2ce with SMTP id e17-20020a056a001a9100b004fab21d02cemr17887607pfv.75.1648358387326;
        Sat, 26 Mar 2022 22:19:47 -0700 (PDT)
Received: from localhost.localdomain ([139.177.225.239])
        by smtp.gmail.com with ESMTPSA id m18-20020a056a00081200b004faeae3a291sm11115940pfk.26.2022.03.26.22.19.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Mar 2022 22:19:47 -0700 (PDT)
From: Muchun Song <songmuchun@bytedance.com>
To: torvalds@linux-foundation.org,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	cl@linux.com,
	penberg@kernel.org,
	rientjes@google.com,
	iamjoonsoo.kim@lge.com,
	vbabka@suse.cz,
	roman.gushchin@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH 2/2] mm: kfence: fix objcgs vector allocation
Date: Sun, 27 Mar 2022 13:18:53 +0800
Message-Id: <20220327051853.57647-2-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.32.0 (Apple Git-132)
In-Reply-To: <20220327051853.57647-1-songmuchun@bytedance.com>
References: <20220327051853.57647-1-songmuchun@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=wBkFbXGM;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Content-Type: text/plain; charset="UTF-8"
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

If the kfence object is allocated to be used for objects vector, then
this slot of the pool eventually being occupied permanently since
the vector is never freed.  The solutions could be 1) freeing vector
when the kfence object is freed or 2) allocating all vectors statically.
Since the memory consumption of object vectors is low, it is better to
chose 2) to fix the issue and it is also can reduce overhead of vectors
allocating in the future.

Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/kfence/core.c   | 3 +++
 mm/kfence/kfence.h | 1 +
 2 files changed, 4 insertions(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 13128fa13062..9976b3f0d097 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -579,9 +579,11 @@ static bool __init kfence_init_pool(void)
 	}
 
 	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+		struct slab *slab = virt_to_slab(addr);
 		struct kfence_metadata *meta = &kfence_metadata[i];
 
 		/* Initialize metadata. */
+		slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
 		INIT_LIST_HEAD(&meta->list);
 		raw_spin_lock_init(&meta->lock);
 		meta->state = KFENCE_OBJECT_UNUSED;
@@ -938,6 +940,7 @@ void __kfence_free(void *addr)
 {
 	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
 
+	KFENCE_WARN_ON(meta->objcg);
 	/*
 	 * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
 	 * the object, as the object page may be recycled for other-typed
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 2a2d5de9d379..6f0e1aece3f8 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -89,6 +89,7 @@ struct kfence_metadata {
 	struct kfence_track free_track;
 	/* For updating alloc_covered on frees. */
 	u32 alloc_stack_hash;
+	struct obj_cgroup *objcg;
 };
 
 extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220327051853.57647-2-songmuchun%40bytedance.com.
