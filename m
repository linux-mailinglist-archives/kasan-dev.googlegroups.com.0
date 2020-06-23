Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGO6Y33QKGQE57WGY3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A290204B04
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 09:28:27 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id j43sf1609795pje.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 00:28:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592897306; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qhh6A59X9WK06TXrRM1Rz7KvGW/+vAqEn621fROznhsh8KdFyV8jkQsLVB5tITI3Vc
         yqFQ9if0Ak7EpOn2uEpXfIJJRAlYYuEC8v+Epyao39Ie5Ysbvon0vNJYzu5tbsNar3Cg
         seT8ihMnKIhSLHbk1e+LbsQM5J+EdI5i+ify63RS84el1Sk7tXhsDpW9E9zVZ32jbde7
         Blz+pnS1HloD6cgu+UMdLuO91D8OqONvdkHZU3AhjBcKOA8VQLgKIn05zJZNmJo0y5qa
         hlsOOpZzPYpY0ifFI/jc/ld3RYkBvaOli3LoqfBe4yzP6vRg2fPtFL/DruasQSN7RpYZ
         Lgwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=g4S103uuLUbNerXcS+hplxNzM+QAnVgsdvoo16mtNIE=;
        b=cIxuU1fNHFUktPHT8SwezT48asxezvp6O9V5r+P7/Y2unPq749UwWRpaUwC8lxvCu9
         MSPnVGoui/ml7QZSQVEALpzdFzV3ibD8vGbzPeqXH8GHcNie+igwo2JuGDdAWKJ9FIkH
         FRwI8XWxpOxP4294iQ3N1eX1Kkk8nMBC5jUnzVvqAvM8kwQ3zgTDIu7J65vYe8OYp8Kz
         bLxRN8eDWLgimw8xa1MQhfDlu5kq7sZXSkZv9MT6opzPp1zebf+0y2mJ21j2eoybPQ6v
         GYKI3k9nZwAEcH56FMg6XxVcNbKMqP7Ee4ZhEeDI2yYxtQOSYYOlUbjgtNIq85FXHEQS
         B7Hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e7XzSW9B;
       spf=pass (google.com: domain of 3gk_xxgukctsbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GK_xXgUKCTsbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=g4S103uuLUbNerXcS+hplxNzM+QAnVgsdvoo16mtNIE=;
        b=QyUoXx6UkllrpDbPfvlJyzh1Udg5hkSi3w59fh6OShBu8YKsqAGxuOyBrP48UYfoT4
         V7t/hsWJ9RZ13bUhhF1JpNAp8CuVMG7hJyDQTTR+A+ffelDpknGg9RQ8/tQn7dw9IH0U
         uUhdSok07qc4YXNJjgC/QW7gHwGlXQVs26ay3fY7UhlxiFcOYatHRdOe3SR1K/Lo6Of5
         KlijD5Nh1H0z8427p63crjUeeTxt0VahxvguJRyCDteWLQeFB4KtZqwANjHU2ekPHFmH
         iCT5eUtUD1PvG7JmlR8hR44O6KXR3Agz3IBfbF0jFPnt05PK7jjgYUt6Niypw+2gK2RF
         H+Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g4S103uuLUbNerXcS+hplxNzM+QAnVgsdvoo16mtNIE=;
        b=ek/uO5dLSf9GV2z2e3ysuMrgkxb14t6eXV6F8oF8eHczYFyk8dhWtRoRmVpe027BbO
         rEF4SveTQEwwy9EXpICMqSyS+9EN8RDRU61FMF25UYPbR00u1w7PjX9Mk5f/TfsCmxeA
         azKb+DQBeQr9yT3PrevohW+qoFtaPMaCQI0bj1dDo/wCJoRHiucZkNzYSAi5RSTGV6Qt
         NleLGGM3SS1w2x/pRUG/Ua35bUuO9odnlbGd1/chVrI8saDrc7nUTfl29R9xRGq4TAUN
         NdFkMBkrNv6ToM1cZ+Pk58xGFvEwo0rxVrsIZDuas3khe0E9rqtpM1JTfhh8u6ivTn8O
         ijpA==
X-Gm-Message-State: AOAM531EnfpxgCMvb4bOMytyJ9hY+6qlJV9ZoiI2qMIx6xRSKPMroeNa
	+TCKhyuweD8uBxqx7GQwUvs=
X-Google-Smtp-Source: ABdhPJyI5Cb+8ul1UA1zccvKZrzPgBa7XUeQty5csIQ07cSq7FH7iqdmfEg4prJ3SesmGyn5fFRJJA==
X-Received: by 2002:a17:90a:6e2:: with SMTP id k89mr22740363pjk.74.1592897305975;
        Tue, 23 Jun 2020 00:28:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384c:: with SMTP id nl12ls973529pjb.2.canary-gmail;
 Tue, 23 Jun 2020 00:28:25 -0700 (PDT)
X-Received: by 2002:a17:902:eb4b:: with SMTP id i11mr20597902pli.122.1592897305451;
        Tue, 23 Jun 2020 00:28:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592897305; cv=none;
        d=google.com; s=arc-20160816;
        b=mT71pM/S1AjJDbX3XWMRFFRhZKMqAcrLRBFRrDofJLp8kY5mgXHNS40gJa5Y64VKxc
         MC57pphdnpTIagJ1NBB23k1cp79tVTRPPeyYX9fExLYffT8ON1VRtVUtLs6ZTJ8SGlig
         hWJVaG6Yi9tnp5GKiVtmuYyNnkgm5TLJb3kn8EE0RzSiFkx5VDo8Gl8mLMxMCytlg0e/
         KlJv4dUKdrlg66Gh/ZpTYx5Iz15ymknCpNI/HdSNYsoWa5gLoH4wf42z600rowT6ta0J
         62gFiJd0dOZM1Tpsm3NigYHlfH+Zp2wJKdW4u6PzIPCZa2I2yKAzkn+sKCejtnMaU6k3
         ueqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=nTQWvepZzYSn4rQEU0+1xmqZl1OOXUog19hqREujmU4=;
        b=K9vz+F0irL6BLRGxNV1nUUZKSzkqOQR+cEr0EHj0Az1k4ctzgguo51As5oonCYbBNC
         W0zaq7fNZBJ9iRDPZAUOgH3gbycaP7ppHMKt9YOKzRq1Iq0kvaxKXpZJjgm4g7gB6RAg
         Zz6pclvfhDB5jkOOpkP2xXskBoXSTwx8Az1RXr0CtKMBf55pwZcZPw4QxfXzh2G7Cnb+
         M0hgeWOf4nHzJrdl1G2ES4XWcdCCHhgm12sskcmFrYPG/mv3BRh6wqhMtB1wBuBudLEq
         PnLDER9H/P0gtGLpFg1yojYMyRY3Ap0aq63VCZV+MveSAbMjZs4sFTLtnxQgqbvbBqAU
         XF5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e7XzSW9B;
       spf=pass (google.com: domain of 3gk_xxgukctsbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GK_xXgUKCTsbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id q36si5065pjc.3.2020.06.23.00.28.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 00:28:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gk_xxgukctsbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id j18so3298023qvk.1
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 00:28:25 -0700 (PDT)
X-Received: by 2002:a05:6214:8d1:: with SMTP id da17mr5298435qvb.62.1592897304605;
 Tue, 23 Jun 2020 00:28:24 -0700 (PDT)
Date: Tue, 23 Jun 2020 09:26:54 +0200
Message-Id: <20200623072653.114563-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.111.gc72c7da667-goog
Subject: [PATCH v2] mm, kcsan: Instrument SLAB/SLUB free with "ASSERT_EXCLUSIVE_ACCESS"
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, cl@linux.com, penberg@kernel.org, 
	rientjes@google.com, iamjoonsoo.kim@lge.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=e7XzSW9B;       spf=pass
 (google.com: domain of 3gk_xxgukctsbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GK_xXgUKCTsbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Provide the necessary KCSAN checks to assist with debugging racy
use-after-frees. While KASAN is more reliable at generally catching such
use-after-frees (due to its use of a quarantine), it can be difficult to
debug racy use-after-frees. If a reliable reproducer exists, KCSAN can
assist in debugging such issues.

Note: ASSERT_EXCLUSIVE_ACCESS is a convenience wrapper if the size is
simply sizeof(var). Instead, here we just use __kcsan_check_access()
explicitly to pass the correct size.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* SLAB_TYPESAFE_BY_RCU allows racy use after free within RCU grace
  period. If slab is SLAB_TYPESAFE_BY_RCU do not check access.
---
 mm/slab.c | 5 +++++
 mm/slub.c | 5 +++++
 2 files changed, 10 insertions(+)

diff --git a/mm/slab.c b/mm/slab.c
index 9350062ffc1a..cba71d88e89c 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3426,6 +3426,11 @@ static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 	if (kasan_slab_free(cachep, objp, _RET_IP_))
 		return;
 
+	/* Use KCSAN to help debug racy use-after-free. */
+	if (!(cachep->flags & SLAB_TYPESAFE_BY_RCU))
+		__kcsan_check_access(objp, cachep->object_size,
+				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
+
 	___cache_free(cachep, objp, caller);
 }
 
diff --git a/mm/slub.c b/mm/slub.c
index b8f798b50d44..4a9d43fda669 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1470,6 +1470,11 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
 	if (!(s->flags & SLAB_DEBUG_OBJECTS))
 		debug_check_no_obj_freed(x, s->object_size);
 
+	/* Use KCSAN to help debug racy use-after-free. */
+	if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
+		__kcsan_check_access(x, s->object_size,
+				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
+
 	/* KASAN might put x into memory quarantine, delaying its reuse */
 	return kasan_slab_free(s, x, _RET_IP_);
 }
-- 
2.27.0.111.gc72c7da667-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623072653.114563-1-elver%40google.com.
