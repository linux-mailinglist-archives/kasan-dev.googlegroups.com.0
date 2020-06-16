Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAEDUP3QKGQEKS2GGXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CD5E1FB13E
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 14:56:33 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id n184sf10536159oih.17
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 05:56:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592312192; cv=pass;
        d=google.com; s=arc-20160816;
        b=IP+iDi65dbt3sDozQDQ79oU1EkoluWQAzsUjoLDcXwMiEMhB80ryq9dz9fDDnTSDJV
         5S7rFCyHJIHyRkV6Bo5LAqruNqD3/sZciNXqz8lpz5FkK8KirzkSbT/tdtjpOyLj5Kw9
         FG394kCDQk9/n1e6ie1rY4g2jCqf5zzR5DFd6JMJ9nDxELunVJaTe7pkpnrGDHwduDQ4
         tasaL/xFitNQvB4YY1qIqBldG7U2K9m+G7JYBhrvexDUTVM8ZgJUNA1NcEGqBt/QsWLl
         VZTeAwCwrSWMNnyHWki+JfYgCqufXkouzI78CtFWXDd+oeJnyukFD9fLGSJU75uK3mgr
         VKtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=r9xfcISEV5EDC59C0m2FrQwGD80WsTuLMAi81pZFs0Q=;
        b=iH35EQXTJjK79+e66mp5JSs+j1yqc80puTbZzHziIbtQdSs3u9qFZfwzPsk2iOaHWX
         /fSHQ3grR7LvhKIZi2IdBtbpNoJiXpJkIt4qy0cq7E+6y8tlBWlwmkIySHbFiFe2n9rI
         50X1tJBlwvtg1gDhBsqcEPh+oSy72V+UMi0oy6YQmW+AFBM2CnTx5pTtJDuQ/6dOvTh1
         xbYQmizCfc1mOsCIWukZqngq4SAvw7OA8NmZ3S8vfr8gtp/XFHctEQtYFcem3mwbXxaa
         eSomJ5bpzhhJhyMGTqDLbNcAZWbvAOHs32CnwpEwHsi0PNLAZVP8svaau3Q/yCrDHwiz
         wJ9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sSHE2J4H;
       spf=pass (google.com: domain of 3f8hoxgukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3f8HoXgUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=r9xfcISEV5EDC59C0m2FrQwGD80WsTuLMAi81pZFs0Q=;
        b=FA6gqlCIFSxjdZ+BCHOoJqiwsPV5kOKKQwwn5WhKzw2/LnnlG2tuOOUtdYpGakYs4k
         XsBDRGFQDDEASBIdd6axgEOhxBX7pXjI/YkElwpjSDkOnL0RfpizS6oMFdmAxjLF47FB
         LFCprlcaEaDBcsxX2f0byuPTMgWcYOtCk5j2VL0LyihoIo2IwvwXgBeE7OTQfPs7kiou
         B9bHedDvEo+uPVHWP8g/1YoLZdncs1C6LYML/RC02ri9YT5KFcWCbJazCLhxZvqFyyTa
         0nhJ0Y/75IiyNysvokdVIEzQCY6c6kJS6CjQuRRkQSRsHWrRf+dtgHS5LVCQrv7SCvJl
         ta4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r9xfcISEV5EDC59C0m2FrQwGD80WsTuLMAi81pZFs0Q=;
        b=bkcXZanrnnPgxPFG5QctqY4ny3FrIxD8H3d4x+1+8c0QxQmFBm5duavbvprdScIo9O
         bxUbxExkOVcdq4SzhK9ssisip1Lu6cjWcCoJNU6fYTuhFBGFuZ/gqGUQtgMfTssoIFC5
         GviVQjlxq74wPef0GMBbBODd5Y9xK7eJ+R+APzkj6Rb8SHxFDtmfvZbiMmAVuRMGM7K/
         AAQXD6JIBRbGOIbANL/oeCCNdGDMVH31ERW8p2sHsjFMtso/DoXvaXYqsOJEaWKjcOCF
         nn7hXGHXTxtH5YyQNP02LcMDNWf7EVz1NS4u9Jlt7d6Z7qT8xzdW5cBSf5ZDj6K/+JG2
         HiMg==
X-Gm-Message-State: AOAM531ozwS5ZY2e8zDvZ7qxtel9m1dj21vY91oiayvLQmygLpDZk3DY
	0iN9XpkBWMsiFBobX8z8XII=
X-Google-Smtp-Source: ABdhPJzc2UHfQbsnRfHpmxBCn88GUPz6kjxhgoO4GKwUCugoVqNiqJCj+j5SK9IMISgbGkVFOC6CPQ==
X-Received: by 2002:a4a:2412:: with SMTP id m18mr2260391oof.36.1592312192598;
        Tue, 16 Jun 2020 05:56:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2c46:: with SMTP id f64ls3812058otb.2.gmail; Tue, 16 Jun
 2020 05:56:32 -0700 (PDT)
X-Received: by 2002:a9d:1296:: with SMTP id g22mr2400750otg.102.1592312192282;
        Tue, 16 Jun 2020 05:56:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592312192; cv=none;
        d=google.com; s=arc-20160816;
        b=F8VmM3icZwxu80jpHAGmPvE6PZBgvq/K8y7NJc2eoOORrI7JP0EWK+7zHyp3c26KVE
         RJdm3u4ZhUjSH09Qxtwc2f8iC+VYPTDId5le0ySg+8pugal3Zl+1GdMZkEQGuWB/Y27r
         9zABgI+CuSMEtCoCRRQ2+jZFCjx5zn8AlodmIjZmprkKvFhKbhQ/q2na1+g7glwslnXN
         JDSA6GaR6YbU6/gfFSXVrJmJ81kuE4+eDV1ENv6LHsL5JjSlc+uAdGiTD9HICq9q/QwL
         4UwxF7MYF3Ww5MEdTfBQg14rMyfMZ8M/Qo08S9F8yw/I2GoWWNENO9p1V4F6ZWZTg6uY
         DVMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=JEQhTwQYPsGwAzZzLRu7bODyjB8wxGLamvh49Pujfk0=;
        b=g5etS91CBY11mHqXyHygbRsWNxzru63CWbHLZhWvJflHYW0ziKvJpYGW0qaE0WPezq
         SWYlMh8S8nrklwjuB3+T0z9TA+DTi6lhEUO3GphL6v1DY5/W5AnQUFJVXxbPQMHqk2Bt
         iZFNAjNpRiH1Q4yR4FNv0ClankJvqpYSQeM+ok3fayb01kSckD3X1xoa72RCNL6im6hn
         iNXzz1RDh+U28cmvUCG0hLG99vHg5MsLnOkgxsy4tyv26tY0qrMdIv5YWK0AYPI7jhvw
         chtG6/QOpyC385AVX9d85TVVpno+i0SikGco8XwHZRddaXENRF+YIpILKDulqmMwA4zt
         WLOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sSHE2J4H;
       spf=pass (google.com: domain of 3f8hoxgukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3f8HoXgUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h13si1699398otk.1.2020.06.16.05.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Jun 2020 05:56:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f8hoxgukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id d145so16688823qkg.22
        for <kasan-dev@googlegroups.com>; Tue, 16 Jun 2020 05:56:32 -0700 (PDT)
X-Received: by 2002:a0c:e5c1:: with SMTP id u1mr2081593qvm.140.1592312191743;
 Tue, 16 Jun 2020 05:56:31 -0700 (PDT)
Date: Tue, 16 Jun 2020 14:56:17 +0200
Message-Id: <20200616125617.237428-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH] mm, kcsan: Instrument SLAB/SLUB free with "ASSERT_EXCLUSIVE_ACCESS"
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, cl@linux.com, 
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sSHE2J4H;       spf=pass
 (google.com: domain of 3f8hoxgukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3f8HoXgUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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
 mm/slab.c | 4 ++++
 mm/slub.c | 4 ++++
 2 files changed, 8 insertions(+)

diff --git a/mm/slab.c b/mm/slab.c
index 9350062ffc1a..4c7013eeacd9 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3426,6 +3426,10 @@ static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 	if (kasan_slab_free(cachep, objp, _RET_IP_))
 		return;
 
+	/* Use KCSAN to help debug racy use-after-free. */
+	__kcsan_check_access(objp, cachep->object_size,
+			     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
+
 	___cache_free(cachep, objp, caller);
 }
 
diff --git a/mm/slub.c b/mm/slub.c
index b8f798b50d44..57db6ca2e0dc 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1470,6 +1470,10 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
 	if (!(s->flags & SLAB_DEBUG_OBJECTS))
 		debug_check_no_obj_freed(x, s->object_size);
 
+	/* Use KCSAN to help debug racy use-after-free. */
+	__kcsan_check_access(x, s->object_size,
+			     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
+
 	/* KASAN might put x into memory quarantine, delaying its reuse */
 	return kasan_slab_free(s, x, _RET_IP_);
 }
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616125617.237428-1-elver%40google.com.
