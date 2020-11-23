Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQFQ6D6QKGQEPH2SYQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 36A5E2C156A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:14:58 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id c24sf5500541pfd.13
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:14:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162497; cv=pass;
        d=google.com; s=arc-20160816;
        b=beGXCjeH8dOBpwO5lko21UjKYKn6pJhUMjOh9CVbkG1iTT19bdj1GRI7SqKqItesOw
         yZJ8CMXEq/7LMPuezhznZn8CLs1fk6jrE+FqahKqzBkq22z7E2VVFddD/R/DPbz8YFCE
         kgMsJENeRzQ8ZNLa06fcjo/8h2swsLN+nxw6GUFqWBalaOR9htAhDshn53VJlBnYRJSI
         BZYms/gLK1sN9iEpZs1xMRGLxoP4+/Ix9cg3evcJnaRAYXoST16cndMlgQ2C7tgRSiYi
         EKjtqtAHOkljezBPviKr8Y8sg/3yfi1UO5bgJRYJCaTlT+RO5FfOG5rsoZ2bu8Oi57rv
         vxfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Esn8rV50TM6MdAb1Dnuqpq6GrxaiGZ5r2sruu56ZaQo=;
        b=KEXaul08EE0D9d9YbkYBi/YzZkUwF5BpzbZJZ7bXiPKINwmTxIfT/KgMn3XXVE2RRm
         rH/B3ma1PyUhRzXEgi3dnZSmH/LbNqouUzWvFZx3HdLtfZel1rq7XpaHpK/TmDGVF2U+
         D86IDu+jTSAFsFdlDevbn3vU4pit+E28TB2vKtWdxh91SrBfq3QM60me85pBlRSKigW2
         Aqa2XProsc0/DuWtiz0JZ3uAhrY9U7xdj9SARFUhlEvo3y/SWMjVEBtxcd5gJvlH3r8C
         /MqT8JXt7DMXEaKyQsAt3hzAukzHNI3ObBvM2b7NaQnip/n15mDWiovnGuuVVrUn6x9f
         0r3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vE2RlTTz;
       spf=pass (google.com: domain of 3qbi8xwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3QBi8XwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Esn8rV50TM6MdAb1Dnuqpq6GrxaiGZ5r2sruu56ZaQo=;
        b=X9fX8+Qi94v+/sk7NjfLNUhB6pfm+gr6lG9ZVBRr0HMjZXaCwGQnMznHC88aoVlTE3
         9Q1MdQbw9eSi+s6YCyoeFi97IBVBmJ5M76I6n9C3IXJbeF5w7WyGDNqW8j8luumTJ4Vo
         +1XqNu2i+QiAtdGqC+wlO4hRgTvB0mhOMfoEsqTOTKh5Jo5lrasQnfAmQH8Fv8QGPfM8
         tdfOQRYRipNP1RJU0tx0k80y9m93PUbBmRPwFk7QO8L7pVV+NbgSHCqeiPMwcqaaIydJ
         4517Zbk27drwaoca8vaegGJX0Z603JzvcrgriZshl4dyWxKRZBBRNV16c9FHRHx1BDaR
         BI2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Esn8rV50TM6MdAb1Dnuqpq6GrxaiGZ5r2sruu56ZaQo=;
        b=jCeRhPN9Hu/vL/bm3gCXvvQ5bh+LJ2azZrVg5r+00S/0J/biC0TILejdM6YnCK7AAW
         aujiya8iHQgQCnLzOf6i/lkPd9uV8znj4v2YmWoLs9c8v3x2mDZ3VYiUf9J5WQ/XuSvu
         E2Tn3jF6cAq1+97UBOs4PWpmvB6Rh+irfCrbcuqvUXOpc/AWKE2Ywugk/AWoF+Ux6nR2
         72QCeYeeHgZfwTpXyVfdqmXtBHsULTzvZHNZ5iVDnjKtnpxnYRP5fGHpXr9D0GHFVrrc
         3DAwXNMm75Neu81cHuuHzyrMkClOwViVTq/pACn6IMqLWNMHxJwbSL2wyHYDRpzok6SY
         HdQA==
X-Gm-Message-State: AOAM532rrWULY4jtt+bTjRVxNtjTMBtZf8DeNI+nCQc5w607+WDPz+NW
	O6tYYEVbX12OM+CKYalB7kA=
X-Google-Smtp-Source: ABdhPJxQcP9n1iSgOjnfBX9CbSVT69g6pOQmSTH50JCfWD8IphSdJd3pg40xk3lL25z2QPJpkfOj+w==
X-Received: by 2002:a05:6a00:c:b029:18b:eae3:bff0 with SMTP id h12-20020a056a00000cb029018beae3bff0mr1034895pfk.9.1606162496976;
        Mon, 23 Nov 2020 12:14:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7c7:: with SMTP id 190ls4591588pgh.8.gmail; Mon, 23 Nov
 2020 12:14:56 -0800 (PST)
X-Received: by 2002:a63:5126:: with SMTP id f38mr958188pgb.11.1606162496476;
        Mon, 23 Nov 2020 12:14:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162496; cv=none;
        d=google.com; s=arc-20160816;
        b=j5VTohcyuwtxQNON5fNak4vgu5+kHTXc0jj1VGZ22dvOgAtFOwDup5X7VsixbR7MtU
         1V2cS9eIdGVYd3MiAQ9mBakgKVjb14st1zXoskKOrd2cUStEb6YVUeyRUnXUIuTJWcsk
         5D0U5oiK0Ir9erzBiqvNMgff1YgxQ0xIe6YfX++6tYp4yuHRF9eh2WrlXXwXlylpwQ+D
         0Xl4T3PaZmmiucfZgMduelgx1u/fqiTIDFiWg0PXi+O47ca8RleHy1YcLgnfcXAeWzQf
         wUa5a2zTQziLhjcpAO7KRCzXPILBvj8iqrWawN0SiIXUBYgI43hxKT6ha8MHFXOeFTY+
         9Jtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=X8He+i5DTpgfYKqVr7f46nksdkLo8KZ5P0WRCUmFYW8=;
        b=Cwr3GZiopeJspg10ISUjvNI6ixIICTiWKZUsKjQV6uJvGoDdRr89u3X2CMzBW3b/78
         +NRt7gGlO05HwoEW8Pr1lQmHHM2d2F/PYM9gxJYfVtBJwsDUf6O7MpkDSc7DFGJwFRPj
         7/LTKQPy6ucVByBsjL4F456u3Ll9dDAxko090mDVU63MlmaqWqhONHUn/O9HmeXcj3oH
         I+pLZZGMus0BXZjdHzlFdiiais4Qxs4gKZbxOJVoCJpc+qeI1ZowfdMBF5CwN9NlZ/eR
         /LzQ2/PKdIxn+yRgYhozJmaq/Kk4dwNOgXcWTpyExia+A3xb8iBj9B92B97coAx6D6fE
         1AGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vE2RlTTz;
       spf=pass (google.com: domain of 3qbi8xwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3QBi8XwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id b26si765827pfd.5.2020.11.23.12.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:14:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qbi8xwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id v8so13697709qvq.12
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:14:56 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:eac4:: with SMTP id
 y4mr1134178qvp.19.1606162496039; Mon, 23 Nov 2020 12:14:56 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:31 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <312d0a3ef92cc6dc4fa5452cbc1714f9393ca239.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 01/19] kasan: simplify quarantine_put call site
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vE2RlTTz;       spf=pass
 (google.com: domain of 3qbi8xwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3QBi8XwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Move get_free_info() call into quarantine_put() to simplify the call site.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Iab0f04e7ebf8d83247024b7190c67c3c34c7940f
---
 mm/kasan/common.c     | 2 +-
 mm/kasan/kasan.h      | 5 ++---
 mm/kasan/quarantine.c | 3 ++-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 998aede4d172..e11fac2ee30c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -317,7 +317,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	kasan_set_free_info(cache, object, tag);
 
-	quarantine_put(get_free_info(cache, object), cache);
+	quarantine_put(cache, object);
 
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 64560cc71191..13c511e85d5f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -216,12 +216,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
+void quarantine_put(struct kmem_cache *cache, void *object);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
 #else
-static inline void quarantine_put(struct kasan_free_meta *info,
-				struct kmem_cache *cache) { }
+static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 580ff5610fc1..a0792f0d6d0f 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -161,11 +161,12 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
 	qlist_init(q);
 }
 
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
+void quarantine_put(struct kmem_cache *cache, void *object)
 {
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
+	struct kasan_free_meta *info = get_free_info(cache, object);
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/312d0a3ef92cc6dc4fa5452cbc1714f9393ca239.1606162397.git.andreyknvl%40google.com.
