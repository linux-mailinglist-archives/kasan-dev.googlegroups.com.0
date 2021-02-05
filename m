Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO6N6WAAMGQEMEWQZHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 51B25310D42
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:41 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id q8sf5708075ljj.13
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539581; cv=pass;
        d=google.com; s=arc-20160816;
        b=w1UV+Yw0qoYd9QsmGJsLi3CTtjYsRhrRLkDeGYHPF5/NgoKajUs7uHUdfIvfOjAnLS
         dNerhMgng+rPc7rAcp2BrgKX+AzVTLF9UEIufKmVvFKXDgXERL3B+tPwB1kEMc0EPG5B
         q5KhmNQGSrOMUi3n7HAxiB8q4OtwnO0BcQkY0PARBC2OswYwcencwuTJBQ2pger0glMG
         4MEzNPLBp0LMyPs6saJvdHnhGZgtBXNC+ybHBvJwY94iUGUjH++CaoUcrsK9FFprAIv3
         IRwKXkJWWhu8Zm5huqNjGMY6BeQFSgQq05f8J64lcVuCrhr6MvSGPz+MIhzTMH2TT8SY
         AX/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=uxr/9g3F2SOuxNj3+Lro55GWOV8/0mjy57JpJgPqaM8=;
        b=TEWvU59jAU2z0g1vqp5bNc+5XQF6BFCvlPq7wpVuykfxFhdNhoXIfiDbGI3nxfncAA
         Kcbw6NTKJbRUHCOOGTBD31rl7jAIa8guOCv0fYn7MDAsIbKwTjo9UrkpzDbC6IBEg1Xb
         PC6O3jyqTGFMBBe/eYd+2lEwouYiWHES+/nJr+PV9rWD3ygSKrklFIPWx2m5DjGrT/Hc
         akOsAEqaMKgcEiW4kql5d49G8t/vwo2wxdaq39ugloW3caoN4wbh7pz+xlZvP4ibW5wc
         nbXFqt6aCLbd9YdhhrS0eLYzUzv2sWj3njNeqq4oQo8UESw5IVfZ3E29Xyg5m/SQOfaW
         Ba2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TwrM5M5C;
       spf=pass (google.com: domain of 3uwydyaokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uWYdYAoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uxr/9g3F2SOuxNj3+Lro55GWOV8/0mjy57JpJgPqaM8=;
        b=AeknmtAQOI/kwIdWJghy/bCaRbmWgV3K/2ZBXKhYB/0HBnY+gu4KTRFdpkDMYbWSk+
         DoUzOVA5Wuaz4wTYMyYjrTV5u6+MIZT7MaaMSza8Osaw7vS+mAaUzFLgZoKoF7CJUwzt
         nK1wkFjdKpEgEQVO+TXx3/H9WKQF9e5YqxXp9GzO42PLAo/iwVlDcgmcS3V5pvKL0n6D
         XFfQZ9sXQoq4C7KVIYCjIlsyYhcxGanRUdjfjoYxwjVouWgWPa0UPjrERZC3WtKu53sU
         5YuQXsGfCSArAgwvA2eyXDEiXYEt67PRAKgAj2WS9HkGFxV5iDuExhcAyt+tLf4Kr3zo
         o6qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uxr/9g3F2SOuxNj3+Lro55GWOV8/0mjy57JpJgPqaM8=;
        b=mCv1B8fSo3C+Lz8L14C7jhyZ+aTY5zy/ijsRXGZIawBzEor+sZEFDhyyU2o5sW92Yb
         WxOJEobTaE3NvAGjNYMmRHJvzj8upBUwHSt1dM4nE/S79gpsjisDLQidzVV1PrHR5SXh
         3rDzTD71mSUndLRCXY1vglAUaaquC2GSUVPsFlPiT2859Ak/P0ZHHzKFZ0jNCLeTv4jz
         UujTawt3knjw1OlCFCe8ZJREQdSXDsVVtq8x+qL8Zjxhkg1aVfUE02iCXoyeoelbcWvN
         nw1nD+rPWDFurf/20+jBjbwg8szkgEdruWUoZO/ci9fRKSunU1HLWmeQK2otjDqK1YW/
         Gxsg==
X-Gm-Message-State: AOAM533VZlKQkBtEA5pvj+HCfOIbBedBSKmqkrSiN41uaN6Bmc3hlt9i
	k02xE+AQihQhVbgPdqnRfP8=
X-Google-Smtp-Source: ABdhPJxcXcLIg6c/TuorMQdObjvuQzxlkIDoieDL/S1jeWh1qR6BfgD6zgDm1YqushHmGNKfMehurg==
X-Received: by 2002:a19:4810:: with SMTP id v16mr2801895lfa.658.1612539579674;
        Fri, 05 Feb 2021 07:39:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:97c5:: with SMTP id m5ls1756793ljj.10.gmail; Fri, 05 Feb
 2021 07:39:37 -0800 (PST)
X-Received: by 2002:a05:651c:2108:: with SMTP id a8mr2919450ljq.329.1612539577777;
        Fri, 05 Feb 2021 07:39:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539577; cv=none;
        d=google.com; s=arc-20160816;
        b=TV8hQBhKksr3DJOCncbJhLsrZz6xnJrv0V6sxuQG6woUJxE1UhLDQ78vWhqgkdSY+1
         hOatNhN7S3CVEKE1OT++RKqesVnEj3GNTUVvjeGUOgOyxGcQNvCtQZm3QT699TqUrBRe
         NygWtJvrjrdi9ONo6mM25YnRb7gin9OigL4/gPN0r16/YWbNOlnGjZLdJxsThxQ4zuRu
         01SaZ4nE6X21fRgxFZ4N9U+0gI/NEGxY5atrnHuwQWfD/77ViBhdw7NcCkLqD+vLJnqC
         4UnJM2EKjJD3F/ePatB+PKF2IhqEtIU14XodJJQxnrFffgrj61qtRCtgNKfrUZjSBEcd
         7Ung==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ISHwxx5EnSKzUDUjZ1ysUZFyHBfF802klWxWhYA/428=;
        b=SEux3U7k4mbwTFDG3xbqDK0JSfmuTI6/jmWZVaxC8JmWVFUYV0z5ldLXsGnt5CGN3R
         LgQSSbuQLK7fk0j8BTUuhOzubEFT/PURTJC7JnVbgkZTpIlmEIFNeuQsNH21zAwHwCb4
         Pcn/6hTg6CzOOt4BF0SKjjHKs6UKltaDHIodK5C/wTUKtAQCAU+yqOuj4PHrEJzQgQ6d
         gh93/3BmXfOM47j/BAVxBojCmgYxK4+AvwW8QmJNz3gr5PvvaR5Yc4qa/BkMWXltvb+L
         LysYwltyBOAGVP2FSa9BqdRTx69EpxErK7Hf7qFbCsLLYt8d1leHO2UI1a7uYXIKWv64
         2nFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TwrM5M5C;
       spf=pass (google.com: domain of 3uwydyaokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uWYdYAoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d24si344521lfa.9.2021.02.05.07.39.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uwydyaokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id o17so5595211wrv.4
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:37 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c5c1:: with SMTP id
 n1mr4107578wmk.163.1612539577356; Fri, 05 Feb 2021 07:39:37 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:09 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <1cf400f36ab1fd3c83e7626c3797cb11ebf9ef7f.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 08/12] kasan, mm: optimize krealloc poisoning
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TwrM5M5C;       spf=pass
 (google.com: domain of 3uwydyaokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uWYdYAoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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

Currently, krealloc() always calls ksize(), which unpoisons the whole
object including the redzone. This is inefficient, as kasan_krealloc()
repoisons the redzone for objects that fit into the same buffer.

This patch changes krealloc() instrumentation to use uninstrumented
__ksize() that doesn't unpoison the memory. Instead, kasan_kreallos()
is changed to unpoison the memory excluding the redzone.

For objects that don't fit into the old allocation, this patch disables
KASAN accessibility checks when copying memory into a new object instead
of unpoisoning it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 12 ++++++++++--
 mm/slab_common.c  | 20 ++++++++++++++------
 2 files changed, 24 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7ea643f7e69c..a8a67dca5e55 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -476,7 +476,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 
 	/*
 	 * The object has already been unpoisoned by kasan_slab_alloc() for
-	 * kmalloc() or by ksize() for krealloc().
+	 * kmalloc() or by kasan_krealloc() for krealloc().
 	 */
 
 	/*
@@ -526,7 +526,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 
 	/*
 	 * The object has already been unpoisoned by kasan_alloc_pages() for
-	 * alloc_pages() or by ksize() for krealloc().
+	 * alloc_pages() or by kasan_krealloc() for krealloc().
 	 */
 
 	/*
@@ -554,8 +554,16 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
 
+	/*
+	 * Unpoison the object's data.
+	 * Part of it might already have been unpoisoned, but it's unknown
+	 * how big that part is.
+	 */
+	kasan_unpoison(object, size);
+
 	page = virt_to_head_page(object);
 
+	/* Piggy-back on kmalloc() instrumentation to poison the redzone. */
 	if (unlikely(!PageSlab(page)))
 		return __kasan_kmalloc_large(object, size, flags);
 	else
diff --git a/mm/slab_common.c b/mm/slab_common.c
index dad70239b54c..60a2f49df6ce 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1140,19 +1140,27 @@ static __always_inline void *__do_krealloc(const void *p, size_t new_size,
 	void *ret;
 	size_t ks;
 
-	if (likely(!ZERO_OR_NULL_PTR(p)) && !kasan_check_byte(p))
-		return NULL;
-
-	ks = ksize(p);
+	/* Don't use instrumented ksize to allow precise KASAN poisoning. */
+	if (likely(!ZERO_OR_NULL_PTR(p))) {
+		if (!kasan_check_byte(p))
+			return NULL;
+		ks = kfence_ksize(p) ?: __ksize(p);
+	} else
+		ks = 0;
 
+	/* If the object still fits, repoison it precisely. */
 	if (ks >= new_size) {
 		p = kasan_krealloc((void *)p, new_size, flags);
 		return (void *)p;
 	}
 
 	ret = kmalloc_track_caller(new_size, flags);
-	if (ret && p)
-		memcpy(ret, p, ks);
+	if (ret && p) {
+		/* Disable KASAN checks as the object's redzone is accessed. */
+		kasan_disable_current();
+		memcpy(ret, kasan_reset_tag(p), ks);
+		kasan_enable_current();
+	}
 
 	return ret;
 }
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1cf400f36ab1fd3c83e7626c3797cb11ebf9ef7f.1612538932.git.andreyknvl%40google.com.
