Return-Path: <kasan-dev+bncBAABBMWH2CEAMGQEWUTMX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id F10243E98AE
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:23:30 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id g70-20020a1c20490000b02902e6753bf473sf2411260wmg.0
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:23:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628709810; cv=pass;
        d=google.com; s=arc-20160816;
        b=Buo0crQKD6fZ7lNBuk83wBZ51AgpSt+ELzIhE/xH2kNOLZbzr+bmfxLiBbH0hmhcXJ
         XcB9ykv4DsenlJWIRKueZhDeA3a7nU1XNjwzTX8MAZtSeonwFYuid4Yk0UjdMRGaGzp8
         t4Wq8OiOIfZHzKtiNHPDE9MtgPnYGBJg+/+KnyZSVIFjSKuO01BDBfbBgtWh0iNjDoSQ
         LGXatXEsv3CvjtEd3iFlTVnl2D+paEaKlcaAgfn9JpTz1CtmNtrYF+luNARX6RV28A8i
         J4uiIu/+uFTmzQY+ZvVBCnEMSUsKoe3Hn3NyVs0XFcmD3Zm0bz6H2qnrP0y8w7keI4eH
         9j6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ukNvZVXR6WkQpRXcTDHQP8vqS0Dq8/R+3h/2Qr8MIv8=;
        b=UL7qCLwdBb2ArBY4DI/iAG1OTFvdABDUQy7R8qYdNdK50XpLBoFpZZln8O54GYxrz0
         cnbRbwwSmwmLT7j+xOu7MRNtIi9gpNoDCO+xIGL9jIj2OdiRL9qZzguxLsgN8PhvSQeK
         USk1Z81awFgK8uPpbIwqkZG7bVkkUKwbRUlLykY/wgIJgRF9Y6d8morAxiNcxTV1YZ2o
         +IBg+6V+I8WcUc4CY2otK27qbBvOdY/7uK7fXxAMqRhGayBQs/u5OwTjFcOsxNKFZiDy
         QI3NiJ7Mgld2uKSM/4IJG9a1I2FpvfrD+uUr/wz1DEtqIri5c+vf0pyBBJaG1QEMsar+
         PDlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mtaLyk+u;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ukNvZVXR6WkQpRXcTDHQP8vqS0Dq8/R+3h/2Qr8MIv8=;
        b=Meqte8p5GrG9iYjnuXQOJY8/yAlXC+wNltQYrG5EvKbUXLG0daKD7ca1jRyKY0r4JY
         dlDl9ajHnv0Wzrwh3PLOsqIaRLM9dCUPg6KU8VTNsSZZy+sYDvAPDtO+3lYNKb+lZPMJ
         9cDnps1y6hxZYd3x9RvM+s0VX+LO6RxLI6KBHKFeBeGoM52CSEzwgrr5nAGy2Pev/cf7
         F3aoqjvDVe30DRFsRwIPM412VHkD7ysoxL9iEIqZNAi9L6EeF2/nISvxZriZmJrVGSx8
         cf7kSj5lYpOIxGI7nucZ+LbgnE7lV3vMnf/w3hkqWILPDVjEOVi9yBgg6aYep7JPGrLr
         CiQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ukNvZVXR6WkQpRXcTDHQP8vqS0Dq8/R+3h/2Qr8MIv8=;
        b=IRYbO69JHCKsJ87jlsnUao8CXd58N92OQ/JABUOfUOx9mKMG+p3j5PdYyRtXEGcr+e
         y0fRsp0Xbsppyn7IpTse5WEb/9pCoi2hthXO4sB6o/G1HNDXyWbtDISD95zYgcWJ4Jv3
         HXX2PEnwdL4ctJj4QBR9xiYRklgbR3QVHHudHg7TGJFN9RzR//JqMo9Si9nQO+I/jhft
         95IkOpY2sjbyBli1fdHZSC0f0ORo14gaMhWxVx5KDdjbRl/drp9qOD7Xw7j8wcX6F7jg
         vdSlYWgmtLpj5OuLYCGrBveJrACzbm/V/qtA9HUOGYmzk6c2noGg2UceWFx42igNGFZB
         xbsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HgRVmXbeX5e2Pkdhyb8KPZmYwVV/Z2gfSwkkstU69W7z4ETQM
	MCVnYdqOz6bA4/0LTPn64kQ=
X-Google-Smtp-Source: ABdhPJx4FMmDCzdbOkY7Ueu5/rt7mK1ummMXxxSIy8YseVLGO4UzLP9+cwsk747wQgXGCVjc1QeV5A==
X-Received: by 2002:a5d:54c4:: with SMTP id x4mr32932wrv.83.1628709810814;
        Wed, 11 Aug 2021 12:23:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb09:: with SMTP id u9ls1605472wmj.1.gmail; Wed, 11 Aug
 2021 12:23:30 -0700 (PDT)
X-Received: by 2002:a05:600c:154d:: with SMTP id f13mr143226wmg.0.1628709810132;
        Wed, 11 Aug 2021 12:23:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628709810; cv=none;
        d=google.com; s=arc-20160816;
        b=AzR5IbXBKEGIUzIg1uHgjlF+aYLuPrFTJQ/5GRs6T8AoRzoma97QYvAytrBdrgkviQ
         O3fkS9lNi/04O24cGJAwzJP2oj8issgqEp53clqbPy2aGM7MbE8BkD44vYDoxDGHAq8R
         ZDkh/qRywINm7lplkwqMKBgtsPW2SGOdzIHq4z+LutGDG5ORWkJ/ink9GBxOQ7vZcTO9
         u93l4Z2LCHOWnziUh8358rcWEWJY/yOVL+XV5xNhd62HYZ1+MahsuCLySUojrtanaqZn
         kOJnY1t2ekvrhVqcp8as8lfNtDxyixnTFNo3qbX0GIGlUDvgTfYphprJjK/gLEqtV/8M
         NMAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ID41gjBfMNhlXLlGhJT64AiAC6qEC6DO99tAHE2Cp4g=;
        b=A3dePAsDFuOOrydgBUyjsZm+JkWbR/qrRWBlQrUbbJ+mgB+NGKR1LgbJr8m2+2DFWV
         nxQSAIfUxTfrSRmLwjKYgoXkMV8jq627jQcABOpW7sZa/G5xZe8pbcSd6otoD6SSRcc+
         FPlxnVHAhxoe9yTgWQJOjjMfdpw3stErnu+omDv/iJLbOmhAwBpq2JljV1vpbjnDe6T9
         miNMt7pp9XLjSpLNydMTO3ATFnN5RWLb7+/xa0y78DY+ZKQ5qSQB0bJPKF1ERGzUGzJj
         p99xKFQZkzWQph3DDXMl9xI9ZNKkwd4rAz7AA0c9Ypu0F4CeL2vjmv/o0GHdbngWCjpr
         6wCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mtaLyk+u;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id s12si377044wmh.3.2021.08.11.12.23.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:23:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 6/8] kasan: test: clean up ksize_uaf
Date: Wed, 11 Aug 2021 21:23:27 +0200
Message-Id: <3773f984cbd64f008af9b03e82fc1b317cda9fda.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
References: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mtaLyk+u;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

Some KASAN tests use global variables to store function returns values
so that the compiler doesn't optimize away these functions.

ksize_uaf() doesn't call any functions, so it doesn't need to use
kasan_int_result. Use volatile accesses instead, to be consistent with
other similar tests.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index efd0da5c750f..e159d24b3b49 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -731,8 +731,8 @@ static void ksize_uaf(struct kunit *test)
 	kfree(ptr);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *(ptr + size));
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
 }
 
 static void kasan_stack_oob(struct kunit *test)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3773f984cbd64f008af9b03e82fc1b317cda9fda.1628709663.git.andreyknvl%40gmail.com.
