Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXG32GAMGQEZZMVKIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id C5478457089
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 15:22:38 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id p4-20020aa7d304000000b003e7ef120a37sf8501753edq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 06:22:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637331758; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojV9hD7sQOXrKGWfUKDbwnGsh1YhIz96+ylickcO/1NMJCpJ/NzhPD9329K6P7xGBl
         4Lgrf58Y4n+9iFqOgGu+TvMc596WRzNaHyMBIudcK3llu78sqqfi5aaBTXduVowtsfWM
         BSe8qf6BmtSVOJBFQyGO55vKaVf0kfGdenFojCtsrJzZVnbyt34WSJKe0FWDJACEMC4f
         2PXA5yrrCWLB+QGH16w7Ex6HzUwIYHhxbiJa6cIetgZ4jyMrFHZPq6xPVuvA/aszoVVb
         xfaaTa8YIccVU9EtOtAcE1w8e8P2zkSyhAnl5exjasteKp9pR91MsSMn0kMSmSUiRf15
         vndQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=A5WqzVHtNjGHou3+vJxlZvf+KYG4YY6RwkGOrrBc6y0=;
        b=q6YYGCZ1ZuKIPWY5JUJvghFekdCfwIyaLtiu9Aw+amlim4Ty4u4bT97PtS5voeFiPf
         CEeNcAabFg2wYGdKdaEjTZ53aeIrJea9sROUPCODrQZnjSGcfOlJ++gXzVCWp3nWR4T3
         TfmDPDiSPa/1l9ZZc6kymj8lJBOthBmAgHZlBn2V+6xy5ke2GUZKbJGWewGPaB6Zroc6
         pHC9SJbz2YQiaE+QZVZqHJjVqtz8H8g+LD7O2GeIBa3G7pYjcgR401KDokHPl9o3U7mC
         trPmCyhIHOOp/YYIEkVeGBjtsGW7DeTFksTOuuGFN4a45TU2xi0NK4gNUdmFOSnGqcKV
         4CVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dd6fdpFK;
       spf=pass (google.com: domain of 3lboxyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LbOXYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A5WqzVHtNjGHou3+vJxlZvf+KYG4YY6RwkGOrrBc6y0=;
        b=gEzYAIeLUFH+3Kv9JCCBbcQT0DrxbjQh8qU6/Me16FKM4Oye2ad5MOGcvi2kiah219
         dizOVwYEmdxzOaSqkoGaMiE5R02CfW00KCFdnvdYNBIBrnA4JFM8NrofJu03/F3qAzzb
         cK5uuNpPOOXV0ZM//jpIbOyGQL1kBV8toPLvBvreGwWjPZzmgyp6Pz8h74inh2HugN9L
         0VQ4ouMaiEvYebof+KWF/u6hNYeBH9J091nSXE3qNBLPl8FYQ8GDG36rqzsjGNm+600J
         YksTVszLA9WF+pi9+vI+0Ectu9sWohMH0vAt9aLrzKmLTbnAdSEUbRjozVve6Wc9vpAa
         f8zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A5WqzVHtNjGHou3+vJxlZvf+KYG4YY6RwkGOrrBc6y0=;
        b=xwJ7bSOPX/ramK/PqrMVSyGjiKSOL7GoweYcs6fg3TpJwyUdiiaNArSjBJmYuMB9yw
         t+MVJeI6w3mbEDHhjAwLcgnSeCOKtXZJDtA/M6+4NIB14s/wuvkBtgcV3u07t50uiDLX
         HPrDbFqnzhubJKQ/Uifqbu8RHHhvvG95Py+DkQcZ3kwXArGitwtK0hkfCKL5Y6c6Mh7a
         ysfWkoO8qH8JQCIeYgo52Tlwfwy8SFFe6TANbRj1kkGXiVPSXxulU9CNoakD/lsEisr/
         Cbg9/7MRheA/CoBT44J5Ie0bLyCysBCx79dbuQ+gfKgoyf6jq6Fm9ZQdOIytOdy7Ny9g
         4rzw==
X-Gm-Message-State: AOAM531K2adyyJLSmTYzznvOf7DfpdIEqR5TZDo6YiJTOtDna3tDrMxw
	yG+ZLKb/zbQ7mGdpFwBIDmM=
X-Google-Smtp-Source: ABdhPJwDafCxIsG8+hXnokaPAhi9s3uUV3GIxhCbfn7o+3BnTHkzUBjweAfV5ElDYDhtsSw1AWe90Q==
X-Received: by 2002:a17:907:9484:: with SMTP id dm4mr8102228ejc.307.1637331758554;
        Fri, 19 Nov 2021 06:22:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:c0a:: with SMTP id ga10ls1433206ejc.9.gmail; Fri, 19
 Nov 2021 06:22:37 -0800 (PST)
X-Received: by 2002:a17:907:97cd:: with SMTP id js13mr7995766ejc.357.1637331757444;
        Fri, 19 Nov 2021 06:22:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637331757; cv=none;
        d=google.com; s=arc-20160816;
        b=J/o5MKRG16AqiV4g1p40guaYXbwwudwBLDS84ERqJDqMacNnRdbOH+APBga2BEofI/
         BOoucv/E7ipceyNgUXvavxL383N6cR31V7/2hs9FrCyD4vkVffkMJXfFBMpPZa1+ag2w
         d0Pz4gsuJdV4zSOURUxWK1brIBOjJHYrBBvaElbze5cE/TYon1tfBNvzOoSHO8qny0oq
         iiSxyQSYkU+SzRZR7FnfFa/TJ2/BkX2OY/ELjF6Xjb+3xg+8J+qK4Gn9quTnPNQ07J04
         2nGczURAV0s4sNeJQ65HaehYH9VmytU1pNxz9AZCqE6oLqWFNCT/ct/p25GMvhmCw0tg
         uioA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=IEIj8/RLwMC8pWEHCeAMmji/+yQZYVPCoiXY0EfgE4k=;
        b=i0mHe+8c1TFLO2LoSYqjNeWbXxNaYyrLQXK5OxekwQi1JGZDSMgxN+wtSy+vYeuCTn
         Ci9DjvSBQfgWM8TI6C94apPzYZaVtMy6i0YEQW0V5q+LjHHCGt/xYyKiIya8KkKO0dcO
         n2b5fUGJ8Re0TP/uXlfK5/JERF6NNf2R3EsF14bNO8km8Y+jceWeIMhXBXs7/z7fR6Yf
         +2kzJ9a797ckrL51hsMgdla6H4Kcc+XBqWpSJVvHx2ymGVIcwotPPvBwqOozQNF7g4nz
         QlnYRPP9gvsxCSIIn6ZM6DsWg18JQq7Jl1m7XE5Z8OVNRGWE+ktzpiDge6jEzAKsR3We
         l4Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dd6fdpFK;
       spf=pass (google.com: domain of 3lboxyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LbOXYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id w5si1808ede.3.2021.11.19.06.22.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Nov 2021 06:22:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lboxyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id r16-20020a056402019000b003e6cbb77ed2so8523588edv.10
        for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 06:22:37 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:24a0:cdec:f386:83d0])
 (user=elver job=sendgmr) by 2002:a05:6402:2210:: with SMTP id
 cq16mr25134631edb.32.1637331757116; Fri, 19 Nov 2021 06:22:37 -0800 (PST)
Date: Fri, 19 Nov 2021 15:22:19 +0100
In-Reply-To: <20211119142219.1519617-1-elver@google.com>
Message-Id: <20211119142219.1519617-2-elver@google.com>
Mime-Version: 1.0
References: <20211119142219.1519617-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH 2/2] kasan: test: add test case for double-kmem_cache_destroy()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dd6fdpFK;       spf=pass
 (google.com: domain of 3lboxyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LbOXYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

Add a test case for double-kmem_cache_destroy() detection.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/test_kasan.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 40f7274297c1..4da4b214ed06 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -866,6 +866,16 @@ static void kmem_cache_invalid_free(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void kmem_cache_double_destroy(struct kunit *test)
+{
+	struct kmem_cache *cache;
+
+	cache = kmem_cache_create("test_cache", 200, 0, 0, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+	kmem_cache_destroy(cache);
+	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
+}
+
 static void kasan_memchr(struct kunit *test)
 {
 	char *ptr;
@@ -1183,6 +1193,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(ksize_uaf),
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
+	KUNIT_CASE(kmem_cache_double_destroy),
 	KUNIT_CASE(kasan_memchr),
 	KUNIT_CASE(kasan_memcmp),
 	KUNIT_CASE(kasan_strings),
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211119142219.1519617-2-elver%40google.com.
