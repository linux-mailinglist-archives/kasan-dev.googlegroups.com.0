Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXE5XCCQMGQEOECQW5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 19E9239134D
	for <lists+kasan-dev@lfdr.de>; Wed, 26 May 2021 11:03:25 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id o5-20020a05651c0505b02900e5a95dd51esf149129ljp.10
        for <lists+kasan-dev@lfdr.de>; Wed, 26 May 2021 02:03:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622019804; cv=pass;
        d=google.com; s=arc-20160816;
        b=kejUHFJNJv/YIOb4qruO8bnSByhI1+rSJlXAxG+gsAQgrOvAo5uVzaUAQcWxDM7ZJb
         PXjX1baA/U9rMfPOEOaYhJFY5J3R7JRyNlnZu8Cm3nX+SlG/5j9rE6N8uTF0icIqtgUo
         JwezTvIQdJvdjO2/fA1BQy3FGbwwU/M0LyI7qQ2YtJzRFiE2Q1Xhc8SamEeVoum4uPzt
         qQkpdQ8/xzTUNQWRFGW/gw9WXPuUVWjUhyOp+fELJKyJhGuUbUt/lt7yELKJJcwBaHQT
         Mymd12Xo8tlwSXsFHa+0ehftBohYk03qU3/rnPO12oXZyqHr38fVLOWcMGkcU+rAzqaj
         bdJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=M4WqIZ/XBzaaHXzVIbwnyFpHPQZL1iHwtCDIA2tFFp8=;
        b=rj6nl5zzol3dQwPFE8VcrJsK2EQbyoi2HIfNrH3S9sxnvuMyvm4cCBPIcQxJfmbSnh
         IC1G1PHcXk94JlrVAsfOicyPhWpQYvZYMGwUa6Tv4DepBhGonc1Y8lsIqEx+ehfdZhl2
         RCQlkrLK31sKHEW68d1cTN+HL8nW5xQaJJR3ydKwS9msX73TyEJTJX/91jSjxxzsjX42
         CJAjWHd7aUfAqWmPK9kfXqn8uhusmr47bu24tOirIzdIAzew0A6DCdLMqnQv7+i12unG
         kX3wi3Rrrl4Qp2Ufkp24uBn4iMH4DmXVhigVEjro3fpjOJcTsHbZD+MJmerHitZM6Hsp
         eKuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IKLvO0Am;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=M4WqIZ/XBzaaHXzVIbwnyFpHPQZL1iHwtCDIA2tFFp8=;
        b=LxLqqx8wxpvkQl5Zr6o+TBYl7tEH6v3858tQGv8cqUR+7TsGOstVTGt/mQZU6j5Zg5
         4Y4jj0ICJ0wHsZwbnB9C89OatlDOoo8qJy9C6MexdyjU+B6UMsFh+78sLXpN8t5qrSjw
         zxmxKIZ09LVkxwwKPzBbUqCazdae2RPO8SGBmglS3PSixFD26uMA4DU0wlKMTPojyPuD
         BRzMlNnA5W1Td3d8PHk1w5nN6MXTMsVXfbFvWouLzrbqPwbe2J0ZHYvwffxj8Yt4g1dy
         qx9QBpuBBExLRtr+7vtHAFKmynIIQTMI8ugpIUp1sbVb/HUk7uGpOjCissGJP4etGivH
         apIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M4WqIZ/XBzaaHXzVIbwnyFpHPQZL1iHwtCDIA2tFFp8=;
        b=ssMLB/to+oSl1uRuOhakQe78wIrYJnp3XI7SfVeUQt0BJhGGhL5HNVKFhwM5AfDNB1
         SOSa7zXgJ1oJ8L1ztyhcin+j/E6e6F/3WTljrL6EkbzvPla1lS7pxwGqOB2Cje8rOKD8
         ZiG1iDQnNnsabpF/3/DZCGjKc+s1NNqhxapM5FQIz5Mr0c9m2oQr4VX2787VsxzQBUxp
         UWlAu+Qa85ccIcjn8PWjBOpPJjWhPYs40wWdB4IYg+cwi/Zr5/Apa8N9freZyauTAxsE
         DRnxyeC2agWb2E8yEl2mlYTwzYcdhm2mnvr050WIjRD9h8CfwByaEDz+oitQRdDy0TMC
         lFcw==
X-Gm-Message-State: AOAM5331RlF8kpR6zRZG9ZSWEuYs7bm1LZfBxBAiQMaZTogimRNtt22Q
	2Dvt53ngnoCSSifZkm7yWRc=
X-Google-Smtp-Source: ABdhPJwH4wgHzcOyXW3DKyIvMpG0TFkyWgLWT1bk7rvbxBBefJ2D5tr5GltquBFG/Lq2GntSLwdQMg==
X-Received: by 2002:ac2:44a8:: with SMTP id c8mr1488285lfm.232.1622019804562;
        Wed, 26 May 2021 02:03:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:230f:: with SMTP id o15ls4534555lfu.1.gmail; Wed,
 26 May 2021 02:03:23 -0700 (PDT)
X-Received: by 2002:a05:6512:1150:: with SMTP id m16mr1448613lfg.486.1622019803326;
        Wed, 26 May 2021 02:03:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622019803; cv=none;
        d=google.com; s=arc-20160816;
        b=aqOwxnXgLp0czpOn8WijVtgAhjQYGv3hRO/vWMv5+j42RQuEx6ZqsAxwWmDJm/tsBV
         iepIBcPcUjYQvez+a2MzAHTCGCwjWlne4NbjZbMl6FiohO2aLvLJhAczqKa3TIrWeAnd
         TP/qCTfiWhzdyePT/BCA/JS5AnGjEksF57GOYbTpuTzTRycCYHIO8uRGpDFZCFey2Z30
         VXNTOj099LSYy5sYYZ65zULP37K0wAwAoyX209BZIsWfe8PjBl0EZJBQqDzzzP/JnEsk
         GORgMm0RpdqEptNtDljDZSfDWGwAskO1X+QoUEs+AWLXpTe4WkgDHzV9YkOhYTjYnItu
         S0wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/arfmioWBLl+bsHh1UkXgXV/45lpjUcVc8QQOrErq1I=;
        b=yBeZMuaoqsG6K5ZaU+WKKH4CpDWZFmbQNpS9F8+TCK+rFe/IW9UO2XP7sxZOAVedZb
         0eYxQihZdxDOj6weUiQe+pBOCMzIt2diTuQ6nG0DMQWHebwKTs92ePCUND+T8xaRfcCR
         QH2gJhB0a04yBRt0TMFk6oC4utjfPFvgyY850EpqCTt8Gcqz2/9Bo/y6KpNaAZG4NSjZ
         4GC471aw4W0KjZwkLrTK4Vp7dCCMtgJK9IfnfeZyfBc7peMvABheYhCs3ETTdhzsZJQA
         myQ5gDgikRDbieytrwtUpGez3X6gs+4topkD12s1OebtTGIXqz+2zvCbMM0JIwemRU5+
         KBvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IKLvO0Am;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id o13si911763ljp.0.2021.05.26.02.03.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 May 2021 02:03:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id n2so320178wrm.0
        for <kasan-dev@googlegroups.com>; Wed, 26 May 2021 02:03:23 -0700 (PDT)
X-Received: by 2002:a5d:5688:: with SMTP id f8mr31819035wrv.237.1622019802699;
        Wed, 26 May 2021 02:03:22 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:cd98:de82:208c:cbdb])
        by smtp.gmail.com with ESMTPSA id a17sm19021929wrt.53.2021.05.26.02.03.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 May 2021 02:03:22 -0700 (PDT)
Date: Wed, 26 May 2021 11:03:16 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>,
	Alan Maguire <alan.maguire@oracle.com>,
	Shuah Khan <skhan@linuxfoundation.org>, kunit-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org, linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] kunit: Support skipped tests
Message-ID: <YK4O1DkP1/DKzVU5@elver.google.com>
References: <20210526081112.3652290-1-davidgow@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210526081112.3652290-1-davidgow@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IKLvO0Am;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, May 26, 2021 at 01:11AM -0700, David Gow wrote:
> The kunit_mark_skipped() macro marks the current test as "skipped", with
> the provided reason. The kunit_skip() macro will mark the test as
> skipped, and abort the test.
> 
> The TAP specification supports this "SKIP directive" as a comment after
> the "ok" / "not ok" for a test. See the "Directives" section of the TAP
> spec for details:
> https://testanything.org/tap-specification.html#directives
> 
> The 'success' field for KUnit tests is replaced with a kunit_status
> enum, which can be SUCCESS, FAILURE, or SKIPPED, combined with a
> 'status_comment' containing information on why a test was skipped.
> 
> A new 'kunit_status' test suite is added to test this.
> 
> Signed-off-by: David Gow <davidgow@google.com>
[...]
>  include/kunit/test.h   | 68 ++++++++++++++++++++++++++++++++++++++----
>  lib/kunit/kunit-test.c | 42 +++++++++++++++++++++++++-
>  lib/kunit/test.c       | 51 ++++++++++++++++++-------------
>  3 files changed, 134 insertions(+), 27 deletions(-)

Very nice, thank you.

	Tested-by: Marco Elver <elver@google.com>

, with the below changes to test_kasan.c. If you would like an immediate
user of kunit_skip(), please feel free to add the below patch to your
series.

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Wed, 26 May 2021 10:43:12 +0200
Subject: [PATCH] kasan: test: make use of kunit_skip()

Make use of the recently added kunit_skip() to skip tests, as it permits
TAP parsers to recognize if a test was deliberately skipped.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/test_kasan.c | 12 ++++--------
 1 file changed, 4 insertions(+), 8 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index cacbbbdef768..0a2029d14c91 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -111,17 +111,13 @@ static void kasan_test_exit(struct kunit *test)
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
-	if (!IS_ENABLED(config)) {					\
-		kunit_info((test), "skipping, " #config " required");	\
-		return;							\
-	}								\
+	if (!IS_ENABLED(config))					\
+		kunit_skip((test), "Test requires " #config "=y");	\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {			\
-	if (IS_ENABLED(config)) {					\
-		kunit_info((test), "skipping, " #config " enabled");	\
-		return;							\
-	}								\
+	if (IS_ENABLED(config))						\
+		kunit_skip((test), "Test requires " #config "=n");	\
 } while (0)
 
 static void kmalloc_oob_right(struct kunit *test)
-- 
2.31.1.818.g46aad6cb9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YK4O1DkP1/DKzVU5%40elver.google.com.
