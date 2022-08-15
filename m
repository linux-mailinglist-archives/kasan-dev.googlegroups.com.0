Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBWWG5KLQMGQEALG56TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3372A593A82
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 21:49:48 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id s6-20020a17090a764600b001f551416ef5sf4197700pjl.4
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 12:49:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660592986; cv=pass;
        d=google.com; s=arc-20160816;
        b=mtSe7RXS+YSKqkxui2YcIckIQMgrfR4rNHE4iKZzw/U5klVFBnxtcmy+pnECBSCFbH
         ADFzTUbY9xkLqaj20VNlynaldmrzIXXyni4qh1845+4jAmIDCYLH4jQUTqy4+fw+OcRc
         y7Flrd565e6JUMa2upLmDujrNw8/mb0l07dgUikmfTSWXegVgdPErckCf7ZLo0vatVNa
         vt2zWUcn4RxjoclPoYRi6p0GDFA3/S9taHUqQTTP+oBHtlhMdUWZ3O85dANJw2DU69Pd
         02YPxUdJiKt24d/8Ap/z6nMehY0i/4HoPLU714ygyt/EE6wyH0cGSyQGve2ybDcQNixf
         9dQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=rw5o6HxV1WW6vUYrxYAL3XYrR9gx+p8yiiUPa3NWm+M=;
        b=g/fJ0wGQA9TxgoX+uIkIkgC1o95oSGvrRgdwO6rEY8D5+YJLtScw9QxIeyvl/uhCw6
         brFqQKmryWBUL+dXmgVUyAegZtA7ovdNzTa3S3mo1sxa0tbQ5twaXB5Sf1O8qS6uixKc
         9rfEXrCvhDMHncN7hf163UfBesmdCuAv6hQm2pzHgeAtNpHa0Nhwy3pQghmCKfbCxtFd
         t/DbFX+1y+TV69Xo2Q1oWiYQE65wL9GGMtg4sBMDFo2hY0in6iWqWJ1DJwwqQ/LFUAkl
         LDN9L4YiqnWrrTM9kHe3iqDkBurro3IdvgJ8QqZqVTyQoCvtkX0UtQNr+1NjWubiSAsx
         Homw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=dbiLDWCW;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc;
        bh=rw5o6HxV1WW6vUYrxYAL3XYrR9gx+p8yiiUPa3NWm+M=;
        b=TTXSn4yKWH/CRefXMNXgqXgjp+OpwvHRr8+tQ1obmBls8hLrvqfqX9QuUfsvvsgKq2
         2XONx+UGdW619XnFlLaM5MIUdqkPz2vNzlLziJbth9Eovdb4iKxURfKMBlA939+d6zKM
         32odAq57+wibmuZclzToM28DBTft1/QhYloLopb05IXbpGPkNXtXlGnJyD+NnaeHZsV3
         1C3hXYC1tdRFO/jsSee4FP0jGT+gATDk5PS3neSauL00DXAEbX9xdM7hVlIsUAZ45vQe
         Sb32u6nFokWxqA6xmG8JmxdPY97XEeLiiG9/OWa3blzbOJc2GLl0hLuY7DwB/aq7y+gq
         TvJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc;
        bh=rw5o6HxV1WW6vUYrxYAL3XYrR9gx+p8yiiUPa3NWm+M=;
        b=6FmEuwtzZgULOtDWjdxVfZk/kVtBMw+Wfa5zHCHUUBiv44U6Y88ZAduCXqUBuEGdWZ
         Vhn8ktvMrU9e9SmcF2wi3kgg+VtLMU5YzS1JFJk+p8fifEJtFm7/SJa078dnpaayhGRn
         Jd/0w+amB1gOHZWRSYZUU+gzxZuye9aqfPE4cDkgPIpyz7aDghc5OT4noJnzGQK2BmrN
         doxv2FfhFNaW+PB/hsd5awzByC6CVG+eXwssQuj5wxuFe0OWGKxDbxejj+v/OJ3ofNGP
         IDfZTGN18e/w6JzF8yHtMTsj/ljiMgnPKw0QJHvc5EE2XhuODOm7JR/8+LUpI5PDC/R+
         Y60A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3jP5ol4yRv+clQE40og0BGvIECYtG+CTQkE9a0xxrNnnJ7VIGU
	5OpZQ8Hb0MdEupKUFM9GONQ=
X-Google-Smtp-Source: AA6agR6BVB2hiEC54JHuHR3ikgKn3Nr/NXACSOaSZtQo/udQEejTeqmVg8yly2v3kTZdWHZXW6s3tw==
X-Received: by 2002:a63:d847:0:b0:41a:dbc4:ef9e with SMTP id k7-20020a63d847000000b0041adbc4ef9emr15044053pgj.379.1660592986447;
        Mon, 15 Aug 2022 12:49:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2dc3:b0:1f5:35a6:600a with SMTP id
 q3-20020a17090a2dc300b001f535a6600als9596754pjm.3.-pod-canary-gmail; Mon, 15
 Aug 2022 12:49:45 -0700 (PDT)
X-Received: by 2002:a17:90b:1110:b0:1f4:fc9a:be2d with SMTP id gi16-20020a17090b111000b001f4fc9abe2dmr29254271pjb.41.1660592985751;
        Mon, 15 Aug 2022 12:49:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660592985; cv=none;
        d=google.com; s=arc-20160816;
        b=NI4DP2eoJd+kGTDe1Wdw9ecwcB3+tXb642K5SuMlvSC07gnD2eaRQlFjMss7Oqriu9
         7WkA/TmZrwvjtQAhhqRR3Ko0YDsishVIqjU/BDrlTCtQqZnh4licc/DRCLnMERC6AWbK
         nu7y7TuRBbHanyq2erFHxAAmUHpRK7g3AcPAFJP5AtV2+8U17BVpy3kxyJXW7z5y+mpg
         mqAmHlNLbtWv//4viUOpB3C7X6y7+xyULrG8ZAVvx1XxJYhEkHmZAC+hO7hTNCZmqGKP
         dXh4V3lBzOYef0pbUzAW4XBuGjyjE2mPOs4PM94BfhLhYlTYfihfq2KRPXAcUr0jNOq3
         g6cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=gEsiCc1uHZf2iIl1jS/mS/QK/9xcwoIBVTzboVIh2IQ=;
        b=OZFARrJSZoITBBltE7kAbHCF9oAsSgIOwM+EzsAa5z2toeFOOyrf02NlD6vje1w0+4
         PHN0ZeyNJHcRaHN78xbl8IMq7Fq9BRBLxSoEcjlVZsNG24Z1TInuJXcam+rhnjqKz4h1
         7ogR15+eaUBq30nGZeIAdbw8yFCjvVEsyUpgsz4+8Oyu1DX3ZBBYzoBrBOSrKYaBQdV6
         ei4KmCy54EYLp3M3wypDhpMwkNbbNRta7ccF4991zogfAOH6aBUUS+ihg+lTMRibtx2t
         q/Re3OejMKhmSzPbQMy/I8gR7CY8tF22qqIq9VmRixLni9TLaxd2kf6g9GJxaks3mWIT
         0AGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=dbiLDWCW;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id f64-20020a625143000000b0052fe780ae79si439445pfb.6.2022.08.15.12.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Aug 2022 12:49:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3366861262;
	Mon, 15 Aug 2022 19:49:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2CCE2C433C1;
	Mon, 15 Aug 2022 19:49:43 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: linux-kernel@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	stable@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <keescook@chromium.org>,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 5.19 0196/1157] kasan: test: Silence GCC 12 warnings
Date: Mon, 15 Aug 2022 19:52:32 +0200
Message-Id: <20220815180447.555804762@linuxfoundation.org>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20220815180439.416659447@linuxfoundation.org>
References: <20220815180439.416659447@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=dbiLDWCW;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

From: Kees Cook <keescook@chromium.org>

[ Upstream commit aaf50b1969d7933a51ea421b11432a7fb90974e3 ]

GCC 12 continues to get smarter about array accesses. The KASAN tests
are expecting to explicitly test out-of-bounds conditions at run-time,
so hide the variable from GCC, to avoid warnings like:

../lib/test_kasan.c: In function 'ksize_uaf':
../lib/test_kasan.c:790:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]
  790 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
      |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
../lib/test_kasan.c:97:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
   97 |         expression; \
      |         ^~~~~~~~~~

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
Link: https://lore.kernel.org/r/20220608214024.1068451-1-keescook@chromium.org
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index c233b1a4e984..58c1b01ccfe2 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -131,6 +131,7 @@ static void kmalloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	/*
 	 * An unaligned access past the requested kmalloc size.
 	 * Only generic KASAN can precisely detect these.
@@ -159,6 +160,7 @@ static void kmalloc_oob_left(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
 	kfree(ptr);
 }
@@ -171,6 +173,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
@@ -191,6 +194,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
 
 	kfree(ptr);
@@ -271,6 +275,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
@@ -410,6 +415,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	OPTIMIZER_HIDE_VAR(ptr1);
+	OPTIMIZER_HIDE_VAR(ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
 	kfree(ptr1);
 	kfree(ptr2);
@@ -756,6 +763,8 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	real_size = ksize(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
+
 	/* This access shouldn't trigger a KASAN report. */
 	ptr[size] = 'x';
 
@@ -778,6 +787,7 @@ static void ksize_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-- 
2.35.1



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220815180447.555804762%40linuxfoundation.org.
