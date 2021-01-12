Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNGK637QKGQEL3UJ7XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B27312F31C9
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 14:33:41 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id i23sf1059224lfl.10
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 05:33:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610458421; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mp3cRDUSf4U2nDFsR20mcSlZ2obDiVaBdv5u9mSwrV3pNIYLwiuL/2VI+PCS/q+Adx
         ku5EvXJtr0pHz/A1tH2BOxLRNJrwPKEUzOPHZynGFiCSY99j1m3WYdKkknFJ/Fz99gXQ
         /dHZIdzC/pLBu9b2vSfaK5ySaSttPweKLZ316C/mi+LXX5f3Vy3O6yM7Q2/yilA/gv4u
         /qKe3NGadUlSBDaopxAwsYVJ6octynJwv8VYai2IKaY8+UoyEBJOZ3aXQ3vinnGlwzwI
         2zjkyu/+9r0AxskvkJnyZz2FqHstMMtdFc7BSnpXKiw5/7POvRUu1/xdMKNgglKJ4fDy
         P4HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=aCmfMQauDgVJDbnrC8OB/fxa1gM7yVmXtLezdxGHrsk=;
        b=DtR1mVnGGB5HYLHZZDlgM4IrtFcR9VpNC1vNSW9ZWyTLaylev2yDM0rCKz7S/GWC5B
         drn11FSl6ptRNKiiudolW133FsYXhDwE8ffJzAEdlybSDMJsZh0CGH6sv7FPdiBEscM+
         v7bbVhlYjYu0REI8/7TbCgZunBcPH99wgCEP+aQCWkF2qiqqA5dvQ/+YbzisbrrAtjgX
         l6vK82mo9TZcIhkkzERtawTp11kwv5Z2+HMShvAv1ixj3V6zzh7H0WnFoBXWdzigBWdh
         m2N6jUcoasplhiHJ1MGa8xe+S85W2LuXOGcG8rSDij5uqikiqLSi49GHHT4E16cwdv2a
         VP8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LulKNfPy;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aCmfMQauDgVJDbnrC8OB/fxa1gM7yVmXtLezdxGHrsk=;
        b=c4LIxx732+ZLsFYBRv9StxYsO2mzDfuYcr/MD4iC2s0YGKXqj8zVkt8vHIXOPOKrfI
         nXTxQV+7KC0xvJ+WHf8cj/M6tClpPGtZeF8Jq53VPYu94tP8DDtWvqhO9qFgrg4EkSYm
         KrojrXsQnGDkEOwqa/J6SlnzYxVAG/17WSgZNYxWhnQTdupoT5yPtnGiFhAX1PSaR5C2
         3GpOA87yKN4hnJQgVuq1relGSDqNlYxTrWVcMHrOSjW//opTxXJaeRoPc3Zf9xyoGxJe
         LP4QTExA3WiHx8V7Zq6++aFUmD2N+5Vx66pMECdlk21VahxGK3xgCBOw5lyPiiuPr/L8
         cw0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aCmfMQauDgVJDbnrC8OB/fxa1gM7yVmXtLezdxGHrsk=;
        b=q6K5L7hjBSOJWoytsfq7Sp4ywv1qi+NRsRc848mo3U3f6hcJyBHQ36hT76+ieuPfKq
         MhPrPiB6ssw2dEhnhnITRzY8swEn1qWlR/zgMNe6cQkUrA4ToPYRrfhF1vEdtenLj+1F
         XkroWGsRpLTP80B8w/3PnoEjc78LQgZ5Itt/fAl/ACgBm2Lyi/kqBW+wQwU1qmjgND4S
         8ex8fuHZA3uQy/SejkwfsWoXlBNGSNQ/sm9I5WVH0I7ohKJyVLLhnswNVuRhMQk13sqH
         TpbxExS/rd3e6aqXnqfmi4UIvCnuH/jCML8Fu3+pCTVd4LcjnBfI8X9x88qiP9rqDOSs
         eOmw==
X-Gm-Message-State: AOAM532jRGrDgyozgIdT99aMsI9TrBRsfTrZ+dNVd19jG0U0XfojbFz6
	ipbq+BLH05FVvxTQOrKkQLA=
X-Google-Smtp-Source: ABdhPJxffVN2Cxrej85DdBbZ8AnNC3ooEoCxpW9zx4YX/cVrGI79zB8MRlAB0GjkoG7khatcnmyAkQ==
X-Received: by 2002:a2e:b52b:: with SMTP id z11mr2077429ljm.178.1610458420983;
        Tue, 12 Jan 2021 05:33:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls2266082lfu.3.gmail; Tue,
 12 Jan 2021 05:33:39 -0800 (PST)
X-Received: by 2002:a19:804a:: with SMTP id b71mr2149882lfd.504.1610458419806;
        Tue, 12 Jan 2021 05:33:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610458419; cv=none;
        d=google.com; s=arc-20160816;
        b=IMs0ejzD5n1ia43XqNkJK9BIDEZtn1fjuN+VPKOgUAVtbwZNy0ufAv3BdqqftX/24k
         LUytluLZFWn4SweNuAnW/17iuIfOJFEVvGgotE5SXwJdtUrfg7PWOZtKkAhqXyZ46/1Q
         usJAekEOk4/H8VM66kqrULXyANt9Myqj2F6RVu7C+mWKOrgUip8K6dIPQ1w8rggoq3zX
         CuJRKUAt7eCj38olyYid972+m/3+GjRF0QdImwDli8bB9inzL3Uhk/paxUmzsrVHhiNp
         zv4UEtY4cFLC7iKAxxvxauE0kUwC+5yl7DmdP3ZRuhIIkEBIs0iSXtXmw0ZOa9Xn7eAO
         MEVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qMb9wiTztKRoS07hzB3mhdKsb+sq4X1Trw3VZKDYs14=;
        b=NbXnbWqOBYmD5Ns4gQiq37Ay38yygd3ic1vsH+IpLKSTac7yHMtNxFABPYSE4LYsmA
         zgDCUnSP1uDnc4sfdChc5CaQ8ibYRaOkLuc7Z4R9wcSCJhNK+xYGGpGfHTbTr1fojA7B
         cQeWBM8XutaIexbobqvrj+GTC7c8agwq3mHHKIGQxCE04YgoVLE0ecU+1sntgLBwXX4P
         WanGqYfb8QWbf/2vS2oacTlccCLIDTenTKv6BZbiWNYIv8yVv0ExfUrvmVn2bArUVbFu
         +6RlKJrHQvG4fEDURfOVrmqIjfIrxsiZxMR/0K91nAiciLSzdovTVms9TmnG97Jh8eAD
         Nh+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LulKNfPy;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id t65si123371lff.3.2021.01.12.05.33.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 05:33:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id r3so2540758wrt.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 05:33:39 -0800 (PST)
X-Received: by 2002:a5d:4712:: with SMTP id y18mr4402827wrq.229.1610458419201;
        Tue, 12 Jan 2021 05:33:39 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id s63sm4156014wms.18.2021.01.12.05.33.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 05:33:38 -0800 (PST)
Date: Tue, 12 Jan 2021 14:33:32 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 06/11] kasan: rename CONFIG_TEST_KASAN_MODULE
Message-ID: <X/2lLAOWi4PHJh/Q@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <ae666d8946f586cfc250205cea4ae0b729d818fa.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ae666d8946f586cfc250205cea4ae0b729d818fa.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LulKNfPy;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as
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

On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> Rename CONFIG_TEST_KASAN_MODULE to CONFIG_KASAN_MODULE_TEST.
> 
> This naming is more consistent with the existing CONFIG_KASAN_KUNIT_TEST.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Id347dfa5fe8788b7a1a189863e039f409da0ae5f

Reviewed-by: Marco Elver <elver@google.com>

For this patch, as-is. But we could potentially do better in future --
see below.

> ---
>  Documentation/dev-tools/kasan.rst | 6 +++---
>  lib/Kconfig.kasan                 | 2 +-
>  lib/Makefile                      | 2 +-
>  3 files changed, 5 insertions(+), 5 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 26c99852a852..72535816145d 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -374,8 +374,8 @@ unmapped. This will require changes in arch-specific code.
>  This allows ``VMAP_STACK`` support on x86, and can simplify support of
>  architectures that do not have a fixed module region.
>  
> -CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
> ---------------------------------------------------
> +CONFIG_KASAN_KUNIT_TEST and CONFIG_KASAN_MODULE_TEST
> +----------------------------------------------------
>  
>  KASAN tests consist on two parts:
>  
> @@ -384,7 +384,7 @@ KASAN tests consist on two parts:
>  automatically in a few different ways, see the instructions below.
>  
>  2. Tests that are currently incompatible with KUnit. Enabled with
> -``CONFIG_TEST_KASAN_MODULE`` and can only be run as a module. These tests can
> +``CONFIG_KASAN_MODULE_TEST`` and can only be run as a module. These tests can
>  only be verified manually, by loading the kernel module and inspecting the
>  kernel log for KASAN reports.
>  
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 3091432acb0a..624ae1df7984 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -192,7 +192,7 @@ config KASAN_KUNIT_TEST
>  	  For more information on KUnit and unit tests in general, please refer
>  	  to the KUnit documentation in Documentation/dev-tools/kunit.
>  
> -config TEST_KASAN_MODULE
> +config KASAN_MODULE_TEST
>  	tristate "KUnit-incompatible tests of KASAN bug detection capabilities"
>  	depends on m && KASAN && !KASAN_HW_TAGS
>  	help
> diff --git a/lib/Makefile b/lib/Makefile
> index afeff05fa8c5..122f25d6407e 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -68,7 +68,7 @@ obj-$(CONFIG_TEST_IDA) += test_ida.o
>  obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
>  CFLAGS_test_kasan.o += -fno-builtin
>  CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
> -obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
> +obj-$(CONFIG_KASAN_MODULE_TEST) += test_kasan_module.o
>  CFLAGS_test_kasan_module.o += -fno-builtin

[1] https://www.kernel.org/doc/html/latest/dev-tools/kunit/style.html#test-file-and-module-names

Do we eventually want to rename the tests to follow the style
recommendation more closely?

Option 1: Rename the KUnit test to kasan_test.c? And then
also rename test_kasan_module.c -> kasan_module_test.c?  Then the file
names would be mostly consistent with the config names.

Option 2: The style guide [1] also mentions where there are non-KUnit
tests around to use _kunit for KUnit test, and _test (or similar) for
the non-KUnit test. So here we'd end up with kasan_kunit.c and
kasan_test.c. That would get rid of the confusing "module" part. The
config variable could either remain CONFIG_KASAN_MODULE_TEST, or simply
become CONFIG_KASAN_TEST, since we already have CONFIG_KASAN_KUNIT_TEST
to distinguish.

But I won't bikeshed further. If you do a v2, I leave it to your
judgement to decide what is most appropriate.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2lLAOWi4PHJh/Q%40elver.google.com.
