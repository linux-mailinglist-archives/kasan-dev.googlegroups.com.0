Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH7FV72QKGQEPSZ3GNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6869C1C1089
	for <lists+kasan-dev@lfdr.de>; Fri,  1 May 2020 11:57:52 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id u4sf666203vkl.7
        for <lists+kasan-dev@lfdr.de>; Fri, 01 May 2020 02:57:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588327071; cv=pass;
        d=google.com; s=arc-20160816;
        b=i45LNoYjJpwVO7sEAFmmZY4516lr8erIwVcuyA4oheQTyuyh+F5JWmfOtHlYQDr4a3
         iz76KEEUAFejaiy7RnEMK+lq+5dzBglIYEjaWFPBDA/zySuMZJcfKu7MhrH90SEoKu/3
         Rq25eCulYDpCgPjAel6fY2RTaBkM7sG4c3GK3FZHS9AmAZYskFfUyd3xSLn4kvi2Qlrh
         5RRbgg9V9qyHw0kbkQx3roW7nZkQg8hO2znTiEEnllkLCBHAf6wTw96H+6+4XyRB0F55
         vOVt7j8x/UQYxYfpGVQNYeUsOko1iyE5ufPihQcqk70eJMB103nKmJEQ0LFyNae0tkPA
         Ho/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=38bIR/AlyYNZzJk6dvpWiMyZM66dr756eOfUBVLsRo0=;
        b=Yx9OSpatg3toCG88p2ItyRSS62o3kBg2mT5bfa0tTAsV0aBzPEub7fDToNvzmeDNP5
         MLnKWFAEOCUVJFVsMDUvHBghHj8z6rBQ8cBRbn+HaVHsgwBfQeGRkJlceJRt60SMlCMw
         bGp8nkNnHbf8C+Ruc/m1K5xkQcVrfwKVgiDAzDSo9S48njLtKUm3VQ3hYIh5w7f41qnn
         yVvxF3Yj3MrhKx1MJPYyWZVBfgs1HGkLHSvDwlU9F5SgFU0dHPI35Gjm2fm1bLYLIiZu
         iv3XZOOdgPS9EFJCU2g6HnBJ/KEycoEx3KLX/aCJguaTCpZ6KD31nMRHaav1+LQuLUZq
         P5rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RXxxyQky;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=38bIR/AlyYNZzJk6dvpWiMyZM66dr756eOfUBVLsRo0=;
        b=ZnweJizD5pY5R28zfrCV8fwQEpK/WZOYUBDpfrNfq3wLXgbFQ1rGcrqnLxMfRcjxoc
         8YoKrbzAHKsKLagqrf2LO9Q+i0RXXTgSUTrR8ybhjdJ+yMjsftZj3aNfJNPmYyszZ5aM
         /REhqCiEjAnNghNHbL1spADIGNiY1jwzE22Ccx49RROkggfFZ63lsa1oz9c5g7lc94Nd
         p37q5zwygd/0jZOkQH3oL4JcCFgAqBKU20AdWE1JaY9ptVz3CyHZg+MTqfwXuhkCmegm
         ZNQtGHs8G+j9fn5yAlyybhn1riBqKy+rL5JLxR/aHy+CcLkauU7LeMKl0TTWDwGTjHn2
         6r/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=38bIR/AlyYNZzJk6dvpWiMyZM66dr756eOfUBVLsRo0=;
        b=tIBYHj6M73mpYBuPMbK2SkigPsvVqV0nM8M3SRbFBnnCpibPliq8i0Vv83GVKWNuCY
         fkOnLjiZU7fSDe4KX5LWUYM3qWYc8gwE0D4bBawKMWhBR/5UsZ7ez9O70j56mggnfXiU
         liEe2a2u7/0ePFkLw2LzD3URehLfnbFdgwUd0OhfPqM3N/3vW3ei7bUjEJQhEEgmrIES
         Lp3+AqnbSQwt8zlVONNDq6TOCwTFHr+cESG0F+QSR9og+tSv+L17fjA91KDORm5S1TJz
         yY3C3UPpsWoUdLhVSxfCvXmx7J3q/+56oLRNzkg7AQFyJL5kb+//WDSuiSQhqVNZ0UP8
         CjPw==
X-Gm-Message-State: AGi0PuZ4oP9Uoqz2TEBXHWLqJhkq8rHHNrqeYGYObIh7OsNcSC9fnQsN
	SMNjwWTjxfUhHXI3nVEZwIE=
X-Google-Smtp-Source: APiQypKhwz1WvFQP6rEggZY4luBBfXr3TllSn/ur+W92H9mOEy9Jz9NnGE3cxJhXbsHhacFCxOm+mw==
X-Received: by 2002:a67:fb06:: with SMTP id d6mr2397828vsr.66.1588327071487;
        Fri, 01 May 2020 02:57:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2844:: with SMTP id o65ls783371vso.8.gmail; Fri, 01 May
 2020 02:57:51 -0700 (PDT)
X-Received: by 2002:a67:f60b:: with SMTP id k11mr2639213vso.17.1588327071023;
        Fri, 01 May 2020 02:57:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588327071; cv=none;
        d=google.com; s=arc-20160816;
        b=P4+9lfkh4a/V2eKPOzp4C4Kts+yapSHLT8fd0UF727cyPJpObg+IsA+Op/Dqh+04Wr
         femGL77eT3/dxshVKq8Y4/bmDaSLiixHYyVqD918VZUWSfwtvBfMFuSk/+R86tFkbI5/
         ws9ail52NdQT8ejATkh8pIQDQ8IGbJdWufxTRjawWVZ0I/+90mnS6X7XueMyASjUICiJ
         42Sx3P4wbY8tqfpzJ8Ro2hQvGP2/Rd3FlHRr2+Djk6eaD4Sxbd7eIOhOYcRL30AqphDB
         /Gg8dsQ+iFg2NUiulVbguZ+EbqRVytJ9TUDMkgf6qUUuAAoGBUaJEwbr6yEZPwbZo3yI
         43HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nGaU+wKFVbV2rAss2AjKpFbiC5Lau7H8388Zbazbr4Q=;
        b=FW3MgHcj39ZJ8KDEa7Giej2lK9G5rldWiX+iP3Td8Yt9cMIpZlBtuaMuEHrxIDw4HH
         A41cqH7xD7WDzhxwbUariAYfcY6ML2H61RXpGFQCuW9GIfkYavMAQyoj/FPP/PPRPQdJ
         N+AIG1QGj+Ky2YQarQwIzwfyJV9e6BkYWtLBGJwDiJmmr2XtHMr7SfJ3bh0vC5Z63WI9
         V8xZ6LHY1JvHe9dOrvkxVYoaUxVDGRIncl8T0gjetcFrfM7Kxpc+9SMzRSz8wLLsUJfT
         zCzUrd0lKK5G8GY9DFHZLtPVSvdBHcUUdcoiWfHJ7j28X8Dx/lEGB1N5HtdO0rywlGWv
         Gzsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RXxxyQky;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id a65si251736vki.2.2020.05.01.02.57.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 May 2020 02:57:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id x17so617423ooa.3
        for <kasan-dev@googlegroups.com>; Fri, 01 May 2020 02:57:50 -0700 (PDT)
X-Received: by 2002:a4a:e1d2:: with SMTP id n18mr3123585oot.36.1588327070112;
 Fri, 01 May 2020 02:57:50 -0700 (PDT)
MIME-Version: 1.0
References: <20200501083510.1413-1-anders.roxell@linaro.org>
In-Reply-To: <20200501083510.1413-1-anders.roxell@linaro.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 May 2020 11:57:37 +0200
Message-ID: <CANpmjNNm9DhVj5T1rhykEdNBiTvkG-YxL6O25bSfQi8ySh9KtA@mail.gmail.com>
Subject: Re: [PATCH] kunit: Kconfig: enable a KUNIT_RUN_ALL fragment
To: Anders Roxell <anders.roxell@linaro.org>
Cc: Brendan Higgins <brendanhiggins@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "Theodore Ts'o" <tytso@mit.edu>, 
	Andreas Dilger <adilger.kernel@dilger.ca>, john.johansen@canonical.com, jmorris@namei.org, 
	serge@hallyn.com, LKML <linux-kernel@vger.kernel.org>, linux-ext4@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-security-module@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RXxxyQky;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Fri, 1 May 2020 at 10:35, Anders Roxell <anders.roxell@linaro.org> wrote:
>
> Make it easier to enable all KUnit fragments.  This is needed for kernel
> test-systems, so its easy to get all KUnit tests enabled and if new gets
> added they will be enabled as well.  Fragments that has to be builtin
> will be missed if CONFIG_KUNIT_RUN_ALL is set as a module.
>
> Adding 'if !KUNIT_RUN_ALL' so individual test can be turned of if
> someone wants that even though KUNIT_RUN_ALL is enabled.
>
> Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
> ---
>  drivers/base/Kconfig      |  3 ++-
>  drivers/base/test/Kconfig |  3 ++-
>  fs/ext4/Kconfig           |  3 ++-
>  lib/Kconfig.debug         |  6 ++++--
>  lib/Kconfig.kcsan         |  3 ++-
>  lib/kunit/Kconfig         | 15 ++++++++++++---
>  security/apparmor/Kconfig |  3 ++-
>  7 files changed, 26 insertions(+), 10 deletions(-)
>
> diff --git a/drivers/base/Kconfig b/drivers/base/Kconfig
> index 5f0bc74d2409..c48e6e4ef367 100644
> --- a/drivers/base/Kconfig
> +++ b/drivers/base/Kconfig
> @@ -149,8 +149,9 @@ config DEBUG_TEST_DRIVER_REMOVE
>           test this functionality.
>
>  config PM_QOS_KUNIT_TEST
> -       bool "KUnit Test for PM QoS features"
> +       bool "KUnit Test for PM QoS features" if !KUNIT_RUN_ALL
>         depends on KUNIT=y
> +       default KUNIT_RUN_ALL
>
>  config HMEM_REPORTING
>         bool
> diff --git a/drivers/base/test/Kconfig b/drivers/base/test/Kconfig
> index 305c7751184a..0d662d689f6b 100644
> --- a/drivers/base/test/Kconfig
> +++ b/drivers/base/test/Kconfig
> @@ -9,5 +9,6 @@ config TEST_ASYNC_DRIVER_PROBE
>
>           If unsure say N.
>  config KUNIT_DRIVER_PE_TEST
> -       bool "KUnit Tests for property entry API"
> +       bool "KUnit Tests for property entry API" if !KUNIT_RUN_ALL
>         depends on KUNIT=y
> +       default KUNIT_RUN_ALL
> diff --git a/fs/ext4/Kconfig b/fs/ext4/Kconfig
> index 2a592e38cdfe..76785143259d 100644
> --- a/fs/ext4/Kconfig
> +++ b/fs/ext4/Kconfig
> @@ -103,9 +103,10 @@ config EXT4_DEBUG
>                 echo 1 > /sys/module/ext4/parameters/mballoc_debug
>
>  config EXT4_KUNIT_TESTS
> -       tristate "KUnit tests for ext4"
> +       tristate "KUnit tests for ext4" if !KUNIT_RUN_ALL
>         select EXT4_FS
>         depends on KUNIT
> +       default KUNIT_RUN_ALL
>         help
>           This builds the ext4 KUnit tests.
>
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 8e4aded46281..993e0c5549bc 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -2123,8 +2123,9 @@ config TEST_SYSCTL
>           If unsure, say N.
>
>  config SYSCTL_KUNIT_TEST
> -       tristate "KUnit test for sysctl"
> +       tristate "KUnit test for sysctl" if !KUNIT_RUN_ALL
>         depends on KUNIT
> +       default KUNIT_RUN_ALL
>         help
>           This builds the proc sysctl unit test, which runs on boot.
>           Tests the API contract and implementation correctness of sysctl.
> @@ -2134,8 +2135,9 @@ config SYSCTL_KUNIT_TEST
>           If unsure, say N.
>
>  config LIST_KUNIT_TEST
> -       tristate "KUnit Test for Kernel Linked-list structures"
> +       tristate "KUnit Test for Kernel Linked-list structures" if !KUNIT_RUN_ALL
>         depends on KUNIT
> +       default KUNIT_RUN_ALL
>         help
>           This builds the linked list KUnit test suite.
>           It tests that the API and basic functionality of the list_head type
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index ea28245c6c1d..91398300a1bc 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -46,8 +46,9 @@ config KCSAN_SELFTEST
>           works as intended.
>
>  config KCSAN_TEST
> -       tristate "KCSAN test for integrated runtime behaviour"
> +       tristate "KCSAN test for integrated runtime behaviour" if !KUNIT_RUN_ALL
>         depends on TRACEPOINTS && KUNIT
> +       default KUNIT_RUN_ALL
>         select TORTURE_TEST
>         help
>           KCSAN test focusing on behaviour of the integrated runtime. Tests

I think if you want this patch to be picked up you need to split it,
with one patch for each test that is not yet in mainline or the tree
that should pick this patch up.

The KCSAN test is in the -rcu tree, but I don't expect it to be merged
before 5.9. Most likely, we would only be able to pick up the patch
that would make the chance to the KCSAN Kconfig entry once the rest
here made it into mainline.

Thanks,
-- Marco

> diff --git a/lib/kunit/Kconfig b/lib/kunit/Kconfig
> index 95d12e3d6d95..d6a912779816 100644
> --- a/lib/kunit/Kconfig
> +++ b/lib/kunit/Kconfig
> @@ -15,7 +15,8 @@ menuconfig KUNIT
>  if KUNIT
>
>  config KUNIT_DEBUGFS
> -       bool "KUnit - Enable /sys/kernel/debug/kunit debugfs representation"
> +       bool "KUnit - Enable /sys/kernel/debug/kunit debugfs representation" if !KUNIT_RUN_ALL
> +       default KUNIT_RUN_ALL
>         help
>           Enable debugfs representation for kunit.  Currently this consists
>           of /sys/kernel/debug/kunit/<test_suite>/results files for each
> @@ -23,7 +24,8 @@ config KUNIT_DEBUGFS
>           run that occurred.
>
>  config KUNIT_TEST
> -       tristate "KUnit test for KUnit"
> +       tristate "KUnit test for KUnit" if !KUNIT_RUN_ALL
> +       default KUNIT_RUN_ALL
>         help
>           Enables the unit tests for the KUnit test framework. These tests test
>           the KUnit test framework itself; the tests are both written using
> @@ -32,7 +34,8 @@ config KUNIT_TEST
>           expected.
>
>  config KUNIT_EXAMPLE_TEST
> -       tristate "Example test for KUnit"
> +       tristate "Example test for KUnit" if !KUNIT_RUN_ALL
> +       default KUNIT_RUN_ALL
>         help
>           Enables an example unit test that illustrates some of the basic
>           features of KUnit. This test only exists to help new users understand
> @@ -41,4 +44,10 @@ config KUNIT_EXAMPLE_TEST
>           is intended for curious hackers who would like to understand how to
>           use KUnit for kernel development.
>
> +config KUNIT_RUN_ALL
> +       tristate "KUnit run all test"
> +       help
> +         Enables all KUnit tests. If they can be enabled.
> +         That depends on if KUnit is enabled as a module or builtin.
> +

s/tests. If/tests, if/ ?

>  endif # KUNIT
> diff --git a/security/apparmor/Kconfig b/security/apparmor/Kconfig
> index 0fe336860773..c4648426ea5d 100644
> --- a/security/apparmor/Kconfig
> +++ b/security/apparmor/Kconfig
> @@ -70,8 +70,9 @@ config SECURITY_APPARMOR_DEBUG_MESSAGES
>           the kernel message buffer.
>
>  config SECURITY_APPARMOR_KUNIT_TEST
> -       bool "Build KUnit tests for policy_unpack.c"
> +       bool "Build KUnit tests for policy_unpack.c" if !KUNIT_RUN_ALL
>         depends on KUNIT=y && SECURITY_APPARMOR
> +       default KUNIT_RUN_ALL
>         help
>           This builds the AppArmor KUnit tests.
>
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNm9DhVj5T1rhykEdNBiTvkG-YxL6O25bSfQi8ySh9KtA%40mail.gmail.com.
