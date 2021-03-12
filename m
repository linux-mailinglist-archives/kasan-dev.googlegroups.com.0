Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDEJV2BAMGQEEWVWYFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 33B573390DA
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:11:09 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id q2sf11625007edt.16
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:11:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561869; cv=pass;
        d=google.com; s=arc-20160816;
        b=f+IdeA8BCiq6DJ/4U4KfgZM9TqSRhWnEH39hFFuDnBnc28iRAAR5bvzWbeYWp07jAw
         vHwub/aYno0xv+OKabGKPtBPWQWtgXFD9qCvHEYV3KgqoiIxP9W1PDUO/tFAWbyThtNk
         ncgthfcJRaycwfhEkUEIhcPGEv9QD+y3dDMinVCuGeJ21/HLc1spV38BSJU5KVCm9zBe
         kiyvGAC1V6yQGfR9SHDk9TgZcF3dPZFsboYqToaf7sP3fiTvdbSUkn2Mf2TnauiaXW4H
         Bipw5wcZiKmYWemyEW+Dx/vVihxv8Zf3bWfAG6uDmFuoxFwjlWpcdPir10MifcsWPuK1
         /OLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zmriiOBiUC9pkbFzlHzE2YKP1t7epS4CjM6CIRO1BnE=;
        b=HnWV2+5wLUQzecpd3oQn2GQpg+dsTnNjej86560rPitA4MV8w4Ht407DGsZYC57r6I
         2kRHFItZZSvdZ/oN4T7qa6Rjc7etTjQqh7BKxAzVnZd1pIOrDUMVlKnEtRETWnSnLvxF
         miVZu7GmO6aIDTuVpxGKQ6qG9UQcerwvJtbtDSvaBmoRh8Oyv7POhSAUwOBa67v1YuVB
         74I/K97mypaqwKl0A/Z1oEegQXtHR5m1nGEUInPLU38t622+6Uj3E1jKUcOKIR2n3cB3
         BXKdwlzjnOtl0cuYNKff1eHIk925zEVMlrLQmNq3UamOowDs7ZdYkb0k5jMZt24ivBO5
         JI5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="knGlT/fa";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=zmriiOBiUC9pkbFzlHzE2YKP1t7epS4CjM6CIRO1BnE=;
        b=XNT8KPzLpFINkQItZeF6fPGOL3oh+6jVl2x3yvXyIl3y3tY2gHCirSvHnqt9zG0gu0
         gXeuQ2JkGMJ0lclpkYcOycy7uodp5nJxp4+w/OTltGVTBmRJAHuILBx9dWFN8SA6/9SJ
         b23nUsXLvjs7QcZ8PQRkU/8lWu9/AK+aHWbXuwqCH8U7vWshznYLCDEgFimuCa19SJAK
         yDfWKIuinNoQqyxBow4tLBjdKXP6iAEa4r3CbajaFwOFJJcSKK49fYsiEczL9EvdHUST
         qwVQgcJHyIRtlDUjbyD5xZHBD44vz5+VUR32VMBXiEpljtubkeSIq4P6VnA4W650I0/P
         Lyqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zmriiOBiUC9pkbFzlHzE2YKP1t7epS4CjM6CIRO1BnE=;
        b=lcJ4AhnOnuS3PQvS8WE1BXZKvW7BBO6ERxbc5ZLKsEj/2ZwuKHYbN5R5wt7SOuyJHT
         8MPg+mvGUpujDNXRX8sawQvBtRZcxpzKiiQsEEQr6xnQVMYewR+Kiy+HOJ5jthP+UTgx
         0qjAfXuNaBzspGdu+AK1XM0lziaJtvFUmwsOkHw5sQe2Yju+ldIDrkO1lUhqjM+2ii1F
         Rg0CIA28vNvyalcMnSFEs19Q7drLBW15h0e4U6ipnAHz2DaEeMdn2V1JKK5p9u3tVQfj
         RSltQa2d8isq7LrsKbz8poAdkPULU/fDOs80OBXrpwjaA2OE7GXDGWVkP0yhaYlgSZgL
         0ICg==
X-Gm-Message-State: AOAM5337WXeMk1hr513P4lR70YBJVa2yJWmVBWqx9qPZhqjGFzue+X/v
	zd1Uas1qEN4179K082B9Eb8=
X-Google-Smtp-Source: ABdhPJzxofcz4VL4WkKaMDVUKO18SCZwpLbRBIkna6A9d/DD8AgoScJS2S5CwToE9A9EWeqngaOBPQ==
X-Received: by 2002:a17:906:814b:: with SMTP id z11mr8995605ejw.290.1615561869013;
        Fri, 12 Mar 2021 07:11:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1553:: with SMTP id c19ls2291301ejd.1.gmail; Fri, 12
 Mar 2021 07:11:08 -0800 (PST)
X-Received: by 2002:a17:907:d15:: with SMTP id gn21mr8747262ejc.337.1615561867993;
        Fri, 12 Mar 2021 07:11:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561867; cv=none;
        d=google.com; s=arc-20160816;
        b=NwKhvi6OmV1c8kK/XmXWRnlItlbfSEgGGU1RR58ju0/8syngL84qMZN1YmGdTsBsHd
         cSj4DxA3dslw4+uvRLJDOWTcmZgQwZa68Cf0lATXrlDhpBPU5+xMhwpaf991caelbQq/
         zUZH5mCz0O28Cm8oSQVFzmV6MMhCQLIeRuWwHQ3xokAtgXe1vX+8jNE+flJACCp2q+k0
         te/3zv1Xplqc7hqQ2mN2qkvN3h4PUf9poltDfWC9RxCrg1WL0p45t5hYfy5PzkCYDwoW
         XbqNrsOKigJPvYqf1MN/R5NwzyYUlGuegfXwvr+Q+/VozNBUzKsS96Dchc5MB5rNgF0s
         Kf7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jcr1/ntj/CbpMghQTHSbkEub+1AngnBAtvqWktUi4eA=;
        b=NLnMGiUQ/tbSzxSSIZES4wX9tb2c1ekMCTuTT2eLACPxeU+s5k1c/4SB1IZBuXYVGs
         1Z49FaV+y1L494OBUoywZE9NtEw8X2Y2M0uhJ6P7MmjG36B58D9AKeLEmYsZgCQzdyf9
         qeljQCCqeEc9u1jtYqSqXlEyDtl6iiZDrYgWkwHdnND0VJMGwkYbVK9AJkmP/Z5tCqp+
         +JLY8DBVcLkKubvUJjqORzX5f/iQKsbz6CyF3stxcB5M7twVGwppbyuTcZpg2H3dqUrr
         xvmCJr+8wDK3ImGxfxFemqSLBXQDZFOV1zp6b7Tb4Ty5xiw5b8XuAxRRYqTp77whstML
         Ac7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="knGlT/fa";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id df17si275136edb.3.2021.03.12.07.11.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:11:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id y124-20020a1c32820000b029010c93864955so16011717wmy.5
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:11:07 -0800 (PST)
X-Received: by 2002:a7b:c242:: with SMTP id b2mr14133600wmj.119.1615561867587;
        Fri, 12 Mar 2021 07:11:07 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id z25sm2801177wmi.23.2021.03.12.07.11.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:11:06 -0800 (PST)
Date: Fri, 12 Mar 2021 16:11:01 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 11/11] kasan: docs: update tests section
Message-ID: <YEuEhc1JBq5dTpxp@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <fb08845e25c8847ffda271fa19cda2621c04a65b.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fb08845e25c8847ffda271fa19cda2621c04a65b.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="knGlT/fa";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as
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

On Fri, Mar 12, 2021 at 03:24PM +0100, Andrey Konovalov wrote:
> Update the "Tests" section in KASAN documentation:
> 
> - Add an introductory sentence.
> - Add proper indentation for the list of ways to run KUnit tests.
> - Punctuation, readability, and other minor clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> 
> Changes v1->v2:
> - Fix missing snippet delimeter around "test_kasan.ko".
> - Drop "the" before "test_kasan.ko".
> ---
>  Documentation/dev-tools/kasan.rst | 32 +++++++++++++++----------------
>  1 file changed, 15 insertions(+), 17 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 5749c14b38d0..a8c3e0cff88d 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -411,19 +411,20 @@ saving and restoring the per-page KASAN tag via
>  Tests
>  ~~~~~
>  
> -KASAN tests consist of two parts:
> +There are KASAN tests that allow verifying that KASAN works and can detect
> +certain types of memory corruptions. The tests consist of two parts:
>  
>  1. Tests that are integrated with the KUnit Test Framework. Enabled with
>  ``CONFIG_KASAN_KUNIT_TEST``. These tests can be run and partially verified
> -automatically in a few different ways, see the instructions below.
> +automatically in a few different ways; see the instructions below.
>  
>  2. Tests that are currently incompatible with KUnit. Enabled with
>  ``CONFIG_KASAN_MODULE_TEST`` and can only be run as a module. These tests can
> -only be verified manually, by loading the kernel module and inspecting the
> +only be verified manually by loading the kernel module and inspecting the
>  kernel log for KASAN reports.
>  
> -Each KUnit-compatible KASAN test prints a KASAN report if an error is detected.
> -Then the test prints its number and status.
> +Each KUnit-compatible KASAN test prints one of multiple KASAN reports if an
> +error is detected. Then the test prints its number and status.
>  
>  When a test passes::
>  
> @@ -451,27 +452,24 @@ Or, if one of the tests failed::
>  
>          not ok 1 - kasan
>  
> -
>  There are a few ways to run KUnit-compatible KASAN tests.
>  
>  1. Loadable module
>  
> -With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
> -a loadable module and run on any architecture that supports KASAN by loading
> -the module with insmod or modprobe. The module is called ``test_kasan``.
> +   With ``CONFIG_KUNIT`` enabled, KASAN-KUnit tests can be built as a loadable
> +   module and run by loading ``test_kasan.ko`` with ``insmod`` or ``modprobe``.
>  
>  2. Built-In
>  
> -With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
> -on any architecure that supports KASAN. These and any other KUnit tests enabled
> -will run and print the results at boot as a late-init call.
> +   With ``CONFIG_KUNIT`` built-in, KASAN-KUnit tests can be built-in as well.
> +   In this case, the tests will run at boot as a late-init call.
>  
>  3. Using kunit_tool
>  
> -With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it's also
> -possible use ``kunit_tool`` to see the results of these and other KUnit tests
> -in a more readable way. This will not print the KASAN reports of the tests that
> -passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
> -for more up-to-date information on ``kunit_tool``.
> +   With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it is also
> +   possible to use ``kunit_tool`` to see the results of KUnit tests in a more
> +   readable way. This will not print the KASAN reports of the tests that passed.
> +   See `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
> +   for more up-to-date information on ``kunit_tool``.
>  
>  .. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuEhc1JBq5dTpxp%40elver.google.com.
