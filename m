Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBDOSSSKAMGQEKMHC7AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ED6E52C0DD
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:12:46 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id ga27-20020a1709070c1b00b006f43c161da4sf1294665ejc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:12:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652893966; cv=pass;
        d=google.com; s=arc-20160816;
        b=cWCA96+SBxhy6Uvm09mXpw4TxzQtsvaInAYSbO63FEv1dEHyYXDxDSiyjLGabcgN/M
         f4JBlf1Z/avmTDCo+nL8XobrqSWiwZnCPz+bI3A12DzkQEKZaku94olRPW3mBloHvBZt
         KUvxFuyxQsZfh5KtucvXxHC1WG2aUMBAkqDv2WwPjt1d5XpJzNaUnHD4DRFI/TG2FQll
         fcn8a00NLFfch1VkrxAimDvxr57ki1BRJL7icCURVSWvWPmbFBekFRrWR9skH5ZPwVz1
         Kwtp6LnJqn9YtKPkpXok1ndcnMj4NvHtG+C/Dk6CmyYf+bgH8XgkrtLkmM6QAthWrzA2
         XGAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BhmeYYYhecjc/jBF695thbGwi6l1yS4+x50yDRvvfiI=;
        b=Tg4pf5Hk8Jj/WxKBgtYAmEahE6mLApaPRwg99Rm70JeiRUvGJuBYp2mfbI05co5/js
         alcXH2S1Gc97epGOWrb/4NGTtN2y0e8e7+1O5XfRxzwnC9jVZ1xaloRX7JKvXF6YArHK
         5l8Zhdxd1HraN7cPClbgZGJyPhXaDxPKS6O7gz95DoxCT1+WwTJS4pVdgjTkOngEqDyA
         7eeG6Bjb/YCDSEnTHh8ata00Ax7INYG5CWRM/lm6eYyLCTNPOatHxxU/MzopWYX765Rh
         HWQjjUuHPaUQQxy/XBeHgvblWXVGGM/C+sJM173mFCTjcVl8HO0kph3Ri7nq3+HtSTxf
         16wA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ma9D+cIl;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BhmeYYYhecjc/jBF695thbGwi6l1yS4+x50yDRvvfiI=;
        b=ROzw8YDwg5YE/02BxJErOOjKqTgDfo2R33pp5hXCkjvcmfaScVeuPIY6WKXpJWUxbU
         tpBiMwO2LoIwWH5kQcRKZJq8RDzIfkkCDcEGtFIg8KN8ien4HMGNAIU6osgZqSuTw7yv
         gaeJqJZD6r3GhxgrjSN2Wfp0kw6coT/JTRmogeivMZyUVRmI7ISomAgUbA9ylIrrnVI8
         RDEJp25TW3hTCzJFiseQ7gkh83HsWXESUqY0hktE1M3Mu2AylRzaTz7ylkXIphlZ+u69
         +YOvn1FNaT6x7Xd8KmTXEEOwdtODESS2LmO1bV/iJmQSD6FHmTdZENrIvlw4ULX9GbkP
         etbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BhmeYYYhecjc/jBF695thbGwi6l1yS4+x50yDRvvfiI=;
        b=XAnKU+oBKdWFLgy2YMWZNKBV+RjvhvT3psqmTLilOX7H9g3MTd1WS+C6ZUKy7Y1bSw
         XOQdmHy5JeKab/pfh6a34KU1Kek3j53kOYX8B6M+Ti133H/4k+bmWgREzT2pqOlsx18U
         O9ejOdD+Of39QHbQeznch+LUEYfLrJTGPM7fkbhkyZ+1L+qbzHusBCFQGirEsO85CvBK
         Tn2CjL2HchxflbiOUAiq1SiGU799pGRmx5dD1PyfVrp9NCaIboznxxLkcck5ME7+Mh7M
         iI21Y0we9C/YvadogsIUjCZjkDkKBv9otCX0Ngs0ghtmA3CG1xNJvl18anIjGtUt+hnR
         gQHQ==
X-Gm-Message-State: AOAM530r+TfhobGN5bDJowlxcWmYkXIJMjIgS9DkAVvAcxsbGJi1Mmgl
	2rLREq3PCpsqeGlj44XPbaQ=
X-Google-Smtp-Source: ABdhPJxNz+sEF8AeXJcZM8MJ8Qprh49qWXTb22kcQa22U911IGzuvYRoUS/QHKG1ZfBik7/q6XayxQ==
X-Received: by 2002:a17:906:478f:b0:6fe:91bb:fa3a with SMTP id cw15-20020a170906478f00b006fe91bbfa3amr532996ejc.333.1652893966100;
        Wed, 18 May 2022 10:12:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:40d4:b0:428:1043:6204 with SMTP id
 z20-20020a05640240d400b0042810436204ls250331edb.2.gmail; Wed, 18 May 2022
 10:12:45 -0700 (PDT)
X-Received: by 2002:a05:6402:2547:b0:428:1dd3:2751 with SMTP id l7-20020a056402254700b004281dd32751mr800791edb.87.1652893965111;
        Wed, 18 May 2022 10:12:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652893965; cv=none;
        d=google.com; s=arc-20160816;
        b=lSaiwmDAbQWxXpHXMcDqBzUmFKtFBs4OH9qUPwbWo/GBfnPT1pb5ClYdTM2jKCUVez
         WorvZrDyN2gUCS4g1W5KJrMOVn5DiJdApmxQ6RzHnHo2PBJmpg/IWJV58vGD2EsSdclj
         NWCCLAoHNxDI2PNY8bEBDSl4XDtSpcx+xWFWCvAgORtPWjz+bGDFWIS1LfJDQHhPl+Rd
         P+b7nB/iJu3kBJuhTkXL+w7yw30UBkmhXNlARfk4iy4W8h4g4CN+RUV7LZb/M9AHh7Ze
         aI0XRVlDM5ot/uuBPv2y2uhGAWVobX+Q4D5u0ytrQBQ5mX7YEtdXKCeRc+4uarfIHci7
         nqDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WoeKVgQABRiIJ4QhptJclADbVq8q7TSfdxFYu0C6EmM=;
        b=wYyNkkSmXEpMcQt/y0X85pKIxCJUkHjijvCZURTsQn2hJ3ApLuZC4JPI8WhwU5xj2Y
         WutOjQKjm4ZvLX2bxijAqaZTr8HikFbYt1y0Z4wdeZNG65r9Dqiask7yBlMlB89kF+X2
         0i+Jhhenv3SwKT6pqnkHtZLclpXeu0Smket4kZaAV6Hat/PBGXP5BfiMxkBZIEja0Af8
         HftFprISy7PaX4vcq1D/8YKkHRM+lEH4+sYmZvEcwADjjFX/a27EU/ASFT0VgVkA78wq
         SfOtEROriLb6L0LKHsKAF46W6TbX7E0pFI1naV90vvbG4aovPfW3JDwHoYqP2+kGMImb
         B9Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ma9D+cIl;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id q6-20020a170906b28600b006e8421b806dsi166799ejz.1.2022.05.18.10.12.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 10:12:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id s3so3836726edr.9
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 10:12:45 -0700 (PDT)
X-Received: by 2002:a05:6402:84a:b0:426:262d:967e with SMTP id
 b10-20020a056402084a00b00426262d967emr857938edz.286.1652893964661; Wed, 18
 May 2022 10:12:44 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
In-Reply-To: <20220518073232.526443-2-davidgow@google.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 May 2022 10:12:33 -0700
Message-ID: <CAGS_qxoVucD5N00g3Tjav5gmYQWvxndTWJYHuKY6mH4bkWXGgA@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Marco Elver <elver@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ma9D+cIl;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::536
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Wed, May 18, 2022 at 12:32 AM David Gow <davidgow@google.com> wrote:
> diff --git a/kernel/kcsan/.kunitconfig b/kernel/kcsan/.kunitconfig
> new file mode 100644
> index 000000000000..a8a815b1eb73
> --- /dev/null
> +++ b/kernel/kcsan/.kunitconfig
> @@ -0,0 +1,20 @@
> +# Note that the KCSAN tests need to run on an SMP setup.
> +# Under kunit_tool, this can be done by using the x86_64-smp
> +# qemu-based architecture:
> +# ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan --arch=x86_64-smp

Just noting here, if we go with --qemu_args [1], then we'd change this to
  --arch=x86_64 --qemu_args='-smp 8'
and then probably add
  CONFIG_SMP=y
to this file.

[1] https://lore.kernel.org/linux-kselftest/20220518170124.2849497-1-dlatypov@google.com

> +
> +CONFIG_KUNIT=y
> +
> +CONFIG_DEBUG_KERNEL=y
> +
> +CONFIG_KCSAN=y
> +CONFIG_KCSAN_KUNIT_TEST=y
> +
> +# Needed for test_barrier_nothreads
> +CONFIG_KCSAN_STRICT=y
> +CONFIG_KCSAN_WEAK_MEMORY=y
> +
> +# This prevents the test from timing out on many setups. Feel free to remove
> +# (or alter) this, in conjunction with setting a different test timeout with,
> +# for example, the --timeout kunit_tool option.
> +CONFIG_KCSAN_REPORT_ONCE_IN_MS=100

Tangent:

Ah this reminds me, unfortunately you can't use --kconfig_add to
overwrite this atm.
Right now, it'll just blindly try to append and then complain that one
of the two copies of the option is missing.

That might be a feature to look into.
Or at least, we can maybe give a better error message.

E.g. with the default kunitconfig, the error currently looks like
# Try to overwrite CONFIG_KUNIT_ALL_TESTS=y
$ ./tools/testing/kunit/kunit.py config --kconfig_add=CONFIG_KUNIT_ALL_TESTS=m
...
ERROR:root:Not all Kconfig options selected in kunitconfig were in the
generated .config.
This is probably due to unsatisfied dependencies.
Missing: CONFIG_KUNIT_ALL_TESTS=m

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxoVucD5N00g3Tjav5gmYQWvxndTWJYHuKY6mH4bkWXGgA%40mail.gmail.com.
