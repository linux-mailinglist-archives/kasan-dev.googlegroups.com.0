Return-Path: <kasan-dev+bncBC6OLHHDVUOBBDMSRL2QKGQEE4WICTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 067871B6E3C
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:37:02 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 17sf3512667lfo.12
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 23:37:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587710221; cv=pass;
        d=google.com; s=arc-20160816;
        b=g6SUkoYAsqGoYdTrHGqVJKt2lVb1hiTr427kwtSJiY3w7rS8AUMnI6cU0tbjJHFcBj
         s/ykIcJB618qqGGJ2BUZZfyZWJAnSwvxYWV2Qx1Eyqs1Uj0YMzPgihwwk/z7/VNuG9QX
         nf3ACFU7YOeco4hHPbOg6rOTGj+QnPt9BoyiWFNFcaX9INFdBafrqjbkXmHTI6aNyQpM
         u/rBOBNFYxbzMstaeDvo+vkSXNaPpGEtQwVJOxRSKNnkas0PsCremkbq4UUq/8/4+0hW
         pUqAxI2+lU6PLA+wyvmjsskwlGmpByBqw9PUPC/PHZduEn4Qqe+w9tro3XJMYq62R5md
         h+pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LQrIyWA9HsnBJuCjgh0ZqNmfz330wjeJGVQXOkC2dMQ=;
        b=FGUtvBtzpOHW705WiBDyAZqPVKzsA2oD0+M1f/kelCh9SvbWJ0n+ikqrXM7t1JP/v1
         5O5yI/WmiNxTfYYDdoaxw6AF5TonTgl6hp/Unf0DHq0fX7rUAPOoQZ1dh3hkSntSU2Fp
         1mJtSZIiZQ6tmPDYS6wBoNkvT/pdlM+Xq28+5zpu8/evPLL5LOEjJz9mKQJwUdZFgoES
         f5K/frdF2EtYSUsdpclzLx2Ezyx0gGZdoyPobTRLv70IerqohxnJweT8H9oe7329Ct/h
         3E8/rxBtsoDZbT50sMcgiKQICoBexOxvUC+DllwfBktvCWoGhy1pRgtrKlVIVr5iZcxC
         JcMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T3WvB9Zk;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQrIyWA9HsnBJuCjgh0ZqNmfz330wjeJGVQXOkC2dMQ=;
        b=N5DNJbeToenV7r2UZXc5gU9LHN9VaeV7fJEUs50jThpMUvr8Z/dv5R4IdmJxNwdQbw
         MMwzVaD8alQ7Z//z7a+auzSuJlmd0Yfn+35SnUMQZN9+y4YJBM2iWFB55QYfuhvmaned
         If5rpjKgLNCzq52O5EapIPizIU0jI04kldnoXZKy7W+qihfU5mF3cIn/IP44K643DUI3
         RkKNu9rXaLM/RmzIlfCA75uzC+yqcxLLToZEGawxVUD/0ii/ulbVbS9RcXPfWbq32ti1
         lYKPCqH+EhL8t58a6VhXD1iT997RfBsAcgntJfLSRQW4Z8m6rqb3QO8ov9PCb5OuLxXe
         zUEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQrIyWA9HsnBJuCjgh0ZqNmfz330wjeJGVQXOkC2dMQ=;
        b=IvGFY7Sc69JvbzfuC0F4t+H2UHtydbOlZLm8cJktasxPu/ADOSsxQYJk++yVTm354U
         RgZw13g1zv9dKpuWI3m1PbHnCfFlMi1JgUinx8lkmolILMHLWSa1v1rWjndXv0FxcY6/
         2Gl3UKSFeaQHBilME0nndehZG11DatIMw1IR0sCySPUGG+BCzTwb3+bDjOAh1Bf+ZGRE
         907FekhjJgmOxuP32iBhOD0ZP4PuVTKUcmZuRa4tiJINfa068YalW5AsF9283q81UQFx
         aXNRfhBRA+new7UBTaeAAhnwmdsk3/Cbqiv0Fp5iSlJ5uvuW509JCqFmf0LGn6Y+fkZg
         IV6w==
X-Gm-Message-State: AGi0PubUCHoro49O0vmCasZnSxXsT0meIJGti3ZNir6ISnuMlytax9u1
	Q7V2EIYBG6+98BANQOBG+pk=
X-Google-Smtp-Source: APiQypJCHYivH4SmFIoEqfdoxObMz1KlgKuC2cvcixGYeXpf8lCobFZSKk3nUaPuE47c/UAAqOEJSw==
X-Received: by 2002:ac2:5185:: with SMTP id u5mr5169353lfi.64.1587710221497;
        Thu, 23 Apr 2020 23:37:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81d6:: with SMTP id s22ls2589077ljg.0.gmail; Thu, 23 Apr
 2020 23:37:00 -0700 (PDT)
X-Received: by 2002:a2e:8813:: with SMTP id x19mr5127251ljh.83.1587710220815;
        Thu, 23 Apr 2020 23:37:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587710220; cv=none;
        d=google.com; s=arc-20160816;
        b=bkoG2vmy9+v9xyfqcnyc7msg+uhwApc/17GkfgLCUpZpLjApJ7Dm14VCZtA41gloll
         /uEMfdwNIhgAUAHBJaA0DZiXtT/Ezdd0LXZk+ByAb7w511iKqjP2385BYXUA0pjChwOx
         MDszg6yvqcpELnN+0R7Od+ERiTWdmrwA/p0gJg67OwRqBSnw8g5V78etJmHLaQhMfhSV
         z7jWzIZEHvlwcIUVmejeVFyE1rVgl+rFlITDd5VJFSuxmktivweltOsfqwHwR7zohT9K
         ns9/Lj4lED5JTXLch7u26yLg2LBHfoeMs7+mQy2z/lXCmD2KmsTS0CwZf5MSGLyhwSR6
         TFfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Nl042EYhQkNdGgGpL0PjYS28b3/nSBEMCyC0XuhXcY=;
        b=lH7hZJrTcfddbMGB/NciyhX6QYYZF8bNsuwCwgaYRTH2WG9UtJLWkY0YkfwqXe+x2z
         5GSexk0gWheT1Pa9e8nTmDv3WDecbowxY3O/JKoeC2rSENOhoVw8xBagZTAPvVxIwh8S
         362W+zeml2FsWybSHO41CN60r6xZSMm1u/blNgrxaWcOxlOPMoZ8oo9MibVVkRJrmvr8
         /k6SFZyugts/Oohg5w7rUcJK+0NqOUJp8zvyKi50L/3daXuza562/LfjstMoY7bscb1o
         VCBX6hmpiLXgQxy+GUuZfMvJyYcLHfgy/1HRnwolI45R5Blp+UGehmtc/XnBL+QJKlFn
         yTgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T3WvB9Zk;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id x145si249437lff.2.2020.04.23.23.37.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 23:37:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id v4so9178764wme.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 23:37:00 -0700 (PDT)
X-Received: by 2002:a1c:a512:: with SMTP id o18mr7973525wme.138.1587710219940;
 Thu, 23 Apr 2020 23:36:59 -0700 (PDT)
MIME-Version: 1.0
References: <20200418031833.234942-1-davidgow@google.com> <alpine.LRH.2.21.2004181619110.12187@localhost>
In-Reply-To: <alpine.LRH.2.21.2004181619110.12187@localhost>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Apr 2020 14:36:48 +0800
Message-ID: <CABVgOS=k2eCMwt-Tz46=mCXg1Kxjb54sD1kW-R=mchFQiCgYTQ@mail.gmail.com>
Subject: Re: [PATCH v6 0/5] KUnit-KASAN Integration
To: Alan Maguire <alan.maguire@oracle.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T3WvB9Zk;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Sat, Apr 18, 2020 at 11:28 PM Alan Maguire <alan.maguire@oracle.com> wrote:
>
>
> On Fri, 17 Apr 2020, David Gow wrote:
>
> > This patchset contains everything needed to integrate KASAN and KUnit.
> >
> > KUnit will be able to:
> > (1) Fail tests when an unexpected KASAN error occurs
> > (2) Pass tests when an expected KASAN error occurs
> >
> > Convert KASAN tests to KUnit with the exception of copy_user_test
> > because KUnit is unable to test those.
> >
>
> I tried building and running and things look good but I am
> still seeing the three failures I reported before, even with
> CONFIG_AMD_MEM_ENCRYPT not set.  My config is attached if you
> want to try and reproduce at your end.  Oddly this config was
> working before IIRC (once CONFIG_AMD_MEM_ENCRYPT was not set).
>
> Here's the failures:
>
>    # kasan_memchr: EXPECTATION FAILED at lib/test_kasan.c:545
>     Expected fail_data.report_expected == fail_data.report_found, but
>         fail_data.report_expected == 1
>         fail_data.report_found == 0
>     not ok 31 - kasan_memchr
>     # kasan_memcmp: EXPECTATION FAILED at lib/test_kasan.c:566
>     Expected fail_data.report_expected == fail_data.report_found, but
>         fail_data.report_expected == 1
>         fail_data.report_found == 0
>     not ok 32 - kasan_memcmp

I was able to reproduce these (along with a kasan_strings) failure,
and the cause seems to be some combination of __builtin functions
being inlined by the compiler and potentially dead code elimination,
as fixed by Daniel Axtens here:
https://lkml.org/lkml/2020/4/23/708

I've sent out v7 of the patchset[1], which I've rebased on top of
Daniel's patches, and can no longer reproduce those test failures with
your .config.

Cheers,
-- David

[1]: https://lkml.org/lkml/2020/4/24/80

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3Dk2eCMwt-Tz46%3DmCXg1Kxjb54sD1kW-R%3DmchFQiCgYTQ%40mail.gmail.com.
