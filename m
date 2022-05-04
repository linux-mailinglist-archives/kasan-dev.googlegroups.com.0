Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFEIZKJQMGQEYQ4S54A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id C34A751A145
	for <lists+kasan-dev@lfdr.de>; Wed,  4 May 2022 15:48:05 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id t14-20020a1709028c8e00b0015cf7e541fesf759830plo.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 May 2022 06:48:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651672084; cv=pass;
        d=google.com; s=arc-20160816;
        b=hcWYZrW/B+dCaY7J+082NImOFhCepxMSJlAHzwfE8wR3eiTKtgZwUH6yZrfGHLAJht
         Ybto2ltLmHUWIYcSDLdZiROHENriJMHqcUn3N0ckEmLRrYx+lhym/KJl4BnEGXEJrCjj
         bco7qlUFL12zxC+KWrG5CZt8aUmbfBbefTgGopODuTu/837Yc0NOmmK9jpiIj0wxpTCH
         cXHAa4LJi0kO1CUnt7vfmCMevfY8P9VdmSTMLjdkCO4p2mUG/RCxu2pZIqqfo5pPf7bu
         eed85gHdCVckaP0nnzyqgb9pjVpfbVuSJiCuNOP8Xf8aRy0/26tPyiUnSCeXUnY2GQFP
         Kpbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mZP3PphyCzqNj76Sc+9SFutl74IzND8cN3Opcqn+Uuc=;
        b=mv9A+eR1zHXlzs9ZnRikYBHvuYv/DblmGcGiAPRX48kS5qMMMhBhRcWw60OQvedpbT
         g0DDSoGHcfqOeIEhs4G/uK5KtN67eL5qFfspYz9KvGeUHsad9JEMkD8FY5T8kugPzKMu
         BtEWyc1z7Ux6heQ1JMrj/JNLb2bB8HRG6yk/Qbb3iB6lC27rqVB3JZ4Hv6hBjFJ1eLnX
         00Vq1bJnijGEhjLNLJXeM1AbyDoJkvFHCn1RSq1JLnwyZUgW/k+7q149mH/JKamUITXO
         NPUFrA0usqcoSdjbi8HO+YOvSAZe9SHFcOGm/zvhwd/S2jMB9gW7ZdNQ9GH4bctNo8hJ
         UbOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="r7wfh/o/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mZP3PphyCzqNj76Sc+9SFutl74IzND8cN3Opcqn+Uuc=;
        b=pnz3PANlC8NYZA46YIJpzyvW2sBfpe1nTTGXD1/OpK8fApBw6LOV0x3hTQUsc1WCmh
         mBVcMmdL8kHwTAPRnS2Ss0cORSClpGwzqhwdQOIBNu4Vf2mn8pJ5ua5bJLoGx4Qig2Aq
         S1g4Ie/dHhkoTXFfAZ+HnrRbJgI0FyJapyuxRkY2cRiJGdMxXpttjH9b74/+P8xHT4RE
         ZiC2dmJxkKwHAzTa0S7AU4S1xlwe/plqqKD+SIDoaMcZFxPJHGzVc+yzuSUK7TCA735h
         e03bLzv0/2SD1PNo6Ih/Dq1KVrbnmuEyhFrgNbS0H+XpcGYCz+f7sbbiSsUPzG+67vE5
         6DnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mZP3PphyCzqNj76Sc+9SFutl74IzND8cN3Opcqn+Uuc=;
        b=FUDuwYv/CPE/vdu6O4SYSz3InfkBc6r4raiIm/SKLPPFtmT+86DHoeq18mHapAlVDg
         329joJ1GlMaJ9gpVMXj/tPzWn3fa0gda4OkJV3sM2EORDcWRxfCgYrHUj2LWsWn/3Pq7
         rYaTv5vEzSLvOdIc6KZr3VHzbt21XUxgYpGae5Crn8eUu/+FyKSc7193bK0yNRGysTMz
         3zxzFx45sVcDxzln5yFgH3jUeIotIN4NvmaPJM/H9kzhliteMMH9zNFUW9UOLX8cdeIP
         on8wszhFqBE3Hq6tnLCYagNjzOhDvTxsLJFu5oLi5tSbW1t5ToWqjZiPeev/qvvLi8cK
         f3DQ==
X-Gm-Message-State: AOAM533cVw16CFRuW3Uu7bblZoJJoObD8d/UjKxcRG0n/vEF2dDNDPIB
	3rY8/iG5PY0C+TFbzzz0MzM=
X-Google-Smtp-Source: ABdhPJwiO8rSjJuHu8YTkDEl6/EewJZK2R9nXQ+8Gsxk45gHEUi3rNB3F+JlOdj6PDqpfj6el078Eg==
X-Received: by 2002:a17:902:9307:b0:154:78ba:ed40 with SMTP id bc7-20020a170902930700b0015478baed40mr21715673plb.92.1651672084148;
        Wed, 04 May 2022 06:48:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1b07:b0:1dc:4ad9:71b4 with SMTP id
 nu7-20020a17090b1b0700b001dc4ad971b4ls4158310pjb.0.canary-gmail; Wed, 04 May
 2022 06:48:03 -0700 (PDT)
X-Received: by 2002:a17:902:8608:b0:158:c532:d8b2 with SMTP id f8-20020a170902860800b00158c532d8b2mr21943807plo.46.1651672083386;
        Wed, 04 May 2022 06:48:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651672083; cv=none;
        d=google.com; s=arc-20160816;
        b=of57VZdeAWXcPVN+7xyOJE1XOHXVYCDmylSV19h+7lOeos+h7xyvP85FFa7qFu93k2
         Z3g1FGL0rPDNqan13nZ8/UJuwS5SeQIx6QfIOMCLzhwHBK+mcVCSyCsG0Ogp4jSe8KbI
         7xSYwRQfmMmGe/rlEHO/hnyZrw7Qikb2RQxfosmssiD3RhPew/ukawXvltJnaZgAnZ5i
         pvRi3TFhdKE/cioHpU7UwEymhr78h+L96KUixdNVbyOipzxFT/K9A00O0eMPddO26rkT
         VrG87tfJ4fwvrXDjmorSFltiSSZQOBlbem02ui8pkAQX57Qfvckk5GXo8fsN4eGVwmKn
         zNpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hGeVcjcx7ubf0H6xiQHVeNK7WJ7KHB5Hzo+aIBcdMbw=;
        b=gSmPDZaOBh+Sj5tJ2Ia529xvPOUminQW+VbXLjhKn/uSk2Hcc+edVoSNLFYEgrVIeG
         S0V1vPsIL+L3wscF9ihrxU1J1ZwEzzObF7P2PjY7cwfOBJcx2jjG3SUxybgOfKsms58l
         wJb4Kbo324NpXv9z+lZBj5qgq8M91vh8yYAby1D0pFgVGPtGyOLSMIfdlh4R0XRv8BzG
         wgqf/b0lxdaxyXzOckscnVkVtozAIN7B9UkMmEhu3jzqVxzHPD6vWeiFsaU89sissMtN
         KQex1qRoAcrlYlh3nL8ek8m9PjHhlDzSl0+dDU201f1da+LOF6cLBncsTi1SeE5QNnlf
         nXJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="r7wfh/o/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id lr18-20020a17090b4b9200b001dc4e0e7124si303064pjb.3.2022.05.04.06.48.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 May 2022 06:48:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id w17so2434543ybh.9
        for <kasan-dev@googlegroups.com>; Wed, 04 May 2022 06:48:03 -0700 (PDT)
X-Received: by 2002:a25:9347:0:b0:649:7f07:4536 with SMTP id
 g7-20020a259347000000b006497f074536mr11795074ybo.1.1651672082491; Wed, 04 May
 2022 06:48:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220504070941.2798233-1-elver@google.com> <CABVgOSnkROn18i62+M9ZfRVLO=E28Eiv7oF_RJV+14Ld73axLw@mail.gmail.com>
In-Reply-To: <CABVgOSnkROn18i62+M9ZfRVLO=E28Eiv7oF_RJV+14Ld73axLw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 May 2022 15:47:26 +0200
Message-ID: <CANpmjNPKyGUV4fXui5hEwc9+4y70kP_XgSnHbPObWBGyDeccYA@mail.gmail.com>
Subject: Re: [PATCH -kselftest/kunit] kcsan: test: use new suite_{init,exit} support
To: David Gow <davidgow@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="r7wfh/o/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as
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

On Wed, 4 May 2022 at 15:43, David Gow <davidgow@google.com> wrote:
>
> On Wed, May 4, 2022 at 3:09 PM Marco Elver <elver@google.com> wrote:
> >
> > Use the newly added suite_{init,exit} support for suite-wide init and
> > cleanup. This avoids the unsupported method by which the test used to do
> > suite-wide init and cleanup (avoiding issues such as missing TAP
> > headers, and possible future conflicts).
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > This patch should go on the -kselftest/kunit branch, where this new
> > support currently lives, including a similar change to the KFENCE test.
> > ---
>
> Thanks! This is working for me. I ran it as a builtin using kunit_tool
> under (I had to add an x86_64-smp architecture), then use:
> ./tools/testing/kunit/kunit.py run --arch=x86_64-smp
> --kconfig_add=CONFIG_KCSAN=y --kconfig_add=CONFIG_DEBUG_KERNEL=y
> --timeout 900 'kcsan'
>
> To add the x86_64 smp architecture, I added a file
> ./tools/testing/kunit/qemu_configs/x86_64-smp.py, which was a copy of
> x86_64.py but with 'CONFIG_SMP=y' added to XXXX and '-smp 16' added to
> YYYY.
> It took about 10 minutes on my system, so the default 5 minute timeout
> definitely wasn't enough.

The trick to reduce the KCSAN test time is to set
CONFIG_KCSAN_REPORT_ONCE_IN_MS=100 or lower. So should you consider a
special KUnit config, I'd add that.

> (It's maybe worth noting that kunit_tool's output is pretty ugly when
> this isn't running on an SMP system, as the skipped subtests -- plus
> the "no tests run" errors -- take up a lot of space on the screen.
> That's possibly something we should consider when we look further into
> how the kunit_tool NO_TEST result works. Not really related to this
> change (or even this test) though.)
>
> No complaints about the patch: I'm just really glad to see things
> migrate off custom init/exit code!
>
> Reviewed-by: David Gow <davidgow@google.com>

Thank you!

> -- David
>
> >  kernel/kcsan/kcsan_test.c | 31 +++++++++++++------------------
> >  1 file changed, 13 insertions(+), 18 deletions(-)
> >
> > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > index a36fca063a73..59560b5e1d9c 100644
> > --- a/kernel/kcsan/kcsan_test.c
> > +++ b/kernel/kcsan/kcsan_test.c
> > @@ -1565,14 +1565,6 @@ static void test_exit(struct kunit *test)
> >         torture_cleanup_end();
> >  }
> >
> > -static struct kunit_suite kcsan_test_suite = {
> > -       .name = "kcsan",
> > -       .test_cases = kcsan_test_cases,
> > -       .init = test_init,
> > -       .exit = test_exit,
> > -};
> > -static struct kunit_suite *kcsan_test_suites[] = { &kcsan_test_suite, NULL };
> > -
> >  __no_kcsan
> >  static void register_tracepoints(struct tracepoint *tp, void *ignore)
> >  {
> > @@ -1588,11 +1580,7 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
> >                 tracepoint_probe_unregister(tp, probe_console, NULL);
> >  }
> >
> > -/*
> > - * We only want to do tracepoints setup and teardown once, therefore we have to
> > - * customize the init and exit functions and cannot rely on kunit_test_suite().
> > - */
> > -static int __init kcsan_test_init(void)
> > +static int kcsan_suite_init(struct kunit_suite *suite)
> >  {
> >         /*
> >          * Because we want to be able to build the test as a module, we need to
> > @@ -1600,18 +1588,25 @@ static int __init kcsan_test_init(void)
> >          * won't work here.
> >          */
> >         for_each_kernel_tracepoint(register_tracepoints, NULL);
> > -       return __kunit_test_suites_init(kcsan_test_suites);
> > +       return 0;
> >  }
> >
> > -static void kcsan_test_exit(void)
> > +static void kcsan_suite_exit(struct kunit_suite *suite)
> >  {
> > -       __kunit_test_suites_exit(kcsan_test_suites);
> >         for_each_kernel_tracepoint(unregister_tracepoints, NULL);
> >         tracepoint_synchronize_unregister();
> >  }
> >
> > -late_initcall_sync(kcsan_test_init);
> > -module_exit(kcsan_test_exit);
> > +static struct kunit_suite kcsan_test_suite = {
> > +       .name = "kcsan",
> > +       .test_cases = kcsan_test_cases,
> > +       .init = test_init,
> > +       .exit = test_exit,
> > +       .suite_init = kcsan_suite_init,
> > +       .suite_exit = kcsan_suite_exit,
> > +};
> > +
> > +kunit_test_suites(&kcsan_test_suite);
> >
> >  MODULE_LICENSE("GPL v2");
> >  MODULE_AUTHOR("Marco Elver <elver@google.com>");
> > --
> > 2.36.0.464.gb9c8b46e94-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPKyGUV4fXui5hEwc9%2B4y70kP_XgSnHbPObWBGyDeccYA%40mail.gmail.com.
