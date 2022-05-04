Return-Path: <kasan-dev+bncBC6OLHHDVUOBBGMLZKJQMGQEXNI5YIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 467A451A168
	for <lists+kasan-dev@lfdr.de>; Wed,  4 May 2022 15:54:34 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id w25-20020a05651234d900b0044023ac3f64sf662180lfr.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 May 2022 06:54:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651672473; cv=pass;
        d=google.com; s=arc-20160816;
        b=H2DeQWGEazX75qhIrjWKrmcaab9Qjvp4F67P0p2asK0Fnhh9SuJ3I/2hkVZaQC8nbj
         FvCBWnq5e8AG1pJr+p8P/skYhJ7SzC8rAfeVqyyanXJTeLxzUP3NljRP2GJnqU+NCDkX
         1Shkg8mN+Tuh08FbnItYxMSUd5tRUMrWN1mLbL4AGutGecPW6HGbR0y5Ft8zcsq3UZMh
         qXtwqv9VmAVphie9+dWbrsrMPAqVAzpe8XWdyyyrLyyYnRJD51NUp/991USBYLLPI9bg
         tOh9Ab+Et5X5CchbmG875bmBIiZjju/9FbYdjuA5ws0OppxaKwEnfPgQRsvzeWXbZUlC
         yDrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c754ocyLMOaZtlasLcSaDB1csxv3UpxrWKBpFaUEbxo=;
        b=DWsttpc8NlubrIBV1pAiVp+l1zOy2Tqb9OM+xnsLnmZZP877F80QmDVLE+Ihybe7Va
         ATf1Qy8Xif0YXVw+cOBl3a+YKX8gJ2y72NnirT5D6aJKF9pGA35CqdjTx1Ydq0HaYEJo
         gy3JQCB+4J6vDLTc2qVMKq/dyneR7fP9db9KaY8DpimHUmAmLb7wbKesnwfgaQV/EZhR
         9qHN1o9jttpX6vDyTop0O4g0E/D9fTjAGYDxaatBO1l408FQd42vkMzjP2giJ73ta0m8
         IZiDKYBCslpTd0QYTSQ9ccHhWcgM/kEn86+vAl9uZb+q+OULiUxWK0J+/SRYJtBY374L
         kfBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M+vNY3af;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c754ocyLMOaZtlasLcSaDB1csxv3UpxrWKBpFaUEbxo=;
        b=AkErHorv6mpEbu+zrg18RhM45aUKooB92DoPCbggql/S6QG+Xv7NIOEe0v4mqtrs3V
         hz4C2sGU5EseJJZlW7/B/633+2/H7S5WVVZpg9KSWiXMoEQ55QS7v4hkQ1owob3CpePx
         +lO0dnJj13Ni6UhczWEOwOWqNKh227rzcSKp/KPnYanyKWBn4VRey6uY3RMv8g4Zp4of
         8SiZKC9tUqABGbm+HU0+HwbqZhmXXpK70HQHr6auCL+3QUco3sdQwgF/wjDLBOBeuOTn
         tEglYvt/F2uIKwdd/TDUU4MNRmA6tgjZ3z6CoeAUEppOrGkeR2UA/P97JsGUP/kbIgG0
         7dDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c754ocyLMOaZtlasLcSaDB1csxv3UpxrWKBpFaUEbxo=;
        b=mUYkLOPoZZX6rnQ2H9JycpAxdXBk3xWu65ofZR7rwSVGrSVShhLiO1lrvRqCOnOMYA
         St6tRfgmaJoTNz5vdiGYtz/LldXFB8IrQ94vW4KVF6V3UN3XvIsw+URF0wkVsq60NsR+
         jtQs6DS3XwvN2SkmuRMPR/US6e/7v8Wf10xdxQwNrJJZjybyjNO6tAEnCpBRuspn2LX5
         zsa5LlPdcCTC9+ETaZBGpJKE3Aef6IUVGA4Pa2OQXLlT+nhUkg3SWjwLvi75bFq6wBZ/
         RfqSxpkZEEgTk7c9FHKwCcC9XlDRrBTgbKNkO6diOo0j0+6yTqNU+AihYl0oAlESUMKJ
         cTOQ==
X-Gm-Message-State: AOAM533wiuwTLlUv/TNnFN4xte6MvEJbmE1Y64xFg8qjwG48kCgwtTC9
	I3m+47E4dLtYMhHkUdHG3kg=
X-Google-Smtp-Source: ABdhPJxO+eiPyAxSzmufL2guiNxyVj5cHwwL50ArvdQLrtTjQEFVfA4QUT/90h3UlCWFFqCuMrPGAg==
X-Received: by 2002:a05:6512:3091:b0:473:bfb1:8da0 with SMTP id z17-20020a056512309100b00473bfb18da0mr1486625lfd.154.1651672473694;
        Wed, 04 May 2022 06:54:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:17a4:b0:24d:5627:cbb7 with SMTP id
 bn36-20020a05651c17a400b0024d5627cbb7ls430533ljb.0.gmail; Wed, 04 May 2022
 06:54:32 -0700 (PDT)
X-Received: by 2002:a2e:5cc8:0:b0:24f:1616:7d67 with SMTP id q191-20020a2e5cc8000000b0024f16167d67mr12345305ljb.368.1651672472247;
        Wed, 04 May 2022 06:54:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651672472; cv=none;
        d=google.com; s=arc-20160816;
        b=SqiImXnrQAjeg+9ys9yci5pca9ReCRC0U9KPSPnLDmYZ+PRSXD3duL2rLaJG/NEM79
         zNjqz399AI2M+3yJwfNSAPivMKmPP52CBu8R3N4BbRGtNuwfIgl5i/6l3Q7le7ZcfhCs
         wI3+vNfN7KINpyjkP0KsIv/z5T86XJwByBhOw8p3N/TtXv+mhzJC4URaxazE+fYRVqOi
         UT6tdmEu3G127cbhvciT8ohqeDxnkp2MK7PxDrmQdMfl3u2OsdYcRMP166N/9N5Q+yjB
         K6mvHy/AdrumzZk2TbOCbf1IAgjtcl3If75ZQBjB7RHvGIaxD48Q7D8rHkC+6Vp3Nimo
         0ifg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A+GOwhDIbDtSZrtYRKjeg/TUTolp/DrA7B48gMykmvY=;
        b=YK66ftcyp0NpMlQY8N3+/YmP2RTQrNFVnOlJpX2KbxBcdcGn7E5FyEjSX/5RwX8gtL
         38xa8g2ISDLjFlsCHgg+4NTrbgOEN9tzgPCvEaaX0WpozUNzT06NM1tt4axDgz67sEmn
         WGjs9W3wY2XRPFDh/iDkG7OFtJhPT3exJY8SvP9Tw8baUBRvwaHO2NyUa92PPc9CHzR2
         tioV6C3AFD9Qk+28ES1xczTNtPEuNVK7tjaMWxawL8RU07taGcETGrjF/XWKM2jfZFUV
         OfO0yZEcVYNshlNZEHmxJOWRcWoL9ofJTDyueEZEmzm3L3B7E/MJ2NBtqiZ3yp7zOG9t
         nnTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M+vNY3af;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id s1-20020a056512314100b00471902f5be2si1202506lfi.3.2022.05.04.06.54.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 May 2022 06:54:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id e24so2125136wrc.9
        for <kasan-dev@googlegroups.com>; Wed, 04 May 2022 06:54:32 -0700 (PDT)
X-Received: by 2002:a5d:4806:0:b0:20a:da03:711b with SMTP id
 l6-20020a5d4806000000b0020ada03711bmr16109055wrq.395.1651672471735; Wed, 04
 May 2022 06:54:31 -0700 (PDT)
MIME-Version: 1.0
References: <20220504070941.2798233-1-elver@google.com> <CABVgOSnkROn18i62+M9ZfRVLO=E28Eiv7oF_RJV+14Ld73axLw@mail.gmail.com>
 <CANpmjNPKyGUV4fXui5hEwc9+4y70kP_XgSnHbPObWBGyDeccYA@mail.gmail.com>
In-Reply-To: <CANpmjNPKyGUV4fXui5hEwc9+4y70kP_XgSnHbPObWBGyDeccYA@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 May 2022 21:54:20 +0800
Message-ID: <CABVgOSkLGryZeWVXdfBDkQKWvSkYTk2LWx+yC9J+4FYQpn2bpQ@mail.gmail.com>
Subject: Re: [PATCH -kselftest/kunit] kcsan: test: use new suite_{init,exit} support
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=M+vNY3af;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::430
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

On Wed, May 4, 2022 at 9:48 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 4 May 2022 at 15:43, David Gow <davidgow@google.com> wrote:
> >
> > On Wed, May 4, 2022 at 3:09 PM Marco Elver <elver@google.com> wrote:
> > >
> > > Use the newly added suite_{init,exit} support for suite-wide init and
> > > cleanup. This avoids the unsupported method by which the test used to do
> > > suite-wide init and cleanup (avoiding issues such as missing TAP
> > > headers, and possible future conflicts).
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > > This patch should go on the -kselftest/kunit branch, where this new
> > > support currently lives, including a similar change to the KFENCE test.
> > > ---
> >
> > Thanks! This is working for me. I ran it as a builtin using kunit_tool
> > under (I had to add an x86_64-smp architecture), then use:
> > ./tools/testing/kunit/kunit.py run --arch=x86_64-smp
> > --kconfig_add=CONFIG_KCSAN=y --kconfig_add=CONFIG_DEBUG_KERNEL=y
> > --timeout 900 'kcsan'
> >
> > To add the x86_64 smp architecture, I added a file
> > ./tools/testing/kunit/qemu_configs/x86_64-smp.py, which was a copy of
> > x86_64.py but with 'CONFIG_SMP=y' added to XXXX and '-smp 16' added to
> > YYYY.

(Whoops, forgot to copy this in properly: XXXX was 'kconfig' and YYYY
was 'extra_qemu_params'.)

The x86_64-smp.py file ends up looking like this:
---8<---
from ..qemu_config import QemuArchParams

QEMU_ARCH = QemuArchParams(linux_arch='x86_64',
                          kconfig='''
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SMP=y
                          ''',
                          qemu_arch='x86_64',
                          kernel_path='arch/x86/boot/bzImage',
                          kernel_command_line='console=ttyS0',
                          extra_qemu_params=['-smp 16'])
---8<---
> > It took about 10 minutes on my system, so the default 5 minute timeout
> > definitely wasn't enough.
>
> The trick to reduce the KCSAN test time is to set
> CONFIG_KCSAN_REPORT_ONCE_IN_MS=100 or lower. So should you consider a
> special KUnit config, I'd add that.
>

Ah: it might be worth adding a dedicated kcsan .kunitconfig, in which
case this would be helpful. It'd also need the SMP qemu config above
before it's particularly useful, and 16 was a randomly-picked number
of CPUs -- not sure if there's a better default.

If you're likely to use it, though, we can definitely add it in. I'm
sure there'll eventually be other uses for an SMP config under
kunit_tool, too.

> > (It's maybe worth noting that kunit_tool's output is pretty ugly when
> > this isn't running on an SMP system, as the skipped subtests -- plus
> > the "no tests run" errors -- take up a lot of space on the screen.
> > That's possibly something we should consider when we look further into
> > how the kunit_tool NO_TEST result works. Not really related to this
> > change (or even this test) though.)
> >
> > No complaints about the patch: I'm just really glad to see things
> > migrate off custom init/exit code!
> >
> > Reviewed-by: David Gow <davidgow@google.com>
>
> Thank you!
>
> > -- David
> >
> > >  kernel/kcsan/kcsan_test.c | 31 +++++++++++++------------------
> > >  1 file changed, 13 insertions(+), 18 deletions(-)
> > >
> > > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > > index a36fca063a73..59560b5e1d9c 100644
> > > --- a/kernel/kcsan/kcsan_test.c
> > > +++ b/kernel/kcsan/kcsan_test.c
> > > @@ -1565,14 +1565,6 @@ static void test_exit(struct kunit *test)
> > >         torture_cleanup_end();
> > >  }
> > >
> > > -static struct kunit_suite kcsan_test_suite = {
> > > -       .name = "kcsan",
> > > -       .test_cases = kcsan_test_cases,
> > > -       .init = test_init,
> > > -       .exit = test_exit,
> > > -};
> > > -static struct kunit_suite *kcsan_test_suites[] = { &kcsan_test_suite, NULL };
> > > -
> > >  __no_kcsan
> > >  static void register_tracepoints(struct tracepoint *tp, void *ignore)
> > >  {
> > > @@ -1588,11 +1580,7 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
> > >                 tracepoint_probe_unregister(tp, probe_console, NULL);
> > >  }
> > >
> > > -/*
> > > - * We only want to do tracepoints setup and teardown once, therefore we have to
> > > - * customize the init and exit functions and cannot rely on kunit_test_suite().
> > > - */
> > > -static int __init kcsan_test_init(void)
> > > +static int kcsan_suite_init(struct kunit_suite *suite)
> > >  {
> > >         /*
> > >          * Because we want to be able to build the test as a module, we need to
> > > @@ -1600,18 +1588,25 @@ static int __init kcsan_test_init(void)
> > >          * won't work here.
> > >          */
> > >         for_each_kernel_tracepoint(register_tracepoints, NULL);
> > > -       return __kunit_test_suites_init(kcsan_test_suites);
> > > +       return 0;
> > >  }
> > >
> > > -static void kcsan_test_exit(void)
> > > +static void kcsan_suite_exit(struct kunit_suite *suite)
> > >  {
> > > -       __kunit_test_suites_exit(kcsan_test_suites);
> > >         for_each_kernel_tracepoint(unregister_tracepoints, NULL);
> > >         tracepoint_synchronize_unregister();
> > >  }
> > >
> > > -late_initcall_sync(kcsan_test_init);
> > > -module_exit(kcsan_test_exit);
> > > +static struct kunit_suite kcsan_test_suite = {
> > > +       .name = "kcsan",
> > > +       .test_cases = kcsan_test_cases,
> > > +       .init = test_init,
> > > +       .exit = test_exit,
> > > +       .suite_init = kcsan_suite_init,
> > > +       .suite_exit = kcsan_suite_exit,
> > > +};
> > > +
> > > +kunit_test_suites(&kcsan_test_suite);
> > >
> > >  MODULE_LICENSE("GPL v2");
> > >  MODULE_AUTHOR("Marco Elver <elver@google.com>");
> > > --
> > > 2.36.0.464.gb9c8b46e94-goog
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkLGryZeWVXdfBDkQKWvSkYTk2LWx%2ByC9J%2B4FYQpn2bpQ%40mail.gmail.com.
