Return-Path: <kasan-dev+bncBCA2BG6MWAHBB7VMYD3AKGQE5MVGL6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 645D81E6BB6
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 21:52:31 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id g9sf168932ybc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 12:52:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590695550; cv=pass;
        d=google.com; s=arc-20160816;
        b=nO0qQ7fwtcN3PQU/uGxWL0QwrbX0ocks+/H2D67Ol4Vvan+oWQh1aC1Nf0E/2mFKcB
         KJcwytM20JiaWheIDOsOhs79LS2b+lH5wTUX53RzpVZIedGkZEs9pU7TZWTGfyAQzvsK
         6yVu220179tudB3jFnrZ7c5TOpK7sDM0+I2HlQIXR5Skrd41L2omv89lvm1/tuVpEM53
         jmopuXOmhvSIOLvAMMNxudm0Tm87wyDIuaymcP6J7oTowQD9dRHCzTweoXYu9GSjMfqi
         7ISuQHbVr0QO+Bw29jzD2YYKMIOwJV9SxRnI/JlxYnqONsTdFPKOY4O+eUUOowjm4DfS
         GFAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=84TNZndHgFB0AbIyblFPU/fEr9YK/SWOgpp0F/XWlHs=;
        b=z70LI6qkmKekeN0Mg/KcKc/CRbMyDYzI0antz3uskxrDm1UTJGkAf2tdH2XVq1fC5Z
         xEoMGoK2UZtO/SSDwUlNWQFZ1w/mx65IKZ3vDXuRB09Es7YUHuihwZdamxp5W6yon4hd
         eCQmPwYOuNo8gMwc7Lu3/XWGNrSozCjbkYhrvT8dIAHfHeJnSRJjdklhiXbv7SCKM+rz
         b+HUlCmIBagQKl3MypAA/qQSpb/3h06OpHXYrn+O6x0JtKXKPbKkbalPaoy0o4oXzLnE
         E/u9XrNFJ8CJ1tTs1FHVCn7dL+jYBI1XmVmxjgWtBq16DTDk6ojDOl1FU1tU0fZd7h6v
         dRfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ijypAQ4/";
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=84TNZndHgFB0AbIyblFPU/fEr9YK/SWOgpp0F/XWlHs=;
        b=cdo4lDSBrXG7MjP6igoLQ9hytinYWnfT6ZWPVCRfCxfAvwAjyS3lkJPCj01/R9/iba
         6mGpPLyACWe5025YsYc6RSOUIeNC5KycBIIhBJ405bNhz/D/4GWPaUI7oJelO9n2U/9b
         q24ySxPNLdgwYPLLDMEt+UEDXd+qC9TjFftKlOk0XgQxDwL27PYP4jc/irkeGESitMXc
         mLsoNTkuJMfZan1v6qt3UGr298zZMkjad8vffjBoQA75N4QQ4lYPo7JEdBMm8P/UeHlp
         hwReYxSClKeuq+T95Z+BEg0Lj/56Q2zSE2HORk67nyLUhH5e4NNBXjANk16Smm6MNLAD
         jNsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=84TNZndHgFB0AbIyblFPU/fEr9YK/SWOgpp0F/XWlHs=;
        b=RPQvXnr4ta74hyQ0Ht50N0GRQGvoi5BY17qGeOQZ+RNZhvgZ0K94acv0gI3HcBraPv
         GPhcy0eWXT7RGN2lifITXWUs7ZDtkAjkld2Px5zuc1e/FES/B1+BLIX9ihBkPqYDXw5Y
         PEcRKoe5KNzut5BeI+c3d0D+qSWdQGPYJD7rXPwhOHY32O85sO5QF5VE7xm9gqc6FCuN
         h8sMHwtiIqK4veFkcgmznrX9RsUR5PEJfEMbDqXUv9wVmtxFTqnZIJK1J5gviQuvkj5E
         QklfJbK5k80h35ehSxEsdoomvy3w+lWEJBe2dlNafpN2gR36KWr9ubu2o7ETu44p1OfV
         oMoQ==
X-Gm-Message-State: AOAM5334nD38TkqRrCwPE8RPTh50lIctlAPYkgt6hkNBD7Q+cfK3jTnp
	Rcfxr4ShoUthodY/yUBjDKU=
X-Google-Smtp-Source: ABdhPJxvBwom37v6Ya/7xpDhO7De+MWpzTKdFSUXTCp67gdfoDm8o9YnVFs5hzKimY/owtM6bzA0gg==
X-Received: by 2002:a25:c6c7:: with SMTP id k190mr5427672ybf.422.1590695550419;
        Thu, 28 May 2020 12:52:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:72b:: with SMTP id l11ls1347792ybt.8.gmail; Thu, 28
 May 2020 12:52:30 -0700 (PDT)
X-Received: by 2002:a25:aaea:: with SMTP id t97mr8312600ybi.86.1590695550085;
        Thu, 28 May 2020 12:52:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590695550; cv=none;
        d=google.com; s=arc-20160816;
        b=w9QoWLlnR5q41/Fw355gHRMj1Dt9+FclXEbQOWbEsxGh419NS34hfA0v13o2gN2S75
         hWmsZJuds781N9PpoPBOCeD3okD3+g/l9xpDeAaeoirf1ZZjTYTKnSsgjDjDgC3fo3ti
         Cnsm+OR9oIvKawwDRrhSBo5IzW+pe/8klGwRl5BPCEM6DCzSXwIzbQvC9Ku+uc6t2gPp
         rDHEatum2+IabKUI9YD3c+Pfb5BDJbCBduD9hKLrmyAmRWs5Axbff5nAKn4bQgGnFn3Y
         GkyP9PoLlxVLkvKbOaJf0FwzR+xld7U+aXlKxGyYuyZRig+INuy1HsXVoXAthQFNIoIy
         67jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WYeCBR8WcHvQvd56ESdKiIjSS5Wn/icLWSDDTkY8XKE=;
        b=u4aQzu5LPo50eojt1tyTKfimIKQm+Pez865oC+AmclpI59eYaP3ZsC0lLFiPDJiRdC
         zyryWuwIFivpyThjWJrFdADsXooIEGDpGiyAXWi5uDVxp+eCf4t2KmoXeA3KBYQ/809q
         mr0oMB1JkzpulbY7EOpHgf8VVrOuhsmJLFClUH1+uG4Zv++knxOw3E+Isq5UluuViycO
         Ub9DgJpmVwudW19aeGBC6HAi0RnoSTEZOAW5USK1vMDJko4G2G9JKR2sVesYghM+b4LD
         W4bTb4rlpbMxSDGQlXztjlN10EtwPliDrydbRtjawIbmLc1+bozr9AsMJ64VZZXp7ksb
         ZJoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ijypAQ4/";
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id v184si31539ybb.5.2020.05.28.12.52.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 12:52:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id 131so5716442pfv.13
        for <kasan-dev@googlegroups.com>; Thu, 28 May 2020 12:52:30 -0700 (PDT)
X-Received: by 2002:a63:d04b:: with SMTP id s11mr4435032pgi.384.1590695548943;
 Thu, 28 May 2020 12:52:28 -0700 (PDT)
MIME-Version: 1.0
References: <20200424061342.212535-1-davidgow@google.com> <alpine.LRH.2.21.2005031101130.20090@localhost>
 <26d96fb9-392b-3b20-b689-7bc2c6819e7b@kernel.org> <CABVgOS=MueiJ6AHH6QUSWjipSezi1AvggxBCrh0Q9P_wa55XZQ@mail.gmail.com>
In-Reply-To: <CABVgOS=MueiJ6AHH6QUSWjipSezi1AvggxBCrh0Q9P_wa55XZQ@mail.gmail.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 May 2020 12:52:17 -0700
Message-ID: <CAFd5g46Y-9vSSSke05hNyOoj3=OXcJh8bHGFciDVnwkSrpcjZw@mail.gmail.com>
Subject: Re: [PATCH v7 0/5] KUnit-KASAN Integration
To: David Gow <davidgow@google.com>
Cc: shuah <shuah@kernel.org>, Alan Maguire <alan.maguire@oracle.com>, 
	Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ijypAQ4/";       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Tue, May 26, 2020 at 7:51 PM David Gow <davidgow@google.com> wrote:
>
> On Sat, May 23, 2020 at 6:30 AM shuah <shuah@kernel.org> wrote:
> >
> > On 5/3/20 4:09 AM, Alan Maguire wrote:
> > > On Thu, 23 Apr 2020, David Gow wrote:
> > >
> > >> This patchset contains everything needed to integrate KASAN and KUnit.
> > >>
> > >> KUnit will be able to:
> > >> (1) Fail tests when an unexpected KASAN error occurs
> > >> (2) Pass tests when an expected KASAN error occurs
> > >>
> > >> Convert KASAN tests to KUnit with the exception of copy_user_test
> > >> because KUnit is unable to test those.
> > >>
> > >> Add documentation on how to run the KASAN tests with KUnit and what to
> > >> expect when running these tests.
> > >>
> > >> This patchset depends on:
> > >> - "[PATCH v3 kunit-next 0/2] kunit: extend kunit resources API" [1]
> > >> - "[PATCH v3 0/3] Fix some incompatibilites between KASAN and
> > >>    FORTIFY_SOURCE" [2]
> > >>
> > >> Changes from v6:
> > >>   - Rebased on top of kselftest/kunit
> > >>   - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
> > >>     incompatibilites [2]
> > >>   - Removed a redundant report_enabled() check.
> > >>   - Fixed some places with out of date Kconfig names in the
> > >>     documentation.
> > >>
> > >
> > > Sorry for the delay in getting to this; I retested the
> > > series with the above patchsets pre-applied; all looks
> > > good now, thanks!  Looks like Daniel's patchset has a v4
> > > so I'm not sure if that will have implications for applying
> > > your changes on top of it (haven't tested it yet myself).
> > >
> > > For the series feel free to add
> > >
> > > Tested-by: Alan Maguire <alan.maguire@oracle.com>
> > >
> > > I'll try and take some time to review v7 shortly, but I wanted
> > > to confirm the issues I saw went away first in case you're
> > > blocked.  The only remaining issue I see is that we'd need the
> > > named resource patchset to land first; it would be good
> > > to ensure the API it provides is solid so you won't need to
> > > respin.
> > >
> > > Thanks!
> > >
> > > Alan
> > >
> > >> Changes from v5:
> > >>   - Split out the panic_on_warn changes to a separate patch.
> > >>   - Fix documentation to fewer to the new Kconfig names.
> > >>   - Fix some changes which were in the wrong patch.
> > >>   - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)
> > >>
> > >
> >
> > Hi Brendan,
> >
> > Is this series ready to go inot Linux 5.8-rc1? Let me know.
> > Probably needs rebase on top of kselftest/kunit. I applied
> > patches from David and Vitor
> >
> > thanks,
> > -- Shuah
> >
>
> Hi Shuah,
>
> I think the only things holding this up are the missing dependencies:
> the "extend kunit resources API" patches[1] for KUnit (which look
> ready to me), and the "Fix some incompatibilities between KASAN and
> FORTIFY_SOURCE" changes[2] on the KASAN side (which also seem ready).
>
> This patchset may need a (likely rather trivial) rebase on top of
> whatever versions of those end up merged: I'm happy to do that if
> necessary.
>
> Cheers,
> -- David
>
> [1]: https://lore.kernel.org/linux-kselftest/1585313122-26441-1-git-send-email-alan.maguire@oracle.com/T/#t
> [2]: http://lkml.iu.edu/hypermail/linux/kernel/2004.3/00735.html

As David pointed out, this series is waiting on its dependencies.
Sorry, I thought the "extend KUnit resources API" patchset was ready
to go, but I realized I only gave a reviewed-by to one of the patches.
Both have been reviewed now, but one patch needs a minor fix.

As for other patches, the patches from David, Vitor, and Anders should
cover everything. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g46Y-9vSSSke05hNyOoj3%3DOXcJh8bHGFciDVnwkSrpcjZw%40mail.gmail.com.
