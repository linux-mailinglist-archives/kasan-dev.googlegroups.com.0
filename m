Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBO6STOIAMGQENB34WNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 634E14B3113
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 23:54:52 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id z24-20020a056512371800b0043ea4caa07csf2641117lfr.17
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 14:54:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644620091; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z9XfDWn0vt/VS0/gUv/T/+cbga+EiNLzkM8b+zQYxu7T/gsomQaVaVWMPk+kGQVzD1
         d0OLONXAIDTvJFQ2sycJxNKUA8bcRrDvZFYvaLxKn/pij5E4PixpWrU+NIyJ0i5Mj6ot
         QIm+PwTl3pEjgIszdkZY/wwKdlqlR0JNb5ayEKDkBRofSeY20f3riCfAqcMMfJycSN3M
         i+HOHX8PA3muwWV9WmDNenvlZwbBdmiVSm91fXgX44pwAUykZ8cP70URnLXwsW6aOJRe
         lYMPnJTZstfedxfc1siZJwz44XmG17XMau7hi5CT5HIjilCWHQ2zVi9NF4XLn+DHDULp
         KpHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k/Oe7bjzu94r6X1M5C31XOkpEjlyPHPcDVFNGVJ02Lc=;
        b=Gmz8T4epbEON/Ntk6bfZoD30MvHS4MaYBjJccSEJLUp+bcThL4BX/t5TNeft7paOy+
         d5ZcsbNVK0idKnzhYi/G5ZH+FbMvicGlyn9HrIlsypOYXUQqbWukNEZmeeMpkSYUIu6c
         i1QHaTvG6ntl/7ZVkehqyeGz1EODNIAU6X36Baxd+A2xn/3630PNAouACJueY7FRrsoT
         THLmZHuo2ueFEZjGRk0CU2RCydYO2AB/CtcLg9jw4yFIeRwaVaB1HsOw3u+g0xCza2LM
         yJd9AKoJflNri2xwTYoQSPsZ8k/RSCxYYBHAHsLvxhmpUw/ofTiEDPXcBHN3Eo8klhJr
         wIZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PN9gtVb6;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k/Oe7bjzu94r6X1M5C31XOkpEjlyPHPcDVFNGVJ02Lc=;
        b=QA0/APL1VCVPYkUSBczH9eXn3H4h5oJxc93aIz/7n9OVSqUTSDYD+WhfsWcOuM9ETO
         0mJT2R+IDe83stm463rNCeNpc8C+pjjA+I0p44V8MrLQQtpLr7YLvvL4vN3o4jAV84ta
         fxMvtqSsvV2O1I03ABqVPVE58PZ+DH3n+1IqHVhNiwZXWkpBum81n7znXluZDIl/j2RM
         N31D/krQiDdaIqsv+4AM+N6iKC7JCjZ8ph+VYynnnXf1kgFEMO4ZhCZLMM82oZN8MTVG
         Fks2cDHxG7M38CzsDqvoP3wQOFq9lEhlA5iCnkms+2rhJGHENfWwJ7+0QQxWtiqZLfYJ
         0d1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k/Oe7bjzu94r6X1M5C31XOkpEjlyPHPcDVFNGVJ02Lc=;
        b=TNabyeDsBVxOGokTR6ojCpvWuT6HPDVBaLDAz1a5Fdm8VUca6edpFeyCV07wV5PXlD
         KG35RhZnU+V/UH11vNXsxenryv/bYvudzmgmeFhmeySoEyDhEsqP1deAM2lmaIBaFtkL
         o7KMLoI/+gmeFreQwyl4LPZPZkD12PwhBRQZrfI50hCA+q6t0OzATWzSanNqb+wWPM0I
         mEliuE2sf10dNxiHua6WcNeViT0a6it79qlmVho2+cIi/nsoSKI8wlcWpGeV2LBwiP5V
         D8nljpyNwGpY1Y7t7Dyi6ulkb/M7uVR87TA1vlLNx34kINiU5vqbuKfFMh1md/rpgaLD
         Xbjw==
X-Gm-Message-State: AOAM530MnxFBkOyT8bkwr1Nuo0WonDA/NqkO40CPkDXS5hgWi4kMoqhn
	jGfYUucPf+2oZnVSCFGlr2w=
X-Google-Smtp-Source: ABdhPJxAt6hPZG5DdHAu2lZ4TeHzWtarXnkS7lQzWne5YF8tFqiqo4ckr8q/MRq9Vi9DCp0e0yBIGw==
X-Received: by 2002:a2e:9806:: with SMTP id a6mr2273641ljj.444.1644620091665;
        Fri, 11 Feb 2022 14:54:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls912546lfr.1.gmail; Fri, 11 Feb
 2022 14:54:50 -0800 (PST)
X-Received: by 2002:a05:6512:1292:: with SMTP id u18mr2629175lfs.360.1644620090679;
        Fri, 11 Feb 2022 14:54:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644620090; cv=none;
        d=google.com; s=arc-20160816;
        b=B8KQ7nwVX9G+RzuHxDqe+aZ9FMpHCGhPk9OfN6efrTagNusrLQn0u+e8/ao3jPWKMX
         q4MufnpyZ9yOZCCp1H655gcT9SOfc7VJgD2DrUIO8L/URcepNflyxDLPvwq/af7EEzWc
         /GMA7/iAX+0dHu02j0TZUtXSBIEi0tgylfD72EItFAkWkPpMLBoDba3J0ubWEPNk4sBj
         RDstDR0b50fTY/56QphSaR3fSmONBb26Z3BgMZ00p05tuZOxVfx1cFBFYiS/SpQPxRKG
         4ZlDrY97JAHWdp4z7MjxcphqhxrEDBLWXSezq+KwznnN+F0TL/YE99I3jaNOK51yhreY
         K9rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MNyMAxSIRfmX6E7yXPlJDgtVqsNPCnT37/UNnUhdfcg=;
        b=twY1gjT+Hc5LOfvGhmC8JbYi4BORsWqGHXueF4TN3j7vhmBGXWq/6+AOXBNVU4gXf5
         cGGnVYGSbHgB1LQJVribxmb0CVchzq3iwyxEEyyk1OXSZeixyFdDLtC5UmkycF/mLTGv
         o42AKzhQMTMtIYhC3Xziuas/jFNnMh9ypVJtB9cMXB1PN/WEEnpznR7fCKh0ndAaKFWZ
         jk1ULkm3VsymeaPBRLtpl3RK3k+/wdNeMYl+qQpwxkHfN7U7UaZKB3klB1Mc93yESoxP
         v75TBGrATaRZbcKK6dcR7mnbRr3umF+BCvG7NJ0GEmSYgD74zFzAhdkn3L36PFfq9seo
         86Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PN9gtVb6;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id d6si657955lfn.5.2022.02.11.14.54.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 14:54:50 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id da4so18536426edb.4
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 14:54:50 -0800 (PST)
X-Received: by 2002:a05:6402:289:: with SMTP id l9mr4272896edv.272.1644620090064;
 Fri, 11 Feb 2022 14:54:50 -0800 (PST)
MIME-Version: 1.0
References: <20220211094133.265066-1-ribalda@chromium.org> <20220211094133.265066-3-ribalda@chromium.org>
 <YgY1lzA20zyFcVi3@lahna> <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
 <YgaOS8BLz23k6JVq@lahna> <YgaPXhOr/lFny4IS@lahna> <CANiDSCs7M_hSb2njr50_d3z=cx=N9gWHzVe-HkpCV1Au8yVwOw@mail.gmail.com>
In-Reply-To: <CANiDSCs7M_hSb2njr50_d3z=cx=N9gWHzVe-HkpCV1Au8yVwOw@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Feb 2022 14:54:37 -0800
Message-ID: <CAGS_qxp3OHFwK__wCHBGr9cMsLR=gfD2rhjejXcmFNJ276_ciw@mail.gmail.com>
Subject: Re: [PATCH v5 3/6] thunderbolt: test: use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: Mika Westerberg <mika.westerberg@linux.intel.com>, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PN9gtVb6;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::535
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

On Fri, Feb 11, 2022 at 8:33 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Hi Mika
>
> On Fri, 11 Feb 2022 at 17:31, Mika Westerberg
> <mika.westerberg@linux.intel.com> wrote:
> >
> > On Fri, Feb 11, 2022 at 06:26:56PM +0200, Mika Westerberg wrote:
> > > > To test it I had enabled:
> > > > PCI, USB4 and USB4_KUNIT_TEST
> > > >
> > > > and then run it with
> > > >
> > > > ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
> > > >
> > > > Unfortunately, kunit was not able to run the tests
> > > >
> > > > This hack did the trick:
> > > >
> > > >
> > > >  int tb_test_init(void)
> > > >  {
> > > > -       return __kunit_test_suites_init(tb_test_suites);
> > > > +       //return __kunit_test_suites_init(tb_test_suites);
> > > > +       return 0;
> > > >  }
> > > >
> > > >  void tb_test_exit(void)
> > > >  {
> > > > -       return __kunit_test_suites_exit(tb_test_suites);
> > > > +       //return __kunit_test_suites_exit(tb_test_suites);
> > > >  }
> > > > +
> > > > +kunit_test_suites(&tb_test_suite);
> > > >
> > > > I looked into why we do this and I found:
> > > >
> > > > thunderbolt: Allow KUnit tests to be built also when CONFIG_USB4=m
> > > >
> > > >
> > > > I am a bit confused. The patch talks about build coverage, but even
> > > > with that patch reverted if
> > > > USB4_KUNIT_TEST=m
> > > > then test.c is built.
> > > >
> > > > Shouldn't we simply revert that patch?
> > >
> > > Nah, either build it into the kernel or load the driver manually:
> > >
> > >   # modprobe thunderbolt
> >
> > Forgot to explain why this does not run the tests (I think):
> >
> >  ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
> >
> > The driver depends on PCI and I don't think that's enabled on UML at
> > least. I typically run it inside QEMU.

You can get it working on UML now.
If you apply the patch upthread for the test to use kunit_test_suites(), then

$ cat usb4_kunitconfig
CONFIG_PCI=y
CONFIG_VIRTIO_UML=y
CONFIG_UML_PCI_OVER_VIRTIO=y

CONFIG_KUNIT=y
CONFIG_USB4=y
CONFIG_USB4_KUNIT_TEST=y

$ ./tools/testing/kunit/kunit.py run --kunitconfig=usb4_kunitconfig
...
[14:48:55] [PASSED] tb_test_property_copy
[14:48:55] =================== [PASSED] thunderbolt ===================
[14:48:55] ============================================================
[14:48:55] Testing complete. Passed: 37, Failed: 0, Crashed: 0,
Skipped: 0, Errors: 0

Mika, should I propose a patch that updates the test and adds a
drivers/thunderbolt/.kunitconfig with the above contents?

Then it could be invoked as
$ ./tools/testing/kunit/kunit.py run --kunitconfig=drivers/thunderbolt

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxp3OHFwK__wCHBGr9cMsLR%3DgfD2rhjejXcmFNJ276_ciw%40mail.gmail.com.
