Return-Path: <kasan-dev+bncBDOILZ6ZXABBB74VWH2QKGQEKERD62Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 65B761C1A6B
	for <lists+kasan-dev@lfdr.de>; Fri,  1 May 2020 18:14:55 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id j5sf83822wmi.4
        for <lists+kasan-dev@lfdr.de>; Fri, 01 May 2020 09:14:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588349695; cv=pass;
        d=google.com; s=arc-20160816;
        b=iEoOtbxZfK9cOXPE0uIQF/RplImholnTplQ6wMjLmCWsAhKhADn4t1B+XW1vkyDViN
         xz6pCZX55QEOjwXTSlRSlty223/zWW6QDfN09UfGWX+M+Wb6Qh27v5X6O/+N5NT/H8rN
         f/A/JE8Eeq5EW4BFmAoW03bOOSVlx8cYJnvfMyF/MuYj2Y7P1EFGtGFtJCKAxqmWhfS/
         gz27VR09BW84MwRr/5tLIch/CF8AugAFhN7lmJCdpAhN7FAWscgc7aGFbfSPOYOb9LN1
         y0N7CmXSLL9ZSwPDCEP3ZazVNnF2Gp1qRk91l0ZSrENR9UuXfHuxJB+qDbUqrw60Cjh6
         w9iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=7ym7s9Ga/sF7fmKF0toyUHOoy/3hnQwf9UfEPAMBDVE=;
        b=X/DjTp/0hZdkBSQ6yWiVW314lqNurkub5JC0Sre12ue6Z0L+GsPdVxibpJJn29VJ4Z
         LXKcQS3PXr4SQKQNhELPJPAgjMrttQdXMWR8iwb0T8Cfvz8Pv614nqxJ7iCR3vq9d0yj
         ML5iSJkSJSgmgiX+09AbDokyzUlrT5zNR9CQIqwIj5o5uWeV2KN6+9kTzAFyq06qeKLN
         qx8b0p5UstWrq9Ei33A8prukLoDSVPGb99cElvjiIgFXj+xxyiYgaVG9AxgqR51/ueU8
         bZVFZ8XKZkIAcEU/4lLM7anjm1l2KHqRsFOLpORK9aQ5nOY1csg1flUz2eA7luETAP9V
         W62w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=pA76bR8I;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ym7s9Ga/sF7fmKF0toyUHOoy/3hnQwf9UfEPAMBDVE=;
        b=X4/7xn2ZZFMUGCF/zwzU+QqyS4+G7oxwVOKJ/7+H08mmzF771vQlyDmZYAuPCO1BQr
         Zi6vpIrXCu9faO2vjXErON/R66nTIyITbHMd1hJoPIR3SPaWV++2+KwqOL1zyn1yKhQO
         ezRKi7gGPPOGHSDedsW34PZIZlnz/0QYqhCb1A2EdlasbOlxWf4GddzGVAHWiu1rljbN
         0DG910whBWQDKneWTVmjUkehiROTcKaC8x6y01qX3bfj6sxCQVHh4F8VElmc59w9Dvnf
         KHKf6+94wyfbmbYmVFAVHq0RagGpfHAu29zeJh3e1UCbAt7lpNhQfTX6QqJ8JgT0FDYQ
         ltww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ym7s9Ga/sF7fmKF0toyUHOoy/3hnQwf9UfEPAMBDVE=;
        b=T0U7M/ImG+D8QHfAEjLEdcXcKo5MrnKBHyMt7+L0hJ544FpfYO9ED4DnKAczJpHZ9v
         ISk28QtYaLA7yWDOiVoyfNwOfHIf+GNpdz+vYcMGdgUNX17cUu7wcvNXEluUU5YbpocA
         hAyHSy/hhoK0TCNXhH36vFgEqzOKpi4eJvDVB3xLib5ESlCxzyVKjgKQimmV37bztcag
         Q+6auhnSijEWxcGwZCHWKKwXunNlO4mWdznzG+FlwdcOcYXAODPyWsl5tgd3EnTsVhBl
         DtRaTsw/OLawxDUCYi6/wCDg4zCW5zv8wnNtttKQyCURPSeemu7LJkJcQkMpuHIOSYRB
         UkjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYH7vUjUVA2Gk5hBgn9GwR1hju1+5Qx5X03ZXfdc12CI/oja6Vm
	EGX40yFy8Mfii3MeVkJgkzs=
X-Google-Smtp-Source: APiQypLPieEKcA5JNA8Q+2qiqb2+yh4VhCMsgvzT5lZZafKMJJpXU7uzcWkEHZFigdYm1YtzFUY6Fw==
X-Received: by 2002:adf:80ee:: with SMTP id 101mr5021626wrl.156.1588349695064;
        Fri, 01 May 2020 09:14:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5386:: with SMTP id d6ls7858082wrv.5.gmail; Fri, 01 May
 2020 09:14:54 -0700 (PDT)
X-Received: by 2002:adf:f750:: with SMTP id z16mr5192941wrp.115.1588349694544;
        Fri, 01 May 2020 09:14:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588349694; cv=none;
        d=google.com; s=arc-20160816;
        b=sEDM2/Tx+r2K88Kbeq6R+3D56JQAROwMeLrvOYLySgyfWzssglb+EvjkT78ihtJzMK
         aqdERVIIrFLiIuDG73itb5X2uOBAJ10FXCrKy8duPwJvwKv95VSqbxexkb1eq+Gzrf2Y
         p8K/O+WsZD96R1yZwHUzNq/J48rTVxqvpM8JcoSc0qFVr/fvQf/OWZmB6BA5hL51C9ZL
         xJBCgoCPbjAXJWhvrMkNHe9IrAHjqyM+MhQaHxc8bNKnTLZPRt5S/7AhxrKrffalRm2x
         2RbnmlGFozTbKaz4DzLBAHHdZ2oL3Jepx6w7dlOMdBySnURPv37cNtnrnRNnzQtji52X
         YGFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E9HC4TtDYcMl70D2yLsiFayEi4W3obxsAzPswR8DMak=;
        b=se7ciz11JAnWLBpouAUX0FiN6tiRvPBSlP4XtBWKwXFAo6yio3Scs2Kz1vQeZG//yF
         s0ety7qhT46FjdQFuy2FB3bMEURTHbPQbEZA3+NKojWQ5urP/8f6VvH/e25XLWqfEEH0
         zwaQwfI0MvD0LUH6fUdyll4J4CH3L64fTcNUndFkarZnk+qIs4+wxG4aaZku/8kniI5U
         mlROhe9qwauvyuyAlpJzFgvJoXFy9VV+HThtevb7LzL7Z6K33w4QH0dlknu1qm5gQEh8
         Cl0pFsT44hAoHwx1HJyN/r+7qWQ4CVUeiJ7r2tMKJb6BJFIsIZPtzBmLC80aCXAtpBi8
         FH2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=pA76bR8I;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id 71si790837wmb.1.2020.05.01.09.14.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 May 2020 09:14:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id l19so3021088lje.10
        for <kasan-dev@googlegroups.com>; Fri, 01 May 2020 09:14:54 -0700 (PDT)
X-Received: by 2002:a05:651c:107a:: with SMTP id y26mr2869691ljm.80.1588349693754;
 Fri, 01 May 2020 09:14:53 -0700 (PDT)
MIME-Version: 1.0
References: <20200501083510.1413-1-anders.roxell@linaro.org> <CANpmjNNm9DhVj5T1rhykEdNBiTvkG-YxL6O25bSfQi8ySh9KtA@mail.gmail.com>
In-Reply-To: <CANpmjNNm9DhVj5T1rhykEdNBiTvkG-YxL6O25bSfQi8ySh9KtA@mail.gmail.com>
From: Anders Roxell <anders.roxell@linaro.org>
Date: Fri, 1 May 2020 18:14:42 +0200
Message-ID: <CADYN=9KLb6FVZ1icbvCY0ondiim44CNk8g8buFCGqpC5cMqyVQ@mail.gmail.com>
Subject: Re: [PATCH] kunit: Kconfig: enable a KUNIT_RUN_ALL fragment
To: Marco Elver <elver@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "Theodore Ts'o" <tytso@mit.edu>, 
	Andreas Dilger <adilger.kernel@dilger.ca>, John Johansen <john.johansen@canonical.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-ext4@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com, 
	linux-security-module <linux-security-module@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=pA76bR8I;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, 1 May 2020 at 11:57, Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 May 2020 at 10:35, Anders Roxell <anders.roxell@linaro.org> wrote:
> >
> > Make it easier to enable all KUnit fragments.  This is needed for kernel
> > test-systems, so its easy to get all KUnit tests enabled and if new gets
> > added they will be enabled as well.  Fragments that has to be builtin
> > will be missed if CONFIG_KUNIT_RUN_ALL is set as a module.
> >
> > Adding 'if !KUNIT_RUN_ALL' so individual test can be turned of if
> > someone wants that even though KUNIT_RUN_ALL is enabled.
> >
> > Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
> > ---
> >  drivers/base/Kconfig      |  3 ++-
> >  drivers/base/test/Kconfig |  3 ++-
> >  fs/ext4/Kconfig           |  3 ++-
> >  lib/Kconfig.debug         |  6 ++++--
> >  lib/Kconfig.kcsan         |  3 ++-
> >  lib/kunit/Kconfig         | 15 ++++++++++++---
> >  security/apparmor/Kconfig |  3 ++-
> >  7 files changed, 26 insertions(+), 10 deletions(-)
> >
> > diff --git a/drivers/base/Kconfig b/drivers/base/Kconfig
> > index 5f0bc74d2409..c48e6e4ef367 100644
> > --- a/drivers/base/Kconfig
> > +++ b/drivers/base/Kconfig
> > @@ -149,8 +149,9 @@ config DEBUG_TEST_DRIVER_REMOVE
> >           test this functionality.
> >
> >  config PM_QOS_KUNIT_TEST
> > -       bool "KUnit Test for PM QoS features"
> > +       bool "KUnit Test for PM QoS features" if !KUNIT_RUN_ALL
> >         depends on KUNIT=y
> > +       default KUNIT_RUN_ALL
> >
> >  config HMEM_REPORTING
> >         bool
> > diff --git a/drivers/base/test/Kconfig b/drivers/base/test/Kconfig
> > index 305c7751184a..0d662d689f6b 100644
> > --- a/drivers/base/test/Kconfig
> > +++ b/drivers/base/test/Kconfig
> > @@ -9,5 +9,6 @@ config TEST_ASYNC_DRIVER_PROBE
> >
> >           If unsure say N.
> >  config KUNIT_DRIVER_PE_TEST
> > -       bool "KUnit Tests for property entry API"
> > +       bool "KUnit Tests for property entry API" if !KUNIT_RUN_ALL
> >         depends on KUNIT=y
> > +       default KUNIT_RUN_ALL
> > diff --git a/fs/ext4/Kconfig b/fs/ext4/Kconfig
> > index 2a592e38cdfe..76785143259d 100644
> > --- a/fs/ext4/Kconfig
> > +++ b/fs/ext4/Kconfig
> > @@ -103,9 +103,10 @@ config EXT4_DEBUG
> >                 echo 1 > /sys/module/ext4/parameters/mballoc_debug
> >
> >  config EXT4_KUNIT_TESTS
> > -       tristate "KUnit tests for ext4"
> > +       tristate "KUnit tests for ext4" if !KUNIT_RUN_ALL
> >         select EXT4_FS
> >         depends on KUNIT
> > +       default KUNIT_RUN_ALL
> >         help
> >           This builds the ext4 KUnit tests.
> >
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 8e4aded46281..993e0c5549bc 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -2123,8 +2123,9 @@ config TEST_SYSCTL
> >           If unsure, say N.
> >
> >  config SYSCTL_KUNIT_TEST
> > -       tristate "KUnit test for sysctl"
> > +       tristate "KUnit test for sysctl" if !KUNIT_RUN_ALL
> >         depends on KUNIT
> > +       default KUNIT_RUN_ALL
> >         help
> >           This builds the proc sysctl unit test, which runs on boot.
> >           Tests the API contract and implementation correctness of sysctl.
> > @@ -2134,8 +2135,9 @@ config SYSCTL_KUNIT_TEST
> >           If unsure, say N.
> >
> >  config LIST_KUNIT_TEST
> > -       tristate "KUnit Test for Kernel Linked-list structures"
> > +       tristate "KUnit Test for Kernel Linked-list structures" if !KUNIT_RUN_ALL
> >         depends on KUNIT
> > +       default KUNIT_RUN_ALL
> >         help
> >           This builds the linked list KUnit test suite.
> >           It tests that the API and basic functionality of the list_head type
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index ea28245c6c1d..91398300a1bc 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -46,8 +46,9 @@ config KCSAN_SELFTEST
> >           works as intended.
> >
> >  config KCSAN_TEST
> > -       tristate "KCSAN test for integrated runtime behaviour"
> > +       tristate "KCSAN test for integrated runtime behaviour" if !KUNIT_RUN_ALL
> >         depends on TRACEPOINTS && KUNIT
> > +       default KUNIT_RUN_ALL
> >         select TORTURE_TEST
> >         help
> >           KCSAN test focusing on behaviour of the integrated runtime. Tests
>
> I think if you want this patch to be picked up you need to split it,
> with one patch for each test that is not yet in mainline or the tree
> that should pick this patch up.

OK, would it be ok to do one patch per subsystem if it's in the mainline tree,
and another patch if it's only in the next tree for the same subsystem?

>
> The KCSAN test is in the -rcu tree, but I don't expect it to be merged
> before 5.9. Most likely, we would only be able to pick up the patch
> that would make the chance to the KCSAN Kconfig entry once the rest
> here made it into mainline.
>
> Thanks,
> -- Marco
>
> > diff --git a/lib/kunit/Kconfig b/lib/kunit/Kconfig
> > index 95d12e3d6d95..d6a912779816 100644
> > --- a/lib/kunit/Kconfig
> > +++ b/lib/kunit/Kconfig
> > @@ -15,7 +15,8 @@ menuconfig KUNIT
> >  if KUNIT
> >
> >  config KUNIT_DEBUGFS
> > -       bool "KUnit - Enable /sys/kernel/debug/kunit debugfs representation"
> > +       bool "KUnit - Enable /sys/kernel/debug/kunit debugfs representation" if !KUNIT_RUN_ALL
> > +       default KUNIT_RUN_ALL
> >         help
> >           Enable debugfs representation for kunit.  Currently this consists
> >           of /sys/kernel/debug/kunit/<test_suite>/results files for each
> > @@ -23,7 +24,8 @@ config KUNIT_DEBUGFS
> >           run that occurred.
> >
> >  config KUNIT_TEST
> > -       tristate "KUnit test for KUnit"
> > +       tristate "KUnit test for KUnit" if !KUNIT_RUN_ALL
> > +       default KUNIT_RUN_ALL
> >         help
> >           Enables the unit tests for the KUnit test framework. These tests test
> >           the KUnit test framework itself; the tests are both written using
> > @@ -32,7 +34,8 @@ config KUNIT_TEST
> >           expected.
> >
> >  config KUNIT_EXAMPLE_TEST
> > -       tristate "Example test for KUnit"
> > +       tristate "Example test for KUnit" if !KUNIT_RUN_ALL
> > +       default KUNIT_RUN_ALL
> >         help
> >           Enables an example unit test that illustrates some of the basic
> >           features of KUnit. This test only exists to help new users understand
> > @@ -41,4 +44,10 @@ config KUNIT_EXAMPLE_TEST
> >           is intended for curious hackers who would like to understand how to
> >           use KUnit for kernel development.
> >
> > +config KUNIT_RUN_ALL
> > +       tristate "KUnit run all test"
> > +       help
> > +         Enables all KUnit tests. If they can be enabled.
> > +         That depends on if KUnit is enabled as a module or builtin.
> > +
>
> s/tests. If/tests, if/ ?

correct, I will fix that.

Cheers,
Anders

>
> >  endif # KUNIT
> > diff --git a/security/apparmor/Kconfig b/security/apparmor/Kconfig
> > index 0fe336860773..c4648426ea5d 100644
> > --- a/security/apparmor/Kconfig
> > +++ b/security/apparmor/Kconfig
> > @@ -70,8 +70,9 @@ config SECURITY_APPARMOR_DEBUG_MESSAGES
> >           the kernel message buffer.
> >
> >  config SECURITY_APPARMOR_KUNIT_TEST
> > -       bool "Build KUnit tests for policy_unpack.c"
> > +       bool "Build KUnit tests for policy_unpack.c" if !KUNIT_RUN_ALL
> >         depends on KUNIT=y && SECURITY_APPARMOR
> > +       default KUNIT_RUN_ALL
> >         help
> >           This builds the AppArmor KUnit tests.
> >
> > --
> > 2.20.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADYN%3D9KLb6FVZ1icbvCY0ondiim44CNk8g8buFCGqpC5cMqyVQ%40mail.gmail.com.
