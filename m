Return-Path: <kasan-dev+bncBC6OLHHDVUOBBD5XXD4QKGQERH6AQIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C06C23F625
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Aug 2020 05:27:12 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id a12sf758288ljn.12
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 20:27:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596857232; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tx1BQCbhr3rgtP7AycDOxiB0H6MYotZXhB2NJ6kJINysOStHROvT01t/sB0uCEYhub
         kI+1dnUGaiE2GOFZoVJrpVnr3kfeR/PJwhYfCDXhjRllgWqTG6dq3QNA2WiODaX6l1rc
         pEyMTAjZ9XXKcjbmkvNUvaJJgKIHVLV5mlV+8XA9CQKB9kknpwlu/LHikpI73z83J9WC
         /XwY0mGVyHM8IAtlvVK2MyCD87+S/3tvF85O+KZoRjPaB2tzkpakmBHICWXV/wgzuBRB
         /a9sZwML6w6u5c8iwQi4le1h2XFjE3SzHyyMsg8QWwZX4of2+VFk3+5s94i3pDLJ5pp6
         YIsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1W57spunnfxJBn1STRIYo+ZOHhKUh0DkeYrVyKN+waw=;
        b=SjKPXxP780KWdMa8tS+qQFH27ZzfGaqD3HHYQ57PpwH7LJtLigSDQyGgP3loZOdLiV
         sGT0Xexal7C7X/6Iq3UEyIKlYfL18fIoxRjLXM5UpFwA+STViyjsK4zBltTAv1Lalt7k
         agKFFkhxbxrzu4yPA5I7yoNq6fkOC7K+PhHjTKf+VMPVR9LyMO8xJAkQR6piW+Ox7W9e
         72hA1Yt2Ooei8PeAryAkyvw9VsATEGT8ZSk6dsoR67LbsdaYkEZ/+6MhKGDKxjRmckJ7
         HUKXlHf9LNZWFXJ4OnLNWed2q18+9asyo/xSGMd0/uaA+FJ+vXM5zhZbS1MuyX5fRtjU
         UzJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mYnRitoD;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1W57spunnfxJBn1STRIYo+ZOHhKUh0DkeYrVyKN+waw=;
        b=LyApqX9D9VJ2OorQRCJltj/mdj3ESUoZJo2qAeeABpCfo+5RW1Tz2Ox/+5PdktG73g
         2Mm26RRP/OY5gHT+aY2l57odhIb2Tvtmu2CZHe+ly9QceTz9PRTXbaqUODNu1JpPd9SV
         QuEkDqkziTw3NOumA5q6nn908XyrG+xvYBHS6M1Om+ltvyB/bfeUeD161105qMs93eK9
         hMhk4yvrtCu7BzHMsmnym9dvrMwQJwFUP6cxpa4i7HmewzGgdmZuTfDZ05IZsNPNgPSs
         MSZ9oQ/6l7ZDlIk3O89+bVIiz4hJAM+lW16S2gPB+UVoLd5C5vJs00s36jvDbZzzIpAe
         HZQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1W57spunnfxJBn1STRIYo+ZOHhKUh0DkeYrVyKN+waw=;
        b=qU6zWPKXgUBOFn/t9wRZMYn3LCNWHgmBMRcpLUDiUrnsSKNsuHOS3M4mE6MNNDIiJM
         IyZwAPNWvGdiIsVasYAOy4ys3UsgJGxzlXLKwQOeLiI94rIqP7TVT88TDZgGKbVZKoJG
         WYJV6oLVGFRwVUbJ03lKjEBbP5WHmxCzIbbk8gq6VEZPm9ei/Kqm2Qi4PQ2TpCPveYMJ
         iQ8Mnlzey9wPHmtD1ReFryzyqc7TGnTbAuHdGSMWm6loh5+VPRbc4wVne5pfw6Trnlg4
         aEBRtr8GihtwMNGWt1BluHBdyuVTSzeotjSbk8O+GPQaUuLQRYC7Fxc4M7ktrPDM9rIS
         l4lg==
X-Gm-Message-State: AOAM5309KBUb5ShZ8LKM+9W66nLxPgP7NhRbbVLIXDuNBxVK4qPDcp5x
	+D5XaNsjhNoOhcoygq9iZ2U=
X-Google-Smtp-Source: ABdhPJwVUkDiro3Slwvsf/LQfnjfmvGB430ByRZyep6djRVLBfVbTL9oe3uMdyPVWisKdVJyaqp/pA==
X-Received: by 2002:a2e:9d8e:: with SMTP id c14mr7928615ljj.332.1596857231857;
        Fri, 07 Aug 2020 20:27:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1182:: with SMTP id w2ls460958ljo.2.gmail; Fri, 07
 Aug 2020 20:27:11 -0700 (PDT)
X-Received: by 2002:a05:651c:204f:: with SMTP id t15mr8235389ljo.308.1596857231032;
        Fri, 07 Aug 2020 20:27:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596857231; cv=none;
        d=google.com; s=arc-20160816;
        b=UG+u2jus3Z3HCs6Iy5IBVGm+8o4AfBBgNvb3NmxP/Okc9scCSuqftqRZmxW861GRk1
         M/YisBIzhX0Wuas8eTsVz5ZDUn69yEjNWsWRZHwFqlv18JhVedRZj20qB+CZRHMrEUY+
         TTtjINe7UMK0nf4V1YpzUmmt8Qo6/gVTM65jfz8S374lfXK66qBMQ+82nKL8sfzYWQCW
         DfSNYZDJunbSqJZD6ZDcpVjN/uOi04lmHv7SMxnvcasv580DmbaXdzb17dCE7pkYbkqz
         LWta+A0tV9o/HPZwk1E6L4rCA7+zGotaNStFmsmQ//dCztAVsKu9kKqop9DkbWRvXXo6
         Ct1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I0+G3ptAFziJUCT/18IT+zTZUcvz/66QmwQnq2ejpjY=;
        b=wR70r30rHcvpPpGbOaTSfpFW1dyoOmsH3Gj2savfbN4DWqFMv+IGQBF9hkraO1Mr0v
         f1ezvxXlrqvf/BsratlaQ1fPkOPHkxOuqB7FTragaI9nbpGUBRR+xJ1eyclwRYH+qTL8
         ZFwGbysiMevilCwt7U0bccv+T62KlJxWFlTK6FY1enEw8vxlklqYXnmLQb7We39OoHVo
         2N4c047Ua1l0G1HSAM4YB/wdsWi54R23nhhxuZ1Owdus8if16QBUgpoliv1Wz/9nPJ6e
         MfuDmRTxdyLekIlky4qQyEu8ey1Ef1hosnwRavAJaX/QogScE3HMmvgq+hhPwnuxV3g/
         agRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mYnRitoD;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id z22si385922lfd.1.2020.08.07.20.27.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 20:27:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id c80so3252704wme.0
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 20:27:10 -0700 (PDT)
X-Received: by 2002:a1c:2485:: with SMTP id k127mr14768659wmk.138.1596857230126;
 Fri, 07 Aug 2020 20:27:10 -0700 (PDT)
MIME-Version: 1.0
References: <20200805042938.2961494-1-davidgow@google.com> <CAAeHK+wPt46879AnV3n3d7+JZqkv2Vo652OPBAjHcuyru56h9w@mail.gmail.com>
In-Reply-To: <CAAeHK+wPt46879AnV3n3d7+JZqkv2Vo652OPBAjHcuyru56h9w@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 8 Aug 2020 11:26:58 +0800
Message-ID: <CABVgOSmveFxFq-Kvtq9+EQa61ko-wQ4CTJ2WCfJWbjUWzBaQrg@mail.gmail.com>
Subject: Re: [PATCH v11 0/6] KASAN-KUnit Integration
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Patricia Alfonso <trishalfonso@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, Shuah Khan <shuah@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mYnRitoD;       spf=pass
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

On Fri, Aug 7, 2020 at 9:15 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Wed, Aug 5, 2020 at 6:29 AM David Gow <davidgow@google.com> wrote:
> >
> > This patchset contains everything needed to integrate KASAN and KUnit.
> >
> > KUnit will be able to:
> > (1) Fail tests when an unexpected KASAN error occurs
> > (2) Pass tests when an expected KASAN error occurs
> >
> > Convert KASAN tests to KUnit with the exception of copy_user_test
> > because KUnit is unable to test those.
> >
> > Add documentation on how to run the KASAN tests with KUnit and what to
> > expect when running these tests.
> >
> > This patchset depends on:
> > - "kunit: extend kunit resources API" [1]
> >  - This is included in the KUnit 5.9-rci pull request[8]
> >
> > I'd _really_ like to get this into 5.9 if possible: we also have some
> > other changes which depend on some things here.
>
> Found a small issue in patch #3, but otherwise:
>
> Tested-by: Andrey Konovalov <andreyknvl@google.com>
>
> for the series.

Cheers! The issue in #3 looks to be a rebase issue: I'll send a fixed
version out soon.
>
> The patches apply cleanly on top of the latest linux-next/akpm branch.
>
> There are some tests that fail for tag-based mode, but those are
> unrelated to this series, and require KASAN improvements.
>
Do you think it's worth disabling these tests if tag-based mode is
disabled? Personally, I'm leaning "no", but if the planned support for
explicitly skipping tests existed, this could be a good case for it: a
test which is expected to fail due to a feature not existing in the
current config.

Thanks,
-- David

> >
> > Changes from v10:
> >  - Fixed some whitespace issues in patch 2.
> >  - Split out the renaming of the KUnit test suite into a separate patch.
> >
> > Changes from v9:
> >  - Rebased on top of linux-next (20200731) + kselftest/kunit and [7]
> >  - Note that the kasan_rcu_uaf test has not been ported to KUnit, and
> >    remains in test_kasan_module. This is because:
> >    (a) KUnit's expect failure will not check if the RCU stacktraces
> >        show.
> >    (b) KUnit is unable to link the failure to the test, as it occurs in
> >        an RCU callback.
> >
> > Changes from v8:
> >  - Rebased on top of kselftest/kunit
> >  - (Which, with this patchset, should rebase cleanly on 5.8-rc7)
> >  - Renamed the KUnit test suite, config name to patch the proposed
> >    naming guidelines for KUnit tests[6]
> >
> > Changes from v7:
> >  - Rebased on top of kselftest/kunit
> >  - Rebased on top of v4 of the kunit resources API[1]
> >  - Rebased on top of v4 of the FORTIFY_SOURCE fix[2,3,4]
> >  - Updated the Kconfig entry to support KUNIT_ALL_TESTS
> >
> > Changes from v6:
> >  - Rebased on top of kselftest/kunit
> >  - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
> >    incompatibilites [2]
> >  - Removed a redundant report_enabled() check.
> >  - Fixed some places with out of date Kconfig names in the
> >    documentation.
> >
> > Changes from v5:
> >  - Split out the panic_on_warn changes to a separate patch.
> >  - Fix documentation to fewer to the new Kconfig names.
> >  - Fix some changes which were in the wrong patch.
> >  - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)
> >
> > Changes from v4:
> >  - KASAN no longer will panic on errors if both panic_on_warn and
> >    kasan_multishot are enabled.
> >  - As a result, the KASAN tests will no-longer disable panic_on_warn.
> >  - This also means panic_on_warn no-longer needs to be exported.
> >  - The use of temporary "kasan_data" variables has been cleaned up
> >    somewhat.
> >  - A potential refcount/resource leak should multiple KASAN errors
> >    appear during an assertion was fixed.
> >  - Some wording changes to the KASAN test Kconfig entries.
> >
> > Changes from v3:
> >  - KUNIT_SET_KASAN_DATA and KUNIT_DO_EXPECT_KASAN_FAIL have been
> >  combined and included in KUNIT_DO_EXPECT_KASAN_FAIL() instead.
> >  - Reordered logic in kasan_update_kunit_status() in report.c to be
> >  easier to read.
> >  - Added comment to not use the name "kasan_data" for any kunit tests
> >  outside of KUNIT_EXPECT_KASAN_FAIL().
> >
> > Changes since v2:
> >  - Due to Alan's changes in [1], KUnit can be built as a module.
> >  - The name of the tests that could not be run with KUnit has been
> >  changed to be more generic: test_kasan_module.
> >  - Documentation on how to run the new KASAN tests and what to expect
> >  when running them has been added.
> >  - Some variables and functions are now static.
> >  - Now save/restore panic_on_warn in a similar way to kasan_multi_shot
> >  and renamed the init/exit functions to be more generic to accommodate.
> >  - Due to [4] in kasan_strings, kasan_memchr, and
> >  kasan_memcmp will fail if CONFIG_AMD_MEM_ENCRYPT is enabled so return
> >  early and print message explaining this circumstance.
> >  - Changed preprocessor checks to C checks where applicable.
> >
> > Changes since v1:
> >  - Make use of Alan Maguire's suggestion to use his patch that allows
> >    static resources for integration instead of adding a new attribute to
> >    the kunit struct
> >  - All KUNIT_EXPECT_KASAN_FAIL statements are local to each test
> >  - The definition of KUNIT_EXPECT_KASAN_FAIL is local to the
> >    test_kasan.c file since it seems this is the only place this will
> >    be used.
> >  - Integration relies on KUnit being builtin
> >  - copy_user_test has been separated into its own file since KUnit
> >    is unable to test these. This can be run as a module just as before,
> >    using CONFIG_TEST_KASAN_USER
> >  - The addition to the current task has been separated into its own
> >    patch as this is a significant enough change to be on its own.
> >
> >
> > [1] https://lore.kernel.org/linux-kselftest/CAFd5g46Uu_5TG89uOm0Dj5CMq+11cwjBnsd-k_CVy6bQUeU4Jw@mail.gmail.com/T/#t
> > [2] https://lore.kernel.org/linux-mm/20200424145521.8203-1-dja@axtens.net/
> > [3] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=adb72ae1915db28f934e9e02c18bfcea2f3ed3b7
> > [4] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=47227d27e2fcb01a9e8f5958d8997cf47a820afc
> > [5] https://bugzilla.kernel.org/show_bug.cgi?id=206337
> > [6] https://lore.kernel.org/linux-kselftest/20200620054944.167330-1-davidgow@google.com/
> > [7] https://lkml.org/lkml/2020/7/31/571
> > [8] https://lore.kernel.org/linux-kselftest/8d43e88e-1356-cd63-9152-209b81b16746@linuxfoundation.org/T/#u
> >
> >
> > David Gow (2):
> >   kasan: test: Make KASAN KUnit test comply with naming guidelines
> >   mm: kasan: Do not panic if both panic_on_warn and kasan_multishot set
> >
> > Patricia Alfonso (4):
> >   Add KUnit Struct to Current Task
> >   KUnit: KASAN Integration
> >   KASAN: Port KASAN Tests to KUnit
> >   KASAN: Testing Documentation
> >
> >  Documentation/dev-tools/kasan.rst |  70 +++
> >  include/kunit/test.h              |   5 +
> >  include/linux/kasan.h             |   6 +
> >  include/linux/sched.h             |   4 +
> >  lib/Kconfig.kasan                 |  22 +-
> >  lib/Makefile                      |   7 +-
> >  lib/kasan_kunit.c                 | 770 +++++++++++++++++++++++++
> >  lib/kunit/test.c                  |  13 +-
> >  lib/test_kasan.c                  | 903 ------------------------------
> >  lib/test_kasan_module.c           | 111 ++++
> >  mm/kasan/report.c                 |  34 +-
> >  11 files changed, 1028 insertions(+), 917 deletions(-)
> >  create mode 100644 lib/kasan_kunit.c
> >  delete mode 100644 lib/test_kasan.c
> >  create mode 100644 lib/test_kasan_module.c
> >
> > --
> > 2.28.0.163.g6104cc2f0b6-goog
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwPt46879AnV3n3d7%2BJZqkv2Vo652OPBAjHcuyru56h9w%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmveFxFq-Kvtq9%2BEQa61ko-wQ4CTJ2WCfJWbjUWzBaQrg%40mail.gmail.com.
