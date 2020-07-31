Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVNXSD4QKGQEGP6M4MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D5DB52346D0
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 15:25:42 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id y22sf12307919oog.21
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:25:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596201942; cv=pass;
        d=google.com; s=arc-20160816;
        b=irJAVTMWEOIy0YRoIgVqutVHWwpbtVwIzxmwCPNDVbE/DYtSVdNuBNpimbi6jYpRoW
         LvNsT4MeJXc+3DRPNsteCJQSIN+bfQbE1Y/fdd8LP40zMqufwfmkwi65UH4Lf33xfuAZ
         O/rycLrm4nPGCcdLrSbFMlB6ILO/asc+3eLxDuwtOGwAAY0b1TRmmuDiVgODkQSN6uto
         2WLqRKnYlCW0elry/rm6e7Es5FhFrAGP6Jc//zYb2ivLitaH7/2DNgh9CabxCoQuGpq4
         l50rLtwmJkDFBmwT+lL/yjwB6vv3WzzGtIcekEK6YGSDLWrj7BixmXaefYuLyEJBqcfO
         rAXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sOvaGVJdeywSeATWj44ZghVdmOb4HMLgZwz/94HhUAM=;
        b=D71pKPD7W2xaSCkixNWkxJ7tlSAIjpbPf67i/XXWbHT2STHhKY4YNqn65hsBHLQWhv
         JL04UdbCrR5qN/YjpW5K3dEsLJ1tvpP0QA3JavdDNOVy8lJ5bb7yof6iOiLeFKOgCv3j
         j9K/y/fU1BuWV/k0Kj+4nB8x/Y9NJ5FlkKU2POQ9wKRQBKKId3pL/5ZL5vXRCk/36jaH
         9b3O7hvQn1hPWZeFQlDMjQhFWQ7bYcZaEntSPvTbC6wQO5Rg26eB4sS8/3TbjP3kqteE
         u8QDl/kZQQOVrGC6M/7u8RxlNB4AeWOcsdz5//Cfp2F9OOfX+vQ0Nsq/R8r+pSeNzpNX
         /kMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EFgAoxc1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sOvaGVJdeywSeATWj44ZghVdmOb4HMLgZwz/94HhUAM=;
        b=rBh5gU+SlzTjxudC2DQr+b1vW1hYWcOO5se906+184t0A/tc1dtltwqywLyJiLaxFc
         N9AbLdrpMvrUAPjOd8+UkLJG7ZwWmWhlZkb+4VqsnU6JTB1d4fL03ooGCLPz8tA2Ftdj
         8A4QA2BYpuesCvK3YJJjzkzj+ZlNGWkRDTgOILm0b4+mdeGRlypGXp6dhnas8y4OeqUG
         fXPmmCjNHRmHcQGApN/7WO47y8BlwVppoorBgQV2xaWcKswfer+OOZ40z+FeoWixITeX
         N9npFsAXw8/YQ3l6/EdDuF7rcBc6162xBAsLMtzO/X09I05h5qkEVbMI5toB2qvcJYcK
         UcpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sOvaGVJdeywSeATWj44ZghVdmOb4HMLgZwz/94HhUAM=;
        b=HUwfFC6Vvq1MPbfSGRMQ7xGz+dw2W9ELS34lfZigTmBw93HtfTUhQmx+StRP/KOkUL
         bDBNbgifXlTMcDQu9WMiQq/sAQAkF+moBVxsKGOf0Hqcmo/Vu1yMm0Zv+7E3m9hxlEnQ
         B4ZeFJxV4ITxOXQvXFocxDyUieNk2iv8vA7Fc9Kyb8r3RE+hNJkhjytjRoF6pqpHFFR0
         jo196XVElAOEsjwiUIz/urMZz+2JAZVTPV9jVMAuWE5yCqakNNItNl78SaD2GIlr0fvM
         fdbz+9i/V8QU3aSt9PoA5UyZYnSZQhDawHyETajyQQxlEsnfITVfObQECdLd4IB5VKXy
         gNSw==
X-Gm-Message-State: AOAM532p2Ww08SYXRxG8syK/eU9McCnuKlqwqTyY7lmv2LYjc7v4I5Xf
	6y1DG/8eEeR/3BS8w8c7yaw=
X-Google-Smtp-Source: ABdhPJwUMUVrBG83Y7u3IDj7phOJS2qkvX6y7/NGiQtVzObl9Oyw5NwaBaptiplvebhAFzROTSPP4g==
X-Received: by 2002:a05:6830:1112:: with SMTP id w18mr2843976otq.301.1596201941812;
        Fri, 31 Jul 2020 06:25:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:56c3:: with SMTP id k186ls1558360oib.5.gmail; Fri, 31
 Jul 2020 06:25:41 -0700 (PDT)
X-Received: by 2002:aca:5885:: with SMTP id m127mr3048868oib.4.1596201941484;
        Fri, 31 Jul 2020 06:25:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596201941; cv=none;
        d=google.com; s=arc-20160816;
        b=GPB1hJrgqFKl6KYj961fnvgJ8yOcKBWKkISK7D3e89lLf1rumtVM0eg+lyv7Jdd7wO
         PZy23R+bmYorasDSURIqg/RywDx4TbXMlVRqKdeDR7xsIt+J5YoQCvSXWtjBT4PF1igR
         27OjtR7hJOO/aFPPIIpaoXKBRviNYvamWRMao5uf0qSIj6UfkHf24tRo/IrPgShL3aFM
         IOoPX9AcfoMFrbVSVg5O6BosSsGnTTHgns8TO2QI7mYkVwsLZCC9qCrydJKml0iZV6ny
         K78YPKTAi49/baBXBxGiAPhH5atJVw7rT+oAgkY8pqA4XHeB9t7zONfbhdPRcmqLviX/
         BPzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JEI7QlNd+n7mCSlqUP8tfyoHThcUKaKtV6i9WVkU4rE=;
        b=jffTU3FfljhrpadnrhOX6phH3Dpl6mfKqlKXnf6ZSqjTzmRN6tOTRva8HmryRdcF+i
         BwdN8kGtApF4P+UNxxuE6bE5G86OUK3m6OnsQN9YD+PB8JKFrb3CsyRmIAS5b+j5m0yZ
         u6W1QM9xH6guhxL4sRbdocVbIUdYunXIs5YikTqty8SbiL/xqaVAKeYtjvRiGxCA8Hnp
         5SiMv6tX6sDL0+EFrXyf6eCrS9LVFIhTcPs3nxMHxNoWUs3CXzBd56Kgt/3ag7VX3X0A
         1t+9A51hYZZ/YSBylfpfASXEbBYeNY4/YMht7Gv0KeDfw1qxLvCvL7o9QQCIJeRmrJRk
         pBJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EFgAoxc1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id v18si476579oor.0.2020.07.31.06.25.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 06:25:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id w19so4405909plq.3
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 06:25:41 -0700 (PDT)
X-Received: by 2002:a17:90a:6a8d:: with SMTP id u13mr3852021pjj.166.1596201940297;
 Fri, 31 Jul 2020 06:25:40 -0700 (PDT)
MIME-Version: 1.0
References: <20200731044242.1323143-1-davidgow@google.com>
In-Reply-To: <20200731044242.1323143-1-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 31 Jul 2020 15:25:29 +0200
Message-ID: <CAAeHK+z0wJ-3+dXey9o3zysy9fPOqk-YdFFtVOB5==WcG3B8+Q@mail.gmail.com>
Subject: Re: [PATCH v9 0/5] KASAN-KUnit Integration
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Shuah Khan <shuah@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EFgAoxc1;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Jul 31, 2020 at 6:43 AM David Gow <davidgow@google.com> wrote:
>
> This patchset contains everything needed to integrate KASAN and KUnit.
>
> KUnit will be able to:
> (1) Fail tests when an unexpected KASAN error occurs
> (2) Pass tests when an expected KASAN error occurs
>
> Convert KASAN tests to KUnit with the exception of copy_user_test
> because KUnit is unable to test those.
>
> Add documentation on how to run the KASAN tests with KUnit and what to
> expect when running these tests.
>
> This patchset depends on:
> - "kunit: extend kunit resources API" [1]
>  - This is already present in the kselftest/kunit branch
>
> I'd _really_ like to get this into 5.9 if possible: we also have some
> other changes which depend on some things here.

Hi David,

You'll need to rebase this on top of the mm tree, which currently
contains Walter's patch titled "kasan: fix KASAN unit tests for
tag-based KASAN".

There's also another patch that touches KASAN tests in the series I've
just mailed titled "kasan: support stack instrumentation for tag-based
mode".

Thanks!


>
> Changes from v8:
>  - Rebased on top of kselftest/kunit
>  - (Which, with this patchset, should rebase cleanly on 5.8-rc7)
>  - Renamed the KUnit test suite, config name to patch the proposed
>    naming guidelines for KUnit tests[6]
>
> Changes from v7:
>  - Rebased on top of kselftest/kunit
>  - Rebased on top of v4 of the kunit resources API[1]
>  - Rebased on top of v4 of the FORTIFY_SOURCE fix[2,3,4]
>  - Updated the Kconfig entry to support KUNIT_ALL_TESTS
>
> Changes from v6:
>  - Rebased on top of kselftest/kunit
>  - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
>    incompatibilites [2]
>  - Removed a redundant report_enabled() check.
>  - Fixed some places with out of date Kconfig names in the
>    documentation.
>
> Changes from v5:
>  - Split out the panic_on_warn changes to a separate patch.
>  - Fix documentation to fewer to the new Kconfig names.
>  - Fix some changes which were in the wrong patch.
>  - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)
>
> Changes from v4:
>  - KASAN no longer will panic on errors if both panic_on_warn and
>    kasan_multishot are enabled.
>  - As a result, the KASAN tests will no-longer disable panic_on_warn.
>  - This also means panic_on_warn no-longer needs to be exported.
>  - The use of temporary "kasan_data" variables has been cleaned up
>    somewhat.
>  - A potential refcount/resource leak should multiple KASAN errors
>    appear during an assertion was fixed.
>  - Some wording changes to the KASAN test Kconfig entries.
>
> Changes from v3:
>  - KUNIT_SET_KASAN_DATA and KUNIT_DO_EXPECT_KASAN_FAIL have been
>  combined and included in KUNIT_DO_EXPECT_KASAN_FAIL() instead.
>  - Reordered logic in kasan_update_kunit_status() in report.c to be
>  easier to read.
>  - Added comment to not use the name "kasan_data" for any kunit tests
>  outside of KUNIT_EXPECT_KASAN_FAIL().
>
> Changes since v2:
>  - Due to Alan's changes in [1], KUnit can be built as a module.
>  - The name of the tests that could not be run with KUnit has been
>  changed to be more generic: test_kasan_module.
>  - Documentation on how to run the new KASAN tests and what to expect
>  when running them has been added.
>  - Some variables and functions are now static.
>  - Now save/restore panic_on_warn in a similar way to kasan_multi_shot
>  and renamed the init/exit functions to be more generic to accommodate.
>  - Due to [4] in kasan_strings, kasan_memchr, and
>  kasan_memcmp will fail if CONFIG_AMD_MEM_ENCRYPT is enabled so return
>  early and print message explaining this circumstance.
>  - Changed preprocessor checks to C checks where applicable.
>
> Changes since v1:
>  - Make use of Alan Maguire's suggestion to use his patch that allows
>    static resources for integration instead of adding a new attribute to
>    the kunit struct
>  - All KUNIT_EXPECT_KASAN_FAIL statements are local to each test
>  - The definition of KUNIT_EXPECT_KASAN_FAIL is local to the
>    test_kasan.c file since it seems this is the only place this will
>    be used.
>  - Integration relies on KUnit being builtin
>  - copy_user_test has been separated into its own file since KUnit
>    is unable to test these. This can be run as a module just as before,
>    using CONFIG_TEST_KASAN_USER
>  - The addition to the current task has been separated into its own
>    patch as this is a significant enough change to be on its own.
>
>
> [1] https://lore.kernel.org/linux-kselftest/CAFd5g46Uu_5TG89uOm0Dj5CMq+11cwjBnsd-k_CVy6bQUeU4Jw@mail.gmail.com/T/#t
> [2] https://lore.kernel.org/linux-mm/20200424145521.8203-1-dja@axtens.net/
> [3] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=adb72ae1915db28f934e9e02c18bfcea2f3ed3b7
> [4] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=47227d27e2fcb01a9e8f5958d8997cf47a820afc
> [5] https://bugzilla.kernel.org/show_bug.cgi?id=206337
> [6] https://lore.kernel.org/linux-kselftest/20200620054944.167330-1-davidgow@google.com/
>
>
> David Gow (1):
>   mm: kasan: Do not panic if both panic_on_warn and kasan_multishot set
>
> Patricia Alfonso (4):
>   Add KUnit Struct to Current Task
>   KUnit: KASAN Integration
>   KASAN: Port KASAN Tests to KUnit
>   KASAN: Testing Documentation
>
>  Documentation/dev-tools/kasan.rst |  70 +++
>  include/kunit/test.h              |   5 +
>  include/linux/kasan.h             |   6 +
>  include/linux/sched.h             |   4 +
>  lib/Kconfig.kasan                 |  22 +-
>  lib/Makefile                      |   7 +-
>  lib/kunit/test.c                  |  13 +-
>  lib/test_kasan.c                  | 858 ------------------------------
>  mm/kasan/report.c                 |  34 +-
>  9 files changed, 147 insertions(+), 872 deletions(-)
>  delete mode 100644 lib/test_kasan.c
>
> --
> 2.28.0.163.g6104cc2f0b6-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz0wJ-3%2BdXey9o3zysy9fPOqk-YdFFtVOB5%3D%3DWcG3B8%2BQ%40mail.gmail.com.
