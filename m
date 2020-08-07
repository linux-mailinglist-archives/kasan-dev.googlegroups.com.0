Return-Path: <kasan-dev+bncBDX4HWEMTEBRBU5HWX4QKGQEGU5YJZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F46E23EDF6
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 15:15:00 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id y5sf1111210ota.0
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 06:15:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596806099; cv=pass;
        d=google.com; s=arc-20160816;
        b=dq4BhgTGLRtInlI0xixnXAAdU13bLakEoQxUG8fhtERwI025Esg3b9jsFF1Q528VsK
         +nrwopdJvA4E2oOtA256k/EsBS7RckjvPU7CWUB3xA7HyueaqUPUbXGlD3pJ36NOG17t
         KgXPl4iTs/852l/QZFrLIUFnP1tgCNOV3xMscXP8k8kfR+BjOUMSkF6Hq4TQQQbjjEOK
         PlfROmfD7UnCje3TRj3L1oq++M0oLA+/Mqnlm6gfkpGJmgLcx+2nWKmdpa3qFAjpJsOp
         wk6jteteaWmkDsdvGnO7bEGU+CZYU0ZMLLnAQ/hY0nwCMbk/nd2m4vIm02CwZ6LilEt5
         e91Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MVSiKatcZAtNufvEGpP7CJmLRBRN/VuSBuu4tKM9Z1k=;
        b=dnQKrKUVmi7yc6XpNRsUSAYg4xQN7eeLtxN69k04IF4k1hPVB+yO8Oz9+QRk9hviB/
         vRQuK3SggLp48nyYm/uGTuMWALENXr3s8bOm6sqyPSSTzIdoLplbac3kCkqjN1rVpKFl
         vGFDjKRipgWJuhsW/kYlxRxd8uymr1blNDzO1d3vtAf7AmcqWbh6uJ0UUMCM30Imw44B
         wWvxbEZytk37DzEvlLX6r0x8kXNbzDP1wT9Rpjehmqj1VOG5jGUOcPLWGf3NlbigZi5h
         rq1544GcjldX7Vp4cyhiqevT2goQ4ZKz2gJ2EqhpytAkEmqoKyiKAW1r/7NTHZOAbKun
         9MEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JGA6dj+D;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MVSiKatcZAtNufvEGpP7CJmLRBRN/VuSBuu4tKM9Z1k=;
        b=EYa+5rxjyiM1bHicRLSoPCHBodjHRJsvj+qbMftpSNzi/31mDWoFjG1LTVj+9nabTl
         dfdw2hk31IJy4hXpkezQq0DXkAImZct5sVnfdgZRjkfESFbxVv+l61QbMv9EkddkUGhN
         axqZFuA4qkjnxSlU2IsNz8B6/hAfGjeK+Akd63le5Gw03QPFyh3YBOEJBgxFXgYt7Y/i
         tVkD2vNUuUK7vxz5x5cB6RGOv/p0ealhWjhPnf5Gmzeak4cGLBcpFt4OAYerL20R+QFd
         3rEkh7cHDrw4DeQFnl2E96ObQtGFnSvV4/jOwvQEmlVTzTyAIAH/3xdBEKf6OZyiSaWa
         vztw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MVSiKatcZAtNufvEGpP7CJmLRBRN/VuSBuu4tKM9Z1k=;
        b=toRBomV+BgRBfQMtOxGSBuOef6+R3QkQZp4Xnu4eY9r/rgEnHMNRL1uxZwyGJK2EQ+
         OiqLxdvZrO7gMJt5fI/aIOXnmexGPO5hBticonFYT4/RutO8tGivdDWa0fx0jkZ+mUzC
         PNW9hLjSiiUSZkBf3aNKO/omhidd3qKsDjWgiS7dlwhxyYvzgvfuCgw9lOba6XvCxfYe
         pmvcQAMndVRaNjyUHsH578rZRX9B/cCWEchdLt+IHNgJPNN6THfk989tyJXWhbMfaCT0
         JN2Q3oQ8LWi+NKKzAFqtrWyGqmDqRdL0M4upXjBG1MZ/8W5NdeJq1nLx1+uGG9tW3Y3V
         4Ajg==
X-Gm-Message-State: AOAM533HI/ykTXVTnYcKV7I43VGjrY9nQf+LlPuqxcZ9SDNOJO4V4EmY
	Xfry9/AmC2p6LUxnWhRNFWY=
X-Google-Smtp-Source: ABdhPJx2WzZlOB1YIAY0IueftS645TjE6+zld4dFOHXSrBPZJ0CoOGZV6l4niyjG8ux6yRaJpWKd4A==
X-Received: by 2002:a4a:4594:: with SMTP id y142mr12327013ooa.24.1596806099110;
        Fri, 07 Aug 2020 06:14:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e9f6:: with SMTP id w22ls606269ooc.4.gmail; Fri, 07 Aug
 2020 06:14:58 -0700 (PDT)
X-Received: by 2002:a4a:88f2:: with SMTP id q47mr12017969ooh.34.1596806098688;
        Fri, 07 Aug 2020 06:14:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596806098; cv=none;
        d=google.com; s=arc-20160816;
        b=jAyo8TjOTE3Bcnh7n0mYbX89SZvhunOk/tI/rosfmnpqJjEXyU1eURpXscI8Quz2H2
         BtLu54bYXnZbduMEgTUZwmTskkI/FvVPkNdZEQKeQGbXhXYxWdUkpBk1RrxIYvmwYJGw
         IWEpeyUKLnjWSvenTKXK77n+uJZzed1FFOh6Ja+i3coRBMm/qca90svwFJ/XjrciYax8
         FM2TUiBqTjqnQ85XbT9YFa3oPeJ7eX7+lsfmDXhSOWw2xlSHsd1fnGcuvIPF+A2kRjcO
         ZKa8/GR4yyeUPf93ID+jjvgMCFmVPqMvANLa3n1MPpunIQ43xXsGYcEUDSWbROHFE5+l
         pHHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ta64/e/ZJXKZ0XNP6hKz3om+KF+Ie9VnHpiNymcsYTM=;
        b=Ro5ER9xkCgpNE9WWrqNDTYXvXmAgzEHk+GV4dwZ+3/V/MrrFSMJCzxYJ0jJLl8tFC7
         oKjPyp4W61zCrNZayc0wU/igRIbhOk0G89L3nG7jla3DswsvoXtEM7mfWMeavb/G5JPx
         LnK2Pp7+qgJxgAUOckLPMLt3IP82cUGN4t54g/9fBNgsmEAvGUANHVRwJN8M46s18JPu
         Vic/fVhHvj4rjnSILKKDR2B+/jWWQX1F1Ls26vrHryHvvske7BDtUIavLGBh6lU4SGW6
         Kz08ZUFHjsV0e/1HT2iUlu1NjvtOlWlaGUxcY5LUWWXdWjzuay6k8rwAJopB/zIb7R2s
         2New==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JGA6dj+D;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id w1si546774otm.5.2020.08.07.06.14.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 06:14:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id p3so891842pgh.3
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 06:14:58 -0700 (PDT)
X-Received: by 2002:a05:6a00:2a2:: with SMTP id q2mr1649947pfs.306.1596806098023;
 Fri, 07 Aug 2020 06:14:58 -0700 (PDT)
MIME-Version: 1.0
References: <20200805042938.2961494-1-davidgow@google.com>
In-Reply-To: <20200805042938.2961494-1-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Aug 2020 15:14:46 +0200
Message-ID: <CAAeHK+wPt46879AnV3n3d7+JZqkv2Vo652OPBAjHcuyru56h9w@mail.gmail.com>
Subject: Re: [PATCH v11 0/6] KASAN-KUnit Integration
To: David Gow <davidgow@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Shuah Khan <shuah@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JGA6dj+D;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
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

On Wed, Aug 5, 2020 at 6:29 AM David Gow <davidgow@google.com> wrote:
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
>  - This is included in the KUnit 5.9-rci pull request[8]
>
> I'd _really_ like to get this into 5.9 if possible: we also have some
> other changes which depend on some things here.

Found a small issue in patch #3, but otherwise:

Tested-by: Andrey Konovalov <andreyknvl@google.com>

for the series.

The patches apply cleanly on top of the latest linux-next/akpm branch.

There are some tests that fail for tag-based mode, but those are
unrelated to this series, and require KASAN improvements.

>
> Changes from v10:
>  - Fixed some whitespace issues in patch 2.
>  - Split out the renaming of the KUnit test suite into a separate patch.
>
> Changes from v9:
>  - Rebased on top of linux-next (20200731) + kselftest/kunit and [7]
>  - Note that the kasan_rcu_uaf test has not been ported to KUnit, and
>    remains in test_kasan_module. This is because:
>    (a) KUnit's expect failure will not check if the RCU stacktraces
>        show.
>    (b) KUnit is unable to link the failure to the test, as it occurs in
>        an RCU callback.
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
> [7] https://lkml.org/lkml/2020/7/31/571
> [8] https://lore.kernel.org/linux-kselftest/8d43e88e-1356-cd63-9152-209b81b16746@linuxfoundation.org/T/#u
>
>
> David Gow (2):
>   kasan: test: Make KASAN KUnit test comply with naming guidelines
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
>  lib/kasan_kunit.c                 | 770 +++++++++++++++++++++++++
>  lib/kunit/test.c                  |  13 +-
>  lib/test_kasan.c                  | 903 ------------------------------
>  lib/test_kasan_module.c           | 111 ++++
>  mm/kasan/report.c                 |  34 +-
>  11 files changed, 1028 insertions(+), 917 deletions(-)
>  create mode 100644 lib/kasan_kunit.c
>  delete mode 100644 lib/test_kasan.c
>  create mode 100644 lib/test_kasan_module.c
>
> --
> 2.28.0.163.g6104cc2f0b6-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwPt46879AnV3n3d7%2BJZqkv2Vo652OPBAjHcuyru56h9w%40mail.gmail.com.
