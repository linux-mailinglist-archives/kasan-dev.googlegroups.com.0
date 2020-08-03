Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD7VUD4QKGQEK4YE5PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E276823AA6D
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Aug 2020 18:25:52 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id t11sf14830205pfq.21
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Aug 2020 09:25:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596471951; cv=pass;
        d=google.com; s=arc-20160816;
        b=DPq+uLqD1Mi0aPS8pLiy8e/FtgwAYjh0qty14pw6eW8yJTsCiNuCdR2DSaQyctqRae
         qwjNHRSfMQiqzpJr85H6pekEWY1gUMCnDZJRLCTrN2ao0eZnR4xBp21Iv3OaxDfmbQY/
         i1lzfSuYi1u2RwaQ4jJsjscL7iKmI1mbEp0nr9Kmda7enyb8ga4XGbVT4FoEyaYMdX+p
         GvHARSMI7EBjkitdoouX7oG1cN8U4J0iBbL6RiXMszJWPoQA1oZP6jFgfnRDu0fnIv9J
         kwh5yRdrBo7iQX1fyXe/NwHmToXTy45o0VytqMJP9aV9P+1a/6qQ4AuwCACwBhaWTaTD
         5Htg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7AERy1jTjktpHnZ+AHdEYMzB6Ji0RHXH197oIq+Ci4A=;
        b=r2kIC78Mx8PmonCa7hkBP5llHQ9CrflYlcbzFscoLmH+YOWNQxVIiLNx3gwo7zhS/P
         q4rC7ZYd8Fje6QHPCXsmcQy/5AJwyj6z73oqqKU5pNpNOjGpDz9pv0QiCNHhdkCUo7+U
         ishStr6O2XJC9dDdyhCbxV1aBFitqILKeFIUIUNYk+3m+eVQLv8h0aPfGzCOny0AYQZ/
         Mfb9x2w4xXtapjSfeMACkNj8YcTQtePj8IzS+acEoJwfKx5E4BFce5nxu1SopGJfVL8S
         V3cJAdhPzACDCYQemivKb2H75E4qaeTOAZE3iy38BOFWNdmQpF9Q2QaYm2pq8ED2KFLH
         ABsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WJtI6scH;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7AERy1jTjktpHnZ+AHdEYMzB6Ji0RHXH197oIq+Ci4A=;
        b=BCKbkia/ysCf/n/OZfHoxXg5uaMUVRuuZgFn6ztLghthOCGtLxHTf6anwQ8Egaze1s
         /4f0vNZdY2JWfRZVZgD3Omp/EhcZxOItotv5d49vHXyNjkYL3YiR42dCC98SEkfY3MpB
         SzmCN4xPhVJTLsy1XrZ1X5S2/U+BzVLJ6wNmQZeWfCIFVK4FrtLBrn9swswKhMstTJ5d
         pUTVjeufKxdeNyxZ6h0w6WwEAw065FupXrGEKnV/ts5SDPseSIp+wV7W2e3CgIrjZZ6Z
         F3WCHWmdypbEZ6K9sb3CfRTdVahwXqwB3QDZx0Wptbk+w6vFnqPcYer4DgOgVnQ1d1vI
         vqkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7AERy1jTjktpHnZ+AHdEYMzB6Ji0RHXH197oIq+Ci4A=;
        b=fWr1SEm8wlt/ySF6uEkoTdPbqJyGnFaKj0cfi6460EeRRVmOscJ9rLkbsTwB6wplmV
         2W4bpUqPVnLcRjwI9PQvYQRSmCigYs4i9GjreEBX9/pYBoj3RtU1yFM5ZnbHRa6kbAU3
         RQ2WMYbl2gv8hW5i+U8dYp45TP6DVxPf8L2Mah56zk2AKyzGUwM3eC/rmveBtLYX/hep
         scVDsECiCGfPxSP8F8kMe9r1hAak8cxhFkQ/oXwpfRApKA4iTL2s/GMHhN2GKQVyHugP
         8zSLzp+Xf7YGDgRJqjl6dM2Te0wG5Wj83WjipK10LoO54eiD6fq3ueTRMVhUTFXAoKx8
         pCjQ==
X-Gm-Message-State: AOAM533uPx1pNREjWMORu812b8tqPoD4C6TNO8mX4PeFjc+NZ/cSvppX
	Z40mfzOzzZUO+1EsTJVSxsI=
X-Google-Smtp-Source: ABdhPJwx8jgAzmFkyOU9trpnw7ejjkv/5hRakFjUU/9RwlMgkZqDtEhbhWaBAZgIobCdObtVFdS/6A==
X-Received: by 2002:a63:3587:: with SMTP id c129mr16097786pga.322.1596471951323;
        Mon, 03 Aug 2020 09:25:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7593:: with SMTP id q141ls5762133pfc.0.gmail; Mon, 03
 Aug 2020 09:25:50 -0700 (PDT)
X-Received: by 2002:a63:ce41:: with SMTP id r1mr16008910pgi.203.1596471950632;
        Mon, 03 Aug 2020 09:25:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596471950; cv=none;
        d=google.com; s=arc-20160816;
        b=WtNRGOoz40ag/v/e48QVG0T5Z5Bp3kMUt2j9yPaO3QT4qcspv4tbY7eqD9U8QJZvBj
         ck7tJcfl4e4+cWRwbJZpo/HVUXHKnQmUohrmdQv0hfoZVjxhdkvSbMmFx9mA7GyR5wmH
         E3BAW+bIbo2zcrrbX5ugYNOpCn5qVmi5W3RBvCgyPfdCoDM8308uyUTRuuEGBfHaSxfQ
         5Rb/ZuSkQcJ+oLtjLQUxwak5V6qTefNZ9zcr/kwUOXRHdAANQKFXKa+lqqOUJFgpfeNO
         x1QToMRMe8meU0o2CYnTttSn4lHQ/Ij8UcQ1fSuZSHQLNwUXoWUqJ8cxdtNRkAVw3Wzb
         nJAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IN89B/Ojkw/pvP1l4s5A6ia3yKGl9XfJ2ORu0fQjOxU=;
        b=g/rZ8WbOLBR+nxuQUnPxpvh3aT72bSaXwjKrDz1hGVG6YgEM5Hultj3/atW8JPDIQN
         134L657OeNdFLibF7Kf/ImdI5eZqf31K0nZwMQMonWlDmRGAvVSoReyq091uBZmZ1AqG
         xJyPKUlAxayYsmqqH4d2dEHCc9nvwYVFN9HejQGazHUFtzTzB+N5cwshIiSRbBEU+o0G
         E13o6bJWO4qReW2kBu1ZgIWU46EvO/vy4pTWtDpIQtUH7Y/82m0ONoIF/eOId6v+6pJe
         /TuBfIiHhTw7mTCaIjSRSvf+JP330N+LeOh7utZrmSz5io2YST6jgUmBuOtD1zUoF8tX
         Nr5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WJtI6scH;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id k12si846283pls.1.2020.08.03.09.25.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Aug 2020 09:25:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id a79so2616016pfa.8
        for <kasan-dev@googlegroups.com>; Mon, 03 Aug 2020 09:25:50 -0700 (PDT)
X-Received: by 2002:aa7:97a3:: with SMTP id d3mr16432430pfq.178.1596471949983;
 Mon, 03 Aug 2020 09:25:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com>
In-Reply-To: <20200801070924.1786166-1-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Aug 2020 18:25:38 +0200
Message-ID: <CAAeHK+wpt+Pko3pCBwO3Q=6Su7chVj+xhAGgHiVabbzC58rgDw@mail.gmail.com>
Subject: Re: [PATCH v10 0/5] KASAN-KUnit Integration
To: Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Shuah Khan <shuah@kernel.org>, David Gow <davidgow@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WJtI6scH;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Sat, Aug 1, 2020 at 9:09 AM David Gow <davidgow@google.com> wrote:
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

+Andew, could you PTAL at this patchset?

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwpt%2BPko3pCBwO3Q%3D6Su7chVj%2BxhAGgHiVabbzC58rgDw%40mail.gmail.com.
