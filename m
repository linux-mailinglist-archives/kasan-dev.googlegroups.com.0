Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGFZZ74QKGQEB4NIYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id ECED5242925
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 14:12:09 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id z8sf300321vsj.15
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 05:12:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597234329; cv=pass;
        d=google.com; s=arc-20160816;
        b=EyYMAekfdeYru8GfWRD34KKeap3cMwbBkYE3sAK84uTTtvCnLuKDqjfy4RUNQKzrpO
         v7jWBPZJgm4dcYoaClmNskoPGJuSBpCG9ShKqycK3yPXZqkSLIetqGxMwsV7A+tMsMa5
         cYENP3aE8WxzZYm2nZHARiLhdWP/34eAlo7zJuxElVTP52HofSUbwtsisCw4LvLtMhCu
         J4omYaCCLJeUpqXfnaL41emXdt/lErQjFFx/Yzl1y2v9Fetg5DpNzMehb5ukZvjJLiF/
         NkmU4wCR0k9AbBmKS6EDuNShCq4o9UiOlJsy82lFwG/1QYJahznh+l3abzNDHOeRoSWZ
         dQRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Bh0iW0IIoYOZ7LGkQ8Y0z3Yq3bhX6QV52PMWHrZG7nM=;
        b=cPNBFHxcNlL1E7Y7hzUQsaJx6UUUASn7dRAgw6nrO91cNj3sFhWHgdDL6HcNIQLZ7X
         9kzGWJv3SVHzfr/kMugy4Pcq1xmhr4izXXNARBSfcSyvCUlZHwXUJDkw35S9dR+hYaZy
         tU6nJQSJmwOfBCPnX4nj9xmvabQCtY5pk2tI5IotB37Z51meart3c+cbZgKYhZVeKd/K
         GuLKMhup9pDNFialF56s+Mqs+VyvW0JtAUJ/4jjaVNmrOfWirWMFDwm/V91U7n61Ry1h
         jfEcpLNULGXMtIgym4ChU1NX7lmW3tR/UQstaNwEdiedZ0PPsk3Vhi5Ch0rwtrELHUHy
         ZMKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fbJ+Kqwr;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bh0iW0IIoYOZ7LGkQ8Y0z3Yq3bhX6QV52PMWHrZG7nM=;
        b=eg8ymp2qdlB/y76FA7xI+PzA3vkeEZnryKmKiFZrbFIkL9uk1/ofgZ+nGh2zlEnPYH
         DHhZZRAoT2xZu0KVkQoi5FYfQE6QF96APNkEXGAwPNCAqv2RN0Iwf5vaA27H/F5J7mQr
         CZNgBRbEGoOWFgyNW1qotbbJ+ky7MXTM0OF8cGUPotBZhcmqeSvbZdnWGcSt711A4jid
         XEi9So+i7Hzhu5ncBoWgyzlnm1m87qqgvvZpvPLVVwYF0azQJZsSuE6HjfyBnvLKVskj
         EC17BICcaAOcOEdzMjXt0ngRsogyv3HolMiBoeU1oNUbMCvnensb9M9iNUbngIThx2MU
         /mgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bh0iW0IIoYOZ7LGkQ8Y0z3Yq3bhX6QV52PMWHrZG7nM=;
        b=olikilAqxf/EOU/GI4rhVtDon43+ki16NFdx+dOquwGhqftZFLUHMViGxHkpcnlRCo
         dh5xwJTh95HuTyru8QHiCz2xn8bGmsF9QIZ1kSLZd9WyT8ktcyuQuwvx90jrk8reEZg8
         xzu7fVco3GD0XrM3pNgIiA3zfcTLbhPZRagibjVBQdAHcG4hAuYWl6KR7JaFV7uEbXC0
         gDjp8nJ+7CL+O7lT/D1kgF0aLQoaawas/Xd4EAN4n+QKIrWpYJaoo0jGxTEP5oa1qW0j
         5OV+1aXXQTjF2S/9g9pCxeXUdcftbCniwl6Rc/leBU3yISu0327q9yjp7Y1gs8ScF2/V
         tTzQ==
X-Gm-Message-State: AOAM533FSXod8NEd8G9aMIv2Cq4MOkGwIA/5Q5YvCigmEs3+D6LUtXtg
	/9yEnV60GYkAAcnhqK1T50I=
X-Google-Smtp-Source: ABdhPJwoLqhGdkJK7DepWW7uTDIHHlTg9OrfdrKdnY2U7GH+H+/vQyAounNcJjxI0WyOOc/vHDspQQ==
X-Received: by 2002:ac5:c925:: with SMTP id u5mr27992134vkl.68.1597234328906;
        Wed, 12 Aug 2020 05:12:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5404:: with SMTP id n4ls114195uaa.8.gmail; Wed, 12 Aug
 2020 05:12:08 -0700 (PDT)
X-Received: by 2002:a9f:24d7:: with SMTP id 81mr27798297uar.68.1597234328407;
        Wed, 12 Aug 2020 05:12:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597234328; cv=none;
        d=google.com; s=arc-20160816;
        b=Fnlq8M0fhZV9RyrgShn2V53CIfEub+uSxsodq66bkD1mDIP2Aw6kCPDOKD0arW5Fw7
         9wZVfzwwskl1PGDd7zLmq1UiS3YMf6GGU7n24JdGcA6Znj9UXGhFX1ywycJtEF3sEii3
         t0jgOzV7E4JPSn6Ee6PXj3TiJZab/L478AM87FmEseIlGFXv0vwqpX8lAv67wXQV5edD
         QhcuWAHez9m85DCvpgBP0VQntqXM/YrzivGayg9TMkc8gKsq3d6IKhNne6+x10MGKCPN
         SRecOVCwHs2hzQM5wcMszMjZeGl8xUu9r3l0Rtsz9sBFnEf35bj3Y0JrNLjR+aYgK0FR
         34HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VBv5/z2Ow9pFbDPFGGYjiRaQjvVika1ng+xJ7HOOxEU=;
        b=MMBbiubxdJC1PYj2nZLZjKNVisudE6lY3IPvrO9BqZOkOtmWjCVvjX2R0KaCHVqNIc
         tV8w60wtjxNmHO9RVhvRsv91U6bRlNzVQF2uQu7rO4o3x02NaOrCYlzY+Shg+6TH5lKx
         KdPqoTu61yRDZQRgStqJYPmi+Iq8ToRW3C1cofzS2va9YHiC04sKBtft3bZTvsiTL5Sc
         Q0c0JpTx+bBdHeY20a+J906k0HYxthXBI9Abv473fbDsD0iK00oh4YoBLoZDzx7q4SdW
         WPLFFVk9IRGtiDzbLC7NyACyz2jHJ+hIt1DwPWuhmNICNR0fT6DgLeSyRpUI3tO8tzH6
         Wnlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fbJ+Kqwr;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id t72si160082vkd.5.2020.08.12.05.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Aug 2020 05:12:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id f5so1019656plr.9
        for <kasan-dev@googlegroups.com>; Wed, 12 Aug 2020 05:12:08 -0700 (PDT)
X-Received: by 2002:a17:902:9009:: with SMTP id a9mr4663327plp.252.1597234327266;
 Wed, 12 Aug 2020 05:12:07 -0700 (PDT)
MIME-Version: 1.0
References: <20200811053914.652710-1-davidgow@google.com>
In-Reply-To: <20200811053914.652710-1-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Aug 2020 14:11:56 +0200
Message-ID: <CAAeHK+zhA+ifqdOMc9AJ3Y_70CAsKbBX=wX0mnvBscz=Ts0uHQ@mail.gmail.com>
Subject: Re: [PATCH v12 0/6] KASAN-KUnit Integration
To: Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Shuah Khan <shuah@kernel.org>, David Gow <davidgow@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fbJ+Kqwr;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643
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

On Tue, Aug 11, 2020 at 7:39 AM David Gow <davidgow@google.com> wrote:
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
> Sorry for spamming you all with all these revisions.
> I'd _really_ like to get this into 5.9 if possible: we also have some
> other changes which depend on some things here.

Hi Andrew,

Could you PTAL, and consider sending this upstream for 5.9?

Thanks!

>
> Changes from v11:
>  - Rebased on top of latest -next (20200810)
>  - Fixed a redundant memchr() call in kasan_memchr()
>  - Added Andrey's "Tested-by" to everything.
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
>  lib/kasan_kunit.c                 | 769 +++++++++++++++++++++++++
>  lib/kunit/test.c                  |  13 +-
>  lib/test_kasan.c                  | 903 ------------------------------
>  lib/test_kasan_module.c           | 111 ++++
>  mm/kasan/report.c                 |  34 +-
>  11 files changed, 1027 insertions(+), 917 deletions(-)
>  create mode 100644 lib/kasan_kunit.c
>  delete mode 100644 lib/test_kasan.c
>  create mode 100644 lib/test_kasan_module.c
>
> --
> 2.28.0.236.gb10cc79966-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzhA%2BifqdOMc9AJ3Y_70CAsKbBX%3DwX0mnvBscz%3DTs0uHQ%40mail.gmail.com.
