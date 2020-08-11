Return-Path: <kasan-dev+bncBC6OLHHDVUOBBF66ZD4QKGQESOOKTXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 50720241601
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 07:39:37 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id mu14sf1506375pjb.7
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 22:39:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597124376; cv=pass;
        d=google.com; s=arc-20160816;
        b=cvKwsl4e/eHuGlp1qhPsStq2Udjjsqaqbht73c9S0mP7j66N35jFmLkfpSR/U5RJl/
         y7G5d/bPeECPGWIllZ85f7S8Zv80S6kazq/HFarUjG2nUxzaz28cWZgTcY70cNrVAsIW
         qhEqd9QRN6b52T+rO1rx3u67HGLEdYCLFwJwga4GK3cHnvM4q6JLrbyXjVUpN7wgvb9p
         Or8l70qtptYLy3pVhN89M0Aq8CyqW0boDjEaqMNY4S/8ksqSWrWx03CLdhnRl0TOb0SZ
         WhvRoa4mxucThbBuepSODUq4IZUy7ucmDVrBMFs4Pv+ks4FzuQXdF0FnEmfA71KQaz9v
         KubA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=otAzPMDXAERXCAz+1VsR63NwJZ0VHChZzE0OO+MtvdA=;
        b=TJRURGfL46R5yID1dHe9ChyX2aX4CrOZbNA9WiM/7+B6NUNQ+/F9znlJne3sOsLIE7
         OQtiKdk7tZmg+4vJOADY1VW/OtoTTPIhPQ72/iZn8TddyjRXaYfV8fTDlPQpHwEBrQnC
         +AQesc/LQONBxDGbmjrasWg1ZTrHeYtJwbjClHCPdHXAvEi6RIvlR+Sme3mlEjX/5dSm
         LtBgT1P4wh5KnxUl8POfdhyUxYhTsPLU0QRi5/5FSZYFXlaRMdhniYRAQPDCyMfyObUt
         Zd69YgxxBqYSHz55v257HB+fGSW6JnieHoD5jn9pXzM+pzPUZzh/WXaBcsRw7ydS+o63
         btmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BrmmSX27;
       spf=pass (google.com: domain of 3fi8yxwgkct0czuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Fi8yXwgKCT0cZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=otAzPMDXAERXCAz+1VsR63NwJZ0VHChZzE0OO+MtvdA=;
        b=OsVS56SM8RJzm0c+MQhCrhVCOxR1oTQC0738wQZwuBNKzS6keNJbyw2pCEwmo1ao3X
         BJSTAORISRa2EhFlUlTnPoiknWkRBHiRQuMmPhUHgAGaLaSzL0DKsZCiwRqsFRupCEYL
         3VM0c7NsuFOfe+2eqX/nMasgbaPTMngKXvR8GrdEridnyG+90reSeH+Fj4pHyD4JQ4Er
         d48mC67YJdt0aVKoDLmX9zpbKEpe6g/kl3hFbk9ofP4ewHx3a2nxicxJFudH6lUWVX7B
         1KoxzcAcJ5i2OEgGkP/mgrIsOVwqaE6gP3R+1mtifnyLRqdkt2dXruriAZIH9/GeS7sw
         keuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=otAzPMDXAERXCAz+1VsR63NwJZ0VHChZzE0OO+MtvdA=;
        b=pwE/PinZeu4QInRklJ6Bi2NvYMqAAhXs/Tl2OSq186bPpXMHGNCgF/iVjy8DfIV7TU
         tuwb2vR0v2qWpaCSaNW5zKTuFk/Y2hozpz06P8HpQMOZJcALctqqQZdOMuiQ3q29h1pH
         sPPLV/QwUdp80IdMt3CxPqhsakz3Bv4NusqqSJQNeejm2Qr6mONMIj9HYwtyjsbekM7V
         d3x/CRW660/+NhojXTtNQbwJu3Z3Q1WZUugZZc06hbY2D2cNtUJweSfUpEDjZ71Z2hqx
         twUIHu1NaAgVJFg0zoGazEhhZEWOWaLHBYgPVfZWUP/kWvPeGRpdCFuv6GX1w5qAUzp5
         s0Jg==
X-Gm-Message-State: AOAM5323u1s2qT/Fa/9PXyZK2DwoL+AWQfbyna3b9deovYHs4VR6Dt8E
	eb4ArOOB9E41vEl63i9K6KU=
X-Google-Smtp-Source: ABdhPJxGUlkE6/IwubOCkFtg5wFtmEU7EgwvTIn1tn7NclaM5M1nYOxltr0OH1DPLSy+1PqXoHoXWw==
X-Received: by 2002:a17:90a:3488:: with SMTP id p8mr3073456pjb.211.1597124375741;
        Mon, 10 Aug 2020 22:39:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c252:: with SMTP id 18ls7871872plg.3.gmail; Mon, 10
 Aug 2020 22:39:35 -0700 (PDT)
X-Received: by 2002:a17:90a:33e8:: with SMTP id n95mr2972837pjb.183.1597124375261;
        Mon, 10 Aug 2020 22:39:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597124375; cv=none;
        d=google.com; s=arc-20160816;
        b=sIS/M3PaQBZOB2f2MvHHn6qzDnWBgPyLBT7PBQWD6r8Z3SwBp3x5//7oBUz/+goKlq
         44ELCK0/APA9V5iu8O32PHIlY8IDfjZjW4smR6mpcBeGh0WImZi5It20ZT+oeeEpq2DD
         XUXIstCKelol3NiqIGC7JVUuv5PNgTOoTyqTvbawhU4rZykaQHMSncS1YE1x4shKX8FM
         pGYWtSvwTASWVCTD6NrgOljEQJ3Hx1HDYYF10jyudPMrEFxFYx19dd0FiqlwZvydlA33
         6GU4BE2VMukHpv3Nq0cImlvCIGzTMWlnnauxcZYqSMoDbho5guDcuUeUpvfAxLmkPQfC
         Sgdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=eI3dpvpZLLpmJ9nqCDi7T91G61DRoZz1t5zO7N7HKA8=;
        b=zjkFDmJk/xRpQRuHnV2dM5U0+UWrOuBp5cws+IYb4g+Cjd1wsd7B4K9eqV9OIsmp8j
         5CxUfSvOuZvx6pzzKOdVrKZk7pgCyW5cfBeu0CexWzxbLAi/8v7wF5g8zRjWzd2UAYoV
         rbC12CvnKxVK+Rv+bcCNpt4z4EFUZkG2ruzAPd1+lZ5YSuQdUgZFka9peE/Ln1b8MZjg
         Uy2Gn6akgXTf3041rWeHOR1SLzFTzIigybwPIB3tNloTz3PzJn2uzPEUPaF4dESeRafJ
         A0vdUsUsmxVCcIGiU78xHa6xNQE3XlSuhi8gA5Ky6xVg1xZMiuHa/iaPB+xtfvR6uqhB
         PkGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BrmmSX27;
       spf=pass (google.com: domain of 3fi8yxwgkct0czuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Fi8yXwgKCT0cZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id n2si1521637pfo.5.2020.08.10.22.39.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 22:39:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fi8yxwgkct0czuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id l13so9656154ybf.5
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 22:39:35 -0700 (PDT)
X-Received: by 2002:a25:de48:: with SMTP id v69mr15076735ybg.191.1597124374426;
 Mon, 10 Aug 2020 22:39:34 -0700 (PDT)
Date: Mon, 10 Aug 2020 22:39:09 -0700
Message-Id: <20200811053914.652710-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.236.gb10cc79966-goog
Subject: [PATCH v12 0/6] KASAN-KUnit Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BrmmSX27;       spf=pass
 (google.com: domain of 3fi8yxwgkct0czuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Fi8yXwgKCT0cZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

This patchset contains everything needed to integrate KASAN and KUnit.

KUnit will be able to:
(1) Fail tests when an unexpected KASAN error occurs
(2) Pass tests when an expected KASAN error occurs

Convert KASAN tests to KUnit with the exception of copy_user_test
because KUnit is unable to test those.

Add documentation on how to run the KASAN tests with KUnit and what to
expect when running these tests.

This patchset depends on:
- "kunit: extend kunit resources API" [1]
 - This is included in the KUnit 5.9-rci pull request[8]

Sorry for spamming you all with all these revisions.
I'd _really_ like to get this into 5.9 if possible: we also have some
other changes which depend on some things here.

Changes from v11:
 - Rebased on top of latest -next (20200810)
 - Fixed a redundant memchr() call in kasan_memchr()
 - Added Andrey's "Tested-by" to everything.

Changes from v10:
 - Fixed some whitespace issues in patch 2.
 - Split out the renaming of the KUnit test suite into a separate patch.

Changes from v9:
 - Rebased on top of linux-next (20200731) + kselftest/kunit and [7]
 - Note that the kasan_rcu_uaf test has not been ported to KUnit, and
   remains in test_kasan_module. This is because:
   (a) KUnit's expect failure will not check if the RCU stacktraces
       show.
   (b) KUnit is unable to link the failure to the test, as it occurs in
       an RCU callback.

Changes from v8:
 - Rebased on top of kselftest/kunit
 - (Which, with this patchset, should rebase cleanly on 5.8-rc7)
 - Renamed the KUnit test suite, config name to patch the proposed
   naming guidelines for KUnit tests[6]

Changes from v7:
 - Rebased on top of kselftest/kunit
 - Rebased on top of v4 of the kunit resources API[1]
 - Rebased on top of v4 of the FORTIFY_SOURCE fix[2,3,4]
 - Updated the Kconfig entry to support KUNIT_ALL_TESTS

Changes from v6:
 - Rebased on top of kselftest/kunit
 - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
   incompatibilites [2]
 - Removed a redundant report_enabled() check.
 - Fixed some places with out of date Kconfig names in the
   documentation.

Changes from v5:
 - Split out the panic_on_warn changes to a separate patch.
 - Fix documentation to fewer to the new Kconfig names.
 - Fix some changes which were in the wrong patch.
 - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)

Changes from v4:
 - KASAN no longer will panic on errors if both panic_on_warn and
   kasan_multishot are enabled.
 - As a result, the KASAN tests will no-longer disable panic_on_warn.
 - This also means panic_on_warn no-longer needs to be exported.
 - The use of temporary "kasan_data" variables has been cleaned up
   somewhat.
 - A potential refcount/resource leak should multiple KASAN errors
   appear during an assertion was fixed.
 - Some wording changes to the KASAN test Kconfig entries.

Changes from v3:
 - KUNIT_SET_KASAN_DATA and KUNIT_DO_EXPECT_KASAN_FAIL have been
 combined and included in KUNIT_DO_EXPECT_KASAN_FAIL() instead.
 - Reordered logic in kasan_update_kunit_status() in report.c to be
 easier to read.
 - Added comment to not use the name "kasan_data" for any kunit tests
 outside of KUNIT_EXPECT_KASAN_FAIL().

Changes since v2:
 - Due to Alan's changes in [1], KUnit can be built as a module.
 - The name of the tests that could not be run with KUnit has been
 changed to be more generic: test_kasan_module.
 - Documentation on how to run the new KASAN tests and what to expect
 when running them has been added.
 - Some variables and functions are now static.
 - Now save/restore panic_on_warn in a similar way to kasan_multi_shot
 and renamed the init/exit functions to be more generic to accommodate.
 - Due to [4] in kasan_strings, kasan_memchr, and
 kasan_memcmp will fail if CONFIG_AMD_MEM_ENCRYPT is enabled so return
 early and print message explaining this circumstance.
 - Changed preprocessor checks to C checks where applicable.

Changes since v1:
 - Make use of Alan Maguire's suggestion to use his patch that allows
   static resources for integration instead of adding a new attribute to
   the kunit struct
 - All KUNIT_EXPECT_KASAN_FAIL statements are local to each test
 - The definition of KUNIT_EXPECT_KASAN_FAIL is local to the
   test_kasan.c file since it seems this is the only place this will
   be used.
 - Integration relies on KUnit being builtin
 - copy_user_test has been separated into its own file since KUnit
   is unable to test these. This can be run as a module just as before,
   using CONFIG_TEST_KASAN_USER
 - The addition to the current task has been separated into its own
   patch as this is a significant enough change to be on its own.


[1] https://lore.kernel.org/linux-kselftest/CAFd5g46Uu_5TG89uOm0Dj5CMq+11cwjBnsd-k_CVy6bQUeU4Jw@mail.gmail.com/T/#t
[2] https://lore.kernel.org/linux-mm/20200424145521.8203-1-dja@axtens.net/
[3] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=adb72ae1915db28f934e9e02c18bfcea2f3ed3b7
[4] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=47227d27e2fcb01a9e8f5958d8997cf47a820afc
[5] https://bugzilla.kernel.org/show_bug.cgi?id=206337
[6] https://lore.kernel.org/linux-kselftest/20200620054944.167330-1-davidgow@google.com/
[7] https://lkml.org/lkml/2020/7/31/571
[8] https://lore.kernel.org/linux-kselftest/8d43e88e-1356-cd63-9152-209b81b16746@linuxfoundation.org/T/#u


David Gow (2):
  kasan: test: Make KASAN KUnit test comply with naming guidelines
  mm: kasan: Do not panic if both panic_on_warn and kasan_multishot set

Patricia Alfonso (4):
  Add KUnit Struct to Current Task
  KUnit: KASAN Integration
  KASAN: Port KASAN Tests to KUnit
  KASAN: Testing Documentation

 Documentation/dev-tools/kasan.rst |  70 +++
 include/kunit/test.h              |   5 +
 include/linux/kasan.h             |   6 +
 include/linux/sched.h             |   4 +
 lib/Kconfig.kasan                 |  22 +-
 lib/Makefile                      |   7 +-
 lib/kasan_kunit.c                 | 769 +++++++++++++++++++++++++
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 903 ------------------------------
 lib/test_kasan_module.c           | 111 ++++
 mm/kasan/report.c                 |  34 +-
 11 files changed, 1027 insertions(+), 917 deletions(-)
 create mode 100644 lib/kasan_kunit.c
 delete mode 100644 lib/test_kasan.c
 create mode 100644 lib/test_kasan_module.c

-- 
2.28.0.236.gb10cc79966-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200811053914.652710-1-davidgow%40google.com.
