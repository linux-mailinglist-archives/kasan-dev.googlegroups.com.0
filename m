Return-Path: <kasan-dev+bncBC6OLHHDVUOBBPHLVD4QKGQEM4ZVKEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C6CD23C48E
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 06:29:50 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id g12sf6783822vkl.22
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 21:29:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596601789; cv=pass;
        d=google.com; s=arc-20160816;
        b=WswuGV1rCMD1IqpUWTxTYqdvv03Otz5fww4CEx9AqzIGuK61L2ytBi/fiBOv9ZiAdf
         CsvJ+mKObhvJEwtDwBKR89wjGGCmT2u8iz4bVgYynCDTGcjqZ0rqCgvXAUCUAwwJCm3R
         oAxX8PnHHmJh/0v/GN9w0ZfW5oYsCCuRX9VzqsZJacsihVDlpH7+NU/7Wvz9BNO/CNvi
         /NHq2LYzFBJ40K99VSxdHBKX/Bs9MRahuJJolFGo8JUXn8eLIdqezinXhckMdSkxcbY8
         GgpOjHNfGobPJtXCMEaLTwtGVS++Od8V7imYGskPi1WmxXCpoHcnuohMhxeLE4eYuVNZ
         RQYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=6n6vnG4BALr++cJIrlZY7vQOrGq3l1fpwyOJuLdEDLg=;
        b=VO7ioaLt5OF+8mHwQ50AjUS90cmZ5V52M/nLRYvJJYkU5Sa0WrD7ix3F48AbFE2a02
         W27CsGi1C7RcOUtBDYgqMSzZ0/1ac3Pw8s649huXtV9NQvMIJHTwtE/KgEk7xdl98mYw
         QyRrvmcsNXj5nwIGv60jMlc5aMOjxhmRvVXsRHdBVxbq4Z9pd4FB3t73h6eaFKzZxxZu
         E6hFl+7V9BPeNOr7zCirx2wC8Ec4AamKfmvNf5jlW75Bvng1PkVlQ/oj+EyBEuziP2oi
         toHw4piBtgtAXJlE+/C+5lq025tbTkmb7+WkFCie+foCiI0nQR9Qlcsf++HsRHvvQG2n
         fPog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mMDKVECH;
       spf=pass (google.com: domain of 3uzuqxwgkcc4xuf2x08g08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3uzUqXwgKCc4xuF2x08G08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6n6vnG4BALr++cJIrlZY7vQOrGq3l1fpwyOJuLdEDLg=;
        b=mdpvNURBL5MXIzdwIrNj3RibSjtRZp8F/ScM9bYcvX0d/KZKYrNyoPJvin55AxS66k
         aHZu3+wFN1xrrRjlbIa3TlXK0gM4AdEKrUdmoqNmNVBmC+qemjHb2nax3RguP4F2ZfiB
         3Wvtp0zQ10DdioC5ONyjqMe/xW0PZwierYKxaDRY6NKqQ4/UXD0wBOdBc2UbFJIs37v8
         i3kHZUdMeORtsbOmSS8fXgLLBK5KomRPElGPTCCnHsr7CeELo8+2oYD4zC4LgPwU1pwE
         AJOLSMKcZC2aWNwCjghVV1zpAE6ZgEL5N9rD5LC0L2Y9XWR3EQVb9HjOix/YwFGl6Ui1
         Tw9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6n6vnG4BALr++cJIrlZY7vQOrGq3l1fpwyOJuLdEDLg=;
        b=Oy2K7uhCdvPkmRuJOXI6bZA5A01mLmZ+Vg1Kj0TJAlkZodFoIBmjXwdBL/r9vdz/2C
         GVbxXEQcHDWgtSDyQh0F9emsB2hYkNMigMDx26mooeaZOuZ9PCkBYwoFICgncWFStBTN
         3W2F00w3v+gfG4rvY8No2B2zbCAWeLnq4VzjAUEFohnSv0sTteTVzJzJNrJzEIPlr0Kc
         kFfxGg3beJ25n69glrH6vCYdbmqQU0vf7bbQdSNsrxzX2O3fknnWtrk6wOHEfQXHFZZ3
         1EVInIo2aLO7Aovvml/XUVsOE3YzzXV/0ULn7Iqo/uQ+pHl5M1NipGuv4TXeM+tJWA8z
         sPiQ==
X-Gm-Message-State: AOAM531jukH0lUzrLd5GWGHf577rUqNPDDYBfjlw4yFW/Iks8n9TZgeI
	LK/cOxPcyPrnkzhXWfFQlGU=
X-Google-Smtp-Source: ABdhPJw7phvwL0xxQMh176OWAkg3FKbOQQATysPh7APjwZ5pQhGnI6veTo+v52jE9jvZIpdgPPdEUQ==
X-Received: by 2002:a05:6122:2d1:: with SMTP id k17mr1098238vki.20.1596601788752;
        Tue, 04 Aug 2020 21:29:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f415:: with SMTP id p21ls94643vsn.7.gmail; Tue, 04 Aug
 2020 21:29:48 -0700 (PDT)
X-Received: by 2002:a67:f698:: with SMTP id n24mr700982vso.50.1596601788289;
        Tue, 04 Aug 2020 21:29:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596601788; cv=none;
        d=google.com; s=arc-20160816;
        b=GcW7kVZpQmdA23e/0Ox1PQ+iLsE+3K//MhYiL74xha38Q/pfmSD+opZPmFu2yakyxY
         XqtjxI3es9+mxO9PclguQmwU28WnV3EwZXeXKxSZra96AAaUjXornrF29A2J1P60TWym
         sewXxjXFWN/3cUuQZ9IQn+N6uszt9sr3sldrOMWcXXw2erU+WxFWWwawQcfspLTWksa6
         3P6cwtc8MSHAq24jRGlGcf012H/J+RTmaZwqCiH8sgR7HedGLvwuPTdB7xDQH6w5JsO+
         zyxl/Cs9Brkmg1XVPyCjkOOspDrHTeyDiv71ZixLfg6Mt4ziCTNXeg9V+Z/G96t9v5jj
         +yJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=NPvcc5+BxYjhobsJ3xVoRbExfcueCfGL3AJz9ZlSlfw=;
        b=i+ocFdhKhdBfe0KQ5fhPMFT7kj9n7JwPvqzIsRjK0LI7GkO9nBLWKIESSpZ89kkXpb
         T64pka8Y2NEj86GpAa/BvKH8AJM18wwiolRpD17skwVdkMLPLkXXyVFAtw6jInOkuL6L
         KUw7bVhQQBjky/cptSOZqHwPvdC3/O4fESbLgqLntjaIoI1GDyE3PO+EVi50KoymNrVJ
         gB0bwIpHkQYOMKmj4SC5nICMDMiMZxJWFm13UQpn/mxLKX7oHbNH77NPqBZoAAX3cIf7
         zLvTFcH+M9KNAsf6rwUr2j38f7vsYVZV9PFdDqWt1Zt7BQikmhWwzvkJoCaB+XOV52e/
         q5/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mMDKVECH;
       spf=pass (google.com: domain of 3uzuqxwgkcc4xuf2x08g08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3uzUqXwgKCc4xuF2x08G08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id k201si47137vka.4.2020.08.04.21.29.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 21:29:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uzuqxwgkcc4xuf2x08g08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id v65so7796979ybv.9
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 21:29:48 -0700 (PDT)
X-Received: by 2002:a25:4945:: with SMTP id w66mr2061459yba.285.1596601787731;
 Tue, 04 Aug 2020 21:29:47 -0700 (PDT)
Date: Tue,  4 Aug 2020 21:29:32 -0700
Message-Id: <20200805042938.2961494-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v11 0/6] KASAN-KUnit Integration
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
 header.i=@google.com header.s=20161025 header.b=mMDKVECH;       spf=pass
 (google.com: domain of 3uzuqxwgkcc4xuf2x08g08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3uzUqXwgKCc4xuF2x08G08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--davidgow.bounces.google.com;
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

I'd _really_ like to get this into 5.9 if possible: we also have some
other changes which depend on some things here.

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
 lib/kasan_kunit.c                 | 770 +++++++++++++++++++++++++
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 903 ------------------------------
 lib/test_kasan_module.c           | 111 ++++
 mm/kasan/report.c                 |  34 +-
 11 files changed, 1028 insertions(+), 917 deletions(-)
 create mode 100644 lib/kasan_kunit.c
 delete mode 100644 lib/test_kasan.c
 create mode 100644 lib/test_kasan_module.c

-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805042938.2961494-1-davidgow%40google.com.
