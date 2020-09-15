Return-Path: <kasan-dev+bncBC6OLHHDVUOBB3XXQD5QKGQEDYJDMNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id BA45B269CB9
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 05:58:40 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id b1sf1289978pje.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 20:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600142319; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wb3lRLfcCIQRjWRW0Bf4bhe1m3dqiTLd1HgeO+CPe9S1HVyE4QRfmOgi+wPRnIB2Rl
         gqxIrmcI8CCocQY1u4YVRoyzB2WANN4Mtq7DGUVuqkPZUH528KfDqMvmTiSCqYp7gfL9
         WDZMHU/WasUj83hKtbItM52MObUgCJxfSVBW4FLKQG8HyaN2vMhmNRgbL98K1uK+BvkW
         AfxXMhtubsYtdUSKsL06sVsQPVQCbSMnlK7UFrxfFlgHFw+OVA/RQV9my6toNoVDYG9m
         JHVXZUfB5MQiqPMYmk81ofLDrb1yZfuk3UPO0ULSDUvjY4QxcngRMiKey4+5OtzO7mjt
         IlBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=I57Zt8kx9QJfKXt3iUiKYjfwdBPr4j+WNn7+NO0WrgM=;
        b=LY87ikmr6Ibyv2bkz+B/gZOGONSWhFkFgstLYcgEmNAUSNbOnWgoCXlAoLcUrIQrY3
         Mwiz6qDpt/mjrqZoHAIHfqQ3oLyaYf1JpqobErH2aOKU3LaqPuUnnnHgOpuAfOfuYpTt
         JYB/pgs/Y5sx2ViCtVpsczp3I4PmcwxiJ4YSJGFcWG2FsYnFlU934FtyGTuPKQ22izIG
         fDTS3cKmrcbOXTkrOVKMfXqakfS0hesWkxhxmpjBTCwbrfdtA707/mqF2Bv9aKB0pHEF
         nJfLX6NsEMWDPt+4lUnowlALz6+m+6sFQAQ7NR+dMVPaJDzQEKSZStncTULo9nplvzJx
         PiEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T7K2uPiW;
       spf=pass (google.com: domain of 37ttgxwgkceylidqloweowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37TtgXwgKCeYLIdQLOWeOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I57Zt8kx9QJfKXt3iUiKYjfwdBPr4j+WNn7+NO0WrgM=;
        b=rW9BRHrjOVuCaBgKtFIu9bPrRVbtj9xpZUGJGtlStAcPSNtrnQYHVYYHRk1wmv4mWh
         IjxZlLfT9OoZwxRRJjQYYEAhyVVl4puQLUE1CLfpANkh1LJNAE3bw3eiGw5+HotD7Oft
         p4jUWI3tcSlFNUo9aYnRIuyD9PWqbkilr+X2L/nu7qLmiPA8q7EokiIQPLwHZOSOgr12
         0G3zAiAAN/XfuLctkkyrj7Y1ND9c2v917mNa/iw+qOOuclt2m9j0DdIkgSnFMF5vzrlH
         y0kpkJm5zAkewT9417fD8Cq7mvwLHWrvOKfWjGQkWYUX8puNgyGf2obT2u2bQgKXRhVR
         RENQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I57Zt8kx9QJfKXt3iUiKYjfwdBPr4j+WNn7+NO0WrgM=;
        b=pau4zhW4iNR3aCN/4v6LeEBjJHBN0tmiwkRXB/9Jlen2Ajatjyjk2LGYjjInqMx1OJ
         4JcXcrH2lqHzlfxwIFzj2Brhajn6Fo8QkKfNzBBtGVPE8v8DBHLClJ2Cf8z+IABkSDHl
         OrKFIJZ3TdEtOWG6ZnaIk/rEap8DHhNdmrFCkPyfMoUFlOPMD/eJQsHFQoniN//8EllL
         CLV5t63tWAnUbmILqqgq+mMSXQ0saN1thstRZ0ndIBwJU0FlT9/z6C6GOrTRIo0qqCth
         5dpHrkIgOZPheEAViVmeuo+79cipu6WulBRf2rWxiv5Dd7slb39JoWLFVa5Tkjw0ygxT
         7FYw==
X-Gm-Message-State: AOAM533qR0sal7bf5AihUVhD3ouAUIGisJ2Phf1X9VRK9mI6xVW+AuOo
	DNrT3o6zZgjjvMQ/1mdK3mw=
X-Google-Smtp-Source: ABdhPJxeLP9gxdSdqo4Xlz5rwQoGkdpAsX6Vg/LJkSOZL7XxzQsMkrzydGWO373G+T6FvxBDWhPc0w==
X-Received: by 2002:a17:90b:1487:: with SMTP id js7mr2284761pjb.187.1600142318986;
        Mon, 14 Sep 2020 20:58:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:368a:: with SMTP id d132ls2601706pga.6.gmail; Mon, 14
 Sep 2020 20:58:38 -0700 (PDT)
X-Received: by 2002:a63:fd11:: with SMTP id d17mr6682376pgh.213.1600142318294;
        Mon, 14 Sep 2020 20:58:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600142318; cv=none;
        d=google.com; s=arc-20160816;
        b=NOYM08jjrynbhEvPU15Qy7rLK+UCx/LWzSM/wwWQjUFxqCQo8+qOQnj8LBwBCDha0e
         vQyfdiLj5/RM1x4dMVlXpVYSWIekEy6hCdNv+aVqrCy5UoqLoQj+5SJ9+Ku/fpGRw1+A
         ZQp9jKPya1wMhyJ+uIyQPO/YZmoYsyLxCmIQOPzJ06xNP+gG0DD0VjLsg8JefYpyvDG7
         irQKw0zDl/E0zAJkxkJUnAAL6ttf6lPxbzKeWJDbGbYxva7ZCk8gHFLwu91F3q/0KviN
         txEpnql3bVUqUTPTnU3cTyOqUetmaVVnnjmtSN2NVWNoj8O38Ll7U0AdsXS4Dl8AkNq8
         o/5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=t2EDhHpbxYvpooWPkPafyfVXhtngpgFAoszDJvgbFKI=;
        b=WU8VH9RyVfDJh+O8iJkL81IlH43kPwf80cuUl6wJQ+8HILNjWtNYHsmhIHly2sGPn4
         sIfrVeHI0iW5XhqVc0VKj0oKV/idQ5zHnrnFtJN5g/zzY4otDQ4yjcmHRAlVmzhrOaCV
         P+cYIS6tPU30uNb0SZ4WeWD48nLI5NCzJcATk7BjxsV7PE7dO6CNgWgO/S4ivWMrfgBG
         4WpUlBxeg7bR9dupYisA0tEgB+yMbshtvkBTAHE9Khx0I5HEYTe0lzg84uLvIBB2JVIs
         Ogi3oBZjFgfcb0Als8SnEoE7FkmawFrW0pVoWH3N1DYRv4z58Brsafm6zVDSFI4GuKQg
         hKRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T7K2uPiW;
       spf=pass (google.com: domain of 37ttgxwgkceylidqloweowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37TtgXwgKCeYLIdQLOWeOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id b9si770884plx.0.2020.09.14.20.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 20:58:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37ttgxwgkceylidqloweowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id c5so1837249qtd.12
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 20:58:38 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:a05:6214:1712:: with SMTP id
 db18mr15740565qvb.4.1600142317345; Mon, 14 Sep 2020 20:58:37 -0700 (PDT)
Date: Mon, 14 Sep 2020 20:58:23 -0700
Message-Id: <20200915035828.570483-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v14 0/5] KASAN-KUnit Integration
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
 header.i=@google.com header.s=20161025 header.b=T7K2uPiW;       spf=pass
 (google.com: domain of 37ttgxwgkceylidqloweowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37TtgXwgKCeYLIdQLOWeOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--davidgow.bounces.google.com;
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

The dependencies for this patchset are all present in 5.9-rc1+.

Changes from v13:
 - Fix some compile warnings in test_kasan_module[9]

Changes from v12:
 - Rebased on top of mainline (ab29a807)
 - Updated to match latest KUnit guidelines (no longer rename the test)
 - Fix some small issues with the documentation to match the correct
   test name and mention the module name.

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
[9] https://www.spinics.net/lists/kernel/msg3660451.html


David Gow (1):
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
 lib/Makefile                      |   4 +-
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 728 ++++++++++++------------------
 lib/test_kasan_module.c           | 111 +++++
 mm/kasan/report.c                 |  34 +-
 10 files changed, 554 insertions(+), 443 deletions(-)
 create mode 100644 lib/test_kasan_module.c

-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915035828.570483-1-davidgow%40google.com.
