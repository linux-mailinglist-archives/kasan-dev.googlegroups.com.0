Return-Path: <kasan-dev+bncBC6OLHHDVUOBBK5L5T3AKGQETPQQTXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8221D1F048A
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Jun 2020 06:03:56 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id w2sf7060049iom.13
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 21:03:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591416235; cv=pass;
        d=google.com; s=arc-20160816;
        b=R5SGH3q7TmWxj0TzIAJTE1HkIy9mAQByMoLoirUvgykQSi/5e6Vh68dUJ/lp6OITtv
         hhRyA3l0+pkVE0pKqpBda1qF+qtsRTA0PXaAjaFFRr1s7hERCJ49f7QJxvyD7Of2rKDp
         b5sNsg85pNz5YKBlp75XxOXLZiHeHL3+I0sEb3UCdQkA822wrFLetZwVuLf9JBASvOb4
         owNEtvSLF/b0Fm5W0rZMVbLHl8Nx7veI68+mab36TKxyG+jyIckkd8Ek0dmMsn/Buwuu
         /LHeAzppCpBowmnbPVtNm/LNoZPZPsFsyJMChE4VHsBNCCjkEmG2Jcfp8JCQu9d8EN7Y
         Qw9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ClYLtaB2xXfzUsH8to4NfF0yivydVXeL8hi6J+QEEO8=;
        b=PsZGndJVKn/9u380ObyCzAl8n0+VHDpl/ACyZTy6Pm+d4ZHySLGn2J21eP0HiyEcPW
         cpv3FxBbB03j56M1fTYliVhZ9ZDUkkBT6DWwQr+4oQN9EEHL5O/9QBKyCJzXGfzDyffO
         Yn+JC9ygFKbY2k1hH5WkHQ19sCOOHwYa4SjOnEfp4yOxe60LpzfgdenS2xcpImDQ2aKx
         +zr+GBoXtMv8HzVergYD2NNgDpeZ0I1btib2ICq7bm+t5REcX7fHqiZSf574Yp0JTYFK
         xtY1HzF4sXUivLhXZ+lV8ar5peTL2yC+NYIiviDY2mvOfPGl+I7U4lVFrR9CL3qH9Jo2
         LT5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qi0rYfZ2;
       spf=pass (google.com: domain of 3qhxbxggkct8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3qhXbXggKCT8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ClYLtaB2xXfzUsH8to4NfF0yivydVXeL8hi6J+QEEO8=;
        b=C2vI7Lpq/iHvPenGQeMQSpfr07tVG/u0V+6LlV89C8eDFXqvazDuQBgobFJo2pBXT7
         UAWG0lD3V3fqIeC1ycGRaa8gsJzLsYa+fyFJtyIYUkOeqRbgkV7TZ8r8ZTF3Xrlgyex4
         MgXe+DMif3hKVvswDvwSFaLbC5qgldCjVwHHPpu3gOSR4EhIHLlZ1gkY31BRFlvwxrdt
         5NsNpp4XlHjpEAjW6KgmTAeAQrrtDmtY1qIkOuv825dSg491X5fFr34NHLOl3KDYqw5e
         HvoJPVlgstPeBUDotf+Y67RVUAQEqDE9tM031o0Ovwp4MoZdXmxDES2UciQxiKKxcRgz
         pTOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ClYLtaB2xXfzUsH8to4NfF0yivydVXeL8hi6J+QEEO8=;
        b=niji/qfOE66dxrc26sxx+f2GQlmQns0/kGjprTqrUzze9io6zrqn+8IlvFvb+frsJW
         DRPXnNUdL7BEcK5NkY8HNTmpPcd4J27+ktX1pjMjKxRmC2H7o9bTtbVjJ0VhJvDFHtO/
         ngfZAiIYtlhx8BLpE9JGfAQes3UnSC6HrIW9hYndg7w6lnfmPipT3fWMivC3Ep/gvoes
         /Cj1kYrh2jYBXBLp8uppW2XSaTOCVSeOXynWKhzCdcYLRTY95ei9fQChzI1BMUm7d+f5
         IixAbJX/+Ved0rj31NtfIAMsQJFHSQpF3p5kmqS5Nqgxv/oREj9ETNPz/10eJaRrIb1+
         6f0w==
X-Gm-Message-State: AOAM5334IPB8P6rbvRCjNF3bLOrfy30oF11yXMhOXZzA1SGHrryTxslB
	egrpPWvbWrsWql2XVyJPKOo=
X-Google-Smtp-Source: ABdhPJxYvn2ZqxymW+QyPOESCW2NktbJiW+fGmnEt8X/x1D+HBuab9XjwRI289eMZrnBLdRfI48Zlw==
X-Received: by 2002:a05:6602:2c0a:: with SMTP id w10mr11427245iov.46.1591416235527;
        Fri, 05 Jun 2020 21:03:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:84c6:: with SMTP id y67ls3012295ilk.10.gmail; Fri, 05
 Jun 2020 21:03:55 -0700 (PDT)
X-Received: by 2002:a92:b644:: with SMTP id s65mr11788893ili.205.1591416235088;
        Fri, 05 Jun 2020 21:03:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591416235; cv=none;
        d=google.com; s=arc-20160816;
        b=Bcl/YNMmK4FV2M7t/dCndnpa6gBJkgLxe/Dill+Z6BNFlCZbUFsAxgdvitI1A15yQN
         df/xKWg9TAAr2ua2oSd6ndKXcg5wW8B7u8H6Hi4v095w6db+k7eFK8TYlGyioFoClibm
         4kq8CSfVuKQCiIFhTIQNGkjeT0jVKlLyaLdBmE4nGaBIbulFlk7+NEl3zOslcH/mvD13
         g1NamHPYAKeNmvo/hAqy1hczBpmxSjfidNLGo9oogeV3h8ajGm9/oaZuLmifvFs9I6+e
         cFLQaM9HtMwmsd9nuSC+Jt13ucIJ4+ZrU34bGX+QWZakER2jb/z5+CnDCCLPEZYY3gZg
         Trvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=lkHQ0AMN1NLC6Z6ECpqhjd9XH4I1l/DaQ7IG53sVopM=;
        b=bwsBWuht5kWuBsQfHmnom3S1HXIHId4E4Uwe7QUGzyeW2jf489yAO/QQ8sLjzJfY8U
         6VCMGB0SepKe4kDRggaXWSwbLIl/75IMw5eagyUM0g4OQTGhdIC4xwgV7/GEDtlQwgxE
         7nw2SWJjLZe7CudhqvuDQFZlXOpMciFurgOMB2IWGaF4D/TGnWh3awgV2Gq2WGuNy13e
         5LreGsb44i+bnX7c9/zS4w4/B5Zi14IxnA//9pO1dL0GeuCjH5J0YdUNSeqHVI3Ga7NS
         1tQhjN860yEu4/NvAW66f4SPHkK7bx5PvsyOb5KrkNMBarmv62OTJk7g+sUlOEYR0FM4
         eugQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qi0rYfZ2;
       spf=pass (google.com: domain of 3qhxbxggkct8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3qhXbXggKCT8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id k1si423034ilr.0.2020.06.05.21.03.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 21:03:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qhxbxggkct8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id o140so6631121yba.16
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 21:03:55 -0700 (PDT)
X-Received: by 2002:a25:328b:: with SMTP id y133mr21693800yby.468.1591416234543;
 Fri, 05 Jun 2020 21:03:54 -0700 (PDT)
Date: Fri,  5 Jun 2020 21:03:44 -0700
Message-Id: <20200606040349.246780-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH v8 0/5] KUnit-KASAN Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qi0rYfZ2;       spf=pass
 (google.com: domain of 3qhxbxggkct8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3qhXbXggKCT8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com;
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
- "Fix some incompatibilites between KASAN and FORTIFY_SOURCE" [2]
 - This is already upstream for 5.8[3,4]

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
 lib/Kconfig.kasan                 |  19 +-
 lib/Makefile                      |   3 +-
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 688 +++++++++++++-----------------
 lib/test_kasan_module.c           |  76 ++++
 mm/kasan/report.c                 |  34 +-
 10 files changed, 515 insertions(+), 403 deletions(-)
 create mode 100644 lib/test_kasan_module.c

-- 
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200606040349.246780-1-davidgow%40google.com.
