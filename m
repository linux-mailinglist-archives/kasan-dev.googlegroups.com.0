Return-Path: <kasan-dev+bncBC6OLHHDVUOBBTU7475AKGQEWUCZ2FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E0C4B263DE4
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 09:03:43 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id b109sf579691otc.16
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 00:03:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599721422; cv=pass;
        d=google.com; s=arc-20160816;
        b=RWVl7BvvH+fSaZfAZIjXRGwP+5jtuMnocM7ggeND+q19Ba2lFSArcRtUhAg/lnPpNk
         jS8MmwC3g40PJkB+KJtjeSRhrMn3VeO17h8ZHswDgYaXZ8GTOLoT7HJ71ogJNDtga3vL
         cStyRYZP8DqtJbUW/JSEHtEYKW30+c8/yzUuJQzttdN/qloiG7IKr7rPKr0d0Yl7wcSP
         P+rH5zlEO5arJE8eJt1vX4YuwYORcjOi7mt7j4PqPTtGd1QVA0qnpgkO1BUbRlNuM6m7
         RJl7qnvkQk1VHgeVHZO/TIz20ODtiWEyMHrJFNbY5joqV2tq/EZX2HCsBc05KjX0TbVo
         znpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=jmrWOHaYZTXP3WTB1VO1kPEtCPFxNiCJBh6pqc6hK7I=;
        b=WNsoy2XLzf/TvOJpRMPbGPQhXeDieXNsKf8buRj3IXI394o+SuJEwI6xQ30rBneTkX
         T3KY4Dse67yzEuQv7QTI4URtn3dfGwkwevyiZdE8BqbeDzjVOefANmjxPP6m6nZNQEvK
         tkCLTWXaPX6S971GHrut2MHqyE6CIvd1UrcaXVHydF9tE7YfGD3d+oIVjCZUk0XdZmjO
         T4eTayxucsl7z1rBmPGmssMLvuGHNun+dccfv+UDkeU+l0NVqcqJVIRwpkBwZbTg2uBM
         k3e4u70besFcamreCsQqBjRUFGuHAIdqzxzLWqtB+HXI6+jIfCXzwn56qbN5wcRnysYI
         fKWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="RnP/Bqkg";
       spf=pass (google.com: domain of 3zc9zxwgkcdq30l836em6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3zc9ZXwgKCdQ30L836EM6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jmrWOHaYZTXP3WTB1VO1kPEtCPFxNiCJBh6pqc6hK7I=;
        b=SZXzQBl1hQvLRImJkqAKV6/fKe8RzDwlEWYQIl8cmcdS6TeuFpFthIcz3TOxiPhFRS
         UGsJOJV8qcsxGXsAZIvYM418oK1WHWSlyH0HZrPWJyDFD3KDMOoWWyGXb4JlkLXAb5vj
         gmyHeRqsqroQR+86+KF5FV+xrLRpegTQ9DYfvj7yqoomYXt31VGnyowKx9F9dqvjyzR1
         5byP9yVmRbs8kRYur/93O7pjytzHyu+tgmPDIjc21GULOTPro33UNV3B/hvk1T7tFtUd
         vlrrOnYn8XRcDIHZ6Pd5Xwk1YsHQB+HAizw39tQ/5AINFW6yzcfzukDSOfv93yJe/ut7
         6gGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jmrWOHaYZTXP3WTB1VO1kPEtCPFxNiCJBh6pqc6hK7I=;
        b=dcRFDGbYrwC+uxQPHAabVbJOI3lhylWYXjM9ciTjHSRjEIZIrS7/ryryyN1MhcBePx
         DTsV+kxIuSzvUS1uE5NSqDf3tWMYEU/4hd+JJOF2y5P+6LoHv2+5cLOqRmfLOInLYzGQ
         1SaK44v36t8WlGcro64V4iZu/taEbMHxqscS2O0+k8yS9lfZg3iCnaw5tbJ5U5WA6cPO
         I/rjGh2Kn1INQErJ57aBuI2yg2C2/cQiol4MK5wvqs8w6pyNkjMeyveyjwZ0nbR+RQ9y
         jUdDSXKTBKDDOdBw6Ay3C6NxMeoT9xkEHTe7mxCwwQyGF/DgQncamMnoYlM1GnH0WvvP
         PRuw==
X-Gm-Message-State: AOAM533stfQoL0r0qJKbeSLn/XM7dfBuhg69EqYoUtJTXeVcDgPvBSHe
	tULG9omaawcixWp2UlLWA7w=
X-Google-Smtp-Source: ABdhPJw/zhYmGTzFb9hp9B7ai9TNFv9pL39oIR8a4i40MsTwG7lcysFYsv27HdB3lsKHBikHBhji1g==
X-Received: by 2002:a9d:14c:: with SMTP id 70mr3182468otu.369.1599721422514;
        Thu, 10 Sep 2020 00:03:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:312:: with SMTP id l18ls307885ooe.3.gmail; Thu, 10
 Sep 2020 00:03:42 -0700 (PDT)
X-Received: by 2002:a4a:3516:: with SMTP id l22mr3441918ooa.6.1599721422008;
        Thu, 10 Sep 2020 00:03:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599721422; cv=none;
        d=google.com; s=arc-20160816;
        b=N+KHguoAT5OYc8lOOkEl3v6hizUb2NdO3cGXNpOl3IBZEQmRL4LHUBOZrlv97bC2+l
         gi4DzYVFdM8HkFEni/yOcciZBso1j5rnPi2gJhGSIG0lLf9sjQ4mZpmjhGMo6eXHKWDg
         IylKZdCnih96ij+ZJOPfw+cnFcoM9Re7x9MqAxLQKdVYXPVFAsLU6R5B4z4MpGhzOwW1
         GUc473FXv/Eyp9hX6LdBwVgppJc5d4LhGTG2D60TGP/K4ESSbygBHChUkf6L9voqBqc/
         EFqmRAWmqPtnyv2yrtYF9IW0R6CDkNZp9ygg2DpIYuAQJYrMuR1wT9N2CEf3cisAqu3v
         8U8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=cAxIDHIAu5nqfj/dy7DKq8nUC3kZ+oYozl0NSp+uVoc=;
        b=NHW9PrTLj9tEA2R76vINQbjU2umG071bQRbuYaN0A+uK8bu3BmY94XsE+owRM3VLhr
         n3aAn/lq3QfX1co2gGM2Ms2aIU2vjW4gU3EKSPXgAr2iex3Hl90V+vNU3er2eF8bwF/3
         e+lAscDASovPeaFI4pNSYhn9+ArbN9OARUcMRXKs93OgA7ZZMZFyp4tCrqb7AGOqwNqJ
         lGOjWEBLCwACdiPTGm//KvsBrVLk6LN/lx4f6/it53+PizoTjMDcVx9eLdKqlREIaHqS
         GGJnndLxnH5+VaKzCVEXntPffdWr9WvnxZs0mqPjgdQ78pcaiz5YA4bRO0xoVV7l4VOU
         stLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="RnP/Bqkg";
       spf=pass (google.com: domain of 3zc9zxwgkcdq30l836em6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3zc9ZXwgKCdQ30L836EM6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id t74si317491oot.1.2020.09.10.00.03.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 00:03:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zc9zxwgkcdq30l836em6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id l39so765411ybe.14
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 00:03:41 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:a25:2d1:: with SMTP id
 200mr1111668ybc.210.1599721421325; Thu, 10 Sep 2020 00:03:41 -0700 (PDT)
Date: Thu, 10 Sep 2020 00:03:25 -0700
Message-Id: <20200910070331.3358048-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH v13 0/5] KASAN-KUnit Integration
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
 header.i=@google.com header.s=20161025 header.b="RnP/Bqkg";       spf=pass
 (google.com: domain of 3zc9zxwgkcdq30l836em6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3zc9ZXwgKCdQ30L836EM6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--davidgow.bounces.google.com;
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
 lib/Makefile                      |   3 +-
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 728 ++++++++++++------------------
 lib/test_kasan_module.c           | 111 +++++
 mm/kasan/report.c                 |  34 +-
 10 files changed, 553 insertions(+), 443 deletions(-)
 create mode 100644 lib/test_kasan_module.c

-- 
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200910070331.3358048-1-davidgow%40google.com.
