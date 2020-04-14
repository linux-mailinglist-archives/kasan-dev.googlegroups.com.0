Return-Path: <kasan-dev+bncBC6OLHHDVUOBBO6W2T2AKGQED55WWKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 25BAD1A7190
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 05:17:17 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id r141sf5319230vke.10
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 20:17:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586834236; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMgMKvKTwtjWxBM9HuxSJ+oz/KP52Jxr9JmwXGmrip6BWiQFiR3IPbkHxgsKznZ4aO
         ICeY3V3QSC5r9T8oj8IC35y6733YVH9FB03IoFeM/elSE9NksLY271i5J7tyWytaS3+p
         kyqqSI3lJmLJPH42w9XdBdq7Qcc9edQZAIHC2QbksSzCR87XAPeHq3kmimfblp+y0kkU
         1jNiKNvzNmp0EfJdDD1Z69Zn+MeeI+AYpBwNSk3LI1FmSFdxsoxo5FU747AGBOOUtWgo
         okH0OWLJCJx5hD0VERP9Qoupr9Jn68RNoN8hgVT8TtFM0Bw30bfpkIbRyuV3lVsNecp9
         1tUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=KC0DO7poVj8m+qugBZczsVRoYNMI+vKt+nl03oNtkoA=;
        b=Z/wN4SlqiyMUMntzTOlpGrODotD/hafm4LXSMW/skZVf3DDLVCzjK1O53FUWtwO9tK
         ylLdRhN1QsauWSh7BUZxt5jmJn0ZUHgec8P+QfFLbjrhOrFv2ZR3rR4KM75L/0guN6VS
         cOH3S0t9QUV6E/VsylTRUgLkmPmuObkUyrSR4ghCyMpk5g9Hso0BmY/3fXy2gOTR10aT
         AXKkKN9QWWzg36KhGsFgBaF8idLxzdkscmVhopxyP1Q/e4aYQw4lsLNCgbHWgZ0wiMj3
         3PxJz7YsbxMMdgPPuCChBW3Tu3BT5hQbn3yxOMsDEO8ZPnsjPg3EtTGm6aebZiLlUZW3
         6g8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uc1OBjTi;
       spf=pass (google.com: domain of 3oiuvxggkcd8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3OiuVXggKCd8EBWJEHPXHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KC0DO7poVj8m+qugBZczsVRoYNMI+vKt+nl03oNtkoA=;
        b=XEM0ebxnnI/XCr8a7tJabTbdXHK6tHPemrs7Gvivsml3Jgn0ZuKrRg0B87+su1hn2W
         2/n38TwKe73/ek2gdgHG74XTlmo/aWvAZgznlTdBL329o92LDN3nRW2xw/GVch3mOxlY
         L5J1MKlbJdKLP/5tmXAB/33c7aQCBC+sTZiEu3RziF7taXXvCQ9fWrDsr7nidDg0peua
         DG8wsVMITLj36vvD6UUY0rmmc3Bvrn5tcR2T1hMIgi8DIw+LirgJniTVIz/IY42tDB9t
         dxbhKhlnagTvlHZHSK7sUpi6StP527qxCIjq/g0Z4q8kTv38pJlVU2N1AifT8M4KqrBb
         aHoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KC0DO7poVj8m+qugBZczsVRoYNMI+vKt+nl03oNtkoA=;
        b=TzXjhB/WGZcE+v4CGKSHN/GBITo1F9/D3B0e3zkhHEEm8NhmmxoTebZfUGRZJjnnlv
         slfQGp1+9DmzXsgC5Cd4oX5NpXYCsM1nROl8FglGl/jtwfht9MDgbk1sor1RnEJGVLGm
         bdSLAHRdO2+uAdYTU3Jy5E1TUpZpIYNoejpQ/mXsq+SY9T4n5M61/xTj6SsmRWjSnrdJ
         KELHvIXhS56+Ob+ym97qVdCGGpqS67rFD3RoVV8phbDpCg09tnC6Upwf2kuQ+dC3Oada
         zf5tscR9NaUJdHlR1IbEb9CHulBrV6HosUbOMz1jVCjww1Ut5JKFiXPP/kj8x2EKlin0
         bSmw==
X-Gm-Message-State: AGi0PuYm9clItZ76CEjrt2xWlQ8bHq0Bqjh9ipmlXwmI2oyUTxkxkOzL
	Bdgr5bTblEfHHVUM2UR8T9A=
X-Google-Smtp-Source: APiQypJV3sEdk9cymn2LI5BBjOAHvs+BNJUctxyEDWoMVAmajyOTZVwth+rYGD264/QN5cMhLeowJA==
X-Received: by 2002:a67:6c4:: with SMTP id 187mr6354197vsg.54.1586834235955;
        Mon, 13 Apr 2020 20:17:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:66c5:: with SMTP id a188ls236413vsc.5.gmail; Mon, 13 Apr
 2020 20:17:15 -0700 (PDT)
X-Received: by 2002:a67:f90e:: with SMTP id t14mr14963489vsq.27.1586834235505;
        Mon, 13 Apr 2020 20:17:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586834235; cv=none;
        d=google.com; s=arc-20160816;
        b=ZtbrFMY6uQ2xW1PxdEDK/VDexzAA4baXRX5yTexWlGSlDeBObY0Wgtnf4w4wer2uFx
         YRRM3OogrxEo9se/Wv4fYFh/xQb5ScqzlaoWnQDJlI2M7l9ln7H6XrdfyTAwV2JZDJGF
         eZPkz0j49baE/2O4rDalawsbvqfkBOz1suvIfvvD58DWWDO3yzM887hZKIfWbpN4Gd02
         eeeW0+NN9t3mpDlaIbqgkTLtda99OypflgpPa4s7i017t235p0isr1pxYm9M+7FHNriJ
         dhVxPGTASbf+dWKlvDwIsnU8ArEmSoywdRsGmcV4Vy8lxPuCA9Sbwr2rI7FahrEoW+BR
         td1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=gxEoz/v6zI9kY9dLzPfoceYRowmrIoXtyev6zAIHHPw=;
        b=LevGENmpjS0lQV2Vm1KjKbbc9Sj4nic9Qm3KXWs0TrFG4bziX3MdxXrN1wWsZwm2uH
         BxvAdXijUQuWgpxTI2cYwdbw+HmynvIqyT/UDLuWi74oWQzFEbXeRfGkpl9N9QkUuVzr
         XVkSi0O8MSS4uxFz75ktduNr5zYsjN5t6WqEWah8D1IhMXGwJ1Q7Xwbo+x2XyKfb9uWj
         f71kRU/Gl7Vl8LOsAUt5Wh1XDrfvhg3HB8uu1J6nOoxO2hzOI/Lv/JSbw22fWsfnAcHr
         Moz8Uzj0h8W6G0PYZyvbPuibiFPMxn2ow/K61g8c+Sb/jsFGdHIE/Ngb3rTIMJAo3R5C
         iAlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uc1OBjTi;
       spf=pass (google.com: domain of 3oiuvxggkcd8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3OiuVXggKCd8EBWJEHPXHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id t191si770602vkt.0.2020.04.13.20.17.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Apr 2020 20:17:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oiuvxggkcd8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id w3so8763233plz.15
        for <kasan-dev@googlegroups.com>; Mon, 13 Apr 2020 20:17:15 -0700 (PDT)
X-Received: by 2002:a17:90b:19c9:: with SMTP id nm9mr827821pjb.86.1586834234588;
 Mon, 13 Apr 2020 20:17:14 -0700 (PDT)
Date: Mon, 13 Apr 2020 20:16:43 -0700
Message-Id: <20200414031647.124664-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.0.110.g2183baf09c-goog
Subject: [PATCH v5 0/4] KUnit-KASAN Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uc1OBjTi;       spf=pass
 (google.com: domain of 3oiuvxggkcd8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3OiuVXggKCd8EBWJEHPXHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--davidgow.bounces.google.com;
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

Depends on "[PATCH v3 kunit-next 0/2] kunit: extend kunit resources
API" patchset [1]


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
 - Due to [2] in kasan_strings, kasan_memchr, and
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


[1] https://lore.kernel.org/linux-kselftest/1585313122-26441-1-git-send-email-alan.maguire@oracle.com/T/#t
[2] https://bugzilla.kernel.org/show_bug.cgi?id=206337

Patricia Alfonso (4):
  Add KUnit Struct to Current Task
  KUnit: KASAN Integration
  KASAN: Port KASAN Tests to KUnit
  KASAN: Testing Documentation

 Documentation/dev-tools/kasan.rst |  70 ++++
 include/kunit/test.h              |   5 +
 include/linux/kasan.h             |   6 +
 include/linux/sched.h             |   4 +
 lib/Kconfig.kasan                 |  18 +-
 lib/Makefile                      |   3 +-
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 668 +++++++++++++-----------------
 lib/test_kasan_module.c           |  76 ++++
 mm/kasan/report.c                 |  34 +-
 10 files changed, 504 insertions(+), 393 deletions(-)
 create mode 100644 lib/test_kasan_module.c

-- 
2.26.0.110.g2183baf09c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200414031647.124664-1-davidgow%40google.com.
