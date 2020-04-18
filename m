Return-Path: <kasan-dev+bncBC6OLHHDVUOBBF7D5H2AKGQEGMQ2OYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id EE5571AE988
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Apr 2020 05:18:48 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id l18sf4531568ilg.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 20:18:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587179927; cv=pass;
        d=google.com; s=arc-20160816;
        b=SZL8rleUS/GDm/O1fdGueubFEBb3E6BkiAXJriSFOp01Tmj+xsnZHh28LCFCGYvlZ9
         VxJJQLzowCihdT51R/nQAylQK1ioY6OQ18Vk5HPBIQefM4kADSXUR9Cvo/yzx0aYVBCS
         Y1wOMP/xBD3dYwr16haRUbBczr2kbxkEiCQoTuIocKbxYI4oq8wuM3ESUuzYU3iM9+EE
         qTB/VREylTk8aziFPqMIHw7zXngHgsz7bwwIaKanZIgWeoGYH3DmVq5RBF1vWPP9dtmP
         Uuq5yxV9AAn8G9vq25H5V/wOfEIO2qJWJeY97p/cDpLYbwVDhGb+1vQHXhc0RF4NV8JN
         KarA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=s1O0cbNfBmkxAOYa56EfvAZMsrZPrSXZ9eWftw9aAhw=;
        b=Q5sPuqoU/8rCjLGe0bL2bBWnV9TEOv8GxFO9Wf5elY5DZvotkxZsD03Xsb89UnnUCw
         YSaRfiZTkntDjKNGydIz3mZGC0RowigDSC2Wc1mYccspMfMgeqnjQuskw64zJfEJ6322
         fwNip0QTHu9M6wGAzpx1ub+jBIfv87/8UL4gRlaU46GjTjnsuDH3q6jnP3fo+sj/bhTa
         aMLboFY03aNYR1Ae6cqnIRrK5P8xItFdbFTGRbujWSiOGBRVsUccI5iRK4560qOuMQNe
         zHtNky0q1UwQZljBAhWmfUMeoff6yHzRLnPnt50Hc8dnWNE4Nm5UaXdvo/t1aa3q/S3p
         09SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BhjWeQqf;
       spf=pass (google.com: domain of 3lngaxggkcd0c9uhcfnvfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3lnGaXggKCd0C9UHCFNVFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=s1O0cbNfBmkxAOYa56EfvAZMsrZPrSXZ9eWftw9aAhw=;
        b=H/Dqf/rNh9rgiw+zNZFOa7z3PGSX7nlSdVivdorcbZQxpQ1fNdyb6iAa9PJGr6EcA7
         TVXxO4hKHSQFxPmqz4lZ4MC4Yoft2tNeopBaRdmUpcSsLdiaWSq9XTlNk+rmIoKRN+Wv
         U08K1MYDM7bfTBDW8TKS8rrcxQkdyxL+Rn24ACxDewT2qiDlzbbnjgnG9UsCVRflFFzO
         aee6sYilH0l90vc/WTdxoitQjVbfilOPp7vyc9+DuMlL3LDHtsFqnS5zWrBpFFe0C0pG
         f+57MWQ2Dt4CgZiitTtYds51oTW3LRsgtUVQpy5mktxLXr6DG9mtqFgs8EhL8N4Ck5Z+
         dcPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s1O0cbNfBmkxAOYa56EfvAZMsrZPrSXZ9eWftw9aAhw=;
        b=HHLCiwV+SdK07iQJuwtDQKFYYV7Mrs6I0a9Mt9uZ1/2rluccpGQ0WSIlQ961qZgO0Y
         vIH/bL3yNbI4/QqZQFnZj7D/YRRLvyXCKRY0MnDscoDC0emXiVQ4qCt6Zf2UO9JLbtSu
         XTQyIbqK8bhMJyv+uVTlYGCJ958SZ/t1wlnQFDqmVdMz0iw9aEOAA22R622iyqxDBc2Q
         w6BLxa6NbALmAULRvA9MgDtYsJoprtXOonjwfkAlARzrQiIBfLyobKSGeElRFNDf3jcN
         SP2jbx8tqqLsL9hDww9Y0O2XVhpf5O3ntvrgDabdKyJsQJdlqigLWBrHd5x7lwqXU2Fw
         jy1A==
X-Gm-Message-State: AGi0PuYZV7kFNBhlmJ0GemvlhWbrGS1YkwD0n4EralLhesX524KyyN40
	rbarUfVlcANZi590u/7UpYE=
X-Google-Smtp-Source: APiQypLNhQYbQvnfuRJ+FHiOBceo/sltLA+fDnOOqMAzLmbQ5sWsvPyP+YVTPolc2kUHj5cJU5Zx0Q==
X-Received: by 2002:a92:3d85:: with SMTP id k5mr6430046ilf.26.1587179927651;
        Fri, 17 Apr 2020 20:18:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3a9a:: with SMTP id i26ls1767978ilf.3.gmail; Fri, 17 Apr
 2020 20:18:47 -0700 (PDT)
X-Received: by 2002:a05:6e02:48b:: with SMTP id b11mr6179493ils.304.1587179927329;
        Fri, 17 Apr 2020 20:18:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587179927; cv=none;
        d=google.com; s=arc-20160816;
        b=H4A0r3SoBXKCM9BKg6ETSBxhwpM57Epq0maEhBo2yf2SqWme16Quu29hv+HN8Fn40s
         caZG3jUnW5kQC2g6Pi8DKnRXMF/tGMvLoglMWi2BYgB3PbhK82nH8NljPJqaR6bKbRrh
         HYGenp3pHf/wqCcARi3iR3Xu9r1SYXle5aEyFN9/Z/IITwZC5hDYOZZ6gUkaSc3l2NAn
         eZrs5Ou+FZmYT2IWDx+tRZDhOjCemaTuRPvuQd4gK5KNYQVkghFJ+tNWFup8hKptto3X
         BjlOUqNRYEXPGmRMA5jaturNT0/udqvA13RmQxZYDKMbD+Ala+QU3l4PO66E/+xrB3hc
         wXhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=KjuhJjKQQb7YT0HRwB6PPqCXcgSLxnxCVsCILm1vXYg=;
        b=aosX5RNm99YMvcOUB3oQE8wSDzZXBTw+AYAFUFujKrsqlcNvOK/PLPmeIJfWPfzCiD
         ZJEQ+D3JKcE56rCxnzoioyq8yz6rXK3FduMS99Yi2/h2YBTwh2PwigNDOgiUMld3nO4d
         74PMqCaQvzUlly8zBxPaE7hP1peb/5S5IrDdp/MoTziNKRRZA8fqDh23OEYyj0jUhpy2
         6ICVK5FNDmtSbvRYxxNpbwa0VbbLfJcmwKMQPgh13L81cTxdswLrEohzA9T3h57Ep52Y
         oHXwkStqyqR3ry+gCqnOii8AOGCytTRBa/rlajAWQwRn8tA8fVHVZd05YM5HCcpzfW5U
         QS4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BhjWeQqf;
       spf=pass (google.com: domain of 3lngaxggkcd0c9uhcfnvfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3lnGaXggKCd0C9UHCFNVFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id z2si1819973ilm.4.2020.04.17.20.18.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Apr 2020 20:18:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lngaxggkcd0c9uhcfnvfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id np18so4124934pjb.1
        for <kasan-dev@googlegroups.com>; Fri, 17 Apr 2020 20:18:47 -0700 (PDT)
X-Received: by 2002:a63:d510:: with SMTP id c16mr6300263pgg.123.1587179926575;
 Fri, 17 Apr 2020 20:18:46 -0700 (PDT)
Date: Fri, 17 Apr 2020 20:18:28 -0700
Message-Id: <20200418031833.234942-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.1.301.g55bc3eb7cb9-goog
Subject: [PATCH v6 0/5] KUnit-KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=BhjWeQqf;       spf=pass
 (google.com: domain of 3lngaxggkcd0c9uhcfnvfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3lnGaXggKCd0C9UHCFNVFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--davidgow.bounces.google.com;
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
 lib/Kconfig.kasan                 |  18 +-
 lib/Makefile                      |   3 +-
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 682 +++++++++++++-----------------
 lib/test_kasan_module.c           |  76 ++++
 mm/kasan/report.c                 |  37 +-
 10 files changed, 513 insertions(+), 401 deletions(-)
 create mode 100644 lib/test_kasan_module.c

-- 
2.26.1.301.g55bc3eb7cb9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200418031833.234942-1-davidgow%40google.com.
