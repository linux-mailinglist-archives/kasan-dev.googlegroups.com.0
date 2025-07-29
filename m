Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB2WFUTCAMGQEJNWT7NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E82CB15384
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:16 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2ff8a9716d2sf297429fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817834; cv=pass;
        d=google.com; s=arc-20240605;
        b=HcS/nASH4N+93LaHg8T+4WEibdYLOz4Psk/eYeYz+PkM/xK55/u4uzZd1R8Gn8NREF
         W+x/wHov2uf3HcTi4YtXyBP4j5E5koIapA5cb+gYAvRmrv3wBBQ/617YihJZgla7B1+e
         M11eufI+u8C66c41kH1BaeMwCFn/WAl4mTZjGTu+pkKYnjtPL/8pdy+/scaKZzuENCpa
         WLfVhTWYTnPwuhr6MdBMMzFYZ2SWyKqF4F043kr0wZ677XQSdrkn8OxQ+P5NW7lN+Sqm
         /Q1ies7Vw0bKLW0oEOrbGTXuVl5LAsYPZhTk+tJTrvucs1j/wj6QD/pfZMuLx4HJ5c0C
         z0yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=s6DIsI4KxTPgIPvSEnSPoFKBizz5rqaecLOv9u/XaIg=;
        fh=/l5wzii/boTBtDiN0RYj9fOo5zhnHT4e5ngpUR/doMI=;
        b=RLeBYB6zuvOV+Uv3cq0UmtjQSNoK2OMsLXMZhVBQns4s+hAb+mKZdtEk1iv+H03DPU
         9gubqpx297yKHaptBMbUe+Cz6m66KvqGvKZkBxc7F/PyFOetkqD0yfg3sW9zt4FnjGJ7
         lKuCvmHLPylyatZ8M4mJnxAJA8XvKSYHYZl3zYQ0Zsyw+PjyuMe1QfQZJS/KtsXlPfbb
         dHXKraafe6NhBUEqdPGOc1H9ErbYyw3jeLtjDDbGsMa5QkOm3qjjPSRQ4pm9OcupV8Ho
         vD2Cr8XmqsmQr7gvwZ7kNio1NTuhClUHltLrx3aQQ51puZRUX0Prf6sTQfbrDC+L3SY/
         FwFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Y0BfFsDO;
       spf=pass (google.com: domain of 36skjaagkcz4k8pgctgaemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=36SKJaAgKCZ4K8PGCTGAEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817834; x=1754422634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=s6DIsI4KxTPgIPvSEnSPoFKBizz5rqaecLOv9u/XaIg=;
        b=CUG9apM222NqcKf2CUEgNFOO6qu4RBbrd6xnz6qlhq/uz2hfcwgfIlSbz6GNYHqOJm
         7VceFS1OeYPUq1yrRL/S9oOA2qONpLpAf5Hza8BRSLotDpkxLgq262Y46xVB9j8pPI8a
         x7MhjVS6bR7ZbXOhM67/CC0pQ8fhAi8hS6a0cHlDTz26dksX4C2SSY76HO+audFltWth
         RpGgEOu2NeLxigDJWonPNl581FrE0eM1pzRuwAe3mWX9jm/vx+k+lAOEzSXPZftBeFcT
         4QJOwCJDW3LtQEWKCAMWvLMusvMyqGQRTo1twIkZyay6j+drSOPrvg1lDQxaxtuR8wdI
         qvHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817834; x=1754422634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=s6DIsI4KxTPgIPvSEnSPoFKBizz5rqaecLOv9u/XaIg=;
        b=MX6NIo2gT20V/I8GaW3MnsI/qoVwrPjJ4KQbFCKtBUqnnjWkf561G/vNTLtvJGu7fJ
         xK7V1MBzNxaQnqzytamASeL+Mv+IKOcsihMU+53qU1ZbcjHkQh9sQaO6N9tkVfQmZqeu
         9p23/nO0oRk23kVu1zCdn+mqSKGO9kE7yharWGCBTr7QetNAxfgHjLBFat1IVud5hGPs
         mbaBVXHkWT1LvxRfxcuIHshBi525MliPGC6WvBIpH+5YaA47NIwZhD1wPz+DIlBAJ67E
         tlFNllt5HNxLQ6LcEMCqaXdi+RzLc7t1L8SOE+3gJG+VbWH0ECZteYMN7Z6+uf11Clrk
         fBhw==
X-Forwarded-Encrypted: i=2; AJvYcCXTS+CIwcof9zWWjLRTviJdje19f8T2UWnPzaAzzs4hOuoP4TtnuwqhSB6sZPR4LXzx26RBZQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzd4Nm1GrfT01PAg8JuM7suSHvoyvOcTTuhI982vY56C8AjLCMx
	ahAEzfNUA2rkmSNO4WIl2tIkjoX8wNDN20fJ7zQHtTA5dPF7lWNVqV9U
X-Google-Smtp-Source: AGHT+IGUJ3Ck0AGxgNOpmvAqRQ+LY2lbyY+GmRpzIctRLkOO3nl/wvzsEf+DWPTyJKh2F7N433iGXQ==
X-Received: by 2002:a05:6870:be8f:b0:2d5:2360:4e7d with SMTP id 586e51a60fabf-30784db426emr546106fac.8.1753817834575;
        Tue, 29 Jul 2025 12:37:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcQhe7o8TZFrh9iSDNlkTdM/ev6LHRIBZrPp3b0BLvfqA==
Received: by 2002:a05:687c:261b:b0:2d5:17b7:9f8c with SMTP id
 586e51a60fabf-307855888d5ls69710fac.1.-pod-prod-00-us; Tue, 29 Jul 2025
 12:37:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGegn1pnck42oJ05SgLg9Zm25YcBFOIHMVn7uGATWJ1tclstmPQDg8u/fyg7kE+iecr99iDQtRyPo=@googlegroups.com
X-Received: by 2002:a05:6870:4e93:b0:2d5:2dfd:e11c with SMTP id 586e51a60fabf-30784d7d700mr544771fac.7.1753817833808;
        Tue, 29 Jul 2025 12:37:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817833; cv=none;
        d=google.com; s=arc-20240605;
        b=XAR32j8Qf5Yd7rEGrBljyeoantHB1qLUW+s3FRWJ1xZOt55DDXvoEjbsZFCBveHxoT
         1R+0TGrTwAyhBjkw9tPEv28i3PJtRKKT5qzwjiBEtXkx8WPkeqv6/1gBVZivz6ULUdCh
         q8bXADwqNbbh/XA4knkY7FzdB0wamHknNraK36Ci5gbrfGY5UYtKq90mnXgqHPk3zNZE
         MWsxBukn6e+isPXxF7uIAm49NYrlVamh/o/zLpcHdEDPVdNIQghzzDNTVsSbKhMulrpo
         4eF/gQHPgU6uJpoao9UHpSsA4EO2UenzGnhjtT70WuhT3yC7Hjyd2dpv/Zquni/tpnkE
         IOxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=iY//lVxLTeQ/wpFhoCwsWTSD0JOlrDoBeeghyQ/Upjs=;
        fh=zdBuewJ7zcafMfF2QUU4739eiejn4v4D025dhhUJcoY=;
        b=UQMBuE5WE0s4oBA6cWIaiEkrvkwlqAECuHPC5mbhMQHh1DRBpcz63Yv+H41ZF5x+ag
         eJtCoCCYesiy+LiOZ/Ai00RlrFWGTLXE7UUbCLnbXY7IHzdTlkMa4C88kOxXPAMXnJ5c
         wUPEMYBHnrziGynsbNym2dVbGNnkiMdyyjkkM22DPGLwhKpUJMHqLo7jyxGurB5nAzYi
         6oNWbOKYCv2atJMKZXawCc1e/J835HCPMh/7UjHFSUdqNFhRcjeXOr4Ppmcgta4n32eA
         fJ9fkJWC36sgTM6KOSA1fQGMSiRyaNtbmbeG/DOQwHAHwnUqLFLnO8JNnSWGdp70jAZT
         xAhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Y0BfFsDO;
       spf=pass (google.com: domain of 36skjaagkcz4k8pgctgaemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=36SKJaAgKCZ4K8PGCTGAEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30712fff7e5si453286fac.1.2025.07.29.12.37.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36skjaagkcz4k8pgctgaemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id af79cd13be357-7e651d8b5e0so369182885a.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4nXm0HgDEQLLQiOvJysq41ROzV0t0mT8Oml+aM4VpHNB+i0lczYKUo08l3eX5qzbh5Yoe9nW3gZo=@googlegroups.com
X-Received: from qtbfc18.prod.google.com ([2002:a05:622a:4892:b0:4ab:b55c:cea3])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:a10d:b0:7d4:4aa6:a509 with SMTP id af79cd13be357-7e66f39138amr112976185a.48.1753817833109;
 Tue, 29 Jul 2025 12:37:13 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:38 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-1-marievic@google.com>
Subject: [PATCH 0/9] kunit: Refactor and extend KUnit's
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org, 
	Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Y0BfFsDO;       spf=pass
 (google.com: domain of 36skjaagkcz4k8pgctgaemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=36SKJaAgKCZ4K8PGCTGAEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
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

Hello!

KUnit offers a parameterized testing framework, where tests can be
run multiple times with different inputs.

Currently, the same `struct kunit` is used for each parameter
execution. After each run, the test instance gets cleaned up.
This creates the following limitations:

a. There is no way to store resources that are accessible across
   the individual parameter test executions.
b. It's not possible to pass additional context besides the
   previous parameter to `generate_params()` to get the next
   parameter.
c. Test users are restricted to using pre-defined static arrays
   of parameter objects or `generate_params()` to define their
   parameters. There is no flexibility to pass a custom dynamic
   array without using `generate_params()`, which can be complex
   if generating the next parameter depends on more than just
   the single previous parameter (e.g., two or more previous
   parameters).

This patch series resolves these limitations by:

1. [P 1] Giving each parameterized test execution its own
   `struct kunit`. This aligns more with the definition of a
   `struct kunit` as a running instance of a test. It will also
   remove the need to manage state, such as resetting the
   `test->priv` field or the `test->status_comment` after every
   parameter run.

2. [P 1] Introducing a parent pointer of type `struct kunit`.
   Behind the scenes, a parent instance for the parameterized
   tests will be created. It won't be used to execute any test
   logic, but will instead be used as a context for shared
   resources. Each individual running instance of a test will
   now have a reference to that parent instance and thus, have
   access to those resources.

3. [P 2] Introducing `param_init()` and `param_exit()` functions
   that can set up and clean up the parent instance of the
   parameterized tests. They will run once before and after the
   parameterized series and provide a way for the user to
   access the parent instance to add the parameter array or any
   other resources to it, including custom ones to the
   `test->parent->priv` field or to `test->parent->resources`
   via the Resource API (link below).

https://elixir.bootlin.com/linux/v6.16-rc7/source/include/kunit/resource.h

4. [P 3, 4 & 5] Passing the parent `struct kunit` as an additional
   parameter to `generate_params()`. This provides
   `generate_params()` with more available context, making
   parameter generation much more flexible. The
   `generate_params()` implementations in the KCSAN and drm/xe
   tests have been adapted to match the new function pointer
   signature.

5. [P 6] Introducing a `params_data` field in `struct kunit`.
   This will allow the parent instance of a test to have direct
   storage of the parameter array, enabling features like using
   dynamic parameter arrays or using context beyond just the
   previous parameter.

Thank you!
-Marie

Marie Zhussupova (9):
  kunit: Add parent kunit for parameterized test context
  kunit: Introduce param_init/exit for parameterized test shared context
    management
  kunit: Pass additional context to generate_params for parameterized
    testing
  kcsan: test: Update parameter generator to new signature
  drm/xe: Update parameter generator to new signature
  kunit: Enable direct registration of parameter arrays to a KUnit test
  kunit: Add example parameterized test with shared resources and direct
    static parameter array setup
  kunit: Add example parameterized test with direct dynamic parameter
    array setup
  Documentation: kunit: Document new parameterized test features

 Documentation/dev-tools/kunit/usage.rst | 455 +++++++++++++++++++++++-
 drivers/gpu/drm/xe/tests/xe_pci.c       |   2 +-
 include/kunit/test.h                    |  98 ++++-
 kernel/kcsan/kcsan_test.c               |   2 +-
 lib/kunit/kunit-example-test.c          | 207 +++++++++++
 lib/kunit/test.c                        |  82 ++++-
 6 files changed, 818 insertions(+), 28 deletions(-)

-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-1-marievic%40google.com.
