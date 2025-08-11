Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBCGY5HCAMGQELODD5QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D613B21810
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 00:17:46 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3e55b4c81adsf3119355ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:17:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754950665; cv=pass;
        d=google.com; s=arc-20240605;
        b=exF0+6y0wMdaLLiAlJmDOEKDdAOz0q68iNs3lhw/SDQrv3cts7cTQ7T6L8Ecin9AAp
         o7Ue4ioWsMFZp1R5CvilOBXm18cWT9PoETwOwc6APKdCMFslHpK2nxCvBN+E5M6082OW
         u1dKPsx88zC6Bb2tmb+vg/GOANu+Ms2VflNKfc5jgNjXnuCLXsuC6fdRVkCIIfd2l/fQ
         eVTHAyi7Dfnpu4NgfwHED0nEdJiXMVn0Z5DTFNVCOCSbwpD77YKzg4u05oqsiNoqi9G9
         iBx4ECtlrUs+ciUq46efJyGhg1J0QlEn+29oMhMAz12/9z3jCsRIuzEKcG7ICYdebF7x
         C5+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=zHQKWpHE/CUDCPBcJfybxWUt1Pkae4gS2YNzTl/tcwQ=;
        fh=53Rz9djbaIDKwhjkr8r09GVEJacDdRhE6ELUG2iwWX0=;
        b=UKlGhvXcPyH8O1HHR6oWHDHAVF94QQ9x97rYHSMaIrYmPcjTriU9KTtWZMohRed8tB
         eww+Igs0yCBUAPqHQkEB9QZ7Ca740sILU0rHbtBsQOSCifS/5XRB/WRNWaUz9ibEkryb
         YL1xwSKNxTj82nFXobPThN/KmRk0JrsvKWtFyMDVWu0wly+kGOuvMBcAS47DcjzFD3gI
         jAN8UwkdcBQqfmVKKg9BPb+8HX4UPoo17l0usMmU43BgpMtv30OQq0N7oUZNTW1Tiy/G
         Bwa/lM4dehrJAB3UiILcyI7W/lc6WxEfutYy1wz2gK1EqmMEtqx2asw/JpsLOw/zGJ6x
         Pa1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="GD1dI/F4";
       spf=pass (google.com: domain of 3b2yaaagkczqayf62j604cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3B2yaaAgKCZQAyF62J604CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754950665; x=1755555465; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zHQKWpHE/CUDCPBcJfybxWUt1Pkae4gS2YNzTl/tcwQ=;
        b=luNP2qrYMf3oCstz/NQCz67Jjroczm8la3TNz0aedh9wSjZMVi7OjhNb1rRHOE5YLy
         4q2C0zOh9tjFngOs6Y04afHGApsBUWzOeid3cfHFyy6RKQTk1rH/Dsb7WlWBdGLdNhby
         jL36bbQ93Q26TGjCZDA4jjs4ULP1jemZZfsdTNi6t62BnItV9UVHIPg5b8jfRYi6ULyV
         IUDFlFRNR14NWKzn7uhGo0btO/i5vGTXC+73grurJSRRt7XbGONElgK9HAgUBbsvWJ4o
         HBUnB/ZxyMYlvbQ0/6VZVutq3B6zNytudVTBotp+wDJ2L8p2nJVqLpYS+Tn9H3kT1f3L
         ow9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754950665; x=1755555465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zHQKWpHE/CUDCPBcJfybxWUt1Pkae4gS2YNzTl/tcwQ=;
        b=Rofj+K8FVm/0uGWg3r7e4ulXvOvR1iIuZMW1LCnfMpG7iMlH6qM4X4EPjBOQFIGPze
         39AcehuY56qs9KoT8JfDUuQ7Gzf/b66ymkywsMZfvFjP50cT/mwEVR6JiIXiiRFObz5W
         zdrf+MFtEPaY4EvyGM7VGJpo3dyps2+44zm1f/4RjoTxOZ3pP6VZ8IG8ekUWinQH86Ni
         0g38KzKiU4Lc5t8Po5atXsMFuhKUebmqix0gXTKFBSnuSH4YNrm/wo+pdhWvhn1ahkn5
         WKNYUwFb0rtUF5SmAVOrdfYTeYJGeS3vWUoJheWU5xxp9vTSw3okLYmUdDI+Pss5kLgW
         a1kA==
X-Forwarded-Encrypted: i=2; AJvYcCXjz4dk1+jeO5IMR6P5zuOV3sptONAGWyKTcQ35rdpX9WwlOUZx+gKpV6DAjddcXTIg+wZbQQ==@lfdr.de
X-Gm-Message-State: AOJu0YyNjhGwtcU8asNqZbMsiB5YtRxXgRlIFNfakqxCigATqYsqG4o6
	gdIcUw9bSznJ5Km9brbQOBgXTHv8RzeOPku12qkSaZz+JthqTeIg2KlS
X-Google-Smtp-Source: AGHT+IG8ugGku1tphC/4/CrnddIj605S8h0nnrNXK/BkfmaxycMVc/ZPKlbULeSqU5CQUtDcn087FA==
X-Received: by 2002:a05:6e02:b2e:b0:3e5:4eb2:73e3 with SMTP id e9e14a558f8ab-3e55afadc9bmr18924985ab.16.1754950664912;
        Mon, 11 Aug 2025 15:17:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcnlvh/BcZH+N3Pil4txq7b0FqyeMs4dGrH7tfEZK8pwQ==
Received: by 2002:a05:6e02:e11:b0:3e3:cec6:58f0 with SMTP id
 e9e14a558f8ab-3e542bb35d9ls14240095ab.1.-pod-prod-03-us; Mon, 11 Aug 2025
 15:17:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmRx/HW47XUTqu4mtC1Tg9A83z8sl2nKKT5WflmCv76meJgbvdz98v66QOrrUs0/KRIKxPDb9zuWU=@googlegroups.com
X-Received: by 2002:a05:6602:340d:b0:881:81cb:57de with SMTP id ca18e2360f4ac-8841bf117e5mr289690639f.12.1754950664074;
        Mon, 11 Aug 2025 15:17:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754950664; cv=none;
        d=google.com; s=arc-20240605;
        b=UT548aZAMUgWTVubh1A4KYBgaEVyUZJvUMDoGi1OzYhkxmUjj7+PnAOG29KkC9GPxE
         uJgKC0vnaofzMxYK6uVkeWM+D5//g+II2JGHx74OddiWeMDbYqAnjYjz/OhG8mj1mToB
         Ruissit/hf0zeBTgkBEzC5Ko33ZhSA6C8RDnhBSoYOVi6HUzQ0Tf8IKbXaA/XtnZnctL
         AgDD43/y1D0Oxqt5wjmYD5PC7CFeldWbzTlC4rLsW9o2Qhzkn3QQBh5SAsou0M2USgM0
         l6lswRdOPEJSAY7qhPxK1Mpe69lQrR2Jlc7DE3WY/hYywU7ZcIFScGLd3k2JNHpukWLw
         4Eow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=tsTpiVRLtnpCIisNiGgEETpcDrFcJWiGEHWB60H2Tzc=;
        fh=OfFsVjCuqk2FbWdfdOnNiCstwYVxuta9TFTHHGwbxeY=;
        b=GVNOKyQtWcP0GPrZF6Ri/9OBJb9jjUrNR2VfohgOTmYF5BVlz3xx9h4m1Zc51abcoh
         9JAnPsvUNTRMKY74c49kXo2qaBkSIkQ6keZi8sG+0xt7u28nyf9r6clvGP/TTLFncdqx
         2IC/lJUUwMKkPeh1++oK2/TxMlPR5tSH9z4cWpdPWuVBG8qdVOt5Jls1S1vDsChbE1ef
         R7gThGBZ2g0U7NzH8FNOnhXu4I6qqFB0tLFR7kyzbg0UnG7+LcNT0b98l4wxLVv8ki+G
         Z/0TXxAtH/c4WR1gqpQlxbRBHtR/xXTFvYFUQiVWkih80ME6ZmPvUynNELsA5aVg+cwJ
         3k0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="GD1dI/F4";
       spf=pass (google.com: domain of 3b2yaaagkczqayf62j604cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3B2yaaAgKCZQAyF62J604CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8840d814c65si17021539f.4.2025.08.11.15.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 15:17:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b2yaaagkczqayf62j604cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id af79cd13be357-7e69e201c51so1114307585a.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 15:17:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJsleYvIHxxfKvDqgVLTsvFqiZFcBVvR1MC9fQXayK2s596KchKJP/Q43rrYrM6Ar3eMUnMIlU0L8=@googlegroups.com
X-Received: from qknwd46.prod.google.com ([2002:a05:620a:72ae:b0:7e6:36d3:ccf2])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:612a:b0:7e3:35e3:3412 with SMTP id af79cd13be357-7e858897035mr146693485a.34.1754950663342;
 Mon, 11 Aug 2025 15:17:43 -0700 (PDT)
Date: Mon, 11 Aug 2025 22:17:32 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
Message-ID: <20250811221739.2694336-1-marievic@google.com>
Subject: [PATCH v2 0/7] kunit: Refactor and extend KUnit's parameterized
 testing framework
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org, Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="GD1dI/F4";       spf=pass
 (google.com: domain of 3b2yaaagkczqayf62j604cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3B2yaaAgKCZQAyF62J604CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--marievic.bounces.google.com;
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
run multiple times with different inputs. However, the current
implementation uses the same `struct kunit` for each parameter run.
After each run, the test context gets cleaned up, which creates
the following limitations:

a. There is no way to store resources that are accessible across
   the individual parameter runs.
b. It's not possible to pass additional context, besides the previous
   parameter (and potentially anything else that is stored in the current
   test context), to the parameter generator function.
c. Test users are restricted to using pre-defined static arrays
   of parameter objects or generate_params() to define their
   parameters. There is no flexibility to make a custom dynamic
   array without using generate_params(), which can be complex if
   generating the next parameter depends on more than just the single
   previous parameter.

This patch series resolves these limitations by:

1. [P 1] Giving each parameterized run its own `struct kunit`. It will
   remove the need to manage state, such as resetting the `test->priv`
   field or the `test->status_comment` after every parameter run.

2. [P 1] Introducing parameterized test context available to all
   parameter runs through the parent pointer of type `struct kunit`.
   This context won't be used to execute any test logic, but will
   instead be used for storing shared resources. Each parameter run
   context will have a reference to that parent instance and thus,
   have access to those resources.

3. [P 2] Introducing param_init() and param_exit() functions that can
   initialize and exit the parameterized test context. They will run once
   before and after the parameterized test. param_init() can be used to add
   resources to share between parameter runs, pass parameter arrays, and
   any other setup logic. While param_exit() can be used to clean up
   resources that were not managed by the parameterized test, and
   any other teardown logic.

4. [P 3] Passing the parameterized test context as an additional argument
   to generate_params(). This provides generate_params() with more context,
   making parameter generation much more flexible. The generate_params()
   implementations in the KCSAN and drm/xe tests have been adapted to match
   the new function pointer signature.

5. [P 4] Introducing a `params_array` field in `struct kunit`.
   This will allow the parameterized test context to have direct
   storage of the parameter array, enabling features like using
   dynamic parameter arrays or using context beyond just the
   previous parameter. This will also enable outputting the KTAP
   test plan for a parameterized test when the parameter count is
   available.

Patches 5 and 6 add examples tests to lib/kunit/kunit-example-test.c to
showcase the new features and patch 7 updates the KUnit documentation
to reflect all the framework changes.

Thank you!
-Marie

---

Changes in v2:

Link to v1 of this patch series:
https://lore.kernel.org/all/20250729193647.3410634-1-marievic@google.com/

- Establish parameterized testing terminology:
   - "parameterized test" will refer to the group of all runs of a single test
     function with different parameters.
   - "parameter run" will refer to the execution of the test case function with
     a single parameter.
   - "parameterized test context" is the `struct kunit` that holds the context
     for the entire parameterized test.
   - "parameter run context" is the `struct kunit` that holds the context of the
     individual parameter run.
   - A test is defined to be a parameterized tests if it was registered with a
     generator function.
- Make comment edits to reflect the established terminology.
- Require users to manually pass kunit_array_gen_params() to
  KUNIT_CASE_PARAM_WITH_INIT() as the generator function, unless they want to
  provide their own generator function, if the parameter array was registered
  in param_init(). This is to be consistent with the definition of a
  parameterized test, i.e. generate_params() is never NULL if it's
  a parameterized test.
- Change name of kunit_get_next_param_and_desc() to
  kunit_array_gen_params().
- Other minor function name changes such as removing the "__" prefix in front
  of internal functions.
- Change signature of get_description() in `struct params_array` to accept
  the parameterized test context, as well.
- Output the KTAP test plan for a parameterized test when the parameter count
  is available.
- Cover letter was made more concise.
- Edits to the example tests.
- Fix bug of parameterized test init/exit logic being done outside of the
  parameterized test check.
- Fix bugs identified by the kernel test robot.

---

Marie Zhussupova (7):
  kunit: Add parent kunit for parameterized test context
  kunit: Introduce param_init/exit for parameterized test context
    management
  kunit: Pass parameterized test context to generate_params()
  kunit: Enable direct registration of parameter arrays to a KUnit test
  kunit: Add example parameterized test with shared resource management
    using the Resource API
  kunit: Add example parameterized test with direct dynamic parameter
    array setup
  Documentation: kunit: Document new parameterized test features

 Documentation/dev-tools/kunit/usage.rst | 342 +++++++++++++++++++++++-
 drivers/gpu/drm/xe/tests/xe_pci.c       |   2 +-
 include/kunit/test.h                    |  95 ++++++-
 kernel/kcsan/kcsan_test.c               |   2 +-
 lib/kunit/kunit-example-test.c          | 222 +++++++++++++++
 lib/kunit/test.c                        |  87 ++++--
 rust/kernel/kunit.rs                    |   4 +
 7 files changed, 726 insertions(+), 28 deletions(-)

-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-1-marievic%40google.com.
