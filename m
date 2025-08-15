Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBGU37TCAMGQEGSRFBXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D2692B27E51
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 12:36:12 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b471737c5efsf1245710a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:36:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755254171; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bgnny8r/30vmr2fjXhSr2P+qqTFMa85xdHHwxrKmKnNqcGpIfGT6d51Hl4M3wQXZTj
         C0wvBuXmEiikqxLVyxG7AFgKSDvDtrGSczcR/su3xvWnpJzXD81oWCofcHgaKEA+EDnp
         3KJKhoM22Q313wZRzMiWbVH2y0kEJDgMzhoV5EetngrNYD65hvm4ekUHrzbflmmeOCo/
         2ukfWtmZf7vlMXV+eo3ff4exlJNvDZBm2UApC6QyW5cvr8cBJFik+ksF6zgw/MuGQtyu
         d1Xm4p2ZygEBgWOzJa7UQKuhJJjh9D9t2+shTTpIUqBjahgVFY4LqYbsb8DS9u2Bh07f
         GgnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=2iCzv2+t9l5qyR28TLBaAWdJcM5H/B1/Bi2ScIOZkWU=;
        fh=IF0SF2Gpo1um1W3uSZf5yYaOlmCg8xVvd/U3vsNJHSY=;
        b=cLU2PameH1HvbG7hOLAAlo1yE3dflsPj7PPztel9+F1cnHeeXENKWLz5VS98cBWWe6
         Ds2zO1DElJFJM/HbUifGwSIIBBS8T80G8ZNn0DM2WgyGBOG4HshsBx8E/Zog0KzLJdK0
         nK1IogXUYV3Zu19DKJkybXFUSTAA/Ty/tmmMQ3NC/+1Bn2jTrxsBVasXyuw21dnV2y3e
         QYE8gxcQJCwKnp0tQvEyHCU9keF86OLs76RW6VrtTyzN7G33LvpzrwoCh3831LlUEHci
         CBYj0X+jyL5fXaqxXEixgEC7h04OoYdHv70ihQKCkx0tovkApOji/WqGD8qPazqgrlno
         alBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PmIyazLJ;
       spf=pass (google.com: domain of 3ma2faagkcxslzqhduhbfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3mA2faAgKCXslZqhduhbfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755254171; x=1755858971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2iCzv2+t9l5qyR28TLBaAWdJcM5H/B1/Bi2ScIOZkWU=;
        b=Jow7Aotksybt1e+qHPo7ZkgqSKG3eXwOnKTXcwU9LLz7RiW+HtbV3v1hQMtTy0ywwN
         +6YmK3V052KNu9c9xSLVM1uSXbDwlMUuSXUhOpM/QapN/RsKOaJZM9qXvOgjSiZoWMMD
         suXEfO9oZ9gd/Fgtg8MhmkP1ezD413bpTNHtDS+mIQ5VKYpA3WRmuzI0WkLvZu2NdNz0
         ivRVpEgPd3kP0T7fGdAI0qOid17eMU0mjeZ8BiJTQmF8H2y1amQ052axF4JqKB3K3osk
         L/HZm9nPo1H+0x5Q0NK8cotxxTJznf5/vNZ1mssODrpayLtRhxkRBY/lI4KPtgdDb6zL
         fxeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755254171; x=1755858971;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2iCzv2+t9l5qyR28TLBaAWdJcM5H/B1/Bi2ScIOZkWU=;
        b=pJFPzHTbaTED2AX8aUIBAW0vHbQAYq/tnLR8GvodcTZBjHjmZA2zHK1j0xsAkJics9
         gE+CJwFAlaHGkinUVkQcAx8lxiXC07OTHGauuo1Or0UIKQUGhl65WBuAMOfhgoJoqH+i
         LtVJ/x+TsypQQWDMI9xaL3EmmUEfJpxPlBqZhiFiso7WYOu4Zadd+0HrGIPO/nPTuC3f
         gmwsOFGBcw9btbldG7anU+ktUPSVDg8/SjmexB5/wmsc/5k49QI5u38GAoMZOkj0qyH3
         COFhASENFd43eIkvnzltPOMBt7HLiP/FNSbJ5mhA5w7yys7AVyxYqD2Z89e4+SgOsDTm
         fPwA==
X-Forwarded-Encrypted: i=2; AJvYcCVHnhsR1KXS2CTXvHuEJLWjA7nn7VWA3CIJV/uF7+JVtULm91N4JnjK1IvL7xy5Y/n2Lp1/+A==@lfdr.de
X-Gm-Message-State: AOJu0Ywg7k3Lpc6fAFzqFaZJmc0AG4PS1xp3rWw5PPAVq8TuWEmrotnd
	lKWpUnwmRvidpjtJFYoU6OCH1jOvSM2KsEDuGOkmlFr9Zai73vbtul7o
X-Google-Smtp-Source: AGHT+IE9gus7gVSTQSE+4FUtAxz/4owZXh/KsJ61tKEtReGTfu93SsI6o7KRLrTj2KxFnZb6th16Ew==
X-Received: by 2002:a17:903:41c3:b0:242:e0f1:f4bf with SMTP id d9443c01a7336-2446d720275mr23341345ad.18.1755254170731;
        Fri, 15 Aug 2025 03:36:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdPxTZ6pGhgq38Jt3+BZutwkMhOkgudmtGgMCnVnhUUJw==
Received: by 2002:a17:903:2d0:b0:23c:7b21:3a41 with SMTP id
 d9443c01a7336-2445759f953ls18294075ad.2.-pod-prod-05-us; Fri, 15 Aug 2025
 03:36:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyzl51EXOjn8Vn3QqdOWzhOqwMvRx/sQme7jC2vZ2Hg8xkWLdE+nwQm7+RGzv4BdtBZw/twfad24Y=@googlegroups.com
X-Received: by 2002:a17:902:f70c:b0:243:8f:6db5 with SMTP id d9443c01a7336-2446d6e4e7amr21271665ad.6.1755254169468;
        Fri, 15 Aug 2025 03:36:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755254169; cv=none;
        d=google.com; s=arc-20240605;
        b=AcI+AtD6F98oSjIT/QzamW715cAKASr8iaomSVU7c9OOxlXAXoB/1TjiZSn1k2pK+c
         nZjCwdIq+e9oXbgLSEw0WNifnW1bfG6rP0IZSPEZWIutu44gec3f9uqOhrFZc7MKWH91
         Hhni5E4Dxy64bk1Dk4aph1HGOAr/Ui4lyi1ewj/KPsUTGMvOuGYLNnwfmSs6SFDC3B1f
         XF7rHhLmWb32fIDVwhnKM1sptSTy+RH347v8+GigUbYg1MmdOMBDkkC2WqF9pawmC8zB
         Tu5xb9UZ6523HBKWwYsTd+R+/WojTrsPyPvKKJVwGhEpHITbvjHwuuas5J9VjigxJN1i
         Ww9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=eFpXxq44oeslvizqCF8Bv0M0ZVaQrSB155EOLBMECVQ=;
        fh=nXFfsgzaiYeyKhNEZ++rY8WHtBGR1ixdjmWEZKVykvg=;
        b=e8tTKrm/e8i2TxVTVcioa9h5NzfOhiVaUX/XWmlw/gTLNIkfsVs+R3pnMNVuicvl7t
         Cgq4dL+ufcOYXe78S+2s+/o0XYDiAmTM+7NKY7afWTo0ztA7lCY8DKx7mip6GFlcMel4
         fdlm7YLy7v7X/Jf9crdO2PNdYreSEIpRYdIPRulEQqTemqyWijuajNIUKuFbzMZtPF5+
         fXimTsr+qNt5M5+pPTt+UE0Qm4oUVVDXcthGzzFOASjxZFQDL0KRh4x5k4i2SOJl4CTK
         6e+pVCchHWWfSlKb068/GjYlUv7PwcnEiAH/0q2SbTt/hBCSx7DzzYQ8Cr+ie6Vboa6j
         ugXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PmIyazLJ;
       spf=pass (google.com: domain of 3ma2faagkcxslzqhduhbfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3mA2faAgKCXslZqhduhbfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2446d525defsi517765ad.6.2025.08.15.03.36.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 03:36:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ma2faagkcxslzqhduhbfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id af79cd13be357-7e8704b4b01so434808685a.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 03:36:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUFXz8wmY951uJIuP3Hx4o3xHRt2hH5BC12q3KgWBnlrmBM1541axfGl7Y8sXafgTgF40DmSrL5d7o=@googlegroups.com
X-Received: from qkpg1.prod.google.com ([2002:a05:620a:2781:b0:7e8:14fd:d2c9])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:1a17:b0:7e1:9c2d:a862 with SMTP id af79cd13be357-7e87e06b8dbmr185880085a.39.1755254168517;
 Fri, 15 Aug 2025 03:36:08 -0700 (PDT)
Date: Fri, 15 Aug 2025 10:35:57 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.51.0.rc1.167.g924127e9c0-goog
Message-ID: <20250815103604.3857930-1-marievic@google.com>
Subject: [PATCH v3 0/7] kunit: Refactor and extend KUnit's parameterized
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
 header.i=@google.com header.s=20230601 header.b=PmIyazLJ;       spf=pass
 (google.com: domain of 3ma2faagkcxslzqhduhbfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3mA2faAgKCXslZqhduhbfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com;
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

5. [P 4] Introducing a `params_array` field in `struct kunit`. This will
   allow the parameterized test context to have direct storage of the
   parameter array, enabling features like using dynamic parameter arrays
   or using context beyond just the previous parameter. This will also
   enable outputting the KTAP test plan for a parameterized test when the
   parameter count is available.

Patches 5 and 6 add examples tests to lib/kunit/kunit-example-test.c to
showcase the new features and patch 7 updates the KUnit documentation
to reflect all the framework changes.

Thank you!
-Marie

---

Changes in v3:

Link to v2 of this patch series:
https://lore.kernel.org/all/20250811221739.2694336-1-marievic@google.com/

- Added logic for skipping the parameter runs and updating the test statistics
  when parameterized test initialization fails.
- Minor changes to the documentation.
- Commit message formatting.

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
 lib/kunit/kunit-example-test.c          | 217 +++++++++++++++
 lib/kunit/test.c                        |  94 +++++--
 rust/kernel/kunit.rs                    |   4 +
 7 files changed, 728 insertions(+), 28 deletions(-)

-- 
2.51.0.rc1.167.g924127e9c0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815103604.3857930-1-marievic%40google.com.
