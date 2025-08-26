Return-Path: <kasan-dev+bncBC6OLHHDVUOBBSXVWXCQMGQEQ46R5CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C2D1AB35853
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 11:13:48 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2445803f0cfsf60109065ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 02:13:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756199627; cv=pass;
        d=google.com; s=arc-20240605;
        b=b+aDx3UBa+U/AbyYrVGYCUTpw3ekO69J90SFozshMs+rBlKDI2EU7ou0niwEw/Pltr
         SpL3H/dPSngxrFDONEuEXRvc/cXHopKyGVPE23Zw6q0mh560U3y6bQxOx+KoNFYcmXak
         gWrb/LslQ8oGDwJbCJXJWAqMrnDUsZVRW/hQnwd7eSq4FQa7gbx/vnxhzBf2p7FEdvyM
         H5ctOTdDBXbC3j8kTGuyvQCy2ztaUNBPecjpWmwWjOs8rbiQeJmwtMdFRecqMQE+yD0T
         SX9sQLhGxzOpNKUN9lq2ZDecxvvn/giKBs5edBu7iEr2Bvr/Q5fEbpIhl7/ikczHvbaN
         5ozA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=fyrqCTmRI555ECm7f+uWLpdvHvtBb+6uL5GAvi3oelg=;
        fh=h+sgQDKgaTm9NatuYCesr6Z0nsP2P2wOVz6vlcp+eBM=;
        b=i2RC+pNxX7Asx3ViQjHI9Wzru3OsF9AQ++foCRMnUFhvLosiGc8hD3WVfZdzeElP6A
         jttoNTI6COGLotxgvjeb0xN2t0j/hzwwbqPb5irQEwXPHvX2y7VZNPdZT4sxxgkv7R//
         lMJ9W7OUt1PEWyUdRWz1slEsImAuuBwt9BeyW3/4K8106aCFsCLXyxatHb83DefG3oJP
         PeDxl7/K4F+UsXXLfOtmY4Ni2kOg1KlDWcJj4xd6QhM5m8cIh8dhQqMBKvxUvH2kmU4D
         h8yU1hMSsoeiwhR7QGIddpeOLsqdgdWW547XfzcPekIOEhP4QT0D9/kKOqRSjbrxtxGN
         2U5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fBXt6tUt;
       spf=pass (google.com: domain of 3yhqtaagkcb8if0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3yHqtaAgKCb8if0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756199627; x=1756804427; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fyrqCTmRI555ECm7f+uWLpdvHvtBb+6uL5GAvi3oelg=;
        b=K9TWRjN7fG5RfGFXxh+H2tEAg2Gn4Wxui9njOx/bUiaFsK91OkJksq2Htrzp6TppF4
         tPPmRi5IkKunawqiVV5Kxdzpsj6BCZjcAtUvYAIqmYMzI5z1rLs2Cn/oJ6UvPSJ+X5vu
         gCAoJAy8xcwwD217+97k7nHxH7XWIdXn6CRVN/q9KsgpRwbIc2n6RMLE158FAnkhfACo
         7PfXu4GeuQbxuGsWCQseDSkNxkuFiYC0f2FHlI59FYDz6kpLWLr7AUrpJmO2hsMVeugN
         atSUKneGDQj4kla7v7mYryLVrwVfZPn9xqJVfZZZwgw3SdUC0X7hd3lm3ngPRnsOrGVv
         vl+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756199627; x=1756804427;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fyrqCTmRI555ECm7f+uWLpdvHvtBb+6uL5GAvi3oelg=;
        b=CyMcHjTE00XhxdpuWDc2c9ssGgvynvdHIauP94EqubJCMVh74WX/YJ/20W1TJneoIP
         DfE7WpQ4ofWmJipRj8uZ/2pM96ruyDL3P1tCt6+9CFEWGUahTROayNqiWBs+zjCmeuW4
         ahbCpFrAapY5UPRqo6IdCaFodReA8JaDyzg+o55BP2YRdLNZR466T6SlkoT7VOmAgoVZ
         nNnecK8V/FkEb6c8h4Wt/QzXLgFwRFebZ8G29xZ6xf8eTuLl4/maAdcYEAMczUnOmb9Y
         87dO+FZEfNdIgahQhqbwAif8NJViVOll8mzCzdNV5sp4a36ysBjnv4uZVmanxM2QAAEF
         Nt5Q==
X-Forwarded-Encrypted: i=2; AJvYcCXX3znco2DGhbi9NfvEEJon8Boans93GqEkC5yT22HScoFO1z5jbUS+whqrfBZqM7XmKCJ5ag==@lfdr.de
X-Gm-Message-State: AOJu0YyLSCu3onew0XalkZIfYy4ChEUDALvd+ZEaMdS6kyd2tgK+YKBt
	mJpwcfKhc0slJoyo0yAD6Qp4TznrViFCALS0sySwe3GpvfGfc+jF4mW+
X-Google-Smtp-Source: AGHT+IEPGmvD8AwmSaT3iZaT3YMee7BJpnZBStOkAXgDudoK8/Mj7EHAZaYUtKxjTpubhGuXsuLzpg==
X-Received: by 2002:a17:902:da85:b0:234:c8f6:1afb with SMTP id d9443c01a7336-2462eb37ab9mr189287145ad.0.1756199626988;
        Tue, 26 Aug 2025 02:13:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZez3Gd3kDobnfc2oMTU3g3rJsmhsFiR2yS/R5swxg/58g==
Received: by 2002:a17:903:1c9:b0:240:9e9:b889 with SMTP id d9443c01a7336-24602ee0b8als65092155ad.1.-pod-prod-01-us;
 Tue, 26 Aug 2025 02:13:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVImQI4FfHA7I3hVkuA1rLcmip/360yI9ogPByPTw86m/Qg1+PHw/Y7FSbbjI5JjJCRZsNXR/z72x8=@googlegroups.com
X-Received: by 2002:a17:903:943:b0:240:968f:4d64 with SMTP id d9443c01a7336-2462edcf75cmr204862565ad.11.1756199625153;
        Tue, 26 Aug 2025 02:13:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756199625; cv=none;
        d=google.com; s=arc-20240605;
        b=ALjEe3aB/OBFJX1UvE4GTZvsbTCRySTGTxQPLjtUrBmGVbF4VRZkC9KJLgChcvzfeN
         /MXcftp1g5+Xw0HfaL12zPZ3+390UHkR3y+cBK+Pxi1bZX5ieeib/73YtN41K3PCJe60
         0NCk+uMV+yCfXDRV0RRIeYknAP0EQybGp6bLG3qEX7/gNd5LWNxfygryc56bsAvJsBUn
         wDZuAMZ9rVW6PVJyhgHh2d3/9EeJYJcqKX/vKuqCuusPWFX4tyA7ofHjk1aFzeObJcfL
         yh6z8Q8qkBxqs6TH8F2UhXuEG73AzwprcLv0j7N28QiC/ePJLCsmHbFdb560SY9z7fsj
         v+sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=znqW7t629WY1D1c5x2OGn1PouDI+EiyaNYCniW4dbvs=;
        fh=owQd9GcIUp35Y0/0ZSYRUn0hxj+8S5eQFSGJUm3Hv80=;
        b=dyoIjSazo+1LNCYNodZo++rnACwTH7kF5KaWzEEmlSmjHwTrbmzkhXufrt7/VFayHB
         mvETTr136/Eksx+KGGixANi5YosJpzlm0NRSSklmHFG73ig6NXCfSDYHRVMqQcNchanK
         C9pf5pQIYdE/SBPHsermDjnQQTLqF6WLVGWawWFfqw938AR98ZS02TlMHGbpmDJre+UF
         laBU7xFPFzUDj6cWUdD0KiuP4DLPmu275lcBtRlj3MYkO4L82FCVwo/YqEK62UuaqN7d
         sjb+8EBXzzX8wOFCBeMoQY4y+qIjbKp2H/RgfD83w7iCnavm+XoUblgBzMdx+wF/SOEA
         QAJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fBXt6tUt;
       spf=pass (google.com: domain of 3yhqtaagkcb8if0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3yHqtaAgKCb8if0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x44a.google.com (mail-pf1-x44a.google.com. [2607:f8b0:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2466884ab84si3454365ad.3.2025.08.26.02.13.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 02:13:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yhqtaagkcb8if0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) client-ip=2607:f8b0:4864:20::44a;
Received: by mail-pf1-x44a.google.com with SMTP id d2e1a72fcca58-771e331f176so1631712b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 02:13:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUuTMDkyEi0FzubQjUxfSsIR2SfrAcedoBP2hIwaQddHDPvpWF26EPPInNfhr9dGeMjo3IvnQ1+BKo=@googlegroups.com
X-Received: from pfva1.prod.google.com ([2002:a05:6a00:c81:b0:771:3e92:f3aa])
 (user=davidgow job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6a00:a2a:b0:736:8c0f:7758 with SMTP id d2e1a72fcca58-7702fa4f732mr16572148b3a.10.1756199624679;
 Tue, 26 Aug 2025 02:13:44 -0700 (PDT)
Date: Tue, 26 Aug 2025 17:13:30 +0800
Mime-Version: 1.0
X-Mailer: git-send-email 2.51.0.261.g7ce5a0a67e-goog
Message-ID: <20250826091341.1427123-1-davidgow@google.com>
Subject: [PATCH v4 0/7] kunit: Refactor and extend KUnit's parameterized
 testing framework
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marie Zhussupova <marievic@google.com>, marievictoria875@gmail.com, rmoar@google.com, 
	shuah@kernel.org, brendan.higgins@linux.dev
Cc: David Gow <davidgow@google.com>, mark.rutland@arm.com, elver@google.com, 
	dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fBXt6tUt;       spf=pass
 (google.com: domain of 3yhqtaagkcb8if0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3yHqtaAgKCb8if0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Hi all,

This is a new version of Marie's patch series, with a couple of extra
fixes squashed in, notably:
- drm/xe/tests: Fix some additional gen_params signatures
https://lore.kernel.org/linux-kselftest/20250821135447.1618942-1-davidgow@google.com/
- kunit: Only output a test plan if we're using kunit_array_gen_params
https://lore.kernel.org/linux-kselftest/20250821135447.1618942-2-davidgow@google.com/

These should fix the issues found in linux-next here:
https://lore.kernel.org/linux-next/20250818120846.347d64b1@canb.auug.org.au/

These changes only affect patches 3 and 4 of the series, the others are
unchanged from v3.

Thanks, everyone, and sorry for the inconvenience!

Cheers,
-- David

---

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

Changes in v4:

Link to v3 of this patch series:
https://lore.kernel.org/linux-kselftest/20250815103604.3857930-1-marievic@google.com/

- Fixup the signatures of some more gen_params functions in the drm/xe
  driver.
- Only print a KTAP test plan if a parameterised test is using the
  built-in kunit_array_gen_params generating function, fixing the issues
  with generator functions which skip array elements.

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
 drivers/gpu/drm/xe/tests/xe_pci.c       |  14 +-
 drivers/gpu/drm/xe/tests/xe_pci_test.h  |   9 +-
 include/kunit/test.h                    |  95 ++++++-
 kernel/kcsan/kcsan_test.c               |   2 +-
 lib/kunit/kunit-example-test.c          | 217 +++++++++++++++
 lib/kunit/test.c                        |  94 +++++--
 rust/kernel/kunit.rs                    |   4 +
 8 files changed, 740 insertions(+), 37 deletions(-)

-- 
2.51.0.261.g7ce5a0a67e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250826091341.1427123-1-davidgow%40google.com.
