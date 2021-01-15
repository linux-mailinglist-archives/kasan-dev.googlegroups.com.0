Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7FMQ6AAMGQEZKIRBJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 495CC2F82F1
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:01 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id v187sf3356041lfa.14
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733181; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQiN+Z3iQm0JsYFvo2af0hpYeCLerPNjkpzFjLR5FQpPvPyYgEWJBNF9oGCtj7bKgo
         OSQtKzmJwn29mmCbpej9Ktf5wgdo3D6x0Zm/gUDN50R04YfoNsvbJsZT0bC96mPtCvOR
         kxdiSmlTnqRQOS2o1qzhg0tIP/uhgg+5C/yAHNyQcbXltQdK8uJeTlfnZLTHrhewUGxH
         Km5pU4jcbAG63QCnuhPYI8PuGSxqL4iaHDBVVLdA8Q1NnE7ERXIUPnNrqq2Bq0ra5sYb
         /U2fUOOX12NacdRlA4EV2Ep6xZypvsEtDjaajxFuOfp5D6E4FhLauNjNTaEaVwcIxkbU
         CQQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=RIeACWM3g/AahSg/Szt13O7WSwbm4gJT8vP0wd+ewqM=;
        b=kfgv3bSVVLu0UvleVhMcrwM9Ij92rPgLgkTXBFe0BCAOnPS5ILj4JmNft3yozKQnH2
         d4EHb8yqfpxD9H2YlxUiINzVAIIubUWBKd4IqV5Ch5/MEkZZ40TfWfrFoyoyjzXcYciM
         auWSS1zM8fKRKO5rmny0vsvQFn5BSgrfl4OwiRdWnd2OzkXFEbaa/ZsrKnr4Gtj5eKU+
         uvr2uKreZnPWwe8RivCPYfazUc2cRkRAM52FdePIQdkapwxYo1cKMXXUKf2N8c9PqNhH
         KVvkfDqUsGMBaFtZ0qxtg4APJwL/IJ6RNhuB55NdOhCt7hdUocUGdiuHW+DmEVZeIhJF
         Rtsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V3MEXFzA;
       spf=pass (google.com: domain of 3e9ybyaokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3e9YBYAoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RIeACWM3g/AahSg/Szt13O7WSwbm4gJT8vP0wd+ewqM=;
        b=rHvLwiwx1K+hkV+EMUC2sn+KS4v3/MDLj9Z8p7ZhrPBj9NbrydsXL9ckPNM+S2BARY
         GyIuFFsuUQbrnduqwiNgVRn/WcPhiJeML9Qe68V0X6W/xilstDLbEeYxSXp/393ZwphJ
         7bGEnMhJ0UR/hxordmFj5mQ5ffkpuftn29aYzjOsnKoKS35W4f2FJ7wg06MAI0y4m/cg
         Mfexd2o9tQiKvVwX1tZX+THQhbIwWLigzIUjgDr1l0yh9SjfKlsUkrKRlsoBOMuZxkcY
         4TmU7TrYteQEVgBO3zdY/cJKABbmaWZF2T/gi/v+nOyAakPNjZHluoqtqR7HwcUYX6Z1
         BwAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RIeACWM3g/AahSg/Szt13O7WSwbm4gJT8vP0wd+ewqM=;
        b=ZeOS4nDGT/3VXBIhihbg5VKqhx8U+SUeXX1NiUxxavDMb6+Hslsmzvox3dUud3qDHt
         P/+rR6xGCZWxTntMIDUxf1l3A5zQO5Wq+ggnin2Z3WTbSfcmmLvVinMD3oYI7OD/TBjh
         QQbDmKBagoZ4rJygSlCcUg4jBtfhvs9pjrV8zeUT/pfZuzY5+YQrhdoTM/p4lsgdXXCy
         7AGjXTPDOcrAWSyz7mA5DH+xlyBilO5KbbYPvIe9g2+s6pJ+5oyEChrRTOvc319i3f7l
         VTy25O8m0HDyI2dDXoFXubMvNTjDNft5jhc7SZ/aLj90WUNfmr8A92XuNJfpooblkT2i
         xAqA==
X-Gm-Message-State: AOAM532HVVsmZH8qdgf/uSxksb+z5aVknVnEa4a3HP7BI4DSQiegWluc
	vWKayPj/5mxzoG/Uv0CrriA=
X-Google-Smtp-Source: ABdhPJzn10bD34i/qlquhoQBvUAk28pCc4pXiPWdDYRqEynKfpbi82z019Jhra8u7LvejHr/RBOI+g==
X-Received: by 2002:a2e:3201:: with SMTP id y1mr5755921ljy.12.1610733180896;
        Fri, 15 Jan 2021 09:53:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c1cd:: with SMTP id r196ls599900lff.1.gmail; Fri, 15 Jan
 2021 09:52:59 -0800 (PST)
X-Received: by 2002:a19:3f01:: with SMTP id m1mr5836346lfa.203.1610733179834;
        Fri, 15 Jan 2021 09:52:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733179; cv=none;
        d=google.com; s=arc-20160816;
        b=OJFAj2zHobHfPITp6NTjJZq7+XjxxU0tPAlhRUhWXFeXp89ovmrC+eyvUrwjprlDyQ
         Cdc7bSeOq0Ebpk6I/PyXuMba91SWQYrPWM1sVuxvoE4YYUm3zHUrylV6S+4o5GfMjjnY
         8cf5ga5YNhu724KaH4rm3M0LtobyBtNxTZ/XpiNuZPGV4zMlV7Hwk/f/Rnm9Lu2sJcSe
         6nR9wktIh1DyoYcZuRRiewoeyVK8R1ZtnH30Vxy7DUTRUcDP7jF8p2bYPOVLNSiuUAzU
         D89wp3iVa/twTIyAQ+pvNFPnLKvrkX2cyhpGgPOCa7+U2oYPA/q/IwzPy8EvZfyHLOaY
         r68g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=RYO/TR1Bbm4mW1iECzdQbQ7ZTGAweoPPzyjiEaLEaqY=;
        b=0La2gtfp9EXaRY6U6ToEWue/W9hEAIo8SqhYCqHvtI2pMHt8HHK6G5lP2bb10Us66A
         BaRCYTC3FhC2QFpsnFImkmqbDoKayGvXOJrv2tdUhPEBbSeMrYCiGggGYLBWo13UoSpz
         yTjFW8GkbQ72gOKuoXLyPIkerWatPjEyE7zl5zENQghcW24m485rG2u/UST1//jMsA6D
         dDrKlS7huTaBGVBi9N+KVEqLF9zBLw8ovWFAWEuohp16YZEEsdEOAXjYbQujbn2RrCvO
         h+kuTEPa3PMqfl9G27Tv5R4kvKjb7c3HdshW4zFxArgT2f6igpad1QNbwoROzW7FL3bD
         KWrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V3MEXFzA;
       spf=pass (google.com: domain of 3e9ybyaokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3e9YBYAoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id l8si364577ljc.2.2021.01.15.09.52.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:52:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3e9ybyaokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id u3so4418404wri.19
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:52:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:c64f:: with SMTP id
 u15mr13855560wrg.270.1610733179247; Fri, 15 Jan 2021 09:52:59 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:37 +0100
Message-Id: <cover.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 00/15] kasan: HW_TAGS tests support and fixes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V3MEXFzA;       spf=pass
 (google.com: domain of 3e9ybyaokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3e9YBYAoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patchset adds support for running KASAN-KUnit tests with the
hardware tag-based mode and also contains a few fixes.

Changes v3->v4:
- Fix using tabs instead of spaces in bulk tests.
- Simplify is_write calculation in report_tag_fault().
- Add a comment about tests to report_tag_fault().

Andrey Konovalov (15):
  kasan: prefix global functions with kasan_
  kasan: clarify HW_TAGS impact on TBI
  kasan: clean up comments in tests
  kasan: add macros to simplify checking test constraints
  kasan: add match-all tag tests
  kasan, arm64: allow using KUnit tests with HW_TAGS mode
  kasan: rename CONFIG_TEST_KASAN_MODULE
  kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
  kasan: adapt kmalloc_uaf2 test to HW_TAGS mode
  kasan: fix memory corruption in kasan_bitops_tags test
  kasan: move _RET_IP_ to inline wrappers
  kasan: fix bug detection via ksize for HW_TAGS mode
  kasan: add proper page allocator tests
  kasan: add a test for kmem_cache_alloc/free_bulk
  kasan: don't run tests when KASAN is not enabled

 Documentation/dev-tools/kasan.rst  |  24 +-
 arch/arm64/include/asm/memory.h    |   1 +
 arch/arm64/include/asm/mte-kasan.h |  12 +
 arch/arm64/kernel/mte.c            |  12 +
 arch/arm64/mm/fault.c              |  20 +-
 include/linux/kasan-checks.h       |   6 +
 include/linux/kasan.h              |  37 ++-
 lib/Kconfig.kasan                  |   6 +-
 lib/Makefile                       |   2 +-
 lib/test_kasan.c                   | 424 +++++++++++++++++++++--------
 lib/test_kasan_module.c            |   5 +-
 mm/kasan/common.c                  |  56 ++--
 mm/kasan/generic.c                 |  38 +--
 mm/kasan/kasan.h                   |  69 +++--
 mm/kasan/quarantine.c              |  22 +-
 mm/kasan/report.c                  |  15 +-
 mm/kasan/report_generic.c          |   8 +-
 mm/kasan/report_hw_tags.c          |   8 +-
 mm/kasan/report_sw_tags.c          |   8 +-
 mm/kasan/shadow.c                  |  26 +-
 mm/kasan/sw_tags.c                 |  20 +-
 mm/mempool.c                       |   2 +-
 mm/slab.c                          |   2 +-
 mm/slab_common.c                   |  16 +-
 mm/slub.c                          |   4 +-
 tools/objtool/check.c              |   2 +-
 26 files changed, 563 insertions(+), 282 deletions(-)

-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1610733117.git.andreyknvl%40google.com.
