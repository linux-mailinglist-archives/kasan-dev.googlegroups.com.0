Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGV47T7QKGQE7TF2OLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 999592F4FB9
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:21:47 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id u66sf409891vsc.12
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:21:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554906; cv=pass;
        d=google.com; s=arc-20160816;
        b=jOS5Infs7SodmuRFSP+uIWtLpCsQ7v9y65oTpUX2Z9439l21DpqsQofZGnO/ddHFmk
         Eu3bi51C86J5dWylUZqYYTo4elm0dDHgrSnthp3OYBoB0EQn0tR12gui34sT9tnUKVqV
         ayGo+xO1rPdIm4K58N37rteKeAcDpYgyuvaYypJqlwT5lP9HJMtxOFaHtuA7dvh7KQyX
         ofGW8iH/QLW7p5noGwto3bn/6xdVAbIZ3XeBV5aB/J+0woSW95zBaDHe4kiijdFq4WOn
         HHqkkPdi3TBg+OnRUZF/g6PbR8BmaqIvPjBJbRvRyRTDDpRDenRTzuZFNavNDimzniw7
         tdFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=BeNzPusIDU3pkw4QGstQMBC907hhG1JRGaXkU3J0URE=;
        b=C1/eW41QmB9/uUpeOWxsumFMkXkHhhThmW2ujXETbjRlf3UeMroXeilduv7H86swiT
         MMtUWei2rl5Wkv1ZObL4qEJOTdLqvT221mtLiqePtnxQ4cEektPpjxP1fjs4cR+OKoz5
         w8CLIPPOxHzEjH895sdORufbL/5x9XS0oFRMEcSdVFd3YTke5TLEdwI8kvYDDRdEJ5PH
         8Ha18dj5ovm7pdfY2X/s/473K1HLZRN8Kv3xXNijWpkR2ZX2EC3CdifwJa47aHXxAx5S
         oNFs/JTzPfO/KzIkvSMP2fMgPGafEtD8WWlGZM29lL/Y0WtFyv+LlrpMPd/h/kFRoVNJ
         pMsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kexc0GKf;
       spf=pass (google.com: domain of 3gr7_xwokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3GR7_XwoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BeNzPusIDU3pkw4QGstQMBC907hhG1JRGaXkU3J0URE=;
        b=h9rUwfecyhiVb5fTJD8tb77wS2UrGeVz7lH0czwesp1IIZ4OMzm7ReB50e10ABZ6zu
         dxXX+M42Y8o8LXqQ1sa/FefJ74dQ+rLBxhYSethOIFMnnC3ZIB1HOcl+s31IDRxW3UA8
         P2+Y2YBc0ZgmcId8r2QdQ7Lj7L5QZDpag8dezflP6n7OFXo44MZstLOz38lzL/2Vh3r7
         1KXK4SeKY+JU/i6y30FuzyerUmVF6EN2cCfnr9+e/f1g2binjnTHSEJr6dYorTc+7v2y
         vorBJSMPdEfTnchXQuMvyNBfJ7VjGr0ATOs8pDurVw9SHkQYmUOI6P3uyJnqoEvLZNg+
         itjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BeNzPusIDU3pkw4QGstQMBC907hhG1JRGaXkU3J0URE=;
        b=kBDbPagU2O4GvHXGHKMMN/0PhVOO1GbUZQfe17B82IynFmaDNfDGSBmSCWYHEQUPZo
         M2Lon3w4cZsGu8z2vBsPKHlrpAdX4e5qHPGaIfyejxuMJq3A8EkvubYta2N/9zSP7IAq
         tuEgiNV/EdgmUkqNiyK/AHXAoBKcF6akqf+P7/UsTJgPC2Jsq0u3xAeKwsQd5ABtRrlg
         ELceC9saQUE/RZ+EqtCSyDT4ZpuW3FIjIKJOfC37pn0nxebAtfuQALDz8zt8tMiXuYR5
         8k55oxxtPvVFUzH+m/BoXN6gWNqe0rmXAHuMf3GHejnRYmqMOhC/lfB2JRFx+764PRG4
         J7Iw==
X-Gm-Message-State: AOAM533raMJwJHcfzxwBt7Cf8S97ZUUL2jn0LQwMhKGbFI07OSFbstOg
	4vWmpvdJUw85cCgVWl7hRvE=
X-Google-Smtp-Source: ABdhPJwIn8XNsEN+Dmh/H61lJYNQtI30mXbBbEbUtcLBqVd2pEoQ/vnnVPdHja6Bv/qWS8gBKWTHtA==
X-Received: by 2002:a1f:5fd5:: with SMTP id t204mr2798652vkb.6.1610554906619;
        Wed, 13 Jan 2021 08:21:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:5f0b:: with SMTP id t11ls127931vkb.4.gmail; Wed, 13 Jan
 2021 08:21:46 -0800 (PST)
X-Received: by 2002:ac5:c815:: with SMTP id y21mr2680004vkl.15.1610554906019;
        Wed, 13 Jan 2021 08:21:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554906; cv=none;
        d=google.com; s=arc-20160816;
        b=WJrr/rfPvAJ8+THOyPuvJgEnZ1lOhEpGLB9muV1L6PmoaArl0pzeqlEFQEKX7H7Pqv
         JEs/2F5mZacZfOVWFmyVT56lW5q1psshaCsgwmqBp9YjmgbBE2YZtsgyMWkVDb1Sp+Ds
         cgkW2yQPEsCgdipRtiob0OC2KPywIkKU5UmAef/aWac0OQfXGmt08wu+d8k7th4sAQPY
         61nwEx13pscNucTby/c2tkq66YmLDl/f8PgWfiXlwnofCQ7F8gSDtQ4fz25XZF50ObJw
         47tBBB6VeIDVbVvcYfKYDO3RyuR0efs12ernu/9JdsQ+6xS/sWUhn0BxbPGv+bcfeW1u
         O75w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=TpRL7Y20jiGyVCcZ/tWCsLwlWMyTmyOwumaDR68J98Q=;
        b=ucuWh3AH38j3qC3m0nwPekXubdzUedOGVTvuC9lyJE0z1xhlLhAsTO2nwLbwso+jR2
         VXBNpKbPxnpHyPGw6pwR+3Q3WeuAIG5Y+LnIzY1eKUjrwB/F+5F8Bp1jWcV7gxzTNr8p
         qwF3KLLT4dxgv3PpbNfXj+yJ8SbxFwW0a09cOpolMHLIQS8AeXteKX+2sCunarFkxITo
         TtCH680H3zzoEv3G57s9ho/XYuto9TDUIx729kKl+5k9Tqziz0jDC9SeG7lgwd5hr1rT
         dyBlvN7la3InmxnBe6OTY+R97Fk6Q5Ft8zgOXvIAevvQ6Jn46bc7Y1/SNwj9arJ+ic9s
         ZG6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kexc0GKf;
       spf=pass (google.com: domain of 3gr7_xwokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3GR7_XwoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id h123si139058vkg.0.2021.01.13.08.21.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:21:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gr7_xwokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id u8so1833298qvm.5
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:21:46 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b99c:: with SMTP id
 v28mr1527191qvf.12.1610554905578; Wed, 13 Jan 2021 08:21:45 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:27 +0100
Message-Id: <cover.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 00/14] kasan: HW_TAGS tests support and fixes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kexc0GKf;       spf=pass
 (google.com: domain of 3gr7_xwokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3GR7_XwoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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

Changes in v1->v2:
- Fix return values of kasan_check_byte().
- Use KASAN_TEST_NEEDS_*() macros for checking configs required for tests.
- Fix unused size in match_all_not_assigned().
- Fix typo in KASAN docs: "consist on" => "consist of".
- Use READ/WRITE_ONCE() for accessing fail_data fields.
- Doesn't leak memory in kmalloc_uaf2().
- Do up to 16 attempts in kmalloc_uaf2().
- Use kasan_report() for reporting from ksize() check.
- Rename kasan_check() to kasan_byte_accessible().
- Add a test for kmem_cache_bulk_alloc().
- Checks that pointer tags are assigned from [KASAN_TAG_MIN, KASAN_TAG_KERNEL).
- Don't run tests with kasan.mode=off.

Andrey Konovalov (14):
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
  kasan: fix bug detection via ksize for HW_TAGS mode
  kasan: add proper page allocator tests
  kasan: add a test for kmem_cache_alloc/free_bulk
  kasan: don't run tests when KASAN is not enabled

 Documentation/dev-tools/kasan.rst  |  24 +-
 arch/arm64/include/asm/memory.h    |   1 +
 arch/arm64/include/asm/mte-kasan.h |  12 +
 arch/arm64/kernel/mte.c            |  12 +
 arch/arm64/mm/fault.c              |  16 +-
 include/linux/kasan-checks.h       |   6 +
 include/linux/kasan.h              |  16 ++
 lib/Kconfig.kasan                  |   6 +-
 lib/Makefile                       |   2 +-
 lib/test_kasan.c                   | 423 +++++++++++++++++++++--------
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
 mm/slab_common.c                   |  15 +-
 tools/objtool/check.c              |   2 +-
 23 files changed, 544 insertions(+), 266 deletions(-)

-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1610554432.git.andreyknvl%40google.com.
