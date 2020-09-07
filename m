Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5XQ3D5AKGQEBMKVRKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5531925FB8B
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:11 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id g79sf4927547wmg.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486071; cv=pass;
        d=google.com; s=arc-20160816;
        b=fbWm3gGrGiYP2pN2xHulprYw1BYjI+SW0MtZlOVv4IZ2773MBp39F1+JK/5Cxh7G0t
         /ECH3bWil5+PHjlMRkWpBTgiKotVqUJ6VIBrfu502yg243NLXmzUK7+n3xy0krixR8vn
         SvN6q5j954vjvG6O31VQHkpYLGSaZMCLH7jIiCfmT7VGMMHEv46RfabWuBEJh3JP8tcF
         koF0pg5gNrSt8xz2GBujz+iiTNdl2tPPQJ45nLo+grbAZdfSkkaIm6zP5/O5bGuINZ0p
         f5xAVLBVOi8GUQSLuXvBfe9BmgOvxKv5eJ/3L3RRGamdUipURNOvfo9WGTKbgVfVRT0J
         F8Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=rWDDPtGFlvsZ05uDCdYL5wxLmnimw+N5wpKp+7pukjI=;
        b=wyX1DjOciQHIiCr9pd6NEUo4Mq8am4k/yQoWzmES1LWdgedATyceGPZM09B8M0+ErY
         6fHpiNxXruuBJHkwviOBTQEkusXHgj89+zRJbJReJWPCqhADdEuSIkwDJzP43j3kD19V
         zMtHROFD7WeSMrulz66UKWv/I3mJhjY5P1Gk9O/72rIm1ewDVRVk6b1kAXAYjcTPUB2G
         n574E2EzL+DGubEknCjtURfMwaRnEOR5FdT58pfuUBBeFwS52OO+yTWaEp66w4vrBZQx
         crZFlUVfY0sYh08Z4X7gOluPUsqTNLUFW+oaqv8mYOO5fjUmjz0HQ3Vj/NyvBH6oqXHW
         eVtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gi64PDyC;
       spf=pass (google.com: domain of 3dthwxwukcuagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3dThWXwUKCUAgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rWDDPtGFlvsZ05uDCdYL5wxLmnimw+N5wpKp+7pukjI=;
        b=ieXI+IB5eKqsrc5LSjpc3QX9xFdeQDzjBm7NIp8SpYqlAuKjbFOlCmD/qqmLzGI4cn
         g5tEeH5v9HgTY0cD0qMfSLzgnPnUTR552Qt99qfzdLOP01ZnIKUCxyTwMt7cf6x7JkkM
         NWtqmFe48fb1zspjYEkFZK6Q54i9/866rk09zj7N8tmjSiRcg1DEVzJcUYcC8IpCRal1
         ix2xIwiTIFRtIwzk7C5n8ZrU64HeVeQfnp6J187i360WEaR8V9SZaMKq8Pr4/ET1cflh
         GxPod/K92FVYIvs631rkR3HbUhZqgeUj2/uPEIj3ZIYPUCpldmrhaNvY97UtcmabUJgJ
         000A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rWDDPtGFlvsZ05uDCdYL5wxLmnimw+N5wpKp+7pukjI=;
        b=b8u3L/zHYCkFMUe5JBnIfoa7ZZboqe8lz3yZg99B5DUbhFPeka40Td15NpXvFXJpUl
         yW12J0f4c3sO5OTvTSIMkI4s6t2MdSK/Pv9zsty/Hw2cIEN6/5dPUcw4lkG9h+mbPZyD
         wp4eWg/4MU9JdefPocnDcrNThc3Vz/mmiQmWbj0pkjyVLoSIcOJGa9sWPd8uk2wtAWGI
         VUdla8Fn53XHd5ZIlkl3CwnJ0CbI/sUXGt4hQS9wxYdT/DioSS+jgGnPlpTY1PTiw4eU
         Mwpkt/B1ZSJcSmnTOkUjTRyUaIapEs4VwOX9juEdqEPgyyDA1hzi9E2wlEzM8FIQYQRc
         jrdQ==
X-Gm-Message-State: AOAM530cFFHcuWvFHiMZ8mX0BrMrt2k7ZlTXkHwS2BU0+FesDaXfz1t6
	FFMHQPtS5OIU1QxTFuEJxpI=
X-Google-Smtp-Source: ABdhPJyjKvUZMbTbc7/PW5JAwmH3qfcd/i80gUvpiEr5LS2/mwJAqdSaQCduRo3LQGnqywrRDbMHqw==
X-Received: by 2002:adf:b442:: with SMTP id v2mr23387518wrd.213.1599486071031;
        Mon, 07 Sep 2020 06:41:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca44:: with SMTP id m4ls8208887wml.0.gmail; Mon, 07 Sep
 2020 06:41:10 -0700 (PDT)
X-Received: by 2002:a05:600c:230c:: with SMTP id 12mr19958060wmo.23.1599486070047;
        Mon, 07 Sep 2020 06:41:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486070; cv=none;
        d=google.com; s=arc-20160816;
        b=qvCENxJcMkuq17YYv4QV85ZtuyDDyBWoKexc1dk9qXzbQAzN9DJcPt0RSl8WA97M1u
         PfL+hXVCb/d1YuAeiMeyX/LIoYa5G/yBzxIVD+aB9dPmB7kJmob+bC0nO/dT2GM8610I
         F9Wz7CwwkwiT0NycoUprmHmQIJCxqx4AMq49P8Kuj69K3kQBKfWjC5Ns9MjhSCddp395
         aszJ+xWMakz2El6ezpH7zDwTQptrmZ9FkErTNkzooVUKEYsGcgLOdYJS1cJfrPhOxLyh
         bT+TkN3eJjGM4WWH5bPyeqwwhu8qdocE9E2g3ZzDnAjMnKGwtmFl1GWyOeHtioTm8hPU
         /6Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=06/chDIM1D/CQyVkMXWbiHKfJ0qcUiQ/wlOCjUIfV4g=;
        b=lVYxKHnUkZ9Eafj+EHvGdp9v/H/rbeyjbpId9LMg3Wjs2e3mVPNEWmyXP9KjzgIufp
         Z87Mo3WkBsnbYaK15XRuyXhuFffRa3JJUi1zr6DhyzE37/2GuMfBbhyLA/J2vXW+6FHH
         yL6nL85MXL94txdlhrc+c75TmG4Fl+DI7Tdm5ecyZcpU06YuNAiM0ohdgpKEbhhd66v5
         iImTYSTh1+pTJtl9jgdK9mDoCo4PewcROodciQxAJ4BN77Zy8TCkPsx4mpywxQZ65CIP
         TtD561P+yZwzx5Ms8pQuf7UOV46CGa4FZiGDKd0sjIFFdZEcNBVmpTmowwaU3+vAtTTr
         nH/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gi64PDyC;
       spf=pass (google.com: domain of 3dthwxwukcuagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3dThWXwUKCUAgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f134si845333wme.4.2020.09.07.06.41.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dthwxwukcuagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id x15so4858365wrm.7
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:10 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:ce0d:: with SMTP id m13mr22014038wmc.83.1599486069496;
 Mon, 07 Sep 2020 06:41:09 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:45 +0200
Message-Id: <20200907134055.2878499-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory safety
 error detector
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Gi64PDyC;       spf=pass
 (google.com: domain of 3dthwxwukcuagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3dThWXwUKCUAgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
low-overhead sampling-based memory safety error detector of heap
use-after-free, invalid-free, and out-of-bounds access errors.  This
series enables KFENCE for the x86 and arm64 architectures, and adds
KFENCE hooks to the SLAB and SLUB allocators.

KFENCE is designed to be enabled in production kernels, and has near
zero performance overhead. Compared to KASAN, KFENCE trades performance
for precision. The main motivation behind KFENCE's design, is that with
enough total uptime KFENCE will detect bugs in code paths not typically
exercised by non-production test workloads. One way to quickly achieve a
large enough total uptime is when the tool is deployed across a large
fleet of machines.

KFENCE objects each reside on a dedicated page, at either the left or
right page boundaries. The pages to the left and right of the object
page are "guard pages", whose attributes are changed to a protected
state, and cause page faults on any attempted access to them. Such page
faults are then intercepted by KFENCE, which handles the fault
gracefully by reporting a memory access error.

Guarded allocations are set up based on a sample interval (can be set
via kfence.sample_interval). After expiration of the sample interval, a
guarded allocation from the KFENCE object pool is returned to the main
allocator (SLAB or SLUB). At this point, the timer is reset, and the
next allocation is set up after the expiration of the interval.

To enable/disable a KFENCE allocation through the main allocator's
fast-path without overhead, KFENCE relies on static branches via the
static keys infrastructure. The static branch is toggled to redirect the
allocation to KFENCE.

We have verified by running synthetic benchmarks (sysbench I/O,
hackbench) that a kernel with KFENCE is performance-neutral compared to
a non-KFENCE baseline kernel.

KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
properties. The name "KFENCE" is a homage to the Electric Fence Malloc
Debugger [2].

For more details, see Documentation/dev-tools/kfence.rst added in the
series -- also viewable here:

	https://raw.githubusercontent.com/google/kasan/kfence/Documentation/dev-tools/kfence.rst

[1] http://llvm.org/docs/GwpAsan.html
[2] https://linux.die.net/man/3/efence

Alexander Potapenko (6):
  mm: add Kernel Electric-Fence infrastructure
  x86, kfence: enable KFENCE for x86
  mm, kfence: insert KFENCE hooks for SLAB
  mm, kfence: insert KFENCE hooks for SLUB
  kfence, kasan: make KFENCE compatible with KASAN
  kfence, kmemleak: make KFENCE compatible with KMEMLEAK

Marco Elver (4):
  arm64, kfence: enable KFENCE for ARM64
  kfence, lockdep: make KFENCE compatible with lockdep
  kfence, Documentation: add KFENCE documentation
  kfence: add test suite

 Documentation/dev-tools/index.rst  |   1 +
 Documentation/dev-tools/kfence.rst | 285 +++++++++++
 MAINTAINERS                        |  11 +
 arch/arm64/Kconfig                 |   1 +
 arch/arm64/include/asm/kfence.h    |  39 ++
 arch/arm64/mm/fault.c              |   4 +
 arch/x86/Kconfig                   |   2 +
 arch/x86/include/asm/kfence.h      |  60 +++
 arch/x86/mm/fault.c                |   4 +
 include/linux/kfence.h             | 174 +++++++
 init/main.c                        |   2 +
 kernel/locking/lockdep.c           |   8 +
 lib/Kconfig.debug                  |   1 +
 lib/Kconfig.kfence                 |  70 +++
 mm/Makefile                        |   1 +
 mm/kasan/common.c                  |   7 +
 mm/kfence/Makefile                 |   6 +
 mm/kfence/core.c                   | 730 +++++++++++++++++++++++++++
 mm/kfence/kfence-test.c            | 777 +++++++++++++++++++++++++++++
 mm/kfence/kfence.h                 | 104 ++++
 mm/kfence/report.c                 | 201 ++++++++
 mm/kmemleak.c                      |  11 +
 mm/slab.c                          |  46 +-
 mm/slab_common.c                   |   6 +-
 mm/slub.c                          |  72 ++-
 25 files changed, 2591 insertions(+), 32 deletions(-)
 create mode 100644 Documentation/dev-tools/kfence.rst
 create mode 100644 arch/arm64/include/asm/kfence.h
 create mode 100644 arch/x86/include/asm/kfence.h
 create mode 100644 include/linux/kfence.h
 create mode 100644 lib/Kconfig.kfence
 create mode 100644 mm/kfence/Makefile
 create mode 100644 mm/kfence/core.c
 create mode 100644 mm/kfence/kfence-test.c
 create mode 100644 mm/kfence/kfence.h
 create mode 100644 mm/kfence/report.c

-- 
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-1-elver%40google.com.
