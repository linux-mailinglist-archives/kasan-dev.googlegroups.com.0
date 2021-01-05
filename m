Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMW72L7QKGQENVWKOEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id AF3832EB283
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:03 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id c13sf537781ilg.22
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871282; cv=pass;
        d=google.com; s=arc-20160816;
        b=e0EjzMfH6BijJZMySV6uziKLXXt3D10Bqek8g3XYyUS8Jh2z9ujR+AQsPMIGsIi75A
         IozrPE18czX/w2EGBD/qe6KsUR9sNtsonkTn/FFQj43IP4zL08SsUn7ReKsKZ749vPA8
         wMSOGdOPGAtXAol4iCM2Q7JYf3qZU1jm9kmX6BuDxTfV17r8E0oRfJpM4StMOf4Ym0bB
         10d6khhWvFXGTgEwpvKoNuUh2aapXhejThfRDUrBaClGdilM96fDXfUA7vlSz1mMwfq7
         UQP+BGJNhOW5pWszyDKUlFOrFO/gTpzIV8Emar4ANlxIn1spE3/iV9eiKFqjLEDlRvtm
         Ac5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=poBpY2qglbkZmwkZClTP6tOT1x+N3qjgRzfEEBGDrZY=;
        b=vm7YCy4mEZ76hDFDjd8SmW1XKC6xvQM1vJCk3ee4Vxz3YMLL2/aM3izBAm4MhyR24P
         vAZYY1ZkCq+YJmcxz3tYpJEiS6G2IjTGi33k3ebjqw/0bPxq20hL3RxVTtmOFH2i21CM
         BaOeqOxvHG+keAAJh1i1Vh6AiHfNJb84jk3dpODHEuQP7YCapusR3Ci3Y7kxZBEg1jns
         nLICU/IUOzrJ5nnu539Lm7tCNC1yI7mWzpjSMrtYbqX9+ncyGYDu4movH74g/TaMURcM
         fv51UGSOt4eBOhgs1CQfCgouqHYkf+vU2fLAN0ccJrbsd7/gyo15XM97btcnkXrcC+O0
         t0xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v5sqPJZx;
       spf=pass (google.com: domain of 3sa_0xwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sa_0XwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=poBpY2qglbkZmwkZClTP6tOT1x+N3qjgRzfEEBGDrZY=;
        b=EYWFXGfImh3XtEmXozpxfqIHOpnhZ/lAfuGpZv1MJsEMGpOB90enwBGnlS4hyz9OAP
         1NYhqnF4YQnRLmcCIf7qSmiy+APFHPDjg09C6BdOYqirIAxzBadoXmP3ZhEJhJHj6yBg
         gLNpeRMfdQ/Wud0dUZEGlPnx2S2vzxygqaWYJTRLAcFI6pyDe+NcuPRiHakvfhF6uf0u
         NiCvrwZJAApDAc+tUMC+FGEsXXTea5v38MU70K49aQne1Vm1sk3c/fTAMBQqZqe7+OMn
         6Y4Sa9saKmP93aN0xmLF+WI+TGFM2ANzbA+8gqU/WYpJUd6W7VjSkBXHr7xvr1OPK1st
         pIig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=poBpY2qglbkZmwkZClTP6tOT1x+N3qjgRzfEEBGDrZY=;
        b=h9k9Mzt6jNatog8d8zEC+Rc+XATwlCdaZByKh3gPYI6a1WtrK0U6m7yp/Nm8y780Sw
         hfyIXN0j1rcWZSBy4ITmU2xpwpwIO5wngrHauIwwuH0Be1AfSqq06iEjibX+n+omAdKn
         iBsjhrPxA8Gg+amo5Dp7bPT39OK82Hog6bqhS3ih0nxNJMC7R8MYf28kk2twkI4asRLW
         9FCY9g2t0/NLO9UWc6mMwSZPRHMjI+rD+2bNTBpD21ZCn6uRCJOyjFV17d5te6vN1n1i
         i0jBZMNTxkxcyS11nJjrPi9HC5hOVF9Q0wetUeiHiQEU2JuRe/7tIS7Quwp+XIxg8cfr
         MC2Q==
X-Gm-Message-State: AOAM533+tbbBvmlT6hjzYt4x8vHONCZqRgiIuFrHbDM6cmfZoAATwJKI
	MP/oUBP8ilQWpZXlZn/q1eA=
X-Google-Smtp-Source: ABdhPJztdYurdGbxAmh3qp6SxT49WdAUzCEFtHtPN6lHzbpoCAFnE4UMHx1HLBvSwEZE9jWH97hyTw==
X-Received: by 2002:a05:6e02:1a04:: with SMTP id s4mr914074ild.8.1609871282631;
        Tue, 05 Jan 2021 10:28:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6cc6:: with SMTP id w189ls18414jab.4.gmail; Tue, 05 Jan
 2021 10:28:02 -0800 (PST)
X-Received: by 2002:a02:8622:: with SMTP id e31mr819065jai.88.1609871282265;
        Tue, 05 Jan 2021 10:28:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871282; cv=none;
        d=google.com; s=arc-20160816;
        b=GIRcblNqozHBNY990Fdhx/i/y8NDxiFITrrqleTAYnb1QCtGbAF/zrRv1OezlbCHrY
         bqDneeQybWDxSC2EgkvKo4bYZZaaLBcJy5d637JNoh+pSXaqnGRwZDQ0W9pbG371hBGI
         DGmdLbM7qoJ1TOzVgjMByZAQoGtO7BRJQKa8Xdg/NhRXKRFgS0t1S4nfKccmOlAOoMHx
         BNLmFgjor09DayIqKkaHSjJ1KiQ/5kOtb964UpbdSaxGA6FS9mu2CuFP7ea4KEGoktab
         AMorUtgUe0WGnn2P2PZlmyPxEYcyJF74z0NjudNUmBhLs6Ozd4B/X6XA7WekHRJoN44B
         5geA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=nYphEf0EMXtBFuH3fG+hMPTfNDw2lJ9R5ysG4cvqPlg=;
        b=cEmcZt6ReJnAiEZ0z74gBjxCXL6bZ3Efc2iCVd/v7xlchhLjD5bYaHEljluRIKmMAA
         ArQzJ2HcJTYBBUHevRgq7fRVHmY44VB0J8Xg7HwZIg+lrTyjaXKrgJZ35ELHiNMg+Rjj
         e4G0D2FuMgeSsU65UQk+ZD0X1Z/sC9nZbGapYKdXjIQpq1nAqy9N7w367pKVNXIMFSih
         14EQSteVeQm9mbxy3vzt7QPa+J6me3z9HKtTOyUevUSjdxn1B0+ezzYycGzd2LysC+vz
         w4IqghOI3UiFqPSh5tBtRlENpVb2aGLptYSfgFo6Jg48fvDzOyoA7ojBxw8fn0Vqqa+J
         i9pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v5sqPJZx;
       spf=pass (google.com: domain of 3sa_0xwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sa_0XwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id j4si13540ilr.2.2021.01.05.10.28.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sa_0xwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id bp20so350657qvb.20
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:46e7:: with SMTP id
 h7mr858980qvw.44.1609871281623; Tue, 05 Jan 2021 10:28:01 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:44 +0100
Message-Id: <cover.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 00/11] kasan: HW_TAGS tests support and fixes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=v5sqPJZx;       spf=pass
 (google.com: domain of 3sa_0xwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sa_0XwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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

Andrey Konovalov (11):
  kasan: prefix exported functions with kasan_
  kasan: clarify HW_TAGS impact on TBI
  kasan: clean up comments in tests
  kasan: add match-all tag tests
  kasan, arm64: allow using KUnit tests with HW_TAGS mode
  kasan: rename CONFIG_TEST_KASAN_MODULE
  kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
  kasan: adopt kmalloc_uaf2 test to HW_TAGS mode
  kasan: fix memory corruption in kasan_bitops_tags test
  kasan: fix bug detection via ksize for HW_TAGS mode
  kasan: add proper page allocator tests

 Documentation/dev-tools/kasan.rst  |  22 +-
 arch/arm64/include/asm/memory.h    |   1 +
 arch/arm64/include/asm/mte-kasan.h |  12 ++
 arch/arm64/kernel/mte.c            |  12 ++
 arch/arm64/mm/fault.c              |  16 +-
 include/linux/kasan-checks.h       |   6 +
 include/linux/kasan.h              |  13 ++
 lib/Kconfig.kasan                  |   6 +-
 lib/Makefile                       |   2 +-
 lib/test_kasan.c                   | 312 +++++++++++++++++++++++------
 lib/test_kasan_module.c            |   5 +-
 mm/kasan/common.c                  |  56 +++---
 mm/kasan/generic.c                 |  38 ++--
 mm/kasan/kasan.h                   |  69 ++++---
 mm/kasan/quarantine.c              |  22 +-
 mm/kasan/report.c                  |  13 +-
 mm/kasan/report_generic.c          |   8 +-
 mm/kasan/report_hw_tags.c          |   8 +-
 mm/kasan/report_sw_tags.c          |   8 +-
 mm/kasan/shadow.c                  |  26 +--
 mm/kasan/sw_tags.c                 |  20 +-
 mm/slab_common.c                   |  15 +-
 tools/objtool/check.c              |   2 +-
 23 files changed, 484 insertions(+), 208 deletions(-)

-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1609871239.git.andreyknvl%40google.com.
