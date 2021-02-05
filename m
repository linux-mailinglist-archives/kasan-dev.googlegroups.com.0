Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ6N6WAAMGQEQBBGOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E22C310D38
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:20 +0100 (CET)
Received: by mail-vs1-xe40.google.com with SMTP id a5sf815765vsa.23
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539559; cv=pass;
        d=google.com; s=arc-20160816;
        b=fWiLZo13S8QqYzAWe0TZMQdwftrWXiUMVqd/uvXYJ22GAvOrnWq65VYw7j1+qMjRcr
         CZJVnYVNsXxVT+A4LrOCZxho9kNCf4bVUakCq7K+w1881j5Y6as8eQUoRU+41ysyBxxD
         lubHEDN2acEDh3MudsTehoERjdzQWfNX5qWQlgMDy2Klu7bXQWRDko8cuMWxYGvcIqDA
         V2nSXkW5fNzluuQHDs5EGMiLCNmEWH0AYi/05SrKvDFVpNab/KocwOegZFK/liRoIpTI
         wYmIVvE/kpaUN5PNssEb19yA/kzbbXbHvgdABJ2iZf7msmu6bxYGpwdaaFVaJbL2eZYk
         8AxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=Feo1JoP2NIYGS1n9JFGRLcqxDfGZjfWcjYfIzvqfTO4=;
        b=Hht0Z4UxkdJohW9ZM690JFUCRlK0/iI3IExPhQh2PztmCvFaKyODbXHIDOv9MZh2S1
         LnU3uoOohLLK4TDVJ7LCpVE2FWPcVj39cLHBSEWbuBHfhoOJJN1bZc6Pk2g57eNOHyM0
         yX150MDjynfowfeZUj3Yq3q2tj5DhoXKTlv5yK3cnZzJ4WOWhNfRYlZHs9B1LRgjtpJ/
         a33ofINxKLczfN+HdhNSWpdTMBpFzytyk2CSXO/g7A0QnV0Z6JPVpLYQg4ij0fe30Ccx
         fSBLb0vkm4HY3Le0KWPSsPiFDPs9ph/88iPFv5Lq1RXKXJD9E/adOZkHy03dQbQ1z5Pb
         r3Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GLpv906g;
       spf=pass (google.com: domain of 3pmydyaokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3pmYdYAoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Feo1JoP2NIYGS1n9JFGRLcqxDfGZjfWcjYfIzvqfTO4=;
        b=jh5T9ITkfp8zIcQHxGVMJeURYbOhbhj33uXpC23RCq6qd9Pr6+BiCd2Wq3GRBOS3LQ
         lV2br80Pq72rZud4EXGFmZx+PFeENBwSJz3kQkXqUKamvddfF7c1wPKfi2G0uTOviLaZ
         i1OBvYRsMRBgbEDbyoEXi9VmwiJHhXbiDi2CMV4AeIfz+IdNHXFJMICkQj7/wAdLL3qY
         e96iIUXwoNUXE2QHFc9xYV2Hcn6mQQgSopIwxDb2q6JMD7mtcalGQkyu2h0qSdmS8aUq
         i9reZirKnlJAQfBWkKNCHIcvc+93apbGGIZd2yHrObRMJ8OxwJx1w6HApIVleGG9R4wu
         1g7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Feo1JoP2NIYGS1n9JFGRLcqxDfGZjfWcjYfIzvqfTO4=;
        b=UOZcciQApeG6T3KrVsoDMDc5b/ptcjvLXLQWEDlhBJwNFI8ik1gF3xNFzICcELBNvF
         qB1idmB7iUGNSDiZtqJ6+V7ibYisNwwL4fftUxuna2ZbXhntblr0ExNO6CclBr+sbcC0
         aUMM4pLHe4ofvIJc3tiNTC1E/GfBBvuCrc4l5hg2eiRzH+nGkJV06vqthAfXL9lkMgpb
         84pUhTvMMv/+YYtbx5eOabTqYvP+ufZFXkMjxTBsuaWuYxSsMv8tIABxvghcKgXeOb6p
         dVHLqIDttYcjkoosL4fenSoYxv09UBTJgGgsxAmo58LBU+WgRCjHWO+QJjOToEb1lmCj
         Ci1g==
X-Gm-Message-State: AOAM530lU1RX5k1rvGrFp1OnOeiSO0Zk7cx+Egzq1zV6demXQqTaLLJE
	vcyMmFbXEPgTtZraMXnNEMc=
X-Google-Smtp-Source: ABdhPJx/UkLfSXFRT7x0uvKqrz2vK3fv8gcUa1g8eyMNF6b9imskQzQmzx8VnzApQJ3SbnMObQYfxg==
X-Received: by 2002:a9f:236e:: with SMTP id 101mr3671103uae.24.1612539559090;
        Fri, 05 Feb 2021 07:39:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8886:: with SMTP id k128ls1212150vsd.4.gmail; Fri, 05
 Feb 2021 07:39:18 -0800 (PST)
X-Received: by 2002:a67:df17:: with SMTP id s23mr3245597vsk.41.1612539558685;
        Fri, 05 Feb 2021 07:39:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539558; cv=none;
        d=google.com; s=arc-20160816;
        b=Z1YOf5hYLUZ2XjNoivNYxrNaRFctg2NPqgmwViHo/2Teic5kxPKl/48QR1i9rOre//
         p17XMoWGEOZPP3GO1IbI/G29S4/mMkSF8jQA6T9CpdVdjGtJ1tXwlG82oouBFp+ssDeZ
         YzoH9+fcdYA/Wvx5N+8FuH+bdK3lLXKGXeEOSwyAIKRzEoNuZcpph/aFQp6V1GeK0sEB
         gPZA5cezKCLhatqXA8JXd732qusKU6Up6AKlOV5lh8ZNTJK/rGAIOsF3YodbBdeJg3og
         j4wz62gFXHhbnsR/3oPFhj/LoAalv7avxhvUD/QLlXSgWt+XQhzv7aHBvbN/5Jawkjj3
         UXJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=PJe3Rz3EeSdJQyMwgR6n+MLd+6qUSUTULfhGZkHnlC0=;
        b=bwvQFACDmAmG4E9HmXYuOyU5nxXciyUyB8dXLEj/Ey0O30pm6sUQ6YhrUkDbGMFNDT
         1tkK6uuIO62b51KU+277VlzEKX9XVM+OJ4ePWmzeT+Qd+gV3RUCD1iM3s/AbFX48U310
         22WVicD0bUPsmVct0uBWbQ8R6sORkhRbqGaBjO7FcShAqex2FpHW0VNnGpU4GW+o2gZq
         mW177k+CFHOzy5NKWlavZF75XHfs/3LVBH20QBH/2p5ZNg5YYCS2+BMQAkwGtMN7oQBF
         mERLeA+q5VlFhqHJ1KyzCEzFryjM2intmWCzvl7+mhtS2EbEY/CZXLPPhnErwuien/f/
         1bQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GLpv906g;
       spf=pass (google.com: domain of 3pmydyaokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3pmYdYAoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id q11si714413ual.1.2021.02.05.07.39.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pmydyaokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id d194so6166495qke.3
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:18 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a692:: with SMTP id
 t18mr5040489qva.18.1612539558216; Fri, 05 Feb 2021 07:39:18 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:01 +0100
Message-Id: <cover.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 00/12] kasan: optimizations and fixes for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=GLpv906g;       spf=pass
 (google.com: domain of 3pmydyaokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3pmYdYAoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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

This patchset goes on top of:

1. Vincenzo's async support patches [1], and
2. "kasan: untag addresses for KFENCE" fix [2] (already in mm).

[1] https://lore.kernel.org/linux-arm-kernel/20210130165225.54047-1-vincenzo.frascino@arm.com/
[2] https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?h=akpm&id=dec4728fab910da0c86cf9a97e980f4244ebae9f

This patchset makes the HW_TAGS mode more efficient, mostly by reworking
poisoning approaches and simplifying/inlining some internal helpers.

With this change, the overhead of HW_TAGS annotations excluding setting
and checking memory tags is ~3%. The performance impact caused by tags
will be unknown until we have hardware that supports MTE.

As a side-effect, this patchset speeds up generic KASAN by ~15%.

Andrey Konovalov (12):
  kasan, mm: don't save alloc stacks twice
  kasan, mm: optimize kmalloc poisoning
  kasan: optimize large kmalloc poisoning
  kasan: clean up setting free info in kasan_slab_free
  kasan: unify large kfree checks
  kasan: rework krealloc tests
  kasan, mm: fail krealloc on freed objects
  kasan, mm: optimize krealloc poisoning
  kasan: ensure poisoning size alignment
  arm64: kasan: simplify and inline MTE functions
  kasan: inline HW_TAGS helper functions
  arm64: kasan: export MTE symbols for KASAN tests

 arch/arm64/include/asm/cache.h     |   1 -
 arch/arm64/include/asm/kasan.h     |   1 +
 arch/arm64/include/asm/mte-def.h   |   2 +
 arch/arm64/include/asm/mte-kasan.h |  65 ++++++++--
 arch/arm64/include/asm/mte.h       |   2 -
 arch/arm64/kernel/mte.c            |  48 +-------
 arch/arm64/lib/mte.S               |  16 ---
 include/linux/kasan.h              |  25 ++--
 lib/test_kasan.c                   | 111 +++++++++++++++--
 mm/kasan/common.c                  | 187 ++++++++++++++++++++---------
 mm/kasan/kasan.h                   |  72 +++++++++--
 mm/kasan/shadow.c                  |  53 ++++----
 mm/slab_common.c                   |  18 ++-
 mm/slub.c                          |   3 +-
 14 files changed, 418 insertions(+), 186 deletions(-)

-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1612538932.git.andreyknvl%40google.com.
