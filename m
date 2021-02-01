Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3NT4GAAMGQE2ILU5JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A33230B097
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:43:41 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id u3sf10964855wri.19
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:43:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208621; cv=pass;
        d=google.com; s=arc-20160816;
        b=AIwDFq2kX+Ti4DpB6QipDATKIbMuKoCLK0v6dQcXFVlozc4g1Qn/9L52eM7Vn96xtE
         f4abCE6jOEpU4/GDq8oRQxN3cid3NI3vqlPgaEG9Ef+S7oFNHxkXSiVmj38ZbPoFdbn/
         PDFG0SjdB3hHBMz7TntFNK8kPhUMwhr4r28sIrZxGlkGl9V7+IktF8VdzAxMtCLJAR1z
         wWLDPNQCoOnlADKteQGWcqUQohVIcQvxUfnXVSQsnyAMNd70im/YW7jUJzrX45vsrkJl
         zvYZLHzpWW42+EDbGs7Em0Kfi67NmLzBfhOkYg6au+gGoAV4yiCaUVEfckpcOzs8WbKH
         K4PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=fv/sQcvRHSkGNWGWw6LKTggLlm7V0EKZDZZxYkAJcKE=;
        b=Afez/VIkUZ7gCWeL9uXbqMprWCFmy+PIB/g8KPGilH3e/NWyEe90LBg7FuTcODL59q
         paY/wmmbTOKDN2tH/DRvqt1H8v2qUpgv2E+owXHYMSL4dMoFohGqNpHxuwKuSc58bE9Y
         VbUIBtEXSz5aPkvfO6WehlTUlJSE5Rykcz7Qv2Zs2JqWxXJhOr7IrcNUwnFcLXPbv+51
         NarUyCB0vYh4kvwzqAUyZh8vFMPkXQFo5omYidoc2R6NAnyZ6D/i/IMmf6vNCACJwWbw
         rctanNZyDWcN1nwpySFXx8RHI90PVO0cGAOFgdhYbzSm36G9WbSeanvuxAX2zsx1xV3r
         EUNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sCPdWL3T;
       spf=pass (google.com: domain of 37fkyyaokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37FkYYAoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fv/sQcvRHSkGNWGWw6LKTggLlm7V0EKZDZZxYkAJcKE=;
        b=cDWSw6FLS/46MBAdxZZjDzIXGW/k+j+qOIL9QHESl7udwe/CeN0TqieqrzSl/lCy14
         7f6UpiXIDWyeJmxpNTQlLqK74GIIO9++Q/2FuFwkTnvyUkI+SMOsml1cK4qnSChGxBjQ
         p9ttMmlFJyR3Farvq2hMra6b+nDCCkXZ3sqor0Q2r3BPpvNwxur+nlNXJfnLkoLjIlq6
         GQ6B+7mXgU2YggwB62ICmcwGY4A/nTQvU8gTpkOuifyn4vLK24WQ7Khu3Mbfvs1rZdhz
         r5et08L2mt5ok1AJIux7HBATBR0G5QtFX9yiexHoCMUBOykdOIHlt6IESkYXg0QAHzqI
         iMgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fv/sQcvRHSkGNWGWw6LKTggLlm7V0EKZDZZxYkAJcKE=;
        b=qyU8Xj73SGKIBWd5QmRS+Naycf8ekhukXGws7fDBGTVUYKpOgbT9/UY0Z8AaEYMncI
         1swOG4jo4XWQRihP47PnrxrAklT5PkPh4sqeVJONY2FpdizPs0nwxRGIHquCQxlSqstM
         otHyMz1ZMKgGZr1SeXH7VB693FfmCPwVdY8aCTrqNdTys6awGD+AcKYMS06t0gz8uJqB
         uvPP/M3N34t6MXeXm/aVykM/6IT0HMOSIQOG/C3Tlvie597LfaODr4iJkX15PT3XDDzo
         D6SJobrn8CRV51O3BW3od5940h9/G0MHmK4Q/Lh5tRcU/NhsXDV09XpKY8hpX3zG1sUC
         qJ0A==
X-Gm-Message-State: AOAM5328LN/i1xZC9czJ3TWRIUN13PhLfp0UyLOcKe1U7oA25KO1gQ62
	UX9udVt5nuS2DrFcWn+wxPs=
X-Google-Smtp-Source: ABdhPJxpc/RWHFh3XLtlm+zZihCvg3a/a+Qr+YmLOw+NqoMwEYf4HImjCyvDxNbq8dNqGdB28UTnjA==
X-Received: by 2002:a5d:5051:: with SMTP id h17mr20694929wrt.164.1612208621358;
        Mon, 01 Feb 2021 11:43:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls127683wmb.2.gmail; Mon, 01 Feb
 2021 11:43:40 -0800 (PST)
X-Received: by 2002:a1c:f312:: with SMTP id q18mr392916wmq.79.1612208620591;
        Mon, 01 Feb 2021 11:43:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208620; cv=none;
        d=google.com; s=arc-20160816;
        b=D+AovMwp/KFwf0a9ghD1oUXXT/hwsLvrivPj5AhfkJOopl79y9HoUdMk0StsvndqYY
         6RTvCpafbvO4oYqjtnZaIcC3ALIKVD1Jj57y2eX8hZyTo2lLRjEiU9cxAGZVfW5ntQUj
         ZoOOk/rjmmgbcEI6ThfvAEqXrkYYEuI4HMaIoSGA4FHNMtmNzEj0UjD9JPsUw6CF+0P+
         OuCLTl5dylTaoRCPCyQol01TT0RnqwwU+JhJixpUIFbRnoxtPG1Xn8mD44T4wwMkRQzT
         7tk2Xfkpq9SA9+8nVpbW4o8FlVsb42OuGcHkBajOTlJ2V+g98lKlTM0mK83qWBXW6liU
         O8Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=rJ16AiwqkpNVRFh+KkU2Ds7vTu96Je2z+5GU1bmSu0w=;
        b=U5G9KiEtsury7IAl73cWVFOkjPoDfIu4bMuAbKJQl3UA+85UDiPP430+R+pt4owy7b
         I1E8aAAgRXhTuZvXLU2pZ3OfaDEHhYixJrf9I4ghElXu6/2v8bL/xkxyNaNNJVQQO3X0
         dn2oFQec1Q4cv89n8njXFuR+6d1RSal6J62uxkPntnTj66IaD/TxWU3gM0VHfbIcw4si
         AzGU28l+dPi3gxTvY+qusQP7MPr2LImqu6nup++mi6fHXVn8GBryYQbLDnKEjJC1zQfv
         cHRBGxsAdO6RcJeUsRvRkqEvEOs3NXLEYKxtlZaDTCvSZOK8ppvumoHCTzFW9FfK9kPy
         wKrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sCPdWL3T;
       spf=pass (google.com: domain of 37fkyyaokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37FkYYAoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id n7si1000647wru.2.2021.02.01.11.43.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 37fkyyaokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id s10so165521wme.8
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:40 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:356:: with SMTP id
 83mr415730wmd.31.1612208620129; Mon, 01 Feb 2021 11:43:40 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:24 +0100
Message-Id: <cover.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 00/12] kasan: optimizations and fixes for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=sCPdWL3T;       spf=pass
 (google.com: domain of 37fkyyaokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37FkYYAoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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

1. Vincenzo's async support patches, and
2. "kasan: untag addresses for KFENCE" fix.

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
  kasan, mm: remove krealloc side-effect
  kasan, mm: optimize krealloc poisoning
  kasan: ensure poisoning size alignment
  arm64: kasan: simplify and inline MTE functions
  kasan: always inline HW_TAGS helper functions
  arm64: kasan: export MTE symbols for KASAN tests

 arch/arm64/include/asm/cache.h     |   1 -
 arch/arm64/include/asm/kasan.h     |   1 +
 arch/arm64/include/asm/mte-def.h   |   2 +
 arch/arm64/include/asm/mte-kasan.h |  64 ++++++++--
 arch/arm64/include/asm/mte.h       |   2 -
 arch/arm64/kernel/mte.c            |  48 +-------
 arch/arm64/lib/mte.S               |  16 ---
 include/linux/kasan.h              |  25 ++--
 lib/test_kasan.c                   | 111 +++++++++++++++--
 mm/kasan/common.c                  | 187 ++++++++++++++++++++---------
 mm/kasan/kasan.h                   |  74 +++++++++---
 mm/kasan/shadow.c                  |  53 ++++----
 mm/slab_common.c                   |  18 ++-
 mm/slub.c                          |   3 +-
 14 files changed, 419 insertions(+), 186 deletions(-)

-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1612208222.git.andreyknvl%40google.com.
