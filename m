Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4O5L4AKGQEVPPUXVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7252C22BE65
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 09:00:23 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id z12sf2547659edk.4
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 00:00:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595574023; cv=pass;
        d=google.com; s=arc-20160816;
        b=DNYsfJ0Lom+DYByXffGHvPtaGwE4JjubhCzDGGLTKejaPyk/a5juW17B9UzfBvjh78
         +AFN/abxGhMQBdoq12l7IK8aI6j0jMh3p3022avoPiuRawgZjUqXvGR8UF7uTV+xlzGI
         Gswe95OaWFM7XMv9F6fYlVC52IIupVmeG7NzT3vo0QLxBAeTFPd8cd6MRU8wSvzXrS7r
         B/4QeDoWJna8+BLTyiaIJhd4YrhW5VEp2fycOV9Tt7WTbRMpGSEu67xDoe8B0XkXA+ZG
         kxIqhl1tKtlkvuRk71ibxzcrPvF3X9A89T5hWGX3YaK9Pcr96qSk52E0+WwRS+HlHk3R
         IDjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=K43476UhZqo37bhIN1HPUvcUGvuDG89eRmegolbNRRQ=;
        b=d5KPBvMMG7HyiVLdGpxAF4MzEje5/DxXxSWNWhyl4wqFfCcyGKo0IFdpMm/n7x2n4e
         rskYjNu6mViXHAeq19ZPrbESqEVlpCR/sMDQwb+ZSvObd1sqUTNqF2d6wdVW1WJFCt1w
         zDTilMaUcOhXrEAvjMrcu44gM6Oap/VMcvkct7gY49xnxTmpBB3D4eHYiZI+QJ0yRGlp
         fZbgMREQCSRXw0UGU4YczxVVQxF9gYLglQwCZFTBoT9xlUU/TNwVJBKTbhKgnOmL/3eB
         hmJJp3E8Gs567hIEnMTy8spDlk2E93cI4VI7BmJwnqk3LKaaT5wy3xNbOZ+teuHSS2r7
         90Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VmnqZ2EA;
       spf=pass (google.com: domain of 3bocaxwukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3BocaXwUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=K43476UhZqo37bhIN1HPUvcUGvuDG89eRmegolbNRRQ=;
        b=An6tHpYBW45mf+U5BTTlGD5GOEghBzFtAbX7oYqsP0kddRgngeT4tYC8Xb1QFkzPvn
         /+Q3aaQU7bZ3JnMs+ZAkOI5FVjG4SfDsvfBMyVxVP5qNcpiQ1y0ltaGLPhq3diClhpXs
         jYj8nsMUhUN2UOwk2N+geNEPkKb4+WnepMzz9ExcuxHjLbez24iL2/MRoaJfNx5SgLvU
         K2yZO0AAKmGDEjVJik+uEmmcIAuI0BqyTFIQonF/LwJtQTAAVOuMyxn8UuT319ysnDpU
         StI0+Y7E8pIddpyFOzshkwxRRv2ffiXN0+kpdQFtuvsdWJ1Dtbl/UvoyhHCx92Z/kgVo
         9epw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K43476UhZqo37bhIN1HPUvcUGvuDG89eRmegolbNRRQ=;
        b=BfwRIot8eevf0+7HrJMriG3AjOIvHCZFUwD+gvjY3yBw6bl9UPR4IjPFgXpHlzfwlw
         I0Oi5LnesHITV2J0Gae7DXdzOQak1Wm7bapYvcHXciQh5z8oWQqH48uKNv1yST/E7Hwp
         NNRXsxYVabTnrNWBy2MEQlb0DTm5dHg1bxWmix8xeK8S+V4LFJ/mI8y/53yFdnrBqPR8
         3ndZtBVkHBsfb0kKIXAEBNqd9t26MNa1riVYGlV+kDqQA/vkjxs1nbhFsgP0Xf8hSPmS
         z80m5jU6gMXVhRSLOawMw18MDPF94AheThHyZ6aE9PYPlWC3oXPmCg2flOywp2fcAEQQ
         NU0w==
X-Gm-Message-State: AOAM5310c4kdpc2un8AH7ELqTN1jyKfcgoAkhMxjyufpdRO18HVFjNmu
	w0cKXgR46CRxzalERzxPV2o=
X-Google-Smtp-Source: ABdhPJyW+231NJ7OXS2iS6v3la+1b2OhSFnZ5x06ZkX3A9KMLg6Bl3qSppV8vQml3bSMXQoJeohN3A==
X-Received: by 2002:aa7:c655:: with SMTP id z21mr7717957edr.330.1595574023098;
        Fri, 24 Jul 2020 00:00:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7f92:: with SMTP id f18ls3812225ejr.8.gmail; Fri, 24
 Jul 2020 00:00:22 -0700 (PDT)
X-Received: by 2002:a17:906:7c07:: with SMTP id t7mr8131255ejo.487.1595574022476;
        Fri, 24 Jul 2020 00:00:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595574022; cv=none;
        d=google.com; s=arc-20160816;
        b=Bw6nKXfvVJpksNfeh0LTYJTTzkMJH3+t6ZkAlWB/Jxs4961Ht3MMbHAjbhw7sVZFkF
         JJrZFY6bY6mZxqsM3dzJvDvrglCMQDTCRG5RYjeVOccNnJ5xz8oMZimbgif2gkER+8MS
         DZy0ArAgW3qGPoWP1F5eKSdO10hiBYNwz5eqtQs5Rh4JE5Ay0w0AYcq1q8XG/1PUJV1S
         Ekd9GvghRftW45UwRorkUhckPr0POhzs2YBqisOD3UW6HvtD/iyPj2ys2+6+H0gpeFcu
         5jc+3pHk9+82I6tbKs5ttIqZu/KivYN6jB9DXPE1AuGp8tk2KA+dj+KTDLnr3QT+l2F9
         /t6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=nYhmgKcIIGxCsAi7Og+Yd3I+h1LrKRUSXiXnS3u5PnU=;
        b=utv9PwQJtKbEijoyZ0PdgvrCDieXR3FpQC7qafHzB8UD289OPm15kmozx/KQbjuign
         E3erer07YwLVCLYS2CkbeC8a3Xl+V5WwchUe2BV34RP6DfQn1qQXbn4Nz7+NRlGRagwr
         TZyXJsLNKgahmeZQn0yuxVgpRVF3N1XyEmBVyACrUswWCy7c4LaOmKDF3wmvoTrCzkJd
         04TpwYVm8XLC4H9r2RdWqSxYKb3PvX/EDUBz94jZuYPgzD7cvbsyRsicRC76B79qtg4d
         LjtFNX46TMmnRAdGR1aek9SsOh9XnCvUB6OdXY+LesskUxqE3gIDHzKgEOtAiWVBCZQM
         AyaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VmnqZ2EA;
       spf=pass (google.com: domain of 3bocaxwukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3BocaXwUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id q9si3353ejj.1.2020.07.24.00.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jul 2020 00:00:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bocaxwukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id a18so1881285wrm.14
        for <kasan-dev@googlegroups.com>; Fri, 24 Jul 2020 00:00:22 -0700 (PDT)
X-Received: by 2002:a7b:c4d3:: with SMTP id g19mr939521wmk.29.1595574022053;
 Fri, 24 Jul 2020 00:00:22 -0700 (PDT)
Date: Fri, 24 Jul 2020 09:00:00 +0200
Message-Id: <20200724070008.1389205-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH v2 0/8] kcsan: Compound read-write instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VmnqZ2EA;       spf=pass
 (google.com: domain of 3bocaxwukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3BocaXwUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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

This series adds support for enabling compounded read-write
instrumentation, if supported by the compiler (Clang 12 will be the
first compiler to support the feature). The new instrumentation is
emitted for sets of memory accesses in the same basic block to the same
address with at least one read appearing before a write. These typically
result from compound operations such as ++, --, +=, -=, |=, &=, etc. but
also equivalent forms such as "var = var + 1".

We can then benefit from improved performance (fewer instrumentation
calls) and better reporting for such accesses. In addition, existing
explicit instrumentation via instrumented.h was updated to use explicit
read-write instrumentation where appropriate, so we can also benefit
from the better report generation.

v2:
* Fix CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE: s/--param -tsan/--param tsan/
* Add some {} for readability.
* Rewrite commit message of 'kcsan: Skew delay to be longer for certain
  access types'.
* Update comment for gen-atomic-instrumented.sh.

Marco Elver (8):
  kcsan: Support compounded read-write instrumentation
  objtool, kcsan: Add __tsan_read_write to uaccess whitelist
  kcsan: Skew delay to be longer for certain access types
  kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
  kcsan: Test support for compound instrumentation
  instrumented.h: Introduce read-write instrumentation hooks
  asm-generic/bitops: Use instrument_read_write() where appropriate
  locking/atomics: Use read-write instrumentation for atomic RMWs

 include/asm-generic/atomic-instrumented.h     | 330 +++++++++---------
 .../asm-generic/bitops/instrumented-atomic.h  |   6 +-
 .../asm-generic/bitops/instrumented-lock.h    |   2 +-
 .../bitops/instrumented-non-atomic.h          |   6 +-
 include/linux/instrumented.h                  |  30 ++
 include/linux/kcsan-checks.h                  |  45 ++-
 kernel/kcsan/core.c                           |  51 ++-
 kernel/kcsan/kcsan-test.c                     |  65 +++-
 kernel/kcsan/report.c                         |   4 +
 lib/Kconfig.kcsan                             |   5 +
 scripts/Makefile.kcsan                        |   2 +-
 scripts/atomic/gen-atomic-instrumented.sh     |  21 +-
 tools/objtool/check.c                         |   5 +
 13 files changed, 354 insertions(+), 218 deletions(-)

-- 
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724070008.1389205-1-elver%40google.com.
