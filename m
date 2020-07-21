Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR4H3P4AKGQEPFP6DYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 60E0D227CFC
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 12:30:32 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id x13sf2455724lfq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 03:30:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595327432; cv=pass;
        d=google.com; s=arc-20160816;
        b=vh83Ifg4MZhS+oJnQ0Z52RDqL4qsHYhS1QDJeqq+zkc5qHjLVV0PCf37mtc4Qu2IiP
         wppQgdCf9PfX2NaYKKp7zpkqquEIS5f5KXoIefn76342k1rh5eKbJwKQcH+muCXQ7rh0
         iBrBbQ3mE3NHsr3dIKLD1BKlry0V/IC5DxKjxHRpB58QYKOJ9rLEniH4Dqs8FXjAIdZK
         koEfNEoREnhDdwMhRbK5xjiQ66+0MjsvMUO/s46Vz5RhQvCvKDSwTXPzwTMHXA1SE6Ac
         TLH3zJ2kRiz2FYBp2NHMBr6BeHMlWbXoosXLGKfdtQRocka/GzfxeKA/QzVnF3R32b+W
         T7uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=nt+f9lHMCXP6jSwrUQxP1C310r6+M3k8sre9gc/IdNQ=;
        b=bKYGKUKuK7/NJR15W3IVUXzwer7yk8JgLtTLPcNi+BVikaM34omouoyODOjzAtXqKv
         Tms22laR+ECWXYjQladD1huRFEXYAfYy6S1oIoxIYNjbfCQf/JGCOkzB6twJn904ClUE
         OIa3Ko7ayxGpXwGHcSUEtDXgHCtO3B0lVswmgj1NOQrTAav3AsJ50uLYrl1i6UTl053J
         7XY1IOl97oVkui6j8IwStc6L3LR4CI5pWNcehfvwgONg4Cjanp2DeobLro6eWfW3AwEj
         qQoq6YhakY1nB1H8HnEon1yX8I36yFsWXRstieDHjOBeX5qB911G9n1i53B32aBGJKhN
         YHHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v3lpyN+v;
       spf=pass (google.com: domain of 3xsmwxwukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xsMWXwUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=nt+f9lHMCXP6jSwrUQxP1C310r6+M3k8sre9gc/IdNQ=;
        b=YjYCspvB9EB2hJz1WTq0wDDPZ7kQPlbnXXYrr+6NATEGjd/OBsAU14slfMc+FAmOnu
         31GcZAzJVPmud3LsAfeg/S+gZRokq1uGg7fCHvMaTovNwdBXDngt3vWXTHXuq7KUkcx/
         K+emGA77f8CTFZ+snmVdXMqlFN1tS3RfNrf8dLjQuOz9mJP+I/jsDw9BO4RXCUrZQxGp
         7AcKB61XzHUpNe4QWZRHMaH+pqwe9Zkkf9gdoGy/nSTyBvfcCL44P4VAxIoheDd9PJwM
         4OQqz+B1roZr2MGoJV/9j6bD2jWzat613vVnd+ERgPPpXOR+FCVJhNnRdNJUaRPanpuC
         S+Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nt+f9lHMCXP6jSwrUQxP1C310r6+M3k8sre9gc/IdNQ=;
        b=JM4RbyjEBMFoyn0GZJ6pMIPe8jpWWzNOaM9y+E93WRlKi/fyyCYgfEnu43ZdE+O1o1
         p7IOavO7ZmTdX99n1V4w4Tlv8Im65CfDPqsFQv61Qkxb579XxASujDGwkPTfrpoy6pwD
         Xt/BkAd8iyeCJfetLeFM8LB/wlJEuPD9LZL0uiuyz8jbme4+D6BDzbCk5n5NJau4JiZS
         Ul+DbmotVon0OlEnTNsohLbWfjOo9Els040vyhDM6rsR2hpdxus5LqyG4gYXKOYLeHKn
         10iwaw7OJvi057jsr45jilMGcQmht3SxrF+I3WavfDZaDf5r9wF7pXKDX1NVTDVkTy6/
         luyA==
X-Gm-Message-State: AOAM533akSK+486rmTfL0Sgl4n8svVhGT6d87mfWGEeDI8DJS8J9AuEh
	XNRYen55BKVEkK/kY0Omopo=
X-Google-Smtp-Source: ABdhPJy1AlMs0AiINV9jJBsLpME1V8blUQbdh5MCyyZGvs+S8Ogl2VCqwiRUFqXONbAXgNmB8wEcdA==
X-Received: by 2002:a2e:87c2:: with SMTP id v2mr12663664ljj.78.1595327431855;
        Tue, 21 Jul 2020 03:30:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:60e:: with SMTP id 14ls2946386lfg.0.gmail; Tue, 21 Jul
 2020 03:30:31 -0700 (PDT)
X-Received: by 2002:a05:6512:556:: with SMTP id h22mr2421609lfl.200.1595327431120;
        Tue, 21 Jul 2020 03:30:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595327431; cv=none;
        d=google.com; s=arc-20160816;
        b=WNjKomzKZ/YysBzjlWR1z4a0F0GLr1Om0SlMwusVutTUA8PVU5lFmPjPyHf4nl/Tmd
         /KHy1bHFr0afTgwszhMU4ydaZQIlxWpW/eKHGH45nsOHQR0qj3nyNXoHXAoSokC6rndU
         tabPK4V69tiwccqqJ/EeqLEkJOfBL7J4fH34UTFouz0dPjmbNA+4S7K11yAF2Fk1P9jD
         aHiJiV/QoRqyvofpr2jWYtLwqBJKE746ETDEj2EfwmldCmLcflCLvIOuFp59nqarDY4i
         eGZ7hO18Q2AVsHhUDIyGB7fzB1+R/I+DUWDlo0sYYQiiEQj0WO3tfJZfueXsGMRidMvt
         AfTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=PTq4pBrZslvVrftV71rNSLVaaKAAwjQ/mh+57cb51SY=;
        b=bMgpBK8lKhO2Czd64xNKUDbnAD9rIJEOSbTnCxreuCf8tsYaXT7tDIDQFSknHRkwvN
         +rd65fEd4uoLsVCcwYA5iscJ1QIYHc0gDA/ohTFykQqKmkIIYbmrZue8dru3Rpvcv9Jz
         uXhMIsymc+S/piHqDiQKukjYmclG5Z1tgJFBPSCJKdO6BA9MSZbQ99WO00qL2IpoNNoc
         BAF968b6H3weQfOSbkeAcqwV0rULFcH3ch4iMQbHLN1dxIdMxWlgUw9CXRlQqHdSlf2w
         xgta6/RIv5D++dUvmtMioc7haTAp5BzGF+GpflyuhWoxN4OWRl207A64I+isecTIm8uJ
         ZMuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v3lpyN+v;
       spf=pass (google.com: domain of 3xsmwxwukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xsMWXwUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id k10si1179171lji.2.2020.07.21.03.30.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 03:30:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xsmwxwukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id s12so833583wmc.5
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 03:30:31 -0700 (PDT)
X-Received: by 2002:adf:b74b:: with SMTP id n11mr13648048wre.310.1595327430479;
 Tue, 21 Jul 2020 03:30:30 -0700 (PDT)
Date: Tue, 21 Jul 2020 12:30:08 +0200
Message-Id: <20200721103016.3287832-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH 0/8] kcsan: Compound read-write instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=v3lpyN+v;       spf=pass
 (google.com: domain of 3xsmwxwukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xsMWXwUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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
 kernel/kcsan/core.c                           |  46 ++-
 kernel/kcsan/kcsan-test.c                     |  65 +++-
 kernel/kcsan/report.c                         |   4 +
 lib/Kconfig.kcsan                             |   5 +
 scripts/Makefile.kcsan                        |   2 +-
 scripts/atomic/gen-atomic-instrumented.sh     |  20 +-
 tools/objtool/check.c                         |   5 +
 13 files changed, 348 insertions(+), 218 deletions(-)

-- 
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721103016.3287832-1-elver%40google.com.
