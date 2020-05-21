Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHM5TL3AKGQEYS4RWUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2741D1DCF73
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:23 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id s1sf539963ioo.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070942; cv=pass;
        d=google.com; s=arc-20160816;
        b=l1ii5bkaCFla/jYYHDPaCqjzLd7Sm94CdFZruZZMtR0G+dOJsL1n43+tecd9RNyKtT
         i4joYaXNJmEkxWnZpwAfVLx2gx3tZ9Il7JGOF7APZqOLLE+HrgPPc0AWZMENUakYih51
         +bAHUhZsFBi19vSvAQilkyzosTHt9pbyPr//hqDHFx0c6xwRsC/oxPZxx+qmgFTI8Il3
         oPzoqNPJxh66dlxsqTYdmy0+uXLx17J8FNZMudBbQ81T55PIy5Y0QODlxpaYkrC838sD
         745Y8jemmtOFtT/1dhYuUNBMiDGIlMDI1Jek3iUlajkSM/DSSDNOV/zrZ85SvWaF0G7h
         dHPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Os4VZDJ+TeKaTSHTwORfJDmADgcrfrth+AvUj4FweY0=;
        b=FD6sYP5tXkJRiBbCQyttf+s3mRxauIuJ9M0D31xDeexU1Njt1CbbAae5qCDUtlzBnx
         QBUElh7KOF0+8XzZBwzkQHWkRKXkVuy/GMp1UHBT3x80AA7/6V1M5dVw9aP+3hP+1Orb
         j8Tw6DPnJeLWjcrrMOTTUWWUMwCsaH1/ak/9QaHbFD6mOj4hVwiO0y1XAwVokTk+BAF9
         15QR24o3xZCjRS9A2kQgxijfwmMzuVdpikgwbDLsdxLP0WqTd7KYMKFpKxfk8GI/xuK3
         xsBpYvw1sPKY88El5Sg31E1DJLFicrEukAMfoYEn2RQSF4/+WRdfJZ5T+SPaxPAArgXf
         DLMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N53ce3W4;
       spf=pass (google.com: domain of 3ni7gxgukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3nI7GXgUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Os4VZDJ+TeKaTSHTwORfJDmADgcrfrth+AvUj4FweY0=;
        b=s3RLRrQa76Oqun1MwxYu+Btb/dmiDgBCuVsg2LWc4snKsamwa3XxwWuCRpIr5TFZ9Q
         EXLKy7qKfhclH3AdmqvrhJyXr4EtcigQeGGCmQp/8C0kHmAMHl8oaE9CcizGDlmoRZy4
         7sBYUmhTxj2N66bseVFtAXeLvo3qJ+955eren/SZEz9+Yqgg0Jo7FVi66hpHxo1iz0MI
         /qSzF6FdBcHbkiyBnN6xb4jRCOxzv4CBvwA4mhnGym1ZNeNLsrrsY6b/X1UlwkvaXvnh
         L4pZlcMBjxPNcqghdH/Jy6waHAKyfkHojx354I1l8T8WW9Yhr5i2IkSZhMihoriPtiwe
         h6yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Os4VZDJ+TeKaTSHTwORfJDmADgcrfrth+AvUj4FweY0=;
        b=uOdF/2wilxzOo9ji79rZN2a0ufGnT1ix3Tx7BGkx5/xcqtXVOaVxEGTCQXWOLr7A/B
         ghz7+pNJ0CHcjTIupn0NxNJwS9zPp32hdZ9aVvMBaoAaMjVqV7DPquCkqmSloqQeKKeY
         e7I3Nc07oGHZQxVYpREqOlmclRTjCD/OnaC8HAzILWh11e1tuHCMp7v3KY66OEMhyRFF
         jxe/6HvedZaQE2gROwM/itn2pjviC4Ry9ZDJv0IJcLU1qQO3Ec2+ZMuDG/jJrU+Lmp+G
         6sSL5w9sCA52MbVdDGelPUgc+Uhu15+LbchTtPLuF4EQmJJa5WRREPn79IdRt1NpaLWm
         Zuew==
X-Gm-Message-State: AOAM5339DgbmXunzxnTBGPwjfQ+uoyBoTVlZF7uChMMXD99dq/tGnMhZ
	MXJ6t2uJnnBy+5szT06x2lk=
X-Google-Smtp-Source: ABdhPJzoBcEqzoRYW7TWdOqV1+qjYh4ZiZ7c4K1+Hqkw09zbPxAKhig3hj7ZuKR4flhhK9luZmiTbQ==
X-Received: by 2002:a92:d34b:: with SMTP id a11mr8774319ilh.180.1590070942067;
        Thu, 21 May 2020 07:22:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7a59:: with SMTP id z25ls313953jad.2.gmail; Thu, 21 May
 2020 07:22:21 -0700 (PDT)
X-Received: by 2002:a05:6638:1405:: with SMTP id k5mr3862343jad.108.1590070940838;
        Thu, 21 May 2020 07:22:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070940; cv=none;
        d=google.com; s=arc-20160816;
        b=oRO9a42RARSXtfHaQ01w+oFRdYonqaxcEarXBNuI9sI9Nm83ZdbEkoQfkRE5xQgQw7
         YjSad6kYO4uy8kdmZtqs8kWWmVdjvhb6gCfZa8DNUgIVQs+zDObIbuHTq/H4sD0xDUXR
         JDW6iW165GbrIdggg6cuWnVFY7MxMaTj2MJ2sw3ILbNjQLmZvq/TtxhEi/0dY5xcoQQl
         P9EVJhtsyTnrz38m+GQKeq01j7uW7odcMIpIouwp60rDMx886/4qhRsD/T4fnz/KGAtl
         Ln4bW3T5m990k3Saooq7TVSax4gOkc+ngFNA1rtHUGsXLbL70mX/dNFy3F6g0v97sXLO
         SFuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=oGh0kqYNNAZM+Pjnllixvw53KGUxiJ/hODIqL9XqSI8=;
        b=c1QQyrmZwaZJbvvqjAJ2+P02WxG8jOKc83u3VsILxkW4YFXsFzoM9bdFNjSLbxEEPH
         zDbAibuL9f69LYjvTyzh89gKwsoWk/xK769PVikjz0KwrR6JsBKXCZxVltvQdFrD0g4k
         dGoX2m39Z+Yr0n0Ab5xyBT6KULcln94ScYBHtoly2YTiJA76rsjV3uibqtA4jsxLkvU/
         FCQOvswNlJCY/LmX+e5Ny7JeAX5iIwXHO/G/meTyDwyKpEcihDM67QNi/Wxte9vY2x0Y
         6HNZyztGmC+vCOjAoSYK5N8/duC5T9LNM716HL3BnbwbuMWOtoRhM2yq2K2ZE1u3AqLe
         pkSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N53ce3W4;
       spf=pass (google.com: domain of 3ni7gxgukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3nI7GXgUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 2si364181iox.0.2020.05.21.07.22.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ni7gxgukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 186so5478427ybq.1
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:20 -0700 (PDT)
X-Received: by 2002:a25:e86:: with SMTP id 128mr16977291ybo.344.1590070940186;
 Thu, 21 May 2020 07:22:20 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:36 +0200
Message-Id: <20200521142047.169334-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 00/11] Fix KCSAN for new ONCE (require Clang 11)
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N53ce3W4;       spf=pass
 (google.com: domain of 3ni7gxgukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3nI7GXgUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

This patch series is the conclusion to [1], where we determined that due
to various interactions with no_sanitize attributes and the new
{READ,WRITE}_ONCE(), KCSAN will require Clang 11 or later. Other
sanitizers are largely untouched, and only KCSAN now has a hard
dependency on Clang 11. To test, a recent Clang development version will
suffice [2]. While a little inconvenient for now, it is hoped that in
future we may be able to fix GCC and re-enable GCC support.

The patch "kcsan: Restrict supported compilers" contains a detailed list
of requirements that led to this decision.

Most of the patches are related to KCSAN, however, the first patch also
includes an UBSAN related fix and is a dependency for the remaining
ones. The last 2 patches clean up the attributes by moving them to the
right place, and fix KASAN's way of defining __no_kasan_or_inline,
making it consistent with KCSAN.

The series has been tested by running kcsan-test several times and
completed successfully.

[1] https://lkml.kernel.org/r/CANpmjNOGFqhtDa9wWpXs2kztQsSozbwsuMO5BqqW0c0g0zGfSA@mail.gmail.com
[2] https://github.com/llvm/llvm-project

v3:
* data_race() fix for 'const' non-scalar expressions.
* Add a missing commit message.
* Add Will's Acked-by.

v2: https://lkml.kernel.org/r/20200521110854.114437-1-elver@google.com
* Remove unnecessary kcsan_check_atomic in ONCE.
* Simplify __READ_ONCE_SCALAR and remove __WRITE_ONCE_SCALAR. This
  effectively restores Will Deacon's pre-KCSAN version:
  https://git.kernel.org/pub/scm/linux/kernel/git/will/linux.git/tree/include/linux/compiler.h?h=rwonce/cleanup#n202
* Introduce patch making data_race() a single statement expression in
  response to apparent issues that compilers are having with nested
  statement expressions.

Arnd Bergmann (1):
  ubsan, kcsan: don't combine sanitizer with kcov on clang

Marco Elver (10):
  kcsan: Avoid inserting __tsan_func_entry/exit if possible
  kcsan: Support distinguishing volatile accesses
  kcsan: Pass option tsan-instrument-read-before-write to Clang
  kcsan: Remove 'noinline' from __no_kcsan_or_inline
  kcsan: Restrict supported compilers
  kcsan: Update Documentation to change supported compilers
  READ_ONCE, WRITE_ONCE: Remove data_race() and unnecessary checks
  data_race: Avoid nested statement expression
  compiler.h: Move function attributes to compiler_types.h
  compiler_types.h, kasan: Use __SANITIZE_ADDRESS__ instead of
    CONFIG_KASAN to decide inlining

 Documentation/dev-tools/kcsan.rst |  9 +-----
 include/linux/compiler.h          | 54 ++++---------------------------
 include/linux/compiler_types.h    | 32 ++++++++++++++++++
 kernel/kcsan/core.c               | 43 ++++++++++++++++++++++++
 lib/Kconfig.kcsan                 | 20 +++++++++++-
 lib/Kconfig.ubsan                 | 11 +++++++
 scripts/Makefile.kcsan            | 15 ++++++++-
 7 files changed, 127 insertions(+), 57 deletions(-)

-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-1-elver%40google.com.
