Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7OCTH3AKGQE464FY3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E78E1DCBAC
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:09:50 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 137sf4907248ybf.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:09:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059389; cv=pass;
        d=google.com; s=arc-20160816;
        b=G2PSPDDtRtD2MyxTAt29AdWHRalVIxXxOHBqGS1uAJQTp+AKCqpVM0MOkmnlHityu7
         KbXlqKYr2hHnyfA+LDAkTisjDfywhVQeDLgYJ6PdKhLtqo94mCd7TlGPNPiJqM9G0KFw
         UJfXhQpLCRlUEW6icKCuh5D+zUDY5Qqmaj/0XR1IBoqCiosok6eqDFYGv/pIj0jEcg5p
         9JCJ6MVhihzcrWU1hXPAkBR51VwBCzImh0eMA663SvYoxMnWkSX8LdcA7fDiqg1mCdNH
         6xTi380fiOsbyu5fhB16+PvLnHcxlrrULumthWApicX+JrjDgYwIci5+khfQrTKUjmoN
         CPxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=mcGRobzG0ubvN1lh0apO4HEDCjcrZ6/JGFirGcXrIP0=;
        b=I83QZRSfpw9w1iyjp217hXaa7n4ShoZ0we4kDicfyZJRC6tsLa1RKc9TK5H8SiJMFj
         mBBuNOGJOUlcXPGfkz2Dxt4rqlcRATT0i8mf21wjITLS5SbcaCLN7pba24mRGm4IYCn7
         HgQngPfMn7jJmyt0MNS5tGfgKiytJTg7n+ZZ42FEnKe6JdE4GxeW0+s0E0Hgf1KaRsIn
         xAnUEQqebqgJyGsPuPn9qIZ/g/G59Bcqp9eS83qUyIG+Nzo6SQ6xqqccSynR7Vmk954B
         0fAkcGE78KrnFka8o6sSxlyvDvVKTo8IyobixCBRdKTxA/CQqIol4TTZTgPwzDeJkXZP
         oATQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A8yrTvao;
       spf=pass (google.com: domain of 3fghgxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3fGHGXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mcGRobzG0ubvN1lh0apO4HEDCjcrZ6/JGFirGcXrIP0=;
        b=AVcMFf3VCtbvs/Tk/4LlDLB7y5rLYE8nDwyB2KQweoVjrsuSJhBWXmAoqTLlq5eqPl
         vWqnu5Vn4mDjmsLU1+/oVNuaq9PlZfGNtObQk3/vQCsrgE003eAdwFSY/wAZcze8gp/a
         1oN5r51ipdlPI2wfE3cV5j6NeMtRc012dYSDPRSsfMSTP7J5pQAht41KyNuiVjjFC/yQ
         NKI0ZKVSxsGiEtihnoNg70BLLVV1n4yNjuzjEZ+bihoq7sSFrt1F3obpCA+MUfu2a9Au
         k5xeVbV4hqklBys0+JtrIs1RVuQA9aEitW5aGF4rDROkBEanCazPD0LYk4Uqce0gVudi
         UY6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mcGRobzG0ubvN1lh0apO4HEDCjcrZ6/JGFirGcXrIP0=;
        b=BuAt5k0OFEOpw2iK7DWbvopve9X9PdP+7444DCbT7eFZhBWQPSfZK5tQpe3Y2LQtiC
         tx9fOrcUwZFOKCoMSZYiaAS+quaqiWVt/J86OJkhv3R6C3yZtJho2+bOp7lGUXFl2+aL
         i3485CY7fJJKePg2tesCjovYNWiyUp3Xq6XmiqNrMKvVT1iliC7HX7X6aVv9cbot9nMI
         szyYOcSXxSahycqiFbbI9Xd+EZvHNnh7YqIMD5xEhj6nNh6k8OkNmSRZPgRwb0/ZIfgL
         gDPNGDVhKXmwuSGUS5Jl8au2/MRjQaAqTTZHCxahvPFyDyiloEWmicI4LK6PAcQHvpyV
         TRZA==
X-Gm-Message-State: AOAM530vf4nI5XG9sXqLeCV1ljl0WBTuGLpA3w/fHI5mMtRaHWpxeChH
	cEpI8ZFeZuLkNJU4jKYs5jo=
X-Google-Smtp-Source: ABdhPJwSTpRb6ey2Epl2lEn1ujbcR1eAzGLlYEs2vlm0ByFlSgpx/nHmGva+ET1EaOXzeYWqUfJ1ew==
X-Received: by 2002:a25:af52:: with SMTP id c18mr13429131ybj.24.1590059389500;
        Thu, 21 May 2020 04:09:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:824a:: with SMTP id d10ls631199ybn.10.gmail; Thu, 21 May
 2020 04:09:49 -0700 (PDT)
X-Received: by 2002:a25:1089:: with SMTP id 131mr15323939ybq.227.1590059389171;
        Thu, 21 May 2020 04:09:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059389; cv=none;
        d=google.com; s=arc-20160816;
        b=yAWSjJB8hXouJ9o8DoOPcO37JUpWuh8TWnh+UTiwUuarVEUpeegZqtycOcX2rnw0G0
         rGGlUzrlPvOiqdbZwxmSosrUKc5alGsQV3MX2+p7MlBa+l7t4CiEEPaCQK5TZ32Yif/z
         Jsk63g79ucMcE/hYi//s6S8x1cO7UOzyNGbPl1ASNDW6C3zUpznzvNXIYJ1/jNM2xmyo
         JoJNorkuURcZ7t8NDtpmq92bu2Ar4Xi7VG0g7ju2egi4qoZpl28a41NgJVjKtg5WK3ip
         sillkgEWKj8GC44k9TvZ0ixAi6xNOMuhUhFDmTXyDjJ2MoK3TCFIq/PmB+wNpSc54WiY
         1ccw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=IzoT0kShpKOHmhw0CGt76GVflwk27IMd1HUpDtAtB68=;
        b=vC/yszUrH4W84KiZcsh9Cl6bIQaZXSLpHiFyyNF7Ie/oPCWE75uckuWbnfzh8ZwqEL
         cEixUwydvXXsB3YkBO1fLkPh7iO5SsM7IGW8YfIdX9F2KRMFwa7wGN8WJzHCaDs6LSWd
         8x4TXc7y2lHdO4FVei3ATVOQBacltDD40rudFT3sGq21iq4WNwapjqbVl6T/tIcejvC8
         46cCHLoQZu8qWVXOC7yOaawThMeAnVj5NeDjktklEcCEhHJ2AJXhlrNITP4DHaXHbjJO
         EXZxSu8DzZY4Wwc1JsqsYlRkhYtO065hmOBHdd6MhIBnuGR58SgWX3Lk4nqpdbCK+nNa
         4KQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A8yrTvao;
       spf=pass (google.com: domain of 3fghgxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3fGHGXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id a83si442257yba.1.2020.05.21.04.09.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:09:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fghgxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id t57so7263930qte.7
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:09:49 -0700 (PDT)
X-Received: by 2002:ad4:4e6a:: with SMTP id ec10mr9092247qvb.225.1590059388762;
 Thu, 21 May 2020 04:09:48 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:43 +0200
Message-Id: <20200521110854.114437-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 00/11] Fix KCSAN for new ONCE (require Clang 11)
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
 header.i=@google.com header.s=20161025 header.b=A8yrTvao;       spf=pass
 (google.com: domain of 3fghgxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3fGHGXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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

v2:
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
 include/linux/compiler.h          | 53 ++++---------------------------
 include/linux/compiler_types.h    | 32 +++++++++++++++++++
 kernel/kcsan/core.c               | 43 +++++++++++++++++++++++++
 lib/Kconfig.kcsan                 | 20 +++++++++++-
 lib/Kconfig.ubsan                 | 11 +++++++
 scripts/Makefile.kcsan            | 15 ++++++++-
 7 files changed, 126 insertions(+), 57 deletions(-)

-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-1-elver%40google.com.
