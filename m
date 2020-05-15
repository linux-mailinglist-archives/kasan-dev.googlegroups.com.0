Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUW67L2QKGQE44F36LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C20441D52E9
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:03:47 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id g132sf1397840oia.11
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:03:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555026; cv=pass;
        d=google.com; s=arc-20160816;
        b=bj0LWvOA56SXP6NPhlCSLA3kwH1yIAUkKY6e4tW2/1yAcfd9GxMUzz8c0BeGMCjWq3
         h0vsoplvPXI+JRJNBkDX4OzV/APEBCwyE2HMJJGqbB4IzUohVIdBfEJP1sCR7T5Lh4FO
         0A/u9Rhxozi/6BNZSXvX13g+RiK1AK+WAkcsy33XycsHNOURgWj7DXWywYBtx4nGELYs
         ReNbEjGmWoJK5CbjUqFP9MAuoS/HvY10MgJSnyAV4cU79DXMiyZKi08/A6mfon23vZbP
         0tiRWzUTzFJ7S+/Cy9d7s9Jgq7yUjqwtBjzNlUkcPlydQSLRM7gb8/4JNuy1rXJIxCgn
         FISg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=FVflsSKq2U5cfDiBMrqhyhpExmtQOzTexQMMyQWH/g0=;
        b=St2gAMb/WiXyKiTSXJgCTA48pvfFJvsiPkWwQDFHRjNJ1ecCb70+C02bGDAP5FTY7T
         vg758ovFytiGvUUc7+peutx5leTPZA64tkz0GdK6cZq7pGFVyBAj9QUAn44GIGRPV6jx
         3MMzxvREldjSyA4487uM3FFpUBZT4Q2b6le23f2gsr3ti8tGb2+gzh+lgI+a3ZEk3A0B
         nNoaBucHbjviI65OUac6xqdpLLn72RDvG66gzc6UDCvsL5GsIfsVhyL05F7X6yvGTfE4
         fKGrIpnmqOGREXul/H9/9FbWrUgvYFtRAhzfx+7ITUoFuCNLI6mQrAClCpFyMkayoUzz
         AAVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="RR/K1jJt";
       spf=pass (google.com: domain of 3ua--xgukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ua--XgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FVflsSKq2U5cfDiBMrqhyhpExmtQOzTexQMMyQWH/g0=;
        b=EtaZ5VZnXHJEqFPYI22he5pGjjrpn5Ynz7oRG6MXFk3f8My9EEri9Wq0c4WpYqXedY
         CLyDAg3lUAMoatyhP51EEeIiPkDtfOCofUA1q7nl21sIgDM8lQzxIKJlchBkvjoffXy4
         q219pqyB7+ebs9FuUYpk1yUJ4NLY/ZPJ7o6zKxpXV8hmeuno37rOdmSPJXG7qgfRtD86
         sgkAyQQ6et9dTTVxoYRIaCSp1LgVIgvi0+rkp3z9YRMCXai3QSlah4tbUecKzuwQ2o3S
         2DgZKc1ca+TYv+s9pOswvkMP6mqmGpnP0OTOJ+bhdGbLmgYktvgNRm3jitoJnjcY+6a1
         jyyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FVflsSKq2U5cfDiBMrqhyhpExmtQOzTexQMMyQWH/g0=;
        b=ENMocBhDt19tqER0JkwPbMG9xVuU3qLBNO3HcJ+yOldE4otRy7lGohtlnAN+gf+0j5
         05LBGJAvg00jlHigSnkFeDrsCx05YhEYwSMsCLaxlgxwU/Ld37sppOne+gXeFwLdqmY6
         Mc38Q1Ca9AfJVJ+EUTlQ0M8pS6RV2ENY50dYsJjxf6E3Mb4a1yLqKMhzoUEf2lZXncwW
         hQv77lTNB3TWlcYDq9jkcWAgE0MtBVndIcCCw4DZKNxFSwPYNCtkVS2TailKu+67rP3w
         R2i1tyizrLm0d6hYc/xll6l+8ZXze6ZOAwYbAhwi4OG6JyPJ54GeuEaUaKOWiIJyKRDf
         pXPQ==
X-Gm-Message-State: AOAM5318I1tQRdq73XOZuhc9b6gQ+8sSI3viqKlXKyIKNYDiltNRflqW
	Vm5oTbvNfWehOyACifQt+UU=
X-Google-Smtp-Source: ABdhPJwfkOf3Y4c/b9yLL1m7rSg4ubfoTvOW/+IFCJyGXBzmCtAK594JzwU1EOasRewKLcNgEK00Qg==
X-Received: by 2002:a9d:5888:: with SMTP id x8mr2708808otg.230.1589555026270;
        Fri, 15 May 2020 08:03:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:7516:: with SMTP id q22ls578641oic.1.gmail; Fri, 15 May
 2020 08:03:45 -0700 (PDT)
X-Received: by 2002:aca:b18b:: with SMTP id a133mr2518655oif.142.1589555025861;
        Fri, 15 May 2020 08:03:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555025; cv=none;
        d=google.com; s=arc-20160816;
        b=WFOPKgXt86/tBeC6qOxk9ChnQdtFKdtAOUagJtLHniTrv2Ws9/OJhjwjYZqLonS/k0
         rdB6ifFP7B75WtYSvxmjym1d4qIsHTX6O6rhhOnfNifUfz2VRdOYst3SrY4eKZ/lE3KG
         AYTKg3Qh6HTl36n+Uh5Q2wU+RFClABPAt3ee754cbFG9DeNxtLDO4SXQ/34MKFtTo3yY
         4O6Xs9chXfMbUTmFXSht642G1e41N5gySHeosT1SmlhLnYUVROnDx9F8fRrozd7O3w01
         MGMN3QXsd+tFwcQfbymivEr1hqwnSLOmgtfLQgGU0ltSass7xXvoIbUWYezV86OBok+O
         xGog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=c51QaJvL6D/qqlVaG3mfBJRBx6GYLLBQHT61u+1oODA=;
        b=ziLIDfgHGWsMApRD0nTBaFi8o2k/pBh2YHD5gzYomhKQR60yMBa+pYsELFkmbFbho/
         paSrrP4SNDf01n7pDlVydHVIvaBecdzvkBYKNlg1HOLS3XeRyB0QzkcGKxHe+rHMwCSo
         g3X/zHkRa8Tb6PYmc8AYazqE8qbrd6x7zi7bsH2cpaK7Bh0v4JOj6XskGW1x2lAZauVQ
         Rh8FsBfiXuKnjyz4e9h3d95SbQ8SB5CBM4VYTfhrzxU3stcpK77aCyV81JvsAU8Bw0Yt
         yKzfksN1MUK5R+0RoPHYMsNDVQaT3ekOYN9McNoMGb/JJ57AqpR5gc8365i0L9UKGR8b
         zaAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="RR/K1jJt";
       spf=pass (google.com: domain of 3ua--xgukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ua--XgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id n140si200687oig.0.2020.05.15.08.03.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:03:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ua--xgukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id x10so2863804ybx.8
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:03:45 -0700 (PDT)
X-Received: by 2002:a25:2054:: with SMTP id g81mr6167148ybg.470.1589555025225;
 Fri, 15 May 2020 08:03:45 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:28 +0200
Message-Id: <20200515150338.190344-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 00/10] Fix KCSAN for new ONCE (require Clang 11)
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="RR/K1jJt";       spf=pass
 (google.com: domain of 3ua--xgukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ua--XgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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

Arnd Bergmann (1):
  ubsan, kcsan: don't combine sanitizer with kcov on clang

Marco Elver (9):
  kcsan: Avoid inserting __tsan_func_entry/exit if possible
  kcsan: Support distinguishing volatile accesses
  kcsan: Pass option tsan-instrument-read-before-write to Clang
  kcsan: Remove 'noinline' from __no_kcsan_or_inline
  kcsan: Restrict supported compilers
  kcsan: Update Documentation to change supported compilers
  READ_ONCE, WRITE_ONCE: Remove data_race() wrapping
  compiler.h: Move function attributes to compiler_types.h
  compiler_types.h, kasan: Use __SANITIZE_ADDRESS__ instead of
    CONFIG_KASAN to decide inlining

 Documentation/dev-tools/kcsan.rst |  9 +------
 include/linux/compiler.h          | 35 ++-----------------------
 include/linux/compiler_types.h    | 32 +++++++++++++++++++++++
 kernel/kcsan/core.c               | 43 +++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan                 | 20 +++++++++++++-
 lib/Kconfig.ubsan                 | 11 ++++++++
 scripts/Makefile.kcsan            | 15 ++++++++++-
 7 files changed, 122 insertions(+), 43 deletions(-)

-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-1-elver%40google.com.
