Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPWKWKPQMGQE7D4ORQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id DDDE56978F1
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 10:26:24 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id n2-20020a170902d2c200b0019a8c8a13dfsf6457186plc.16
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 01:26:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676453183; cv=pass;
        d=google.com; s=arc-20160816;
        b=WVLYGJCPhHHYZ8M7ZBHaj5iN9/gZXuzfqAKFXnPVJVRpoBsuiKma5CNrVMc08Abx30
         UMJBklxb/H+NjmBRLWx2OVVX2/OaKw69hNvNu4Rm/mn8wmwfxaL6dd4qzqXpESHUvNfb
         0PfJDSnCFLT9PMtpESgZkQ9L5evAc8w2c4u/FhX+yzNYprbXHZ2R5NBX2HUuyJP5tKSp
         vegfp6P1e3y2m7ZoymZfE+x3gdE4Du4yqpYgcFXZSskVSXmVESkXQ/zIx13X43YfdFL3
         CEAm/PlQC7TNnvxcB0qyKCzWqvCQjgUNpyDv/qlWqkLr26azzcEtWwm/kOOK4MZM4p+p
         HQXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fbMmpXlcMIwtEAL2lsxEXbmRrS6VoiM+Tuj3+YjcS5c=;
        b=Q9RciNSq+5/NlxB4PNWueWDafVHGl0kpkhWRjfzwFodSHF6CLZ1Zrd2yFEAZPL71GV
         HJ3+K9NtljsccdLCa3pvHVN4t9THgqaD2XQi1g3tNEvEQYuOzBQYVkNWiIZYrkSFXB1i
         oEh8BwXYOemDG3EPOqRT9Pmp/OjcAB4UeiXCiLiaSsjM4f9ag33D8T1TSFkcYhl4CK3f
         qq9z0J6wPuugaWnRn+P5JI8P6hohanxY6UzJM7dgrUZhZO2odkXfT6gQ8cgsTl2Loakj
         U1BTiUvc13/BYQCU4brrkMTAIyiawcw/S4lVvc/NQQ47m8QT8dD75YR4x77Ff302zkqd
         CWrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R+gC83k8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fbMmpXlcMIwtEAL2lsxEXbmRrS6VoiM+Tuj3+YjcS5c=;
        b=oZZvsLrFMm3C+nP1L0IClhLEAIRwbiVmDwnuFM4rzESS8kNWL3YhOfnAqMdpUx3TtN
         RcFPGKNEhdUNBH9invIzG7QaI/ZduGPD3cL0RVOzO1d2LLW0k0F5TajG6XO+j3d1AAjN
         5UCE+bIq1sSq5sjMnVwNISTX9eLTKElkadeij6IM2hmroBaYqOocmjkgbwNg3i24/enK
         CbbLrKfNJeBDPmm5pl1HO+CQq651cqFODxLwakXkzJlJOmp79G3CKwhsgTVOByFSiPwN
         JSKQoTYNRuQuWYnzn7ygG2+ktp1+PU7RbykMiRjQKIj1mtVHNSAssEjyrz79SypNyA6l
         nGDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=fbMmpXlcMIwtEAL2lsxEXbmRrS6VoiM+Tuj3+YjcS5c=;
        b=q65nEdSHtrM94huKeTMNa8X2UsT7EPVyaGhjLoolqDXw1w4TgWF3l1FTYo5JTJFjwl
         5nu1lTPuIZyJ2A1q9oTnC2N3/BD4LpwKPofpYAcRJATSdE9P+LOT5iU7qMYr/8cexGfO
         A4jTQ67ZMev+YdSGt6hoBCBNJJ+biwebpLEw+WKQ/QuX6pQexxQUpxXIWxu0Sm9JLmXQ
         36ixM6vQEw+16NVcWSCjMsE7tYewroZRQhGS1AkT73iQ6Sbn9JoqMqeDat22inWaLCUS
         Qv0lR2QRDI65t/4+nfE/9J9xQ+nYvs+nSqB/hi0uAxwmnhIBf069e+k5x2MLiAuG8CEb
         Yssg==
X-Gm-Message-State: AO0yUKUPZ7UhZTNSZfNWjm0Xb6wJjm/VFENTB8Hhgjpc1YMBm6NmuQ/f
	V956uOviva4cXI9uSFe8QnE=
X-Google-Smtp-Source: AK7set9UEAfvdDlZ5hjraJr1FthB3PDNpAMcCTOQI7In7PhcnleTNQfSGbxu0v5ihpDtAwqxtDi9Vg==
X-Received: by 2002:a17:90a:9a4:b0:234:2ef3:8a73 with SMTP id 33-20020a17090a09a400b002342ef38a73mr394130pjo.129.1676453183099;
        Wed, 15 Feb 2023 01:26:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:31cb:b0:233:e65f:ffb9 with SMTP id
 j11-20020a17090a31cb00b00233e65fffb9ls1841372pjf.3.-pod-canary-gmail; Wed, 15
 Feb 2023 01:26:22 -0800 (PST)
X-Received: by 2002:a17:902:e888:b0:198:e1b8:9476 with SMTP id w8-20020a170902e88800b00198e1b89476mr1964227plg.15.1676453182183;
        Wed, 15 Feb 2023 01:26:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676453182; cv=none;
        d=google.com; s=arc-20160816;
        b=PGATzKhqbHNeApW15sP0NLcFkKlfN5UEeUiSk5XgXKcCSRDue6WxoSMrlIP5fILGY3
         szn/R+3j4Lq+Kvv5RxECbff9hEsQRivXSsVlXEHBfjmoeetnKCEXKjdzMIZV5GtBz8W7
         gBl8xC3nRqRoOpizRVs4SH0m2A+TyA+zc+Cuu+Pjj9E3qvdGK9xu3nwGRMoUvsMCWnlf
         9dXrK9mSK5WiFIf+xZs7J4mDEFy+3bTpW4Av7xWBM3tnUxMCCVRLQl7Bxa7elniMFhua
         /sr5wWjkz352Bk7HaGAt9jZEO62RnsFxYOR7evwI0qPjZcoW4Rcnc3AnmvJXUa20RBj5
         fkEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8JZ7cPQMzKcdcwW48N+uKI3jJsqc1Zm4J233qZzbj50=;
        b=xySGxrclLLcFQ1KM0ZLmCyIy342U+/+imnnWYQh7g1+2Sx/DxaosrygeXWBtlz/5Zg
         lhVwFxR3WytpDYYg8Un94k6m+nZOyGmGjX7w5ly7gNP0ol6dQdhZEXZ5gFF8ohv+05PB
         Yv9qorf60W9+P/E1SFfAjPl39y02s/JvzViJyyD73Yrcrfk+664tKHrlS1ju5FHBDFCN
         Hf0RNCfCgdS8xsPfmRWYHOprULYzl5kMYBvb0PgllwxLIOA3In8wjyUsQrqo0ukFRsJ9
         v63JlKHSYHTY1fl0RR6PfWS9IR/lA8JhJ0X0Dz/BbphomSCb6rfCtud0RFw0LQRopjr+
         DhXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R+gC83k8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x936.google.com (mail-ua1-x936.google.com. [2607:f8b0:4864:20::936])
        by gmr-mx.google.com with ESMTPS id 144-20020a630596000000b004fb840b5440si889734pgf.5.2023.02.15.01.26.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Feb 2023 01:26:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) client-ip=2607:f8b0:4864:20::936;
Received: by mail-ua1-x936.google.com with SMTP id 89so3431762uao.2
        for <kasan-dev@googlegroups.com>; Wed, 15 Feb 2023 01:26:22 -0800 (PST)
X-Received: by 2002:ab0:7442:0:b0:661:1837:aad7 with SMTP id
 p2-20020ab07442000000b006611837aad7mr174248uaq.45.1676453181317; Wed, 15 Feb
 2023 01:26:21 -0800 (PST)
MIME-Version: 1.0
References: <20230215091503.1490152-1-arnd@kernel.org>
In-Reply-To: <20230215091503.1490152-1-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Feb 2023 10:25:44 +0100
Message-ID: <CANpmjNNz+zuV5LpWj5sqeR1quK4GcumgQjjDbNx2m+jzeg_C7w@mail.gmail.com>
Subject: Re: [PATCH] kcsan: select CONFIG_CONSTRUCTORS
To: Arnd Bergmann <arnd@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <keescook@chromium.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Miroslav Benes <mbenes@suse.cz>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, "Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=R+gC83k8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 15 Feb 2023 at 10:15, Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> Building a kcsan enabled kernel for x86_64 with gcc-11 results in a lot
> of build warnings or errors without CONFIG_CONSTRUCTORS:
>
> x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/copy_mc.o'
> x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/cpu.o'
> x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/csum-partial_64.o'
> x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/csum-wrappers_64.o'
> x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/insn-eval.o'
> x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/insn.o'
> x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/misc.o'
>
> The same thing has been reported for mips64. I can't reproduce it for
> any other compiler version, so I don't know if constructors are always
> required here or if this is a gcc-11 specific implementation detail.
>
> I see no harm in always enabling constructors here, and this reliably
> fixes the build warnings for me.
>
> Link: https://lore.kernel.org/lkml/202204181801.r3MMkwJv-lkp@intel.com/T/
> Cc: Kees Cook <keescook@chromium.org>
> See-also: 3e6631485fae ("vmlinux.lds.h: Keep .ctors.* with .ctors")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Marco Elver <elver@google.com>

Looks like KASAN does select CONSTRUCTORS already, so KCSAN should as well.

Do you have a tree to take this through, or should it go through -rcu
as usual for KCSAN patches?

Thanks,
-- Marco

> ---
>  lib/Kconfig.kcsan | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 4dedd61e5192..609ddfc73de5 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -14,6 +14,7 @@ menuconfig KCSAN
>         bool "KCSAN: dynamic data race detector"
>         depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
>         depends on DEBUG_KERNEL && !KASAN
> +       select CONSTRUCTORS
>         select STACKTRACE
>         help
>           The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
> --
> 2.39.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNz%2BzuV5LpWj5sqeR1quK4GcumgQjjDbNx2m%2Bjzeg_C7w%40mail.gmail.com.
