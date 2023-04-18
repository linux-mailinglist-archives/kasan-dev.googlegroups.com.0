Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI5M7KQQMGQEJ2AIMLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id EC2146E656A
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 15:07:48 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id w10-20020a9d450a000000b006a5f5cb8e22sf563844ote.5
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 06:07:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681823267; cv=pass;
        d=google.com; s=arc-20160816;
        b=aFNGMAoXNC7aknI7t4Cl/Zba+CkcZ4nLP3NzHWcss1pFO9/zJglUlMXi6nQ9LLipN+
         dkYy7zHgp7J2eoXUC0d9b1txCngXUpbVRkwh49I5aQP4YjFyMpXX7kl/R5eLj9hMJJFj
         C0VL4xhXQz1Io8OeC3Z7wZQldFytua6Y/5GOLLbbi2MSkZWogSavyMnBnRpyglG+Oann
         tOEOyvTlfHWgT0WPR5bdxvn28wRTlMnXT54IxUXBjhPNEXi5MCLKNZTX43l2u5VW+Mvp
         yid0OakMzBX1MivoPdcccoidQtTTxLE/emPlA3h2U8JxQPhAmPbKl9Oh0qAMetosAwsK
         2SRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OJPWfMVII4UCMP/2ki4MfiQBoRASM4JijPmeF9vrisw=;
        b=Qgd8pv/E8YsHTdcxEvpCpZS6hBjjI4XWiUDFw1rTFG/2pDuJIBKw6sb4SwwKFq0Ydf
         W71PZMtRXeXHEfxEqV4Jm6qANTPDFt+u7eae8xHUZtfsDp7v1lj4OLqi/6254qRkrOv0
         i+d68/6aeDQdyiQAfadfgAn2cN6FV29zqlXOl1vMaXqcPZmeqmXEengCy2pNChRFtLgx
         kbWggECqTMDJylv7Y9FBE/YdsD8ScgEVSqwP1WIB/vd2/K0tpOAWrSaN1qqnhtSALY6u
         UBKCPN3rzW/H4RY45NjOc2F5ePVuyCPyWAXxf3gMOtOYAZQQCmrRMPLA3WZBpa8Tjos4
         KMwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=FEhqIjfU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681823267; x=1684415267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OJPWfMVII4UCMP/2ki4MfiQBoRASM4JijPmeF9vrisw=;
        b=pBW7yTfoRrOli8RL2PNEwjEdBmJGDxCuIK4bVzLUtxFdrehMlRSskwDsiN3Hk3pTBZ
         XjiKgPFfsC6Nn0GR5b4N2VgdCo4dmFXT5mTXFQeMm91JU6R85jIABwVJ1Zez6yuiMR60
         qCtQD4A05ZjrZEngQ+AnsDvEryHJefZ1VnW+s0pTZLE4pJKWxLe6/9Bx03QjG5h58oBS
         wl/LJGg0nyKJ2I2Lj4z9hAtZ4tfai5ULRHZhrwYBRITnL/bMiZYzJiy60TVwbMfzG9oR
         CZFGMTb8FRoHIDuZ838Mau/o/9BOkuOYTl7yKvw6jrRNC8dhC0ocW4agV4QAZv2SxEEL
         L+Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681823267; x=1684415267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OJPWfMVII4UCMP/2ki4MfiQBoRASM4JijPmeF9vrisw=;
        b=AccwHZLVXEL48/tjeCZmC7kiZ8OGyXm3oLNet2sypXq90yZpJtJD4r6+paEp8NCNCL
         BZxjIa1caTceNySJ7oru/opb/KUN9O44PI6wcFEKazwJCxCwKhnMVqY48T/krc9RHwla
         gqd603XvgiSm4qJdKrQOLBx538ZzU8m4WiBW4E78pjmayxeNPVQR4SaTboaD98vpV+4a
         lVTsZrL5NH+7HgG3MeCiMfnMF6Mj5dIWy4wwEgUzfMdQFbC1QAeDANLDK/mgoPm3geb7
         LGBJKQglsjpGImWzsp7VCkMRNpTEEMnL+QbUr3BcQO+GpvUo47tbsK6ArSGPxsarQWsP
         tGgA==
X-Gm-Message-State: AAQBX9fSSpnpw2pwaNHK23WiJPjOtfkRuztP7f03DtqVaUfmAa0EL9vm
	Se4hLEJitrme8DuOdqJXkIs=
X-Google-Smtp-Source: AKy350YQix8tr1kgSfElUdUbpXaQtMaMcQMzB+KCf5GFHkjVeDGBbF5uXtdTzWiPUx6Vqf/VFDnP3Q==
X-Received: by 2002:a05:6820:138:b0:545:2048:7d71 with SMTP id i24-20020a056820013800b0054520487d71mr3354051ood.0.1681823267146;
        Tue, 18 Apr 2023 06:07:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6018:b0:6a4:2aff:59e5 with SMTP id
 bx24-20020a056830601800b006a42aff59e5ls2809115otb.7.-pod-prod-gmail; Tue, 18
 Apr 2023 06:07:46 -0700 (PDT)
X-Received: by 2002:a05:6830:4424:b0:6a4:1938:7d92 with SMTP id q36-20020a056830442400b006a419387d92mr1205655otv.13.1681823266578;
        Tue, 18 Apr 2023 06:07:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681823266; cv=none;
        d=google.com; s=arc-20160816;
        b=MCteYgAsbxKasgmmleE7GRnUQL2Xpk9IpXlyNdEDbChMMNfjvCxVabMNlQh8P1Hlr7
         t1FpW7mbUyiPC3w1Nj1oucPL7rua3+8taDUP7VzO7k5o5OC5/PznKlwK7JB+AjiX3DfD
         +a0fHJVN7PA1btfS8hctSpl8X0iHZ7nw3bCSIuR7WBiPBYLFjvj60NCoylXBQ117U7Nk
         vpPWlmNP1lBdgatrDGsG1bl1PDur4l959s27lXe+Aht4kNU6Kk1R3hHYJqEKrRUIYcDP
         sPU8IeGa7AN8K+ny108803LUaL7/4c+kqyAGq3c7nyHyTVevZWLfoEwHaDWvyYRNuwc8
         R9Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cXVmjV8MVgirfDn+CQoxVOKGwz3EOWGBSd7QdBjs3YU=;
        b=kCgHRQevy2wUI2+sCbrqfpWSUYIApyZIkxUh77TYVNQVOjorM6zLdiaryO72/r3lJA
         M1jdzpivITazjjDdYlgOPtAz8aZtvJtOop0E4cu3iWinX9L1xew6TDiuKmu+lKj7pqWK
         Hsc/mdbcT0oBbzesFZrDHrEoMfK0DDLwJZHUIkbZJg1Uh5TB8K80MTMj04YXNHBeD+tv
         71jlhZM2vYaS0cXHLFXdKPFbzncY3D8C4J+ZPA002JAoBD5tLYShoNkr8CXzysQdijXW
         +mWQKmUai+I/kmSqwSkTkuvr9i5pph7js9N5b4bB+RJGWz9y4kuI+irkdaP7vfZV8b6u
         Xsmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=FEhqIjfU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id db11-20020a0568306b0b00b006a5f12c714bsi96345otb.0.2023.04.18.06.07.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 06:07:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id e9e14a558f8ab-329627dabfbso32548735ab.0
        for <kasan-dev@googlegroups.com>; Tue, 18 Apr 2023 06:07:46 -0700 (PDT)
X-Received: by 2002:a5e:8607:0:b0:753:989:ebb5 with SMTP id
 z7-20020a5e8607000000b007530989ebb5mr1792769ioj.7.1681823265971; Tue, 18 Apr
 2023 06:07:45 -0700 (PDT)
MIME-Version: 1.0
References: <20230418122350.1646391-1-arnd@kernel.org>
In-Reply-To: <20230418122350.1646391-1-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Apr 2023 15:07:09 +0200
Message-ID: <CANpmjNOSi32aN54_=WH1xb4jqzso+-riMomLxoqebO=AdbpHVA@mail.gmail.com>
Subject: Re: [PATCH] [v2] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1
 for clang-14
To: Arnd Bergmann <arnd@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nicolas Schier <nicolas@fjasle.eu>, Tom Rix <trix@redhat.com>, 
	Andrew Morton <akpm@linux-foundation.org>, "Peter Zijlstra (Intel)" <peterz@infradead.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=FEhqIjfU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::12c as
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

On Tue, 18 Apr 2023 at 14:24, Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> Some unknown -mllvm options (i.e. those starting with the letter "h")
> don't cause an error to be returned by clang, so the cc-option helper
> adds the unknown hwasan-kernel-mem-intrinsic-prefix=1 flag to CFLAGS
> with compilers that are new enough for hwasan but too old for this option.
>
> This causes a rather unreadable build failure:
>
> fixdep: error opening file: scripts/mod/.empty.o.d: No such file or directory
> make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:252: scripts/mod/empty.o] Error 2
> fixdep: error opening file: scripts/mod/.devicetable-offsets.s.d: No such file or directory
> make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:114: scripts/mod/devicetable-offsets.s] Error 2
>
> Add a version check to only allow this option with clang-15, gcc-13
> or later versions.
>
> Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memintrinsics")
> Link: https://lore.kernel.org/all/CANpmjNMwYosrvqh4ogDO8rgn+SeDHM2b-shD21wTypm_6MMe=g@mail.gmail.com/
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Marco Elver <elver@google.com>

Thanks!

> ---
> v2: use one-line version check for both clang and gcc, clarify changelog text
> ---
>  scripts/Makefile.kasan | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index c186110ffa20..390658a2d5b7 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -69,7 +69,9 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
>                 $(instrumentation_flags)
>
>  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> +ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
>  CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> +endif
>
>  endif # CONFIG_KASAN_SW_TAGS
>
> --
> 2.39.2
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOSi32aN54_%3DWH1xb4jqzso%2B-riMomLxoqebO%3DAdbpHVA%40mail.gmail.com.
