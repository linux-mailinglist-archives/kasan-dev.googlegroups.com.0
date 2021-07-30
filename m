Return-Path: <kasan-dev+bncBCS7XUWOUULBBXUISKEAMGQEDHHJAOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 07F113DC15C
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jul 2021 00:59:44 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id v9-20020a17090a7c09b02901778a2a8fd6sf3653228pjf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 15:59:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627685982; cv=pass;
        d=google.com; s=arc-20160816;
        b=TS12Iy/WgvhT41IjXQjzCYrggr+85ws0C+N19Ra7Jv6YOfp5Sr/QJ5lgP2bvO3YEzx
         fjr/WTLbJkOZHD7k2uKYoBDaywMWSM0iOu9/6TG1ntFQgHvcbZY/tGVMGtqukEg/rNe2
         JEuuW1awI9VN+CmXgGRdHGBF/dUb45aQ/BevTtr5Hp1SQPShWcqfQ/Q/Jq53msA3gxch
         7xecxtnVZYI7gbg7mSKt7fYsxG6dFFWK0e01ftQqNyCTrU8eoS8t49RbD+1uz86rFXfe
         VYlC0+18Z577CHyJgioDwbelgfHZ7Hh1fukNxxk6wT0e6sDStuIrzpL5vaE+sVWEsTgW
         GkdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jdiW42hHw+qXuY4PKd+ELNQE6ZdI6DOsADptGFtYf3o=;
        b=laXVMEkx/Ag0PYpaA5hnwhZWNNajAqw+EEUVc5d24xTXukLkjieR0d053LYGWxYl/t
         dhuQOqMoO5h1wm+Gs5HSjxXQz0itt0vH1U+IZKvg83qZrggWTqMmrGbBI8O7QGUcjQyQ
         /xSe9GXEY57ZTNNq3UWjqZDn5GerKVu8eWLFEJ27LfbMpcmblB6BaG+CWmZbUo+IqsvP
         d6qSGRTqsr2d55LbaKfqw27s/sCItO8nj2F/NW+yhnEmpYqy3ryuD1WBhrwsoA31j8N3
         iG4tCQ7t7cWquh4RUUqAL630hbMJdzt/7vcMlA7xCJF3kmbEcGFOC14ae/WuJ9WJHDXs
         2Zlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sCMXYE8B;
       spf=pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=maskray@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jdiW42hHw+qXuY4PKd+ELNQE6ZdI6DOsADptGFtYf3o=;
        b=mTk5tnKygkWMtVumEqy0+riKtB910UxQkSySIjCg90AqW9/hDm6vR6CNKquUWGvw9T
         QFV3tN0IUoRpGX3YX9wZxODugyx7g+8OyeItBIzsHLbu8PTH1zF692k/R5Au/HTl4YUX
         izm01lLcAljaXsZDQ0gOJpL8cEDxTlgJsJe47mgEe2ZC0dZKoQf/SjfPNE4nR//aWuGN
         pIR1/wEk81s6oxhK6fxDk/2UDAByHO5TawbhuWAvTvz9KbhltIw07V70Pm/nes43dRHe
         /jyB7EhNheUZChE6LbNeMFST40nV8+n8cpvZYIYqUAbmCCsUIHnioXUsEFae5oYCTJQt
         qdjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jdiW42hHw+qXuY4PKd+ELNQE6ZdI6DOsADptGFtYf3o=;
        b=qgADIiZRWRb8rBosamXPW4GzI2FpDWtyXQ9ACKTSrtflKYpn742B0FtnGFwrxJokqB
         m7Uf3dQLYj3uwDX45kFoRBhIfk5DOSewHb3GDXveeZEouA4lB6C/Zep+oft8IJ7wnwg3
         Y5mRx+7BfKd3T+IIMfv2utHeRYfrlPRSt9e7ilKF86fnK/lhqFWXN9z47ZmKBGSRT3KX
         G9rurkUp+BNUghQDdexBCyUXGPk83jBBxVGEolLb5t2VcGXr9EjvVteijnwPbiVQbehg
         /TyceUE1xXkyDrpEEjba2sodOrXvrkU0FX3mVtGWvv8UPhilGJJ2mY0gBZ9O8iz5P9YZ
         BuAA==
X-Gm-Message-State: AOAM533us0UTPyobhT8w7TXSYY+4CNjjKGB3FRiaconytho/dgHJuZrl
	L3wIWJhlFfKHmM7q7GHPiZo=
X-Google-Smtp-Source: ABdhPJyj1/5IHiY30FFsX1HqbOz0Jj2un1iHLxlEBsK11NGlhMKpFAhFb9q7hCSgWo+CvbS+J6iZmg==
X-Received: by 2002:aa7:8b4c:0:b029:314:5619:d317 with SMTP id i12-20020aa78b4c0000b02903145619d317mr4874480pfd.60.1627685982704;
        Fri, 30 Jul 2021 15:59:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:192:: with SMTP id z18ls1598885plg.5.gmail; Fri, 30
 Jul 2021 15:59:42 -0700 (PDT)
X-Received: by 2002:a17:90a:d251:: with SMTP id o17mr5451171pjw.200.1627685982067;
        Fri, 30 Jul 2021 15:59:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627685982; cv=none;
        d=google.com; s=arc-20160816;
        b=cyiDu/Jb+iFP+1lJ5a0ngr67OcTxUWHCLmn0UfqVlzpxNg42K+z6kHkrI0vtE7J7bx
         MAWpZjtKeCz33EWdsRuA8BhUZiAg/FhY/Br2ow/XQBuujjdP8NB1VULGwvst5flvvg3u
         bHHiUyivbJk05S+X11eysEZPLo7NqWxlgvs1YzcmbK3XrfvSJqeMHnS9i+7sY7CfAd4Y
         B0m5euai3W9/0gHW1MTB60J5nzA4ONFy4T/3IEZWn9EdXkwXGmU3xqlCLHnAFoTaSqmG
         eGWOEY4BraovX534FVBf8R2oQR368K7cyOfPVYM0Ge+c45Innvyxlw6ZG2WJYVPmvGqI
         El6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=V2dvuvNFpryb1cvQLGlVrhhfsTfSnu/5+tUDbUkQolo=;
        b=FHFtjo/M2MSQhZwu5DNXV6EZ+W6FH6SRSfbnlnWFf8GlZpI72N/8Q8B2lvSOI9esEP
         NHmFKGfhNnDoUqLxnHzexYfeCbWeee3LCt+yij7ru91vBmeWh3pK7Eb0fPi3HDMwGnRS
         Mb2aoaQrRURX+4cA2KsAQWOT/FSzCMZ87j1kYI8lPy5SDexyttbJQEeddHbwbiV9o4zi
         bwBINWains4jM2UWjrOJjjZWNLzfYl9fkPZv1OdOVRDMNLXOGzk4JpIOq1bjLhr/9DI0
         vM6OC3bBKnPfJ67SpJE1RhpZyupSLvuMJIxgwXMhpRi6kMGxBvzEMlaqNpjHIBaYyBbF
         +p8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sCMXYE8B;
       spf=pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=maskray@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id o2si230651pjj.1.2021.07.30.15.59.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Jul 2021 15:59:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id z3so11509172plg.8
        for <kasan-dev@googlegroups.com>; Fri, 30 Jul 2021 15:59:42 -0700 (PDT)
X-Received: by 2002:a17:902:b713:b029:12b:b249:693f with SMTP id d19-20020a170902b713b029012bb249693fmr4511815pls.17.1627685981632;
        Fri, 30 Jul 2021 15:59:41 -0700 (PDT)
Received: from google.com ([2620:15c:2ce:200:160:995:7f22:dc59])
        by smtp.gmail.com with ESMTPSA id a20sm3235150pjh.46.2021.07.30.15.59.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Jul 2021 15:59:40 -0700 (PDT)
Date: Fri, 30 Jul 2021 15:59:36 -0700
From: "'Fangrui Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>,
	Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	clang-built-linux@googlegroups.com, stable@vger.kernel.org
Subject: Re: [PATCH] vmlinux.lds.h: Handle clang's module.{c,d}tor sections
Message-ID: <20210730225936.ce3hcjdg2sptvbh7@google.com>
References: <20210730223815.1382706-1-nathan@kernel.org>
 <CAKwvOdnJ9VMZfZrZprD6k0oWxVJVSNePUM7fbzFTJygXfO24Pw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Disposition: inline
In-Reply-To: <CAKwvOdnJ9VMZfZrZprD6k0oWxVJVSNePUM7fbzFTJygXfO24Pw@mail.gmail.com>
X-Original-Sender: maskray@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sCMXYE8B;       spf=pass
 (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::634
 as permitted sender) smtp.mailfrom=maskray@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Fangrui Song <maskray@google.com>
Reply-To: Fangrui Song <maskray@google.com>
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

On 2021-07-30, Nick Desaulniers wrote:
>On Fri, Jul 30, 2021 at 3:38 PM Nathan Chancellor <nathan@kernel.org> wrote:
>>
>> A recent change in LLVM causes module_{c,d}tor sections to appear when
>> CONFIG_K{A,C}SAN are enabled, which results in orphan section warnings
>> because these are not handled anywhere:
>>
>> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_ctor) is being placed in '.text.asan.module_ctor'
>> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_dtor) is being placed in '.text.asan.module_dtor'
>> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.tsan.module_ctor) is being placed in '.text.tsan.module_ctor'
>
>^ .text.tsan.*

I was wondering why the orphan section warning only arose recently.
Now I see: the function asan.module_ctor has the SHF_GNU_RETAIN flag, so
it is in a separate section even with -fno-function-sections (default).

It seems that with -ffunction-sections the issue should have been caught
much earlier.

>>
>> Place them in the TEXT_TEXT section so that these technologies continue
>> to work with the newer compiler versions. All of the KASAN and KCSAN
>> KUnit tests continue to pass after this change.
>>
>> Cc: stable@vger.kernel.org
>> Link: https://github.com/ClangBuiltLinux/linux/issues/1432
>> Link: https://github.com/llvm/llvm-project/commit/7b789562244ee941b7bf2cefeb3fc08a59a01865
>> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
>> ---
>>  include/asm-generic/vmlinux.lds.h | 1 +
>>  1 file changed, 1 insertion(+)
>>
>> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
>> index 17325416e2de..3b79b1e76556 100644
>> --- a/include/asm-generic/vmlinux.lds.h
>> +++ b/include/asm-generic/vmlinux.lds.h
>> @@ -586,6 +586,7 @@
>>                 NOINSTR_TEXT                                            \
>>                 *(.text..refcount)                                      \
>>                 *(.ref.text)                                            \
>> +               *(.text.asan .text.asan.*)                              \
>
>Will this match .text.tsan.module_ctor?

asan.module_ctor is the only function AddressSanitizer synthesizes in the instrumented translation unit.
There is no function called "asan".

(Even if a function "asan" exists due to -ffunction-sections
-funique-section-names, TEXT_MAIN will match .text.asan, so the
.text.asan pattern will match nothing.)

>Do we want to add these conditionally on
>CONFIG_KASAN_GENERIC/CONFIG_KCSAN like we do for SANITIZER_DISCARDS?
>
>>                 TEXT_CFI_JT                                             \
>>         MEM_KEEP(init.text*)                                            \
>>         MEM_KEEP(exit.text*)                                            \
>>
>> base-commit: 4669e13cd67f8532be12815ed3d37e775a9bdc16
>> --
>
>
>-- 
>Thanks,
>~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210730225936.ce3hcjdg2sptvbh7%40google.com.
