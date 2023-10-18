Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUMYCUQMGQEKFPVLAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 121C07CE29E
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 18:22:57 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-6b697b7f753sf4445285b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 09:22:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697646175; cv=pass;
        d=google.com; s=arc-20160816;
        b=0xEQkeexo151FJm2wCKB45z9ugp51gWe7yI5BkkMlV7YNMoS/MrpjIpTaqbjCeBMw7
         /OkH/QKjX6XCOPXBMC/3Ktn7dPwWrYIg+QRt2G1XzstRbqICp4iGzvP9w3lhRBwNwwf0
         RIwhMqhx9wwZilCMIGHKoDNdGiY+E4nP3X83k481tZbXigdJioqrLlJSHkQii3hD9hhS
         k6Y83G+LbEMZ4PUaXcjFXgqQb44KVlkBiaOrHF4DtVSs8zHLLbYTNretn5omvc+HUIZi
         FiWalsoL8Y9XfMXNQDWDf/NuftWiyxHJ2ATGlpbbM+jxaOYjzi4SmScpI3yiWTPyYUKv
         wPuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TV9Z69cKjkPeYvIP6745tafV0Ez84koycVgGd0Vf+WI=;
        fh=iavFEGiaH83Lc5aDzeABOQpyXUB7IiGge6GRfnQJa9w=;
        b=dQ8BUxC3swlH1KObqMJIUPwKdLkzSzdNSiwhfgxgHJpzeCF71SEezFykd3SQdVXoGl
         hqmtWBF1qL2Z6bJaWsr7u4uF42Wc2azM/OMRmjCkT4F7L+Evq0Y7A1t/6UM4nXH4l7jq
         HGVsdwl+OocC13I+eABbpT+L1iRcBxzKrU39to8yJYxMxfSG7WM/LvPaH00toPgUgU3i
         GnNYhvp8z9yBLBlzyXPvRP3aWlu9712lwBbq1Uj4eUNyR/vzsHR6lUbbaZugjK4GQkFR
         DoyEZW6Mq3UQWsc6IWuljAh546U7uMHseqRqYc2kiRERm4401ru29T87D9tyzyi7/i8O
         +9nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4b5Vj2Mu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697646175; x=1698250975; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TV9Z69cKjkPeYvIP6745tafV0Ez84koycVgGd0Vf+WI=;
        b=aOns3pYXrxparQ5aR9ja/PNs9q1mcRW77Zi46EQ46t6mLQvimBroaZGcOSBJTwVip1
         BTj5xqoCIk8c0yszfPBdg27zDwLAJgF1iBVlhwSsX2yJZ1pnk0uns0x31hVqEvWGc5de
         ceqPFNsTBHQtu7bYb8pToZDQvsQJgbzGcOlN9zkGxuS32yQdgI+pI0oPrLURcBA/M927
         q/8mqZKw5aB4D28YwFoTbiYfvAxuDEEmU2t639n1qrSSHb0Oh7fPjqpjD/xTQUQyV9DD
         8UBx9MbJdn9t+kPVHCJ8dFOTBpTqCVPNj06JRwKzg00nJlbbdhT4cJKMTFrmAg+hwXfa
         4uiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697646175; x=1698250975;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TV9Z69cKjkPeYvIP6745tafV0Ez84koycVgGd0Vf+WI=;
        b=h/tC3X00bz6QT4PVLIkiAyYPpNmbDlZUR8Z+JF3naM2c6tlbRUQeXjziGxZ2SJhvXK
         ytEMhWBNHVtx837uBucX7XlFAfR7UgN6APSdqxcr0oBbYxNQbubVesF97h9hDM+slKRA
         e8d4jzZnWPcZ+gzkoiF+AnxQ0li+r4QnOTPS0b+N3JOvXEyxtm5XAT3M6Nfp1V2SU+c1
         Z0gbzdF3qygUvm5Azz87P8WYp/SXN1xZrax+Vd3mhyiRkc3E57m72hoqGdtvXtT9SjqH
         /pa2wUkbFMLk6JS4c3u3EXrnJb0MQqPmA7z4GnwKfgRS+6P/rr+7pFGv0P0Eq/B8vJnD
         yPtg==
X-Gm-Message-State: AOJu0YzuqJhxahDZR4vUy8vWGy2Y3+C5X52UOSlFrS0zcI6Rzm/O5EAU
	ADLAs2crxVL/4kYAH0/Y9vE=
X-Google-Smtp-Source: AGHT+IGxxTsRDGZvTGfMiVhBrE39zH/p2+yMmEje/gtNBih2kHDgQa5mnkeKSEvHCmPdH0xFo3Ls1g==
X-Received: by 2002:a05:6a00:c8d:b0:692:b429:390 with SMTP id a13-20020a056a000c8d00b00692b4290390mr6465528pfv.29.1697646174880;
        Wed, 18 Oct 2023 09:22:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8497:0:b0:68f:e0e4:7af with SMTP id k145-20020a628497000000b0068fe0e407afls2855508pfd.1.-pod-prod-06-us;
 Wed, 18 Oct 2023 09:22:53 -0700 (PDT)
X-Received: by 2002:aa7:88cf:0:b0:6b2:5992:9e89 with SMTP id k15-20020aa788cf000000b006b259929e89mr5876430pff.9.1697646173674;
        Wed, 18 Oct 2023 09:22:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697646173; cv=none;
        d=google.com; s=arc-20160816;
        b=GpcXJXRMmuyJg4VqPTWegQlS56weGt2cGoa5eNkKwAUAxxzAeAqEocpDne1CJsToUd
         xCcR9dhbMYp3/x1nUemSaa9d3/zkzOCkWwJDd7y+hHQUeOlN5jFnBn26d6/He7q19PUB
         yI5kKtdfDZ8OzFCsda1LhqHt/gN9k7PbK3stkW7jIZLPgsM7x2z6OeAdINr1nXgfwyyV
         FILpfiQrGI+9c1705nENvk1plmAfl2lL6NX7o2fAzdWlKTiHCPpLG3QMPIcHNV2jMpZh
         FOCZt1/xjxPJMz0nov7FAvTXCxICOdfdM9MMoVOPm/IsxrGtMptRdaO/oyMjz5cjsC4M
         B2RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i8uMytjHiXi9xKsw6qoUi0Pc7HNlD5A1bFtvpbrNGTM=;
        fh=iavFEGiaH83Lc5aDzeABOQpyXUB7IiGge6GRfnQJa9w=;
        b=Tsw4W92rEllCilp4sRfUEUMg0uWzBJOmHKTVDr88Gori0i1FFY7QabrBjbCQ8TY4VU
         IK+wiNW+K2IkchnAyemxzqo1gFJs4Rcqu6zEjmOuZJgEX6zN/+sJLhdSgYdgh8PKphud
         IrLHgt5pufed13AbBNeI/cyVcyYmvnkGYF12Gm2W/hc6YFR69ypiHlXsQ1xlkzYrZX6S
         2Obb19unA2WS0n7OlTmfl+G9D3Se0aDWGkW7vR+EH0fitln1yIQ/MdMRJVbLcNHNy/6h
         vBDJZVio67S+p7evSSI00d1rLvrvKFX/2STGOUPAg6rkr4MuIMplWKi89Uj3xVGqwZaq
         errg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4b5Vj2Mu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe34.google.com (mail-vs1-xe34.google.com. [2607:f8b0:4864:20::e34])
        by gmr-mx.google.com with ESMTPS id ea14-20020a056a004c0e00b0068fc872aba7si305926pfb.0.2023.10.18.09.22.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Oct 2023 09:22:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) client-ip=2607:f8b0:4864:20::e34;
Received: by mail-vs1-xe34.google.com with SMTP id ada2fe7eead31-45853ab5556so518080137.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Oct 2023 09:22:53 -0700 (PDT)
X-Received: by 2002:a67:e14c:0:b0:457:cc6c:9491 with SMTP id
 o12-20020a67e14c000000b00457cc6c9491mr5467384vsl.17.1697646172621; Wed, 18
 Oct 2023 09:22:52 -0700 (PDT)
MIME-Version: 1.0
References: <20231018153147.167393-1-hamza.mahfooz@amd.com>
In-Reply-To: <20231018153147.167393-1-hamza.mahfooz@amd.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Oct 2023 18:22:14 +0200
Message-ID: <CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ==xmH--4E65g@mail.gmail.com>
Subject: Re: [PATCH] lib: Kconfig: disable dynamic sanitizers for test builds
To: Hamza Mahfooz <hamza.mahfooz@amd.com>
Cc: linux-kernel@vger.kernel.org, Rodrigo Siqueira <rodrigo.siqueira@amd.com>, 
	Harry Wentland <harry.wentland@amd.com>, Alex Deucher <alexander.deucher@amd.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4b5Vj2Mu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as
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

On Wed, 18 Oct 2023 at 17:32, 'Hamza Mahfooz' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> kasan, kcsan and kmsan all have the tendency to blow up the stack
> and there isn't a lot of value in having them enabled for test builds,
> since they are intended to be useful for runtime debugging. So, disable
> them for test builds.
>
> Signed-off-by: Hamza Mahfooz <hamza.mahfooz@amd.com>
> ---
>  lib/Kconfig.kasan | 1 +
>  lib/Kconfig.kcsan | 1 +
>  lib/Kconfig.kmsan | 1 +
>  3 files changed, 3 insertions(+)

Do you have links to discussions that motivate this change? This has
been discussed in the past. One recommendation is to adjust the
build/test scripts to exclude some combination of configs if they are
causing issues. Or we increase CONFIG_FRAME_WARN if one of them is
enabled (KMSAN sets it to 0, 32-bit KASAN increases it a bit).

That being said, we're aware of KASAN having had more issues and there
are some suboptions that have been disabled because of that (like
KASAN_STACK). I'm not sure if Clang's KASAN instrumentation has had
some recent improvements (we did investigate it, but I can't recall
what the outcome was [1]) - maybe try a more recent compiler? However,
KCSAN and KMSAN shouldn't have any issues (if KMSAN is enabled,
FRAME_WARN is 0). And having build tests with them enabled isn't
useless at all: we're making sure that these tools (even though only
for debugging), still work. We _want_ them to work during random build
testing!

Please share the concrete problem you're having, because this change
will make things worse for everyone in the long run.

[1] https://github.com/llvm/llvm-project/issues/38157

> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index fdca89c05745..fbd85c4872c0 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -38,6 +38,7 @@ menuconfig KASAN
>                     CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
>                    HAVE_ARCH_KASAN_HW_TAGS
>         depends on (SLUB && SYSFS && !SLUB_TINY) || (SLAB && !DEBUG_SLAB)
> +       depends on !COMPILE_TEST
>         select STACKDEPOT_ALWAYS_INIT
>         help
>           Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety

This also disables KASAN_HW_TAGS, which is actually enabled in
production kernels and does not use any compiler instrumentation.

> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 609ddfc73de5..7bcefdbfb46f 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -14,6 +14,7 @@ menuconfig KCSAN
>         bool "KCSAN: dynamic data race detector"
>         depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
>         depends on DEBUG_KERNEL && !KASAN
> +       depends on !COMPILE_TEST
>         select CONSTRUCTORS
>         select STACKTRACE
>         help
> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> index ef2c8f256c57..eb05c885d3fd 100644
> --- a/lib/Kconfig.kmsan
> +++ b/lib/Kconfig.kmsan
> @@ -13,6 +13,7 @@ config KMSAN
>         depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
>         depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
>         depends on !PREEMPT_RT
> +       depends on !COMPILE_TEST

KMSAN already selects FRAME_WARN of 0 and should not cause you any
issues during build testing.

Nack.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ%3D%3DxmH--4E65g%40mail.gmail.com.
