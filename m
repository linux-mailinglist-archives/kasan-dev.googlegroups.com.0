Return-Path: <kasan-dev+bncBDW2JDUY5AORBBXOSWPQMGQEUZP7D3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id B89B5691399
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 23:43:19 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id c20-20020a67c414000000b003ea09dfe14asf609371vsk.7
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 14:43:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675982598; cv=pass;
        d=google.com; s=arc-20160816;
        b=k1xLddugTy9Q2Hdfjm4yq+evlGV+pLN0+vsFlI61XJh/sPW7ngGld+1lYMECnlDBxW
         L/EY4ojJcDtWb3C66JPzMbrVo2xzbmb3aJte4NfKdiTlMSIUnG8ed6F8Og/oBiJIo0Rq
         SdP6PcND6IvARjc0LAIaCVwsL5Y8cOJVkq4Xb7ba2CpDqxTUzMVfDf24oRVHkushckcJ
         o2DXc74QR30U8tTFHccXUPkg+PIObaeSzO6nzft95Lwp5JVeUvrnvon6g85gMOEeoCXF
         qdTBl4UOw/vg761xhFauYCzjeewPPLGEWel2Aqjt4gVs3o5C7BnHcveGhxXy50owYg7E
         RLSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=BxtlQZkVKlpebvluLHcsiM7qhhf5ra1JXNxv7xHh98U=;
        b=eDbeSFRTMOQOtX/fvo0cnfRfdLXR1iuMRVexAG0vv6stAgsADJXBz6ZbLM28bqls96
         4PfnSzL0/T1D+O0tpHf0sVs72+xzu8NyT8DLbRKzQPRp91XX6J6gqrQtYCrf6rBGXon2
         Lh+4t/ZCWOEvo46jLYt3lc4NkwtaAey6O2ZXNORf0hihQGlJ5Socaem+w0xtrkRXb4cZ
         O9gLKqtZb8pQNUb0Q94D6qleEJEeOrqujbEPaZPUry6rZxlw5vHR3T/P93dzPWn0z9mi
         8gaSOigeZ9GlJkFL3xqwCOHG7VBQIktXSEV6ouqF1wYxwj2eJrcjJQ9Ni06iRykI2VyQ
         4MNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=C2Raiuj9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BxtlQZkVKlpebvluLHcsiM7qhhf5ra1JXNxv7xHh98U=;
        b=VZTPNEUPDl2T9/8c1VM/VFvhZHnl56M2sOD11FuQtWDI5brFKuoj6brF1YGNLR6pCM
         ABIUmVeJ+qajEEkarvktaQsQOEFCnq8DBtGwU3IOOB0CLGwBktSG60jFBcrMY6aRiT/f
         Aq1gJpE8/ji385sTr0lI7Sy/pJo+ker8y1FekWSlyyqSd5oJ8ZEs44mpt8JMIubBVZ7a
         y8mWNYIwDXRjpwBmEJZMolDSpyop3qX7j9IB5Pvr81V7SGXxX4fIK5EllBzbrcefJyyw
         s48JlH3b4tEpn9a8GqcSRPGGrQXiVilJk/fzHjBQQo0TwJTieidCOpYV1B+2CjMarCbT
         NHwg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=BxtlQZkVKlpebvluLHcsiM7qhhf5ra1JXNxv7xHh98U=;
        b=ghM9jqmdiZJt1XsaKnz/rjuYN9I228G8BDvl76V2KVPeFd4EkQNHHCYcM1U+OVSqtJ
         TbltaNuobgOO2Uu41dfRtEoKktOHLm/25reUhgQRpsVa/I8vuFT36IuiwZTW3nMF+5eA
         4drJtKxDf3aBLJlgkUoYzz/6QkS6zwYtfqPPvJScuGbfgPcUzYFo5mU38NTUB8++T+uM
         aF3H5t9Sx2xN5PcOQS7R+bHi6yMACA4orgF6Qt8bDqOzE785bH5P3RB6HYUsMlrZUcgc
         UjhkI4EDaA8dGZoQz9vRE2SJlH3oN7U6Hmw8/nFSvHFQpdVtmbPnluZL2ijsoZ75HE/c
         ftyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BxtlQZkVKlpebvluLHcsiM7qhhf5ra1JXNxv7xHh98U=;
        b=HjzoUpxp49A+mu02XlkwpaTPVw6nqpwwdxPHU40EK4JITi+MzoORCJBsCplqJkAOuP
         1/mbSY1dxEtmU9GMVpe/SRxxlX3HUyetg03gQG24Z+v6rWXsuo8azhL7Crw8M2fh04HH
         IqY8/d4112ea8xRfqZLN+/8SXrDqbLtzl24bzYhwJoYN4gJ4d0Wuki9UQek/ggEry730
         R6VuumVc5GlJxyesAC/DmQacgkVCIT7vLnoXV7rWO3KH6GjlDfvq2cArhxOC4WOMNa+f
         e/abQeI60YQNJyZ60w/c1wjPhz0dHvq9xP1p24QvmJWr0ZFpwHjVgsYSoLSKB/ZxYC0k
         zg+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUHaG/R4tDhiPzxsXzJYoYwgQqs3rP2kDpy7flo8vIJZ085kaXl
	nYczBAcwqbBSSfvAofhwjeM=
X-Google-Smtp-Source: AK7set8GB0j7Vw8kp66PNOl7siE2qT1YlIBAm2/vYx6Qykj764aQ20bN7f+Jb7LEaX1WD/t9utvq/w==
X-Received: by 2002:a67:ab07:0:b0:401:5ed:9a8 with SMTP id u7-20020a67ab07000000b0040105ed09a8mr2732896vse.10.1675982598600;
        Thu, 09 Feb 2023 14:43:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:5cd8:0:b0:400:7c10:91d3 with SMTP id q207-20020a1f5cd8000000b004007c1091d3ls673243vkb.6.-pod-prod-gmail;
 Thu, 09 Feb 2023 14:43:18 -0800 (PST)
X-Received: by 2002:a05:6122:1796:b0:400:fe53:afc8 with SMTP id o22-20020a056122179600b00400fe53afc8mr5772305vkf.10.1675982597933;
        Thu, 09 Feb 2023 14:43:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675982597; cv=none;
        d=google.com; s=arc-20160816;
        b=bQ7ANdB5jWKecHYb+c9vJ5RwTTz5XvvYk3toSp2k34ZgUSglvKBIhj7u/phNUhyzja
         6/8FZhKHdaxSIVo/GyUn9WWxU66PFI4OtvoQ9jWZJmp8woCRGdUlJ+QQjZnRW00UQtD7
         kVhLgLpp0IkfloPXLNdPEi0wPnoKL7dtM+nYV7gTU6DrOkx0D14UW1lqMjXMF4fwicKm
         Y8HYHXuLaMFHnEk2Lw3cdp8pwVSM+gjPbAiwnveDiW6V5BXU/aF8kOgDD0+GriJ2w7ww
         rpEGzthpt/lSlXIlOtglMuXlSkREFOA3x3oJSdu5pftcoLtM9A+I7jwAME0ZsBOhduBu
         zOXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zptQebfexw7ADz0p1vyYhnhBqZ69swmuxOP2gn0h68k=;
        b=HkyKykhIoOL/nrYpZAeaCBwrTMlZGpcZGw0B2VknK3eEX3An5X9pvX0i5bmXp5jE/l
         Dwxa8MWY1yb9NtOXSe7NQJPtyT0JVX88u3gA0HQ/3eC7SeYfQGTbDBwm5mSduPlePHdb
         vfeThtHFedn1JC7WKGqe1JvKMrBQ7R/As4VB6alCZHyV2IBAopCaJdWSUaCT6R5PmQZx
         muUveLvhDEO6aAd2jaGmElKLHMMj6FdIiTFaW4kQPCAOiBej2Y6kwViFoMOMt5VyTqRS
         8bBQA+HIVgJdbMBjmrln9PJLyPIooS6/m6ovm/KpsbmaklzC4wEjOqobsx7thWCOanK4
         iNHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=C2Raiuj9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id j2-20020ac5c642000000b00400dba9ad27si261429vkl.0.2023.02.09.14.43.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 14:43:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d8so3373040plr.10
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 14:43:17 -0800 (PST)
X-Received: by 2002:a17:90a:764d:b0:232:ccdc:2687 with SMTP id
 s13-20020a17090a764d00b00232ccdc2687mr955780pjl.100.1675982597028; Thu, 09
 Feb 2023 14:43:17 -0800 (PST)
MIME-Version: 1.0
References: <20230208184203.2260394-1-elver@google.com>
In-Reply-To: <20230208184203.2260394-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Feb 2023 23:43:05 +0100
Message-ID: <CA+fCnZeU=pRcyiBpj3nyri0ow+ZYp=ewU3dtSVm_6mh73y1NTA@mail.gmail.com>
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable memintrinsics
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ingo Molnar <mingo@kernel.org>, Tony Lindgren <tony@atomide.com>, 
	Ulf Hansson <ulf.hansson@linaro.org>, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=C2Raiuj9;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Feb 8, 2023 at 7:42 PM Marco Elver <elver@google.com> wrote:
>
> Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
> with __asan_ in instrumented functions: https://reviews.llvm.org/D122724

Hi Marco,

Does this option affect all functions or only the ones that are marked
with no_sanitize?

Based on the LLVM patch description, should we also change the normal
memcpy/memset/memmove to be noninstrumented?

These __asan_mem* functions are not defined in the kernel AFAICS.
Should we add them?

Or maybe we should just use "__" as the prefix, as right now __mem*
functions are the ones that are not instrumented?

Thanks!

> GCC does not yet have similar support.
>
> Use it to regain KASAN instrumentation of memcpy/memset/memmove on
> architectures that require noinstr to be really free from instrumented
> mem*() functions (all GENERIC_ENTRY architectures).
>
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>
> The Fixes tag is just there to show the dependency, and that people
> shouldn't apply this patch without 69d4c0d32186.
>
> ---
>  scripts/Makefile.kasan | 7 +++++++
>  1 file changed, 7 insertions(+)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index b9e94c5e7097..78336b04c077 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -38,6 +38,13 @@ endif
>
>  CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
>
> +ifdef CONFIG_GENERIC_ENTRY
> +# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
> +# instead. With compilers that don't support this option, compiler-inserted
> +# memintrinsics won't be checked by KASAN.
> +CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix)
> +endif
> +
>  endif # CONFIG_KASAN_GENERIC
>
>  ifdef CONFIG_KASAN_SW_TAGS
> --
> 2.39.1.519.gcb327c4b5f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeU%3DpRcyiBpj3nyri0ow%2BZYp%3DewU3dtSVm_6mh73y1NTA%40mail.gmail.com.
