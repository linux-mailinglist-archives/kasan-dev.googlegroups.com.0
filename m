Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFWFYT3AKGQENVEI2YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1366C1E8103
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 16:56:24 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id b11sf1783660ioh.22
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 07:56:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590764182; cv=pass;
        d=google.com; s=arc-20160816;
        b=b68moNgdDrh+mIdMEhQIJvE5luCYaEoBHE3QPViUvkLzxeOrqyAcWA1V2vsOF20g+K
         et1VeHm/vm7kVJLBFgN8nco0sN+t6itISmo8JZcKtDr+yVLpi6RKt+tppvTX/hdpvlEq
         1o9J0SFLCR5JcqE4grXLRYh5bD33ZOPSrONC7a5jjsA0FyHiVNI/7LLyyxVvqiFKDAix
         DsaOSgAHQde+MFJL8EkAcHFJJVdYRmsiDMJQi4PtMLMsqEM8s8Yp7j+XNqSag0pLM894
         gQHpSf8jETHzc40qUI7noVHbh/x+GSLvoShknjIlS0fwznZezW7fKh5fl3S6Yzm7cUBU
         MCew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZbUAHzjyWPNDCz211dFIkvAgVV2llizngkDp6nNPGzA=;
        b=JsVM0UavArxxsEYCafOvKBhV3hMW2B0Xo0xv7I6VIkicqL2l7O78PYumzh428GbZHv
         oA8hn9fx7FlbHDvmgdlAt1D/hIXqc4yDNqm1OhMymtCBuVAsIwqKhamQnyKF20fBsXV8
         unGgl6euCuQNwWIHh5Hno+B+NrEvdau9xji3oQOW6u+YFGpfklGiVp69YCrn4ymiMFNu
         FgoNEgMY3J8liQx1h6JG84ftrvLrfLmO9hkgUUzuszQcWt/z7wSb/lxvobehlh06oTR0
         +jabhB94u1NCTqauYVQ9mWk9Q1SaFWZtGaa0cPisTPsdrxuBWoD8KvnYAE7YLLymX+mR
         INWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Bw8wnVbk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZbUAHzjyWPNDCz211dFIkvAgVV2llizngkDp6nNPGzA=;
        b=fcnxnj6skJCno3XNraS76/nAd6DDPpHlmMiQTmfixBTc934xAMAYDBpJGe6Jhcxtkc
         lLnGPb45REjYBSFb9OoEzUyu2UQrRWLJ4YLor7T0FwY7Tw9ETUcR/X+MwW6dPTXGLUXK
         4FR71NGjsSFWHMfRzdldrN+/9Je76ne6LqvW69cy7WSFEzPKTcGvxSR3ACkLwdZknvXc
         pTgmi6P7I9+v1bHWCDR5vbtkillL6u2oct0rPBnw1dYQc3ZYjkWh7w1oRNFx7HaGMb4w
         8qliKrNGPLGVuWeH27IUcMJOZWSGVOMfO7iFm4TEOlKck+L0sPGblJzpOgIWURkvOoYN
         47GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZbUAHzjyWPNDCz211dFIkvAgVV2llizngkDp6nNPGzA=;
        b=i4Qh6XU2xc7kwjlhMWFdnO5re/bUr6E99MwZjzifg2QsifL7GsEiDzDSXj/X6Qnhjr
         0tLht6Dl0SlrXhfKhkvFUgwEUosxApwJj5TmBOqS7X0V7NdqBjWvNcF1W1XTbscM4pRq
         PfFMk9+4QZLWSCbPcItFhmKOB2l/e2PuiRk+jvFbkD0N9zJzwpY93JMfLsKpT9jK4wx/
         t3NqNIya/JkwcEimnuUlHUzg1VVz4fWnbk4bHHwBwQwxp/XWwijpHoakuSi21WelKlsl
         n28iEUTWnMOMmDWXOXmVrgTGHYNGYJzgCsSnIE8pF+p1nbY4As1BRhrbha7MXdw3fF2d
         0I1Q==
X-Gm-Message-State: AOAM5303yRCSdk4PwYzX/urZkKH5fcO8Em0wng5KwA6UETgNLHR6ZN5G
	UZtMujK6XbFMFcZH0yvhNvU=
X-Google-Smtp-Source: ABdhPJw5FK7YDRipyCx5NgiZzmSwOVfqiuyvMO1VOTH/cnx0D/CDQwhsNlrqR7Z/IznKhoA5ELeATA==
X-Received: by 2002:a02:390b:: with SMTP id l11mr7597575jaa.54.1590764182596;
        Fri, 29 May 2020 07:56:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d28a:: with SMTP id p10ls1394994ilp.5.gmail; Fri, 29 May
 2020 07:56:22 -0700 (PDT)
X-Received: by 2002:a92:5cc1:: with SMTP id d62mr7428421ilg.95.1590764181895;
        Fri, 29 May 2020 07:56:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590764181; cv=none;
        d=google.com; s=arc-20160816;
        b=xtPT0GemyLiHvsEqZqnd6Xj9/mIFvZmsr+CBLu1aUaUGOQ59avVG/NDtDuePpbVHZR
         c7UKJEmUFqJuXY9Rvs2cl6DXN/I0B197Cmwe7TJ0myRyy9e4WXHj+1WEZ5H3RnZIJtQ2
         RVs9jG3HFPjRLyizkNgemvF8OJ0btM3vwatCBfKt+m/5BhKsjVXOQREdlq0YQwcaPqnH
         7znOxPa9MuVEr+jpqlSjQUsMhF5fpU4g0y7nZj+Hz6tY2BEM54Rd003fSG9GChA6vkRd
         TOz9I8BcQxa4iouVzkvHOw9dDgB4UfGWopOSll8gpPo3L2btCfEQ3JMjFxmYcVovx9B1
         DOwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bTRjknFZ9qzPfihryROjWMbhSeglLc+Gkjpy43aIAlk=;
        b=bAU8dtaqF9u1TaBQDQ2HRwTkZeBtgeJjTg7hf+CRZ+8YbDCx0s9O/HKKEilkwxKHSz
         ZzDKfRRKKu+rKrwQcwQTifKvH1QgjqoeADhnZExVDP7bE+OjfdSCjgX+5xHEtOEsjbEQ
         gsMH5R33O4ylDW1zVg0hoBoXsau1REXrOfhhhSnvfSwII7DNx0SHIJ6w7hejtaNP+oXi
         i+fYbIjGmGvtowMvXCvHgAqmUITM0PFV6+38IaPCkYo3KkZkjdORNVyq/OMu4DUD8Q/W
         qSLCbdLc+3t9DIkona/ekJNKm8T6plJpRD28EMFHg/++DEbNxygDfnqSOM89AMkrZ/tC
         M5nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Bw8wnVbk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id 2si554661iox.0.2020.05.29.07.56.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 07:56:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id b3so2751632oib.13
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 07:56:21 -0700 (PDT)
X-Received: by 2002:aca:d0d:: with SMTP id 13mr6056826oin.172.1590764181216;
 Fri, 29 May 2020 07:56:21 -0700 (PDT)
MIME-Version: 1.0
References: <ced83584eec86a1a9ce264013cf6c0da5e0add6a.1590686292.git.andreyknvl@google.com>
In-Reply-To: <ced83584eec86a1a9ce264013cf6c0da5e0add6a.1590686292.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 May 2020 16:56:09 +0200
Message-ID: <CANpmjNPr5MrwPFOW10pRkUgxwktXNiUweNj+pGJMunoZKi7Cdw@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix clang compilation warning due to stack protector
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Bw8wnVbk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Thu, 28 May 2020 at 19:20, 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> KASAN uses a single cc-option invocation to disable both conserve-stack
> and stack-protector flags. The former flag is not present in Clang, which
> causes cc-option to fail, and results in stack-protector being enabled.
>
> Fix by using separate cc-option calls for each flag. Also collect all
> flags in a variable to avoid calling cc-option multiple times for
> different files.
>
> Reported-by: Qian Cai <cai@lca.pw>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---

Thank you! I was about to send an almost identical patch, as I
encountered this when using clang.

Reviewed-by: Marco Elver <elver@google.com>

>  mm/kasan/Makefile | 21 +++++++++++++--------
>  1 file changed, 13 insertions(+), 8 deletions(-)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index de3121848ddf..bf6f7b1f6b18 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -15,14 +15,19 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
>
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
>  # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
> -CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CC_FLAGS_KASAN_CONFLICT := $(call cc-option, -fno-conserve-stack)
> +CC_FLAGS_KASAN_CONFLICT += $(call cc-option, -fno-stack-protector)
> +# Disable branch tracing to avoid recursion.
> +CC_FLAGS_KASAN_CONFLICT += -DDISABLE_BRANCH_PROFILING

Note that maybe CC_FLAGS_KASAN_RUNTIME could be a better name, because
other flags added in future might not be conflict-related. But until
that future, it doesn't really matter.

> +CFLAGS_common.o := $(CC_FLAGS_KASAN_CONFLICT)
> +CFLAGS_generic.o := $(CC_FLAGS_KASAN_CONFLICT)
> +CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_CONFLICT)
> +CFLAGS_init.o := $(CC_FLAGS_KASAN_CONFLICT)
> +CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_CONFLICT)
> +CFLAGS_report.o := $(CC_FLAGS_KASAN_CONFLICT)
> +CFLAGS_tags.o := $(CC_FLAGS_KASAN_CONFLICT)
> +CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_CONFLICT)
>
>  obj-$(CONFIG_KASAN) := common.o init.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
> --
> 2.27.0.rc0.183.gde8f92d652-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ced83584eec86a1a9ce264013cf6c0da5e0add6a.1590686292.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPr5MrwPFOW10pRkUgxwktXNiUweNj%2BpGJMunoZKi7Cdw%40mail.gmail.com.
