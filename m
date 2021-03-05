Return-Path: <kasan-dev+bncBDX4HWEMTEBRBU5ERGBAMGQERAHOG7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id DFE2432EF47
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 16:46:28 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id a24sf1711698pfn.6
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 07:46:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614959187; cv=pass;
        d=google.com; s=arc-20160816;
        b=kgp0dOLhl2etDB2e46e/YRG2Gda82QXgvmIcoDFZnQM0YC5Nubu1AmpqXO4o0RvQjX
         ijAqhPHrBZscb1CIzCokHp6YEJP+q7dS/D0Tx8JDvokfV2lT7d8bHXVDGpONBOqGcMrd
         GwMvR5e6+WAVpWqbzinQ+/7ywmzTjT+H1s4cZCJ+cx/DaNxl2gxXC3bTLjZCkpCxKKlm
         qy+G09V6BLjvk0JOqhZqfQsu4NrjHsb2IBgrKFEoV1hkxw05E4FNzfVfUJoC3p5a8KT+
         zV0At8/nhBROz5DXJNbUYEx5n8uqKDNB2nFw/jq6tCuB7+zBSQO1ZvRFRzMgWXL5+2CQ
         Uo8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JCUR5bssJbT5QOebx88QJ+Bx75iUirHH+aowfkh4/fc=;
        b=TF/db0eoQ3Ro9/w/hy9QJ1bSv8/RVhw6uekj5e/2EGRMSH2ml63ZiHCUrhGkHnbEqx
         GuXlAQ0b9iTUzEPKjunXVDYlM+Zu6khnszIbHV19rw9ivVSj02L2ApZmNkmccjcEIjn9
         PwRd+yYvwCAHSyHMbw/nzPgzFDYSsdKwZ7GgLUtmLEAWlrjllPkz1wMhxmVuAMJVQ49A
         JV04Lg8+goYex77zTQFrxM0kUL4/3u1yDP0++MbM8TZYsBuaiYXkewztnoNt/+r1NUTT
         lP8uAKSztJ+LE9umztLD3IdMQ8Xs5mX//G+nCPJn62AXIv5Wbbf/bj73DZFiMUM5V4E7
         qb+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S5LjfiLS;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JCUR5bssJbT5QOebx88QJ+Bx75iUirHH+aowfkh4/fc=;
        b=hOcusmX8KyxBKLo1lz0hm4kTgxlQxFlK5unQIS0aJtFMq8HrAxg8VHu6XyBrLtGf9e
         wRmsHsFIxlxsuMJIRoSYx6htGl6tGYdYFTwoCnPU1TTyz3aiOIiz91iC1Jn5xbN72k80
         PT1pJzoayaQG+v651UZwAGjvCi4tZ6btja0PGlbGyK89eTEHNutme8lfMZF7r3dGmSjo
         QYHj6qTIUE3ZH3e9Kgg++QJHrcIZXIXB1pk5ZVlNsm7ik5gIWjR+hqa58o4JTU9kKJ0v
         Eb1NFMh4hIdwOXKAfVS+WEmHq9iscS/oRHj1HKTwxvgsWpMnNPfshw5T2Gl6kM5/e9vS
         R4hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JCUR5bssJbT5QOebx88QJ+Bx75iUirHH+aowfkh4/fc=;
        b=BHfaHpDMd0KmR4EBAWykwhHPxI9jVJDXt/vcACeOIGjPA8uZseMEuMItJNvnsZVwem
         9oDtUNSjKLcHv1odXxeaKSuMzAFDoG4xvkq9oRJRaJEuTsRxgL4yzNIR4FneqB4oCzp8
         uXVVsP5XAdgnEoYaeaMoSS5ZAjPZsXYo0PVXK9sNxGauKEZCGtOyIhvrFxOdHuZKrZHs
         ymDK4hZyxc4AIu8jnAIeLhVAfjNcNtF7CPXKbiI6uxncKR2ymFr/D9SpP2ASZnMR2Tdu
         jeu8RNjtExVLDEBo2X/Y6AcUpoIon6yu31ehFcFWp5kFfrLIo++sgvxVpO3jGCDh9/EY
         0sOQ==
X-Gm-Message-State: AOAM531TNpdTvvaNStzxyBzZuv9gFaHVhXsyZ5RlykcEl1E3LG+EuQ2j
	5uTaPJFp6hv9s1Qx+zbv7vE=
X-Google-Smtp-Source: ABdhPJyLxrpnF+zgHo7bmZ1dyoZHxMGb9ZaFmRYdIgmcbuphgJaKGAQrlQMQQOeDdc8tNy9oLtk+vw==
X-Received: by 2002:a17:90b:2304:: with SMTP id mt4mr11380165pjb.179.1614959187134;
        Fri, 05 Mar 2021 07:46:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ed0d:: with SMTP id u13ls4058347pfh.3.gmail; Fri, 05 Mar
 2021 07:46:26 -0800 (PST)
X-Received: by 2002:a63:da03:: with SMTP id c3mr8905737pgh.176.1614959186654;
        Fri, 05 Mar 2021 07:46:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614959186; cv=none;
        d=google.com; s=arc-20160816;
        b=i7sY9N6XTDGpUhRJIRdQalwltN99hgLcGr+bWHKB5Ah8ChB4p/VyebrWkqM0Rdnuce
         A+z77Z2YwCFZFFRFQF4jyux49x29DGrOWuDDiNtMOS/HptSgLya/cfNGnWNqWev0Z+FV
         A2nIo+Mba8g0i3QqqEsBte1VaLfR1QZxlbLeIKFMTVsc/4ed8Ddt/2JbMNwpwkxVw15O
         MC4VKaWE7h1dB+crQafbhlrq0nHqoV8oGmrhYRH0TwqAys+9k09PJT20W/8bxrGbCcIR
         ggJwILYKqdDptN5mVtd1VyntJns6popPPHgnZ0zZ+/yJXewhGpVaWvapwvC7vJTagXCQ
         h1rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P/UOJ2ouh3jCawvJJDBF9MwK+LARNE7PChR+Eq9d4AQ=;
        b=EsOs/P05KG/Swm2ebrxXVYsK7TdI4kv8KTCb2tLCGTcDILm4tf0C++oI2mynuPEcE4
         BykCzm8tBBeI7T9Z/2Nr50xtoYJscOS3Yamnb9RiQEFwI3ezL/GAdR3NjVtAB8vcZMyX
         W453gzXTHKwtcARet+FjurkG8ZcjWipKni0vBBKVnlPjNe6C3qwSimxRgniaPoRl71H4
         9+PjH7P3b4brfFu0Byzo3r0yZ2/MJdP8aM20iWmZJ1dcb26d4bOXzUV/2VJk+vLW0EuI
         qjc/ZXl48OkAa+0gIGr8RK6wcOoAkJBDnQl13kUmIqWJ1bQZh43JAGzxP1rsdxXo5dnB
         Anig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S5LjfiLS;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id h7si187404plr.3.2021.03.05.07.46.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 07:46:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id e6so1647400pgk.5
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 07:46:26 -0800 (PST)
X-Received: by 2002:a63:455d:: with SMTP id u29mr8980133pgk.286.1614959186302;
 Fri, 05 Mar 2021 07:46:26 -0800 (PST)
MIME-Version: 1.0
References: <c8e93571c18b3528aac5eb33ade213bf133d10ad.1613692950.git.andreyknvl@google.com>
In-Reply-To: <c8e93571c18b3528aac5eb33ade213bf133d10ad.1613692950.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Mar 2021 16:46:15 +0100
Message-ID: <CAAeHK+xaPBNB+VpXcj_Xdk0qg-FgDe9i1m4mEY1-ChxQND_8kA@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan: initialize shadow to TAG_INVALID for SW_TAGS
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=S5LjfiLS;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Feb 19, 2021 at 1:22 AM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Currently, KASAN_SW_TAGS uses 0xFF as the default tag value for
> unallocated memory. The underlying idea is that since that memory
> hasn't been allocated yet, it's only supposed to be dereferenced
> through a pointer with the native 0xFF tag.
>
> While this is a good idea in terms on consistency, practically it
> doesn't bring any benefit. Since the 0xFF pointer tag is a match-all
> tag, it doesn't matter what tag the accessed memory has. No accesses
> through 0xFF-tagged pointers are considered buggy by KASAN.
>
> This patch changes the default tag value for unallocated memory to 0xFE,
> which is the tag KASAN uses for inaccessible memory. This doesn't affect
> accesses through 0xFF-tagged pointer to this memory, but this allows
> KASAN to detect wild and large out-of-bounds invalid memory accesses
> through otherwise-tagged pointers.
>
> This is a prepatory patch for the next one, which changes the tag-based
> KASAN modes to not poison the boot memory.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/kasan.h | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 14f72ec96492..44c147dae7e3 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -30,7 +30,8 @@ struct kunit_kasan_expectation {
>  /* Software KASAN implementations use shadow memory. */
>
>  #ifdef CONFIG_KASAN_SW_TAGS
> -#define KASAN_SHADOW_INIT 0xFF
> +/* This matches KASAN_TAG_INVALID. */
> +#define KASAN_SHADOW_INIT 0xFE
>  #else
>  #define KASAN_SHADOW_INIT 0
>  #endif
> --
> 2.30.0.617.g56c4b15f3c-goog
>

Hi Andrew,

Could you pick up this series into mm?

The discussion on v1 of this series was hijacked discussing an unrelated issue.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxaPBNB%2BVpXcj_Xdk0qg-FgDe9i1m4mEY1-ChxQND_8kA%40mail.gmail.com.
