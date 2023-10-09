Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTH2R2UQMGQEQQA7PNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A5E197BD56F
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 10:43:57 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3516579e7f7sf32848165ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 01:43:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696841036; cv=pass;
        d=google.com; s=arc-20160816;
        b=mUm0glR2ycZurzWUFlkKsBFukupz9c6/aI+zvemCgnzqIx8xw6uElVOMHoWRbjQnOU
         3jP422Dpx1jN/HPYMJGbrFo4iVI8U3AH8eOlHMOGYc6QGtLDXYn7BHUKX+Iqr2zYG7Si
         jfq72NimiqhLKo9cpPN93WcLRzloip5jLIw8aMTRJ6zJ22mf9bS6qg5M/KxGAezGqfxk
         bn5ex34BIK+IK2Lmt7owNE/kww5wh9CBKDwsgshd2NTT6UOlz429021srWe+aYMzkY+o
         IPqMfLVLqbmbz2L7RJCOjQw9L0zHKJOVegjIZ27fmlYGOeidRkHXoGWe/XALzQBCyy6z
         GdiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MLT5E4Z2lxnJBnH6BnxAdVCFm02pJYOsHiEjZg15S0c=;
        fh=PAMwWFIyYDX+NdZBJdEl/NRibBpELs9BvAUsR3hyWOM=;
        b=WqKO4iXHQPcefSe/fKdhedY5AipTa1QOSML7gp+oXPrELO+RO/xXpLbgGQwF3LTq/H
         RgfpWQAXWf4UwhPt1YLmoXWA34mK/tHQPpfg62Rmvqo+p0udPlhFYGMjM3IV1+ruwoNT
         0Hn9UiWzlsdrBd6UZyPelr0R6shh5KuMMpBbHjrgyJK3KjQ0+VoeUNkzXeugQsmkq118
         Llagsn0hq7cs5vJGYgFfLdLnj5sd/YacnvRgCeiMFKMpTTAj+PrKE4rHUgUGfyj4oXXM
         mtJoEaSYUYQgnPMKmvojtCWIJ+LMRZkdHQY1X7Dx/HfuhBUNs/+XWqq+jLRuVP7q7AGl
         qP3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="AIyLM83/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696841036; x=1697445836; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MLT5E4Z2lxnJBnH6BnxAdVCFm02pJYOsHiEjZg15S0c=;
        b=n0ouMU3+VmO6vtUPT6IdRFDTCto+7PyZVk3vGO7mWEXtfguqXADvCuEo4G1MYYiI7q
         bLERCnpVPpMmfR+xYn3DwUvxvDu3JzFMLoxCUN914mfAbAk/GLr9RMHmfSlUleFcQeO9
         pxsl2xOWL0ENr+EZw8vk+2TqGfaC1PlJFbrXzyP8njbX7uDuLPRjuk2asDjhPe5+IcDi
         3slgNXHi79CuBPILos5BklwpduJ+dUwXdUujxHNWXa2BIqqrqzCpL2rFrSe9lrnvAryL
         0jHnxZx7mZx9uiFNU4MKMz6WElAm1moasgmX0zDZZlTw3VIVyRilcQK4XPgVBxD+igTR
         mupQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696841036; x=1697445836;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MLT5E4Z2lxnJBnH6BnxAdVCFm02pJYOsHiEjZg15S0c=;
        b=BTf5k7u8uDRjMIEs+lEDiHplcNam1mAbsVgWbzAlZ74LVwCc7tnIVxGns/VRzzwP2+
         zN+dUp7Njkr3OIVjpOaF2lPG6bncuy2qrIeKZgQ6efdfYJn4tVYP+Lb32EDafKxTAwUf
         WBzn6kLzZPUJxk9wYD8miJh9CPA+8BomBaddcd4pC88sezdmWUaFqJmHu227a84AKdWy
         EIy/vnkAJsge3Nnr5gRbDxQ7YudfghjRqnMSDu6sARFkEClxIUwbf/Hr9FSua8VnNZzm
         J9uRKgzHts1DE0WYWY2j4wf1YK8T0pK3o4XrCIcgK/zDjgx8tipdHEMLQP+URkQwq+PZ
         5YCw==
X-Gm-Message-State: AOJu0Yyurx8AxIYsHX34cwyV1dDXsV/duEVomhymzETOBUb0BTUIQln6
	m7CK6dMRdE7Z4OOQOUGHVSA=
X-Google-Smtp-Source: AGHT+IE90K01188XBF8HXFCJgk8IJZprcOJ/C1PLB+63vBaT7x0lQNumKzVMXX192dSRoTh79ZKiZA==
X-Received: by 2002:a05:6e02:170c:b0:350:f510:3990 with SMTP id u12-20020a056e02170c00b00350f5103990mr20825397ill.2.1696841036379;
        Mon, 09 Oct 2023 01:43:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8e10:0:b0:349:aa0:9696 with SMTP id c16-20020a928e10000000b003490aa09696ls564753ild.1.-pod-prod-04-us;
 Mon, 09 Oct 2023 01:43:55 -0700 (PDT)
X-Received: by 2002:a05:6e02:170c:b0:350:f510:3990 with SMTP id u12-20020a056e02170c00b00350f5103990mr20825371ill.2.1696841035464;
        Mon, 09 Oct 2023 01:43:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696841035; cv=none;
        d=google.com; s=arc-20160816;
        b=zaTzA5yZ/+nnKbJyn9n1lV490lgUxDuXxt135jvgF3TBePblBUi5v4CIeiV0rImyrB
         Q+oz0W0UFr/jv2YNQHy+x0uZc3dArZpf8tSiykjk7SdgdKnRQuuo2EzZVPA5E6g/igzu
         9PtxPct8ABwhAOw7UkPzi4ZVgQ/VcBOTns1O7QeA0JJyR6V9zQRM2aRqWsd+52v4sYSo
         cOx7AkskKjA5HtwUWKd8Jfrzgky8NwtfCjl1C37C7fLU0MPq6feKriXDfTSxnC9U1tDp
         5zeaO8ZGH/qbSMlaWzpjDoOXhbGE08Y5prb+3CD/xpKv5c+tAOmLLCldBn314QEPwTkU
         /cUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YuCgwwEHpzwhAs2/TQufmyBSZG1iz25UrBV2AHFZCKg=;
        fh=PAMwWFIyYDX+NdZBJdEl/NRibBpELs9BvAUsR3hyWOM=;
        b=VU3H4ZssJGM/NFAIwiXJQ6SnGkNb47GMj1ILqxY+yCd6vs9D+chRFx6v7hWHNxHHV4
         fhYUjFtb7bKt+SAieXA/M4IzVtxvR+DyQRSYj5GLI2FnH3sPE3YONhKvxabWz5zWCTbK
         EbCqdn7JkShvD0KRuq8zsCMUkrIKrmXSGXr+stG6aX9b5bb1cUqaNxsoc6vABAxdpOS+
         G3RSyv32Gh+6wEj2E3XMbTkgBhCyr+W+fq8Hm1Q9qQd+VTLIZ5+M4MOATc9ch6sQXCUC
         XvdQxs4ycrmcbtI5DkZIM2OqrS1Gjc2Ay8qB00/7DYA3x/GdurAbu/DLBvKg3zk13aPz
         drzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="AIyLM83/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92a.google.com (mail-ua1-x92a.google.com. [2607:f8b0:4864:20::92a])
        by gmr-mx.google.com with ESMTPS id d10-20020a92d5ca000000b0034f4837dd87si543832ilq.4.2023.10.09.01.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 01:43:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) client-ip=2607:f8b0:4864:20::92a;
Received: by mail-ua1-x92a.google.com with SMTP id a1e0cc1a2514c-79df12ff0f0so1710802241.3
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 01:43:55 -0700 (PDT)
X-Received: by 2002:a05:6102:8c:b0:44d:453c:a838 with SMTP id
 t12-20020a056102008c00b0044d453ca838mr10464598vsp.5.1696841034758; Mon, 09
 Oct 2023 01:43:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1696605143.git.andreyknvl@google.com> <35589629806cf0840e5f01ec9d8011a7bad648df.1696605143.git.andreyknvl@google.com>
In-Reply-To: <35589629806cf0840e5f01ec9d8011a7bad648df.1696605143.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 10:43:18 +0200
Message-ID: <CANpmjNOWirLmtSrNOOfs8Lm0c+uUkfdh0Zf5OcmDfdfNk2W2dg@mail.gmail.com>
Subject: Re: [PATCH 2/5] kasan: unify printk prefixes
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="AIyLM83/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as
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

On Fri, 6 Oct 2023 at 17:18, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Unify prefixes for printk messages in mm/kasan/.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/kasan_test.c        | 2 +-
>  mm/kasan/kasan_test_module.c | 2 +-
>  mm/kasan/quarantine.c        | 4 +++-
>  mm/kasan/report_generic.c    | 6 +++---
>  4 files changed, 8 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index b61cc6a42541..c707d6c6e019 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -5,7 +5,7 @@
>   * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
>   */
>
> -#define pr_fmt(fmt) "kasan_test: " fmt
> +#define pr_fmt(fmt) "kasan: test: " fmt
>
>  #include <kunit/test.h>
>  #include <linux/bitops.h>
> diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
> index 7be7bed456ef..8b7b3ea2c74e 100644
> --- a/mm/kasan/kasan_test_module.c
> +++ b/mm/kasan/kasan_test_module.c
> @@ -5,7 +5,7 @@
>   * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
>   */
>
> -#define pr_fmt(fmt) "kasan test: %s " fmt, __func__
> +#define pr_fmt(fmt) "kasan: test: " fmt
>
>  #include <linux/mman.h>
>  #include <linux/module.h>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 152dca73f398..ca4529156735 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -8,6 +8,8 @@
>   * Based on code by Dmitry Chernenkov.
>   */
>
> +#define pr_fmt(fmt) "kasan: " fmt
> +
>  #include <linux/gfp.h>
>  #include <linux/hash.h>
>  #include <linux/kernel.h>
> @@ -414,7 +416,7 @@ static int __init kasan_cpu_quarantine_init(void)
>         ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
>                                 kasan_cpu_online, kasan_cpu_offline);
>         if (ret < 0)
> -               pr_err("kasan cpu quarantine register failed [%d]\n", ret);
> +               pr_err("cpu quarantine register failed [%d]\n", ret);
>         return ret;
>  }
>  late_initcall(kasan_cpu_quarantine_init);
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 51a1e8a8877f..99cbcd73cff7 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -220,7 +220,7 @@ static bool __must_check tokenize_frame_descr(const char **frame_descr,
>                 const size_t tok_len = sep - *frame_descr;
>
>                 if (tok_len + 1 > max_tok_len) {
> -                       pr_err("KASAN internal error: frame description too long: %s\n",
> +                       pr_err("internal error: frame description too long: %s\n",
>                                *frame_descr);
>                         return false;
>                 }
> @@ -233,7 +233,7 @@ static bool __must_check tokenize_frame_descr(const char **frame_descr,
>         *frame_descr = sep + 1;
>
>         if (value != NULL && kstrtoul(token, 10, value)) {
> -               pr_err("KASAN internal error: not a valid number: %s\n", token);
> +               pr_err("internal error: not a valid number: %s\n", token);
>                 return false;
>         }
>
> @@ -323,7 +323,7 @@ static bool __must_check get_address_stack_frame_info(const void *addr,
>
>         frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
>         if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
> -               pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
> +               pr_err("internal error: frame has invalid marker: %lu\n",
>                        frame[0]);
>                 return false;
>         }
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOWirLmtSrNOOfs8Lm0c%2BuUkfdh0Zf5OcmDfdfNk2W2dg%40mail.gmail.com.
