Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDHG52UQMGQEXBRXFVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B6DA7D98FF
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 14:54:37 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-58403acbbe2sf2552698eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 05:54:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698411276; cv=pass;
        d=google.com; s=arc-20160816;
        b=VCeL9ygk1CVe6NAxyLOAJ6/uBdvlm1XL6V1EnGu9Ep/FcnD+kYFv7iE+yLfZSnLzuc
         +eAuCBZPTI9oohTjlUCntcS2lgwuKt4uAgkeKboAilYzH8kSQSvhdxymyjOvWeAqCvsV
         52GzSgs9lW5GiAd8LVuBvQiSwwInIcD1dYpFOzcZkfn00UHMtzlLZqlyd7/nPCQdol3V
         vfla2/wq2tP3LqhCU88mFoDjcLvEFA0PEzmOh6Bddz+ablirh3o9kS2npMJaaypjfCOA
         HNllOPHlpL81XhaOifan3MxVrRVwRXQ9pbKYClvRi5MlXQ5PfifmTkk2EDI4I2Fi/cOS
         P0mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LlGSk3V21iS48xZ6NGu9cMdCEOa3zy7pU4Y4lgqTW58=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=N3NMrmSlD/rRI5LtYrSHaV78BcgNh+QrXI2BjaArMRiYYS2QU6cx0T2m5QupTLAPdF
         cmQ/dw1iZ6SLw2z0bkfSlu44Nicv8CHu7bg3BtUMRnNRUO43iHqWQy8AfWnGCU5ijt1+
         M5hYjLiBqMZiBloUc5RreLPeUooSs42YYpNzJN67CHyggmZrrEqffCMy1s2DT1Y9E6zO
         tgfCumQwiXsPgNrzYIqz7wvipy3yBHK1RfobNGYAnAZwSQ6N12ecjgJWtAINV7opKOxm
         erWfBkYuWxv20+lEsEZwqGcloG4iwwWNuyBA3VQJt/yVhyLPIqlpNIQGPlvMf/N1aI5I
         XQ5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1+fvjHqb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698411276; x=1699016076; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LlGSk3V21iS48xZ6NGu9cMdCEOa3zy7pU4Y4lgqTW58=;
        b=ILaXBiuFdsaWp+rbXYHF0YiX94eOf+8vvm0aTlcWOPjWClq4+3TLf5aONPlL2uL+bU
         c/g1YrV/hu+2aY/Jtt1r7CVs1kodXi40MkKYjFcOaAXO1eoAXInFRhdtbTILfPAihseI
         rEgh2N6PGfHqAtfbJN9WIFa9nGR5qYlgLiTnL6ZsIFQir4W2on6qDPo8DLdFabGsPjdi
         DXKBdU4Ud7BbKQwbuY7ymyiSeXPKLlYSoLy4kFyTnJmPRxEXeV/XWkGe005YSuOLlyyx
         aJfa9NfDV6DYIn8wn8X0BAEc8S3UOM2NCZJkbn03ft5wM4t6NePZmkgfhmjHFbK8jbMt
         G5rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698411276; x=1699016076;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LlGSk3V21iS48xZ6NGu9cMdCEOa3zy7pU4Y4lgqTW58=;
        b=qT0xR4prgZunwBSLY1QRqVOrcvzfCJn1xdZ7MGkaXyovHENY6VU/52DLtepRDsZbwZ
         kytUxKqG8t1hRMxBoIkJswrFPE3m2dzTtjAUE8U3m7NNd8DExRjIvR63jg0IqBjn5c++
         k6bvrdawPgIfz7YvlrDE0Ply9SzrEYO/kts4SFXCkksqE7Ed825Ji8xosDmPXBLHN1Mn
         AHwAK3KviL75rdzXDX+AgnOQxJuH9zCbkHhg4ljGMQ8KY3Bv1Y7apqu7C4W+kfNDjkxP
         +AFpS9WoKEXiFwweDkgjZe5e+JiJMpwdgksjxY7PXO5V3C1RoQXVrq0cSsOXFuj1NgI9
         +bXA==
X-Gm-Message-State: AOJu0YxsqJyugQxAS6aZyfvQI3T8I3Rxf7H1q5GOi9t56AhIDw+F/t0o
	uLUMAHYry2BrgifOlcGe8V0=
X-Google-Smtp-Source: AGHT+IHUsZonCjDJq4qAdbiuxNeKGqeUiziM38YjGaDYpZWgeMnlV5+t1m1DI0G5q7ZsyAn7B0FTZg==
X-Received: by 2002:a4a:db8d:0:b0:581:9066:49 with SMTP id s13-20020a4adb8d000000b0058190660049mr2660448oou.0.1698411276187;
        Fri, 27 Oct 2023 05:54:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ae8e:0:b0:57b:5446:2f55 with SMTP id u14-20020a4aae8e000000b0057b54462f55ls43939oon.2.-pod-prod-06-us;
 Fri, 27 Oct 2023 05:54:35 -0700 (PDT)
X-Received: by 2002:a54:4592:0:b0:3af:26e3:92e with SMTP id z18-20020a544592000000b003af26e3092emr2194344oib.28.1698411275489;
        Fri, 27 Oct 2023 05:54:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698411275; cv=none;
        d=google.com; s=arc-20160816;
        b=lZKdYmACZqs+p5sXEyMRvAjW24LQ4svQNxI51l/cIGAiyI0A+PZLmufOt2+YC1Vg2y
         hpX3e8S0AO4Q8fgabgFcttD7czSHq9DwVVmwe1K/Fk9wHwgwrZdVqH6tx7ScMWCAzFg0
         K2/gtNMNnOc2Wx4shkjJCGQKBfwITWOL+nm4yK/ZL3t14ziTCGYV8QUi9kwFyjv0AV2h
         UOluGvLhNgzwetIL+km45jqnNtHD6D8Apzfr4NsoVEaqcvAo7CXQ4Bt4f0JKRTdSTy/t
         PHglMAZBeBKr7rU0FFheYc5rrGBfz1pYEb6BC409MfIDzFN8gb4aJx4OYvnqOtoeknll
         xKRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DwNfFFS57QhT5eEqPbXTCH8wXRCZS40xeP0h1OwCxS4=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=ixUfNXKzIcerNeC5zSzBkK9y3V55ghmz6IL/7WwqVE2Qn6gV4pAN8dCwxvvMDmLaBs
         2B6LERHJsjeK9KuE0prRG3AwDilUqV13xaNiJBe3rsY+37N5VM5MOqnPk/prPXKcNmdQ
         Z1HCqEXUeTZIWaHCUKIXAyGCdzMIFpkWxnqcOLvpoBgGTUWwPRvaGj6gFe8v+Crxu45m
         E6lhetRWYzdqM9/mOQB2EBgIBYWmvAYLfjVW1Uui4OeO6To8Yr3yGqj9kUIV1OHcnSQP
         sNeascJILMew799PChUU2vg35hOLQ4K5b0TBQFA6o1e1aFEdDkQYx7LxSvjh0u9vOVMS
         gIDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1+fvjHqb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92d.google.com (mail-ua1-x92d.google.com. [2607:f8b0:4864:20::92d])
        by gmr-mx.google.com with ESMTPS id eq10-20020a056808448a00b003adc0ea0dc4si113112oib.1.2023.10.27.05.54.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Oct 2023 05:54:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) client-ip=2607:f8b0:4864:20::92d;
Received: by mail-ua1-x92d.google.com with SMTP id a1e0cc1a2514c-7b625ed7208so920793241.1
        for <kasan-dev@googlegroups.com>; Fri, 27 Oct 2023 05:54:35 -0700 (PDT)
X-Received: by 2002:a67:c105:0:b0:44d:4a41:893f with SMTP id
 d5-20020a67c105000000b0044d4a41893fmr2921932vsj.9.1698411274739; Fri, 27 Oct
 2023 05:54:34 -0700 (PDT)
MIME-Version: 1.0
References: <e237a31ef7ca6213c46f87e4609bd7d3eb48fedf.1698351974.git.andreyknvl@google.com>
In-Reply-To: <e237a31ef7ca6213c46f87e4609bd7d3eb48fedf.1698351974.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Oct 2023 14:53:57 +0200
Message-ID: <CANpmjNOrKpkV3aEPsTZSuL6Nb7R5NyiBh84xkbxM-802nzDtBg@mail.gmail.com>
Subject: Re: [PATCH 1/1] lib/stackdepot: print disabled message only if truly disabled
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1+fvjHqb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as
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

On Thu, 26 Oct 2023 at 22:28, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Currently, if stack_depot_disable=off is passed to the kernel
> command-line after stack_depot_disable=on, stack depot prints a message
> that it is disabled, while it is actually enabled.
>
> Fix this by moving printing the disabled message to
> stack_depot_early_init. Place it before the
> __stack_depot_early_init_requested check, so that the message is printed
> even if early stack depot init has not been requested.
>
> Also drop the stack_table = NULL assignment from disable_stack_depot,
> as stack_table is NULL by default.
>
> Fixes: e1fdc403349c ("lib: stackdepot: add support to disable stack depot")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

for the change here, but there's a way to make it simpler (see below).

> ---
>  lib/stackdepot.c | 24 +++++++++++++++---------
>  1 file changed, 15 insertions(+), 9 deletions(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 2f5aa851834e..0eeaef4f2523 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -101,14 +101,7 @@ static int next_pool_required = 1;
>
>  static int __init disable_stack_depot(char *str)
>  {
> -       int ret;
> -
> -       ret = kstrtobool(str, &stack_depot_disabled);
> -       if (!ret && stack_depot_disabled) {
> -               pr_info("disabled\n");
> -               stack_table = NULL;
> -       }
> -       return 0;
> +       return kstrtobool(str, &stack_depot_disabled);
>  }
>  early_param("stack_depot_disable", disable_stack_depot);
>
> @@ -130,6 +123,15 @@ int __init stack_depot_early_init(void)
>                 return 0;
>         __stack_depot_early_init_passed = true;
>
> +       /*
> +        * Print disabled message even if early init has not been requested:
> +        * stack_depot_init() will not print one.
> +        */
> +       if (stack_depot_disabled) {
> +               pr_info("disabled\n");
> +               return 0;
> +       }
> +
>         /*
>          * If KASAN is enabled, use the maximum order: KASAN is frequently used
>          * in fuzzing scenarios, which leads to a large number of different
> @@ -138,7 +140,11 @@ int __init stack_depot_early_init(void)
>         if (kasan_enabled() && !stack_bucket_number_order)
>                 stack_bucket_number_order = STACK_BUCKET_NUMBER_ORDER_MAX;

stack_bucket_number_order seems like a redundant variable, that should
at least be __ro_after_init. All code that does "if
(stack_bucket_number_order) ..." could just do "if (kasan_enabled())
..." and use STACK_BUCKET_NUMBER_ORDER_MAX constant directly instead.

The code here could be simplified if it was removed. No idea why it
was introduced in the first place. I think f9987921cb541 introduced it
and there it said "complemented with a boot-time kernel parameter",
but that never happened.

So I'd be in favor of removing that variable, which will also simplify
this code.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOrKpkV3aEPsTZSuL6Nb7R5NyiBh84xkbxM-802nzDtBg%40mail.gmail.com.
