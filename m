Return-Path: <kasan-dev+bncBCMIZB7QWENRBC4B3KSAMGQEAXEDEXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CE6773C6F3
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Jun 2023 07:35:09 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3129fbfdea3sf774513f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 22:35:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687584908; cv=pass;
        d=google.com; s=arc-20160816;
        b=ORSUZYuOdLgMVKVrsX+OUuAjNrERnMftwTg0+waJPASuCV2cvFAKAaS5fkBQrPL/jA
         K32tp3RBFGCrDAJjTzv6mIsgZFS74o6P9KD4SCOFDgEOyiKBvYyl3zDELjx0vl37NURd
         0thZo/dOS3vnUz6GXVyMDTEjiC0vva4BvWlFi4hlYAs710VPIjomXKb6a+uGIWw5ydHV
         WxQZXmi5Mknve+Xah7w1VmPmTkd9Tn3WdKgwjDFsOEkwsI3aNqUnZFHCy3w9KNLnhoet
         VughexVTzNH667kt7iMqsv9tAOiYz2oknc28ztFM9dVnbmrWgfDPqlGob5qOsUJBNF/T
         t2gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sNPZ568PHeRV6L+pAS1DeYX3fblM0vfzOI0HLLvj3lA=;
        b=s6D9qrAZi+GCA2Jk7zq/bHogJSKiloMSKnv1n/kNXMDaMX3t3v6+VKgSw4N6ger4HN
         /0zF6kR41tvAKsdTwo60kr3wZaViIV5pfFpuAnjgj1/o8Za0j/Nf4yVsnvhYPvmwWV3y
         IltaeG4Cn59qV8qWKXi2OiMjO4dpC2yFEYfDhDUWtVsyFs7EQbBGsDb4oCp0wrZdu6iE
         CXYW9Z1SKYB5PautjlbJ8tiR5I9o9xHxMZLWQSznmxNcb2yfQky3zE0x7P10/XQzXUN4
         rKom2BEbJ9P6uQCEwkx0XP2qHuuRdlcjgGgpmF73Famj3ShpZaGueNSNCiulT1/x0yCf
         lHsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=HtigScLa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687584908; x=1690176908;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sNPZ568PHeRV6L+pAS1DeYX3fblM0vfzOI0HLLvj3lA=;
        b=U5c11qBnFCo0oGUkFxGDEL98giHIB80llO8qOZhX4weDEeLCZsNa6ppHxRju55FrjT
         N+QxcM4wkikjfC3rSL7Czj0jna+NcKjpv/8/uKy5LhM81c8LlYe1YKlxAmy3lnyxOfaf
         tgn0xsU78xpIDbsslDLQwFLgqG0ihSS4sf/Y+xOYUcmtOX/mQDm3w+BIx/skeYR/IVwj
         OM6Tm9m0raMWd9l44c944Tef87ox6XB4xpUjtXTS3WgFHtK+PiGEscnrZBqXxX5ADGWc
         y3CjKAu+2EvhP2hH1MJi8h4xdJPdVODlfxnWUHOZ70mwD7FUK/dMfnjpY42ilXc9SQOc
         Gxgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687584908; x=1690176908;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sNPZ568PHeRV6L+pAS1DeYX3fblM0vfzOI0HLLvj3lA=;
        b=FOByN2vWsHYKWYAyVBCbdA9hjo1D+Tfyad5M+4WBqm6mYF6I9MK+xJCSfWWdURjl5Z
         jIjeFo7z8NWO89kJqgi0IzofE2v62C0l+R/TDWmcv2k5ivqFYsnCzeiOjLyPuAc/JN1q
         If3vOlnmmcdqLzPBYi4nkb+Cocsd/zjShEbVNSGzjiobXR/x1DvrOZ56wnLPBtt63lyZ
         npCfJ1pZpQNUvUxxtMd6IQyezv15zyy3MZ9aQPYfqDHP3XqUVdP8zSByDhiK5SQ0eE+9
         tZ7tqwEeu+X41rFDNFk3oXmzGw8MmqApxoglMd+PyzXynwFdSlo7X1cTiTMK2+iL1m06
         V1FA==
X-Gm-Message-State: AC+VfDwmyS7TKwBKa8U1FKYK6vVAK48ErSnJ8x2PZXBFIM19vEURI06G
	wsylhp1FgaLQdYBJpr8xa3c=
X-Google-Smtp-Source: ACHHUZ7p70x894F+5TUbDTxgxEP/ZOwj4fzL7xHXsxFGnRZNDpeftVE8VrttpbDkWSVHgggwD680Ag==
X-Received: by 2002:adf:ed09:0:b0:313:e526:f6dc with SMTP id a9-20020adfed09000000b00313e526f6dcmr164653wro.48.1687584907597;
        Fri, 23 Jun 2023 22:35:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3cf:b0:312:74a2:3ba with SMTP id
 b15-20020a05600003cf00b0031274a203bals409426wrg.0.-pod-prod-05-eu; Fri, 23
 Jun 2023 22:35:06 -0700 (PDT)
X-Received: by 2002:adf:f882:0:b0:311:15a7:8789 with SMTP id u2-20020adff882000000b0031115a78789mr18667487wrp.56.1687584906335;
        Fri, 23 Jun 2023 22:35:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687584906; cv=none;
        d=google.com; s=arc-20160816;
        b=i2WXz876yihC2yQihQdSU6A+9zChzuJIdzoegiY6QgIvOCxrneHGfFLitcc5sc1+1F
         qfVuutkQ1ed2R0YLCtlxqmrUUgGH0aKN4UCUSHgBHdRrUNSLBciYp1Z1Zm3AMYjHnBkp
         AW52ErQRKBxZKETFkW3LpaoOQG5cRO9iuPgRd3lomvLC3xWQxMKZMWQ30j1UNwpuW9z2
         zDr2uGZaivNobe1HVTyiFfG/b3/b4AHKaCKOclSRkvOucY1/Vy6W5lgn9d/7o6eMSEAt
         oDHMgCppvncNtWgt6fWAFHQdY0V8YN6UmImdgXUTGX9K4hBhks+XSQnOPB0trG6AAe9V
         nTNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=unxnCCJRCGrLNc6DK9W9SYp6CzMnpymgA+tJ26E5z4c=;
        fh=m5qfyJ25CZp5yrDkPpyI+sYRou1/lTfoYdnAHslh29E=;
        b=lPvneuqFyt0ohYUAxDJUqy58jh2oklOU1QTUhfY+Wkex36l6Uyo9BmIX2L8aXTSZGA
         GplvPOkYef1HvTJg/9NO/8kmH1pPE/EQRKLP3lT7iWM9xw2mDYlkWB1EJKd0HYe155je
         O2vxtf7+OQueq7M8YgOuo11MQ6Xam5Cd3QC1SbA0LCmUoRBQeMzNGFRKBbwCQPOTlCnF
         Hh8qfBCBmIUd/TdbwJKOoNNrPz9SwuXA6ybPvGMqbftbubMG8iq7HJySO0H1VJUdrwv+
         iPovNisdGkjcH6807OECy54GuQxQCLIO/hGiilW6UH2sDMMhncBSupQkdnaGUX+f5Yah
         b/MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=HtigScLa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id ck7-20020a5d5e87000000b00311110bace1si52699wrb.8.2023.06.23.22.35.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Jun 2023 22:35:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-4f86840c45dso807e87.1
        for <kasan-dev@googlegroups.com>; Fri, 23 Jun 2023 22:35:06 -0700 (PDT)
X-Received: by 2002:ac2:43d5:0:b0:4f7:5f7d:2f9b with SMTP id
 u21-20020ac243d5000000b004f75f7d2f9bmr12852lfl.1.1687584905392; Fri, 23 Jun
 2023 22:35:05 -0700 (PDT)
MIME-Version: 1.0
References: <20230623211457.102544-1-Julia.Lawall@inria.fr> <20230623211457.102544-18-Julia.Lawall@inria.fr>
In-Reply-To: <20230623211457.102544-18-Julia.Lawall@inria.fr>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 24 Jun 2023 07:34:52 +0200
Message-ID: <CACT4Y+ayUeSpdmkec3pCna1kVSd1QTgBYLAb3zNJJ-7wcDHGdQ@mail.gmail.com>
Subject: Re: [PATCH 17/26] kcov: use array_size
To: Julia.Lawall@inria.fr
Cc: keescook@chromium.org, kernel-janitors@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=HtigScLa;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 23 Jun 2023 at 23:15, Julia Lawall <Julia.Lawall@inria.fr> wrote:
>
> Use array_size to protect against multiplication overflows.
>
> The changes were done using the following Coccinelle semantic patch:
>
> // <smpl>
> @@
>     expression E1, E2;
>     constant C1, C2;
>     identifier alloc = {vmalloc,vzalloc};
> @@
>
> (
>       alloc(C1 * C2,...)
> |
>       alloc(
> -           (E1) * (E2)
> +           array_size(E1, E2)
>       ,...)
> )
> // </smpl>
>
> Signed-off-by: Julia Lawall <Julia.Lawall@inria.fr>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/kcov.c |    2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 84c717337df0..631444760644 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -900,7 +900,7 @@ void kcov_remote_start(u64 handle)
>         /* Can only happen when in_task(). */
>         if (!area) {
>                 local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> -               area = vmalloc(size * sizeof(unsigned long));
> +               area = vmalloc(array_size(size, sizeof(unsigned long)));
>                 if (!area) {
>                         kcov_put(kcov);
>                         return;
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BayUeSpdmkec3pCna1kVSd1QTgBYLAb3zNJJ-7wcDHGdQ%40mail.gmail.com.
