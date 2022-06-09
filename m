Return-Path: <kasan-dev+bncBDW2JDUY5AORBC7YRCKQMGQEVVB4WFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D68B545427
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:29:32 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id e5-20020a255005000000b0065cb3669fe9sf20903214ybb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:29:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654799371; cv=pass;
        d=google.com; s=arc-20160816;
        b=NfHqeFUfjcYc48xBoGf4k/2lgEgKFCgKVXX0SKSWdjyPDcyUiRkcQXqXwFvPlMKoi7
         jubKflIT3lSo2YvV2J/G5W6E2WQvfB9wxvSyYj3fe4s8t8oNBWWN6sxAN42VC0StF+xq
         RJZHYiPDxDk35ZLFvfjjTKwO9KqaKkDuSjy/NRsOmLU/ZnkHCcyWeP9uO0zz1HNiW0MI
         NcJD7jSvcfa4e482Q6EJTOSmqmxRotEwAVx7kGeav/LilKwCCrd5MeDT7zNGozv1rrmm
         lzBMgpNx+6XaJ13DIwW6oOn6NWGnhTaIsuigokJG2OUIE/dCQuD8yEcLBHFxnPD2fJIo
         y6Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=nvUbcF5IgvzZxOOtEJMw+90Bf0eYbdLCSf6LBdT6YkM=;
        b=deerOxCGiMc6Th0WqrhFZWxr01RBiA82WSJP5aX7SvqgVB/LxIt4k2RGbuX+T1proB
         lOKL1+rJOWMpJz9VR3AQf0+ysiazSxi9JPk+BaWacGntt+UJVLbn4s+8iUJiLegje/me
         BvaHrQMvv+VI+2Rp2lsWBfCqqAN6YOpqZG+AUIcX27khqiaOGY0ZC0OdDbtuTFWWLbhg
         1klgtPBaxCUAx6PlzGxXuC1NBG7nX+mR1jjNJAB0+r9np8hvX2t7yMktMWBkh5hsnv5A
         D+9oiVbyhoTQTi3zGNF2K7zZAuiFVY1erBmpUHd6UCL8AfRMxZXHzkmfCm/Cdw0a1a/+
         tX8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qR91jK00;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nvUbcF5IgvzZxOOtEJMw+90Bf0eYbdLCSf6LBdT6YkM=;
        b=K3QGZZDPhpBUUd3CqB2Eij67PW2oMdYXfOv21MaUVJN39XF3rsRI6iRApK3YQ1/4w3
         J8Mv+DxWYSLfRkvRLyNZ070pBiXdQl0hJdTdfANGt0reC1+VDSpNFJhQbpAakwytOquu
         Gf4SamEX0k/L3cIP0SIEua4QtowMdABXEGYd8ca3dQRz5VdtDHmFV7c2KWw5K2nAO04W
         CnYyPCJUSolq/vb1f1qn80i2aKtaIjCMxhAJDfK13ECcIxHJzpYO84eid+i9YThpAuNL
         ZAL1L3pc86MH5bZherRZW4xL9oLCaF38AGj/fEsI7NjZhjNwEHy7ly2k3JpRh6RrHaxU
         yo1Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nvUbcF5IgvzZxOOtEJMw+90Bf0eYbdLCSf6LBdT6YkM=;
        b=SXiSnxHhXKldEnpaaMq+ydKJmlUio+S81ez4DgpB/aDOiWoJj2YGPM21Y0rh+gcJbR
         j1jYOZ+g8ex4rlsnWyaPTAHZ8CR119BOKo0CV7xTCtkKSas1TMhRQO8X0Tl3bxaCaPwL
         zzzRbM7aZrU8dQId+IobTIe+TbYKsHKYe1yTi2vzioHhO6dQK3pTtfeE6n7bH04R49m/
         Ou7LMlRYWu019+iBlc4ZbXgFoMrBjQK6hZkSy8pIKfKbmhgKzREykNsIHrRIxCrXc5Rg
         m5hfSVt+w0WNSJXGswO41WeCdtRQ3DprKh6yqKDzQblh0dA7L67MQ79aU7qOUjBs5CpG
         wkoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nvUbcF5IgvzZxOOtEJMw+90Bf0eYbdLCSf6LBdT6YkM=;
        b=N6rIVMmlOaCIhW3s5uC5tkGuwLHG6anVnGUQh4v3QKEbDrL/10PATtzGMQkwRYMOC9
         EGlgtb16Al4I4nnAqTNRZQTTRoWbpgbp+n+/I81SJn+fbVlmR7FqnYatNkGlaW0RTvX/
         P8qOYNzAzJXgprPWuA3xFWMnYbqqzNMadHeR+rPWFDavZ/uAYJe01/vtXTj6eFYjfbAo
         jG6EjLtL+al/pJ+XEAW+hiSI+YT4mkBjxLT3OZnvXBC9HXnB4qOGGV/gg8xtF/RlUfg8
         UWF26mCnSlWu8H6gqJxHOaIpqf0/8osO7yi2zd/fvO58JhksPOfL8VWl42DEligK7dfy
         jg/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pSXENqFZnJCEpaGnulJNOKnPYJviP0aDVk5c55CCS+XYwJF+t
	rjGJMPl9Fm9i/gHJ9wD0nAk=
X-Google-Smtp-Source: ABdhPJyudXhbqAg1YyW3/EBTs8xHglJjG6KR0d7wmMYLAsVLU6zyZcUAxg/xuAbmpUqmCXq/ozVEqQ==
X-Received: by 2002:a81:4420:0:b0:30c:3a84:3617 with SMTP id r32-20020a814420000000b0030c3a843617mr44491783ywa.23.1654799371439;
        Thu, 09 Jun 2022 11:29:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:23cd:0:b0:30f:a61b:123f with SMTP id j196-20020a8123cd000000b0030fa61b123fls3172661ywj.11.gmail;
 Thu, 09 Jun 2022 11:29:31 -0700 (PDT)
X-Received: by 2002:a0d:d8c4:0:b0:30c:2f27:4711 with SMTP id a187-20020a0dd8c4000000b0030c2f274711mr44885755ywe.232.1654799370961;
        Thu, 09 Jun 2022 11:29:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654799370; cv=none;
        d=google.com; s=arc-20160816;
        b=FY5oR4/vkrXadUG5aDsWpEtC4iswJvU5y75kGcQ3eebHPCQAxWEIys2MRWOhp9TqQa
         r7nb9yFAr60tim4NWDU+lqWC1UMF0HJxPtBgIxUtVVeOzpf8hMGiMYT4+0d9s6paBoWQ
         rXFVX2LNb09AH2BjUfY9B/NleOpHWKyEattelz084OowhxTMrW1PawiRgsepCiFE85Gb
         Cl0sSyQN4GkCwP+IwbRs9W8hcyLZ85Epwo29ZG4UDwVH5xsFfIZjXXThEZLdbcHezall
         1USWGES+ef2BWZ3i/1B84TWKqcAhouAKEGjV2G1Dufgmaxo6ECIbFzg4RXBoJXtKoMHp
         wlxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XvsbFBsXbCJC8twXzpRgm1jbeXhuSUvfjaB5kCcvYXE=;
        b=kqQCLw9PE9RPKQAYVcBtZWaBxp3Wqb+zq2GI6Pt1K+uEn8tEkq6UlSeMkR9vn6v94H
         eGwpx0Rt66F8ZKMb9dWbFW6U5oVSiW2dVqlrWvzLCNjduihx5Ud2EQ5jFqrelArV/uJB
         WQH20cR2ZlVEhXDUmYs3RGFHFwEmfMMnDiuika6XRgXrDKcWT+tUIzvENaEw1x4V0Reb
         UM6Ldq75ORnSehl9Od7j3pBzTXUnoRTuxU3/69boBgyxpfaAdALeHaQlWuxkJPZs8Iw/
         61BEB7QoQvMJVNYxjdRUirr+1EKSE32YpW0F/n9mOXdkikrrBI6ndq4nXpjIQf9nhELn
         4DeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qR91jK00;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id v76-20020a25c54f000000b006500741258esi1784261ybe.1.2022.06.09.11.29.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 11:29:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id 19so3695775iou.12
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 11:29:30 -0700 (PDT)
X-Received: by 2002:a05:6638:22cf:b0:331:a5b9:22f2 with SMTP id
 j15-20020a05663822cf00b00331a5b922f2mr12558649jat.218.1654799370610; Thu, 09
 Jun 2022 11:29:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220607033122.256388-1-kunyu@nfschina.com>
In-Reply-To: <20220607033122.256388-1-kunyu@nfschina.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Jun 2022 20:29:20 +0200
Message-ID: <CA+fCnZd-JS2tdojpNigt9brcH=ZX78Pe3AB-wwc8o+3UNnGuJQ@mail.gmail.com>
Subject: Re: [PATCH] arm: create_mapping function to remove unused return values
To: Li kunyu <kunyu@nfschina.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, linux@armlinux.org.uk, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qR91jK00;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32
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

On Tue, Jun 7, 2022 at 5:31 AM Li kunyu <kunyu@nfschina.com> wrote:
>
> Change the return value to void to reduce eax register execution.
>
> Signed-off-by: Li kunyu <kunyu@nfschina.com>
> ---
>  arch/arm/mm/kasan_init.c | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> index 5ad0d6c56d56..db2068329985 100644
> --- a/arch/arm/mm/kasan_init.c
> +++ b/arch/arm/mm/kasan_init.c
> @@ -187,7 +187,7 @@ static void __init clear_pgds(unsigned long start,
>                 pmd_clear(pmd_off_k(start));
>  }
>
> -static int __init create_mapping(void *start, void *end)
> +static void __init create_mapping(void *start, void *end)
>  {
>         void *shadow_start, *shadow_end;
>
> @@ -199,7 +199,6 @@ static int __init create_mapping(void *start, void *end)
>
>         kasan_pgd_populate((unsigned long)shadow_start & PAGE_MASK,
>                            PAGE_ALIGN((unsigned long)shadow_end), false);
> -       return 0;
>  }
>
>  void __init kasan_init(void)
> --
> 2.18.2

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd-JS2tdojpNigt9brcH%3DZX78Pe3AB-wwc8o%2B3UNnGuJQ%40mail.gmail.com.
