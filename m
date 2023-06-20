Return-Path: <kasan-dev+bncBDW2JDUY5AORB4FGY6SAMGQEMIJV23I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A3C173717D
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 18:27:30 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-3f9c8169878sf49004901cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 09:27:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687278449; cv=pass;
        d=google.com; s=arc-20160816;
        b=EawiJkU7Q9RB7S+oeD3mvgUcOoZtQCsGck/6xpXNcxUVWpzrA1jglfwW4eETrEyVFu
         Je+jRbbzPWc5IRnhgswkrreMvtO1FCgbEAnTTpTcamRQ9K7tagU4s3jU7dAuJx+KBEsW
         mZiq2OnWIshxnmjgE4E+zbQOh46TprKmF2ZdkXV5Why4shPh/7092qrJCukAIOe9Ow/D
         N92Pwdgu9SPxdqMl9Bi/2f671FRdHH080GjMcJFszMbrWW0n2BjIWqNUt4BY3x3y8ei8
         PQh64HEc7b63YCL6i7cujXgzM7XtcPT716/dQECANqubyuZdx6Wf1ec0+LTJoI9RkXyD
         23sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=czrVMYfQMcA++MEq5rdhsxs6GBKdNQKklQim5xKECmY=;
        b=omlazYO5roTphVm6pfHTylFwIR9kGOMWFUE6VJbhONr6MGc2RILOmIzqUEE5T5ovhB
         ziGvZE1VTftPV7uYOSAQ/kVKQZuwH0dJsN4caC4p10I0b8my4d8ihoSK2xyJqildQYoE
         U311hHKSkoyk4E43kWM4iWWz+CN3yzgCkflVsegdVnf+Dq8Ub4K/WUr5amQP4I5zdaWs
         /J6p4ViWx+moLV3SXHdsxzNnhH8iVvZkBIwFal1kVVMtUYYQWL5NisXhHpwyWWtVkauL
         S7S2Gb5SzvcqYiXR46gNGOdYvbIpTDFhqTruohdNBsF+pXOEsS4HkBZhjWhl57ShtYYC
         RCPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=bzBfGUDz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687278449; x=1689870449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=czrVMYfQMcA++MEq5rdhsxs6GBKdNQKklQim5xKECmY=;
        b=T1LrWwLtzBkcMlEs7IucfGWPoy3UzRgb0j/3BEyj/RZCIeck6pHCp1c4dG9E3R3p/O
         K7NwKt04zmekbdQvqBIg0lj5htBmILdf0G3n40czNuIdsWJ5a9+upztoq5hvEk4snTKH
         TeZpjIc3qiJn+bsTF6CB0rQausr8Zlo8DEXOy+BfaUvsL9d4GdXKQ6rAYTQSYMNsRq3U
         DlqyikJfXLFbXyxPX2lKOmvE8NCzZVHXqw5JW5/99ZkXSCUly7vyxX+/hTmV4wgQ4Xxb
         hnNJmk9FDzGVUF+BCCCOjDrVoLpDKjMkNF7FB8Ly4P5cHUogD7xKyavePs2lWV8eMqAK
         mwTQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1687278449; x=1689870449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=czrVMYfQMcA++MEq5rdhsxs6GBKdNQKklQim5xKECmY=;
        b=qLtqiaATNpnUlUdce5wkslQz6bsPb8IETgEzZ/M+84LeKXu5YWxAjV2ci9JeRgEZnK
         0Idn1Sr9vHF3/E7M00lhzSRPk9BDEe4EIXXkxZ7zASjqvulwVLG7gPTB5KiWlEDnKfX4
         8r6oqoptYf3gkbK3GDysd4NR0g0C+8m2GadhH+aORv2iO9adLexzkW1m7NcJ+JFroT2h
         9ZJNjD7x8D3Rg7DHQSJq3ZYctptMs04mas+IklmOqF5eKUwee9VccnIzwu4BT/laBpuM
         H24eD9zzdbs9+flSQVY4gEecUORvgDiiHYp0NVzJuYhrrwqkk2IJM9wlhJfyXqzxQ9re
         XKuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687278449; x=1689870449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=czrVMYfQMcA++MEq5rdhsxs6GBKdNQKklQim5xKECmY=;
        b=eR73WsapwSqr33lwGIBbFRN7rA71GUN2wLa4goiTouA4JtYOXLGTJpZkzl7L1HxNK1
         x/V66C1mEeW5iki18EUJJsrCf421PIN1EOYUKew8UeO0aylWsAujE95k93QhW4UgM9AU
         10ba4aGGwi2+pChfQ9w+SOxgdaC+AGOIj3jXhJGn+hktGay0E6zin7zNBl/XLCeIoAvR
         YulTJgycDa6CsXereL9J6pq+JI2SMqQJxx5zfW4qT47n6YlvzxZ2BOqvcUiZ8LuoZRYo
         32MeLiOoQbtCv5Jpytze/Z8Td6c8M38xGftB5D3D2GE5dn5i+7J5/pg2DdrtPCKh0hrc
         Gq5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwojgVD/l4QYxd7n/5t4T3cfgIEaZgdkd2uXDoxjHiJLAt+QyWT
	+Ad2t7M8QnwD6vw3Qi+XozU=
X-Google-Smtp-Source: ACHHUZ7rO9z2z6bXWA7q4/B4B4h0eKPpzqcvJja+PYc9/+zgcRs6C8jcUq1Fq770ISs5cQsd9OxGtg==
X-Received: by 2002:a05:622a:244:b0:3f5:3641:f3ba with SMTP id c4-20020a05622a024400b003f53641f3bamr15172576qtx.3.1687278449047;
        Tue, 20 Jun 2023 09:27:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7643:0:b0:3f9:f049:6422 with SMTP id i3-20020ac87643000000b003f9f0496422ls703879qtr.0.-pod-prod-03-us;
 Tue, 20 Jun 2023 09:27:28 -0700 (PDT)
X-Received: by 2002:ac8:5753:0:b0:3f5:45c2:467f with SMTP id 19-20020ac85753000000b003f545c2467fmr14154791qtx.5.1687278448574;
        Tue, 20 Jun 2023 09:27:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687278448; cv=none;
        d=google.com; s=arc-20160816;
        b=aJodRGlG/4nDcs5W5wdkSpH6AlfTmiidH1RjlNFz+Jn+pqzwv2ngPz+UVaA8IwPwHW
         a3LZoOzBU88CPyzFNk23t89bzXqLiL7s8U01ot+Zfy2/f5TARigI7TJB7AWpInr7TGTe
         BNUyjAuW2iTLyQB4wI4+jGOwrw9+1kpJ1tKRMH5sDo2bMjiLxIvgilmmeU/oxdKL6M/W
         jgSg5D7UiExP90LI5c2twzCrebZdcKL+i4kfNC0N5udazeRldBv/PUQNP+VmF2a9HFbj
         xT+6O7y5+Aqu/fMC64WFo4ugTvpv74WkGHxTa26/xqzufw95t/wG7gWAlBavFxg63HZh
         Op9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Rpnniq76PXiCDxg/rDwxgmARY1zRtNLr8bVJxlqw4q0=;
        b=yYvnZMbbJ5glyCPFsqZGkQBXI2kOMTUHBVFyP3FcH2m8SNchRVGcxIgHqWOxag9+gm
         mXtBfPE5WmEvkxZtFe7knGdx2QJndyJEcJcY729LGOF6JeN7f78lC67yWmz4mp0esO5A
         cag8f845t6BNdrfwArxTALGR3vwU4jG5h+MuMvCsmc7goovEM/4ah0vfyvYQcsxU1uU2
         ZP6sC8loasTPoxLZHhV6LIrER+TJlHchhi1+NGDHKM/KWnu1SxAP0gwVIoYrm5gLmxQy
         Cq9mSjJXMR906V7eTdP/rA59nOY3qS6aakreZZmMHhT1IcVRD1vKCF6q2r8/hLIfY0iV
         4jGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=bzBfGUDz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id ch14-20020a05622a40ce00b003fde92c5ad3si318434qtb.2.2023.06.20.09.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 09:27:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id 5614622812f47-3a0423ea74eso255171b6e.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 09:27:28 -0700 (PDT)
X-Received: by 2002:a05:6808:1481:b0:3a0:373c:2960 with SMTP id
 e1-20020a056808148100b003a0373c2960mr3238276oiw.36.1687278447901; Tue, 20 Jun
 2023 09:27:27 -0700 (PDT)
MIME-Version: 1.0
References: <20230614095158.1133673-1-elver@google.com> <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
 <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
 <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com>
 <ZJGSqdDQPs0sRQTb@elver.google.com> <CA+fCnZdZ0=kKN6hE_OF7jV_r_FjTh3FZtkGHBD57ZfqCXStKHg@mail.gmail.com>
 <ZJG8WiamZvEJJKUc@elver.google.com>
In-Reply-To: <ZJG8WiamZvEJJKUc@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Jun 2023 18:27:16 +0200
Message-ID: <CA+fCnZdStZDyTGJfiW1uZVhhb-DraZmHnam0cdrB83-nnoottA@mail.gmail.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Taras Madan <tarasmadan@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=bzBfGUDz;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::235
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

On Tue, Jun 20, 2023 at 4:49=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Tue, Jun 20, 2023 at 03:56PM +0200, Andrey Konovalov wrote:
> ...
> > Could you move this to the section that describes the kasan.fault
> > flag? This seems more consistent.
>
> Like this?
>
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 7f37a46af574..f4acf9c2e90f 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -110,7 +110,9 @@ parameter can be used to control panic and reporting =
behaviour:
>  - ``kasan.fault=3Dreport``, ``=3Dpanic``, or ``=3Dpanic_on_write`` contr=
ols whether
>    to only print a KASAN report, panic the kernel, or panic the kernel on
>    invalid writes only (default: ``report``). The panic happens even if
> -  ``kasan_multi_shot`` is enabled.
> +  ``kasan_multi_shot`` is enabled. Note that when using asynchronous mod=
e of
> +  Hardware Tag-Based KASAN, ``kasan.fault=3Dpanic_on_write`` always pani=
cs on
> +  asynchronously checked accesses (including reads).
>
>  Software and Hardware Tag-Based KASAN modes (see the section about vario=
us
>  modes below) support altering stack trace collection behavior:

Yes, this looks great! Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdStZDyTGJfiW1uZVhhb-DraZmHnam0cdrB83-nnoottA%40mail.gmai=
l.com.
