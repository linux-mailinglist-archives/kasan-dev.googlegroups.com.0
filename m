Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDOZSWAQMGQELTQJNBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7049A319145
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 18:42:38 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id s10sf2779440wro.13
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 09:42:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613065358; cv=pass;
        d=google.com; s=arc-20160816;
        b=L8TK6BHPwiYCxKs9YRWpDbWR6UySg9/evVtrCOoq9UOu/52MNrX3MsI6TlyJehz03L
         Vn6SqwDeASg06FPJQNxjA2UcErwsClENHgTw/llV5+GPWWFXApMhI1ACoKR+IntlCsd+
         6LoBsIiA+MgQ0tqrLBEvws0QLfkpH/fQyx7CqMFsvyGw+LZqS4srx9mjC5F8GRcEdBXn
         AWollSSeMszcCLZ3VSJrGFRToql0iV0dDJe5p7nrKAq4ogY9hoa9rVYCXWumDAS6UvvL
         6rRPDOvyk6Zr67wxNHtK9DlXljHZ6NEJipM5bzCmrEIn+xiSRfRg94l/ZDvbW6DAf9Hk
         WvuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cctExl4UT6qikPVOEizvdnmkentDSpD6bE1hhmw/Ww0=;
        b=e7HPIdS9UqXg97Eyiaojn7TSE1D3zBmJ/DcqNLxtIqDGg07XnUoz/vDs6YXF3QHf4O
         3po/n1EEjTsW/RLIoXxqCbUShVByxQOKFBG7mfsstxNlP/E3Z1Iu2OKTBLzh17Y3/K6u
         yqblmO1YIMMCv1RExJ7HXFQfyhsnytAK3vxJZyQdsRhdDQ7PugVlJQhGBGmBZ00YaWC+
         TicslojxBOpMr9JhKLEmrjBJ3ABBUmYOEGTQs50F6D5kmJR79XkBpO7V1j4rteLt9EAU
         VCLadq24xJfmGcXkmdAo22pFh2iKJ82imQ468YDrQQrK1FnaaKoQGpQ7cD9Z/dSHSqZ4
         3cLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T0oWKSDZ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cctExl4UT6qikPVOEizvdnmkentDSpD6bE1hhmw/Ww0=;
        b=eJ8aW5sukOg3I5Pk5ucJog7gRkh0YsjxHnmr5ubu1K23++rWhY1BBZB3WyA/FOoBS5
         Lo5Q0xd2SDR8C2klC1KeZ0KUozSAkmIUiEbmYKkL+lFrCBDlBiaVsSxTUm5V76N3LHfk
         bXeDegOnrs2fv2fZfms8j79zt5PZ2jowKqJqWsvD4YMBRj7QpiHUcBXezdNBrVvho/0Y
         4eGFIQWogBdQ3AytdIuC09Er3SdG8VJIy1SSLapIVl9TQj7uXjNtKlxhckZFZEM4V7mf
         gs1JJNRrCm9oFfilsoObAptjQ6mnkJVuxpqm+VwXKpv9NYvxwdv7q+P0PmxGKTU7Xybv
         FVbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cctExl4UT6qikPVOEizvdnmkentDSpD6bE1hhmw/Ww0=;
        b=XJoKSbv8ULVZVcUclrKywQqxLJ+An9ZF3VGuX9u3oqHJBVeANdGPnAaXeZ3eP2MQbB
         K2ScM0PUq1wpG9GUIJ3gaXqAWn7BBruqlPS5NXniNVFZmbuYDCDIuSfhwjux82hmdXwq
         IhyXfhlnObgAtovXRlRWMNXtCXMeRKP4mBChePb3IplM7QBD6Q0/bd9mYDWkQ1tt5Y7S
         b6ie1AaLlq+hThq8VpNoXkgn+36toMH7TydJzgT74yIRCOIXXmKjjiJcfHxCv7Sy3/rh
         +PkY8AFBniYzD0/gnbQzZ4bCsOn8ffO6aDTxsZV12Sgr8jICj5MCEV4PAj4JaNBdzoZ3
         VYTQ==
X-Gm-Message-State: AOAM532r1FVga/hRb8/YHdcNLsKDs+/FhWxjOMTwPEFnOF/+cWT36gTw
	iGbWcb2lxxc7oox/7KoRQMM=
X-Google-Smtp-Source: ABdhPJyhTVpyX9QA/SXH1JckOAHJ6+rU52N3Lv+zQvhZRWeqHpb1cmmxlw6kNn5lXNvtfk041upvfA==
X-Received: by 2002:a7b:c5cc:: with SMTP id n12mr6197678wmk.123.1613065358115;
        Thu, 11 Feb 2021 09:42:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:640a:: with SMTP id z10ls413287wru.0.gmail; Thu, 11 Feb
 2021 09:42:37 -0800 (PST)
X-Received: by 2002:adf:a41d:: with SMTP id d29mr6969233wra.196.1613065357413;
        Thu, 11 Feb 2021 09:42:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613065357; cv=none;
        d=google.com; s=arc-20160816;
        b=k1eLdkqtyii2mEZjdYN4lOnHZfXI+QkWqS7P27qEB8zLPSi10zbXi9QrUj+5U0lzkh
         vYDhdUEqEuTIixt4FhgIVezWdrIy4pcEKX4LibMrwP+LOUdzFODc2TmJwOsOn5ZilWil
         emUM2M/Kk3b5yAc1BLmp70tR+rbHadW4XlZg9I6zaV48ugYu9muGSQxJc7I9J/XS97AA
         H8UqN1ezQsckYNW8VLTSaHqpk67yYocCJvlN/ia8nz/MQ6M1U9G/FlSmRz32WIehiOTo
         Jsq7qlukKRgKnvLcSYjo9G55P+W+lmHWFSAeMux6mV0Aw/wddgcRi0dKyyYrub8DY/LU
         NvIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jZSkmFMKUaJrbCLhz//LG/yQTwJ20UA+ZhLO4rlMv6Q=;
        b=vqzzHK4ZpdoL4CljPvZPWk/EMLqZo3gFGOh8e/LGkhMfavJ+ytPIxkOvnFaLPDJaHM
         BIpsD+asaAxuXfrvZOGOyYE2gBnB48/Au3ODNp8H81CZMlW8gYp5uk5O0542x4Z6njX5
         dNIluF99U0ZSUJSW9Hc9l6m6mHfU7zPVeXsRS1GyY8iH+qnQAQcloIZ0BxF7xsHU6+2I
         xDD0PCHgAjYE7Vxysp5d44u8Hb7agvwWzrgL+GGlkPo/I9ZiQpaNlye6qQ8GN3EApS6s
         dyw55uLRX2O3J2SSPYQJOvoDtrkN6U+jdht+FuLK4zO2OJBibjq6/ZOy1U2TIfTpge1u
         AjkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T0oWKSDZ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id m3si752031wme.0.2021.02.11.09.42.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Feb 2021 09:42:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id v24so9294000lfr.7
        for <kasan-dev@googlegroups.com>; Thu, 11 Feb 2021 09:42:37 -0800 (PST)
X-Received: by 2002:a19:6748:: with SMTP id e8mr4983032lfj.224.1613065356718;
 Thu, 11 Feb 2021 09:42:36 -0800 (PST)
MIME-Version: 1.0
References: <20210211152208.23811-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210211152208.23811-1-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Feb 2021 18:42:25 +0100
Message-ID: <CAAeHK+yBrWeXTXoR=_jrH55YORf6YPfcXYZOZNuEzRsuwq_CQQ@mail.gmail.com>
Subject: Re: [PATCH v2] arm64: Fix warning in mte_get_random_tag()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T0oWKSDZ;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::135
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

On Thu, Feb 11, 2021 at 4:22 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> The simplification of mte_get_random_tag() caused the introduction of the
> warning below:
>
> In file included from arch/arm64/include/asm/kasan.h:9,
>                  from include/linux/kasan.h:16,
>                  from mm/kasan/common.c:14:
> mm/kasan/common.c: In function =E2=80=98mte_get_random_tag=E2=80=99:
> arch/arm64/include/asm/mte-kasan.h:45:9: warning: =E2=80=98addr=E2=80=99 =
is used
>                                          uninitialized [-Wuninitialized]
>    45 |         asm(__MTE_PREAMBLE "irg %0, %0"
>       |
>
> Fix the warning using "=3Dr" for the address in the asm inline.
>
> Fixes: c8f8de4c0887 ("arm64: kasan: simplify and inline MTE functions")
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>
> This patch is based on linux-next/akpm
>
>  arch/arm64/include/asm/mte-kasan.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/=
mte-kasan.h
> index 3d58489228c0..7ab500e2ad17 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -43,7 +43,7 @@ static inline u8 mte_get_random_tag(void)
>         void *addr;
>
>         asm(__MTE_PREAMBLE "irg %0, %0"
> -               : "+r" (addr));
> +               : "=3Dr" (addr));
>
>         return mte_get_ptr_tag(addr);
>  }
> --
> 2.30.0
>

Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2ByBrWeXTXoR%3D_jrH55YORf6YPfcXYZOZNuEzRsuwq_CQQ%40mail.gm=
ail.com.
