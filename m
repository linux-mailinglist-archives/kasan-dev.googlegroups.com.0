Return-Path: <kasan-dev+bncBCMIZB7QWENRBKGVYCSAMGQEFX3BAKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F1E17351BD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jun 2023 12:15:05 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-30c5d31b567sf1018176f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jun 2023 03:15:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687169705; cv=pass;
        d=google.com; s=arc-20160816;
        b=MI/GA6RB7RhrSFOg4Dl4uDRn9DxgXhAL+EsTqqiY0ljhehrbimq8SdvouTd+UodaoY
         9A4M14VMXB51IyP0jmhjfvIJWbk1ZC7jjL+GRgYhxyPrVtj82sAfQFqGzzO4sPNYlnL9
         y+uFs/s1O1zlsQfRpIcx4C6/g8kdh3K2hcwMvo+QL8BX74BpgLHDquPQuZjROUHgZvjJ
         HyYqExtmCTjb19QQFv76bztiBGYZ06Giz+VicE1L3haCv30vvk1P24RJHmp/BTW0AZWR
         /JHiCsBpaTP0Gd1zcXM9OQXa7mxAQG0WaHwLU8H1pCxmCqJWDyMHwbHAT5ED6D4aqCgF
         eIKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ebsUloMnfCjbQaxL9eBZmnt7ZOkH41v4wk7fQ7CZX/o=;
        b=nZDRGD3WkIYb6srbBhfYbi9zUz+bPlRq8OcYJnF6WhVdYF9PihkXVsB/1Tv0/q9aog
         PH/2ZZd702qiQLpBEuyq3iz6pCxOhIVO/8wKVS9N6QsQS7GCrXdBw0g+ALWh2hl+7zNs
         Udr5cayV5UGdO8NZom/O9wzeowBDEZqmKUZ+R2byoabTZ6V63vsFvTfRnaEhE+5nTVxG
         SRPvmpTYNPcjyeTwXUshSPNEInTkIPQfCLyhWKGoid/W2d6sudfneNOqoJ7e/jdV5Nl5
         cDquJ9jS/G0+q+zPxRrVNBoaLEvfKOPu2uvZDGPHxzgAEYVjaqEHtadczcaLZMGkybhJ
         ZIRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="2XPBs/hc";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687169705; x=1689761705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ebsUloMnfCjbQaxL9eBZmnt7ZOkH41v4wk7fQ7CZX/o=;
        b=W97KlM01jkmbdzg6GeGKiqPQhFHORXad3rJZ9019oUHKmhGJn+3bVqu3TJOQoDwGDl
         i9FZzyLRwETVkRsHULzo9ORjPNmRIhjV1Pl1EdmzgxBhRm20Wm/bILC4SzQRj/fkeySY
         h6VFDcnV3FGSdSvJ6/oj1eooCb6yisYSjS/y6N5By+CDHwEK2q+kI+N8NhxJ4lWWEv8n
         uOAKJ10Rf9uyWYik5Std5Wnqsbdn9utPg+5oT3T7oHKdM4m8gw6cDUqXNwF0CP7+Sofv
         jjpPiIfZOFNdSJV7+CTkE1AprR9qOhTAoRpepo0DOtTs4ohyayqtDJwMg70jC4bMUGWJ
         mm2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687169705; x=1689761705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ebsUloMnfCjbQaxL9eBZmnt7ZOkH41v4wk7fQ7CZX/o=;
        b=OkYTbYBfFm3BadDO1qN33zbbYu6vovPmTQaCL5j/dRNozug4m2QoYAdpBn1uwXJEZW
         8KWMSCoYzax+3vv3B2kbi8hM+M8yEixzX5joRXXpmYlLC5ee8hJuqTCrj3eg2ny/XnUX
         4uSKHc7Pgmquyq6qU0Dz+nNKBiIwtIpqRGwCiVkrErzrPZGh8mNpLhsTQ5kBHIGoI0VC
         hJB30Mcr9TYEL1kKUob4H3ilDmr0tOIGvtsmy3hU7P0rQ7VP/lqVWKGQpGsFsrJSTfXy
         q+61e/Pu/T262pCMOlopMl/w4drhMsKDmW8sy37UdOqBmuhXpglTqMkTxE+VaxxZOOfb
         0HSQ==
X-Gm-Message-State: AC+VfDzUo/tLwg59/XAydkL8qXKt9CE8N4RKZVDpdd8jPyrhUhsWZLg1
	58k7ymjFm10nvFW8lD1tMKc=
X-Google-Smtp-Source: ACHHUZ5UMmpgHQExbvD7VBHsWoLqljXHhfqXiVkQ+O0whNBwmlnguJC+LU4goAHTrtEbHnSOnmDjxA==
X-Received: by 2002:a5d:568a:0:b0:311:1497:a002 with SMTP id f10-20020a5d568a000000b003111497a002mr5727589wrv.3.1687169704220;
        Mon, 19 Jun 2023 03:15:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:170d:b0:30b:7d44:f9d3 with SMTP id
 n13-20020a056000170d00b0030b7d44f9d3ls25139wrc.1.-pod-prod-08-eu; Mon, 19 Jun
 2023 03:15:03 -0700 (PDT)
X-Received: by 2002:a5d:526e:0:b0:309:51ec:9ce0 with SMTP id l14-20020a5d526e000000b0030951ec9ce0mr5250855wrc.69.1687169702965;
        Mon, 19 Jun 2023 03:15:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687169702; cv=none;
        d=google.com; s=arc-20160816;
        b=vlk2u3Fsyv0HY9ZFkedHMlEVJwk2KSvEjq6lhj36JwJuPhBmhjboGHLiO1DvvA6xaY
         X1swmy+4fn3ir3I4XJNflsvk2kfC6A9slkbpyFnLyhT68rfqQt+VinoxDQvBpP530NQO
         rFD6QWy3CN8lH4f+PYOqj9pwf1Lup/qmRKyweVcea3nj0+PBAx8F4t3MPnXgpLHMDKjI
         1m0d5C3W3ZhT0T5XyESQl0bKWUmKkWcV3sY4OPFi3e01tfZIzlbtVzCluG6AVh5iXwaQ
         H/7tIT61/hfGAX6hGm54J69CL/GgaEa523qZFsTo4UmHOpkBzF5FfFYuvLZxyGTCMx2n
         4/rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h6+4WUre3d5bVXKSjFFWZpGKa0679AOLoEWy8qr2V00=;
        b=VFUGGYo5tDxJ5xqGUwmYWvVCtaBzUZSLr9M4rVNtdkFNtL6qurlvnI6+RgPzn4vbqP
         cMd/8Gcjwzt65nIdxAbgANrl2a8pAL4dDA6pMeMTDfiBeCymRrFoWcdtc83pI8F0Rs0N
         r0G5LSioy6i0nnsMf06pjXRAi7nOPRmXrwT2Aoj5YjJeAJ13S6JxfX7agJ4seHVUQWxw
         Z0TwAUvGEUgUXdr7g2huYXFC28icaDV8WMF30KjfIs78Fa0fB0polvF7kSyvwQjm7Fag
         syUiI4XYRMkEZKNUiyim0LLXttCySOzCYrPQFB2uJmkhQo5J+URrAjbBDEkyBLWihol8
         nxrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="2XPBs/hc";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id ay5-20020a5d6f05000000b0031122f71bcdsi450715wrb.6.2023.06.19.03.15.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jun 2023 03:15:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-3f9b4b286aaso1735e9.0
        for <kasan-dev@googlegroups.com>; Mon, 19 Jun 2023 03:15:02 -0700 (PDT)
X-Received: by 2002:a05:600c:691b:b0:3f7:3654:8d3 with SMTP id
 fo27-20020a05600c691b00b003f7365408d3mr141237wmb.2.1687169702435; Mon, 19 Jun
 2023 03:15:02 -0700 (PDT)
MIME-Version: 1.0
References: <20230619101224.22978-1-chanho.min@lge.com>
In-Reply-To: <20230619101224.22978-1-chanho.min@lge.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Jun 2023 12:14:49 +0200
Message-ID: <CACT4Y+Zn49-6R00buq-y_H0qs=4gBh6PBsJDFBptL8=h6GPQYA@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix mention for KASAN_HW_TAGS
To: Chanho Min <chanho.min@lge.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, elver@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	gunho.lee@lge.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="2XPBs/hc";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::333
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

On Mon, 19 Jun 2023 at 12:12, Chanho Min <chanho.min@lge.com> wrote:
>
> This patch removes description of the KASAN_HW_TAGS's memory consumption.
> KASAN_HW_TAGS does not set 1/32nd shadow memory.

The hardware still allocates/uses shadow in MTE.
Though, it may be 1/16-th, not sure.

> Signed-off-by: Chanho Min <chanho.min@lge.com>
> ---
>  lib/Kconfig.kasan | 2 --
>  1 file changed, 2 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index fdca89c05745..5be1740234b9 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -124,8 +124,6 @@ config KASAN_HW_TAGS
>           Supported only on arm64 CPUs starting from ARMv8.5 and relies on
>           Memory Tagging Extension and Top Byte Ignore.
>
> -         Consumes about 1/32nd of available memory.
> -
>           May potentially introduce problems related to pointer casting and
>           comparison, as it embeds a tag into the top byte of each pointer.
>
> --
> 2.17.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZn49-6R00buq-y_H0qs%3D4gBh6PBsJDFBptL8%3Dh6GPQYA%40mail.gmail.com.
