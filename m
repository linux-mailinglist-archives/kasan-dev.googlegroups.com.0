Return-Path: <kasan-dev+bncBCLM76FUZ4IBBJW3S6YAMGQE7AJSPXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A243890D7D
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 23:22:31 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40e4478a3afsf7597775e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 15:22:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711664551; cv=pass;
        d=google.com; s=arc-20160816;
        b=CiqRqjN8XIV1eCwxg+VpVzjJgtKfvUezDOfR+33Y7Elk/IZrvZbu5TuLK6yfdfrXKw
         oOXWl/qbxkq7tbtHQPcKFuoc5shE8QDZd9QUPMCK6V81syQqB1x5dis4obSU5PTyKqWo
         pc0ecg5iOgevMVLxA77uhUrGE94H1hoAZnLunmVShj79rBWAUekpr1mlDgUAJoM3TWnS
         xIXIfLwizRV4SgONl7pLZrOaJS84Ijzd9/O256HcwuNY/bkSRiIG+BGmvMLKhvDaBsAA
         ToXe3VDmD9CSXl+V5GuaME2wd2awjQ7RH/X0v2lw2UazOJmu7svpQtIqKZ23MVDW1Ify
         jxkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oUTXgByTwKEQTUpSJGUd+R6kkwroZ7pPDqSxAb/nlm8=;
        fh=PRQEwekOhIyNutR2mE4InAMkP79iQCCFh756+BJKyVY=;
        b=ckMaX2Ju3mGt6CYuUJVEQmjwu//e7GvuWhm4C9rmJNT9W0tnd+kuON5vtL73dUwbIy
         FWd4kZ3zpUtuIZUMcD7CerR/w9PgXVa9eR7PS03zyKlcsOL263tZLfyg3h0RYILM2A8o
         KgTQctsuXfQRSXpSh3hAHfDy6GHopV9UGK1zcfVXlKnDu3qQtYgEdJJXR+RLSJeS3nmf
         CmPE+6cPw9QifGb7u8I04IxVSkEw6Q5LYfs8Y4OM+29PT4EZNSFLNkVR2Sdb/ct7JUY1
         5zz7SrQ/18bmbtUSv7iE48TB1G9eDiE6bePNPLNL9BsM/BD58uupx6fdpRnMz9ozEmpS
         UyBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UMrnfAMp;
       spf=pass (google.com: domain of justinstitt@google.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711664551; x=1712269351; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oUTXgByTwKEQTUpSJGUd+R6kkwroZ7pPDqSxAb/nlm8=;
        b=WxmqgwxlS9lV4L9CVyQp0Fr1aI/gna/wDpCq0mf9wzgmzS/9u0APNQYv2iZniTPTUr
         QsHHBuTL0Ny2uDFqWemflCm7Z6Teib+KkMttUcAMgjnPwJdTJj5N7qhmkhv0kf+uJl/r
         kOy/2yq/vKoytwJFPmThdGWOF6VcMW8UGHjcjqS9QHbrVnncJYhPOL4EYii9BL7j3Mbj
         j6bp2hwN6dzym2cR+aa5NpVNKEoBzshebPaNI16gPlsy3Y6k0tQr3HAP4Yh2lEVvcPNX
         mUd4JEmWNTYLeM8NA8ytg3sB1XVava7/6cqEH/7jqSg+HqE7ynuzXKnYgpN6ehxWpYd0
         SFyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711664551; x=1712269351;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oUTXgByTwKEQTUpSJGUd+R6kkwroZ7pPDqSxAb/nlm8=;
        b=XcHmb0ZhCHrBe8PVaqZ2uKIHc1V1Q+PXS8XJE/0NZsV/F5/fnyExpF73rJRikbl5eE
         E7SwaEya1RxVKUQOVGZ+ZA59RmTAcZMnJ8agxTxOmBvuVIU0efkblr4++WKMPHZ+n7YM
         Km8xQUs4Ek0B/KELXYxT/tA/R5nE4fwo6PatQShhALU3pu0mWnDEx5PkpMUig9RDHWJa
         GIHJk/pbn8sBM02GI95WzuT6yxAVXzkzvZTzc9D9HsyctbmhiSZRgvA4itQfE0gGZwBz
         zDQDrM23lI1OhsfR6MEpQ4olC/CfFhDP70zG8uzFnND1nmksDQlvCPc73ZCEE7uBc6xC
         grAw==
X-Forwarded-Encrypted: i=2; AJvYcCXIUq7BLKyXa18XwDafbcoKVivIuhWhxg1eaqQtuYAjJ89FzfM53HSRI1/UaRfqlqwijcTjRqfwjBsgF0BmFv7jwluzAo+Kxw==
X-Gm-Message-State: AOJu0YywNOWngcI1b91rkfbBJAasmXLpPjvjs2pmh3qqaaoTRSID2+sV
	/Ym88BoG0DWmydo4kCCPdTkXA7Y03irLYvDdY/qfqgYGBhGpz+be
X-Google-Smtp-Source: AGHT+IGkDzbCTOp3vyGDYDexx6AEGMRWsNlsz/Cgmqdu0vWonmzU3dmiujLsxeZX0VM8h/mGHbTspg==
X-Received: by 2002:a05:600c:35d1:b0:415:431d:7747 with SMTP id r17-20020a05600c35d100b00415431d7747mr2765136wmq.7.1711664550548;
        Thu, 28 Mar 2024 15:22:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fc5:b0:414:486:ea6e with SMTP id
 o5-20020a05600c4fc500b004140486ea6els545804wmq.0.-pod-prod-00-eu; Thu, 28 Mar
 2024 15:22:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUg2/aYyyJ6vzGDH54LSjF7CcTn+rhvXRU2RmBTilMgUr0d/yefbdBf7cpEVh91kW8r2SaZosUzhTOtLBhQG+fbgFZnJ39V+WmP/A==
X-Received: by 2002:a05:600c:1911:b0:414:7fc6:e482 with SMTP id j17-20020a05600c191100b004147fc6e482mr589248wmq.0.1711664548466;
        Thu, 28 Mar 2024 15:22:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711664548; cv=none;
        d=google.com; s=arc-20160816;
        b=RU7KICEzu0DC8r86a6tZH6v0GBFZ9cXdEo2yzj2B2hlGXDPQ7HlY7D285iYQQ/G44j
         HfprQfIxdUIBN4xr98/a+8MSNDn42sUYl9oDfkXuFBph102jHV7MYY/NoAwhHFbKamrd
         LPR+Ban+zfiNsbKHdGa2nN5Z9dHhdaEtzMDpPBCEjNEWiWqVIMe6B4J45Z7mVwvEAC0p
         ed0LSE0zTml6/NHaamKm+DYU4ETYz2wjVFIHiTcz06ZnITGj/UXmfNOxgcgH+5FC61d2
         ANE/LnR9qqjgM02sZ27yAhb9adEi1zFegsZ254/vKVSowOGoERYlP6wdGa4MDDlx5Sqf
         dE6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=F/OjdkXwLEp7mczzswJbuZjPn4dGgroiJ8sIvpa89YE=;
        fh=sC6WIajlq4Y4TnSaDza4ubEanHLcMDNAIdUn+jLUYhY=;
        b=YzTEpigzJo3B5xSDlyb5+T9RNq0LSYvru+w81iRJpC3d0WchasOBUxN2Dd7z/jFTAI
         x4MbFFOX3UxPMeVOs6MiMhvhA8OY9Ibg3K5xZclO28NlhMYF2KLgMKhnA8Q9tN1VXgx/
         ZR+D1ocQ+JRsyuqPxMFlxxMRHvDqeVoA2539D+IpjdWjRG9NvKeaEglIt1O9XlfVbqis
         SvArVXiEswhltFAQi4pQ09GAaY9JTKPPcke9B5Jj9kZkVvn3+aoOrjfCw5WQg6Nd2hch
         CPw3YLEAxZMF9yzzUrbD6F/+fdCN0t9HRz0S5jknv2fFiWxUR02UMpFKKbtwLm4drBkm
         Vb1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UMrnfAMp;
       spf=pass (google.com: domain of justinstitt@google.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id m14-20020a05600c3b0e00b004134299eca3si500017wms.0.2024.03.28.15.22.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Mar 2024 15:22:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id 4fb4d7f45d1cf-56c36f8f932so4392736a12.0
        for <kasan-dev@googlegroups.com>; Thu, 28 Mar 2024 15:22:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUj+rfgHNCoaK2CsRnuFdnrDjRrdNYNiKViqw8GSoEq7xxiPWDLjixxhiox7CSb4HYPzvz1EmVaedlb4kcFQTU95biSlmw5qNWlRw==
X-Received: by 2002:a50:9feb:0:b0:56c:53b2:9e32 with SMTP id
 c98-20020a509feb000000b0056c53b29e32mr527053edf.13.1711664547964; Thu, 28 Mar
 2024 15:22:27 -0700 (PDT)
MIME-Version: 1.0
References: <20240328143051.1069575-1-arnd@kernel.org> <20240328143051.1069575-5-arnd@kernel.org>
In-Reply-To: <20240328143051.1069575-5-arnd@kernel.org>
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Mar 2024 15:22:16 -0700
Message-ID: <CAFhGd8qDCMkP6rZ6A6i3b7DuJ0Rzem=V0TxAkvmMTsZM3NH43A@mail.gmail.com>
Subject: Re: [PATCH 4/9] kcov: avoid clang out-of-range warning
To: Arnd Bergmann <arnd@kernel.org>
Cc: linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UMrnfAMp;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2a00:1450:4864:20::529
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Justin Stitt <justinstitt@google.com>
Reply-To: Justin Stitt <justinstitt@google.com>
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

On Thu, Mar 28, 2024 at 7:31=E2=80=AFAM Arnd Bergmann <arnd@kernel.org> wro=
te:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> The area_size is never larger than the maximum on 64-bit architectutes:
>
> kernel/kcov.c:634:29: error: result of comparison of constant 11529215046=
06846975 with expression of type '__u32' (aka 'unsigned int') is always fal=
se [-Werror,-Wtautological-constant-out-of-range-compare]
>                 if (remote_arg->area_size > LONG_MAX / sizeof(unsigned lo=
ng))
>                     ~~~~~~~~~~~~~~~~~~~~~ ^ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~=
~~~
>
> The compiler can correctly optimize the check away and the code appears
> correct to me, so just add a cast to avoid the warning.
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Justin Stitt <justinstitt@google.com>

> ---
>  kernel/kcov.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index f9ac2e9e460f..c3124f6d5536 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -627,7 +627,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsig=
ned int cmd,
>                 mode =3D kcov_get_mode(remote_arg->trace_mode);
>                 if (mode < 0)
>                         return mode;
> -               if (remote_arg->area_size > LONG_MAX / sizeof(unsigned lo=
ng))
> +               if ((unsigned long)remote_arg->area_size >
> +                   LONG_MAX / sizeof(unsigned long))
>                         return -EINVAL;
>                 kcov->mode =3D mode;
>                 t->kcov =3D kcov;
> --
> 2.39.2
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAFhGd8qDCMkP6rZ6A6i3b7DuJ0Rzem%3DV0TxAkvmMTsZM3NH43A%40mail.gmai=
l.com.
