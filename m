Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRH2UWYQMGQEJFXKGVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id F1E848B154A
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 23:44:37 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5aa18a128c6sf425651eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 14:44:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713995076; cv=pass;
        d=google.com; s=arc-20160816;
        b=doNw1tG8fSfrFL/FQ3J4Sm7ZVjZODI32iYVRU9GzoqGxTTk2OQ2yMWMmWN4v93Zh4j
         /+bjILl7a03Xzlbw6oKorhQkEm0Fjox+lCzABvTtwNdyOjP45Bsabel5LC0fe2KWuq55
         jnbHPWlfMwgjvyDwALR02Re05JOevgc9+eik3TcHiIXI8JQFf0wF0YGvHEJ0XfeIUlFO
         OQmQ/bSj1Y35WiGm+Mg8LGMA7xthfBMlXEoCIrGA0OsbQSIGlPdF7TMxJqKBV6yCF+IS
         mSs9Pk0D7P5iKsA3TYSifgqEfWVq9HFPlUIlvp+d7/XfpqJxVq++jQ/nztzyAXCdYiAd
         vMzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OErPLv0jGXZX9ykbU25s3fJzc55f/rNCdP3veP2OvCg=;
        fh=AAdHZlIKL83lKZbK8+4Mn7rS2VAwoOoMP6If7SRePB0=;
        b=RolwsnwYblzina3tp5RiQHHBCaXsBUvAJp25DJDxHgJaT134YjC6HXzBsbagkjo9MR
         VGWXzc0VmZ22qMVWH6HQ+IURT9YEWnApYQsSEuRtvBD8RSlxZ7zHUnzLQKgLHlopc0BD
         QDFBXSRCInZo1FEwI1mxH6z64OkPtXry+t+/Rp6Lpq+x6gFU+AliEyftR0gvMozbkc+h
         zXeYPrP70P7tNjzG4pccrnwtexpKw14Hf8qHbZJLdLySlAaW84eL+2v4KDfCLj+yURtz
         22SHlRDBhE7ZDFpn0SzxGeSngli82BRvEWJPS7CAksemQ+R+GHmiyTgrHP2pIsl9UuwK
         IHfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RpHPgj06;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713995076; x=1714599876; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OErPLv0jGXZX9ykbU25s3fJzc55f/rNCdP3veP2OvCg=;
        b=HEcG0SlZgsVatf4FBo6pt/D60bglizoSExmKKuZ4+4eyJ9ZGMZry8GNwylAjsmbEM7
         pLEN8Ncn21Q4lqrR3gFXDNwjnVo1YVFS0ac1MHemxlcP8hhyiQZT0YVWE1y85/PmAVN7
         PTCHPIv/M6yDgNBro/TU6+DHlst105PCbTsDA71Alg5VYVK4f3gEMVnkC3i6ibTAKHs3
         bCysyqpgXjGukFAZG1FdJOM32hSBMEaUO4zdKaiTzXObXoJobYtwsiEb1RQ6MtzflMuX
         VKsijxvkiI7U+57VwDPPOLaw2zBxTWuEcGGbopqy0L/Uqs0Yjp5yaICIUV9PfjJoOeKO
         Fg+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713995076; x=1714599876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OErPLv0jGXZX9ykbU25s3fJzc55f/rNCdP3veP2OvCg=;
        b=J2vZUyYLJeEoqrDmmwVceN1GYlvBX9udlOYFNQkTXAEieCJMqLeOS6PVrSV0CKJM+q
         +vu1Jl0Xci8sCfs6sTOZlDELxctK3RXoBk1war7Aa1K2zaDTC5puc55hwrSgNneSAJrc
         RhloH5HkFr3/mEB5nlsVMen5DYDCdGDXUNGUyAtyEHy4p6bKbzTz1e+0uflfLrdjXJKL
         zCYCcn3cK45CEESYHUGYK+w4hqLZ1qi8bjSzboRKGCTjLZqZWaeiAikLbxq2feS4TML0
         Oc4wq9ErnXV7Q5R+tUVa+UQZzX2aWVTiugsADcj4nIypXZPQeDgT2/Duzd+VGHMllCZS
         zOvw==
X-Forwarded-Encrypted: i=2; AJvYcCVu/OPlJmV/TxbqVUs4lHUPOAJSBf8pnXE3eplz/GYPFcEfFN5JBzMD3g4uO2IqGx1skqAzM5ULYuY3e2uHpzHCf9LD3m1Z1Q==
X-Gm-Message-State: AOJu0YyqqMk4P4Rb6KJ2fkHBv3eipWPq/aAA0B7e+M4a74c8dKVDzdi2
	/m1trIfV9KW8PrDI//H2grt5xB2T4SIciqoVmgNyp3/QTfgG0GAF
X-Google-Smtp-Source: AGHT+IHSSAI7uFkzu+3CKypKVXT/OV/szEcjt69VIJ0DnrMM8m141iRqennJy+qpmr28ByYzlGW6Ug==
X-Received: by 2002:a4a:5441:0:b0:5ac:4372:1d6a with SMTP id t62-20020a4a5441000000b005ac43721d6amr4092826ooa.3.1713995076737;
        Wed, 24 Apr 2024 14:44:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:183:0:b0:5a5:68e3:9cc9 with SMTP id 006d021491bc7-5af5d3a1453ls319001eaf.2.-pod-prod-01-us;
 Wed, 24 Apr 2024 14:44:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVpjn5U4xLRlShqPDvazdJTeMNS3yUlG2fXp6RpGjpDbwUrupwR8/tf67GM2e6jG9ccOkvw4vi4Q0By/85p4hS/Ghe8N3TiQm6Pw==
X-Received: by 2002:aca:2412:0:b0:3c8:39b2:bd8b with SMTP id n18-20020aca2412000000b003c839b2bd8bmr3836384oic.55.1713995074716;
        Wed, 24 Apr 2024 14:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713995074; cv=none;
        d=google.com; s=arc-20160816;
        b=JPvDVrJQ3ofZEp7+RxOvISAlbRWWIfbG/l/S3gzFS4hhsLhqAIaAeOpL5a8fYk0GOD
         L4qFMSuYHLnCKV8lvTJMprPfbEYCKoCSFkK17rF/8Iaf7Vur8+t9TlM/LYzus7A2SZGB
         MeU1E6TwGixUOOnJaC8IelyyhnjnzThERXjgZlPOttfgu7k9khemw/fUtCsTI1dow+H4
         eIia51LHpwvU8zhWo8292v30G+/FZX50TJClmnlwSeK5e36sMDfab2HLUrBJFR3tpnqS
         g/7KtRbb/Jlkdw7aODJoJYqZB7d3SWyeA/6dPZo3DfcAm1GTV1vGEmXTN1+FEMfst+mk
         eYGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YP575gq/gmDMB9w/VjeltQDFfmbUMJx+bMv5C2CUKNs=;
        fh=MMNvVBiPkxtoMv/MQ7aCEGy3bfeaImZ2WviGQAMarDA=;
        b=BcxqRSmDA0CmWeuTIj024/1Qzd1xcvt8dqAcWfbp0ptLW9d7k/2E274ChQVR2prckZ
         s+hV+quDjpY5LOiSD8S2UJqoHS6yRzkX0gFugAz9geLo+E776EdyItad5GMGn4ag2AJQ
         UnI8fAQnOzkCsYrgJmQgEGIirS8iD7AWgCY5dp0yMqGHLo1LI4GM0X9cxMJQQ6hDoCJn
         F4KRGlBWvgCBTVrq+EmQE9s2Id7DMrgsUYEBJyh34AN+4OopVaCF/iIkxqHRmOtKEO5d
         2PoASQNDXsq7MV0PrtBw61fI3Ejptn1Eg1y+UCPOIdDeoKciLjXSU4DlPS679mN3WgjK
         nkvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RpHPgj06;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe30.google.com (mail-vs1-xe30.google.com. [2607:f8b0:4864:20::e30])
        by gmr-mx.google.com with ESMTPS id p6-20020a544606000000b003c5fa00aebasi1361304oip.2.2024.04.24.14.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Apr 2024 14:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) client-ip=2607:f8b0:4864:20::e30;
Received: by mail-vs1-xe30.google.com with SMTP id ada2fe7eead31-479f50bcd7bso129274137.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Apr 2024 14:44:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUD13SAI+7ggjuxFAd3oehMpokdWTzwaCZp3P21BRLucl43MRhfE9Ybifx+8gvhx3fpvRDRUSNOcrkmEzMEpRuztrVVrmRfOPgycQ==
X-Received: by 2002:a67:f8cc:0:b0:47b:b94e:9162 with SMTP id
 c12-20020a67f8cc000000b0047bb94e9162mr4484501vsp.4.1713995074217; Wed, 24 Apr
 2024 14:44:34 -0700 (PDT)
MIME-Version: 1.0
References: <20240424162722.work.576-kees@kernel.org>
In-Reply-To: <20240424162722.work.576-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Apr 2024 23:43:54 +0200
Message-ID: <CANpmjNN1+bZdQJSdc4o0EY4Kpe_L5s3JyT9smAEx4O_w08GaXg@mail.gmail.com>
Subject: Re: [PATCH] MAINTAINERS: Add ubsan.h to the UBSAN section
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RpHPgj06;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e30 as
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

On Wed, 24 Apr 2024 at 18:27, Kees Cook <keescook@chromium.org> wrote:
>
> The "ubsan.h" file was missed in the creation of the UBSAN section. Add
> it.
>
> Signed-off-by: Kees Cook <keescook@chromium.org>

Acked-by: Marco Elver <elver@google.com>

> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> ---
>  MAINTAINERS | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 7c121493f43d..5acac5887889 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -22653,6 +22653,7 @@ F:      include/linux/ubsan.h
>  F:     lib/Kconfig.ubsan
>  F:     lib/test_ubsan.c
>  F:     lib/ubsan.c
> +F:     lib/ubsan.h
>  F:     scripts/Makefile.ubsan
>  K:     \bARCH_HAS_UBSAN\b
>
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN1%2BbZdQJSdc4o0EY4Kpe_L5s3JyT9smAEx4O_w08GaXg%40mail.gmail.com.
