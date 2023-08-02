Return-Path: <kasan-dev+bncBDRZHGH43YJRBME3VKTAMGQEMCLJKSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B0F8376D4B4
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Aug 2023 19:09:05 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-6bb31d627ebsf129565a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Aug 2023 10:09:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690996144; cv=pass;
        d=google.com; s=arc-20160816;
        b=SphFufZwGe3wSIFUTBth2FgrbAHmrOJANTbqkBcUkGWMYHGReK8Rc2tSzohD/hGGwI
         1xqA1+GpGoH9tVyXhvPc9VeM16JqwLVjjZmLMMSt6TjttgdVkTLXzIpBAnkYjByD+t92
         Aws3cW2tz85uYtoldna5noraUUpAOlm/YWN+2pQvgg0cB9vfK/B0eSbfDLjXX0r+TaP0
         ht1f7cAjTSeFCQyvpAcSZh2yg7DOMNJd9GaTV9m28WLPhT1pdF05/cdiSn2kRj3IWYLA
         c1x5AzQrdc61xlfViqt0gUNf4SuF6GIhBmlDIxshWcDeqbG0mGEGEkMFlOjdLuOtw3NL
         loWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=49AC+uw9i1kXdTS40XhYyy4oiVXYl5vTbG3mgwIPPsk=;
        fh=ddTbSXCcqsa4KsF9+A4JAtnuJlth8cg+VIOfuX9vnXE=;
        b=DoZ6KQlABQdBHTWFm0X24XcdOXU6zxqv4jlOXdW/yja5YblBf+t/gCOV46IZcOT3BW
         YdillCaBJmMx1Ej5ToN+P1lsVUW6cwxAIG3W6ahxeR1CMWwmYnxYqwVw6uiWJcJp7VAZ
         EGBw0E5li8HPqZoyIdD0bwsQwaB5ibtIshoCl3YaxkHH4JSx2ebAcQ9LryDxGwC9omQb
         WEtcOeSZYX1eI3iKp4ogJ+BeCpNkV/+Q8Rxi7ISiinLm6HXR69n8u4igbXLc/iq/34M5
         HCJle0kpkij/YwkG3VIxN3xrL80mPBn4dhtKAx1vBydKPq6p5WWXoxNWuYxP9x7GVSn5
         /1fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="fPw/kdvf";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690996144; x=1691600944;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=49AC+uw9i1kXdTS40XhYyy4oiVXYl5vTbG3mgwIPPsk=;
        b=cZM/bDMT3qEkQezIWaEF9wp5Aa8JiDDQ772adAUnvAa+kA6Zv3j7mE4vyFP/Lwzj5K
         ImPDb50oGi5L1HiPBHbZGCFPhxGqcy16DkrJvFKyMAlXmWATmeiwKmhb018knpKn9NLH
         Sa9a/CNr7TYovZmdD8IfiF/0fL9ipgGq69jKF+Sde/dFYJNtW4nGzKVojcQEk+Q7OBo8
         rQLX2+yNsLu/IehWt4kD5Nd9oHey4tf1qLORj/4lDYoCNlUhX2m5oSdLgh6S4O8tTbNM
         BM1SSvdAdnz6KnNblnMkqhsEzxVY4yYLqd14TVtC7kny9j1tfWc1d35rpWrItgUnQqPD
         CWyg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1690996144; x=1691600944;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=49AC+uw9i1kXdTS40XhYyy4oiVXYl5vTbG3mgwIPPsk=;
        b=ZhWOqddzhpCuHhVATjaekZXbj+6JGB6pmSwomO5On2eXGwl21B10Od4XlCWWtQHPVg
         PHeXi7MmVznz2idDG9Zohj8DADgu/GAcLeB+pH0wlpLXEICKHPzkgh5/g0y1HspYRgFB
         RJVHq1ZcGtBZVjmpdmxvHoG73cF3v8u2zRNhrj6O950eFo6nhWLZqZ/NuWOHnGJDysx3
         Ub3Zy+YZkIxAwSVWoAx1i6xMXFMS8lKkLXJ7wIB1sT/sfbBB/3Is9wEKW2LhDiAL6u/d
         xzXEFTBx8/jBn8232quAv3vIE44Gxs0DNBOAxMsnSZu4kMfCg0w/h24cDyeXWnN9pLtX
         eTfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690996144; x=1691600944;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=49AC+uw9i1kXdTS40XhYyy4oiVXYl5vTbG3mgwIPPsk=;
        b=CuKEtXrT8GoygI0jFzle36HvHAWEypu0zUEhNLz6r5LAHAatXqHZjSa5rFBLK4mNSQ
         LwvZLe1WHJe2MaUdT/48kYWmCelJaTgNYcJQ1i2YREnxcosGekyUV1IC8NjOiSdYQhAU
         5j3PC+TSY+7xEO5oOotyA5m2qmVHVMGW4KeSaY+P/+YEECXOiIL7asqrxDRoc/NI+u7r
         2SqvZzKMLhUgoC2qZykPUxit4ERB4VSglKFPhuJXbPWREaoOzBMN7SRXOHfvVZDdJui/
         nOziuUw7rfeUgb7fJFRvBUXzA5jPL8FM810ehSt49yxmQXSbi4ykOubzDMLHRXaGklFt
         3cCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaEXWCQG/C9c8wkQdSrcfksjb7d65l0RtPKLRUCI1P/ywhQ0SRS
	zo8/1UgnitwCTFnsp5ABdB4=
X-Google-Smtp-Source: APBJJlFKL2HamFHexU+MxfZk0kqvAFgORJxHwwK/BRua3HL0iRdSgNFhcLw1HGEAnOJozQXpv55P9w==
X-Received: by 2002:a05:6870:51c6:b0:1bf:d8a:b5bf with SMTP id b6-20020a05687051c600b001bf0d8ab5bfmr6575123oaj.36.1690996144248;
        Wed, 02 Aug 2023 10:09:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:40c7:b0:1ba:d90a:7d69 with SMTP id
 l7-20020a05687040c700b001bad90a7d69ls3419666oal.0.-pod-prod-01-us; Wed, 02
 Aug 2023 10:09:03 -0700 (PDT)
X-Received: by 2002:a05:6870:a54a:b0:1be:f311:4a2b with SMTP id p10-20020a056870a54a00b001bef3114a2bmr9759047oal.24.1690996143653;
        Wed, 02 Aug 2023 10:09:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690996143; cv=none;
        d=google.com; s=arc-20160816;
        b=BsmxSYf2NSG9d1dvHpMOKYcVXZS6YCVGkExXaQFdo/CoX0RrmCdy63fjg4yQhoVW1M
         +xBPKgnNdobI8dH2MZ1efQM7gqsti+ylEvmqp/cIsejYoY/VpNWf9IbvAllfKS+028R7
         CdxFBmoZ6CCfR5/1Xg4Pd0LGu0ifAOQLGwgQqvidvbsH73rxClaqyU4UfEsPPnUICxur
         a9SzyF3Fle+/z0kNHsFrrm8InSKCo7WXzK79shGZRKBQ9R3JqNrphcrk6RK/cSdm/zxU
         ji6sbplnclj3v4sTwI+PtoOU7dTfVaRi//XtISResTuwb/QlyY9M9HrGR4DONb/w96b0
         OPKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VzgOK7S/nDkSxIWVLP6Niz2nC5TbUp6AvvmSTjYDoz0=;
        fh=ddTbSXCcqsa4KsF9+A4JAtnuJlth8cg+VIOfuX9vnXE=;
        b=Y9oJSfGhIL1X+zMX96CT0NyOibca5nLvbsDzTRmhIph8ibL6C+T4A4WWQbr0s8P22G
         EtBovRYNUR2qHL0pU1GPFvXD7iohlILXTEwVQ/HdAwgQd24vF1MY30/0d7xAzuaNQLRx
         rMV3vVtk8rrmYdytp3GbLn5hEfAWWqeXu/F9IlILD0H3qiJPQlvKDYYnoZxjRnpnik8m
         V1g5/BKIuA+FzMnGjMSszoK+QdlBEn1eGSX5xS0LEam2yUjQQr4Qb8Yux3PtpYR49I6r
         I3HB3GThn64L3odGwu7YfS2KyYnGbqwCU7W4nh9Aj1YuGkOfU4mgwjcA5sbZKO8d22RZ
         c/lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="fPw/kdvf";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id t14-20020a05687044ce00b001bb6f89348esi1250808oai.1.2023.08.02.10.09.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Aug 2023 10:09:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id 46e09a7af769-6bb07d274feso93727a34.0
        for <kasan-dev@googlegroups.com>; Wed, 02 Aug 2023 10:09:03 -0700 (PDT)
X-Received: by 2002:a9d:7a41:0:b0:6b9:482e:ed10 with SMTP id
 z1-20020a9d7a41000000b006b9482eed10mr18099228otm.21.1690996143376; Wed, 02
 Aug 2023 10:09:03 -0700 (PDT)
MIME-Version: 1.0
References: <20230802150712.3583252-1-elver@google.com> <CANpmjNPVO_t058c6Wcwr9TBwxeoH7Ba0ECsf6Wapn60br8EtkQ@mail.gmail.com>
In-Reply-To: <CANpmjNPVO_t058c6Wcwr9TBwxeoH7Ba0ECsf6Wapn60br8EtkQ@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 2 Aug 2023 19:08:51 +0200
Message-ID: <CANiq72k7_Ujg31UHfivv8zyog-6Vs7YehTpk2y-qRiuT-KMmAw@mail.gmail.com>
Subject: Re: [PATCH 1/3] Compiler attributes: Introduce the __preserve_most
 function attribute
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Guenter Roeck <linux@roeck-us.net>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b="fPw/kdvf";       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Aug 2, 2023 at 6:51=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> Mark says that there may be an issue with using this in combination
> with ftrace because arm64 tracing relies on AAPCS. Probably not just
> arm64, but also other architectures (x86?).
>
> To make this safe, I'm going to move __preserve_most to
> compiler_types.h and always pair it with notrace and some comments in
> v2.

Sounds good, thanks! The patch here was otherwise good in terms of
`compiler_attributes.h`.

I was also thinking about the implications for Rust. I guess if we
need to call them, we will go through a C helper for the moment, and
later on if we get cross-language LTO (or the LLVM IR hacks), it will
hopefully not be a performance penalty.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72k7_Ujg31UHfivv8zyog-6Vs7YehTpk2y-qRiuT-KMmAw%40mail.gmail.=
com.
