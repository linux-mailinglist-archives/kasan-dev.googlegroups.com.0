Return-Path: <kasan-dev+bncBDT2NE7U5UFRBMPJ36UAMGQEOK4FWIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 74EAA7B3FD6
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Sep 2023 12:13:07 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6557c921df1sf209548606d6.2
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Sep 2023 03:13:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696068786; cv=pass;
        d=google.com; s=arc-20160816;
        b=wk1c6+IbMOLLirvaJMvVWcU9sbA4N2EbYL3Kfn58M4ZclkwdWL/LOiBCmGuwN6hiY9
         o+Yak9EV/7XOW9troJkswLnasy2Lig3ffi4D2rJKmxXZLEEcuelMJQR4xaA1t44gwxwS
         iWJO2mMNRr4AU2SdM18zZ64BeVwHneDgILXfZQqZxXFR4cZiyeQ5gOehpEnJBYRjIfv4
         FdhOjYYQXIYVxJTyD6Qs4WPiQMxDSlRvNEKTSaooBy6a/VhpUcN26u60nXY/9rzJmc58
         GYHSiKk3V0fvMF5JMnfd65W6dxZSpRJD5XIe9mbOls6U48c6qbSS2W5/Yh24yAk4RYJT
         OxWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=cXLEn5TGJyV71MjHUnyVwLK2zTswCBq9hax5IXXUMDU=;
        fh=QrEmM/VDBxThTLR7EcmVE7I4YShlGpiaZZhv0c33kE0=;
        b=pXdT2j9iAy9q+LiCVQpty/R5dpdSdcabw9MaQtvyNskdVRlUEPnEzMey/8pFvrcf8x
         rqCIap2eoX3o6+/sWFPmCI/BRfeeizs9t4z9Jm1RwLLt8bC9JdzuizUdFyzaTduaPy4D
         shSoCLCwYf+jh33CwmNaNf8H1xn1TRf9+IQXbx+mXxGoXqA5DYISuJ+t8HWTFJOU9d+g
         FYM5+rc9Qm2evrKxj9ccaXsENCo7bXIdxQYAYEJWk/3hcib/Z05MiiE04jWQSOC/gqA1
         zkwwzmtogc8FNF3HiBlalpT/o/HsD9xDy4RU/IW0imDaRM92/L1HzJsqm+bTzKgapGus
         da/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Cd+L2zUW;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696068786; x=1696673586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cXLEn5TGJyV71MjHUnyVwLK2zTswCBq9hax5IXXUMDU=;
        b=bnzOb2UW//gcmcvyQjwWsSZ7fXmEZgmR9+CFDbWj0csy9PQAuGdQVTlfWIUQH9X1ie
         od+v5o36TKuwu8gQqRWikJRin3OZyWqP9bN/gHsfJ1BxNd3T0p2SU9Bc0gtUfsO1Zcc/
         Wjb42ghLFU6CFPRnjDfUKi7VLDZ5rpvPz0zNndH8EJIQwuPg2GbIXFHjcWLpDyRx3S1S
         gRvYeyTqkvl60PU4iiwc10u050gJGEX5o83WXkN+LL8lXjVHApesEKLs2swu9N+FpIvq
         DnRmNakNe1hAlsakAVz06sg0G9fhCPXKITUS3EP3NDu3McMc7OSWmPalK6fQDYuzVd/D
         ++yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696068786; x=1696673586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cXLEn5TGJyV71MjHUnyVwLK2zTswCBq9hax5IXXUMDU=;
        b=ZDPZbfSkkCQPqRuGxQC+I8neZoPyR7ndh5hJiuukiuRu/4fDKFaa2sxLKHtAEx5+35
         idU5/7jmaQpt8Lns1SR37UsosBp6SWHBaY1Sah24QpqZwm2yqs22jGLM9e3UefM87eke
         hGQFZuYzSo5p7SElycdGtxWMIFfUxmJT857dw0apYXn95nzrUXLIWm0Pz9PF/4BOVEhS
         hXKj8BTihcUu4O22d9tg1mMNSrbIbtdCg3RLqABrsgEbsohsSt975h8S7WDZjX0eIq0y
         +Bc81a1Sx7GYF9O9Py41lEN+4X907ulKl7hEAqO3wnLqYeo6C93XDxBPh7/sOlv+VIb5
         tVjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwqRE674ecVR1zO3z0NR0KwAVhcX0ld/w+s8+p/GmJDnaVAIg4H
	rxMVxBAZKDB0MahMhMdx09o=
X-Google-Smtp-Source: AGHT+IG8/C9Z2ZIiB+1BqdLlG/uWdDRgunYuZd3v0b/eanGp7DPgKCF/Bxbi2wQygbk+d0+kilr54Q==
X-Received: by 2002:a05:622a:614:b0:40d:589d:9ce5 with SMTP id z20-20020a05622a061400b0040d589d9ce5mr8267569qta.34.1696068785969;
        Sat, 30 Sep 2023 03:13:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4d4e:0:b0:418:f20:220a with SMTP id x14-20020ac84d4e000000b004180f20220als907941qtv.1.-pod-prod-03-us;
 Sat, 30 Sep 2023 03:13:05 -0700 (PDT)
X-Received: by 2002:a05:622a:1756:b0:412:206b:92e6 with SMTP id l22-20020a05622a175600b00412206b92e6mr6987923qtk.16.1696068785217;
        Sat, 30 Sep 2023 03:13:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696068785; cv=none;
        d=google.com; s=arc-20160816;
        b=Y2K4qiFeKtZD4Jwt4aWG8SSbaRcI247iNul8L8BFY+X4bHkQLByPx+1TVLseaYEhoT
         oqG9NonmXsRfQszWHWIAdW4Nq84h8ewYYvPxjCsSEamD7d1VdqO8BfLAbH8EAgEHIlyn
         XbiWQLxaPPOv0Az5ErGKSaAcPyGIcIfC9Rmw4MveQDvc0zZ0nXNTeL+1qzAVxCwofg8h
         2IC93BH9XMlNWJyqYwviGeCRcFWPhOIPw8muTYjt0/I0S1lUTg6OanQADW+Ne90G9l46
         ySWldjfV3bec/YCCENaLaaGF84369ekdda6f3Q1fOQKeVDQQ67uI2ctJJcwag4+z/1qX
         frgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IsZF4TWVX1SRhu6LHbwwMx3eoaC8wL2iO+qcbuu8h14=;
        fh=QrEmM/VDBxThTLR7EcmVE7I4YShlGpiaZZhv0c33kE0=;
        b=bTgBBlrUMkBzJ1mkLPNMTpCdsLBVve7HzjSQBpQtT5n+1GqeacC1q1LgrLGCbw6dZN
         CCB4Ohr0giozLK3f3wxyLMbO2tkRFdNC5KOClokmHIriIeNfeQpolcD9/tlpTeEhVB2L
         Gs9l57jVxjHPdpDmUiEEfglZu4wuc/iE5tpnjaV9hSax1aD9FnYVb6355iG4EiindnVQ
         dp/jq6DBic++U2BymdhB+xDlsuEQBoPxBk7SxigCFYVaanuXh7SiyPprg0obRBcUqSIF
         Q+RjDzzuy9/z3lrOtFpmoEkJoSVNuKwLMz84zrX+CtgpwgNDGJIfOH4dUzQLEthIN2KB
         xGnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Cd+L2zUW;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id z25-20020a05620a261900b007742b036b37si1310604qko.7.2023.09.30.03.13.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 30 Sep 2023 03:13:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B19BF60AFA
	for <kasan-dev@googlegroups.com>; Sat, 30 Sep 2023 10:13:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6709CC433C8
	for <kasan-dev@googlegroups.com>; Sat, 30 Sep 2023 10:13:04 +0000 (UTC)
Received: by mail-oa1-f52.google.com with SMTP id 586e51a60fabf-1dd830ed844so3309020fac.2
        for <kasan-dev@googlegroups.com>; Sat, 30 Sep 2023 03:13:04 -0700 (PDT)
X-Received: by 2002:a05:6870:96ab:b0:1db:3679:198a with SMTP id
 o43-20020a05687096ab00b001db3679198amr7517135oaq.24.1696068783796; Sat, 30
 Sep 2023 03:13:03 -0700 (PDT)
MIME-Version: 1.0
References: <20230928041600.15982-1-quic_jiangenj@quicinc.com> <CAG_fn=V9FXGpqceojn0UGiPi7gFbDbRnObc-N5a55Qk=XQy=kg@mail.gmail.com>
In-Reply-To: <CAG_fn=V9FXGpqceojn0UGiPi7gFbDbRnObc-N5a55Qk=XQy=kg@mail.gmail.com>
From: Masahiro Yamada <masahiroy@kernel.org>
Date: Sat, 30 Sep 2023 19:12:26 +0900
X-Gmail-Original-Message-ID: <CAK7LNASfdQYy7ON011jQxqd4Bz98CJuvDNCUp2NRrHcK29x3zA@mail.gmail.com>
Message-ID: <CAK7LNASfdQYy7ON011jQxqd4Bz98CJuvDNCUp2NRrHcK29x3zA@mail.gmail.com>
Subject: Re: [PATCH] kasan: Add CONFIG_KASAN_WHITELIST_ONLY mode
To: Alexander Potapenko <glider@google.com>
Cc: Joey Jiao <quic_jiangenj@quicinc.com>, kasan-dev@googlegroups.com, 
	quic_likaid@quicinc.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	linux-kernel@vger.kernel.org, linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Cd+L2zUW;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Sep 29, 2023 at 11:06=E2=80=AFPM Alexander Potapenko <glider@google=
.com> wrote:
>
> (CC Masahiro Yamada)
>
> On Thu, Sep 28, 2023 at 6:16=E2=80=AFAM Joey Jiao <quic_jiangenj@quicinc.=
com> wrote:
> >
> > Fow low memory device, full enabled kasan just not work.
> > Set KASAN_SANITIZE to n when CONFIG_KASAN_WHITELIST_ONLY=3Dy.
> > So we can enable kasan for single file or module.
>
> I don't have technical objections here, but it bothers me a bit that
> we are adding support for KASAN_SANITIZE:=3Dy, although nobody will be
> adding KASAN_SANITIZE:=3Dy to upstream Makefiles - only development
> kernels when debugging on low-end devices.
>
> Masahiro, is this something worth having in upstream Kconfig code?


Even if we apply this patch to the upstream,
you will end up with adding 'KASAN_SANITIZE :=3Dy'
to the single file/Makefile.

I am not convinced with this patch
since this nod is not so useful standalone.



> > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>



--
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAK7LNASfdQYy7ON011jQxqd4Bz98CJuvDNCUp2NRrHcK29x3zA%40mail.gmail.=
com.
