Return-Path: <kasan-dev+bncBCT4VV5O2QKBBS4GYHDAMGQEPLMOW4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E1A25B8E318
	for <lists+kasan-dev@lfdr.de>; Sun, 21 Sep 2025 20:26:34 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-57b35e1778esf1547385e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Sep 2025 11:26:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758479181; cv=pass;
        d=google.com; s=arc-20240605;
        b=jUUADWR/WQqgZbEvS5FBVGWt8esiwZENpWaz1HooRbMm9EN73M4o4hKdB2ttdeE8rW
         NKkV+ip1wNZqu70wTnuzyaXC1q+eTiIyC4Gv6sCt4um63jVNjxC8Aqtmvh8FBX7x1y+m
         mRdwjWp2OVIiopKNzyEPyUr3AltDu/6fZizHcZWcuOJ5xHV6+MiA9ZU/ub9Zobmhkgyz
         xaHApCvfyflK2OGUynV1sW/A5+s1ATT7MuUaIylI1+3t6swGcKsPGTgDK49qQdpLmC4N
         LOAeoizSODFRsj9jN7Q7Xc8s1oNgvxMM+ew5FpMJY1rvMt3Ob1uUeANL3YvnmE9EdA8u
         F1zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ioBr6/1uH1Q/K3M/i7hQXQOwxzCFnSe5d8dL4VooeRY=;
        fh=o5wXlymuoH1Z+QbD+0xyEirE5kjGc0/BmTF521or7V8=;
        b=ISJNVDbKvp8ZpmxPE4zXNVk8UpdtQ7IDIIyr8e+2atDa61LWNTYP0Eq3l5dcD8MIZo
         PVXqc49MF0JoYMm7WoMu4OGYilIo+XAZ9ZjH2Lys7AOxTf7eiB70Mb3sSSj3r5THPbxU
         ssQTclE41QUoVuNGONXHpnqVv6CymCyTobxWjt7ZzzyunfGraqSFezKUmfyVKIXMcyT/
         YQ88Y+7UJ0/WLVWL6G1K1/XHE4Iq1JU2BawdR4ixRfeuvZ/BGNWaOrkrGHLeyDX5vyUE
         IuLeIv+IBUzW+dgPBCuLbqs586cnlb4bDuZxvam5EgTc9YDPgSLXIHVIPdgUwzsITl74
         WaIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FmnE4Mb0;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758479181; x=1759083981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ioBr6/1uH1Q/K3M/i7hQXQOwxzCFnSe5d8dL4VooeRY=;
        b=HEyoHc3uL6o7Rt3tyt0tPzxbUW7SHExOEo5EDpMPyrxxHrLK7SU5S9JbVgo2PtppcZ
         KxWMnmE0y8N1ohQJYq0Esnmzv5zr38QvwXc9UwFmBy/nnauYPh4LJCejlmIWjK7nZ1w3
         wJX29kl60C8aZLEu+luLpA7Yk1awcXPHfTuIcLBBA5jyRAD5QWGIJciYipPn2Y+h8KXY
         RZ8z7jELxsTn6lKhGuKEYUTUehAkMrlzF0ZZ6jvuPZmJp66TEdKSfVOYzXrU0IJHy12A
         +JywG4U12KFJFw1nwD+nKeqFziNBWpwEobmtwan7+bqW6UdLO1dV52jUbDcB0ts98OoZ
         JNww==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758479181; x=1759083981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ioBr6/1uH1Q/K3M/i7hQXQOwxzCFnSe5d8dL4VooeRY=;
        b=TvOzvnSMgCcyHFuooybVril3qrpFfLOYWmsQ80C6iqa9qS9n7JjwUhbhZVj9e8XIq6
         lRPG1nDcksQq6zhSzNwxBM8HeKVXED4ijN76xXmE86zi87nqLRhhzr4MRdMNrpWMeJZA
         t/BZ8x48aUupBbojaxbyIDPVAzuy52ZTc3MBZS3kGUmrcsi3zoT9tdXoxLanWpmjxt81
         iWEa1oY7cl9doGSIbBAMUMTIjhSANADJCEIMB2WKthuPNWUUUHURQxs9sN6Afu++99sO
         4W89Hb7DXixEVSaLivZncFWEzoUvOPjK6DbIJLg7WH9ZK+hM4uW50BsLclXNq9El+IEM
         BBOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758479181; x=1759083981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ioBr6/1uH1Q/K3M/i7hQXQOwxzCFnSe5d8dL4VooeRY=;
        b=OHzcLcN3fpvl9eQZVsGBpdch6wGCSHNuJdeFAv6+DpC4ECVSc6KX+ypotd7j5J2xM8
         DBwSPeAtzpC66iUuTyPnqISuuDbr57nisjeTLwUPg6r9H+MLomMc8Bpp6YH7bTo9TXce
         lsZvEDnRDzPKFnCq5MipfS/Yh2rbfCgXBLLjUgnTfbnoQoSSPZIMjxb9iYQgUDTnH3R4
         CXdLiG23PPJcbiZMruM2v7UfTFYK+RuEnY2aBY8nr74KgWvsPyI4LYzlSoKXcQTMcWiR
         kf31n3biFkL5IfB5Oa9ILO+6qRZin9SlcJRNz7YAb5nVQftx+L2JOGizmedvDJNaP7zj
         kPow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/7SfJ8vP+VEeCdIJKSkuiq9sWuFzxjs7Efbq2E/UUDwYXSl9SXP7D2keSxg+eaHuj4Z7qCw==@lfdr.de
X-Gm-Message-State: AOJu0Yx5M+4JM4qReDoDWBP/dtJDxbSyTjDPM84S/LGsEaL2GGu1S1Le
	E7iSNBaUFufxvpCTrn7o6035FYdhpRmeEVEFnwNSM+VfX102M83QGyOT
X-Google-Smtp-Source: AGHT+IHDzSemSNtR9f/Uyxmi/Ip/vkmuv3Nu/A1Cn0PrjaeM2B+LIi2VbGXF9NOR5H9ZqZpI3YxJ9w==
X-Received: by 2002:a05:6512:12c6:b0:572:f47:d10e with SMTP id 2adb3069b0e04-579df8cede4mr3411120e87.3.1758479180654;
        Sun, 21 Sep 2025 11:26:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd71t/a5V7wGSnniZQ01j6nNfo8YkTz+2WA6XQJPuM4QTg==
Received: by 2002:a05:6512:3e3:b0:55f:48d5:14b3 with SMTP id
 2adb3069b0e04-578caac3307ls884438e87.2.-pod-prod-05-eu; Sun, 21 Sep 2025
 11:26:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9cm6A7VN7I93wZ888X2F+1kJ9RbA+2GXG3V19sdnF/gz8Mhf0O5K/+UyN1Z+Ho00BICrjQ1zKXBo=@googlegroups.com
X-Received: by 2002:a05:6512:a89:b0:56f:d5f6:fdfe with SMTP id 2adb3069b0e04-579e03c153bmr3281102e87.23.1758479176964;
        Sun, 21 Sep 2025 11:26:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758479176; cv=none;
        d=google.com; s=arc-20240605;
        b=MGk/IIigeY1FMLysxMaNp5XzzFG41vso6P+x5D3ao8c0zSbNA0VRA98X08O0O1wHGs
         ApFC3TP4igkDzX5jy9aD+LRmeYaPw5JQmTcH/qPX1Jjys85vpob2iiAP8ba2HygFzLPI
         qT1m7dZMCTpZIgufcOUgPabpWkcezI0jnoAV47AC+SbBlOdHqAD9q5KMcGzndMiYqhJq
         Rcz76xYkR7Cc9/caDbZ+zprPMUcv7MvtGmXNavcwKUBQvzbONqeOQmgXulCpAtBitmSM
         i4DNCFzRM0nZVeB4bwUCo7rPHhBzi3Ia71PUGtAsau0gPP4MrkQ6hFqutv+JvKim/NLR
         5+AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=F4zmkAHPjhKHpB7D8+DDrYGAR3U5WXK9thJ0sK89yEc=;
        fh=5xnbGjrm02/E1z8cSNwLBdYsrCBPNc1lvdWc34kJIKU=;
        b=aKBtzdhZKYFiS/aCNmWxmFaNug6GOQxPmG+3EiojJ90HFilXGPNUfrND+7mj88Ro2q
         7RSqCZUBwwRBdupXhfbIfF+UF3Z6jm91NF2zMZA+PvTTuDvdKQcmGoB71Z62K6S9PAQ7
         qr5PF+3x0ScjPl9xU9NkXRBB2X2wXVMWv1rwaky2yHLM3P/1xtzOujjnKO09zU6CRqGy
         7OBMWqjilp7R9HPJjwAlPMJvkOWemZpo5AfBzt3b+PcAaBMOsBUMeRpX7SLjBeKHbKOZ
         2eAdwbkX0swTT2lLwhl5FjnkND4lVrJzHB8ARvmqpjBICyeKfLcK4bfqrBKCRLC4wO95
         OY8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FmnE4Mb0;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-57aa85bd5d3si149622e87.4.2025.09.21.11.26.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Sep 2025 11:26:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id a640c23a62f3a-b0787fdb137so553039566b.0
        for <kasan-dev@googlegroups.com>; Sun, 21 Sep 2025 11:26:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWB0OPti8ibvnmWagl216Hmig4EIhJxIcgeCbvISrKa5iejvIEK9xSt6S2XCFwVOPX92n5UkbjCSUk=@googlegroups.com
X-Gm-Gg: ASbGnctHMQdXaEFnjQjIdACKz36ShYR47kk6LtnhWAelmjXm1FI/dHWW/2XSkD0XiBg
	VCVocZs5I6hbCG7ySZ435ddIzEDvMobF/tTB6GX9dSnVnWORnkaPSo5IjcRRCPUh4ycwrXjRcs0
	489SyFqpUez7MjFjT4KFnwzx8SkOtI1x6XHNyY/aZU7vo3PYBa7tJ0a1afhTR3Eh3Ray0OeVN1U
	YW8OBg=
X-Received: by 2002:a17:906:c155:b0:b04:6fc2:ebb9 with SMTP id
 a640c23a62f3a-b24f442d968mr1064293266b.45.1758479176060; Sun, 21 Sep 2025
 11:26:16 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
 <20250919145750.3448393-9-ethan.w.s.graham@gmail.com> <CAHp75VdyZudJkskL0E9DEzYXgFeUwCBEwXEVUMuKSx0R9NUxmQ@mail.gmail.com>
 <CAG_fn=XTcPrsgxg+MpFqnj9t2OoYa=SF1ts8odHFaMqD+YpZ_w@mail.gmail.com> <aM6ibO75IidHOO3m@wunner.de>
In-Reply-To: <aM6ibO75IidHOO3m@wunner.de>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Sun, 21 Sep 2025 21:25:39 +0300
X-Gm-Features: AS18NWCeZeZJHwiXQSoRlyelBxs_br4n2Gp5Ptss7c3DoCLdwMlYv5AhZy2eILA
Message-ID: <CAHp75VeyCujEX3dFBVF=ioHOqPbWQRtuB7_zFGndAejYbMW05w@mail.gmail.com>
Subject: Re: [PATCH v2 08/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Lukas Wunner <lukas@wunner.de>
Cc: Alexander Potapenko <glider@google.com>, Ethan Graham <ethan.w.s.graham@gmail.com>, 
	ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, rmoar@google.com, shuah@kernel.org, sj@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FmnE4Mb0;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Sat, Sep 20, 2025 at 3:47=E2=80=AFPM Lukas Wunner <lukas@wunner.de> wrot=
e:
> On Sat, Sep 20, 2025 at 02:08:01PM +0200, Alexander Potapenko wrote:
> > On Sat, Sep 20, 2025 at 12:54 PM Andy Shevchenko <andy.shevchenko@gmail=
.com> wrote:
> > > On Fri, Sep 19, 2025 at 5:58 PM Ethan Graham <ethan.w.s.graham@gmail.=
com> wrote:

...

> > > > +/*
> > > > + * When CONFIG_KFUZZTEST is enabled, we include this _kfuzz.c file=
 to ensure
> > > > + * that KFuzzTest targets are built.
> > > > + */
> > > > +#ifdef CONFIG_KFUZZTEST
> > > > +#include "tests/charlcd_kfuzz.c"
> > > > +#endif /* CONFIG_KFUZZTEST */
> > >
> > > No, NAK. We don't want to see these in each and every module. Please,
> > > make sure that nothing, except maybe Kconfig, is modified in this
> > > folder (yet, you may add a _separate_ test module, as you already hav=
e
> > > done in this patch).
> >
> > This is one of the cases in which we can't go without changing the
> > original code, because parse_xy() is a static function.
> > Including the test into the source is not the only option, we could as
> > well make the function visible unconditionally, or introduce a macro
> > similar to VISIBLE_IF_KUNIT.
> > Do you prefer any of those?
>
> Just add something like this to drivers/auxdisplay/Makefile:
>
> ifeq ($(CONFIG_KFUZZTEST),y)
> CFLAGS_charlcd.o :=3D -include $(src)/tests/charlcd_kfuzz.c
> endif
>
> Alternatively, if the file in tests/ always has the same name
> as the source file but with "_kfuzz.c" suffix, consider amending
> scripts/Makefile.build to always include the "_kfuzz.c" file
> if it exists and CONFIG_KFUZZTEST=3Dy, thus avoiding the need
> to amend all the individual Makefiles in the tree.

Thanks, Lukas, for the ideas. Yes, something like this would be acceptable.

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AHp75VeyCujEX3dFBVF%3DioHOqPbWQRtuB7_zFGndAejYbMW05w%40mail.gmail.com.
