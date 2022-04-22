Return-Path: <kasan-dev+bncBDW2JDUY5AORBLFGROJQMGQEO2EG7HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 309CD50BC9E
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 18:09:18 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d6-20020aa78686000000b0050adc2b200csf3785114pfo.21
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 09:09:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650643756; cv=pass;
        d=google.com; s=arc-20160816;
        b=nfzCW3sBbID2j0ZjXL8PiMyiFZcH2+uEDCh/TutHb/W+CfTh+fq6HFisXHvNBvwhWO
         k1GUdB1IfQ+wfr0Sgv0EZ6xJ4lNiGq2/obfkwUQSbXh7paclyklIlgSoUAJAPKq2wnr+
         n4HKd2ThNWBf1F1wQofS6SizO2T7Mi+0sy2dw47NDBihF5eDH0T0ppI0YDEnVUWPjUP4
         wPjtKFKgzoFI0113ux6R1BRXfxfx8Ui/+T2nJ5+0E/OEx8FlWxjA/26OwWvQw2wj/w8q
         hZepiD5Jjwjm1s4mUp9jjWSUrbAtT/8MskPoTq0T2hFTfZJOt8rE3nUhr+cXlomAmIoS
         YWqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=MUHjDneOGjozaVa5CUD/tuFbJS5WMaLBEZgNPVRtUg4=;
        b=OkyQ5vRYg3JRGsmk/2NONPAb7SmNkp51y2r/K8yr9YG6cA0shoSYKJmDR7dbmQTFBn
         hFvpYVLywhF0PQYN06263Loh/CHgjRfQncF2d0QeE+wwW5Ys5qPM6Ic+Y9Bl2CUMkMXY
         uFOZm3SS7lxfMp8hJRYJduxv5PYzNwbrEdjmIAbqkHnFvFLqFsb5gxr+vWZQikgMn7lL
         PBX0V7yFKBnQ2pjqJgbu9S+CuPlP9ub5c8o5rwa+7qJzKxWrqJZxmzuPIPVxdyB9N7+n
         sX4IIpnnqPfrhg37fC2Uc8a5qz54d0sJl7mma+8E91PzsjwyFX0sHt8Ox8kGcRk0FgwR
         COKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oG1haJS5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MUHjDneOGjozaVa5CUD/tuFbJS5WMaLBEZgNPVRtUg4=;
        b=WXFTq/rDIbH1bHbL5ckJuBgcTuCOCzfgChvsYQkFjzldyxVG4eudvLuxxyE6S21OPm
         y1S8JgQwVBSv5EX/+3CrfJ2Pg7/ZpWvdUPocJowYFcnOdyQARqd9v9E5FMj+jqtGNBr4
         sL6IPpWxNC748qhxAA56+1Gf+Hclj7z+4uyaRb+ZDX8/sHBGafW5QBwTfga75WCV+8Qi
         ZJwjKhYyv8DQz2r1DQudIUUvHHn4KJcSpL1aztcBq/0OmQEvS9y5Ia57gGObuB57ApLx
         VewesBreQSvqqIh497togw0o6pF9ezLNHg51UfpnSGNy9dqE16mZaq3blalNYMomxbuD
         Ei7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MUHjDneOGjozaVa5CUD/tuFbJS5WMaLBEZgNPVRtUg4=;
        b=HWMncc+s2T2SF8NJRE6nvR0V+UzLhwA/aerIHQww3j3kSbET551w+qCa8CyL5OdeX2
         gZ24Y7v0ENK6bBvFI7bB5FbRpTvGw0m4RkGdJYZktL/6ziqFKN9urpCeqZ7hiLsfiHw2
         MFevJ6++PiD2pluMjq92XtpfxHULh5fWGHzxVcT4hMDFDCSfffdsdk8GHVOCouOudNe6
         62hJlCQ36dC82tQ37w/ms7NJ6EVL0gWHFiR+ulE/M8K57Nm5q+PhwijU3dP95GKpCxzx
         /Gno2VXS+RtaTbAMO4MWU/Yuqijpl/tu5e7K6g8R/w0yYFWWWsB3mH9hRJpPJOuM98o0
         YcPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MUHjDneOGjozaVa5CUD/tuFbJS5WMaLBEZgNPVRtUg4=;
        b=ONIETHAh/Xy2Im01I79+GR31gZ51IeSNLEaHZmIEmYb6WeP2fG+vKfc5IaJl88jXL5
         NSNWqydHZof3BQAR2AoHgBr6KRlRXsDj/Ynect7X4dvZaaiZFcI/a2z+U/xPtpsEjK5H
         o/tBHks3ARgjL7NB2UjfjJi6UUvFlv9wUMye4F1T908X0BouMU/qFzyyiIADZgnV9d7S
         apuOgvmSaPi5ycUAOEMsBTTWKcQhH90G4ECgX1gnRob/Vrm2PLtG6R0aZKiDuTRHU3Gg
         QSIB0FsX0WJLdEH1Gp9pVth9Tc7fIVounnf+bb8dTZWQdPz4VjT8G+Blwj+2U8GprCDk
         LNjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GdO4SsJgPdN5Vqmocywmc+ep9WYHto8tcyKgnWpIuTWlDjlUM
	G2rYkDFzxCryOqFFYJ2e27g=
X-Google-Smtp-Source: ABdhPJzckAnJ3gOlcyIR104Xs9MdOHCxKaQopSmVvOQF57iG+0atXyWmvv2bjZ+LmgdE/OdyLmkPBw==
X-Received: by 2002:a05:6a00:1903:b0:4fa:fa9e:42e6 with SMTP id y3-20020a056a00190300b004fafa9e42e6mr5699036pfi.1.1650643756794;
        Fri, 22 Apr 2022 09:09:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:ace:b0:505:bb88:8eb0 with SMTP id
 c14-20020a056a000ace00b00505bb888eb0ls218565pfl.10.gmail; Fri, 22 Apr 2022
 09:09:16 -0700 (PDT)
X-Received: by 2002:a65:6093:0:b0:373:9c75:19ec with SMTP id t19-20020a656093000000b003739c7519ecmr4636841pgu.539.1650643756046;
        Fri, 22 Apr 2022 09:09:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650643756; cv=none;
        d=google.com; s=arc-20160816;
        b=pZGx3hWWFxzRrHhge4tnOl0c7XT9utOy9WPQFwx+3HWJj8z9Jw0KADejoNr/V/zoUF
         +bg1VHd5lAe6bPFX6Fkw9AcO3R0d5G0yl8fakkagr0lSvpKBtyCRW52rf9OVNxnt+GeS
         D+hue5D8sI4Wue/m1mktLVEzvrHScJBdU9TZnxIIf6Jfbb3EdiEU+xCHigDEkkkq7CrU
         NYcKw1BSzbtDDmNHJnfpGZuAvRhnOunRSG5RzkQ6weNq7C5Qjoy1DdqToEyqw5jasDr0
         mC2tyxhbtjZAxF/x+hsuKePy/DoFy8AnijkK0Dr+yDva8ou+BhiN8QeF8bdOrREQCr6a
         tK6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7ywngeaPOxck8z+da0Rb5cHl7IWBnc+HuyghQxZLcVk=;
        b=M2P5YCPbwchg2h5NRXYXc1rzqM8bo8s/gPJoJcf6GHRVJJQsUaytoh4INW5a46p1MF
         80uKsn1zjXo/T2/2OYu9y9N35UHbn5CHDezgPZ5A9Io5Hv5AjCVvRFLzr2r/2DieDRno
         3Y27pQbcMt86T+9rQ2YqJPxSLMWI2EOUPr9CHWJVGZ0E+sxaCZ5HxsdLcemvWRvuhJwQ
         U0PC1LZ/M5IEtg8rx2IWWU2jborlCwjqFhOGcmhlrJ1yw07vMaUz4VMxo0m24FrVazRF
         7G8c8wTcy2oVJn5p5IB+cBBQdZWpE4YeGiushbWkJAQK0E3Tjhp+C6rXHkZ4/DftTR/o
         f0ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oG1haJS5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id v6-20020a170902e8c600b00156ad216c72si675153plg.8.2022.04.22.09.09.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 09:09:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id n134so9056340iod.5
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 09:09:16 -0700 (PDT)
X-Received: by 2002:a05:6638:dd3:b0:32a:7bdd:799b with SMTP id
 m19-20020a0566380dd300b0032a7bdd799bmr2474463jaj.117.1650643755556; Fri, 22
 Apr 2022 09:09:15 -0700 (PDT)
MIME-Version: 1.0
References: <20220421031738.3168157-1-pcc@google.com> <YmFORWyMAVacycu5@hyeyoo>
 <CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com> <YmKiDt12Xb/KXX3z@hyeyoo>
In-Reply-To: <YmKiDt12Xb/KXX3z@hyeyoo>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 22 Apr 2022 18:09:04 +0200
Message-ID: <CA+fCnZdTPiH_jeiiHCqdTcUdcJ0qajQ0MvqHWTJ1er7w6ABq5A@mail.gmail.com>
Subject: Re: [PATCH] mm: make minimum slab alignment a runtime property
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Pekka Enberg <penberg@kernel.org>, cl@linux.org, roman.gushchin@linux.dev, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, David Rientjes <rientjes@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Eric Biederman <ebiederm@xmission.com>, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=oG1haJS5;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c
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

On Fri, Apr 22, 2022 at 2:39 PM Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
>
> > > kasan_hw_tags_enabled() is also false when kasan is just not initialized yet.
> > > What about writing a new helper something like kasan_is_disabled()
> > > instead?
> >
> > The decision of whether to enable KASAN is made early, before the slab
> > allocator is initialized (start_kernel -> smp_prepare_boot_cpu ->
> > kasan_init_hw_tags vs start_kernel -> mm_init -> kmem_cache_init). If
> > you think about it, this needs to be the case for KASAN to operate
> > correctly because it influences the behavior of the slab allocator via
> > the kasan_*poison* hooks. So I don't think we can end up calling this
> > function before then.
>
> Sounds not bad. I wanted to make sure the value of arch_slab_minaligned()
> is not changed during its execution.
>
> Just some part of me thought something like this would be more
> intuitive/robust.
>
> if (systems_supports_mte() && kasan_arg != KASAN_ARG_OFF)
>         return MTE_GRANULE_SIZE;
> else
>         return __alignof__(unsigned long long);

Hi Hyeonggon,

We could add and use kasan_hw_rags_requested(), which would return
(systems_supports_mte() && kasan_arg != KASAN_ARG_OFF).

However, I'm not sure we will get a fully static behavior:
systems_supports_mte() also only starts returning proper result at
some point during CPU bring-up if I'm not mistaken.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdTPiH_jeiiHCqdTcUdcJ0qajQ0MvqHWTJ1er7w6ABq5A%40mail.gmail.com.
