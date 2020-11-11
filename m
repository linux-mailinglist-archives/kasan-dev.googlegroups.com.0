Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZXLWD6QKGQEFK3UDWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CCD42AF8A6
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 20:05:12 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id k10sf1937521pfh.17
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 11:05:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605121511; cv=pass;
        d=google.com; s=arc-20160816;
        b=vTLF2EceWUbiVmU5j7oHQJ5TwONvNySqCSm8UHoSsyg9H2ofRPsvW62SahipyU457m
         NodDqQx6DFDzRIcFZ3saX/VcoSI/wp2nhoXDU8CbVOv0sIY5grgM/MJ+43Op/RQQuog+
         oDz1Yl28PqROYGT7azAz0v0IEE54RqfREpEOS5h93WV1y/GXgNm8AgdaLTO6aHwN5UYY
         YUdd1b0xosKCxE9rH7Axh9bH4Ydlhhk/JYmSJmLMK57UAASaVknLgoc/jnudA4INhNSc
         TTGbqe2SVSieCPqBPx2iZwR9WIaLRaAl1ctrFMKMcEEyW4hUD1NOtx8IePNAqJd+dprg
         IV8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6jPvas5WvCFNnmhgDSdHXv6B/5unYGiDbIjYDCtatlU=;
        b=qAwbI6D77iHz4/MBYfX6w9wTMUi54shbfW+VS/Q7rEOpVIf+9okDuRAVP7kxcO58DX
         BoDmOVfd89U7vUdxixuJmsLYhRZmTE2oUMKoQlG4l/20ZeuKsR6xhIPm0oMhrBHmTzbz
         /f8ReTcNyyTPrdMx31UzvEXd/ILZtF7xaV4quRamHs6Sh2ZAyoikhIMfW5zwMCmwKlx9
         4/zM8jF3r9ZaOsr9DJtOCvfq3pxk7+2CpfOMlZa7tHXnuTVPd5En9LOb1irr19qL6iNW
         Em+tZj3Yu0XTdViCI+k1eNX+yUtKbVVjRNiabs9004l90q3FwAaVgPO1yuIoXHoV6irh
         jjvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IHIZ/9tF";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6jPvas5WvCFNnmhgDSdHXv6B/5unYGiDbIjYDCtatlU=;
        b=K+RPl5H03/IKL1HetivlUEr2YnFp1a2yQ/ki15E/srVAn7G2HFP+nXzUmQRFP2soTv
         /gde2BXqztObogGgL1OmmywLHoCSR7ATn74BcBhIjOb4aS0gufOtkkErq1NowzpF6PeN
         WxYMIN57GisFRBgOLmJoba9EdIjgP1EAz8dnA7PR6+zqGq1ol5ClJn3Y1Lt3S3mBq/jd
         ZbvAufXnXUtTBRqlPs8RAybqaUO5EYS5rHOkhY6z3saiJUD2E8338K0poI1j/cuB1A34
         UGOKAiZSH2g3SuVjEka/QwHIR5qycUajeDm3NV0WdzAS7c73kZB8HPoHG/2BFmov4MNL
         WOEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6jPvas5WvCFNnmhgDSdHXv6B/5unYGiDbIjYDCtatlU=;
        b=Z7o8hY7xE53PANDqxCX+VSOScDmbt0LZN4QxWd4WvkZqFdkFG4U8+ZBTK2gwp197dE
         dwJXjBcNnvTtc8IY4zAy8RiGD2GpnlvxoaMC88zmnhBkC1HAUT79wn1ufHUu3nQQd59g
         3fEcdsn6IgLeC8I6eJKdLRzmWOR5kiOAvEZl9ahyLloWdFrTrnnrRMuK+umbs3GD3TIk
         1gRa16SWPHaG6mffF0jpI78fI95n2+g6skqTYULn9fRRj0VCpTmk2PDv4z+HWJRFlHWy
         K8lYaVvizGDRNpprD0oVuuhYVBo55Mj3MiJMisVyLnsfQnHXJY0U1AvAbEKvKLDoD+1i
         E+fw==
X-Gm-Message-State: AOAM532rwQN4MVf/gA9YO2OW8CZ7sN85t3orHxX+PfPZaRCqsT1SkPEf
	3lCI/NtyIJAdjlm8Rd/pF4U=
X-Google-Smtp-Source: ABdhPJwMwXdxZSV0opjsMhkHvjHMIQwaRZfA2Q9i+18PYgMaqBrsxUe0oRC3IQjOhss6MNVlmXgY8g==
X-Received: by 2002:a17:90a:e996:: with SMTP id v22mr5534115pjy.170.1605121511002;
        Wed, 11 Nov 2020 11:05:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:223:: with SMTP id 32ls283899plc.1.gmail; Wed, 11
 Nov 2020 11:05:10 -0800 (PST)
X-Received: by 2002:a17:90a:b88e:: with SMTP id o14mr5331909pjr.226.1605121510376;
        Wed, 11 Nov 2020 11:05:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605121510; cv=none;
        d=google.com; s=arc-20160816;
        b=NLm5MYZUmpySmQzkRi4VxdrknWTR+0RRSlNKI0LJdCflnPCc1TJx7dL+WewqNhHHAk
         hxuEQix3ZQIuOGo+6AqLLyRFxdz9knnxkSR2cN6YrgYgWk1zqM+X2c97LkrAKwMmkDKC
         JbGCbCqSOH07SmaYF3n2QRBZkteDRCrj81etiMgVIDls/CUfTHGrh+Zn3BW3NJvv2nu+
         LVO6lTRG3jn0vWgNk8qNFiyRrKqddnkcagrdjSVoZ3l2sx/RklDfI6WwruAlCkkXfnV4
         rEy05J0QTtLWl3/DveVNrsGgMJ2mLacnRRH0F11Qpc9djYMhhjDQTpK7wWTVWkize3PV
         3DZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dqQUt8nF2kgPMW+WfpdEe9JIcv1VB4HVulAU3CTX4MU=;
        b=dQi5/WFALbifJzJ2MqmRf6oHf9rdhZOMGQe8vjisubVst/cFfmKgyK9ordhwTylvWw
         nYEpoHeDPYkIscHAN2fqFLV6VTq0kL5WoUr8EcVBf4WHq8m0z1sHK4GsG4NVNBHC8MqI
         nEKMpLPFkz8sFdqrejHyyTGNb1kTquXxbOA4tm/ZBGF/eEUQQ8hYNcfjebhehmP5FRGk
         n61wFM8BB0GV75JL0nXeer3SIiusSjTGkQIMyy8ZaJUqgUTvFwf6F4OBS1z5In3RRiUX
         iQx0P+dw/dxyXtu0Tx5WZb+S0FzP0OX9HYaLv4CJe1GAFEhdveC52z1K+o4Nqu8pSSVf
         RBAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IHIZ/9tF";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id k24si193224pjq.2.2020.11.11.11.05.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 11:05:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id a15so3169519otf.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 11:05:10 -0800 (PST)
X-Received: by 2002:a9d:65d5:: with SMTP id z21mr17412658oth.251.1605121509540;
 Wed, 11 Nov 2020 11:05:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <85aba371903b749412fac34e44e54c89e5ddae30.1605046192.git.andreyknvl@google.com>
 <CAG_fn=VuM=4axS6ex7_MgCeZ47o+Scon1WuFGStF78T36sHayw@mail.gmail.com> <CAAeHK+xq2tuVYGOPx=_uj08Xwa_1o9Wv-ODrgN3yWXxAgEGV3w@mail.gmail.com>
In-Reply-To: <CAAeHK+xq2tuVYGOPx=_uj08Xwa_1o9Wv-ODrgN3yWXxAgEGV3w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 20:04:58 +0100
Message-ID: <CANpmjNPkUJreN0YRSWB743L-nrJvMObdKXdL_b9pBAK7AaLGVQ@mail.gmail.com>
Subject: Re: [PATCH v9 10/44] kasan: define KASAN_GRANULE_PAGE
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="IHIZ/9tF";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Wed, 11 Nov 2020 at 19:48, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Wed, Nov 11, 2020 at 3:13 PM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
> > > the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN code
> > > to simplify it.
> >
> > What's the physical sense behind KASAN_GRANULE_PAGE? Is it something
> > more than just a product of two constants?
>
> No, just a product.
>
> > The name suggests it might be something page-sized, but in reality it is not.
>
> What name would you prefer?

Is it actually KASAN_GRANULES_PER_SHADOW_PAGE ?   AFAIK we're trying
to calculate the granules that we can fit into a page of shadow
memory.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPkUJreN0YRSWB743L-nrJvMObdKXdL_b9pBAK7AaLGVQ%40mail.gmail.com.
