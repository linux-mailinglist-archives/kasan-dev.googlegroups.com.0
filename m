Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBNP2GAAMGQEQGJZOBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 42D10308CB1
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:44:22 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id o13sf3948278ote.19
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:44:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611945861; cv=pass;
        d=google.com; s=arc-20160816;
        b=SHSEC7AVzuR7XYHpsXhRE/8HWAkVmW2v4RDI2c2shSQ64ZioaL4OSO7mOMO4yrddlD
         MzUR0xmd29xs6pyZRdcMzCBp6w3GVkV0VfeIka22pNwU7r6giwroFD8XPphjZZJRCy8B
         0q8O5bF2o0ZxHFxbbid483omgltc73YwU/ryB64tdzIjZ3OL/IcTlf6NumSKk8kucGwn
         Zk3jLKii+y9J+WF/UxC02gZpqWIw3WHlWSTP0xUbr3ArV2isUFFEtruPhCaHq/JHrA7b
         5r0UU1wfqejGEioqvTC/iOKDqzHdgCvRRu+sMNK7taneux3vT+WAtpX/rzpiRXUD5CW3
         87XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wzE/ltqI+Av10t/rxgjxO5E+YPVLZsR9ScUDRb19FbA=;
        b=0kcl9KGyYRxdaFHrgZlbCn9wbCVgWKosplKFu/C/m91rj4OIZzZkJGwVfKsJ9IyF25
         U1iUPUGqGwQ4eGNMHlEg3hUcCYplM8T5D0Y8v5bSTdoQm3mk2zh6W4BqN56EOeNSMjUz
         0cOE8BJ5RyEhh6GLCLYnnigp6craSnWo86mDPzK6yfSX7CKftjk1tkUUoC5bO1tMA5HQ
         VdSEkD0WLh+Oi3sz8/dTSQP5FxSYejI5Rbw14zzjfSMVYchrYhlP0crmdX3XPE3KeW0Z
         gfbGIOTN48ir6XDMzVPRVwSw8HhLkuR19txvzMBl38PJKQHBbN62e6gVw337krH8kLV2
         V6CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LvbHs1K3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wzE/ltqI+Av10t/rxgjxO5E+YPVLZsR9ScUDRb19FbA=;
        b=aENTropXyls8fIkHzOIrtz3gdpQkMD4dwaegYEKF+WgcX7rtJBtTOONF7Mq6Ab1qXl
         5T471UFPt8UC/B8Xil3abK6ZWPfLCUl6FtXkS858VzvwVwCLv2RDKLASNCsvHFlII6Q0
         U5jdqdbQ8JZWRkD78Z03ifHpypcvAcKDp3tkO/MmxxLYo32C5kyNs3cwfIg7a16gG5VR
         tB1Zf/QPHp8yBvx4E3P+PQagktTQPi4Dt0krGSWPBjto61iVUaEBmpdCnyXTLReynq4w
         EmkmzN7xhZl2U2PztA7jpUmgo7N1uOk5o2hsszuqgWtKkcqSzupd47Qx/8e0C2I8e3Su
         wbAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wzE/ltqI+Av10t/rxgjxO5E+YPVLZsR9ScUDRb19FbA=;
        b=Ld5g6Z6HEdOo3yJQ+Ur1maHYMty3s3XXVIqJzG1xXNC0EzWWfBOCyuOX6dFWyjpbQ1
         RpwYc8rzxFRR4ZmSkOhfwlnjLZhL1DiOP8Wn5y8pwX0+DSj7j2hu0K1TImDG15ASRo+7
         HoaoCCS4Rt59oN/rX6wLoUimAJkCPCvkED4sfwgOEXVBSWzRM9I68mqd+1x12dQLiKTR
         NjSFzBGbykPP1XL8wFBixRsHQRntU5iq9+bzGbwjudWDSwaxqgePNk9z01IODjsY/Bck
         b0RqQPFypOD/hPIGosD6V2VlDaBGyJIoTBRrMy2IZh/Do1hTLKqaaZvbqD5Gb1CO5ILm
         pfPQ==
X-Gm-Message-State: AOAM530sNbufZ1f9MaM+7utsZ8K8CnB/T3cesmSo4o3Q8vl4jGAv/lTl
	NfcPWeo//KpwanSa9ErwEQs=
X-Google-Smtp-Source: ABdhPJwDTc2TluluPB2tsZ89/qzznpexFAQOMA+g0/9qutNtcAFge1/jrcC9lRRkP9dhD4HRC8HMLw==
X-Received: by 2002:aca:54d6:: with SMTP id i205mr3469783oib.130.1611945861177;
        Fri, 29 Jan 2021 10:44:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1309:: with SMTP id e9ls2285321oii.4.gmail; Fri, 29 Jan
 2021 10:44:20 -0800 (PST)
X-Received: by 2002:aca:4854:: with SMTP id v81mr3248501oia.171.1611945860830;
        Fri, 29 Jan 2021 10:44:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611945860; cv=none;
        d=google.com; s=arc-20160816;
        b=Kd6XnHYxUmUfA41rxR/lotsvczR31VadoAimtD34Nx0zRFXYMJ73mFtrq2ZcsBXHaB
         dVakOSe3BJiHLFd3RWCWptLyJ39c1tLypmkAPrj724/ZBDMeD7HnQoggucZCySKfALY3
         f5ffnLff5DH064KOFP19pRFlXIahkTEmjF8LzZ7NRz5YUjmdzh+bWdgeRVoR4zeMEJH5
         dGc01N8Wr09zNM984v8XKhMVRXmtyGAl/2CcX3oSV4lg95Xs4pqx728IZU8TexvC/QWE
         WkgWai9GgTZXpDh1I+oYVidT46CM9iAtBiceizKyLX36HgngKJnVTnKCrpLvD3cpT61t
         5pig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yfdPqJx+KOQg2lShAaFTUWcq3owFmz8E/slr0pFcBmE=;
        b=Dz/pXRVwZyhYkjAVbUyq4SiwbSLEVQ51ixpfJmny/87yeg9xY3st1t4VwVlXTTcb/p
         /s0zaKzIZj8k//yXOzJFKLC8O9MwC9/J8sfgXURV+qxq7ZtTG8rtvX+ga7M46aQ5R/0i
         hdU8FSwAIqrIPvU/4b4daJXlha3DeXLb4XFpBDpPXBbbwVydbfggy4FqioLWL+FBpSRR
         eDwf5lgk96qQQPSnMozq1Wn4Bozivu8loRT894hJgTVmcHM34xVl9SX8S54FS9SDHdbZ
         LX1S6ohkagg9rAVumWpMUYw/Gxaro/ksaeESNapKf1V3NA0V8+zZ5NALzZAPYxpaYwMH
         fj4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LvbHs1K3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id f197si558171oob.2.2021.01.29.10.44.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Jan 2021 10:44:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id e19so6774415pfh.6
        for <kasan-dev@googlegroups.com>; Fri, 29 Jan 2021 10:44:20 -0800 (PST)
X-Received: by 2002:a05:6a00:1:b029:1c1:2d5f:dc16 with SMTP id
 h1-20020a056a000001b02901c12d5fdc16mr5488629pfk.55.1611945860133; Fri, 29 Jan
 2021 10:44:20 -0800 (PST)
MIME-Version: 1.0
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <20210126134603.49759-4-vincenzo.frascino@arm.com> <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
 <e5582f87-2987-a258-350f-1fac61822657@arm.com> <CAAeHK+x5O595yU9q03G8xPvwpU_3Y6bQhW=+09GziOuTPZNVHw@mail.gmail.com>
 <f1ad988d-6385-45e0-d683-048bfca0b9c0@arm.com> <8021dbc4-8745-2430-8d52-6236ae8c47c7@arm.com>
In-Reply-To: <8021dbc4-8745-2430-8d52-6236ae8c47c7@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Jan 2021 19:44:08 +0100
Message-ID: <CAAeHK+wcVMeqct2ime45eXckUpj7uvfuPe801tmRsFdxVLY-Fw@mail.gmail.com>
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Alexander Potapenko <glider@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Will Deacon <will@kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LvbHs1K3;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e
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

On Fri, Jan 29, 2021 at 7:42 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 1/29/21 6:16 PM, Vincenzo Frascino wrote:
> > What I meant is instead of:
> >
> > if (addr) trace_error_report_end(...);
> >
> > you might want to do:
> >
> > if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS)) trace_error_report_end(...);
> >
> > because, could make sense to trace 0 in other cases?
> >
> > I could not find the implementation of trace_error_report_end() hence I am not
> > really sure on what it does.
>
> I figured it out how trace_error_report_end() works.

It's intended for collecting crashes for CONFIG_KASAN_HW_TAGS.

> And in doing that I
> realized that the problem is sync vs async, hence I agree with what you are
> proposing:
>
> if (addr) trace_error_report_end(...);
>
> I will post v10 shortly. If we want to trace the async mode we can improve it in
> -rc1.

Sounds good, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwcVMeqct2ime45eXckUpj7uvfuPe801tmRsFdxVLY-Fw%40mail.gmail.com.
