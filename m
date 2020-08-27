Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6OUT35AKGQEC4CLBIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D0060254528
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:43:38 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id g185sf1650194vkf.18
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598532218; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZjQL87CdRWU6gEV+gsjYAaia0sCqdmR1be3sMm8wpyoevNvn1WgsjAMz1B9l6uHWax
         /Y3Iw556zpLGfOyculSGwMxU55nGdqO7ldZJ/JAwhbsAV7FmzWQhI49SZwggW/GlyEJP
         LNuZpiP/tYk/jk0ZJzcnNU01W0xlkSoVZcl26p3p+MPw+1hDqcaMD3p1/T3vO5OgBOkJ
         U2P0AGrLN2qphDRoxdSPzlVk7iLNZw+5QGFr/h8fzC5tjwh/kzg9iWnGmIvH+vWIbBps
         YlqY3KSDqUg4i2JGReqsyC/zAcqBaAvMRmMbN/1kMekkwVvU9eiYJukHZ+KEN/Pnv/Xe
         vcRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ThsWX/wbEAvBslDdplcmYbYfwTXcXJX7jkQAisL4bsk=;
        b=pxV+oYXXovsfm6/jS5lq2wyosHuq+eW25Osl0nXXOEFNl3yFMXM+fRT4k6DLYvTtVT
         l9posC2multHwwyLBvNwn6xiv2oB8ztNtbozEF8XYYklSOX/Tq3ueaBaAf0PELGRaxpa
         1mjhGBJOyVosPlLtwOMAOyEhJgKZ2TFtl0Cus4ptRtSgRvfR47MaVjoITug5DXRZpFq9
         yvU0qDDogvVlLlJKR3q0AoqA0xzc8bo1fFAGgkHSOpNOyVFsKua7WEP0ZKQzrHcvrXki
         RDAr30fanOVeXc78bts+s52lFiZ2R6ZYTdkK3nQNiuumSTNyZoTNV3MQDy8/ooAQL4nV
         SaEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UHlALGet;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ThsWX/wbEAvBslDdplcmYbYfwTXcXJX7jkQAisL4bsk=;
        b=M2qFpcjmv6z9C37GaQ2QQAE+Y1Qc/mBWsPc2aVvmCdMng4gCGFObV9nI9+D/5FmJXr
         7gUuJsizTG0REutMSz5olxBXGz4vXL2gW93cnuYXPvt5JUg77K29bdCcO2boIpw7Z8A2
         xLsS5eNgdZwlocW4lIeXPkQDDw1Cn/qm8W3GOk54KEXOJ4Boovr5pNolnbrUD3pnkc/E
         hzrPQc3sIaBdZfPEWX2MyeTUyiBzigPwazleT2IB2kcaOQDqRjXtS9k0kTCSDPLx1TDF
         7Nl5EpjTE7UX2NrxzhrwuOVktOA7K5Q1YFOuOeOTSoX/hS/BrSAvWSo9Wg5E5VOddDJT
         fmIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ThsWX/wbEAvBslDdplcmYbYfwTXcXJX7jkQAisL4bsk=;
        b=O0Am/ZlPy98lo4TlQXWATmhPfE9VDV2ZxqdGVxajcIJjcX2ciPnFbdlZR1uqRLczER
         MmUryjLqZt0HVlmNFvFh0+G/E3u8yuyU8XKqJYh/nwi5rQr1vC/bJ8Teprmy0hDiIgyt
         SFtB5u/247m0LAyIKK5IgNbcqS6QGkk77e5sCdpxIHCsTg48Ue9wNZP5esVTjTB/CVHj
         HS+husrEGakooMuFWWJL0M1wClQzzQNoXdXt9Ymhi/rZnnzWAjo8v3VqUv1Wm064Vdxy
         Sgm7ta6aidNTkwd1u0pA5vEkx7le9X/VTDIAM5jEkC+e/5ZwtcYukLB8zrE6IeSuVo/o
         u1Vw==
X-Gm-Message-State: AOAM53055mVDQWoKdE9B5qbz/K4+RJy2b1umn2H6B5sruwMard/DqtjM
	bF+y6hlanTp1fQYZpsJh9VU=
X-Google-Smtp-Source: ABdhPJwdl2LAezj1Fzc/BcI5vpT0xP62KppcYOw+38SMtK4H1nHQUuVStUnvSFwngVM8DyWHdkxgWw==
X-Received: by 2002:a05:6122:2d1:: with SMTP id k17mr12078772vki.20.1598532217869;
        Thu, 27 Aug 2020 05:43:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2667:: with SMTP id 94ls155328uag.0.gmail; Thu, 27 Aug
 2020 05:43:37 -0700 (PDT)
X-Received: by 2002:ab0:3a2:: with SMTP id 31mr7715214uau.32.1598532217512;
        Thu, 27 Aug 2020 05:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598532217; cv=none;
        d=google.com; s=arc-20160816;
        b=NXV8PXsXKhevKOGZVaIBvoDawJbQZav61Jj3QxlfahkhHu+FYAZ9DnlH0p/8Omx7af
         kDfoGwSkb2sK52YhbjK/NI4e4MtFDQHhzosWA2qcXuwtJp2TWb3MrIWJCkNDpm7+3CPS
         kmWfVTTMEoBE6HxuGPY3E5/2Pdk0qsM5cVF/K+KTUyZvykESwwfz6OjAIGY0HOCamJC1
         coRZ6YmIC/AiFc99CH9WUgDaAaaJGbmpeuWDYjNUJbVdCdI1PbfrVhwpxsayQ7ZoiMes
         MW/9WgAigyylV+xuaLQ6CaMhX3Uyzzcba7Msi+Xct3jvqzx+H2FK67RtlPnl/BKFb6oY
         +7Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tpzREOcIrukXANPEmvrI6Q05nccQGVBf08+JNfkt4Jw=;
        b=lAZsZgwJvB+jkMSmSB3DKvSus0bj7N5OVllwsNpl5bHwdWWjR2jI89w5rWsBVacSkC
         FcCOgBnbH2UuvCzbtAIoVVv3bdj6V4/LozFZNL2sjAESNcbvVZCkUL27Q/dTsLT0rp84
         A3ZYEfz3Da2nTlOlv8OBvIB3xZ1BMqkKFfNyX6snMjp25Kvc/qzUv5TtXXeSbI0zFJFS
         hhgzy0azLsvceXqG8NLhDv/D2lkBz8oynmk00N2OalaY1STM97twfubJSd2q8Kak+Yr2
         Yh68z++R5SzZv9ymDY3l6CQfINtAKqdW1HSxlhu1E3BW0Mpdpw1yOyPHfPbfRmHSM/fU
         LTPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UHlALGet;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id r16si50469vsl.2.2020.08.27.05.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id g33so3275754pgb.4
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 05:43:37 -0700 (PDT)
X-Received: by 2002:a63:4c:: with SMTP id 73mr14624887pga.286.1598532216123;
 Thu, 27 Aug 2020 05:43:36 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia> <9c53dfaa-119e-b12e-1a91-1f67f4aef503@arm.com>
 <20200827111344.GK29264@gaia> <d6695105-0484-2013-1012-fa977644e8ad@arm.com>
In-Reply-To: <d6695105-0484-2013-1012-fa977644e8ad@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 14:43:25 +0200
Message-ID: <CAAeHK+wGKjYX6eLztiwQA2iObjibHPKt3A4oU0zpXPKk-4qdOw@mail.gmail.com>
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UHlALGet;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Thu, Aug 27, 2020 at 1:15 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
>
>
> On 8/27/20 12:13 PM, Catalin Marinas wrote:
> > On Thu, Aug 27, 2020 at 12:05:55PM +0100, Vincenzo Frascino wrote:
> >> On 8/27/20 11:40 AM, Catalin Marinas wrote:
> >>> On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
> >>>> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> >>>> index 152d74f2cc9c..6880ddaa5144 100644
> >>>> --- a/arch/arm64/mm/proc.S
> >>>> +++ b/arch/arm64/mm/proc.S
> >>>> @@ -38,7 +38,7 @@
> >>>>  /* PTWs cacheable, inner/outer WBWA */
> >>>>  #define TCR_CACHE_FLAGS   TCR_IRGN_WBWA | TCR_ORGN_WBWA
> >>>>
> >>>> -#ifdef CONFIG_KASAN_SW_TAGS
> >>>> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> >>>>  #define TCR_KASAN_FLAGS TCR_TBI1
> >>>>  #else
> >>>>  #define TCR_KASAN_FLAGS 0
> >>>
> >>> I prefer to turn TBI1 on only if MTE is present. So on top of the v8
> >>> user series, just do this in __cpu_setup.
> >>
> >> Not sure I understand... Enabling TBI1 only if MTE is present would break
> >> KASAN_SW_TAGS which is based on TBI1 but not on MTE.
> >
> > You keep the KASAN_SW_TAGS as above but for HW_TAGS, only set TBI1 later
> > in __cpu_setup().
> >
>
> Ok, sounds good.

Sounds good to me too.

Vincenzo, could you take care of Catalin's comments on your (arm64)
patches, do the rebase onto user mte v8, and share it with me? I'll
work on KASAN changes in the meantime, and then integrate everything
together for v2.

Perhaps the best way to test only the arm64 part is writing a simple
module that causes an MTE fault. (At least that's what I did when I
was testing core in-kernel MTE patches separately.) Or reuse this
series, all KASAN patches should rebase cleanly on top of the latest
mainline.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwGKjYX6eLztiwQA2iObjibHPKt3A4oU0zpXPKk-4qdOw%40mail.gmail.com.
