Return-Path: <kasan-dev+bncBDX4HWEMTEBRB34JT75AKGQEWDNJN4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C79CC254709
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 16:36:32 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id r1sf7753245ybg.4
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 07:36:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598538992; cv=pass;
        d=google.com; s=arc-20160816;
        b=btQWlpnDpQj3nnkYX92qypeGymNaZ9ixg32XzbRgwAb24KBlJd4oTCoiLHwaNc0OZ3
         7+11YYsWmU0jriPWJrtz1Cu/Pu5NzYeR6eClkuDxLkPZttgO3k1UqQAxk9ktc/JMMA8f
         vt2uMlD/+mjlswud0Myms7shXhHAn1nuCFwBvWE2JjNA7qNr6K0fnSzox9MknTBOlCMD
         u22mf0US2vgL/RtHetTAbToteox1KZl/K5NTCNEbY+VH1EKU325RcL5p9YGDOD5S+mmu
         zcSMicTAswhVCQN8aAYFHvCaUp0SnVPezgUlG3FCvzhDFVTLW/Rrhmv4WWr+O2sVXyJI
         wPzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=91XFscEUIH8hqd4KJHWV6461s5Z7hSIzYfM1J3WHvy8=;
        b=dK0SslGFREyt59jBUt522WMsi0cr84jIjioYUVRFF0/V4UdPO6rxLyaiEd/tqBNqYA
         UZo/XPosLIZUS/m3B5L9YU0XFgQ4xAcPCycDnzZPfxXnJhePF5IY/Vvoa+Igcp2zwvYi
         DAFROQP3SX6NACUjI7irfP2sFZouwucvuWkGuAExw4vb+/x6hUtebFhkkvZOEkKixdMJ
         kSRXKhB5d4bQLL+7Lad4n7mDvfXUM6IFyU6PG2jGA9IdQPo+GTrKGzZSep3GSKQVhR/d
         KKHUrga8llmoBrWZaQrBalDjC+UMe0EH5bSxvI210VoHXmVoaGUriz2dwUPpGjWrTi+p
         beyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g5T69mNO;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=91XFscEUIH8hqd4KJHWV6461s5Z7hSIzYfM1J3WHvy8=;
        b=TlUHTHX5YtKFwZMlyfhEfNQPJn567/oQBmzyfgID8O/f0lcQuNJNQpnGzlhQiOdwYd
         2KkAGMK9wUVma8bryP7vHhNYb15rIJYcXc5+oE9qTpC8upJDkKlfhEm6nEehZIFPho38
         yDCsimwRyMcBgYBDtNnnwLV/g/Y6YsLH4KebEt+mV8SP7C9luN1dX/4XPxv+tMnRIhxE
         HyEs6h+rxRUAXUnxBwsD2hwYtja/tz+hd1ZC8BJMwcc5YpAGZz/VYuIx9UnZv9o+3Ppc
         45zG5i5tmp0X5hue1xNzwIjQYAZcIXotIcGwXMsD/KYwUsOCCkuLxVkaGz7z6pvglHYH
         HdTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=91XFscEUIH8hqd4KJHWV6461s5Z7hSIzYfM1J3WHvy8=;
        b=i1wTX7wpjYmIkmFEkr5F4fiIVIklfMhH72xmh2jVEEUC2YwpGOD71OnMWctV8I656Q
         77oJc9qqvnbOkj8Qy+aqV6TzqIMkn3k2WB4ZAqDgf6SSFCWUBX7QmnXX016BU1d+wKT3
         nhRzj3KwuBnvM3tgLfb9FRSLOb36j7QpOBHOjKsuXEZDj0AIjCR7/ja2dsCJAD+W0l71
         1VE+huf7IyjyJ3iajDY8gAAgIK7ERB2pVOcetnI/0M6Sa48Dq4ElGgS6UKzCBW/7ym5C
         XDC3dC5+z86L6hR1a83QAGCRJe2ruDl0D4lfJf6FTeE23FV3xakt7tP46yH5duHl3FjR
         k2tg==
X-Gm-Message-State: AOAM533+cr7irUeXX8nXld/wCsK8XqbXelPTj7f3A+1u3V62q7cc3+jb
	9tOIpIK+WhnIVOkcEVRrAPI=
X-Google-Smtp-Source: ABdhPJxVVEbarkVCEvU28zQn6aVC23AjtgGgwBF55vjFJ6kitFUM6TpjLGbd0nApYeiQgh4HuVM48A==
X-Received: by 2002:a25:2006:: with SMTP id g6mr32885578ybg.143.1598538991854;
        Thu, 27 Aug 2020 07:36:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d451:: with SMTP id m78ls1075476ybf.1.gmail; Thu, 27 Aug
 2020 07:36:31 -0700 (PDT)
X-Received: by 2002:a25:4684:: with SMTP id t126mr3815061yba.515.1598538991462;
        Thu, 27 Aug 2020 07:36:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598538991; cv=none;
        d=google.com; s=arc-20160816;
        b=Muux2DouQK+jdb4kwxdk6VV60uLIkgK4dE0t5i1z1kConniVivFVtPhAlrd1/JaVV6
         ddgRqLqbsYYspyPs1kicu3UCTIqaCI8bZLT3ptIeTMwCFAHXymH84CYA7reTgTFB9qMb
         z+k8uf5WgPEWK43fR4EqlU2O2FaWWyAu6mHysuwUK7RwswXggklSGNpr7BFYqgcWaqL7
         ZqTu1evyNnFd0RD/lrC3hinr0DYwoevYPjubUS8CCfY4XTwsJdKCepNZSLD2VpXjLYXg
         BacByjuY4cfcHQVWZsFM+Ejxce+UPMOXZIkaOilKK87Mp03egM1CGvxByUgfZNUeu/mh
         gFnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ESqQJ3ododn8j9sB4yCnSFUyTmI5ABpQzOrhit8Rb1k=;
        b=o6IJvvqwZlcYcDMrFCuQ/S2yHPJQNqUj/b0u/33MRRqZmZvsZYI0hDvhwTtsmZ0cU3
         UsQZfrDRQWBe8AsVoyl0EI1AJ1FCBAXlBzT5QcvE7w6G6P6QG87MXo8j/xUrNXJY00s4
         DV/fDknF+EJ1GZDsCsUWlUdA/SuRHn6nHYCfdOWQxNMm2Xu7NOsXE5d3oZjVLVTPMMxz
         wFA2NuCIe0PzceX4Zqpj3NX5cHqS7Ev6zNZuctiPnNPF9ItqTTmXd69/HAelnN/Mn2aN
         Euwocx81CCjxV2MLbQFfjmt11LymniCS+XlgqSx75F01jIVvrofEr1vP73ruK0ngkcE9
         l6uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g5T69mNO;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id m193si187550ybf.1.2020.08.27.07.36.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 07:36:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id h12so3506574pgm.7
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 07:36:31 -0700 (PDT)
X-Received: by 2002:a62:2bcc:: with SMTP id r195mr8138438pfr.123.1598538990077;
 Thu, 27 Aug 2020 07:36:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia> <9c53dfaa-119e-b12e-1a91-1f67f4aef503@arm.com>
 <20200827111344.GK29264@gaia> <d6695105-0484-2013-1012-fa977644e8ad@arm.com>
 <CAAeHK+wGKjYX6eLztiwQA2iObjibHPKt3A4oU0zpXPKk-4qdOw@mail.gmail.com> <30b90e66-2ac0-82b3-b590-5a2b35fad446@arm.com>
In-Reply-To: <30b90e66-2ac0-82b3-b590-5a2b35fad446@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 16:36:19 +0200
Message-ID: <CAAeHK+ws8H=Ba7Q2J-UiaweK1KuKYMQA17RD3U3CO7b5FvMx2g@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=g5T69mNO;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
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

On Thu, Aug 27, 2020 at 3:42 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 8/27/20 1:43 PM, Andrey Konovalov wrote:
> > On Thu, Aug 27, 2020 at 1:15 PM Vincenzo Frascino
> > <vincenzo.frascino@arm.com> wrote:
> >>
> >>
> >>
> >> On 8/27/20 12:13 PM, Catalin Marinas wrote:
> >>> On Thu, Aug 27, 2020 at 12:05:55PM +0100, Vincenzo Frascino wrote:
> >>>> On 8/27/20 11:40 AM, Catalin Marinas wrote:
> >>>>> On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
> >>>>>> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> >>>>>> index 152d74f2cc9c..6880ddaa5144 100644
> >>>>>> --- a/arch/arm64/mm/proc.S
> >>>>>> +++ b/arch/arm64/mm/proc.S
> >>>>>> @@ -38,7 +38,7 @@
> >>>>>>  /* PTWs cacheable, inner/outer WBWA */
> >>>>>>  #define TCR_CACHE_FLAGS   TCR_IRGN_WBWA | TCR_ORGN_WBWA
> >>>>>>
> >>>>>> -#ifdef CONFIG_KASAN_SW_TAGS
> >>>>>> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> >>>>>>  #define TCR_KASAN_FLAGS TCR_TBI1
> >>>>>>  #else
> >>>>>>  #define TCR_KASAN_FLAGS 0
> >>>>>
> >>>>> I prefer to turn TBI1 on only if MTE is present. So on top of the v8
> >>>>> user series, just do this in __cpu_setup.
> >>>>
> >>>> Not sure I understand... Enabling TBI1 only if MTE is present would break
> >>>> KASAN_SW_TAGS which is based on TBI1 but not on MTE.
> >>>
> >>> You keep the KASAN_SW_TAGS as above but for HW_TAGS, only set TBI1 later
> >>> in __cpu_setup().
> >>>
> >>
> >> Ok, sounds good.
> >
> > Sounds good to me too.
> >
> > Vincenzo, could you take care of Catalin's comments on your (arm64)
> > patches, do the rebase onto user mte v8, and share it with me? I'll
> > work on KASAN changes in the meantime, and then integrate everything
> > together for v2.
> >
>
> I am happy to do that. I will be on holiday though from this Saturday till the
> September, 9. After that I will start the rebasing.

Ah, OK. I'll see if I can do the rebase and fix some of Catalin's
comments myself then. I'll let you know the current status once you're
back.

>
> > Perhaps the best way to test only the arm64 part is writing a simple
> > module that causes an MTE fault. (At least that's what I did when I
> > was testing core in-kernel MTE patches separately.) Or reuse this
> > series, all KASAN patches should rebase cleanly on top of the latest
> > mainline.
> >
>
> I can reuse the patches as they are, unless they require changes when I start
> rebasing. In such a case to not duplicate the work I will scale back to use a
> simple module.
>
> --
> Regards,
> Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bws8H%3DBa7Q2J-UiaweK1KuKYMQA17RD3U3CO7b5FvMx2g%40mail.gmail.com.
