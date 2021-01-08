Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6574H7QKGQE5XYWRYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A15B2EF326
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 14:37:01 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d84sf3822364pfd.21
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 05:37:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610113020; cv=pass;
        d=google.com; s=arc-20160816;
        b=EtMh+m12JIB3PKDtN29ePezgr8GcSQ6ywZnh9ebx284ARDfBRaiMK9oUTVVbXgXnKn
         OCCX6DGmMYJqIzm+THJmRQKuwfd81z1a74WiNHn9iASHD64OW3FkCWz7k2dd4GLoU5nu
         SDpLCU61cGkNVbCczh7O9jbGTtnPVmrWNZOsBJ+y8ruuCosqk45Qh+kmlUm7vna6AVqF
         pwQ++VFxEmQoo2WyKXeZ2Aqo32Y9qex+ljNIgxVE6oC1Nzhs5kpgPJSKhCjzYKaR51D3
         zt+eZSWit0isLYqFoTkOh810hg4owa3gsqBgwOmpSWed+PpT7ixf3Tc60oKfGeJevKfg
         cuXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vxbM5GWZyLXyJ/+NHwuPtPHvbCh0YUidSHeetc5EEeI=;
        b=sxEIeM8ZHwdz7XqZhCiHSnAbtNzMoB5qLgO9fKZX0gvAPgV9k3hAUs10RFrSxoSGv6
         8DQZgRh2XVW0MkWZ/0AkYxlmyPT8TYDbohRVaxn1m439jxnjd60BqExkZTTSpRCxF8iq
         9O2FeED8iQBHC5M5MtybUYM2gYQg7Pfy5Sdk9Uh16JwJvuftOYueq8O0K6EBrf8gBZXk
         2KbomDq/aVu0mKQaSEApKyPlkEzUNaVzMFfGAiS35J9kpcfznaGBHq3S5hpSFHlzbbkk
         8GBjFZ6jiI+IPEJlSfFl2dZw2EzVTrXNsaROJyhImgzlegFPnePMd0ygMrdInSz0OHgg
         CiUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SLY+Qxdr;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vxbM5GWZyLXyJ/+NHwuPtPHvbCh0YUidSHeetc5EEeI=;
        b=lDfeeMxtZLWSZ+bEeOFIOREAvS1Qo5gXnyxVu3ZFF2s+hV3/PMI687tIJXEAPrSW8a
         c1+k6HflvEoNDaZAbQl/6GBc0EslBwssiwdi+53M6Hh3WCa9/wsKMO/C5ABF0I2kdTfs
         D1S54QmRhgHCvyMXZO69bQwBHi9meHAyao9SUrqjRnNjt/sCbKYPGKR2Uyv5LM+jsyza
         wBIBQXBn7tstwnR8IFdRvl6cXCDgLZOrE5gBwPo46DgAkk9FlUt0nPu0SNZCtYzBkv5j
         wJzYAZeDcucCFDB2HC0PfPlsrOtBtn/xfd9YNh1MG7gsPpUNun6l/VuUiU7QBPSCu0kg
         oP4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vxbM5GWZyLXyJ/+NHwuPtPHvbCh0YUidSHeetc5EEeI=;
        b=KBH5GogDVyS68RwuHahNM5DAYpUaOJ1Blrgb/FpThvqi7RIfzCjdPkrz0iCpm9dqSY
         Yztzj46X2qq2jf92FZ4Z/k66zxz4ehvErgHvow4zScp9thcS0Tj3wwOMiJ4RXUNHpM2/
         B8Ql4LUaK0o4bpb0KJ2JuHV/PkYVeVDeNFAu9cTsz3yUNE8VOtiL+02JYTa2zld0gDnG
         a+EBiJ2IQVtSwKptt7Ylv3csnY01490LfNhDg8I2BPHKYuW45Uvnxi2tU2wripjnwe1D
         xnvhoU3Lccnga3aqDN+t//h6S9Vbaw1PXAdZ2K/O2C524orMz3OmDvBrEycQVxI2qGcE
         mLpg==
X-Gm-Message-State: AOAM530LIjKJd8Z61t840g8DL2lQwiAjqEv2UCka738lZGojESmKrmdZ
	mcwlz9YznCRwg01J2/zuUpY=
X-Google-Smtp-Source: ABdhPJz1chcZEMv5NVXzyuKSvvdIYNU+Nbd9081TWYeZqVhtWKPNiKKdPWJaqwIh04E17W4ZORQCBg==
X-Received: by 2002:a65:6713:: with SMTP id u19mr7068525pgf.364.1610113019971;
        Fri, 08 Jan 2021 05:36:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab83:: with SMTP id f3ls4867900plr.9.gmail; Fri, 08
 Jan 2021 05:36:59 -0800 (PST)
X-Received: by 2002:a17:902:eb54:b029:da:29d7:cffd with SMTP id i20-20020a170902eb54b02900da29d7cffdmr3915372pli.28.1610113019414;
        Fri, 08 Jan 2021 05:36:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610113019; cv=none;
        d=google.com; s=arc-20160816;
        b=WrRDzKPW5lJ8UYFn4cmSMBPHW8trJ5V4XISfxDs5ktVisgkstU9SdlLjk74Urk/C+J
         7HI2UeVNZYnwHAHLEDbOgqiKYCOsjht8SAUNY39KA5hU40pHzNDiEj+hq3Imnz1hc5TL
         /bikLTuDrGuRXaoI7z15knfLP3/MPbg71bfmy9n6qEWUufqq986fMcRSrSvxQ1H7K3M4
         B6HlA+wcPexUKBHoPppp8/08wtvecdLpJAwm3mmqHbPn/YY0+UeVgniPZVOMrBB65j0E
         N4Da/VBuUV3vpHoOOBR2EBmtiOy+au1CAiPDeyURImhR2nKN6Ywo7L9VD8S1lPG1qIXO
         93BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2H4NRUpssxmHvO//onxHk/0LPtfW86OVu0j9eYubnLc=;
        b=ZRe6WrpjkpZ74+oqiN6C7hDGWI6fnR5J7IZKBpOukhiBsPGwG8C7dq+vN7L0CgnImw
         9YmMBC6AYTya6yWDKMhAIO9rU+vSdHG14mQuLe8qmpXrOxs9rQyZCoApMJU/Evw1J8gw
         QnlouWc4ZiymyxM72gXNnjhQw3n3MyWWm52XM3IMbQVEJ5nj06JfOf7QNUzkD0Ql6wim
         FnuITWG7uq9QEnD18yE3RvNxCD9e45S1nnMFmS1azYOnvg0wvzhQhZSf9Q2MTTgUCZNh
         Gtl82q362GOZWV4p/Wxl0O8GqvuhgV6o1DaxrQoTTbvj+C2F6nM6/yjNzi1i8TC5QOqn
         eqIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SLY+Qxdr;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id ne6si539791pjb.1.2021.01.08.05.36.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Jan 2021 05:36:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id u4so4456975pjn.4
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 05:36:59 -0800 (PST)
X-Received: by 2002:a17:902:9009:b029:dc:52a6:575 with SMTP id
 a9-20020a1709029009b02900dc52a60575mr3718033plp.57.1610113018926; Fri, 08 Jan
 2021 05:36:58 -0800 (PST)
MIME-Version: 1.0
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
 <20210106115519.32222-3-vincenzo.frascino@arm.com> <CAAeHK+xuGRzkLdrfGZVo-RVfkH31qUrNdBaPd4k5ffMKHWGfTQ@mail.gmail.com>
 <c4f04127-a682-d809-1dad-5ee1f51d3e0a@arm.com> <CAAeHK+xBrCX1Ly0RU-=ySEU8SsyyRkMdOYrN52ONc4DeRJA5eg@mail.gmail.com>
 <c3efaa8d-cb3a-0c2a-457e-bfba60551d80@arm.com>
In-Reply-To: <c3efaa8d-cb3a-0c2a-457e-bfba60551d80@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Jan 2021 14:36:47 +0100
Message-ID: <CAAeHK+zjwr0M92zqUjseJmRmhHb=4GjevEft-mahfx5DOkq==w@mail.gmail.com>
Subject: Re: [PATCH 2/4] arm64: mte: Add asynchronous mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SLY+Qxdr;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032
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

On Fri, Jan 8, 2021 at 11:44 AM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 1/7/21 7:18 PM, Andrey Konovalov wrote:
> >> Boolean arguments are generally bad for legibility, hence I tend to avoid them.
> >> In this case exposing the constants does not seem a big issue especially because
> >> the only user of this code is "KASAN_HW_TAGS" and definitely improves its
> >> legibility hence I would prefer to keep it as is.
> >
> > I don't like that this spills KASAN internals to the arm64 code.
>
> Could you please elaborate a bit more on this?
>
> If I understand it correctly these enumerations I exposed are the direct
> representation of a kernel command line parameter which, according to me, should
> not be considered an internal interface.
> Seems that in general the kernel subsystems expose the interface for the
> architectures to consume which is the same design pattern I followed in this case.

It's fine from the point of view of kernel interfaces and such, but
not from a higher-level design perspective.

I think the best way to approach the KASAN-MTE architecture is: 1.
arm64 code provides API to enable, disable and otherwise work with
MTE, and 2. KASAN builds on top of this API to implement the logic of
the bug detector, including which APIs to use. Part #2 includes making
the decisions about which mode - sync or async - to use and when. And
that mode is chosen by KASAN code based on the command line configs.

With your current approach, the active decision about enabling
sync/async is made by the arm64 code, and that doesn't fit within this
architecture. But having a decisionless arm64 API to choose the MTE
mode and using it from KASAN code would fit.

> > Let's add another enum with two values and pass it as an argument then.
> > Something like:
> >
> > enum mte_mode {
> >   ARM_MTE_SYNC,
> >   ARM_MTE_ASYNC
> > }
>
> I had something similar at the beginning of the development but I ended up in a
> situation in which the generic kasan code had to know about "enum mte_mode",
> hence I preferred to keep kasan agnostic to the hw implementation details.
>
> What do you think?

Perhaps we could add a generic arch-agnostic enum to
include/linux/kasan.h and use it in both arm64 and KASAN code?

enum kasan_hw_tags_mode {
  KASAN_HW_TAGS_SYNC,
  KASAN_HW_TAGS_ASYNC
}

Assuming other architectures that support memory tagging will end up
with sync/async mode separation as well, this should work. But even if
that doesn't happen, this interface can be adjusted later.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bzjwr0M92zqUjseJmRmhHb%3D4GjevEft-mahfx5DOkq%3D%3Dw%40mail.gmail.com.
