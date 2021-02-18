Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHM2XOAQMGQEDUO35DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id CFFDF31F0EF
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 21:25:02 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id a9sf1969599ilm.11
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 12:25:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613679901; cv=pass;
        d=google.com; s=arc-20160816;
        b=i2YkqgocsIEEnEX7liwdN5YhZ8Hky3LZ0n8PThFFjBm8mIYocAEP9aNFNaSI2WMnj5
         zzmRA4XX3ht+859c0aTIwQYMahc9t+LZb8ByV2vw/1ba0mz6DlIcLXFDHX+2IIgNHAV3
         O9psrp75LNW0XyJvHHx9asAYbTMaqMhvNFta7HkqG3P8IUmRjwIWO49BEMaUZWFvLQwl
         NVs5i3Bo2c2IUMj6mGYqqIY5XYOTGoEb04pkXDaBFgxfT+LiJe07YNVY23kyaU2O74GD
         SecHpHL9Dybp9QTxEol8xtflxJlotocAvd1cPeGIg/z075Ml4GpwXnUh13Dp8VBD9QJJ
         RC1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jB+BVfUC+G99ytn6bcYSVKenx8d424bMTERa2oF3Co4=;
        b=LLD1CD6ZtTp5yaW9zeeSJJYd/WEDkTOLSfWdk+jG0ByFCMUEhnHyTNBhqHVnoCqH24
         SQr7geMe7kqePtajS0lKjFqiVyXZAc+OBmdXSKSMoNWimkOUNDsbcRk1GodCOtaf4dvF
         KqpfUsLgHWtlSmVEv5iCy+ZyKSzlf9hb8bLfD2kuOHSsAqjpJZL2VMEK7zCKiulbl2ut
         HpbEjmH/8NeLGfmrEwgYj1juR3VVqL825eGksVsVMjmVw31eI7g8bTBnBqtdmLVhEnDd
         u/X4vKXqK1el//I2khH6YPYXUYcAuGNX8OEEXl9zR3CZpc4wIDkK1S1ml2l/al/7V2n7
         xT7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uVV7VcwG;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jB+BVfUC+G99ytn6bcYSVKenx8d424bMTERa2oF3Co4=;
        b=ed7YnTf8cZCC33wo1M5yGOU51y7YJVDXIC3CBYSpWn+sEWBP7mAgv3GT8IMDNIQb0w
         RGqtL5Lr8579CjSzDMPSc8o4QNOl23JQM3BbDkjSTsISgY1V+oUHpDrSQHPAclTYrGb1
         aC7eFXIxV5ko7m90lQOcWn9QWVlGOxERBk4P9fR+XMRGjBWnOrrT4SVow7lvi45wJzEv
         QFd/WOkqBaGvwfE8JWw1tmgMjLmYW3nDI97ASC2ZVP9gk6OuCmHSDAhPZCCxwQ00InJ4
         J1OYuUm2odGTdppcWFvyePrZ3eTFr8MpdDVY2LwHXFmjU4KxUbYzM/3aDWmnkVr1J1+1
         MJ1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jB+BVfUC+G99ytn6bcYSVKenx8d424bMTERa2oF3Co4=;
        b=pl90LRtKmwjw3K27czCd65EYJ6aGTNDmBVtOM7PhQw+b2AaG4Tl2u5GKdFuqosqGA6
         v8LRwVt8/4RI8IDUitjh/EUZbJwqQxUtmKMaIGdipLv9ZzojGUdpmwdR1LNrg309ywqc
         bgmpinokRnB+3c+CNJopO9JYiOXzRACafhKqJ+t0IvR5iBQuda+4KH1+Rg3YcrV9O83p
         aTQ9poFOqCSbJgyP1svzXvQVSYVijBmrrSFkDFxKlPOXcaMv7NYj+3oXxrhaiwrCEYka
         YihUQNOJ+oMBfXxglt6R931SX+DHMFkvdxHhycET51CmQ0+8wHHR1mOrBG4oPfM4W+ut
         Tqzw==
X-Gm-Message-State: AOAM531xXH72ZZobQdsMgYIqSV1Oysi+GG+w6koypcmlFtqk34A3mPti
	A6d8TzTWZJH91xTEo8Haw6Q=
X-Google-Smtp-Source: ABdhPJy/qBYFjrlljD2AAagwoLtwF4FnpKJ4jPmMTH6RQPN6Tq/URd/MmD4+A7xWS6YgAREtQw1efw==
X-Received: by 2002:a5d:9584:: with SMTP id a4mr737761ioo.183.1613679901724;
        Thu, 18 Feb 2021 12:25:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:860b:: with SMTP id f11ls1217256iol.10.gmail; Thu, 18
 Feb 2021 12:25:01 -0800 (PST)
X-Received: by 2002:a5e:940a:: with SMTP id q10mr835521ioj.66.1613679901281;
        Thu, 18 Feb 2021 12:25:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613679901; cv=none;
        d=google.com; s=arc-20160816;
        b=OONhcNf8oPD17YVQaRoJesK4Wo2lYsHJlc18gTU5ejW1B27/GwwwcvpEbcz+5KRse0
         aSI8XF8+x3YU+8h+hWHIsu7B75E+EVZXvZI54uLV3r/jxrVBFz8zLCliJZdU3PaPJBSV
         Vk4MDOiqX31CLN0a1xbwoLb5b3SnBvgzgU6vurb4Lx9+/v2JwizfhLo+LKjp43+V5ang
         WokBUj/20PBM88AoPmpRfiZmRdNvUH0M845+xuKBLL/cENteN1UIrL0AAWeMvcT/SNPE
         Ta8kuAU4NFOgG5iBRMWUtgkoFaOkSvjE9DMpBw0Ji9glnRj5H4LfIdGC26QSK1RtD6tQ
         I88A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9RsUf6DAvJrxkKF61sw0FoJj/88tOAO5Hu0eokieYoU=;
        b=oAQY2fIGWzNY61fmice/Umq+RLNe9oJq+Hur0/7ZM4bpgR0B5vPt/v0HWRJl/Qau6g
         lMlSXRe2TE/+CgbhmqgNhxJKV/CJOdxOMKTnLD1QlwEqhQ3wQ3BUIc+Fn7KSRVuPm0vL
         MS5VhwbiC8o05CmVt4+V7lHlpbXnrNEFgcjsyYL5n4bmvOWv6bRoCd/YB5Hfwpetgehk
         mmY5Bb7GqATcLKqTSeBKDRrHI23ct9ExwMbRl2cQeJSTl5zTloSpJdmb4CqVoJDexhDa
         zLe74C5pWg/wQyDLXzh2RBwGjBaogaO2RVfOwk1UANvrc/zBl7CMOtLAH7J0WE8+sA7X
         6WJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uVV7VcwG;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id s10si251292ild.2.2021.02.18.12.25.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Feb 2021 12:25:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id y25so2079487pfp.5
        for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 12:25:01 -0800 (PST)
X-Received: by 2002:a63:416:: with SMTP id 22mr5353156pge.286.1613679900548;
 Thu, 18 Feb 2021 12:25:00 -0800 (PST)
MIME-Version: 1.0
References: <8d79640cdab4608c454310881b6c771e856dbd2e.1613595522.git.andreyknvl@google.com>
 <20210218104626.GA12761@arm.com>
In-Reply-To: <20210218104626.GA12761@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Feb 2021 21:24:49 +0100
Message-ID: <CAAeHK+z-Vsuombjed8OYYpFoL4rENpf1J5F3AzQF8+LsqjDHUg@mail.gmail.com>
Subject: Re: [PATCH RESEND] mm, kasan: don't poison boot memory
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	David Hildenbrand <david@redhat.com>, George Kennedy <george.kennedy@oracle.com>, 
	Konrad Rzeszutek Wilk <konrad@darnok.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uVV7VcwG;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f
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

On Thu, Feb 18, 2021 at 11:46 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> The approach looks fine to me. If you don't like the trade-off, I think
> you could still leave the kasan poisoning in if CONFIG_DEBUG_KERNEL.

This won't work, Android enables CONFIG_DEBUG_KERNEL in GKI as it turns out :)

> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>
> Just curious, have you noticed any issue booting a KASAN_SW_TAGS-enabled
> kernel on a system with sufficiently large RAM? Is the boot slow-down
> significant?

When booting KASAN_SW_TAGS in QEMU with 40G there's a noticeable
start-up delay compared to 2G, but it doesn't seem to be caused by
this memblock->page_alloc poisoning, as removing it makes no
noticeable difference.

I also don't see a noticeable "hang" when booting KASAN_SW_TAGS in
FVP, compared to the one I see with KASAN_HW_TAGS. But I do see a
"hang" in QEMU when going from 2G to 40G with KASAN_HW_TAGS.

It seems that doing STG is much more expensive than writing to the
shadow memory.

> For MTE, we could look at optimising the poisoning code for page size to
> use STGM or DC GZVA but I don't think we can make it unnoticeable for
> large systems (especially with DC GZVA, that's like zeroing the whole
> RAM at boot).

https://bugzilla.kernel.org/show_bug.cgi?id=211817

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz-Vsuombjed8OYYpFoL4rENpf1J5F3AzQF8%2BLsqjDHUg%40mail.gmail.com.
