Return-Path: <kasan-dev+bncBDW2JDUY5AORBOWDWWIAMGQEFNIK6ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id BCA784B928F
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 21:42:35 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id cs16-20020ad44c50000000b0042bfd7b5158sf3040642qvb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 12:42:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645044155; cv=pass;
        d=google.com; s=arc-20160816;
        b=jPrUK7OFEtPDLNG+mrxE6fEy7UZKXgBQsLZZFRwxSpNUx1KoXkupBZsNbaZ3JMA2hF
         aak9mKmPKTzRLxZ5myTcVspBxB1cDMAq3W1oGAJcgT9X+Y4KeM3hYe/2ToNfljbvuKuo
         CCLQAd59P1BWN+T4vlsdVAqEXWuIY7o2eWOLVZWll5BQXU5U/vhSAJsCYy8+UQAr/fO6
         TD+ntPDGmLCViLVWoBWa5113XhaSupUrLe41rvRmnDPdjz51S0mtY9iJMYXBOY1xxN3B
         BRgOLZAiwXeO/ZdYKC4XvxsROfZyhHC8yHj2VThEN+94ktbp9RFstB843OKMXCo2KhHs
         x9cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=jnMduSI73Ldkow35SK8FhPGBXLfcDAARNfQujKZyU2c=;
        b=y/ZID4gL1R4K7mEgZ9I5a+iTZYRcPyy8JlJuoW/dGpLCH9AE+DhCuP2Y39V0wL9/Oo
         ZL8YRtliYrp0oGalCeyhJMbNSbTaPuoZ/27ySwXrhuDXKIpPo+9TyArvdAFmlqWYz1/5
         8LXJ0vgUoALJsT3iSWRnKtZu89grM1ywUSUhj2U4tBlSMY0c944ZTD3bNKUaJ5mymaCS
         ymwrYNlhmvUJkkwubMC7kEXW9YPNYPE52PgIxQs4zm1lJU46ZGH2yHFH1TPKsDHB/UKP
         JD5Vr/xM/vHl3zjlwPR8Y5SlW38z36ORm6a39qDcu7VI8lCIYD4yPBzOpTtl7ISSq23D
         00eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=l5ABOM2n;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jnMduSI73Ldkow35SK8FhPGBXLfcDAARNfQujKZyU2c=;
        b=C3LCrUiN+zTqOVm2dZUX/1AuxlzlVDsleuuuIzuB3jVaGvAL5rvp+m+7gW9tkbgpQN
         vQE6nXtJ9Z1ZIlabfuGQqquQu0L6npj8NfFTp8tvSIRQ6rv4U94BbfSxVU3Jw+tsJBOA
         +wfXfl4Q5jsR1sguvRIE7Eh06/xqYzgULgEF95mZA/GIdHoTUFKMnFTdxy3SlNuTJ8u/
         1WsrFHZBEY0Ryg294Om68e1fSOd2WFWROVGuNkRg2IddllkoqOHYLh2qb8IbfWnA7C05
         kMkCyVr6Ph7j3xD9AJUUHBXXy//i0KSEwbQdiOO+mNEyAMhSvwVh7cicPjYadi139t10
         lJMA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jnMduSI73Ldkow35SK8FhPGBXLfcDAARNfQujKZyU2c=;
        b=O3RNqt8FXZTqXctfv3iyEQtFtmsHRc/4t7Dc+3Tz7m9hi+VlRTSikFRUf3MP3x6HUu
         UOvXmuK8yoklda8/8XAkm0CuxCV3smcJjMJ+T2B8rh2wGKouG1nXawvDLIhHFq/MBt7U
         NoctMuIoe0ShVuNv2/atWW14F7ZDt5bEqlZVerkfbJSgp4yVCXhcwgxnxs76nIXz7PtS
         Bpe3GK7dgmvz/qEu+JFyTJ4aIRLaFp4UwFqqnEnZE8unmeegc1bYncBZnQf/9ZH7cMTj
         bMkvUGhlG2sAqTosoY7TR5TDf5XmeTto8u7nCsO9/r/dJ8ev4GbQJzDHtKoURERn050m
         jxSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jnMduSI73Ldkow35SK8FhPGBXLfcDAARNfQujKZyU2c=;
        b=m67DOs0e1eTctljp3VfZAbLTXnoxUPFV0pKKlDIVChps1dbqRrQyIIJXhxJ/Sx/RbM
         XBwk6eDwUub0/6sytRkGhgL8tT3g9xX9EGDtH4kWnXS8I7lpYIo8zpyLT7gCTXYuFH16
         Kz9baq78eLEvADIlvdf9MgnuqniJeBeUg2qUmoytLS622OMpNm+/5lEO9Ty2I6wV8VDk
         6/Uvc3M6gFMK/pGYa980aHSLO0dERzD2flKXHGLXcVtNQfcGhtOgsBltFD6iuDIx03Ty
         AVxJGUfqsnUO9xLbPYQIkCSOwWQh5vIJ2t8rZP/h2ueZo0E3NJDC0uPLec0sjkSLr09U
         QaMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313MNHbZZiILbhoB9NQtdCBzWMAdFQvtM/jfaQxz8dXirAsue7/
	NfB5LQdS1Bosdpi9A64Vut8=
X-Google-Smtp-Source: ABdhPJyT9MxWUNxCAGWoClYGWaAvHfiD7gHc44Et9mVCbEFTfTg9pvrNTUwz2vfzIvjECwM/7xfetQ==
X-Received: by 2002:a05:622a:44c:b0:2dc:901c:4fe3 with SMTP id o12-20020a05622a044c00b002dc901c4fe3mr3357196qtx.496.1645044154844;
        Wed, 16 Feb 2022 12:42:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5012:b0:42d:1bec:319c with SMTP id
 jo18-20020a056214501200b0042d1bec319cls298064qvb.9.gmail; Wed, 16 Feb 2022
 12:42:34 -0800 (PST)
X-Received: by 2002:a0c:f801:0:b0:427:47d3:3715 with SMTP id r1-20020a0cf801000000b0042747d33715mr392225qvn.46.1645044154419;
        Wed, 16 Feb 2022 12:42:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645044154; cv=none;
        d=google.com; s=arc-20160816;
        b=GZCGol/eFfygJSdbriiuHj1zIfFAW8+dpDfKOqQr5ux1PRVBMlJ0x6zyZkzmcvBf4d
         emtkvLVDCRHHvPyrqpZeGIA10gXXwP73DqEu+V62GKPPQhqwivQDuK37QTA+hJHdxi/+
         4a437MNSOInDWn+fyzEmtmC9MIhYkfVsREFJk9WbSiaYCKS3mCvMtFNUdv1McOXqRnDY
         aDQfahSeOPVdpY4bb7ErOIK8RPCciz5zQqLVMAAzTdtYvDb530PBRGGpoLcZRzW76qvs
         kNFAA6PsYYtH/eBnnJA7bgKsjQM5yvNQyeh5Faq4TmFKwKfqZOeMwdAiScqgfqchGLkV
         crrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vkHFJYvYVkKYBcB7iK0KWU7QvRr9ZBff0a6WbJBCpHQ=;
        b=TChMs+U+3DF4gpYWF5QjMBEFeaUCIKDUDi8tNDKYtynzahEoLx8WmYy4cQ7ynW3Nsn
         gq71AAuwQZNj+FGVihXH0odxAgGFXNBdsD+LsLP/XZWGPL8UQmG+2ORfQkSCZqblG4Yr
         pC+2ryNWguruLBK8n6WSbncbWMg2bTmqFSOhADcnOTYYgE5s3N1dtXLMe3Y8+JtvrA67
         MPp0Mz8Ii/esh6mw5CwFsvCiwi9rq502t7m500UtlE2cxsWfsqZXoGrqkKboFlnn4wmE
         yk3g5FnxEXdx25SzjGjdjSr6kgpoUUA8KdzF6CcmseCy6vFpa436xeNTEgSx2VhXUcPP
         PYbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=l5ABOM2n;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id f13si1594036qth.3.2022.02.16.12.42.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 12:42:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id z2so1203818iow.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 12:42:34 -0800 (PST)
X-Received: by 2002:a05:6638:13c5:b0:313:f0f6:2346 with SMTP id
 i5-20020a05663813c500b00313f0f62346mr2833881jaj.218.1645044153997; Wed, 16
 Feb 2022 12:42:33 -0800 (PST)
MIME-Version: 1.0
References: <5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl@google.com>
 <CANpmjNP0QCMhSL+ePf5G8UwbmdjM-qpimAQbuQD+pYK8Gx+2Gw@mail.gmail.com>
In-Reply-To: <CANpmjNP0QCMhSL+ePf5G8UwbmdjM-qpimAQbuQD+pYK8Gx+2Gw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 16 Feb 2022 21:42:23 +0100
Message-ID: <CA+fCnZd0aXZcZaSs7ijUZ+WaD6+s0vPcnp1vLOn2=1dSJQMa8A@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: print virtual mapping info in reports
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=l5ABOM2n;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
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

On Wed, Feb 16, 2022 at 8:31 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 16 Feb 2022 at 20:01, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Print virtual mapping range and its creator in reports affecting virtual
> > mappings.
> >
> > Also get physical page pointer for such mappings, so page information
> > gets printed as well.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > ---
> >
> > Note: no need to merge this patch into any of the KASAN vmalloc patches
> > that are already in mm, better to keep it separate.
> > ---
> >  mm/kasan/report.c | 12 +++++++++++-
> >  1 file changed, 11 insertions(+), 1 deletion(-)
> >
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 137c2c0b09db..8002fb3c417d 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -260,8 +260,18 @@ static void print_address_description(void *addr, u8 tag)
> >                 pr_err(" %pS\n", addr);
> >         }
> >
> > +       if (is_vmalloc_addr(addr)) {
> > +               struct vm_struct *va = find_vm_area(addr);
> > +
> > +               pr_err("The buggy address belongs to the virtual mapping at\n"
> > +                      " [%px, %px) created by:\n"
> > +                      " %pS\n", va->addr, va->addr + va->size, va->caller);
>
> Can you show an example of what this looks like?

[   20.883723] The buggy address belongs to the virtual mapping at
[   20.883723]  [ffff8000081c9000, ffff8000081cb000) created by:
[   20.883723]  vmalloc_oob+0xd8/0x4dc

> It's not showing a stack trace,

No, only a single frame.

> so why not continue the line and just say "... created by: %pS\n"

Putting it on a separate line makes the line lengths looks more balanced.

Also, printing a frame on a separate line is consistent with the rest
of KASAN reporting code.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd0aXZcZaSs7ijUZ%2BWaD6%2Bs0vPcnp1vLOn2%3D1dSJQMa8A%40mail.gmail.com.
