Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWVDWX6QKGQERWOT6FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E9732B083B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 16:16:44 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id w16sf3710573ply.15
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 07:16:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605194202; cv=pass;
        d=google.com; s=arc-20160816;
        b=dVIOxDRu1FrsyBv7ZrnT0PqZvAhmgLW8EkQiHYV6VNVDUIwHHADUca5nMLVHZWXY7W
         togPJX4naJ2YERIXrKAJTTKdTIc3vDa4jtliqiTBGhiUr5dn3pxWnU3hBdTbhhJC90Ls
         0qIK3BHsuAszi4DCv+CSPsHgU0zqmsJWVwT3/ACaUCTst4bpaJJ73nguLJQUFzNRPucH
         cLlfvstzCAoMXJ4a/ZR+P7XLQCNE9x3nSRLBLDNGzVlPXzxpby64mjwCX+kDHdbt1ABE
         gUwLbID/FbTcm3c0FSLA08iS6s9O4JWS8RDfU62NvhvzzUM5IB6Ar73kF7XwK0IhkUFv
         wG1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CSw3ky8PwJaRuRPcaOlAwYPRjtwijDtoi5V1mqLy+WU=;
        b=AAON7ja0AkwtTJ9XFss4poIlkajbEBTJicHG/BVkQruN8XJcBkNNE/2vaU7tDetOpf
         v7XbzZcpoyCMnhchLcVpUdV3CDemInr7OrrPRHII31abLmDnmgzYcm1bYv0LaekWLQ/f
         B2v7Mm2yNPn4elaY2KGXQ5tRL9q841sQYbRolBY5yb1Cf/crJV34wUbOOQzMKQpinLoE
         nEOSnfYs68LGyRAR5Kp95Udnp/r6BVN18gbjGsScjxUGBoyUgoieK82LAsTjkVDeCBz7
         Iwsp2aV02FV16THEw/oIhy7a1m1mDvAuXt+WiqS5eDUq4OaIIRWE0dP6lyMo+uLbOqSn
         ydGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iDTiyouP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CSw3ky8PwJaRuRPcaOlAwYPRjtwijDtoi5V1mqLy+WU=;
        b=LKQ8W5jOCqzmhM2QuLPcz1jUDA3RUSHj9EP2U4iEb5sHy00OcjmeeXY6OooiRtRPEy
         TdBb6FJNaIO2OW1/8+MCCeZyFz26Uj3t+C1CUqzHtwuZ1eE2MXtgoQNYCngtCwl/JZbj
         zqWe7SoSFOw21AcWjSjRtXKRg+ClAI5nO1GGeboq9Kdat/+K+6XROZDFn4c9P6tTFzNe
         ZDG7Vp2GsMEMQnY9rguD32cUoCwxVkESdIxEMcG2lv4gMUtZ2czFv1O9+U7LjKAP3AOc
         XIQkq9puNtff3ly4ucztNvvXIgrE5U0UjNruP+EkMxE64raN4ZYYWxwUPrg+HAinkx/3
         a1nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CSw3ky8PwJaRuRPcaOlAwYPRjtwijDtoi5V1mqLy+WU=;
        b=ZUOOaV7etgbEQlhX+wGMUK8wcxs0tbn0+SRdvCFQLgbWdyt0fxNAh6slfRqDn+n0i1
         BEg2hQGlVCeXFNyW8h7sDCEGsSFADwaU8IZuPhgNVfvR7JWyvRUYFkQr0exqnKaZBT3F
         H82AkTMzDzSnL7E+F/GIygccYjoxbUFKGL18HmfSCC0ZwhmkZq5sPvu4cAJLL4kfZSQn
         4mV4G//bmsRepwngFust3l317NDDlRmWOy2V9YEzJ1nYsuB5BCKaPgOU4T7Asmj1BFSo
         DhrRJkDzxszFHXjuoyaxf97gXxXDkXxtmczrc196OqNGHanNT+tMngM+bpC2XN8jJf1r
         cOng==
X-Gm-Message-State: AOAM533Va1r/2y0o7ktPoAAfSSQ+GDGCL37uH6Mmt9D4dtQV40+fva7H
	f8sh7vqJmklQA+gTfsQc6fw=
X-Google-Smtp-Source: ABdhPJwp1RGhLrcJ9xKH9g8QbsYU4lSmrH9NUcoMVQAo7dg5YbMHBuyC9+llg+Pgdt4gLdBHbrxLsQ==
X-Received: by 2002:a17:90a:aa15:: with SMTP id k21mr9932820pjq.169.1605194202813;
        Thu, 12 Nov 2020 07:16:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ac96:: with SMTP id h22ls1601222plr.2.gmail; Thu, 12
 Nov 2020 07:16:42 -0800 (PST)
X-Received: by 2002:a17:90a:6042:: with SMTP id h2mr10471518pjm.77.1605194201967;
        Thu, 12 Nov 2020 07:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605194201; cv=none;
        d=google.com; s=arc-20160816;
        b=Bt4BVOirw4Ka0P5ENDX9i3gIHGvfMj5S+XKAecq5OtAWs+eH6DBFhEa9KyRm5ukJWK
         /0Ee7G5pkB5sltnIxXvTop/ZAPAUn1mVPRS73buSnY2usn4UPIbCp/rQTiNA2x3NgCQA
         BfRKo4XJ5yGLWFMIQeDPP4lItcgdxfA2Vl3RUTBTb+CFibmVZSUIWn1PXiJsthM2J0c4
         8DvRN+d9RUpARGcSSjPeSejqNrcui8uJm/C+AbszuL2VNtJYzfn/YYUc32YW+yfBiCL6
         G3LuZFQwH4m4m75EqCBKCSCCzTAHHubYlrjuQ+y938MeMov8jCq67lPP/SvwBwKAdSsp
         Yy4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TM7ug66yDX2zb6iHncrZGyoO9ARI1hTYVm8tRUTfYcA=;
        b=bMs41xX+FjtKzRrUnqxcfW48vo45RSSMVrDr+W15Q9DLMANTV/O6Z38ixwhMD0HzAu
         8NdtvEVGxWMH7fXOHvSAseoqf3dFjph2DJGMEDJCmDo+KITQD/6ymhDOXwzMx9yv94f5
         mAh0lP3znue22z3hWJDwZYmf2TD8ML9EBH3y1OVmdO79f4ZzxFf0cMo0evQVmDX5PmHH
         y9NbQ2yytOYhSK63bc60P2WIkMkdkSrirk0WrJ0QI9IRl0gDiH4u1b9SHCtBwiszmFfx
         f5Icrm1+f6faLBDDVcwmZq8ORGxrt/OicGncFTJkSGL61njgjnR8ktlStCp2gkuibjDB
         IbAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iDTiyouP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id i5si856147pjz.1.2020.11.12.07.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 07:16:41 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id i12so4195289qtj.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 07:16:41 -0800 (PST)
X-Received: by 2002:ac8:5c85:: with SMTP id r5mr24292471qta.8.1605194200855;
 Thu, 12 Nov 2020 07:16:40 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <49f7f2c12b0d5805f9a7b7092b986bbc2dd077a1.1605046192.git.andreyknvl@google.com>
 <CAG_fn=VXhK0d__FkNdhdquy9F4VmB64_6eJQOQBRecy2oL6huQ@mail.gmail.com> <CAAeHK+wX+JPyZm2A5mDdGFCqnH6kdSBLyOZ2TnWfZnZuq_V0Bw@mail.gmail.com>
In-Reply-To: <CAAeHK+wX+JPyZm2A5mDdGFCqnH6kdSBLyOZ2TnWfZnZuq_V0Bw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 16:16:29 +0100
Message-ID: <CAG_fn=VPEC4Lk+zaN25M8fygFKpvqLVzwYg-WHB9iXdY5JK1sg@mail.gmail.com>
Subject: Re: [PATCH v9 21/44] kasan: kasan_non_canonical_hook only for
 software modes
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iDTiyouP;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Nov 11, 2020 at 7:52 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Wed, Nov 11, 2020 at 4:09 PM Alexander Potapenko <glider@google.com> w=
rote:
> >
> > On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.co=
m> wrote:
> > >
> > > This is a preparatory commit for the upcoming addition of a new hardw=
are
> > > tag-based (MTE-based) KASAN mode.
> > >
> > > kasan_non_canonical_hook() is only applicable to KASAN modes that use
> > > shadow memory, and won't be needed for hardware tag-based KASAN.
> > >
> > > No functional changes for software modes.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > > Reviewed-by: Marco Elver <elver@google.com>
> > > ---
> > > Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
> > > ---
> > >  mm/kasan/report.c | 3 ++-
> > >  1 file changed, 2 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 5d5733831ad7..594bad2a3a5e 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -403,7 +403,8 @@ bool kasan_report(unsigned long addr, size_t size=
, bool is_write,
> > >         return ret;
> > >  }
> > >
> > > -#ifdef CONFIG_KASAN_INLINE
> > > +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))=
 && \
> > > +       defined(CONFIG_KASAN_INLINE)
> > >  /*
> > >   * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the=
 high
> > >   * canonical half of the address space) cause out-of-bounds shadow m=
emory reads
> >
> > Perhaps this comment also needs to be updated.
>
> In what way?

Ok, maybe not. I thought you were restricting the set of configs under
which this hook is used, so this should've been explained.
But as far as I understand, CONFIG_KASAN_INLINE already implies
"defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)",
doesn't it?
Maybe this change is not needed at all then?

>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/CAAeHK%2BwX%2BJPyZm2A5mDdGFCqnH6kdSBLyOZ2TnWfZnZuq_V0Bw%40mail.=
gmail.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVPEC4Lk%2BzaN25M8fygFKpvqLVzwYg-WHB9iXdY5JK1sg%40mail.gm=
ail.com.
