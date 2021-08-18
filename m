Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFE56SEAMGQEIRK37MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3874E3F0512
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 15:43:50 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id p40-20020a056a0026e8b02903e08239ba3csf1306553pfw.18
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 06:43:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629294229; cv=pass;
        d=google.com; s=arc-20160816;
        b=q2x1LK1CE0EmZkVKfpcXRjTAv7up4PwNZOieTj2m8/kKEc6WBqlnGwVgN96o6nfQK1
         6YHViKJmi0fBmoO1I56HvMxLlGoTNGOqwMU/o4xS3otzlD2rS4Yz2ygoMzE3tfX2mPYF
         VGzM9iIaN7g/5jsBobcuugbNqwAquyztZXjNDfI7c9WKebBgqcIWLB8WTXHfvWCGxwZI
         AvHJKYAN+6x6I1wVn4oFFqUFmIM3xFlZM2Ykd9YTKUr8DtqBwS/7B0dhFhT8Gd0dQFlj
         3MtftsQy0wcBwtIADfg5PM4PE3JtdPz19schcHXRVkcPrbryP3oO2ucq3Th6l059aydH
         prvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eoHy9lCAblQYZy9kvSKokSOAHAAcK32TCc14+GuGdZQ=;
        b=0Ia/yjOoIaKEl0vZBSAi572icAaU5fpxwMIF364YNQyEWd4mZDY+kwDbWhjCiiQ2Bj
         NXvZ2NmBpKoHgS72r7pVnqpTDukofXN8NSup+0OU5CNpbBYRRSs75yzmVHr0crIBoSms
         H+5QlPnMHTUS7bUlYT41v3pROKZXKFeBMeXLuuX2SO2H8jP/9aSCQb1xbn2dOvKnrJkz
         2QLvRM+Xvxqdou/vvXwejs27COn5HgyQ1oe12077qjN/W+JmgKafsUa9aGDxHe2mXLuc
         oEv518wcTl++f1qg2ulE4mX40Wh2SiTw5meVkzp7gEGn5oDxtlSdKsXrSsJ2mDzecP2G
         wcIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Pj9w/afK";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=eoHy9lCAblQYZy9kvSKokSOAHAAcK32TCc14+GuGdZQ=;
        b=QU0B0UTk97sg8PGjZzcU5xGQgOjX7I1+6v+Pmc+n0R9R5LMrUaCUPbgW3soq0nbnbR
         MDV5hzLHo6QAqMb3GDHb8uTCVlYySEGf8d0oIMKh82cK7Aws4tOYaMrMJ8uKn/uZvsc6
         ihrBlEgMjoGqVGTf0Ix4KbE6Nna7UomSyIauCf9T+XDkgUiR2Q+98rsXIAHgFY2Alrvm
         4fw03cj5KYUtyVjQeijAQmZp5O79OcVIp7XIvtPQLH6CP8BgeF+gUdUHHcGH99vNqsyT
         AuU2WvbAn7Tmezv7evLm4c0Ly83+T630a41d7DMvg5lf9TG1V+wJsK7PA2HpH/fmcVqY
         etNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eoHy9lCAblQYZy9kvSKokSOAHAAcK32TCc14+GuGdZQ=;
        b=TxL2kGbBjezEGSJsCMjNCw0KNdykuzdT//HHjmoy6JTgnjzWGBDy0+L34Z5qb55lKP
         TnF5N4RnbddIuWQT339PeD179ywstXDVIeJsmeM9j9ZiEkogkZSUjcY2tUaiIrLIRZ0/
         ryBbWld6+AlrbBV6bRA3DzP+FRdzHGQVFSxlJlGuK2zK1Ir2/ZTDD7vCjqv8X1xW4qWA
         N/UC67XYV70MCqdGO+xSvO2RhDTSvBO2Mp8r10iPqRKSgofPxJksXIHP+kLM16Pjcufr
         gG/GZyPK5ZFBIU2f7ds1Nlj/84ilRdx3E+OZA21Ds+87LyYF9OSGHxnjKvXa3PHNSm4M
         3dVA==
X-Gm-Message-State: AOAM533qWUWtD5xgGS8JZdtEGWSAZwaAQGl9ryQU+6TqVJIIGJOlajAg
	2UJPTjoxddwWxQrZ/X9G1xI=
X-Google-Smtp-Source: ABdhPJxvOy/9c/OzAkmbS2vqPZizbcbhG7faL+qvO7gIYJtlaWeH4ID0CIVde/7CrGYM8ekHAWM5Qg==
X-Received: by 2002:a17:902:7584:b0:12d:8cb5:c7b8 with SMTP id j4-20020a170902758400b0012d8cb5c7b8mr7519608pll.84.1629294228861;
        Wed, 18 Aug 2021 06:43:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f81:: with SMTP id q1ls1313044pjh.1.gmail; Wed, 18
 Aug 2021 06:43:47 -0700 (PDT)
X-Received: by 2002:a17:90b:4b49:: with SMTP id mi9mr9481988pjb.87.1629294227564;
        Wed, 18 Aug 2021 06:43:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629294227; cv=none;
        d=google.com; s=arc-20160816;
        b=u6/fCNVyHZyVaVe/vheB/4kuexnszDv95QgRpb2J/HVg3el9SzNrWLXrD4sRSV7LHL
         L5GCnp5glxSvEpAtW6GUyMClrPdCGLPLQFe+2+tN5SUXcvbCN1IrW2BVpcHDintdWyVF
         QFFUlVSNWn0KOE+CJBJy2+4S4h5PMU0mqNiMglPs7lVnl5h24ohtGC4PkT9+IQKb2DFI
         Nsd0JtuLsda1cevTgsicGZOFVGRE66ZSH/6UBkQECiAsF46o6yR4yzMycKpb2mWv6O5r
         /QULwGJcspCI/60w7uGTiE5KMaG+xBzLPqVUh2R6PVowLvgT5ssJL4L7GVbavKD4MyE4
         XDTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=S5eDEdgJSEI6ifHq/vU3nLhIVHOqJcFRYhjJl8EuhE0=;
        b=cHr/CyKmHywyugdtG15bCaJFsZ75AgXABks28c1HGqxZpw3up7nNjQ/ozJnziKihHa
         RrfDaZMyiJzKB51Cy4M30r4fVNF2LtJH6BpX26jsj0v/f/6dq6/EsMXWiSFCbh+Xaa9q
         mmIeBujRBSUcF3zX4YunVkXDdDWo1p6IGOygD91o5s4voPdZgG/ikwFmi1pnYGGatyIU
         /TQauBAw1w3BXMhUGcPyAyPsz1ftM/a4KRmmu1HvCPYcUHztH8tcz3ymtCDTG/zwIiQH
         op6eTPD5tIMNkwvLBy+QB65p3YHdHIfIWE6JEwzTP0JEpD9BYckvw5OuXhza9GwT4B89
         QjMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Pj9w/afK";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id k15si200597pll.3.2021.08.18.06.43.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Aug 2021 06:43:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id m21so2947634qkm.13
        for <kasan-dev@googlegroups.com>; Wed, 18 Aug 2021 06:43:47 -0700 (PDT)
X-Received: by 2002:a05:620a:d54:: with SMTP id o20mr9700090qkl.326.1629294226642;
 Wed, 18 Aug 2021 06:43:46 -0700 (PDT)
MIME-Version: 1.0
References: <20210818130300.2482437-1-elver@google.com> <CANpmjNPX0SANJ6oDoxDecMfvbZXFhk4qCuaYPyWT1M8FNpy_vw@mail.gmail.com>
In-Reply-To: <CANpmjNPX0SANJ6oDoxDecMfvbZXFhk4qCuaYPyWT1M8FNpy_vw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Aug 2021 15:43:09 +0200
Message-ID: <CAG_fn=WvyuFbDyx5g8qkjak7H87htc=yk6+5hazXgK5nMZvx1Q@mail.gmail.com>
Subject: Re: [PATCH] kfence: fix is_kfence_address() for addresses below KFENCE_POOL_SIZE
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, stable@vger.kernel.org, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Pj9w/afK";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as
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

On Wed, Aug 18, 2021 at 3:40 PM Marco Elver <elver@google.com> wrote:
>
> +Cc Jann
>
> On Wed, 18 Aug 2021 at 15:03, Marco Elver <elver@google.com> wrote:
> >
> > Originally the addr !=3D NULL check was meant to take care of the case
> > where __kfence_pool =3D=3D NULL (KFENCE is disabled). However, this doe=
s not
> > work for addresses where addr > 0 && addr < KFENCE_POOL_SIZE.
> >
> > This can be the case on NULL-deref where addr > 0 && addr < PAGE_SIZE o=
r
> > any other faulting access with addr < KFENCE_POOL_SIZE. While the kerne=
l
> > would likely crash, the stack traces and report might be confusing due
> > to double faults upon KFENCE's attempt to unprotect such an address.
> >
> > Fix it by just checking that __kfence_pool !=3D NULL instead.
> >
> > Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> > Reported-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>
> > Cc: <stable@vger.kernel.org>    [5.12+]
> > ---
> >  include/linux/kfence.h | 7 ++++---
> >  1 file changed, 4 insertions(+), 3 deletions(-)
> >
> > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> > index a70d1ea03532..3fe6dd8a18c1 100644
> > --- a/include/linux/kfence.h
> > +++ b/include/linux/kfence.h
> > @@ -51,10 +51,11 @@ extern atomic_t kfence_allocation_gate;
> >  static __always_inline bool is_kfence_address(const void *addr)
> >  {
> >         /*
> > -        * The non-NULL check is required in case the __kfence_pool poi=
nter was
> > -        * never initialized; keep it in the slow-path after the range-=
check.
> > +        * The __kfence_pool !=3D NULL check is required to deal with t=
he case
> > +        * where __kfence_pool =3D=3D NULL && addr < KFENCE_POOL_SIZE. =
Keep it in
> > +        * the slow-path after the range-check!
> >          */
> > -       return unlikely((unsigned long)((char *)addr - __kfence_pool) <=
 KFENCE_POOL_SIZE && addr);
> > +       return unlikely((unsigned long)((char *)addr - __kfence_pool) <=
 KFENCE_POOL_SIZE && __kfence_pool);
> >  }
>
> Jann, I recall discussing this check somewhere around:
> https://lore.kernel.org/linux-doc/CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nade=
uiu1Byv+xp5A@mail.gmail.com/
>
> I think you pointed out initially that we need another check, but
> somehow that turned into '&& addr' -- I think that's what we ended up
> with because of worry about another memory load, which is clearly
> wrong as that only works if addr=3D=3DNULL. Simply checking
> __kfence_pool!=3DNULL is enough. I also checked codegen, and the
> compiler is smart enough to not reload the global __kfence_pool.
>
> Wanted to call it out, just in case you see something even more
> efficient (probably the only way to do better is to get rid of the 2nd
> branch, which I don't think is possible). :-)
>
> Thanks,
> -- Marco



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
kasan-dev/CAG_fn%3DWvyuFbDyx5g8qkjak7H87htc%3Dyk6%2B5hazXgK5nMZvx1Q%40mail.=
gmail.com.
