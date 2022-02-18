Return-Path: <kasan-dev+bncBDW2JDUY5AORBWXMX2IAMGQE2YTS2XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B86B64BBBD7
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 16:08:11 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id b3-20020a056e020c8300b002be19f9e043sf4103406ile.13
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 07:08:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645196890; cv=pass;
        d=google.com; s=arc-20160816;
        b=e6NbMaHkP5hM9C2TTcVzCi6JotoUzJDVkAXLMD0tMkALbr6QWFotEqCVFvyg9LBGLa
         PECWvVFbjv6t9QfXJvl9DYxQcES0qkoZAxoZEMa0W+qOpzA2OJQAYfyP6jEESH/ntu2d
         r5v4NEU5gZQFgnkEAr2mpUOS40DJHdaYoCuqf0L8YWDB4xMw6bfBhtRDHH3ShJyeI6jJ
         285cXnVw0suJrOmOqtvvMdvXNUMq/A4VLwpNGABY97Rmo0q1iwfu5gwUZPnTSslLytQ3
         TV4n2KQ/1uP6Wcyl1e9RXePu3KBcUaFdIQ3Q47da1cuKWXYPoRybf7EqcO9GW6/vT0DN
         0Xvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tIQQxTfhW5Avpuu++tgfqRq7qdl5Y9JwNotGaqlaqls=;
        b=v8LRD4/NRzh0vWW551LNHH1BxMCPeTcQFEc/jPBKr1uZtFlnpZ3liRdJ2VXaEFeBx6
         ZF40/iGzMe8pKs4/70DEVh+WMghQ91MSsZ0K/nsHtPIXLE9vrUnMLRvNmccTG6HEg9xR
         VPoR2/h4l7S18HK9OicZ9yLaWcCHHbHljetoQUPyEp2FMqA6tivZRl4TcCk/ljhwtjRo
         Mnv4d+ABZ7uim8k0jgm+/mDD6uiLF26gpgiLdB6HyBrW98A6w0ofhigMmQ53VxnLaxWK
         kaY6YExsuHAoTJGIDpcyWOoeBN+rn8mzobKq4c5Mh0R27O+ErjGMQ07y7b/3mhSBTSJW
         c74w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=k0fc5rFl;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tIQQxTfhW5Avpuu++tgfqRq7qdl5Y9JwNotGaqlaqls=;
        b=TJlvSb9CfNh9ucw7kwuzH+1avMZNSUOK6I1tFHcLRo1jZRqAl60P1mKK58X8B+n8IF
         a7fTo1hg/ZogAyJeeHKSqOOH2kPJPYmwHatdJhSm5C7re9DKmzhN69PzzaSjf2os0YB+
         z46HhgNjQFI4MiJ5su4r9QF4LzbtAB2lCvqz3twhKakZa0HMeGMdBrB8OBtCW/nrqOAT
         sKWlZzwP1i5BFPfWeTBaqDIIGQrFMwFypr9zOVdZNX+Ve5wsQTPSGjBf+gGsDGEOOLH7
         Ea24Rk+tAovm1ZZ4NhuvMwfgJC1RCC9wezqoZVHfJQp0gjXsXqR5PVhWRZtc020jdLSp
         0xxQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tIQQxTfhW5Avpuu++tgfqRq7qdl5Y9JwNotGaqlaqls=;
        b=niTnALe/qbJ5bGpcYD2pqR5Fhp1e+3LGL62YdLKA03HyOA5PkHsbovY2icjRpjnCz9
         OP0F1a7467VcGi8h9bNwPy35FWh9dtgtGE99KQH3sRieSeHhbP2Dx/kYww5fdjZu0NV1
         Eq/MsQKlvIS4XPjpJA60Z9OOgec0suJiwxreMAU1kVtDt9VEji1S4oa+99tYXa4NwU4+
         yvBKTeYO9fhFefm7SRgeRJ6mjwY7f2Wbr9WwE3tyFuF7YeyNzHfwTjcMCAWQYugGMkqW
         CIP8Ey0nSZ7KJeku0V3G0iDremROL9zAojtkWTe9lWExVsMj216KDfQwM3wG2BFImBYL
         XS4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tIQQxTfhW5Avpuu++tgfqRq7qdl5Y9JwNotGaqlaqls=;
        b=uQY/84ZkyULQa8jiKS7TSZZ7qOd/NfAOWF02loWoULWtJrrVm5C9G+2PwP+4WN7xu6
         hlUKEn+qg6mmIBl6qV2CoOw+wkJ1eKey+WYlH7xEmYng+5jjFhzhLAPQsltj0uOBxpV4
         umk1ndOHbj33ivxTzX3tCHY/HRhDtf0X3F+iND5lY4ImSSI23dXLqFEp6hXsi6T51NwY
         MLFwWqcvEbAshTlGI57zlPcAghmaBLIAJntQRBHMJfKvjKURWKYynxi6ain9UQUXQPfe
         AbN2HsgmIpuP/G1IofaJ62ph3ay6m41sTDNq1vdMJoA3BXsSFD60r7A2uOJN490WYGoh
         fOog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530e0FeV29tpLF6lAmUgIgk/po8UjIJI9q66A8M8o22ZiG11ZXgZ
	FPkLCnukhRaFC+WG9Bv8qlY=
X-Google-Smtp-Source: ABdhPJwW6giuyALHbzbjKX9NcvVOR2Pj+EmCu0kRn8/DNRdBd0GXcilszWZZrvT0rXpvbOkRYs4dmA==
X-Received: by 2002:a6b:3b86:0:b0:610:4244:1d19 with SMTP id i128-20020a6b3b86000000b0061042441d19mr5753228ioa.199.1645196890467;
        Fri, 18 Feb 2022 07:08:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cda3:0:b0:2bf:ac47:dad8 with SMTP id g3-20020a92cda3000000b002bfac47dad8ls1197960ild.7.gmail;
 Fri, 18 Feb 2022 07:08:10 -0800 (PST)
X-Received: by 2002:a92:c26b:0:b0:2bc:84b9:fbc4 with SMTP id h11-20020a92c26b000000b002bc84b9fbc4mr5718732ild.241.1645196890111;
        Fri, 18 Feb 2022 07:08:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645196890; cv=none;
        d=google.com; s=arc-20160816;
        b=oXRyE2qAmjQRSIb5BlXN2gIRfmUb7Hj4TYjz5JZ7kwGph+AlVx2Be6WX0jT4rjxBZS
         zFrxMr50r4RUKU9+ieIGDkfnv0F3vRDdZu+l1bR4UocIhPwK6VmsVsJBI48hMiKTay7S
         ZFEgYOyduzDRwy/o5hJI3nC4sE3JMGeDum4bvuTj4bW+xLOr8PSj0OvM9UhLrLDvIUsP
         7h4pvpxjoQVc549Fo1s/ARwvvSyATglpLhYTHuNJtVCIoE6t18HmglFaRxbMtdwuJyy2
         /wvjgTjezDBSXT+WZje9SJEO2+ZMYsAuAKCN5xe5golpdjD7scYh6Ob9fG+uIfe7z12w
         eL4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0WAY4GVsgjaO40pd4PC+o5Qrkod87XgfNtjMligfgoY=;
        b=I0wDuNBDEtiu30AnxFOAgPY8fvHN0C/n6o3ZDSXFcOw8/k6yxvf2zlNkCQGZUvz8Pc
         7o7rxyn58SeFAerzbyHE2pgKVbCHw3P/UO97HgODkAdGRtv0lC2DUoLu1KN2+KB8QFwJ
         PO/z8JxcOXOU+N/4eXw0G15Cv+KDTzsfsTm5g2IQZAgSyqEoDEJ8qWUPOLVo3EzvXKu0
         oCcoEZkT4z4twvQjnhdDJ/mqiGmJjjfzNTvFuvsdDeT3CtQlSR9YuxKXci9W3CKPKOnm
         BbhWAA+O5nYJIwtam1XcM/T2QgJc4UJOHyBdcFCPRwBNksdkpaw3eWndN6JeVy/I3uA1
         4V/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=k0fc5rFl;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id n11si1441651jat.6.2022.02.18.07.08.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Feb 2022 07:08:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id z7so4839588ilb.6
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 07:08:10 -0800 (PST)
X-Received: by 2002:a05:6e02:1905:b0:2c1:e164:76eb with SMTP id
 w5-20020a056e02190500b002c1e16476ebmr982921ilu.28.1645196889849; Fri, 18 Feb
 2022 07:08:09 -0800 (PST)
MIME-Version: 1.0
References: <5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl@google.com>
 <Yg44yQJ9tQMgmiZq@lakrids>
In-Reply-To: <Yg44yQJ9tQMgmiZq@lakrids>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 18 Feb 2022 16:07:58 +0100
Message-ID: <CA+fCnZfAwSJQp7zE+qHChaSvy1uEL6xi0JiHtMi6iq29Fk3tRw@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: print virtual mapping info in reports
To: Mark Rutland <mark.rutland@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=k0fc5rFl;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f
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

On Thu, Feb 17, 2022 at 1:00 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Wed, Feb 16, 2022 at 08:01:37PM +0100, andrey.konovalov@linux.dev wrote:
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
> >               pr_err(" %pS\n", addr);
> >       }
> >
> > +     if (is_vmalloc_addr(addr)) {
> > +             struct vm_struct *va = find_vm_area(addr);
> > +
> > +             pr_err("The buggy address belongs to the virtual mapping at\n"
> > +                    " [%px, %px) created by:\n"
> > +                    " %pS\n", va->addr, va->addr + va->size, va->caller);
>
> The return value of find_vm_area() needs a NULL check here;
> is_vmalloc_addr(addr) just checks that `addr` is within the vmalloc VA
> range, and doesn't guarantee that there is a vmap_area associated with
> that `addr`.
>
> Without the NULL-check, we'll blow up on the `va->addr` dereference and
> will fail to make the report, which would be unfortunate.

Indeed. Will fix in v2. Thanks, Mark!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfAwSJQp7zE%2BqHChaSvy1uEL6xi0JiHtMi6iq29Fk3tRw%40mail.gmail.com.
