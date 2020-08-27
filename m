Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK6LT35AKGQEZARP6VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F5FE2544E6
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:23:09 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id a14sf7058291ybm.13
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:23:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598530987; cv=pass;
        d=google.com; s=arc-20160816;
        b=riG9URqBF2uT4zqw0xnW+px+iiOYV4dWTEEu5XHjo5qkXDB+dKjJEGKCjX9BdpdcTr
         p+z1b6HSHMR1m9B1UuPTkcNHEXPQ9SrXLxzAW/p4Rt/Q9SWVHfMubsxTeb95lvEwaxUa
         aVV7nqaf7AzM9+EqumV9jwDB5ZDt3foraxOvPil7x2xWWuf+witCaUfcFwTvb7T5aMcE
         DP0eMigyx577e+hOZsq5M1hQt/rzF2XCtRfrLkXQQwOfH8y+W6uN7vCaihY1/mt+YbSw
         CHlU2WtQVR9qCh+xKKU1riJPzkVNuyIQjVrzYqv4xzvbjRsA+L2WeeywVffBm+3ThEkw
         U90A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cU/++XFzksSQK/sKdpRGUG7sCRdOE/ygn1htGgMud54=;
        b=cQB169/Mb7RzLa9H8ZJP7haEP6q0Oby6xpfMyMlPVde4+H1x3kysZeL2mCcKYp0Bn4
         SMLI3HBjI5qXp1CHEnDZPceVclzhhSmOvEf61GkwlyC1hMr/IGqvRQRs9DqgI5kN4XoT
         KwONfuL31PNkmr9WUm3nazuUrZ/H3nKpHwBGnMN1JzxC5jgMmULX5Px7gTHdUfjoy6Mb
         gqUZrdd6X6NwUTtG+xuo9pH4+9w8b54AUesRVhHjLF/DsmOU2mikUo0pnrPfgXTQq5S+
         5LGZ9bP8hgUyUZMG0yLhBOqkEdqwvz2z8VV2oNa84XJkvNBB7ntc31y4r7KocxsKtk73
         zHWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XunWIOHV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cU/++XFzksSQK/sKdpRGUG7sCRdOE/ygn1htGgMud54=;
        b=QQDBKeFbNB8I4ig7DG46/9c0mCfOPdM5W2ri6FwkWHLJc6pH+nmToglyIWXakDxm6i
         n9jMgpvJNECqXg889ge3+eebufZfYlnmROn5iVzmEMwCaswQ0e4R1LOfABJZFmCgp+aF
         wjFTYak4ipycDnMWjXuZxFqBO80ch8w0wU4Hjs3UkJW0lOpzoMrVkWbDEQ2UnjvvxsdG
         cyjy5aw1/cNSBRKwSgkHFzZVbruFxfbVmLtRr5BmET6+NveaxCnrcpVojvtJjHvYeOXJ
         mvz7Ye2bAUNmo7c2CdK4GDLatFp5mdKhOc4KXI70RQRzKzBJe6/zvruXU0X4TZRoJFNn
         Xjow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cU/++XFzksSQK/sKdpRGUG7sCRdOE/ygn1htGgMud54=;
        b=V5FEdIH6ETWZlFxCuty7osAmFB+Qr/ps8nLLCH701uP0eW5m7W6NLsGGCD8F4KkPMQ
         A2mSo4p9fkj9ZEbV4ymVmD1gZJGU0TZ7Fs+PRtCLzATKMHZ0yhj/xeOlW1guBUZDXAOV
         1WjJwm9txHo2rD2SyhduBBi5giIjlxZgg6t+KlYpDkhd0J0B8HFeHeHq41zAU0aVWWEL
         5acARqpghCrqRSI57uMUmVmVfmpZDb7CVgncRp5HZEEZWmmkaQ0yVmAVl9tRIyDdP/Oj
         qLJKwPUOpGx7I7RkefoH633dTlfnEmzZLvGJr1odjcG2t+fJmWLsbJVbMCuGrq2cp0x3
         HY0g==
X-Gm-Message-State: AOAM5304w5Nd8Da1OL0t9biFAs0fF7FwQahvG4qb4MsOfCYNnTX6J3Nd
	fPrRScqwoDPuAhxhZTR9kYk=
X-Google-Smtp-Source: ABdhPJwfS+cRvttgQzCCQx/6HLYUSPembyaxxhRH6Qn1VsBXi6KJqCiTvf2AqlGwbN6GjHy7qJZfMw==
X-Received: by 2002:a25:868b:: with SMTP id z11mr27476620ybk.108.1598530987669;
        Thu, 27 Aug 2020 05:23:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ab50:: with SMTP id u74ls898983ybi.6.gmail; Thu, 27 Aug
 2020 05:23:07 -0700 (PDT)
X-Received: by 2002:a25:b443:: with SMTP id c3mr29469784ybg.118.1598530987321;
        Thu, 27 Aug 2020 05:23:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598530987; cv=none;
        d=google.com; s=arc-20160816;
        b=kO9r2NU1rD8SLze6FGe8p55NQhVz8Yl6TU61AgFnpeJXyXTv+WxaZotK1tMFyJajd4
         MnQmsXqA0hZj9ubMlsj7qvLigd4G1k35LuKbgNgoN7UyQdDs+/arGOUZNRr059NDyPuE
         W3DjaRr7f6h+APr7+GX23+LJTY1/1AVInRkosLf29uqaRS1TCMXULPyY7tpr37Beao92
         3Xw54m+dfFuT5RtGrD7UsHxyt+5WSybNFJfcIIasPSKnMoolN3s6JA384MmKUHEIKK/g
         A2DKCLuy8yWns/sMDjkvdERbQx1tnLiwdS1+pUIP7pkVT2ZECxP9qN+tbc5NRCugFEvv
         C+xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wRmOM+lY0GqSNROHa6fviQnhx1T7htrFs5kxwy8CYOE=;
        b=FL4p0z4n7NUpoT+ntrjxbrJznHQJdWJv6d3wJ1L/yBUDO8rBZN2ET19MWRIRUDUsuL
         zLYaHmmANheU43UQhUZPtJHi89UaM0dsn25Ss9Ce5xWlxjfqdIq0j3UtNaf9p9Sljgxm
         rpieE65j4XYPYVhbek4Rb9JNEJXYgSADaug7eZctLQ/V8vukCW+hyFlt4hKweBeECcsC
         K+HVqwDpqB8fwVngwTQVOR0EbpGz9wD6lGYJGor0QpA23RDAkpge2iAaAZ386b7B/0NZ
         uYjKKt3snFG76PW4pmG0NY5SzI0kV7ENqvvuEc/f7mTMWupEeLoGqpDJOY6oDuMFQMei
         LD2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XunWIOHV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id 7si87604ybc.0.2020.08.27.05.23.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:23:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id g29so2217624pgl.2
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 05:23:07 -0700 (PDT)
X-Received: by 2002:a63:4c:: with SMTP id 73mr14564236pga.286.1598530986286;
 Thu, 27 Aug 2020 05:23:06 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <8a499341bbe4767a4ee1d3b8acb8bd83420ce3a5.1597425745.git.andreyknvl@google.com>
 <b7884e93-008f-6b9f-32d8-6c03c7e14243@arm.com>
In-Reply-To: <b7884e93-008f-6b9f-32d8-6c03c7e14243@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 14:22:55 +0200
Message-ID: <CAAeHK+x+DMs9jdeB58XaoJTO-kv+iiWT1_BuhYiJzJH-DoY9EQ@mail.gmail.com>
Subject: Re: [PATCH 25/35] kasan: introduce CONFIG_KASAN_HW_TAGS
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XunWIOHV;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
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

On Thu, Aug 27, 2020 at 1:31 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 8/14/20 6:27 PM, Andrey Konovalov wrote:
> > +config=C2=B7KASAN_HW_TAGS
> > +=C2=BB bool=C2=B7"Hardware=C2=B7tag-based=C2=B7mode"
> > +=C2=BB depends=C2=B7on=C2=B7HAVE_ARCH_KASAN_HW_TAGS
> > +=C2=BB depends=C2=B7on=C2=B7SLUB
> > +=C2=BB help
> > +=C2=BB =C2=B7=C2=B7Enables=C2=B7hardware=C2=B7tag-based=C2=B7KASAN=C2=
=B7mode.
> > +
> > +=C2=BB =C2=B7=C2=B7This=C2=B7mode=C2=B7requires=C2=B7both=C2=B7Memory=
=C2=B7Tagging=C2=B7Extension=C2=B7and=C2=B7Top=C2=B7Byte=C2=B7Ignore
> > +=C2=BB =C2=B7=C2=B7support=C2=B7by=C2=B7the=C2=B7CPU=C2=B7and=C2=B7the=
refore=C2=B7is=C2=B7only=C2=B7supported=C2=B7for=C2=B7modern=C2=B7arm64
> > +=C2=BB =C2=B7=C2=B7CPUs=C2=B7(MTE=C2=B7added=C2=B7in=C2=B7ARMv8.5=C2=
=B7ISA).
> > +
>
> I do not thing we should make KASAN_HW_TAGS MTE specific especially becau=
se it
> is in the common code (e.g. SPARC ADI might want to implement it in futur=
e).
>
> Probably would be better to provide some indirection in the generic code =
an
> implement the MTE backend entirely in arch code.
>
> Thoughts?

I think we can reword the help text to say that it enables tag-based
KASAN mode that is backed by the hardware in general, and mention that
this is currently only implemented for arm64 through MTE. I don't
think it makes sense to provide a common arch interface at this point
to keep the code simpler. We can do that when (and if) another
hardware backend is added.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2Bx%2BDMs9jdeB58XaoJTO-kv%2BiiWT1_BuhYiJzJH-DoY9EQ%40mail.=
gmail.com.
