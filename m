Return-Path: <kasan-dev+bncBDEPT3NHSUCBBLVT47UQKGQENKHJIMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id E2F7675419
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 18:32:47 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id k1sf13463788vsq.8
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 09:32:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564072367; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Qr7/JqKfAmv5AFD6MQI8cwFaXtvSjxSM66Jik/u3yriHUc3qde8ch03kh3jfbq+aj
         jRKYQe74IhJ85or5n4cbbkLH3dV5j8L0PbbcoX+WMJrwkYprN/PHM1rd5BgK9B8S2dwT
         3zuZxNgsFNS3ETkA+sbLytjI7CpMg5L8vYboaHQUSLYRmMiysv8OJBQB/xOCQLaO0s+j
         8QwGJYNesgpAm/8dwXNkYolUSLljG5rON9DliwVg4H8UpILlObdHjkg9VAaLK18pRI6A
         Bd3skvvbSDySBql2aaO8leGHLgOVaSjoRWdv5DMasWTvkcC1BQhqo3mwWxsKmtZILVQ1
         HG6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=ZvkAKQRaRZMqP3HtNJrTeAss1hpqQW4ys14pCOzV1Kg=;
        b=F2WxTNq1MbfcH/E3455/8Ooq/ofKqETFJ1e1oWRZkDvYj//ckGu34TmpQ3uAcoSO3K
         XW9fCjaHsVLo5yOJ7EMxg7KWBBpeddsWeVa3WjnzqoBAdEK2L6hHvZefmraB/3Ali8Il
         J9zVxiPAcqaF3f/r8ln17vTQycvXNGoNH6Ld9/m5sfWNGFl6ERDJX/iWKYtZBnLvKN/p
         BLho5eSuw68+aEneWbaYTpDnv7m+zrx7N9ztm3txoSFgjtCG5wLM6km0c9w6RikadJK3
         /qm1gjoTAXTFqJSKZA/j8FX9GGIqTtsVn/LXIsysTF9udOI0M8bca5IttLKP3dcrhHiP
         JM+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gQ74RKc+;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZvkAKQRaRZMqP3HtNJrTeAss1hpqQW4ys14pCOzV1Kg=;
        b=b9Ypvst6oA64XEGjk1PKwVaT4+az5sN1a0LGXslgRZADm1gIe1vR26/A5RfXdqFsn+
         qxMmzK2J5xEneGOh8zTDXo/u0QZx5Mm9jgwWgDNGxrS9NeD/nMjxPP9B/K1crOkabro/
         +USUlGltRNmjldj8wp1oxLxD2xNK7jYN1LlEGj2YAXS+ToKz1WUiv2UYxFI/aE5r+xai
         ldO/mUM0t9CjHD3VEqeQT4cnBF8w1qkyyoQWa8uYA7/nX9vUlt+ofDcxpEf9B0WTcO6Q
         NIj+Jn1sFyG4HBd5DtnjyMH5FIti9zZ1fzi353+Nw3NuLs17kmSxk2Kg+NtIvZEid+ua
         kzKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZvkAKQRaRZMqP3HtNJrTeAss1hpqQW4ys14pCOzV1Kg=;
        b=ChD4jgVIuBV6UXLQNSgrGBkCKoUNmIcMnrReO4Lj6l0eLO83FgFo73k0Iynq36s0yw
         MCb3TScrZrY7RcZnGcyc3UjZyCKWggqCCROJTJnOIZCFwdUcbcJOJdDa6qQEAnpOjxrS
         ebWFhxcAf5d0e6YOdfHtZllKX/l7pR7wcC9vIANvHlO31PK4vzqD48FtAjS5qx39pouG
         gUGYhwoXxkpkHGpzdn6qkySc5MgM4uXTmjGjdcKwcL18Kpbj+7cRFoJDH9hrQXl1gmKj
         +c3DxtY3qYsfQ/tHyZM89hrM1lpMovPQHElCbsjVpcWyRL7rpgiiNdyo0azqbe61WmkP
         qh8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVTGniGgV9CeQ+Vf833tb0QF89+em2hp/TcGoZXuQvjLrn/Ol3U
	SQ1o6lhpEPKuYLgoQ8WO9xo=
X-Google-Smtp-Source: APXvYqyDnnBagRBlkyWMLb+mkHJCP9LrwzKuZqtv77SQwnM7G9WvSmeEiUYfIUWCVRk4QMf9y4v6Zw==
X-Received: by 2002:ab0:4307:: with SMTP id k7mr45052666uak.45.1564072367013;
        Thu, 25 Jul 2019 09:32:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8cc8:: with SMTP id o191ls6443112vsd.15.gmail; Thu, 25
 Jul 2019 09:32:46 -0700 (PDT)
X-Received: by 2002:a67:ea49:: with SMTP id r9mr36027195vso.223.1564072366744;
        Thu, 25 Jul 2019 09:32:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564072366; cv=none;
        d=google.com; s=arc-20160816;
        b=pXat9Pz2JOzJv/wOYAJIzZXRf4QWtUu1UmebtvlxKEnIK+AalmaydrHCub/Vf9sM4s
         f8vEFfaRqG6V6OxPIQg0TtDm8WlJNQI65+i2fTt4p5R/TV04LdxB5MYpVUnOIiRbAx4V
         YFWWdTlhDYz7bUz3pFMITalnR54xKycUNCtDEZ5rwaMShQVh6qFSuw1IyB9tKErDBJWA
         p1SKgBRXbz7tKgtisyEFfAlTuhmEYU362QP4myvx75xnlgmhhGoF9X2+LEqy32ylHhda
         5W2cKKRquHFeAymEVgmbLNXlHICAZG2Y4DodK8RyPRebFXp1BkPJODemnkclbt/f8H0E
         Y+Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OKgzFeHdg3Ku4H+GZnC9pLfW3Z4D1feqUYwGaJi6wmI=;
        b=Yq+xNJ9aXDlmx1Tdjn8B3VXS27mXOyAv/lQb3HnC7l2OBgIQNw+H60FDhkc77HGU8T
         ap1ohxfxnPJDs3V06JEUWj1MEy32evYX7aMXQVv/3P79CuwM79pVevcT56uHz0iDDTG0
         1C14V6oThSaKsBffoCrwJv3Oiw5HPFT8PPgWoqFPuVn3hS9TbJ77VlGeFTuU53ObdiL1
         ZSJJIqq4Lf/gP20beZYlJeREMmQm2hXimp8JUmNTLnu9KyDkTHneoCPDnKn7zbh54i2M
         ff6NfiDAH/5m2SLNXPy4VBSUEVJNF6ppZAA7Pq7AtcVnr15BnFlCTc7tHbolvK37BzEo
         UELQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gQ74RKc+;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u189si3433794vkb.2.2019.07.25.09.32.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 09:32:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wr1-f46.google.com (mail-wr1-f46.google.com [209.85.221.46])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5268D22C7C
	for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 16:32:45 +0000 (UTC)
Received: by mail-wr1-f46.google.com with SMTP id p13so51428479wru.10
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 09:32:45 -0700 (PDT)
X-Received: by 2002:adf:f28a:: with SMTP id k10mr17529201wro.343.1564072363818;
 Thu, 25 Jul 2019 09:32:43 -0700 (PDT)
MIME-Version: 1.0
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-4-dja@axtens.net>
 <CACT4Y+aOvGqJEE5Mzqxusd2+hyX1OUEAFjJTvVED6ujgsASYrQ@mail.gmail.com>
 <D7AC2D28-596F-4B9E-B4AD-B03D8485E9F1@amacapital.net> <87lfwmgm2v.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <87lfwmgm2v.fsf@dja-thinkpad.axtens.net>
From: Andy Lutomirski <luto@kernel.org>
Date: Thu, 25 Jul 2019 09:32:32 -0700
X-Gmail-Original-Message-ID: <CALCETrXW_=6sPd8gcdkZtYAmCTYhoOYMYhp6_yVd-8Wd5zYsrA@mail.gmail.com>
Message-ID: <CALCETrXW_=6sPd8gcdkZtYAmCTYhoOYMYhp6_yVd-8Wd5zYsrA@mail.gmail.com>
Subject: Re: [PATCH 3/3] x86/kasan: support KASAN_VMALLOC
To: Daniel Axtens <dja@axtens.net>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andy Lutomirski <luto@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: luto@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=gQ74RKc+;       spf=pass
 (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=luto@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Jul 25, 2019 at 8:39 AM Daniel Axtens <dja@axtens.net> wrote:
>
>
> >> Would it make things simpler if we pre-populate the top level page
> >> tables for the whole vmalloc region? That would be
> >> (16<<40)/4096/512/512*8 =3D 131072 bytes?
> >> The check in vmalloc_fault in not really a big burden, so I am not
> >> sure. Just brining as an option.
> >
> > I prefer pre-populating them. In particular, I have already spent far t=
oo much time debugging the awful explosions when the stack doesn=E2=80=99t =
have KASAN backing, and the vmap stack code is very careful to pre-populate=
 the stack pgds =E2=80=94 vmalloc_fault fundamentally can=E2=80=99t recover=
 when the stack itself isn=E2=80=99t mapped.
> >
> > So the vmalloc_fault code, if it stays, needs some careful analysis to =
make sure it will actually survive all the various context switch cases.  O=
r you can pre-populate it.
> >
>
> No worries - I'll have another crack at prepopulating them for v2.
>
> I tried prepopulating them at first, but because I'm really a powerpc
> developer rather than an x86 developer (and because I find mm code
> confusing at the best of times) I didn't have a lot of luck. I think on
> reflection I stuffed up the pgd/p4d stuff and I think I know how to fix
> it. So I'll give it another go and ask for help here if I get stuck :)
>

I looked at this a bit more, and I think the vmalloc_fault approach is
fine with one tweak.  In prepare_switch_to(), you'll want to add
something like:

kasan_probe_shadow(next->thread.sp);

where kasan_probe_shadow() is a new function that, depending on kernel
config, either does nothing or reads the shadow associated with the
passed-in address.  Also, if you take this approach, I think you
should refactor vmalloc_fault() to push the address check to a new
helper:

static bool is_vmalloc_fault_addr(unsigned long addr)
{
  if (addr >=3D VMALLOC_START && addr < VMALLOC_END)
    return true;

#ifdef CONFIG_WHATEVER
  if (addr >=3D whatever && etc)
    return true;
#endif

 return false;
}

and call that from vmalloc_fault() rather than duplicating the logic.

Also, thanks for doing this series!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CALCETrXW_%3D6sPd8gcdkZtYAmCTYhoOYMYhp6_yVd-8Wd5zYsrA%40mail.gmai=
l.com.
