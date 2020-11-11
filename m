Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWGJV76QKGQECXSSAPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 788E02AF1E4
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 14:19:21 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id f4sf954307ote.15
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 05:19:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605100760; cv=pass;
        d=google.com; s=arc-20160816;
        b=v+QxlagvFku4nUJo0zhpvQmeTLVPZ197bTxPnlDIPuyL3qWMySoTW9LOGeI76BaDcE
         kg1a2uAWsjut/PMPbIrXSWkPwmrGNupJo9xKZu+2H0yCuGOXzJSPULRWV0XJLjizmOWK
         0/jGzN2jJRyKhQpnzZPivIlR1OMGvi5puRrBgkrWD7a5igrjZTK9uTlFwMVukvnr+tcz
         a0xiGM9QRxmAy9++hsgOmlHBRUT7HHLAEfgp1VobVwGPzYiD//OPn7SZzXkfcX/ZekiM
         ToVsWOcLKSmL9lSwvxItlA9ZT8WSGbYVshCkzEIU5t5BCOOrYLDu9mUy7O0pGCGm8rHp
         E8Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VFjgRblDUwUrtnu4bh8S6gbNZsWU29mtF+ycgAhdki8=;
        b=CeOoNaYX85PN583K5jywD8moGn1YIM9sNGvUIj4ZpoqI/RlQ8Oqoj/fzusW//SnutA
         +rsnKi7HHC08j7AHRlct2lMfVSthIkQHYL+Q56qeE55nIJa18iT9X6VBb1njJjeBM0gu
         1iNnEScB4NdAHd7PUaSu1A5SGS/nhGjAfsYVooIyIRmAfWKLbemSfIG/O6RR1G2lqrdt
         P6BI9GX+kvhIa4yhURvajLLG1BUO3YtgXjQ1vphSrd8X+WC7BXow2sqatUlzcQVIsEig
         OoNqS9aKsVHlJQxYyo8eUjytivEF5bcnhzz1l2dbLJm38A0KBIjTbfIibzH3vfZI7aBS
         pjtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iZREhgva;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=VFjgRblDUwUrtnu4bh8S6gbNZsWU29mtF+ycgAhdki8=;
        b=sCxrdoknkUBEIj/WFxH/PY4SeoK6NSvqpSFEuEzz0lhlUg2P2hwHOVNhV8oAcaMMZk
         8i61rGP1ybjC8zrgb+xdAtnfMVxCE5xsnxE1Z2OzTqjc1DnVaJKy63Hoyg8DpwZbVqQ2
         dTfNouoF95Lf1QeVbb92t0aiWvR11trX21WNDzwGe1M5xJcRCBid73uCiTWWrWmIZwYd
         LJ5bgETcT1IBpb69x9CmpwHPHvEgTmP9KgMhNqKGl0+jXSihPcJhiQ7syP6JcacV50Fg
         ZF/5IFSdfaOsdLpV3wUhgR4lM3d6IsUWIGh0iB49ulMC0LPihMr/Y8qNJXqeH+9EZVfe
         X2oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VFjgRblDUwUrtnu4bh8S6gbNZsWU29mtF+ycgAhdki8=;
        b=otxwUlIh7PzjlZpc4RSXAFVdxev4QOT9TzQcoWaryu9hn1rKuKZtmgkkNVKRUTUgp4
         Gx6/mLOohdyHLjMm2nZ0JXhQ//r76fM43oL2KD00YRNyMSizeCiCuC5AvxUOdt34tbxZ
         sqESdBBvty/2BC6pg2L5+2CSKa3LLoMIPbjNtLxoj5IQGTfjsqPT2MFlByKF/na+FGyj
         pHUQW1KGrjAohi9N9IN79xc4Wx2Y3RjdMSk/QG/IqnMT3D1MrRQCFZGQbnoQ4o+k0VnR
         0l9PH4Jgc2K0N/M67Qm5+oeUikKXUOrrZLiJ47nUwLfQ8X8xN31hE/l3iQT6+9LDq2av
         Q+yw==
X-Gm-Message-State: AOAM5310DbhrjE0ZaaAgJokR3LeR2lXb1y83GARwNltz04f4EnkvLqZB
	DJNV+WBNOcOZwjkgPfXhOzo=
X-Google-Smtp-Source: ABdhPJz4BNT1+F3qkOKlafQHZV9GDLVsxiUNxkbLbpFIxIXO94yf2zvmOvTK5KAD32YklMYKG034Gw==
X-Received: by 2002:a9d:929:: with SMTP id 38mr18439084otp.170.1605100760433;
        Wed, 11 Nov 2020 05:19:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:389:: with SMTP id r9ls978724ooj.1.gmail; Wed, 11
 Nov 2020 05:19:20 -0800 (PST)
X-Received: by 2002:a4a:96b1:: with SMTP id s46mr7844281ooi.39.1605100760070;
        Wed, 11 Nov 2020 05:19:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605100760; cv=none;
        d=google.com; s=arc-20160816;
        b=KbCuFfVdzqYsqrJK9Qv4ByURabZI3BjRikTV/pb5/xkR69PvggNkoTgP70JdGsHQZ6
         PneOq8QnuXgTahm26BpNxz4+oHE6WF3GY9sdqp6vL6A60CP+h3KJNMCc1Ai7XNip4GYY
         pDkWMzg9Pdo4AmboWfejBHSvz57TKl16sQwEVSpqeA2hY8sUfzWLnU2fI4k0ZKBiyUV+
         ZwKpqc7TYYhhT2tUcPEa7UzNUBc5EPb6d0pid5mLNTl+pDctxKanOlABXz+BvDH7y3mQ
         8KstdEk3XERxwY+nTGMK2rLdAwDVmUGeITWhIuQ3sHHoAHFMBUQn7G67d+LQIiVJMYPj
         K8NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3ogrn6Kw5lJiQVWMvQTcQ5thm+MqBh+iV3abSct+RxI=;
        b=yJDbuHgMPixxhZgpJUEWZRFP7z33hYqa6LHieNhEHgbcYWO793EEh/epO+EiyeAfZo
         kz+dn2/1eDPe7wHKUBSerVnsqsjTe62ueweO6xvourrRlFWjaFApwp1IVTDZCwp9Esxe
         7ixVIIfal2i1UUqoADkCVwwgHyUhVwDTb4XNKp3kKXeTSODyhk2jvXW22WDCPNibRCQy
         Ruu3c3a2HMwqqij301FNwbvYF7VYHIAUIM+vQHXDetkRjv5bpCvpI7QrbUqAqYMVONiq
         35HA0oewuI8LkvALQOV1/TuWpDOZomxYKEEW52jtZP43TGU+RzQLmlHMfFnDS1NrtQUA
         cT/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iZREhgva;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id d22si192778ooj.1.2020.11.11.05.19.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 05:19:20 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id q22so1554445qkq.6
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 05:19:20 -0800 (PST)
X-Received: by 2002:a05:620a:211b:: with SMTP id l27mr1788572qkl.352.1605100759422;
 Wed, 11 Nov 2020 05:19:19 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <24a25ef0fcfa07a94129e2ae5ec72f829c57ac42.1605046192.git.andreyknvl@google.com>
In-Reply-To: <24a25ef0fcfa07a94129e2ae5ec72f829c57ac42.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 14:19:08 +0100
Message-ID: <CAG_fn=Xg5J0JABbpiHDXMty6=BSHohnaqG3kv9xkPoXEHbMk7g@mail.gmail.com>
Subject: Re: [PATCH v9 02/44] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
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
 header.i=@google.com header.s=20161025 header.b=iZREhgva;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Currently only generic KASAN mode supports vmalloc, reflect that
> in the config.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
> ---
>  lib/Kconfig.kasan | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 542a9c18398e..8f0742a0f23e 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -155,7 +155,7 @@ config KASAN_SW_TAGS_IDENTIFY
>
>  config KASAN_VMALLOC
>         bool "Back mappings in vmalloc space with real shadow memory"
> -       depends on HAVE_ARCH_KASAN_VMALLOC
> +       depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
>         help
>           By default, the shadow region for vmalloc space is the read-onl=
y
>           zero page. This means that KASAN cannot detect errors involving
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


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
kasan-dev/CAG_fn%3DXg5J0JABbpiHDXMty6%3DBSHohnaqG3kv9xkPoXEHbMk7g%40mail.gm=
ail.com.
