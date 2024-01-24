Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRUPYWWQMGQEAJIYMSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9606983AFAB
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 18:24:23 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-68698ded8basf33456036d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 09:24:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706117062; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vt6Ny6mHAuQMGCGsXxhL3kyrwcEzzjLgp2ht0NfAtmanvpDNEcjjQ51mCYVZ3PkzsM
         E17Dfs4x++5VuO2dgjiuM1GLqDn8KQR4TJeFNnMnmyAsiVlSqHBraEHbGtq0n1B7IKa5
         QRBRXvmMA81L8/xh9qW7ktTj/rYOMUvrPlVWRk/01SvQ1DDG+Ehho28ly5bQhyAIRxJd
         mjfyu6hjMB5Ixqg7F6qpPJP2rH7IlkKNWlbIZ8YRfUJIEx6iXtRag5r0Yn/Ib/UDxqOe
         1zfM09B1rBgo5kFBwwglFyT15gye5t75ingcNa9zyctE13Byt+dijSylbZwn5XziSVLg
         Vd+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/ObThZI7Ydqq4eVarWOVixIWZWUdBj2J0TwXdeNFQOM=;
        fh=ruJj7QyGmeUMeB+3d5gjmDRoEqn9dh6wnhgHgQc+/l0=;
        b=bBl3Oo8NehM8/p1cTXVMCNk/ipyBjH95Et5y5PEFWReEqnDTLakM5oHR3dDSCw+1iY
         fU4/7mE9dRGR64vCZ5AjAfcLCnqWavfuU+TxhMVBrYy++B+Cf9DrhcFjZW1AcgI6C12a
         sjNS4YGj3bJ5q5SU24sOP85Tf8NxF1DXgYCfFJKqtNttZ86u7wg8IpmZXkcAXyLqaPtC
         ZNfuGetfA05sHuopwZRohAezer0azRWHMJsi9P00I84feCn1WBJmPlPPljY0bugduYxF
         KUMrJ8jq0RQwxIlZ7JtEvdY5TL3o/MTahIkEzTogZndtJj8nM1XH2RUgFH3ZDdx1/p5K
         w/+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fV3tx2OG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706117062; x=1706721862; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/ObThZI7Ydqq4eVarWOVixIWZWUdBj2J0TwXdeNFQOM=;
        b=kFXpkxzOHuamnEP3exfgXuKbjLgImC4Uoo+0B1l8dcowJObJtDdlIB7RBRQwG2Inkl
         5O/8KYpgqLK2MNhV4Uk/b2l8jBlepZmMpv7u8azVstekTPU6eBT/UsLRsLfQyc0gqrOU
         357t8x30Qio09GEF4KlUZymOG9A936SzTTsvV3gVo98xtandKAy447f1qERoNZqo3W+h
         FJPSEYMeA5GJwCz/D1TJ0sZzQBsHUDIgZCUUDL01l4rdewodhz/g3xxtt966cYhxCHAn
         zxFCuiKeI3UZ8pvz5N5xg6mSs4HcGXKyF0hHpI9hmUXSyj7Bp4pXdsruDKBbxDNQ3mkn
         Ge4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706117062; x=1706721862;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/ObThZI7Ydqq4eVarWOVixIWZWUdBj2J0TwXdeNFQOM=;
        b=FBXXV1Ls+t4lXzIW0SM/oMVQdYiCyOhIy9DvwRzPWmVyZxg+DFb/BC3IuZtMp8Eh0i
         Ngt/RpHNWecWIoG089XEayMzvHQ/homeSTEHm2r4Z/+z3GHoB1RauNFXNQ1ZRoHYDVRL
         gBmvEz+1YdFaitLvHrojm+hLSxqQXzLFIl39cyX4ayFvVGwfsLIDCGQAzJQA0FH6yNyL
         mm9+iGly/AgzwuMSpXhx/XRibjfbUFlD+OHx4UcAfg4LslUtEUx12hfAOZYgvqjTrXCl
         P0G8IaiYZUPCKbVHc7uyufpGAzkMzOll3vRearIQZ23pyx3HjaS2YQPS3rAl2NmSOAz9
         eCBw==
X-Gm-Message-State: AOJu0YwPB67FX68s56HsQ+AqiEs6WCKuSMgbSUvg9zAz1Fk0GIbn3W2N
	QZfHB0YfxsaOWmIYdIkGoytWvB8HHEfY1B1uitk3aEx8v0mvsAwS
X-Google-Smtp-Source: AGHT+IGTuF0IasXoItr3iuIc0vd3B0d0P8XBRDehXcLbzphAIctndvY2m6mSBJHNeqyf9Oml1eV9vw==
X-Received: by 2002:a05:6214:c82:b0:681:781f:6781 with SMTP id r2-20020a0562140c8200b00681781f6781mr3900841qvr.1.1706117062180;
        Wed, 24 Jan 2024 09:24:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b3d2:0:b0:681:993a:b34 with SMTP id b18-20020a0cb3d2000000b00681993a0b34ls1190861qvf.0.-pod-prod-09-us;
 Wed, 24 Jan 2024 09:24:21 -0800 (PST)
X-Received: by 2002:a05:620a:a42:b0:783:926b:a12e with SMTP id j2-20020a05620a0a4200b00783926ba12emr8512402qka.21.1706117061581;
        Wed, 24 Jan 2024 09:24:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706117061; cv=none;
        d=google.com; s=arc-20160816;
        b=uGdvofoRSQCzV+qVihybkJLwrdBXvCzkzZZRXYFkw8+0LgKQbqk31eP/CTFLnb2DiO
         Ql67Td5A0ZgtTOhiYHzJ+n4ax5MNDxN1nmYSz+bipvi64F6v8WeiPLQx53wCBeUGnirZ
         cpuuZFcKb1+4fxabcX5m668W0+cvhkjjWJwhQVBUQm24dGXCp/Ns4q81SbXPU8BcMpl0
         gilZP5cpxDQPD9d0xKCM0GHnEPRY15B+ZCL9oMpshedbBmKpsURpUuc0eWk6U4H/ng/L
         4tNZ+MCxaylMhSSTdaeXO0YscgoF/c6qmzYlCtOszUfqAUBDS6cuu4Hd5W6/3Kh7Ewli
         DtTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cSxEs95VFilTX9ZMn4g3/pmadRUIIAuhSiude60Z10U=;
        fh=ruJj7QyGmeUMeB+3d5gjmDRoEqn9dh6wnhgHgQc+/l0=;
        b=mkn5DAW7DKJQi+6HMAt/JbwTxsZWtO/w9L3UjI6RHeqbVDT8i4M7ONgaVmoXjbZx2y
         Xy0t4Za1NpvOS4J4xilxUAmYru89ogvkinKlKIDfTZK5p4LQ/JlIWjKNwVmGb4ZRZRq7
         L/MNGs5FneC7QwampqrTZMLYP87uVMS7LZfYxuuyefcKlr9B/4gPGM+yOty9MuWueXDV
         PXqH65ydK/97+iybSyMFOBYTM2FJGQK0L4TxoJzmfpwWYgLcugLrPF+v+sqLdUmPHo83
         FUt6adAm0b+7gqq3nQhGO+i9yrjbNe2mSefF2zaKV/RzXE1OrBLCDqca5X20ESZjV8v3
         ycRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fV3tx2OG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id rq4-20020a05620a674400b00783b77c39d2si71305qkn.7.2024.01.24.09.24.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jan 2024 09:24:21 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-6818d263cb3so41708736d6.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Jan 2024 09:24:21 -0800 (PST)
X-Received: by 2002:ad4:5dc8:0:b0:685:55d:18b5 with SMTP id
 m8-20020ad45dc8000000b00685055d18b5mr3888783qvh.84.1706117061161; Wed, 24 Jan
 2024 09:24:21 -0800 (PST)
MIME-Version: 1.0
References: <20240124164211.1141742-1-glider@google.com> <CANpmjNP-9hV_d3zEHhUSpdUYpM1BAFKmTTzWwe5o5ubtwTvQAQ@mail.gmail.com>
In-Reply-To: <CANpmjNP-9hV_d3zEHhUSpdUYpM1BAFKmTTzWwe5o5ubtwTvQAQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Jan 2024 18:23:39 +0100
Message-ID: <CAG_fn=Uy_h6YnQYdncewoUeOd4TutsRVygbHK5-qwn+zQYCvPA@mail.gmail.com>
Subject: Re: [PATCH] mm: kmsan: remove runtime checks from kmsan_unpoison_memory()
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Nicholas Miehlbradt <nicholas@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fV3tx2OG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
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

On Wed, Jan 24, 2024 at 6:15=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Wed, 24 Jan 2024 at 17:42, 'Alexander Potapenko' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Similarly to what's been done in commit ff444efbbb9be ("kmsan: allow
> > using __msan_instrument_asm_store() inside runtime"), it should be safe
> > to call kmsan_unpoison_memory() from within the runtime, as it does not
> > allocate memory or take locks. Remove the redundant runtime checks.
> >
> > This should fix false positives seen with CONFIG_DEBUG_LIST=3Dy when
> > the non-instrumented lib/stackdepot.c failed to unpoison the memory
> > chunks later checked by the instrumented lib/list_debug.c
> >
> > Also replace the implementation of kmsan_unpoison_entry_regs() with
> > a call to kmsan_unpoison_memory().
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Ilya Leoshkevich <iii@linux.ibm.com>
> > Cc: Nicholas Miehlbradt <nicholas@linux.ibm.com>
>
> Tested-by: Marco Elver <elver@google.com>
>

> missing ')', probably:
>
> +       kmsan_unpoison_memory((void *)regs, sizeof(*regs));

My bad - you are right. Thanks for catching!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUy_h6YnQYdncewoUeOd4TutsRVygbHK5-qwn%2BzQYCvPA%40mail.gm=
ail.com.
