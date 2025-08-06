Return-Path: <kasan-dev+bncBDAOJ6534YNBBLVXZPCAMGQELVO6IPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id E1149B1BF9A
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 06:35:59 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-61598e5e8a6sf5542926a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 21:35:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754454959; cv=pass;
        d=google.com; s=arc-20240605;
        b=W66DHvdmekW86NXn8+QcmMsw8S43Zd73Cq9GCOk8Wlzre496yvcpw5Q2aLjnIIcSn4
         Kzzp2HvHJFUN01osw+rUnwUjdAomOVM6fi4MEqoW6b9ItBQsfay0sSdm8Yi/nWk1vg+g
         u4G25kgNXdfOB9x1veNGrgUAjCskA2foqIngpWL2QdBxaSUnjbprE4Al76zRnHt0kL9K
         m0kv778+1pZkKMdXKAcdlwQk8/GDV7WYERW2osYbaSwwWBqtp0gtc5akOFxZrGHAatBq
         KpmGgCvOhvbJIK5HqTp4u15mcSs+R8TVUYo0sE/IzPisNep5fEKrVsEYgguLjR7AcVjT
         U42A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=FX7VnAg+sPw15s9icfXQVOvs3OUAYfSJQeyZE2AFKOY=;
        fh=6HexHXUD4HSp/H+qMpmRL79aT/yzneTkkjUqVPJgkI0=;
        b=PdwMQ8WQ0bWkXqipH/PI/6IFg+B9B87afw4GL65GfohpjNlxfkG9xZ1dQ8WiGBeauL
         06BdRFbZHxl8hmhh+r7QBW8NJ6sXYnaR9W7k+/vJEMB7tUk2QmemHZ8xnHbHMfP4wv3T
         p+SW2XJJKenfoFRcnzlgQsPACgXhWWWsx4WpGWPejUBYhvw47S5gP523d6GDDhqeEZcl
         UfzgNNtElte0dXk4FRDKc9Ho7qYV1lXzbeo/WqOoDYntVRA2E5uv/UbTzBgnxDibllri
         X3U1JHzS2huOWULJ518eC87ugO2RWSSrEvPVTHT9w/oaliZ/4PzB004Wo686YJ2Ri99a
         slAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=C4lA7E4K;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754454959; x=1755059759; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FX7VnAg+sPw15s9icfXQVOvs3OUAYfSJQeyZE2AFKOY=;
        b=KiAkJL+E/PmCNkPvAT2KI74nbyfVVGbTY8iT/lZEf9y0MllHjbH3iAerNB7Zp77hWy
         wqJN9Xm6DEuaUJGHr6MaRZM7N+knJ9xoUQ8uYhsqLuCik25fXliNdv6T1/aaaHfYHyq8
         sOd+EmuANbUtZ62z9CNRmw5uPrR2myvsri11GLljxqMp1k6Cmim4W+QhlhorptirA0Bl
         I0Wnf7MRyjWQX+gMyaRllUGmdic5ur4wnG+lsr1XS9zWmH7ysPyuTHdHwzYmMwWX/FVn
         YevNuoQ+ROUL7laCS3YeSWUx/f4IO7fyaXbBwHeMKQ7XzzggWF4V2oBB/OKPy2vXcMM1
         iGrw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754454959; x=1755059759; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FX7VnAg+sPw15s9icfXQVOvs3OUAYfSJQeyZE2AFKOY=;
        b=aoJcp8FekBl1bVfB7+wgMqhbzy8fPKI4yXrqR0+8U+pCe5bSBLkHQF55OKSIQBKgC5
         v1Y8x3NCLwP0YcGyab1f8JjMc1o6HcpScUMSvDHCDgyQMmS5kEdXJl5Ia7Gb6tcmTMXu
         5tm/+amevdiEhdDYMSsPEDLdcde+laPJwL+b57MF1dMD3C6tG3XnPHzwyMl8UXReQaQ7
         vvUgMnrL5za62B0gmIVqopLNr3eIleC4GplmkV+BYXpPYpCRu176PWU6WIUZuR9hegJP
         GugfKIVWwnbhK0H9tG56hGR1B7awLgT2KO79pVg3o9aREUgfV9mYnklzJIdTMNDDPl8c
         bo7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754454959; x=1755059759;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FX7VnAg+sPw15s9icfXQVOvs3OUAYfSJQeyZE2AFKOY=;
        b=SimR0c5xIZsSKk+oFSLyaYrn16ezxYP+kwJWgHzzKpcxInLGx2NkSGlZ1JRYVQsns5
         OkcuX1F5CzlEnjue8eHQ2SKUUNAKG21v8iq/0Mc0O0mca/dLAwtmn2GisDQ+jab0jp4E
         wdyRr4fOtySk5CIRfAW+wmJ2lvZeVkzQE6J/c9Mj42PpwsihA3uPw9+4r7V9AAGOdtdT
         Vlbzn37VffDmOil/49Py0+OS4dhhW+oLuzbaPmm4m0+p9uBUd7At223PlBHkF/Dm5j4d
         O6MJaq3b18wBe00lV86Wy22ihLH6H8NkO4g2Gk7PTj7chNGpYnNVwbQruB940TqBRkwy
         Kr2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWNpHHJ9yjcGJRniK9gccExs8QOZUGYDqjKqZnaoGb+02BVyhxPkO17QayytOZxUBs9U3AayA==@lfdr.de
X-Gm-Message-State: AOJu0YzjeML5pbzqlzMYcxON3JKPBUHtqJs3K9WUViAk7ee68yZeDMN+
	3hyXQUMRdclqQZROCCgmCu1vxdXSqhOviL/KqDo0KV19sU8ZGkJyKqEo
X-Google-Smtp-Source: AGHT+IFNpk6n4wxq3cpXmT6GTmhiUSDDGbUFNZ1bWTOez+QiqYm4fcqfP1tbsuW0XuMjwDXfNVTD/w==
X-Received: by 2002:a05:6402:274c:b0:615:6481:d1c with SMTP id 4fb4d7f45d1cf-61797c5cc4dmr957242a12.1.1754454959031;
        Tue, 05 Aug 2025 21:35:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdkF0NcLoE1dnZiMxDgmmlZmV33h+zcWw1BSnJRoo0zLQ==
Received: by 2002:a05:6402:35d5:b0:615:9353:4c7e with SMTP id
 4fb4d7f45d1cf-615a7872c85ls4398596a12.0.-pod-prod-09-eu; Tue, 05 Aug 2025
 21:35:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXaBn1fpRQYN+6rhEjofzxmHgIxA0mSIcpkY4EwAG/jP/mJWh8DaVggOp0+qeieVvDBwnyhEbxJQtM=@googlegroups.com
X-Received: by 2002:a05:6402:4406:b0:615:cc03:e6ab with SMTP id 4fb4d7f45d1cf-61797c5d0b6mr964231a12.2.1754454956187;
        Tue, 05 Aug 2025 21:35:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754454956; cv=none;
        d=google.com; s=arc-20240605;
        b=FFALcKNY7oG+vRSmBDb/U645lhdua5LmL023n/EZBd20YzR/FwTaV+h6Px4UNYjmJr
         E77n9FlS3ZTKYD1vuzVq8tvEqrKRVwTwZQXKKWzMTXnDQbgWVN495XNRvBAjX3vUumvs
         2mYuyZqad/hoCMO53NG8c0nnBWSgrnjqNDHYxMWVV3IZ5rGP7hy+3MOofR0haKsk1eF7
         EystUW6IyyCSTwWNTlw1rHzWyZ6WFgYzdhWixEFwFhBYfjvgJyaHqvvvxRZqM7XZeXQY
         kZ1T11SljdZ2GRxL4rOJRzx0X2FruV16Z43/7gLXMyzGu4Bx3xqX/C3/JzNsFJCIwjuG
         yevg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dyl+4iOlTi/aeKebUp39F24cwHyqM1kxjjt1F2AMIE8=;
        fh=tWOhTuI9vMnnT3lWE89U531HImMg1joQhMOBNUC8JQ4=;
        b=KuU0WhkwTEqdXzZIgsyKj5nnoH2PE6nlLZSJnALv0GUuSMsfDdvQJUmyPWvwIr2gQu
         3B33pedM7VBQXaqnq7LJf18Yp3PgfH4wbMA7KfzxWfuuuqsleqn1y3Z1mZNGZI6JnDeb
         jWOfS8kqLLCqfwTvdivgldB8eohOpzq82F5RYRq5aSMA3kXT8YpE+JPHaEq51d/UNj3g
         gwi0Eo60sUEgI+K5fiNQCLLCLW7ayYh6AAbQnHKWzzBTLCokXTGIDfch4YAr7a/wl3aX
         9X3/4CPtXdX90v3ZcHwc4yTa8GAPI8rQmFbfkaaM0YNz+nWaLGuAy+mwKv/IHIwzA7m4
         CcFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=C4lA7E4K;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8ff4e94si261719a12.3.2025.08.05.21.35.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 21:35:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id 38308e7fff4ca-33243562752so35666191fa.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 21:35:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV9pqR2cDG9+wVs0sBSJCNNlDCGq+SPA7NU+rbK8P1HGlar/J0R7rTuBfJ+/lXku2UPQrGpQWbYxx8=@googlegroups.com
X-Gm-Gg: ASbGncuRC8/qsbW1DWU7BA2GV9y836zKGjp+ceoGtkklGPCORzepPmd5rs2alDnmoA3
	a0NiozUutGZWU47SHFt8v1HNUFq6Lj2mb9+7whPiKWbKoJwTRs1i0rJckGHyD1ncJMm7jns1Njt
	w0T3xhqXP71MXdd9k4O+lv0z6W16tOLYd57tA8z514FRh/onhDC+eD19tWhb36SixKS6Cawnq9d
	fWHL2w=
X-Received: by 2002:a05:651c:f0e:b0:32c:e253:20cc with SMTP id
 38308e7fff4ca-3338128c651mr2551171fa.11.1754454955157; Tue, 05 Aug 2025
 21:35:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250805142622.560992-1-snovitoll@gmail.com> <20250805142622.560992-7-snovitoll@gmail.com>
 <60895f3d-abe2-4fc3-afc3-176a188f06d4@gmail.com>
In-Reply-To: <60895f3d-abe2-4fc3-afc3-176a188f06d4@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 6 Aug 2025 09:35:38 +0500
X-Gm-Features: Ac12FXwBfBQD8yoFidSr60fw7LigvE8ZBweRU29uoAzLmmdybvheO1FdbNA_5DM
Message-ID: <CACzwLxhs+Rt9-q6tKi3Kvu7HpZ2VgZAc4XEXZ4MEB60UbFjDKg@mail.gmail.com>
Subject: Re: [PATCH v4 6/9] kasan/um: select ARCH_DEFER_KASAN and call kasan_init_generic
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com, 
	agordeev@linux.ibm.com, akpm@linux-foundation.org, zhangqing@loongson.cn, 
	chenhuacai@loongson.cn, trishalfonso@google.com, davidgow@google.com, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=C4lA7E4K;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 5, 2025 at 10:19=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
>
>
> On 8/5/25 4:26 PM, Sabyrzhan Tasbolatov wrote:
> >
> > diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> > index 9083bfdb773..8d14c8fc2cd 100644
> > --- a/arch/um/Kconfig
> > +++ b/arch/um/Kconfig
> > @@ -5,6 +5,7 @@ menu "UML-specific options"
> >  config UML
> >       bool
> >       default y
> > +     select ARCH_DEFER_KASAN
>
> select ARCH_DEFER_KASAN if STATIC_LINK

As pointed out in commit 5b301409e8bc("UML: add support for KASAN
under x86_64"),

: Also note that, while UML supports both KASAN in inline mode
(CONFIG_KASAN_INLINE)
: and static linking (CONFIG_STATIC_LINK), it does not support both at
the same time.

I've tested that for UML,
ARCH_DEFER_KASAN works if STATIC_LINK && KASAN_OUTLINE
ARCH_DEFER_KASAN works if KASAN_INLINE && !STATIC_LINK

ARCH_DEFER_KASAN if STATIC_LINK, and KASAN_INLINE=3Dy by default from defco=
nfig
crashes with SEGFAULT here (I didn't understand what it is, I think
the main() constructors
is not prepared in UML):

 =E2=96=BA 0       0x609d6f87 strlen+43
   1       0x60a20db0 _dl_new_object+48
   2       0x60a24627 _dl_non_dynamic_init+103
   3       0x60a25f9a __libc_init_first+42
   4       0x609eb6b2 __libc_start_main_impl+2434
   5       0x6004a025 _start+37

Since this is the case only for UML, AFAIU, I don't think we want to change
conditions in lib/Kconfig.kasan. Shall I leave UML Kconfig as it is? e.g.

select ARCH_DEFER_KASAN

>
> >       select ARCH_WANTS_DYNAMIC_TASK_STRUCT
> >       select ARCH_HAS_CACHE_LINE_SIZE
> >       select ARCH_HAS_CPU_FINALIZE_INIT
> > diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> > index f97bb1f7b85..81bcdc0f962 100644
> > --- a/arch/um/include/asm/kasan.h
> > +++ b/arch/um/include/asm/kasan.h
> > @@ -24,11 +24,6 @@
> >
> >  #ifdef CONFIG_KASAN
> >  void kasan_init(void);
> > -extern int kasan_um_is_ready;
> > -
> > -#ifdef CONFIG_STATIC_LINK
> > -#define kasan_arch_is_ready() (kasan_um_is_ready)
> > -#endif
> >  #else
> >  static inline void kasan_init(void) { }
> >  #endif /* CONFIG_KASAN */

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxhs%2BRt9-q6tKi3Kvu7HpZ2VgZAc4XEXZ4MEB60UbFjDKg%40mail.gmail.com.
