Return-Path: <kasan-dev+bncBDAOJ6534YNBBD4W4HCAMGQEMNTFURY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B314B1F8DD
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 09:32:33 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3b785aee904sf1495316f8f.2
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 00:32:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754811152; cv=pass;
        d=google.com; s=arc-20240605;
        b=eNu1tby1RjH7r7BRxdCHkvHE+/xf/aHO7VODuKC4mg5G+OlAlxhCco5/SktmB+NH+U
         qcnSU55ArS9Ri8LRvJEWplO3QsTslJoWIW6vhqzlSkZmbc9Eygz3Tkib/z/6ITDjH7Ab
         /LWuC1teGcPSyGG0FLEMmqZ+ww3CkfLlz68IXbGaDBwD+OYOApjE2dgA7ytJSHL1BwU7
         02S0ivPrIrLneLManmJK+SDirhoIq/esPZ61iULDvC88t4ifuTFuQ68hcX/UTl0WcFxs
         2hsTCyDl3N37fwLQqYu7Iz0hc3Ha5EvH9Li3ZkPr5YfGeB6X+jJAspvxoSTnJW+UfcT1
         LXiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=94sD3M67djaJHcAXBKfSqcx3c+5yM+vs/cdMFf6DXYA=;
        fh=LlQM0Lyt5c370ku0S6AKkjFIyWF5WD3cXwb01nHG/gY=;
        b=Ib009fDnvvO6iwM6XODiPsddAdgGKNuJOO3HgiSv9qWHjvfm4TNE+fyjcc0mQrVRCf
         IWa7BXJMm6KMXKEWBc4mfubtpNjFxKXD2UkA6aw7rgnIMJja5v0BFN3yWp4wsk0I0ZR2
         c5ntxn/hAoJNyITkp9rXP6R85/4lLCIpWFYaxKaUfBh7C9d3xkcAvvkRz5vyVFrUhQiU
         4YU1dlIvJtpk8kPDTxjDkuUhlH7D0UxRJIjnK7m4TI10RaWxKzgkCuE2Tpm1JYFPr8DG
         MtuRkp/sy+UcQYUEvXYKqvFPqjS0AY5pTPo0xuCItgoJIhea09g2pAFkD2bijzgt/QXd
         KFeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PVpQVPmt;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754811152; x=1755415952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=94sD3M67djaJHcAXBKfSqcx3c+5yM+vs/cdMFf6DXYA=;
        b=sX+RT+GWjccm6Z/Yvc5jnCI6x1eQmoLOTJjwoeUe1ZJDqrK6yuPUKI2yUaaCXTXT4q
         EbferESFKnV4rm3DJYcYEsOHHYPHLURwx4aOXP2LbStKK7MIcyKi+yLVIXX18vdD8QAs
         LI3xFvUFQV1+FLTTD8l8zdPq23CF/8szBGUZeFKV6HR5FMNyx+t4HwyzhGqASTRHzrrW
         RR408QC+DdR8avpCq7c3/6e78ygMz6bFpSiSQ5Sr1zk8pytqQKW6rzfXrcKBbNABpt3b
         34wXcwi1OzLTnu/LS9iz3PIw2rbiChYXDPR71g2EEPxed3bz3PYAqMDDlbRT4sr3ES+E
         i4uA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754811152; x=1755415952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=94sD3M67djaJHcAXBKfSqcx3c+5yM+vs/cdMFf6DXYA=;
        b=k1TA5MeGBABzsdg4HN3Ht/liJJdfm5OKmbXPmitTgIOseZul/6rIrjiWklIC7dwTzl
         hXgs+H+X+LsMd0DlF1CycMUi0YUz9yppe1dYKGN6DQ8f9l+NdAlGZnucGvy0X1GlbARf
         LX4d8gB+0j6QARsk6jnkb61VKIe+IFqaUKCpinrvALBmnpsB0Qq21gEa91N0zuP3zp2m
         eGNijjGLVw4kyOXKLPGMmdy7SgVKISW7tSEgDuMFBHxpSPxMdpvEcPg2URmbjYDDaUNM
         fvY+lQ/lmXUeZ+W0yQkbnziYv1EAlWXeBEIdRhTdrhE/xKehTWFrEkwfatrcjfAtP7Zk
         WgGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754811152; x=1755415952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=94sD3M67djaJHcAXBKfSqcx3c+5yM+vs/cdMFf6DXYA=;
        b=OxBR+0EeZqiruQUj852tAxPsth2+OCzDHmmh9IKHHWrQzThQJEVv2cDudWMPErkUWi
         +YYPcpWUzgzK8xuL3pv5uXbD/NgnMVgGWk7GYeBf3lKY5m2ihMRy8f8/0bN862SZO3Rx
         XfBKoZvU8Cueit1fXFoCGKliNk9ruhW8qmomGopOE9KjZ0zRPkbHDVaa6fsQCRhQjwJJ
         IpnGvdN1QTcyIr4hFZEKuXcyFVM52iLi0C05UB4mKa9tTSW0ZW5VdwLdlX2v7Q4MR3oz
         Gh7I/KxZ+3Tt22pVMoj9+bsm7aXM4aQVj7PsZADvpFGX4J/wYKl4sUDiVmzdW+o8fi6u
         tOkA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUv67/2IJS50gY58xAb1SdiPVFjvtQbnoToo5Dm7c7Ry5vJvRzFtoUOLVPyn6d8pOvjotNt1Q==@lfdr.de
X-Gm-Message-State: AOJu0YzOrgphoSLYOB+A7DuM0yeeXM2JOqxuEjwJu8gAS2D5TDqIW2AF
	ymINuVD4XBe/P072pqlhWSXN84cwAyMX4OBhdMat0xU4NoUhGbp8Q+Xr
X-Google-Smtp-Source: AGHT+IEZEJaDavQLxqaEugJbwRSbqz+eBOibxXSOq//3MD5wFdqkIr/GZtzhRAR9lv0y3MykRK7AAw==
X-Received: by 2002:a5d:5848:0:b0:3b8:893f:a17d with SMTP id ffacd0b85a97d-3b900b511b8mr7365776f8f.49.1754811152258;
        Sun, 10 Aug 2025 00:32:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd+PRTK3COlZzoHvQJd3bdCgNI2lq2kE5HN4RloXkwcXA==
Received: by 2002:a05:600c:43c5:b0:459:ddca:202d with SMTP id
 5b1f17b1804b1-459edcf9cabls12600395e9.1.-pod-prod-01-eu; Sun, 10 Aug 2025
 00:32:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6WYzUm4m9wO0Q44XxpIYRIWs1dEXyHGMH8ItQaHmNbLxB37Cm4p0+hROcUlpewVbVN3y3OvJpTu4=@googlegroups.com
X-Received: by 2002:a05:600c:4e86:b0:459:db5a:b0b9 with SMTP id 5b1f17b1804b1-459f4fb05cfmr68886945e9.28.1754811147467;
        Sun, 10 Aug 2025 00:32:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754811147; cv=none;
        d=google.com; s=arc-20240605;
        b=h19pyx9MFF0GqN14m4MIOUlB4Q4UWIhWMeCsVbIY72hF6LYto34ijpLLFD2Ar7yzm0
         LCanV3T2G/QU057V5h6A/TL5jFpzgLDTZg73n1iJa8wzLMCvu1rdfKRHpJtLnbZisHAP
         eichUjzGMJWcjileU+4lhnkqO/W9Q5aABvGds6FI3Zglx6HaAhAmHsIk4+ZsIIHEDtcu
         8TEHLNpgJOALwxTlG8a9APFkewigft60UyYMM1wqV4qQEfQUvMcQpS0QnnbUN3rKAMtV
         0t+78wA5LkFIzISIdTh17enAu7QrvuX+cZsvYPlDDKevLALpPAjPaFmLXNxrtuy7bECq
         +m/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=to3a2j5jgrrDRsoCDy9JGxvNqhRLdP/C+mURmWO4ysI=;
        fh=05GUflQM4G7HXb1Ofk3kgoeehIQOZnXVx9IxKWyQg/k=;
        b=TS7IbYtgjA3hztQEHh0XOxW9F1BJJGXR8pgTMuwi8J98rfFWKJT0wP+oMY49Eq9Uhs
         NkfePDIGxLwmk70fGjkQ1OhFcHnm03hZLg96FLrI/6tpbmG8I+f6QlgA8H/8tNPJzj3C
         XIQc29BhY9aGYq1/x6pxlzUegAtkRfAy3yQQuLye2b7mIgtlgCas+K+g1JCp7DMsSVx/
         fShB6HYynWUXjVllJJlfmgncokOlEegznwNGDMCdVWiu5+SuazGet3/HqwZr7hZfTcpt
         GlnSV147ozYqJK2ikqL0BZaiSBnpUhv3Pwdo5C546Z0FqaPQxoz+c1AdtUoJW7bXkFAQ
         YqcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PVpQVPmt;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-459eea5156asi1641315e9.1.2025.08.10.00.32.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Aug 2025 00:32:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-3322a34e84fso30214091fa.0
        for <kasan-dev@googlegroups.com>; Sun, 10 Aug 2025 00:32:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUywTU35CNFm2QB/PqtFTKP2jrWsqMlNciK0MTvVXQ4WSIpkmpHWXOXT9X8icI+i9RB6PcMajdzRU=@googlegroups.com
X-Gm-Gg: ASbGncuNQfkRaR2H7NXOje4TT9WebZ1VJhqjqnU7irdD+K6PejB/qD7bWWspLqaQvPJ
	KNCoYmqK9v5ZHC8jjrSy6N7DJPGOhqtHi9b2C4nxLvU+GGnNsBrr7wegdCAnTDuclxCieeeT6FF
	cnWUX9cJ7wvqsWTUul1FI+UXZPs+ZotK565MV1eTL7UMnGBupTX1qmqLRhFZFhuUDiSrBNtg8b6
	wJ+ZgeMWIgK1botNdG65vEWlIBg4jJCcAvI6tX0UCdO7fx9ig==
X-Received: by 2002:a05:6512:1052:b0:553:2480:2308 with SMTP id
 2adb3069b0e04-55cc00eb7eemr2065404e87.21.1754811146600; Sun, 10 Aug 2025
 00:32:26 -0700 (PDT)
MIME-Version: 1.0
References: <20250807194012.631367-1-snovitoll@gmail.com> <20250807194012.631367-2-snovitoll@gmail.com>
 <22872a3f-85dc-4740-b605-ba80b5a3b1bc@csgroup.eu> <CACzwLxjnofD0EsxrtgbG3svXHL+TpYcio4B67SCY9Mi3C-jdsQ@mail.gmail.com>
 <af677847-e625-43d7-8750-b2ce4ba9626c@csgroup.eu> <CACzwLxjr+Z+xUj-936rcWDSqEwfUP7bRB1xcqZQKGE7ux-gEXQ@mail.gmail.com>
In-Reply-To: <CACzwLxjr+Z+xUj-936rcWDSqEwfUP7bRB1xcqZQKGE7ux-gEXQ@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Sun, 10 Aug 2025 12:32:08 +0500
X-Gm-Features: Ac12FXzPCnTCatZw8a7ccc080L84VXsdNPtKeE-8RXfhfS3owZfq0geCNjkMt-Q
Message-ID: <CACzwLxi5AKT_81ej4AZ1ztsncBDY4jDJCyWboF0X9-kiH_=NMA@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: ryabinin.a.a@gmail.com, bhe@redhat.com, hca@linux.ibm.com, 
	andreyknvl@gmail.com, akpm@linux-foundation.org, zhangqing@loongson.cn, 
	chenhuacai@loongson.cn, glider@google.com, dvyukov@google.com, alex@ghiti.fr, 
	agordeev@linux.ibm.com, vincenzo.frascino@arm.com, elver@google.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org, 
	davidgow@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PVpQVPmt;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232
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

On Sun, Aug 10, 2025 at 12:20=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> On Fri, Aug 8, 2025 at 10:03=E2=80=AFPM Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
> >
> >
> >
> > Le 08/08/2025 =C3=A0 17:33, Sabyrzhan Tasbolatov a =C3=A9crit :
> > > On Fri, Aug 8, 2025 at 10:03=E2=80=AFAM Christophe Leroy
> > > <christophe.leroy@csgroup.eu> wrote:
> > >>
> > >>
> > >>
> > >> Le 07/08/2025 =C3=A0 21:40, Sabyrzhan Tasbolatov a =C3=A9crit :
> > >>> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures [1] tha=
t need
> > >>> to defer KASAN initialization until shadow memory is properly set u=
p,
> > >>> and unify the static key infrastructure across all KASAN modes.
> > >>
> > >> That probably desserves more details, maybe copy in informations fro=
m
> > >> the top of cover letter.
> > >>
> > >> I think there should also be some exeplanations about
> > >> kasan_arch_is_ready() becoming kasan_enabled(), and also why
> > >> kasan_arch_is_ready() completely disappear from mm/kasan/common.c
> > >> without being replaced by kasan_enabled().
> > >>
> > >>>
> > >>> [1] PowerPC, UML, LoongArch selects ARCH_DEFER_KASAN.
> > >>>
> > >>> Closes: https://eur01.safelinks.protection.outlook.com/?url=3Dhttps=
%3A%2F%2Fbugzilla.kernel.org%2Fshow_bug.cgi%3Fid%3D217049&data=3D05%7C02%7C=
christophe.leroy%40csgroup.eu%7Cfe4f5a759ad6452b047408ddd691024a%7C8b87af7d=
86474dc78df45f69a2011bb5%7C0%7C0%7C638902640503259176%7CUnknown%7CTWFpbGZsb=
3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFp=
bCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=3DUM4uvQihJdeWwcC6DIiJXbn4wGsrijjRc=
Hc55uCMErI%3D&reserved=3D0
> > >>> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > >>> ---
> > >>> Changes in v5:
> > >>> - Unified patches where arch (powerpc, UML, loongarch) selects
> > >>>     ARCH_DEFER_KASAN in the first patch not to break
> > >>>     bisectability
> > >>> - Removed kasan_arch_is_ready completely as there is no user
> > >>> - Removed __wrappers in v4, left only those where it's necessary
> > >>>     due to different implementations
> > >>>
> > >>> Changes in v4:
> > >>> - Fixed HW_TAGS static key functionality (was broken in v3)
> > >>> - Merged configuration and implementation for atomicity
> > >>> ---
> > >>>    arch/loongarch/Kconfig                 |  1 +
> > >>>    arch/loongarch/include/asm/kasan.h     |  7 ------
> > >>>    arch/loongarch/mm/kasan_init.c         |  8 +++----
> > >>>    arch/powerpc/Kconfig                   |  1 +
> > >>>    arch/powerpc/include/asm/kasan.h       | 12 ----------
> > >>>    arch/powerpc/mm/kasan/init_32.c        |  2 +-
> > >>>    arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
> > >>>    arch/powerpc/mm/kasan/init_book3s_64.c |  6 +----
> > >>>    arch/um/Kconfig                        |  1 +
> > >>>    arch/um/include/asm/kasan.h            |  5 ++--
> > >>>    arch/um/kernel/mem.c                   | 10 ++++++--
> > >>>    include/linux/kasan-enabled.h          | 32 ++++++++++++++++++--=
------
> > >>>    include/linux/kasan.h                  |  6 +++++
> > >>>    lib/Kconfig.kasan                      |  8 +++++++
> > >>>    mm/kasan/common.c                      | 17 ++++++++++----
> > >>>    mm/kasan/generic.c                     | 19 +++++++++++----
> > >>>    mm/kasan/hw_tags.c                     |  9 +-------
> > >>>    mm/kasan/kasan.h                       |  8 ++++++-
> > >>>    mm/kasan/shadow.c                      | 12 +++++-----
> > >>>    mm/kasan/sw_tags.c                     |  1 +
> > >>>    mm/kasan/tags.c                        |  2 +-
> > >>>    21 files changed, 100 insertions(+), 69 deletions(-)
> > >>>
> > >>> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> > >>> index f0abc38c40a..cd64b2bc12d 100644
> > >>> --- a/arch/loongarch/Kconfig
> > >>> +++ b/arch/loongarch/Kconfig
> > >>> @@ -9,6 +9,7 @@ config LOONGARCH
> > >>>        select ACPI_PPTT if ACPI
> > >>>        select ACPI_SYSTEM_POWER_STATES_SUPPORT if ACPI
> > >>>        select ARCH_BINFMT_ELF_STATE
> > >>> +     select ARCH_DEFER_KASAN if KASAN
> > >>
> > >> Instead of adding 'if KASAN' in all users, you could do in two steps=
:
> > >>
> > >> Add a symbol ARCH_NEEDS_DEFER_KASAN.
> > >>
> > >> +config ARCH_NEEDS_DEFER_KASAN
> > >> +       bool
> > >>
> > >> And then:
> > >>
> > >> +config ARCH_DEFER_KASAN
> > >> +       def_bool
> > >> +       depends on KASAN
> > >> +       depends on ARCH_DEFER_KASAN
> > >> +       help
> > >> +         Architectures should select this if they need to defer KAS=
AN
> > >> +         initialization until shadow memory is properly set up. Thi=
s
> > >> +         enables runtime control via static keys. Otherwise, KASAN =
uses
> > >> +         compile-time constants for better performance.
> > >>
> > >
> > > Actually, I don't see the benefits from this option. Sorry, have just
> > > revisited this again.
> > > With the new symbol, arch (PowerPC, UML, LoongArch) still needs selec=
t
> > > 2 options:
> > >
> > > select ARCH_NEEDS_DEFER_KASAN
> > > select ARCH_DEFER_KASAN
> >
> > Sorry, my mistake, ARCH_DEFER_KASAN has to be 'def_bool y'. Missing the
> > 'y'. That way it is automatically set to 'y' as long as KASAN and
> > ARCH_NEEDS_DEFER_KASAN are selected. Should be:
> >
> > config ARCH_DEFER_KASAN
> >         def_bool y
> >         depends on KASAN
> >         depends on ARCH_NEEDS_DEFER_KASAN
> >
> >
> > >
> > > and the oneline with `if` condition is cleaner.
> > > select ARCH_DEFER_KASAN if KASAN
>
> Hello,
>
> Have just had a chance to test this.
>
> lib/Kconfig.kasan:
>         config ARCH_NEEDS_DEFER_KASAN
>                 bool
>
>         config ARCH_DEFER_KASAN
>                 def_bool y
>                 depends on KASAN
>                 depends on ARCH_NEEDS_DEFER_KASAN

Setting Kconfig.kasan without KASAN works fine for 3 arch that selects
ARCH_DEFER_KASAN:

config ARCH_DEFER_KASAN
       def_bool y
       depends on ARCH_NEEDS_DEFER_KASAN

Going to send v6 soon.

P.S.: Fixed email of David Gow.

>
> It works for UML defconfig where arch/um/Kconfig is:
>
> config UML
>         bool
>         default y
>         select ARCH_NEEDS_DEFER_KASAN
>         select ARCH_DEFER_KASAN if STATIC_LINK
>
> But it prints warnings for PowerPC, LoongArch:
>
> config LOONGARCH
>         bool
>         ...
>         select ARCH_NEEDS_DEFER_KASAN
>         select ARCH_DEFER_KASAN
>
> $ make defconfig ARCH=3Dloongarch
> *** Default configuration is based on 'loongson3_defconfig'
>
> WARNING: unmet direct dependencies detected for ARCH_DEFER_KASAN
>   Depends on [n]: KASAN [=3Dn] && ARCH_NEEDS_DEFER_KASAN [=3Dy]
>   Selected by [y]:
>   - LOONGARCH [=3Dy]
>
>
> config PPC
>         bool
>         default y
>         select ARCH_DEFER_KASAN if PPC_RADIX_MMU
>         select ARCH_NEEDS_DEFER_KASAN
>
> $ make ppc64_defconfig
>
> WARNING: unmet direct dependencies detected for ARCH_DEFER_KASAN
>   Depends on [n]: KASAN [=3Dn] && ARCH_NEEDS_DEFER_KASAN [=3Dy]
>   Selected by [y]:
>   - PPC [=3Dy] && PPC_RADIX_MMU [=3Dy]
>
>
> > >
> >
> > I don't think so because it requires all architectures to add 'if KASAN=
'
> > which is not convenient.
> >
> > Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxi5AKT_81ej4AZ1ztsncBDY4jDJCyWboF0X9-kiH_%3DNMA%40mail.gmail.com.
