Return-Path: <kasan-dev+bncBDAOJ6534YNBBKXCSO4AMGQEBFUDJ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 187FD994274
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 10:45:33 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-5c87a33e5bfsf6694016a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 01:45:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728377132; cv=pass;
        d=google.com; s=arc-20240605;
        b=XzMoY4eca0P8yYGw5Qq8ZMIBWHjpQ05+XJxtR6OK8UfQ+cGxmQUnFddsZ+Cob+aaM2
         OM4lZPQwxyWPv4bnQstbsgcK2V31F8/C+TMuSZM7DKTJx4OeQFzbKy7UXbLV1iAVK9+D
         zFZkbliJ/XEur4EPz4ZhcyP+5NfJFbab5SIawu9+mcNP/4J4I/Y0t7Ofyewu+Q0pnGAw
         ONrlrrvOhN9xOfThHgfHbRbTzBbY15oKDNl0TCoRcTRJrTSkqjutuZUmrYpW+3c0LF3q
         36nkgdswUQwrfQSms3sTom1LwInyFr8GklSR0U2rDK9bHuZ+zExRd/M8xZva2ygZGSay
         NFDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=uxeDKrqqPgYcLZP/1dUzYL1jpgE25KJLUHDFa85T6XU=;
        fh=z0Lxxff88rioko8O2gyoGBurljRGy6xwcE1qwdfiSfo=;
        b=V/SIvD562WGi38Bg7x4lMJDz32g5HnSggfipiZalQBKd+xJKt0Ao8ABWcEeRcR8npD
         CUKE7swELJmAjUrBaAYeO1Nkc8E9DpKcoBKe6rObin27fmJJdcY9FbYYIl2V4VP1Ie92
         d+GoRcwgo6rpujcrHIPkW3Nu3nmbyU01vMy6PKK6+Md8s1DZwMCHNhKVi1azPakyAjLS
         NCD6WLFcib9CVeDCnnhvHAGjJrzDxH+XXzMl6EQJnlpSQGt4bLsyLXhrjPs/cGNE10DA
         QdkwxHdRj46bE70NDEfEJZ3B0ymgf4UO9TnGC/mYzP9r7gwdd2i+gzs3SFJXAiFYEA0R
         RCLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="inw2hY/p";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728377132; x=1728981932; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uxeDKrqqPgYcLZP/1dUzYL1jpgE25KJLUHDFa85T6XU=;
        b=Qeia6XCJZY0hgK6aH7vO9RNodBZLvp1Xl1iTqCrIojmwLDfcfp+4s141YUYGEUGeug
         pV95tuu2dGJGt8Sjf/Nq79H+GPZveKP1+jsBTjluJDdvTjKaC7BTbrp+ze/E7vKkUuoZ
         aFToOC/KENIM9oe7CHxsKlg/OKUpLOyEpxA4A4CuOriSfLmbWNc8J2+UCVLXWha03WUp
         hH2X/zRqvpf0D8czS0snK/aMsNULdTsjcvVGWDyvE2AnsQi1pur4zeLwcGBC0bb5Zpfw
         AxxkQYx6tPvPx9GRisHf5jMigYtDgSNXdhJae6JtTFJIha7UCxbqm4iIgv3WKsRwvXW7
         ePEQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728377132; x=1728981932; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uxeDKrqqPgYcLZP/1dUzYL1jpgE25KJLUHDFa85T6XU=;
        b=l22+rDSn4oktIP32u51eBjqI6cytM2sDXAf3hY+/opRp62rlg5rZZh4Gv52pw1ju6D
         tabt6iGZhAAvXHGnntFsCnPOHz1hEI5XMKNKSrxl27Z4OqqQqO5Ai4ZouN7D5EZZsgRx
         rqi5HtSrgWko6uFoCw99o4WDM9s9cmawqqWl0rpIwObTAFCLITSjuXhIElkRMqJpH9Fw
         DKjy5uIalNrjbz4rODNaxoRfzaGuB2I50Z4B0dp9NwOtxSCymiW3zfiLF/TwnzyLc0vg
         mLo4v9+V8zXBtwtuMeJvmitEmYXLIVAdt1cdSYA84qqSAqwwmEqBoakkxQwIGGaccSvo
         HyuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728377132; x=1728981932;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uxeDKrqqPgYcLZP/1dUzYL1jpgE25KJLUHDFa85T6XU=;
        b=fxfTlba7I0DullqXOJCEeZ4cpPNFm17341Wb3aEfYrTwArt3brcTMf8uw4RFUV+YOn
         gSBN1KLGnia4vOza7IHflJ+BCCXyBo71j2VidwB4TOl7OGgxGq0DTKH4YH5D/42OVqfJ
         mcvVrAcVXQC7ApsucbDpnJmsi+TKAqgOQ2x7Ia1JUy7YBI4Hh1i7Mex45J1yadDPmFd+
         cb8tV2iLgj6w6TNWzdgg3l6NUvqHeGqjicnEs9Oe6NNYkzdt3MDvRQpsEn3pOqOgo7uJ
         jjhD8R3Nd53Hay8w9ugEnMFdQmOwq6MdjJCaT+0ZOCYutuWU6iWBCGLvWYiDrwJoC0lV
         opzQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWHb7yBFG3eH4ro7V6I6aJxK9bge7Akxl5VM0Xigh2mAt/xYF6I4oGT6DToa9LtjrvP23IiyQ==@lfdr.de
X-Gm-Message-State: AOJu0YwaAUEQ8aMbQwh7jtVPxXgr4GSy4Hb7aEOwaspC424vZUkiSXRs
	RTMB5PXTjRZ2GtQhH2xJg33OruEqVvjHEyiC2AilyPeOvdJtAyNw
X-Google-Smtp-Source: AGHT+IEevtADqGl9j5rOQIPF04wU4fO8dQDPzjVedKuDk6rCpwlF5hdX+hInFSQJvGSc60fLTL2GBQ==
X-Received: by 2002:a05:6402:3221:b0:5c4:1320:e5a3 with SMTP id 4fb4d7f45d1cf-5c8d2e260c9mr13261223a12.16.1728377131029;
        Tue, 08 Oct 2024 01:45:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:8c2:b0:5c9:1100:f7ef with SMTP id
 4fb4d7f45d1cf-5c91100f8bbls78276a12.0.-pod-prod-03-eu; Tue, 08 Oct 2024
 01:45:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCyKPbkwZFwRh70v1WJvSONgYiTcR+MGfVaGT1avth1vgKhekXKG6oK0HaClPf2LsMphDeCRwJk9I=@googlegroups.com
X-Received: by 2002:a05:6402:4025:b0:5c2:4dcc:b90a with SMTP id 4fb4d7f45d1cf-5c8d2e9646bmr13503210a12.34.1728377129126;
        Tue, 08 Oct 2024 01:45:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728377129; cv=none;
        d=google.com; s=arc-20240605;
        b=hg7LQl2zcDcI+uDa+htnUJNZI0M2/nnz14FqmIgc5g7MfjCKWslJfsBVI51ktcg8kk
         fm0AWFk5EWVYnMgxE/9x3BRokMQqRXIGMTZGlkwQ5Pq0rM8baSJqZZOidA4eyJ2rfdM4
         WTcX6FOTq17AeFEsSlB3vKRkJcYJHg+dAdMIU/DtAodedcGJWjJCDlYcxxW60yiO4f2w
         yFFKbZKFrZ3o+YqehqEl/C3E2+cvOKwclvu2Rm5iOgSbw88is8xYMojBTiw0Gh4YTGUu
         +v35Qg6LW6o3lGkve9yfwd8yQTRORx5wPbTcb/VM1L27k/I44yckWc68jfvYzFzkfQJx
         v8mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tjUdOJA4jWMVSrUGgvOSdZl3neMitSFURhlyYwW/SrM=;
        fh=PdIN+tPfDCVLck5WOufvkU8xZXq7U/JYH/p4zEJoJ5o=;
        b=klMc0ax51z88w3EVRIr7w+dhsTTY7reulwyQfGgmiC84oFAvgYLTV8750byXS0WGv/
         1arWLdAaObDC1Hi95YAVkytoibV1e7ovsEMx/7CZkeDhnxiPcq/YzTcG0XSwbvnNRpRa
         FARXn5nmpMivKHpZvPnoUAwS/1js0DnGYAtXSajXssjVSLY7Buufnsxr2k1kBasfkc0Z
         f0nicLhA/ACjA26bd7zN8S4CL8bUq4/ZkY7tnV2I/BJFids0boh4v+WxwTLC815b7MHP
         7kiAg3DKy0RXGHXPHYizwZMT/QJha4Ezmm5QYDBmtqlHYE8nKF7Be/GVqprGmrXBOLlw
         kCDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="inw2hY/p";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5c8e05874f9si271720a12.1.2024.10.08.01.45.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 01:45:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id 4fb4d7f45d1cf-5c903f5bd0eso1724741a12.3
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 01:45:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUVX0kWsQ06yLx/LpL5Y/hgjdt0NqbGgNA0OSgcHbUxG8gv+Kl3FumnmZod0yYA2EVimaoVLFLK4iI=@googlegroups.com
X-Received: by 2002:a05:6402:5108:b0:5c7:1922:d770 with SMTP id
 4fb4d7f45d1cf-5c8d2d015cfmr10905346a12.6.1728377128325; Tue, 08 Oct 2024
 01:45:28 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNOZ4N5mhqWGvEU9zGBxj+jqhG3Q_eM1AbHp0cbSF=HqFw@mail.gmail.com>
 <20241005164813.2475778-1-snovitoll@gmail.com> <20241005164813.2475778-2-snovitoll@gmail.com>
 <ZwTt-Sq5bsovQI5X@elver.google.com>
In-Reply-To: <ZwTt-Sq5bsovQI5X@elver.google.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Tue, 8 Oct 2024 13:46:17 +0500
Message-ID: <CACzwLxh1yWXQZ4LAO3gFMjK8KPDFfNOR6wqWhtXyucJ0+YXurw@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, bpf@vger.kernel.org, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="inw2hY/p";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::531
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

On Tue, Oct 8, 2024 at 1:32=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> On Sat, Oct 05, 2024 at 09:48PM +0500, Sabyrzhan Tasbolatov wrote:
> > Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kern=
el
> > memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> > the memory corruption.
> >
> > syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> > KASAN report via kasan_check_range() which is not the expected behaviou=
r
> > as copy_from_kernel_nofault() is meant to be a non-faulting helper.
> >
> > Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> > copy_from_kernel_nofault() with KMSAN detection of copying uninitilaize=
d
> > kernel memory. In copy_to_kernel_nofault() we can retain
> > instrument_write() for the memory corruption instrumentation but before
> > pagefault_disable().
>
> I don't understand why it has to be before the whole copy i.e. before
> pagefault_disable()?
>

I was unsure about this decision as well - I should've waited for your resp=
onse
before sending the PATCH when I was asking for clarification. Sorry
for the confusion,
I thought that what you meant as the instrumentation was already done after
pagefault_disable().

Let me send the v3 with your suggested diff, I will also ask Andrew to drop
merged to -mm patch.
https://lore.kernel.org/all/20241008020150.4795AC4CEC6@smtp.kernel.org/

Thanks for the review.

> I think my suggestion was to only check the memory where no fault
> occurred. See below.
>
> > diff --git a/mm/maccess.c b/mm/maccess.c
> > index 518a25667323..a91a39a56cfd 100644
> > --- a/mm/maccess.c
> > +++ b/mm/maccess.c
> > @@ -15,7 +15,7 @@ bool __weak copy_from_kernel_nofault_allowed(const vo=
id *unsafe_src,
> >
> >  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label) =
       \
> >       while (len >=3D sizeof(type)) {                                  =
 \
> > -             __get_kernel_nofault(dst, src, type, err_label);         =
       \
> > +             __get_kernel_nofault(dst, src, type, err_label);        \
> >               dst +=3D sizeof(type);                                   =
 \
> >               src +=3D sizeof(type);                                   =
 \
> >               len -=3D sizeof(type);                                   =
 \
> > @@ -31,6 +31,8 @@ long copy_from_kernel_nofault(void *dst, const void *=
src, size_t size)
> >       if (!copy_from_kernel_nofault_allowed(src, size))
> >               return -ERANGE;
> >
> > +     /* Make sure uninitialized kernel memory isn't copied. */
> > +     kmsan_check_memory(src, size);
> >       pagefault_disable();
> >       if (!(align & 7))
> >               copy_from_kernel_nofault_loop(dst, src, size, u64, Efault=
);
> > @@ -49,7 +51,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
> >
> >  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)  \
> >       while (len >=3D sizeof(type)) {                                  =
 \
> > -             __put_kernel_nofault(dst, src, type, err_label);         =
       \
> > +             __put_kernel_nofault(dst, src, type, err_label);        \
> >               dst +=3D sizeof(type);                                   =
 \
> >               src +=3D sizeof(type);                                   =
 \
> >               len -=3D sizeof(type);                                   =
 \
> > @@ -62,6 +64,7 @@ long copy_to_kernel_nofault(void *dst, const void *sr=
c, size_t size)
> >       if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
> >               align =3D (unsigned long)dst | (unsigned long)src;
> >
> > +     instrument_write(dst, size);
> >       pagefault_disable();
>
> So this will check the whole range before the access. But if the copy
> aborts because of a fault, then we may still end up with false
> positives.
>
> Why not something like the below - normally we check the accesses
> before, but these are debug kernels anyway, so I see no harm in making
> an exception in this case and checking the memory if there was no fault
> i.e. it didn't jump to err_label yet. It's also slower because of
> repeated calls, but these helpers aren't frequently used.
>
> The alternative is to do the sanitizer check after the entire copy if we
> know there was no fault at all. But that may still hide real bugs if
> e.g. it starts copying some partial memory and then accesses an
> unfaulted page.
>
>
> diff --git a/mm/maccess.c b/mm/maccess.c
> index a91a39a56cfd..3ca55ec63a6a 100644
> --- a/mm/maccess.c
> +++ b/mm/maccess.c
> @@ -13,9 +13,14 @@ bool __weak copy_from_kernel_nofault_allowed(const voi=
d *unsafe_src,
>         return true;
>  }
>
> +/*
> + * The below only uses kmsan_check_memory() to ensure uninitialized kern=
el
> + * memory isn't leaked.
> + */
>  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)  \
>         while (len >=3D sizeof(type)) {                                  =
 \
>                 __get_kernel_nofault(dst, src, type, err_label);        \
> +               kmsan_check_memory(src, sizeof(type));                  \
>                 dst +=3D sizeof(type);                                   =
 \
>                 src +=3D sizeof(type);                                   =
 \
>                 len -=3D sizeof(type);                                   =
 \
> @@ -31,8 +36,6 @@ long copy_from_kernel_nofault(void *dst, const void *sr=
c, size_t size)
>         if (!copy_from_kernel_nofault_allowed(src, size))
>                 return -ERANGE;
>
> -       /* Make sure uninitialized kernel memory isn't copied. */
> -       kmsan_check_memory(src, size);
>         pagefault_disable();
>         if (!(align & 7))
>                 copy_from_kernel_nofault_loop(dst, src, size, u64, Efault=
);
> @@ -52,6 +55,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
>  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)    \
>         while (len >=3D sizeof(type)) {                                  =
 \
>                 __put_kernel_nofault(dst, src, type, err_label);        \
> +               instrument_write(dst, sizeof(type));                    \
>                 dst +=3D sizeof(type);                                   =
 \
>                 src +=3D sizeof(type);                                   =
 \
>                 len -=3D sizeof(type);                                   =
 \
> @@ -64,7 +68,6 @@ long copy_to_kernel_nofault(void *dst, const void *src,=
 size_t size)
>         if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
>                 align =3D (unsigned long)dst | (unsigned long)src;
>
> -       instrument_write(dst, size);
>         pagefault_disable();
>         if (!(align & 7))
>                 copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxh1yWXQZ4LAO3gFMjK8KPDFfNOR6wqWhtXyucJ0%2BYXurw%40mail.gmai=
l.com.
