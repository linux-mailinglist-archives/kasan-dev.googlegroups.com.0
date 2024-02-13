Return-Path: <kasan-dev+bncBCT4VV5O2QKBBFWRVSXAMGQE5TROCXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A19C852B34
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 09:30:15 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5113b77ff80sf3533698e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 00:30:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707813015; cv=pass;
        d=google.com; s=arc-20160816;
        b=zw+wpVzX18GRXaoMVcNZ6HKHsP8NKvpIiO0bS2HVTqJ/BVnPVkBIRO6pUw74Y+get3
         G99cEQ6dhI/qJQ97orVkuluO3vEQ/m//dIyaFDHHDDE6fsSh8Gd8ekBHFdIsIqHLXpVj
         qreNRV8Q8/OjyWfljTCsoVcEUixmoBWfy+ggnnsQRRa1fd/pDekLIXUDxwmB1Lm0Z3nq
         KrJLnUIUCtQW9zqx4XaAGmUhfRoCxKk7ZkkJDWa4MIUHFmlJaDrYrDJSgKPr/21jGPeC
         rqRcblYTqe8++0lg/Bgp998TFeSrbhRdkA1F9aZWD1dbel/wYPfbKxBWeC2LL5icwn8t
         U7SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=04GxZr6vGhEqoeSvEhy7j582CWXreYNKU15mPXeaTxI=;
        fh=Yn/ZJBpNJTqXQdXv8cKoq3/1bBgixlvSpBLz7ULhpKQ=;
        b=SO3mBJtney0q/oLSwaTeFR2rwqf/G9AUGbz66o/cSJ57JgakyB8f6DoKh/gE+5nLbt
         esTD4IzOkXwfXIRvveEVQ8ocW3AZtqorPXoMc2ljxdNNYKsn/p4h5XgP5JbafAMNK8r5
         zH2l+dFYlz8wiaF2FA0An3WRR7MrWn1ap0BJd74p8cw2iqYiUjAXoDgTApHmvvXOE1bD
         ub+khwZw913b6YpFFSskcgD7ktoQ6SCwhN/PUwpAAxrkpXaJkdqbUEKWd2Fw7lOpf32e
         PNDobR4CJ9PJPZX9z0cE4X/jCBcE/5bLHN+55ZqB5rLIMYechCZZfnX+i/CAQ43+5Yva
         yd+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q+Z4BEN7;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707813015; x=1708417815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=04GxZr6vGhEqoeSvEhy7j582CWXreYNKU15mPXeaTxI=;
        b=HCjeNSlGCAWt5F5OwIWWdFb5lC47Wr9DaMgw9ZMid7VeNObhcdXUIbnc3o1ZOeymS2
         FKARv7BidMAPSCA5mTbe8VCD+0sYcpaNRqgH9PaCOkD2dmi+T9elH8AYrKiVdHCLPZmi
         xlB4400aXRomGrTjkiZcQ5f6Z1X+yWCuMZxEyFotLm0kdHaMiUtBBDuJjz7JeCLMgG9l
         a8LZ2csCSKkQfWIz7ZT/vygMFs25EJnCUpzhidnBwG2m/HVlCUp9pUESpy6NJwBLuu7/
         TWpxf57YdBhfn9ktdTxug4dtKkVLWjyhF09qsxuv62FJOZJySCR0UC2i95jLuGg7lHI2
         4RUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707813015; x=1708417815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=04GxZr6vGhEqoeSvEhy7j582CWXreYNKU15mPXeaTxI=;
        b=j2oMZK73UtiDHZBQQkW55cvGpK8fXZ1/vealHKf66jUgvXygJQpFDjQLFzGRSrNvZX
         evGr1jbEaHXpL/SYExNMB8wfK7Oc4U2U5s9QvYrMtgvaErMY5HM7BppLUMC4QffehSzF
         /U/UWee5Z9aflUH20/HpsRHZ+ul3k7ayHMcZLsLagQ+mR+OkPNeuFex4HbD+wWHXW28k
         wSDu+sR7FqKKLqcyKen91izL8S74skUP5Flg1g4uYNUecw6oTEizs7eEsOii2CU4nYxd
         TyJdW8b613TwwNntXX5qRQxzINZ9S51m5QkWi60dZBiZMTXkYot9wtCI9M2Tg0P25276
         zNIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707813015; x=1708417815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=04GxZr6vGhEqoeSvEhy7j582CWXreYNKU15mPXeaTxI=;
        b=ACru5pWnw8tGGg+kuFccwfUFwsAdMwJvSl1t8IVrOGwhwFJfuRJUPbUTwE/+9Iiiyj
         sFbKlIqdUc7pQHvnCWgnljRqGbI0Bds7T/jncQPKA+f4WvcUOMsaOYcV2pWviMw8K2lg
         xKqIIanourXPXE5gMHe03VVpVRTHTIbkjaYXJiyhCq6AiJ16a41mAGDCu0FGeZ+Do0rI
         IcUyYxmAuKr7gMqZHsV65tJSZOpHWjYS60JW15p+W8wHXei19S5YcCpGd6KWd3w4lnRI
         xhtGRg86BjdCkcm2bkQX3nSIwGX900xG/FiA+rUfrZQlULetj1wYRUJ2kXuopGqnBA3H
         pQ4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFWJzwHF4apERRqKDnJ9v6rXjD+sEUG18Y5dlYj+WIFFOCgX3AWJAsWfWlUqO5Xv3cxaYhqiLfOM18jdoEJedhsBlgp3lGig==
X-Gm-Message-State: AOJu0Yz50lZh+tTvr6nuYP+5mzoGTRPuV4x9E/Ov/K8CeeH9XjfOjKRJ
	H8fNCKHQxhhYHwGJG4tMg/MOS9VvUEOzC3vNo125lmc07rmOBqkh
X-Google-Smtp-Source: AGHT+IFfDmdhmZT2mBruih3rTjak+C8MDBLHU9EbR6PRarCI2gU9Bc2WDfL2mwRcnQHyQCEzXqRdLg==
X-Received: by 2002:a2e:9998:0:b0:2d0:b6fc:addf with SMTP id w24-20020a2e9998000000b002d0b6fcaddfmr5533744lji.3.1707813014340;
        Tue, 13 Feb 2024 00:30:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:128d:b0:2d0:9fd0:8d89 with SMTP id
 13-20020a05651c128d00b002d09fd08d89ls664491ljc.0.-pod-prod-03-eu; Tue, 13 Feb
 2024 00:30:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU+IH8K4Y9lLndco/e9iijtsH3aRfsEkJncNX8lTKcuBxe23dJ85EWE1g5MjhNxrBPHF4WtzU4TTRiZGpInKpWBnwFS0SvBVEqFnQ==
X-Received: by 2002:a2e:8014:0:b0:2d0:a47c:d544 with SMTP id j20-20020a2e8014000000b002d0a47cd544mr5732957ljg.53.1707813011897;
        Tue, 13 Feb 2024 00:30:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707813011; cv=none;
        d=google.com; s=arc-20160816;
        b=lL3oLpWVGkOCzBDbq7HBGLI5qcU8yYXmhCF5mZpieqtT/0dM1JbK5FFShfRjZ6Bqno
         ynlvX5XuHj7Az9t7gNIe5Bzk5jmmg6j2U+LtJ4+MYEJ2KaE/xozhFjVLfSlkB5qPJlOe
         dxIoJEbD/+gO4Eg+mg9Gw1q3UZPogspwg1MuH/OAy1O3TGcBC5zry2nFk5/EwOoAcoJk
         XN3dlW7lU448U2JMzmwnpYvo4F9R2zBj72p8dbFkfyUGOzpOkvD9Dh+XBnm+AhtEcV6f
         LprVaqpk2ee/mQGfS130HjfA+Uy/Jh8JopSxZRfnvRFMJ2IBcMiwep4CZKb8OYhgCJNq
         89eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UVoibj/kriuj68qpqrmYwyDO76NZZTUK51M4zJowuXg=;
        fh=TRAFUH6XGNHwhPhwZB4Q3kZKU9yWvOhpav27SD/ZEt0=;
        b=nWxx/2MwZyQIIJ1wTrDcQiJ84dWgw/Xf1trlgZMzPiSVj661oDIz7m4Ic5I2+3mAux
         3e21FIBrh9mIHn51K0YAMzh+GyuEKM0wVh/+9gJ5qfJTZdP3lLZl0g2Rfu+v/AeN8Fyg
         toIBVWEuZDrKs6lJES00G0hOphzgOa6gflXVPEgmcPsicID7Y1i2ry88VYdw4tOWdgMV
         HUhWFly6yTp2nCcYmvdoWSW2UruDMvJU8pOdCsqLwe1a4Zb8AnoQXjyFZK7F5I+50/8P
         FlQ/jWnIYgaC1By48C9evfqO8IL5K50Gju9hlhOTAuNU+BDCnKkFZhYYUHA0f3qcj3CY
         8PyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q+Z4BEN7;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=1; AJvYcCX7r9tF8AgdDOudUtpn2X/lQhjLEdJWrA5hNXrsY9aQI7kZWuz+6NTw/TRnAGGMUb/2WIJXakbYOoR2i73+UT3y1ZdUbipmdwvV4Q==
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id i13-20020a2e864d000000b002d0a7814671si192084ljj.7.2024.02.13.00.30.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 00:30:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id a640c23a62f3a-a26f73732c5so560763366b.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 00:30:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUBGoSvylEUxZdOaPdKIXKlTUiEACU7sezPM/hDes5prqPxHILjsT6SG0s7dYInzhjvysJN8bY55Dvr1vVFfZr99GlWD36vNOateQ==
X-Received: by 2002:a17:907:7896:b0:a3d:704:d688 with SMTP id
 ku22-20020a170907789600b00a3d0704d688mr613690ejc.47.1707813011047; Tue, 13
 Feb 2024 00:30:11 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-2-surenb@google.com>
 <CAHp75Vek3DEYLHnpUDBo_bYSd-ksN_66=LQ5s0Z+EhnNvhybpw@mail.gmail.com>
In-Reply-To: <CAHp75Vek3DEYLHnpUDBo_bYSd-ksN_66=LQ5s0Z+EhnNvhybpw@mail.gmail.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Tue, 13 Feb 2024 10:29:34 +0200
Message-ID: <CAHp75VcftSPtAjOH-96wdyVhAYWAbOzZtfgm6J2Vwt1=-QTb=Q@mail.gmail.com>
Subject: Re: [PATCH v3 01/35] lib/string_helpers: Add flags param to string_get_size()
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	=?UTF-8?Q?Noralf_Tr=C3=B8nnes?= <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Q+Z4BEN7;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Feb 13, 2024 at 10:26=E2=80=AFAM Andy Shevchenko
<andy.shevchenko@gmail.com> wrote:
>
> On Mon, Feb 12, 2024 at 11:39=E2=80=AFPM Suren Baghdasaryan <surenb@googl=
e.com> wrote:
> >
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > The new flags parameter allows controlling
> >  - Whether or not the units suffix is separated by a space, for
> >    compatibility with sort -h
> >  - Whether or not to append a B suffix - we're not always printing
> >    bytes.

And you effectively missed to _add_ the test cases for the modified code.
Formal NAK for this, the rest is discussable, the absence of tests is not.

> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> It seems most of my points from the previous review were refused...
>
> ...
>
> You can move the below under --- cutter, so it won't pollute the git hist=
ory.
>
> > Cc: Andy Shevchenko <andy@kernel.org>
> > Cc: Michael Ellerman <mpe@ellerman.id.au>
> > Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>
> > Cc: Paul Mackerras <paulus@samba.org>
> > Cc: "Michael S. Tsirkin" <mst@redhat.com>
> > Cc: Jason Wang <jasowang@redhat.com>
> > Cc: "Noralf Tr=C3=B8nnes" <noralf@tronnes.org>
> > Cc: Jens Axboe <axboe@kernel.dk>
> > ---
>
> ...
>
> > --- a/include/linux/string_helpers.h
> > +++ b/include/linux/string_helpers.h
> > @@ -17,14 +17,13 @@ static inline bool string_is_terminated(const char =
*s, int len)
>
> ...
>
> > -/* Descriptions of the types of units to
> > - * print in */
> > -enum string_size_units {
> > -       STRING_UNITS_10,        /* use powers of 10^3 (standard SI) */
> > -       STRING_UNITS_2,         /* use binary powers of 2^10 */
> > +enum string_size_flags {
> > +       STRING_SIZE_BASE2       =3D (1 << 0),
> > +       STRING_SIZE_NOSPACE     =3D (1 << 1),
> > +       STRING_SIZE_NOBYTES     =3D (1 << 2),
> >  };
>
> Do not kill documentation, I already said that. Or i.o.w. document this.
> Also the _SIZE is ambigous (if you don't want UNITS, use SIZE_FORMAT.
>
> Also why did you kill BASE10 here? (see below as well)
>
> ...
>
> > --- a/lib/string_helpers.c
> > +++ b/lib/string_helpers.c
> > @@ -19,11 +19,17 @@
> >  #include <linux/string.h>
> >  #include <linux/string_helpers.h>
> >
> > +enum string_size_units {
> > +       STRING_UNITS_10,        /* use powers of 10^3 (standard SI) */
> > +       STRING_UNITS_2,         /* use binary powers of 2^10 */
> > +};
>
> Why do we need this duplication?
>
> ...
>
> > +       enum string_size_units units =3D flags & flags & STRING_SIZE_BA=
SE2
> > +               ? STRING_UNITS_2 : STRING_UNITS_10;
>
> Double flags check is redundant.



--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHp75VcftSPtAjOH-96wdyVhAYWAbOzZtfgm6J2Vwt1%3D-QTb%3DQ%40mail.gm=
ail.com.
