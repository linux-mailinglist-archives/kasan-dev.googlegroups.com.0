Return-Path: <kasan-dev+bncBCT4VV5O2QKBBNOQY3EQMGQEHJEI2DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 09EB7CA43F2
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:26:47 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59578f8468csf664892e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:26:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764862006; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zs0nXB7I9bSUnL8jE49yjJ0Zn9BDcHV4t6Fhi5tA1NVyECv0eK6Ufh2SVnD5qtuPBj
         3PKF0iqh/avd2RoDIO1B/jPwwNyY7wfvQb8qf2PjaU4b+A02ksAQg7UE0z0Y1rpdnaPE
         URLuQd4Xv+sc/GT34zwNTD1CIKW0zomyGTdse7xpzSn5UGDXFVj3J1Mktb81ETx1PIac
         ORHSSiOwVQfE6q6oMSjgCc7VAfZ53Z9OSS08TpA2Rs4sE36fDhF++/Rf+K05kOoFyHzo
         PXRL6oAGmFtXkPDdBkQ2246kTNo+W4/WOO5e4vkmTkQs8XZTxoaqDJJuFUkkETyethw4
         p2uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/axCgpjqqEeku2wLmMy7ftQC47JqRBR5+FBTE9KWMfM=;
        fh=/YoLTTGhZdmX7X58u5hu3w9nvNrJoSuh85Cwjw8hsD8=;
        b=S/b94ERJ6GOq4Xe4e/syxMy8UA5X8cSob5DoFwfYgOnxVgc3p0kdwpQlJwWAdG75Hh
         Q2ls78HpZyKEqWb+4pa3vgKuXuDVNrb5xQ+yiXdWMeG9ZHWvLkyzHY+rkK9bzmtP/BTu
         pPKvcDjxSa5O324MX5XUMwHe76Fym6+Sn+YgPaJlLJjPa0rXgvrDytrz8P3q6PDf2f+a
         Alf5UE9O5Y/ZXFOOo8cayV2yLwRpCrkutxUtxGEpwgik1bBKsK8xGC0DvyCXf354bu+m
         bNjvTbESuNlxZrTY2i2XqfuDoYotdXB+J+JlpCd4wl20WnhMpZn2EF7v+25LfrGa1LyM
         i8BA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YzIbWIsa;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764862006; x=1765466806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/axCgpjqqEeku2wLmMy7ftQC47JqRBR5+FBTE9KWMfM=;
        b=VVBXoh3d9PolJZoiklUASAxLIooz7ZYfBtkd+obgdXIKnLuXYor4BztZRX2RdV+N4o
         vYjbTbRk7Q4LZWw8gBWP67iHDfKriCYSS1C3y6CMzp1TABmO1AUGxJj4bli+udPk9+qY
         1A2+Ic3R30qHsAhxaj1/JijAoLO9VnNOgMF74EF+u4fzPMUugBkOOk4hEYu0A2tVMPQY
         a3L/P5LMQ5qcdr0pBf2qvPXmeqKJ8qgCbHlrRxDGty6cjq2ByFmRVQD+V9Mgn5vSgP+c
         Dzz/5j5LwTwl2uMB7btH7YCu3i+Z646/PKgg38jKe+3F74sjhJr0hJYmMhptmkgAK2Mo
         UtkQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764862006; x=1765466806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/axCgpjqqEeku2wLmMy7ftQC47JqRBR5+FBTE9KWMfM=;
        b=c8L9CJGNRruRCZePDoOllsskvCaBR/5MFJGNy+ndyfpapOOg+ePtQcxklfAfr1BvFI
         F2Kc5vVeZJHKs2obtz9mtPW9VdOHhmNQFvY+BS/NNuHV6bcZKT4pVNltZj+T1m1QssgN
         mTGZnJmZk6IeisW7lwKKk9Dy4iQyqfwy3qIPuwq0OP8FJ+qGXRM+eHxq6XEykPQWCPay
         xN3zmq069iBXdMOIvpjYJp4jcdZDLCLBGwJ/jsDopXzn73N/7ArtJEfzF8bqTxnh7hRE
         5XJ2k2cUCn3krtc5T68mBlWOyaMDh7y2DheWXoW7CyzG7L2Tu7fl97bxCLBvb1zKiAnr
         2orw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764862006; x=1765466806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/axCgpjqqEeku2wLmMy7ftQC47JqRBR5+FBTE9KWMfM=;
        b=uH8OkW0DGzDJ4VAtF7ZKqHszyaB9mVQbaq3a4/7Prv+abfitUMgtY4VLZc6RAh66pF
         6zaoILFcXcc3AXJkn37dFC9/hh+jAJrNxGjS0UEMGsoRTsbMzPRzVA/HoaZDpM4pwTpz
         LbmQVlpqG0sSC/UtF0lX2c0TY2/qgs8mVmWAQXiBlCsnuAOFC+mQbb4TM/POWNyk49rd
         pwJbxwTgCajSNkN1yxA31ZSmikBEhvH+bqrx+f3Rhl5Wb/zaDZi6BYFKeSsTxuSk92wN
         WjfKCG+0S+SvKV9JB3gze0O07fFvQb1M38V6m9XDNQjMDinujUvO5lOPr+dVSZmXIaa+
         OQCA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhzOTnaYRXUzILm8qi7iCyIJt9+P78aj7I2jmW8plKoGus+ISl0ARlU1/JxNYbe/7pLbvFvg==@lfdr.de
X-Gm-Message-State: AOJu0YwBsyV6wXXrAPk3kN4uep60bhmu3PQjmGTZRb/jo3f+6Qb+48j6
	n7gXLHM18dHR8bT8lSuD0kbadbUoTGuwS0e8One+4JhipPZ/xt5iW2lq
X-Google-Smtp-Source: AGHT+IEtHksJ84F/TQGXJIrcxuV/98x10vZzcOdIZ4cl6qMBV29R+tuDOZO9WOMYAB0wpAPs7M0IYg==
X-Received: by 2002:a05:6512:23a1:b0:595:8200:9f8d with SMTP id 2adb3069b0e04-597d3ef6f73mr2778639e87.8.1764862005678;
        Thu, 04 Dec 2025 07:26:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YDRMWkuVxkW+RiJ8H2dBPn9AylQIXJ0ee0RA9bCEBVMg=="
Received: by 2002:a05:6512:3350:b0:597:d79e:e081 with SMTP id
 2adb3069b0e04-597d79ee277ls128323e87.1.-pod-prod-03-eu; Thu, 04 Dec 2025
 07:26:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVDKtfbSGM2hP/yCfr93Tka199esfCROS5rRSzDtKgGZCmBxymDObM6OQti4BebJ33D7njELLNqICw=@googlegroups.com
X-Received: by 2002:a05:6512:318f:b0:55f:701f:933 with SMTP id 2adb3069b0e04-597d3fe2e71mr2549936e87.41.1764862002137;
        Thu, 04 Dec 2025 07:26:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764862002; cv=none;
        d=google.com; s=arc-20240605;
        b=kfsNZg9ulkYWUAmu63mIfonLYRM4Jy2NtxR6d8mMnxLQkR+WV/1Y+kB4eBR31Jv0hQ
         5sElKHOOzKuXPoUGTuLYMWnEgsQNoAAMqTmgWC+7O+xR4ikLsc5qipwb3Xc0cSbJHTiG
         HTBuZP7eoytaSOJ+W5/4eaFVOtTXfzuE90ZFEBE5jNhPj/jeexoXCzvK4aUdvRabZEUk
         TBqrUsOEtO8l+4fXTutcCXvTaaPuOur9a5RAAJdHIiMioc66tu1ma3MnpXKLH+lzK5Aq
         rGd6jNYmyy0Ti8qz6ayhZ9udRAm01TREBd6QQ7bedCoVraRZWYZMkg9Tsun6W6sAAS1j
         PVGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hRDq8VRZX7ObisK4LUGIJP6XjIFCzmZAVr9+RtuDKSA=;
        fh=/UYjO/RwpJNzdfVmrVeDZl7vlP3b+1soB8cQSLtWpxc=;
        b=FFecZXXEX1imM06lnpcLRFfH0GK8DJZGGjNzXzWeeDhJNFwHmdWzG6chbJ0vY3ZGdX
         x/depz+N1O5lbO+CJwWEFSKoTZGpy07CRVejfkLgKtYn217LNlaEkisBnRQ9m0NsT8SN
         k1oFEv9jdBbEPuLULUWiujQXiybVmXxB4Vjx9h/DJKjP/xij/nkgjSEMKI2gNGq8/o+h
         mK7azFDsUSwbzC1aTHTHNrXDxqpi+UYwkaEMkP2y2BxGcVeiQOBcjl7uCH3IjnqwOhLN
         dKShNIOv/VOu+Tvd8r4u1JEdrW1h28kU55MxvQJBz/OHrXRGLYmaBlXSN0a3j7FFQjJL
         oU0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YzIbWIsa;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-597d7bf8fe1si34380e87.7.2025.12.04.07.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:26:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id a640c23a62f3a-b736d883ac4so182707666b.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:26:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU6Vt2kOezGKKnTd6zHHV2BLKSc/EW6dL+rxgIocC8NDzhFEeZm7yZ58wB8rMkl+t5s4VC+IYhIsLw=@googlegroups.com
X-Gm-Gg: ASbGnctjcyOnF9cPjFtlz+2fz8Hi/5C0+Sa2baAaD1KSuznjU4KftJmVZSj2fJiGlep
	RgGiijXF3pTDbBiUfYGccI8tXe8WzcvB9gYQAbOBJXcxCHMfR4advM8bxYOvhADvN0P0bPWwLqS
	xKC6mnKXfpyZcUzYFItB3S2v4+NedNQ7xUO8uOwcBE+XM4uQ78YBwkgUiXcPLyQZt6m669K5b2O
	LQatReEH21wGM4m/fxgtJbfA6zQyYC43ax2gIIUDJ4osOoQgvU0Xh+2Z7Jp3IEnCo2PFshog+Qc
	g233Mr65EyGAzdp07ddXhYvLmEiRzQOThbOFenGsQuOW04XaRxNk0bkFyDyB81OSSq6YCB8=
X-Received: by 2002:a17:906:6a09:b0:b73:210a:44e with SMTP id
 a640c23a62f3a-b79dc51af33mr666433666b.30.1764862001190; Thu, 04 Dec 2025
 07:26:41 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com> <20251204141250.21114-10-ethan.w.s.graham@gmail.com>
In-Reply-To: <20251204141250.21114-10-ethan.w.s.graham@gmail.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Thu, 4 Dec 2025 17:26:05 +0200
X-Gm-Features: AWmQ_bmIoeQpAWoaWpHaqI6dnG4PTWdKQq3rnGgG66adF0zPHqO5BwO2Z5x6PEQ
Message-ID: <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: glider@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com, Ethan Graham <ethangraham@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YzIbWIsa;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Dec 4, 2025 at 4:13=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmail=
.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add a KFuzzTest fuzzer for the parse_xy() function, located in a new
> file under /drivers/auxdisplay/tests.

drivers/...

(no leading /)

> To validate the correctness and effectiveness of this KFuzzTest target,
> a bug was injected into parse_xy() like so:
>
> drivers/auxdisplay/charlcd.c:179
> - s =3D p;
> + s =3D p + 1;
>
> Although a simple off-by-one bug, it requires a specific input sequence
> in order to trigger it, thus demonstrating the power of pairing
> KFuzzTest with a coverage-guided fuzzer like syzkaller.

fuzzers

> Signed-off-by: Ethan Graham <ethangraham@google.com>
> Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>

I believe one of two SoBs is enough.

> Acked-by: Alexander Potapenko <glider@google.com>

...

> --- a/drivers/auxdisplay/Makefile
> +++ b/drivers/auxdisplay/Makefile
> @@ -6,6 +6,9 @@
>  obj-$(CONFIG_ARM_CHARLCD)      +=3D arm-charlcd.o
>  obj-$(CONFIG_CFAG12864B)       +=3D cfag12864b.o cfag12864bfb.o
>  obj-$(CONFIG_CHARLCD)          +=3D charlcd.o
> +ifeq ($(CONFIG_KFUZZTEST),y)
> +CFLAGS_charlcd.o +=3D -include $(src)/tests/charlcd_kfuzz.c
> +endif
>  obj-$(CONFIG_HD44780_COMMON)   +=3D hd44780_common.o
>  obj-$(CONFIG_HD44780)          +=3D hd44780.o
>  obj-$(CONFIG_HT16K33)          +=3D ht16k33.o

Yes, this level of intrusion is fine to me.

...

> +++ b/drivers/auxdisplay/tests/charlcd_kfuzz.c

So, this will require it to be expanded each time we want to add
coverage. Can this be actually generated based on the C
(preprocessed?) level of prototypes listed? Ideally I would like to
see only some small meta-data and then the fuzzer should create the
object based on the profile of the module.

Input like:

bool parse_xy(const char *s $nonnull$, unsigned long *x $nonnull$,
unsigned long *y $nonnull$)
Or even with the expected ranges, and then you can generate a code
that tests the behaviour inside given ranges and outside, including
invalid input, etc.

But okay, the below seems not too big enough.

> +// SPDX-License-Identifier: GPL-2.0-or-later
> +/*
> + * charlcd KFuzzTest target
> + *
> + * Copyright 2025 Google LLC
> + */
> +#include <linux/kfuzztest.h>
> +
> +struct parse_xy_arg {
> +       const char *s;
> +};

> +static bool parse_xy(const char *s, unsigned long *x, unsigned long *y);

Is it still needed?

I mean, can we make sure that include in this case works as tail one
and not head, because otherwise we would need to add the respective
includes, i.e. for bool type here, which is missing. Also I *hope&
that kfuzztest.h is NOT Yet Another Include EVERYTHING type of
headers. Otherwise it breaks the whole idea behind modularity of the
headers.

> +FUZZ_TEST(test_parse_xy, struct parse_xy_arg)
> +{
> +       unsigned long x, y;
> +
> +       KFUZZTEST_EXPECT_NOT_NULL(parse_xy_arg, s);
> +       KFUZZTEST_ANNOTATE_STRING(parse_xy_arg, s);
> +       parse_xy(arg->s, &x, &y);
> +}


--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AHp75VfSkDvWVqi%2BW2iLJZhfe9%2BZqSvTEN7Lh-JQbyKjPO6p_A%40mail.gmail.com.
