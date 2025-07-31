Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTOGVTCAMGQEMD75DVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F3D2B16D19
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 10:03:28 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-240012b74dfsf6110165ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 01:03:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753949006; cv=pass;
        d=google.com; s=arc-20240605;
        b=YCbo3gc8zAtmDo28no6XcDPYybHsfVSf42TmLEJTeryfagYHP/L2g3UOfq4Kp3Nitx
         wR17mpnYFZDL1p5t0XnSa+fSkkmXN67uO1w8EXBmpqRMk1d3gm+RSgcq9plXApMd1vCJ
         BX0L48PqsTAKuVoaJJx90wmZw4XXicBCWEmm8TsE5Y3hiBQ+oOyXz/FG4iNqRReCwQXB
         uIGdhLncEkakc6oFtHqBHj+2xmb2vzuu3GYG2V3V2MSMYVTztaWmFrYXSUtB9uJaS+3O
         nVsXAnckEz0iL2kDoS6Z0wlooQY03e1UgA/frGknj1Y8rmSe5P+VNKSotbt5rYfK+hEw
         FjxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O74ICI8O1TvYsxXm9gRXR42fRKlDw/ZjQj8hVKVotR4=;
        fh=o6jzcUL0byw51Zje1BNjOxbOFKzwaZfAd/4oURvjr1Y=;
        b=h6AMP3KEQ3N5BUAe2jSsNdoXzkt6Sd8ny6QIXyE2zPbnAXrrbLMLtn6Ywu5FjfqpkQ
         hM7jtnBxeTNT+TeajJ4GQtdzGspQzUJ6SWj9WUtCBW/Wrl0E6EMwSziDXVA5x8D8AMwl
         /faBOdhoZqA6ZIlIGFXN2Wg8Xv4w0crEqJO+B8IwVfaxxeCU446tSJn8rb5fmV0KhshY
         Jq5xxQZIr7I50QE2aN4a0SSGgDxhEjmQTGlcE88XhRr4r7IM1FH0R9YNJY86WR1/+Vxo
         bY82wAcPUeOnaCMoWTsKyzZpgj3RPZNGIS8aw+ZEPp31OxZrVPvOTiQEYglI9qAMdhVY
         6lVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aw6F5GBA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753949006; x=1754553806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O74ICI8O1TvYsxXm9gRXR42fRKlDw/ZjQj8hVKVotR4=;
        b=mW8egfn+ejsCkvn8nOEdIf2OoezyfvxSbC0ukkNPhloS4yQbCDny3EjrHVH8ElgM9C
         7KliichwetsyPQl5HMc+K9IN6g4ajjOPZPaILs+endTPcF9LXPXVLQRTDpvTXf+UiSKz
         KSXWkhunWXf2mEDV8GoYereFUkSdbl7hsjk0iOGJg+l9nH34HC6ih8tHcOdUdB7dYufn
         ZJuJKfVGuUUQ9sXNu3GBfIqUtOj9NnkhORgS5MzPbpudCKjhHjc1qtg9hpu++VxnnjYC
         erwyy8SlKyNyxaTnHDelotyS5lIQyNm2sGXN0q9K5+1K+Oac6spcTgvv85Lj8hF9pQ6S
         hb+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753949006; x=1754553806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=O74ICI8O1TvYsxXm9gRXR42fRKlDw/ZjQj8hVKVotR4=;
        b=YaFTN+eA6ruwVLT58Q6WHnRwi6NR+6FSNnnhpxCOWHAbVLcN1ICbn9eMiR1zd2uEKF
         jXDGbJA5MwOdDtuhHMO7dKpjp20zdnh+Z3jEdjp7yV04h4QAidPfwE0IN1GXcVVZEbR9
         bWq6Z4dIoH7e/Goia/ZLQElBauLz23cH+6ofJPpjn4DUHvX061Fnu/F4bZI27J78DtAI
         pZXvWp3IMqpe1ZccBpEN+WOos3vd3kRrbUHQ1Hh9PVT5zHReAccAwrDNl20MwTE+A+fa
         vhvfQhArG4XjkJ3mdPGyj2tWZuEjLO08i0OKKWxtFcLHFnCpw6X6XmLn+e2BSnzwjVmW
         VQEw==
X-Forwarded-Encrypted: i=2; AJvYcCX/fmWwGDXeuZPRgAVpZ2C/KmBCGW48ZtMFdhtuWJEr+0w+Lgkn9vvhj4nDjpkyicZc5uUbXA==@lfdr.de
X-Gm-Message-State: AOJu0Yz9Bg+TAiyvvus5dBibWVn8ILwOdECMz0hXpr28DdtrTxPgO3eN
	S/HkT8qNh2MgkZiBU10oavQ4LwQAAlkeiofzHE+hPDcWKzfAbWveJxQu
X-Google-Smtp-Source: AGHT+IHCOXFWkEMkDunptAgIJSSjfOo3TG7bRFMtvxpCD7s0ruv0OERisd0kaBeMQamoj2n04Ak3EQ==
X-Received: by 2002:a17:902:ef0f:b0:23d:fa76:5c3b with SMTP id d9443c01a7336-24096b0ec4dmr98675355ad.22.1753949006128;
        Thu, 31 Jul 2025 01:03:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeGji+AwchkCUsMGStWqUfp772j46lIz4WIknhmbN92/A==
Received: by 2002:a17:903:1aab:b0:23f:fdbc:de3c with SMTP id
 d9443c01a7336-241e8967360ls5773415ad.1.-pod-prod-07-us; Thu, 31 Jul 2025
 01:03:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVPs0XGYCiTvZ48LDiXtYmEzwmYzUyDTZ5m2wjLF2jsk7ZTbGmcQ6vw8hBWVI/3gLy8UIZykq8ZvoI=@googlegroups.com
X-Received: by 2002:a17:902:f0d5:b0:234:98eb:8eda with SMTP id d9443c01a7336-24096b686b5mr68355575ad.28.1753949003755;
        Thu, 31 Jul 2025 01:03:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753949003; cv=none;
        d=google.com; s=arc-20240605;
        b=b+TsDRxDwcEnhhi3LS6+fBHQmGOuub86Cw5wJCoi/JkMpoA+Yb5wkRfIW7KO/YHV62
         ZCogpbJU0waO/Y7DSTqQUlBgE7PSJJjT4pxnxFjrSnrzunmfHpgUbd0Vl9N4jhbpkAkM
         alk2CfLD65vBnpKcnxEZJEB5GFw2x+s1PG0jUrdqvUWqLES3ZMjjFfAACNJTDvsfCaDg
         zqCC7gzwG5hZd54y/s9brV0WUUgsIrcr0OGthehJgxsLEuT9YMRywK8sDkz8xjVm9pZg
         glRj27rIiTGbdKeW9MdgktEzSAKOvc0xx7n4hRTsR68mAvrOGHlAK59UuTfNvIYwnfEK
         5E0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=E0RizqeeSEQXWVsY0Sxzh6E2pfnIevB3317J+qjJefQ=;
        fh=pAhB4t30X35sq57ScEpG34wPYYZfXRX4RipuSQxVtBg=;
        b=ExG0a7dwUK0oiLfTmRu8WFygIj/RPttFdG6WP45StTr+wzMdlig78M6xFxG2P5WlWa
         XeKHYBdykSTy6z29ASyMqrRvbegLdc40tl2y0w49dkD3bSTAIIWCu8R1nutWSekV3Bg5
         XjQ7VdvWT6M+qukwwIwzKTRJ6hbQdccs/JnhBxqSTIcl9yd2wMr8a81RQA/Nyztq2jZk
         lnuy1ZWAs3TBORd7lQsMws1misraHOeuF+ns/uKYV/2qP6f7x3I7xOM6E8+es6E1FoNV
         bGLgPQqHGsm2WFQ8SIyo13fQX9HjBbl+3vw37QFU9Zt0H3u/6z0z7Yr32JozsWBnWV0A
         CYcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aw6F5GBA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1fb30e6si387495ad.6.2025.07.31.01.03.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 01:03:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-70884da4b55so768906d6.3
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 01:03:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVHMi6f71ikRzP9adF+J89OHzUVCPSbU1YAw5VprO2iAjw9t3rxCL2cAAIwNWaQ5W+Xx6YYBMVym2s=@googlegroups.com
X-Gm-Gg: ASbGncv9QuVx7hUMl6fl9psBpxjVrjyxvoOQI522itLqX6qEzB98+F1o5hv3g7phpBt
	HWjdUO156g8yMRKxmjOyswQ/hg1fB9SbB6timeiEJF+flB7fY3DzaWSR9jxie4F+QsGI3yhMFHP
	lgtLXDMCcSTgEHpxxoEOoR5cTCM5mRSDkOZ4xO7Oy60ILYiTdrrdVPJq3thbS1cqbWfNK5Dhzjh
	CsagnrqHMyn9XrSzmH6SpcbY0nR/YP9Kf0=
X-Received: by 2002:a05:6214:23c6:b0:707:4e41:d352 with SMTP id
 6a1803df08f44-707670532a0mr69396966d6.6.1753949002615; Thu, 31 Jul 2025
 01:03:22 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-10-glider@google.com>
 <CACT4Y+Y6gkd23+cVEkTs_MDfvOskd=Z4=dVh-LL-F_Jbgf8xnA@mail.gmail.com>
In-Reply-To: <CACT4Y+Y6gkd23+cVEkTs_MDfvOskd=Z4=dVh-LL-F_Jbgf8xnA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 31 Jul 2025 10:02:45 +0200
X-Gm-Features: Ac12FXwla-B03ct7tMQ3jw6Uy5HlsYMbId5MW3BmN9-L_RLD8ecivdhVV9pI6Zo
Message-ID: <CAG_fn=WDOu2sRv_RhRm8XhgCAgVJsMaPXp9TbcaknTn_84cNOg@mail.gmail.com>
Subject: Re: [PATCH v3 09/10] kcov: selftests: add kcov_test
To: Dmitry Vyukov <dvyukov@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=aw6F5GBA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Jul 29, 2025 at 1:20=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com> =
wrote:
>
> On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > Implement test fixtures for testing different combinations of coverage
> > collection modes:
> >  - unique and non-unique coverage;
> >  - collecting PCs and comparison arguments;
> >  - mapping the buffer as RO and RW.
> >
> > To build:
> >  $ make -C tools/testing/selftests/kcov kcov_test
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> > v3:
> >  - Address comments by Dmitry Vyukov:
> >    - add tools/testing/selftests/kcov/config
> >    - add ifdefs to KCOV_UNIQUE_ENABLE and KCOV_RESET_TRACE
> >  - Properly handle/reset the coverage buffer when collecting unique
> >    coverage
> >
> > Change-Id: I0793f1b91685873c77bcb222a03f64321244df8f
> > ---
> >  MAINTAINERS                              |   1 +
> >  tools/testing/selftests/kcov/Makefile    |   6 +
> >  tools/testing/selftests/kcov/config      |   1 +
> >  tools/testing/selftests/kcov/kcov_test.c | 401 +++++++++++++++++++++++
> >  4 files changed, 409 insertions(+)
> >  create mode 100644 tools/testing/selftests/kcov/Makefile
> >  create mode 100644 tools/testing/selftests/kcov/config
> >  create mode 100644 tools/testing/selftests/kcov/kcov_test.c
> >
> > diff --git a/MAINTAINERS b/MAINTAINERS
> > index 6906eb9d88dae..c1d64cef693b9 100644
> > --- a/MAINTAINERS
> > +++ b/MAINTAINERS
> > @@ -13018,6 +13018,7 @@ F:      include/linux/kcov_types.h
> >  F:     include/uapi/linux/kcov.h
> >  F:     kernel/kcov.c
> >  F:     scripts/Makefile.kcov
> > +F:     tools/testing/selftests/kcov/
> >
> >  KCSAN
> >  M:     Marco Elver <elver@google.com>
> > diff --git a/tools/testing/selftests/kcov/Makefile b/tools/testing/self=
tests/kcov/Makefile
> > new file mode 100644
> > index 0000000000000..08abf8b60bcf9
> > --- /dev/null
> > +++ b/tools/testing/selftests/kcov/Makefile
> > @@ -0,0 +1,6 @@
> > +# SPDX-License-Identifier: GPL-2.0-only
> > +LDFLAGS +=3D -static
> > +
> > +TEST_GEN_PROGS :=3D kcov_test
> > +
> > +include ../lib.mk
> > diff --git a/tools/testing/selftests/kcov/config b/tools/testing/selfte=
sts/kcov/config
> > new file mode 100644
> > index 0000000000000..75726b2aa9979
> > --- /dev/null
> > +++ b/tools/testing/selftests/kcov/config
> > @@ -0,0 +1 @@
> > +CONFIG_KCOV=3Dy
>
> Doesn't it also need CONFIG_KCOV_UNIQUE=3Dy since it tests the unique
> mode as well?

You are right, I missed that.
Another option would be to skip the test under #ifndef
CONFIG_KCOV_UNIQUE, but I think for KCOV developers it is important to
enable all the necessary config options.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWDOu2sRv_RhRm8XhgCAgVJsMaPXp9TbcaknTn_84cNOg%40mail.gmail.com.
