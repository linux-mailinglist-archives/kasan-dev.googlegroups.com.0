Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HDX2SQMGQEBG3742Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A72D7751B0F
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 10:12:25 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4f84a8b00e3sf472771e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 01:12:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689235945; cv=pass;
        d=google.com; s=arc-20160816;
        b=irEY+3NfgiCHtcl8Q6ekur7yp7YxN2A2Pzbxf8XFcO7yEu1Nto4j651UhZKyjF8vD1
         6R1o7LJ223UU4BcmnkUIEvZWBBOThtdzFnk+aD1NnlKiN6aMoR1aNPel+yHUzgh1l7Z5
         u85rp6pSkb3US7z0lmmFC7hYJJNUqq1bpWVaN+qeYTm/jvxT/+tSV6o7RwKwvJHEqnri
         1jLKnhMQnJ+ay3GI4qhg5dsV575mgoTC9q3QXg30UrVfeNE0bALd8fA2Fmpgcyv8vzGd
         HnfNTulXjV8Q+4V4OStsFlN0KrYIwz5Q/ymgVOztxBPk97D73A17SuPK5iKHtIn2fjpq
         Pykw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+7C3rRjIpPD6rbMZ5z84mNVmMXWH93G4ghNs3qVKIc0=;
        fh=HEeri+fgzgF1pvJBLUJC/ziUJ55VCcdomH/MOUdH4TA=;
        b=WR7XPCXvSpWSFyk4G1VtmawYCOJPycsj1SNBuroU2DtN4KV6ZyI2A3crRGGjuWOXkz
         VyDJdVaGrzrkFIccMhZvxMwbquFBtt+TKPRmoWbFE9Omf1VyRofzCtn9XZuuNTdoOK2X
         iU5wINL4SEkTHKu1q5icVjrgQn5KQQBZJVuG/ee7HFhENYkXX2gnwfRVn+5TQ+g3O95H
         Ei+7VXb9WEE1DsjB2PbJUxw8YHHKvmEW5U0ss0TVCkXUODLdYsA4jrTfEag98wl6LfQH
         WIjS3SN/RzLEhD4gZhW//OCtoZL8SKEMFtMJnNCuEPwaFZK7Sa9j2ztpQ+paOzhvTujP
         m/sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=DnPN+crQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689235945; x=1691827945;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+7C3rRjIpPD6rbMZ5z84mNVmMXWH93G4ghNs3qVKIc0=;
        b=CmxMwy7a+bEZiGAWHMobNEkyh0M47QXTiLvCTfDg/27Qn2p7xmX45C3jOHMLOwVTRf
         DzPkPJ9eaNzZeO4HITH5eB4qflcEif3sRKeQTR7R9NRu7+7DM7wK8jUtpGlwvHIGknJa
         NXlCcVkxdgSO/ngh8FmYC1KRs3AHYrDj9dcN4jhFNQCbAAkQaVNK2tHZZTT4cKYWC9Iq
         Cp1NPGYVg/9VFkVsfghPcf/PTQIpp5NiM5sVvmAlXpQixo8KscLY/EihPyHv374iTh5C
         Q2gKXf748h/FZFRHcat1JxN7WY4wH/YsvX9CShcikMyUrfjslGUNF/AHN2+uYiMEe7i6
         OR3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689235945; x=1691827945;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+7C3rRjIpPD6rbMZ5z84mNVmMXWH93G4ghNs3qVKIc0=;
        b=OB36MFz5vYny22Ffs6KRSnuM5xTlkRR56Kr85169DNSKa50el95B3OcdvqIOZqw2fy
         hQeAcmLQdvVsyfE/w1MlXDaqS9lFUnfovVXNcY0AwCEf1Ey6kU5e7qFtMBRuABgQm/RA
         q+YHE2FAM1NFGIcxDeuLEhhIfd+3VYY5bOdSVkJVZ/d4VdEqazimQqU9/JGy04+SxXZv
         2JuH+T726Tr3+slA7bb2u7hWaTQogPqCnJj0/yrPPvKeOx7hC34MC+4/ou9D8/BcT3Ld
         xaDo9fVpsV8RQ0dwRh6UUeZJ7ZHIYF1kiuJB7pIT55il++GFDosnqAUUfRggFfv+ls0e
         hVKQ==
X-Gm-Message-State: ABy/qLYjmm8f3IiQvmJHm/KqAqP6QL5Rlx56+Q85n5oqrziMY1c9/ydV
	mIloe0r7oHvrzyuKLpo7gdI=
X-Google-Smtp-Source: APBJJlH8C9K0W2TnKr58x7coe7xLaTQA9LGelb3n8ZAfaARR25TkuySBIse3tg95iFPhvDUaSpatfA==
X-Received: by 2002:a19:6459:0:b0:4f8:661f:60a4 with SMTP id b25-20020a196459000000b004f8661f60a4mr496363lfj.41.1689235944248;
        Thu, 13 Jul 2023 01:12:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:603:b0:4f8:52a6:ee15 with SMTP id
 b3-20020a056512060300b004f852a6ee15ls228426lfe.1.-pod-prod-07-eu; Thu, 13 Jul
 2023 01:12:22 -0700 (PDT)
X-Received: by 2002:a05:6512:3c81:b0:4f9:69af:9857 with SMTP id h1-20020a0565123c8100b004f969af9857mr765738lfv.51.1689235942462;
        Thu, 13 Jul 2023 01:12:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689235942; cv=none;
        d=google.com; s=arc-20160816;
        b=h9KH0ZcmEgn4jXYvyIEoisDczvwgFgtxQWtAbqNf05+gutmUFnnv3tVcjT6dJEQpK4
         6SiQO7rXPspGkQf6BHx47hl/051Uh5CrtU7LQ1iYK23RODsvpTrQFPWSIjksU0qJPmD7
         pY0YLZkfkX8nfGh+3Tf/wWcBLrgcrrVwHYz65wopllwZECmueNPsQZG9m4+Oa9NoJ6qx
         6+uB4Ukv3sOOy03a+Finj+gdtoIqwG9BMj8W30+EAwxRyiAuEOILOm1qfZJb7c7ixw/I
         yNM4Dn7MRkTp+XhIGnLg0AYC0wnxb4FzZQjcJg39pPGv4RIeU5eyxmhtwU6n/GVIl+N6
         BFtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TrQCc9kUgFr8IMcT2wAzVxl0kqKdfKNdGdTb067Hl18=;
        fh=2hAGxa7g7VqtPPlK3wVxmTgQGiCIRbvXF89XdKNrIsE=;
        b=IfZi0wgJEkB9tJw+KKYrpRxGHma8sKj6NdJOiNjYPxDTaVwpxuB2+WTm64rrP+w4Em
         41NC3qK3mUinStoes3iVijLoBo4pXlSVe06b5FXcW6UhxcHae0QzULI/3UDo67nhW4pd
         KZT1z/xjcG0IjLXzrseNw/0shRbMNGXfZ7jBb9QM9l3Yl0VXIYAVyeEBkp1G6hfDsSUc
         PKqSx2o2r+kJX9RR1rWPvl7eUPdhJbss+/Zk6U1jQHQAqopi5xoN8qN26wmqMAIR0ZfH
         bHfnjEpsx1ZFTdwWcbDfLOd70pn8TdZb/Q8qDFsSURUbYOAK6JO8JK4kwTmgwZVlFN0o
         UQTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=DnPN+crQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id z17-20020a056512309100b004fba12b2dfasi527172lfd.2.2023.07.13.01.12.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Jul 2023 01:12:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-3fc04692e20so3511935e9.0
        for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 01:12:22 -0700 (PDT)
X-Received: by 2002:a7b:cc15:0:b0:3fa:9561:3016 with SMTP id
 f21-20020a7bcc15000000b003fa95613016mr701967wmh.30.1689235941682; Thu, 13 Jul
 2023 01:12:21 -0700 (PDT)
MIME-Version: 1.0
References: <20230712101344.2714626-1-chenhuacai@loongson.cn>
 <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com> <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com>
In-Reply-To: <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Jul 2023 10:11:44 +0200
Message-ID: <CANpmjNM_FEpXPVgoAbUwEK+9m90X54ykWnMvpUP2ZQ8sjoSByg@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tests by removing -ffreestanding
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Huacai Chen <chenhuacai@loongson.cn>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=DnPN+crQ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 13 Jul 2023 at 06:33, Huacai Chen <chenhuacai@kernel.org> wrote:
>
> Hi, Andrey,
>
> On Thu, Jul 13, 2023 at 12:12=E2=80=AFAM Andrey Konovalov <andreyknvl@gma=
il.com> wrote:
> > On Wed, Jul 12, 2023 at 12:14=E2=80=AFPM Huacai Chen <chenhuacai@loongs=
on.cn> wrote:
> > >
> > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX hopes -fbuiltin for memset()/
> > > memcpy()/memmove() if instrumentation is needed. This is the default
> > > behavior but some archs pass -ffreestanding which implies -fno-builti=
n,
> > > and then causes some kasan tests fail. So we remove -ffreestanding fo=
r
> > > kasan tests.
> >
> > Could you clarify on which architecture you observed tests failures?
> Observed on LoongArch [1], KASAN for LoongArch was planned to be
> merged in 6.5, but at the last minute I found some tests fail with
> GCC14 (CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) so the patches are
> dropped. After some debugging we found the root cause is
> -ffreestanding.
[...]
> > >  CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> > > +CFLAGS_REMOVE_kasan_test.o :=3D -ffreestanding
> > >  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
> > > +CFLAGS_REMOVE_kasan_test_module.o :=3D -ffreestanding

It makes sense that if -ffreestanding is added everywhere, that this
patch fixes the test. Also see:
https://lkml.kernel.org/r/20230224085942.1791837-3-elver@google.com

-ffreestanding implies -fno-builtin, which used to be added to the
test where !CC_HAS_KASAN_MEMINTRINSIC_PREFIX (old compilers).

But ideally, the test doesn't have any special flags to make it pass,
because ultimately we want the test setup to be as close to other
normal kernel code.

What this means for LoongArch, is that the test legitimately is
pointing out an issue: namely that with newer compilers, your current
KASAN support for LoongArch is failing to detect bad accesses within
mem*() functions.

The reason newer compilers should emit __asan_mem*() functions and
replace normal mem*() functions, is that making mem*() functions
always instrumented is not safe when e.g. called from uninstrumented
code. One problem is that compilers will happily generate
memcpy/memset calls themselves for e.g. variable initialization or
struct copies - and unfortunately -ffreestanding does _not_ prohibit
compilers from doing so: https://godbolt.org/z/hxGvdo4P9

I would propose 2 options:

1. Removing -ffreestanding from LoongArch. It is unclear to me why
this is required. As said above, -ffreestanding does not actually
prohibit the compiler from generating implicit memset/memcpy. It
prohibits some other optimizations, but in the kernel, you might even
want those optimizations if common libcalls are already implemented
(which they should be?).

2. If KASAN is enabled on LoongArch, make memset/memcpy/memmove
aliases to __asan_memset/__asan_memcpy/__asan_memmove. That means
you'd have to invert how you currently set up __mem and mem functions:
the implementation is in __mem*, and mem* functions alias __mem* -or-
if KASAN is enabled __asan_mem* functions (ifdef
CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX to make old compilers work as
well).

If you go with option #2 you are accepting the risk of using
instrumented mem* functions from uninstrumented files/functions. This
has been an issue for other architectures. In many cases you might get
lucky enough that it doesn't cause issues, but that's not guaranteed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM_FEpXPVgoAbUwEK%2B9m90X54ykWnMvpUP2ZQ8sjoSByg%40mail.gmai=
l.com.
