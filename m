Return-Path: <kasan-dev+bncBDFKDBGSFYINRUXSSMDBUBEHQQZOU@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id CBC1B5245C6
	for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 08:29:45 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id n4-20020ac85b44000000b002f3940d55eesf3128516qtw.19
        for <lists+kasan-dev@lfdr.de>; Wed, 11 May 2022 23:29:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652336984; cv=pass;
        d=google.com; s=arc-20160816;
        b=b5JV0rDs19qUWYzB4LtjwWYn1681aMr8rfAXEkcc0k1/vPeTWm1CUSfA0o16XF5p0f
         Py+q4R1qPUp4iJAUf2GFmH+hXL5zWYOvxloOM3ReuHXblIr+qXL5P2uhh3FhtxucQCrG
         MSgCIpE46ui0ArIlFKW7k9xuNJz6hdyTxuKbP8SFKOxjqRsHcNb2HOsxAuFq08YNAx1Q
         yCiJOyPpIHHYNFgg6oT752cUcOtl6CjSJlR1dz/bTZxa1TD/dSGA3PBShv+kMUBR4mK8
         V6qbTONMcQqqr0r0OmBLjS/rngO1GtbMHgZsujtgUK/w3RHsgXdF4O2/2gyG5xvYkreH
         g6hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=GJTlq+jgXebhNSczLBgaKtK7mt3YFpTNA3xy+I0N3ZI=;
        b=gFJs0KniZJKEV9AY/zAjVBnzQUsZLOurSAxC6a4hls7tc7X/7VOjN12zCyB9wUumts
         hJKziiL9JvpJ8hdEYbKxwodSq/AZHyI8rzxBljs/QZigofjKlVIUkrSGgELF+TOarleu
         iiJsv3SY/ftKncNIpeebLaaOhMYuIwT0AtLMlwrwREJoQcVocnY9peOKjYjrxPd+WxYn
         2v+SIQbHYB7UYkoY0UWnrdLC8GxJNSmDSHxDLQjuRcrCgdW+racSpMOvnp3Xa9xy96jf
         K7sRq1xzyNsANJNZEXkxla2CW0vQlnQNmkJmRwyLYnBHTTIlvWI3/wZ8Kjsi3URNRIoH
         aABQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=KUQ7PIrt;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=atishp@atishpatra.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GJTlq+jgXebhNSczLBgaKtK7mt3YFpTNA3xy+I0N3ZI=;
        b=f7Z+qDXXVBLYmrkMtPQUQ9N/TJb1wkjMThw5CZT/ImjL4pOqHG40YtclchZdrChPbI
         KJ37jHcnrQav/hl+8tq5fdl9eEcPLBrE8l/3yILK8Vb9KRZeyMcyQgwunlbnb3oCcG+Y
         GrJcuMglGMPMzlge9TpvhNbp3/pR/fDD2HRmY8jbboD+QwZZCPTr+Q17VeFnl7crAuMM
         vjdVXJkkMAzu1SpN3lAttc9ir+t+Lrj+2ySEP6QHXUe/Qr3Jt6AdGbYEmnrGZa+Dszaj
         tRLbMBuC7gM2sDDw3XDcAjy/9WPPe4YjkRy/uPFyOKCz8yM2cCgxSJXBHN63h9avYC5s
         wr/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GJTlq+jgXebhNSczLBgaKtK7mt3YFpTNA3xy+I0N3ZI=;
        b=mR8XW3XRQhxOy5oL7wHLGWD4rGuQ86w0ujCpUSvW0LG1KRU4RiiNXe9ohWZ6Apqozg
         qyzgL4te6hg6kOULow4gfRyihHPtefITBE10lRu+0GfPs77qqCqy8VfFr2CWhjlYqfUv
         Wr2qfqaYG4gyASY741KfjHvGWYLZM/vxUqpxuUFOHUHjbmXT+SWZV1Xg18I51UI9rTV3
         w+PEncmfOkUMsKaaMpkm0Ir1meBAub5BVmjisi6zKSS56LMzqYyAaKmXveQblhs1b4yN
         zY0X6FI9Ot45KsF7a6XLlqjdzxCHDeAefqguTK0mbE98PFTGjGkIC/aeOF8EtaUoOA5V
         4UBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZyHjPFqwhbx7D15T3C/4o8k+cy3Z2tEve7zbwe9TtSn2b1NE8
	80TaOAhCG9kkxpqfHMYWxIE=
X-Google-Smtp-Source: ABdhPJzCf7uRhw1elatRnX6fGY3ihP0FjGU8tlgIRs4TFCdtIdZNVSn0oVfYHn/ymppE4UpCjfFAmQ==
X-Received: by 2002:a05:6214:21af:b0:45b:694:47ce with SMTP id t15-20020a05621421af00b0045b069447cemr17602945qvc.33.1652336984722;
        Wed, 11 May 2022 23:29:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1f85:b0:2f3:c7c1:2dbe with SMTP id
 cb5-20020a05622a1f8500b002f3c7c12dbels2718289qtb.0.gmail; Wed, 11 May 2022
 23:29:44 -0700 (PDT)
X-Received: by 2002:a05:622a:1212:b0:2f3:bd14:1ec6 with SMTP id y18-20020a05622a121200b002f3bd141ec6mr27534996qtx.342.1652336984252;
        Wed, 11 May 2022 23:29:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652336984; cv=none;
        d=google.com; s=arc-20160816;
        b=W8pI+iR0XoCCMY7L4HfEN7rYK1TwYAF/eUuvZzwO5+Cxwu+19edHpKEvrTgPMF/rDh
         ruokUm902itq8oT+dMb/MnWkEJ1Tr5UbrKz/OSLXK45oKt18a32kXuiydgBw6P1CXHBW
         mp3CICyqv4avP1KognBgw7IRPkZDNVjLs6bx7FB1Cmr9+ReQPZWYoFPfCjpb+HuKGyNW
         N3So3NsYjRpbBN8PCJKOAuQmK/4ImShSeCKdGsaMKj9nNyEwlHd5kysH7iVydbxDLYwJ
         ezd7gbRj1P1anwv48giSKtZM5N+a4FEcrTostFXjPYJdOz3iOoLdT7XfvhTmV9T8+suG
         xK2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UsIye2bBDqtRb22afIRHd19srECco2EdRoKMOSfw2lU=;
        b=TanR4oaY3tSVTnfQeoQUPyzHbyfjhgTWnRtwHtKMEByMTa26ZKh+asETGq1P/MjOMF
         aPjQ2IEultuZPHokpoqsxvSik/SaUsaUYbSjZNgw1kNJMZLgTpj9XwvEZ//rqSWfZigU
         oZSB+6PR+qOusaQqXtVdb8+IQ/8oX2FmSRXGAYzDpdWn7K3vuQ0wBVjknunKIHC/ZfTb
         JGCCVfhhp0JL+oAxsXJJ73Y997XB9H8Nvr0fnMEyA03ttAj9jyNvtlCwF7EEcJx7kc0d
         7qsXJH5SfpUu7GXWalWKFb1VU2n3IHcj9OHP/XylelMjmDtH7pRWe9n+97XFVjATL5R1
         YKLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=KUQ7PIrt;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=atishp@atishpatra.org
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id k19-20020ae9f113000000b0069f96278236si226245qkg.0.2022.05.11.23.29.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 May 2022 23:29:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id w187so7998084ybe.2
        for <kasan-dev@googlegroups.com>; Wed, 11 May 2022 23:29:44 -0700 (PDT)
X-Received: by 2002:a25:b20e:0:b0:64b:4c0f:be27 with SMTP id
 i14-20020a25b20e000000b0064b4c0fbe27mr3490771ybj.53.1652336983775; Wed, 11
 May 2022 23:29:43 -0700 (PDT)
MIME-Version: 1.0
References: <20220508160749.984-1-jszhang@kernel.org> <20220508160749.984-3-jszhang@kernel.org>
 <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com> <YnkoKxaPbrTnZPQv@xhacker>
In-Reply-To: <YnkoKxaPbrTnZPQv@xhacker>
From: Atish Patra <atishp@atishpatra.org>
Date: Wed, 11 May 2022 23:29:32 -0700
Message-ID: <CAOnJCU+XR5mtqKBQLMj3JgsTPgvAQdO_jj2FWqcu7f9MezNCKA@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] riscv: introduce unified static key mechanism for
 CPU features
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Anup Patel <apatel@ventanamicro.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: atishp@atishpatra.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@atishpatra.org header.s=google header.b=KUQ7PIrt;       spf=pass
 (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::b2c
 as permitted sender) smtp.mailfrom=atishp@atishpatra.org
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

On Mon, May 9, 2022 at 7:50 AM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> On Mon, May 09, 2022 at 09:17:10AM +0530, Anup Patel wrote:
> > On Sun, May 8, 2022 at 9:47 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> > >
> > > Currently, riscv has several features why may not be supported on all
> > > riscv platforms, for example, FPU, SV48 and so on. To support unified
> > > kernel Image style, we need to check whether the feature is suportted
> > > or not. If the check sits at hot code path, then performance will be
> > > impacted a lot. static key can be used to solve the issue. In the past
> > > FPU support has been converted to use static key mechanism. I believe
> > > we will have similar cases in the future.
> >
> > It's not just FPU and Sv48. There are several others such as Svinval,
> > Vector, Svnapot, Svpbmt, and many many others.
> >
> > Overall, I agree with the approach of using static key array but I
> > disagree with the semantics and the duplicate stuff being added.
> >
> > Please see more comments below ..
> >
> > >
> > > Similar as arm64 does(in fact, some code is borrowed from arm64), this
> > > patch tries to add an unified mechanism to use static keys for all
> > > the cpu features by implementing an array of default-false static keys
> > > and enabling them when detected. The cpus_have_*_cap() check uses the
> > > static keys if riscv_const_caps_ready is finalized, otherwise the
> > > compiler generates the bitmap test.
> >
> > First of all, we should stop calling this a feature (like ARM does). Rather,
> > we should call these as isa extensions ("isaext") to align with the RISC-V
> > priv spec and RISC-V profiles spec. For all the ISA optionalities which do
> > not have distinct extension name, the RISC-V profiles spec is assigning
> > names to all such optionalities.
>
> Same as the reply a few minutes ago, the key problem here is do all
> CPU features belong to *ISA* extensions? For example, SV48, SV57 etc.
> I agree with Atish's comments here:
>
> "I think the cpu feature is a superset of the ISA extension.
> cpu feature != ISA extension"
>

It seems to be accurate at that point in time. However, the latest
profile spec seems to
define everything as an extension including sv48.

https://github.com/riscv/riscv-profiles/blob/main/profiles.adoc#623-rva22s64-supported-optional-extensions

It may be a redundant effort and confusing to create two sets i.e.
feature and extension in this case.
But this specification is not frozen yet and may change in the future.
We at least know that that is the current intention.

Array of static keys is definitely useful and should be used for all
well defined ISA extensions by the ratified priv spec.
This will simplify this patch as well. For any feature/extensions
(i.e. sv48/sv57) which was never defined as an extension
in the priv spec but profile seems to define it now, I would leave it
alone for the time being. Converting the existing code
to static key probably has value but please do not include it in the
static key array setup.

Once the profile spec is frozen, we can decide which direction the
Linux kernel should go.

> https://lore.kernel.org/linux-riscv/CAHBxVyF65jC_wvxcD6bueqpCY8-Kbahu1yxsSoBmO1s15dGkSQ@mail.gmail.com/
>
> >
> > Another issue with semantics is that this patch assumes all features are
> > enabled by default and we selectively disable it. This contrary to the
> > approach taken by existing arch/riscv/kernel/cpufeature.c which assumes
> > nothing is enabled by default and we selectively enable it.
>
> This is implementation related, can be modified in next version. From
> another side, assuming some feature enabled by default can result in
> trivial performance improvement for most platforms. For example, if
> most platforms are FPU capable, we'd better assume FPU enabled by default.
>
> >
> > >
> > > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> > > ---
> > >  arch/riscv/Makefile                 |  3 +
> > >  arch/riscv/include/asm/cpufeature.h | 94 +++++++++++++++++++++++++++++
> > >  arch/riscv/kernel/cpufeature.c      | 23 +++++++
> > >  arch/riscv/tools/Makefile           | 22 +++++++
> > >  arch/riscv/tools/cpucaps            |  5 ++
> > >  arch/riscv/tools/gen-cpucaps.awk    | 40 ++++++++++++
> > >  6 files changed, 187 insertions(+)
> > >  create mode 100644 arch/riscv/include/asm/cpufeature.h
> > >  create mode 100644 arch/riscv/tools/Makefile
> > >  create mode 100644 arch/riscv/tools/cpucaps
> > >  create mode 100755 arch/riscv/tools/gen-cpucaps.awk
> > >
> > > diff --git a/arch/riscv/Makefile b/arch/riscv/Makefile
> > > index 7d81102cffd4..f4df67369d84 100644
> > > --- a/arch/riscv/Makefile
> > > +++ b/arch/riscv/Makefile
> > > @@ -154,3 +154,6 @@ PHONY += rv64_randconfig
> > >  rv64_randconfig:
> > >         $(Q)$(MAKE) KCONFIG_ALLCONFIG=$(srctree)/arch/riscv/configs/64-bit.config \
> > >                 -f $(srctree)/Makefile randconfig
> > > +
> > > +archprepare:
> > > +       $(Q)$(MAKE) $(build)=arch/riscv/tools kapi
> > > diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
> > > new file mode 100644
> > > index 000000000000..d80ddd2f3b49
> > > --- /dev/null
> > > +++ b/arch/riscv/include/asm/cpufeature.h
> >
> > We don't need a separate header for this.
> >
> > All this belongs to arch/riscv/include/asm/hwcap.h
> >
> > > @@ -0,0 +1,94 @@
> > > +/* SPDX-License-Identifier: GPL-2.0-only */
> > > +/*
> > > + * Copyright (C) 2014 Linaro Ltd. <ard.biesheuvel@linaro.org>
> > > + * Copyright (C) 2022 Jisheng Zhang <jszhang@kernel.org>
> > > + */
> > > +
> > > +#ifndef __ASM_CPUFEATURE_H
> > > +#define __ASM_CPUFEATURE_H
> > > +
> > > +#include <asm/cpucaps.h>
> > > +
> > > +#include <linux/bug.h>
> > > +#include <linux/jump_label.h>
> > > +#include <linux/kernel.h>
> > > +
> > > +extern DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
> >
> > This is a redundant bitmap. Please re-use "riscv_isa" bitmap for this
> > the ISA extensions.
> >
> > > +extern struct static_key_false cpu_hwcap_keys[RISCV_NCAPS];
> >
> > This should be called "riscv_isa_keys"
> >
> > > +extern struct static_key_false riscv_const_caps_ready;
> >
> > This should be called "riscv_isa_keys_ready".
> >
> > > +
> > > +static __always_inline bool system_capabilities_finalized(void)
> >
> > Another misaligned name. This should be called
> > "riscv_isa_keys_finalized()".
> >
> > > +{
> > > +       return static_branch_likely(&riscv_const_caps_ready);
> > > +}
> > > +
> > > +/*
> > > + * Test for a capability with a runtime check.
> > > + *
> > > + * Before the capability is detected, this returns false.
> > > + */
> > > +static inline bool cpus_have_cap(unsigned int num)
> > > +{
> > > +       if (num >= RISCV_NCAPS)
> > > +               return false;
> > > +       return test_bit(num, cpu_hwcaps);
> > > +}
> >
> > This should be called riscv_isa_have_extension() and it should
> > internally call "__riscv_isa_extension_available(NULL, num)".
> >
> > > +
> > > +/*
> > > + * Test for a capability without a runtime check.
> > > + *
> > > + * Before capabilities are finalized, this returns false.
> > > + * After capabilities are finalized, this is patched to avoid a runtime check.
> > > + *
> > > + * @num must be a compile-time constant.
> > > + */
> > > +static __always_inline bool __cpus_have_const_cap(int num)
> >
> > This should be named "__riscv_isa_have_const_extension()"
> >
> > > +{
> > > +       if (num >= RISCV_NCAPS)
> > > +               return false;
> > > +       return static_branch_unlikely(&cpu_hwcap_keys[num]);
> > > +}
> > > +
> > > +/*
> > > + * Test for a capability without a runtime check.
> > > + *
> > > + * Before capabilities are finalized, this will BUG().
> > > + * After capabilities are finalized, this is patched to avoid a runtime check.
> > > + *
> > > + * @num must be a compile-time constant.
> > > + */
> > > +static __always_inline bool cpus_have_final_cap(int num)
> >
> > This should be called "riscv_isa_have_final_extension()"
> >
> > > +{
> > > +       if (system_capabilities_finalized())
> > > +               return __cpus_have_const_cap(num);
> > > +       else
> > > +               BUG();
> > > +}
> > > +
> > > +/*
> > > + * Test for a capability, possibly with a runtime check.
> > > + *
> > > + * Before capabilities are finalized, this behaves as cpus_have_cap().
> > > + * After capabilities are finalized, this is patched to avoid a runtime check.
> > > + *
> > > + * @num must be a compile-time constant.
> > > + */
> > > +static __always_inline bool cpus_have_const_cap(int num)
> >
> > Same comment as above.
> >
> > > +{
> > > +       if (system_capabilities_finalized())
> > > +               return __cpus_have_const_cap(num);
> > > +       else
> > > +               return cpus_have_cap(num);
> > > +}
> > > +
> > > +static inline void cpus_set_cap(unsigned int num)
> >
> > Same comment as above.
> >
> > > +{
> > > +       if (num >= RISCV_NCAPS) {
> > > +               pr_warn("Attempt to set an illegal CPU capability (%d >= %d)\n",
> > > +                       num, RISCV_NCAPS);
> > > +       } else {
> > > +               __set_bit(num, cpu_hwcaps);
> > > +       }
> > > +}
> > > +
> > > +#endif
> > > diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
> > > index 1b2d42d7f589..e6c72cad0c1c 100644
> > > --- a/arch/riscv/kernel/cpufeature.c
> > > +++ b/arch/riscv/kernel/cpufeature.c
> > > @@ -9,6 +9,7 @@
> > >  #include <linux/bitmap.h>
> > >  #include <linux/ctype.h>
> > >  #include <linux/of.h>
> > > +#include <asm/cpufeature.h>
> > >  #include <asm/processor.h>
> > >  #include <asm/hwcap.h>
> > >  #include <asm/smp.h>
> > > @@ -25,6 +26,15 @@ static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
> > >  __ro_after_init DEFINE_STATIC_KEY_FALSE(cpu_hwcap_fpu);
> > >  #endif
> > >
> > > +DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
> > > +EXPORT_SYMBOL(cpu_hwcaps);
> >
> > Just like the previous comment. This is a redundant bitmap.
> > Please use "riscv_isa" bitmap for this purpose.
> >
> > > +
> > > +DEFINE_STATIC_KEY_ARRAY_FALSE(cpu_hwcap_keys, RISCV_NCAPS);
> > > +EXPORT_SYMBOL(cpu_hwcap_keys);
> > > +
> > > +DEFINE_STATIC_KEY_FALSE(riscv_const_caps_ready);
> > > +EXPORT_SYMBOL(riscv_const_caps_ready);
> >
> > Please see comments above.
> >
> > > +
> > >  /**
> > >   * riscv_isa_extension_base() - Get base extension word
> > >   *
> > > @@ -62,6 +72,17 @@ bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, int bit)
> > >  }
> > >  EXPORT_SYMBOL_GPL(__riscv_isa_extension_available);
> > >
> > > +static void __init enable_cpu_capabilities(void)
> > > +{
> > > +       int i;
> > > +
> > > +       for (i = 0; i < RISCV_NCAPS; i++) {
> > > +               if (!cpus_have_cap(i))
> > > +                       continue;
> > > +               static_branch_enable(&cpu_hwcap_keys[i]);
> > > +       }
> > > +}
> > > +
> > >  void __init riscv_fill_hwcap(void)
> > >  {
> > >         struct device_node *node;
> > > @@ -236,4 +257,6 @@ void __init riscv_fill_hwcap(void)
> > >         if (elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D))
> > >                 static_branch_enable(&cpu_hwcap_fpu);
> > >  #endif
> > > +       enable_cpu_capabilities();
> > > +       static_branch_enable(&riscv_const_caps_ready);
> > >  }
> > > diff --git a/arch/riscv/tools/Makefile b/arch/riscv/tools/Makefile
> > > new file mode 100644
> > > index 000000000000..932b4fe5c768
> > > --- /dev/null
> > > +++ b/arch/riscv/tools/Makefile
> > > @@ -0,0 +1,22 @@
> > > +# SPDX-License-Identifier: GPL-2.0
> > > +
> > > +gen := arch/$(ARCH)/include/generated
> > > +kapi := $(gen)/asm
> > > +
> > > +kapi-hdrs-y := $(kapi)/cpucaps.h
> > > +
> > > +targets += $(addprefix ../../../,$(gen-y) $(kapi-hdrs-y))
> > > +
> > > +PHONY += kapi
> > > +
> > > +kapi:   $(kapi-hdrs-y) $(gen-y)
> > > +
> > > +# Create output directory if not already present
> > > +_dummy := $(shell [ -d '$(kapi)' ] || mkdir -p '$(kapi)')
> > > +
> > > +quiet_cmd_gen_cpucaps = GEN     $@
> > > +      cmd_gen_cpucaps = mkdir -p $(dir $@) && \
> > > +                     $(AWK) -f $(filter-out $(PHONY),$^) > $@
> > > +
> > > +$(kapi)/cpucaps.h: $(src)/gen-cpucaps.awk $(src)/cpucaps FORCE
> > > +       $(call if_changed,gen_cpucaps)
> > > diff --git a/arch/riscv/tools/cpucaps b/arch/riscv/tools/cpucaps
> > > new file mode 100644
> > > index 000000000000..cb1ff2747859
> > > --- /dev/null
> > > +++ b/arch/riscv/tools/cpucaps
> > > @@ -0,0 +1,5 @@
> > > +# SPDX-License-Identifier: GPL-2.0
> > > +#
> > > +# Internal CPU capabilities constants, keep this list sorted
> > > +
> > > +HAS_NO_FPU
> >
> > How can "No FPU" be a CPU capability ?
> >
> > We have ISA extensions 'F' and 'D' which tells us whether an FPU is available
> > or not.
> >
> > I think this file should be a table with two columns
> > "<lower_case_extension_name> <parsed_from_isa_string_yes_no>"
> > I this this file should look like this:
> >
> > i yes
> > m yes
> > a yes
> > c yes
> > f yes
> > d yes
> > h yes
> > sv48 no
> > sv57 no
> > sstc yes
> > svinval yes
> > svpbmt yes
> > svnapot yes
> > sscofpmf yes
> > ...
> >
> > > diff --git a/arch/riscv/tools/gen-cpucaps.awk b/arch/riscv/tools/gen-cpucaps.awk
> > > new file mode 100755
> > > index 000000000000..52a1e1b064ad
> > > --- /dev/null
> > > +++ b/arch/riscv/tools/gen-cpucaps.awk
> > > @@ -0,0 +1,40 @@
> > > +#!/bin/awk -f
> > > +# SPDX-License-Identifier: GPL-2.0
> > > +# gen-cpucaps.awk: riscv cpucaps header generator
> > > +#
> > > +# Usage: awk -f gen-cpucaps.awk cpucaps.txt
> > > +
> > > +# Log an error and terminate
> > > +function fatal(msg) {
> > > +       print "Error at line " NR ": " msg > "/dev/stderr"
> > > +       exit 1
> > > +}
> > > +
> > > +# skip blank lines and comment lines
> > > +/^$/ { next }
> > > +/^#/ { next }
> > > +
> > > +BEGIN {
> > > +       print "#ifndef __ASM_CPUCAPS_H"
> > > +       print "#define __ASM_CPUCAPS_H"
> > > +       print ""
> > > +       print "/* Generated file - do not edit */"
> > > +       cap_num = 0
> > > +       print ""
> > > +}
> > > +
> > > +/^[vA-Z0-9_]+$/ {
> > > +       printf("#define RISCV_%-30s\t%d\n", $0, cap_num++)
> > > +       next
> > > +}
> > > +
> > > +END {
> > > +       printf("#define RISCV_NCAPS\t\t\t\t%d\n", cap_num)
> > > +       print ""
> > > +       print "#endif /* __ASM_CPUCAPS_H */"
> > > +}
> >
> > This script need to change refer capabilities as extensions.
> >
> > For every extension, there should be two defines.
> > For e.g. "sstc" extension should have following defines
> > #define RISCV_ISA_EXT_sstc <#num>
> > #define RISCV_ISA_EXT_FROMSTR_sstc <1|0>
> >
> > > +
> > > +# Any lines not handled by previous rules are unexpected
> > > +{
> > > +       fatal("unhandled statement")
> > > +}
> > > --
> > > 2.34.1
> > >
> >
> > Regards,
> > Anup
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv



-- 
Regards,
Atish

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOnJCU%2BXR5mtqKBQLMj3JgsTPgvAQdO_jj2FWqcu7f9MezNCKA%40mail.gmail.com.
