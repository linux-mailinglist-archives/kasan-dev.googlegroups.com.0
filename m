Return-Path: <kasan-dev+bncBAABBMOU4SJQMGQEPUAABQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DD2752004C
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 16:50:26 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 23-20020a05651c00d700b0024f12064717sf4224812ljr.15
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 07:50:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652107826; cv=pass;
        d=google.com; s=arc-20160816;
        b=b5chqSsi+wJVJUa48TiAWNwL13TJCSdf02HLA3oy7JoK1E7beWssFeyRFoAXWXs/5U
         vjQE3cYE/4OPNsAFla9w5O8v40xsPddL/E9qS0x2IVY1ftw7kcO0qhSUn8ld60gBtmGB
         KtZma5JLlmMBuY2r8HtXjiXlT5vGBhiJLv2Xc0t+pXnBrSSmLdf+hyXjdyosy94hQqnO
         FrfzVYMCWHgMuIz6wqJqwD/phYXSTflUTpMqIplrQpLFoZRnYIocYPslnf+xw8fqWFmz
         io0GmBSbyNkJ2nvZL0LMKtfpggM+3pmGInshmqBX5i9DPQ7jxBAUWYIciiQBdKbuuFsT
         d/6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9zHCGBg4O1im7SI94nm1pWzLsErVc7lF8EcPfSngweE=;
        b=TVIFTdRdF8MmDViIip9FvGZ8aDRSwxn+mWkA0FgFkklNm2EhIr9fgcaYXwQeiua0Qp
         kgvZAwtnGqNFG8yqOiTlLBKchpeZRxv3EybZmGWLLtui2oPoAcwtQv20nDfB+GlrzpJS
         SQd+Ie+1Uq05fhL/2yc1yk3WtM9qkZz3pk9nHGyxS1gjqCvyUrlVXxSzH6ER10ctTYOy
         OSxtGB8z+Ytwn5dlH+/nO47pcvi5vR7KS2HwU3vsnEmGimp2RN9lzjfq0ntAJbJ5xQ9v
         Bj6V5Z2OstZ0lbkgSFQGfDt7C6ero1RYA/24gvms0yqb7Q2xnBxX6rtF6K2GSq47Xve/
         fzfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tAj9LYXq;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9zHCGBg4O1im7SI94nm1pWzLsErVc7lF8EcPfSngweE=;
        b=UyIQWzau9u2HoEH6H4vZQymEZgqjuD2aCi2WEXHzWqhLQMZreo2sd54HmhShYIy//l
         qXSbTQM8LVs/A8duTbtqbm/lc0ZOS+J9GBoYPiPjQEhpVum0LsMxV0TgGKaoFZlNx6Yu
         s+bpiEvKbvOLbzAjLV1Q6qvYz68pGfiSYvub5WN5Iw1fR+QOl44edBRA/NbY5Yatf3ju
         LyHRwHGh579MR7W3dzC0+yOnAzEgIQ6F5x+qhg9hv5ehewC7ObycLt9xEjG28rgqjv7X
         cSkNHxd/PGKe3fvdXOfmBTGDlJeLA6s0tSZZmqCk3YAVApeujq7YzV7+S5xjkgxMUGy6
         6wwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9zHCGBg4O1im7SI94nm1pWzLsErVc7lF8EcPfSngweE=;
        b=k41gAKBIwwtFhNRxxyQt0z48urZohxXIpmONaM0/hrrQFrHx6PXi3P8UpZFk1SLG1v
         qTPdF2/xEPboVYuyj0Mq0h7obMb2qLnpqg3UfV39Y/RRF9bQJOAol9h5oQc6Fa5Fvaai
         NeNYsLUcYClsvBa35lWzH/HQE1tef1TOh58c+V+sqN8r2s9WpyTVsdiY20/4HZ2bwIZW
         St8RIdsuB/0zl/SDnv3srlkVsd1Dt1rUoXohcQ97pIclWH7w/+w5xRetwjpGRmo8pwLr
         ivhbS+F3E187QaZRWSAwUVfctGLo5ZhWUabDRNSZSBqx/qL3fwDyowmgXNN4h/48ZSul
         0+lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531p/7tjw423Ukmud410v8GpSoZGXw4ZwZoGAtC+wvTXBXpTKcKW
	oED8kPu66cCQnJyJqFG2550=
X-Google-Smtp-Source: ABdhPJxSJMH9NW5ELXL3ZY4LQpESrZqd4JxsPOko0MXO1KZbMEdbYbRqlpDF85AqRzzlpjQRrcDNwQ==
X-Received: by 2002:a2e:a30a:0:b0:24f:cf6:11ab with SMTP id l10-20020a2ea30a000000b0024f0cf611abmr10496243lje.461.1652107825986;
        Mon, 09 May 2022 07:50:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als2440684lfa.2.gmail; Mon, 09 May 2022
 07:50:25 -0700 (PDT)
X-Received: by 2002:a05:6512:12c9:b0:473:c33e:a65b with SMTP id p9-20020a05651212c900b00473c33ea65bmr13423052lfg.285.1652107825147;
        Mon, 09 May 2022 07:50:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652107825; cv=none;
        d=google.com; s=arc-20160816;
        b=0hsg/3jv1odHcL+URKjXZ/CBYVh4zggwH4vkkawnR2bZv2Rix6Pex1yOggjCifO+5s
         r8WbdqayTdgllwqBNp0DJVDtqTjkR2xsX8oTAHjSGXffRAicpPlE6CBg+wnO3KspO1Al
         VYfi6i81oAs7YoiV9voCswKwYjXHYRxxVFs8o4SHdf2x0UV0rK/tYLMiqHxpUQ7t3dVC
         Xg/wMuBOuYRZlmV0jq5Zd5n5AoPIzH8DnlvAJGmlUNvwDrDuMdZ/dMQGJlSKdH4zUzsA
         GgSIJPJWTXpsGLNGaWxByxxUK35Rit7ifH+EAyPqYJJNojvg4sYIjftExDtlvpNxSU5d
         NOAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CdsgVqLO+zlKjLqNgvnJmfCA+0G59IC8NzHd7PkUylQ=;
        b=vHeecDj14pVObTEb/sP0b9YgphOgvB13nNUYd0qjuP8/8S+LtneCguK5bCbllM1eDb
         orqBTXCTA2cFf0Y9oGn8H19WsRplDn3t//B7MXdc11/IJR3Cj8JeSmlYgtZ/Tjt1CYEG
         zGVIsvnFE6KnRD9nX44FdDdkdDe0RbWd/wHLyE5E6Bt4Cu8O6ADiKyE9731VudBbAdnP
         WgLXLDtcXjPfUtdX/g7bdm03Zf4PF0UNYkZb6sxxk4kKMbkGRryuXZsbx/D0trERQ44+
         kGug316TmKZP6kwFULa50tj6G5/Pr2mMkYDwipQP1hFqNAj5yWvrWnFHkqlhh7sQnfyv
         FBkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tAj9LYXq;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id v8-20020a056512348800b0047238f0bc72si666167lfr.12.2022.05.09.07.50.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 May 2022 07:50:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 51EDBB815FC;
	Mon,  9 May 2022 14:50:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E2E39C385AE;
	Mon,  9 May 2022 14:50:15 +0000 (UTC)
Date: Mon, 9 May 2022 22:41:47 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Anup Patel <apatel@ventanamicro.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	linux-riscv <linux-riscv@lists.infradead.org>,
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 2/4] riscv: introduce unified static key mechanism for
 CPU features
Message-ID: <YnkoKxaPbrTnZPQv@xhacker>
References: <20220508160749.984-1-jszhang@kernel.org>
 <20220508160749.984-3-jszhang@kernel.org>
 <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tAj9LYXq;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, May 09, 2022 at 09:17:10AM +0530, Anup Patel wrote:
> On Sun, May 8, 2022 at 9:47 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> >
> > Currently, riscv has several features why may not be supported on all
> > riscv platforms, for example, FPU, SV48 and so on. To support unified
> > kernel Image style, we need to check whether the feature is suportted
> > or not. If the check sits at hot code path, then performance will be
> > impacted a lot. static key can be used to solve the issue. In the past
> > FPU support has been converted to use static key mechanism. I believe
> > we will have similar cases in the future.
> 
> It's not just FPU and Sv48. There are several others such as Svinval,
> Vector, Svnapot, Svpbmt, and many many others.
> 
> Overall, I agree with the approach of using static key array but I
> disagree with the semantics and the duplicate stuff being added.
> 
> Please see more comments below ..
> 
> >
> > Similar as arm64 does(in fact, some code is borrowed from arm64), this
> > patch tries to add an unified mechanism to use static keys for all
> > the cpu features by implementing an array of default-false static keys
> > and enabling them when detected. The cpus_have_*_cap() check uses the
> > static keys if riscv_const_caps_ready is finalized, otherwise the
> > compiler generates the bitmap test.
> 
> First of all, we should stop calling this a feature (like ARM does). Rather,
> we should call these as isa extensions ("isaext") to align with the RISC-V
> priv spec and RISC-V profiles spec. For all the ISA optionalities which do
> not have distinct extension name, the RISC-V profiles spec is assigning
> names to all such optionalities.

Same as the reply a few minutes ago, the key problem here is do all
CPU features belong to *ISA* extensions? For example, SV48, SV57 etc.
I agree with Atish's comments here:

"I think the cpu feature is a superset of the ISA extension.
cpu feature != ISA extension"

https://lore.kernel.org/linux-riscv/CAHBxVyF65jC_wvxcD6bueqpCY8-Kbahu1yxsSoBmO1s15dGkSQ@mail.gmail.com/

> 
> Another issue with semantics is that this patch assumes all features are
> enabled by default and we selectively disable it. This contrary to the
> approach taken by existing arch/riscv/kernel/cpufeature.c which assumes
> nothing is enabled by default and we selectively enable it.

This is implementation related, can be modified in next version. From
another side, assuming some feature enabled by default can result in
trivial performance improvement for most platforms. For example, if
most platforms are FPU capable, we'd better assume FPU enabled by default.

> 
> >
> > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> > ---
> >  arch/riscv/Makefile                 |  3 +
> >  arch/riscv/include/asm/cpufeature.h | 94 +++++++++++++++++++++++++++++
> >  arch/riscv/kernel/cpufeature.c      | 23 +++++++
> >  arch/riscv/tools/Makefile           | 22 +++++++
> >  arch/riscv/tools/cpucaps            |  5 ++
> >  arch/riscv/tools/gen-cpucaps.awk    | 40 ++++++++++++
> >  6 files changed, 187 insertions(+)
> >  create mode 100644 arch/riscv/include/asm/cpufeature.h
> >  create mode 100644 arch/riscv/tools/Makefile
> >  create mode 100644 arch/riscv/tools/cpucaps
> >  create mode 100755 arch/riscv/tools/gen-cpucaps.awk
> >
> > diff --git a/arch/riscv/Makefile b/arch/riscv/Makefile
> > index 7d81102cffd4..f4df67369d84 100644
> > --- a/arch/riscv/Makefile
> > +++ b/arch/riscv/Makefile
> > @@ -154,3 +154,6 @@ PHONY += rv64_randconfig
> >  rv64_randconfig:
> >         $(Q)$(MAKE) KCONFIG_ALLCONFIG=$(srctree)/arch/riscv/configs/64-bit.config \
> >                 -f $(srctree)/Makefile randconfig
> > +
> > +archprepare:
> > +       $(Q)$(MAKE) $(build)=arch/riscv/tools kapi
> > diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
> > new file mode 100644
> > index 000000000000..d80ddd2f3b49
> > --- /dev/null
> > +++ b/arch/riscv/include/asm/cpufeature.h
> 
> We don't need a separate header for this.
> 
> All this belongs to arch/riscv/include/asm/hwcap.h
> 
> > @@ -0,0 +1,94 @@
> > +/* SPDX-License-Identifier: GPL-2.0-only */
> > +/*
> > + * Copyright (C) 2014 Linaro Ltd. <ard.biesheuvel@linaro.org>
> > + * Copyright (C) 2022 Jisheng Zhang <jszhang@kernel.org>
> > + */
> > +
> > +#ifndef __ASM_CPUFEATURE_H
> > +#define __ASM_CPUFEATURE_H
> > +
> > +#include <asm/cpucaps.h>
> > +
> > +#include <linux/bug.h>
> > +#include <linux/jump_label.h>
> > +#include <linux/kernel.h>
> > +
> > +extern DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
> 
> This is a redundant bitmap. Please re-use "riscv_isa" bitmap for this
> the ISA extensions.
> 
> > +extern struct static_key_false cpu_hwcap_keys[RISCV_NCAPS];
> 
> This should be called "riscv_isa_keys"
> 
> > +extern struct static_key_false riscv_const_caps_ready;
> 
> This should be called "riscv_isa_keys_ready".
> 
> > +
> > +static __always_inline bool system_capabilities_finalized(void)
> 
> Another misaligned name. This should be called
> "riscv_isa_keys_finalized()".
> 
> > +{
> > +       return static_branch_likely(&riscv_const_caps_ready);
> > +}
> > +
> > +/*
> > + * Test for a capability with a runtime check.
> > + *
> > + * Before the capability is detected, this returns false.
> > + */
> > +static inline bool cpus_have_cap(unsigned int num)
> > +{
> > +       if (num >= RISCV_NCAPS)
> > +               return false;
> > +       return test_bit(num, cpu_hwcaps);
> > +}
> 
> This should be called riscv_isa_have_extension() and it should
> internally call "__riscv_isa_extension_available(NULL, num)".
> 
> > +
> > +/*
> > + * Test for a capability without a runtime check.
> > + *
> > + * Before capabilities are finalized, this returns false.
> > + * After capabilities are finalized, this is patched to avoid a runtime check.
> > + *
> > + * @num must be a compile-time constant.
> > + */
> > +static __always_inline bool __cpus_have_const_cap(int num)
> 
> This should be named "__riscv_isa_have_const_extension()"
> 
> > +{
> > +       if (num >= RISCV_NCAPS)
> > +               return false;
> > +       return static_branch_unlikely(&cpu_hwcap_keys[num]);
> > +}
> > +
> > +/*
> > + * Test for a capability without a runtime check.
> > + *
> > + * Before capabilities are finalized, this will BUG().
> > + * After capabilities are finalized, this is patched to avoid a runtime check.
> > + *
> > + * @num must be a compile-time constant.
> > + */
> > +static __always_inline bool cpus_have_final_cap(int num)
> 
> This should be called "riscv_isa_have_final_extension()"
> 
> > +{
> > +       if (system_capabilities_finalized())
> > +               return __cpus_have_const_cap(num);
> > +       else
> > +               BUG();
> > +}
> > +
> > +/*
> > + * Test for a capability, possibly with a runtime check.
> > + *
> > + * Before capabilities are finalized, this behaves as cpus_have_cap().
> > + * After capabilities are finalized, this is patched to avoid a runtime check.
> > + *
> > + * @num must be a compile-time constant.
> > + */
> > +static __always_inline bool cpus_have_const_cap(int num)
> 
> Same comment as above.
> 
> > +{
> > +       if (system_capabilities_finalized())
> > +               return __cpus_have_const_cap(num);
> > +       else
> > +               return cpus_have_cap(num);
> > +}
> > +
> > +static inline void cpus_set_cap(unsigned int num)
> 
> Same comment as above.
> 
> > +{
> > +       if (num >= RISCV_NCAPS) {
> > +               pr_warn("Attempt to set an illegal CPU capability (%d >= %d)\n",
> > +                       num, RISCV_NCAPS);
> > +       } else {
> > +               __set_bit(num, cpu_hwcaps);
> > +       }
> > +}
> > +
> > +#endif
> > diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
> > index 1b2d42d7f589..e6c72cad0c1c 100644
> > --- a/arch/riscv/kernel/cpufeature.c
> > +++ b/arch/riscv/kernel/cpufeature.c
> > @@ -9,6 +9,7 @@
> >  #include <linux/bitmap.h>
> >  #include <linux/ctype.h>
> >  #include <linux/of.h>
> > +#include <asm/cpufeature.h>
> >  #include <asm/processor.h>
> >  #include <asm/hwcap.h>
> >  #include <asm/smp.h>
> > @@ -25,6 +26,15 @@ static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
> >  __ro_after_init DEFINE_STATIC_KEY_FALSE(cpu_hwcap_fpu);
> >  #endif
> >
> > +DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
> > +EXPORT_SYMBOL(cpu_hwcaps);
> 
> Just like the previous comment. This is a redundant bitmap.
> Please use "riscv_isa" bitmap for this purpose.
> 
> > +
> > +DEFINE_STATIC_KEY_ARRAY_FALSE(cpu_hwcap_keys, RISCV_NCAPS);
> > +EXPORT_SYMBOL(cpu_hwcap_keys);
> > +
> > +DEFINE_STATIC_KEY_FALSE(riscv_const_caps_ready);
> > +EXPORT_SYMBOL(riscv_const_caps_ready);
> 
> Please see comments above.
> 
> > +
> >  /**
> >   * riscv_isa_extension_base() - Get base extension word
> >   *
> > @@ -62,6 +72,17 @@ bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, int bit)
> >  }
> >  EXPORT_SYMBOL_GPL(__riscv_isa_extension_available);
> >
> > +static void __init enable_cpu_capabilities(void)
> > +{
> > +       int i;
> > +
> > +       for (i = 0; i < RISCV_NCAPS; i++) {
> > +               if (!cpus_have_cap(i))
> > +                       continue;
> > +               static_branch_enable(&cpu_hwcap_keys[i]);
> > +       }
> > +}
> > +
> >  void __init riscv_fill_hwcap(void)
> >  {
> >         struct device_node *node;
> > @@ -236,4 +257,6 @@ void __init riscv_fill_hwcap(void)
> >         if (elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D))
> >                 static_branch_enable(&cpu_hwcap_fpu);
> >  #endif
> > +       enable_cpu_capabilities();
> > +       static_branch_enable(&riscv_const_caps_ready);
> >  }
> > diff --git a/arch/riscv/tools/Makefile b/arch/riscv/tools/Makefile
> > new file mode 100644
> > index 000000000000..932b4fe5c768
> > --- /dev/null
> > +++ b/arch/riscv/tools/Makefile
> > @@ -0,0 +1,22 @@
> > +# SPDX-License-Identifier: GPL-2.0
> > +
> > +gen := arch/$(ARCH)/include/generated
> > +kapi := $(gen)/asm
> > +
> > +kapi-hdrs-y := $(kapi)/cpucaps.h
> > +
> > +targets += $(addprefix ../../../,$(gen-y) $(kapi-hdrs-y))
> > +
> > +PHONY += kapi
> > +
> > +kapi:   $(kapi-hdrs-y) $(gen-y)
> > +
> > +# Create output directory if not already present
> > +_dummy := $(shell [ -d '$(kapi)' ] || mkdir -p '$(kapi)')
> > +
> > +quiet_cmd_gen_cpucaps = GEN     $@
> > +      cmd_gen_cpucaps = mkdir -p $(dir $@) && \
> > +                     $(AWK) -f $(filter-out $(PHONY),$^) > $@
> > +
> > +$(kapi)/cpucaps.h: $(src)/gen-cpucaps.awk $(src)/cpucaps FORCE
> > +       $(call if_changed,gen_cpucaps)
> > diff --git a/arch/riscv/tools/cpucaps b/arch/riscv/tools/cpucaps
> > new file mode 100644
> > index 000000000000..cb1ff2747859
> > --- /dev/null
> > +++ b/arch/riscv/tools/cpucaps
> > @@ -0,0 +1,5 @@
> > +# SPDX-License-Identifier: GPL-2.0
> > +#
> > +# Internal CPU capabilities constants, keep this list sorted
> > +
> > +HAS_NO_FPU
> 
> How can "No FPU" be a CPU capability ?
> 
> We have ISA extensions 'F' and 'D' which tells us whether an FPU is available
> or not.
> 
> I think this file should be a table with two columns
> "<lower_case_extension_name> <parsed_from_isa_string_yes_no>"
> I this this file should look like this:
> 
> i yes
> m yes
> a yes
> c yes
> f yes
> d yes
> h yes
> sv48 no
> sv57 no
> sstc yes
> svinval yes
> svpbmt yes
> svnapot yes
> sscofpmf yes
> ...
> 
> > diff --git a/arch/riscv/tools/gen-cpucaps.awk b/arch/riscv/tools/gen-cpucaps.awk
> > new file mode 100755
> > index 000000000000..52a1e1b064ad
> > --- /dev/null
> > +++ b/arch/riscv/tools/gen-cpucaps.awk
> > @@ -0,0 +1,40 @@
> > +#!/bin/awk -f
> > +# SPDX-License-Identifier: GPL-2.0
> > +# gen-cpucaps.awk: riscv cpucaps header generator
> > +#
> > +# Usage: awk -f gen-cpucaps.awk cpucaps.txt
> > +
> > +# Log an error and terminate
> > +function fatal(msg) {
> > +       print "Error at line " NR ": " msg > "/dev/stderr"
> > +       exit 1
> > +}
> > +
> > +# skip blank lines and comment lines
> > +/^$/ { next }
> > +/^#/ { next }
> > +
> > +BEGIN {
> > +       print "#ifndef __ASM_CPUCAPS_H"
> > +       print "#define __ASM_CPUCAPS_H"
> > +       print ""
> > +       print "/* Generated file - do not edit */"
> > +       cap_num = 0
> > +       print ""
> > +}
> > +
> > +/^[vA-Z0-9_]+$/ {
> > +       printf("#define RISCV_%-30s\t%d\n", $0, cap_num++)
> > +       next
> > +}
> > +
> > +END {
> > +       printf("#define RISCV_NCAPS\t\t\t\t%d\n", cap_num)
> > +       print ""
> > +       print "#endif /* __ASM_CPUCAPS_H */"
> > +}
> 
> This script need to change refer capabilities as extensions.
> 
> For every extension, there should be two defines.
> For e.g. "sstc" extension should have following defines
> #define RISCV_ISA_EXT_sstc <#num>
> #define RISCV_ISA_EXT_FROMSTR_sstc <1|0>
> 
> > +
> > +# Any lines not handled by previous rules are unexpected
> > +{
> > +       fatal("unhandled statement")
> > +}
> > --
> > 2.34.1
> >
> 
> Regards,
> Anup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YnkoKxaPbrTnZPQv%40xhacker.
