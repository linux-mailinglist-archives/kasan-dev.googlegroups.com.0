Return-Path: <kasan-dev+bncBCQJP74GSUDRBDNJTOPAMGQEVXBVXDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CDC766E44D
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 18:02:07 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id v12-20020ab05b4c000000b0060547d4c3d5sf2193883uae.23
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 09:02:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673974926; cv=pass;
        d=google.com; s=arc-20160816;
        b=O0qCpoTTYQI1X5YshlTppOFALWGD8bb+Uy3caEzOw/peKly224KgsauEAFXzBIkEG4
         h1vWdqdovs+IVbTYvRD2diU2mRPv8s8g8XpgQsZrzL/0HvMq2CQdGTbza8ZwKrubjIJ4
         +xTRmeH4aqcphS64PkW1zMXZ7GmJCV1q0BKoeNpTHnM/9QNM7WdUmPXhG1lzOYk3vSRl
         zoPr2+KdKhuizdnZo2bcjJR6g23SZBqYXHTqgtBLMXAINIwK8MohvzgHvIopIDI7ZoPZ
         0G3qbuR+svllkYZBYuYP3JpubJteB9fiOjGAL/1qfmzeuM8hW/DyNyUl13lMlgKru1De
         kfLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=HjjSJ9Br5ZlwEi/uMm4oQvpNVme1m29fdmyDA6YC3k0=;
        b=MYLz1QGXDlkLWhoAD4uoxa2oHCNvJC3LSODp6sZ/A4JUhvpVsO32q20RpQ4Ed9N9zr
         3ygcVox6ikeo+U92Bwg1/4MnwZTtYHuKtcbQ1klVXQjsrb4OGlsFGXmmtHKp/HBHnPtR
         wVNAsCCVWFv+0GQRoHHRS7JzRmRWf2INkG5XaZsNF5IdAiuyb3MQ37hPjtaOyvElHxUF
         vd1xjeITJLUHQy7ImFzHdWAAtJz3d2Y4HQ4QrkroMyYhWHRV5i24N+qKlkz2ZXsN2hNl
         Q3Qpha27Urn1RDe3p/w7duSLzVDPOOBJd9g0J4Fd+lSXGL9seXLragHkPyYw4QNZ+SWq
         Buuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.46 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HjjSJ9Br5ZlwEi/uMm4oQvpNVme1m29fdmyDA6YC3k0=;
        b=baCdXOeAPy3fddMiRBu4gOq9UayaEEwN6JlI+qiqru+APKh23qHMoxumLbIx3inmPd
         9J8C3NpScJgkNxus4tmQuKVGpDjSPiU8+l2ZNYH9+AXHi9oSQS0yzBw3SQtZkrVEQi6/
         Cez3lbSc0ifL+pNvoFESpIqdmFoc0S4ZRQQI+shTU2akkmtXL7vaDfUgLLRWYrd/Uihn
         7JTmQTb7QqVAD+jGexsZbxvIvK34fbzxOYSQMmF7ydz+nFnvf5zLcsILP8Syt38IfWIr
         VUtEoY4zYpOo8/EdJ2gCCtk58iu/j7J9tIHPGByGtCmJlmx95MGSTU0GqcA34sVhlHJ6
         0FeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HjjSJ9Br5ZlwEi/uMm4oQvpNVme1m29fdmyDA6YC3k0=;
        b=50/X4v++FMrIYnJowkrr2cv4w4q31DTVn+tc4Jlp4Vb3sUKub3IDQxs1SQ6hPAOOfT
         dGNnFGb+I7eHU6ZTiobcG1s842RZtdkklWR2TOOdkPq5VQtKb/r1I7dwLalucfHJJJfw
         Cra0yMdfvhMnvA0sHy4TY21V2rWibEG0vyMBZPym8TNExBo57EmEOqOwfJiyL+AsfB2U
         a9uVuQ1vGwl+Ek6Y8cThSSFVukWmvZdvjVDiZswbZooXOIc7U3ksiKu/hF/4yisIJ35S
         qNOCMh2kTE5WAZDwUM6utLGNtGwVfGeJGbAzYLGDLedqriMzi+78+DVpKwfQhSWgL19z
         72Aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko1V2OGaVHBWgHgmYB8gkFM80iMSNRn1wfDgTAVno/BdQN+uDQV
	8VUu43L8nhup4p6iByYbTN0=
X-Google-Smtp-Source: AMrXdXunac/p7m9UPw37ianppVrktA9cCiUT3MV+ArAlsV3VaWHiDVkooDe+YQQU7x/7xfzUsEEXLQ==
X-Received: by 2002:a05:6122:992:b0:3be:14f1:b364 with SMTP id g18-20020a056122099200b003be14f1b364mr489994vkd.17.1673974925808;
        Tue, 17 Jan 2023 09:02:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1fd8:0:b0:3bc:2cac:f10e with SMTP id f207-20020a1f1fd8000000b003bc2cacf10els2547701vkf.0.-pod-prod-gmail;
 Tue, 17 Jan 2023 09:02:05 -0800 (PST)
X-Received: by 2002:a1f:434d:0:b0:3b7:af18:3b7a with SMTP id q74-20020a1f434d000000b003b7af183b7amr1634236vka.12.1673974925136;
        Tue, 17 Jan 2023 09:02:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673974925; cv=none;
        d=google.com; s=arc-20160816;
        b=OZwTar1YFRksaGYXxOwr7zmKP56GHCa9K/5xtImJZfh7pnH1I9PBi+evPZ97oEVqgj
         yVzPg0t3/8h/RzhSKEs1UOYmmE28e4yaDyupJN7gfsiSRgTQxm8eFgNErklVfYLalh4K
         Z8H9sPtHW3ijY0pcmrfPOA8mGSx3oY1vRhU1v1lxcXH5I1viYzRkWWUyd3lHugoCe4S5
         tOCSjcvKQREAxK+MslBENduwjKBDTHmw0qSEQV3o8l2L6brTgkU0jbbXR93ob9jy3Cr7
         yoqKKg3JYB+Ly1gNNgf4j6RfqOVEv7H4uCueLse1rqCVZb5/xvZx2DHM2Cf0yLiEqiqp
         BrEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=AG07rkufzJudbSBlfxWXzYs9DtgP7S33LaaSRTlg/Ec=;
        b=Olxfg3C4WUcTwEpac6hzoquveIjbI6W8PWGq8tYNzAQHOQb7aU9eNDdf/W7YHFWoZF
         hcZSRoZLTs+TVVq5EPf9d0HHP1fCNMX0zM0lzFnqcnM6CAFtT5dc5kbAterkmn1ySxdJ
         OGfKl4Y1Q5JTrfQV6oOd+DrC+WvL1UpFfXVr3WXGq6Ja0ciOJ1sdN98AtllolhWqoMHw
         P2XorXB3AGOF+3EbMcRLkyrIcYLdYllMpktecpNrGv5sWkPI4pQF/KCd9mmQOZiY2y8b
         19ZAm6aou6ARuneAO3OI4b74IUtf/jnXBFD8dQ+6v8iiP1+2NxJRH3WmviAHY3xendop
         a01w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.46 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-oa1-f46.google.com (mail-oa1-f46.google.com. [209.85.160.46])
        by gmr-mx.google.com with ESMTPS id 140-20020a1f1692000000b003daf0a8001asi1555715vkw.2.2023.01.17.09.02.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Jan 2023 09:02:05 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.46 as permitted sender) client-ip=209.85.160.46;
Received: by mail-oa1-f46.google.com with SMTP id 586e51a60fabf-15f64f2791dso2307783fac.7
        for <kasan-dev@googlegroups.com>; Tue, 17 Jan 2023 09:02:05 -0800 (PST)
X-Received: by 2002:a05:6870:8e17:b0:15f:2d1:4fa1 with SMTP id lw23-20020a0568708e1700b0015f02d14fa1mr2319061oab.48.1673974924187;
        Tue, 17 Jan 2023 09:02:04 -0800 (PST)
Received: from mail-yb1-f173.google.com (mail-yb1-f173.google.com. [209.85.219.173])
        by smtp.gmail.com with ESMTPSA id br31-20020a05620a461f00b006fa2cc1b0fbsm20438524qkb.11.2023.01.17.09.02.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Jan 2023 09:02:03 -0800 (PST)
Received: by mail-yb1-f173.google.com with SMTP id l139so34817050ybl.12
        for <kasan-dev@googlegroups.com>; Tue, 17 Jan 2023 09:02:02 -0800 (PST)
X-Received: by 2002:a25:d88c:0:b0:77a:b5f3:d0ac with SMTP id
 p134-20020a25d88c000000b0077ab5f3d0acmr418050ybg.202.1673974922451; Tue, 17
 Jan 2023 09:02:02 -0800 (PST)
MIME-Version: 1.0
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org> <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com> <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
In-Reply-To: <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Tue, 17 Jan 2023 18:01:51 +0100
X-Gmail-Original-Message-ID: <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
Message-ID: <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
Subject: Re: Calculating array sizes in C - was: Re: Build regressions/improvements
 in v6.2-rc1
To: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org, 
	linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org, 
	linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, 
	linux-xtensa@linux-xtensa.org, 
	Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.46
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Adrian,

On Tue, Jan 17, 2023 at 5:42 PM John Paul Adrian Glaubitz
<glaubitz@physik.fu-berlin.de> wrote:
> On 1/6/23 16:17, Geert Uytterhoeven wrote:
> >> I'm not seeing this one, but I am getting this one instead:
> >>
> >> In file included from ./arch/sh/include/asm/hw_irq.h:6,
> >>                    from ./include/linux/irq.h:596,
> >>                    from ./include/asm-generic/hardirq.h:17,
> >>                    from ./arch/sh/include/asm/hardirq.h:9,
> >>                    from ./include/linux/hardirq.h:11,
> >>                    from ./include/linux/interrupt.h:11,
> >>                    from ./include/linux/serial_core.h:13,
> >>                    from ./include/linux/serial_sci.h:6,
> >>                    from arch/sh/kernel/cpu/sh2/setup-sh7619.c:11:
> >> ./include/linux/sh_intc.h:100:63: error: division 'sizeof (void *) / sizeof (void)' does not compute the number of array elements [-Werror=sizeof-pointer-div]
> >>     100 | #define _INTC_ARRAY(a) a, __same_type(a, NULL) ? 0 : sizeof(a)/sizeof(*a)
> >>         |                                                               ^
> >> ./include/linux/sh_intc.h:105:31: note: in expansion of macro '_INTC_ARRAY'
> >>     105 |         _INTC_ARRAY(vectors), _INTC_ARRAY(groups),      \
> >>         |                               ^~~~~~~~~~~
> >
> > The easiest fix for the latter is to disable CONFIG_WERROR.
> > Unfortunately I don't know a simple solution to get rid of the warning.
>
> I did some research and it seems that what the macro _INT_ARRAY() does with "sizeof(a)/sizeof(*a)"
> is a commonly used way to calculate array sizes and the kernel has even its own macro for that
> called ARRAY_SIZE() which Linus asks people to use here [1].
>
> So, I replaced _INTC_ARRAY() with ARRAY_SIZE() (see below), however the kernel's own ARRAY_SIZE()
> macro triggers the same compiler warning. I'm CC'ing Michael Karcher who has more knowledge on
> writing proper C code than me and maybe an idea how to fix this warning.
>
> Thanks,
> Adrian
>
> > [1] https://lkml.org/lkml/2015/9/3/428
>
> diff --git a/include/linux/sh_intc.h b/include/linux/sh_intc.h
> index c255273b0281..07a187686a84 100644
> --- a/include/linux/sh_intc.h
> +++ b/include/linux/sh_intc.h
> @@ -97,14 +97,12 @@ struct intc_hw_desc {
>          unsigned int nr_subgroups;
>   };
>
> -#define _INTC_ARRAY(a) a, __same_type(a, NULL) ? 0 : sizeof(a)/sizeof(*a)
> -
>   #define INTC_HW_DESC(vectors, groups, mask_regs,       \
>                       prio_regs, sense_regs, ack_regs)   \
>   {                                                      \
> -       _INTC_ARRAY(vectors), _INTC_ARRAY(groups),      \
> -       _INTC_ARRAY(mask_regs), _INTC_ARRAY(prio_regs), \
> -       _INTC_ARRAY(sense_regs), _INTC_ARRAY(ack_regs), \
> +       ARRAY_SIZE(vectors), ARRAY_SIZE(groups),        \
> +       ARRAY_SIZE(mask_regs), ARRAY_SIZE(prio_regs),   \
> +       ARRAY_SIZE(sense_regs), ARRAY_SIZE(ack_regs),   \
>   }

The issue is that some of the parameters are not arrays, but
NULL. E.g.:

arch/sh/kernel/cpu/sh2/setup-sh7619.c:static
DECLARE_INTC_DESC(intc_desc, "sh7619", vectors, NULL,
arch/sh/kernel/cpu/sh2/setup-sh7619.c-                   NULL,
prio_registers, NULL);
--

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j%3Diw%40mail.gmail.com.
