Return-Path: <kasan-dev+bncBCQJP74GSUDRBKXX4COQMGQEOB54WNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CC456602E2
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 16:18:04 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id bk2-20020a056a02028200b004a7e2a790d2sf1110284pgb.18
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Jan 2023 07:18:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673018282; cv=pass;
        d=google.com; s=arc-20160816;
        b=sqS8YmFQNLA7bmS8oo0EJpmqqXAZ5ZhwbanNtLyv0WVPz1xNWNemcslFC7Kf3dlz4T
         OySIZ6+DpDdj/WL9HnoRBhPP+geZQMcs/6AmRGg9nwEKfEWXSBiOWEqXlzWsEnVH75JQ
         CezL46wPtxhtTauQny8EKJ7sYnHb4RYQrbbLo4Wg1YwQzTl3u2gYe8EfaqXg7+yen2m2
         4Mg4rIjC0RpxoHaFx9i87cxLdXppQWqzmj4Bv27PkGROPvpu2SG22H3f0CjUEFkp0QM3
         s5CXruaF2Xr9chlQt94Ju4wcc2y4SZMaoQMZoUWjHH99si6ewKWcXpto1ZGtITKwdj2u
         6Asw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=PgIseHS0qwn3A7x5w8lM91s1nmEL0BOem77xPpuTE0U=;
        b=Z9NDsMmRnpA1WiS0Kn3snndvaTnNiygs/VhCNmeVWzHy0Ladzn+0knypDZRGC/EqVz
         ZmhJEvBG7O0WBc5ae9u0ryj9C7PMvEPbrJDC6pdaznIZvNIfPZiuRna5bnoP11623S3j
         dHOxnFmnKV9C3Y7+iq0vtFtSaSN5hU/x4YiiowJZ43fh/OJoTyoCLfZLIQT+na0g1q5Y
         JMrUO07OeDz5i0u6BH9iHiVxYGUMVxnETaB8dYiDRPpMuonja7c6tNC71S3o3lShDMQf
         RrHXyuwdxbVUfJ+g2AHKPGcp3JZgoKOI5l3I/e3lfrmhrrkmXZfZbQdh4CrGchVxcm57
         ACsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.182 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PgIseHS0qwn3A7x5w8lM91s1nmEL0BOem77xPpuTE0U=;
        b=d69ahcHkF61l4MHLEvpUBrvcdOOUX39rVi16EBvTxw3tloZdYlhdRqSfYn0WP3c9bX
         ehktM4VnGgNoYs9cV+uSZ9hAoDfp+9tWaJxBINct676h1m3l69Q4nfUTIja1uFBFO2YG
         tUNlpZiLuRB3eh0fPMaqoDyYqed7kvT5y7Ny2gyTKoZj9fuUVZDDpXweYhi4BJoGPYX8
         oOuf72exHzdmdTfWmpG9/7uv24+ZTw8nVT+oG4Q2gLmIHyeDqR1rmFHB0VVq39YdY4i1
         Lo6Q6V3oR8zn6jLZLEVGHv/upSrN5kopfyIr/6e5CBgnB7w0N/jQesv3/Vj0zFd9YNGE
         SXDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=PgIseHS0qwn3A7x5w8lM91s1nmEL0BOem77xPpuTE0U=;
        b=kWUEFr5EKNC2cIM9mJ95MVKTyUikb8WDlFzLj1diGAkXnAE2hLSHe4gIueCkNOGpnq
         vPtG/pNilvKr1uv0wtTuTCkoKMXDU+XtVJEmj9VSDKgDd+aHF+wGqK7X/cck7B+k/7vh
         e8GKUo+4hGBVdhqoAfL0F8ddGjm07+VpAGWgyrQOG9TauN54zBKlg6wYRkAVciUKvJkK
         eICRreLEhIrrO0VH64SYbEBBH1G3Mfi9J6uFpyas3d5Q/BNTUXg2X6s+oNnM/u8DbYXG
         CldcUcmmavNf6Kx58MrokSisTBewSKJz77p0aovUXH3G2eHvbYUNXGTJN+W2RG46YsZD
         MSJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kodFQJxJcYUTsGoBk+Z7621C9mK3/EcQp3fGECTPVsgF3smy876
	DT7TPVNlyydDYbf2TW2tGxs=
X-Google-Smtp-Source: AMrXdXvqqpZXTuTdkokO+qz5PvWl91By7/nnBy/E7PRCDpb0GDtjzeo9XU2rPWC4TdNaUzriVq88zw==
X-Received: by 2002:aa7:8051:0:b0:582:e939:183d with SMTP id y17-20020aa78051000000b00582e939183dmr1034832pfm.63.1673018282251;
        Fri, 06 Jan 2023 07:18:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f786:b0:178:3881:c7e3 with SMTP id
 q6-20020a170902f78600b001783881c7e3ls41503516pln.11.-pod-prod-gmail; Fri, 06
 Jan 2023 07:18:01 -0800 (PST)
X-Received: by 2002:a17:902:a50c:b0:192:6c8a:6b81 with SMTP id s12-20020a170902a50c00b001926c8a6b81mr44427982plq.31.1673018281180;
        Fri, 06 Jan 2023 07:18:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673018281; cv=none;
        d=google.com; s=arc-20160816;
        b=dH4X5ijehn9PRUbBBl5a1clqVqsQLOVW+M8MXFJ0iixT3PHGjZW5JEL/r+fqhicvWh
         pf23cKnLTf1E1VHbFTCIwzhKB58en5/hqdLL+oNucKPiJfid+yG68Ve4CbPMzJkpaafO
         3WrYzX2NII5wdMsnxtpKzTXswxRxujWkn6+QR1xzeW2VmwmfFywOC9SR1uO9DRYUJoxD
         HcFMp4n1tB/iaXSaJzA8+ug8gA2tvyIomlHkoLNb6iE5s+ej3GevE109e9jHbiWfbFoI
         uzaHzx/p/unEsZZfutXNJDCCfplBj9v+jUWbA0CPdnbGCuxNQItOActyczlG9akPNFiN
         eENA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=Alz05ZcNgoaQdFl2lti3Hdp2W/onZPDBRRL7a7nm+Vw=;
        b=FfceOBEwAWFfy1E1jMiJDC5XsXTrmdDxzWAwM1TO58ao99L0t55QBzGaOSMx9h0E/l
         JI8TT43E94cF6GRgXFLW0326gTUBpn27YRC6yp8HTGmle+wz1TpLZ/SWug2THf8KuyqU
         +54WUgI9O4Yk2wVD8TwM+Yr6T9d72R4Qh2MOcxpL6PI+jjJ9JlEq96FbRCvwc6TQsrbc
         EUQ+SjxeQOjv1v2e2uSMASA/K4YD7vqAOrjgSNnQAHSMB1mtgpSfYAIOB2Vr1MOdkkwS
         DXCJmWw19Hs2KOBss8jspO2N/oR/lcc4C5Vp61zC7bNOEM3mcJtrcz01cHWeUOGqj689
         zgRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.182 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-yb1-f182.google.com (mail-yb1-f182.google.com. [209.85.219.182])
        by gmr-mx.google.com with ESMTPS id d17-20020a170902ced100b00174ea015ef2si99259plg.5.2023.01.06.07.18.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Jan 2023 07:18:01 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.182 as permitted sender) client-ip=209.85.219.182;
Received: by mail-yb1-f182.google.com with SMTP id o75so2201684yba.2
        for <kasan-dev@googlegroups.com>; Fri, 06 Jan 2023 07:18:00 -0800 (PST)
X-Received: by 2002:a25:b088:0:b0:7b5:e896:7574 with SMTP id f8-20020a25b088000000b007b5e8967574mr4843312ybj.0.1673018280046;
        Fri, 06 Jan 2023 07:18:00 -0800 (PST)
Received: from mail-yb1-f169.google.com (mail-yb1-f169.google.com. [209.85.219.169])
        by smtp.gmail.com with ESMTPSA id w12-20020a05620a444c00b006f9ddaaf01esm650118qkp.102.2023.01.06.07.17.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Jan 2023 07:17:59 -0800 (PST)
Received: by mail-yb1-f169.google.com with SMTP id l139so2142042ybl.12
        for <kasan-dev@googlegroups.com>; Fri, 06 Jan 2023 07:17:59 -0800 (PST)
X-Received: by 2002:a25:d84e:0:b0:7b4:6a33:d89f with SMTP id
 p75-20020a25d84e000000b007b46a33d89fmr557375ybg.543.1673018279290; Fri, 06
 Jan 2023 07:17:59 -0800 (PST)
MIME-Version: 1.0
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org> <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
In-Reply-To: <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Fri, 6 Jan 2023 16:17:47 +0100
X-Gmail-Original-Message-ID: <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
Message-ID: <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
Subject: Re: Build regressions/improvements in v6.2-rc1
To: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org, 
	linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org, 
	linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, 
	linux-xtensa@linux-xtensa.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.182
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

Hi John,

On Fri, Jan 6, 2023 at 4:10 PM John Paul Adrian Glaubitz
<glaubitz@physik.fu-berlin.de> wrote:
> On 12/27/22 09:35, Geert Uytterhoeven wrote:
> >    + /kisskb/src/include/linux/compiler_types.h: error: call to '__comp=
iletime_assert_262' declared with attribute error: Unsupported access size =
for {READ,WRITE}_ONCE().:  =3D> 358:45
> >    + /kisskb/src/include/linux/compiler_types.h: error: call to '__comp=
iletime_assert_263' declared with attribute error: Unsupported access size =
for {READ,WRITE}_ONCE().:  =3D> 358:45
> >
> > In function 'follow_pmd_mask',
> >      inlined from 'follow_pud_mask' at /kisskb/src/mm/gup.c:735:9,
> >      inlined from 'follow_p4d_mask' at /kisskb/src/mm/gup.c:752:9,
> >      inlined from 'follow_page_mask' at /kisskb/src/mm/gup.c:809:9:
> >
> > sh4-gcc11/sh-defconfig (G=C3=BCnter wondered if pmd_t should use union)
>
> I'm seeing this, too. Also for sh7785lcr_defconfig.
>
> > sh4-gcc11/sh-allmodconfig (ICE =3D internal compiler error)
>
> I'm not seeing this one, but I am getting this one instead:
>
> In file included from ./arch/sh/include/asm/hw_irq.h:6,
>                   from ./include/linux/irq.h:596,
>                   from ./include/asm-generic/hardirq.h:17,
>                   from ./arch/sh/include/asm/hardirq.h:9,
>                   from ./include/linux/hardirq.h:11,
>                   from ./include/linux/interrupt.h:11,
>                   from ./include/linux/serial_core.h:13,
>                   from ./include/linux/serial_sci.h:6,
>                   from arch/sh/kernel/cpu/sh2/setup-sh7619.c:11:
> ./include/linux/sh_intc.h:100:63: error: division 'sizeof (void *) / size=
of (void)' does not compute the number of array elements [-Werror=3Dsizeof-=
pointer-div]
>    100 | #define _INTC_ARRAY(a) a, __same_type(a, NULL) ? 0 : sizeof(a)/s=
izeof(*a)
>        |                                                               ^
> ./include/linux/sh_intc.h:105:31: note: in expansion of macro '_INTC_ARRA=
Y'
>    105 |         _INTC_ARRAY(vectors), _INTC_ARRAY(groups),      \
>        |                               ^~~~~~~~~~~

The easiest fix for the latter is to disable CONFIG_WERROR.
Unfortunately I don't know a simple solution to get rid of the warning.

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k=
.org

In personal conversations with technical people, I call myself a hacker. Bu=
t
when I'm talking to journalists I just say "programmer" or something like t=
hat.
                                -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMuHMdXNJveXHeS%3Dg-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g%40mail.gmai=
l.com.
