Return-Path: <kasan-dev+bncBDZJXP7F6YLRBOWPQSNAMGQELRPW3CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 635BE5F83FF
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 09:33:15 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id u24-20020a2e2e18000000b0026dfd4bd721sf2776797lju.22
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 00:33:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665214394; cv=pass;
        d=google.com; s=arc-20160816;
        b=eDzx8+9p0L0m34BAjMhJe4Q4EeoCrJWIDD0yHWcZ7JcRx+3AHuyTmaEoznT1gR0i+X
         g2oLw0ijuNsXrwkYiqxD5LBIb69tT+NxaX6yD6o3R3z2GxoG7bVrI6d497RQYlXaz7qC
         3KqpIlhmDHoPV8BBLsGpY5RaiKGaEM8SYTgsAB27Mudx83oASx01B9u8w9p1Q99a7j6k
         lYGz6qMllN2ET3bfdP7POFb1FE/XGTEcLypfxPjuByRQBt70jO9u1kP0c9nJl61/VwvE
         8SOBwSqrICGaQyo0M/Yr0MTUo0lHfiZ2pJbo1c9euPM2geoeXkQS9/r4kdlo9z0rRQvo
         Zycw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5NoP4P2K5aCQqLo31NXJiTQmef2SumZDyA9+/+vICZA=;
        b=GXPIRTXLYOzb424FdN1oRIMxxBsVWeyjV/w4ifcTHr/kRg7jSe0p7ws7zcwnvNef8q
         S+p4XJFfDcFnnCIHXOwOvbN7nHhW8G9bgGNvpHRrTaIN+lZP1+rX8xiIFHkWOXGgyDi8
         G5b5VShV2jMVFYVM31KdyAQAZ+wTQt8BwjKaDCoWDZQk9V0/cZUk5kW4JyuRqM2ED1YQ
         NX1O24ENICKiQTtMEoODkUv37mvuOgTAKGWJ1JD2tJW7UeDrckXVhKlU0RyYx3p07qsL
         zBqYbKGpO4DyMVV6Y7a6NAOx77LJoKiOoOtkPOrHqZQlkQhRQGolxg8kdD14cYQyNMdC
         8nDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=j3ST7SGn;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) smtp.mailfrom=julia.lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:message-id
         :in-reply-to:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5NoP4P2K5aCQqLo31NXJiTQmef2SumZDyA9+/+vICZA=;
        b=LmR5VKTX74e9xz1xStU2AF02TZ2p20Qw4a5w1A6x5+z+VZjOoifyUtYPfNjeXODAqH
         FFLt5eISJLMxai5eOltI4f/nhul9SpWyCjUqne3KUGkywKjpLH+hpQHHgiKZR/ABy5n6
         ND6Dg09/3OR/3CDfduUgYEtiQEqn+zXRQqcBjpkvMpaSet8oWnBeqQKAt8JIfgbW/8aa
         ID9I7aBHMUaE49zVcx93OQxz8OJXZspR8McmdTHSsJqQc0XdDHMLODyazC3es3fJthXd
         n8OWJbc6VuYPb8oCdB/UOo1liB3yUjo3X0NlM1qnkSbU4vzn9mT7P7JmK91a0IqRHuP9
         giIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:message-id:in-reply-to:subject:cc:to:from
         :date:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5NoP4P2K5aCQqLo31NXJiTQmef2SumZDyA9+/+vICZA=;
        b=lV36JAtntX/u04CRQqiZ3BlU18w+EAjwGrYljZJRXEJuTPISt5krdSHAseZbfyvoiF
         8Av9A3hURTZTwtlsHyMyCFHyvrxZ+o8eS9EdpNRaYTKBE8SoaOQT6b3mXo/lbbf1g7Ot
         IQ/R5CzFd5Y7fntgHV/L03A96ILKpfPUK2gIUaGIOVV7EgWRx3XDCZiv44FgMXl7i3oV
         5R3ZDhtKzCfLhFX9eWnqchDvL+rKppievpAOgfYRJW54yoYd6v3t39vVveYYrnuUuszY
         cky4rjiwT6DNrEa/aNF23GgIzb4YHN/0m1Nnfc+ykH2Ri5svyETkWawl30ffC1641zck
         j67g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3wdCZYBZRiXTgBrjAFgWkS75DSsJSU51+YoMXMzhTETR4J+GUz
	b9r5EW1pypmFfR6i+aK7/DI=
X-Google-Smtp-Source: AMsMyM7R7cywoYybrVV3LIAjKW172QJNpfacCa85tVrSpyDL5iZc1BPflCWXDpTC5M5H3ehY/Qbx6Q==
X-Received: by 2002:a2e:8347:0:b0:26d:e2be:b6e3 with SMTP id l7-20020a2e8347000000b0026de2beb6e3mr2997177ljh.247.1665214394808;
        Sat, 08 Oct 2022 00:33:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81c3:0:b0:26e:3a10:642d with SMTP id s3-20020a2e81c3000000b0026e3a10642dls685442ljg.9.-pod-prod-gmail;
 Sat, 08 Oct 2022 00:33:12 -0700 (PDT)
X-Received: by 2002:a05:651c:4ca:b0:26c:50e6:a9d3 with SMTP id e10-20020a05651c04ca00b0026c50e6a9d3mr3117241lji.318.1665214392886;
        Sat, 08 Oct 2022 00:33:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665214392; cv=none;
        d=google.com; s=arc-20160816;
        b=0V9E5IhB1pTDErd/4WbVNHtA8QcFGUJ64PR/mqrM6hql+pEVRp9ngTwcfNZMrXdop0
         zau9gMBTLHVZH59Xifuwfc/an+l5cAwReFJPVV4uBxiVqKICEks2GUYwI9P1Y/Xtdeba
         L5AFZtwYeSApmFsjTguHbs9WcLN3xT4TNiab+k8vWWQX3NPvtTMSHwjW5ObpQ/rKPiqh
         uytFvhkANHTidnrVT4HlIF1svJvu+L88qy8A2fNJWYiZK5ywiwR0vBxqS3I6jMtD+Dug
         p+ziTSv3fmIBYwYI389Pi2Dk3bBiytUEKh9lWUAheWZGH5ixBnouknEzslQPNBta09x3
         9kiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=zZQ88pPgtouR86lBpg+x1aw/csf1v9uxp8peXKk1cb0=;
        b=j/2UfFGFNDN7osybsPchNbNxZW0s8oyaLsa+XQm0Gp00aYs1bj8eABgGGgTC7A2XbB
         B50YvebrRLZp4BoE5TUwfmF5U8iyQIB/wPyNvViM1AZftyMfaLxV6YLxco9LlngAyrh/
         H8FD8lNjuC1YiOplsOpjtzO4iIlWcKffJBs6NY3iIdyN9aPnNljlEnephFZUh6f4MQRD
         F7EjTqn96Pb+onEubdlpl/gtyqUdFjxPuhxRAKUXFRy6qi9bKSr8vN6Wp4MTnq5WLcFP
         +LB3Z+NDJAyULE6dXsufyDKXuJ/PNXVleMdV29IdCGbaKS6URHtid2MZyX4XiNDF10P5
         Kk/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=j3ST7SGn;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) smtp.mailfrom=julia.lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
Received: from mail2-relais-roc.national.inria.fr (mail2-relais-roc.national.inria.fr. [192.134.164.83])
        by gmr-mx.google.com with ESMTPS id v18-20020a2ea612000000b0026e8b14ad83si56562ljp.6.2022.10.08.00.33.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Oct 2022 00:33:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) client-ip=192.134.164.83;
X-IronPort-AV: E=Sophos;i="5.95,169,1661810400"; 
   d="scan'208";a="56593050"
Received: from 51.123.68.85.rev.sfr.net (HELO hadrien) ([85.68.123.51])
  by mail2-relais-roc.national.inria.fr with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Oct 2022 09:33:09 +0200
Date: Sat, 8 Oct 2022 09:33:08 +0200 (CEST)
From: Julia Lawall <julia.lawall@inria.fr>
X-X-Sender: jll@hadrien
To: Kees Cook <keescook@chromium.org>
cc: "Jason A. Donenfeld" <Jason@zx2c4.com>, linux-kernel@vger.kernel.org, 
    patches@lists.linux.dev, Andreas Noever <andreas.noever@gmail.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Andy Shevchenko <andriy.shevchenko@linux.intel.com>, 
    Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, 
    =?ISO-8859-15?Q?Christoph_B=F6hmwalder?= <christoph.boehmwalder@linbit.com>, 
    Christoph Hellwig <hch@lst.de>, 
    Christophe Leroy <christophe.leroy@csgroup.eu>, 
    Daniel Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, 
    Dave Hansen <dave.hansen@linux.intel.com>, 
    "David S. Miller" <davem@davemloft.net>, 
    Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>, 
    Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
    "H. Peter Anvin" <hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>, 
    Helge Deller <deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>, 
    Huacai Chen <chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>, 
    Jakub Kicinski <kuba@kernel.org>, 
    "James E. J. Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, 
    Jason Gunthorpe <jgg@ziepe.ca>, Jens Axboe <axboe@kernel.dk>, 
    Johannes Berg <johannes@sipsolutions.net>, 
    Jonathan Corbet <corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, 
    KP Singh <kpsingh@kernel.org>, Marco Elver <elver@google.com>, 
    Mauro Carvalho Chehab <mchehab@kernel.org>, 
    Michael Ellerman <mpe@ellerman.id.au>, 
    Pablo Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, 
    Peter Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>, 
    Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>, 
    Thomas Bogendoerfer <tsbogend@alpha.franken.de>, 
    Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>, 
    Ulf Hansson <ulf.hansson@linaro.org>, 
    Vignesh Raghavendra <vigneshr@ti.com>, WANG Xuerui <kernel@xen0n.name>, 
    Will Deacon <will@kernel.org>, Yury Norov <yury.norov@gmail.com>, 
    dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com, 
    kernel-janitors@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
    linux-block@vger.kernel.org, linux-crypto@vger.kernel.org, 
    linux-doc@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
    linux-media@vger.kernel.org, linux-mips@vger.kernel.org, 
    linux-mm@kvack.org, linux-mmc@vger.kernel.org, 
    linux-mtd@lists.infradead.org, linux-nvme@lists.infradead.org, 
    linux-parisc@vger.kernel.org, linux-rdma@vger.kernel.org, 
    linux-s390@vger.kernel.org, linux-um@lists.infradead.org, 
    linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org, 
    linuxppc-dev@lists.ozlabs.org, loongarch@lists.linux.dev, 
    netdev@vger.kernel.org, sparclinux@vger.kernel.org, x86@kernel.org, 
    Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
In-Reply-To: <53DD0148-ED15-4294-8496-9E4B4C7AD061@chromium.org>
Message-ID: <alpine.DEB.2.22.394.2210080925390.2928@hadrien>
References: <53DD0148-ED15-4294-8496-9E4B4C7AD061@chromium.org>
User-Agent: Alpine 2.22 (DEB 394 2020-01-19)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Julia.Lawall@inria.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@inria.fr header.s=dc header.b=j3ST7SGn;       spf=pass (google.com:
 domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted
 sender) smtp.mailfrom=julia.lawall@inria.fr;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=inria.fr
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

> >> @minus_one@
> >> expression FULL;
> >> @@
> >>
> >> - (get_random_int() & ((FULL) - 1)
> >> + prandom_u32_max(FULL)
> >
> >Ahh, well, okay, this is the example I mentioned above. Only works if
> >FULL is saturated. Any clever way to get coccinelle to prove that? Can
> >it look at the value of constants?
>
> I'm not sure if Cocci will do that without a lot of work. The literals trick I used below would need a lot of fanciness. :)

If FULL is an arbitrary expression, it would not be easy to automate.  If
it is a constant then you can use python/ocaml to analyze its value.  But
if it's a #define constant then you would need a previous rule to match the
#define and find that value.

For LITERAL, I think you could just do constant int LITERAL; for the
metavariable declaration.

julia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.22.394.2210080925390.2928%40hadrien.
