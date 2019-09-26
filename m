Return-Path: <kasan-dev+bncBCD3PVFVQENBBLHRWLWAKGQENSUAOCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 44EDCBF3C1
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 15:10:06 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id m17sf1351186pgh.21
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 06:10:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569503405; cv=pass;
        d=google.com; s=arc-20160816;
        b=BVIY3Axs1w381EKd+7dlwKDT9tM2kXuYh9KHyq9wgwF1YWHmxTUYgrQzf9u/5HY8zb
         BgwOhk3TmP6UUc0PfGdgPHP5zX9sxrP/zdvdoxvxyKREK+kwnO+yyTnt12s5dDoYktC1
         x47+d0FJc99awiI17PvjKUgc2CqvaGTrihCdbYiiHy16mFgKYb+275g7olaDo92t8Oe1
         kipI58Y83lMfaYFV7RQ1VzPLzblSe22tqDZDVkwyvqgadzzf+6w8mo57P2+yqwobMuSC
         8sKyFbWRfMxSp9iD95x0960C1FligCB9m1j5P+Hbta/Szyd8ODGZodq1te+AP/SuI98/
         e7kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=QiFnbI1TpGOLNupg6zjJ/2+1B0+/C+wbydZb4v140pk=;
        b=QBV1D2JYdKQTv14Q0eMGaX6zohdL9xMHNTU8BjwIL5gYj/jbN/8I20G8DRtLBt4yTQ
         n5nciwRYhCsfAUJ1b/0Kd2fm6D0n47BG7oXrY1ZXTXhzUVcU82s+b45jfxKUIqsYmblx
         AWUFVdCQCxHm4x9qUjAy6O9H5KIEQfmmXZhf92wGas9eEKNmj+Ofnwaz/YmBqGZaDsq/
         o8xLqDkND5VQMXKWrOBc65xhdYpndHl7o4Xh5cssQIzgNXVLPBDS6zGP4PEKloJ+Y0kw
         x5RYJNA2fb2Slk2u2l7PLF2306FhDLapOR0pDX3D+G2A/w6WgsAtsUkRlIL/KX4R6Du1
         y6iA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=M0MOZVUz;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QiFnbI1TpGOLNupg6zjJ/2+1B0+/C+wbydZb4v140pk=;
        b=HJKRIe6gPBTuHmPJqn9PJB6rfX74ZdKzaSqgY1v6LYWjCIaUBu9Aa4L8e60JwJazKC
         sK9doLMVIlqZMoHwoyG/Ytnlr7CprzNYtc8ZZHsPAjB7P6dfaL5qnqiLS3laNFnp6eN3
         b43xfIF2CpoTp0SisM73OY7pyBd/MUxMA7YtozIRHz+LOTCyP5JeAOVf3bIE6+i7CVKQ
         sQyT6lJQAgXuHsavpP0K3MANpIA+7zf/qxF+2tdOOmEIqq1BbCs6FrL4A0qdGK5TkfoX
         CeM2U177FWHg+bvdUpFy8MUuLTI3UdJSkUglqm/c8twiF2dYbZ7YxPBUz5eUCV2rWxHq
         Afug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QiFnbI1TpGOLNupg6zjJ/2+1B0+/C+wbydZb4v140pk=;
        b=HLRluOm72O3jdSlY3Ztl+7AjRVAbIv/wD2GFlIQM609m0aSpcU7t9Zsuu9yd8pL4om
         l93Hk6uJNjgRhB108LNrCTq3Dx7bIFLyyFQOxqK+ccb9ZrfzO91EMp+ae6dgSMCw+d0N
         mPlprGQ2lwnKXsJmGxtRYhyp14vaWlenOCpSTTAbCxjT61ppUpS/VbOioLfUexfdxC2q
         28P7dHQ1KOb8Y81lSZuS13VrNpCZy6ravcAUxWFb7Pm3a4mfUlWiqKsol0sk0sC4JaQp
         JZALgrZMpqTJe6Ptj9PYG2snewj++ZHsT1XNGWgslE2m9OAnkhXSyBBZe/hm6/VXhfHR
         i3og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QiFnbI1TpGOLNupg6zjJ/2+1B0+/C+wbydZb4v140pk=;
        b=GPeXRHuXqJxKGtOBaqHaat6GB4J/AEZsls51eNNNf+3OEd8JBUBN6XOwgdBAUzmQoH
         kh9We5jAYSiMedlHy5xHP8aeGlDbqEQ2iXKqtSK9xjUba33HeZ97+VIUFkOd5KgT1NLP
         qIYOyk2BxTEFiJqDszG/FfM3kLZMILPsVIuZc/gSeBj7lGDnVLXTbrF8EUmodjklw6ZF
         bLW/MuQC2t3QnPRkh87t/yzuZIFu6Uo06Vk3dOxRmqWYqTZsW5mcpLKjPOPlq4VzrSd9
         KKQkJtD28BTRt3bsPt0ZpGmUo9B76bdWmV+7seuMytBs9+sStx41envqpb3ecEABoSer
         wzig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXQzYr3KCb1nbtW+qyqpuXcnViENCRNoV0NCESr2SBMbhrUcDFP
	pmic0DTqd3xRQzhHnyrQio0=
X-Google-Smtp-Source: APXvYqxhkNY252Nt5xAE28/fTwLQwcFs9+SxHiVJzHoxFoCAj4OrzvnNeZrCA0B3LSybdga4575q6Q==
X-Received: by 2002:a63:e116:: with SMTP id z22mr3432101pgh.424.1569503404833;
        Thu, 26 Sep 2019 06:10:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:24f:: with SMTP id t15ls725798pje.1.canary-gmail;
 Thu, 26 Sep 2019 06:10:04 -0700 (PDT)
X-Received: by 2002:a17:902:9684:: with SMTP id n4mr4276866plp.14.1569503404510;
        Thu, 26 Sep 2019 06:10:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569503404; cv=none;
        d=google.com; s=arc-20160816;
        b=n1esye3LgJeACbRxVnM96ZTEsCrTZT64T0gRmkxDKkcIlHLu957rFI0unH8ZJBEEqC
         num4Zx7Eq543yzIrJ5TyFUf3y41kKO3kdfbqKeuzjyH21BvqiHG24zWAAsI9r9uND2EC
         dlFUgIAd7F51MtH7mg0gpB481fksVIps2BcQ92AvlzmeIogM71gvQNV160xFE2j5Yv/l
         UhT+rTkqA/g271rJ7qwyc/Q4gU8rMIB9QDZ/Q0Nlq6TdcWP5wm28gn2dCGHNMFf6Lbr9
         h/4dWsKkfmnxH+gmwonguwvBdfZVa5Khsz+HJScr+HbLkc7hWJInFSgJZ/RzZNPLARAO
         ulJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FZIPxOACSyBTtRH5A7Lgyz9YR30y4W13jpD2I+1mgJM=;
        b=IEv6umHHUGYvXk0N4YoLrj0BjQeQ9KagmoUrfk1k3WJHD+7rCb0CGDqhAt0MAoyLZB
         IfH2NGyYG4gsfIoSTEIMO2odXesoe8MVVVl9dVA4gOmCPLmz6iRmP4fqZCrjaSHnYdHH
         zmwMQv6xz/Z6s1X+2fmkdpCBW2eW3JZvja4T1LrHzQZofyDZwEJj4Y4OT4hOEbD/in+a
         H/nL48OKjkLRgo9WQhVezonxU/3DXpVW+hbSgZihHuDoV1trXja0Gdr93yE3NS66p5gw
         bRv63KGhp7gqTrZ2BeynGUHGIxwLSVDHJgzuIJBMBu1aDR4aRpo98YM420gITDg6Joa9
         tuRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=M0MOZVUz;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id a16si73514pgm.1.2019.09.26.06.10.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Sep 2019 06:10:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id q10so6415325iop.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2019 06:10:04 -0700 (PDT)
X-Received: by 2002:a6b:d601:: with SMTP id w1mr3118098ioa.158.1569503404009;
 Thu, 26 Sep 2019 06:10:04 -0700 (PDT)
MIME-Version: 1.0
References: <1548057848-15136-1-git-send-email-rppt@linux.ibm.com>
 <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
 <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
 <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com> <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
In-Reply-To: <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
From: Adam Ford <aford173@gmail.com>
Date: Thu, 26 Sep 2019 08:09:52 -0500
Message-ID: <CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg@mail.gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
To: Fabio Estevam <festevam@gmail.com>
Cc: Mike Rapoport <rppt@linux.ibm.com>, Rich Felker <dalias@libc.org>, linux-ia64@vger.kernel.org, 
	Petr Mladek <pmladek@suse.com>, linux-sh@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Heiko Carstens <heiko.carstens@de.ibm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Max Filippov <jcmvbkbc@gmail.com>, 
	Guo Ren <guoren@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, sparclinux@vger.kernel.org, 
	Christoph Hellwig <hch@lst.de>, linux-s390@vger.kernel.org, linux-c6x-dev@linux-c6x.org, 
	Yoshinori Sato <ysato@users.sourceforge.jp>, Richard Weinberger <richard@nod.at>, x86@kernel.org, 
	Russell King <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Mark Salter <msalter@redhat.com>, 
	Dennis Zhou <dennis@kernel.org>, Matt Turner <mattst88@gmail.com>, 
	linux-snps-arc@lists.infradead.org, uclinux-h8-devel@lists.sourceforge.jp, 
	devicetree <devicetree@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	linux-um@lists.infradead.org, 
	The etnaviv authors <etnaviv@lists.freedesktop.org>, linux-m68k@lists.linux-m68k.org, 
	Rob Herring <robh+dt@kernel.org>, Greentime Hu <green.hu@gmail.com>, xen-devel@lists.xenproject.org, 
	Stafford Horne <shorne@gmail.com>, Guan Xuetao <gxt@pku.edu.cn>, 
	arm-soc <linux-arm-kernel@lists.infradead.org>, Michal Simek <monstr@monstr.eu>, 
	Tony Luck <tony.luck@intel.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, USB list <linux-usb@vger.kernel.org>, 
	linux-mips@vger.kernel.org, Paul Burton <paul.burton@mips.com>, 
	Vineet Gupta <vgupta@synopsys.com>, linux-alpha@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, linuxppc-dev@lists.ozlabs.org, 
	"David S. Miller" <davem@davemloft.net>, openrisc@lists.librecores.org, 
	Chris Healy <cphealy@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aford173@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=M0MOZVUz;       spf=pass
 (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d41
 as permitted sender) smtp.mailfrom=aford173@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Sep 25, 2019 at 10:17 AM Fabio Estevam <festevam@gmail.com> wrote:
>
> On Wed, Sep 25, 2019 at 9:17 AM Adam Ford <aford173@gmail.com> wrote:
>
> > I tried cma=256M and noticed the cma dump at the beginning didn't
> > change.  Do we need to setup a reserved-memory node like
> > imx6ul-ccimx6ulsom.dtsi did?
>
> I don't think so.
>
> Were you able to identify what was the exact commit that caused such regression?

I was able to narrow it down the 92d12f9544b7 ("memblock: refactor
internal allocation functions") that caused the regression with
Etnaviv.

I also noticed that if I create a reserved memory node as was done one
imx6ul-ccimx6ulsom.dtsi the 3D seems to work again, but without it, I
was getting errors regardless of the 'cma=256M' or not.
I don't have a problem using the reserved memory, but I guess I am not
sure what the amount should be.  I know for the video decoding 1080p,
I have historically used cma=128M, but with the 3D also needing some
memory allocation, is that enough or should I use 256M?

adam

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg%40mail.gmail.com.
