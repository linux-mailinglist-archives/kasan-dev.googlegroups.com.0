Return-Path: <kasan-dev+bncBCSPV64IYUKBBSXQ736QKGQETK4VVJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f59.google.com (mail-ed1-f59.google.com [209.85.208.59])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E05A2C56BE
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 15:14:35 +0100 (CET)
Received: by mail-ed1-f59.google.com with SMTP id c23sf1151507edr.4
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 06:14:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606400074; cv=pass;
        d=google.com; s=arc-20160816;
        b=xWyZqvzMRhpGA9J7LI8+1WQCuRLJ3ro5ux/Wj6SwVC8SlAXJniFzthpzrIYV1lUxVh
         jAIeAYK6bkuRQKjb9JrUaAjxF7BQpABqIUK4Excy5BbGt3NZPacxC1t+gwIfm415606N
         rr2dK4xFpgaSanOmLlyoqhRJDwAf1ZWOWSrvSYNOCBJVS0bViRnxnR1ZREUHrnNQNhGN
         sgXdXmzuZlY6Z8+N2gCy+4oWLrXAplz7eVRdnskrUlijrOE1k06hWylV3mQg4wMjr7WZ
         sYeUpxwXTvQb9GS8jpdOojmprR+ko59/+hyugkY4blPkp9DxbhFdkPk1W+D/UBsojlAK
         XWRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=640W4o2t/J+u7teLGyuncde2KyTXONBnRXUpKk9cFSw=;
        b=jup8nVlkDJC0daghCxH8MEmQSUItr9Pr7PJi7jv9rvaa9N7Olcr1xFZ2pmIEixjTl1
         +f/8Rb2zI+Rn7XIUbgVFDjZFL5/jc6gZW3YkFRWEk6H6+4HySt4ambh1xcqqcIpqf8eN
         LLyRop1SQE8w9+WkxZpUeGjqeD4yOqP5oZfKE04A4pc2ZeucSocHtMbPChegnPN6SAOr
         F3fA+OAESviPYhQSKpk5kpOn8h+tapqQzIojXQ1lDmrqwH0XKa5oDpsQmH4WReG05yWJ
         1GWZKFMKY//1n+nJRIsdzvNbqD6EYPrK52dZ+sG9fdSHFwJohCYhefBbSBmXSfUJaXhb
         itNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=zRe5uvbk;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:sender:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=640W4o2t/J+u7teLGyuncde2KyTXONBnRXUpKk9cFSw=;
        b=gbaQtMa8zLK61feX+HXAkeuvy1OxCwgfQ8D/LuYIUoeqoIAauWCTErsLxdJj4YJfpV
         PI1/4H9XnyewVzMmcGcjlktfFBpsfStzJQPfDUFIOhCjDSrUB4YkLWVr3fVucUfNA/nT
         qqxrqQFelvy9cfX8Vky+VCzMWk2j4PtrzKcAoufNE0COEAZ+WPjX5UCqx6fOmdYlLIvh
         1ebr4arZf93vZNvjq3b+jFqVpf/AlraGE7hC+EAW3YI71ABUrfifaZWtkMu7+IfMhkbj
         GOOutfkMWBI7KA1oM8JSrcj7UlZg2BYeFZzRXm3XPD1AoThdFFR/J/58b00TT4irs3FJ
         K2kA==
X-Gm-Message-State: AOAM533CFGYBOoDZ7l/oVrCnSb7PgNq/iizaslJa54LDf7ieQ9A4u+MM
	7cpAgWIT8qeFOwZThAD8w3I=
X-Google-Smtp-Source: ABdhPJxLEPP++YGPwby1IHh5Jo8aOvpYEGuwl0Ou3gnTT0efYEAYcb1JgGrU7qM9X7u72NlcSitQKw==
X-Received: by 2002:a17:906:2e55:: with SMTP id r21mr3068102eji.46.1606400074744;
        Thu, 26 Nov 2020 06:14:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d151:: with SMTP id r17ls2333777edo.1.gmail; Thu, 26 Nov
 2020 06:14:33 -0800 (PST)
X-Received: by 2002:a05:6402:19b4:: with SMTP id o20mr2725064edz.103.1606400073876;
        Thu, 26 Nov 2020 06:14:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606400073; cv=none;
        d=google.com; s=arc-20160816;
        b=bGzuZs+SqJZA2JSMuRexA5rxmjlu86NaCwC+nNqYksHukAAMuGyGL4FMyPy3z7yPQD
         RaTTc68W0fu5pGC+1OfRxyHtct8835pvbsCC7YiBpVISnrx6wtR74wWcgPnYzXh2+4Sf
         mp1R1xlV47aE7mb6IZq9ExwThHvHLTn/vp/Px/5ipIOIsMQAUIbYGAtYqDQje41VhiWw
         Ev4KYXP4EDEvGoNCTML2UcoFPgZ1r2UUxF3sTZE3pNkLLB1UFxQuqTmKGlK9FV0tlamE
         dkSDZh6CkJGJlBqw/Zy8vC5XJ9w/f/HLMmcY9epxZAxM86QNs9PgNsUev8vjUqtHAvlR
         9VGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=l+r/ujMibWxRMGoyxuToDzSWZqq35vXIRnqSxtmnTk8=;
        b=C4HEKUVuHbfkWXYJ3unAc5vIXHKMd+ufw+R1msFhpH4a4mIK/5cg7ny4NxFvIIq9SZ
         LIkW1K3VzR8u7mr/G0jP7sqjYVKOFdjwHH0q9gIKSpZ1VQHrF2qutLSq3h1TVFbgv3OH
         iPfP5hTnuEZLgWJkViLs6b+g2A1Gi9PPAJMaIIlTNCqMbaIe+no29ZT24kX26Ctsvt1p
         xyW5hWZkBSmvdXNK8i9BoW6tn74kCTSuJMCQCn65UBl895wbbx3eQ2EJYL/mwvNnykIE
         w9U+FT4PB9MqVrQqFxLv9h/rBMiXKrDT5QGhFRlSPq9vUoJXHOTb3aQwHfZhOZKnS8yl
         MGxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=zRe5uvbk;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id v7si316529edj.5.2020.11.26.06.14.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Nov 2020 06:14:33 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:36344)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1kiI2Y-0001qm-J8; Thu, 26 Nov 2020 14:14:30 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1kiI2X-000108-Af; Thu, 26 Nov 2020 14:14:29 +0000
Date: Thu, 26 Nov 2020 14:14:29 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Valdis =?utf-8?Q?Kl=C4=93tnieks?= <valdis.kletnieks@vt.edu>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: linux-next 20201126 - build error on arm allmodconfig
Message-ID: <20201126141429.GL1551@shell.armlinux.org.uk>
References: <24105.1606397102@turing-police>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <24105.1606397102@turing-police>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=zRe5uvbk;
       spf=pass (google.com: best guess record for domain of
 linux+kasan-dev=googlegroups.com@armlinux.org.uk designates
 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

On Thu, Nov 26, 2020 at 08:25:02AM -0500, Valdis Kl=C4=93tnieks wrote:
> Seems something is giving it indigestion regarding asmlinkage...
>=20
>   CC      arch/arm/mm/kasan_init.o
> In file included from ./include/linux/kasan.h:15,
>                  from arch/arm/mm/kasan_init.c:11:
> ./arch/arm/include/asm/kasan.h:26:11: error: expected ';' before 'void'
>  asmlinkage void kasan_early_init(void);
>            ^~~~~
>            ;
> make[2]: *** [scripts/Makefile.build:283: arch/arm/mm/kasan_init.o] Error=
 1
> make[1]: *** [scripts/Makefile.build:500: arch/arm/mm] Error 2
> make: *** [Makefile:1803: arch/arm] Error 2
>=20
> Git bisect points at:
>=20
> commit 2df573d2ca4c1ce6ea33cb7849222f771e759211
> Author: Andrey Konovalov <andreyknvl@google.com>
> Date:   Tue Nov 24 16:45:08 2020 +1100
>=20
>     kasan: shadow declarations only for software modes
>=20
> Looks like it's this chunk:
>=20
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 59538e795df4..26f2ab92e7ca 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -11,7 +11,6 @@ struct task_struct;
>=20
>  #ifdef CONFIG_KASAN
>=20
> -#include <linux/pgtable.h>
>  #include <asm/kasan.h>
>=20
> Testing shows putting that #include back in makes it compile correctly,
> but it's not obvious why putting that back makes 'asmlinkage' recognized.
>=20
> "You are in a twisty little maze of #includes, all different"... :)

The real answer is for asm/kasan.h to include linux/linkage.h

--=20
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201126141429.GL1551%40shell.armlinux.org.uk.
