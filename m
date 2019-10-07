Return-Path: <kasan-dev+bncBDEKVJM7XAHRBUPP53WAKGQEMZCHVVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CA43CEEDA
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 00:10:26 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id f17sf6583993otp.13
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 15:10:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570486225; cv=pass;
        d=google.com; s=arc-20160816;
        b=u+YUFbAumpszlPPGl+IZUKn5+ud9HutvYkwShOf+etyYfxgdTLDGEg/99sgun+w/q+
         wc2H0ClNT22J/HRFrW4Roer6utMcNGWlBiDgIhZVVagMk/hBwMtwqBa8FNRvK+stZjdW
         CNxX90fJ0cAx44CETwDa6YtuKmqsA3XQ2OIkyhkhmrMdGSzKpdr5FYJHexscNb/FelhX
         y0l2UN9oozMBt/hT/GrKOSCJqhcok65AOjIDM++P98CGfyiJxfMWsTKuCAqFhF7jRTui
         r7ZfqDrzIdBFdFLOmw/fE1mDMURukbpjYp1CrrmsyiCoctw2Y1k7BBvFMgkt6wIr9WxR
         LnrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=fyZhR5bcbGe6Oi9lJSHw+TdHwcNzt7gp2DV0OAiMGfw=;
        b=YGcO+qmHfL0C3Ih/mAnj153yNL75UrZGs1TPs6rFtecRkHREhmdi8PbThw3t45DmXP
         oWBtdmK2ex33p3ZQrTLVGznaVEZG3K0MB5qJfeBq7CjkSnNoQfXkgVMTcuSu+mmpBtxr
         bPvAYe09khxeSXlLFEotZDiY8/gSMVZ4rVPSZbQGMVutEL2Ar2bYY8qDFYrOsDusnPS/
         rz4q4SYH3zaEcVLR4BvJdVpbI3eeMH3/22d6vM9/0e6Sl331gMxow4X1g6WxGc7ibSMv
         AFr5SQptD+o+Wh8qulZdCjGFkEO3xhL5YfPHPS+QWNVNhl7bxAhjL7bJZaZZ+8XecUtc
         ytsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.195 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fyZhR5bcbGe6Oi9lJSHw+TdHwcNzt7gp2DV0OAiMGfw=;
        b=SeQJXWImKSIHOdq7AWxklQgkpE41hRNCadhP22BnJtO7NzztvAibTrJH91PwQxj7f5
         Ar6gyhgMcK0P6is2ubJ//Ee1uBYWifXV9Ep+JHZHO2xM4P2FgGffKHPhaAYZLNpFxdIQ
         x8sx9hV5r7p2BVNx6gZFIaS0hJiwyJJ61Z+HV3P2Gmlnb16R3IKmniUUGcn4sx0z3aOr
         roJxw+HxBkWME4QwPDC6avHBGsLHq3ZlOafNFwAw7uwYnzgCzTCkT/j22CyVJysLHThh
         uvOANfmSUMoK28lyp9oQN9ez0JYOZvN3jry2MNvUy8ru19Dlu2bKf4Sz1fgQFr9RssKw
         WlbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fyZhR5bcbGe6Oi9lJSHw+TdHwcNzt7gp2DV0OAiMGfw=;
        b=Jmb4NpAT+SP8RU/5NzkQPd6KdCJjLpVx6kha1IXqhJfEg7LjI6FWv3bJoL2Ejd6HdO
         n5OBAaqtxa5fW8LqfxofCf0Jtf4KiikmPXDKlBRDjFDTa4ppENSNyCdDAcpcJGyrUl76
         4zWiv5Vko+j8IE6s33eCP0u4gs4shxfgAjm5ZeT05Q06QJgSc8pes+ItMU0D58y3Vqm5
         17KyBgzsKZbleqlxR3ovKFkwsO1MMA6AwDkuUWQNEfVSW84SF2IniLCC7Fcwl40qphO6
         M62burogVfoABOBs9ibeLPC8mfu67qrZn04rg0PSA64iUjPk5vV5s7wzHBoY3NHFsTjs
         pzDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWV5xNBmnNgniVhd0LJqg79lTFS4jsYzfTuOCF2c912ZZKsgXb6
	lbTeF0lQ54zK9GakSV4KJNI=
X-Google-Smtp-Source: APXvYqzfshVHu7jheDRbWolW3SQuMq4imbyBJBamCcl3/P4z+LXO1ROLMhd7T3fvsVKiNRZx0EUFCg==
X-Received: by 2002:aca:c4d4:: with SMTP id u203mr1231889oif.121.1570486225459;
        Mon, 07 Oct 2019 15:10:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ad92:: with SMTP id w140ls255971oie.2.gmail; Mon, 07 Oct
 2019 15:10:25 -0700 (PDT)
X-Received: by 2002:aca:5854:: with SMTP id m81mr1320767oib.130.1570486225012;
        Mon, 07 Oct 2019 15:10:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570486225; cv=none;
        d=google.com; s=arc-20160816;
        b=UYG5XRxShTzsCHH/ENQe+jCWjamI20PHbxzVspaZ8Qh6v/+vG0SEMWjRMI2E77R/Ef
         rrgveao+4tQB5iIaJ1F8OmlmUg4/8viyZPfeSY2iPzJwDe3ArgEg7Fre8OvbXTob3IX8
         lUu3fZ6XdelbPyhFrzImyNP0OxkqOx36eHUv5W53piAEjS4QssnguJAHD5IBA26ptxEy
         nJBI11gxcC9WUzCP3H972Uh+tfj6Am2I06lKoV76XGFDMa+aEqv29uRpb3dyjunu5Chl
         cO2boTmtzCUd2gJ5bwFKdVC032pZzmWrslu2trGHDdPdAn19ESEy/HWk62+4o37FIlw3
         eefw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=Ejfq0Mc5y2dQchNRlWvp8Diy33ha1r0LaAd27i+X0Y8=;
        b=VkMQPXDl5GvkaHLy8/mD/rYLurilk4PGh8I3X2dPVXpblCJXqBdGCHB0ylFvHGLDBm
         e8u2bX4NmvwuY7gW4dDj3xfSZsJgqbjdc9bxsG15MiNaqtj41LEh35WYiHY5p+QGHETB
         uGQB1set82PkXmYEbpc9XDly7mOhVBVY5ihb0/7CdU8RQ6Yg2UohuA2bFANGYWMJfgiP
         2iUWCKTESgx/zZt6qmmYDV/GA6Cyzod2n/UwU4RYmrEjY3XTFweIupHbOUUHaCivtcla
         u+R25fLeweG2QlZ0KzhnB5SjjMDDicRZMYaKy5dCTVJgmOW0h0xMqmwqBhmBRwFh75OE
         tS7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.195 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
Received: from mail-qt1-f195.google.com (mail-qt1-f195.google.com. [209.85.160.195])
        by gmr-mx.google.com with ESMTPS id c6si1377931oto.5.2019.10.07.15.10.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 15:10:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.195 as permitted sender) client-ip=209.85.160.195;
Received: by mail-qt1-f195.google.com with SMTP id i26so4649320qtm.8
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 15:10:24 -0700 (PDT)
X-Received: by 2002:ac8:342a:: with SMTP id u39mr32462138qtb.7.1570486224339;
 Mon, 07 Oct 2019 15:10:24 -0700 (PDT)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <CACRpkdbqW2kJNdPi6JPupaHA_qRTWG-MsUxeCz0c38MRujOSSA@mail.gmail.com>
 <0ba50ae2-be09-f633-ab1f-860e8b053882@broadcom.com> <CAK8P3a2QBQrBU+bBBL20kR+qJfmspCNjiw05jHTa-q6EDfodMg@mail.gmail.com>
 <fbdc3788-3a24-2885-b61b-8480e8464a51@gmail.com>
In-Reply-To: <fbdc3788-3a24-2885-b61b-8480e8464a51@gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Tue, 8 Oct 2019 00:10:08 +0200
Message-ID: <CAK8P3a1E_1=_+eJXvcFMLd=a=YW_WGwjm3nzRZV7SzzZqovzRw@mail.gmail.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Alexandre Belloni <alexandre.belloni@bootlin.com>, 
	Michal Hocko <mhocko@suse.com>, Julien Thierry <julien.thierry@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Christoffer Dall <christoffer.dall@arm.com>, David Howells <dhowells@redhat.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, kvmarm@lists.cs.columbia.edu, 
	Jonathan Corbet <corbet@lwn.net>, Abbott Liu <liuwenliang@huawei.com>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Russell King <linux@armlinux.org.uk>, 
	kasan-dev <kasan-dev@googlegroups.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, drjones@redhat.com, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, 
	Marc Zyngier <marc.zyngier@arm.com>, Andre Przywara <andre.przywara@arm.com>, 
	Philippe Ombredanne <pombredanne@nexb.com>, Jinbum Park <jinb.park7@gmail.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Nicolas Pitre <nico@fluxnic.net>, Greg KH <gregkh@linuxfoundation.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Rob Landley <rob@landley.net>, philip@cog.systems, 
	Andrew Morton <akpm@linux-foundation.org>, Thomas Garnier <thgarnie@google.com>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of arndbergmann@gmail.com designates 209.85.160.195 as
 permitted sender) smtp.mailfrom=arndbergmann@gmail.com
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

On Mon, Oct 7, 2019 at 11:35 PM Florian Fainelli <f.fainelli@gmail.com> wrote:
>
> On 7/18/19 12:51 AM, Arnd Bergmann wrote:
> > On Thu, Jul 11, 2019 at 7:00 PM Florian Fainelli
> > <florian.fainelli@broadcom.com> wrote:
> >> On 7/2/19 2:06 PM, Linus Walleij wrote:
> >
> >>
> >> Great, thanks a lot for taking a look. FYI, I will be on holiday from
> >> July 19th till August 12th, if you think you have more feedback between
> >> now and then, I can try to pick it up and submit a v7 with that feedback
> >> addressed, or it will happen when I return, or you can pick it up if you
> >> refer, all options are possible!
> >>
> >> @Arnd, should we squash your patches in as well?
> >
> > Yes, please do. I don't remember if I sent you all of them already,
> > here is the list of patches that I have applied locally on top of your
> > series to get a clean randconfig build:
> >
> > 123c3262f872 KASAN: push back KASAN_STACK to clang-10
>
> This one seems to have received some feedback, not sure if it was
> addressed or not in a subsequent patch?

ebb6d35a74ce ("kasan: remove clang version check for KASAN_STACK")

got applied, it seems clang will remain broken with KASAN_STACK
for a while.

> > 053555034bdf kasan: disable CONFIG_KASAN_STACK with clang on arm32
>
> This one I did not take based on Linus' feedback that is breaks booting
> on his RealView board.

That likely means that there is still a bigger problem somewhere.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1E_1%3D_%2BeJXvcFMLd%3Da%3DYW_WGwjm3nzRZV7SzzZqovzRw%40mail.gmail.com.
