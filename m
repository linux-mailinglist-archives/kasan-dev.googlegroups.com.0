Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBREB4HYQKGQEUE2LIEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 56A76150A2E
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Feb 2020 16:48:22 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id p19sf6476543plr.8
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Feb 2020 07:48:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580744901; cv=pass;
        d=google.com; s=arc-20160816;
        b=aNAXKJjHU6klCHJRZOWg8RcCY+7/UkExEBBkifXiHShH7n3CEbbT/fxWC0eyHMuAY1
         CA+sJ1gcR0/xkDzD1OTbS4VPYQrcBfckYKASQ400y+1u6x7nFejGwvpWasbPEOSDgSRP
         joPBdZb3HhV2CbAcVn1jXTXYV/HBkFm0RE+6cY8RiZUnHjixP0NUSbFv+evhNsNNm/VB
         40wZlVktyP2IySX88qyAIh/qSbMljT3FCfBtG+BjZSQTus2UUWBYFm63GgPxLFsg1ZO0
         V4O7349tkuV5tKwZZOAxVklJkMmr2YG3vX8qo8JlTGExCM8xWMgsG0duJVALomrgPxE3
         3Gbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=zOJmHiLBJqCiaptXAImR2aUcwlkumGeNS+M1U7xw3OQ=;
        b=JcpKAvIBQw99f/ucPxTB/rA0PEem9y/kvV6dzW95eiUcA47nTvq7S05gx1NvoS4JuP
         InjJ9FNMOL/rSV8njgmCNhjZEbPrd4+7oLJT1jyQ9cyMu4V2LLwhfTZTz2fAGRv7OAPD
         rKxe0sD3C3N4K7QQF/xhtgxnvUoMSbneQQhE8KxYNiwffhVQgkIHGaDi53jaoQeHn3Zg
         vo0/oZtf0iodXlmqEp8JV6kvLbkYAMLPgCW8Rt2ydmxfItF+L7TRSSP1CivnDruZo4pN
         gnU0Fos3sMEaoSXe/0XmjSTVakvIpolhmQMuOXjq8En3Ek8+DwO7ZZ2gWwUsyOe+OTAR
         qmgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=kUu9P+c9;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zOJmHiLBJqCiaptXAImR2aUcwlkumGeNS+M1U7xw3OQ=;
        b=dIWla9rMPaMOcgiEghaADGLs/oTsoD0B0Sa45gOT6W938usBRQ/2MxxWs7Hqw+Jl/I
         C3EsKqo3IXsziLoi/WaruYeaZkjjJ4MJSSyYTA1c8/VPmd7cTwWN3UJnrRUdzKn5zNBq
         Z6dhPBYaTa4cADWsnmqGIBycE2WrsUCPENaxVoi6mJaINf6IF6jk/NBNKopJnNyR/49S
         wmWtO9+F+nIvQVgmlVsyWvTHBnEUSa4eLUPn4mlnKjZYVYXiU2NNobMhPzBmDnjBVtc4
         f3m2U/dmt1L6FdbLJ9EP/WjB9TGg4IB2XKTFQg/1Pb1B4OXMp5DzUc7WbvJje4kM8JVh
         EyUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zOJmHiLBJqCiaptXAImR2aUcwlkumGeNS+M1U7xw3OQ=;
        b=uA7tfYOVn2FAcJ+6PB42jRnIZP2GGFmwDEfR6mAEXv4h/DrLUoPSpyKXb7xvrNW6s0
         7MtV5mvbAy5qKN2YDFrBHzELxBeR6C+kxewlICR6E5h0WLXp0EQ8rirrz1DeDPEOmkkI
         QfmtDyvfJW9wf4OhZ9LAXhlgPFWM5npHNrebzQ17k1Hj4ul1xbaqFw5FkQ+qCMZGF2nh
         nHVIrMTJ0hX0/gYb/uTrbWiEffd3+qxM2OhU2+8uqTYlmKBLSQl6IOP92eU/4htJbCfe
         e6wwOQ/QYYu0oEiBRtqcdOeYqRQ4sgRHQxnFw2gQTvUB7bwAVSSzNLLlIB5Mnr90KHzk
         9VaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWJRN3ZPrGm53Wo/cUGSWnF0YPcFLSDJ4bnLHH44AVBVaUaKZwy
	oDN16R77r+562wiDmRavkHk=
X-Google-Smtp-Source: APXvYqzbOzW/MsZpsutdnQqyKWAF0WxWIyDfc+bNWvW/mpOEfN6YLKF7yELJf8HTEjyul92mcQGLcQ==
X-Received: by 2002:a17:902:8f94:: with SMTP id z20mr24761539plo.62.1580744900955;
        Mon, 03 Feb 2020 07:48:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2a04:: with SMTP id q4ls5934984pgq.6.gmail; Mon, 03 Feb
 2020 07:48:20 -0800 (PST)
X-Received: by 2002:a65:66ce:: with SMTP id c14mr26996667pgw.262.1580744900523;
        Mon, 03 Feb 2020 07:48:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580744900; cv=none;
        d=google.com; s=arc-20160816;
        b=YjtYX44f+gh/G9wG9+e7et+1AhYflSfZX0A5MkwRSKQIVl8sGXZum89gGzIxG/bUvm
         /IqpylmJIxvBMK2P9A7/GxxNqKGuI8Vnqh65FBTvXXoxjVBTbXUNTtSMhZHsBke4AVaW
         iUl3U+uMX3VE9QMq5Jabl22rAueRkvBDias/nIDM0MKikO8g5uFgYB0wB7PiExZp2WUi
         c35qFhVrSryzi63yxI2B2IMhLHmQ38vi8HaJgnCQ/5CQr1+BkhRhyhnHhVQyHVt5ZAiz
         nm4JqZGD3LzRdj07//tlBojiNyVMyfYNeBVQz/9WZvs0pUJfp9sNZT3hGhwkyJ0fstwb
         vOYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=YNMOJs1FPm/l462+AObUcJBpy8J/6Ie1z+BZTrXlP78=;
        b=PTago4qUYOsSQEq6J6pMdHOi7aLZUQ13vEPoUHnB4TB2+5njloIEDg2eP5BK3d+Hq0
         /I2YffQzVssgAzylpNILlxMG9n3E+8hGMB8Fu7otgkq3YZ7XOb+JV9vK03t8eFLB+2GM
         7DwHf5CYyw40WhUxzrYT2VTGLqz2YzS+qomgc3wY8bUvczq2udPmNoapojVbSpZc2TSm
         DXpX3TnfbjyaN3zfr7/K8xWum99YwRbgy0iQ4iiRoIS+S031ba00d9PJUpgg5Aka3nSr
         DNx3hJDzRJz+NqgUlvMHoH6Oxw2AVn35Tdb+5jDgOAYNSkdvWeYkeLNORVOOiuAV/irs
         WDRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=kUu9P+c9;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id m187si259571pga.3.2020.02.03.07.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Feb 2020 07:48:20 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id l19so11746427qtq.8
        for <kasan-dev@googlegroups.com>; Mon, 03 Feb 2020 07:48:20 -0800 (PST)
X-Received: by 2002:ac8:7695:: with SMTP id g21mr22123082qtr.99.1580744899546;
        Mon, 03 Feb 2020 07:48:19 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id n132sm9814556qke.58.2020.02.03.07.48.15
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 03 Feb 2020 07:48:18 -0800 (PST)
Message-ID: <1580744894.7365.3.camel@lca.pw>
Subject: Re: [PATCH V12] mm/debug: Add tests validating architecture page
 table helpers
From: Qian Cai <cai@lca.pw>
To: Christophe Leroy <christophe.leroy@c-s.fr>
Cc: Anshuman Khandual <Anshuman.Khandual@arm.com>, linux-mm@kvack.org, 
 Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
 <vbabka@suse.cz>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Thomas
 Gleixner <tglx@linutronix.de>, Mike Rapoport <rppt@linux.vnet.ibm.com>,
 Jason Gunthorpe <jgg@ziepe.ca>, Dan Williams <dan.j.williams@intel.com>,
 Peter Zijlstra <peterz@infradead.org>, Michal Hocko <mhocko@kernel.org>,
 Mark Rutland <Mark.Rutland@arm.com>, Mark Brown <broonie@kernel.org>,
 Steven Price <Steven.Price@arm.com>, Ard Biesheuvel
 <ard.biesheuvel@linaro.org>, Masahiro Yamada
 <yamada.masahiro@socionext.com>,  Kees Cook <keescook@chromium.org>, Tetsuo
 Handa <penguin-kernel@i-love.sakura.ne.jp>, Matthew Wilcox
 <willy@infradead.org>, Sri Krishna chowdary <schowdary@nvidia.com>, Dave
 Hansen <dave.hansen@intel.com>, Russell King - ARM Linux
 <linux@armlinux.org.uk>,  Michael Ellerman <mpe@ellerman.id.au>, Paul
 Mackerras <paulus@samba.org>, Martin Schwidefsky <schwidefsky@de.ibm.com>, 
 Heiko Carstens <heiko.carstens@de.ibm.com>, "David S. Miller"
 <davem@davemloft.net>, Vineet Gupta <vgupta@synopsys.com>, James Hogan
 <jhogan@kernel.org>, Paul Burton <paul.burton@mips.com>, Ralf Baechle
 <ralf@linux-mips.org>, "Kirill A . Shutemov" <kirill@shutemov.name>, Gerald
 Schaefer <gerald.schaefer@de.ibm.com>, Ingo Molnar <mingo@kernel.org>,
 linux-snps-arc@lists.infradead.org,  linux-mips@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org,  linux-ia64@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org,  linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,  x86@kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev <kasan-dev@googlegroups.com>
Date: Mon, 03 Feb 2020 10:48:14 -0500
In-Reply-To: <8e94a073-4045-89aa-6a3b-24847ad7c858@c-s.fr>
References: <473d8198-3ac4-af3b-e2ec-c0698a3565d3@c-s.fr>
	 <2C4ADFAE-7BB4-42B7-8F54-F036EA7A4316@lca.pw>
	 <8e94a073-4045-89aa-6a3b-24847ad7c858@c-s.fr>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=kUu9P+c9;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Mon, 2020-02-03 at 16:14 +0100, Christophe Leroy wrote:
>=20
> Le 02/02/2020 =C3=A0 12:26, Qian Cai a =C3=A9crit=C2=A0:
> >=20
> >=20
> > > On Jan 30, 2020, at 9:13 AM, Christophe Leroy <christophe.leroy@c-s.f=
r> wrote:
> > >=20
> > > config DEBUG_VM_PGTABLE
> > >     bool "Debug arch page table for semantics compliance" if ARCH_HAS=
_DEBUG_VM_PGTABLE || EXPERT
> > >     depends on MMU
> > >     default 'n' if !ARCH_HAS_DEBUG_VM_PGTABLE
> > >     default 'y' if DEBUG_VM
> >=20
> > Does it really necessary to potentially force all bots to run this? Syz=
bot, kernel test robot etc? Does it ever pay off for all their machine time=
s there?
> >=20
>=20
> Machine time ?
>=20
> On a 32 bits powerpc running at 132 MHz, the tests takes less than 10ms.=
=20
> Is it worth taking the risk of not detecting faults by not selecting it=
=20
> by default ?

The risk is quite low as Catalin mentioned this thing is not to detect
regressions but rather for arch/mm maintainers.

I do appreciate the efforts to get everyone as possible to run this thing,
so it get more notices once it is broken. However, DEBUG_VM seems like such
a generic Kconfig those days that have even been enabled by default for
Fedora Linux, so I would rather see a more sensitive default been taken
even though the test runtime is fairly quickly on a small machine for now.

>=20
> [    5.656916] debug_vm_pgtable: debug_vm_pgtable: Validating=20
> architecture page table helpers
> [    5.665661] debug_vm_pgtable: debug_vm_pgtable: Validated=20
> architecture page table helpers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1580744894.7365.3.camel%40lca.pw.
