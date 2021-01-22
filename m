Return-Path: <kasan-dev+bncBDAZZCVNSYPBBZODVSAAMGQEKRBGSWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 74109300C0B
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 20:05:10 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id y2sf3972072pgq.23
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 11:05:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611342309; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZErm/F4bH2N5IOg0zo0Boib0Uwo6gNWUDGeIpk4fv1FITgygtiFcGfALQx9wV6wn0f
         +atVb0meTbuiLNWJXXD9ophOrKXImz8pUOQpiS15nhsDCafdjRWkoK7l1hGSwJFcDDvR
         9cJVT6IdAUeQzohp6GUjjTWbzh8vHCw9qUcbtgLcUV7uvQLaZGcI6dPNkm1/qwidUFJl
         0qQAsabcrO5vd7G43Yfef2aBvPHEGOQGZcUsmTpAz8W5nhKXyQ1HLoVQAd/s2amygpIr
         FB8tqmv5gQv/W0H/nLmEf3S4C8OQJH/lt+hta98iSQc/k/IyUS/+uoqTkiDqnlaW7oBP
         0jsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=zRoaOFtKZ8vKBGt7QPmpYjMgo/HJdcpaY8NVX3yB7hs=;
        b=xkP8IVC9N7TfQO65TIdDPZC4B1wKvojI4txL9n7sqlc/AtyVWW4esADdFPsUNWkH+K
         pnAYRFePo4vCGHG457rmaCB68uTUNaURYcZ3eS+JJRowldjZ9AJl7Dr8ngsc/FH7iwGO
         2mHiwwfvpME67esw4Bl29jcj6A0nMBAkwqYhR/zH6yEPtnB3pWXD/n29FfO9Hgluk0Fo
         M1Hug7oAxIt4nbOFWU2THBDL8cZQsMeNqu4jywP9qeAimGoyulnDvDQnzwCCDLExwPyS
         V7D9RNeqStUhCFAcULjnLXNaJAQ+p15MShHv+uWuNqgH4L4GeD93l17gk61Uz2EPspG4
         vdWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UAhzpczD;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zRoaOFtKZ8vKBGt7QPmpYjMgo/HJdcpaY8NVX3yB7hs=;
        b=BIln80gNEMkiNADOxoDX107gXAyFlDlVnbNFz9TabK5DVCPxJWPL42V0IQ+7nA+V9g
         aQlyRTUQUDwfEQDjvsRh4or0XlHZv+gaVDiiLToWACIwmCYU5svoQqXs/FEL39YrE8Uc
         +EItPZIdZ9gLZ3TvSmA2Wvzin1VWSCjUYENC3+OM8KFLUMcEBr03lnnrjpSCwW7oRBhH
         ddn94xTSnhG7u8XmJuHnMKm+JGTkMrOUiXHnzyHTg9dOEvrWGeXbeaAxPR9SrpuFsBHy
         2tsZzWz7uCBB9Ny5jle4pBmFqY8PUPeZ2d2/LeB4R378hcbzO/O5XnlHVpcwivQ/Lj6y
         O2/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zRoaOFtKZ8vKBGt7QPmpYjMgo/HJdcpaY8NVX3yB7hs=;
        b=dnW8ZSj7/fXahNl9CfBg8sQff+85s7ipIgORqqFY/mqNbV3rEts27rZdcAEoRXbeEM
         NiwiSPdW0svhtf1sCQxrZRm4+qAqtfNg10x4LPXqtyZ9UDyNRWcEnIzmD4pC8WQMwfdF
         nMTZA1xNjRYTWsS73IXgC9d8V+CM2Jzq1GUN2F52Jh4AhSkSeCafQWRvi5TJaTrNHu7R
         WlEpVMufV+ISBZSA704Sw2ddfGeh+CD5WHanX18UC/ON/iw/olBQgjc+Y6BvWvNTiTAS
         tN9D0NMxrm0JvP9e/nTaJ8i+5E/VDJ/1fhKhCl8Kgfamb0oSTVoHa8mosIZK12SGzwNQ
         WzLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320UN5WpmuERMhwkri/j++hI2RKc4GU1EqxniHSUix5tkrZtyR8
	k3fsDWpMtpnTsCizJF8jL8U=
X-Google-Smtp-Source: ABdhPJy4JEItNKA84sSJqxl8POlhw3oEInyKJmH07DEy1jrabi7Y0KHNHfN0uUnGor7QdGkqS+Dgtg==
X-Received: by 2002:a17:90b:4acd:: with SMTP id mh13mr7096516pjb.229.1611342309227;
        Fri, 22 Jan 2021 11:05:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9155:: with SMTP id 21ls2470154pfi.3.gmail; Fri, 22 Jan
 2021 11:05:08 -0800 (PST)
X-Received: by 2002:a63:4557:: with SMTP id u23mr63719pgk.346.1611342308785;
        Fri, 22 Jan 2021 11:05:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611342308; cv=none;
        d=google.com; s=arc-20160816;
        b=R89eUKB9/zxxUf53bEBHhDYIFn7fzVpm8a5y5YhM2b6R97QoHeJjQibDxl1Tua4tAJ
         Mav7SeGkrtz3s8O9mzRpBY+5u9cTU8wSjYZFNhoGuZHw69H8xMaibE7gaaprpXzRcLYR
         1sU15wnCbcGAU1gNmu5jKcZ3JRrmYDkCGA+CZiP3Vzrae1q5SjuEjgN/XW/oFH1pe3aY
         xGblcqXnsFGKK3D/ncH11Wyl0YBjf/OAmJdXmSh3Ast2Cj83zqVe8Bb+HkxrIZk1GugQ
         d63GHJVxlrWUTrJW1SEjTkT3sa5JHhseM2DH/wEVOybAXy3tMzL2TwOUPAeklFFGsEJz
         9ABA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Sm6COnege4Inf+2wVpPt4PES6NqYQf1AI6YlFWvMG+E=;
        b=OnyeARnxlPZrXEqnCy+9uTnVRiUkwP7UbiI6rU5RSlsZoJYxYYP31kOSdzpeVEXgvB
         kW6X3cRdjVJaaJcq3KneXA3KLncInR3IcBs5sKuObAf9vPZGvf398bUpms1/4ywGK8gc
         uJfsqEeuk28G1PlUnLkaEgjf578/3cZQuMvv5ixr957jGst1E9WSCLhg46NEjvV6w7nq
         ckfonMwrh39S31W2JtGRyaFTDDw48kVRCrUqIFFwzMrQUFO2iPqn/oO/IdgExvQel5Py
         6Wx65jYHx66WoocFh3QEbw717VxwMSBFw8vvXCaMzvTCRImDXvvhrTRfwy4CUniV4cvz
         B/ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UAhzpczD;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id jz6si651337pjb.1.2021.01.22.11.05.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jan 2021 11:05:08 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DCB2023AC1;
	Fri, 22 Jan 2021 19:05:04 +0000 (UTC)
Date: Fri, 22 Jan 2021 19:05:01 +0000
From: Will Deacon <will@kernel.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Dan Williams <dan.j.williams@intel.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>,
	yj.chiang@mediatek.com, Catalin Marinas <catalin.marinas@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>, Mark Brown <broonie@kernel.org>,
	Guenter Roeck <linux@roeck-us.net>, rppt@kernel.org,
	tyhicks@linux.microsoft.com, Robin Murphy <robin.murphy@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	gustavoars@kernel.org, Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
Message-ID: <20210122190501.GA25471@willie-the-truck>
References: <20210109103252.812517-1-lecopzer@gmail.com>
 <CAAeHK+z3oYx4WqX7Xor7gD=eqYkzW0UBS4h4is00HnfNnNkpDA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+z3oYx4WqX7Xor7gD=eqYkzW0UBS4h4is00HnfNnNkpDA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UAhzpczD;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Jan 21, 2021 at 06:44:14PM +0100, Andrey Konovalov wrote:
> On Sat, Jan 9, 2021 at 11:33 AM Lecopzer Chen <lecopzer@gmail.com> wrote:
> >
> > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > ("kasan: support backing vmalloc space with real shadow memory")
> >
> > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> > by not to populate the vmalloc area except for kimg address.
> >
> > Test environment:
> >     4G and 8G Qemu virt,
> >     39-bit VA + 4k PAGE_SIZE with 3-level page table,
> >     test by lib/test_kasan.ko and lib/test_kasan_module.ko
> >
> > It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL
> > and randomize module region inside vmalloc area.
> >
> >
> > [1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")
> >
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > Acked-by: Andrey Konovalov <andreyknvl@google.com>
> > Tested-by: Andrey Konovalov <andreyknvl@google.com>
> >
> >
> > v2 -> v1
> >         1. kasan_init.c tweak indent
> >         2. change Kconfig depends only on HAVE_ARCH_KASAN
> >         3. support randomized module region.
> >
> > v1:
> > https://lore.kernel.org/lkml/20210103171137.153834-1-lecopzer@gmail.com/
> >
> > Lecopzer Chen (4):
> >   arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
> >   arm64: kasan: abstract _text and _end to KERNEL_START/END
> >   arm64: Kconfig: support CONFIG_KASAN_VMALLOC
> >   arm64: kaslr: support randomized module area with KASAN_VMALLOC
> >
> >  arch/arm64/Kconfig         |  1 +
> >  arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
> >  arch/arm64/kernel/module.c | 16 +++++++++-------
> >  arch/arm64/mm/kasan_init.c | 29 +++++++++++++++++++++--------
> >  4 files changed, 41 insertions(+), 23 deletions(-)
> >
> > --
> > 2.25.1
> >
> 
> Hi Will,
> 
> Could you PTAL at the arm64 changes?

Sorry, wanted to get to this today but I ran out of time in the end. On the
list for next week!

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122190501.GA25471%40willie-the-truck.
