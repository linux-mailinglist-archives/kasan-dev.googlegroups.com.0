Return-Path: <kasan-dev+bncBDPL7R4J6AKRBWXNZWGAMGQEDJHMBQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D5BA452DB9
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 10:16:11 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id b133-20020a1c808b000000b0032cdd691994sf926860wmd.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:16:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637054171; cv=pass;
        d=google.com; s=arc-20160816;
        b=VJM46vED6Bx3P6QvqWSQ4MNVQ3xfUj67E/WcvFqCDsy3dbxCHmsRDkJJMw4ZflasHN
         CXO5pFr6ElDa6a6MkMB3C+U2OHPfzPoS7Db8+jctMKXD8k0oqJql9NxPzne7hRNsjAEs
         NJPOe+N15WWSS1MH0/JqAxbgxexcsbEEDTuDDrF4z0S5P1Xe7KBkmJUFXNjlIkbelOAL
         XeUjMmcwirsM3j99Lic8Yklj5kCW8QG1zKKy82j/eBTjtF7ykGhTiLLafHrIIihvY97m
         iRBPrm1dyB5mKELbHiMc7VOOoKI1nR+ELGJMljEaVBJRy9gZR9AWdicQmbz7jXQGifxD
         /mZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=glcEFC0pnmoiaX+4J+d/y2IRU3qb6UNx1OXNVXXJswI=;
        b=yX+2XXh+Xy45O2fI9rRKVbrmLhxqEyyGd4diaFCn9QE4DnQCZFBVvOtreNGctR7+Zc
         DlEelXYPC4Rvl/mPK7jc0c86N48/0hkXUPFl5Kuosc1NbkBpH5fkYb4DXdVJkdGeBxid
         pn+HABgMMYuLbgBdxfDhC4sNWaCKl4dBBrf5xeMcKZZjOeEUnzmqclAN2VGC9Mn65Pu5
         g3gNj2GWof1cCvJei7At66B8TFClKO5OnJmLsURQLSFmetWb39Sg4tWvtGnn1rkO/w6q
         4NdW4CQbPkroKx4XEogeKZ8pze5jTP1opiy708oGbYMwvQM4Hyssw1Dz6VF+YA9+FZtj
         6wuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tsbogend@alpha.franken.de designates 193.175.24.41 as permitted sender) smtp.mailfrom=tsbogend@alpha.franken.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=glcEFC0pnmoiaX+4J+d/y2IRU3qb6UNx1OXNVXXJswI=;
        b=b6xyfqFD6hTdpG60G/436ElPHH9exjAnWsAhRyrN5qcQAWK2BPgk0kViZUYCmKcKBn
         KJRmuzKU5xIJlBt9xMHwBHWHo3NEHxmf5p/zkh4A/aClpxEn2HPPvFF3UGyMKeLcPxJr
         9qTceyEwpiWCxw/WV9TvCq9aBQQw0mwWNfY7DeZVrwoYVYaFnp35dA4XFKC2a2gvuuyZ
         SEZpgHaqXHkdSr25uABwIPuZ6u6trs8xL9aznLiuoPniMVgIPqwsdIk1X7gEtc6dRY1U
         s4+IovdU2q0W0i4W8jGKyPgfmyO6sp1jNNy3QIHzG9jb/HzZO3/4czN03b9JlN/J/jKe
         TF/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=glcEFC0pnmoiaX+4J+d/y2IRU3qb6UNx1OXNVXXJswI=;
        b=Dg7R0NZgK00Y6NWJ8tl43W9c6/Ryx09wPnKKiSIJcoDKmbwcJyAKnQKIFy97jW2q/K
         5AOCnxLatVNwvA0dpMUskBrW3PKtJd2isuUDWzmfuq8p5d7lWKhJqbjEsgl3ksOe3dhj
         H5cUaZLwQBoQ8C2TykkDqjC8RebTnkDVSVviIBz542UwGZiGJXB5DAEHl7BZeNuxMFvY
         ScD7K16ufcFV/iRdxU1gZf2Psp8KYdsnaj6ks476d1+kRdnoHb+UcZhvGtzbuxrjyDGm
         aPN4O2Flksrt1HphoZAFNhHo0p914ABMM//B/tiK4D7eWBp+Sgku7+82c9Hyd6jGSoJt
         JJzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320GNvHke26+rD3v7IN1rnuXYQzZyTyZdxcrwUNTx582S7hlJPW
	smUsxKf6AlWktCLs1NyH8c8=
X-Google-Smtp-Source: ABdhPJzz0bVhf77z/S88R3CV18YN4OcfTtK8jzzVH5bMiZcbk1Z971Z/shfImTKbyiki4GDOLPfLxQ==
X-Received: by 2002:adf:aac5:: with SMTP id i5mr7589489wrc.67.1637054171195;
        Tue, 16 Nov 2021 01:16:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls762395wrr.0.gmail; Tue, 16 Nov
 2021 01:16:10 -0800 (PST)
X-Received: by 2002:a5d:6e8d:: with SMTP id k13mr7672321wrz.295.1637054170221;
        Tue, 16 Nov 2021 01:16:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637054170; cv=none;
        d=google.com; s=arc-20160816;
        b=TUU48UfSiumnKJhrWvRFBo9YcJKrECvA9cRl7zCoAHvMOvE1hcSmQr9WpbmJcH5uB6
         vNliQLdwnzNAQFcRiQOQkj6J3kKjz1it440zvI9imD01b//nS8rdZ5Cn0YK4/BfVMoz/
         YNxl7aiA0Ltj1Y4IUZkONwuOEkDkDlbcFmt0uyOBynWOMyRz7CUznoT7JTxzXn2ccHIv
         1A5cdgiqfS37PaGDHEy51D7JWiYl1+zED1lPPcRy5590whHZHw6QIBMk0Myf3pcfX4rG
         +3rXfdsF4mdIVA/BoHUscCli8TnZWT5UTd9oD+tJrlw+vE3Dh3JPaqoC2TH9U/v0mv5r
         H6hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=MLreTCntOoen73QdN84UWsQmncIGcwNLv5YT/rQQDgk=;
        b=FHd9A0XZNNXXZTfwJh3pxMkfvgJomB+OoJcQqwAYsdD+YX5pivtRnts1UzDj+a4UAL
         WLMn5GVDoPPHh6/X4jZhRVSck0I3eySE4iSLMLIdi4Qbe4o6oqHMFaVnPx40V8ST+gJl
         RWWpclV2PmVBmqZyKiIPYnecV5iZ7xftHA/x5HuhVAy7TWn5bHQGcArd1P6ahqDvojjB
         q0OCvb8Naqg3y1brATddEnl4UrckJbE2eAMkVugicm+q4AYNHoJ7134oPKhQ21b2wsqq
         7ZzeRHBXA+b6YUziGx76vJZrmYaraSaDs0ri6M+t3SvuPuATiUaQwde0lD+drAkphPgU
         tKLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tsbogend@alpha.franken.de designates 193.175.24.41 as permitted sender) smtp.mailfrom=tsbogend@alpha.franken.de
Received: from elvis.franken.de (elvis.franken.de. [193.175.24.41])
        by gmr-mx.google.com with ESMTP id e18si1022872wra.2.2021.11.16.01.16.10
        for <kasan-dev@googlegroups.com>;
        Tue, 16 Nov 2021 01:16:10 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of tsbogend@alpha.franken.de designates 193.175.24.41 as permitted sender) client-ip=193.175.24.41;
Received: from uucp (helo=alpha)
	by elvis.franken.de with local-bsmtp (Exim 3.36 #1)
	id 1mmuZJ-0006sq-00; Tue, 16 Nov 2021 10:15:57 +0100
Received: by alpha.franken.de (Postfix, from userid 1000)
	id 5D232C2D9C; Tue, 16 Nov 2021 10:15:42 +0100 (CET)
Date: Tue, 16 Nov 2021 10:15:42 +0100
From: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Nick Terrell <terrelln@fb.com>, Rob Clark <robdclark@gmail.com>,
	"James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>,
	Helge Deller <deller@gmx.de>, Anton Altaparmakov <anton@tuxera.com>,
	Sergio Paracuellos <sergio.paracuellos@gmail.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Joey Gouly <joey.gouly@arm.com>,
	Stan Skowronek <stan@corellium.com>,
	Hector Martin <marcan@marcan.st>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	=?iso-8859-1?Q?Andr=E9?= Almeida <andrealmeid@collabora.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	"open list:GPIO SUBSYSTEM" <linux-gpio@vger.kernel.org>,
	Parisc List <linux-parisc@vger.kernel.org>,
	linux-arm-msm <linux-arm-msm@vger.kernel.org>,
	DRI Development <dri-devel@lists.freedesktop.org>,
	linux-ntfs-dev@lists.sourceforge.net,
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>,
	linux-pci <linux-pci@vger.kernel.org>,
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Build regressions/improvements in v5.16-rc1
Message-ID: <20211116091542.GA21775@alpha.franken.de>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: tsbogend@alpha.franken.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of tsbogend@alpha.franken.de
 designates 193.175.24.41 as permitted sender) smtp.mailfrom=tsbogend@alpha.franken.de
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

On Mon, Nov 15, 2021 at 05:12:50PM +0100, Geert Uytterhoeven wrote:
> >   + error: modpost: "mips_cm_is64" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
> >   + error: modpost: "mips_cm_lock_other" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
> >   + error: modpost: "mips_cm_unlock_other" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
> >   + error: modpost: "mips_cpc_base" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
> >   + error: modpost: "mips_gcr_base" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
> 
> mips-allmodconfig

there is a patchset fixing this

https://lore.kernel.org/all/20211115070809.15529-1-sergio.paracuellos@gmail.com/

> > 3 warning regressions:
> >   + <stdin>: warning: #warning syscall futex_waitv not implemented [-Wcpp]:  => 1559:2
> 
> powerpc, m68k, mips, s390, parisc (and probably more)

I've queued a patch to fix this for mips.

Thomas.

-- 
Crap can work. Given enough thrust pigs will fly, but it's not necessarily a
good idea.                                                [ RFC1925, 2.3 ]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116091542.GA21775%40alpha.franken.de.
