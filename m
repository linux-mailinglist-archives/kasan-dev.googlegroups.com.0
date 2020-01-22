Return-Path: <kasan-dev+bncBCNOLFNUSYCBBHFNUHYQKGQEO327XNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 17D2C145768
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2020 15:05:17 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id j6sf4632728edt.21
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2020 06:05:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579701916; cv=pass;
        d=google.com; s=arc-20160816;
        b=ST/R3gjERldsqx16hWkGXI2glEbUwg8z0Mk+bWpWzCn0mVnw7PIC82Z6CbWFT67+gX
         4tnYDNNZxgbdh4UAX9yDF2KbTvajjkJBofRTIF1lVV8KMFy4kHn83LAtLk+zvwGB58Xl
         41hdHyYjf1tFXdnEoWS/e6LTxMe30KiQ2n/cRK8enLpKPi7gHHR+8aqH86AXXrPeScWy
         QuNicEePjrxvvzJ9eYJwnXDGmmrWLaKbCRTLDwWvTBrkwnFXKMvBAWv7GVGTOyYP1spe
         VcSaIpkxsZMLNNitlKWIi1VZsDMtySXw9dF4v6CNE1Kjo3ZNDut1bG6ZgD4dyq7LC1D6
         7W/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=/WDzDDY7zmq27p7XyPJ7BEkYokzfxsTFNsHUc2CvRfM=;
        b=vcMEZSsN5yACT2ioegooKkezWrs60W0vkdnbG+dyajaNDvr8RDiMVPGwz56m2YOl69
         +h6uJ+gNyLQsVnjJIqVjpVG59U6Cd8rs7C9XoxuDYgxVk/MCBEd1israbpNHcghATKce
         pzJfgoHKeOuNKZICgjmyC0yAak/MuJiEF5JhTlowjstU+y6BIJSP22nnyrBAYz5Irgz2
         4QBL3ujsijRtx0UJy2Zd88RjweVLjLSTUOeO7/zOpZld+vZ7bzusgVo/ha7MYkzL3trr
         I+1TMQtqmYEIk3Z6A8UM6KIQSejzCH8Q3mbtWD3RYkkenETJ1xhnXm1pkHSjZKczbYVg
         okUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wei.liu.linux@gmail.com designates 209.85.221.65 as permitted sender) smtp.mailfrom=wei.liu.linux@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/WDzDDY7zmq27p7XyPJ7BEkYokzfxsTFNsHUc2CvRfM=;
        b=OU52EpsXG8dDIZ1fnw2hx6er0KeXnVEjAYbFRTQCLb4DwuHdX1ni7dUiD+KqZ2HjsP
         AF+lj7NbP/2gPC5wDl6Wr47DPzRg4LHarwg4fMcrIa5rkxjmx3DiJWzJagYAfEYpYcxe
         Q06EoW4C6tYyOpc88eZa8h5a6FMk1AnIbZDmGWDu7lGIlw5Pt1WnPiUwnQ2XdEKW2h7b
         zPmm51e+pNIZjh5EHh+rX+QOuy3msRSPrWBBZ1VvAKXMRCdy2dtpC9fxnC4BaX8XkT5k
         K3GYz/YH/gCTqZ8MjSmtC3az/lZZeizpTK1k0JCUuA15x9nFFhyTfAAKZL4sGkH/hXCs
         lPMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/WDzDDY7zmq27p7XyPJ7BEkYokzfxsTFNsHUc2CvRfM=;
        b=eDWH8nB0hkAHtc74tSFyxqlc3oRvX9ZQM4Zr8twj4NGkKHoIVx0prsHTUDQU3s6CYs
         LGixFqemdh5Wg/TyxAEtxTOZd26QPlF1OZDNTC1oALEmRLG02AK0pDQvWQfffl3UIInV
         6375zTim9E0XQoYev0YJSaT4wV2y7lBFyjxPZygSYkwIdRwdOpSKp3LSxpEmsNIj2eTt
         Eb0EmsO8ZF5bERk0s2Gk9AsNyBX8tRHARfDndfbRBwfVsgg7DbrUwPQNP8/k2Mi+cLla
         ls0rvBEwX5DieOZgVDr9fY1nZsp4xshDzW3RqQr7AocvBgoy3dxwyXK18b8RtI3fceJB
         slsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWPNNHq81y1/Nnf/I2A/KMVwCM+laNp5fGAG0xGKFJeePfM/eGv
	pzII21qupT/RzbQUbdxgAew=
X-Google-Smtp-Source: APXvYqxz8pc61bhSLvSKrwGf3YGjWH3lPm0RchgnkCeZyhuPfEQgQqtouzGksCHHy0pMzgUARQh5AA==
X-Received: by 2002:a05:6402:714:: with SMTP id w20mr2770194edx.46.1579701916785;
        Wed, 22 Jan 2020 06:05:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:584f:: with SMTP id h15ls11103998ejs.9.gmail; Wed,
 22 Jan 2020 06:05:16 -0800 (PST)
X-Received: by 2002:a17:906:af55:: with SMTP id ly21mr2670173ejb.115.1579701916237;
        Wed, 22 Jan 2020 06:05:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579701916; cv=none;
        d=google.com; s=arc-20160816;
        b=XeiUt1ETwTAflopqMT8RuojIKLOhuHE1x10vvYiGqJ0vaDvrVCLM5B5sGhiT7F3lAY
         4r+MVALQ4axXssdOuJe3S6axGxKE/507NfBaRlK/eWnPBSOGjbWHFefhz1aY6KT3/XVy
         VP693YjRtu3uMroK9vD5Rqkq0wPlew2/hYy15IJ3Rooovm3u8IV2w1zij2pWhjK19bxA
         cC1Wnl3sRFICLJj2D5Lm1KIk5ksQ0IVbE63BgCyu+2KQLrqwaJprui0RkWAGDEyCyTS/
         XphCFtKqW7l6tvcxeeWRzDLNo2NORONCi1Xh0MHQLMiJ2uHdGOzDRV8HsD/wOHzbF25n
         xYGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=nTDawKBuPPz3RFrkaA7TRY9Jia2zninb0DeM+/pbQ8U=;
        b=YG7yEoYuRPN7O6bjnZxqcVmH94YaaDiJoNslnZAXi6rAS2jXWuHiOTEBDm++WBj6wf
         lvruyV94vcL1OYPezSis1zdJj7DnsrSqqqWTUucGeJGVUP/XS5bxzZN8nFpozJ9O8q+v
         erUGUMydgIMOd4sc+OpmhMPM+CIbmm6PUKkAqwKhe8+KiMW38aZSQw3Ykl2NVyhiw2qp
         UlmsKoWDIyANdDTHzzz58yoFLX+ouMi0/0b4b8YNeyYeS8/ZY3wFCvx9ymwyF5YPt2oa
         9a64XdKVXYoiZKV6ku8che1eG/YaFO7eDhaGUScVerQwLEizqwg7saxsp81biZrVSRZm
         fw/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wei.liu.linux@gmail.com designates 209.85.221.65 as permitted sender) smtp.mailfrom=wei.liu.linux@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wr1-f65.google.com (mail-wr1-f65.google.com. [209.85.221.65])
        by gmr-mx.google.com with ESMTPS id x18si1739542eds.2.2020.01.22.06.05.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Jan 2020 06:05:16 -0800 (PST)
Received-SPF: pass (google.com: domain of wei.liu.linux@gmail.com designates 209.85.221.65 as permitted sender) client-ip=209.85.221.65;
Received: by mail-wr1-f65.google.com with SMTP id c14so7383561wrn.7
        for <kasan-dev@googlegroups.com>; Wed, 22 Jan 2020 06:05:16 -0800 (PST)
X-Received: by 2002:a05:6000:1241:: with SMTP id j1mr11170497wrx.26.1579701916005;
        Wed, 22 Jan 2020 06:05:16 -0800 (PST)
Received: from debian (41.142.6.51.dyn.plus.net. [51.6.142.41])
        by smtp.gmail.com with ESMTPSA id b137sm4417661wme.26.2020.01.22.06.05.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Jan 2020 06:05:15 -0800 (PST)
Date: Wed, 22 Jan 2020 14:05:12 +0000
From: Wei Liu <wei.liu@kernel.org>
To: Sergey Dyasli <sergey.dyasli@citrix.com>
Cc: Paul Durrant <pdurrant@gmail.com>, xen-devel@lists.xen.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Boris Ostrovsky <boris.ostrovsky@oracle.com>,
	Juergen Gross <jgross@suse.com>,
	Stefano Stabellini <sstabellini@kernel.org>,
	George Dunlap <george.dunlap@citrix.com>,
	Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Wei Liu <wei.liu@kernel.org>
Subject: Re: [PATCH v2 4/4] xen/netback: fix grant copy across page boundary
Message-ID: <20200122140512.zxtld5sanohpmgt2@debian>
References: <20200117125834.14552-1-sergey.dyasli@citrix.com>
 <20200117125834.14552-5-sergey.dyasli@citrix.com>
 <CACCGGhApXXnQwfBN_LioAh+8bk-cAAQ2ciua-MnnQoMBUfap6g@mail.gmail.com>
 <85b36733-7f54-fdfd-045d-b8e8a92d84c5@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <85b36733-7f54-fdfd-045d-b8e8a92d84c5@citrix.com>
User-Agent: NeoMutt/20180716
X-Original-Sender: wei.liu.linux@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wei.liu.linux@gmail.com designates 209.85.221.65 as
 permitted sender) smtp.mailfrom=wei.liu.linux@gmail.com;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Jan 22, 2020 at 10:07:35AM +0000, Sergey Dyasli wrote:
> On 20/01/2020 08:58, Paul Durrant wrote:
> > On Fri, 17 Jan 2020 at 12:59, Sergey Dyasli <sergey.dyasli@citrix.com> wrote:
> >>
> >> From: Ross Lagerwall <ross.lagerwall@citrix.com>
> >>
> >> When KASAN (or SLUB_DEBUG) is turned on, there is a higher chance that
> >> non-power-of-two allocations are not aligned to the next power of 2 of
> >> the size. Therefore, handle grant copies that cross page boundaries.
> >>
> >> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
> >> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
> >> ---
> >> v1 --> v2:
> >> - Use sizeof_field(struct sk_buff, cb)) instead of magic number 48
> >> - Slightly update commit message
> >>
> >> RFC --> v1:
> >> - Added BUILD_BUG_ON to the netback patch
> >> - xenvif_idx_release() now located outside the loop
> >>
> >> CC: Wei Liu <wei.liu@kernel.org>
> >> CC: Paul Durrant <paul@xen.org>
> >
> > Acked-by: Paul Durrant <paul@xen.org>
> 
> Thanks! I believe this patch can go in independently from the other
> patches in the series. What else is required for this?

This patch didn't Cc the network development list so David Miller
wouldn't be able to pick it up.

Wei.

> 
> --
> Sergey

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200122140512.zxtld5sanohpmgt2%40debian.
