Return-Path: <kasan-dev+bncBAABBYP35PUQKGQEPMJWBQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B6F57672B
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 15:19:31 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id p20sf40145871yba.17
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 06:19:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564147170; cv=pass;
        d=google.com; s=arc-20160816;
        b=ebIBQ4v7c0LwffjBupImrqjcWuwY8qfm1cFiBfItBiJS6CgxORK59QMQbNAAsI6ctv
         Z84aI06c+u3nWwf3TN5EJ+8anj4/qgzEJgkl9q3zHk14Ak48EXPshkRJHJvjhD81NRkx
         FE9XU7In0fu6bmCM3K0ALNXDQ8hMXfOtjn9j6oaNF6fBMF6Ybm0JXjLagHd3Rz1ZWdFd
         j1fIzBeaihX6dlPaGFlo6ETv5qBtzK+ZRsZT185lnC6oADHPydUcxDs4OGzCCdOXC1n8
         T3P5hLybqI5UzGNQTpMf33lKbQaLMgTSaZ6BOgUvKc79UCv0ECpTn8NiBJvZq4TVENX1
         SigQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=rmCezVRpExOrvD5UH3NKZtkmr4WwEpLvVOk64QfgI1I=;
        b=0fbm/hCXOjBeb+HeaTcsFKGCrLFDURyTqCzz5235gVwoA7OebC8Lav05Y1E86SDhDX
         bIgqMO+OWzDy4m5TYFZjUO6Iu04h7WouQjchpQV662Xt6zDFAqEr1a5HlB/plwBp3Nys
         2t5F+eAfwAAu3K26QZMAk4vik4/GoqEETecGwXdGSesugfvRIzNlHnRrnZO73bNThFOb
         Zlj4KYfZ27Ql3VDcY+keKsWXB3JGh3UEpKHQTCNOSYuUH5C87bCBzbkzVLPWw1XyQ5Yh
         Ye8WzVb1CwNE0/S94A7fov6yLuaebxgTsNaDCp6xlZs8qQxz1BoGbjoe3HNzIcNzWUxP
         KOug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rmCezVRpExOrvD5UH3NKZtkmr4WwEpLvVOk64QfgI1I=;
        b=XSS+dMiIb0e1oK2FbcGS9EZlVw+7LRTcSN8/jmKlw5Cw1ayGKjkh61GIWlut5hOnIF
         wxiG7lmbqvRm6IjolkloKpvqGemo2Au7tLtDmdN0XXBV9Jf0CGXhaF+AiZSg5SXs/IeE
         VmcC8jLelDG/VAVFpQxGxBAh8zoUMXtWVTijEKs/8X4+hYcIoldkbYDr+VY/L32jlFy7
         uNIaUjHugY9Y56Q0NraUL+KjB6vz9wUCzCiQjKjQJ8WpLuC1QA0k4B0fi3nZMyDYxp1Z
         Ubjze0kx9EzAVxMNuUWMSneYcz/eDMQuGFbrqAwamwbQe6mxe1YEC0t3SM+ipYYPhQW9
         I9gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rmCezVRpExOrvD5UH3NKZtkmr4WwEpLvVOk64QfgI1I=;
        b=AMYaUmzJ1iSQHgerEY1usfNY925Pv5bMBXr/Rfm4210TPps3Os4CyD5sTLo63iURTW
         rjZ7fAafyyEwwMh6rudVoqgg5l77OzBzv+cbD6CgobZSLe9XDG2nZ6gchhZ8orVMfDkv
         eexI4Dvwq4nLZAZj1dwdy3Tpa1rVPVYv85YYH27L3oUh88glyDLhEjrAYnlh7ItRRbXA
         67hpo5AnYeGEmIB/yNl7zHVd4fCPpONh/CuJVXGwJyBjdIWGyVfpbiXEaVMC3ChYc1Nw
         B3ysSLywouu2YLGjwgbWt3WCJsPY69wFcZJ4Rp4c/MgSN2Y1LyWPVWn3t3rrEqkZIWQP
         j+1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW5gMi+gAi6OQ1SUhlKfvMAIOqYZAE5QD9U/gg+ZTuNu2Iiq5ya
	EXD1s+UTa3atfOsdB6gbg0I=
X-Google-Smtp-Source: APXvYqyhrrrgjOJLZ+b+OMQFkKBnPBfsNY2UXpkRsHP5Zu1Zj6uO/zcMawYgXMvp/j4V4XhQX+7J1A==
X-Received: by 2002:a25:d15:: with SMTP id 21mr49605082ybn.506.1564147169981;
        Fri, 26 Jul 2019 06:19:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e684:: with SMTP id p126ls7228183ywe.12.gmail; Fri, 26
 Jul 2019 06:19:29 -0700 (PDT)
X-Received: by 2002:a81:7805:: with SMTP id t5mr60417198ywc.312.1564147169667;
        Fri, 26 Jul 2019 06:19:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564147169; cv=none;
        d=google.com; s=arc-20160816;
        b=VXFgCOvzGOD91UuBxk/m2FId28fEv8h1ZzSSAtH/aRKPNZ/mXcRIEc7TAAue0cygxo
         4xvDpiX2G11iDW4/IUIiq4mLO4Av61ixMey8UxDx47V+1cqNnqgIL2V6eEb7qGsHAzLX
         TcnImCkVvunZecqZaG8+D4Zci41R05vo1cMpMY0+5MHF4qKm7b6GRnqA7HpS21yoXKW1
         ohXXpsjShjWH0gTo15NXtjoeOCnJLpuicsqIeeT2Vyp2OdGSG7uqVIiw+dAmpqaDQLMB
         RRIMYzKAuVjuhM7TgZOmAJo0a5u9tMyqmRT5ovdiEwTehVYvBdbChTn7pDajLrTtmcS0
         fBHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=Dk4vQtmJTJwidyR9ji2Z1X/x/ODb/8xrAJ4pYnp3tso=;
        b=Uv6hQZ6x8p65RS9kCFS8ePCPlT6/9GglMBptBG1jBpACZ+M9cNAMAbr+z4oKwZJokS
         xLQiKiH8PHG83KzGwpoGMwmXfmi1KFna4Udqd9VsWf6/LqA6yWd8saXH7TzDnkyK3uL6
         Np/bCSbKWap6ZxkqiOozbwyakNi1X0fXw8FvSGApy607cgk7Mjc+7Teht/ssGHthS8ay
         SyxhC0Ux2xBTPInw07FgDJBOWa/9lsKTCUO+nXH0lbFpjMdIs94ux/Ci+sWZMq/hX1Fz
         ZYMyJtcJFTNiaP4aAn788BNdmm0QQqCCMpWKTHqlhJaLxiMyel3XCAx+Z/Z/wfDbvD7J
         ROow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id r15si1616640ybc.3.2019.07.26.06.19.28
        for <kasan-dev@googlegroups.com>;
        Fri, 26 Jul 2019 06:19:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0811d90d0f9943609049e07c27e9d03e-20190726
X-UUID: 0811d90d0f9943609049e07c27e9d03e-20190726
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0707 with TLS)
	with ESMTP id 1211687384; Fri, 26 Jul 2019 21:19:23 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 26 Jul 2019 21:19:24 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 26 Jul 2019 21:19:24 +0800
Message-ID: <1564147164.515.10.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko
	<glider@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>,
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Fri, 26 Jul 2019 21:19:24 +0800
In-Reply-To: <71df2bd5-7bc8-2c82-ee31-3f68c3b6296d@virtuozzo.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
	 <1560447999.15814.15.camel@mtksdccf07>
	 <1560479520.15814.34.camel@mtksdccf07>
	 <1560744017.15814.49.camel@mtksdccf07>
	 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
	 <1560774735.15814.54.camel@mtksdccf07>
	 <1561974995.18866.1.camel@mtksdccf07>
	 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
	 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
	 <1562640832.9077.32.camel@mtksdccf07>
	 <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
	 <1562839579.5846.12.camel@mtksdccf07>
	 <37897fb7-88c1-859a-dfcc-0a5e89a642e0@virtuozzo.com>
	 <1563160001.4793.4.camel@mtksdccf07>
	 <9ab1871a-2605-ab34-3fd3-4b44a0e17ab7@virtuozzo.com>
	 <1563789162.31223.3.camel@mtksdccf07>
	 <e62da62a-2a63-3a1c-faeb-9c5561a5170c@virtuozzo.com>
	 <1564144097.515.3.camel@mtksdccf07>
	 <71df2bd5-7bc8-2c82-ee31-3f68c3b6296d@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Fri, 2019-07-26 at 15:52 +0300, Andrey Ryabinin wrote:
> 
> On 7/26/19 3:28 PM, Walter Wu wrote:
> > On Fri, 2019-07-26 at 15:00 +0300, Andrey Ryabinin wrote:
> >>
> >
> >>>
> >>>
> >>> I remember that there are already the lists which you concern. Maybe we
> >>> can try to solve those problems one by one.
> >>>
> >>> 1. deadlock issue? cause by kmalloc() after kfree()?
> >>
> >> smp_call_on_cpu()
> > 
> >>> 2. decrease allocation fail, to modify GFP_NOWAIT flag to GFP_KERNEL?
> >>
> >> No, this is not gonna work. Ideally we shouldn't have any allocations there.
> >> It's not reliable and it hurts performance.
> >>
> > I dont know this meaning, we need create a qobject and put into
> > quarantine, so may need to call kmem_cache_alloc(), would you agree this
> > action?
> > 
> 
> How is this any different from what you have now?

I originally thought you already agreed the free-list(tag-based
quarantine) after fix those issue. If no allocation there, i think maybe
only move generic quarantine into tag-based kasan, but its memory
consumption is more bigger our patch. what do you think?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1564147164.515.10.camel%40mtksdccf07.
