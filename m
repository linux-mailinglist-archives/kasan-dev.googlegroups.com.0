Return-Path: <kasan-dev+bncBCN7B3VUS4CRBXV3ROBQMGQEE2CNFFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BECE34E2E6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 10:14:24 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id f26sf9180531qtq.17
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 01:14:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617092063; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wz1BbJunA8RFvO81k0Cj1a11wVde/Q9LzLLwhcKvph8xlcnpt/GHp2EhoE8lGTLgF5
         deCNKuuDkuw/UWAH8bs5WQhvBVOm/5EG+3eEQ6NBb40nsazYMx8bAa0fn2r2nWyGLubq
         wGw2Dq3X7cwhAuTcPJwveTJ/sikO8lXeE7cn0gmMC4HW6X0hOPl0wUDGaVH5C/CNORX9
         1cqOy1rVwluVY0N69R5uCYRZnHtu2rAJIIfQ7nhzzxLCJsr0hArSdzjWO8tQUfNOuj2c
         FwwjqfWbSwkn4rj1y44AKCfQoWPew94iLhZ+qgNMv7fu0mDS2t/Q+s4glPItdPWNYMJd
         A6Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=o5l8V4RtiLmCYNWIfFi3Dx25Nd4q3s7MxHF/FxkdzHo=;
        b=KT0H71ixeRtRsD5bXZfxBBNHyAbTVS/opACcZHmkgKqHA0HxO53tlurEHSzQCpCQbe
         RgsWueWTFQSE8MiMttHYXjJ02txQeYkvqOax/d6BRcenEKkgddpZApQbEJZgYlhMkYk4
         Q4M5YumaHouywXBEQjcRsWdLcNQydAvBK8kGERb2uykNOwtdw1Vv7mNg3HE9ljRN6SYe
         W92bRicdtehWShwMxwW+MBCG5jITddvz8TkJc6JC2L/l/y5Y/at9PUmNZgtElOYA3ai2
         wSHLVvGrAtSkpCCgWqmlLUECY3saC9fvXxYziVrdB+3luzr+FVj1VyD5O9jG067FkD23
         d8ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o5l8V4RtiLmCYNWIfFi3Dx25Nd4q3s7MxHF/FxkdzHo=;
        b=VboCt9yRC8OzAfJawNxD8n6T73/NkY32FFfRVSgQK2y9LZoL370DBYM29Y1qd+AcgV
         rCaMMPLrLtGukpoWSygscapVX5KojRKYZF+AuDufiJX4B7xGb4m4ikiENqbd0JMuN+cc
         tF9D+45n++z0/Ga1WdQRGOkYLgqNopgcQNsViallbICCQXZCC5ywNHF2lyLQ0IBiROFI
         AyXbsWA6mbCn0atbnu07cLxw9c1VICWw0EnJUngiyBPUhQmCLS312oN6RKRS/IwCutDE
         S+da09uY3RRUGvFDdxasRAA/NGpMpwhA6f6T0SZ+VR6SfC+6lOkToLcl3zEQEfnMmnN+
         QLkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o5l8V4RtiLmCYNWIfFi3Dx25Nd4q3s7MxHF/FxkdzHo=;
        b=EVFgIgOPbMnXxNzsxofuzIbZaMvwUA5W9BV3raBKUmdX1M3o6aFLTmaD7fQCXQc+xd
         chjGdb1AZ7tHfEuNYAo6drjVDzaZ1cC8JN7tdfDIOtdaeqO58Scg36gctr9LrA7ZU84+
         8bcd2DH0kRNkAt3KDswL5n7DdUqGr7Tg7pr6g/kfxRuWLbDpfRpIGh7Y4iSlY5DzZtV4
         RMGF5ruweVr9lG+BYojVAuzsPzd4XgUDTK3j6TSj+WrxAfwhl0Bl0EFjdMhM9kKawbpX
         iNVtJclbWC1IwXQcO0BI7HDIMT1lw102014YuQw9u6XoCoMGuUzO8ATgU8+ufBha24ea
         WPiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530D7AFq1szY7R+aVn0I+b8KNuOKz2TOenV9JtfTgYmbVlXfBkPU
	JIENA1j9Ak6DU1JJgCRRq84=
X-Google-Smtp-Source: ABdhPJxkSlEMjodKlHaanbu6ijtcR4doySH9yHmn3n4Zv6nD1d9PxVyyiY0Mxb/oEqw8X/JP00oSqA==
X-Received: by 2002:a0c:ff48:: with SMTP id y8mr29462874qvt.8.1617092062892;
        Tue, 30 Mar 2021 01:14:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5810:: with SMTP id g16ls7042932qtg.11.gmail; Tue, 30
 Mar 2021 01:14:22 -0700 (PDT)
X-Received: by 2002:a05:622a:110e:: with SMTP id e14mr26643780qty.335.1617092062471;
        Tue, 30 Mar 2021 01:14:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617092062; cv=none;
        d=google.com; s=arc-20160816;
        b=HyI12NuAdRrIb0SL17Tp07krUkdM+r6rhhrvoNJOywiy4EqOccXsiQ8Is68LRKj91n
         hP5QHLAtVTCVT3eGHCOrseEqI0nMD4YkbFQqNenSRPDYJ+HTIvEbC0BuhvwbRiiGanyD
         JKt7p0vqX30Sl9wIzq4N0ybxjo6aPkBTiwxWI0Q3+lgTcUFpHPVdbhOs1N5eZ0K47VlX
         tiiGRy8zOOarFhkkFsv8wF8H233WKj3e74IJmQiz/3eewTuhyR1IgvDtd7pS3AGzeSfP
         ymnlBwh96TQLzas4Fl8b/GejL97Fhwc6DcYX0WfRbHEmdf+sASVc2b44lE2nTCDYs7AR
         xo1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=lnFMp/+Cwu3CoBbhB8f4VE+VpVnYB2pSI0tnOqPNBXw=;
        b=Ubae1kGyQo/DzZAolF6+A/99T/kMU6uLCAMJ/zm5IQfdEvqiMEeIlQSuR/iSCo0cCH
         aXi1uofRmx4nj4zr98Rn/kRvBenmHNbfLuf8DOxT3lsAaqjQqXb026qym/6SMqtUGM6K
         sZYy1imPrQqT0CEoZ0BrScW91PbVxAj/YyXnYW1Y/CYvAzGG71sQcj+7QV3yl5W6PeQs
         rshbuboiGBDNdetCOmNGzrGTqrGwZ3OEJeEmLSzn2ImIuW/1kwJJF8TuibzC5TbrHhM8
         BpGYE3UAGfFi0oDfZZsB5ftxgOizY1yeIskkEo57ZZogaqjVeNRa6oZX27ENko2Em8Wp
         inNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id r24si1231060qtp.1.2021.03.30.01.14.21
        for <kasan-dev@googlegroups.com>;
        Tue, 30 Mar 2021 01:14:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 30b0eb7514ec41389a1557a0acfc5cc1-20210330
X-UUID: 30b0eb7514ec41389a1557a0acfc5cc1-20210330
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1259450712; Tue, 30 Mar 2021 16:14:18 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs05n1.mediatek.inc (172.21.101.15) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 30 Mar 2021 16:14:17 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 30 Mar 2021 16:14:17 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <will@kernel.org>
CC: <akpm@linux-foundation.org>, <andreyknvl@gmail.com>,
	<catalin.marinas@arm.com>, <dvyukov@google.com>, <glider@google.com>,
	<gustavoars@kernel.org>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux@roeck-us.net>, <maz@kernel.org>,
	<rppt@kernel.org>, <ryabinin.a.a@gmail.com>, <tyhicks@linux.microsoft.com>,
	<yj.chiang@mediatek.com>, <lecopzer@gmail.com>
Subject: Re: [PATCH v4 5/5] arm64: Kconfig: select KASAN_VMALLOC if KANSAN_GENERIC is enabled
Date: Tue, 30 Mar 2021 16:14:17 +0800
Message-ID: <20210330081417.22011-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210329125449.GA3805@willie-the-truck>
References: <20210329125449.GA3805@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
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

> On Wed, Mar 24, 2021 at 12:05:22PM +0800, Lecopzer Chen wrote:
> > Before this patch, someone who wants to use VMAP_STACK when
> > KASAN_GENERIC enabled must explicitly select KASAN_VMALLOC.
> > 
> > From Will's suggestion [1]:
> >   > I would _really_ like to move to VMAP stack unconditionally, and
> >   > that would effectively force KASAN_VMALLOC to be set if KASAN is in use
> > 
> > Because VMAP_STACK now depends on either HW_TAGS or KASAN_VMALLOC if
> > KASAN enabled, in order to make VMAP_STACK selected unconditionally,
> > we bind KANSAN_GENERIC and KASAN_VMALLOC together.
> > 
> > Note that SW_TAGS supports neither VMAP_STACK nor KASAN_VMALLOC now,
> > so this is the first step to make VMAP_STACK selected unconditionally.
> 
> Do you know if anybody is working on this? It's really unfortunate that
> we can't move exclusively to VMAP_STACK just because of SW_TAGS KASAN.
> 
> That said, what is there to do? As things stand, won't kernel stack
> addresses end up using KASAN_TAG_KERNEL?


Hi Andrey,

Do you or any KASAN developers have already had any plan for this?



thanks,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330081417.22011-1-lecopzer.chen%40mediatek.com.
