Return-Path: <kasan-dev+bncBAABBX5VSLWQKGQEYQ4NMZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id A15A0D66A4
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 17:57:20 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id b143sf17358397qkg.9
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 08:57:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571068639; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mcl++fYyE4BF08E24siC+NnvlIIcEJb54phyfwcpmJw4kCeWVII98wU3LyGBVTKSe2
         m2X5Oqckga1yOjRXzIwnz8dkgzH1sUV0ljVEZi80x30lAyEsRcFeqHdwxGI1JZy/5J3d
         KCCssfusm74oQOXiMJDr9XziMUGBG5JAm8tqVZpFbat+ApbF1QBpiOwf+A+XPE5ov6Jl
         sKEXs8zIAoOg31OIjbGF4BGAhzBJ0o10Bzf/q38uOZTZgwJmLfeft0Q2m6/5m5TUc5tQ
         KzSP2agv49XfsbiEZ0NqW9YSuJhdz8+prA/X9so0nSyqNg7ruTOzALcmkbyFNIUCX+sy
         TAQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=MxU8uTLaXiLLwXkcDw2nUyCVfh56R+L8mMJIWnGi3xM=;
        b=O+w13Hp2p13I6DscU2dlXkEN+PyHumroSYnxhDkX0AjGpvkqqMj7nQLIEfTteXDVNg
         WUpWnZSQpAuTfn5P8PIB+QhZS7CK9LcCxABkA51JyMgd0EDuUcMei8Ym1tR7YW01GD5M
         jwIfFI2lHq8chIJRYlqq8ET3W0d6m7VvmTrtJoV2MGXS7qb+1IKRAruuee+MPY0ohjbJ
         89XZVaKDxoABtjLrZp5gRuuw02rkbpJ8WS2pmd/NIuIeLZeVmkBx4eOMv4Dqz6aJw0mZ
         2lkE6SeZ5IECeqpL027QjRI9xptKk4AFOi6oxk86lQU9MCBpgtBRaZVwKuKp6HO/1Xvi
         j7Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MxU8uTLaXiLLwXkcDw2nUyCVfh56R+L8mMJIWnGi3xM=;
        b=M4vu9Bp8NnhzuMObC5hET8NPj6Brph9gTnKspIi6lUGaSn14hldCYY48P34TqBZtgr
         iNfJgffiRkBwqOcqK82MfbogPk70Ugq1+ZcSephnfiqhsxcjMwDzWQf5a20hlbk7Q+qE
         LwwuKDy56g1ClRs4CPrpUjzKMEjFO4wFKtXpkweIm+tDNpat4G/m+qQMRgJV7+Itt/FE
         Wn4DYaCBlpW9tb1dOo6QawMHB89KhFju+KspAKWHRk98eGf45BFVsGNPfbWZqaY0sGLv
         T88m84Jv1hBXa9QLSWQxicctyktT1sD4Y+ANFyNnsHf2HXNMca4N0ahryVaI7uhYtW5F
         6WRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MxU8uTLaXiLLwXkcDw2nUyCVfh56R+L8mMJIWnGi3xM=;
        b=LBwT4jK0c8zTu0SHs53j2/UwiZ82vF1JiP75wM5/uLhr7lpUgnL3lTtdvUybzBk6Ml
         tXqMr04mPXFgrLuZFuFVYk00aKXyjWt5QuQEdOYdfI910RoPQgzrS579hIiHvPlnoGLY
         kzyOaf47cG38iCwhLrndpznHoPCjDpta8peUhR8G4lkoL84fM1mhvwqVNEB6pBmseDyF
         b82PsiUhBL/8wfX1+79RavovzASln/UIYhyzCnAyMzukBLcbiY1VrxTnAPBuxplIdi1L
         MkaY+5byEllI9xdveNPzrjezZA58QHnsAolDOjJdrjpwzVUOufVE9R4SY+OR9xij2Kr1
         cPuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXWWt42ABAb5pbiO8+QZyHI+neurmyAaEWCzCWQ+wE8/5v95dke
	dDQZBCjWjmQHdyVwJ7gJDWs=
X-Google-Smtp-Source: APXvYqxU6dgG0gJlMKeiHa/QpBFyyNiYMPuGoz9lmdt1RGAu/sal+br0V2msEz/SqwoTfoLJS4mumQ==
X-Received: by 2002:a05:620a:552:: with SMTP id o18mr29663475qko.295.1571068639400;
        Mon, 14 Oct 2019 08:57:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:d92:: with SMTP id 140ls4398520qkn.13.gmail; Mon, 14 Oct
 2019 08:57:19 -0700 (PDT)
X-Received: by 2002:a37:a8c8:: with SMTP id r191mr30878999qke.12.1571068639090;
        Mon, 14 Oct 2019 08:57:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571068639; cv=none;
        d=google.com; s=arc-20160816;
        b=oB8zSqv+fEw7mpSu7NOaH+g+diUu14xPbgYiL0Fwia1IeicUxZ+0YNR+keQEM+NDib
         VUxz3MuWQU5c63KjPSJvO21Uve1cgu+VvG28we1ng1hrKbWgzcMhGbl++AS268mmgx9N
         JKRPH3xW+cjAGkRoVh2XG7nbjqWdFfJHPQvaUU1xaZsONDYTcBoLfYttxZqgwllwQMwX
         z1t6erpcOZA7wHjBuv10jQZSX6iNBNTDFUvT2AGC/ZNiNc7VsHkhOyhrdj9poVTRfNYW
         ZejQD4P+l3P92UEp9AQ4Cu+SKpa+dbe4Q+i5FBHeylDNFMMyEmVJIBITLaawGSJKVXKQ
         tIkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=y5ZlhoGEJVPYV8UeyWosgrzvDj1Ro60Iqic0DilBEO0=;
        b=WcSZ/DaxAfVuFjrFNOQD5p70KK2HMTBLZ6HfKCovpFX8XxiWdPnkqEX2Sreo7H4Qwt
         K+PxtjI34k6ySfDx8jg/V+GsiIrO8O9C0jL/dNM0+kPbwo2NNLeeONEKYJsnrRLs1mFk
         4cTzUcAGAhhlOpfuWV2KNI4o5OUW9upIs8klSnKJ0ihcDRZ8zbB/A/ydV8B6ww9tZTjM
         BosirNTRrADjqxlXSziw31eXxt1MYogv6BVkLrYFx2Oj8AcNF70VkRqT0qb4wKBvc50X
         mDlckzPInyq+RWGAHFhuDP/sWhrabHTG0ayC2gpeFs7asto/8vlHNfU7R6MfNlj4N2uN
         +cLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l4si768496qtl.1.2019.10.14.08.57.18
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 08:57:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 82e2e07d42c8401c9fe66a906d53cd58-20191014
X-UUID: 82e2e07d42c8401c9fe66a906d53cd58-20191014
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1492891351; Mon, 14 Oct 2019 23:57:12 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 14 Oct 2019 23:57:10 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 14 Oct 2019 23:57:08 +0800
Message-ID: <1571068631.8898.8.camel@mtksdccf07>
Subject: Re: [PATCH 2/2] kasan: add test for invalid size in memmove
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Matthew Wilcox <willy@infradead.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Mon, 14 Oct 2019 23:57:11 +0800
In-Reply-To: <20191014150710.GY32665@bombadil.infradead.org>
References: <20191014103654.17982-1-walter-zh.wu@mediatek.com>
	 <20191014150710.GY32665@bombadil.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

On Mon, 2019-10-14 at 08:07 -0700, Matthew Wilcox wrote:
> On Mon, Oct 14, 2019 at 06:36:54PM +0800, Walter Wu wrote:
> > Test size is negative numbers in memmove in order to verify
> > whether it correctly get KASAN report.
> 
> You're not testing negative numbers, though.  memmove() takes an unsigned
> type, so you're testing a very large number.
> 
Casting negative numbers to size_t would indeed turn up as a "large"
size_t and its value will be larger than ULONG_MAX/2. We mainly want to
express this case. Maybe we can add some descriptions. Thanks for your
reminder.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1571068631.8898.8.camel%40mtksdccf07.
