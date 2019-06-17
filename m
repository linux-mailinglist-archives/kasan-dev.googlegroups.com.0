Return-Path: <kasan-dev+bncBAABBV4QT3UAKGQEOZ3RUCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 46AD648271
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 14:32:25 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id i136sf12013256ywe.23
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 05:32:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560774744; cv=pass;
        d=google.com; s=arc-20160816;
        b=ukXRCFw8hycZ1ktLr4NKbbC+3313nloAKk2Eve62tMmI121hN+V7zjUKrU+Cf1HQ/S
         dzWIAo53TJzQjf6+2tjTD8bBJzc6OMtFYrzQjj2TsbnXsGpSzZzTvqjVjkbtmpB9aA6a
         ZsVyOQDnIWpR19CIPBd9oZGUHKDEIAoCwgc1KaeSWWxa4383Fqh397zewfKAKfxSaZ8V
         fCB33swg9rdwI/i9bJfRv6aWB7xVkkDdosNg4Q/dQLT922g2tZjyOfE3/o9Zp7k+tZX6
         TdyuOdA33m5V+Xfr/XvcHn3UO9C8YgvsmZRdZJiGAAOfX9E6kFRj2Mgeu6C7Vf7JJl06
         c1JA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=xeVI1IYcSiZ19kIiLe9WLnW/HPXOEB9OCgzgWEaiE0Q=;
        b=Weu0boqc22yPpVj+XZsvMdmu81NZPXRqYLpgDhdgo+uOc6LazVQieDV8bOYxe/SKIY
         /TNJPqGxj6ScAD3QYuuIY3BV8IT2CikaBVWeVRTyZZ2o2DvKGZXoFH7jDOuRggCgXn3c
         PC3LMrLWZTarCiMR35zYhfpH5lnlZ1DIDO2xwRWuGtO0djYZzi9bH2e/OCXoIrC6riB5
         0lGofDK/p1VmMd0Y2NIyNDAO22+zibHNimUJQ7WCmYsw3Z7hhdm3OV/I/W2gUCEpI/JA
         Mxg0arjGq+KaQoNwTr0TK3iPXsixVIIa1VUPAg0YL1SFqEOKdA+bBvRQkpgwpHxbs6yy
         Q0jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xeVI1IYcSiZ19kIiLe9WLnW/HPXOEB9OCgzgWEaiE0Q=;
        b=k1fXSJDIla2xz9ajdSxm4iWWWVAzE0mWwCQE/fowHsg5OUwmBseR+hrDAnP5dbhR0I
         lf6Aw3wsobT/40rXM+eGvhOh4DY4oz5h1bR3FWhkc03AhsmhJzbeRQm76BGLoYUSO25l
         vNhRQOc4ajkkr1wUPPm87nEEzGtOkZwu1b3Uj3WCxiNFJzKADT+BIXakQfpV1kIhvk7f
         rh97ZbkRbPB/HTskqt//ywU0HWVc9mRv+AcuMfW3rY+vWCULma8p26EINBBDdypH8Ll3
         LXeJi9ZRr5nAmBI5w3n1cDPgt8Rm1eGCcswDBJfEMat6eJKf2a2OBKm5wDSEi7MkAQEo
         0Rlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xeVI1IYcSiZ19kIiLe9WLnW/HPXOEB9OCgzgWEaiE0Q=;
        b=VzBfnt/bodJKlFoSgjbe4zoqh4gIJpRYfcDzJ0qK1IMFNwUTPCuw9CQSJm1CRKrTk1
         I/d4TSoQ4nmI9/yLapGWp6BuTeMX7wfbPbGBPe79gwLKIaF2fLQn+g3GKvidPzTK8YMr
         sDBmik0Ti87xuayDAhHEAWm/ipnJ9pPASRXVgeiM70QYI55Bi6KAjRmBYT/pkye61JC5
         2Tj/S/trJAqlX05W6kll7+P/WajEKZSwsC8dmZTQep+gh4VEg//jenxdGy/Fk3ybyxQ1
         L0fGb/65DLVT34Eh5TSXx1cyYOXWt/ErQf8U1+++QOFyWnOCs48mfQq3YvIQ/l7/6vU8
         Swig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVR3h0R2py1iqD7kKRa1CfnVtl4D+GEvglG0BGxkX9KbUBhW1AU
	Uf5ovLzOd/aj5vQ6l+2HwFk=
X-Google-Smtp-Source: APXvYqygnfwoRnBGBsUBJ2QwwCkLQ9V6hcoBT8CZhxyMzuqH7L+jerbwEw/t8aHKfzEL8DuaX6DCfA==
X-Received: by 2002:a81:70e:: with SMTP id 14mr14391268ywh.105.1560774744058;
        Mon, 17 Jun 2019 05:32:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2c0b:: with SMTP id s11ls1944249ybs.8.gmail; Mon, 17 Jun
 2019 05:32:23 -0700 (PDT)
X-Received: by 2002:a25:bf83:: with SMTP id l3mr56129273ybk.446.1560774743815;
        Mon, 17 Jun 2019 05:32:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560774743; cv=none;
        d=google.com; s=arc-20160816;
        b=w8DMcewPr9cCs+98fFeIBe9SSrxnU/kcMeVnQ/EUOwUvY7kjWu9V0Ft8VnAfYsLsko
         rHzax1Y0hAGAu04iMnHSfXSsYsbYJn0Ecg0Oy0IFq54SQ/AQ+7+Lo5HIW+1j/LF/cxrA
         zPsk5qOhLQNaCIrObmxAJCWLUpRsVGaFLxmUAoMwMCuYhgxlM3bJcNU+S2sZLyj7IXUy
         xGypzNOFiqnJkE1Xcv1v2qicbcPv8GPk3N6kxd9H0igUAE1iApjI4rrxe/P1V/zXRXNt
         ygevCsGpHeC0f6zDjcSXmAN3Ok9m6bJdsIsU76QbQ6WRGVm5MblRbHMkAWOsTAkTrkc3
         Sn3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=VvSYcK6eQX6u/sd5ArJc1SHarZ4lDgJFax/GOUSk0hY=;
        b=XvrA6+aqQEZkdMg+1HH+9ESA3iaDTPZ8z6Dau34rmyGzYkoYSmjJ0k2kh2FaWT4R5s
         pfpEwQLdPYjDjwFMfJkFOVC1ZaGJ9hZ61sEZga2/BH6IIzKF1B4w2okxSHqBPbgMIDVH
         Zn3OLBjqNhqhHfPplOEytafQCLotVJbWT65x6MHxZ8sFpeN3jb+SL4FZAHowxLHNLyeG
         G9/F3RhIGBtb0SG+gKtZHpirFemX66rbgp4mFQUAqrmATHeScplB/Jd2C/xA0f6lREGN
         LvemsEkBykhKLJHpHgw1Eky1N01OHOl9D9ruO/4hP5fwaPTNyQtpsG3h46JvtPnSRsgZ
         oJIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id e21si611460ybh.4.2019.06.17.05.32.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 05:32:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: f6edc7ac94bd449186c8b83a503b53db-20190617
X-UUID: f6edc7ac94bd449186c8b83a503b53db-20190617
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 904270075; Mon, 17 Jun 2019 20:32:16 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 17 Jun 2019 20:32:14 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 17 Jun 2019 20:32:14 +0800
Message-ID: <1560774735.15814.54.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
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
Date: Mon, 17 Jun 2019 20:32:15 +0800
In-Reply-To: <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
	 <1560447999.15814.15.camel@mtksdccf07>
	 <1560479520.15814.34.camel@mtksdccf07>
	 <1560744017.15814.49.camel@mtksdccf07>
	 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 792F3DD2252100ED132A309A0254155715B3B58D81E671EBE2156836FF5FF2582000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Mon, 2019-06-17 at 13:57 +0200, Dmitry Vyukov wrote:
> On Mon, Jun 17, 2019 at 6:00 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Fri, 2019-06-14 at 10:32 +0800, Walter Wu wrote:
> > > On Fri, 2019-06-14 at 01:46 +0800, Walter Wu wrote:
> > > > On Thu, 2019-06-13 at 15:27 +0300, Andrey Ryabinin wrote:
> > > > >
> > > > > On 6/13/19 11:13 AM, Walter Wu wrote:
> > > > > > This patch adds memory corruption identification at bug report for
> > > > > > software tag-based mode, the report show whether it is "use-after-free"
> > > > > > or "out-of-bound" error instead of "invalid-access" error.This will make
> > > > > > it easier for programmers to see the memory corruption problem.
> > > > > >
> > > > > > Now we extend the quarantine to support both generic and tag-based kasan.
> > > > > > For tag-based kasan, the quarantine stores only freed object information
> > > > > > to check if an object is freed recently. When tag-based kasan reports an
> > > > > > error, we can check if the tagged addr is in the quarantine and make a
> > > > > > good guess if the object is more like "use-after-free" or "out-of-bound".
> > > > > >
> > > > >
> > > > >
> > > > > We already have all the information and don't need the quarantine to make such guess.
> > > > > Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> > > > > otherwise it's use-after-free.
> > > > >
> > > > > In pseudo-code it's something like this:
> > > > >
> > > > > u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
> > > > >
> > > > > if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
> > > > >   // out-of-bounds
> > > > > else
> > > > >   // use-after-free
> > > >
> > > > Thanks your explanation.
> > > > I see, we can use it to decide corruption type.
> > > > But some use-after-free issues, it may not have accurate free-backtrace.
> > > > Unfortunately in that situation, free-backtrace is the most important.
> > > > please see below example
> > > >
> > > > In generic KASAN, it gets accurate free-backrace(ptr1).
> > > > In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
> > > > programmer misjudge, so they may not believe tag-based KASAN.
> > > > So We provide this patch, we hope tag-based KASAN bug report is the same
> > > > accurate with generic KASAN.
> > > >
> > > > ---
> > > >     ptr1 = kmalloc(size, GFP_KERNEL);
> > > >     ptr1_free(ptr1);
> > > >
> > > >     ptr2 = kmalloc(size, GFP_KERNEL);
> > > >     ptr2_free(ptr2);
> > > >
> > > >     ptr1[size] = 'x';  //corruption here
> > > >
> > > >
> > > > static noinline void ptr1_free(char* ptr)
> > > > {
> > > >     kfree(ptr);
> > > > }
> > > > static noinline void ptr2_free(char* ptr)
> > > > {
> > > >     kfree(ptr);
> > > > }
> > > > ---
> > > >
> > > We think of another question about deciding by that shadow of the first
> > > byte.
> > > In tag-based KASAN, it is immediately released after calling kfree(), so
> > > the slub is easy to be used by another pointer, then it will change
> > > shadow memory to the tag of new pointer, it will not be the
> > > KASAN_TAG_INVALID, so there are many false negative cases, especially in
> > > small size allocation.
> > >
> > > Our patch is to solve those problems. so please consider it, thanks.
> > >
> > Hi, Andrey and Dmitry,
> >
> > I am sorry to bother you.
> > Would you tell me what you think about this patch?
> > We want to use tag-based KASAN, so we hope its bug report is clear and
> > correct as generic KASAN.
> >
> > Thanks your review.
> > Walter
> 
> Hi Walter,
> 
> I will probably be busy till the next week. Sorry for delays.

It's ok. Thanks your kindly help.
I hope I can contribute to tag-based KASAN. It is a very important tool
for us.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1560774735.15814.54.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
