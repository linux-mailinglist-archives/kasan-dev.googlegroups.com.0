Return-Path: <kasan-dev+bncBAABB4MO23UQKGQEJEWTAGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id BBFC56FD0C
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2019 11:52:50 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id d9sf33033986qko.8
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2019 02:52:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563789170; cv=pass;
        d=google.com; s=arc-20160816;
        b=noVpVSwyHhG0iqny1Zhzfy2zzPrsvhuqS4aKr16ZOqVXoQ2XtukwSa/ubVRaXWOZvi
         s08acM1Lpc9ZlPwebNt4q99BTzn70wMAq03zifpGH9HzUA29RPUkVosieOJpvb6QKGhZ
         7v2W41aNJUQfpiEMmLfUCTUtHWRA4fac6o9/gj2XEmrj7LNEh1irJN34+N7075f1ouNg
         i/E2zTPMmqI6ze1BfPDqGMJxeM3Mf/Pmat/PYob8q7jzkmq3puFSF05650Cb5f/Badh0
         j6P3837/6E3ziaYNCZkfHM85HYu0p2X2Bkf4vFQ7oFcvwdVuWDe2vbaH3NVpz5x/yBaR
         sL+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=hSINPr+hUUSb9PztM0hNuOrpTuZOGOC+NJAG2MQgC+0=;
        b=DvYcnm9O09TCRPly/BRiA4LB1Whao7eTdlQpN8ebVLGn/jYZwVL2cWP3br6Uw0AAXm
         CgdizDzrHRqLxLzTw5wNZjyCzUh4sk4ggwHkfONgRXJULGOoVPwnpdkyAYF2Pxy4yNkn
         9Bb2M68TMMK6qCYK81sqeop/Dy1XfZOjh+vAZmpy/Vysy1tSvcv/NccW1kMxdPkwo4XP
         znYOv8/xY9B7cgV2Vf4k8SBhjQ398BamwtlJtM5Opi5WSacfFATj4P9B+YJPFFaV2qFP
         ZFA3q0IJoAZAniSIZEwBJRomJYa38+uKI0ZIOTEUNDW0ipZV1H47B0jK/8v47TCKtmmA
         xlQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hSINPr+hUUSb9PztM0hNuOrpTuZOGOC+NJAG2MQgC+0=;
        b=YKxlIBGwJhH67P5IxFKUhqg4Ev1Ij055KxnwiKCC8kb1VeL0ilVrxZsdelnw9nZYtW
         pY1vpuBq6f7GsqdcZp+pBgQmbjsjz7FvTdViGmOspyRblNr41Lt/8Vl2JVZ0UBJf/T6L
         +NUBVnG90T1V358ji52xjBs2cK4HsibM+n5rPjOhXW0ZxXjTaoVbDkUwcvoOEKncG55b
         gQHke1WwrEiURxXCCkwB0MnrjpGpa2Fw2cR6k0ZruPJLFajM+wuB5IEDqq00NlWK44RU
         bBzT780OmXDhq7VPhJwqWRYzmKGME2sVj7JZMMpUgDyHAm+s0CPqcAtKLSD+8SK1oFgB
         o1IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hSINPr+hUUSb9PztM0hNuOrpTuZOGOC+NJAG2MQgC+0=;
        b=tDThQsNqCdThUKAZNV5mh1BR1gVuK6QCtWnXYqC0ek69n7Ih2TIYL5bJlxJkrMbI34
         QOy3X/KugjiEfWDPKfzNChzF74aHKfluzv2ucIazuj/Ftb8iXISGk5jSDXJFs6APnpjn
         zhYyqqN//SZ7SSLKdHLpdOWA/nG611IHKdoIyKbE1xPIne+Y5orsk38/MPKGgwmf5Kz1
         rcnASfEKNFq4vZfGTyDkpzWN+18HOkfyE8r6mlGg8UTqykT90LetlNeLXzsn+CCfafmZ
         h8bLHJhN7BWVFtRGYqNDko/2NigE7CtO6J6o/DXdB4e2WJyZMqGA6adGX3FAy0aUZnrP
         QHlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW3HaeOo56TinV2BE0gCuOimgtuiWSTccyiEFbAeucLHCVrirR0
	oC7Z4wcPq/FlEv3kIyB6aME=
X-Google-Smtp-Source: APXvYqwD92uNj6HOYsMbozxICTJJ5dJSPU/t2eHpk0QYVRb5uYVKOC0MaS3iCjfhe33Y3dYqF5JXYg==
X-Received: by 2002:ae9:eb4e:: with SMTP id b75mr44864506qkg.478.1563789169900;
        Mon, 22 Jul 2019 02:52:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:d203:: with SMTP id f3ls2815969qkj.10.gmail; Mon, 22 Jul
 2019 02:52:49 -0700 (PDT)
X-Received: by 2002:ae9:f017:: with SMTP id l23mr46032689qkg.457.1563789169701;
        Mon, 22 Jul 2019 02:52:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563789169; cv=none;
        d=google.com; s=arc-20160816;
        b=FsU1kNsFsjBF+XFcoI/e11uV3Emc26nYNJd+yJez+S/dATGLgQyiHG1kxrHYmOABbo
         Vq2slUZWcOhhpxT5Rs1uFRrKgZ3Jti8GU/2JGfE/kE1PDLyn5pVpR8TdRe9vv/V+rsyp
         T/7fv+j/HGud/4GBx6lUWCV6mXaWEYIFSyfInPdVeRZ3lncjNlm/3dNnjOWroRAJJ61c
         E654lzz4/qDW4RI38C0++/adKiyJNkMtAjAOop0w3q6Ri+2Iu8zy2BVL5CpEhlTMB6mD
         F8lEp0NbL36AgSZiIBXrOHcTl6BVo8hPMlsxs8UV8FWr2i4fqepNwjTXN7CvERefHoLj
         pt5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=+9Hah1o88uTNtSe4/7uYaciyMFH0liersSRqkZ9QIvs=;
        b=tO2cJi4OekTYLNiqlNnJzKLWux9pvcR/2z/bQ8W8GqztTLhIiL7RnXSexqxyjdJsMm
         2StrJnCWU1e2W5sq+rHUJa5k/igZZRu3ChVXilp9F6WTCefWRNYT//tM/Jf0xi8dtLBZ
         +NIdOjIRaJhCqxbJLqLhDiBi27FJN0IFGfORh5GhKfHQ8HbnEhq7CxdhHGGM63kHoQ/4
         ne5NulsBy32OLRpCY3oRfUOBx7K3ELu7ecVCC8ttlv3ebIyNn8j7g2p/MGxC6VMweyZ3
         fYZVrA1+QltZ1GQZlKa3hIH5SJC5SG6f4w4weA1+I0xjTwIUh59J093AFQHb7A+zCxRG
         lUSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id 34si1825406qtz.2.2019.07.22.02.52.48
        for <kasan-dev@googlegroups.com>;
        Mon, 22 Jul 2019 02:52:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4416e42ecd35467192de92f81e192f6f-20190722
X-UUID: 4416e42ecd35467192de92f81e192f6f-20190722
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1042474360; Mon, 22 Jul 2019 17:52:43 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 22 Jul 2019 17:52:42 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 22 Jul 2019 17:52:42 +0800
Message-ID: <1563789162.31223.3.camel@mtksdccf07>
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
Date: Mon, 22 Jul 2019 17:52:42 +0800
In-Reply-To: <9ab1871a-2605-ab34-3fd3-4b44a0e17ab7@virtuozzo.com>
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
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
Content-Transfer-Encoding: quoted-printable
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

On Thu, 2019-07-18 at 19:11 +0300, Andrey Ryabinin wrote:
>=20
> On 7/15/19 6:06 AM, Walter Wu wrote:
> > On Fri, 2019-07-12 at 13:52 +0300, Andrey Ryabinin wrote:
> >>
> >> On 7/11/19 1:06 PM, Walter Wu wrote:
> >>> On Wed, 2019-07-10 at 21:24 +0300, Andrey Ryabinin wrote:
> >>>>
> >>>> On 7/9/19 5:53 AM, Walter Wu wrote:
> >>>>> On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
> >>>>>>
> >>>>>> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
> >>>>>>> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.=
com> wrote:
> >>>>
> >>>>>>>
> >>>>>>> Sorry for delays. I am overwhelm by some urgent work. I afraid to
> >>>>>>> promise any dates because the next week I am on a conference, the=
n
> >>>>>>> again a backlog and an intern starting...
> >>>>>>>
> >>>>>>> Andrey, do you still have concerns re this patch? This change all=
ows
> >>>>>>> to print the free stack.
> >>>>>>
> >>>>>> I 'm not sure that quarantine is a best way to do that. Quarantine=
 is made to delay freeing, but we don't that here.
> >>>>>> If we want to remember more free stacks wouldn't be easier simply =
to remember more stacks in object itself?
> >>>>>> Same for previously used tags for better use-after-free identifica=
tion.
> >>>>>>
> >>>>>
> >>>>> Hi Andrey,
> >>>>>
> >>>>> We ever tried to use object itself to determine use-after-free
> >>>>> identification, but tag-based KASAN immediately released the pointe=
r
> >>>>> after call kfree(), the original object will be used by another
> >>>>> pointer, if we use object itself to determine use-after-free issue,=
 then
> >>>>> it has many false negative cases. so we create a lite quarantine(ri=
ng
> >>>>> buffers) to record recent free stacks in order to avoid those false
> >>>>> negative situations.
> >>>>
> >>>> I'm telling that *more* than one free stack and also tags per object=
 can be stored.
> >>>> If object reused we would still have information about n-last usages=
 of the object.
> >>>> It seems like much easier and more efficient solution than patch you=
 proposing.
> >>>>
> >>> To make the object reused, we must ensure that no other pointers uses=
 it
> >>> after kfree() release the pointer.
> >>> Scenario:
> >>> 1). The object reused information is valid when no another pointer us=
es
> >>> it.
> >>> 2). The object reused information is invalid when another pointer use=
s
> >>> it.
> >>> Do you mean that the object reused is scenario 1) ?
> >>> If yes, maybe we can change the calling quarantine_put() location. It
> >>> will be fully use that quarantine, but at scenario 2) it looks like t=
o
> >>> need this patch.
> >>> If no, maybe i miss your meaning, would you tell me how to use invali=
d
> >>> object information? or?
> >>>
> >>
> >>
> >> KASAN keeps information about object with the object, right after payl=
oad in the kasan_alloc_meta struct.
> >> This information is always valid as long as slab page allocated. Curre=
ntly it keeps only one last free stacktrace.
> >> It could be extended to record more free stacktraces and also record p=
reviously used tags which will allow you
> >> to identify use-after-free and extract right free stacktrace.
> >=20
> > Thanks for your explanation.
> >=20
> > For extend slub object, if one record is 9B (sizeof(u8)+ sizeof(struct
> > kasan_track)) and add five records into slub object, every slub object
> > may add 45B usage after the system runs longer.=20
> > Slub object number is easy more than 1,000,000(maybe it may be more
> > bigger), then the extending object memory usage should be 45MB, and
> > unfortunately it is no limit. The memory usage is more bigger than our
> > patch.
>=20
> No, it's not necessarily more.
> And there are other aspects to consider such as performance, how simple r=
eliable the code is.
>=20
> >=20
> > We hope tag-based KASAN advantage is smaller memory usage. If it=E2=80=
=99s
> > possible, we should spend less memory in order to identify
> > use-after-free. Would you accept our patch after fine tune it?
>=20
> Sure, if you manage to fix issues and demonstrate that performance penalt=
y of your
> patch is close to zero.


I remember that there are already the lists which you concern. Maybe we
can try to solve those problems one by one.

1. deadlock issue? cause by kmalloc() after kfree()?
2. decrease allocation fail, to modify GFP_NOWAIT flag to GFP_KERNEL?
3. check whether slim 48 bytes (sizeof (qlist_object) +
sizeof(kasan_alloc_meta)) and additional unique stacktrace in
stackdepot?
4. duplicate struct 'kasan_track' information in two different places

Would you have any other concern? or?




--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1563789162.31223.3.camel%40mtksdccf07.
