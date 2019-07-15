Return-Path: <kasan-dev+bncBAABBSG3V7UQKGQEYQXGPOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 140C668269
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2019 05:06:50 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id a4sf7761487vki.23
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Jul 2019 20:06:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563160009; cv=pass;
        d=google.com; s=arc-20160816;
        b=YvZwzeu1FvlNe1K8FDpW24moXtWmzRac2uxwaZv7FLfvnTkgg+OVac5tgErGTl7LCH
         3ePJjvmUfMQcMilOux4Doahz13qGuLaCDZzRnnviMHy9Ttvo9GPnkVZmwKiGTOscG8sC
         H9wAYD8Ltt4FBXpk8+iHpOlJe/t03Hne610IzwFWa2gk6mATTZznOZYXro+/xuFxX7JF
         69X1oNs4iacrgSytJz7HU0la3Gk4FACckH0k6WOButWMHR5RNaI74LBlPtX2vetMaCAu
         pZM4cBv0LE9MKh7eab72DoosrG691VVGYXqJgitEjoeLzmA9l8LNJ5XyoFTasRcsgpBM
         36Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=PIilH8/oC//JhcfhawI/wKoly0zR9F+9ft/PWlJu+C8=;
        b=TxOyB47kBJG+RS4B2UQbkQ925CPnwD9KoTRT+0I40oEROUc4omGwyGrbZEjn+6x1Bu
         q8JlaDkILOlinQbcfBTMcELZjPWjD6s57J5a49ST8hSvPTnOMAFuu3hE1gTeFMEuT+Xv
         +sO0crwSJccEPHscZBjw7/Ym1FJLtwY6gK5IhuaqOqBSIh1UteMQguX63bMYLFCqt1c3
         5lNduBrqldW8ud96IIHsttx+MwvAKDB1dIEBvsUk1mOfn05M3HzhWRPrMdLTb/vfLBDc
         MMME+Tc+BegueVihAQYCDH0G060Wxtf2P9FlcwqXP3Uyib24/wDLk8HxBERrgR3sdvuE
         ODpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PIilH8/oC//JhcfhawI/wKoly0zR9F+9ft/PWlJu+C8=;
        b=F1ZoGW/Ul5Vc9IV7B/vyTkJ+HTxT7l/er0BzUbUpN5S+gKKiin6Rop8fTJzvZg3XCG
         4PohBVroLVlhm6qvinxfVtR+Hd61A2T1TbQyI5fGAERiV+jt8vFrC7tj858vatwui5P6
         NAAxXz9Biwc/ERThA5DaF/3u/MnkNxE+U6MEhNJ8wTINcM/JuPyQGpZ8uyV4UoHuW4sA
         u5WQh7vFUmD77Mx9Ef4q0fT1eogRwtttS8DuAXDfGZJsvD51e9hfbAQqX0XjslY1uUsL
         mGH/93B9D7qfgwi2/PU3X8xHlV4wUWhsbGX0Dwsx8Nclm8QmN4s2WdlTFKCWXZn49KZW
         DVYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PIilH8/oC//JhcfhawI/wKoly0zR9F+9ft/PWlJu+C8=;
        b=lRdNm+C7ivN9epvOC+AB3249poUfQ3/Ad4QLeAGF4uODwmGQjVQbaAGFrbqrCu/Xja
         52As69943lNkF2FfblHsZo+fQBIEeH/2tlE0yepp2UCWeGRDO551jHxiRH72hZ2RjzRT
         5gAjxY2wuw5niTi1qdzBtS8Byg+SMVNPLGYj38rPXdEUrOrq11lEDRyKdQK2gxyog5bP
         B0dOmeK98FFJhaygNec7UTP3b58AP8uPkygoC1OSUU6nglChWYHgjl0K5nte9lsF925V
         hjVAalGqJLxKTjSZaQOnfGSrvorMww2b0PCuURcRq8OD5Ij1FA8bgWkUWMgIcSxjber0
         fHzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWykBdr4V5IR+ztLgg3kSdoVW9du/J/phqHgSEhuCA3V+WgN/9M
	Fla75t7R8K83aeDC9+r8G/I=
X-Google-Smtp-Source: APXvYqzDSQR5jAMCsFwfI6EQhan7o44XoWPZs0kAOPaRgI0SlRs4g9w8jA2GWhi+2shmsMgWE/KWbw==
X-Received: by 2002:a67:bc15:: with SMTP id t21mr13919263vsn.99.1563160008951;
        Sun, 14 Jul 2019 20:06:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fe99:: with SMTP id b25ls1926261vsr.16.gmail; Sun, 14
 Jul 2019 20:06:48 -0700 (PDT)
X-Received: by 2002:a67:e41a:: with SMTP id d26mr15371072vsf.71.1563160008473;
        Sun, 14 Jul 2019 20:06:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563160008; cv=none;
        d=google.com; s=arc-20160816;
        b=O+YOHS8fawVgQMWtwlWK6a5KMZRJW+9YY/+EkIWEYFW7NEich/8u/KKurEnC1EVjyE
         Dq/E6GnXdK0bkGVf6Le4OJBeA1qiVwWUjuy95KWkGSluAsKKVXwpzNzXhzcKEJH+/eN2
         LoyUWG2ZbjwYBpj6xdYLQLAEBUJKpacJYMVjS+8VIcOYJA7wWPp7gDslhAl7GofteMqt
         T4XHKdwJoyALMJNITW7mSAPlEwo6/khUZshtxWbTrBxQuDwc+Mf/HJuHdhLXD6VfV0Np
         RWqG3dgOa3SKcoQCrKoPFjOX4ZSuXRYMAhi5cZwUwMKp900HVpER20Y8v88FbehAAilu
         mfFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=EjusoFySDJ4oOrd0QsyomBUcAt2tgctPtdTv2+1Q2o4=;
        b=HqgkhYfca4Z1bIuYnsS8R3fGapbyclbWW4xu7TxIIYtgiAgaK95zqwF9mI/BMQSYvI
         4+4qc9ZaEXckwOl25Xy3dzoxPn1fOUd8PcWFH/d+2Zpu6SNI2HV6q5ufnyRKvUIxi0VL
         s3iKmo7wikIo/nrYc9WOzfo20g8+YE7akbjb+4auXHvFyqsZYiBsGYs3Q2Oc1utDs5Ea
         LGq1Du7GXESec1kUu8LJSJA/O7ayb3yOqB88dPAvQxlTezJu+gd9Vof5yJhPBlZSgSsI
         JI645cxOrI1EN9etRrG1QFuWG4wf6PFXE45vOMomEwWla/59r2vq6xDZf8YwmKHJF3k6
         IV7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTPS id 63si917063vkn.0.2019.07.14.20.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Jul 2019 20:06:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: d5814ede6d58453e95a0b6c0fcd31521-20190715
X-UUID: d5814ede6d58453e95a0b6c0fcd31521-20190715
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1205297470; Mon, 15 Jul 2019 11:06:42 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 15 Jul 2019 11:06:41 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 15 Jul 2019 11:06:40 +0800
Message-ID: <1563160001.4793.4.camel@mtksdccf07>
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
Date: Mon, 15 Jul 2019 11:06:41 +0800
In-Reply-To: <37897fb7-88c1-859a-dfcc-0a5e89a642e0@virtuozzo.com>
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
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

On Fri, 2019-07-12 at 13:52 +0300, Andrey Ryabinin wrote:
>=20
> On 7/11/19 1:06 PM, Walter Wu wrote:
> > On Wed, 2019-07-10 at 21:24 +0300, Andrey Ryabinin wrote:
> >>
> >> On 7/9/19 5:53 AM, Walter Wu wrote:
> >>> On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
> >>>>
> >>>> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
> >>>>> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.co=
m> wrote:
> >>
> >>>>>
> >>>>> Sorry for delays. I am overwhelm by some urgent work. I afraid to
> >>>>> promise any dates because the next week I am on a conference, then
> >>>>> again a backlog and an intern starting...
> >>>>>
> >>>>> Andrey, do you still have concerns re this patch? This change allow=
s
> >>>>> to print the free stack.
> >>>>
> >>>> I 'm not sure that quarantine is a best way to do that. Quarantine i=
s made to delay freeing, but we don't that here.
> >>>> If we want to remember more free stacks wouldn't be easier simply to=
 remember more stacks in object itself?
> >>>> Same for previously used tags for better use-after-free identificati=
on.
> >>>>
> >>>
> >>> Hi Andrey,
> >>>
> >>> We ever tried to use object itself to determine use-after-free
> >>> identification, but tag-based KASAN immediately released the pointer
> >>> after call kfree(), the original object will be used by another
> >>> pointer, if we use object itself to determine use-after-free issue, t=
hen
> >>> it has many false negative cases. so we create a lite quarantine(ring
> >>> buffers) to record recent free stacks in order to avoid those false
> >>> negative situations.
> >>
> >> I'm telling that *more* than one free stack and also tags per object c=
an be stored.
> >> If object reused we would still have information about n-last usages o=
f the object.
> >> It seems like much easier and more efficient solution than patch you p=
roposing.
> >>
> > To make the object reused, we must ensure that no other pointers uses i=
t
> > after kfree() release the pointer.
> > Scenario:
> > 1). The object reused information is valid when no another pointer uses
> > it.
> > 2). The object reused information is invalid when another pointer uses
> > it.
> > Do you mean that the object reused is scenario 1) ?
> > If yes, maybe we can change the calling quarantine_put() location. It
> > will be fully use that quarantine, but at scenario 2) it looks like to
> > need this patch.
> > If no, maybe i miss your meaning, would you tell me how to use invalid
> > object information? or?
> >=20
>=20
>=20
> KASAN keeps information about object with the object, right after payload=
 in the kasan_alloc_meta struct.
> This information is always valid as long as slab page allocated. Currentl=
y it keeps only one last free stacktrace.
> It could be extended to record more free stacktraces and also record prev=
iously used tags which will allow you
> to identify use-after-free and extract right free stacktrace.

Thanks for your explanation.

For extend slub object, if one record is 9B (sizeof(u8)+ sizeof(struct
kasan_track)) and add five records into slub object, every slub object
may add 45B usage after the system runs longer.=20
Slub object number is easy more than 1,000,000(maybe it may be more
bigger), then the extending object memory usage should be 45MB, and
unfortunately it is no limit. The memory usage is more bigger than our
patch.

We hope tag-based KASAN advantage is smaller memory usage. If it=E2=80=99s
possible, we should spend less memory in order to identify
use-after-free. Would you accept our patch after fine tune it?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1563160001.4793.4.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
