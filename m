Return-Path: <kasan-dev+bncBAABB2PD5PUQKGQEXKEB5EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id A819B765AF
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 14:28:26 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id u200sf20984920oia.23
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 05:28:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564144105; cv=pass;
        d=google.com; s=arc-20160816;
        b=mqiLtw04J5wSzdFwJRbWT0CPiG/LnJZW4n6g+hznfg6z25qiUWhjNnQEoye6Q9l5PX
         ratXMfui9tfbtfzMsk+CLrbtSKM+jCkguN/Ho6Pslm/pgQ5uNy2jMWnEQKAuoDu6ud2J
         VjmAKIp2UVzuls5vfBwGdguBetcjg8rIo9ye+q4Bl5nPOufa0kQxl9fa7FBWxmD7yzzP
         NPaZvygVwyreUScHQj8dAkWKNdMalEVxiEQqhlOkZ2OeFCGUbknSpZkqyJPC2lkfhQ0w
         7KtVmwRNUXYVLiLFLkc58OmmLUSvqEVr8La6Y6gz0sM+axWbq3Qkp4UkESjzccNLGuPb
         tB6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=rofJq+MRV/N82mgliTsEgSdjaxXTFX/eAhEY3dWMd+c=;
        b=H/EZTrjE3XLdd8AavpTpyxbpQuAoaOA4NfqvhqToBlK5BXHgAs0cyrYLo6yutb5Xjg
         zLDOuu/w6djEY7SZyxkU/EL2nx7oZc7QMSpFKCsic1HaktcQgK4n7RkyAYBZgpyDY21u
         Dh6oLljnMyGG7PlYzuVQsWwwvc2tO5D/DVU4lSkwXmVKYcgTLdGoMd86mPUEjRISgSJH
         aqAiTFpBEP67m9J3bzwvAp20f07NQgqzV8NR9bOnhw0pwvZ5IsUpBD4wYL1ssUOo3nXz
         p/jBqwFQN0Iz0c1p+BdT9ATDx3mZ1yiNIdvHXCNaAH7V0A/1w5yWrVt6LMW65CJxPxlz
         fAyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rofJq+MRV/N82mgliTsEgSdjaxXTFX/eAhEY3dWMd+c=;
        b=Asg1hhue7rQVls9YYoMRJUUaiQN1YqBvnh+igZrnjBHl5BTeHPr+q5s6lOTs7mf79n
         hzIDhFadfJHGbDfyjyGjSyEMBTNcgP01jjze6qHKGrssa5/hyM+9dYdJmJXh3ylGBlNZ
         CgBEGzFe5E7lkQKg+HMQV3RQQZ1vZTNdYc8lZR1bJDb0HOSV8TaDEvhJ07E7XJU27HM2
         0Ut3L4w99O03ygKxn9f79df4LtQLd6EA/KtUVzmLYfMGD7SadPpDqzi1LYy4UqZVO+sK
         8FvsinANcNlMHJ88NEIF/45qpwJZelbTLADXeViXImFngtAVrxcY+4LmZUg+UhDRkpLe
         Z14g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rofJq+MRV/N82mgliTsEgSdjaxXTFX/eAhEY3dWMd+c=;
        b=cnX3BOC5rUKUW6uStnevB0PsgZ4S0FfjUa43x5kFOPPsrQBrkFMJda0zavyxPFIYGw
         RNKcNytSFE6KhrM4Yl9CCV6lNOjZAVfQ5wx+rMXKfrR5uqkWpCzFQsG4rwSBQEsfbIBY
         zL8FfAroifMIIIQ4TC5fkO3LSOnThZiwHF8qMxCGlyH1e5PIt9UTnmKJIrr9E6NMZ8Dg
         tqlLup2wOZNduwbIQbChEuCg/GxvyTpzWHX/XBr5YWeePXfqv94Z51tUrD2FFrZjTsLN
         2mp5UKzSSgibjkbsHyRbIvUXQ6ouUuDzij18PjC0npVMvXeUIGPMksLbwbEhRkFOjJQr
         jKMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWEJBqkOQSYUIjTiShqRHlOS7dvR8WhIVGwisccJ0XMy9Aca1d7
	YD0XszDsegdSDHzo+gHggDU=
X-Google-Smtp-Source: APXvYqzg7whrbtuyRe2bfI/gUn04/HW14h2KnrRjjdG3S4vSjioR2n09oaikUaUK4O1AeiKtVI8OKw==
X-Received: by 2002:a9d:7643:: with SMTP id o3mr38561066otl.49.1564144105160;
        Fri, 26 Jul 2019 05:28:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:60d7:: with SMTP id b23ls10288400otk.14.gmail; Fri, 26
 Jul 2019 05:28:24 -0700 (PDT)
X-Received: by 2002:a05:6830:128e:: with SMTP id z14mr12256726otp.172.1564144104960;
        Fri, 26 Jul 2019 05:28:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564144104; cv=none;
        d=google.com; s=arc-20160816;
        b=vhGhEhJEf0Eki2z7zTGhMysFegsa9XVhPt/KwWPJ9vkvo1j0uOB+zIsFY6kqcZdJNn
         h+auGOlzU4JjC9m51W9YrlthXIUASCcRer6okLN0rYo/JieEAhG93ChrlMSiaKZTS8f1
         Aiw4eA1xObw92ko/iMTenxsxRPOh+Apky/3RiSzUEoFJifWnu8KuLJaN8tLC5DzHZGNK
         DNZJYyziZ0VhhdpPDINfEtN/t5PEsic7EyoA8jjB3xzn96UEs4z4s/lL2mw/gKah2092
         MsjAZkptpiOzG2pnotmDYlyG5X2oKvMRwETss+UZQ9OzDR9d+MsSaUlbCNqbjKcg9E+E
         YFiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=tf9SlYB3vDxsjrpdAXfoKRzNdUzFpR3V6KOtlIUPDaY=;
        b=w4dnTX9QJ0SXymHM6aTa5I6NEPZvxdl4jTYOEHPh6IlbNcCxvF71+2qpKJqtAAvkN7
         TZwphhoO4E0ZkxKVviXR5kzdl9bqPjNqg+WWhp0A7vVs6oqY556woFPQKmqpzG6xOsG4
         2O4Giosj0rLzy2smYyP4W826f5Snu0ohMiCKQOQI7LH6a8n2sErqcqMsGjG/e4+9EwOU
         n977paw3ZcycFJIqa6g0XoqLMOc+aO/cBpfWAuIVU8ilPpdvQwmo8zdTAInIOQ4QHheO
         FkdnBHU+Wau5NMsM/CtEnsfav/I5aP0AA2qzcY3X3zxf31JY2DyHFH7bC9YCj7uYc48R
         g3hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id n27si2574348otj.1.2019.07.26.05.28.23
        for <kasan-dev@googlegroups.com>;
        Fri, 26 Jul 2019 05:28:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: c0115c5e4bb04f198b33f101ac812dbd-20190726
X-UUID: c0115c5e4bb04f198b33f101ac812dbd-20190726
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0707 with TLS)
	with ESMTP id 1220834546; Fri, 26 Jul 2019 20:28:14 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 26 Jul 2019 20:28:17 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 26 Jul 2019 20:28:17 +0800
Message-ID: <1564144097.515.3.camel@mtksdccf07>
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
Date: Fri, 26 Jul 2019 20:28:17 +0800
In-Reply-To: <e62da62a-2a63-3a1c-faeb-9c5561a5170c@virtuozzo.com>
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

On Fri, 2019-07-26 at 15:00 +0300, Andrey Ryabinin wrote:
>=20
> On 7/22/19 12:52 PM, Walter Wu wrote:
> > On Thu, 2019-07-18 at 19:11 +0300, Andrey Ryabinin wrote:
> >>
> >> On 7/15/19 6:06 AM, Walter Wu wrote:
> >>> On Fri, 2019-07-12 at 13:52 +0300, Andrey Ryabinin wrote:
> >>>>
> >>>> On 7/11/19 1:06 PM, Walter Wu wrote:
> >>>>> On Wed, 2019-07-10 at 21:24 +0300, Andrey Ryabinin wrote:
> >>>>>>
> >>>>>> On 7/9/19 5:53 AM, Walter Wu wrote:
> >>>>>>> On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
> >>>>>>>>
> >>>>>>>> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
> >>>>>>>>> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediate=
k.com> wrote:
> >>>>>>
> >>>>>>>>>
> >>>>>>>>> Sorry for delays. I am overwhelm by some urgent work. I afraid =
to
> >>>>>>>>> promise any dates because the next week I am on a conference, t=
hen
> >>>>>>>>> again a backlog and an intern starting...
> >>>>>>>>>
> >>>>>>>>> Andrey, do you still have concerns re this patch? This change a=
llows
> >>>>>>>>> to print the free stack.
> >>>>>>>>
> >>>>>>>> I 'm not sure that quarantine is a best way to do that. Quaranti=
ne is made to delay freeing, but we don't that here.
> >>>>>>>> If we want to remember more free stacks wouldn't be easier simpl=
y to remember more stacks in object itself?
> >>>>>>>> Same for previously used tags for better use-after-free identifi=
cation.
> >>>>>>>>
> >>>>>>>
> >>>>>>> Hi Andrey,
> >>>>>>>
> >>>>>>> We ever tried to use object itself to determine use-after-free
> >>>>>>> identification, but tag-based KASAN immediately released the poin=
ter
> >>>>>>> after call kfree(), the original object will be used by another
> >>>>>>> pointer, if we use object itself to determine use-after-free issu=
e, then
> >>>>>>> it has many false negative cases. so we create a lite quarantine(=
ring
> >>>>>>> buffers) to record recent free stacks in order to avoid those fal=
se
> >>>>>>> negative situations.
> >>>>>>
> >>>>>> I'm telling that *more* than one free stack and also tags per obje=
ct can be stored.
> >>>>>> If object reused we would still have information about n-last usag=
es of the object.
> >>>>>> It seems like much easier and more efficient solution than patch y=
ou proposing.
> >>>>>>
> >>>>> To make the object reused, we must ensure that no other pointers us=
es it
> >>>>> after kfree() release the pointer.
> >>>>> Scenario:
> >>>>> 1). The object reused information is valid when no another pointer =
uses
> >>>>> it.
> >>>>> 2). The object reused information is invalid when another pointer u=
ses
> >>>>> it.
> >>>>> Do you mean that the object reused is scenario 1) ?
> >>>>> If yes, maybe we can change the calling quarantine_put() location. =
It
> >>>>> will be fully use that quarantine, but at scenario 2) it looks like=
 to
> >>>>> need this patch.
> >>>>> If no, maybe i miss your meaning, would you tell me how to use inva=
lid
> >>>>> object information? or?
> >>>>>
> >>>>
> >>>>
> >>>> KASAN keeps information about object with the object, right after pa=
yload in the kasan_alloc_meta struct.
> >>>> This information is always valid as long as slab page allocated. Cur=
rently it keeps only one last free stacktrace.
> >>>> It could be extended to record more free stacktraces and also record=
 previously used tags which will allow you
> >>>> to identify use-after-free and extract right free stacktrace.
> >>>
> >>> Thanks for your explanation.
> >>>
> >>> For extend slub object, if one record is 9B (sizeof(u8)+ sizeof(struc=
t
> >>> kasan_track)) and add five records into slub object, every slub objec=
t
> >>> may add 45B usage after the system runs longer.=20
> >>> Slub object number is easy more than 1,000,000(maybe it may be more
> >>> bigger), then the extending object memory usage should be 45MB, and
> >>> unfortunately it is no limit. The memory usage is more bigger than ou=
r
> >>> patch.
> >>
> >> No, it's not necessarily more.
> >> And there are other aspects to consider such as performance, how simpl=
e reliable the code is.
> >>
> >>>
> >>> We hope tag-based KASAN advantage is smaller memory usage. If it=E2=
=80=99s
> >>> possible, we should spend less memory in order to identify
> >>> use-after-free. Would you accept our patch after fine tune it?
> >>
> >> Sure, if you manage to fix issues and demonstrate that performance pen=
alty of your
> >> patch is close to zero.
> >=20
> >=20
> > I remember that there are already the lists which you concern. Maybe we
> > can try to solve those problems one by one.
> >=20
> > 1. deadlock issue? cause by kmalloc() after kfree()?
>=20
> smp_call_on_cpu()

> > 2. decrease allocation fail, to modify GFP_NOWAIT flag to GFP_KERNEL?
>=20
> No, this is not gonna work. Ideally we shouldn't have any allocations the=
re.
> It's not reliable and it hurts performance.
>=20
I dont know this meaning, we need create a qobject and put into
quarantine, so may need to call kmem_cache_alloc(), would you agree this
action?

>=20
> > 3. check whether slim 48 bytes (sizeof (qlist_object) +
> > sizeof(kasan_alloc_meta)) and additional unique stacktrace in
> > stackdepot?
> > 4. duplicate struct 'kasan_track' information in two different places
> >=20
>=20
> Yup.
>=20
> > Would you have any other concern? or?
> >=20
>=20
> It would be nice to see some performance numbers. Something that uses sla=
b allocations a lot, e.g. netperf STREAM_STREAM test.
>=20
ok, we will do it.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1564144097.515.3.camel%40mtksdccf07.
