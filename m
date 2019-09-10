Return-Path: <kasan-dev+bncBAABBH5W33VQKGQE6T76HKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 21A65AEAD5
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 14:46:25 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id e69sf13210867ybc.11
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 05:46:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568119584; cv=pass;
        d=google.com; s=arc-20160816;
        b=isAWS0vhp2HSHS7iq2gYWK1+sTq7Ucwy5i5HCKRScQScr6JrMmgbdN6aJAKlM0BE1i
         qFSC0HilxQGR+gd9oZd1S5i/5CaGZeqoXB3OFrg1up1j0Q7vZtptb6+wmpcX55e7IIR3
         R1vUYOiOl2FigEV0p38Ztv1deid4mA7VDLRzFL0Cq+Dvvdx9hF8P0OOQn99CJB0WRiYQ
         r3qTlGOitS0Z4guDoWW1nh7CHqJEdTHA7hNghxJETKLdL2V68bBKIzpGSO1CoXR5jdWu
         2OMxBKJh2JNnszdEVBoHVrzmKp2om+2l/EYkXAe8PxN1oIAGGmQ2WkCaPPv3bjZwHPtH
         jMkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=evPDqlGewFbnEZrre1MfPLcRH+B4A6jCnASp5oIeQxM=;
        b=M9n2ufB0AWqp4zGdhMtpoK1PsGX4KfMDjs0OOykO17zkk0ti4S5HxszeYwooaVyddg
         rKkPLgomBvnyiKeANFpuNKV0bClLWaC0trKLWKnZtWVsQAPNhNMf1UAYEjgmOg6GRflz
         GDvyea1EniuaOySZV/hPA0QlhZ3Wru0xFQRgPj8V32hg9A23J9xusahkWWg2gIZihcRr
         +Ppzj6l44zWM22r82G4ZUXtVKO6T9F67ZwKpGKmblxd7rEs15kPTSRanQrqXsqxyrH/b
         eHao461yBAnINtN5MSkuxUaFuA1cxZy0QoFF8MF6qr/j+Al9KyghJNn93S4IJOzQV8oG
         KVGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=evPDqlGewFbnEZrre1MfPLcRH+B4A6jCnASp5oIeQxM=;
        b=WKPM6Lglvb8wmBLsYVbkvsBW7n41xv8uQyYICCdRIQfUj3SUxRj9aTVfv6YxxcNc20
         LEzbjLoIFWykXVJ2N950iXy6gpDzdS9h2KEokiqA9Z1+A2fSIuvFdvek6uwGiiq32b3W
         4Ct4kcj8WzTd3Ivzg/yiuoS+No2FX+2CQvrSqpmg7Hnh0OGlqqDiHWMwKhXAKW9HqsgS
         a89CFYJnn5c259iIbFxXg8skvgpVsPo3PUIoSjea/Fz1vwqr43Zj20Mt+2VD5DwFMIly
         xPHlkarlzNxsgcao427xp8M/mnljzfCVQK6mXGCVsfDXQDxIDxdbk7sB6xyNdjwhFc8d
         VQDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=evPDqlGewFbnEZrre1MfPLcRH+B4A6jCnASp5oIeQxM=;
        b=Kl6KDwtSeZxi1Je6x/qi9yohvCmFdg1Jvm9cCDwfbXDmws4V8VjY/9IYulim+9VvTc
         jo9grjS0h1BqrGThDhMGFqDyoq241AUrLMP8NQZs4lG7V6YyzPE/uOn92JX/AKCbJcDj
         ZnB1rVL/8eEB0SiX6tKaqUo/L7De68SRQUtBjHTyLHl8tiNjqf1TedoTDcrVMOkdLMRV
         RaHRLXrmexjtfOveXx61/2/OyqsajcQGUZaq8NZBGWQ7tTprv1jFOwOSe9+KT/rMwVY0
         cEX96FQvY5dDBfXxg97Ac8dK7C0/O9brvibgfugTfrq7ysc3+EZ4FfL9eTspIKzUeNz/
         JB6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW7e9WY71a90wFWsiHwereyRJqOYYX0M/WICVSBmRJflKfQ3zqg
	QhVGGIR+I2vZCeZQmBouCL4=
X-Google-Smtp-Source: APXvYqzb7yb3ysykSZ8IUs5GSCF7ovUES0B2mjVi4J7lAG8J0HhP3BBPXuoDnZVWlzA3D/wKpdVmDQ==
X-Received: by 2002:a25:8b92:: with SMTP id j18mr19327267ybl.102.1568119584006;
        Tue, 10 Sep 2019 05:46:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b785:: with SMTP id n5ls1197427ybh.16.gmail; Tue, 10 Sep
 2019 05:46:23 -0700 (PDT)
X-Received: by 2002:a25:7389:: with SMTP id o131mr11181721ybc.491.1568119583775;
        Tue, 10 Sep 2019 05:46:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568119583; cv=none;
        d=google.com; s=arc-20160816;
        b=bFOkXrrx5U1S8/cwgYjsrmmdAtKsszakOzjrlvkVh0OxHIKXEM6XF7FlroTaBoJlQK
         6srNCoeTbOiZiV5xYocupP1ESkk6G+zSguLnAzACccYcrsx4UI1FdvCTHhtEkCm8wXg7
         YzsReZcLIilXanSDFTXM+xgSK7eU4cFp1BuzqWNmfICRRj1u4/Jru6UB9rAhgyDEo1LR
         JD1SMYtlXaa8lj5WPW5SQz9hu5EsgSPt1z1oKB1xSAYJPnrF1M6KhoeXblxJlQsSlc6f
         Tzd6FshMJW/nbXdG995TbeNWUPMczTAy0XLTZ0M1E1tAxpo4gyqlTetahnXqO5jVM9yt
         U+pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=f6TUAR15VJVpSesKQ3w1fx0laV2YC1XRmKoWW9cMSjE=;
        b=UXSyk8/clXSI+gkhbtBBBHZT6lIeugTPXIKkL4JVz+cxUqwNvK6qn58DIEiWJ/ok3c
         CKsQICHvTEKaMYxgjMHi8ia5GULitiEvuP7qFFzmSUvb4Qi0e+nFOGA56N1MOcxHkMxk
         fQZJn5Hq3+5vxdqDhJvsYOFU9RoAthGp0GLVTagVj9XFFDmZ0lIT13yHHq0J94hdZx5n
         1J18y/JWAj3iSmNxg658D9+ucCblI+qQcvfM8AmIy1sIniOO6uT3f2ORoMU/ctb9jFEu
         S00xm2wjsHA0exm6LrMPE05JEqt5ePEkMUWT8PR+CbwvePGeWwYe1No5DDtFmBv5raUw
         jqzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id p188si827461ywd.1.2019.09.10.05.46.22
        for <kasan-dev@googlegroups.com>;
        Tue, 10 Sep 2019 05:46:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 3abd29dae8c34e82833ece7ce660722c-20190910
X-UUID: 3abd29dae8c34e82833ece7ce660722c-20190910
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 723714861; Tue, 10 Sep 2019 20:46:17 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 10 Sep 2019 20:46:14 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 10 Sep 2019 20:46:14 +0800
Message-ID: <1568119575.24886.20.camel@mtksdccf07>
Subject: Re: [PATCH v2 0/2] mm/kasan: dump alloc/free stack for page
 allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Vlastimil Babka <vbabka@suse.cz>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>, Andrey
 Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>, Thomas
 Gleixner <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>, Qian Cai
	<cai@lca.pw>, <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Tue, 10 Sep 2019 20:46:15 +0800
In-Reply-To: <a7863965-90ab-5dae-65e7-8f68f4b4beb5@virtuozzo.com>
References: <20190909082412.24356-1-walter-zh.wu@mediatek.com>
	 <d53d88df-d9a4-c126-32a8-4baeb0645a2c@suse.cz>
	 <a7863965-90ab-5dae-65e7-8f68f4b4beb5@virtuozzo.com>
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

On Tue, 2019-09-10 at 13:50 +0300, Andrey Ryabinin wrote:
>=20
> On 9/9/19 4:07 PM, Vlastimil Babka wrote:
> > On 9/9/19 10:24 AM, walter-zh.wu@mediatek.com wrote:
> >> From: Walter Wu <walter-zh.wu@mediatek.com>
> >>
> >> This patch is KASAN report adds the alloc/free stacks for page allocat=
or
> >> in order to help programmer to see memory corruption caused by page.
> >>
> >> By default, KASAN doesn't record alloc and free stack for page allocat=
or.
> >> It is difficult to fix up page use-after-free or dobule-free issue.
> >>
> >> Our patchsets will record the last stack of pages.
> >> It is very helpful for solving the page use-after-free or double-free.
> >>
> >> KASAN report will show the last stack of page, it may be:
> >> a) If page is in-use state, then it prints alloc stack.
> >>     It is useful to fix up page out-of-bound issue.
> >=20
> > I still disagree with duplicating most of page_owner functionality for =
the sake of using a single stack handle for both alloc and free (while page=
_owner + debug_pagealloc with patches in mmotm uses two handles). It reduce=
s the amount of potentially important debugging information, and I really d=
oubt the u32-per-page savings are significant, given the rest of KASAN over=
head.
> >=20
> >> BUG: KASAN: slab-out-of-bounds in kmalloc_pagealloc_oob_right+0x88/0x9=
0
> >> Write of size 1 at addr ffffffc0d64ea00a by task cat/115
> >> ...
> >> Allocation stack of page:
> >>   set_page_stack.constprop.1+0x30/0xc8
> >>   kasan_alloc_pages+0x18/0x38
> >>   prep_new_page+0x5c/0x150
> >>   get_page_from_freelist+0xb8c/0x17c8
> >>   __alloc_pages_nodemask+0x1a0/0x11b0
> >>   kmalloc_order+0x28/0x58
> >>   kmalloc_order_trace+0x28/0xe0
> >>   kmalloc_pagealloc_oob_right+0x2c/0x68
> >>
> >> b) If page is freed state, then it prints free stack.
> >>     It is useful to fix up page use-after-free or double-free issue.
> >>
> >> BUG: KASAN: use-after-free in kmalloc_pagealloc_uaf+0x70/0x80
> >> Write of size 1 at addr ffffffc0d651c000 by task cat/115
> >> ...
> >> Free stack of page:
> >>   kasan_free_pages+0x68/0x70
> >>   __free_pages_ok+0x3c0/0x1328
> >>   __free_pages+0x50/0x78
> >>   kfree+0x1c4/0x250
> >>   kmalloc_pagealloc_uaf+0x38/0x80
> >>
> >> This has been discussed, please refer below link.
> >> https://bugzilla.kernel.org/show_bug.cgi?id=3D203967
> >=20
> > That's not a discussion, but a single comment from Dmitry, which btw co=
ntains "provide alloc *and* free stacks for it" ("it" refers to page, empha=
sis mine). It would be nice if he or other KASAN guys could clarify.
> >=20
>=20
> For slab objects we memorize both alloc and free stacks. You'll never kno=
w in advance what information will be usefull
> to fix an issue, so it usually better to provide more information. I don'=
t think we should do anything different for pages.
>=20
> Given that we already have the page_owner responsible for providing alloc=
/free stacks for pages, all that we should in KASAN do is to
> enable the feature by default. Free stack saving should be decoupled from=
 debug_pagealloc into separate option so that it can be enabled=20
> by KASAN and/or debug_pagealloc.

Thanks your suggestion.
We will send the patch v3 as described above.



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1568119575.24886.20.camel%40mtksdccf07.
