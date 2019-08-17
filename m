Return-Path: <kasan-dev+bncBDZYPUPHYEJBB7PE4DVAKGQE6EMSIYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 88E9991201
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Aug 2019 18:59:42 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id 125sf2468114vsr.18
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Aug 2019 09:59:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566061181; cv=pass;
        d=google.com; s=arc-20160816;
        b=qCmrs6mdqE2PYS4dvCk1BMDoPM3W+W6A8iqwOgivjVXDFJiMeylijwZXSho+d7nvg2
         sbjsTWt80GJCTQLgg59yGyDQfC4PN2ryVdoen1JmVv1GJI06f6ywVM0NOoeqS1Gse+8F
         b6P0GYixXOAQER1Lz9m7EPlLc4o8T74Kx46OEmR/YxsTiVKRZuMpZ2cCPi+cYbVuDCgr
         4+Ao4noD9j4yeQuGukr2TUpiTCisGQH+w2iTynzInl5z/6y8xiQufUu+rsw43rF1f8hJ
         5mnYMAb7d5RLH8ta7PNF7RunDTHDgH54G2Xy0DY8AD6k4vmTk8enWPQLmeGJnz7dGl4e
         kXzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=SIxeHS4+R3+A3158Qso80X0n0qme4ru5AW27FeA5Y88=;
        b=E8CUD+or+y0FpaoHeVVRpiZjRMziAZZIwa0BDrC2Vzj2EMSQHbzoQ6d/sptyXETkdY
         OsnPP3d8Z2PbQF9CHnEmoMarCSm2+OGFUqXwqKMFF5s5nJbtVmLjHVNXyt37BHKbvE9j
         YA9u8ZnHOuz/CFam2wgXB5sVfy+NC0ytChP9oFKdk0J+huxIs/joyvFygLLuRf4wPfrq
         akvUsNlSzXVkjRvA42iRBUO78dXgCuA/1J18vpVzHEgRV3XrRjxEaahgqfPWVXtF2SAO
         XaIaEjJ27rYHYaj/qpI0xehDHS3Q7EK1WNaWUxIPmlxXBNHeWhn0AFkxXHbTDSzZFuOz
         GLvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel-com.20150623.gappssmtp.com header.s=20150623 header.b=IpKtW8Cq;
       spf=pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SIxeHS4+R3+A3158Qso80X0n0qme4ru5AW27FeA5Y88=;
        b=iCLz/vd94/SY29ITVE9f9AJeBicwkBn30WOeH4PIK8qKyofrVSNIb57wre6CD+DAhY
         kyWcilD4KYyHbJqhrNOTVTXEm/bEm8mil+6PxZbL8SUBqiIYQOPplS/vnDx/SDW9IvPw
         uEXQtkwUD2v1uZbtsBC4ytYNXbWvxxLkCCGCiJADQPCWqHLTcjY/Tniob8I5oTiiOd3o
         BlTC/0XRiB6Y7nO8dnNG36w6Oh5GwcAbJtnawitBI4uLyAmNT9mdhM+YEX2JhgGgoGk/
         d1mfzksVdkR/RLTUHXjfDjSrgQxs0IJ3fBwXupa83e1lvtpd9WQqGa4UkkA0Zhxyib+D
         YFuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SIxeHS4+R3+A3158Qso80X0n0qme4ru5AW27FeA5Y88=;
        b=YA+7ewGJE1KThoePNUvj1oE/rmxhetuyPxot6nexy9tP7q9Qq3OItUIjEmGhH9uUK8
         DBkNA9II2TqVoCYde/WrHXh1xsEXKozvrJxGAru6zxdL8QGAbKN9jgIJv6BUC8a2navH
         Sku7I/TZEe1MTkjq54Y/RuNLyvkKrQEUX0TsjsdgscVgPgKLBQ1O6illAGJ1LHyKwPcy
         O3i571b52KQhCp3PMYpjzLacFY98j4NujPItk3Pv3OK2MeyKL8rO4IsuJruJZcBOc+pQ
         7z4krGcaSYy7qX4r+FVpqwavx4h5q3K9T5h8dAv9/fNmVD2aRl4ShtPwfKit91Hpf8lM
         7wUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVrFnuXdgnjDoqpsq/BFqxrjusv4IqzDBtw3yOLwuhvbEcwdlMT
	o8bSlcZxYhZzBhKacsJbu+0=
X-Google-Smtp-Source: APXvYqymxmlNKFb1Z/az7lY53g7AF73Zu1qf1JOMySdN+SGBDhVvf3T3if7di2x1AURVE0A1F8KwLA==
X-Received: by 2002:a67:a44f:: with SMTP id p15mr7084188vsh.105.1566061181235;
        Sat, 17 Aug 2019 09:59:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2a09:: with SMTP id o9ls735520uar.11.gmail; Sat, 17 Aug
 2019 09:59:40 -0700 (PDT)
X-Received: by 2002:ab0:60d9:: with SMTP id g25mr3054948uam.69.1566061180759;
        Sat, 17 Aug 2019 09:59:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566061180; cv=none;
        d=google.com; s=arc-20160816;
        b=ZgHi7gZbPhyCMSi6Gb80hicNnT/h1eDMdo/AKwinQyjewqFpSo+1poYQZwXZQ/mxc5
         tPM9CflTE9TtFvnbugEYjMivj4jVA4m5CzKAxAe6iZiTnNcYSJt2lE4sqsK8eL8uyUT/
         REuahNtObF59Wyq3V/NhXAKDHXwlZVS4jqrmZ0dgw2yAWBcxx6nKXfSXuRiDjZRKepCv
         9P+UUqCV9ec7Otdwi5fBS2qmheYnZxDY+AvxWiCpDSXkmmhtszcQtRl8Gr+lQMc/4NAi
         c/FIY0pA79fqUJVGvDbHkU0CJ5UICEPGcJqk3sEwQ8tYIXYUUX1+r8vjrpxPM6v+PDYl
         IZ3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4ctyW3Vi5Ibh5x2BY4buy9E2tmdYqlztCCfXF658lFw=;
        b=TbhUZryWDBJ0JPXsLdyfJPWa+84emXdQamcwYXL9if/zeWKb+8eUJJOJ0mcVMRADIA
         OC3jj6s42o2wi1peSUxwj+uxK+mY22AHAzIgjqnK1s1VACIU6R5SfOJa8dXHCdkbfnFf
         VvnSMJqeUMLAGW2SLUsESo19foiKJHPVBuyAMyUbVHlXdldY0QhVMpN9bNInVBXSOWdU
         cTItlByll7TuT0CQH0loPGf128ZmgeCltqhyJ/rq/IBlSN6ClF/zMrQM/MzHcKQIGTKJ
         5v4KX9EVGfHAjkSrt50KmTKbAexN3mdau6EfdBVBdyxoMLcdYhxSw4Qgc1JHAnytv/r5
         yDNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel-com.20150623.gappssmtp.com header.s=20150623 header.b=IpKtW8Cq;
       spf=pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id a128si496765vkh.1.2019.08.17.09.59.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Aug 2019 09:59:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id w4so12335756ote.11
        for <kasan-dev@googlegroups.com>; Sat, 17 Aug 2019 09:59:40 -0700 (PDT)
X-Received: by 2002:a05:6830:1e05:: with SMTP id s5mr11126021otr.247.1566061179762;
 Sat, 17 Aug 2019 09:59:39 -0700 (PDT)
MIME-Version: 1.0
References: <1565991345.8572.28.camel@lca.pw> <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
 <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw> <CAPcyv4h9Y7wSdF+jnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA@mail.gmail.com>
 <E7A04694-504D-4FB3-9864-03C2CBA3898E@lca.pw>
In-Reply-To: <E7A04694-504D-4FB3-9864-03C2CBA3898E@lca.pw>
From: Dan Williams <dan.j.williams@intel.com>
Date: Sat, 17 Aug 2019 09:59:27 -0700
Message-ID: <CAPcyv4gofF-Xf0KTLH4EUkxuXdRO3ha-w+GoxgmiW7gOdS2nXQ@mail.gmail.com>
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
To: Qian Cai <cai@lca.pw>
Cc: Linux MM <linux-mm@kvack.org>, linux-nvdimm <linux-nvdimm@lists.01.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dan.j.williams@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel-com.20150623.gappssmtp.com header.s=20150623
 header.b=IpKtW8Cq;       spf=pass (google.com: domain of dan.j.williams@intel.com
 designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Sat, Aug 17, 2019 at 4:13 AM Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Aug 16, 2019, at 11:57 PM, Dan Williams <dan.j.williams@intel.com> w=
rote:
> >
> > On Fri, Aug 16, 2019 at 8:34 PM Qian Cai <cai@lca.pw> wrote:
> >>
> >>
> >>
> >>> On Aug 16, 2019, at 5:48 PM, Dan Williams <dan.j.williams@intel.com> =
wrote:
> >>>
> >>> On Fri, Aug 16, 2019 at 2:36 PM Qian Cai <cai@lca.pw> wrote:
> >>>>
> >>>> Every so often recently, booting Intel CPU server on linux-next trig=
gers this
> >>>> warning. Trying to figure out if  the commit 7cc7867fb061
> >>>> ("mm/devm_memremap_pages: enable sub-section remap") is the culprit =
here.
> >>>>
> >>>> # ./scripts/faddr2line vmlinux devm_memremap_pages+0x894/0xc70
> >>>> devm_memremap_pages+0x894/0xc70:
> >>>> devm_memremap_pages at mm/memremap.c:307
> >>>
> >>> Previously the forced section alignment in devm_memremap_pages() woul=
d
> >>> cause the implementation to never violate the KASAN_SHADOW_SCALE_SIZE
> >>> (12K on x86) constraint.
> >>>
> >>> Can you provide a dump of /proc/iomem? I'm curious what resource is
> >>> triggering such a small alignment granularity.
> >>
> >> This is with memmap=3D4G!4G ,
> >>
> >> # cat /proc/iomem
> > [..]
> >> 100000000-155dfffff : Persistent Memory (legacy)
> >>  100000000-155dfffff : namespace0.0
> >> 155e00000-15982bfff : System RAM
> >>  155e00000-156a00fa0 : Kernel code
> >>  156a00fa1-15765d67f : Kernel data
> >>  157837000-1597fffff : Kernel bss
> >> 15982c000-1ffffffff : Persistent Memory (legacy)
> >> 200000000-87fffffff : System RAM
> >
> > Ok, looks like 4G is bad choice to land the pmem emulation on this
> > system because it collides with where the kernel is deployed and gets
> > broken into tiny pieces that violate kasan's. This is a known problem
> > with memmap=3D. You need to pick an memory range that does not collide
> > with anything else. See:
> >
> >    https://nvdimm.wiki.kernel.org/how_to_choose_the_correct_memmap_kern=
el_parameter_for_pmem_on_your_system
> >
> > ...for more info.
>
> Well, it seems I did exactly follow the information in that link,
>
> [    0.000000] BIOS-provided physical RAM map:
> [    0.000000] BIOS-e820: [mem 0x0000000000000000-0x0000000000093fff] usa=
ble
> [    0.000000] BIOS-e820: [mem 0x0000000000094000-0x000000000009ffff] res=
erved
> [    0.000000] BIOS-e820: [mem 0x00000000000e0000-0x00000000000fffff] res=
erved
> [    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000005a7a0fff] usa=
ble
> [    0.000000] BIOS-e820: [mem 0x000000005a7a1000-0x000000005b5e0fff] res=
erved
> [    0.000000] BIOS-e820: [mem 0x000000005b5e1000-0x00000000790fefff] usa=
ble
> [    0.000000] BIOS-e820: [mem 0x00000000790ff000-0x00000000791fefff] res=
erved
> [    0.000000] BIOS-e820: [mem 0x00000000791ff000-0x000000007b5fefff] ACP=
I NVS
> [    0.000000] BIOS-e820: [mem 0x000000007b5ff000-0x000000007b7fefff] ACP=
I data
> [    0.000000] BIOS-e820: [mem 0x000000007b7ff000-0x000000007b7fffff] usa=
ble
> [    0.000000] BIOS-e820: [mem 0x000000007b800000-0x000000008fffffff] res=
erved
> [    0.000000] BIOS-e820: [mem 0x00000000ff800000-0x00000000ffffffff] res=
erved
> [    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000087fffffff] usa=
ble
>
> Where 4G is good. Then,
>
> [    0.000000] user-defined physical RAM map:
> [    0.000000] user: [mem 0x0000000000000000-0x0000000000093fff] usable
> [    0.000000] user: [mem 0x0000000000094000-0x000000000009ffff] reserved
> [    0.000000] user: [mem 0x00000000000e0000-0x00000000000fffff] reserved
> [    0.000000] user: [mem 0x0000000000100000-0x000000005a7a0fff] usable
> [    0.000000] user: [mem 0x000000005a7a1000-0x000000005b5e0fff] reserved
> [    0.000000] user: [mem 0x000000005b5e1000-0x00000000790fefff] usable
> [    0.000000] user: [mem 0x00000000790ff000-0x00000000791fefff] reserved
> [    0.000000] user: [mem 0x00000000791ff000-0x000000007b5fefff] ACPI NVS
> [    0.000000] user: [mem 0x000000007b5ff000-0x000000007b7fefff] ACPI dat=
a
> [    0.000000] user: [mem 0x000000007b7ff000-0x000000007b7fffff] usable
> [    0.000000] user: [mem 0x000000007b800000-0x000000008fffffff] reserved
> [    0.000000] user: [mem 0x00000000ff800000-0x00000000ffffffff] reserved
> [    0.000000] user: [mem 0x0000000100000000-0x00000001ffffffff] persiste=
nt (type 12)
> [    0.000000] user: [mem 0x0000000200000000-0x000000087fffffff] usable
>
> The doc did mention that =E2=80=9CThere seems to be an issue with CONFIG_=
KSAN at the moment however.=E2=80=9D
> without more detail though.

Does disabling CONFIG_RANDOMIZE_BASE help? Maybe that workaround has
regressed. Effectively we need to find what is causing the kernel to
sometimes be placed in the middle of a custom reserved memmap=3D range.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAPcyv4gofF-Xf0KTLH4EUkxuXdRO3ha-w%2BGoxgmiW7gOdS2nXQ%40mail.gmai=
l.com.
