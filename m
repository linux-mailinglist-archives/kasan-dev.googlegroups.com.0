Return-Path: <kasan-dev+bncBDW2JDUY5AORBP7H52PAMGQETYBT4CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id AFFF3687E25
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 13:59:44 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id x29-20020ab05add000000b0050f5111c4f0sf816407uae.5
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 04:59:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675342783; cv=pass;
        d=google.com; s=arc-20160816;
        b=hSCHzsnEEXkUN/I27vrAg2PUF25YdnE2VDuLkPg0QoWrOm+LLPouhslMzeLKo5pZeu
         5m71XI/FVnyWv1r/diXL9ATgTwajkvQ0t0z+NOntU4M5YcVW9SCJCjwEZUMxuwwcC4Mu
         azOonLG0QRg65cNN2LJekCYcAhoESfuxu3V4fGjm9pj+aHgjV82LAGqy3UqiUtKnKcCs
         CNMJs/9qSJQ/jm0W3Tlz1gw7nf1lFuzXGMutWouh92b6+ZhcPDgF8b3nzQgEPBs6I/HP
         A1JQHw+YGtq0E+ovi0ELFMq/kIo+qNtdqb2E/vfzmkr4CVKErcDJtR8KJd97PqevhRlb
         wH4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=leP9po+V/3K3NXgZjjDhZe5x1qNmAnfJ1/BT2DvA65o=;
        b=nT2NRRhllR4ZqshB6falFgEIcNyx2t5juOyAWtOscPVXXXp+ZvVOMtWL7WXjCmIy7h
         H5YQmKhRpICyyhuglI/+7A5O+a5p17HXXookrphknai2yxqPoDl2TOCTtx++h8HJe43w
         P0fuSbjoI49KcqO3wTOS2N7KLBWz9a4A03ucKSDNniCaSm5dHh7D8KMl/XvpDYWea9hf
         i6Qvi9ofHyj6racNSMtWnJ4TzDjLIk7b80GLHqAqrvXv8gnfHNCMu5/w7urFhySjDl7m
         m+8j59sSJOpVA1WsK8JuvKym1BScFZ/uChH3IYGUpIC/UnwwnCzrlsMHjfmnUIhUkh//
         s3ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UXfyf0kk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=leP9po+V/3K3NXgZjjDhZe5x1qNmAnfJ1/BT2DvA65o=;
        b=bQLenFpfOSn695eTAr2cR8k5+856R6swe+sbd/895QHIzAv3iTj2KRIKqgHXB3b/Hn
         oxoDDj8IpwqGuMHJPKLk08WiHsWTEyNS+2MqCMO6WUXDiJDdYuFoYyh/0oUuD30gv+rI
         c5fJB4ndNTBfmSd3B7OsCwvb2WtUaYQyAUG3tZn05ZU7nDxzBMMeVH7JQbXyP6EIwifS
         /qRBklDOtfpzbHTvmEmg8C0DLPBLrrx3le+560DoucLCmjoCGbA4onWwxDwE69IS5FmQ
         JaJwGMMAI/C5Xo4RuK52oOOiYqBh0VtZN0X8C4gg0OZXZ6aoBrnjeEDnJ5vZor0cRkl6
         QIvA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=leP9po+V/3K3NXgZjjDhZe5x1qNmAnfJ1/BT2DvA65o=;
        b=KVEsXJ40Vis7iDg6GUNoe+2VrNsjCuLjUKfkk6QSriM/WwwaqWXRrv5/dHzabIaMJO
         NzHUchZ2jYhuCyqB4ZfwLzQjY9T4W4GSIGCA5FpgFD3J0vPW/fkaVXkgwRLd9pzgDsXs
         Y1ylmzAvV+C62W0MloPOdzLadRkw8RMKSgFFd7JbPG/5YHZunbvYYClkhliuWhE0k8QN
         7RV1yaLmOcDeVDagWvO11F4u5sy9tZXyaQHNSusjYeT1jvlXm4H9ZiYcBqShbCuF4Q2B
         4FxzZGSowWYXAg2qpAJ0jbAAVrtssmedHn+ZtlzAYNP6TDnWL0Ii1/8oK5zzRZ3VdyNS
         cY5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=leP9po+V/3K3NXgZjjDhZe5x1qNmAnfJ1/BT2DvA65o=;
        b=j+UbKqXcG/lLIWFUgGNPB4sTCXHhuqldI7zYFt4ZKMjyaJqXakE0x6sf048s8ZxdTj
         dXSm4WLwrJ3HbY1HZBTFqCzItUDDpNYx8YOJu8wwPmtVn6pDBIGR5ekR3h8ul3M4hEn+
         ZYWkarqFnk7pVRHwGGq6L0odhMZrSHtFmtsNZb3MaJDH3uxgSkz7Ak6T2lLljVgvKIE+
         asG8OWjPlrG2Q/RDBHAhjZUVeoNMmsoxuiVmbTIYc7Gg/rGC3RSL2cB7RQtOxPi7IJd6
         KJhM29svtTkOJYp1ymh0jcRviVOU8yPpmHox3W07JmS9t35NrhB1nTudRUlW28CjJgo1
         QWlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWYK2nT6EP1UHfeBkKffD+AXuKpeEp+yV/Q6yT1nWwj1TAx85Jy
	ZMwQ0TKS72AKyGj/v7PvIXo=
X-Google-Smtp-Source: AK7set8qEc52+8fImnfnEPi6SEad4QR9Q3RX5tIfP5YR7+ooLcF88D0hIHTtiymj9HkJfELw/iOARw==
X-Received: by 2002:a9f:36cf:0:b0:5ff:91d2:ea36 with SMTP id p73-20020a9f36cf000000b005ff91d2ea36mr933733uap.43.1675342783558;
        Thu, 02 Feb 2023 04:59:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:1609:b0:3b0:9714:6c49 with SMTP id
 cu9-20020a056102160900b003b097146c49ls551995vsb.3.-pod-prod-gmail; Thu, 02
 Feb 2023 04:59:42 -0800 (PST)
X-Received: by 2002:a05:6102:e07:b0:401:d7ce:7541 with SMTP id o7-20020a0561020e0700b00401d7ce7541mr2261774vst.5.1675342782888;
        Thu, 02 Feb 2023 04:59:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675342782; cv=none;
        d=google.com; s=arc-20160816;
        b=BzPDJZPiFRkR5kAySCygqaykdnQcB/qiEuG0JYhMKHHPmRDhmivEwuAGQB006qRVWL
         sQ3tVG8JdGxvoC/fY8T/bscg23tv77UiJVO06VAmQ3OhsoNMHSnkHU8GdtTq21oSG3Qr
         qLWYv7vH/YkDdMkNDxN3N1gCeyzi9Nza9sVhT/+DgQhzK43bUNMYyIax7vttOkaTANTy
         bX0JG5PxjqjgUPsEGF2kRP88VmdFSnVh6Gztr6OARyYbg3cxcEE/6k2/GL0cHbsz+iVL
         akT2VitGOh4UXO2E7m9LFTAC5KHWWB7bU2ahs38VOwoQIWF9IDDsbnsp6IyjIZzc16KG
         jiXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=loinkwxJErq9bon+a0JV3BFJ9k0H/+4mhcuNPmPw26M=;
        b=c6criEqBEAcR/kiRP6K/2bZ0l/2Qtxtg6GvjRbP05g5AWZE84aYjAMoiAqRnTJ4dVr
         1cokSLDwyErMTsK6RGlQIP0I+Lhjr0fCitzkAuzIZ5/6H4DfHJyka6JKC9eIE7iAp0HV
         LtHbk09GFCR8HJOV9SO9OWoyQoqeHf0FMABEWLO6gkfBVXKLDckz0sOuueGMR4SWV47l
         t6TNMhKtKyUVEligokPamG3Zdy20EfItERKjwGJczb8aGdrz5wJa155bM52l84gnK42T
         f/MOzSvXDUk/0G/yvYNWqMcAvR9XW3XRrQIfSoqiQv1HYhFEaYj+Dob2K23ncr+PvC1S
         8e7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UXfyf0kk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id y21-20020a05610230b500b003f046825252si1339325vsd.1.2023.02.02.04.59.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 04:59:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id cr11so1127569pfb.1
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 04:59:42 -0800 (PST)
X-Received: by 2002:a62:6581:0:b0:593:c739:da73 with SMTP id
 z123-20020a626581000000b00593c739da73mr1304490pfb.10.1675342781846; Thu, 02
 Feb 2023 04:59:41 -0800 (PST)
MIME-Version: 1.0
References: <20220610152141.2148929-1-catalin.marinas@arm.com> <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
In-Reply-To: <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 2 Feb 2023 13:59:29 +0100
Message-ID: <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and page->flags
To: =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>
Cc: "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, 
	"catalin.marinas@arm.com" <catalin.marinas@arm.com>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	=?UTF-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, "pcc@google.com" <pcc@google.com>, 
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, "will@kernel.org" <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=UXfyf0kk;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Feb 2, 2023 at 6:25 AM Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> On Fri, 2022-06-10 at 16:21 +0100, Catalin Marinas wrote:
> > Hi,
> >
> > That's a second attempt on fixing the race race between setting the
> > allocation (in-memory) tags in a page and the corresponding logical
> > tag
> > in page->flags. Initial version here:
> >
> >
> https://lore.kernel.org/r/20220517180945.756303-1-catalin.marinas@arm.com
> >
> > This new series does not introduce any new GFP flags but instead
> > always
> > skips unpoisoning of the user pages (we already skip the poisoning on
> > free). Any unpoisoned page will have the page->flags tag reset.
> >
> > For the background:
> >
> > On a system with MTE and KASAN_HW_TAGS enabled, when a page is
> > allocated
> > kasan_unpoison_pages() sets a random tag and saves it in page->flags
> > so
> > that page_to_virt() re-creates the correct tagged pointer. We need to
> > ensure that the in-memory tags are visible before setting the
> > page->flags:
> >
> > P0 (__kasan_unpoison_range):    P1 (access via virt_to_page):
> >   Wtags=3Dx                         Rflags=3Dx
> >     |                               |
> >     | DMB                           | address dependency
> >     V                               V
> >   Wflags=3Dx                        Rtags=3Dx
> >
> > The first patch changes the order of page unpoisoning with the tag
> > storing in page->flags. page_kasan_tag_set() has the right barriers
> > through try_cmpxchg().
> >
> > If a page is mapped in user-space with PROT_MTE, the architecture
> > code
> > will set the allocation tag to 0 and a subsequent page_to_virt()
> > dereference will fault. We currently try to fix this by resetting the
> > tag in page->flags so that it is 0xff (match-all, not faulting).
> > However, setting the tags and flags can race with another CPU reading
> > the flags (page_to_virt()) and barriers can't help, e.g.:
> >
> > P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
> >                                   Rflags!=3D0xff
> >   Wflags=3D0xff
> >   DMB (doesn't help)
> >   Wtags=3D0
> >                                   Rtags=3D0   // fault
> >
> > Since clearing the flags in the arch code doesn't work, to do this at
> > page allocation time when __GFP_SKIP_KASAN_UNPOISON is passed.
> >
> > Thanks.
> >
> > Catalin Marinas (4):
> >   mm: kasan: Ensure the tags are visible before the tag in page-
> > >flags
> >   mm: kasan: Skip unpoisoning of user pages
> >   mm: kasan: Skip page unpoisoning only if __GFP_SKIP_KASAN_UNPOISON
> >   arm64: kasan: Revert "arm64: mte: reset the page tag in page-
> > >flags"
> >
> >  arch/arm64/kernel/hibernate.c |  5 -----
> >  arch/arm64/kernel/mte.c       |  9 ---------
> >  arch/arm64/mm/copypage.c      |  9 ---------
> >  arch/arm64/mm/fault.c         |  1 -
> >  arch/arm64/mm/mteswap.c       |  9 ---------
> >  include/linux/gfp.h           |  2 +-
> >  mm/kasan/common.c             |  3 ++-
> >  mm/page_alloc.c               | 19 ++++++++++---------
> >  8 files changed, 13 insertions(+), 44 deletions(-)
> >
>
> Hi kasan maintainers,
>
> We hit the following issue on the android-6.1 devices with MTE and HW
> tag kasan enabled.
>
> I observe that the anon flag doesn't have skip_kasan_poison and
> skip_kasan_unpoison flag and kasantag is weird.
>
> AFAIK, kasantag of anon flag needs to be 0x0.
>
> [   71.953938] [T1403598] FramePolicy:
> [name:report&]=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> =3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   71.955305] [T1403598] FramePolicy: [name:report&]BUG: KASAN:
> invalid-access in copy_page+0x10/0xd0
> [   71.956476] [T1403598] FramePolicy: [name:report&]Read at addr
> f0ffff81332a8000 by task FramePolicy/3598
> [   71.957673] [T1403598] FramePolicy: [name:report_hw_tags&]Pointer
> tag: [f0], memory tag: [ff]
> [   71.958746] [T1403598] FramePolicy: [name:report&]
> [   71.959354] [T1403598] FramePolicy: CPU: 4 PID: 3598 Comm:
> FramePolicy Tainted: G S      W  OE      6.1.0-mainline-android14-0-
> ga8a53f83b9e4 #1
> [   71.960978] [T1403598] FramePolicy: Hardware name: MT6985(ENG) (DT)
> [   71.961767] [T1403598] FramePolicy: Call trace:
> [   71.962338] [T1403598] FramePolicy:  dump_backtrace+0x108/0x158
> [   71.963097] [T1403598] FramePolicy:  show_stack+0x20/0x48
> [   71.963782] [T1403598] FramePolicy:  dump_stack_lvl+0x6c/0x88
> [   71.964512] [T1403598] FramePolicy:  print_report+0x2cc/0xa64
> [   71.965263] [T1403598] FramePolicy:  kasan_report+0xb8/0x138
> [   71.965986] [T1403598] FramePolicy:  __do_kernel_fault+0xd4/0x248
> [   71.966782] [T1403598] FramePolicy:  do_bad_area+0x38/0xe8
> [   71.967484] [T1403598] FramePolicy:  do_tag_check_fault+0x24/0x38
> [   71.968261] [T1403598] FramePolicy:  do_mem_abort+0x48/0xb0
> [   71.968973] [T1403598] FramePolicy:  el1_abort+0x44/0x68
> [   71.969646] [T1403598] FramePolicy:  el1h_64_sync_handler+0x68/0xb8
> [   71.970440] [T1403598] FramePolicy:  el1h_64_sync+0x68/0x6c
> [   71.971146] [T1403598] FramePolicy:  copy_page+0x10/0xd0
> [   71.971824] [T1403598] FramePolicy:  copy_user_highpage+0x20/0x40
> [   71.972603] [T1403598] FramePolicy:  wp_page_copy+0xd0/0x9f8
> [   71.973344] [T1403598] FramePolicy:  do_wp_page+0x374/0x3b0
> [   71.974056] [T1403598] FramePolicy:  handle_mm_fault+0x3ec/0x119c
> [   71.974833] [T1403598] FramePolicy:  do_page_fault+0x344/0x4ac
> [   71.975583] [T1403598] FramePolicy:  do_mem_abort+0x48/0xb0
> [   71.976294] [T1403598] FramePolicy:  el0_da+0x4c/0xe0
> [   71.976934] [T1403598] FramePolicy:  el0t_64_sync_handler+0xd4/0xfc
> [   71.977725] [T1403598] FramePolicy:  el0t_64_sync+0x1a0/0x1a4
> [   71.978451] [T1403598] FramePolicy: [name:report&]
> [   71.979057] [T1403598] FramePolicy: [name:report&]The buggy address
> belongs to the physical page:
> [   71.980173] [T1403598] FramePolicy:
> [name:debug&]page:fffffffe04ccaa00 refcount:14 mapcount:13
> mapping:0000000000000000 index:0x7884c74 pfn:0x1732a8
> [   71.981849] [T1403598] FramePolicy:
> [name:debug&]memcg:faffff80c0241000
> [   71.982680] [T1403598] FramePolicy: [name:debug&]anon flags:
> 0x43c000000048003e(referenced|uptodate|dirty|lru|active|swapbacked|arch
> _2|zone=3D1|kasantag=3D0xf)
> [   71.984446] [T1403598] FramePolicy: raw: 43c000000048003e
> fffffffe04b99648 fffffffe04cca308 f2ffff8103390831
> [   71.985684] [T1403598] FramePolicy: raw: 0000000007884c74
> 0000000000000000 0000000e0000000c faffff80c0241000
> [   71.986919] [T1403598] FramePolicy: [name:debug&]page dumped
> because: kasan: bad access detected
> [   71.988022] [T1403598] FramePolicy: [name:report&]
> [   71.988624] [T1403598] FramePolicy: [name:report&]Memory state
> around the buggy address:
> [   71.989641] [T1403598] FramePolicy:  ffffff81332a7e00: fe fe fe fe
> fe fe fe fe fe fe fe fe fe fe fe fe
> [   71.990811] [T1403598] FramePolicy:  ffffff81332a7f00: fe fe fe fe
> fe fe fe fe fe fe fe fe fe fe fe fe
> [   71.991982] [T1403598] FramePolicy: >ffffff81332a8000: ff ff ff ff
> f0 f0 fc fc fc fc fc fc fc f0 f0 f3
> [   71.993149] [T1403598] FramePolicy:
> [name:report&]                   ^
> [   71.993972] [T1403598] FramePolicy:  ffffff81332a8100: f3 f3 f3 f3
> f3 f3 f0 f0 f8 f8 f8 f8 f8 f8 f8 f0
> [   71.995141] [T1403598] FramePolicy:  ffffff81332a8200: f0 fb fb fb
> fb fb fb fb f0 f0 fe fe fe fe fe fe
> [   71.996332] [T1403598] FramePolicy:
> [name:report&]=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> =3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> Originally, I suspect that some userspace pages have been migrated so
> the page->flags will be lost and page->flags is re-generated by
> alloc_pages().

Hi Kuan-Ying,

There recently was a similar crash due to incorrectly implemented sampling.

Do you have the following patch in your tree?

https://android.googlesource.com/kernel/common/+/9f7f5a25f335e6e1484695da91=
80281a728db7e2

If not, please sync your 6.1 tree with the Android common kernel.
Hopefully this will fix the issue.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfu7SdVWr9O%3DNxOptuBg0eHqE526ijA4PAQgiAEYfux6A%40mail.gm=
ail.com.
