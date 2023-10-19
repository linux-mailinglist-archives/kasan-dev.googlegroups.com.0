Return-Path: <kasan-dev+bncBDK7LR5URMGRBIW5YOUQMGQE343TYUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 468D87CF349
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 10:53:56 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c520e0a9a7sf41434721fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 01:53:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697705635; cv=pass;
        d=google.com; s=arc-20160816;
        b=XHsTrNjRi2mFlR0gc/Oh5t422lVU8ISAPP1+xtqQuCZLxz2oLDENiu7/4c+MkgRkg1
         6b6O0FVp4qfEMy5ISaTCvOioO26rxGKnmnL/uwQh3i18CCuU8EFs5lS/Fre7vleviYWj
         tSOFyzz5D/FjapyEJfTm11E2hR7d/gTElknsdx06/cadee4H4VFljyaMbqt5JQm0pwPS
         Y7Qijs7SQxWguK0mYRO9TY+gWgL8nJcpeVLVpx9dV4qRmvt2Ng8q0K2VgREpEpwnQPkm
         Gtju/ZHrBmeImzm6T572hiKqievAOc7P3KOsylJwStCxlwco8jWaDTRt/OIQ61jyZz4a
         5mVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:dkim-signature
         :dkim-signature;
        bh=ORXbQKNThKTQcwFdXfne3QKhU5GH1FZ4KKJGdU4mKVc=;
        fh=04F70whAPAERnJ3lzo1Oo/yAaJ4pllNCL3ZEIND9/kA=;
        b=hXTf7Ug2AHtzvRzck/utXxZK549MdAKaZm017bCuZQ+ilvJGAJrFw/pnXLYVLTir6H
         vYT3AMhWxTxbkZM3DOjfE35V1jttLhvN1sjuUs7SjrtaIgU+yucP+2HZwceQ66q/yacd
         T/3Z219PL47NVs6mYNWfAh91nstfvtyzyintFaVFZMc4wvIWLGNt42HWkjLoC/HVsRUU
         7ga9xeocPiu0eXoO7Ic8Go2pGxtDCFDXzpkx+7HDYeXNTHb1laZg9BKgW9vkS5WGt1nj
         08dj88lezQUPnPDCmpR6Ngg/ej1f1EK6wBXZy31fLWf0hYqdA4AcKkwB2p0YGoemAjB6
         IZjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HcznXIlC;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697705635; x=1698310435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ORXbQKNThKTQcwFdXfne3QKhU5GH1FZ4KKJGdU4mKVc=;
        b=N0g5ThBb1cepJY0wfzEAkGBj0q2CNVckVBev/GpGS3vJmyEKYH8lsV435q7Na44OmT
         TaAyYDaMm8BL+N81tU5x+qkE4fUhSt4UOkYGwsfDVpsXBjU3VrW4m2u/TGAhWQb1S+un
         9nKdS8TEe9UL+xbPcFOAYddaluLbFpwyheTLOgsgkRDq2ENLRPOYLraXCBF5qiPYuIB/
         2gaXsdFfFg1qlakwJS+bPmrrooIu5o8JXx1F9M3LjC6faGJmpqmVqi2GaiEKyBnFtqb4
         ml6vIOZ4PaJ6LiEIpAPI/Vlv8Xg/AsoqXNITmSw6pxLaY/BTcFFas50fVg18CrHz+iQb
         7svg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1697705635; x=1698310435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ORXbQKNThKTQcwFdXfne3QKhU5GH1FZ4KKJGdU4mKVc=;
        b=XuvrXMsONfMvL2oEgffP81s9E+gFUGVT0UbHV32R0X56AFeh7l5s9Kz6fQKL/o0fGX
         oQ12Bimjr1OAPCo6XiR4qfWAeQnKF/oNcl2YYK28gckOhTbVOLE0qnQP/wXndLSESArY
         DO46srPk5d4J1qgVrpR7/R8ectHGkL7Tkeg83ElL8DRmB+xEvjXy93v9kBfakPWKTo6/
         cxgPLiakfFcABS3cmKKAjYYFf8DD/wezaaBg5riqjz0S/6ldMM5WYpc9vW0Qd+FwZ+Ld
         oUFmUsEj5O3ykxkGrWTvnWaxYCoPtIqNbgdmNXPMtmoNpLa4bjbCHMyP0i2Hm173t4/r
         Ja5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697705635; x=1698310435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ORXbQKNThKTQcwFdXfne3QKhU5GH1FZ4KKJGdU4mKVc=;
        b=LqvJN2gXoclfuj9xvUr9saR61XXYn+PwNQmmtMlLqkLaFguYHxUdurXTfi1wRfDQMI
         VaAoXXJxGrZVbXxhmUDTlsJUQQJxX5QN6HyCsZb9zbOBuCW6fnOA+LBaBp2a6pWLi1ss
         ljtAo0YnTA6ndP72aHyzCOirBa0UjBJRaPdeySq8kqDeeZai/yQvnNUA9bou+C5/ZMHX
         zbtXm+QCV53LIN7wWIwD51/9smUTMsxGyJbrUVCqLbXAv6Uhne2G5TL5UsKMRpGQoNVL
         ZNFP3uYiSajSOgQm1u8sxgqgyPsvRsndqSAS2lF7qd0qSKAE5JnZfRiBap4wyK9zMKr2
         6Y5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyusnY+qjUFdVmLY80+FCBJvs742WSJC7q1pigCZDjCHDpj5GZl
	dVQByddpWwRzZVsBO3Fk/CA=
X-Google-Smtp-Source: AGHT+IFbEYwL2BzsyKdnc+NpIJBdCXKZZZQD2Zo3+ySpUrbitlQgZmmdmyp06zE3LiPIbp9aUtFg8A==
X-Received: by 2002:a05:651c:504:b0:2c1:375a:b37c with SMTP id o4-20020a05651c050400b002c1375ab37cmr890274ljp.40.1697705634932;
        Thu, 19 Oct 2023 01:53:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e32:0:b0:2bf:f55d:1df9 with SMTP id r18-20020a2e8e32000000b002bff55d1df9ls151831ljk.1.-pod-prod-05-eu;
 Thu, 19 Oct 2023 01:53:53 -0700 (PDT)
X-Received: by 2002:a2e:804f:0:b0:2c4:fe0a:dc3a with SMTP id p15-20020a2e804f000000b002c4fe0adc3amr893039ljg.47.1697705632979;
        Thu, 19 Oct 2023 01:53:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697705632; cv=none;
        d=google.com; s=arc-20160816;
        b=kMeuMegpG5ketQ52mQR1poBiK97tZ/Pk+0OSA3twfzxSacJVdMDA67yl7Je2d91aLw
         scYI/run8jmchzZkdoMLQp6MKJei0IBB1sGKI4aPNUE5P5/q+nReXH3GMGsEUwIQFZ5D
         SV4/Wt1H4DGImiCs5UhZ4gX5v1Vra2LWHDGe613+SzSc6Jr8x6d01UbprmBo8pvSjGx5
         hj2K6vZiYlUqCs5XKwywlh6o2oksFBnsWtFYBY25cgZm9J4iNbdQg/dBuaYynk3/8mHI
         ifo6aU+ng7IRYu1NbHN/Jw6WfHfD2d5FxaohfC01LJ+Wvvi+7aWXdovqHydKxJPZGtIv
         2HyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from
         :dkim-signature;
        bh=f/xe37AAAQA2ZjgK4jQ8QVjPYE3IU1vje86Gnuet33Y=;
        fh=04F70whAPAERnJ3lzo1Oo/yAaJ4pllNCL3ZEIND9/kA=;
        b=C7u27BEsUB5gcGO2/dfxn4IqIOMPLNgkEfL4sNNDE0A8gA3sXjfiL7TJ9r3YhpM3sQ
         tsYJK2vSLnY64D7rjRrsb6Kg8zTJeLaPkgTEXmCi02qD/HmvbIhh7UvSJGJauTnQ+SB6
         8tE7s+61CSPniKRGRVTxG6iSFrrYY1fPQsg0PbpTfrUeFwFuaRISIoYimmTuiZjlFU9n
         bPMP2btY4zFtzrPKwxz2iW0C1uAhAJBSpBe1ndO1leNtb/kyGQKW1exc+A0C3DOadrSZ
         HjYixrMzh/XmVWD7CWjX+mVj405OYUaFpuZGpqB6gZfWpsBJYynTxAfFoAyfufWLN+ln
         rnJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HcznXIlC;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id y15-20020a05651c154f00b002c17e2e5fb9si226223ljp.5.2023.10.19.01.53.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Oct 2023 01:53:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-504a7f9204eso10309856e87.3
        for <kasan-dev@googlegroups.com>; Thu, 19 Oct 2023 01:53:52 -0700 (PDT)
X-Received: by 2002:a05:6512:3c9f:b0:4f8:7513:8cac with SMTP id h31-20020a0565123c9f00b004f875138cacmr993483lfv.48.1697705632173;
        Thu, 19 Oct 2023 01:53:52 -0700 (PDT)
Received: from pc636 (host-90-233-215-212.mobileonline.telia.com. [90.233.215.212])
        by smtp.gmail.com with ESMTPSA id r14-20020ac25f8e000000b00503fb2e5594sm1007668lfe.211.2023.10.19.01.53.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Oct 2023 01:53:51 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Thu, 19 Oct 2023 10:53:48 +0200
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@infradead.org>,
	Lorenzo Stoakes <lstoakes@gmail.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH -rfc 0/3] mm: kasan: fix softlock when populate or
 depopulate pte
Message-ID: <ZTDunPbSDg29l8so@pc636>
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
 <4e2e075f-b74c-4daf-bf1a-f83fced742c4@huawei.com>
 <dd39cb3e-b184-407d-b74f-5b90a7983c99@huawei.com>
 <CANpmjNPY5NgvnfDcu1GFP-K0rCgiB4_+TqL4-p_ER-bLYvw26A@mail.gmail.com>
 <5b33515b-5fd2-4dc7-9778-e321484d2427@huawei.com>
 <ZTDJ8t9ug3Q6E8GG@pc636>
 <7ab8839b-8f88-406e-b6e1-2c69c8967d4e@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <7ab8839b-8f88-406e-b6e1-2c69c8967d4e@huawei.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HcznXIlC;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Oct 19, 2023 at 03:26:48PM +0800, Kefeng Wang wrote:
>=20
>=20
> On 2023/10/19 14:17, Uladzislau Rezki wrote:
> > On Thu, Oct 19, 2023 at 09:40:10AM +0800, Kefeng Wang wrote:
> > >=20
> > >=20
> > > On 2023/10/19 0:37, Marco Elver wrote:
> > > > On Wed, 18 Oct 2023 at 16:16, 'Kefeng Wang' via kasan-dev
> > > > <kasan-dev@googlegroups.com> wrote:
> > > > >=20
> > > > > The issue is easy to reproduced with large vmalloc, kindly ping..=
.
> > > > >=20
> > > > > On 2023/9/15 8:58, Kefeng Wang wrote:
> > > > > > Hi All=EF=BC=8C any suggest or comments=EF=BC=8Cmany thanks.
> > > > > >=20
> > > > > > On 2023/9/6 20:42, Kefeng Wang wrote:
> > > > > > > This is a RFC, even patch3 is a hack to fix the softlock issu=
e when
> > > > > > > populate or depopulate pte with large region, looking forward=
 to your
> > > > > > > reply and advise, thanks.
> > > > > >=20
> > > > > > Here is full stack=EF=BC=8Cfor populate pte=EF=BC=8C
> > > > > >=20
> > > > > > [    C3] watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [ins=
mod:458]
> > > > > > [    C3] Modules linked in: test(OE+)
> > > > > > [    C3] irq event stamp: 320776
> > > > > > [    C3] hardirqs last  enabled at (320775): [<ffff8000815a0c98=
>]
> > > > > > _raw_spin_unlock_irqrestore+0x98/0xb8
> > > > > > [    C3] hardirqs last disabled at (320776): [<ffff8000815816e0=
>]
> > > > > > el1_interrupt+0x38/0xa8
> > > > > > [    C3] softirqs last  enabled at (318174): [<ffff800080040ba8=
>]
> > > > > > __do_softirq+0x658/0x7ac
> > > > > > [    C3] softirqs last disabled at (318169): [<ffff800080047fd8=
>]
> > > > > > ____do_softirq+0x18/0x30
> > > > > > [    C3] CPU: 3 PID: 458 Comm: insmod Tainted: G           OE 6=
.5.0+ #595
> > > > > > [    C3] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 0=
2/06/2015
> > > > > > [    C3] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS =
BTYPE=3D--)
> > > > > > [    C3] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
> > > > > > [    C3] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
> > > > > > [    C3] sp : ffff800093386d70
> > > > > > [    C3] x29: ffff800093386d70 x28: 0000000000000801 x27: ffff0=
007ffffa9c0
> > > > > > [    C3] x26: 0000000000000000 x25: 000000000000003f x24: fffff=
c0004353708
> > > > > > [    C3] x23: ffff0006d476bad8 x22: fffffc0004353748 x21: 00000=
00000000000
> > > > > > [    C3] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 00000=
00000000000
> > > > > > [    C3] x17: ffff80008024e7fc x16: ffff80008055a8f0 x15: ffff8=
0008024ec60
> > > > > > [    C3] x14: ffff80008024ead0 x13: ffff80008024e7fc x12: ffff6=
000fffff5f9
> > > > > > [    C3] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe=
000fffff5f8
> > > > > > [    C3] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff8=
00000000000
> > > > > > [    C3] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff7=
00012670d70
> > > > > > [    C3] x2 : 0000000000000001 x1 : c9a5dbfae610fa24 x0 : 00000=
0000004e507
> > > > > > [    C3] Call trace:
> > > > > > [    C3]  _raw_spin_unlock_irqrestore+0x50/0xb8
> > > > > > [    C3]  rmqueue_bulk+0x434/0x6b8
> > > > > > [    C3]  get_page_from_freelist+0xdd4/0x1680
> > > > > > [    C3]  __alloc_pages+0x244/0x508
> > > > > > [    C3]  alloc_pages+0xf0/0x218
> > > > > > [    C3]  __get_free_pages+0x1c/0x50
> > > > > > [    C3]  kasan_populate_vmalloc_pte+0x30/0x188
> > > > > > [    C3]  __apply_to_page_range+0x3ec/0x650
> > > > > > [    C3]  apply_to_page_range+0x1c/0x30
> > > > > > [    C3]  kasan_populate_vmalloc+0x60/0x70
> > > > > > [    C3]  alloc_vmap_area.part.67+0x328/0xe50
> > > > > > [    C3]  alloc_vmap_area+0x4c/0x78
> > > > > > [    C3]  __get_vm_area_node.constprop.76+0x130/0x240
> > > > > > [    C3]  __vmalloc_node_range+0x12c/0x340
> > > > > > [    C3]  __vmalloc_node+0x8c/0xb0
> > > > > > [    C3]  vmalloc+0x2c/0x40
> > > > > > [    C3]  show_mem_init+0x1c/0xff8 [test]
> > > > > > [    C3]  do_one_initcall+0xe4/0x500
> > > > > > [    C3]  do_init_module+0x100/0x358
> > > > > > [    C3]  load_module+0x2e64/0x2fc8
> > > > > > [    C3]  init_module_from_file+0xec/0x148
> > > > > > [    C3]  idempotent_init_module+0x278/0x380
> > > > > > [    C3]  __arm64_sys_finit_module+0x88/0xf8
> > > > > > [    C3]  invoke_syscall+0x64/0x188
> > > > > > [    C3]  el0_svc_common.constprop.1+0xec/0x198
> > > > > > [    C3]  do_el0_svc+0x48/0xc8
> > > > > > [    C3]  el0_svc+0x3c/0xe8
> > > > > > [    C3]  el0t_64_sync_handler+0xa0/0xc8
> > > > > > [    C3]  el0t_64_sync+0x188/0x190
> > > > > >=20
This trace is stuck in the rmqueue_bulk() because you request a
huge alloc size. It has nothing to do with free_vmap_area_lock,
it is about bulk allocator. It gets stuck to accomplish such
demand.


> > > > > > and for depopuldate pte=EF=BC=8C
> > > > > >=20
> > > > > > [    C6] watchdog: BUG: soft lockup - CPU#6 stuck for 48s! [kwo=
rker/6:1:59]
> > > > > > [    C6] Modules linked in: test(OE+)
> > > > > > [    C6] irq event stamp: 39458
> > > > > > [    C6] hardirqs last  enabled at (39457): [<ffff8000815a0c98>=
]
> > > > > > _raw_spin_unlock_irqrestore+0x98/0xb8
> > > > > > [    C6] hardirqs last disabled at (39458): [<ffff8000815816e0>=
]
> > > > > > el1_interrupt+0x38/0xa8
> > > > > > [    C6] softirqs last  enabled at (39420): [<ffff800080040ba8>=
]
> > > > > > __do_softirq+0x658/0x7ac
> > > > > > [    C6] softirqs last disabled at (39415): [<ffff800080047fd8>=
]
> > > > > > ____do_softirq+0x18/0x30
> > > > > > [    C6] CPU: 6 PID: 59 Comm: kworker/6:1 Tainted: G           =
OEL
> > > > > > 6.5.0+ #595
> > > > > > [    C6] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 0=
2/06/2015
> > > > > > [    C6] Workqueue: events drain_vmap_area_work
> > > > > > [    C6] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS =
BTYPE=3D--)
> > > > > > [    C6] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
> > > > > > [    C6] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
> > > > > > [    C6] sp : ffff80008fe676b0
> > > > > > [    C6] x29: ffff80008fe676b0 x28: fffffc000601d310 x27: ffff0=
00edf5dfa80
> > > > > > [    C6] x26: ffff000edf5dfad8 x25: 0000000000000000 x24: 00000=
00000000006
> > > > > > [    C6] x23: ffff000edf5dfad4 x22: 0000000000000000 x21: 00000=
00000000006
> > > > > > [    C6] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 00000=
00000000000
> > > > > > [    C6] x17: ffff8000805544b8 x16: ffff800080553d94 x15: ffff8=
000805c11b0
> > > > > > [    C6] x14: ffff8000805baeb0 x13: ffff800080047e10 x12: ffff6=
000fffff5f9
> > > > > > [    C6] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe=
000fffff5f8
> > > > > > [    C6] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff8=
00000000000
> > > > > > [    C6] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff7=
00011fcce98
> > > > > > [    C6] x2 : 0000000000000001 x1 : cf09d5450e2b4f7f x0 : 00000=
00000009a21
> > > > > > [    C6] Call trace:
> > > > > > [    C6]  _raw_spin_unlock_irqrestore+0x50/0xb8
> > > > > > [    C6]  free_pcppages_bulk+0x2bc/0x3e0
> > > > > > [    C6]  free_unref_page_commit+0x1fc/0x290
> > > > > > [    C6]  free_unref_page+0x184/0x250
> > > > > > [    C6]  __free_pages+0x154/0x1a0
> > > > > > [    C6]  free_pages+0x88/0xb0
> > > > > > [    C6]  kasan_depopulate_vmalloc_pte+0x58/0x80
> > > > > > [    C6]  __apply_to_page_range+0x3ec/0x650
> > > > > > [    C6]  apply_to_existing_page_range+0x1c/0x30
> > > > > > [    C6]  kasan_release_vmalloc+0xa4/0x118
> > > > > > [    C6]  __purge_vmap_area_lazy+0x4f4/0xe30
> > > > > > [    C6]  drain_vmap_area_work+0x60/0xc0
> > > > > > [    C6]  process_one_work+0x4cc/0xa38
> > > > > > [    C6]  worker_thread+0x240/0x638
> > > > > > [    C6]  kthread+0x1c8/0x1e0
> > > > > > [    C6]  ret_from_fork+0x10/0x20
> > > > > >=20
>=20
> See Call Trace of softlock, when map/unmap the vmalloc buf, the kasan wil=
l
> populate and depopulate vmalloc pte, those will spend more time than
> no-kasan kernel, for unmap, and there is already a cond_resched_lock() in
> __purge_vmap_area_lazy(), but with more time consumed under
> spinlock(free_vmap_area_lock), and we couldn't add cond_resched_lock in
> kasan_depopulate_vmalloc_pte(), so if spin lock converted to mutex lock, =
we
> could add a cond_resched into kasan depopulate, this is why make such
> conversion if kasan enabled, but this
> conversion maybe not correct, any better solution?
>=20
I have at least below thoughts:

a) Add a max allowed threshold that user can request over vmalloc() call.
  I do not think ~40G is a correct request.

b) This can fix unmap path:=20

<snip>
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index ef8599d394fd..988735da5c5c 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -1723,7 +1723,6 @@ static void purge_fragmented_blocks_allcpus(void);
  */
 static bool __purge_vmap_area_lazy(unsigned long start, unsigned long end)
 {
-	unsigned long resched_threshold;
 	unsigned int num_purged_areas =3D 0;
 	struct list_head local_purge_list;
 	struct vmap_area *va, *n_va;
@@ -1747,36 +1746,32 @@ static bool __purge_vmap_area_lazy(unsigned long st=
art, unsigned long end)
 			struct vmap_area, list)->va_end);
=20
 	flush_tlb_kernel_range(start, end);
-	resched_threshold =3D lazy_max_pages() << 1;
=20
-	spin_lock(&free_vmap_area_lock);
 	list_for_each_entry_safe(va, n_va, &local_purge_list, list) {
 		unsigned long nr =3D (va->va_end - va->va_start) >> PAGE_SHIFT;
 		unsigned long orig_start =3D va->va_start;
 		unsigned long orig_end =3D va->va_end;
=20
+		if (is_vmalloc_or_module_addr((void *)orig_start))
+			kasan_release_vmalloc(orig_start, orig_end,
+					      va->va_start, va->va_end);
+
 		/*
 		 * Finally insert or merge lazily-freed area. It is
 		 * detached and there is no need to "unlink" it from
 		 * anything.
 		 */
+		spin_lock(&free_vmap_area_lock);
 		va =3D merge_or_add_vmap_area_augment(va, &free_vmap_area_root,
 				&free_vmap_area_list);
+		spin_unlock(&free_vmap_area_lock);
=20
 		if (!va)
 			continue;
=20
-		if (is_vmalloc_or_module_addr((void *)orig_start))
-			kasan_release_vmalloc(orig_start, orig_end,
-					      va->va_start, va->va_end);
-
 		atomic_long_sub(nr, &vmap_lazy_nr);
 		num_purged_areas++;
-
-		if (atomic_long_read(&vmap_lazy_nr) < resched_threshold)
-			cond_resched_lock(&free_vmap_area_lock);
 	}
-	spin_unlock(&free_vmap_area_lock);
=20
 out:
 	trace_purge_vmap_area_lazy(start, end, num_purged_areas);
<snip>

c) bulk-path i have not checked, but on a high level kasan_populate_vmalloc=
()
should take a breath between requests.

--
Uladzislau Rezki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZTDunPbSDg29l8so%40pc636.
