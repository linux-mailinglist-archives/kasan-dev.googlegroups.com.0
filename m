Return-Path: <kasan-dev+bncBDK7LR5URMGRB54TYOUQMGQEXMZJZPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CED37CEFFB
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 08:17:29 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-507a3ae32besf5154863e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 23:17:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697696249; cv=pass;
        d=google.com; s=arc-20160816;
        b=ys/xDXq+EP+V/UfotC//q0k24Wq8gXBSuTz0Jxjn0VRDoXfMMna1ELHcDZltpsQv0z
         YeYqwc+yILfKPLppNiepOEzheoyvYmrBmPtXo0/f/GiHlSWmqB3f8nO83a+k7lzcwBKW
         ZLiA9f36pkiho0pQ8gwDod6ikhR4sbFM3qJcaupgPFYiTai+O6C5+GM8GyDFpk7t6uv8
         PivIileixl/NNexSXlYRemxQFr577+ZX8YhiB6+XrsGQB2fPdyK9NAvtgak2wnhW7ub+
         hMdOQeA3Hz3jlkIKDr6Fp7k6WAMhIdSRbM3qHDQAHlN1mVw55AvOqlaYajJe/l57fnTx
         owSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:dkim-signature
         :dkim-signature;
        bh=EvSvtbVtRu0K57QW0iD3GU9NZUU4oHX5fkgZWAfOak4=;
        fh=J7QPmFAQ5mbQApoDRw3OfS6W0YZRCJ8cYTWTm9APPNc=;
        b=Ub3Y1qI7jppy0q0uhEiBz+9Vj5B5ct5oMNX46E2icQf0hHqeSNwYJ+Q+8GJoJ9auVA
         mDdH7H2v0IX93zaAt5JXarokKXf0C5BfcNxXeopTMthMHIOFjfdcNi7Gv9CD4Bs+M5yy
         PEkZSmHo1c8iC5jZFFQQZtKefXuWbsto6sfDNF3VjQznU46KUM6EU9p/XU69uExbifdX
         l/cxbL+4BK0zwbPS55jgba5XHht+FfFsigTuhrkp6sJLAfICpSpumTT2TMLvrHDAPilC
         8RQNXTXpBHKRj5QSzvtodgkLl8r8GuS5ar9867+igqCSFwsuW/LjTvhmtddCnKAxYu1B
         Q0qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=k+3lau8c;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697696249; x=1698301049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EvSvtbVtRu0K57QW0iD3GU9NZUU4oHX5fkgZWAfOak4=;
        b=khXrVJy6ulRbhfODYNiBgLnGHA/PSnYAvuEXljDy3yOkhqyGup2tdFvJgrN8Ns+Sak
         0NedqTTfJtBqQorcRiARB5JPwDCo9CFBJ0GNrWVUGmpp471+xFP0z41bH49MdI/3lgqo
         PSDZNez6KRVt0onbhP4v8lUwN8z+bPPnCIkE2OsED8YGllABtUvD1YVsfEHZbq36vipV
         mZvAo2qNKbte0q84Id6QX3WacSerL7A6mgeIN/L6A3wOfwM3wR0ZDgmq2W8Gy05RiXMO
         cnhlTYFG4hHzm1mlvQYU7HvHkzjSVoGWFsFQW+KS1c3UzSiWSYzuUWdGW3aLO8wMYSaB
         BYZQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1697696249; x=1698301049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=EvSvtbVtRu0K57QW0iD3GU9NZUU4oHX5fkgZWAfOak4=;
        b=WpsPeeP0dFYa7G2CrCkAv0YNDKoHkWOTmiyiP0FeKBMKlOg0mDsIyYcCIOozdTaUz5
         rnZo4KH4+E6x6cjVVyhC1xuVuSx8z7A5IBE1Gukf+Rq9yiO8P+XwmDjCHH+WUBfzRj49
         FH1t8DrDyE//mIfoM59ur2r0m/aNzxewNLuLhJsfAVYrT5VJb3dnBGrBkghqAAOKhhGD
         fhGepb+vnB6AG/xsY3g9Wjt0lJoxrBxmZNCBCXYolwZRptK2uYfS2LC1ZhSCklgmXsQe
         LyhiBjlLpM3VoF7hqmO/YuhStmiQu8TI2ejrN3W9Uo5/sTup4tWfKwCi8DG/MrSW2lVH
         CrvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697696249; x=1698301049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EvSvtbVtRu0K57QW0iD3GU9NZUU4oHX5fkgZWAfOak4=;
        b=Iy0qoPFmVn/1XhGsqk/TFMko2kAV7AQFm01GrqA5ZjZDvASyNncDQAhb4WoxDTWLEU
         ciTXigtLia0MZXLv+ce2D76dUec7vM0oUEXv7ZW1zjus8JozaOiR2ZEj6HRoIi13lNMB
         dGTW+n2TV1J69jR7Xa3HuuhCIYrJdgJsGXKVJ9D2Fi+Lg5h0NnFNF1tqJF7t2iS79MJJ
         FWh2Q9axpG3LAvA2UXhLSNEvJyOLm4qeeq2hZr4Ru07X2fYSNf+YUzhKbfjs5DEk+6LR
         jma+llYzJFG5X7ux99GVKkT7JvNOqYavHXmobrO5BwIIZImDR4xmR4cXVYKwzsPJqqnM
         FaOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwRuP4ONpA5Vhjzpgl+zDbVPT6npBkRdg5AzRpEtBS3db9+y1M8
	8Ut9e2IZl1RlntmDTrUIKb4=
X-Google-Smtp-Source: AGHT+IGAFiIVvldTcwCrsip4b2m1oRqEqJhY+HVgT6c5e5+EEFFuwvRJAzRBUtf7y4uAou4o4uprRQ==
X-Received: by 2002:a05:6512:2203:b0:503:95d:f2bd with SMTP id h3-20020a056512220300b00503095df2bdmr847295lfu.34.1697696248150;
        Wed, 18 Oct 2023 23:17:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5de2:0:b0:503:7ac:19f3 with SMTP id z2-20020ac25de2000000b0050307ac19f3ls494084lfq.0.-pod-prod-07-eu;
 Wed, 18 Oct 2023 23:17:26 -0700 (PDT)
X-Received: by 2002:a05:6512:2512:b0:505:6ef8:2544 with SMTP id be18-20020a056512251200b005056ef82544mr547299lfb.63.1697696246093;
        Wed, 18 Oct 2023 23:17:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697696246; cv=none;
        d=google.com; s=arc-20160816;
        b=r8ttOn80r4YDLquOsbK+4o6a6FO1FEyzISARpwgQPRXZ9J+FAcatD5tiD5nbT3823v
         Gni+LwUdRlrzZte33AIY39PJo+nIOjx8Sz2RrfCGwJ1x1JOz2JDVXu/rhh0tiFaeZbJH
         oCuJi0pTmyQnP+75Ck6dk3+mu6gSFzbxNgEQMzoZupD1juDmWoZj/myykCzECAncBQ9x
         1g9mg8dkM+PnxuuFspZJoZK70sJigpjxNMi7Ht09vFZUNSaUnR/A2Oh8EP63rzdxya0l
         jHEs29xaD9pgmetXppvJ5ouW4934nO2V/B0AnURHdggV9/EiPUvIyymDISHmteyiAhO0
         ZT9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from
         :dkim-signature;
        bh=ZFs1yV2RxCK2OxD+c4DIu8WP+BE3ENkrqmCLTOe10Ww=;
        fh=J7QPmFAQ5mbQApoDRw3OfS6W0YZRCJ8cYTWTm9APPNc=;
        b=FHYn1A31NEtBUSkRasH3RBBQILZX3EkeFsP8zBCHacpSBQwGgAAF00huv1ZR+YlDsO
         9hQSiquyz+NXSeuNGRo6ohjHsxIbV4gWLlV64dcO6PVZwHRmoV0OkSahOqKsUOo4ypkN
         BnjSigF39cXv2YuDTL8V/lf/vMY/cR5A4OC0yT7il0+PvG78ier40iKfYjbknPtFJMdj
         0nA/1EBpsiRtqeL/GPZ4T+GK6ZlxGKukHvvwDHVuyAZ0cTqTheOuh5ob7wk8OjgGNFV0
         OL+KOShtA/QGq828Vab3dwj5NwRYJm7F6H1Hbcu/kvLFtMewiD0ZlHzkIzFHB7T09HXu
         KTRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=k+3lau8c;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id d13-20020a0565123d0d00b005068bf0b332si205092lfv.1.2023.10.18.23.17.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Oct 2023 23:17:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-2c5071165d5so20644621fa.0
        for <kasan-dev@googlegroups.com>; Wed, 18 Oct 2023 23:17:26 -0700 (PDT)
X-Received: by 2002:a2e:9584:0:b0:2bf:f670:36dc with SMTP id w4-20020a2e9584000000b002bff67036dcmr655263ljh.49.1697696245391;
        Wed, 18 Oct 2023 23:17:25 -0700 (PDT)
Received: from pc636 ([155.137.26.201])
        by smtp.gmail.com with ESMTPSA id a30-20020a2ebe9e000000b002b724063010sm976341ljr.47.2023.10.18.23.17.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Oct 2023 23:17:24 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Thu, 19 Oct 2023 08:17:22 +0200
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>,
	Lorenzo Stoakes <lstoakes@gmail.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH -rfc 0/3] mm: kasan: fix softlock when populate or
 depopulate pte
Message-ID: <ZTDJ8t9ug3Q6E8GG@pc636>
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
 <4e2e075f-b74c-4daf-bf1a-f83fced742c4@huawei.com>
 <dd39cb3e-b184-407d-b74f-5b90a7983c99@huawei.com>
 <CANpmjNPY5NgvnfDcu1GFP-K0rCgiB4_+TqL4-p_ER-bLYvw26A@mail.gmail.com>
 <5b33515b-5fd2-4dc7-9778-e321484d2427@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <5b33515b-5fd2-4dc7-9778-e321484d2427@huawei.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=k+3lau8c;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::232 as
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

On Thu, Oct 19, 2023 at 09:40:10AM +0800, Kefeng Wang wrote:
>=20
>=20
> On 2023/10/19 0:37, Marco Elver wrote:
> > On Wed, 18 Oct 2023 at 16:16, 'Kefeng Wang' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >=20
> > > The issue is easy to reproduced with large vmalloc, kindly ping...
> > >=20
> > > On 2023/9/15 8:58, Kefeng Wang wrote:
> > > > Hi All=EF=BC=8C any suggest or comments=EF=BC=8Cmany thanks.
> > > >=20
> > > > On 2023/9/6 20:42, Kefeng Wang wrote:
> > > > > This is a RFC, even patch3 is a hack to fix the softlock issue wh=
en
> > > > > populate or depopulate pte with large region, looking forward to =
your
> > > > > reply and advise, thanks.
> > > >=20
> > > > Here is full stack=EF=BC=8Cfor populate pte=EF=BC=8C
> > > >=20
> > > > [    C3] watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [insmod:=
458]
> > > > [    C3] Modules linked in: test(OE+)
> > > > [    C3] irq event stamp: 320776
> > > > [    C3] hardirqs last  enabled at (320775): [<ffff8000815a0c98>]
> > > > _raw_spin_unlock_irqrestore+0x98/0xb8
> > > > [    C3] hardirqs last disabled at (320776): [<ffff8000815816e0>]
> > > > el1_interrupt+0x38/0xa8
> > > > [    C3] softirqs last  enabled at (318174): [<ffff800080040ba8>]
> > > > __do_softirq+0x658/0x7ac
> > > > [    C3] softirqs last disabled at (318169): [<ffff800080047fd8>]
> > > > ____do_softirq+0x18/0x30
> > > > [    C3] CPU: 3 PID: 458 Comm: insmod Tainted: G           OE 6.5.0=
+ #595
> > > > [    C3] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06=
/2015
> > > > [    C3] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYP=
E=3D--)
> > > > [    C3] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
> > > > [    C3] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
> > > > [    C3] sp : ffff800093386d70
> > > > [    C3] x29: ffff800093386d70 x28: 0000000000000801 x27: ffff0007f=
fffa9c0
> > > > [    C3] x26: 0000000000000000 x25: 000000000000003f x24: fffffc000=
4353708
> > > > [    C3] x23: ffff0006d476bad8 x22: fffffc0004353748 x21: 000000000=
0000000
> > > > [    C3] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 000000000=
0000000
> > > > [    C3] x17: ffff80008024e7fc x16: ffff80008055a8f0 x15: ffff80008=
024ec60
> > > > [    C3] x14: ffff80008024ead0 x13: ffff80008024e7fc x12: ffff6000f=
ffff5f9
> > > > [    C3] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000f=
ffff5f8
> > > > [    C3] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff80000=
0000000
> > > > [    C3] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff70001=
2670d70
> > > > [    C3] x2 : 0000000000000001 x1 : c9a5dbfae610fa24 x0 : 000000000=
004e507
> > > > [    C3] Call trace:
> > > > [    C3]  _raw_spin_unlock_irqrestore+0x50/0xb8
> > > > [    C3]  rmqueue_bulk+0x434/0x6b8
> > > > [    C3]  get_page_from_freelist+0xdd4/0x1680
> > > > [    C3]  __alloc_pages+0x244/0x508
> > > > [    C3]  alloc_pages+0xf0/0x218
> > > > [    C3]  __get_free_pages+0x1c/0x50
> > > > [    C3]  kasan_populate_vmalloc_pte+0x30/0x188
> > > > [    C3]  __apply_to_page_range+0x3ec/0x650
> > > > [    C3]  apply_to_page_range+0x1c/0x30
> > > > [    C3]  kasan_populate_vmalloc+0x60/0x70
> > > > [    C3]  alloc_vmap_area.part.67+0x328/0xe50
> > > > [    C3]  alloc_vmap_area+0x4c/0x78
> > > > [    C3]  __get_vm_area_node.constprop.76+0x130/0x240
> > > > [    C3]  __vmalloc_node_range+0x12c/0x340
> > > > [    C3]  __vmalloc_node+0x8c/0xb0
> > > > [    C3]  vmalloc+0x2c/0x40
> > > > [    C3]  show_mem_init+0x1c/0xff8 [test]
> > > > [    C3]  do_one_initcall+0xe4/0x500
> > > > [    C3]  do_init_module+0x100/0x358
> > > > [    C3]  load_module+0x2e64/0x2fc8
> > > > [    C3]  init_module_from_file+0xec/0x148
> > > > [    C3]  idempotent_init_module+0x278/0x380
> > > > [    C3]  __arm64_sys_finit_module+0x88/0xf8
> > > > [    C3]  invoke_syscall+0x64/0x188
> > > > [    C3]  el0_svc_common.constprop.1+0xec/0x198
> > > > [    C3]  do_el0_svc+0x48/0xc8
> > > > [    C3]  el0_svc+0x3c/0xe8
> > > > [    C3]  el0t_64_sync_handler+0xa0/0xc8
> > > > [    C3]  el0t_64_sync+0x188/0x190
> > > >=20
> > > > and for depopuldate pte=EF=BC=8C
> > > >=20
> > > > [    C6] watchdog: BUG: soft lockup - CPU#6 stuck for 48s! [kworker=
/6:1:59]
> > > > [    C6] Modules linked in: test(OE+)
> > > > [    C6] irq event stamp: 39458
> > > > [    C6] hardirqs last  enabled at (39457): [<ffff8000815a0c98>]
> > > > _raw_spin_unlock_irqrestore+0x98/0xb8
> > > > [    C6] hardirqs last disabled at (39458): [<ffff8000815816e0>]
> > > > el1_interrupt+0x38/0xa8
> > > > [    C6] softirqs last  enabled at (39420): [<ffff800080040ba8>]
> > > > __do_softirq+0x658/0x7ac
> > > > [    C6] softirqs last disabled at (39415): [<ffff800080047fd8>]
> > > > ____do_softirq+0x18/0x30
> > > > [    C6] CPU: 6 PID: 59 Comm: kworker/6:1 Tainted: G           OEL
> > > > 6.5.0+ #595
> > > > [    C6] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06=
/2015
> > > > [    C6] Workqueue: events drain_vmap_area_work
> > > > [    C6] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYP=
E=3D--)
> > > > [    C6] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
> > > > [    C6] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
> > > > [    C6] sp : ffff80008fe676b0
> > > > [    C6] x29: ffff80008fe676b0 x28: fffffc000601d310 x27: ffff000ed=
f5dfa80
> > > > [    C6] x26: ffff000edf5dfad8 x25: 0000000000000000 x24: 000000000=
0000006
> > > > [    C6] x23: ffff000edf5dfad4 x22: 0000000000000000 x21: 000000000=
0000006
> > > > [    C6] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 000000000=
0000000
> > > > [    C6] x17: ffff8000805544b8 x16: ffff800080553d94 x15: ffff80008=
05c11b0
> > > > [    C6] x14: ffff8000805baeb0 x13: ffff800080047e10 x12: ffff6000f=
ffff5f9
> > > > [    C6] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000f=
ffff5f8
> > > > [    C6] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff80000=
0000000
> > > > [    C6] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff70001=
1fcce98
> > > > [    C6] x2 : 0000000000000001 x1 : cf09d5450e2b4f7f x0 : 000000000=
0009a21
> > > > [    C6] Call trace:
> > > > [    C6]  _raw_spin_unlock_irqrestore+0x50/0xb8
> > > > [    C6]  free_pcppages_bulk+0x2bc/0x3e0
> > > > [    C6]  free_unref_page_commit+0x1fc/0x290
> > > > [    C6]  free_unref_page+0x184/0x250
> > > > [    C6]  __free_pages+0x154/0x1a0
> > > > [    C6]  free_pages+0x88/0xb0
> > > > [    C6]  kasan_depopulate_vmalloc_pte+0x58/0x80
> > > > [    C6]  __apply_to_page_range+0x3ec/0x650
> > > > [    C6]  apply_to_existing_page_range+0x1c/0x30
> > > > [    C6]  kasan_release_vmalloc+0xa4/0x118
> > > > [    C6]  __purge_vmap_area_lazy+0x4f4/0xe30
> > > > [    C6]  drain_vmap_area_work+0x60/0xc0
> > > > [    C6]  process_one_work+0x4cc/0xa38
> > > > [    C6]  worker_thread+0x240/0x638
> > > > [    C6]  kthread+0x1c8/0x1e0
> > > > [    C6]  ret_from_fork+0x10/0x20
> > > >=20
> > > >=20
> > > >=20
> > > > >=20
> > > > > Kefeng Wang (3):
> > > > >     mm: kasan: shadow: add cond_resched() in kasan_populate_vmall=
oc_pte()
> > > > >     mm: kasan: shadow: move free_page() out of page table lock
> > > > >     mm: kasan: shadow: HACK add cond_resched_lock() in
> > > > >       kasan_depopulate_vmalloc_pte()
> >=20
> > The first 2 patches look ok, but yeah, the last is a hack. I also
> > don't have any better suggestions, only more questions.
>=20
> Thanks Marco, maybe we could convert free_vmap_area_lock from spinlock to
> mutex lock only if KASAN enabled?
>=20
I do not think it is a good suggestion. Could you please clarify the
reason of such conversion?

> >=20
> > Does this only happen on arm64?
>=20
> Our test case run on arm64 qemu(host is x86), so it run much more slower
> than real board.
> > Do you have a minimal reproducer you can share?
> Here is the code in test driver,
>=20
> void *buf =3D vmalloc(40UL << 30);
> vfree(buf);
>=20
What is a test driver? Why do you need 42G of memmory, for which purpose?

--
Uladzislau Rezki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZTDJ8t9ug3Q6E8GG%40pc636.
