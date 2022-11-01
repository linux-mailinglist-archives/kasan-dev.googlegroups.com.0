Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBGPQQONQMGQEQZK22AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DFC86147D9
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Nov 2022 11:42:45 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id x6-20020a056e021ca600b002ffe4b15419sf13688992ill.4
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 03:42:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667299353; cv=pass;
        d=google.com; s=arc-20160816;
        b=r6sz5Apcfqjf9sYOD6082FonhiOCKUm2kStocJreYLuurQ7BKUxHwz1TXcByBgqdRw
         cvQ975AH2Ogwpub7JMVKTBAMiN7x52dmi8LpjjIW11lkOBYrKEXZptFu75XBjz7UIzkK
         ua9eaU+OtF1zumE7FGg9oGV1qQRvTchvVfLRVvkuCVN/0vbqY7sPLnDKrtgrPBKA3VhD
         2mp/ubStUNqyF4Honw2kiTUfurHiVLJp7MerG3SA8Nal+5iKQXyWrnbbgZvQu5UadIKK
         8abEN5dFnFmp6umUO8TCs4uQRue6/BibM122yziRnlxO03XP2r+pK6STH7PrTSLWx1wU
         0xTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=IfFLIXPvbaaSIiVmSfMrD23QpiwB1Wym+j3XKI2tpOc=;
        b=GyO59DAfxq1pcO2bhvNVB9zcXmhmYJ593zYHfKln+jIpi9Ci2tp3iJPmV4xzJBN/As
         GMElCEWB8facpeCf1K97tGgM9fpDWBfFSbEzRAQ5oKJZkhS/B3ObX8mPiQh9TnAhtu79
         Qfnqd6WVx9R6zD3sS7lzNTvax7U/QZQs/mkz8p5HKcugS5KsHuNCtljiSrr25fbVjtST
         hf8zv4mWpHNXIyyWKbjEidBFCKGUDzPJn6+qyr42o1HK+jlQHVu8DTPndp3s/KvEl9nu
         EmeVCsBsTGeGakClnIlBp/KjPuXqkk0uXBByojGyqEEZksl6NaXqwe6boi6c+ruQ7X0c
         AY4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oR1gZQ+2;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IfFLIXPvbaaSIiVmSfMrD23QpiwB1Wym+j3XKI2tpOc=;
        b=Dga6ZWefxkYAuPoe4pFAGUeZWvPRHHyhAhJB670T1kW3UKOjCHlK+mPXZxDeTzGjs3
         u9J29GynWRJqA5MrhmfS7eMKkG9jUIfUSSV+QmwzHyrUdFrHQoGEGZZy9U6LyybM+2Ep
         ojlzq6uocz47z2aDHMa7J+9uo8Is44Ijls8vZzyvvk1ng0uJudJS21UPnOGwpUt1tJEU
         bxkNI+iT6mfmeM36yQk3HnxppRZe0/2bD39eiyvc620mIl+IiN08QGkrneA1eloGMWyw
         KGgTbdxXuNAGbbQjlmFa1f814Mjt5sJAr4N4odkP69/1Ii4h5K/m3yKanSVDLYDH984/
         q+HQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=IfFLIXPvbaaSIiVmSfMrD23QpiwB1Wym+j3XKI2tpOc=;
        b=VqehnSlkjwZcOQZQTTTPSwlcJ7CHm4D4+h6MIqSGCi8vnj9tqWj2VKBE5QFG1EGLjp
         kuZaAJ6CRRjnj4UnKTv1dCm0Lk0VvHP+0AHjzA/yuhRUpcUF158ycv8DNY3eCINcnj36
         /IOOCViw+qfIcbI0ljlt7CISEdrqOnRQ//fgkLdq2Q6s5965s4LCY0wmtHRfbeHE8hrb
         Tdpu8kW21hY6Q7ibaKwZCB67z/IZwXrHFj0Ls7oTQq7gilIjkgx1ETz89H+5HEup8Z4V
         lrsvfcqSG+qULw/HFzlFvbfcQzrjawXhZ3LtdkDMkbMyLNP8PbI4rr7t+QVEFZ/qCQWQ
         37LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IfFLIXPvbaaSIiVmSfMrD23QpiwB1Wym+j3XKI2tpOc=;
        b=bfIshd7EaHQACLXadMHbA9LaEhR441RQGL6aEeTFCJaEpoWVcFj+tlW4kX4ePZGbW4
         qFaEwnwdfRVqG75W3p70BA9tFyNEHkoe/Xw2LqF3fitkUbRmSK5zTWbnvqHqTxoDWFX/
         ML3yvxcWSIDSHd/8xTgRks/pAvt9+SsCaNvdiiO/yc6jbH9uGQ6HZpqo+2VoThbggykp
         c15qTNtFv78uul0FFaJGF+yyXNrTk8JqTCXvVUku1GbMMHLN5SGX1HIXNlHKCg3uQ4Et
         ibeSqyKNVUr3uWfjtSN2kTn0Q4GcdD2mGAPAJ3ZxlfF0akxeaxLUVbpNZattfcPSWAVZ
         qNgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1QIftB50jGon4Q+2smi37bl8LPmqCn1l3+CHjcH/p1GozGBBCU
	SHuSOiI0ar/c0MfTHu2MzuY=
X-Google-Smtp-Source: AMsMyM7n+NVAzoLsvCmJoypEpqz5BM/BOIDdyq34BTCKNpHG35Vp7PmHJVvyJzxU6rKtbTscQc7H4Q==
X-Received: by 2002:a05:6602:1506:b0:6cd:17b5:dfda with SMTP id g6-20020a056602150600b006cd17b5dfdamr9750934iow.49.1667299353616;
        Tue, 01 Nov 2022 03:42:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d4d:b0:2ff:911e:c385 with SMTP id
 h13-20020a056e020d4d00b002ff911ec385ls2237855ilj.4.-pod-prod-gmail; Tue, 01
 Nov 2022 03:42:33 -0700 (PDT)
X-Received: by 2002:a05:6e02:216e:b0:300:59de:ae8c with SMTP id s14-20020a056e02216e00b0030059deae8cmr2448040ilv.226.1667299353026;
        Tue, 01 Nov 2022 03:42:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667299353; cv=none;
        d=google.com; s=arc-20160816;
        b=geHae2aVP+qHWactQF6wiCSAMdEMU7igbbrYzQZHGt7lFmuvDrKsG3+7r2L+LIMRGL
         l/HFlAtg3cBF7d2ADH5+zkqjpSlZoKx51pU8dWt12U9QAS+q+SAiRLZn54OXW69UdIZw
         tCmnbkYERD+B5TV7+k/+FEgv/7ipyVrWxObpuWPy8p9DlYAeDfKMiJKlwfwF8POb4cZJ
         ZCo9Yf7c2qIpR32eaDurTJXb85el8etQk4Ww2yVMd33iAiCgXipiC0ZFL4WoKPQ57omI
         fjtYZ/16pTZ8kQaznwuxMKVcrbHrsliarCL0vi/f10aO5UGwHRTCJqo61Dkg/stnX8RX
         +x6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Mmgzejyjag96mf7b7LvimdzM9hQQ74MAnXiZchHz7Ac=;
        b=pgDbrA+A6oSOWYdGb/zad74XFy4XIUMZ6ARbeoyDc/xkmg3VLRRleovO5TLnNIwUWo
         tigWpNquNgcBCPpCUzFm+16kZ/pV3RuO1tjqA5DgToCZw2PcapWPCk/hYi3/ead8JPiy
         Zev2z14++d+svHwfKlGolHGKnHUSHQjiB6DLQQRLCfyibwaa49o1vWSWhU5eTYnhWowf
         tT9oduHasjH6d4OP7tyMb3bi45tDqkMF0sj6GajIA6NqxlYso9wwOsqj5ZFfRbqD9Q3H
         vYjxbMs3u/Ft2CHXLYzDExzTVdzvdCy0JpjzfWo7k5BwpvTJSvJILbppiIzYme/i21Sq
         Y4cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oR1gZQ+2;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id t7-20020a02c487000000b003748fd49976si394268jam.0.2022.11.01.03.42.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Nov 2022 03:42:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id 4so13214091pli.0
        for <kasan-dev@googlegroups.com>; Tue, 01 Nov 2022 03:42:32 -0700 (PDT)
X-Received: by 2002:a17:902:e84f:b0:187:2127:cc6 with SMTP id t15-20020a170902e84f00b0018721270cc6mr10405486plg.110.1667299352568;
        Tue, 01 Nov 2022 03:42:32 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id jg1-20020a17090326c100b001780a528540sm6007495plb.93.2022.11.01.03.42.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Nov 2022 03:42:31 -0700 (PDT)
Date: Tue, 1 Nov 2022 19:42:23 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: John Thomson <lists@johnthomson.fastmail.com.au>
Cc: Feng Tang <feng.tang@intel.com>, Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"Hansen, Dave" <dave.hansen@intel.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Robin Murphy <robin.murphy@arm.com>,
	John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	John Crispin <john@phrozen.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	linux-mips@vger.kernel.org
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2D4D52h5VVa8QpE@hyeyoo>
References: <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
 <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=oR1gZQ+2;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Transfer-Encoding: quoted-printable
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

On Tue, Nov 01, 2022 at 10:33:32AM +0000, John Thomson wrote:
> On Tue, 1 Nov 2022, at 09:31, Hyeonggon Yoo wrote:
> > On Tue, Nov 01, 2022 at 09:20:21AM +0000, John Thomson wrote:
> >> On Tue, 1 Nov 2022, at 07:57, Feng Tang wrote:
> >> > Hi Thomson,
> >> >
> >> > Thanks for testing!
> >> >
> >> > + mips maintainer and mail list. The original report is here
> >> >
> >> > https://lore.kernel.org/lkml/becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@ap=
p.fastmail.com/
> >>
> >> I am guessing my issue comes from __kmem_cache_alloc_lru accessing s->=
object_size when (kmem_cache) s is NULL?
> >> If that is the case, this change is not to blame, it only exposes the =
issue?
> >>=20
> >> I get the following dmesg (note very early NULL kmem_cache) with the b=
elow change atop v6.1-rc3:
> >>=20
> >> transfer started ......................................... transfer ok=
, time=3D2.02s
> >> setting up elf image... OK
> >> jumping to kernel code
> >> zimage at:     80B842A0 810B4EFC
> >>=20
> >> Uncompressing Linux at load address 80001000
> >>=20
> >> Copy device tree to address  80B80EE0
> >>=20
> >> Now, booting the kernel...
> >>=20
> >> [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-=
linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU=
 Binutils) 2.39) #61 SMP Tue Nov  1 18:04:13 AEST 2022
> >> [    0.000000] slub: kmem_cache_alloc called with kmem_cache: 0x0
> >> [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache: 0x=
0
> >> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> >> [    0.000000] printk: bootconsole [early0] enabled
> >> [    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
> >> [    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS
> >>=20
> >> normal boot
> >>=20
> >>=20
> >> diff --git a/mm/slub.c b/mm/slub.c
> >> index 157527d7101b..10fcdf2520d2 100644
> >> --- a/mm/slub.c
> >> +++ b/mm/slub.c
> >> @@ -3410,7 +3410,13 @@ static __always_inline
> >>  void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *l=
ru,
> >>  			     gfp_t gfpflags)
> >>  {
> >> -	void *ret =3D slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size)=
;
> >> +	void *ret;
> >> +	if (IS_ERR_OR_NULL(s)) {
> >> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\=
n", s);
> >> +		ret =3D slab_alloc(s, lru, gfpflags, _RET_IP_, 0);
> >> +	} else {
> >> +		ret =3D slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> >> +	}
> >> =20
> >>  	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
> >> =20
> >> @@ -3419,6 +3425,8 @@ void *__kmem_cache_alloc_lru(struct kmem_cache *=
s, struct list_lru *lru,
> >> =20
> >>  void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
> >>  {
> >> +	if (IS_ERR_OR_NULL(s))
> >> +		pr_warn("slub: kmem_cache_alloc called with kmem_cache: %pSR\n", s)=
;
> >>  	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
> >>  }
> >>  EXPORT_SYMBOL(kmem_cache_alloc);
> >> @@ -3426,6 +3434,8 @@ EXPORT_SYMBOL(kmem_cache_alloc);
> >>  void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru=
,
> >>  			   gfp_t gfpflags)
> >>  {
> >> +	if (IS_ERR_OR_NULL(s))
> >> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\=
n", s);
> >>  	return __kmem_cache_alloc_lru(s, lru, gfpflags);
> >>  }
> >>  EXPORT_SYMBOL(kmem_cache_alloc_lru);
> >>=20
> >>=20
> >> Any hints on where kmem_cache_alloc would be being called from this ea=
rly?
> >> I will start looking from /init/main.c around pr_notice("%s", linux_ba=
nner);
> >
> > Great. Would you try calling dump_stack(); when we observed s =3D=3D NU=
LL?
> > That would give more information about who passed s =3D=3D NULL to thes=
e
> > functions.
> >
>=20
> With the dump_stack() in place:
>=20
> Now, booting the kernel...
>=20
> [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-lin=
ux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Bi=
nutils) 2.39) #62 SMP Tue Nov  1 19:49:52 AEST 2022
> [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache ptr: 0=
x0
> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #62
> [    0.000000] Stack : 810fff78 80084d98 80889d00 00000004 00000000 00000=
000 80889d5c 80c90000
> [    0.000000]         80920000 807bd380 8089d368 80923bd3 00000000 00000=
001 80889d08 00000000
> [    0.000000]         00000000 00000000 807bd380 8084bd51 00000002 00000=
002 00000001 6d6f4320
> [    0.000000]         00000000 80c97ce9 80c97d14 fffffffc 807bd380 00000=
000 00000003 00000dc0
> [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000=
020 80010000 80010000
> [    0.000000]         ...
> [    0.000000] Call Trace:
> [    0.000000] [<80008260>] show_stack+0x28/0xf0
> [    0.000000] [<8070cdc0>] dump_stack_lvl+0x60/0x80
> [    0.000000] [<801c1428>] kmem_cache_alloc+0x5c0/0x740
> [    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
> [    0.000000] [<80928060>] prom_init+0x44/0xf0
> [    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
> [    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
> [    0.000000]=20
> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3

setup_arch() is too early to use slab allocators.
I think slab received NULL pointer because kmalloc is not initialized.

It seems arch/mips/ralink/mt7621.c is using slab too early.

>=20
>=20
> Now, booting the kernel...
>=20
> [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-lin=
ux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Bi=
nutils) 2.39) #62 SMP Tue Nov  1 19:49:52 AEST 2022
> [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache ptr: 0=
x0
> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #62
> [    0.000000] Stack : 810fff78 80084d98 80889d00 00000004 00000000 00000=
000 80889d5c 80c90000
> [    0.000000]         80920000 807bd380 8089d368 80923bd3 00000000 00000=
001 80889d08 00000000
> [    0.000000]         00000000 00000000 807bd380 8084bd51 00000002 00000=
002 00000001 6d6f4320
> [    0.000000]         00000000 80c97ce9 80c97d14 fffffffc 807bd380 00000=
000 00000003 00000dc0
> [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000=
020 80010000 80010000
> [    0.000000]         ...
> [    0.000000] Call Trace:
> [    0.000000] show_stack (/mnt/pool_ssd/code/linux/linux-stable-mt7621/.=
/arch/mips/include/asm/stacktrace.h:43 /mnt/pool_ssd/code/linux/linux-stabl=
e-mt7621/arch/mips/kernel/traps.c:223)=20
> [    0.000000] dump_stack_lvl (/mnt/pool_ssd/code/linux/linux-stable-mt76=
21/lib/dump_stack.c:107 (discriminator 1))=20
> [    0.000000] kmem_cache_alloc (/mnt/pool_ssd/code/linux/linux-stable-mt=
7621/mm/slub.c:3318 /mnt/pool_ssd/code/linux/linux-stable-mt7621/mm/slub.c:=
3406 /mnt/pool_ssd/code/linux/linux-stable-mt7621/mm/slub.c:3418 /mnt/pool_=
ssd/code/linux/linux-stable-mt7621/mm/slub.c:3430)=20
> [    0.000000] prom_soc_init (/mnt/pool_ssd/code/linux/linux-stable-mt762=
1/arch/mips/ralink/mt7621.c:106 /mnt/pool_ssd/code/linux/linux-stable-mt762=
1/arch/mips/ralink/mt7621.c:177)=20
> [    0.000000] prom_init (/mnt/pool_ssd/code/linux/linux-stable-mt7621/ar=
ch/mips/ralink/prom.c:64)=20
> [    0.000000] setup_arch (/mnt/pool_ssd/code/linux/linux-stable-mt7621/a=
rch/mips/kernel/setup.c:786)=20
> [    0.000000] start_kernel (/mnt/pool_ssd/code/linux/linux-stable-mt7621=
/init/main.c:279 /mnt/pool_ssd/code/linux/linux-stable-mt7621/init/main.c:4=
77 /mnt/pool_ssd/code/linux/linux-stable-mt7621/init/main.c:960)=20
> [    0.000000]=20
> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
>=20
>=20
> I have not found it yet.
>=20
>=20
> Cheers,
> --=20
>   John Thomson

--=20
Thanks,
Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y2D4D52h5VVa8QpE%40hyeyoo.
