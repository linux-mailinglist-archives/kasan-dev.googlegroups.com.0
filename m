Return-Path: <kasan-dev+bncBAABBJ7MQONQMGQEWPN7O4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 643BB6147BD
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Nov 2022 11:34:16 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id t12-20020a056512068c00b004aab3d19c78sf3960406lfe.4
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 03:34:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667298855; cv=pass;
        d=google.com; s=arc-20160816;
        b=0dhxQdPGWoi/L9dbpMeG0OqiAuvRdpuByvwHbetONVxEcKq3jwiMfpQGYPuTD/BYpD
         vJ0bHMaxtjzbV2uBVna1ydsnp3kVtEVtHBMWtsc8IU7AUBeLUvAj8u7asafskqmPULsr
         x0SQ6lGht2jtZFRlwQwvorJLN1Tgkq54ITJPWaN37gaEJ9q1W2nwPBBwh0NFrrrtm4vm
         C7Roflw6+SxWGfrrXQvqiRC5yvnHvX1dDLhhwNpWD0D0f7aTUzMN/2SYP6lFf+LBQ3zS
         kOKk0Ur1GlZ8YdxsJ0jnF5/6UdIABQXcXDK+iWYQiBfEumr1GENbqayScQfIQj947v0B
         DWlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:subject
         :cc:to:from:date:references:in-reply-to:message-id:mime-version
         :user-agent:feedback-id:sender:dkim-signature;
        bh=+7Xv819+d8n4GucHDzRJMgmmWpucvHpOFii8q/wkdwA=;
        b=Dm8AYQA0ieos6+kuajk2uKadFZ9/M+92DGjcsgAW0uF9725hI9+dboGaxW/2c7/CH6
         JQh8bcBlHjsvwEMpNd5LQqP3fDIYBVIe5COg9UX96cww3LcaVl4KtSNDCPJ/E+EzrLbU
         2nwW/vlWXMLC05Y8BvE5Z9Pmj/2LFjVJbF6CkjYPX7C5iB3bOyfa6dArdlHQk739KHHT
         3UmIoDcqSCbDUlJiJwe8Y6TIfWCFwlQmmkmZqULTgwjS3gEfsg8hBJdMBa0Idy2BxR7W
         xSyCJZJ2WMRkUb+y+Q57izI8YE3vx7ChTOAsY5n39NWvElwwx48s3Rrcf6tloj0Nsj1c
         t7Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=jx4i1eWf;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=QrJoBQb2;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 64.147.123.24 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+7Xv819+d8n4GucHDzRJMgmmWpucvHpOFii8q/wkdwA=;
        b=HjqSmPB0PGtsShtGQBmLztTG0Bgxz9jV30QiAgASZxZcLyGiCoxfbS7dgxsghp6Rxo
         66VaZhhgAvXPWIb7FfxHlAdRcykiqOJW0mM67Grl6GBhfNJRHU+vw53PJvTeGua9fh1o
         UN7EJSJm5j4SH0pYWRB62KmNOjvp/yBZ6kbSzEZrFKU7v0swilAm0mdl2VYUanEsl98E
         GPsckp/SqWEwkq/Ky0awWDwVMGo3wsQ+Jx/Aq+l/m+6BCIxniSFe1kBSCmwTlKjYBPkd
         hAIu0ibGVI/0RhF0++E820h7TiVXZjiJcLcSJ6UnJDljrqRDyYppWokyJNQKdBlpEURy
         qIRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+7Xv819+d8n4GucHDzRJMgmmWpucvHpOFii8q/wkdwA=;
        b=r85E9JL3GzYedMp5Tvki5gLja9tLuYQdZf8IBcjGKV7xzKYIxVrdVAQ26YRep91LsW
         d6qndSCb4urn89pcsGViFeTicIcTmx0E7UTgP/rXRd2zvO+15qNDLGt0b7GlyC56rIyO
         1pVOeEYaKSO/NKXFiiCoDEoCYgavQSI34tba9YiXlXUjkcK/koGT973REUmUeMCW+XEJ
         EpnBPmQaAZ3iTgBXaOwn8CeBMWOpYWOfyxnmMGWjGSgYAD2kUA8Kccx4MOGdnElewR52
         s+MMsWXBe2dmRx8H96Yqm3VJZzIT743MjVnSwSft2IM4do+gs4pD9zxiWA/jgvWN7LfB
         ZZmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2rpX8MzIgO762b0rmI/9XJxGYZs+tI0A14Ln84Eo4JCIhZq0yU
	goyjoUJuX8iAb3xjgRNZhrw=
X-Google-Smtp-Source: AMsMyM6Da//VgGmbQi+kHa7aGSCEOTN3v7ORw1pmBHegoOgddQZJy/J4Sf8PHJvXDHi3SoC+HlmKlg==
X-Received: by 2002:a2e:7003:0:b0:277:6c39:e543 with SMTP id l3-20020a2e7003000000b002776c39e543mr476854ljc.513.1667298855577;
        Tue, 01 Nov 2022 03:34:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2122:b0:26f:b780:6802 with SMTP id
 a34-20020a05651c212200b0026fb7806802ls2060735ljq.0.-pod-prod-gmail; Tue, 01
 Nov 2022 03:34:14 -0700 (PDT)
X-Received: by 2002:a2e:9dda:0:b0:26f:c53d:65c2 with SMTP id x26-20020a2e9dda000000b0026fc53d65c2mr664487ljj.320.1667298854646;
        Tue, 01 Nov 2022 03:34:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667298854; cv=none;
        d=google.com; s=arc-20160816;
        b=Fx3xoHsKJ/DQ3za7VM9rXkmhk4MbU85ekLL451XttjMK+7Xz+AtATiATxtneSeisX4
         MQoNGBgjfZJlBQiOOaWE3KEFl7RH66CgxJNJ8CgNcO6vtoP0F9EXVNR4UHRw8ScDfYj9
         yWR/tGaGwdSpOdJpidsN1GOWMpmNpjIbt+96LzQ0pOWbx+buROC/SwPpxIxqTNzvoJNk
         GMYMqh6jVZzpIoHn9GfDf3LPQPuKaf2DalZgBZhL4MDpzCnzhfEYREGw2NdaYRyzfu6N
         8aPmPgwKdzpLo/WWI8WS8iEuE2FkqtAxGA4r3uBbwqdn3Z24CK2YifZc/HglR4PpunIs
         wtEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=z1rNkUkf7u5akB5pgiOIOqLSL4PvlOcgKqUXRgy689Q=;
        b=MoG4WGhHnBxturLNOz9ILXXR/ejfD04ODoGQ+yPjPrFQmC7G4omLyeJh11ZsKIyvIS
         RwtQTzXy7LnMQh0yYRNJ+gabyxks5oviVe0Y18Hyh2IwbDv4OWu0hSAtFDSKzrC9z88i
         tbYXQR+rE+/dy5e5PeTf3GI6RosuaAU4yvdCvmIyElioPZyox4YlZANWhfU4HU2Zj8ne
         v1lfk2pN4BemkEOseql1NGsUbMFhVJyok7V43xXfIybjeCIX3QJfzh6Bpay/LRxlSK3H
         W7yeQ0zvLWJ9Z1ZbUe4abFWPikOTjHOVTIfnzCUsnxx/dLYk+DW0NPDfYTS45Tb1oUPb
         +rzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=jx4i1eWf;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=QrJoBQb2;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 64.147.123.24 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
Received: from wout1-smtp.messagingengine.com (wout1-smtp.messagingengine.com. [64.147.123.24])
        by gmr-mx.google.com with ESMTPS id 20-20020a2eb954000000b00277385b7372si288191ljs.4.2022.11.01.03.34.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Nov 2022 03:34:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 64.147.123.24 as permitted sender) client-ip=64.147.123.24;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailout.west.internal (Postfix) with ESMTP id 342F23200970;
	Tue,  1 Nov 2022 06:34:10 -0400 (EDT)
Received: from imap46 ([10.202.2.96])
  by compute5.internal (MEProxy); Tue, 01 Nov 2022 06:34:11 -0400
X-ME-Sender: <xms:IPZgY3B6uJPnxqW_YXn0g4swkR6d4Ptx8ky2Yzayu0m7amaARAnqag>
    <xme:IPZgY9jdwuptHuCFqjOXWAIr3D09Rb-oD9j3HQb4R0wnqpEuV2L0mBC9g_HFjD0Eb
    fJ5cePln5Lqhv9FAg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvgedrudehgddujecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpefofgggkfgjfhffhffvvefutgesthdtredtreertdenucfhrhhomhepfdflohhh
    nhcuvfhhohhmshhonhdfuceolhhishhtshesjhhohhhnthhhohhmshhonhdrfhgrshhtmh
    grihhlrdgtohhmrdgruheqnecuggftrfgrthhtvghrnhepjeejfeeilefgfedtkeekfeek
    ffegleetlefhheekleeggfdttdevveduheettefgnecuffhomhgrihhnpehkvghrnhgvlh
    drohhrghenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhm
    pehlihhsthhssehjohhhnhhthhhomhhsohhnrdhfrghsthhmrghilhdrtghomhdrrghu
X-ME-Proxy: <xmx:IPZgYyndyNLG1Bz43rWyG7xVaFPUrR3Wx0d8ZaGBenQLcoF1YsZ1dw>
    <xmx:IPZgY5xs6OqFnbgHF8pfx0n7ZQfgk4nOP0jZPInxmq7snQRp2PEehg>
    <xmx:IPZgY8QqnnpbRY6x_Mj5DjgvOindn9KeAUWlIGHZkVOXyMqVREleZg>
    <xmx:IfZgY9LXh0qSTChG5LXKajlEEFa-gFWdFOzkiC1EzKxnflCAJnjsNg>
Feedback-ID: ia7894244:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 04DC02A20080; Tue,  1 Nov 2022 06:34:07 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.7.0-alpha0-1087-g968661d8e1-fm-20221021.001-g968661d8
Mime-Version: 1.0
Message-Id: <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
In-Reply-To: <Y2DngwUc7cLB0dG7@hyeyoo>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz> <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
Date: Tue, 01 Nov 2022 10:33:32 +0000
From: "John Thomson" <lists@johnthomson.fastmail.com.au>
To: "Hyeonggon Yoo" <42.hyeyoo@gmail.com>
Cc: "Feng Tang" <feng.tang@intel.com>, "Vlastimil Babka" <vbabka@suse.cz>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Christoph Lameter" <cl@linux.com>, "Pekka Enberg" <penberg@kernel.org>,
 "David Rientjes" <rientjes@google.com>,
 "Joonsoo Kim" <iamjoonsoo.kim@lge.com>,
 "Roman Gushchin" <roman.gushchin@linux.dev>,
 "Dmitry Vyukov" <dvyukov@google.com>, "Jonathan Corbet" <corbet@lwn.net>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Hansen, Dave" <dave.hansen@intel.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "Robin Murphy" <robin.murphy@arm.com>, "John Garry" <john.garry@huawei.com>,
 "Kefeng Wang" <wangkefeng.wang@huawei.com>,
 "Thomas Bogendoerfer" <tsbogend@alpha.franken.de>, linux-mips@vger.kernel.org
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of kmalloc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lists@johnthomson.fastmail.com.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fastmail.com.au header.s=fm3 header.b=jx4i1eWf;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=QrJoBQb2;       spf=pass
 (google.com: domain of lists@johnthomson.fastmail.com.au designates
 64.147.123.24 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
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

On Tue, 1 Nov 2022, at 09:31, Hyeonggon Yoo wrote:
> On Tue, Nov 01, 2022 at 09:20:21AM +0000, John Thomson wrote:
>> On Tue, 1 Nov 2022, at 07:57, Feng Tang wrote:
>> > Hi Thomson,
>> >
>> > Thanks for testing!
>> >
>> > + mips maintainer and mail list. The original report is here
>> >
>> > https://lore.kernel.org/lkml/becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.=
fastmail.com/
>>
>> I am guessing my issue comes from __kmem_cache_alloc_lru accessing s->ob=
ject_size when (kmem_cache) s is NULL?
>> If that is the case, this change is not to blame, it only exposes the is=
sue?
>>=20
>> I get the following dmesg (note very early NULL kmem_cache) with the bel=
ow change atop v6.1-rc3:
>>=20
>> transfer started ......................................... transfer ok, =
time=3D2.02s
>> setting up elf image... OK
>> jumping to kernel code
>> zimage at:     80B842A0 810B4EFC
>>=20
>> Uncompressing Linux at load address 80001000
>>=20
>> Copy device tree to address  80B80EE0
>>=20
>> Now, booting the kernel...
>>=20
>> [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-li=
nux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU B=
inutils) 2.39) #61 SMP Tue Nov  1 18:04:13 AEST 2022
>> [    0.000000] slub: kmem_cache_alloc called with kmem_cache: 0x0
>> [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache: 0x0
>> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
>> [    0.000000] printk: bootconsole [early0] enabled
>> [    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
>> [    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS
>>=20
>> normal boot
>>=20
>>=20
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 157527d7101b..10fcdf2520d2 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -3410,7 +3410,13 @@ static __always_inline
>>  void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru=
,
>>  			     gfp_t gfpflags)
>>  {
>> -	void *ret =3D slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
>> +	void *ret;
>> +	if (IS_ERR_OR_NULL(s)) {
>> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n"=
, s);
>> +		ret =3D slab_alloc(s, lru, gfpflags, _RET_IP_, 0);
>> +	} else {
>> +		ret =3D slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
>> +	}
>> =20
>>  	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
>> =20
>> @@ -3419,6 +3425,8 @@ void *__kmem_cache_alloc_lru(struct kmem_cache *s,=
 struct list_lru *lru,
>> =20
>>  void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
>>  {
>> +	if (IS_ERR_OR_NULL(s))
>> +		pr_warn("slub: kmem_cache_alloc called with kmem_cache: %pSR\n", s);
>>  	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
>>  }
>>  EXPORT_SYMBOL(kmem_cache_alloc);
>> @@ -3426,6 +3434,8 @@ EXPORT_SYMBOL(kmem_cache_alloc);
>>  void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>>  			   gfp_t gfpflags)
>>  {
>> +	if (IS_ERR_OR_NULL(s))
>> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n"=
, s);
>>  	return __kmem_cache_alloc_lru(s, lru, gfpflags);
>>  }
>>  EXPORT_SYMBOL(kmem_cache_alloc_lru);
>>=20
>>=20
>> Any hints on where kmem_cache_alloc would be being called from this earl=
y?
>> I will start looking from /init/main.c around pr_notice("%s", linux_bann=
er);
>
> Great. Would you try calling dump_stack(); when we observed s =3D=3D NULL=
?
> That would give more information about who passed s =3D=3D NULL to these
> functions.
>

With the dump_stack() in place:

Now, booting the kernel...

[    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux=
-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binu=
tils) 2.39) #62 SMP Tue Nov  1 19:49:52 AEST 2022
[    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache ptr: 0x0
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #62
[    0.000000] Stack : 810fff78 80084d98 80889d00 00000004 00000000 0000000=
0 80889d5c 80c90000
[    0.000000]         80920000 807bd380 8089d368 80923bd3 00000000 0000000=
1 80889d08 00000000
[    0.000000]         00000000 00000000 807bd380 8084bd51 00000002 0000000=
2 00000001 6d6f4320
[    0.000000]         00000000 80c97ce9 80c97d14 fffffffc 807bd380 0000000=
0 00000003 00000dc0
[    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 0000002=
0 80010000 80010000
[    0.000000]         ...
[    0.000000] Call Trace:
[    0.000000] [<80008260>] show_stack+0x28/0xf0
[    0.000000] [<8070cdc0>] dump_stack_lvl+0x60/0x80
[    0.000000] [<801c1428>] kmem_cache_alloc+0x5c0/0x740
[    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
[    0.000000] [<80928060>] prom_init+0x44/0xf0
[    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
[    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
[    0.000000]=20
[    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3



Now, booting the kernel...

[    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux=
-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binu=
tils) 2.39) #62 SMP Tue Nov  1 19:49:52 AEST 2022
[    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache ptr: 0x0
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #62
[    0.000000] Stack : 810fff78 80084d98 80889d00 00000004 00000000 0000000=
0 80889d5c 80c90000
[    0.000000]         80920000 807bd380 8089d368 80923bd3 00000000 0000000=
1 80889d08 00000000
[    0.000000]         00000000 00000000 807bd380 8084bd51 00000002 0000000=
2 00000001 6d6f4320
[    0.000000]         00000000 80c97ce9 80c97d14 fffffffc 807bd380 0000000=
0 00000003 00000dc0
[    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 0000002=
0 80010000 80010000
[    0.000000]         ...
[    0.000000] Call Trace:
[    0.000000] show_stack (/mnt/pool_ssd/code/linux/linux-stable-mt7621/./a=
rch/mips/include/asm/stacktrace.h:43 /mnt/pool_ssd/code/linux/linux-stable-=
mt7621/arch/mips/kernel/traps.c:223)=20
[    0.000000] dump_stack_lvl (/mnt/pool_ssd/code/linux/linux-stable-mt7621=
/lib/dump_stack.c:107 (discriminator 1))=20
[    0.000000] kmem_cache_alloc (/mnt/pool_ssd/code/linux/linux-stable-mt76=
21/mm/slub.c:3318 /mnt/pool_ssd/code/linux/linux-stable-mt7621/mm/slub.c:34=
06 /mnt/pool_ssd/code/linux/linux-stable-mt7621/mm/slub.c:3418 /mnt/pool_ss=
d/code/linux/linux-stable-mt7621/mm/slub.c:3430)=20
[    0.000000] prom_soc_init (/mnt/pool_ssd/code/linux/linux-stable-mt7621/=
arch/mips/ralink/mt7621.c:106 /mnt/pool_ssd/code/linux/linux-stable-mt7621/=
arch/mips/ralink/mt7621.c:177)=20
[    0.000000] prom_init (/mnt/pool_ssd/code/linux/linux-stable-mt7621/arch=
/mips/ralink/prom.c:64)=20
[    0.000000] setup_arch (/mnt/pool_ssd/code/linux/linux-stable-mt7621/arc=
h/mips/kernel/setup.c:786)=20
[    0.000000] start_kernel (/mnt/pool_ssd/code/linux/linux-stable-mt7621/i=
nit/main.c:279 /mnt/pool_ssd/code/linux/linux-stable-mt7621/init/main.c:477=
 /mnt/pool_ssd/code/linux/linux-stable-mt7621/init/main.c:960)=20
[    0.000000]=20
[    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3


I have not found it yet.


Cheers,
--=20
  John Thomson

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/29271a2b-cf19-4af9-bfe5-5bcff8a23fda%40app.fastmail.com.
