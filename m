Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTWWR6FAMGQEAKNPF5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3600240EEA1
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 03:11:44 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id x7-20020a4aea07000000b0028b880a3cd3sf37561957ood.15
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 18:11:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631841103; cv=pass;
        d=google.com; s=arc-20160816;
        b=KIQhCWl5HGHQF7MT4D5XKGo/5Tb3V47z1RDwimlKE/0+JpB1pYnjYSXF0YLXxJMr6E
         pb9HQgvrKezNcnmbjvS885kgZ7GXg5GLmtkora+yxEqkkWr/m4DelTX68ELw1g+EdeL/
         +RkCdVXuqKJeR38v1iweY4tvqsRpEkbVeXoc8BEnOg88JbU9wSBSFi58zEfRz1tyCjst
         N8N1K1mV2Q/dnRonwRtPLMrtCD0PwszmPzUhFrqHLpgRjIAAT83ouQgD/X6zOKbJ7vVf
         O7a8Y4YMs8JfV3cel1Qih3gpnzGI8Ehf560lyjos2Nv1qgOWjyaQwJWXSl3RH9PkoHip
         XQ5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Qo3DIkbn060i3PZzsR4RYI5In8w84sYkov1CBB7Dwro=;
        b=dhLi9zWXPDWEfFDo/nP/yeH3rYPMpmqQm89/r20Esa7IfpF2KnibG+jnDgBs9B57Tj
         iboG/uTLlKyUx+wIUNcxFeVzvbJdwblYmghUAZpW5ABqbIlccRg4SVQAyX4YVqdLNJhf
         auPihACvkRz/mv6a74LUfb6EqOwi08DBj/DcJcY8VcDS2xzG4BaS+AIeZPkfkrQoQ4zJ
         2sPNhVHVmIJWK2NM3J7qYmcT6Uoobgyt4SPGJ6VQBYVLvvin2Au7DRMShyRHOW/h+O5s
         yp8gFx0xBk7pzbN0VhQrsV0Hg5LtiKmiaZZrd/uYzBODBNH9PvSJUxlKEQTed+uIwOtC
         VXMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qo3DIkbn060i3PZzsR4RYI5In8w84sYkov1CBB7Dwro=;
        b=jBvUXqUiLfzJbwjxzxy6Z9R6cmy0mji/iTb3/tDn/4v65lP7QU+HXgX5kYznY13lrz
         v0f8Hpp2R888R2cL6a27D7f5/tbcJedy0HHuSgJCMMVDTyocz2Gez9Z5FmP7I/peN9vi
         UKJ/ca8hV/qDXUMag/o0FWPIfd3zMYmqACL+Pjro9NccUFIDFXVjiGxe7OQ89sZuFl9a
         hW5Xs3tzMSZVX/9TZTrKJXcez012aIfq4QlURtkHiFhXELhrhVJEd3vklHRZc+WCowTm
         1BeDn/dUQHwanqLuqrtHvP5spHlG1Lv+i3eBu6bjVsmKMNesXsSmK+AvZ3p/Sv1jlgQ+
         utsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Qo3DIkbn060i3PZzsR4RYI5In8w84sYkov1CBB7Dwro=;
        b=CmALDXVE1NhqLKKGSoi1YQCp2r5IOdjq3pznIA5cWjKS+nJDMtCZYLKlNpxmV4zC/b
         DuCxqRW2tVFfS5zE4Pq7hZhzHAoun9sScj7PAlrqmcwtRgAb4OLKiVTyi8aqRJjHl1XS
         TrBK3mhKnAF7i7gopzzmfxbZZRKJNJgwUY8iJn6dJadYgRIFLpJb9YM8EX5K4M9cyRkZ
         OHey14JmAfO2fjy3L/qgNx6ycl10XRGdXxSu9iVNLa4Myl+eBIRtyhQwTfvGhNh/gHjc
         SVSbG+cxrSq/m4Bt/BkX2DXuVQEUX7NpzYsV8XhjSYI+zhha5RNM/+dWK2GV0hH/Duab
         soJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jA78wZyl4GSGm3Nw8b5tQNt61NVvLDPZM2MsfeE+21UxTzZ8s
	1oGlpaURAk8bLVU3zmwtGgM=
X-Google-Smtp-Source: ABdhPJxOXuOZDd1wQGNukL2eyZSxRyFEnxTLeRM3ZipzU76zdR0Dt/SSie4+HgIrZlPnt9OWLPyFGw==
X-Received: by 2002:a9d:6f10:: with SMTP id n16mr7250664otq.150.1631841102897;
        Thu, 16 Sep 2021 18:11:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a8e:: with SMTP id l14ls2550457otq.10.gmail; Thu, 16
 Sep 2021 18:11:42 -0700 (PDT)
X-Received: by 2002:a9d:71db:: with SMTP id z27mr7191645otj.292.1631841102462;
        Thu, 16 Sep 2021 18:11:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631841102; cv=none;
        d=google.com; s=arc-20160816;
        b=UJUfLnr+mQMW3kGR57Ij8E5lQxWY3kfOYZRaZB1qtpEgmO0Hdors41nlaTdFPT/H1W
         wenC14nkCOrzZhlmq9EaLUcLZqicsKaMxu/Ubj2ME2pD3D5OoixDzHXUe0dzKu6Nr1a7
         QBYjokbzyRv76hJWCnHWNeiIcnNJjgqB99cMzg+atO16rI1KFKOH9eWlQeHS2yK1LQ9B
         YAXs0SeLjrgrOC9extW5ecOuqUcQD2pwrwZ/bdR8IUbHhivMqYvaB3yT7p8P+nyXn/mW
         KWFBHwMozZed3QZJ4Px5vGG92iDprQE73M0uqNpbaqxKQV/symqqs+OKvS4BFFL6MWKw
         HbCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject;
        bh=SABJd1YPfkVL7h8BV9qbwyKYb1Rq3HlZqQ+v2x3EzM0=;
        b=TvMxD3V+f7OojubTIOZLnZeKvVlCHUepUrxAwwYEax6ZEfWxIVxkFaKrigdi2UFWd4
         X2RYeSbJW7AE2LmyZU+j8oGaXvnh+H88yMrkhBA4eBWUxvsf4L82J9Mz5QnQof5WIZvg
         nr2DdQjrRwVs8CvIs6sGG11r7eDnsoI8M4IYji8pwFwzM51jGGkknLA34UM9nUoma2DY
         fyfpo+omceWMIi/hVoRLjM8NE4TPnbA5LVjUQuT5Di+D4cRHXMpiyaRv5a8eAVoUDvYP
         X+P8JM7OSuCQc5s20S0HRkHL8W+1Y8lKdBW22ugj++8wSGTt/NPRnUTAa4IzVkF1+MrN
         892w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id bk7si403669oib.2.2021.09.16.18.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Sep 2021 18:11:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4H9bVP11CbzW2L8;
	Fri, 17 Sep 2021 09:10:37 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 17 Sep 2021 09:11:40 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 17 Sep 2021 09:11:39 +0800
Subject: Re: [PATCH v4 0/3] arm64: support page mapping percpu first chunk
 allocator
To: Greg KH <gregkh@linuxfoundation.org>
CC: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<kasan-dev@googlegroups.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <c06faf6c-3d21-04f2-6855-95c86e96cf5a@huawei.com>
 <YUNlsgZoLG3g4Qup@kroah.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <525cb266-ecfc-284e-d701-4a8b40fe413b@huawei.com>
Date: Fri, 17 Sep 2021 09:11:38 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <YUNlsgZoLG3g4Qup@kroah.com>
Content-Type: multipart/alternative;
	boundary="------------6256AA368ECCC2BEADF11DEB"
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

--------------6256AA368ECCC2BEADF11DEB
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable


On 2021/9/16 23:41, Greg KH wrote:
> On Wed, Sep 15, 2021 at 04:33:09PM +0800, Kefeng Wang wrote:
>> Hi Greg and Andrew=EF=BC=8C as Catalin saids=EF=BC=8Cthe series touches =
drivers/ and mm/
>> but missing
>>
>> acks from both of you=EF=BC=8Ccould you take a look of this patchset(pat=
ch1 change
>> mm/vmalloc.c
> What patchset?

[PATCH v4 1/3] vmalloc: Choose a better start address in=20
vm_area_register_early()  <https://lore.kernel.org/linux-arm-kernel/2021091=
0053354.26721-2-wangkefeng.wang@huawei.com/>
[PATCH v4 2/3] arm64: Support page mapping percpu first chunk allocator  <h=
ttps://lore.kernel.org/linux-arm-kernel/20210910053354.26721-3-wangkefeng.w=
ang@huawei.com/> =20
[PATCH v4 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with=20
KASAN_VMALLOC  <https://lore.kernel.org/linux-arm-kernel/20210910053354.267=
21-4-wangkefeng.wang@huawei.com/> =20
[PATCH v4 0/3] arm64: support page mapping percpu first chunk allocator  <h=
ttps://lore.kernel.org/linux-arm-kernel/c06faf6c-3d21-04f2-6855-95c86e96cf5=
a@huawei.com/> =20

>> and patch2 changes drivers/base/arch_numa.c).
patch2 =EF=BC=9A

[PATCH v4 2/3] arm64: Support page mapping percpu first chunk allocator  <h=
ttps://lore.kernel.org/linux-arm-kernel/20210910053354.26721-3-wangkefeng.w=
ang@huawei.com/#r>

> that file is not really owned by anyone it seems :(
>
> Can you provide a link to the real patch please?

Yes=EF=BC=8C arch_numa.c is moved into drivers/base to support riscv numa, =
it is=20
shared by arm64/riscv,

my changes(patch2) only support NEED_PER_CPU_PAGE_FIRST_CHUNK on ARM64.

here is the link:

https://lore.kernel.org/linux-arm-kernel/20210910053354.26721-1-wangkefeng.=
wang@huawei.com/

Thanks.

>
> thanks,
>
> greg k-h
> .
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/525cb266-ecfc-284e-d701-4a8b40fe413b%40huawei.com.

--------------6256AA368ECCC2BEADF11DEB
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body text=3D"#000000" bgcolor=3D"#FFFFFF">
    <p><br>
    </p>
    <div class=3D"moz-cite-prefix">On 2021/9/16 23:41, Greg KH wrote:<br>
    </div>
    <blockquote type=3D"cite" cite=3D"mid:YUNlsgZoLG3g4Qup@kroah.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Wed, Sep 15, 2021 at 04:33:=
09PM +0800, Kefeng Wang wrote:
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">Hi Greg and Andrew=EF=BC=8C =
as Catalin saids=EF=BC=8Cthe series touches drivers/ and mm/
but missing

acks from both of you=EF=BC=8Ccould you take a look of this patchset(patch1=
 change
mm/vmalloc.c
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
What patchset?</pre>
    </blockquote>
    <pre style=3D"font-size: 13px; font-family: monospace; background: rgb(=
255, 255, 255); color: rgb(51, 51, 51); white-space: pre-wrap; font-style: =
normal; font-variant-ligatures: normal; font-variant-caps: normal; font-wei=
ght: 400; letter-spacing: normal; orphans: 2; text-align: start; text-inden=
t: 0px; text-transform: none; widows: 2; word-spacing: 0px; -webkit-text-st=
roke-width: 0px; text-decoration-thickness: initial; text-decoration-style:=
 initial; text-decoration-color: initial;">
<a href=3D"https://lore.kernel.org/linux-arm-kernel/20210910053354.26721-2-=
wangkefeng.wang@huawei.com/" style=3D"font-size: 13px; font-family: monospa=
ce; background: rgb(255, 255, 255); color: rgb(0, 0, 255); text-decoration:=
 none;">[PATCH v4 1/3] vmalloc: Choose a better start address in vm_area_re=
gister_early()</a>
<a href=3D"https://lore.kernel.org/linux-arm-kernel/20210910053354.26721-3-=
wangkefeng.wang@huawei.com/" style=3D"font-size: 13px; font-family: monospa=
ce; background: rgb(255, 255, 255); color: rgb(0, 0, 255); text-decoration:=
 none;">[PATCH v4 2/3] arm64: Support page mapping percpu first chunk alloc=
ator</a>=20
<a href=3D"https://lore.kernel.org/linux-arm-kernel/20210910053354.26721-4-=
wangkefeng.wang@huawei.com/" style=3D"font-size: 13px; font-family: monospa=
ce; background: rgb(255, 255, 255); color: rgb(0, 0, 255); text-decoration:=
 none;">[PATCH v4 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with K=
ASAN_VMALLOC</a>=20
<a href=3D"https://lore.kernel.org/linux-arm-kernel/c06faf6c-3d21-04f2-6855=
-95c86e96cf5a@huawei.com/" style=3D"font-size: 13px; font-family: monospace=
; background: rgb(255, 255, 255); color: rgb(0, 0, 255); text-decoration: n=
one;">[PATCH v4 0/3] arm64: support page mapping percpu first chunk allocat=
or</a> </pre>
    <blockquote type=3D"cite" cite=3D"mid:YUNlsgZoLG3g4Qup@kroah.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">and patch2 changes drivers/b=
ase/arch_numa.c).</pre>
      </blockquote>
    </blockquote>
    patch2 =EF=BC=9A <br>
    <pre id=3D"b" style=3D"font-size: 13px; font-family: monospace; backgro=
und: rgb(255, 255, 255); color: rgb(51, 51, 51); white-space: pre-wrap; fon=
t-style: normal; font-variant-ligatures: normal; font-variant-caps: normal;=
 font-weight: 400; letter-spacing: normal; orphans: 2; text-align: start; t=
ext-indent: 0px; text-transform: none; widows: 2; word-spacing: 0px; -webki=
t-text-stroke-width: 0px; text-decoration-thickness: initial; text-decorati=
on-style: initial; text-decoration-color: initial;"><a href=3D"https://lore=
.kernel.org/linux-arm-kernel/20210910053354.26721-3-wangkefeng.wang@huawei.=
com/#r" id=3D"t" style=3D"font-size: 13px; font-family: monospace; backgrou=
nd: rgb(255, 255, 255); color: rgb(0, 0, 255); text-decoration: none;">[PAT=
CH v4 2/3] arm64: Support page mapping percpu first chunk allocator</a></pr=
e>
    <blockquote type=3D"cite" cite=3D"mid:YUNlsgZoLG3g4Qup@kroah.com">
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
that file is not really owned by anyone it seems :(

Can you provide a link to the real patch please?</pre>
    </blockquote>
    <p>Yes=EF=BC=8C arch_numa.c is moved into drivers/base to support riscv
      numa, it is shared by arm64/riscv,</p>
    <p>my changes(patch2) only support NEED_PER_CPU_PAGE_FIRST_CHUNK on
      ARM64.<br>
    </p>
    <p>here is the link:</p>
    <p><a class=3D"moz-txt-link-freetext" href=3D"https://lore.kernel.org/l=
inux-arm-kernel/20210910053354.26721-1-wangkefeng.wang@huawei.com/">https:/=
/lore.kernel.org/linux-arm-kernel/20210910053354.26721-1-wangkefeng.wang@hu=
awei.com/</a></p>
    <p>Thanks.<br>
    </p>
    <blockquote type=3D"cite" cite=3D"mid:YUNlsgZoLG3g4Qup@kroah.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">

thanks,

greg k-h
.

</pre>
    </blockquote>
  </body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/525cb266-ecfc-284e-d701-4a8b40fe413b%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/525cb266-ecfc-284e-d701-4a8b40fe413b%40huawei.com</a>.<br />

--------------6256AA368ECCC2BEADF11DEB--
