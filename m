Return-Path: <kasan-dev+bncBAABBQ7LZKFAMGQEUQTB3LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id BE81741A8F4
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 08:27:16 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id rm6-20020a17090b3ec600b0019ce1db4eaesf1598732pjb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 23:27:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632810435; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yx9CkraQv5yKLDTRTtyag0K/34FhFZzs5l0pP4HG5tBAPOIfX/LiTtoZGBMx0AWJ6v
         YVLECm3JXZCukhK/wPs/rFsB6P1qnJgT1RsuVnrfweqX2qGwy02A+gnJQa+VQavWVR3i
         0ZD/xcY43GluX3+hRQlOcSzWjhjgp+8hqUtEhHQ17JC+HVRQete4ucUpw87QniUplmXf
         IUaeYcf6w7GhwbZDL49HfdTa4NKirwLhYu32V5JBqYFAD9uCC+tGd1oVQTJy0y267jd3
         iUHX9crPrxQX4Ix9S2BZ3l6JzOJDLB4oVTowx4hCa/VVQQzmco9SfoQMR4AH5yLWC0lU
         gcnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=FbCFnr6hpe9N53ELA1YA4CRFhOhimGJTy016tmS5z/w=;
        b=hUdFwDr0VA9wKi47J0svf2xIzysvBMQS3evbtkYr746h6Qm50mZBOeok0etL1MiIpR
         jYhPy2GB+Y5vyKiiaXqPrzrblAK4hmSbkNH7eX1SO/Aw/pOcVNuuoDhPj6TcJA+ZP3GX
         eRB2xhV0IgAgRqq/mE8AfoyLhxQ3luqjn2bR11uDkKQ+o/5hOKQc6iRXIzz7c4VaQY0x
         qd6C4hnZLaegVTjFLa3EKtFtSRKGCFZRRQCQjQOWfrQ2KQkmBvac6DKRLthPqZAujQgt
         avK7NCzsh1mkNm4R/BIeDLJhF9soACm6kNp0A4iU97UPBJedaZCk5ZfsHzXoeWtL78WH
         bDUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FbCFnr6hpe9N53ELA1YA4CRFhOhimGJTy016tmS5z/w=;
        b=d7wGYFRjSDRSUMoEIkZc3mey+jotOns5zph2y/sD0aNPR+02YSaMFJWeZwpvZCFRnh
         ILRXT6KA2g78Snv4U3geni56wcXNvPylBuxOq835bo/AYLIWTfEgttXJFOlprt1N4/Hv
         Jy9TOQSpq7nzdYVz73Ka0coU/yKHCPDJ0BUT7a8wx7dBGjRWxDz0klQbXXBYYJmDKiWP
         pAaBbq6j8w85iWl7n13K3LrkshpNj2GhF9PrM4BG9uONgID5/ovRsGcKpRN4oDhmyukX
         iy9xYPugJ7RS9T4K70DQKGpWeVS1RFc1PyRDiNBoA97ehrIGaFpo1T+jB921FCjUwgut
         JNtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FbCFnr6hpe9N53ELA1YA4CRFhOhimGJTy016tmS5z/w=;
        b=1bi7NsF6PIuZ6+WcKbRbqt2xBckRXIZNCDm3lN6IR1gbbkd8XAvsefVrrUPvJN2XQB
         JZM5GDxnJo1nPXiuaF6SiBmGAx0UVfm0T9RpZRp5dh5vNnPfjvjvvecIFlgR1Nhef2zE
         q68n9GZrEy0WYYRXjpkD5CgC0+TDQTcZqdH1dFAjLR2U9A9MU6AvSzI1nzIuiX+9ih7m
         yUTVk1EKUTuouYm8G70rnQMxov6S6L30KULRyj2/1uOxEjBqcHrRT/dAr94p59QN5ZDt
         DuuoPhYBoAO+feSwoLZmfQvO8INrjq2Vg5nAei68iEj88chVS8bLb9kkHlum483mqYtD
         PpWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MMvCpqhCiVS5Zrfqs2vfvcS8HIqR3Y/F0uV7JBj2VLU/EfSLc
	Po6SLHZOSsP3ftlSgq4BQxY=
X-Google-Smtp-Source: ABdhPJy31H7aIeSVhvfJJxzAjQNLqGMRXasFLayp8R0Jnf5OAo1s9+NbQn69EZU2Ojau5rfopjJbBg==
X-Received: by 2002:a17:902:e88d:b0:13b:8ed2:9f42 with SMTP id w13-20020a170902e88d00b0013b8ed29f42mr3510334plg.67.1632810435420;
        Mon, 27 Sep 2021 23:27:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f293:: with SMTP id fs19ls1125798pjb.3.canary-gmail;
 Mon, 27 Sep 2021 23:27:15 -0700 (PDT)
X-Received: by 2002:a17:90b:1c8e:: with SMTP id oo14mr3604384pjb.224.1632810434964;
        Mon, 27 Sep 2021 23:27:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632810434; cv=none;
        d=google.com; s=arc-20160816;
        b=XpmW2tW0tjcimKUpcfam2OVLOOIG+9v9MNPfehEUGgqSbjkBLBvsrFQDBxIszp9UN4
         4feeAZIIzvqcyc26xF74CAL8jlSI98sEZFlZ8IHzieCN5k/upRTjn+mq4IzDV2bP2YDW
         3UZ7yo6FJne5zpjIJKTbbLzWTsi9FAP3DUk3gFbRMQ4ys7v0y/njy9u04a85yZ5keees
         NJCsk/bWqz86KsTjZiftf1/ep9xhBDynUKcwD+lTxVZFLsY6dctWhsf2/4Ft8bpVIVjy
         dWeJ5j2nJuObkxsKmzAh7+FA8dhRVRtb9bDUU4UljSomQnd78Y8SK5TPQ9DQK5dBBv7J
         LxJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:mime-version:user-agent:date:message-id:from:cc
         :references:to:subject;
        bh=fHf6IHBNQrfZjy0kNbLYbcYp0xTXTsuV9Hc/8v4bhRs=;
        b=FD6yspYcx/N7qzkgGd6CpFjYW2hJtrPXqWQJmX7B3ZR59zx3xkjyPH+lOk8dW45skt
         5ipUYNQXRoSbbwlKu31Hjb2dAkHcR402b6x5vI9T+NTe9OLc7V9E4bKULKjKMEVi9fUI
         u74xnqkQTdiqxS0zO8pDhCZq64KKMsSLjD83QQ8PfrPHY7JhS9LnEmYNernAAg9KTCOb
         bo/vNwflL7XAkAl453WZJJ+aFmoONVix4/jXFll9jG0o0DxZflJFXJikY6tBqstSH169
         9c8ruqgfpz9bOgXKs1u62fkEH1j1cVdAm/OLcbd6yPznNJ1XjIzHyATxzUvhpKzN2zkJ
         vP1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id j12si1063325pgk.2.2021.09.27.23.27.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Sep 2021 23:27:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HJTtb3cZnz8yxC;
	Tue, 28 Sep 2021 14:21:59 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 14:26:35 +0800
Received: from [10.174.179.24] (10.174.179.24) by
 dggpemm500009.china.huawei.com (7.185.36.225) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 14:26:35 +0800
Subject: Re: [PATCH] arm64: remove page granularity limitation from KFENCE
To: Alexander Potapenko <glider@google.com>
References: <20210918083849.2696287-1-liushixin2@huawei.com>
 <CAG_fn=X=k3w-jr3iCevB_t7Hh0r=qZ=nOxwk5ujsO+LZ7hA4Aw@mail.gmail.com>
CC: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>,
	<Jisheng.Zhang@synaptics.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Mark Rutland <mark.rutland@arm.com>, Liu Shixin <liushixin2@huawei.com>
From: Liu Shixin <liushixin2@huawei.com>
Message-ID: <a40ad1f6-e2ee-5026-7b40-3c36b3bc0172@huawei.com>
Date: Tue, 28 Sep 2021 14:26:34 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101
 Thunderbird/45.7.1
MIME-Version: 1.0
In-Reply-To: <CAG_fn=X=k3w-jr3iCevB_t7Hh0r=qZ=nOxwk5ujsO+LZ7hA4Aw@mail.gmail.com>
Content-Type: multipart/alternative;
	boundary="------------09D87F42F046D6A2C075D970"
X-Originating-IP: [10.174.179.24]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

--------------09D87F42F046D6A2C075D970
Content-Type: text/plain; charset="UTF-8"

On 2021/9/18 19:50, Alexander Potapenko wrote:
> On Sat, Sep 18, 2021 at 10:10 AM Liu Shixin <liushixin2@huawei.com> wrote:
>> Currently if KFENCE is enabled in arm64, the entire linear map will be
>> mapped at page granularity which seems overkilled. Actually only the
>> kfence pool requires to be mapped at page granularity. We can remove the
>> restriction from KFENCE and force the linear mapping of the kfence pool
>> at page granularity later in arch_kfence_init_pool().
> There was a previous patch by Jisheng Zhang intended to remove this
> requirement: 
> Which of the two is more preferable?
>
The previous patch by Jisheng Zhang guaranteeskfence pool to be mapped at
page granularity by allocating KFENCE pool before paging_init(), and then mapping it
at page granularity during map_mem().

The previous patch has a problem: Even If kfence is disabled in cmdline, kfence_pool
is still allocated, which is a waste of memory.

thanks,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a40ad1f6-e2ee-5026-7b40-3c36b3bc0172%40huawei.com.

--------------09D87F42F046D6A2C075D970
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta content=3D"text/html; charset=3Dutf-8" http-equiv=3D"Content-Type=
">
  </head>
  <body bgcolor=3D"#FFFFFF" text=3D"#000000">
    <div class=3D"moz-cite-prefix">On 2021/9/18 19:50, Alexander Potapenko
      wrote:<br>
    </div>
    <blockquote
cite=3D"mid:CAG_fn=3DX=3Dk3w-jr3iCevB_t7Hh0r=3DqZ=3DnOxwk5ujsO+LZ7hA4Aw@mai=
l.gmail.com"
      type=3D"cite">
      <pre wrap=3D"">On Sat, Sep 18, 2021 at 10:10 AM Liu Shixin <a class=
=3D"moz-txt-link-rfc2396E" href=3D"mailto:liushixin2@huawei.com">&lt;liushi=
xin2@huawei.com&gt;</a> wrote:
</pre>
      <blockquote type=3D"cite">
        <pre wrap=3D"">
Currently if KFENCE is enabled in arm64, the entire linear map will be
mapped at page granularity which seems overkilled. Actually only the
kfence pool requires to be mapped at page granularity. We can remove the
restriction from KFENCE and force the linear mapping of the kfence pool
at page granularity later in arch_kfence_init_pool().
</pre>
      </blockquote>
      <pre wrap=3D"">
There was a previous patch by Jisheng Zhang intended to remove this
requirement:=20
Which of the two is more preferable?

</pre>
    </blockquote>
    The previous patch by Jisheng Zhang guarantees<span style=3D"color:
      rgb(32, 33, 36); font-family: arial, sans-serif; font-size: 16px;
      font-style: normal; font-variant-ligatures: normal;
      font-variant-caps: normal; font-weight: 400; letter-spacing:
      normal; orphans: 2; text-align: left; text-indent: 0px;
      text-transform: none; white-space: normal; widows: 2;
      word-spacing: 0px; -webkit-text-stroke-width: 0px;
      background-color: rgb(255, 255, 255); text-decoration-thickness:
      initial; text-decoration-style: initial; text-decoration-color:
      initial; display: inline !important; float: none;"> </span>kfence
    pool to be mapped at<br>
    page granularity by allocating KFENCE pool before paging_init(), and
    then mapping it <br>
    at page granularity during map_mem().<br>
    <br>
    The previous patch has a problem: Even If kfence is disabled in
    cmdline, kfence_pool<br>
    is still allocated, which is a waste of memory.<br>
    <br>
    thanks,
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
om/d/msgid/kasan-dev/a40ad1f6-e2ee-5026-7b40-3c36b3bc0172%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/a40ad1f6-e2ee-5026-7b40-3c36b3bc0172%40huawei.com</a>.<br />

--------------09D87F42F046D6A2C075D970--
