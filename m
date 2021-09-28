Return-Path: <kasan-dev+bncBAABBYXNZKFAMGQEFOKNDNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D245941A900
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 08:32:03 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id x7-20020a920607000000b002302afca41bsf22706816ilg.6
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 23:32:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632810722; cv=pass;
        d=google.com; s=arc-20160816;
        b=BEGt5ALmBmnerDzbwH63ZRF7q+AQWYVihVcRbBTD8+uh2riUT1gVsGqkFd/FDMB2+V
         gcBlS6BJ5p3UXDufluaFSzksiH+NnDomtcftYL1juPiWsbQxPdnsY3liLSG4CP8YMvsQ
         W+UwgV30RI35MfuKJghoZEcGVUlOOj1xjQjSq4bvcZII1lY/pkXUua/HeEuH3fstxyV0
         UQm4Soa1XYuQ4EwI9rdSJ7l5SIIPk3TTGzB8lNLfknuuohoqbz5iIWClTe/5hwshbl3q
         9r8TyQqA+Pc5/MAn4UI6mYt7xKDpaGR5oG4KOb14FtnjFEoJGDvyfg05AoWOS4E5Y+dp
         hxXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=33n2yhnDHPdeLo0Bqgib5F2UOQfLYJ1ZEVMVpbAgrzQ=;
        b=faxASAaJz2xI78QPhE7yssItqMHnYcS7CBd3TWd2LiIRO74uS4HV9G0CrePyUC7/0b
         Y4ARRCtICs1u1ZKgWN8iuhDRGulw7b2WJt06yIJ70wImEUVCKeSvy22at//u7JMRgyxx
         CMkAaB+rorSKotJfAKfl0n7qXGCI5XQ7E6q1Vq4u7YKipSegM3nvbvuhSHXcETq6EqQr
         rz2tEkGhJ8pHQ/3rzO5CmlkE10bH1JPPFUgqnKzBOa3tLoLv7DQQYvm0PAu5xIK3hdDA
         mWDYmq3sprl8eeMO/IGPzGe8+ZgrR6UmXwfdqrBPelD00cONT81cq6FyPAhDNxPFC8Ff
         nBJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=33n2yhnDHPdeLo0Bqgib5F2UOQfLYJ1ZEVMVpbAgrzQ=;
        b=LU8/npo/4e9V0a2Q/5nXpr04VN2Vzawee65+itOMG9Ba9Xp8YPSqksd/Q9xAd4RKsf
         rSXhS1YC5IT8g5ZiOZagYja5r/vXP1Qhvs3F2eKCyH++z548HJAKvVLYqbbLoklrZrNt
         NzeaiOw4QTUCADvCcsottMdD6MD+ePjr3OQK1OPjtnhg4DFnAt078yimQBmxd0gX9Yn0
         EFYW8jwPMpuQHyYdZbwS6BKTr/m+OKfJh9n1/YE5FpkIEr5wWeSRAedfr3wcowlvrCrP
         RVoSjpkAhMC3msXHRKt+dNjfJjrYGOzxNlno6vS4JumGFVpUhapidGYZ8VMbCP7/3b8K
         5TSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=33n2yhnDHPdeLo0Bqgib5F2UOQfLYJ1ZEVMVpbAgrzQ=;
        b=ou/QkDP1kchQoVEU5C9/MCFqs/NIMs+MLMfQuUID+45v+qt3U4C3dtY/TmU3wUBAaQ
         XegzDmUwwNSruEoK2TSCDjpeoC0yBCNaE+k+OXCv3MA+O38HoUK/5PknprEEtz8kScnO
         jiX02NHIpbK+DiZIl/oqQ2bm2X2LWPc3m0yGzmtkZ3nSW+JJDuanHUZEbxgfwO5YiaYh
         uulwvQTGueP6D9HbVZGdjliqK4HaHhI6dUhZDG/r8IMbKu8f67HznJkjyU8aeOCrs/k8
         yEG76hsgj4mhX+99673q3M6AtXKHvH8JPnZ44nsSiczl8g7Efa9/Lck0HOhW4GfvA2Tc
         QDPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320Dyd9yLqUcKDeqqwRFlJ3tiCDukRldQzCzamlkrfbrk1a2Rpd
	c4D+NEbcnWuHWL+CZhmjwYc=
X-Google-Smtp-Source: ABdhPJwrX9zWjQtN7w1Vj22x29RJZfYeNVP3vwQq3MwMec6K2kl3QgyT+JjulYCQd1+iDXhAissP6Q==
X-Received: by 2002:a5e:db0c:: with SMTP id q12mr2810063iop.32.1632810722491;
        Mon, 27 Sep 2021 23:32:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:3f56:: with SMTP id m83ls3620758ioa.5.gmail; Mon, 27 Sep
 2021 23:32:02 -0700 (PDT)
X-Received: by 2002:a6b:5106:: with SMTP id f6mr2662163iob.116.1632810722164;
        Mon, 27 Sep 2021 23:32:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632810722; cv=none;
        d=google.com; s=arc-20160816;
        b=H8YtH2a5Qt0pUW1L5pWmfg3ptXLEbVrkVlA+wtT0wPYk6DwjCKEtjFFV7IvUsBlpgN
         HN1Tedht4fL0aFiymgXrUxzfT6Ws7e3jMYYvUFuxqMYX4aXYcXkmP4o2yCy+cRN0bxdB
         2GC7pmgEnt8y5UBWcGYpw85f6zoD3sB7SPCU8WhB8Tfnu1ulAnhnUJb0gZVDaCUzHXUC
         YAaE3sLikoFKSSk63RrmwtnrC3b+IoFQ7b9Stws9D51DuvLr+O8DepH7CsLtRquKVv1v
         +tH9Dg3Lq8X8PEgZZxcWZo9ZxDfB8M3qhG5OTUheRiw5/yJ7wNnh7Nw3CAlU/qtKwwrU
         +cSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:mime-version:user-agent:date:message-id:from:cc
         :references:to:subject;
        bh=qtSrAXCqEmL17C3LV+h+JNGDTQkJ/U0juVPvyk2XHKg=;
        b=OFc00bYUpK+eopfeRi54oHdzvqlNKC4Ela4abjJkZVYe8MkYLoNHbPOvUkH4CnZ+eF
         SZibkewOV2DWiSRQbYfip3kAcpEA1D9McY3ZySleR/NotLkZOAPsIgZzyukxpOzCN4Y2
         iBnB8A4rJhaS6AS5odNDx9yAeXj1Xk3XU4o+Kqsl6QVR0CUebXSi0pvlK63olVadAke0
         MRGWIc5dQzZnWFvBaq1PGaErZpWF7y5LdsN65DyW7viGZqCDEvuY/t17vkaCwH2xUZis
         ejfvvWFUEVJs/oAiP3OT2vTmhyi+1v/LhoDNf8npt41Ui42ZIxLRIzotfNqlAlfimB3V
         Hr0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id u12si229423ilm.1.2021.09.27.23.32.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Sep 2021 23:32:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HJV0d2QxDzRJ9g;
	Tue, 28 Sep 2021 14:27:13 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 14:31:28 +0800
Received: from [10.174.179.24] (10.174.179.24) by
 dggpemm500009.china.huawei.com (7.185.36.225) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 14:31:27 +0800
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
Message-ID: <a229a46f-5e00-5aab-7271-e6104a331988@huawei.com>
Date: Tue, 28 Sep 2021 14:31:27 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101
 Thunderbird/45.7.1
MIME-Version: 1.0
In-Reply-To: <CAG_fn=X=k3w-jr3iCevB_t7Hh0r=qZ=nOxwk5ujsO+LZ7hA4Aw@mail.gmail.com>
Content-Type: multipart/alternative;
	boundary="------------F2B6EFCCAD7488DC98B9459A"
X-Originating-IP: [10.174.179.24]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
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

--------------F2B6EFCCAD7488DC98B9459A
Content-Type: text/plain; charset="UTF-8"

The previous patch by Jisheng Zhang guaranteeskfence pool to be mapped at
page granularity by allocating KFENCE pool before paging_init(), and then map it
at page granularity during map_mem().

The previous patch has a problem: Even If kfence is disabled in cmdline, kfence_pool
is still allocated, which is a waste.

thanks,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a229a46f-5e00-5aab-7271-e6104a331988%40huawei.com.

--------------F2B6EFCCAD7488DC98B9459A
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta content=3D"text/html; charset=3Dutf-8" http-equiv=3D"Content-Type=
">
  </head>
  <body bgcolor=3D"#FFFFFF" text=3D"#000000">
    <p>The previous patch by Jisheng Zhang guarantees<span style=3D"color:
        rgb(32, 33, 36); font-family: arial, sans-serif; font-size:
        16px; font-style: normal; font-variant-ligatures: normal;
        font-variant-caps: normal; font-weight: 400; letter-spacing:
        normal; orphans: 2; text-align: left; text-indent: 0px;
        text-transform: none; white-space: normal; widows: 2;
        word-spacing: 0px; -webkit-text-stroke-width: 0px;
        background-color: rgb(255, 255, 255); text-decoration-thickness:
        initial; text-decoration-style: initial; text-decoration-color:
        initial; display: inline !important; float: none;"> </span>kfence
      pool to be mapped at<br>
      page granularity by allocating KFENCE pool before paging_init(),
      and then map it <br>
      at page granularity during map_mem().<br>
      <br>
      The previous patch has a problem: Even If kfence is disabled in
      cmdline, kfence_pool<br>
      is still allocated, which is a waste.<br>
      <br>
      thanks,</p>
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
om/d/msgid/kasan-dev/a229a46f-5e00-5aab-7271-e6104a331988%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/a229a46f-5e00-5aab-7271-e6104a331988%40huawei.com</a>.<br />

--------------F2B6EFCCAD7488DC98B9459A--
