Return-Path: <kasan-dev+bncBCRKFI7J2AJRBHNQR6DQMGQEASGUGHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D83933BC528
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Jul 2021 06:12:14 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id v184-20020a257ac10000b02904f84a5c5297sf25754794ybc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 21:12:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625544734; cv=pass;
        d=google.com; s=arc-20160816;
        b=tnFRtXIsptwItymfk7/u8g2LyECQW2yC7V5OODaIRdgYA8iW0XZXeuALiSg6sCoqcM
         SxXjWzpvCEpJXrvIj4ahlsN5isvMPn0zMrciRDcPaLakSNXurUqzWUB+5hzIBV4Xd0OJ
         Yll7dHR+UF6gaOPAUDX5QD/fG847NLn3dgh8/jrrz4/TMxTVm9jJGPaB3UdwgkkY8Oyv
         uYPjGHtpiIQ+0OcdOvEFMKo/31TM1Sq5JEvVKo9qV0F/VIdMih7dEQJLIPUEplkbp4q5
         y8Em+7UUNlwqcpczcyDSopK3B2FG1+9bnEPcKNJ4lgWZeKSnOVPei6zxdxPQ1+M/OdPp
         eJ+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=lUan48Fvd7vwruYyST8gdfRWlTVisQJzCZ75sV9J/ZY=;
        b=jYUKcsqAjh7cezLGAI4O3q/Igw7A++Cv7afnaA2YMos5AaeVWmUcd9xLFbNPziVpC+
         TNSCQql7i2BVJQWANRJwUqkfg+C6qWiEYPYW/WmyL5hnPaI5MLt/XWIuFYtt5xHUlgN8
         /XVgoYWnAp/2FLzeChkwX1uwNEFeDNjSpz9zGko0L2ohjPDaZH83QhCzZnYY0aHMR0XA
         RNrzruUcnhJUY0Z4IUhV77Kbu8TQvZFozuYyCh4N8cvwMTm/O3fvQxAyWWh3VweXggU0
         D6gg2Gm5Ph1IkYqgCMWuTIJ0F6jkfRb0vfo9QXqpLMkT1BkcNEJUFkHrErg9Gk75dZL7
         T+GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lUan48Fvd7vwruYyST8gdfRWlTVisQJzCZ75sV9J/ZY=;
        b=VPBrIBZTAKoUOL93GUlnZyDQYk1eGJeuy8anU5ZFavDLlKSGmO/Bnm5xbqvNSp6eOD
         0h1///H+Ee4iq0aEfddoIOwUrQCYoAlA6BC7hy99UxBbfaeSRGdKBatILTLbe/7f73ck
         N+ph5No7CYSLvrrk8R3b8Gt8hrIn6Vl+fnge5l+tL4sCytBw6c09y3HZC24iRMkFBmLF
         5+lwmQDTFR14+721vHQk0zL4XsJUJ0ZCuxEoWugRVBqPagPbJ4MfD+qkgi+/gkIH71E7
         D8k/dM/xqv29K5X+cZfHOM6J82ZDVbLqltgIoppgXa7Ql+/KtMzuGvnpkWNiWdssEoT3
         DLxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lUan48Fvd7vwruYyST8gdfRWlTVisQJzCZ75sV9J/ZY=;
        b=Y8ewnnzCiVQuDuwQn1Dputf25anDvqMoJaO02lc8Tcb0g4OWIm7MpFruG1UuPy7SZC
         kNsKTSIv3DMA6d4MNzpe3MIrE0WjKh3c64vqZEKAn/4ocqVpgpePEONDQAbemzm6CN6X
         vdCl1nUrz9qWbCdx1zj57YLzUPk6+IpoJ2dq/W3We+RrXe6W6vdfIC/7TK2KbAtmItGP
         5TJW44j+ixlAYgwdaI4COsls3p8SBXfs4GeCXvnv1aKZz8UaUms89taAgGULuCTfm+Z4
         guu6MTBhSvV76UVqg8fkM6LFnDO7zx34t6nHuxD1fBjyXUozA/8vRgB+Wpx5PSLr4W7p
         zthw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304s6O2XmbFl7ZAYtQ/Do+cvnR4P5rCPiZ1dpT/AQUZkLiCUnKR
	uFVW/FmhQVINjfmvw3q0TiM=
X-Google-Smtp-Source: ABdhPJw6TkUOpvNVw+JTxq3PlhtTa45kMgSl9fYs2RuTmuf6b+d7MoJjEI4oafnbgTqQHFezz05Kfg==
X-Received: by 2002:a25:bf8c:: with SMTP id l12mr20329936ybk.200.1625544733938;
        Mon, 05 Jul 2021 21:12:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3f06:: with SMTP id m6ls4338971yba.6.gmail; Mon, 05 Jul
 2021 21:12:13 -0700 (PDT)
X-Received: by 2002:a25:af06:: with SMTP id a6mr21888762ybh.326.1625544733423;
        Mon, 05 Jul 2021 21:12:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625544733; cv=none;
        d=google.com; s=arc-20160816;
        b=HaaU2RWRvp/u1Pph6ZmWVyNrLRQqCb+oYl7X4XfNWbbhXgCUxqLRYEIug1v9SnHHbi
         VHcddPnzUGdBnLNTsMALu7NQXnF4Sb1ffNymU552Q8obUkF8dO+W8uwjNSSySDEsJ3Vv
         lKy+beMayGe6heYWudYPVH47Tmsgk1VMMH69p9TiOt09188qzbPjU6MDB2UJ2Lz+VSXW
         fzqy9qi85HxkHu2U8ADuRTUHQlXIkZ3TGnjV/JrbJTWmZgUsnKiUr7hHJXOsLuPshcM+
         /ZV6eCivb3STqDe9gewtcn5QMYa8wXjDddEsKfFZgW92vbW+6bzBnf9ciuOvsmiSoLlL
         Q8xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=QAqj8RZaJwmer9o5zU1GEzSwr/6CqANktVpVmte4XHE=;
        b=ZjUJfumTKVpgRso52vknLY5PGfVLgT3bbn5QdBBYQK9cOD51DM9ZKm38j8QmqoKj0D
         4wLjQOybjWJHcr80NE0i49J9Yo+3gzdQQUmgyMtG8tKu/eTsWmVr8pQ9DkEDWBmQ/lc7
         J6x9/thFs7Imf4Pxnp2X2LG72mtR8tjMZ18Yp2jSbXYVvGW+0r6ZANSxrzVGFfax6o7t
         98NDZqLoYiZRjkiYOCtbFeLVk1jXTEAcnEAadVaS82lKckEzgur/mxt0KjsID3rLsyoW
         /d0F5vIhx11RT0aFMF2J89wnNpt4/56yHEoB2frs6MZsN0LjDetJDw9icrG2wRDidIX7
         ctQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id r3si888402ybc.1.2021.07.05.21.12.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jul 2021 21:12:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GJpvc0Kmtz78ST;
	Tue,  6 Jul 2021 12:08:44 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 6 Jul 2021 12:12:10 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 6 Jul 2021 12:12:09 +0800
Subject: Re: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
To: kernel test robot <lkp@intel.com>, Catalin Marinas
	<catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, "Dmitry
 Vyukov" <dvyukov@google.com>
CC: <kbuild-all@lists.01.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
References: <20210705111453.164230-4-wangkefeng.wang@huawei.com>
 <202107052207.RUhTJd4N-lkp@intel.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <3463cf5e-2562-7a23-6c57-421d5c3e2b4f@huawei.com>
Date: Tue, 6 Jul 2021 12:12:08 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <202107052207.RUhTJd4N-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
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


On 2021/7/5 22:10, kernel test robot wrote:
> Hi Kefeng,
>
> Thank you for the patch! Yet something to improve:
>
> [auto build test ERROR on next-20210701]
>
> url:    https://github.com/0day-ci/linux/commits/Kefeng-Wang/arm64-suppor=
t-page-mapping-percpu-first-chunk-allocator/20210705-190907
> base:    fb0ca446157a86b75502c1636b0d81e642fe6bf1
> config: i386-randconfig-a015-20210705 (attached as .config)
> compiler: gcc-9 (Debian 9.3.0-22) 9.3.0
> reproduce (this is a W=3D1 build):
>          # https://github.com/0day-ci/linux/commit/5f6b5a402ed3e390563ddb=
ddf12973470fd4886d
>          git remote add linux-review https://github.com/0day-ci/linux
>          git fetch --no-tags linux-review Kefeng-Wang/arm64-support-page-=
mapping-percpu-first-chunk-allocator/20210705-190907
>          git checkout 5f6b5a402ed3e390563ddbddf12973470fd4886d
>          # save the attached .config to linux build tree
>          make W=3D1 ARCH=3Di386
>
> If you fix the issue, kindly add following tag as appropriate
> Reported-by: kernel test robot <lkp@intel.com>
>
> All errors (new ones prefixed by >>):
>
>     mm/vmalloc.c: In function 'vm_area_register_early':
>>> mm/vmalloc.c:2252:2: error: implicit declaration of function 'kasan_pop=
ulate_early_vm_area_shadow' [-Werror=3Dimplicit-function-declaration]
should add=C2=A0 a stub function when KASAN is not enabled, thanks.
>      2252 |  kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
>           |  ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>     cc1: some warnings being treated as errors
>
>
> vim +/kasan_populate_early_vm_area_shadow +2252 mm/vmalloc.c
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3463cf5e-2562-7a23-6c57-421d5c3e2b4f%40huawei.com.
