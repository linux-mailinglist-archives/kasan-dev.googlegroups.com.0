Return-Path: <kasan-dev+bncBCRKFI7J2AJRBA5HTGEQMGQEZAZ2XUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A63DF3F775A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 16:28:20 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id n8-20020a6b7708000000b005bd491bdb6asf610587iom.5
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 07:28:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629901699; cv=pass;
        d=google.com; s=arc-20160816;
        b=bGoOFaEkQj90w40fM+Gulw7w9ngCsO4OCpK4UGW0KdMzOTgFmI4sZbLjJ4sl6EAsZ8
         T6QJChbxJS8keFyTtNqYwfO1kXTl73bd6VDzAumWcU5VAkb8SScBhIqUNL1IpWikbEWB
         Tq90UdwUtj6iAbvNQtbSyY3nH6YM0fZJtlVtq2pvJUmG3vTIu9BhGynJ0subamiYkW0e
         bYBwsVzJzN/XgW28YYiXugk3XbSWX8y49xtpYoFU3Si/JSB+LOm001fXs+b0E9i8xTbM
         /o0ZLvISPxCp9hizrOxKOlmbJ4eYb9cX0Wa4YTjFQtSvtw15m/vpntoccBvMUELRB1uf
         u/TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=GCbueGG4kPR4N93C5fWlKsxLXyzFoxISwaw4ldZpuDQ=;
        b=edRkdjPQPqluDaBK4Zjx0OdMEDBqUrHQeNyadnqfyLxp2BlWo604/cU6s+dVhIhiz5
         RW8SIFsu7ZYqeLWEJmUF2GVA8xBWQZMORt+PPvgsdRjO6tVcGHRcM2CHL/5gRKOal3+4
         ECYljVtSkHhxjtTIO5aXmwwSgXKQ4KLnhw8nOJvpGS+9dc7GK9xL7OgXCk80dxI2J7fz
         GaUp5JXCryNBv73sKPs5BwUzronJvr9ZGhH951rQ1Sgl+wkkawLFyboPDteMT1z5b6jW
         qj2e8wg7KN2GjrPRH/cLeJDHKVGfrRmPzlrA1hGO3rbc0rZ6rprvk4kxsFGfSWYXx7B3
         mKtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GCbueGG4kPR4N93C5fWlKsxLXyzFoxISwaw4ldZpuDQ=;
        b=THnjVzjy2NWHSQWwEi5iDSPVO0q9+2+XJAVMHc6nUpBt/U2H20MD75EEkH6QND9E4r
         xSP5k8zznU8oX8V8KZQSS6NT5aU8Eo2P4su+bB0KcolT01xJwt6lFArSh7KL1m0i/UmF
         ZwAcL5IGgtqCPxe4mgf/IsX5ygYS9cX/TIbQALUXLGm6sIE0lrKFiOUKnxJcU47kZSMv
         uzPM1GC1xEP9O2V/xQ8aHkwpH+g7a4SPY+cHsmXto+kYIzMvH+jFfU4Jui/Rc/epjZNW
         zc0JCqRfLX79MYyeTaf4EcXrt9Jb+Zg1I4RFvTCsPF4yuCECWpvu1/2M/bW1w4LvgnMb
         ghvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GCbueGG4kPR4N93C5fWlKsxLXyzFoxISwaw4ldZpuDQ=;
        b=la9i9vqUDVYpcMw3auoaE2sFeaEvSM2z5GH3ep69SirfPc1a1VmvFqSkd5NWJrqBXW
         HOrrvTQfUW2adtFkM4BB/xZvRLSy3F1pu61MvejlPEh7y2ZxlDGQxAP/qPaBxyHPlgRO
         KRxBZCgyoT55sXF8nmne0pZwCmQYBhnnPzg7AMT8KixX+MojhuRo5FGEJ0FAY4kI8cEP
         C7rrWP9StVKmbBEg4iYmlNWaSLBPpasB2jHLnSYklsvXRgZ18019bb88BRj8R0fBmOQD
         ebqOjXGEu1uNVjW0DxhHbAaBPAme9r1EoR/vF8K/1UkMjnEuFejOTg2uY937NqVOMJEh
         gMBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IjWXEtmprOvR8IhnDteM0XAg6KmRwy6CwdDLtFw9rmGWMSsFw
	bQfEbMw+m3b8wdZSZuTaRUk=
X-Google-Smtp-Source: ABdhPJy4m+ZZawD6r/k3AATtfgiWqdPzwq5+ikFvWgUc4plT48yr1UZNRTqNb/7mYj/vPrFdZoEwsw==
X-Received: by 2002:a92:c80e:: with SMTP id v14mr32416521iln.57.1629901699691;
        Wed, 25 Aug 2021 07:28:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c7d1:: with SMTP id g17ls532744ilk.3.gmail; Wed, 25 Aug
 2021 07:28:19 -0700 (PDT)
X-Received: by 2002:a92:da87:: with SMTP id u7mr32158762iln.297.1629901699314;
        Wed, 25 Aug 2021 07:28:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629901699; cv=none;
        d=google.com; s=arc-20160816;
        b=fTX2/bUtuMpK95EccAQIfoKS0tpAUhJZeXIrzNznbdU6G+UNrcFsX8R8kmYamzm/es
         VUpolRuZbI7dA/cOdc3Qk7LnF8C/qThMFmn1plkq1qXhLRorPHulezS9R9ycFjaEd95B
         q6c7SUK3OXIk+i8WnhSLwzGKnB17SVYWxryCi46SDRrTK9lEpcaBwQ4e9y6fAA58s/50
         PkzYN71ZXA5Mh9aPKWuOrLPvIjgbPd6/iYieWDQxX+ZlPYW/KVTDXDTqs2FQLohyP05j
         CZOeq3Nr7a0iUrX3OatdWdggmACpA7jnaQ+xchsWoJyLnqwoNALx5PrWTN4koyxmVaHa
         lOLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=IkklPvR62wrnHbuuHbz07YDM8k0PnGfEpYkhYa7BjqU=;
        b=AOvSAmFRAXVYEsyplK96wb++Q5Y+YAYnVT7lI1sOUGr+VYyYhYBhpPiTldJabit05P
         tQmzzNQHPXD0w515UaXXsRu+MTZkgqPx13ZrkQxkf+2VhY7tAZlbddIaXpka6gIuyT3/
         2mjOmrxhxs9xgC/znPWH9WSUH44esg7c7UGds5Ep7hHEizucROexrgJlfVql70kbzxa0
         YyduMn+o/VFs8pjUjSgqEMh+Ax7h6pRp7+5KBMrcRqkAZRm9gXScQXOKnihjMNsMSpr1
         JnCqDfEdWKhg+QJ07KMfcrLmKA5kuL8eZHhE6CdibsECj1bYzpoKAeLuFHhR+yUgutnG
         Y6fQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id c81si13305iof.3.2021.08.25.07.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 07:28:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4GvpH32k6fz88qB;
	Wed, 25 Aug 2021 22:27:59 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 22:28:14 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 22:28:13 +0800
Subject: Re: [PATCH 0/4] ARM: Support KFENCE feature
To: Marco Elver <elver@google.com>
CC: Russell King <linux@armlinux.org.uk>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
 <CANpmjNMnU5P9xsDhgeBKQR7Tg-3cHPkMNx7906yYwEAj85sNWg@mail.gmail.com>
 <YSYiEgEcW1Ln3+9P@elver.google.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <7d08a5d8-7637-d109-cbfc-56e6449ae083@huawei.com>
Date: Wed, 25 Aug 2021 22:28:13 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <YSYiEgEcW1Ln3+9P@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
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


On 2021/8/25 18:57, Marco Elver wrote:
> I spoke too soon -- we export __kfence_pool, and that's good enough to
> fail the test fast if KFENCE was disabled at boot:
>
> 	https://lkml.kernel.org/r/20210825105533.1247922-1-elver@google.com

I haven't received the mail, don't know why.

Whatever,=C2=A0 I tested it, this patch is good and it save a lot of times,=
=C2=A0=20
so feel free

to add my tested-by, thanks.


>
> will do the trick. So please drop your patch 4/4 here.
>
> Thanks,
> -- Marco
> .
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7d08a5d8-7637-d109-cbfc-56e6449ae083%40huawei.com.
