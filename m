Return-Path: <kasan-dev+bncBC447XVYUEMRBF7NWGBAMGQEN3BSGPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8792A339CDF
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 09:23:52 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id m16sf8814288lfg.3
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 00:23:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615623832; cv=pass;
        d=google.com; s=arc-20160816;
        b=n/9Rd+EeWzKw559KJ7q2eWA4O5OWlauKz+T6jdBo2kbdMXvn+AQT0R8S04svBKLIT8
         /4iDNWi6xz9dBe/oBim/OYTEbo7yOKnj+uVKB5/vMpmkDr+37uh+MhMYbHKLQkMZW4s6
         eOKDusi05GNuUmsGN6wcgOR9n2sBM5HhAArPZBm8qeTvpuC2o31tecLVai77UzNkXCVi
         yQvfzcz9SjlNg7b5wPNy18me0j77XaGZytApTH7QCtc+UZFxIFEq2hW3q6m41AOxmma+
         spsxCnLwjN+MFC8DQ0EdOp4f5GstutreVH/ZlOZ6MxVNjelLE43Ke5WRpDTF30B4HXXj
         nUpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=SW90VQXCNAaXFADxh575wozHbx3qmUgZoIEtxcoR/8U=;
        b=wBOUSo6MCMZZzQvltv/ttYW0fSduDyyXtvGwiid1cYM4tug7zNwVo7ZAEg2RLUlUtA
         fK5AIocefq9klO2SqvoiCc3BdaOhT7D8rBO6+NPklN7HeiFJjmYD4WZo8nAQ+4Qz6OJE
         8Vay5JFUp9lw2nDE+vm69YQKYxYelzLoo0ZUFeuW3N/KUcz2Xmb74/UIcWtpJDJpp0qI
         Ka1SNSCASVu0nvylsy8O+HYkrxNY3KI29sruxW9ry705UtBL+OKL1XVfnPhVEQfAO2Al
         r+YNsmYoYchZF73PgPQC5jo22d/JBGlSejOj2lJLUQyLu/jezAZ4U4WFpoQXndXzMtug
         ZBow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SW90VQXCNAaXFADxh575wozHbx3qmUgZoIEtxcoR/8U=;
        b=Y7oEWxZ02KD2Zj6afs4VMUNd/vOSI7N93RjtZJgHy/sILw0aHFE3BX/kxtLuLzeWfU
         /MdPSnbrV3tkKRGk20W6P7I1Ulm/FC7sAvzDN8wkVRVVuBHIi/NH3AlAAR5xeXhnptjI
         6MKnQwnF17Xe2adzVWo0i+Mk+lKF/n1sTXu+zIr6KfDJJGX1yvsp/j0qbrR0FBiDlIWt
         0boBcS+v879eDStxFhMRbp12LJe3WxKhdMUVE0ZLm29D4fl4QLZGt69OB72hr+hHSNp4
         YhWTQrBbziopw3dMHIUOfIJQtXGal1Zdfl20O+bps2CapB4jy+gnohmMDL2BzQ7U5P9t
         ehRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SW90VQXCNAaXFADxh575wozHbx3qmUgZoIEtxcoR/8U=;
        b=mD8YLblxj7Q8/+QWqL7ZkC+rzOgtYVnLp9Dl5iXUlvDsYi3PlF4d+WttNrdhRtb+cb
         r5pkuBAEXlO79vnIiB0iJ2Poqk9qkEpIeLn7vyNUZZNpzn8539Ta/9vXtvhnb0NaOxUZ
         1F+mKPY11XhWYEQKk2LKD7j+AU086fvj0RcVP7PGuNemEVnvmZT48VB++jUiAxpFMldz
         m8S4t12U+5MBKJNds8M88e/Egl4jTufZfQbc0QkSJRORNlf6NLSc58dLijZ3KOvnqE74
         2+jxNAD28M/QL6OUwxlvWThAE2K/QRo9Raf7Ay0IoW+cEpNhm4o37CyuWQCi6Yl7Jzj6
         zgHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EwZCfBkNZIugwa/zEdgcGRRPFgZ1oIxTc7IkUna9oevHGwKnV
	yBrpVYAixNrLghP1e27Bknk=
X-Google-Smtp-Source: ABdhPJzNsWaAwPC4rryGG0/S6bg1PACM5xmSqmACZOUPTZVJOyXYNh+Fyd4XZjNoIblMvpEKkkCBdg==
X-Received: by 2002:a2e:b894:: with SMTP id r20mr4751945ljp.222.1615623832013;
        Sat, 13 Mar 2021 00:23:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls3807lfo.0.gmail; Sat, 13 Mar
 2021 00:23:51 -0800 (PST)
X-Received: by 2002:a05:6512:2304:: with SMTP id o4mr1989683lfu.197.1615623830917;
        Sat, 13 Mar 2021 00:23:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615623830; cv=none;
        d=google.com; s=arc-20160816;
        b=gFE+hwolFymG0fxfRXtO2HKtkylSW975IXTV5H8L+mZyuV2NS8p9vHy2S+KlDdci8c
         heIoC2LG7HfnblZ3c0qvb0z0GJqjajWW5y37oDKSTXle56cFrAKi8GhpncFiBq5RZ4Nj
         mpm0NNUZZMtfS2KmJYzFD2CWEy+0CZpiARZDvdRkwVgBXVJhNeiiEi4V1JRURMprxNOU
         ODkHnAfx/YPC2TLijrFsDjAX724j0SBvFAFhLnrOCyoTXwsxXgR+xAWT8sh32/hcNUy6
         vRZFtLDDlkZYOnkp3DJyirHahZ3Lpbxy03Ky1nIDncMZhF1U0jvLo1b2E1kgz/JUcKxU
         nMBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=IktgvvTDtd1vW4cm9wO+7RodcN6AqcOTjkkvO/B6blM=;
        b=NaCuI4aSrKe0TjcdFh212dr9cynzSXGds7R30JUYh6IlRshJWfSafJcXq4MtU3oOw7
         p+caLKkIui5Ywh2JH6ndZFInel1B40V1GcudAzvxnnYhAyDafwM+8VQj18sHg3FM4Eeh
         pNWDJ2rISmg7FEJGLUbxqkf2OnEsD2AxdcK+/+LUT82TWBwRGKIUt+6ykWhJKfYcOItz
         8iLhiph2ibkB8fQwGjQCTeCwDpW2FfiL5oI+ji254UYkwkbrLK6tejmyORp5w2UVaU0+
         QuKu9GWwIZHQ0TD9c/vJ9rHyyn3PpXtUqFCfXB4PUIhTMad8rF1mZriR3Fgry34MpiZi
         MXpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay12.mail.gandi.net (relay12.mail.gandi.net. [217.70.178.232])
        by gmr-mx.google.com with ESMTPS id x41si216331lfu.10.2021.03.13.00.23.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 00:23:50 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.232;
Received: from [192.168.1.100] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay12.mail.gandi.net (Postfix) with ESMTPSA id 24807200003;
	Sat, 13 Mar 2021 08:23:44 +0000 (UTC)
Subject: Re: [PATCH 2/3] Documentation: riscv: Add documentation that
 describes the VM layout
To: Arnd Bergmann <arnd@arndb.de>
Cc: David Hildenbrand <david@redhat.com>, Jonathan Corbet <corbet@lwn.net>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
 linux-riscv <linux-riscv@lists.infradead.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 linux-arch <linux-arch@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
 Linus Walleij <linus.walleij@linaro.org>
References: <20210225080453.1314-1-alex@ghiti.fr>
 <20210225080453.1314-3-alex@ghiti.fr>
 <5279e97c-3841-717c-2a16-c249a61573f9@redhat.com>
 <7d9036d9-488b-47cc-4673-1b10c11baad0@ghiti.fr>
 <CAK8P3a3mVDwJG6k7PZEKkteszujP06cJf8Zqhq43F0rNsU=h4g@mail.gmail.com>
 <236a9788-8093-9876-a024-b0ad0d672c72@ghiti.fr>
 <CAK8P3a1+vSoEBqHPzj9S07B7h-Xuwvccpsh1pnn+1xJmS3UdbA@mail.gmail.com>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <50109729-9a86-6b49-b608-dd5c8eb2d88e@ghiti.fr>
Date: Sat, 13 Mar 2021 03:23:44 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CAK8P3a1+vSoEBqHPzj9S07B7h-Xuwvccpsh1pnn+1xJmS3UdbA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.232 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Hi Arnd,

Le 3/11/21 =C3=A0 3:42 AM, Arnd Bergmann a =C3=A9crit=C2=A0:
> On Wed, Mar 10, 2021 at 8:12 PM Alex Ghiti <alex@ghiti.fr> wrote:
>> Le 3/10/21 =C3=A0 6:42 AM, Arnd Bergmann a =C3=A9crit :
>>> On Thu, Feb 25, 2021 at 12:56 PM Alex Ghiti <alex@ghiti.fr> wrote:
>>>>
>>>> Le 2/25/21 =C3=A0 5:34 AM, David Hildenbrand a =C3=A9crit :
>>>>>                     |            |                  |         |> +
>>>>> ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
>>>>>> +   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fix=
map
>>>>>> +   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI=
 io
>>>>>> +   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vme=
mmap
>>>>>> +   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB |
>>>>>> vmalloc/ioremap space
>>>>>> +   ffffffe000000000 | -128    GB | ffffffff7fffffff |  126 GB |
>>>>>> direct mapping of all physical memory
>>>>>
>>>>> ^ So you could never ever have more than 126 GB, correct?
>>>>>
>>>>> I assume that's nothing new.
>>>>>
>>>>
>>>> Before this patch, the limit was 128GB, so in my sense, there is nothi=
ng
>>>> new. If ever we want to increase that limit, we'll just have to lower
>>>> PAGE_OFFSET, there is still some unused virtual addresses after kasan
>>>> for example.
>>>
>>> Linus Walleij is looking into changing the arm32 code to have the kerne=
l
>>> direct map inside of the vmalloc area, which would be another place
>>> that you could use here. It would be nice to not have too many differen=
t
>>> ways of doing this, but I'm not sure how hard it would be to rework you=
r
>>> code, or if there are any downsides of doing this.
>>
>> This was what my previous version did: https://lkml.org/lkml/2020/6/7/28=
.
>>
>> This approach was not welcomed very well and it fixed only the problem
>> of the implementation of relocatable kernel. The second issue I'm trying
>> to resolve here is to support both 3 and 4 level page tables using the
>> same kernel without being relocatable (which would introduce performance
>> penalty). I can't do it when the kernel mapping is in the vmalloc region
>> since vmalloc region relies on PAGE_OFFSET which is different on both 3
>> and 4 level page table and that would then require the kernel to be
>> relocatable.
>=20
> Ok, I see.
>=20
> I suppose it might work if you moved the direct-map to the lowest
> address and the vmalloc area (incorporating the kernel mapping,
> modules, pio, and fixmap at fixed addresses) to the very top of the
> address space, but you probably already considered and rejected
> that for other reasons.
>=20

Yes I considered it...when you re-proposed it :) I'm not opposed to your=20
solution in the vmalloc region but I can't find any advantage over the=20
current solution, are there ? That would harmonize with Linus's work,=20
but then we'd be quite different from x86 address space.

And by the way, thanks for having suggested the current solution in a=20
previous conversation :)

Thanks again,

Alex

>           Arnd
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/50109729-9a86-6b49-b608-dd5c8eb2d88e%40ghiti.fr.
