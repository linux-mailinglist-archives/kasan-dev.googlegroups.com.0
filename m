Return-Path: <kasan-dev+bncBC5L5P75YUERBUOW5PUQKGQEVWEP4VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DCCA76500
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 14:00:17 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 21sf12303452wmj.4
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 05:00:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564142417; cv=pass;
        d=google.com; s=arc-20160816;
        b=YafBcfM/w+sKXyKTF0N3VdWyZ2+JP55qGl7hihSKIcFQHXgRcHnQD/obLy2qTSzZ+D
         ibptm4SodnpvT98Ljkdjr7wPiwOJ1LsJmjL8rIUY/3sPcr6nDZJ6Pkn4G5ZPSoaEhnaj
         oYZDgVEnb7zyQ6VY4yFCUBG4d6mMi8qfSLocPMsTioKBtvxnRLS6K1ovl9xO9+ak7Du2
         fN0D806aSUvbn/rFmE36w+phUDXVbxIwT1BfdeKI5XH1eDNDtRmM73VQ/rqJ/WA+cHzA
         lmMmlhEu+RchoavuklOXvvIokw136kF++O+9HWt0G0OLFZYW4oE8UbUzhr5kRTvombNN
         TcLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=zhddj0GiB4ylQ0fyeIwuIBdabnbSJbhQAa+cqIWBxZY=;
        b=CAxN0QrqivpfZjqmAnUTcxjoqzcQ2Z068UFHM+EbxQRH6qyB2sn35GIN27vuYK6TTK
         V9XKDWnaW1cR0Wxerb87XavDNKG9fM7YkQ2SR1qCqXTPBp0IbLF8rGGywSURKSfQTlAR
         vsMwIb5MzHdJhwcM04jQc4BKMH+OsgdB4SlTf2fEXqh9nTJX1eKCiJmPLQ4a3bA6Wt0A
         kthNC6IpdnVK7D1l5wFTf6+RQLIzniuDZnj9dzC1wOvse3IcNr0S97t0/A3Aa4bARZCo
         ziKcZ4jAl0z7qN+eCEBAakXKQNFquGOwCCFVNdUx0igFTrxebWS2HTcYXSEhjyIZef7K
         xnhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zhddj0GiB4ylQ0fyeIwuIBdabnbSJbhQAa+cqIWBxZY=;
        b=YP2n0/Cv5eLey9H7Ndjs8PiKZS9VkRujdvnx8l+l+1r7nOjCuMvMXdDSQslnclps9t
         4DSRrOSaDzt4O9G0WHoBL6lcU7Sjqng+EBX4NdcVtKrP/TEs/6/WMqFqO1bYm+flLYkl
         EOT8AOfqYVdccAIb08n1B0j88uo3nDRN941scazxc+fyvbcn2T5JDyxKkfm7xM14848Z
         oNxaZRIkgv+i6754AsMQyvUsX2PzkIB1cRAcYfWl2gbs2OeGBvO6KEDM1XR+wABtiz4+
         dV2EgaWlS9Qjt0P/Xist1uyJeLkG8AF9pzDDSwj5qpBWLYdkN8bWgljGIZYJZsL+Nii2
         uUFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zhddj0GiB4ylQ0fyeIwuIBdabnbSJbhQAa+cqIWBxZY=;
        b=UVUhDGcMARYGdX1Qtw63J8sk6tiRevjrCgCBDW/6lv8gPkjgy+irFTook4S7bwBkB2
         owDUcNQo/KmSNYUhSfNoeES2p8/VURc1nO5jlDY/tiDBvtIPduZX8DUZ/otm8MvRAY8k
         PHybVSe6C6jIoMJeXvoowFv9AamoaT8I10RsjcBR5dDgeo+xcr3dNd9bxG4/VVLg1fWu
         ZjKyOrxkd+9mhrTC46dkv/Y+2VkTvFJLpZI0hztdV3bPXc7T+463iFIyo982hQWw7Wyg
         gwzYqJuTtEI4eJEVHUuuBBz+a1TFNA6Q0urzdxeVHzI6uVqE9AFtjHlM49B2EYucbvQY
         G7HA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW23GfFSR4po0O42HKkTrCJk8mg9ui/olIMavuI6mT1QN9akID4
	JQmvJjrF0siHT5QS35/oz3g=
X-Google-Smtp-Source: APXvYqzn3dfxztuyhCXFe46zl/d/yjmHRNR8xxMBcsJLAxHecPG5NYEdkr+rpR9F5ky26I1/DuPmUw==
X-Received: by 2002:a5d:460a:: with SMTP id t10mr74688907wrq.83.1564142417161;
        Fri, 26 Jul 2019 05:00:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ec02:: with SMTP id x2ls15832753wrn.6.gmail; Fri, 26 Jul
 2019 05:00:16 -0700 (PDT)
X-Received: by 2002:a5d:4d81:: with SMTP id b1mr19193298wru.27.1564142416730;
        Fri, 26 Jul 2019 05:00:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564142416; cv=none;
        d=google.com; s=arc-20160816;
        b=TM02TbpS+u6ePKOAw+7ouPZmtFF9rJGXpy3wOPMha+22HE3P0QCdbAzczPcnsQkH5F
         nhbCNKH15RxRhrMF70yBMDAZXU4HwOUVXyo4XWiHPS0kKiT9ABPDpzG7wh8Cx2Hvi+Wi
         vsLfwe7HVy9juyJj0ufkWAXwhbC9/bq2BdzKHwWssYKdSccZRiKD4sOHVS3S0Vrq4WIR
         9IbIwnXe99nR72NL55780cyobtFAJrGsu3gZJ1x8TlFkTNpAiTMGtMAB1LO/kN4sj1Yl
         oKcLe3iph2JC/amNkUsqT+yT84ZcWwqNf3ux1AEIK+B2VDbMcLp7F6Isf2bJkif787eO
         9kkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=49P2rfnFxRRY9jvnWLrC9nEeePhkdlcYz3DLcNHY0+E=;
        b=tRM58SY0Ci9qNkoU5AQZynbR5AX4tlLiF/ZQN3AE7TeZSquhIPC6coVDW7aKnp6MPR
         2ICbS6Nt7t22bwnm4N+D3dQsK3HbwUeOmXbaf4u5D+/QPov4Z+IRamYtf17TWmsrtIAC
         PL2A7nkCSLRLHRmvF/m+GqyTmnR5DTgvX3t9YtKZjkpeiZ/qwTUQNlu/3TarCCIh0xhS
         OJ6DrP9e0qMvo7jsRdSuDwc3v9scM7aXkU6GmYDSiN24SNnAsaTMvpZGQ/VpuPHqw8x2
         fwZTWJ+RjfltQ0NJA/ZLi7MRUcmRek4BRup4z4jfDxPyJxXFuk98FWtsODlG1HBkY7IB
         9UAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id p4si1328062wme.2.2019.07.26.05.00.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 26 Jul 2019 05:00:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hqytE-0007LO-Dd; Fri, 26 Jul 2019 15:00:00 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen
 <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
 <1560447999.15814.15.camel@mtksdccf07> <1560479520.15814.34.camel@mtksdccf07>
 <1560744017.15814.49.camel@mtksdccf07>
 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
 <1560774735.15814.54.camel@mtksdccf07> <1561974995.18866.1.camel@mtksdccf07>
 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
 <1562640832.9077.32.camel@mtksdccf07>
 <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
 <1562839579.5846.12.camel@mtksdccf07>
 <37897fb7-88c1-859a-dfcc-0a5e89a642e0@virtuozzo.com>
 <1563160001.4793.4.camel@mtksdccf07>
 <9ab1871a-2605-ab34-3fd3-4b44a0e17ab7@virtuozzo.com>
 <1563789162.31223.3.camel@mtksdccf07>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <e62da62a-2a63-3a1c-faeb-9c5561a5170c@virtuozzo.com>
Date: Fri, 26 Jul 2019 15:00:00 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1563789162.31223.3.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 7/22/19 12:52 PM, Walter Wu wrote:
> On Thu, 2019-07-18 at 19:11 +0300, Andrey Ryabinin wrote:
>>
>> On 7/15/19 6:06 AM, Walter Wu wrote:
>>> On Fri, 2019-07-12 at 13:52 +0300, Andrey Ryabinin wrote:
>>>>
>>>> On 7/11/19 1:06 PM, Walter Wu wrote:
>>>>> On Wed, 2019-07-10 at 21:24 +0300, Andrey Ryabinin wrote:
>>>>>>
>>>>>> On 7/9/19 5:53 AM, Walter Wu wrote:
>>>>>>> On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
>>>>>>>>
>>>>>>>> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
>>>>>>>>> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.=
com> wrote:
>>>>>>
>>>>>>>>>
>>>>>>>>> Sorry for delays. I am overwhelm by some urgent work. I afraid to
>>>>>>>>> promise any dates because the next week I am on a conference, the=
n
>>>>>>>>> again a backlog and an intern starting...
>>>>>>>>>
>>>>>>>>> Andrey, do you still have concerns re this patch? This change all=
ows
>>>>>>>>> to print the free stack.
>>>>>>>>
>>>>>>>> I 'm not sure that quarantine is a best way to do that. Quarantine=
 is made to delay freeing, but we don't that here.
>>>>>>>> If we want to remember more free stacks wouldn't be easier simply =
to remember more stacks in object itself?
>>>>>>>> Same for previously used tags for better use-after-free identifica=
tion.
>>>>>>>>
>>>>>>>
>>>>>>> Hi Andrey,
>>>>>>>
>>>>>>> We ever tried to use object itself to determine use-after-free
>>>>>>> identification, but tag-based KASAN immediately released the pointe=
r
>>>>>>> after call kfree(), the original object will be used by another
>>>>>>> pointer, if we use object itself to determine use-after-free issue,=
 then
>>>>>>> it has many false negative cases. so we create a lite quarantine(ri=
ng
>>>>>>> buffers) to record recent free stacks in order to avoid those false
>>>>>>> negative situations.
>>>>>>
>>>>>> I'm telling that *more* than one free stack and also tags per object=
 can be stored.
>>>>>> If object reused we would still have information about n-last usages=
 of the object.
>>>>>> It seems like much easier and more efficient solution than patch you=
 proposing.
>>>>>>
>>>>> To make the object reused, we must ensure that no other pointers uses=
 it
>>>>> after kfree() release the pointer.
>>>>> Scenario:
>>>>> 1). The object reused information is valid when no another pointer us=
es
>>>>> it.
>>>>> 2). The object reused information is invalid when another pointer use=
s
>>>>> it.
>>>>> Do you mean that the object reused is scenario 1) ?
>>>>> If yes, maybe we can change the calling quarantine_put() location. It
>>>>> will be fully use that quarantine, but at scenario 2) it looks like t=
o
>>>>> need this patch.
>>>>> If no, maybe i miss your meaning, would you tell me how to use invali=
d
>>>>> object information? or?
>>>>>
>>>>
>>>>
>>>> KASAN keeps information about object with the object, right after payl=
oad in the kasan_alloc_meta struct.
>>>> This information is always valid as long as slab page allocated. Curre=
ntly it keeps only one last free stacktrace.
>>>> It could be extended to record more free stacktraces and also record p=
reviously used tags which will allow you
>>>> to identify use-after-free and extract right free stacktrace.
>>>
>>> Thanks for your explanation.
>>>
>>> For extend slub object, if one record is 9B (sizeof(u8)+ sizeof(struct
>>> kasan_track)) and add five records into slub object, every slub object
>>> may add 45B usage after the system runs longer.=20
>>> Slub object number is easy more than 1,000,000(maybe it may be more
>>> bigger), then the extending object memory usage should be 45MB, and
>>> unfortunately it is no limit. The memory usage is more bigger than our
>>> patch.
>>
>> No, it's not necessarily more.
>> And there are other aspects to consider such as performance, how simple =
reliable the code is.
>>
>>>
>>> We hope tag-based KASAN advantage is smaller memory usage. If it=E2=80=
=99s
>>> possible, we should spend less memory in order to identify
>>> use-after-free. Would you accept our patch after fine tune it?
>>
>> Sure, if you manage to fix issues and demonstrate that performance penal=
ty of your
>> patch is close to zero.
>=20
>=20
> I remember that there are already the lists which you concern. Maybe we
> can try to solve those problems one by one.
>=20
> 1. deadlock issue? cause by kmalloc() after kfree()?

smp_call_on_cpu()

> 2. decrease allocation fail, to modify GFP_NOWAIT flag to GFP_KERNEL?

No, this is not gonna work. Ideally we shouldn't have any allocations there=
.
It's not reliable and it hurts performance.


> 3. check whether slim 48 bytes (sizeof (qlist_object) +
> sizeof(kasan_alloc_meta)) and additional unique stacktrace in
> stackdepot?
> 4. duplicate struct 'kasan_track' information in two different places
>=20

Yup.

> Would you have any other concern? or?
>=20

It would be nice to see some performance numbers. Something that uses slab =
allocations a lot, e.g. netperf STREAM_STREAM test.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e62da62a-2a63-3a1c-faeb-9c5561a5170c%40virtuozzo.com.
