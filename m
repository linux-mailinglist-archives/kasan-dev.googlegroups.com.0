Return-Path: <kasan-dev+bncBC32535MUICBBZH5ZWAQMGQEKKJ7FLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id BBD3C321373
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 10:52:37 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id f17sf5887979uac.6
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 01:52:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613987556; cv=pass;
        d=google.com; s=arc-20160816;
        b=gtMgu//Qn40yuFeDC/a65FZxtM4mg0fEJXWlhw+F2qynQy+ZTexPs4TZHMGLNBM4wi
         6QUY046L+6aQc7sYk/9FYNV9CBhHUZEvFZ46DwOwtqmejdimfIjqEL6dB5Qz5lM2zWsi
         MNw6KGIERoi1Y7VpBSr/NFPkf9Vtd7JJlS9vtmDkR8HeIh0NtIJdeJOdRerHOUzshTpy
         vH8n43O7WNbgECEbTD+npDjnXeOImkS+CpNkoQgxxv2B7iqGP0mmCEo0fxOmdFHVYESo
         JFG+Dt6zbCw4chAKimrsASjPC/jv8+7frfFcqmkQM0nfVpX3XJn4WEkYleex27s6ApUV
         syJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:subject:organization:from:references:cc:to:sender
         :dkim-signature;
        bh=oAhveDtu6bdKUXozbM7dvl4Q9jMfmq919JHAU7y6EGU=;
        b=mQaE4HU1rOzHPLWh87a+2GNtiO0Tyyll1zY/d/iltdLgJ+O9m+uLFK14IHhTwBkmXI
         Qu1567esGqybc/6PZw+Ic880JQAUWvDrXfBD5sBHmcL62DQ+/95Zz6rHOL88I0dbGnqD
         TQjMZ8Y+HNoC4AAC1Z1wXTL1vagr4u6yHTysWrtyv6hKxMxIr7t3xfLJoQg6urRSPJTC
         fPflD+SKyBaUNfkaskyjM87Ty3kFZ0N1j3i3gmyvPhD8UtJc2nQGHjdOw4DEYiPpdTR7
         pwYov1zC74PUkmUyt2FuvC6sY27KyzDbHHoLyF8qUJI8JceDkCNSD4vE1QgLvqUqSTHE
         Iqvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="ABj9xfk/";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:to:cc:references:from:organization:subject:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oAhveDtu6bdKUXozbM7dvl4Q9jMfmq919JHAU7y6EGU=;
        b=qSXlVYx0MQNmgFCDFbjVlDTC9LavWdyMT4DacAlIWshqG5Vfj/od7uSYOqwLf8OMl+
         VvN+fIqf7sWUxq2GZXf81pHdzSE2iu6S3Pi6VNMxGvkbLBzRI0LQD1tjwUwFw5v1fJTR
         3tmz1KAHVJ1SuvvHW0H3YSN35nzEAO4s0O6XyOm8XNGlccv7GGthSjCO94gOth1WzCuZ
         vnfvRbBSOGsvYMsQrB2D75jNcvciyzuExmPRMKjvNfNmdnZlblXy8xyOGAd5dSR5bgAd
         Elo2cxVFwWlf4X2CcqgJ/nVf6NP7HUscAqYJHjHIjfiR6V9D+22lk0TX0v3IXNpE2aLz
         Qixw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:to:cc:references:from:organization
         :subject:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oAhveDtu6bdKUXozbM7dvl4Q9jMfmq919JHAU7y6EGU=;
        b=PoV02w34b0nucKhiV+dDw0+vXaV31FrttL5h/AaZCCOY1QDpySrvSEOjOzwfq8bnRE
         wB7ZZcUql6b0VVXDkNnG4r+dKDrO611kd7jbKm9GFGx2ShOOxiphojIR4g0ktdSh6szA
         c4MAfBryvtsnc8hhupxX/bGMrra2E+bVz0etOzbO250pW+aHogQr43bD8GrpjSZ5VE6S
         zg2TqB4rU6Zdo700ZUa+vAcGp8GSejsZZ29wUUlD7Vy49Q+dBBE9iN/y4CYQYMp2qYul
         HDv8pIhj7atVFfxuQJQQ24Weeaw+2nZqumwZsBt9Yb5tuKxUH/Z1GFGkeD9hDbbHNYBx
         DBdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ZHZqp9LCV2IpvuvL+q56yyJDp0KEYzVlkBn5CsYUa1eCmH53L
	3CInq9KfnKrEG9B/FcRom0M=
X-Google-Smtp-Source: ABdhPJx5++e4yJiu7QLjJ/l4JLmDnJheoztXeYdUHc1v/mcixz07j2tJYkrP/DZZdV1xGg2QsenQDA==
X-Received: by 2002:a67:25c3:: with SMTP id l186mr6764181vsl.27.1613987556872;
        Mon, 22 Feb 2021 01:52:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls1835772vsm.3.gmail; Mon, 22 Feb
 2021 01:52:36 -0800 (PST)
X-Received: by 2002:a67:2a03:: with SMTP id q3mr2520450vsq.60.1613987556405;
        Mon, 22 Feb 2021 01:52:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613987556; cv=none;
        d=google.com; s=arc-20160816;
        b=t/MYIA61zl8ftiHHJoGZmf81PAlIAb/5O3xEAg53ey1sEBMg2w7PRSP1SmATqlS+Ec
         2OlA284tBlx1g0ZVx0HwddiGFrz7F6uDqfrM3OW8RdjAVIyoSVlP+/jHSx6J5sk0duDK
         hoPI4yathILCthvONudPT8+QjmJHOecY0QcnQCFlfnIj4jPA4DLtMRDiM2SWrhGnKMQm
         0zz4AQHd9WLSUgPy1R4TWYb3sbroWYL5NNwsFqEaiQusw53ZJbCp7EM1peCOcrsz8c53
         wdUUGneHXPC2g3FOtsCEtaGeC5A5jFV2Q6tZhMPAkRXG2vP3Tyi/Ids2+z8oLYOawd9R
         pssA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:subject:organization:from:references:cc
         :to:dkim-signature;
        bh=d5eIr8u8FvWotSBBBi/ahMw0H/+9oyeliDYTeYUXMTY=;
        b=Syz0CG4NOCnciRDdTj12NMGW1ZSDZ9XTimnoLlZZIc4j58YHueHH5rW636lvT3i0TR
         VMNtdgQ54NRTJhY8nEYuFCRw1MFNoCB3p5GMdLEiNTk2ufzmMJp/REtYR8FNIyTJl+9y
         soKmGhzewiEQ71qEsowIj4jLgKmV8Uykx9aWbUQpcwcI2M8qmU6Is0t9mJXWsvwe9CY5
         tQyvoSUQl/RNbQHCv8V+x+pOqarPmkMsDKjnpKsN4C/o4ytBj2aZh5i70yXOw1N6cZnw
         RKy3Ycb/W2k2nsDtNf/TxpS2FCWM16P0u5B60wiJu4om1pmCStz8FrLS1yJskOhamALh
         lSxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="ABj9xfk/";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e11si857126vkp.4.2021.02.22.01.52.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Feb 2021 01:52:36 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-30-3Uvdxx5pNT-S0cgB1-QOkw-1; Mon, 22 Feb 2021 04:52:31 -0500
X-MC-Unique: 3Uvdxx5pNT-S0cgB1-QOkw-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 7C76D801965;
	Mon, 22 Feb 2021 09:52:28 +0000 (UTC)
Received: from [10.36.115.16] (ovpn-115-16.ams2.redhat.com [10.36.115.16])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 160D71001281;
	Mon, 22 Feb 2021 09:52:23 +0000 (UTC)
To: George Kennedy <george.kennedy@oracle.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Konrad Rzeszutek Wilk
 <konrad@darnok.org>, Will Deacon <will.deacon@arm.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig
 <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>, Dhaval Giani <dhaval.giani@oracle.com>
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat GmbH
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
Message-ID: <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
Date: Mon, 22 Feb 2021 10:52:23 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="ABj9xfk/";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 20.02.21 00:04, George Kennedy wrote:
>=20
>=20
> On 2/19/2021 11:45 AM, George Kennedy wrote:
>>
>>
>> On 2/18/2021 7:09 PM, Andrey Konovalov wrote:
>>> On Fri, Feb 19, 2021 at 1:06 AM George Kennedy
>>> <george.kennedy@oracle.com> wrote:
>>>>
>>>>
>>>> On 2/18/2021 3:55 AM, David Hildenbrand wrote:
>>>>> On 17.02.21 21:56, Andrey Konovalov wrote:
>>>>>> During boot, all non-reserved memblock memory is exposed to the budd=
y
>>>>>> allocator. Poisoning all that memory with KASAN lengthens boot time,
>>>>>> especially on systems with large amount of RAM. This patch makes
>>>>>> page_alloc to not call kasan_free_pages() on all new memory.
>>>>>>
>>>>>> __free_pages_core() is used when exposing fresh memory during system
>>>>>> boot and when onlining memory during hotplug. This patch adds a new
>>>>>> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok() throug=
h
>>>>>> free_pages_prepare() from __free_pages_core().
>>>>>>
>>>>>> This has little impact on KASAN memory tracking.
>>>>>>
>>>>>> Assuming that there are no references to newly exposed pages
>>>>>> before they
>>>>>> are ever allocated, there won't be any intended (but buggy)
>>>>>> accesses to
>>>>>> that memory that KASAN would normally detect.
>>>>>>
>>>>>> However, with this patch, KASAN stops detecting wild and large
>>>>>> out-of-bounds accesses that happen to land on a fresh memory page
>>>>>> that
>>>>>> was never allocated. This is taken as an acceptable trade-off.
>>>>>>
>>>>>> All memory allocated normally when the boot is over keeps getting
>>>>>> poisoned as usual.
>>>>>>
>>>>>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>>>>>> Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
>>>>> Not sure this is the right thing to do, see
>>>>>
>>>>> https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@oracle=
.com
>>>>>
>>>>>
>>>>> Reversing the order in which memory gets allocated + used during boot
>>>>> (in a patch by me) might have revealed an invalid memory access durin=
g
>>>>> boot.
>>>>>
>>>>> I suspect that that issue would no longer get detected with your
>>>>> patch, as the invalid memory access would simply not get detected.
>>>>> Now, I cannot prove that :)
>>>> Since David's patch we're having trouble with the iBFT ACPI table,
>>>> which
>>>> is mapped in via kmap() - see acpi_map() in "drivers/acpi/osl.c". KASA=
N
>>>> detects that it is being used after free when ibft_init() accesses the
>>>> iBFT table, but as of yet we can't find where it get's freed (we've
>>>> instrumented calls to kunmap()).
>>> Maybe it doesn't get freed, but what you see is a wild or a large
>>> out-of-bounds access. Since KASAN marks all memory as freed during the
>>> memblock->page_alloc transition, such bugs can manifest as
>>> use-after-frees.
>>
>> It gets freed and re-used. By the time the iBFT table is accessed by
>> ibft_init() the page has been over-written.
>>
>> Setting page flags like the following before the call to kmap()
>> prevents the iBFT table page from being freed:
>=20
> Cleaned up version:
>=20
> diff --git a/drivers/acpi/osl.c b/drivers/acpi/osl.c
> index 0418feb..8f0a8e7 100644
> --- a/drivers/acpi/osl.c
> +++ b/drivers/acpi/osl.c
> @@ -287,9 +287,12 @@ static void __iomem *acpi_map(acpi_physical_address
> pg_off, unsigned long pg_sz)
>=20
>   =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
>   =C2=A0=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_page(=
pfn);
> +
>   =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (pg_sz > PAGE_SIZE)
>   =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return N=
ULL;
> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)kma=
p(pfn_to_page(pfn));
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 SetPageReserved(page);
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)kma=
p(page);
>   =C2=A0=C2=A0=C2=A0=C2=A0 } else
>   =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acpi_os_ioremap(pg_o=
ff, pg_sz);
>   =C2=A0}
> @@ -299,9 +302,12 @@ static void acpi_unmap(acpi_physical_address
> pg_off, void __iomem *vaddr)
>   =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>=20
>   =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
> -=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn))
> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(pfn_to_page(pfn));
> -=C2=A0=C2=A0=C2=A0 else
> +=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_page(=
pfn);
> +
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ClearPageReserved(page);
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(page);
> +=C2=A0=C2=A0=C2=A0 } else
>   =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 iounmap(vaddr);
>   =C2=A0}
>=20
> David, the above works, but wondering why it is now necessary. kunmap()
> is not hit. What other ways could a page mapped via kmap() be unmapped?
>=20

Let me look into the code ... I have little experience with ACPI=20
details, so bear with me.

I assume that acpi_map()/acpi_unmap() map some firmware blob that is=20
provided via firmware/bios/... to us.

should_use_kmap() tells us whether
a) we have a "struct page" and should kmap() that one
b) we don't have a "struct page" and should ioremap.

As it is a blob, the firmware should always reserve that memory region=20
via memblock (e.g., memblock_reserve()), such that we either
1) don't create a memmap ("struct page") at all (-> case b) )
2) if we have to create e memmap, we mark the page PG_reserved and
    *never* expose it to the buddy (-> case a) )


Are you telling me that in this case we might have a memmap for the HW=20
blob that is *not* PG_reserved? In that case it most probably got=20
exposed to the buddy where it can happily get allocated/freed.

The latent BUG would be that that blob gets exposed to the system like=20
ordinary RAM, and not reserved via memblock early during boot. Assuming=20
that blob has a low physical address, with my patch it will get=20
allocated/used a lot earlier - which would mean we trigger this latent=20
BUG now more easily.

There have been similar latent BUGs on ARM boards that my patch=20
discovered where special RAM regions did not get marked as reserved via=20
the device tree properly.

Now, this is just a wild guess :) Can you dump the page when mapping=20
(before PageReserved()) and when unmapping, to see what the state of=20
that memmap is?

--=20
Thanks,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1ac78f02-d0af-c3ff-cc5e-72d6b074fc43%40redhat.com.
