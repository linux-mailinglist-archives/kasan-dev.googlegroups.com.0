Return-Path: <kasan-dev+bncBC32535MUICBBO5QZ6AQMGQE5WJLOKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id A046D321C83
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 17:13:48 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id n185sf829670vsd.19
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 08:13:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614010427; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dl47ZhHPxKqL9gy6XfBVzTZAbdwrzbp5JyFJuRlJz28DuYXTbtLAsQ0+qGCiYbGz1m
         2Q3v9d+RAEvyDg/RJO5muFti03J5GlyFDkcqX8Z6ka/TAh2VwpccswQBAa9uY8079qgn
         mEV0PI12lbSgIp/mhYLJaBojMoQRJuSxSYzFroRHbK2aB5S1BxqovEGW3lbZzh33esgw
         +PTvjvn9hYSNHOv//5RJjcbcX/aQhLqbXGsLyaQ4Oy118zhhDh2qbUc+OUgS7YM5Ids5
         R1QXwCvPiwPjT2Ne9YUHXd9kactAjRRd8Y10l0QJNAmFIhs2FKOy1nEGEpNcsXswFBLK
         m4uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:subject:organization:from:references:cc:to:sender
         :dkim-signature;
        bh=3+VcxlkFRbCy74T1WJX27L9aIC5hV6+3V+xqjVz6lKU=;
        b=nGdZvza9WK1EeiYNB1eKRKiX+1iM83n7VJjuIpoqRuWXsuQjK6JGP19jUmN7ccqwK4
         0AUMLzG+Jk/9k6kKyBvQ/fRe5WAju/ZDDZ/n5mpdNVLyaNTxNsAVHdx4E8sQ3nHxSNLZ
         OMJlHQXe/LbAgTkAejQsXdIBTM28BVVSP/9f6s0fNbAvNDVA95GQV877NVMDB0AU36RE
         IbiU2PoDPwadIKwmxVI5uBoJklmSdcE44Rw8E76Ah7/GgCvfb9oi+ZI+Ne5mnBz/Pn1V
         gUqlb1VY8LBR0jevv9DDd/n/qoDfVN9foReyr+iBCiq0w1HF0tGDIw7m3jqT16eoWu2W
         c7gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="b/+r/ZC/";
       spf=pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:to:cc:references:from:organization:subject:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3+VcxlkFRbCy74T1WJX27L9aIC5hV6+3V+xqjVz6lKU=;
        b=MyL3pcApAZvjw8ibdK334+r/0wYRLrqLz3bh6ZtrmRTs1Puwe5sjUhxWeQHfPWMxWp
         6JP0F3E9lFuJEYM0LWPvWMmN+ODWmuh7VvtJzlS6SSnFov0w5+q/YNeG0xQ22miX1It/
         U50smFLDnYluoliwLHxzBMlCQzDkbgB2zjYKBljbolQTAdW7hdPCm7oT90wJmH0SL0hS
         myYRKCJj55dYmBFc3QhBNhYmh6Zm1mxb8E1Qa30pFy+I0KwTZ0lgFZ34mXIhL5B2PaZ5
         6s/Da87kOYAxMnJp+pRv3/MSl0vh/gyAuIPJHSC11NT1RtYZ5XfuiFOYzjvtWH7hpaw1
         j7EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:to:cc:references:from:organization
         :subject:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3+VcxlkFRbCy74T1WJX27L9aIC5hV6+3V+xqjVz6lKU=;
        b=hy1Tdb1NRpLbYJPcN7DAyvwDex+7FheuUa3wMl57FWT8z5xwbsjItwUGk5e2cgJWY7
         IYGFDOArjpJL2ectMnSNy+c0lMsiwj6Yd2CkXGNoyZW4iJgaVzYmpKypJHhnxJK2QYDZ
         JtyG/G9zEG3jDi7sgFsE3Geiqm7XdGRiN4WhQ2PGzx2tBpzCAM6udYMtsIKJfVHojEnQ
         P0dDDKEcD6UY/Ip71nJQLhrJu6Ff9ErrDzYYoprqLpYM1Zlgf2cFLccz++JXGj7RMJDZ
         FDbJMQbwNiheaPYq3IDKx8fWnD2p1cLfroM85UOs5JFKc8NbkCQdKFmxjx/TqaOifE5D
         ILig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302hnowUZzNAmDHmQbjIIG+VA+KxTpY9I9wcl3l5HooSfsZa7Yr
	aPkpyiY0SgM6Ahx7sxzGYXI=
X-Google-Smtp-Source: ABdhPJz9pj+0Y+5nMKyr90SQUEtRCqh6UFSiXkqvb187bU06aWTkBs6dBk8jnLV58Z6KDXw83MO27A==
X-Received: by 2002:a67:6847:: with SMTP id d68mr13560882vsc.41.1614010427594;
        Mon, 22 Feb 2021 08:13:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a294:: with SMTP id l142ls415860vke.8.gmail; Mon, 22 Feb
 2021 08:13:47 -0800 (PST)
X-Received: by 2002:a1f:2e88:: with SMTP id u130mr13902556vku.15.1614010427095;
        Mon, 22 Feb 2021 08:13:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614010427; cv=none;
        d=google.com; s=arc-20160816;
        b=xnpzpo+pTZQTpgAcW/xGcZLeIecm1EMuH2/2KJwY4VXDn2UZI4ZElg+Mqbc9L3r9lC
         ldcbGP3EX/3yzwOon0lQqM7S5kT92Ia7iAbnlzFltQQQjhW/fTorvDFrp4A29doKe6hv
         lvS9+VICangVVsrnVpyCf6CI+F8hasPHLjVU7TUgwrL5J8h8uckRvyt4qpplQVBUp7IP
         z4ZWjoKO/2hJpxoD3j2V6lbk6YaNpOmPYht8liREdKKNYQjJIwWVY1RwrIZexf48pWrw
         kHzW70GrXaHvrYrHYkIHu4e44tVrwM6im3uiDVYnIxdHc/lWQrCfnWd1uOKQ/sf258zT
         Hc/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:subject:organization:from:references:cc
         :to:dkim-signature;
        bh=vGnfE5dmtvOlJFPabKOkr4gF//An3LQV9JDbxXBmlGM=;
        b=Xh43L845mWKikN5/dFuVP20XyHsfY7nrE4RE2jiitqc3LnQPFFjM5hxunhbCjOarTa
         lwDKRkwx+7leF8LF+APU9Vj1jXm9Il0ljiHZb+k9qJwnRq4WBJz0ihETdnzxSa/H2s6H
         kZjtG9sfS3lhBKAl1SbvO0HXF7e6GBujbajhnBVr6O8EBQVvUoaT/W+RDDVlfy5gbW1B
         YpEiznsZ2URldG1ELg+2dqmckHzFGVPQhkTwJddcF64cVgHtJTkyx2bYlZDWtMUV+CKt
         Zs5j/jrajq17VoBiNFh4ZnP8neT+Qo/9wv3OLA6Plr+/DHBkLJc57TBzaSK64Zf3OwzV
         076g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="b/+r/ZC/";
       spf=pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id h7si544753vkk.1.2021.02.22.08.13.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Feb 2021 08:13:47 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-567-dSb2tbqLND-u__McrvQZgw-1; Mon, 22 Feb 2021 11:13:42 -0500
X-MC-Unique: dSb2tbqLND-u__McrvQZgw-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 44B161935780;
	Mon, 22 Feb 2021 16:13:39 +0000 (UTC)
Received: from [10.36.115.16] (ovpn-115-16.ams2.redhat.com [10.36.115.16])
	by smtp.corp.redhat.com (Postfix) with ESMTP id DD44E10016F4;
	Mon, 22 Feb 2021 16:13:34 +0000 (UTC)
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
 LKML <linux-kernel@vger.kernel.org>, Dhaval Giani <dhaval.giani@oracle.com>,
 Mike Rapoport <rppt@linux.ibm.com>
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat GmbH
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
Message-ID: <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
Date: Mon, 22 Feb 2021 17:13:33 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="b/+r/ZC/";
       spf=pass (google.com: domain of david@redhat.com designates
 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 22.02.21 16:13, George Kennedy wrote:
>=20
>=20
> On 2/22/2021 4:52 AM, David Hildenbrand wrote:
>> On 20.02.21 00:04, George Kennedy wrote:
>>>
>>>
>>> On 2/19/2021 11:45 AM, George Kennedy wrote:
>>>>
>>>>
>>>> On 2/18/2021 7:09 PM, Andrey Konovalov wrote:
>>>>> On Fri, Feb 19, 2021 at 1:06 AM George Kennedy
>>>>> <george.kennedy@oracle.com> wrote:
>>>>>>
>>>>>>
>>>>>> On 2/18/2021 3:55 AM, David Hildenbrand wrote:
>>>>>>> On 17.02.21 21:56, Andrey Konovalov wrote:
>>>>>>>> During boot, all non-reserved memblock memory is exposed to the
>>>>>>>> buddy
>>>>>>>> allocator. Poisoning all that memory with KASAN lengthens boot
>>>>>>>> time,
>>>>>>>> especially on systems with large amount of RAM. This patch makes
>>>>>>>> page_alloc to not call kasan_free_pages() on all new memory.
>>>>>>>>
>>>>>>>> __free_pages_core() is used when exposing fresh memory during
>>>>>>>> system
>>>>>>>> boot and when onlining memory during hotplug. This patch adds a ne=
w
>>>>>>>> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok()
>>>>>>>> through
>>>>>>>> free_pages_prepare() from __free_pages_core().
>>>>>>>>
>>>>>>>> This has little impact on KASAN memory tracking.
>>>>>>>>
>>>>>>>> Assuming that there are no references to newly exposed pages
>>>>>>>> before they
>>>>>>>> are ever allocated, there won't be any intended (but buggy)
>>>>>>>> accesses to
>>>>>>>> that memory that KASAN would normally detect.
>>>>>>>>
>>>>>>>> However, with this patch, KASAN stops detecting wild and large
>>>>>>>> out-of-bounds accesses that happen to land on a fresh memory page
>>>>>>>> that
>>>>>>>> was never allocated. This is taken as an acceptable trade-off.
>>>>>>>>
>>>>>>>> All memory allocated normally when the boot is over keeps getting
>>>>>>>> poisoned as usual.
>>>>>>>>
>>>>>>>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>>>>>>>> Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
>>>>>>> Not sure this is the right thing to do, see
>>>>>>>
>>>>>>> https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@orac=
le.com
>>>>>>>
>>>>>>>
>>>>>>>
>>>>>>> Reversing the order in which memory gets allocated + used during
>>>>>>> boot
>>>>>>> (in a patch by me) might have revealed an invalid memory access
>>>>>>> during
>>>>>>> boot.
>>>>>>>
>>>>>>> I suspect that that issue would no longer get detected with your
>>>>>>> patch, as the invalid memory access would simply not get detected.
>>>>>>> Now, I cannot prove that :)
>>>>>> Since David's patch we're having trouble with the iBFT ACPI table,
>>>>>> which
>>>>>> is mapped in via kmap() - see acpi_map() in "drivers/acpi/osl.c".
>>>>>> KASAN
>>>>>> detects that it is being used after free when ibft_init() accesses
>>>>>> the
>>>>>> iBFT table, but as of yet we can't find where it get's freed (we've
>>>>>> instrumented calls to kunmap()).
>>>>> Maybe it doesn't get freed, but what you see is a wild or a large
>>>>> out-of-bounds access. Since KASAN marks all memory as freed during th=
e
>>>>> memblock->page_alloc transition, such bugs can manifest as
>>>>> use-after-frees.
>>>>
>>>> It gets freed and re-used. By the time the iBFT table is accessed by
>>>> ibft_init() the page has been over-written.
>>>>
>>>> Setting page flags like the following before the call to kmap()
>>>> prevents the iBFT table page from being freed:
>>>
>>> Cleaned up version:
>>>
>>> diff --git a/drivers/acpi/osl.c b/drivers/acpi/osl.c
>>> index 0418feb..8f0a8e7 100644
>>> --- a/drivers/acpi/osl.c
>>> +++ b/drivers/acpi/osl.c
>>> @@ -287,9 +287,12 @@ static void __iomem *acpi_map(acpi_physical_addres=
s
>>> pg_off, unsigned long pg_sz)
>>>
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_pag=
e(pfn);
>>> +
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (pg_sz > PAGE_SI=
ZE)
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =
return NULL;
>>> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)k=
map(pfn_to_page(pfn));
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 SetPageReserved(page);
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)k=
map(page);
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 } else
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acpi_os_iore=
map(pg_off, pg_sz);
>>>  =C2=A0 =C2=A0}
>>> @@ -299,9 +302,12 @@ static void acpi_unmap(acpi_physical_address
>>> pg_off, void __iomem *vaddr)
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>>>
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
>>> -=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn))
>>> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(pfn_to_page(pfn));
>>> -=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_pag=
e(pfn);
>>> +
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ClearPageReserved(page);
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(page);
>>> +=C2=A0=C2=A0=C2=A0 } else
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 iounmap(vaddr);
>>>  =C2=A0 =C2=A0}
>>>
>>> David, the above works, but wondering why it is now necessary. kunmap()
>>> is not hit. What other ways could a page mapped via kmap() be unmapped?
>>>
>>
>> Let me look into the code ... I have little experience with ACPI
>> details, so bear with me.
>>
>> I assume that acpi_map()/acpi_unmap() map some firmware blob that is
>> provided via firmware/bios/... to us.
>>
>> should_use_kmap() tells us whether
>> a) we have a "struct page" and should kmap() that one
>> b) we don't have a "struct page" and should ioremap.
>>
>> As it is a blob, the firmware should always reserve that memory region
>> via memblock (e.g., memblock_reserve()), such that we either
>> 1) don't create a memmap ("struct page") at all (-> case b) )
>> 2) if we have to create e memmap, we mark the page PG_reserved and
>>  =C2=A0=C2=A0 *never* expose it to the buddy (-> case a) )
>>
>>
>> Are you telling me that in this case we might have a memmap for the HW
>> blob that is *not* PG_reserved? In that case it most probably got
>> exposed to the buddy where it can happily get allocated/freed.
>>
>> The latent BUG would be that that blob gets exposed to the system like
>> ordinary RAM, and not reserved via memblock early during boot.
>> Assuming that blob has a low physical address, with my patch it will
>> get allocated/used a lot earlier - which would mean we trigger this
>> latent BUG now more easily.
>>
>> There have been similar latent BUGs on ARM boards that my patch
>> discovered where special RAM regions did not get marked as reserved
>> via the device tree properly.
>>
>> Now, this is just a wild guess :) Can you dump the page when mapping
>> (before PageReserved()) and when unmapping, to see what the state of
>> that memmap is?
>=20
> Thank you David for the explanation and your help on this,
>=20
> dump_page() before PageReserved and before kmap() in the above patch:
>=20
> [=C2=A0=C2=A0=C2=A0 1.116480] ACPI: Core revision 20201113
> [=C2=A0=C2=A0=C2=A0 1.117628] XXX acpi_map: about to call kmap()...
> [=C2=A0=C2=A0=C2=A0 1.118561] page:ffffea0002f914c0 refcount:0 mapcount:0
> mapping:0000000000000000 index:0x0 pfn:0xbe453
> [=C2=A0=C2=A0=C2=A0 1.120381] flags: 0xfffffc0000000()
> [=C2=A0=C2=A0=C2=A0 1.121116] raw: 000fffffc0000000 ffffea0002f914c8 ffff=
ea0002f914c8
> 0000000000000000
> [=C2=A0=C2=A0=C2=A0 1.122638] raw: 0000000000000000 0000000000000000 0000=
0000ffffffff
> 0000000000000000
> [=C2=A0=C2=A0=C2=A0 1.124146] page dumped because: acpi_map pre SetPageRe=
served
>=20
> I also added dump_page() before unmapping, but it is not hit. The
> following for the same pfn now shows up I believe as a result of setting
> PageReserved:
>=20
> [=C2=A0=C2=A0 28.098208] BUG:Bad page state in process mo dprobe=C2=A0 pf=
n:be453
> [=C2=A0=C2=A0 28.098394] page:ffffea0002f914c0 refcount:0 mapcount:0
> mapping:0000000000000000 index:0x1 pfn:0xbe453
> [=C2=A0=C2=A0 28.098394] flags: 0xfffffc0001000(reserved)
> [=C2=A0=C2=A0 28.098394] raw: 000fffffc0001000 dead000000000100 dead00000=
0000122
> 0000000000000000
> [=C2=A0=C2=A0 28.098394] raw: 0000000000000001 0000000000000000 00000000f=
fffffff
> 0000000000000000
> [=C2=A0=C2=A0 28.098394] page dumped because: PAGE_FLAGS_CHECK_AT_PREP fl=
ag(s) set
> [=C2=A0=C2=A0 28.098394] page_owner info is not present (never set?)
> [=C2=A0=C2=A0 28.098394] Modules linked in:
> [=C2=A0=C2=A0 28.098394] CPU: 2 PID: 204 Comm: modprobe Not tainted 5.11.=
0-3dbd5e3 #66
> [=C2=A0=C2=A0 28.098394] Hardware name: QEMU Standard PC (i440FX + PIIX, =
1996),
> BIOS 0.0.0 02/06/2015
> [=C2=A0=C2=A0 28.098394] Call Trace:
> [=C2=A0=C2=A0 28.098394]=C2=A0 dump_stack+0xdb/0x120
> [=C2=A0=C2=A0 28.098394]=C2=A0 bad_page.cold.108+0xc6/0xcb
> [=C2=A0=C2=A0 28.098394]=C2=A0 check_new_page_bad+0x47/0xa0
> [=C2=A0=C2=A0 28.098394]=C2=A0 get_page_from_freelist+0x30cd/0x5730
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? __isolate_free_page+0x4f0/0x4f0
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? init_object+0x7e/0x90
> [=C2=A0=C2=A0 28.098394]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? __alloc_pages_slowpath.constprop.103+0x2=
110/0x2110
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
> [=C2=A0=C2=A0 28.098394]=C2=A0 alloc_pages_vma+0xe2/0x560
> [=C2=A0=C2=A0 28.098394]=C2=A0 do_fault+0x194/0x12c0
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> [=C2=A0=C2=A0 28.098394]=C2=A0 __handle_mm_fault+0x1650/0x26c0
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? copy_page_range+0x1350/0x1350
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> [=C2=A0=C2=A0 28.098394]=C2=A0 handle_mm_fault+0x1f9/0x810
> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> [=C2=A0=C2=A0 28.098394]=C2=A0 do_user_addr_fault+0x6f7/0xca0
> [=C2=A0=C2=A0 28.098394]=C2=A0 exc_page_fault+0xaf/0x1a0
> [=C2=A0=C2=A0 28.098394]=C2=A0 asm_exc_page_fault+0x1e/0x30
> [=C2=A0=C2=A0 28.098394] RIP: 0010:__clear_user+0x30/0x60

I think the PAGE_FLAGS_CHECK_AT_PREP check in this instance means that=20
someone is trying to allocate that page with the PG_reserved bit set.=20
This means that the page actually was exposed to the buddy.

However, when you SetPageReserved(), I don't think that PG_buddy is set=20
and the refcount is 0. That could indicate that the page is on the buddy=20
PCP list. Could be that it is getting reused a couple of times.

The PFN 0xbe453 looks a little strange, though. Do we expect ACPI tables=20
close to 3 GiB ? No idea. Could it be that you are trying to map a wrong=20
table? Just a guess.

>=20
> What would be=C2=A0 the correct way to reserve the page so that the above
> would not be hit?

I would have assumed that if this is a binary blob, that someone (which=20
I think would be acpi code) reserved via memblock_reserve() early during=20
boot.

E.g., see drivers/acpi/tables.c:acpi_table_upgrade()->memblock_reserve().

--=20
Thanks,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/56c97056-6d8b-db0e-e303-421ee625abe3%40redhat.com.
