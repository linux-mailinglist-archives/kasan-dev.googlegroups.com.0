Return-Path: <kasan-dev+bncBDGZVRMH6UCRB4EZT63QMGQETIVMXLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AA731979B08
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 08:15:13 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id ada2fe7eead31-49bc5f5d02asf1760112137.0
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Sep 2024 23:15:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726467312; cv=pass;
        d=google.com; s=arc-20240605;
        b=D5jUN1nP+imEuSq5mwnZWLtUFSOEACsIStA711Iz34wwDzYmEjof62CSBLcPjswPbq
         VD7CeOHskk4Nh3Ui4+I1L58fnhRcuLyxdfx/au337V5GW5OMSPZQi1N6TYBA7Ze+eUKg
         rFKobpgSc71qZ8vvlbnBwAdo73oMYITGGf0QEcxw5Kq5r8ICpo42wZethlPaw6tbgChj
         nCMX1FtYovrQpsM74sMiLIBfDbovMVLiFxcHS6WaT1g0f2OIo7YoyGKDPxry+d03asO/
         lL3LcTXGfp1M8mvyr21HxXpZHTp5FM+ftN1d89cTv4j3eX0f2jOj9jIyvqhAvRvUZ+Ak
         4dWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=9Nlyjwf+Zy7KQtg6D8wcKu8fvS7yw2yDJl7DoXRoUME=;
        fh=WMdBWyEl68gU7aicSKXjoLxLakar0wZ6X4oztsMxtPE=;
        b=XP8MRXa6WGmzaa7ENvEmiBlZ4mGupfqtsagCKJJk6S/29E8dBWZnuofqCGpxYgZbC/
         RF5ibKlVAfZvgzYX/YSj5F02osHoemTSCLwUsEFh/TnTYe+5n9hv8Ek4XnJuRN7CDwCr
         5DkopqLQijB73Molxj0GQTAJ7G3uJRSkk0sPmFeZ27gu7MnPV2SFQoKlflUmeJP7bN4K
         VR4nIpSKcLdhvfsQFOm2K3Nj9aPYr4JGE/O9jV7d3bRMg4c0kSuybeoyg2mH3O2Kutw8
         0LK4UdfKZPYbzIsJC9Kn9Wfop2doxbPD1XmOQj0jL9HoQPbcX26//3qQ1a2T5w/lpeBD
         LoWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726467312; x=1727072112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9Nlyjwf+Zy7KQtg6D8wcKu8fvS7yw2yDJl7DoXRoUME=;
        b=RN2GKBAHcnw2gVL7nt+jprEueXjc11FLngoCu7zLrdhA6goYWB2ii/mqtG22QGw6sD
         eXAdE73Gln/xsj21jW36K3/uG/8L4v2d5OfUJlDAHABqV8atKm4U/7YQLOlQB0JqxLxg
         tArPcM59wIm9690f3uWWMLD7gQtI7JbjnCBQoKKJ5ipXhbK7XTGo3xTA50jlBCgWgMeQ
         i1eK2G97aO6QPKeKxnveJwMyVqb4Y0UCBrtP1KaUfzuO+AVwpYV53Bum4oJdh0MkHti7
         TeMeOJRLLClmSXoLAi5vGYjHikBcMlUCxp0LI/y+9vjjtuB1p72fb5DwAWfvwYrGySH9
         7HXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726467312; x=1727072112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9Nlyjwf+Zy7KQtg6D8wcKu8fvS7yw2yDJl7DoXRoUME=;
        b=NRa6SBZvCe8MO8jtQs66yZxHjrVGmKDbAf86Ts0ijgfZjWr7Gvqeift5tKJByJkM0i
         JtY0nP2xzhva4ph798o+vgvni1iWnXfcUIv9gwbFglDXoT6zJQFCrliIGdtHo9QMLTqX
         3gT+OUPN03jI5L06HYQyEQmjZcfsHAKBRz4gdMueG8mZPOsEF7Dkt+f94Z5QlJsje/gh
         wXbdY1EZO/aLKEigbkBx8wSg39piJyDLbztwnBxX1+4UZA3dL08MzLPh38uj3bHDcDih
         MUVuyfL374iQf0OyOszuYi5/Ya2kEAKqDvYMe0M+05wofmOe2Nghl6Be2umuwFOI66rI
         oJow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWxRx6gB3FcuvJNjKTAHbqQWopBYhxBCV7vNCAHmKWaH21M2oSCarK1oYR5kRTT+XkjYBpMWw==@lfdr.de
X-Gm-Message-State: AOJu0YwGgNsLr7ZJHLEew+ZXO0YMW+yvZ9c34YUn6aoV8pE3bka7jpmv
	ZxNSUBU1FSmAxn45+bylSal2eKTVw5H6VFXv7qEYkQkIDGTjXb0F
X-Google-Smtp-Source: AGHT+IEGnWOATIn+z/iHWNzD+Iy/6Fam2VebRpHk3AZ8fCZl0vQxIOlrVDqbqvvL7sR3a6/uuuSjnA==
X-Received: by 2002:a05:6102:c0d:b0:49b:e3fd:b6d0 with SMTP id ada2fe7eead31-49d4146813emr12323873137.5.1726467312304;
        Sun, 15 Sep 2024 23:15:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4ea7:0:b0:6b7:9a07:4191 with SMTP id 6a1803df08f44-6c57350c397ls54356766d6.2.-pod-prod-01-us;
 Sun, 15 Sep 2024 23:15:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtqxEBqObDcVz1dUcJv+zP+D/g1SwvADwXU5IPFyf2QzCPFw/uSYXPNnUc+Pffgz7AybD0JvjH6hM=@googlegroups.com
X-Received: by 2002:a05:620a:1724:b0:79d:76c3:5309 with SMTP id af79cd13be357-7a9e5ee5330mr1645049585a.4.1726467311511;
        Sun, 15 Sep 2024 23:15:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726467311; cv=none;
        d=google.com; s=arc-20240605;
        b=L6y6Gqeddaw0luAI/nof/EMqCfb5fvIv3b129FB9WB6LnfA55lcvdJ2fQIX+5XZQ3q
         fnXaCV+nUtQ17BAx2XdFMFVaT7+FZSBLVJfGIbnGExPhnbTEg9ooD+GPKOPDLYeurdbT
         1qRMra9ikwJCmVrAx+BpIu6jYr3vD97x3WucHJmtQ7OcuGvUry41B44XPHLldd+84Q5o
         KgcLpUtdXcOQfDDNi9Xc6bIGTBTr7lNDbYZEtgZLHftd7GXERPb23f3DXa3dLcTf5gMu
         qG8FaSJ+KbtvV44SGol/EJPCijPbeID7ea1mNI7rlPS+8eOPnmU9RWtfrzg9Tz8HSmBG
         wDgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=ycUxKFXnDthe/+kyQpwz/V+GToF5jk/XGFoY8kxg4gQ=;
        fh=p0tR56i+t1qaB/8BHJqWR5I6L3jjx8lP5RA59YO9itU=;
        b=aVewBipjxe0BLdw8Mxyhj1WGkcuUWhq1wuftoB0gz7vAzZe2ySa54PlCZ+lUUHt/mL
         8WiEmdwv1jAq2TP3fhurQBt5kcAvFEaHDtIQ3+/mMa9S6PMBdXR7ex0GL3CYV4lvC4+g
         bUzAQqr2KHcR9/BFeW+RkZiUKGjA4z+ynAG1AyLNSnXpNjnyRBOiPLSxifvXqrLo5QT0
         6yI/PUfQgLBorYeNN0Q9MP3/Or4klPZklZoMd5GDdNKUxQRO5qDPSL+ZjfdTklEvzOZs
         NlVZjclJpu4y9iF6cxI+iLts/poLa3u60h97tUhfQW4Ax14BpFSALlxaX6Ix4a3jFCS+
         Cb4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-7ab3eb80006si14757085a.7.2024.09.15.23.15.11
        for <kasan-dev@googlegroups.com>;
        Sun, 15 Sep 2024 23:15:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7DF0D11FB;
	Sun, 15 Sep 2024 23:15:40 -0700 (PDT)
Received: from [10.162.16.84] (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B7AD03F66E;
	Sun, 15 Sep 2024 23:15:04 -0700 (PDT)
Message-ID: <61dafb6a-6212-40a6-8382-0d1b0dae57ac@arm.com>
Date: Mon, 16 Sep 2024 11:45:00 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 4/7] mm: Use pmdp_get() for accessing PMD entries
To: Ryan Roberts <ryan.roberts@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Dimitri Sivanich
 <dimitri.sivanich@hpe.com>, Muchun Song <muchun.song@linux.dev>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Miaohe Lin <linmiaohe@huawei.com>,
 Naoya Horiguchi <nao.horiguchi@gmail.com>,
 Pasha Tatashin <pasha.tatashin@soleen.com>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>,
 Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
 <20240913084433.1016256-5-anshuman.khandual@arm.com>
 <f918bd00-c6a4-498a-bd17-9f5b32f7d6a7@arm.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <f918bd00-c6a4-498a-bd17-9f5b32f7d6a7@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 9/13/24 16:08, Ryan Roberts wrote:
> On 13/09/2024 09:44, Anshuman Khandual wrote:
>> Convert PMD accesses via pmdp_get() helper that defaults as READ_ONCE() but
>> also provides the platform an opportunity to override when required.
>>
>> Cc: Dimitri Sivanich <dimitri.sivanich@hpe.com>
>> Cc: Muchun Song <muchun.song@linux.dev>
>> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
>> Cc: Miaohe Lin <linmiaohe@huawei.com>
>> Cc: Naoya Horiguchi <nao.horiguchi@gmail.com>
>> Cc: Pasha Tatashin <pasha.tatashin@soleen.com>
>> Cc: Dennis Zhou <dennis@kernel.org>
>> Cc: Tejun Heo <tj@kernel.org>
>> Cc: Christoph Lameter <cl@linux.com>
>> Cc: Uladzislau Rezki <urezki@gmail.com>
>> Cc: Christoph Hellwig <hch@infradead.org>
>> Cc: Andrew Morton <akpm@linux-foundation.org>
>> Cc: David Hildenbrand <david@redhat.com>
>> Cc: Ryan Roberts <ryan.roberts@arm.com>
>> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
>> Cc: linux-kernel@vger.kernel.org
>> Cc: linux-fsdevel@vger.kernel.org
>> Cc: linux-mm@kvack.org
>> Cc: kasan-dev@googlegroups.com
>> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
>> ---
>>  drivers/misc/sgi-gru/grufault.c |  4 +--
>>  fs/proc/task_mmu.c              | 26 +++++++-------
>>  include/linux/huge_mm.h         |  3 +-
>>  include/linux/mm.h              |  2 +-
>>  include/linux/pgtable.h         | 14 ++++----
>>  mm/gup.c                        | 14 ++++----
>>  mm/huge_memory.c                | 60 ++++++++++++++++-----------------
>>  mm/hugetlb_vmemmap.c            |  4 +--
>>  mm/kasan/init.c                 | 10 +++---
>>  mm/kasan/shadow.c               |  4 +--
>>  mm/khugepaged.c                 |  4 +--
>>  mm/madvise.c                    |  6 ++--
>>  mm/memory-failure.c             |  6 ++--
>>  mm/memory.c                     | 25 +++++++-------
>>  mm/mempolicy.c                  |  4 +--
>>  mm/migrate.c                    |  4 +--
>>  mm/migrate_device.c             | 10 +++---
>>  mm/mlock.c                      |  6 ++--
>>  mm/mprotect.c                   |  2 +-
>>  mm/mremap.c                     |  4 +--
>>  mm/page_table_check.c           |  2 +-
>>  mm/pagewalk.c                   |  4 +--
>>  mm/percpu.c                     |  2 +-
>>  mm/pgtable-generic.c            | 16 ++++-----
>>  mm/ptdump.c                     |  2 +-
>>  mm/rmap.c                       |  2 +-
>>  mm/sparse-vmemmap.c             |  4 +--
>>  mm/vmalloc.c                    | 12 +++----
>>  28 files changed, 129 insertions(+), 127 deletions(-)
>>
>> diff --git a/drivers/misc/sgi-gru/grufault.c b/drivers/misc/sgi-gru/grufault.c
>> index 3557d78ee47a..f3d6249b7dfb 100644
>> --- a/drivers/misc/sgi-gru/grufault.c
>> +++ b/drivers/misc/sgi-gru/grufault.c
>> @@ -224,10 +224,10 @@ static int atomic_pte_lookup(struct vm_area_struct *vma, unsigned long vaddr,
>>  		goto err;
>>  
>>  	pmdp = pmd_offset(pudp, vaddr);
>> -	if (unlikely(pmd_none(*pmdp)))
>> +	if (unlikely(pmd_none(pmdp_get(pmdp))))
>>  		goto err;
>>  #ifdef CONFIG_X86_64
>> -	if (unlikely(pmd_leaf(*pmdp)))
>> +	if (unlikely(pmd_leaf(pmdp_get(pmdp))))
> Just a general comment about multiple gets; before, the compiler most likely
> turned multiple '*pmdp' dereferences into a single actual load. But READ_ONCE()
> inside pmdp_get() ensures you get a load for every call to pmdp_get(). This has
> 2 potential problems:
> 
>  - More loads could potentially regress speed in some hot paths
> 
>  - In paths that don't hold an appropriate PTL the multiple loads could race
> with a writer, meaning each load gets a different value. The intent of the code
> is usually that each check is operating on the same value.

Makes sense, above two concerns are potential problems I guess.

> 
> For the ptep_get() conversion, I solved this by reading into a temporary once
> then using the temporary for the comparisons.

Alright.

> 
> I'm not sure if these are real problems in practice, but seems safest to
> continue to follow this established pattern?

Yes, will make the necessary changes across the series which might create some
amount of code churn but seems like it would be worth. Planning to add old_pxd
local variables when required and load them from the address, as soon as 'pxd'
pointer becomes valid.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/61dafb6a-6212-40a6-8382-0d1b0dae57ac%40arm.com.
