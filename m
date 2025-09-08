Return-Path: <kasan-dev+bncBC32535MUICBBVHC7PCQMGQEI4NZ4VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 5071BB49284
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:08:08 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b5e9b60ce6sf105071601cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:08:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757344087; cv=pass;
        d=google.com; s=arc-20240605;
        b=h8VEZVwbeY4bnu22FU0J60ee9HIFfWmK8YydGTIy73eYoVzx0W0/IVesdocEMXFHKs
         MN5AnnXHy0avrP9ONM+Ll6S3YefN6sbDGNeMoWn0GOoMrNp/HdhGFnq1sWfEkx63hPpn
         gvEEpAepKqsr32ut5dQd4mSSgz/ttuUhE3SAsXr+UiwUW/Fm6jDllCzB8II50eyUOkNf
         293vr+g3wYOX3B0gFkFeBfm2DFrrpYuhy3KM1qkJ54dvq+92NK1Bxsex+RDquDK4zvsk
         IQr1Gqsezn5k7KWOaEo6FboemkBxZ+qKuPeURlkjGk30j/hW0x4tK0wYPTGjOcrDAZZM
         xzRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=dRrN9Ht4nug5NcAsa/l3bsOtl84ia1iXNOgo1PMkIFg=;
        fh=tGkC/t9JbW3Gru9ci3JSNk8mbAlz6T3D8EhNqnDazjA=;
        b=cLR2kSsM7CydadsVYscU1q1XqcMcm7NHVMP3pF0Lm7LFx+n2+eLlrSrobpSEgFJcVI
         iJoaEe6dz0na5JM5AVLTmzd/mfjmIXGHypWkBZAm7iysBtpzUE/pJjxnZbf1WFOa4T54
         q6wdVX5Z62zXZvGng5bz2oMBWt2IH964SHn3hZURiuuczCxd4L7e9YaxOK8BDXYsdAzt
         QjlNp4XFs9txKbkOrSSqeTWIfgk9uBMS3sN497l9I1MxtM1gvN3X1jlSsMhl7xHkXkM3
         PKf2D5llXKmBEzuKY0O4+pxTFHrwvMOt+BLaSyD+J5lM5a5ubL3ff5WBbD36OV2l7srJ
         W4hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fkRwNQsY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757344087; x=1757948887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=dRrN9Ht4nug5NcAsa/l3bsOtl84ia1iXNOgo1PMkIFg=;
        b=K6Lm5zWXDbGdWRsZi2hx7XMG7wmOUwDsfI80Q4sTPGpRKmYzvzRFjC1UyqBch7Puu8
         HHiDe+lijunTN2+bKi/zjv0PEIR4EO9PHQhBH7H3Ao6PDRojF0xnBuOC1nstGoQE09Mu
         KPwYydJ8dgA1fEYVa0PZV7aNUTYca9Usg3+dZV0NB0dgChyg+q8t5jatqwZcYCsM659Y
         PHq/WGK65dcD7yfIrJrlSVsvPWCWF/XhZGhCPSgQrl5u5YK0lXKQD/mqjDF70kt+17zd
         SY+aH3AOQ+JHjrj5OzcyMt+Ek5q1D6OTyRnlI/qxNGz9JP6FQGmCBJ2h1SZmKGPKrV38
         ahPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757344087; x=1757948887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dRrN9Ht4nug5NcAsa/l3bsOtl84ia1iXNOgo1PMkIFg=;
        b=ZIzmbxLkHS9dxFuwuYwe1B0pHfbmKOMKimfTQWAB7kuVbZ31kh9wkakux+oyhUBDuG
         G7MhjeaLFNJRoqKoIhYkhXRWwB7gUwpvr5lTkHH3FpCtXwoP2RufKBLcSSgRxR6kifrl
         XxzcaiC5ibrS7UciCmSmA7sEImYsnbRDO63q/sTJNno+/RxSMqMKnsiohoLuJrinSDGt
         /SlbUreQOWjYR67W1tkEEHLQmcghfpA9vWFulIa2y/DiQVVMbsw0jz75o0cHE5080CTT
         stMPLz1C0uWE7b0Y3bkCXCbf5APyYV0CpCszhfABpkOkMECeBce6/IgGTwPjgDP94U/7
         qLIQ==
X-Forwarded-Encrypted: i=2; AJvYcCXvCXxpPCuzFYXvbXeiUbQf/S1XZP2A/bcRlYY4nlWhrByrvFsVPPczKRRrQZFp9/O1OuTT1Q==@lfdr.de
X-Gm-Message-State: AOJu0YzYT7RxiVf+RMd9OW5b/P1E4t7QfD2GO9aLCsSSXX4vTfK1BNKL
	ZLGUzRD1sD0NNEorJmoQOmURwUJga6FHEgSyCa0b1qcxt9Xm6XUYDOVb
X-Google-Smtp-Source: AGHT+IGtC5qoXSNWWIoUpW/tnxXp2DDfnA7oolfngBMd0+7S2VbxK+/FoJW3V1x2cLJoHLLXGW525A==
X-Received: by 2002:ac8:5dd3:0:b0:4b2:d43d:8d37 with SMTP id d75a77b69052e-4b5f8448293mr86846671cf.6.1757344085206;
        Mon, 08 Sep 2025 08:08:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwb4jbpyPZFtRKZrUkOK/6ClyJPSqQAiUvqOyabgjMmg==
Received: by 2002:a05:622a:242:b0:4b0:7bac:ac35 with SMTP id
 d75a77b69052e-4b5ea9e5dc5ls61204191cf.1.-pod-prod-05-us; Mon, 08 Sep 2025
 08:08:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYBe6DI0OZ85ISpMENSVF4WLu3TmJfTVqULDvv+byccA1Oo9cbO49hvvR7of5P5OpO5bcuBZR/zy8=@googlegroups.com
X-Received: by 2002:a05:620a:4441:b0:7fc:9c25:8ca0 with SMTP id af79cd13be357-813c6dcb97fmr683478085a.67.1757344083947;
        Mon, 08 Sep 2025 08:08:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757344083; cv=none;
        d=google.com; s=arc-20240605;
        b=I2FHS0iTK6lFNYq+x1i7OWKyix5SlKd5691PudjOJJznjwxZtfjm+teXCCj4aqhttd
         9xiCCBQl+MOQoPinpAzgMcscqgOcuutxpmRgYuSu7Zfn3kdd//px7CAzCpVRrsRcqF7I
         F+E9q0G4K4B9jlJMYpETUNDa85idpLXuBYSoXAnHyJDO7Uh5ewlC6SePqn9/4ECRT4HA
         c1KcFOogUGqPwZ07LnZ+uUPZLSGAyq1+ysbSNpWa6fPxMegflWLWIayCjvd3r05ZhXPj
         ZFBm6yL8FOdPxJvEaf+eLNVxMGTLDlJMQr4sYCWzFYkGaI3NTKre/vOay1nt0b8UWn0u
         CQWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=5pKUW/icABhJPZyV0g3yxdIs8s3bqfZdt2XQu7KwBtE=;
        fh=6S/Jss6Kyjv7f7+shF3Z+tAVnPwfR2UQe86/CaJ2XfE=;
        b=QJF70Bf/rbo/dVDmxmmv/8bnEP9t66k0JZu7lYI34gYnB5q4YeqvD4xP62PHgyQqUY
         t8nDdeGC+zwlwL3aSk30/MkTmM3llyegyEjULXWfkSMtlHvixzlYOMEGWRkcVpEXtKOm
         4FgjKQC/L8g4NNFy8WCsQ+n2B2J79Kpxn1rlJ1Ax1CdSzcWpH+AFzweNCDcztHJDvLMC
         1Zer1Fhg9+vCmqS+mY6u8LmFz2gVcRAaO7UT72SMR52zN0OSruFFcMB3meTIm7DOHe9m
         vGva5z5SrREweplCKNGj6uaJwM66eURE4RhxIP8rY/gCZNXc2PX0wJCGy8iaUOFRk8kj
         DKNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fkRwNQsY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aa94e713csi59804185a.3.2025.09.08.08.08.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:08:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-31-VQSc89WdOOS-XKXh0avVoQ-1; Mon, 08 Sep 2025 11:08:02 -0400
X-MC-Unique: VQSc89WdOOS-XKXh0avVoQ-1
X-Mimecast-MFC-AGG-ID: VQSc89WdOOS-XKXh0avVoQ_1757344081
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45de13167aaso15279995e9.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:08:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLN31j/5lJ+8gMbQ6v+/LsvFZWNIBsG6FOwhuhxHz05M3f6RkHzSXhQnDzadlIRzYT9PL6zGClsPU=@googlegroups.com
X-Gm-Gg: ASbGncsCKkbiErcW75f1ywtdjiWAFB7JxvImwzGTfuWBvUHUM1rcRGv/J0xVe2FxBeY
	Px+XYTijl/fvvQDxpvknS6jUHE6Ckm4S35VuWIMd56Q55GCwQ5wFSWkbQVVrjcS6gI0VrNUT5yX
	yde2/g7QHOFhyd3KbRCQ1ypPjbEnrKwWaQ8dNC7kKGS4261caZwATqiWavpxJ/ufDjhiZ2xbyyQ
	Wi4ro8fjk/BSWpGaKCQx0X9eAcuJLUuCdLq/Z0VvYZQvibCisr/uQ1PNx5jatsjxidgqcEoCIZA
	jUogJCwlCEzcxTego/JORHmg7oAGvzg8E49uaCnHT4CPM0+R+7JySHC6Au0clTfXyEZZV8VljuJ
	tJ+SX4S4Ezxyn32P//yP4/HYJI5eF2wXHs61V9eD8bLepYItu+Q6eap+8cHd2QkTi
X-Received: by 2002:a05:600c:5299:b0:45d:dd47:b45f with SMTP id 5b1f17b1804b1-45dddef7fdamr66712695e9.31.1757344081160;
        Mon, 08 Sep 2025 08:08:01 -0700 (PDT)
X-Received: by 2002:a05:600c:5299:b0:45d:dd47:b45f with SMTP id 5b1f17b1804b1-45dddef7fdamr66712145e9.31.1757344080658;
        Mon, 08 Sep 2025 08:08:00 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45de6e787desm19519385e9.8.2025.09.08.08.07.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:08:00 -0700 (PDT)
Message-ID: <af3695c3-836a-4418-b18d-96d8ae122f25@redhat.com>
Date: Mon, 8 Sep 2025 17:07:57 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Jason Gunthorpe <jgg@nvidia.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>,
 Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>,
 Sven Schnelle <svens@linux.ibm.com>, "David S . Miller"
 <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
 Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
 Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
 Reinette Chatre <reinette.chatre@intel.com>,
 Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
 linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
 kexec@lists.infradead.org, kasan-dev@googlegroups.com
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: JtifQRPqrTE_F-npxF6O4RmVQWBua664j9dFpjA-JPc_1757344081
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fkRwNQsY;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 08.09.25 16:47, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 11:20:11AM -0300, Jason Gunthorpe wrote:
>> On Mon, Sep 08, 2025 at 03:09:43PM +0100, Lorenzo Stoakes wrote:
>>>> Perhaps
>>>>
>>>> !vma_desc_cowable()
>>>>
>>>> Is what many drivers are really trying to assert.
>>>
>>> Well no, because:
>>>
>>> static inline bool is_cow_mapping(vm_flags_t flags)
>>> {
>>> 	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
>>> }
>>>
>>> Read-only means !CoW.
>>
>> What drivers want when they check SHARED is to prevent COW. It is COW
>> that causes problems for whatever the driver is doing, so calling the
>> helper cowable and making the test actually right for is a good thing.
>>
>> COW of this VMA, and no possibilty to remap/mprotect/fork/etc it into
>> something that is COW in future.
> 
> But you can't do that if !VM_MAYWRITE.
> 
> I mean probably the driver's just wrong and should use is_cow_mapping() tbh.
> 
>>
>> Drivers have commonly various things with VM_SHARED to establish !COW,
>> but if that isn't actually right then lets fix it to be clear and
>> correct.
> 
> I think we need to be cautious of scope here :) I don't want to accidentally
> break things this way.
> 
> OK I think a sensible way forward - How about I add desc_is_cowable() or
> vma_desc_cowable() and only set this if I'm confident it's correct?

I'll note that the naming is bad.

Why?

Because the vma_desc is not cowable. The underlying mapping maybe is.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/af3695c3-836a-4418-b18d-96d8ae122f25%40redhat.com.
