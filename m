Return-Path: <kasan-dev+bncBC32535MUICBB5PWTKZQMGQELC5DM5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id E9C8F901D0B
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 10:38:15 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-6e79f0ff303sf1471043a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 01:38:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718008694; cv=pass;
        d=google.com; s=arc-20160816;
        b=te+1Mq/ct2Ctejw1iULCiYZk4HRx7MbqvPt3IbLxODjYeR+lYmakKRMt7Pxhodt04S
         bYtx3/Y9GWTgONCCJwk2wFqDcU9Jett7JmZWNKS2KTj9lPWDt1O8T4yK1NoRMY4ObU0G
         WHUXdv7cdhI4HXaRqOb9O9xwcjcEfaHZMGqAq0gxtMyPejSsQ3tAJcqunQONlJvYk6UM
         1v/yJ0MVjms5ERUUyMWGpuNkwzqpjSQnccEbNEw89DmZ1z9WVPghJKyAUeeIJO5hpJ7A
         1PwgmiEyWkipr8JPryntEjBvL3iOhryGuwsNvXdjs6GUW2QH/N/YrzDkQTnm0vz9NvK1
         yjYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=wG1HCpfh7S2blxmoA42UMCX+AGVfaxhHivQA/Ie2E9U=;
        fh=lDjvewv3+A1cdbJhpaIbu/9AZfThjbVWStNBFodUkvc=;
        b=GedO64JTgeQSGoVNmjnO+0Fr1AHiWeEa5GaVpu88XVfZsWu62I16IBydWjAU19UYMe
         FEenax0xnXE6ZszvVR8+/np6n6+qW2TZPCdMpG5nDSWIc8hp1HWi4pzykQ/FtXunTiBm
         hNvnqECi1qo/2IOAS3lCXq8PVyKQspHaSVAgpIStF5YOc46lo0AuWj0gpMgmS6OtoSqY
         LCKgQLqhSZ6POD/YxG13dP7fsTZaoBeHXWJnGnbhLy3qBtmdvAVkzYO2ShUAno4WyX/X
         SCNG9lr92T2fyj5R2jLzlvl/BK4AGP0JQdAOp4e65DEUINLJR6fRY+Zr9Nts1HuYDmCA
         /Z9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Cz1+gTu7;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718008694; x=1718613494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wG1HCpfh7S2blxmoA42UMCX+AGVfaxhHivQA/Ie2E9U=;
        b=OTxVZOvyYYjr8u5+2kIccc8Jt8Qgh5C7OjAsk7nLOj978dd7whO6ZxlMmW4+MizrXH
         qm5ZwCKL452u42PrEvCyOvFNIVFdyJEreyrBnYpUx81tq7ykte9jip8SroGBglFJq5iI
         kYhOqpyCTk/RcXrTgVA00s5Oc5qbtEqkiBNbUxGl3ecjzPe4UQdd2/POhPH4xKxMghKT
         zlmvJMuy05rmG+yUgFNVh7/LEmc1k7ShRu3PdWdAkeXKq56qSl484WHGWINkncDm1KCH
         P2enNjpSFU0AGwqH7AIuL8fncAo25FcEG3ELWIg3wKgtFCle8mYwn1cM1wT9cSjydtBn
         bdMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718008694; x=1718613494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wG1HCpfh7S2blxmoA42UMCX+AGVfaxhHivQA/Ie2E9U=;
        b=Tlh7mhKd3phzAdvR6kxkEExltHnAL299SKCgyCu3OWEVkrknKZLTeyz96qGhHPm5d4
         lvP8EtehjNs2emHnDmLnGJSP0+hpk7qJK4cHcGB0qiJGRHxM/JZK0z50+M6D5j1DiP8/
         vbm8QzsWzz1flbf/h/0qm3iFn/xevzLM4LkpljiQvkImpyWBHibWELiX2e+lnaHKMNNB
         KySdCSSRMXlcLrQzu2rS0bdnVxpxclhyyIzoq9DMCYlOuo9tWsxrj/lyXJOFFtIRloPG
         FgHPvyBtO3UertngllodRiJ1olviCmBaNh+B699Cs1Bdmxq4QYdPR4MoMSWeJ7d4gEKZ
         Q8aA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWryT5ZWmVrPEv1AvQwlrOkelaZuPYyvQk0a40g0mGk33ISECNTvhChz3lBuGdsOyHnjk8TmtyQTffZe72A6rTygrXa9wqPOQ==
X-Gm-Message-State: AOJu0YzU4eYZaW6nylNDscC+rlZFFFVftNTPhwGFl8pJ1in0El2FMnJM
	SFPwLFzlUgrZQScwi+N3f7Dnfwws1RRPOVtNMgBZN5WioV7teBB/
X-Google-Smtp-Source: AGHT+IEMBYM5NoBojJAaBX04AIjpmY/oZyb/6WtC2QeU2Nth9GlrTwB9tLPyeENvNMEF/n41oL8n2w==
X-Received: by 2002:a05:6a20:9151:b0:1b5:fd58:30e8 with SMTP id adf61e73a8af0-1b5fd586289mr3919924637.18.1718008693713;
        Mon, 10 Jun 2024 01:38:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e802:b0:1f3:16fa:bc77 with SMTP id
 d9443c01a7336-1f6cc4274ddls26285595ad.1.-pod-prod-07-us; Mon, 10 Jun 2024
 01:38:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0GbyE2Q2fMGOyn0I+Dce5x3TkoaPcFh85dH9NY/1pJJwtWeed+9EikiBjoMcCenLwjbnY4XXY2CbRiP9Hoxlg0YpJ3YUR/e9obw==
X-Received: by 2002:a17:90a:d588:b0:2bd:92e7:c305 with SMTP id 98e67ed59e1d1-2c2bcb0f872mr7943855a91.21.1718008692253;
        Mon, 10 Jun 2024 01:38:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718008692; cv=none;
        d=google.com; s=arc-20160816;
        b=oWcSwkWwqVqxqcG3arC/N5VPv5aZs2CGPKV+sNKOBDKkqMVPp/QtNs8L15oUKaK4Dc
         8T8Ib5lB1YR0lFPUgCfpYhfV45ZqRRpSINyr76wJNba5qCE8U+XpE0vjNRixAsWnuSlK
         teQPx76iRMU+KYxVYhZKTsypAJ8Op+VyPVu8QCaFpWyVoGlnYdK+yamw+urIobuOpPib
         NEnqZh2WpipjhMvKz/bh7pwubEKa4kmuWOmekg5V4OGwfTSzbMhOkS71IGBi59agIDVd
         dBkIAfMfR+7nhYHGB9apQ8BJsfVFVZe87qPpuinoig83LENr/URREEY0QRwuOFR5669L
         DWzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=w6nrbStgbGoljYTouWdcfenV64/6o+i5+It1jT8aCEg=;
        fh=+mRjAD8eFmMTLyB+EGUZpQpO/p/19pVxtyYcl6TWBkI=;
        b=a+isQjZW2JbxAwqL+RGPVZEe1B0vwg6z9N4SY+czSxmR4U62Ybtov8rToemyg5W2Rr
         C1IXzb7lEPzMaK6t/AvTmg/P9fJU+kv02KzkqjMwqFtdGW9ibWVGNG+mJWHz9ut9Gjmq
         1slIgn/IKgWxLU3lNa1654qvUksihSEvjKc8o2thv3mgY0V4H/4dUaqM5+IIUYy66VRL
         zPU03k4dk8b6Wcro+yBRy/bRsifiXeT0G6bX7KH5b16v7Di5OIYULbGbnt5ekszvwqcQ
         ZtX8jfnAKXk2vvF7Hp0tH0JORmc549dj1dceVL5KbLczPIiP/1qZ0aFDscG9Fen6hd4N
         hYNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Cz1+gTu7;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c30ea4fcd9si130260a91.1.2024.06.10.01.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Jun 2024 01:38:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-463-Eg5bl6JHNui4z4WsjjYHfg-1; Mon, 10 Jun 2024 04:38:08 -0400
X-MC-Unique: Eg5bl6JHNui4z4WsjjYHfg-1
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-35f1ddd8a47so594719f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Jun 2024 01:38:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV4ztwh3pYe8u0HzBAH62ZncSWNMpbdPyxbiCzw9vEKfqCs2oYoCfuNOCNSYHwa+a4618ARhHcbPRmyYzuY6o7Shx84K8+scfoqTA==
X-Received: by 2002:a5d:5f90:0:b0:35f:22d9:cab3 with SMTP id ffacd0b85a97d-35f22d9cd51mr2249182f8f.36.1718008687493;
        Mon, 10 Jun 2024 01:38:07 -0700 (PDT)
X-Received: by 2002:a5d:5f90:0:b0:35f:22d9:cab3 with SMTP id ffacd0b85a97d-35f22d9cd51mr2249152f8f.36.1718008686974;
        Mon, 10 Jun 2024 01:38:06 -0700 (PDT)
Received: from ?IPV6:2a09:80c0:192:0:5dac:bf3d:c41:c3e7? ([2a09:80c0:192:0:5dac:bf3d:c41:c3e7])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-35f29629231sm157912f8f.67.2024.06.10.01.38.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jun 2024 01:38:06 -0700 (PDT)
Message-ID: <13070847-4129-490c-b228-2e52bd77566a@redhat.com>
Date: Mon, 10 Jun 2024 10:38:05 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
To: Oscar Salvador <osalvador@suse.de>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
 Andrew Morton <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>,
 "K. Y. Srinivasan" <kys@microsoft.com>,
 Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu <wei.liu@kernel.org>,
 Dexuan Cui <decui@microsoft.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>,
 Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-2-david@redhat.com>
 <ZmZ7GgwJw4ucPJaM@localhost.localdomain>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <ZmZ7GgwJw4ucPJaM@localhost.localdomain>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Cz1+gTu7;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 10.06.24 06:03, Oscar Salvador wrote:
> On Fri, Jun 07, 2024 at 11:09:36AM +0200, David Hildenbrand wrote:
>> In preparation for further changes, let's teach __free_pages_core()
>> about the differences of memory hotplug handling.
>>
>> Move the memory hotplug specific handling from generic_online_page() to
>> __free_pages_core(), use adjust_managed_page_count() on the memory
>> hotplug path, and spell out why memory freed via memblock
>> cannot currently use adjust_managed_page_count().
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> All looks good but I am puzzled with something.
> 
>> +	} else {
>> +		/* memblock adjusts totalram_pages() ahead of time. */
>> +		atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
>> +	}
> 
> You say that memblock adjusts totalram_pages ahead of time, and I guess
> you mean in memblock_free_all()

And memblock_free_late(), which uses atomic_long_inc().

> 
>   pages = free_low_memory_core_early()
>   totalram_pages_add(pages);
> 
> but that is not ahead, it looks like it is upading __after__ sending
> them to buddy?

Right (it's suboptimal, but not really problematic so far. Hopefully Wei 
can clean it up and move it in here as well)

For the time being

"/* memblock adjusts totalram_pages() manually. */"

?

Thanks!

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/13070847-4129-490c-b228-2e52bd77566a%40redhat.com.
