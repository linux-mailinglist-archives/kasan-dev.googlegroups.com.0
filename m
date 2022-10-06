Return-Path: <kasan-dev+bncBC32535MUICBB6747OMQMGQEP52VVPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E3735F6B46
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 18:12:45 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id n5-20020a4a3445000000b004728fe7a331sf1184054oof.23
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 09:12:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665072764; cv=pass;
        d=google.com; s=arc-20160816;
        b=FfrGB1wsNveKqus+v9sdwbwRr5DM3uaG9QQIMcfZp4Gydshzp6iGU2FGOHB2/JwMje
         WkYQxKx0PryEut1KxQyCFtHAiCR0F4bhR7eJGnA78MSqrg1TbEnr8rCOVIuKJK942Glt
         0nSAOEdb8HAChbYm/XXQ5mMf0+GqrDbcW3CGVfsdNQjhBUca4jRocBpfpQRDMIw2d6Kq
         llO0FhJh4yJZnqTmmhLAujYODa9ledH3r1SwCPJzfUB5jnxQxK6QBInTLJr/0MJWGqLu
         dsKkuiRonwRCD3zyio1iAEV3NtDmqBN2hwJLpwe4mPkxUrlQV5g1QeZTtE7dB25B5itx
         AtKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=MmYj8wF4UEijDd6z0dbjCzs6YWyNw/8EAaC54SHyUtY=;
        b=NiDXltsqbfyodkNU94+grz/Bsu8Jh1IeVmu1yTz8+YjUWbwq5P2OvZS5j3dARmJAMe
         gLn2rlvij5Bp6AoMDSk3J5OVZRqIyQNOiFKJapXwXpe0FTKC5kO45gbB0Cc37RyaeE7M
         kQpKDZonrTGQih3ix09AVdFkwEiXvucn3V4R3D8g0S552hUODkvnvxf7f7Eq9VzU0sqz
         LXmQRIdITyoI/nAWCA4G0Xq8yTlwbfMTanHQ0b5dlUyxTp5SEi5qttdeyYBb5vNmmbkl
         0XNjVvcidpZI2bA6cZHvPUNUPyw23rcNlS3by8CpH49Xy4yYmUotnwLUE0n3HWeZoCel
         YbDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="g/2FEJzz";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MmYj8wF4UEijDd6z0dbjCzs6YWyNw/8EAaC54SHyUtY=;
        b=LGFgwgFDOFj5rwSIHaXjRFDlA/AYy9pYKbY8WlmVzHP3PpoIG/snzm4FQlhfqzckI/
         Rsq9sAbT6Jr5kEOcAE/zE50C8G7TNrB4iNBL3GfguC1IzMs+vQYwQHbigEB6KI/FC2pA
         tf5e3vu9WB8ETYLooDbuAf7NAVR9c9gDjtPwTWXxHU/zq+U0JHjsUf7wzSV1WYKQ+OQT
         qE3hJxvuU2gG0QLqJeYyBURgdhq/BbaUbGgPnLLopVYUiNoUpFMoBuxoTYznEQmgfe/z
         +rZVZxeaXd8Ip31hutJIYIeEVmxiDO+//yBu4Y+2fzY9dCp7NOYb7Sr88gkdKIs9PpxD
         r95Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MmYj8wF4UEijDd6z0dbjCzs6YWyNw/8EAaC54SHyUtY=;
        b=LefFrUFyfEpjbYsYmHonjX/7UdiVtOTlcyNUE3spUgvdvER3rwmnXYxxpB8wWxV3rG
         vtR5OZ/ewTF/3A0Aor+cJwas0lFWuLUquYsOX1iaYnUVg5613g+GrF/D6ILADwtjnlan
         XZM4UeRFuqsgwEumr14S/4Wt3Q8Ze9MhT0GUF1EoVNFfN962J9FOYxmEMy7WyHxV+GqU
         U9J8aHznIKfI606zy1/pXNIYkxV8ggTE4sbrjDVOz0q1i/7qIdOzP9f4OscKlXLW9kFq
         QuOcAGrXRHRpsHzJR7gvtcQWqpasGxY4/tBCxT4XTP/u8Cl6VgC4p63zV3RBvTWjCXoe
         nGQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf35KhMe2Uu9YGuC8XiCbO13YgORE5Ij2TK0gBudJPOpK76tsQC3
	HDNda57QNZ8qIqIhMV8cqRM=
X-Google-Smtp-Source: AMsMyM6Zr8MWglCFYm06OQHXa29CeMckuEI4EZR0wlfQK5khnmNUMpW7IdWL2TZdlXkrZQTHNEKdJg==
X-Received: by 2002:a05:6871:7a1:b0:131:946a:7b30 with SMTP id o33-20020a05687107a100b00131946a7b30mr5546780oap.67.1665072763962;
        Thu, 06 Oct 2022 09:12:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:af49:0:b0:44e:1e14:3ed5 with SMTP id x9-20020a4aaf49000000b0044e1e143ed5ls88049oon.7.-pod-prod-gmail;
 Thu, 06 Oct 2022 09:12:43 -0700 (PDT)
X-Received: by 2002:a4a:4243:0:b0:475:7ca7:c3df with SMTP id i3-20020a4a4243000000b004757ca7c3dfmr129015ooj.59.1665072763331;
        Thu, 06 Oct 2022 09:12:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665072763; cv=none;
        d=google.com; s=arc-20160816;
        b=zGk7VAd7IvNvc5H+azsdPEopjgFQs1FXW9bKp8OuHHwJghJLKdqr/qvouKEStReTwI
         9rLO/wmCQ4yyHPwTPJEGs2nyKu72NszlStNp6ENlfXIrs9h48JnDxrKDg8tyJhduKLi3
         Euq8SL4mJQXvcw3CCU2tojzr4KFhHuXt0P0PlcOqNWTCoE2yH3653yFIIWeK0WRiZ3Pi
         qGy2fcwQ8n8zKQKh0xKpks9qkUwTRHFYf/La2OrBFe0MPIGw6c0CUePeUzPa/L89lLi+
         hw9pZE1D787JELUW5QMm9RlMELFqxcu4afQ5VuxYxjOgFndk23o4XZyBqbr0p1+rxbus
         06FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=E688m+CVGsUZmRjmdJkUdBL96fMrGrm7kEEkGoS+98E=;
        b=OMUf6ZVEAoPDMB8ZjL50/bJG1WMXli4ryFlnVgEoHnYfW+5IAGaxxyuO6N1CgCR/hs
         7dT6zsCbOav+OLz/X2PEU635S39hEqX4sV8GGLhbDKDCLwJYz87w+hLsIwkxLkdDimod
         1jTW6ZuasFGAMPGpUf2ZhGH98vHxdhVOTrTeyKr10KZ3lT5NpvFSWGSiCeBA75tHFxS+
         lBtEtGVNGbjtGwrS66xZija6b2EDqZYAwS0hPEwFu73NJnh9guh6mFPdOs8XXh8/RnbE
         4KwdquwlWhTmhEMiMiN7yW1yNLe20sk+MqZUAHVKSIRO5najpcK/HeEMY5MEkBMEt2h3
         CRVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="g/2FEJzz";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id i82-20020aca3b55000000b003504d4fcb12si781541oia.0.2022.10.06.09.12.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 09:12:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-500-5oHxvA6fOuOBoAQxbR7kzQ-1; Thu, 06 Oct 2022 12:12:41 -0400
X-MC-Unique: 5oHxvA6fOuOBoAQxbR7kzQ-1
Received: by mail-wm1-f69.google.com with SMTP id v125-20020a1cac83000000b003bd44dc5242so2811046wme.7
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 09:12:36 -0700 (PDT)
X-Received: by 2002:a05:600c:2d14:b0:3b4:86fe:bcec with SMTP id x20-20020a05600c2d1400b003b486febcecmr401954wmf.16.1665072755739;
        Thu, 06 Oct 2022 09:12:35 -0700 (PDT)
X-Received: by 2002:a05:600c:2d14:b0:3b4:86fe:bcec with SMTP id x20-20020a05600c2d1400b003b486febcecmr401932wmf.16.1665072755423;
        Thu, 06 Oct 2022 09:12:35 -0700 (PDT)
Received: from ?IPV6:2003:cb:c705:3700:aed2:a0f8:c270:7f30? (p200300cbc7053700aed2a0f8c2707f30.dip0.t-ipconnect.de. [2003:cb:c705:3700:aed2:a0f8:c270:7f30])
        by smtp.gmail.com with ESMTPSA id dn10-20020a05600c654a00b003b341a2cfadsm4941834wmb.17.2022.10.06.09.12.34
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 09:12:34 -0700 (PDT)
Message-ID: <9ce8a3a3-8305-31a4-a097-3719861c234e@redhat.com>
Date: Thu, 6 Oct 2022 18:12:33 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
Subject: Re: KASAN-related VMAP allocation errors in debug kernels with many
 logical CPUS
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev@googlegroups.com
References: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
 <Yz711WzMS+lG7Zlw@pc636>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <Yz711WzMS+lG7Zlw@pc636>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="g/2FEJzz";
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

On 06.10.22 17:35, Uladzislau Rezki wrote:
>> Hi,
>>
>> we're currently hitting a weird vmap issue in debug kernels with KASAN enabled
>> on fairly large VMs. I reproduced it on v5.19 (did not get the chance to
>> try 6.0 yet because I don't have access to the machine right now, but
>> I suspect it persists).
>>
>> It seems to trigger when udev probes a massive amount of devices in parallel
>> while the system is booting up. Once the system booted, I no longer see any
>> such issues.
>>
>>
>> [  165.818200] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>> [  165.836622] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
>> [  165.837461] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
>> [  165.840573] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>> [  165.841059] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>> [  165.841428] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>> [  165.841819] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>> [  165.842123] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>> [  165.843359] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>> [  165.844894] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>> [  165.847028] CPU: 253 PID: 4995 Comm: systemd-udevd Not tainted 5.19.0 #2
>> [  165.935689] Hardware name: Lenovo ThinkSystem SR950 -[7X12ABC1WW]-/-[7X12ABC1WW]-, BIOS -[PSE130O-1.81]- 05/20/2020
>> [  165.947343] Call Trace:
>> [  165.950075]  <TASK>
>> [  165.952425]  dump_stack_lvl+0x57/0x81
>> [  165.956532]  warn_alloc.cold+0x95/0x18a
>> [  165.960836]  ? zone_watermark_ok_safe+0x240/0x240
>> [  165.966100]  ? slab_free_freelist_hook+0x11d/0x1d0
>> [  165.971461]  ? __get_vm_area_node+0x2af/0x360
>> [  165.976341]  ? __get_vm_area_node+0x2af/0x360
>> [  165.981219]  __vmalloc_node_range+0x291/0x560
>> [  165.986087]  ? __mutex_unlock_slowpath+0x161/0x5e0
>> [  165.991447]  ? move_module+0x4c/0x630
>> [  165.995547]  ? vfree_atomic+0xa0/0xa0
>> [  165.999647]  ? move_module+0x4c/0x630
>> [  166.003741]  module_alloc+0xe7/0x170
>> [  166.007747]  ? move_module+0x4c/0x630
>> [  166.011840]  move_module+0x4c/0x630
>> [  166.015751]  layout_and_allocate+0x32c/0x560
>> [  166.020519]  load_module+0x8e0/0x25c0
>>
> Can it be that we do not have enough "module section" size? I mean the
> section size, which is MODULES_END - MODULES_VADDR is rather small so
> some modules are not loaded due to no space.
> 
> CONFIG_RANDOMIZE_BASE also creates some offset overhead if enabled on
> your box. But it looks it is rather negligible.

Right, I suspected both points -- but was fairly confused why the 
numbers of CPUs would matter.

What would make sense is that if we're tight on module vmap space, that 
the race I think that could happen with purging only once and then 
failing could become relevant.

> 
> Maybe try to increase the module-section size to see if it solves the
> problem.

What would be the easiest way to do that?

Thanks!

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9ce8a3a3-8305-31a4-a097-3719861c234e%40redhat.com.
