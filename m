Return-Path: <kasan-dev+bncBC32535MUICBBNMZUSNAMGQES7BDLNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CEFC5FE94D
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 09:16:07 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id eb28-20020a056a004c9c00b0056326adf7a5sf2465093pfb.8
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 00:16:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665731766; cv=pass;
        d=google.com; s=arc-20160816;
        b=v7XfefntTvnzsWxtJQ3MJmXZR9aVlwVYv3CK4oseQJve+6k3mhS5njB2G3M3A80bip
         58O9cRNgq6Eo0OrHqwEjvAwrEmEkM4h5NV0y9aQ9hpiZpvTS6h74liaobQ2agKQYugoK
         J8cYd3V2+jeb58rRRTzjeh1ykw5zEsatl7Qi1rSa5ZWx5HcIAaqGL80ZfherdKX9HnSX
         eT9DQ9KDAwBt6akGbPgVaOJfRzmrF/QczPk8CqB6k+CzcZNz71ICEXj+WMkh3cnGypgL
         3ERgBTJK+0LUFycscEmm7IfVa5d/WyTfm7MLISfCoRKIKzU0Qsb80RaSnr9k4wbSeXe/
         oA8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:organization:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=56qyPYUu9U0JiavLzR6SKJnAzkMTtulGUykTMhye0Ic=;
        b=OOXa5XEwTSYe45sifHaHuoU4aBF9JtssxbrCyTWo7WCDk1B5eF5ktHea/sivcFnc6U
         +YtkvyRRbUA5+npTqnhqCvQPKDLxm6OlcDyQJ3G8G4sLg5EtPpAfhq+pwp84FhkfY0o8
         KmvINaLvNdYD87BTely1OZ6U/q8P82iwwC081HHaJxwehs4wh/ii1FE3HUP+zmV2Zvdq
         N7/6gpzwUARdBzyp+BYZbNRJOnoPNEEk7q+34zWig5I3KsUxV70BE3yATmf5sHIPyOE1
         iN19zhHixjVUeS0yNvlrYIqviVhHI4ylgCrcFb+eBxYT2adC0UjAUrfiBnsDjrdlj8yB
         B/5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hszTEZzk;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:organization
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=56qyPYUu9U0JiavLzR6SKJnAzkMTtulGUykTMhye0Ic=;
        b=Mn5nxzLY4qMyq4AuZTCydqTCCoBjmy+ytwCYXWhzZa7vM2S0HG7ckoe+TpWXFTAqIW
         Cw0YNH9pcq8PhEKQ8XOWXUjQuB9fTCYx/PGUNdp8eTPszpeYcI7c0LQTCHSbY+1KtkWG
         wMGy1zAB4U31FVeNNN73+kvHPAoYhebpjA16/TAShdfWI9nNxSQtkQmOESrqU/lgZnD4
         kf7QYvfB67mh8Vwvi11mrIvJKbmKNu/PUudB3kulOn9l3xAoi0VuPdQTrKksRjWH232C
         MKg1/d2kGEe4eENqsM0vvhksO/RAUvSfBoyNxM8CBMNID5IBozNSI2LktZ6X1hgVTtru
         Jorw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:organization:from:references
         :cc:to:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=56qyPYUu9U0JiavLzR6SKJnAzkMTtulGUykTMhye0Ic=;
        b=kzhdsApolp2URmYFGgqSlz+gBjo36DlsEuzuT9qLkOycMug5yMfWT4nIxVMJs6Vk+a
         FQR275E4oAeBjrfvmXXH6UAx6WWy/qAtYT5fkI9OfVTHisyt75KyOVzj/DeuTi4jXq15
         kSchJoHEn2fV1viGVN+t2lHR0/pHcX6Va9Z0ffw0eo67TTowsas1wq68BWPlYKF24jkN
         /QVsDILtn31D8vuH1L2JrEr6ptYn8VRabyqjO0AlNNh69U8nh0s8QqMnouixAp80yLsz
         tlaQ9OhgQtxrtWj0rXDrMzckRMjISienl7PH8nIe8pAliPDTP62tJKBdQz9xlxBT0JFo
         vGVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3ilGRN4gUf5tkwWtIvEgkWiXk0UH/qhnr5fNyWCu68Ritxa9kI
	tZ0uVKXBEsZf0Fnpy7uf/RY=
X-Google-Smtp-Source: AMsMyM4/LjuIldL9zAt2aOqNKRiMmHnXBWJJ7xb0jYLUN0oZ9kWviReiYt6y81Ua+Ap69vFrTH5rlQ==
X-Received: by 2002:a17:902:eccd:b0:17f:8ec1:39d1 with SMTP id a13-20020a170902eccd00b0017f8ec139d1mr4039770plh.139.1665731765870;
        Fri, 14 Oct 2022 00:16:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a58a:b0:172:8d81:7e5b with SMTP id
 az10-20020a170902a58a00b001728d817e5bls3237085plb.6.-pod-prod-gmail; Fri, 14
 Oct 2022 00:16:05 -0700 (PDT)
X-Received: by 2002:a17:90b:224d:b0:20d:8828:3051 with SMTP id hk13-20020a17090b224d00b0020d88283051mr4124757pjb.89.1665731765008;
        Fri, 14 Oct 2022 00:16:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665731765; cv=none;
        d=google.com; s=arc-20160816;
        b=Q2q2VffHUfHFI8NAkgOOi2gLZtpa+/PSP4BCleyPc2Lj721svNSSPaoxle4mkSwgpF
         iKdYIzr2xVnc36escCYVbwcEwacA0dyVjUUrvh0H8DXVwgUSffhHF4eXigswbe5Yz7qn
         cvbVx+INO9+CdGq1kLsxXscy1qx65Ay3pGsEpTkvjAcBQExw4w7uGtC0c3xM8MMIbqrL
         9T4WlvtggNSMqdcAbU3vcJXYcxTUN1Ew3bGy1OQAcaTMbwgtHVll1LpyfqhCL+v2Yl86
         ctS/+SO+TimuJZ6/5cEd30z47DYR9JFfe8hd7q/1Qr6czygbj5zciNsHgEWbwe5FMfi6
         jR3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject
         :organization:from:references:cc:to:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=KO4vXEPLGC2thf70UdJUXD19wedZIU97Jq4KCtGmIIs=;
        b=vcPf6tA7OEiUDbZva5qkZxFUivG47/JnM3u2ACfeIIyOYMnvdax2kRMm+6MLTfu8w+
         gX2ZDB7r6hTSzBhLgX+iljWdlIAjmEm0gZ378V9gMF/ozY3oL3gkTNFVe5FOoMTjkwre
         ZartZHSbGZBf/cZj4iQKmxGRhID9Z+bHp5xYxsXiPlfn8gEclzP5ajPo4Uk9ZCWvM+ju
         Eo1xJVikO8tUAXkYU4K4Brom/KiqAKEfn4I4VSBcFpi54C+CCaU/E4H6Ctb6BHIgTzoX
         2wq1wVIfXqALCSZEMUZ/0OAgOzFXS+XMD9P0hwD32sSG/9lc8hSM8OY43fYGuXs0tBiF
         77NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hszTEZzk;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id lr18-20020a17090b4b9200b0020d43c5c99csi98119pjb.0.2022.10.14.00.16.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 00:16:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-627-uIQwdZqlPXmhjEErWy4QaQ-1; Fri, 14 Oct 2022 03:16:02 -0400
X-MC-Unique: uIQwdZqlPXmhjEErWy4QaQ-1
Received: by mail-wm1-f72.google.com with SMTP id q14-20020a7bce8e000000b003c6b7debf22so1759273wmj.0
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 00:16:02 -0700 (PDT)
X-Received: by 2002:a05:6000:1565:b0:22f:1407:9bfd with SMTP id 5-20020a056000156500b0022f14079bfdmr2279473wrz.620.1665731761362;
        Fri, 14 Oct 2022 00:16:01 -0700 (PDT)
X-Received: by 2002:a05:6000:1565:b0:22f:1407:9bfd with SMTP id 5-20020a056000156500b0022f14079bfdmr2279458wrz.620.1665731761011;
        Fri, 14 Oct 2022 00:16:01 -0700 (PDT)
Received: from ?IPV6:2003:cb:c704:8f00:9219:ab4c:826e:9646? (p200300cbc7048f009219ab4c826e9646.dip0.t-ipconnect.de. [2003:cb:c704:8f00:9219:ab4c:826e:9646])
        by smtp.gmail.com with ESMTPSA id f7-20020a05600c154700b003a3442f1229sm6872888wmg.29.2022.10.14.00.15.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 00:16:00 -0700 (PDT)
Message-ID: <77d0c7e8-ca07-bd38-5624-03fbc659733b@redhat.com>
Date: Fri, 14 Oct 2022 09:15:59 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
To: Miroslav Benes <mbenes@suse.cz>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 Lin Liu <linl@redhat.com>, Andrew Morton <akpm@linux-foundation.org>,
 Luis Chamberlain <mcgrof@kernel.org>, Uladzislau Rezki <urezki@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 petr.pavlu@suse.com
References: <20221013180518.217405-1-david@redhat.com>
 <alpine.LSU.2.21.2210140806130.17614@pobox.suse.cz>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
Subject: Re: [PATCH v1] kernel/module: allocate module vmap space after making
 sure the module is unique
In-Reply-To: <alpine.LSU.2.21.2210140806130.17614@pobox.suse.cz>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=hszTEZzk;
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

On 14.10.22 08:09, Miroslav Benes wrote:
> Hi,
> 
> On Thu, 13 Oct 2022, David Hildenbrand wrote:
> 
>> We already make sure to allocate percpu data only after we verified that
>> the module we're loading hasn't already been loaded and isn't
>> concurrently getting loaded -- that it's unique.
>>
>> On big systems (> 400 CPUs and many devices) with KASAN enabled, we're now
>> phasing a similar issue with the module vmap space.
>>
>> When KASAN_INLINE is enabled (resulting in large module size), plenty
>> of devices that udev wants to probe and plenty (> 400) of CPUs that can
>> carry out that probing concurrently, we can actually run out of module
>> vmap space and trigger vmap allocation errors:
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
>> [  166.024623]  ? layout_and_allocate+0x560/0x560
>> [  166.029586]  ? kernel_read_file+0x286/0x6b0
>> [  166.034269]  ? __x64_sys_fspick+0x290/0x290
>> [  166.038946]  ? userfaultfd_unmap_prep+0x430/0x430
>> [  166.044203]  ? lock_downgrade+0x130/0x130
>> [  166.048698]  ? __do_sys_finit_module+0x11a/0x1c0
>> [  166.053854]  __do_sys_finit_module+0x11a/0x1c0
>> [  166.058818]  ? __ia32_sys_init_module+0xa0/0xa0
>> [  166.063882]  ? __seccomp_filter+0x92/0x930
>> [  166.068494]  do_syscall_64+0x59/0x90
>> [  166.072492]  ? do_syscall_64+0x69/0x90
>> [  166.076679]  ? do_syscall_64+0x69/0x90
>> [  166.080864]  ? do_syscall_64+0x69/0x90
>> [  166.085047]  ? asm_sysvec_apic_timer_interrupt+0x16/0x20
>> [  166.090984]  ? lockdep_hardirqs_on+0x79/0x100
>> [  166.095855]  entry_SYSCALL_64_after_hwframe+0x63/0xcd[  165.818200] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
>>
>> Interestingly, when reducing the number of CPUs (nosmt), it works as
>> expected.
>>
>> The underlying issue is that we first allocate memory (including module
>> vmap space) in layout_and_allocate(), and then verify whether the module
>> is unique in add_unformed_module(). So we end up allocating module vmap
>> space even though we might not need it -- which is a problem when modules
>> are big and we can have a lot of concurrent probing of the same set of
>> modules as on the big system at hand.
>>
>> Unfortunately, we cannot simply add the module earlier, because
>> move_module() -- that allocates the module vmap space -- essentially
>> brings the module to life from a temporary one. Adding the temporary one
>> and replacing it is also sub-optimal (because replacing it would require
>> to synchronize against RCU) and feels kind of dangerous judging that we
>> end up copying it.
>>
>> So instead, add a second list (pending_load_infos) that tracks the modules
>> (via their load_info) that are unique and are still getting loaded
>> ("pending"), but haven't made it to the actual module list yet. This
>> shouldn't have a notable runtime overhead when concurrently loading
>> modules: the new list is expected to usually either be empty or contain
>> very few entries for a short time.
>>
>> Thanks to Uladzislau for his help to verify that it's not actually a
>> vmap code issue.
> 
> this seems to be related to what
> https://lore.kernel.org/all/20220919123233.8538-1-petr.pavlu@suse.com/
> tries to solve. Just your symptoms are different. Does the patch set fix
> your issue too?

Hi Miroslav,

the underlying approach with a load_info list is similar (which is nice 
to see), so I assume it will similarly fix the issue.

I'm not sure if merging the requests (adding the refcount logic and the 
-EBUSY change is really required/wanted), though. Looks like some of 
these changes that might have been factored out into separate patches.

Not my call to make. I'll give the set a churn on the machine where I 
can reproduce the issue.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/77d0c7e8-ca07-bd38-5624-03fbc659733b%40redhat.com.
