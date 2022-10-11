Return-Path: <kasan-dev+bncBC32535MUICBBD4TS6NAMGQERXTSI3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 29FB15FBB93
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 21:52:50 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-349423f04dbsf142580137b3.13
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 12:52:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665517968; cv=pass;
        d=google.com; s=arc-20160816;
        b=RKS7CHQF01rVK1cQvfiNQyx+p/WoodlcdQTopG2JcDa4qbzIcOFqqoUS854owwYuIl
         33GunGccV7Jr3fdwXzxYhM1/972m64RpIja15nFdDV5WmGFkAkA5PuFaLn9ZBW5pdb0G
         QCIsYn5hej3xCBwYNGNdILHaszINRqWHO1GJfrF7+LJH+SM5R665UL1+a0oyocgJbtap
         +mE7hNEV3+penod2WtPWZn+S2x3xybN4iEinuUWDcinaqq9VOksEdKHL9ICXSEDElRGO
         NDBSLvrjJGuXUnUV42xyt5Dyg3gbj+W3zzFamkkx0IMzQcgq0VkqHUslfqchSzuW4kQo
         HMQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:organization:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=yCx6c/NuTbYvTJCd/gD3s+T1qPjqmci1uFJqymes5AI=;
        b=Zsi2QlCN64lL7Dq274XgGkWq8ygNABdRFpFZeUrahinAeWrGozAHni0R30TVCESl7e
         n0egO0YeI7nBzg1N/Te6Ogt8dua8RkXPg9mNC3H7MCkHm4hDSRYuXYJcoT92B3A3L2xj
         R2vb2DkJasiRM8Td/xrwdN956rBb+Y6ynMWDDpGzuFkMk6aiMEIXbrDAxPWDQniTu5Jq
         huFjVu7mRALWePKDzdZ9oJ6lTL2QW1XZOcpE/sHrsgEhIoHNedE8iv/6JymItJdtOjX2
         MilNVY/M8TKu3jBt10CO7+6DJttfwRkfa5K54RN2wBO0W0BY2cLnL31PmMYXa/nODT/+
         sG+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Eue6ZsJx;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:organization
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yCx6c/NuTbYvTJCd/gD3s+T1qPjqmci1uFJqymes5AI=;
        b=AYk3XGuECjt2zuIKsae8Gw9Rp2AHijx8Ww8RQuNKHSiW38AGY0MAVCgBUFG0eQRM4k
         lgmz7BdK+2yfDYA1O+DpOWp2UaqbnUZNDF+JWtJWpyPtPTNSSE3te51U/ljhZRl9/xR2
         wlmNI/Q+3TdJzJYCqJPZ+8sxVVJKm3frM601t5EKV+gArK5aj26BcpLMOMfyZwQr+qAs
         PGlWGgokTyd9viQvrM0G6K/TRTiENJrOpVMJDFEXZBC38nJBKF1JheVNSN/vp0J4ZQow
         bKZlPNnHkfzfzlhmrXKnGs1kKv0P+L5WP1pnI8xkBVVXMXRaT6VXJFxslRtnRXG3OsrP
         ct3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:organization:from:references
         :cc:to:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yCx6c/NuTbYvTJCd/gD3s+T1qPjqmci1uFJqymes5AI=;
        b=o6VfM+eVfajGeemJ+0WbL0mSqGDnkQ/dKix84xCyQThf8vTuZAx3+E/talkMnhx8LS
         f2N8U8kcZDclr3ODfK9tHV8q1HmFPTngyL1JF1M6VRrtC5GIKxsx4a+pYV7GrYuAuwrl
         lNFt4Adysmx6zndMXYQDy7PWqni9Yoj1UXiDQaCit7mXMdkMRThbYHCYlcNyalFnRRjD
         tM2c0r1TcI+VbLuuVKo8Hr0LWGKG+ptiEsvNO1J1GK9IyOsSd1pAeC1n6ELGqBXPmdi6
         3FZem6zfEUxLWX+cM1nzBNcAUnzVhkHgHJRdUEPrCa4GzaaJYm3IbR8YZjp3FKh6s/9M
         +xeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3k68XrxIQyE0FCPUKTEKr7F9bT0uRQ6vvIQu0WZFmjx+CigBny
	lAOeGJYgNumwR/pQ6XKcBS8=
X-Google-Smtp-Source: AMsMyM5cgMOu0MERokSTxbJdAy5ZCERiUm9l5tlWTCeMZ5uZ/gf3/dzi7dO3iqNeKsFsQZB9JvV8gQ==
X-Received: by 2002:a0d:c986:0:b0:325:1b81:9f77 with SMTP id l128-20020a0dc986000000b003251b819f77mr22902464ywd.182.1665517968004;
        Tue, 11 Oct 2022 12:52:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b227:0:b0:6be:8daa:181d with SMTP id i39-20020a25b227000000b006be8daa181dls7805592ybj.11.-pod-prod-gmail;
 Tue, 11 Oct 2022 12:52:47 -0700 (PDT)
X-Received: by 2002:a25:2415:0:b0:6be:5349:91c2 with SMTP id k21-20020a252415000000b006be534991c2mr25942408ybk.318.1665517967382;
        Tue, 11 Oct 2022 12:52:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665517967; cv=none;
        d=google.com; s=arc-20160816;
        b=du93LMDr6Gggq5gMID/+W2SE7iBZSKVWqQ+fDPYbfIvnNWbeIuK6axAILr+AGeTpkn
         xFBpFg1CnaMXKOsgaVk67oCtwJuKU+9RXd59OPU2wzJ5PrKF+Cp9aDaCqOZ1/wdMncwi
         QaiwfYWlwm8DnlJ9eGtuydzUKSy4TVVFWvusboijowImFyc6QVWnFegIxWPkj5jMlBfr
         dP8H+f86+vy6q43tbudiN5yYjRY8Ak4D8Ux2Rtaq6OXTZm0CiuY/C0zZe5e8qCNo8GCb
         h9CMlznhdF/GEMvdKjlPLIACV542+4AqCLkq2EGG5EMH8rqt0+7OEOzSJQYB8ElhVpa6
         fl+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject
         :organization:from:references:cc:to:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=hfGmqn9tAmQbOGvVwdHJC7Su1j3vDwXMepRWl/TaZqw=;
        b=eCccSHwkdiFge5+azuyZPtl5YlsWZDMDjSrzqti/oqCc0p4uwuxWHIL/7wE7CM2Ew0
         fgE0EiNJHGfI8mLu14bvUnV/6xjtmidj40kvOZF73UCyHc1zdwIobw44poKw0rv4k5V2
         +wi22hjxFezN7Jw/NVA8ZFXCf/QXEC7ROU/Zf7fTVqVtXelZwP7wUZlLarfsvvu4G+PE
         SbCxd54W2yijsbWnKizP8kUq3ys/T3v4+urYrAGxi3Z1NdKYIkrwou8Bj2etwZWksySk
         /5B/q+SVl35B1RqtGwQSn31SWccvUEdKhfXa2LTKXVxDYUZ1X+tIJgXkaZ4ybSlG4qaZ
         fvrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Eue6ZsJx;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id s68-20020a818247000000b00350b92acf33si1089724ywf.4.2022.10.11.12.52.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Oct 2022 12:52:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-76-WTbtb8FXOg2cGtC03Z2yvw-1; Tue, 11 Oct 2022 15:52:46 -0400
X-MC-Unique: WTbtb8FXOg2cGtC03Z2yvw-1
Received: by mail-wm1-f69.google.com with SMTP id c130-20020a1c3588000000b003b56be513e1so8943943wma.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Oct 2022 12:52:44 -0700 (PDT)
X-Received: by 2002:a05:600c:1c82:b0:3c6:c225:eb99 with SMTP id k2-20020a05600c1c8200b003c6c225eb99mr457462wms.23.1665517962540;
        Tue, 11 Oct 2022 12:52:42 -0700 (PDT)
X-Received: by 2002:a05:600c:1c82:b0:3c6:c225:eb99 with SMTP id k2-20020a05600c1c8200b003c6c225eb99mr457447wms.23.1665517962217;
        Tue, 11 Oct 2022 12:52:42 -0700 (PDT)
Received: from ?IPV6:2003:cb:c709:6900:f110:6527:aa46:a922? (p200300cbc7096900f1106527aa46a922.dip0.t-ipconnect.de. [2003:cb:c709:6900:f110:6527:aa46:a922])
        by smtp.gmail.com with ESMTPSA id c8-20020a05600c0a4800b003b4fdbb6319sm21838765wmq.21.2022.10.11.12.52.41
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Oct 2022 12:52:41 -0700 (PDT)
Message-ID: <478c93f5-3f06-e426-9266-2c043c3658da@redhat.com>
Date: Tue, 11 Oct 2022 21:52:40 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev@googlegroups.com
References: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
 <Yz711WzMS+lG7Zlw@pc636> <9ce8a3a3-8305-31a4-a097-3719861c234e@redhat.com>
 <Y0BHFwbMmcIBaKNZ@pc636> <6d75325f-a630-5ae3-5162-65f5bb51caf7@redhat.com>
 <Y0QNt5zAvrJwfFk2@pc636>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
Subject: Re: KASAN-related VMAP allocation errors in debug kernels with many
 logical CPUS
In-Reply-To: <Y0QNt5zAvrJwfFk2@pc636>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Eue6ZsJx;
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

On 10.10.22 14:19, Uladzislau Rezki wrote:
> On Mon, Oct 10, 2022 at 08:56:55AM +0200, David Hildenbrand wrote:
>>>>> Maybe try to increase the module-section size to see if it solves the
>>>>> problem.
>>>>
>>>> What would be the easiest way to do that?
>>>>
>>> Sorry for late answer. I was trying to reproduce it on my box. What i
>>> did was trying to load all modules in my system with KASAN_INLINE option:
>>>
>>
>> Thanks!
>>
>>> <snip>
>>> #!/bin/bash
>>>
>>> # Exclude test_vmalloc.ko
>>> MODULES_LIST=(`find /lib/modules/$(uname -r) -type f \
>>> 	\( -iname "*.ko" -not -iname "test_vmalloc*" \) | awk -F"/" '{print $NF}' | sed 's/.ko//'`)
>>>
>>> function moduleExist(){
>>> 	MODULE="$1"
>>> 	if lsmod | grep "$MODULE" &> /dev/null ; then
>>> 		return 0
>>> 	else
>>> 		return 1
>>> 	fi
>>> }
>>>
>>> i=0
>>>
>>> for module_name in ${MODULES_LIST[@]}; do
>>> 	sudo modprobe $module_name
>>>
>>> 	if moduleExist ${module_name}; then
>>> 		((i=i+1))
>>> 		echo "Successfully loaded $module_name counter $i"
>>> 	fi
>>> done
>>> <snip>
>>>
>>> as you wrote it looks like it is not easy to reproduce. So i do not see
>>> any vmap related errors.
>>
>> Yeah, it's quite mystery and only seems to trigger on these systems with a
>> lot of CPUs.
>>
>>>
>>> Returning back to the question. I think you could increase the MODULES_END
>>> address and shift the FIXADDR_START little forward. See the dump_pagetables.c
>>> But it might be they are pretty compact and located in the end. So i am not
>>> sure if there is a room there.
>>
>> That's what I was afraid of :)
>>
>>>
>>> Second. It would be good to understand if vmap only fails on allocating for a
>>> module:
>>>
>>> <snip>
>>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>>> index dd6cdb201195..53026fdda224 100644
>>> --- a/mm/vmalloc.c
>>> +++ b/mm/vmalloc.c
>>> @@ -1614,6 +1614,8 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>>>           va->va_end = addr + size;
>>>           va->vm = NULL;
>>> +       trace_printk("-> alloc %lu size, align: %lu, vstart: %lu, vend: %lu\n", size, align, vstart, vend);
>>> +
>>>           spin_lock(&vmap_area_lock);
>>> <snip>
>>
>> I'll try grabbing a suitable system again and add some more debugging
>> output. Might take a while, unfortunately.
>>
> Yes that makes sense. Especially to understand if it fails on the MODULES_VADDR
> - MODULES_END range or somewhere else. According to your trace output it looks
> like that but it would be good to confirm it by adding some traces.
> 
> BTW, vmap code is lack of good trace events. Probably it is worth to add
> some basic ones.

Was lucky to grab that system again. Compiled a custom 6.0 kernel, whereby I printk all vmap allocation errors, including the range similarly to what you suggested above (but printk only on the failure path).

So these are the failing allocations:

# dmesg | grep " -> alloc"
[  168.862511] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.863020] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.863841] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.864562] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.864646] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.865688] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.865718] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.866098] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.866551] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.866752] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.867147] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.867210] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.867312] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.867650] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.867767] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.867815] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.867815] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.868059] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.868463] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.868822] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.868919] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.869843] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.869854] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.870174] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.870611] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.870806] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.870982] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  168.879000] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.449101] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.449834] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.450667] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.451539] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.452326] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.453239] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.454052] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.454697] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.454811] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.455575] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.455754] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.461450] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.805223] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.805507] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.929577] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.930389] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.931244] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.932035] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.932796] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.933592] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.934470] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.935344] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  169.970641] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.191600] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.191875] -> alloc 40960 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.241901] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.242708] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.243465] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.244211] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.245060] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.245868] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.246433] -> alloc 40960 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.246657] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.247451] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.248226] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.248902] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.249704] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.250497] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.251244] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.252076] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.587168] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  170.598995] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  171.865721] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
[  172.138557] -> alloc 917504 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400


Really looks like only module vmap space. ~ 1 GiB of vmap module space ...

I did try:

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index dd6cdb201195..199154a2228a 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -72,6 +72,8 @@ early_param("nohugevmalloc", set_nohugevmalloc);
  static const bool vmap_allow_huge = false;
  #endif /* CONFIG_HAVE_ARCH_HUGE_VMALLOC */
  
+static atomic_long_t vmap_lazy_nr = ATOMIC_LONG_INIT(0);
+
  bool is_vmalloc_addr(const void *x)
  {
         unsigned long addr = (unsigned long)kasan_reset_tag(x);
@@ -1574,7 +1576,6 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
         struct vmap_area *va;
         unsigned long freed;
         unsigned long addr;
-       int purged = 0;
         int ret;
  
         BUG_ON(!size);
@@ -1631,23 +1632,22 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
         return va;
  
  overflow:
-       if (!purged) {
+       if (atomic_long_read(&vmap_lazy_nr)) {
                 purge_vmap_area_lazy();
-               purged = 1;
                 goto retry;
         }
  
         freed = 0;
         blocking_notifier_call_chain(&vmap_notify_list, 0, &freed);
  
-       if (freed > 0) {
-               purged = 0;
+       if (freed > 0)
                 goto retry;
-       }
  
-       if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit())
+       if (!(gfp_mask & __GFP_NOWARN)) {
                 pr_warn("vmap allocation for size %lu failed: use vmalloc=<size> to increase size\n",
                         size);
+               printk("-> alloc %lu size, align: %lu, vstart: %lu, vend: %lu\n", size, align, vstart, vend);
+       }
  
         kmem_cache_free(vmap_area_cachep, va);
         return ERR_PTR(-EBUSY);
@@ -1690,8 +1690,6 @@ static unsigned long lazy_max_pages(void)
         return log * (32UL * 1024 * 1024 / PAGE_SIZE);
  }
  
-static atomic_long_t vmap_lazy_nr = ATOMIC_LONG_INIT(0);
-


But that didn't help at all. That system is crazy:

# lspci | wc -l
1117


What I find interesting is that we have these recurring allocations of similar sizes failing.
I wonder if user space is capable of loading the same kernel module concurrently to
trigger a massive amount of allocations, and module loading code only figures out
later that it has already been loaded and backs off.

My best guess would be that module loading is serialized completely, but for some reason,
something seems to go wrong with a lot of concurrency ...

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/478c93f5-3f06-e426-9266-2c043c3658da%40redhat.com.
