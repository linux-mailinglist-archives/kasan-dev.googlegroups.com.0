Return-Path: <kasan-dev+bncBC32535MUICBBC7WUCNAMGQEZMZD2GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DACE5FDE1F
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 18:21:33 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id k9-20020ac85fc9000000b00399e6517f9fsf1711477qta.18
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 09:21:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665678092; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jl0LVc5/t0dOyi96oOYnTewFErHG6HBWcEoCMCUiE3V+vDa8ovhGUsuw3H3JCC7aKW
         Ib1NgBQ8YAc3C05SjuVWSoo4HlBaPgHE2voS/9NsN5kYTEQIlb82EW3k12QKQuL3RnJB
         9t+dZNN2MGxL8WvN7sDTLF7xzjsHCtzIDYd84SIfRYPsjTMbxCPx3KIiI9sKTyHQ64wV
         n6qzUhh3owsPkP3o/kwltuCnxmKWoDdLaznUryC9xeMJ4FHV8wSUat+FcZsp7j2AwZCo
         jf3vdRbdzZW2CsQ6oGcOVap5wCQFio7qqNEHfRB0FbBGTzIp+o/vJ/SbSUk51cPoGPSm
         76Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:organization:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=fFST8ItQAkkfjpFZt1p/fVsoumpJCaooFTAIpeSaW8s=;
        b=XyzSW5uhUhpmKLyq6SR8bLla1Nsu9vaUpnVWyg6ik+iaQxaLN9phiZCJ7UbwrftT2M
         3sSFT/32rmakWnZotQK8Hos9sownnI28sa6A6QBgY6gVuYko7TmzuIbmOhRvBR03L69T
         inewd+6ZvDvP77vK6wbCQtDyzqdiBxP+stISURhYx0+GoL9WAKG2hW36G0riDBjxKvlU
         49e9x1Z0SeFOSiB8lBxg4rC5DhVOoZ6ntexC1bdAGynqErXcGKfjd6sPQhzRxmWbEp4A
         IquXxUDppJj3FnFQqN7pNcu1OcRCaUHWHeCQvlAdGOfrEyLAGezmmyCP68X62z7262+G
         nYmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZOhIpnhY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:organization
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fFST8ItQAkkfjpFZt1p/fVsoumpJCaooFTAIpeSaW8s=;
        b=AhlaiDSfYLioYhuLQI5emVXwe4tpmG+Di9g1xUMpmyGvI4pJuHs/G/5V1IUNa3wLFS
         2xRmMJVPu3h5ZNUAblES0ctnO95trzftnuNKCXAzvaIsG36sW0m83W5/YjlZzyG/GbsA
         L9S2/xgYO9wthYR1b1K1IAa3rEE2upWfUVwxTIZ20U+/Wrd7wpamCBTBYaf13Wprwd9o
         /ExhOM2wfyWx3f4iABTiEcG2YRjYLXO/ls9A9t5IkaWq34BJlOktmTKLcgMOquukmrPr
         RPYQo0YDLYdFZsDwHyY1RTMDU4dTYq2xDYukEZacZVqGGPt7XzHx4Lq86RQ3y8UOEK6z
         YH/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:organization:from:references
         :cc:to:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fFST8ItQAkkfjpFZt1p/fVsoumpJCaooFTAIpeSaW8s=;
        b=vDzH1PHNhRg0aTaXcy7+stqwtuLKQk/748/EFvRr/7UjDV2ulnkvuwO7Fjhx7Ow0CK
         KJ0L8amIHBGTtQ3GV3GxrV/F0sBx4gSZSnDdKHkAeo29ISOPBSper6RvGd1k3+FxqhR+
         wB3xOMGHgZbMMVirPgMLQ3+TiUHx7zye4H1jMwzqzQsvxRRdfrEeZTMhuK5oSqiG7qIu
         8yPkauYeB+focQ+DFMKxhC1lWWSa5bLMr1E0lYqAlPOAySGo0hmEaWYVjVNCiStaaNLi
         VJu54TeNEP1TBl8UADXD3Um+QjrmC0Ed8d2kVtKcu8ccG75ZI8I1XqbAg2bBqim6SEyJ
         BLzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1EaktNeZpm28eCmGimmfxUYQ2ZulPUKrfSGOarundUHANKRmjX
	3c21Pm5R/hjICNpPM6D7Vl0=
X-Google-Smtp-Source: AMsMyM5S/vif5JK86BOtbkgViTI1/ltY70M4ptSqMUJ0maM/wyIcf7ZHx60mvnBDnThyoP8JCMfPzw==
X-Received: by 2002:a05:622a:113:b0:35d:4465:627f with SMTP id u19-20020a05622a011300b0035d4465627fmr492984qtw.387.1665678091873;
        Thu, 13 Oct 2022 09:21:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e18d:0:b0:4af:921e:f2d2 with SMTP id p13-20020a0ce18d000000b004af921ef2d2ls1362427qvl.2.-pod-prod-gmail;
 Thu, 13 Oct 2022 09:21:31 -0700 (PDT)
X-Received: by 2002:a05:6214:300a:b0:4b4:806b:ea50 with SMTP id ke10-20020a056214300a00b004b4806bea50mr615522qvb.7.1665678091217;
        Thu, 13 Oct 2022 09:21:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665678091; cv=none;
        d=google.com; s=arc-20160816;
        b=wS7gjRfTpbbYHmfufgYDhFsEy8FEbb6PReXCiuQ1YqGxtchl1Iugx88w5q4uYB2cgZ
         exLXokDJch6wBlK8m6e7Qxmj5GAdcjXV3BR++UehkRc7x8mxFAAi69YsloVdD9ClGJpu
         bfUN6JsO++f1pPZqnEG/h51FRmsSJPZ9p49ocUpahsuyCIK7jpc3Jz6DnCPjz0jrD6wM
         bE7XUCb8zNVdMZ1JgE6FDb7rFv32kEXfPc8SuYUfDh2SYNsdF/7JuiA2n56AclCDure7
         DFEj1qTiYBJj4HBGtLKP/kUt2euYkee0aJXS+A0sdyAwJFFw0SpFTjq9BpSLIvoWphgV
         Y/4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject
         :organization:from:references:cc:to:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=kCqR8mB4QLWOY15w1n1k5dkwpabYfzQfC4S08EZLtmg=;
        b=RhYCEMuKBUJ1A7lh8VRZSoxrodO9WL8YCS6CXhFWc+vr7N00n5BBiDQbVr+AaF9GRn
         euURv7sHuNpEzy7IQ5h+8BEaxqZAsqDFwwNtm+1I7OTF/ioICbEEWkD1tZ4waTH5KAp6
         4UFputkAjm5Bv+BnjCLslbJ1maVZneujlYOVrcytMjiyCb1o2N0ZtsxGfkfjYKDRb50Q
         VcPTMJLgkOiwx0PU8gJds5f2dCK5X8igYoq7Hcok3xDLdNSQ+PxO1Yc6NHv2B38ll/JS
         kfNnuToKRJczJfpliaqToj1oi9BDW7C++gz5vnb+Ed2CD/INSMAl53CCEzy12KPgczrp
         yKJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZOhIpnhY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id a28-20020ac844bc000000b0031ecf06e367si42771qto.1.2022.10.13.09.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Oct 2022 09:21:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-299-EXeIP6csM7yaEzv_3kQ55A-1; Thu, 13 Oct 2022 12:21:20 -0400
X-MC-Unique: EXeIP6csM7yaEzv_3kQ55A-1
Received: by mail-wr1-f72.google.com with SMTP id g4-20020adfbc84000000b0022fc417f87cso771552wrh.12
        for <kasan-dev@googlegroups.com>; Thu, 13 Oct 2022 09:21:20 -0700 (PDT)
X-Received: by 2002:adf:d1ea:0:b0:22e:33f9:bcc1 with SMTP id g10-20020adfd1ea000000b0022e33f9bcc1mr499390wrd.535.1665678078954;
        Thu, 13 Oct 2022 09:21:18 -0700 (PDT)
X-Received: by 2002:adf:d1ea:0:b0:22e:33f9:bcc1 with SMTP id g10-20020adfd1ea000000b0022e33f9bcc1mr499361wrd.535.1665678078516;
        Thu, 13 Oct 2022 09:21:18 -0700 (PDT)
Received: from ?IPV6:2003:cb:c706:9d00:a34c:e448:d59b:831? (p200300cbc7069d00a34ce448d59b0831.dip0.t-ipconnect.de. [2003:cb:c706:9d00:a34c:e448:d59b:831])
        by smtp.gmail.com with ESMTPSA id n2-20020a5d4c42000000b0022a2bacabbasm19500wrt.31.2022.10.13.09.21.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Oct 2022 09:21:18 -0700 (PDT)
Message-ID: <e397d8aa-17a5-299b-2383-cfb01bd7197e@redhat.com>
Date: Thu, 13 Oct 2022 18:21:17 +0200
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
 <Y0QNt5zAvrJwfFk2@pc636> <478c93f5-3f06-e426-9266-2c043c3658da@redhat.com>
 <Y0bs97aVCH7SOqwX@pc638.lan>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
Subject: Re: KASAN-related VMAP allocation errors in debug kernels with many
 logical CPUS
In-Reply-To: <Y0bs97aVCH7SOqwX@pc638.lan>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZOhIpnhY;
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

>>
> OK. It is related to a module vmap space allocation when a module is
> inserted. I wounder why it requires 2.5MB for a module? It seems a lot
> to me.
> 

Indeed. I assume KASAN can go wild when it instruments each and every 
memory access.

>>
>> Really looks like only module vmap space. ~ 1 GiB of vmap module space ...
>>
> If an allocation request for a module is 2.5MB we can load ~400 modules
> having 1GB address space.
> 
> "lsmod | wc -l"? How many modules your system has?
> 

~71, so not even close to 400.

>> What I find interesting is that we have these recurring allocations of similar sizes failing.
>> I wonder if user space is capable of loading the same kernel module concurrently to
>> trigger a massive amount of allocations, and module loading code only figures out
>> later that it has already been loaded and backs off.
>>
> If there is a request about allocating memory it has to be succeeded
> unless there are some errors like no space no memory.

Yes. But as I found out we're really out of space because module loading 
code allocates module VMAP space first, before verifying if the module 
was already loaded or is concurrently getting loaded.

See below.

[...]

> I wrote a small patch to dump a modules address space when a fail occurs:
> 
> <snip v6.0>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 83b54beb12fa..88d323310df5 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -1580,6 +1580,37 @@ preload_this_cpu_lock(spinlock_t *lock, gfp_t gfp_mask, int node)
>   		kmem_cache_free(vmap_area_cachep, va);
>   }
>   
> +static void
> +dump_modules_free_space(unsigned long vstart, unsigned long vend)
> +{
> +	unsigned long va_start, va_end;
> +	unsigned int total = 0;
> +	struct vmap_area *va;
> +
> +	if (vend != MODULES_END)
> +		return;
> +
> +	trace_printk("--- Dump a modules address space: 0x%lx - 0x%lx\n", vstart, vend);
> +
> +	spin_lock(&free_vmap_area_lock);
> +	list_for_each_entry(va, &free_vmap_area_list, list) {
> +		va_start = (va->va_start > vstart) ? va->va_start:vstart;
> +		va_end = (va->va_end < vend) ? va->va_end:vend;
> +
> +		if (va_start >= va_end)
> +			continue;
> +
> +		if (va_start >= vstart && va_end <= vend) {
> +			trace_printk(" va_free: 0x%lx - 0x%lx size=%lu\n",
> +				va_start, va_end, va_end - va_start);
> +			total += (va_end - va_start);
> +		}
> +	}
> +
> +	spin_unlock(&free_vmap_area_lock);
> +	trace_printk("--- Total free: %u ---\n", total);
> +}
> +
>   /*
>    * Allocate a region of KVA of the specified size and alignment, within the
>    * vstart and vend.
> @@ -1663,10 +1694,13 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>   		goto retry;
>   	}
>   
> -	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit())
> +	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit()) {
>   		pr_warn("vmap allocation for size %lu failed: use vmalloc=<size> to increase size\n",
>   			size);
>   
> +		dump_modules_free_space();
> +	}
> +
>   	kmem_cache_free(vmap_area_cachep, va);
>   	return ERR_PTR(-EBUSY);
>   }

Thanks!

I can spot the same module getting loaded over and over again 
concurrently from user space, only failing after all the allocations 
when realizing that the module is in fact already loaded in 
add_unformed_module(), failing with -EEXIST.

That looks quite inefficient. Here is how often user space tries to load 
the same module on that system. Note that I print *after* allocating 
module VMAP space.

# dmesg | grep Loading | cut -d" " -f5 | sort | uniq -c
     896 acpi_cpufreq
       1 acpi_pad
       1 acpi_power_meter
       2 ahci
       1 cdrom
       2 compiled-in
       1 coretemp
      15 crc32c_intel
     307 crc32_pclmul
       1 crc64
       1 crc64_rocksoft
       1 crc64_rocksoft_generic
      12 crct10dif_pclmul
      16 dca
       1 dm_log
       1 dm_mirror
       1 dm_mod
       1 dm_region_hash
       1 drm
       1 drm_kms_helper
       1 drm_shmem_helper
       1 fat
       1 fb_sys_fops
      14 fjes
       1 fuse
     205 ghash_clmulni_intel
       1 i2c_algo_bit
       1 i2c_i801
       1 i2c_smbus
       4 i40e
       4 ib_core
       1 ib_uverbs
       4 ice
     403 intel_cstate
       1 intel_pch_thermal
       1 intel_powerclamp
       1 intel_rapl_common
       1 intel_rapl_msr
     399 intel_uncore
       1 intel_uncore_frequency
       1 intel_uncore_frequency_common
      64 ioatdma
       1 ipmi_devintf
       1 ipmi_msghandler
       1 ipmi_si
       1 ipmi_ssif
       4 irdma
     406 irqbypass
       1 isst_if_common
     165 isst_if_mbox_msr
     300 kvm
     408 kvm_intel
       1 libahci
       2 libata
       1 libcrc32c
     409 libnvdimm
       8 Loading
       1 lpc_ich
       1 megaraid_sas
       1 mei
       1 mei_me
       1 mgag200
       1 nfit
       1 pcspkr
       1 qrtr
     405 rapl
       1 rfkill
       1 sd_mod
       2 sg
     409 skx_edac
       1 sr_mod
       1 syscopyarea
       1 sysfillrect
       1 sysimgblt
       1 t10_pi
       1 uas
       1 usb_storage
       1 vfat
       1 wmi
       1 x86_pkg_temp_thermal
       1 xfs


For each if these loading request, we'll reserve module VMAP space, and 
free it once we realize later that the module was already previously loaded.

So with a lot of CPUs we might end up trying to load the same module 
that often at the same time that we actually run out of module VMAP space.

I have a prototype patch that seems to fix this in module loading code.

Thanks!

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e397d8aa-17a5-299b-2383-cfb01bd7197e%40redhat.com.
