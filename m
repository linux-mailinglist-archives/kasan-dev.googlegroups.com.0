Return-Path: <kasan-dev+bncBC32535MUICBBPEER6NAMGQEVCKC66A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id DB2695F98B9
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 08:57:01 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id o4-20020a0568080bc400b003547fbbc31csf1097835oik.12
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Oct 2022 23:57:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665385020; cv=pass;
        d=google.com; s=arc-20160816;
        b=SH33NcxgKTX+F32grarrciZ1yy1P74Q1eRK3MHq8Khw3sZ6onsfuaEdgd7CROI5SZb
         8tOYE0maBPD/veRLs26ImAr5FbFpHJ+tKEaOctpF7dhMyvy+H8hzhsLSz7t4Rl1NJW2d
         jG7sDYStkyZ3DbBebUBZqkC4IZ45ZBBvZeUCkEJX504Dw+wVhknzpSla2QVcVdglM3ue
         m09GqD/Ve78rHcAey0PV7IJt1k0y9mIuub58SRDcrx8mESR5CZo7vsRLr4A20ELB70q+
         5bVYPxnkeRrGvnhAnYOJQ6fgMgFp6ETwUwrqKNKYjqpr3Ev1YDn1/8Gt6yQCLaJhvp+m
         m/tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=04KYrpLq8szM2r/O/TIeBa5U5Gn/ZGxtdPLYk8rtpFM=;
        b=qBBtJrBwmvn1ahhZKMYk3fxmBS9uWZqlUn0/6yZhCKwmkUmh3F0AutdD6sh0H6LZyN
         0p1l24vPnFppvmNCS+aeGEJxnXUrH863qQnFvUJniKY2XceQcPZ06G9soAI52A14pAOE
         tI58d37QoZoMULK1468V1z8NCNxLR2oUtPQ3M2Ld5Uw/eO7NUc+VeKj94eCGrGSYNAyc
         ca4IsIzms0xmgs3fI67gtmlR7U4LFJXWXIce/s/0yI+f6z7HeiotM4BySk5WB9t9GU4J
         H59utorNYjrLk9PBtlJQlXj+wGEAQhWO6VZ0EoCK021A66JNlBtwjtx90ONKXWdLd4Zd
         PD/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WAqlqsoj;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=04KYrpLq8szM2r/O/TIeBa5U5Gn/ZGxtdPLYk8rtpFM=;
        b=V/c2zNdCfrvjTEqjgEeWQlvSjOOBNGrlqMNsiYkOK48tmoUXuswG/col/u6g2Wjy78
         fFy/yI6/RmrS4Wqimgf1nJ6cwQW31Ex+l9yuvNVSgJMiDnSCPxel8IsnoIalH+PyeGz/
         RBzfIFt9UsgUP8ykfPF7a4QikBwGjxh0qEDEFqB7GE1PSB4KvjT2FHPUn5e0/VICiEX7
         Wszn6A/NtRxPB1jxidDwvn4iwRuoX92v83mK4CRJLawKI49S1kWfpVkrAFjG7mW/7f9J
         +5y1IOxAJF6YAyZ7QnOhvU31a2PptKZ6YEK79gXzcNGgoB+/DvSu57Sf83+GsOQ9KEEO
         K8Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=04KYrpLq8szM2r/O/TIeBa5U5Gn/ZGxtdPLYk8rtpFM=;
        b=UdDzrONjVPKQb7/sguU4eAGB8eoRiZ00tBuCAqcj7dh/77gLwDq0sAPFcD1tusRirm
         mup6t4zq8EDQpc7HV3PKOe7mpopF1ExzPULLXcc8a9oxCxhpHq4xlBWWEeizSJ1OgdRH
         rAFXHHToOMnsDGCTGDSgg0pAWWKDAXFJpINH3KuMAzFsPUxf+tAnEbfHXATbJVTN9rqt
         hEgkd8OjoF/4zZryPtpqAeBND+OKHa0LcsYxNfB3I0pwcEFD/0Z/99/H2G5Yf4Ku6Zes
         jL9ObSD4Qv2kvGMbRmyhsedayULdYPJEdR5SkwFTiek2qafle6CxPZJEeG1xhyfeHBjC
         Cggw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1Cj8zz9vGpjzi0Z9BwIqs5lUePgXVLgNgSX80VQSUvcsfsi0QK
	PVgv0ZIVbRcv43dFh6jih1E=
X-Google-Smtp-Source: AMsMyM7ik71RTCB5j3KZJ9vipI2YXBuz6G0+/MU5LSXtGtBuT0/Uv2WfBmPMPOgj9EjuA6tdmxrblw==
X-Received: by 2002:a05:6870:f106:b0:136:3e4d:820a with SMTP id k6-20020a056870f10600b001363e4d820amr6149589oac.292.1665385020499;
        Sun, 09 Oct 2022 23:57:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1517:b0:657:57df:1613 with SMTP id
 k23-20020a056830151700b0065757df1613ls1523960otp.11.-pod-prod-gmail; Sun, 09
 Oct 2022 23:57:00 -0700 (PDT)
X-Received: by 2002:a9d:621:0:b0:639:7585:3c07 with SMTP id 30-20020a9d0621000000b0063975853c07mr7388193otn.349.1665385019918;
        Sun, 09 Oct 2022 23:56:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665385019; cv=none;
        d=google.com; s=arc-20160816;
        b=oiAJCT2Pkh3veo9fsoJKgWeTZkEOc3e2pfO3uN+qmV0puRtVWwX7koHNO5H3dXbtDd
         xb8/05xT0bsWVUm6oLVKR5cOhx/Zz6Oitn1nsEs/qYVrN9wUPvMAHZxTThjdqS1TZ4VU
         8tkwfRWX6dx1ANbltngQimw4/8yBhYtohyF0RTDGsQLNrLs6le5PQUbiJnCJy/sbUX1B
         qOOtsN8I1J7xJKyHbXdD4r6ONuzOHiPpA06icHZwMzUQoIbjbicoblJKIGq7QjyFesCf
         ZJ7bjrE3PW24nrDpxiU1i7ZjW5zDa1h9umx1fNdn7YZx6j36713JVKvCpA7RKxHeESLw
         Q1Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=CTvlZ2UrEc/zYG0ArHPKFycK6DF3ayFdpzEumNdnUnQ=;
        b=sBU8g1a1EFi431pnLtoMtcoHEffuZ5igIuLvbVyFaNT3Za9WwMMdC/rJEjH5rkNulo
         bd/ZwQ0Y5dNd5HqnHRwRHKO4DdswKrVNg3pBbYIMtiI1w9FUWTgNm2hfvEKiIYi0Yjv3
         yEVO5seGed+uIaJq0gnuCh6w8J2NpGY7NP5D9KUVQ6FAxwby2BXjHGO7HdlwSuhNO1aW
         gOtobZT8IFTxTWLV7OWz7ZLCQ2E97YZ1Z+tj05OxaVE0cZkBAMwnaYHj9ySo4nGz1iXH
         YAv5dW9ACaB0I42uY8CnphLvrk+DaQ+eS6bsMEfrjsHYJksIYMX4q56EOL3ETM1j1Noq
         uKyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WAqlqsoj;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 67-20020aca0546000000b00353e4e7f335si302358oif.4.2022.10.09.23.56.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Oct 2022 23:56:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-408-ShEiBjjLPy6nZEjvQng3xA-1; Mon, 10 Oct 2022 02:56:58 -0400
X-MC-Unique: ShEiBjjLPy6nZEjvQng3xA-1
Received: by mail-wm1-f69.google.com with SMTP id o18-20020a05600c339200b003bf24961658so6574246wmp.6
        for <kasan-dev@googlegroups.com>; Sun, 09 Oct 2022 23:56:57 -0700 (PDT)
X-Received: by 2002:a05:600c:a4c:b0:3b4:fc1b:81 with SMTP id c12-20020a05600c0a4c00b003b4fc1b0081mr11244048wmq.125.1665385016786;
        Sun, 09 Oct 2022 23:56:56 -0700 (PDT)
X-Received: by 2002:a05:600c:a4c:b0:3b4:fc1b:81 with SMTP id c12-20020a05600c0a4c00b003b4fc1b0081mr11244039wmq.125.1665385016554;
        Sun, 09 Oct 2022 23:56:56 -0700 (PDT)
Received: from ?IPV6:2003:cb:c704:e600:3a4a:f000:b085:4839? (p200300cbc704e6003a4af000b0854839.dip0.t-ipconnect.de. [2003:cb:c704:e600:3a4a:f000:b085:4839])
        by smtp.gmail.com with ESMTPSA id q14-20020a05600000ce00b0022584c82c80sm8021349wrx.19.2022.10.09.23.56.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Oct 2022 23:56:56 -0700 (PDT)
Message-ID: <6d75325f-a630-5ae3-5162-65f5bb51caf7@redhat.com>
Date: Mon, 10 Oct 2022 08:56:55 +0200
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
 <Yz711WzMS+lG7Zlw@pc636> <9ce8a3a3-8305-31a4-a097-3719861c234e@redhat.com>
 <Y0BHFwbMmcIBaKNZ@pc636>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <Y0BHFwbMmcIBaKNZ@pc636>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WAqlqsoj;
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

>>> Maybe try to increase the module-section size to see if it solves the
>>> problem.
>>
>> What would be the easiest way to do that?
>>
> Sorry for late answer. I was trying to reproduce it on my box. What i
> did was trying to load all modules in my system with KASAN_INLINE option:
> 

Thanks!

> <snip>
> #!/bin/bash
> 
> # Exclude test_vmalloc.ko
> MODULES_LIST=(`find /lib/modules/$(uname -r) -type f \
> 	\( -iname "*.ko" -not -iname "test_vmalloc*" \) | awk -F"/" '{print $NF}' | sed 's/.ko//'`)
> 
> function moduleExist(){
> 	MODULE="$1"
> 	if lsmod | grep "$MODULE" &> /dev/null ; then
> 		return 0
> 	else
> 		return 1
> 	fi
> }
> 
> i=0
> 
> for module_name in ${MODULES_LIST[@]}; do
> 	sudo modprobe $module_name
> 
> 	if moduleExist ${module_name}; then
> 		((i=i+1))
> 		echo "Successfully loaded $module_name counter $i"
> 	fi
> done
> <snip>
> 
> as you wrote it looks like it is not easy to reproduce. So i do not see
> any vmap related errors.

Yeah, it's quite mystery and only seems to trigger on these systems with 
a lot of CPUs.

> 
> Returning back to the question. I think you could increase the MODULES_END
> address and shift the FIXADDR_START little forward. See the dump_pagetables.c
> But it might be they are pretty compact and located in the end. So i am not
> sure if there is a room there.

That's what I was afraid of :)

> 
> Second. It would be good to understand if vmap only fails on allocating for a
> module:
> 
> <snip>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index dd6cdb201195..53026fdda224 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -1614,6 +1614,8 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>          va->va_end = addr + size;
>          va->vm = NULL;
>   
> +       trace_printk("-> alloc %lu size, align: %lu, vstart: %lu, vend: %lu\n", size, align, vstart, vend);
> +
>          spin_lock(&vmap_area_lock);
> <snip>

I'll try grabbing a suitable system again and add some more debugging 
output. Might take a while, unfortunately.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6d75325f-a630-5ae3-5162-65f5bb51caf7%40redhat.com.
