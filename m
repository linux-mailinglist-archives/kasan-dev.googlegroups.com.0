Return-Path: <kasan-dev+bncBC5L5P75YUERB37XZ3XAKGQESF3LQRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 86EE5102142
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 10:54:55 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id f8sf17997897wrq.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 01:54:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574157295; cv=pass;
        d=google.com; s=arc-20160816;
        b=AXvKTz+TIsYS1At7AaOk67ph+hLaaMnGjo8uM7JsL5+Wc4IeYD7C7xoCitJRP4mZWF
         WRBszUXEoTxDLTtPLr8HpXKdIYKujWcNPVMwy8bLefvGPP6LlqLGkf49Ith7tGXyq3QA
         0sUv/4aGbk7t2Vq1Aqj3uO3TovuYnLAg2pdnDR8lqcT3Q9Z/P7iBiHfW1doe73B4ygHb
         iyy71iuljoxo/1IE8f5MAuoBiRgFPACJEwtD9dKodzU9itFakIjm+4nuKj3ku/GSUdPR
         VZ5+o5k4bbaiHAic9BGrk14Dl7L69LNbWYmb+MbEGM2TbEEZ5/Nwyio/bwoeryIotFjq
         YBfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=xlaDJNMgc6RFSlaJ667d6oinZfxCkw6peMsenhvs/5Q=;
        b=dVXmqiy2bD5fVEVAlQgRkrSg4qQW+wvtjLIYAOOF1nESnEHwxNva5uhHJm68GTk1Oz
         YrnAgc65VSEXuLH7qT5Xk4aZcmxstnz8yEfcc+0VmWSmRemTjYxljp5dPnC1M5jAa7sQ
         sSSpqwKM7tYxuq5+BPwba1PlTlny6AeRZaTREH55lJBcg/Yu/DLwHrPJWQgbgSHSETTy
         crT3jdD/oPDKnjbiQ/e1T7ZNtUTBAkMNgb/ExY1DTltPmSH0AozmqQVMFrDx8f5gJvxy
         Z9LaUw7o4h7WNy8ozdc+yTeGOuIrV8tyuLESI8UeXEzcMAJtPr41+ddRov+88dgk0FpW
         D1iA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xlaDJNMgc6RFSlaJ667d6oinZfxCkw6peMsenhvs/5Q=;
        b=TRH37FT082VgOBD+xAhCfAIq1o8Bwgum+Va2ULRXxEoerUbc5mSh/FhRABNOVf8uVS
         afV3lSmGB1WIB+SsiVVK6F/+DQj1T+6GvbFIdIwt33QdKtTqNmgMmfHZEsG1YneGlsC7
         xvhpv4BVvs0VPDg6gb8ZM67i9TPnRS6ulw972RqzbFxIiaxwn1v+3nVQni+oOrjquT68
         PWXwSUxIe6/hXky3ZpknF6WlKFZoEXeWHrmI6SbvgHcwqZmz8WuEz5OfzU+K5EbJYda+
         aH0mWy6WxY+lY/iCmLr+M4uXm+PpaZs30rEVtA9INU3ePXJ45e0eBGuGQE8IsgR6gpx7
         HAxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xlaDJNMgc6RFSlaJ667d6oinZfxCkw6peMsenhvs/5Q=;
        b=WVgK7wEsiUp4oNPlLK6bj/AREL2+vNEdFTi1gATEjK9FhfUbh6PGlT++5X8VTY5c+T
         3xG56p/nE40do+9+v0/DcSW1UbMwEbYKixkCVJpmwqLDgH/4H9YQdhhF7/WAUQaesIlb
         Lli2XTBVpUuqdrJwWPiR87nacU4AqL7tTGptKctg8rBbQw+Aw342RUHkkBm5IxnLTVhr
         LNZnKyqDazivHUlJVOCqLw1woFKtmfjONhsZj10byOoN5ScPjZZwVxYtEQlEf0dNk6qb
         S6WNJJS5e/5ZwEQs/eqJvxXa7Lyloc+xejn5jpPnUBjc8LXE4ZU6tSsNKD7+AU+53+Fa
         FRQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXEOKZpfT7Qk/YbT+3Gh0mzDuHmMk2yZAxi37F9hcDlTWorQlkK
	NXCeevfTVxN3oWGxjSdlxb0=
X-Google-Smtp-Source: APXvYqzbGesqY4cWCjO+8NiphL1U2amJqjbsKRZCgkfkuF7AAYV+XNOYPZhYtty4qhV+fwrgbRkWQg==
X-Received: by 2002:a1c:814b:: with SMTP id c72mr4604511wmd.167.1574157295180;
        Tue, 19 Nov 2019 01:54:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7406:: with SMTP id p6ls5436241wmc.2.gmail; Tue, 19 Nov
 2019 01:54:54 -0800 (PST)
X-Received: by 2002:a05:600c:1088:: with SMTP id e8mr4594257wmd.7.1574157294732;
        Tue, 19 Nov 2019 01:54:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574157294; cv=none;
        d=google.com; s=arc-20160816;
        b=G9Ifud5PZYClXGxCCcSzOw9BxJwgaY1LEiDVFzHB5L64XaxIsSSc2ryZhGJAKzRzQQ
         tdfqc5m7MDoec3gUJ8PYoejSjNVMq4sqk75wojwAPbYrG16ON/h7AzgCJq8MpNvcE4zH
         wtu1vMHfcnD+XNh7+1/d3KVvgA8A0CIGFrkRy5AKP1Jg9olGNRsb2FkoanmrCi1lSgj+
         t6dzsfyrHoy2xTDXCbKH3rSMCmrqAI6megSj77jJd58TBASfZAK12RznWxinOHPyl8Ki
         nWImNgGCKC7I3+DKsgCB0YJEmzbYCJKM6TegolHhDiPqjaiqQ5Hpomk3sWdkSa8v1k7Z
         +Yfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=BSY55w7EfCb7gNvbocVrWkstWTMjyOz4IgD3YA6s2WU=;
        b=h/uNBwsiFq5nJJMk0jMbbswm50YTdsZ8xmx+4t4YCYscp8fvetNImzPg6t22+gUo18
         JCxHFOUQEYzZPSKJCuEkpXI4lpN9fP1D7JFwkCccaOF8SiCfCsDk0kQZ51qrBOQAgKPV
         w6yl3IhCXRvU+jDaH7SgaqehseOM/7iD5l/dYDCrdA/P8g1v2fy43BdLHhXpBZWPQYZl
         lEnQTLyuNi7AeWFSJfJ+qw7JjYM2KxyG3qempfqauxXHUXmAVSaPjy1h/bwPB6JwBZ5M
         Iithf4u0DT87ifZWstMX4x4k+KEqnC2KsrCsBjo09VMhT1ijnYJ2S0X2TlGF/exCfVT4
         vmDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id w10si968524wru.4.2019.11.19.01.54.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 01:54:54 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iX0DD-0002dW-Cu; Tue, 19 Nov 2019 12:54:19 +0300
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>, Qian Cai <cai@lca.pw>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
 glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org,
 mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20191031093909.9228-1-dja@axtens.net>
 <20191031093909.9228-2-dja@axtens.net> <1573835765.5937.130.camel@lca.pw>
 <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com>
Date: Tue, 19 Nov 2019 12:54:08 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/18/19 6:29 AM, Daniel Axtens wrote:
> Qian Cai <cai@lca.pw> writes:
> 
>> On Thu, 2019-10-31 at 20:39 +1100, Daniel Axtens wrote:
>>>  	/*
>>>  	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
>>>  	 * flag. It means that vm_struct is not fully initialized.
>>> @@ -3377,6 +3411,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>>>  
>>>  		setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
>>>  				 pcpu_get_vm_areas);
>>> +
>>> +		/* assume success here */
>>> +		kasan_populate_vmalloc(sizes[area], vms[area]);
>>>  	}
>>>  	spin_unlock(&vmap_area_lock);
>>
>> Here it is all wrong. GFP_KERNEL with in_atomic().
> 
> I think this fix will work, I will do a v12 with it included.
 
You can send just the fix. Andrew will fold it into the original patch before sending it to Linus.



> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index a4b950a02d0b..bf030516258c 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3417,11 +3417,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>  
>                 setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
>                                  pcpu_get_vm_areas);
> +       }
> +       spin_unlock(&vmap_area_lock);
>  
> +       /* populate the shadow space outside of the lock */
> +       for (area = 0; area < nr_vms; area++) {
>                 /* assume success here */
>                 kasan_populate_vmalloc(sizes[area], vms[area]);
>         }
> -       spin_unlock(&vmap_area_lock);
>  
>         kfree(vas);
>         return vms;
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/952ec26a-9492-6f71-bab1-c1def887e528%40virtuozzo.com.
