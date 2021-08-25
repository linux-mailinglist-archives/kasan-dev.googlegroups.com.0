Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJUOTKEQMGQEVSB5C4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 211863F7C0A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 20:08:40 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id b16-20020a17090a8c9000b0018de2b756e6sf229354pjo.7
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629914918; cv=pass;
        d=google.com; s=arc-20160816;
        b=yzp4M4qpDUzxbYH+vghCOsqBDURaAKhq3Qe1MRUByEXTTKqjDETyqeffRY5MVfBy1p
         HQfnhhzxIR36jir+dDkEPzhizRm+fvNzEmcMnWU4//ccAgQ99Z5CUXU4MwPoiv+StdA8
         /hLYt7VvOK5vsKU1FdZKBB08vntxJGsmVYwEmCW0H0bjcG+EsgF1wm0j/ljq7VxXivOX
         VkDmcBKiipLQCkU26d9GsPvcaLQbLX9kaIYIUnkxZjUK6NIPw2QA0vNa3t8FJlE+rsRF
         7SyLZxojd2rDnH6m3KHFf6yph8RQJjJzHZlDFlAjus3c6Fvo9tfU8e1MJVZKxjR16u/t
         Vxmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=dx3bw7petT2VmCJpzH44Szn0SgsRxZXliFtGSSy9KuU=;
        b=EhvNvAJJ5Cx2V840ElqJ3hF7gOyEiJAOp5Ob3ovhI06wIdUVTcRGtDfWb1ZGSg2fPj
         C4O41VZHbkwAnsusbi/OyvPSmSvhev8OlHbUxdApMIKLglSshps1t2nmznApTzaeKmBN
         IeXHIr9MCziZ+VRSNDO7Bj6M/jVJ05oUAE2mD+qJNjwqNPO1ur5UWBLkCR4grxxQG+tN
         jnrrXsMamh/akTtTY7bYTgUa3Jq3Tc1XxOrdpb8yCdK3YoNOnifRlEQohyQl7hVHHHss
         YK8mv4teAiiE5K5nKrKv1+24kCYU4QUPf21BANFypaVEtvYP52ltW/a09VepjOFb96A8
         g68w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dx3bw7petT2VmCJpzH44Szn0SgsRxZXliFtGSSy9KuU=;
        b=Nh7MuVANScD9YYMD9dedG2jldHaibgGn/toOcBpM9SOWWLmrQPNo31L5UNPAL6Tv4X
         fMfSRab9njl4mBBJ/JHOw1myKQue8ci3rYQZBnu8nsWx7V/6tbsREf3zijoR6kpArVUV
         tiJ8Djv6BtxCBsX4m1XOfEybIHziTQwH0uNiBS8MBENBrKyfpude+LU89qltAVwLb2x8
         j4y5z6H38th8v/pNFKM0O/S3oQobgWFdaN+oTAcEjMeJq00x8cE0HbyLKGGlANbo9AzT
         47laGPQYvLgwAMRBIulmXLyu21zwvYL5DXV3xJszryGMkjwVoBL6niltOay68H1RD8R0
         S0XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dx3bw7petT2VmCJpzH44Szn0SgsRxZXliFtGSSy9KuU=;
        b=e8SxugyjSKAzDq+j0qvvgNnspLzjz6V53Q6mwwMZZpQaZFaNxqkPTtnSw1lchLkqY5
         j5Qx2jf5gW4uVImS7aL0kbp6+Qorc99+6OnXwnjOa2tAtOCh+KvHmRh//zSYkTRse7sT
         3/4cCPoRW9TOA5m7Hc8Wc1MRnSDaiwURW1VUUjEAbUBsgHbdlrBcJIWFvT8A2c+Ct1qx
         CnHpvem1Iv7bBrVr3/U1IEDt7UYlN3muO3qS75zWdZd0ulbx8msfRdcKleK6Vxss+1HZ
         09npu0AU3jzadtxRMcmXzkSJJncamfVzeFJcClGCdB1LW8LVJMzfDwY9a7Ea2bYKodUy
         0Crg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533e4RIrtRFiYPePOpCkpPU4yJPItoCCSJZ3XlRAFctoyvZaz5/6
	zzyyQXhDaOCP4RKOHmbVA0o=
X-Google-Smtp-Source: ABdhPJxNN9BylbFk5dVRgkeM+CVMG8FKicSaBrf+7nk06OZwUgzQmU5+zirAL22f8AXwV2VONOTCBQ==
X-Received: by 2002:a05:6a00:23cc:b0:3f0:7c:7bb8 with SMTP id g12-20020a056a0023cc00b003f0007c7bb8mr3168108pfc.50.1629914918550;
        Wed, 25 Aug 2021 11:08:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:164c:: with SMTP id m12ls1178102pfc.2.gmail; Wed,
 25 Aug 2021 11:08:38 -0700 (PDT)
X-Received: by 2002:aa7:8a19:0:b0:3ed:c54d:663c with SMTP id m25-20020aa78a19000000b003edc54d663cmr9581705pfa.24.1629914917943;
        Wed, 25 Aug 2021 11:08:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629914917; cv=none;
        d=google.com; s=arc-20160816;
        b=xmuvg6WG7r/hu70+LTkEYSY0gGA92qJENiWGJ6HA+Q0t6aO1xmotAeGhA1vKHJtr2k
         FH0gFdgi7aJHEKmEC6t4egAgFjC+zKw8n1iYS7dTOjSe7SyvkvXNeH87deTOR4GnFv9V
         mM+narjGV7cJ6cwJVI3nrOfgQPq5MDDC7SIJiCoAnEStFyVros5h6JGuosU06gePITh3
         Zz3JxE89gK5bdprBLi9xP0A4DX36ut0wp1pbbT5ZWC6S5u14vkWLUsfO/7w96jMxW2JR
         9MvKpwyy6FqrCXePaIUfCl8OPZFI89cJRtdFnRKmNYmlURRYQRXyCvOUJXG6Oef+othN
         wfyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=WdamL136JKDHSAEIBeoaD7wGC4BaT4f/MfmjpEHts2Q=;
        b=ADr8YYgZDvZziljTW5bmbtF9zm80Cnl9XPYdpjeCvJ3viU9lNkeHmhJa6Gs2tQ3tI6
         Ta7Dsd77tFzHp+N167uWO+P/MN4gz2ISKijwZH2T7pJUMxGHSkBFe1bgsk9iBWDNJT+q
         k0cDDkBGl8rkEiMYOepgOuniHs40h4rDQJzMvjwyBYhRSA6XCHAhXJ2LD0FLIMUB4BmZ
         krMbKh1xtXcDH/GtRBm2UGwXqeIwB0Xk+CniX9XBqGoRp+ZsG95rERCA6qdezGgxl1zO
         CfWGZ2bmsRFO+5PULzTAvmSGnLZ4m0R3hZjoWNJw+rXFWGnqheUoThTSf+4mxXToBHBW
         mWGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r14si92707pgv.3.2021.08.25.11.08.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 11:08:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 14A8460EBD;
	Wed, 25 Aug 2021 18:08:35 +0000 (UTC)
Date: Wed, 25 Aug 2021 19:08:33 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
	dvyukov@google.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, elver@google.com
Subject: Re: [PATCH v3 2/3] arm64: Support page mapping percpu first chunk
 allocator
Message-ID: <20210825180831.GJ3420@arm.com>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
 <20210809093750.131091-3-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210809093750.131091-3-wangkefeng.wang@huawei.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Aug 09, 2021 at 05:37:49PM +0800, Kefeng Wang wrote:
> Percpu embedded first chunk allocator is the firstly option, but it
> could fails on ARM64, eg,
>   "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
>   "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
>   "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"
> 
> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
> even the system could not boot successfully.
> 
> Let's implement page mapping percpu first chunk allocator as a fallback
> to the embedding allocator to increase the robustness of the system.
> 
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825180831.GJ3420%40arm.com.
