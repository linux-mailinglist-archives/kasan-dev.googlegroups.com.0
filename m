Return-Path: <kasan-dev+bncBC5L5P75YUERBWPD4HWQKGQEY2RDVKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C06B7E8DA4
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 18:07:37 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id s17sf8795116wrp.17
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 10:07:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572368857; cv=pass;
        d=google.com; s=arc-20160816;
        b=i6tYiarhrhFPPIPyvb1RCkXpElytAt86tnHDsDZYdbnQPVbAQwdF3BfhSIphW7JQkz
         M7adkzmB8lLEbfw+1sMWxz4naUERLaIHnx/FV4+HQv8XcOoI2xEkMPjVrC5AuPSUU1Yz
         8Aj0op+0HvUvxTStSBWHpejblydj402y+0gf+JOrSAm/22WvAUvHqRTOtQBjwDMrCZ+W
         6SS8VjO3Ry/M8fwQKe9/fjFx2LVk2Ov9hktwi6yEtH6oQ8rLHXbiT/ks1scE8uAXTGLs
         iNtSjO+RhfOYx/ebZW5Sb8Yipx1VP6K2oe1gTA2lsuPQ2PTktorQu3Lf16DT9VOgN1Fb
         kILw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=RV0k19lHpLvk7VCw1mB2Jo9fDgF0cSNhqn24cxlfnys=;
        b=K096cpTM8xbBU02O+8dhOAB9vB3vdQLuUheMDLGvLjnoJCwUUztt/o8tyvpnUrj52G
         h2bQUN+TjZY9eKPQk2aYHKoWxYgffWGrDfY2IXP2h0n/nA83tFuque8Y12tNzJt09bXU
         KsiD5O+w7kaOGzZ1t3po6yk/uoGT1xShvrkSWWdab/fouT+iCn/nQoDYsh1uWvi9qGxO
         FXT7kwgSjAnv8Bd6bnotLfRczQDhEfQmPpHyT2JAkhcfJmRIkIsA7qK13CV5XOTfEVb4
         mApt3WD4AqEz4qZ41DYn5bLVyIADAEjbMxL3QRN2wAY8I7XyJ1zfQC5WKuC9SR+zyPqr
         W/Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RV0k19lHpLvk7VCw1mB2Jo9fDgF0cSNhqn24cxlfnys=;
        b=HGr03EYV3a6lpUwD4j27oHE5rcG4+1q8dkynaDzbPMSJa+mDkjg0cegwELgxXH4O2M
         PzUuHgRowk1aNSpZRV1/+LWjw2dCbrx5OL0FKTg2acnSvt7QoB3NTgx8coHjp9DYNPdz
         bCyGzfUecMS2wAasO+ZyB6ewqcCAvc540LdM9tqaONLW3qaZw8QACsY7xRordEQ7jMpk
         OtKEx4MmKJXuKdHPxlTFfoW2YwoXCTjoDs0ZdTiJvI+LPPuHMKfsDhqeYSTTgdr2l5Dc
         B9tgsJnG8ZRd7LsEAoP69qFYg1uJNuCv7/RMrKnwXJMK4BlkdD/uXmGQoZtEZcm3HHyh
         suDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RV0k19lHpLvk7VCw1mB2Jo9fDgF0cSNhqn24cxlfnys=;
        b=lKyS+YoR7yQLauRlT1Mk7d201nOJ/IO+cV5PA14U7SdLkzOimYi/DVrzYU7245HXta
         g1dgSGUh8LiAq9uIxSgNuuCVbA8A5+arubjqkeoOfP/vtB67t2Sqwb/BtMtj5hWatMB0
         UZyAg1dJEVI5ATT/pS8It9QytR6h8HqQ+fge7geMiho2iwDKkela7to3Vvl3xJcpwlTo
         CoOK6+8RX63FkAMv/XbEXpDZrje9M1umLPkAx4mlu675vo0DveRASuZY8dm5rp1rlmpH
         5BDf0jzxP0R5KESkfVwJxAQNj7ky38JvIqxaPLpwlvptSnQx/YBja1IhhTgLlgqWCXfD
         27kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXF8CzttjDRgBEE0SmKcPRzbd/qFMYZj5ioYjyfdh7Hf3khirGw
	8RIAlnpENFb3aLadME8x9TM=
X-Google-Smtp-Source: APXvYqwHtPvx8kOZGz171tU+f4a9JPEQxa4kPS5/FWaJhZye3chd+ybICg3kfYs1jL3ULPBnHv95cQ==
X-Received: by 2002:adf:fc41:: with SMTP id e1mr4800898wrs.263.1572368857542;
        Tue, 29 Oct 2019 10:07:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9c90:: with SMTP id d16ls15306832wre.14.gmail; Tue, 29
 Oct 2019 10:07:37 -0700 (PDT)
X-Received: by 2002:a5d:5401:: with SMTP id g1mr21230986wrv.54.1572368856999;
        Tue, 29 Oct 2019 10:07:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572368856; cv=none;
        d=google.com; s=arc-20160816;
        b=tKzAH3mD2two9i9UOJtzR6lfbGOFI51NoVc8/n82aKhUeEV+8z8ex53bHyYo0S+9yD
         6opgwQTKyZ9iU4QLue1wNTyiR1QrCthBLgtytDRqDqh/i+DIaOqLZSpITF/HzCZZIG2a
         4cdXsqFVPyFtQ37KomqK6jK4Kq7YaL1BpQogJfB75vjcPYhje79bfNDECkf4PVhEJ+aF
         lcuWFTc01BXOSq1cKjHFqYZc5eyZZaNkzdJgfZgESJM16TgeeZVXJEKlVD9XT2Y29mEC
         wXLFP7jC9P2RKh/4BpiBCWI41+RGfWIoboIw54xO0u/+96RmJU5+4sWxLAAnbNhzIU5/
         CPLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=YeedTn4zd/DtPUgzOxggrluOryTdLIGQ+xB/BKC1ocI=;
        b=j4iq1MzMPXattC6RR8qw0eDHUlIiRdVjwHWaTPogx6Q/Q6pZiRIH6iw+3i8hPwSQRC
         pNbT1RiPVoOUJ5o1/214giDrQ277fSVAFqwQRTULJK1Xz/iyjlo6svj1c/8JYURsODY+
         HqMeytwudPzDhYtZbpCGMR7x9LlwzXvIDIvq4/PFCzeno8BN7g7KG7U+1U6TqNdot1N/
         wgJBF6khPgoe8jB52WxGVoDRagIY0hVxh+c0d6Lkmk8uUZH80VN3rRjymyxbzJs4fN8Z
         gH7HUL3T+6GPNzP4/lIP6U3I7SBKHoLsTPrR/laa8rMPVCQ03RA98W+sA+Hzv4PI9S+k
         +gEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id m16si107785wml.1.2019.10.29.10.07.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Oct 2019 10:07:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iPUxo-0006eL-Lz; Tue, 29 Oct 2019 20:07:24 +0300
Subject: Re: [PATCH v10 3/5] fork: support VMAP_STACK with KASAN_VMALLOC
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com,
 Andrew Morton <akpm@linux-foundation.org>
References: <20191029042059.28541-1-dja@axtens.net>
 <20191029042059.28541-4-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <6dd97cbd-b3ac-3f53-36d6-489c45ddaf92@virtuozzo.com>
Date: Tue, 29 Oct 2019 20:07:09 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191029042059.28541-4-dja@axtens.net>
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



On 10/29/19 7:20 AM, Daniel Axtens wrote:
> Supporting VMAP_STACK with KASAN_VMALLOC is straightforward:
> 
>  - clear the shadow region of vmapped stacks when swapping them in
>  - tweak Kconfig to allow VMAP_STACK to be turned on with KASAN
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

>
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 954e875e72b1..a6e5249ad74b 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -94,6 +94,7 @@
>  #include <linux/livepatch.h>
>  #include <linux/thread_info.h>
>  #include <linux/stackleak.h>
> +#include <linux/kasan.h>
>  
>  #include <asm/pgtable.h>
>  #include <asm/pgalloc.h>
> @@ -224,6 +225,9 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>  		if (!s)
>  			continue;
>  
> +		/* Clear the KASAN shadow of the stack. */
> +		kasan_unpoison_shadow(s->addr, THREAD_SIZE);
> +


Just sharing the thought. We could possibly add poisoning in free_thread_stack()
to catch possible usage of freed cached stack. But it might be a bad idea because cached
stacks supposed to be reused very quickly. So it might just add overhead without much gain.



>  		/* Clear stale pointers from reused stack. */
>  		memset(s->addr, 0, THREAD_SIZE);
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6dd97cbd-b3ac-3f53-36d6-489c45ddaf92%40virtuozzo.com.
