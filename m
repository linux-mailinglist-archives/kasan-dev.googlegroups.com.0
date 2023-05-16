Return-Path: <kasan-dev+bncBC32535MUICBBSPTRWRQMGQEYCU22CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AB7F704DF3
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 14:40:44 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-55286d5f2desf1187530eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 05:40:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684240843; cv=pass;
        d=google.com; s=arc-20160816;
        b=VdDfadgP/A5VE9obiNNTSHfMMd9CVd01aypQgT1uS2C4fWoX9peMmVYjJj7rW7Gnz6
         4t+bZ1PNisMODBKr/CI19o5TMmqRFUbioGapuAM96M/evL7nijJ/JjzTMS8ZltDl2gUU
         A6+r+4oZXMzC/JAAC3ZVeLwxJIlP8ReaMvAIMvyBn53WePkbGkQ7ycJG3bt9hETUCmam
         GpiK5BYxojIAU3hTyddB2/oaW4AWNRI04rmHLl+G1VaMCXDJFZ+zZlD3nsdNKeAhSe7G
         JioPFVisqZ3KYos0q7G8yJOMMAU/GukVylHCZDnkCjiTSjRNFsCQwZLFaKr9wCYV8QXt
         dsUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=/gTf1fQD1ynNNIy/MH7K6RgiYjXWI0YQslqD+FL91tk=;
        b=vQIq+ijt98s60Tqcd5lZGnS7qHd+L6qBBOaxpL6T2jIDvl30OaAuWwXag2ZGaVHCeM
         Ifaq32c1DvxxFQW2LHOKoLKwLRjoem1s1WimQMHIOg03/eZXjA1aFDp3rKny84vOni7S
         r6C1hM3mbfeEOf4+wF5/2RkXvQ8PK8f5R1nhTsjmQWXZCQjxsKhkBkY2TEYg24wSqpHN
         JIU5Lx7F0peA4cHjGSYf2hdczHhU/zS5BZ2Xy9QfdjvwMlG+5y+CZZIKZbQj/jtS/1gt
         duQMwg02PD/9v9y/4LljAcG3pa4RK8po1DPuuN+gTwSFvefPNKGfFK+kqwPNCsSY7ZSR
         +TCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Fxdr50iv;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684240843; x=1686832843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/gTf1fQD1ynNNIy/MH7K6RgiYjXWI0YQslqD+FL91tk=;
        b=RY8h9Vs5ptxmYYBKaGeh1lLaiUMHZJ3+MVgRKVHP8XwEvkidE0QD/h1wyo6+9fBdp5
         05RMfeMJu4ujcpR/bf3Du4LEHebEp6WNrGUqfh0RgijBKudHZ/2G+lMdpNWp24Av845y
         RowhzdDVciHALEGtuHWs6m8+9LemoS1D9T5a8yhBnqcu2Re9hDxPz34kTNUTRtmimpj0
         V7oX665IS5UDrnVFe/2bI+1E3W5tI0FEI6gdh7XjtojEqeb3pNUL4ye4lgIiR75xUVM/
         vQSzy8p6ey0ot8l3HZpjV9+eqdUlNtTDuKdBWgXHOJK8Kb6JdRHjW361gTv3Onr4oxhZ
         xKew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684240843; x=1686832843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/gTf1fQD1ynNNIy/MH7K6RgiYjXWI0YQslqD+FL91tk=;
        b=CYDLE1JqfDoaCO8DVE/IUBLiF6SGB8cVbXJTQ5+19R40J8+oOrOQA6fH5nUbGDvU4L
         GkQuXmsPiV8RMWA5e2CBonXdtQIYcGHJFZtwYenTE4Jq8cDEhR426v2s5ia+3qHJlcyj
         4yTzvtiVsphaZz+jr3F6Ay6S0b+0kL3upLmWrWdnUY8xmrYFaljkPVl1oTO8qJH0EWZW
         fQ3El5AKIgziQqx6j5qCh9OTDQBA2xSW9cZO4B+0TwAN5tgHWncZtS7zsQQhSq9QjcVP
         fvUbLqeZutDj/WkwnzhE6vkxYMEcsl3NwFKA5E+hMcuoZ332hNhWlUaH2+BGe3tpfEj2
         u75w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw20afYGlRj5frbYLFVjfaMFEdF/uEw9xqEsPnY5Q16/SZJJq0d
	5kMkixB696F9IbMO58fzvE0=
X-Google-Smtp-Source: ACHHUZ4BQyZdwIEtruV1rrbatBzEsw3EN2LAvZgHh/JeJVuL5TFoQ6HQp4nMmimJ9HHUAMz4QaeM1w==
X-Received: by 2002:a05:6808:2514:b0:396:a73:72f3 with SMTP id ck20-20020a056808251400b003960a7372f3mr1363915oib.7.1684240841715;
        Tue, 16 May 2023 05:40:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ed9a:b0:199:ff8d:eca9 with SMTP id
 fz26-20020a056870ed9a00b00199ff8deca9ls112690oab.1.-pod-prod-gmail; Tue, 16
 May 2023 05:40:41 -0700 (PDT)
X-Received: by 2002:a05:6870:a684:b0:195:f0bb:959e with SMTP id i4-20020a056870a68400b00195f0bb959emr17250929oam.50.1684240841173;
        Tue, 16 May 2023 05:40:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684240841; cv=none;
        d=google.com; s=arc-20160816;
        b=DG6RnnlVhX4sxKVwtN7URkEBK5//qbIAqwIcRmb3ceeqq/A5xs0oCJbwb66KOFOkbL
         htg5uhtLVf3CqOK6oKlTTkln1MHyIP62O8nKADqckaqHJc5I3gYFMBj0N/pzSDgZyJ55
         9yRrzencv2XSchJ12zSpzIQY1/HNnuLcF0BOZiROda54DLZxqh2JdVtupDLq16N3NXFR
         Y1yFHW7IevY4uVLFnENSMrhrr1Aw+T1aD0XusJ9YOV62cOndHy7jD8sZNAcX3ZaHSd78
         jojfnfsEroyxOBNGVi7KwtJRo0DlDFHirDU7aIjt9Cu8WQ6r4ce96n4HiKU05UhvDchA
         qiWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=upbxxvOzNSBT926IBK9ZbKutV3zDXORRb/Sm2DRZKY8=;
        b=tGI5xJf+IHfE3HjqHtptJJ4hE+JY+hq4y7ZGihWr6rzGyNOJYMVThckxxQQ8em8KAV
         YbEPMcJ78Y/y2jKC9OFj70cG9d/JlfpEtjtG3hyPEd8YVSe3mCFosyE1Jf2Fx0gMXekg
         herLBxAnjklsaXCrq9VezCc3oDCXiUXeaLsFrjYVPg+zZCNMao/OpnXMNPSdbyqIIwzN
         tPBoc0jUC1DGB94ErYhHQQkTxE4hGgdAYA/61+m5222gGFgui+qR6cMp4h8XUd+SPDb8
         Bmylhg6pekXjjwnXMbWX34+Y1qXxx2Ku58Wivh6ofJ07E+O6lLxCZ6mWP0d8nWoBWQfZ
         AsiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Fxdr50iv;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id gx24-20020a056870b91800b00192c6345ea7si3050828oab.2.2023.05.16.05.40.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 May 2023 05:40:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-119-goOSCjPVPKm8IU2qYYdM9g-1; Tue, 16 May 2023 08:40:37 -0400
X-MC-Unique: goOSCjPVPKm8IU2qYYdM9g-1
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-3f33f8ffa37so48994015e9.2
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 05:40:37 -0700 (PDT)
X-Received: by 2002:adf:e7ca:0:b0:306:4063:1aff with SMTP id e10-20020adfe7ca000000b0030640631affmr27980911wrn.30.1684240836283;
        Tue, 16 May 2023 05:40:36 -0700 (PDT)
X-Received: by 2002:adf:e7ca:0:b0:306:4063:1aff with SMTP id e10-20020adfe7ca000000b0030640631affmr27980889wrn.30.1684240835926;
        Tue, 16 May 2023 05:40:35 -0700 (PDT)
Received: from ?IPV6:2003:cb:c74f:2500:1e3a:9ee0:5180:cc13? (p200300cbc74f25001e3a9ee05180cc13.dip0.t-ipconnect.de. [2003:cb:c74f:2500:1e3a:9ee0:5180:cc13])
        by smtp.gmail.com with ESMTPSA id k5-20020a5d5185000000b0030497b3224bsm2513457wrv.64.2023.05.16.05.40.34
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 05:40:35 -0700 (PDT)
Message-ID: <efd5fb89-4f60-bee1-c183-5a9f89209718@redhat.com>
Date: Tue, 16 May 2023 14:40:34 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>,
 stable@vger.kernel.org
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
 <ZGLLSYuedMsViDQG@google.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <ZGLLSYuedMsViDQG@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Fxdr50iv;
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

On 16.05.23 02:16, Peter Collingbourne wrote:
> On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
>> On 13.05.23 01:57, Peter Collingbourne wrote:
>>> Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
>>> the call to swap_free() before the call to set_pte_at(), which meant that
>>> the MTE tags could end up being freed before set_pte_at() had a chance
>>> to restore them. One other possibility was to hook arch_do_swap_page(),
>>> but this had a number of problems:
>>>
>>> - The call to the hook was also after swap_free().
>>>
>>> - The call to the hook was after the call to set_pte_at(), so there was a
>>>     racy window where uninitialized metadata may be exposed to userspace.
>>>     This likely also affects SPARC ADI, which implements this hook to
>>>     restore tags.
>>>
>>> - As a result of commit 1eba86c096e3 ("mm: change page type prior to
>>>     adding page table entry"), we were also passing the new PTE as the
>>>     oldpte argument, preventing the hook from knowing the swap index.
>>>
>>> Fix all of these problems by moving the arch_do_swap_page() call before
>>> the call to free_page(), and ensuring that we do not set orig_pte until
>>> after the call.
>>>
>>> Signed-off-by: Peter Collingbourne <pcc@google.com>
>>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
>>> Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c61020c510678965
>>> Cc: <stable@vger.kernel.org> # 6.1
>>> Fixes: ca827d55ebaa ("mm, swap: Add infrastructure for saving page metadata on swap")
>>> Fixes: 1eba86c096e3 ("mm: change page type prior to adding page table entry")
>>
>> I'm confused. You say c145e0b47c77 changed something (which was after above
>> commits), indicate that it fixes two other commits, and indicate "6.1" as
>> stable which does not apply to any of these commits.
> 
> Sorry, the situation is indeed a bit confusing.
> 
> - In order to make the arch_do_swap_page() hook suitable for fixing the
>    bug introduced by c145e0b47c77, patch 1 addresses a number of issues,
>    including fixing bugs introduced by ca827d55ebaa and 1eba86c096e3,
>    but we haven't fixed the c145e0b47c77 bug yet, so there's no Fixes:
>    tag for it yet.
> 
> - Patch 2, relying on the fixes in patch 1, makes MTE install an
>    arch_do_swap_page() hook (indirectly, by making arch_swap_restore()
>    also hook arch_do_swap_page()), thereby fixing the c145e0b47c77 bug.
> 

Oh. That's indeed confusing. Maybe that should all be squashed to have 
one logical fix for the overall problem. It's especially confusing 
because this patch here fixes the other two issues touches code moved by 
c145e0b47c77.

> - 6.1 is the first stable version in which all 3 commits in my Fixes: tags
>    are present, so that is the version that I've indicated in my stable
>    tag for this series. In theory patch 1 could be applied to older kernel
>    versions, but it wouldn't fix any problems that we are facing with MTE
>    (because it only fixes problems relating to the arch_do_swap_page()
>    hook, which older kernel versions don't hook with MTE), and there are
>    some merge conflicts if we go back further anyway. If the SPARC folks
>    (the previous only user of this hook) want to fix these issues with ADI,
>    they can propose their own backport.

Sometimes, it's a good idea to not specify a stable version and rather 
let the Fixes: tags imply that.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/efd5fb89-4f60-bee1-c183-5a9f89209718%40redhat.com.
