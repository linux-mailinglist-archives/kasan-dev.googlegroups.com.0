Return-Path: <kasan-dev+bncBC32535MUICBBKFDSKRQMGQEG6YAHHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id F168C7062FB
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 10:34:49 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-5309b380b41sf301992a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 01:34:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684312488; cv=pass;
        d=google.com; s=arc-20160816;
        b=SK/Tvu/+7XZD9QZw1PWnvkLb5JzJvhzIl7qbbGBXDrAHI4MtwdEM0wvTkAx8mS7Oqv
         jrC+a7CUfIPjDeAUEOsds/qmi+SNhkG+9N4or8/Evw2/36g9glboFCoMzau8F6OOg764
         dnG5UHW8bB6k9+QM6XLZ2q/U+5s76cxpxpwhlgek9CNW1LnTlvlO6BIOp1WTP1uxe7oD
         nX6uwJIBcN7wWX8iMxoP0bpxV7RMvNvxl0Pv/5luIL8yuxlz/XDAMmkAmyR2vxkTGIma
         uPnkGwiGjv4xYz28HVnnbNRRir/Q09OTUaVqn2sYDUVJBdaNZ7l/nJ6axj/w+0dLLCRw
         kgDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=iKIjK9zKrSgEgPQfaAFjGScCgAoX/of+252wI2TWs78=;
        b=ZeADV0srMz+k9zs8GsgBpr2U/Pewtd30XAods7PBuXPEfsAIKSa4P7ytvxgWbbxJnW
         GNamDkk7QT5+POmK4fR0XL7n0TK9CXfro4YJUITdy4DBr6OLrmiwEMfcvNrmCX5ODpog
         GlXCdGd/pr4XHHO8hRDN8w6Oq3kUi9UbQtezSHdRklwGVmDgIUx5rVBS+WOV78KOoDYY
         5slXtOnLJq6SM5Dw6PZbic528g+BmPyZVjPlbRQht2mu9sx3OO7m3nVxUYJw9MwrCKFw
         GDDUMO65ED7nL7QyxjP9hcN9u2S8XbfCc0edGUjTXXBMgucCF1qeRvD8FzZVvB5TvW7s
         EjUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=K1pZIcFP;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684312488; x=1686904488;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iKIjK9zKrSgEgPQfaAFjGScCgAoX/of+252wI2TWs78=;
        b=qyaD4DKfSFbZn5Ht26jslksq3En0UyMkfNs/BIkoULq8WJFTfmoma2PDzDbe+VCVNP
         KJBz5o4uNetgkzcssApB7CU6mRTExJVDEznzChAWrJJ85npfGQ1r1sTsRI/JCdmPMcx+
         V/KJqPdvqWl+z+at+audE7EYqD7AjZEcJlMMyVrrC9YzR3pIqb0jtjBdT5xu29jPMjkb
         qweVmlOBPsaESrNTF5r670GGjZx+YQ727BfeIKRMgbd4+300E0yCK3u87nc/r309XdH3
         fChSazd/b8efkCqK8zl2vZXtAL7ksJY3DDq+9qAwKLw6bATgXquujev1nyWxMvg+dwSO
         nCRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684312488; x=1686904488;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iKIjK9zKrSgEgPQfaAFjGScCgAoX/of+252wI2TWs78=;
        b=F6AeBXFqGYALXdKCLr0llLs5aCfL3O1adHL1tSXJSYOR5/VQyWlGZT0TwjJKvul0OH
         p82S1RTDlcogHgdT8jGb4AcujPlMmozxXSLnHK25zVLSadwfyVRPrPuOiq5TFP4f/WFj
         kK2OVOaQAe6pjzx98hHksdhNGNlL9rLKi+FAUc92oMeDMEyJ5gEsCca7bzqNL0k307XD
         hFpYIBiJAjLTMLlb1ytBG8W5lR/t5tvQjhJunVuczmgk0kdp7zsgdqN5o9Eb0v4tVGvH
         jdKibdxialrO6OzKvuwmgt04/4JinZOR6PQ/dYBcR+ByARQ5wkO1Y5U++h3gLMl/Ovw1
         EvLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxfuwvoN+0JfJQTR0+xLh20+o/fwW0T2UOj9LuJmqEX98Pq7znY
	8QXDicaXeXG+EKSki0Bx6AM=
X-Google-Smtp-Source: ACHHUZ7yViXRolsARlEsuUOGv9SLWndG53rBdc7Twnt8j4xN4JsRI1tUEqs0Ie1bY1nY0wxkQzUpKQ==
X-Received: by 2002:a63:6b44:0:b0:50b:dda2:6140 with SMTP id g65-20020a636b44000000b0050bdda26140mr10622228pgc.11.1684312488227;
        Wed, 17 May 2023 01:34:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:14c7:b0:643:4e37:1e0e with SMTP id
 w7-20020a056a0014c700b006434e371e0els3403311pfu.6.-pod-prod-gmail; Wed, 17
 May 2023 01:34:47 -0700 (PDT)
X-Received: by 2002:a05:6a00:124a:b0:63e:6b8a:7975 with SMTP id u10-20020a056a00124a00b0063e6b8a7975mr12435pfi.9.1684312487296;
        Wed, 17 May 2023 01:34:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684312487; cv=none;
        d=google.com; s=arc-20160816;
        b=FRoc0UBa5X64wR4VvfW4w+9Kb/gQ3SoKGkFyHqirhxebIKL8SpjooYILrlPdU71dqA
         3Kz+xq5cj1udbXm4e5/d9tC7PNZYxH8kluQY/L22a+MdTfTHQOdGBaJFg76IO9nMXSvZ
         069wLJ3ForCOoycjpEE/WktnZU+1FJYEGTHMn+qHzj/o0rQlSxCT6WSz0Hne7fWG0sl9
         g+F28jfNfnwL7Cvbb1XMX7VtvAJr1b0VSW0SbNEjCqI3YRsmJ38AVzwmKMoqmYtG+SGJ
         2X5ch2xZxbZOcYBDMVoo44TYzDH7ougGkC+K9YYi7gq/5GDPQF8+IWXWuC9KcFYtdld+
         xB9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=WoyE4KJMZkzKP/aXFBkcgtSqzW5vCFF351V1GgKfqTs=;
        b=gpz5ctOagPih9tTGNSuLDHZV90bUaZNTf2AmpQHbjN3zJ5SEAL1XjvtxAk2qiHI11P
         Y6AXYq+qboswxP+H+ghSHBWvLRszrsS3cWU9t8TMP2kLlL18+ex4ej4nvscbmTTLWVz+
         tQ+6TXg0vk3MurBJPeaSF4yc+521KxQqhz5YbBTdEC0alo4Whd4GoFOIES8RmyDzm0Rr
         Ci/qBFq4Mvkv+RKn7D62mmyry2EqooEdRR0O99ZGC2JkV/gCg0Qg8tVNBY8PoE4uUe5z
         r4+RywsnO2/igLjvWzUQCRTPZJcUXVfnd4rw0EczPf6TAEBgP0gM4fvcEi4vOhfeoO4a
         xpJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=K1pZIcFP;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id p38-20020a631e66000000b0052875a200fcsi1362591pgm.2.2023.05.17.01.34.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 May 2023 01:34:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-355-19C65-3NNTa4NwKkOAmmiw-1; Wed, 17 May 2023 04:34:45 -0400
X-MC-Unique: 19C65-3NNTa4NwKkOAmmiw-1
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-3f348182ffcso3464635e9.3
        for <kasan-dev@googlegroups.com>; Wed, 17 May 2023 01:34:44 -0700 (PDT)
X-Received: by 2002:a05:600c:2307:b0:3f4:2cf3:a542 with SMTP id 7-20020a05600c230700b003f42cf3a542mr18563284wmo.6.1684312483860;
        Wed, 17 May 2023 01:34:43 -0700 (PDT)
X-Received: by 2002:a05:600c:2307:b0:3f4:2cf3:a542 with SMTP id 7-20020a05600c230700b003f42cf3a542mr18563263wmo.6.1684312483462;
        Wed, 17 May 2023 01:34:43 -0700 (PDT)
Received: from ?IPV6:2003:cb:c707:3900:757e:83f8:a99d:41ae? (p200300cbc7073900757e83f8a99d41ae.dip0.t-ipconnect.de. [2003:cb:c707:3900:757e:83f8:a99d:41ae])
        by smtp.gmail.com with ESMTPSA id 7-20020a05600c028700b003f182cc55c4sm1505469wmk.12.2023.05.17.01.34.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 May 2023 01:34:43 -0700 (PDT)
Message-ID: <a9312c59-215a-1213-459e-bf42af555f0c@redhat.com>
Date: Wed, 17 May 2023 10:34:41 +0200
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
 <ZGLLSYuedMsViDQG@google.com> <ZGLr7CzUL0A+mCRp@google.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <ZGLr7CzUL0A+mCRp@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=K1pZIcFP;
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

On 16.05.23 04:35, Peter Collingbourne wrote:
> On Mon, May 15, 2023 at 05:16:09PM -0700, Peter Collingbourne wrote:
>> On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
>>> On 13.05.23 01:57, Peter Collingbourne wrote:
>>>> Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
>>>> the call to swap_free() before the call to set_pte_at(), which meant that
>>>> the MTE tags could end up being freed before set_pte_at() had a chance
>>>> to restore them. One other possibility was to hook arch_do_swap_page(),
>>>> but this had a number of problems:
>>>>
>>>> - The call to the hook was also after swap_free().
>>>>
>>>> - The call to the hook was after the call to set_pte_at(), so there was a
>>>>     racy window where uninitialized metadata may be exposed to userspace.
>>>>     This likely also affects SPARC ADI, which implements this hook to
>>>>     restore tags.
>>>>
>>>> - As a result of commit 1eba86c096e3 ("mm: change page type prior to
>>>>     adding page table entry"), we were also passing the new PTE as the
>>>>     oldpte argument, preventing the hook from knowing the swap index.
>>>>
>>>> Fix all of these problems by moving the arch_do_swap_page() call before
>>>> the call to free_page(), and ensuring that we do not set orig_pte until
>>>> after the call.
>>>>
>>>> Signed-off-by: Peter Collingbourne <pcc@google.com>
>>>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
>>>> Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c61020c510678965
>>>> Cc: <stable@vger.kernel.org> # 6.1
>>>> Fixes: ca827d55ebaa ("mm, swap: Add infrastructure for saving page metadata on swap")
>>>> Fixes: 1eba86c096e3 ("mm: change page type prior to adding page table entry")
>>>
>>> I'm confused. You say c145e0b47c77 changed something (which was after above
>>> commits), indicate that it fixes two other commits, and indicate "6.1" as
>>> stable which does not apply to any of these commits.
>>
>> Sorry, the situation is indeed a bit confusing.
>>
>> - In order to make the arch_do_swap_page() hook suitable for fixing the
>>    bug introduced by c145e0b47c77, patch 1 addresses a number of issues,
>>    including fixing bugs introduced by ca827d55ebaa and 1eba86c096e3,
>>    but we haven't fixed the c145e0b47c77 bug yet, so there's no Fixes:
>>    tag for it yet.
>>
>> - Patch 2, relying on the fixes in patch 1, makes MTE install an
>>    arch_do_swap_page() hook (indirectly, by making arch_swap_restore()
>>    also hook arch_do_swap_page()), thereby fixing the c145e0b47c77 bug.
>>
>> - 6.1 is the first stable version in which all 3 commits in my Fixes: tags
>>    are present, so that is the version that I've indicated in my stable
>>    tag for this series. In theory patch 1 could be applied to older kernel
>>    versions, but it wouldn't fix any problems that we are facing with MTE
>>    (because it only fixes problems relating to the arch_do_swap_page()
>>    hook, which older kernel versions don't hook with MTE), and there are
>>    some merge conflicts if we go back further anyway. If the SPARC folks
>>    (the previous only user of this hook) want to fix these issues with ADI,
>>    they can propose their own backport.
>>
>>>> @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>>>>    	VM_BUG_ON(!folio_test_anon(folio) ||
>>>>    			(pte_write(pte) && !PageAnonExclusive(page)));
>>>>    	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
>>>> -	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
>>>>    	folio_unlock(folio);
>>>>    	if (folio != swapcache && swapcache) {
>>>
>>>
>>> You are moving the folio_free_swap() call after the folio_ref_count(folio)
>>> == 1 check, which means that such (previously) swapped pages that are
>>> exclusive cannot be detected as exclusive.
>>
>> Ack. I will fix this in v2.
> 
> I gave this some thought and concluded that the added complexity needed
> to make this hook suitable for arm64 without breaking sparc probably
> isn't worth it in the end, and as I explained in patch 2, sparc ought
> to be moving away from this hook anyway. So in v2 I replaced patches 1
> and 2 with a patch that adds a direct call to the arch_swap_restore()
> hook before the call to swap_free().

As a side note, I recall that sparc code might be a bit fragile and 
eventually broken already (arch_unmap_one()):

https://lkml.kernel.org/r/d98bd1f9-e9b7-049c-7bde-3348b074eb18@redhat.com

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a9312c59-215a-1213-459e-bf42af555f0c%40redhat.com.
