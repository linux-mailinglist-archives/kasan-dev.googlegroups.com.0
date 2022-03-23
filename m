Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBTGO5SIQMGQE7KEO5JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 556704E53B1
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 14:57:33 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id r9-20020a1c4409000000b0038c15a1ed8csf2836541wma.7
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 06:57:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648043853; cv=pass;
        d=google.com; s=arc-20160816;
        b=0KO+r+RqaQJL8532zJ+/kfRPkPr5ELz8xCVDpIiBdgku/PQ0mG4Npc2MIP15/mAc2z
         jIzDWjlLLNXSi97MIPD8GeRvR7GK+cR5h8Cuwknipu7R9jM0YLim3WEqtHYQqJnsXNyg
         Gux+k3cOT5+iiAX8glitMuLhTsGw0+7Y8AmZ7vuIxlBtk9EtZfBgQUu8srnGfhp1FAYT
         8nVDe585hymMUTDvbCMn/G9dwKEQXQo/jEEOigH1Az2lVn2Rh5Hzllucrp9KjKPoLyz8
         vfdflE9noEUXJuNyADm2YgUhrpT5u/uLVWJ/nogVr7VWZjHpB2l9IXYVQnFmwvk1nerg
         V5BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=I2v70h+o50by6Z5fk6nd8xuGMqRPq3cJIpSHJAakG50=;
        b=r4V6vF6dRWBSCDl1DP/p/v4EA4q0sk5B3wLfHpqTkt0rkdHi3whruUkAwMfXt2ikuj
         RwrZmvKAFqCJdBZ4Zpe5DphFqQRH2AjfFAcWlrGPcBdI44rlirwprA5mDtlfihwqTAK/
         MP1lWcUV2Bf8obD3pQKiSYYIQzW7iCixxEjStb5wYcsgr17RHAGcUvm9SRWVyJ0ASoSA
         02YYfjmV7GrwroETHcVJ08I5rHzH9DOVyoPaeGRHwtcHVBfcbP7mseUxeXhkAtpYAbpZ
         ngHyBSF3dmUB2NsC8fjPgaEdxOv7g9ITLoEePoSEKt773GHy3RRAosf343vIxkyET+zI
         hdEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZsrLi6je;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I2v70h+o50by6Z5fk6nd8xuGMqRPq3cJIpSHJAakG50=;
        b=nFqwe35BL/qCls6r8VTBiy/7ddgHvRS7wm2CzeLXi/nvmgZJ2wg5+vmq9RjL1a4CKr
         pVigW+lj5OneotfM4b5wvRmwkDZqYiUJPHAZqrEh0DwUOR5okQL2vc5LWXkEUuDZrkCr
         ieKE1JCMgrWUa/Lbyl6XjCOXf6U5Q67NSb0V4Lyb17QdMcEAIxsjO2j63tdf7HAI2n28
         mFORrYqMf2VeDjMXxKsUOsGfwtqFUu0DZouGLrsjpQ/J0vV/KuJU+oFePTrJzC+tr8e3
         ZXQ9K6wLdTZWslfUwYkxlOo40cz2fYNO6kwDMg9H8UMhKIXwOmemRc9eJRyiQ2YT/3kp
         7RvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I2v70h+o50by6Z5fk6nd8xuGMqRPq3cJIpSHJAakG50=;
        b=OAIJlszkVF3i2AFE4jrOA+EAXIbPHsX4Re/aVrkUZyjYR0CCiiWPwXpJ27r9Zxc6f/
         yJ5rimam65SJ/h4P+tUQ5i6XKq+jZ1PBpRvMIUA8BIzonx8Y2V2F6tkWUabFwcWp6tUe
         Qd0R6+59BVcfqTJdvc15F/dj7ZoLIghl49ATr7eRJ1GQr2Lkp3Iq03jfT/CcN6SzoaaO
         fs00QgWShCOzyzruLRiEwCa7HDGGkNdglAi1KYJNdcuWuVjhJyoFrSa5J9YCW0YqyekI
         Dwejr2VkiFhosiC50DUV571/QxurqQ1uPI17g4yfTyXDBkSH8+ULLLfGgIzo7nZv1oAj
         fzuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Ii8YKdzLc8ov9UdIKVU0bXMptmHxrHoExK2ykPTWb3wIoAZ9L
	1RxAtuiD3Fc1GlLSTLHJkvw=
X-Google-Smtp-Source: ABdhPJxiUnlEbsmpVzwbAkJFTJaGV1wM4SyX26kS+1oELgVyCa/x1TXDyJUB4b6G0LljE18njAyFWg==
X-Received: by 2002:a5d:6782:0:b0:203:d6af:5869 with SMTP id v2-20020a5d6782000000b00203d6af5869mr27169872wru.213.1648043853046;
        Wed, 23 Mar 2022 06:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1da0:b0:38c:aa6a:36fb with SMTP id
 p32-20020a05600c1da000b0038caa6a36fbls2996228wms.2.canary-gmail; Wed, 23 Mar
 2022 06:57:32 -0700 (PDT)
X-Received: by 2002:a05:600c:1548:b0:389:cde3:35cc with SMTP id f8-20020a05600c154800b00389cde335ccmr9231277wmg.133.1648043852048;
        Wed, 23 Mar 2022 06:57:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648043852; cv=none;
        d=google.com; s=arc-20160816;
        b=MYCG/URvqi9YpdsMHLyydXwcnQgrdOwZve1klGqGy0SdibZNLbzw5Y1VD+9oVA/OtY
         0Vtt5ay//7F8ZBC53GEEyoNJA9H87HWw/YxrHBBjgzJ0UYmjhh8APMIsnxH1TuinLyLT
         8w79++h3itO9FbKhcrpXgoIurAqxOLeFZ73XvKqMdG2frWdINO43ETXTxlzbi1xKfXmg
         LrGVTwMXLtV6Ox75e/JUKy8JwU4SWPcj144KjiB3aqGmgMraFBn1Y+OymLQCiJVPtroC
         /9BTKmzzwsJkRidIp78I1ZYtGKI3bA74NItk5n4u/BBqXBwciOmeIsOs3F1yRVCkDXsW
         b3qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=itu+LHsaFezNfv+6AfxtF3Pylr5NbpawvSpL4NXWxCc=;
        b=zssQRm63WUsheB5Bes3XSlTbkvKY6/eGzDjK5T+27A9fmWa7qJzgUinybskpUqPYQ5
         Ap/lHrWx3BOGpQknJ6qUhIYjUJTcxvQ82oeDucKj9x1wCPn30Jan9k5gQmeM08QSsaLW
         pUNBwa1/V5g79g832xmtRneq3tqhYfA4QcIm1L1cGq0Gn7gDIA7PVLZi9G0bygUyG7cB
         v+gYqjc63Kx5YshlCke56ubcBJJVRZXHrCxFJDITJLA42AKkTe664jecagtJw+K01UUR
         hNybMb/Gbn3f8s22wbgTdmt/S/D/8efnkyVVrcK6OqeFJqv/F5hLpgEiuCxMXPNXdK6q
         jjhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZsrLi6je;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id e11-20020a056000178b00b0020405b47816si5482wrg.3.2022.03.23.06.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Mar 2022 06:57:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id AFFF1210E4;
	Wed, 23 Mar 2022 13:57:31 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 36D8712FC5;
	Wed, 23 Mar 2022 13:57:31 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id RHj4C0snO2LpOQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 23 Mar 2022 13:57:31 +0000
Message-ID: <b4d598ac-006e-1de3-21e5-8afa6aea0538@suse.cz>
Date: Wed, 23 Mar 2022 14:57:30 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH v6 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON
 with HW_TAGS
Content-Language: en-US
To: Andrey Konovalov <andreyknvl@gmail.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov
 <andreyknvl@google.com>, Matthew Wilcox <willy@infradead.org>
References: <cover.1643047180.git.andreyknvl@google.com>
 <44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
 <63704e10-18cf-9a82-cffb-052c6046ba7d@suse.cz>
 <YjsaaQo5pqmGdBaY@linutronix.de>
 <CA+fCnZeG5DbxcnER1yWkJ50605_4E1xPtgeTEsSEc89qUg4w6g@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CA+fCnZeG5DbxcnER1yWkJ50605_4E1xPtgeTEsSEc89qUg4w6g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ZsrLi6je;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 3/23/22 14:36, Andrey Konovalov wrote:
> On Wed, Mar 23, 2022 at 2:02 PM Sebastian Andrzej Siewior
> <bigeasy@linutronix.de> wrote:
>>
>> On 2022-03-23 12:48:29 [+0100], Vlastimil Babka wrote:
>>>> +#ifdef CONFIG_KASAN_HW_TAGS
>>>>  #define ___GFP_SKIP_KASAN_POISON   0x1000000u
>>>> +#else
>>>> +#define ___GFP_SKIP_KASAN_POISON   0
>>>> +#endif
>>>>  #ifdef CONFIG_LOCKDEP
>>>>  #define ___GFP_NOLOCKDEP   0x2000000u
>>>>  #else
>>>> @@ -251,7 +255,9 @@ struct vm_area_struct;
>>>>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>>>>
>>>>  /* Room for N __GFP_FOO bits */
>>>> -#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
>>>> +#define __GFP_BITS_SHIFT (24 +                                     \
>>>> +                     IS_ENABLED(CONFIG_KASAN_HW_TAGS) +    \
>>>> +                     IS_ENABLED(CONFIG_LOCKDEP))
>>>
>>> This breaks __GFP_NOLOCKDEP, see:
>>> https://lore.kernel.org/all/YjoJ4CzB3yfWSV1F@linutronix.de/
>>
>> This could work because ___GFP_NOLOCKDEP is still 0x2000000u. In
>>         ("kasan, page_alloc: allow skipping memory init for HW_TAGS")
>>         https://lore.kernel.org/all/0d53efeff345de7d708e0baa0d8829167772521e.1643047180.git.andreyknvl@google.com/
>>
>> This is replaced with 0x8000000u which breaks lockdep.
>>
>> Sebastian
> 
> Hi Sebastian,
> 
> Indeed, sorry for breaking lockdep. Thank you for the report!
> 
> I wonder what's the proper fix for this. Perhaps, don't hide KASAN GFP
> bits under CONFIG_KASAN_HW_TAGS? And then do:
> 
> #define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
> 
> Vlastimil, Andrew do you have any preference?

I guess it's the simplest thing to do for now. For the future we can
still improve and handle all combinations of kasan/lockdep to occupy as
few bits as possible and set the shift/mask appropriately. Or consider
first if it's necessary anyway. I don't know if we really expect at any
point to start triggering the BUILD_BUG_ON() in radix_tree_init() and
then only some combination of configs will reduce the flags to a number
that works. Or is there anything else that depends on __GFP_BITS_SHIFT?
I mean if we don't expect to go this way, we can just define
__GFP_BITS_SHIFT as a constant that assumes all the config-dependent
flags to be defined (not zero).

> If my suggestion sounds good, Andrew, could you directly apply the
> changes? They are needed for these 3 patches:
> 
> kasan, page_alloc: allow skipping memory init for HW_TAGS
> kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
> kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS
> 
> As these depend on each other, I can't send separate patches that can
> be folded for all 3.
> 
> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b4d598ac-006e-1de3-21e5-8afa6aea0538%40suse.cz.
