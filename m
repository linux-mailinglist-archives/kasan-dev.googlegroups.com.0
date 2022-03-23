Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBZF45SIQMGQE4LT5HKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F9BC4E52E3
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 14:19:32 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id q6-20020a1cf306000000b0038c5726365asf606241wmq.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 06:19:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648041572; cv=pass;
        d=google.com; s=arc-20160816;
        b=aRNgJlkecQK2r0eC8Y8EkPipb9VGSpuclijS7FhVNoG8KH3vrll5y6mHgpN1Jy453W
         y94vFspr/bDK1vDDi7QqcGLp9pticY+t7OZGlrD5tOJ4rcW2oMmdVQtKfVcdhQnR4yrQ
         Rq5To5oyf2fobV2Meo6b8CG4GjlupTsPZQ4ZgM1eZ8TDT6nBG5X8WBujJt3E9u790MCY
         8Gxdn8rQx0FEQTR8JjJl+7cT+Yd4MczjZ86Y+QkuM4UMTSR/rGt7ue0dEXSjx7TPFbd2
         2kZXBRSyiEsYJI11PZhHcptghLTjzfDqZ5FSkna1Naew21nOoEDhHqI30Qyvo53mNxgy
         n7Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=aEnK2wyRP1eIfNvLUHAkJ9urJ90UUoLGGyrx82BbayM=;
        b=oGFYQ3qpn52wT+4MxrFWX72+3s+VGjRAZ5C4aQd/bD1aqHTm6cd6FfRXkMLSPTumrk
         An6qJjUidU53eLrBlyZbJQMZkWsmL8Omj4qO0GmIfSQ/2ytNJ56MfbSZPIOQP2kzR9Ms
         1tYC22A/w9pdMsdIEgB+Sg+bRpeSjNxFQgcfhtHDlFNSa/frGJHlsOrYpqlBX4MyIX3f
         nMAJR8agnw1iAs9FbjtxhbMX4+Xtsg8WX9lYRJayaL7nQ5W4l2UFJlQ57iVUTN3Ic/O+
         9L2G0LMuyEtAS7c3bAjiiyBN1ME2vpkzmSRSwqyLbxvz7F2B61knGh3Bu8EqjT7q6BL7
         Kvhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ExWKBH5g;
       dkim=neutral (no key) header.i=@suse.cz header.b=xJJQhmlp;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aEnK2wyRP1eIfNvLUHAkJ9urJ90UUoLGGyrx82BbayM=;
        b=qJpW7/8p9Rk1sDvL2z53LhrIwY7noHU53tgPuKrI0cT6cNTyXl6Ypu1s7gXItZ8wKm
         gjBRCL5sfEnorwCrZ+Yke8oMdW3XDpapCCBoHJDw+Eivcy7XjXyd1YZjibs3592eJaig
         /Djfjsx8EZXy0Q1dG2pNCGMoYYo+1LTJXHRMO/nWP5MlwWPoBZT6t2C2FupF38ux7ZU7
         SdiGjz6J3Z3HYKsv5ajwcOfLCfS/OwNcnZdPKxEb/WUrMy5pLeQcm8pBYRFUj916fCSF
         akPPsmP/J8i7v+vp3kbb4Vnqa08kqvlq+1yEarlgNzCgZrvIRHzkwBsL0Wwg7zcHrQth
         J2hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aEnK2wyRP1eIfNvLUHAkJ9urJ90UUoLGGyrx82BbayM=;
        b=vNCip4Y4qa0cXho2YPh9dfvNZhzpTo7Oig9UMVAQsrflfJx2hxcpY7l2IRGBq6KT63
         Yn1WrmsHpeWSZKlpyNQ2k4rIMudt0CxiKYWYI5B1FmdFB+VHnOOCwnLA4z7Kkhn5sasv
         HEgkGefEN9YHjQ7qoc32/Sxp3SRM0J3bx2iVo1IKb2Zb8fLnThkEmja3nwkMX4jP6TOe
         r/MnoJOWp9SUt7g5zQdlZIrVnl+c5sdbLWw3VuXotCDhpmQoNEF9kg14M9HXbpS/V79N
         /JqRcP11fah+xWzc//ctMDerbhmYgg+k2WMOZHR9kdMQSfDjzpzy3pP1r/M9pRjs2Idr
         cZ5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Pfnm4BXkhNSjFef2Mkr1V6WhB2ZoujLEOoq5UjoGkKwctxq8D
	7Z4ou2VsRE7T8oVN7AAOpp4=
X-Google-Smtp-Source: ABdhPJyygMhX07aCdPKtQgOcA0qBh3HukxgxU9DemWttPBHxMeKiwDHoB5L4kiSqfnB4sRgbHeZW2g==
X-Received: by 2002:a7b:c24d:0:b0:38c:68a4:eb4b with SMTP id b13-20020a7bc24d000000b0038c68a4eb4bmr9098485wmj.108.1648041572223;
        Wed, 23 Mar 2022 06:19:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:584e:0:b0:203:8599:7254 with SMTP id i14-20020a5d584e000000b0020385997254ls168942wrf.0.gmail;
 Wed, 23 Mar 2022 06:19:31 -0700 (PDT)
X-Received: by 2002:a5d:64e6:0:b0:204:975:acde with SMTP id g6-20020a5d64e6000000b002040975acdemr14818031wri.466.1648041571274;
        Wed, 23 Mar 2022 06:19:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648041571; cv=none;
        d=google.com; s=arc-20160816;
        b=yqW/UG1vMJz+pzoGBlybzek3ObK/0bpQMLWjdv/wghzR1a4Ro9NRJxy0d6IebyfpX8
         SIYTnNb4xZxx98BIxvxzMq6deQ9KpBkTUJVyVEmhU0U+x2szZ/cc+dD94TY0U2NbaMmi
         CnYJotHDY+t3oWyQwxcyz3CVzUA3G6agMOMXXJEitV5jaRC3m/5/EXGyNUoifvhpcSFL
         GUQGMrIRooCjVswEvzZmoBHzLxwWtJDk9tAptEW76c99uk/TNCcMpSIXdUkjDNAEj8sG
         Vkn67oe3FBLFqp7qsIONDlqwDrCMjOQW1KRdFOoXgwytfq3NK6hOaUnurb9pZZlAphIX
         +0bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=skAPDzFpHTiodgB8Q02pBrdUfjbG2DP3aT/OV2kUCTg=;
        b=xLEshmNnpl4qibgmdT+7y4+FMCsVWRV+jb1UU8RUY1/sBpYd5Zc7bqNhC47D8va1ts
         Lx9R3gb00rKHfR01mgVJ9ZxIMwG5ws4I4Mu4KbimFpDZ6htG1zmL6qf39Su755s21LtM
         GF2DArxcYP8KSbE+UcMwzNoe64Sl3LpDRZhVegUOAxF7pDy6JSXLDRBzGhV9FuBQXtOs
         ctYgSQrJBtSIjki06yrDEPa1zcMg4iQZG0g8s3rgG5fGN8vmwnf8+tErVVxFuE5n1ND+
         wopYmPP63wRdcj1pl1DDK+aJ1YKaBcc7CQk+U31brq1jGfZrsxAWFdLdv6Z6p3GpSsKE
         LRAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ExWKBH5g;
       dkim=neutral (no key) header.i=@suse.cz header.b=xJJQhmlp;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bg3-20020a05600c3c8300b0037e391f947bsi496158wmb.4.2022.03.23.06.19.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Mar 2022 06:19:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E2EBE1F37F;
	Wed, 23 Mar 2022 13:19:30 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 6F60C12FC5;
	Wed, 23 Mar 2022 13:19:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ud/kGWIeO2KkJgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 23 Mar 2022 13:19:30 +0000
Message-ID: <93851312-6443-31ec-c194-8117e483f5d4@suse.cz>
Date: Wed, 23 Mar 2022 14:19:29 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH v6 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON
 with HW_TAGS
Content-Language: en-US
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, linux-arm-kernel@lists.infradead.org,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
 <44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
 <63704e10-18cf-9a82-cffb-052c6046ba7d@suse.cz>
 <YjsaaQo5pqmGdBaY@linutronix.de>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <YjsaaQo5pqmGdBaY@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ExWKBH5g;       dkim=neutral
 (no key) header.i=@suse.cz header.b=xJJQhmlp;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 3/23/22 14:02, Sebastian Andrzej Siewior wrote:
> On 2022-03-23 12:48:29 [+0100], Vlastimil Babka wrote:
>>> +#ifdef CONFIG_KASAN_HW_TAGS
>>>  #define ___GFP_SKIP_KASAN_POISON	0x1000000u
>>> +#else
>>> +#define ___GFP_SKIP_KASAN_POISON	0
>>> +#endif
>>>  #ifdef CONFIG_LOCKDEP
>>>  #define ___GFP_NOLOCKDEP	0x2000000u
>>>  #else
>>> @@ -251,7 +255,9 @@ struct vm_area_struct;
>>>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>>>  
>>>  /* Room for N __GFP_FOO bits */
>>> -#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
>>> +#define __GFP_BITS_SHIFT (24 +					\
>>> +			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
>>> +			  IS_ENABLED(CONFIG_LOCKDEP))
>>
>> This breaks __GFP_NOLOCKDEP, see:
>> https://lore.kernel.org/all/YjoJ4CzB3yfWSV1F@linutronix.de/
> 
> This could work because ___GFP_NOLOCKDEP is still 0x2000000u. In

Hm but already this patch makes gfp_allowed_mask to be 0x1ffffff (thus
not covering 0x2000000u) when CONFIG_LOCKDEP is enabled and the KASAN
stuff not? 0x8000000u is just even further away.

> 	("kasan, page_alloc: allow skipping memory init for HW_TAGS")
> 	https://lore.kernel.org/all/0d53efeff345de7d708e0baa0d8829167772521e.1643047180.git.andreyknvl@google.com/
> 
> This is replaced with 0x8000000u which breaks lockdep.
> 
> Sebastian
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93851312-6443-31ec-c194-8117e483f5d4%40suse.cz.
