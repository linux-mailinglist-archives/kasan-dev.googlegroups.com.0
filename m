Return-Path: <kasan-dev+bncBCSL7B6LWYHBBUXZVKNQMGQEPG2VO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 36D44621DB3
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Nov 2022 21:32:19 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id x7-20020a2ea7c7000000b002770aeb6d15sf5512959ljp.13
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Nov 2022 12:32:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667939538; cv=pass;
        d=google.com; s=arc-20160816;
        b=MiAkQuVY/TjfbjVgaU9WSeVxUa48neI7wbg42+cHBB4x0x4wCbQJR4GTfMu9/1PoWf
         fTfWmg3YV2TSgSwO9LZ5gjL3kKPcHkMRlQiqLbylxWiKTSH4WQVy9BS9P8m0I1925gxI
         kt9/7xd0hyfSRTHs/gFmXWgIKOL7Hl6BxHgkZ6HhADLIrZt6E8vYwTIfkPJisLlpaspx
         3okDnz9U5e7xrFuisYY3B67LOu+HV/ss7WWnj+9AR8+1hRfo5Ba7l+tMb0L7do3doY8V
         ODRHlvJ6yJ24+v+07PdF70a7UzKwm1GcG5K9Q+OK+6zMqrhjINGELbI+55NRMZK7wCQT
         LXQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=li6IfjBMFEiOCi7wO0WuCEonHNPDn27VhfA7GJFal58=;
        b=l7JSFGpW7xXU4ugoPgqRQ3lcMVRXP3T6SKgVGqL6PGkUCXvoIXiAwd7bdk5SC+eT3k
         vIaHD0hxFu8C/uqGvEOXrWs3PAlYSG05ftO1cxrQfijNkJiQEdxS3gy/AEFpeKO5nesw
         QqWTIFVznorIRqnsnCXmrqF9g9gCeQw5jp3h7kNBqT2+p+iIE4KVq2976I5yzgOjC3KI
         J+rdB2EjwSzr2QFiU9iA7Uv5Pd0ft50//ueGFSV6b6489bmRJktJvIBCS/mKfu3DlsUO
         Wu/SUJmnoz8E6wDPsm+5reeGCm0zk5waULwzhEm/WrUU+zc2/ZzyFnA49yCgBfSnWtDB
         yuFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZObg1M6A;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=li6IfjBMFEiOCi7wO0WuCEonHNPDn27VhfA7GJFal58=;
        b=SNOxEnySUubtB/lPQtV5th/etDRgeaZglT0AJ7NWiUVm1iBUJU0mAJ8WHDpBOgQZhW
         XwJN/AQKQBI/dWnYHnMSnhKQ/we2+CrUbjMF5Nv2/aA/IX6KRysw+k59Jo1S8VHqVYV4
         sAk1MhToWywAlEvmeMy7d4Rkf7J6tDOerFwMR4FMYn0BX4w/my6wllHCsVwdVFHYGYFw
         z52W9O9P/TlcQhJ1+tijMSEsLGE5Qs6lF51XYO2U3fAaag/iOkKGUPLCOvMBYT19usSW
         dE9CnaOLFxObF7HMkT+jvvpL4tz+Tly6b5LrL2jYySZX0ft99kYq999MlA8K6h7I5txE
         tZog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=li6IfjBMFEiOCi7wO0WuCEonHNPDn27VhfA7GJFal58=;
        b=akNU5mJ9Wi1pT2bHug56Fv3+rUkDM3BRzo5x9PSZPYptZBqk2YlSwHbiOeRF2hUcJE
         TPQORSzalz7EzmaJIKdvLbzKjEzUlx/+2L2rnfHssJ8e6s8cAWAObMrMrKyYk9pn+5hS
         e+KbuelFg3qsI8ek4vHq5O7LpRXKP/gAY4SlAIpccROZ5hiCvYZta0m1QK006Igxt/xr
         vaBwXLVpjsGNrkIRQDoyxI4ECqJv6QIFs/QyJXqYtAv6M2iFWdx17K8d/1nqXnchQoAH
         KsEGxYRTNl/Ogw8w6yEV6aSDBwKEi5l++UGP2U5mtxEpP7YyuYVNdaE2WJb2WYNzBSOE
         oPBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=li6IfjBMFEiOCi7wO0WuCEonHNPDn27VhfA7GJFal58=;
        b=UfxpqVOSE1sjTWVPv6hoShvfLEVS7KCK3Tl5Nbm9JJgtdGAK8Rn7zJc8xNrrx+qGe5
         uIQGJzFK/yBAO5DFUpwxkFM0Ek3hnP27OZDv5tGdDZSgWaYeP8WnIQoOf1L7z6Jp6a2d
         Im5V5c9mRLUU8ljoa7rbr3yh/fgY4Cn0dW4iftM39udPtxAD/m96PBnKQsO0kNk4NJKb
         UofOx5+U18ETGsqK4pfTdQ4Yk0tgDsDfl6fOBVhy6TNxMMNFsPaf+r2WgYdCLzKji2Qu
         Awho0STiAgBIXqozpNLPRnbEV8khWNwgZpMAr9tW08rGYg94ZfluudZZeAAUSdOFLrjl
         l0SA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkuOjbMihXzbbQp7NHnoUmQLzgfhEvfQqQAq3W21oEc+HISsOMA
	2QYGM1qS26lYR89FRweoZ+Q=
X-Google-Smtp-Source: AA0mqf6c3OPef7dWGqDBkpUwlFRv0AE9hbojQ3Zvm/oHDuGj5yTt22LWOkr7BKuEnfecSkxvaEuidw==
X-Received: by 2002:ac2:5a41:0:b0:4b2:777:973c with SMTP id r1-20020ac25a41000000b004b20777973cmr8110414lfn.556.1667939538472;
        Tue, 08 Nov 2022 12:32:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:358c:b0:48b:2227:7787 with SMTP id
 m12-20020a056512358c00b0048b22277787ls2961578lfr.3.-pod-prod-gmail; Tue, 08
 Nov 2022 12:32:17 -0800 (PST)
X-Received: by 2002:a05:6512:25a2:b0:4a4:71c3:70d4 with SMTP id bf34-20020a05651225a200b004a471c370d4mr19317435lfb.462.1667939537059;
        Tue, 08 Nov 2022 12:32:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667939537; cv=none;
        d=google.com; s=arc-20160816;
        b=J2sjyaGMGnucCjtlQrgW/d1tHR/B9MBVKCZEygt0xKJf+luCJ5V3SCqmatorowBky+
         1BvFVpqMAxjdByTJh8zfb/lldi08OMTbuFfz/cPX8ACihCyqAMeZjyuSrOa0eOXrUN/G
         xQ74cLlGc5R7/LDlvZGaHsN5kYIYGwpj9iQYZP5bXWrBBO5aE/aaC8X0hzt/uHSo4av4
         kJDBRsbBNDvTlTo94zuX2X0OTfK0nmU1QDn03886p2dC9YtBHrrLgwU+ZW+h0s/ZU9OU
         E3jFRvN+avL0uBIPb1mHeIc/wl9B3hdQVi84xV85UyMf+beUWFLlr57VbLwAaUPnwlVe
         1EGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=qJt0kVHbBDkDv41VSM0vRXGgK3laYpSR5VQmLWACDUI=;
        b=MnCJTeQ1WfjOQsrkXa5I50D0lwQeacROxbCY7F3H1YE3XYxlZgh0ZiqedkBurPRIrb
         TzGB+0+11Rt1SOSocgGmlBGO2Jja1/6Ypq6gdGdWXslHeJPMxwXc73asAsHhkIBOdmUM
         ZLBOEbtsYhO1r0+pJ/65OGpFdt/CxuRYrFieAq2BXtqBIqudyEQyR8INhoe75RsdSRHv
         +/PYRAJTFKXPGYKJp5HqWNCX7c8cvXB4B+biUw4usi1xYrmydntsmByeU8H2NwOlNd/k
         g3cUb+bAlUE7tbuQm6t6nWaP2Fz/QlK8xgqPI6BYxIZxl7bbvQVbG3R/5irxufkhWMvH
         q4zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZObg1M6A;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id v18-20020ac258f2000000b00492ce810d43si313697lfo.10.2022.11.08.12.32.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Nov 2022 12:32:17 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id j16so22758692lfe.12
        for <kasan-dev@googlegroups.com>; Tue, 08 Nov 2022 12:32:17 -0800 (PST)
X-Received: by 2002:a05:6512:1154:b0:4a2:4f74:f47c with SMTP id m20-20020a056512115400b004a24f74f47cmr490729lfg.367.1667939536837;
        Tue, 08 Nov 2022 12:32:16 -0800 (PST)
Received: from [192.168.31.203] ([5.19.98.133])
        by smtp.gmail.com with ESMTPSA id y19-20020a2e7d13000000b0027709875c3esm1859272ljc.32.2022.11.08.12.32.15
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Nov 2022 12:32:16 -0800 (PST)
Message-ID: <518b5f84-ca10-6943-76dd-a7fa267b8a13@gmail.com>
Date: Tue, 8 Nov 2022 23:32:17 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH 3/3] x86/kasan: Populate shadow for shared chunk of the
 CPU entry area
Content-Language: en-US
To: Sean Christopherson <seanjc@google.com>
Cc: Dave Hansen <dave.hansen@linux.intel.com>,
 Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, "H. Peter Anvin"
 <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
References: <20221104183247.834988-1-seanjc@google.com>
 <20221104183247.834988-4-seanjc@google.com>
 <06debc96-ea5d-df61-3d2e-0d1d723e55b7@gmail.com>
 <Y2q2GFWjLKMp5eUr@google.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <Y2q2GFWjLKMp5eUr@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ZObg1M6A;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 11/8/22 23:03, Sean Christopherson wrote:
> On Tue, Nov 08, 2022, Andrey Ryabinin wrote:
>>
>> On 11/4/22 21:32, Sean Christopherson wrote:
>>> @@ -409,6 +410,15 @@ void __init kasan_init(void)
>>>  		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
>>>  		(void *)shadow_cea_begin);
>>>  
>>> +	/*
>>> +	 * Populate the shadow for the shared portion of the CPU entry area.
>>> +	 * Shadows for the per-CPU areas are mapped on-demand, as each CPU's
>>> +	 * area is randomly placed somewhere in the 512GiB range and mapping
>>> +	 * the entire 512GiB range is prohibitively expensive.
>>> +	 */
>>> +	kasan_populate_shadow(shadow_cea_begin,
>>> +			      shadow_cea_per_cpu_begin, 0);
>>> +
>>
>> I think we can extend the kasan_populate_early_shadow() call above up to
>> shadow_cea_per_cpu_begin point, instead of this.
>> populate_early_shadow() maps single RO zeroed page. No one should write to the shadow for IDT.
>> KASAN only needs writable shadow for linear mapping/stacks/vmalloc/global variables.
> 
> Is that the only difference between the "early" and "normal" variants?

It is. kasan_populate_shadow() allocates new memory and maps it, while the "early" one maps
'kasan_early_shadow_page' 

>  If so, renaming them to kasan_populate_ro_shadow() vs. kasan_populate_rw_shadow() would
> make this code much more intuitive for non-KASAN folks.
> 

Agreed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/518b5f84-ca10-6943-76dd-a7fa267b8a13%40gmail.com.
