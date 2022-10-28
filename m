Return-Path: <kasan-dev+bncBCSL7B6LWYHBBJWK56NAMGQEQALMHAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 59E9661145C
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Oct 2022 16:20:23 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id u12-20020a2e91cc000000b002770fb05c39sf2334161ljg.12
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Oct 2022 07:20:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666966822; cv=pass;
        d=google.com; s=arc-20160816;
        b=H5TLj3BjRL6BaShcVhsFHfsPx11fko2HnlR/AWKDfGvIadgziqVxfQ18pRgarmyraL
         nYziYSSfI0X8J6JSvi4EYZmq6rX6YO4S/4alAtkQ1DkQTZcxjs/+nDuObmIz/6r7pfgB
         g6wFsyDMH979M1u0ABEiwtPyVz3SJ57L6SoszDyofEOUYU2ptY0ZxkmNFYu89go9d47V
         RN/tOACIikfn6fS3vxhHOOE/F8Med4iaYOJUlK0uDdOGGNPL4/dDOlQsmPBhIFg9wuCW
         viyq6ZwBtIEFqidCe8XsuNpzz3lTjsKaGRNTHAceIZz7WjaGb38h9DYu23Llx1CQ7r0F
         LaZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=nDJBkmEjjvJzLDDQsrBLaioUgIWa2oINPeMhoubttGg=;
        b=tpm7p1/Prbo4xbREIUyE8M7Dxd2k3IQjBc4xV5IdmwP5CCy/LMJozRr/8TR1jkNZ6N
         zmQrLC0b4BctMKynnWjWZh9SLnazP3/Il/l9bgPdqNEKiWypDYxm+2bbFYU9TrkHz+C3
         lQIigvffT5jwn5mIg78GkJtyYMK+APAcZhezhRpeOSjcT4Mh64Au0ND7jCUDd9wYOX34
         4YdoKCKkg3A5eZbWFN8uNmXMDqyZxC/Wz875ftWh697awWManbZsHpjdmY5pcsR0ztYD
         uSbY4puXYA9BNMnayW5hs3v58mfVj1z3itpPQRqNFoi7gSJcC/EVsQGpDC3EOxDnN45o
         btUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Og179Q/t";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nDJBkmEjjvJzLDDQsrBLaioUgIWa2oINPeMhoubttGg=;
        b=M5qJ1vlLFTXfXznvjEvPRlWzRt5XvW1a3VaZejEi7HN8DZ26P1bTcOow/VrW1eBXMn
         uCKs5j4sovZ7ASyleUuNXVU4g2LtwQPEXqzxCzvo0OcLbnZYU8H3j+sJzYBP+40eKYLb
         5gSMXEzH/jihsTzoBfqhLRTYO7UmK0uLb8cOQdveSruj3xorVJbKOFIZg7YdvLB7hBfW
         g1wukax5Bnxy0IP428qFOk27EXc3hIJD5T6LlzUVblBwkYUwzvPxwglZWu+0HrFA8wZC
         I+n+KPgQMZDEZGuIjrLHLOlqg+1U7cwWucVGecOFnGSzzE2VAQ+QxCEsB2QpQarY877B
         agDw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nDJBkmEjjvJzLDDQsrBLaioUgIWa2oINPeMhoubttGg=;
        b=kwQPXPBZxATS8p7zi5Obj9tjdRWmDRM8BrBv4k5SpPjY+55lEmY7e6u5CHcX5gCCeE
         Nj1/XPVch8FQCNrJOiCEDAAZUDes3riyTFx7ChVyucT20ChAl0YZ6W4It1qU5xKog8Jf
         4iOLEXWBeLQQ0vm7x8zGjAK/P8G2bUAg+xwQR2n1aAIiiTRxdEu+p4UzPryflxmz8czz
         nawH3MwP396ECs/br5ftUrxPnLgPLkxOD5aD0spkLnkuzI9CCuMbPxoiMYbIHZ90j8R1
         BTyc3yCJypx8dtWD7dwvq+TViaFpcugF2bsUeQwlAnChRGnlPcMo2mDrMDd8pQZlSvkx
         DjSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nDJBkmEjjvJzLDDQsrBLaioUgIWa2oINPeMhoubttGg=;
        b=6kkO5tuv9t3axeyX3OhJtZ3RgPaPaemGEnrhe6VQnnYUeyIbhxxT+U+oC6WKddFoGk
         4/14GvVFIaVcdyoSFsHsp18tmXw+/PK7++5XxxWzoyAnOqkzugMFYjJoE+j3Y+Fcz6zz
         WZ9BDHwsIGDuSMNxFesrP///OI6S73PliWWjKUqbEa0ekPAcRit+in8nzlQnLcg1mCJF
         Geg+kHiuz773oFFta9SVEdRB28pc2Jf9664yV/t9P4RlCzDvF3ZZoE1WpQeQUf24TPFH
         njRzVADL8SIU5ez/lmDY89Y8kkZVkle4tgjHw8mtFvpHdcvz/4cUAuXio4FlxqF/P/jO
         cNVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2wZfx3qED/KBp2cZjAaKuJ04NsC0rDndup/5uXo3ZTzH4u9Lqb
	+7JVRp8XIZanXHHYT85HgRQ=
X-Google-Smtp-Source: AMsMyM5aMTaEN5M/m9p9CQK7eUMb/iAv4xY/lUVW+OsZQFbwQ0mWT48vAzrz+SKQDI7eGKVn1cllXg==
X-Received: by 2002:a05:6512:3404:b0:4a2:c77d:9212 with SMTP id i4-20020a056512340400b004a2c77d9212mr21298402lfr.489.1666966822615;
        Fri, 28 Oct 2022 07:20:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2024:b0:48b:2227:7787 with SMTP id
 s4-20020a056512202400b0048b22277787ls2115989lfs.3.-pod-prod-gmail; Fri, 28
 Oct 2022 07:20:21 -0700 (PDT)
X-Received: by 2002:a05:6512:203:b0:4a4:6f0f:a70a with SMTP id a3-20020a056512020300b004a46f0fa70amr21664504lfo.210.1666966821027;
        Fri, 28 Oct 2022 07:20:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666966821; cv=none;
        d=google.com; s=arc-20160816;
        b=RW7TXci/Q8IbBUhEPR++j64JckOKaoaKsQP+mUznC/iop35GFQmG0fF+AJOLmMdzc1
         36BU8pseedg5v3TXfkXg41msrma7Y7w2kM1XwxgUaApgLW8g6CztFA3GBOJ2juA9a+Ei
         nN/bp1Rp4mz8GKQH2a52aLvtT2rkqh7SaJxUSiaYtwORX3VvTCTyH0NFz2Vz1/s8pp76
         TyeWWybCXWtTIsa5TjfTf5s8Uggj36s4i/L/NZabN8pPSsLDCMNKHQkzTfrU8COzrcZi
         pZ7IH2rZHZzxEasb1u2sHwMdW0Waz1sk4r/aPdikd8hiRAMbNNDzaZAX928h9Og255i5
         XKog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=8rtTsgQEQ98uqnUW/cLp215q8QkVCdpzvy4SgEkrnQ4=;
        b=BbFlSvThVmwFF80CQsAh5o8Unjupq3sF0caMQZhyMiS7ehppkfaiYOfvTOQHkHHoYh
         ZJZXURSfaKbL44+hjJwUN0fz/99TBVSCmJ+UxBS0oO80XknLi1DL12kDq1gLlbRMhhdh
         16rILRMuiG5/k1sA0pPBysewOVAYRoOX7LVfQnC/nsOFt4Ih6qg9Bh4madglCW3c0YnU
         lBF+vqtxMa5r7emOBqLcNEFfiYdkaFgOhrL4luBwGmG/2cgDIqRqfzVK0F4putbm9Qn4
         ahgAxQVYyoZYliEE5ZyWJGS0W1OKWwRkGv5ozuSkAWIlaf+sUtRQrBN06jBEJf3Nnm/L
         8EAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Og179Q/t";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id w2-20020a05651234c200b0049c8ac119casi166360lfr.5.2022.10.28.07.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Oct 2022 07:20:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id g12so8564694lfh.3
        for <kasan-dev@googlegroups.com>; Fri, 28 Oct 2022 07:20:21 -0700 (PDT)
X-Received: by 2002:a05:6512:6d4:b0:4a2:f89:db7d with SMTP id u20-20020a05651206d400b004a20f89db7dmr19764286lff.125.1666966820641;
        Fri, 28 Oct 2022 07:20:20 -0700 (PDT)
Received: from ?IPV6:2a02:6b8:0:107:3e85:844d:5b1d:60a? ([2a02:6b8:0:107:3e85:844d:5b1d:60a])
        by smtp.gmail.com with ESMTPSA id b3-20020ac25e83000000b004acb2adfa1fsm578823lfq.307.2022.10.28.07.20.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Oct 2022 07:20:20 -0700 (PDT)
Message-ID: <c6fbc75a-4e8c-05f4-c1d9-53693a7c604f@gmail.com>
Date: Fri, 28 Oct 2022 17:20:22 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.0
Subject: Re: [PATCH] x86/kasan: map shadow for percpu pages on demand
To: "Yin, Fengwei" <fengwei.yin@intel.com>,
 Peter Zijlstra <peterz@infradead.org>,
 Dave Hansen <dave.hansen@linux.intel.com>,
 kernel test robot <yujie.liu@intel.com>
Cc: Seth Jenkins <sethjenkins@google.com>, Kees Cook <keescook@chromium.org>,
 linux-kernel@vger.kernel.org, x86@kernel.org,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
 Andy Lutomirski <luto@kernel.org>
References: <864b4fbe-4462-9962-7afd-9140d5165cdb@intel.com>
 <20221027213105.4905-1-ryabinin.a.a@gmail.com>
 <3a372c25-7ce1-e931-8d7e-a2e14b82c8f0@intel.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <3a372c25-7ce1-e931-8d7e-a2e14b82c8f0@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="Og179Q/t";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b
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



On 10/28/22 05:51, Yin, Fengwei wrote:
> Hi Andrey,
> 

>>  void __init kasan_init(void)
>>  {
>>  	int i;
>> @@ -393,9 +405,6 @@ void __init kasan_init(void)
>>  		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
>>  		shadow_cpu_entry_begin);
>>  
>> -	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
>> -			      (unsigned long)shadow_cpu_entry_end, 0);
>> -
> There will be address in the range (shadow_cpu_entry_begin, shadow_cpu_entry_end)
> which has no KASAN shadow mapping populated after the patch. Not sure whether
> it could be a problem. Thanks.
> 


This shouldn't be a problem. It's vital to have shadow *only* for addresses with mapped memory.
Shadow address accessed only if the address itself accessed. So the difference between not having shadow
for address with no mapping vs having it, is whether we crash on access to KASAN shadow or crash few
instructions later on access to the address itself.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c6fbc75a-4e8c-05f4-c1d9-53693a7c604f%40gmail.com.
