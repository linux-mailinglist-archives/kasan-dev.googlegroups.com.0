Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBW7ZRWNQMGQE5EF2G4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4045A6178B7
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 09:33:32 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id u3-20020a05651220c300b004a4413d37dcsf326058lfr.6
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 01:33:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667464411; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZXkFKT/9IX5TJMixuqUsL5l8M9wf46opLN1A+ZD+5oVBU9ZVCycMB/1I9YWql9fMf
         tT+o9kJ3AoBOe50Ki+L/e7o0EvNJqhQ7T8gRznHni1HIG3D+BUKAFJceoLT2E3WfLRot
         cYmIu6tJFiX8cOonn+N5YpWySH0FdeZbRyBYo2BmFlyyAI0KCYMrnaE7//PozOrHFZlU
         KHhqOxffHcAHBunrht+FxapA+DNXcmuAMT5LFBWXm4QC9BKyE/8mO4cjsR11DNT4QD5z
         jgiDOk6lA7Cr9QtugdHlsa1lDpV73nbLYhi/25ZuGD6fJIp82a2j0UKN0hcwndQGnc08
         FwVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=BaNSVmpTkdmBrfgQO//7a3KpLT6bCLCk8SKnsipFgww=;
        b=xqlKic+kEDZ8hgJUwjzG2fOU8oSBEurfBUZNG+nukU9mhwEE+mmBcHiFlrMjApfPDY
         1/T9uC49VADz2QTz9DH557NtcgkaDtJeFC2IKcKsUHW67M+zPDSms/Y1QefjO6cDoesv
         zfhqH39HqQA3UnNm8JZrV44gBPhGvbjE0LpbBhh2eaoyYo4lcJQ7XDxIIKeFkeyWsmAZ
         knsQQdAXP4r71kNZA1kcHe1ti1Lo4+WkvNOKIgsyVreSwKVhKhbSSKZRRzKJQ4mOKmmS
         q1cLecQk/PMksEzWPZSbcfZ5w6eOS4LbSzF48t0p0xAkaovj0uyexCBYjP3XOUGqF7G3
         RiBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mjIZMVd0;
       dkim=neutral (no key) header.i=@suse.cz header.b=mMWuZH57;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BaNSVmpTkdmBrfgQO//7a3KpLT6bCLCk8SKnsipFgww=;
        b=e8Dl9ON3zYIA8ecMrtx5UmIFUz6uGlAEntay+8ecIDVGFz865z3VpgIGzOKAtGXe58
         SxYhY3/R2z4D0ny1g3Jq+6UsnxZ2AdYY6cSJF+TM6U75+yh0G5QCG1YH6aikGOe8CzLg
         F+WaS0u+0IvnqF6sZbO47TOsoBp85pjzPM9UbuWK7RpOzlhX6ZTUOcepfzRUm7zlkkMv
         nPRIRg9gJoAEzWuw2p9Uc7G32jBauc9i8uJ/bW3wki/JsnfJC+COxOIFByTSfwrrgVKn
         fUImJdXn50VMgrF2G+yncNWso3Y4l6IKmOIphUvbxZ8bJmidQAU4dTtJXQUbHDzRdcuB
         KoCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BaNSVmpTkdmBrfgQO//7a3KpLT6bCLCk8SKnsipFgww=;
        b=XVAmlfXR4XduexuD8AsjNTfZLLu5GkvtcQIHjPYTtV0KGiuutJTJiUMP5l2DGZjSdE
         LeL+KbB6CJDOI4ROlKk3UOCLRkJTQOJWCxOrBm/+kN7QbbWZD7WRJv5+5qIPhpI5oa9Y
         4V12vL8PEOUSQO1/BRQ9ZQUFD2c4HTkL+nST6wOGaZEAvG446vYVdmwrcn2X/BAaJi6W
         MT48rXwIuf/rNLqI2qv2IEzv41M1GHiZwbKDyaG3Ya1P2sDFuiopvO2XEpeuw71AkSF8
         A4SRg21LwwmtgdR2LcPkhIln/UJDdYPnuMK0u5mSvM/fi+VWBMDrLmmWIY9ROC9r/68B
         uucQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3+lNvsDaBfPxgWiG2vSDueJ7khMrCfjhdJEVrlMGZNCY2+QDIe
	3r7RUI17IS1OkZ9RlOwav7o=
X-Google-Smtp-Source: AMsMyM6XGGJCqqOZBWjQLEDvqQ2/gn8lR3uzdpRivtJyFEKujmiFC6oQGv8MLYuFPuwUzDx/CH4GRA==
X-Received: by 2002:a05:6512:3d0b:b0:4a2:5bf6:c59c with SMTP id d11-20020a0565123d0b00b004a25bf6c59cmr10510878lfv.285.1667464411551;
        Thu, 03 Nov 2022 01:33:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e6:b0:4a2:3951:eac8 with SMTP id
 n6-20020a05651203e600b004a23951eac8ls802157lfq.0.-pod-prod-gmail; Thu, 03 Nov
 2022 01:33:30 -0700 (PDT)
X-Received: by 2002:a05:6512:22c2:b0:4a2:4f7b:29e2 with SMTP id g2-20020a05651222c200b004a24f7b29e2mr10441263lfu.389.1667464409980;
        Thu, 03 Nov 2022 01:33:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667464409; cv=none;
        d=google.com; s=arc-20160816;
        b=OQFZlSZgNi/w4VxlyGOWU6863PJwzkLLXfjylbwQv8qqS9yoTm9zBurbdi7IR5F84h
         YLVLXzVxbYrAwxSMReMZZZ+tjut5TB73vxVcZJlgPquJxxsLs8CwZZPmULwjGIKImYwA
         Vcs01+xbdt/2GiyDIA67YFFNDyjZ5TN2cSBI844LzhzMsGMxCiMEFLakCNaCrWjNdNey
         eBVGqC/kbUExqdPCBBfDdnmfJ1Fb0p0yTtgd1YMUkUFa8yyFq0ckomRWpO9yW89GMSB9
         EwmrsMry/bJi5tUMIfC57LirIiTWGAP7W0D83Wau9GZfMOz4PPIH3GFbuywExtFRAv0z
         qeCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=lW8tq5oEp8fEH7EtnVZjUEBjsnMp73rXze5VdCAXOxQ=;
        b=EKUX8yK18Jn3WDckmWI9Z2j4iThWnjczpRB10JAcG3QS9JU9hseBfnAuSktFQ0hOJe
         /xgcybpc0Snx4RtvFVL9Nq9PHrzFwCFhR1c99L5BrsUn/RfqgSKpZIrMYOjuxFf6qE/H
         r8ZaJJDvj2SWRjGGGeHadYxgaY8vylqS5wPKW3wxMbpyILPTLf10QIaWuU2p7cEOTcR8
         qR2IKkdo/OSGxnEHQvqzNVYvHGUNmb7oZjYymBRtJTD4rZF4XbL35U2xvmoxBKcUBU0H
         4PGAAdDAaoVKYZf2Nmj+WL6TOseCUptmdUBdFKXPxahc4aBx6xz8tTALvR1xJ9Vn36Jj
         ks4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mjIZMVd0;
       dkim=neutral (no key) header.i=@suse.cz header.b=mMWuZH57;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id a6-20020ac25e66000000b004a225e3ed13si9926lfr.13.2022.11.03.01.33.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Nov 2022 01:33:29 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2D09222207;
	Thu,  3 Nov 2022 08:33:29 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id D8B7013AAF;
	Thu,  3 Nov 2022 08:33:28 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id MvsjNNh8Y2MrPQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 03 Nov 2022 08:33:28 +0000
Message-ID: <f88a5d34-de05-25d7-832d-36b3a3eddd72@suse.cz>
Date: Thu, 3 Nov 2022 09:33:28 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.0
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
To: Feng Tang <feng.tang@intel.com>
Cc: John Thomson <lists@johnthomson.fastmail.com.au>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Dmitry Vyukov
 <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Andrey Konovalov <andreyknvl@gmail.com>, "Hansen, Dave"
 <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
 Kefeng Wang <wangkefeng.wang@huawei.com>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 "linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>
References: <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
 <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz> <Y2NXiiAF6V2DnBrB@feng-clx>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Y2NXiiAF6V2DnBrB@feng-clx>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=mjIZMVd0;       dkim=neutral
 (no key) header.i=@suse.cz header.b=mMWuZH57;       spf=softfail (google.com:
 domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/3/22 06:54, Feng Tang wrote:
> On Wed, Nov 02, 2022 at 04:22:37PM +0800, Vlastimil Babka wrote:
>> On 11/1/22 11:33, John Thomson wrote:
> [...]
>> > 
>> > [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #62 SMP Tue Nov  1 19:49:52 AEST 2022
>> > [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache ptr: 0x0
>> > [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #62
>> > [    0.000000] Stack : 810fff78 80084d98 80889d00 00000004 00000000 00000000 80889d5c 80c90000
>> > [    0.000000]         80920000 807bd380 8089d368 80923bd3 00000000 00000001 80889d08 00000000
>> > [    0.000000]         00000000 00000000 807bd380 8084bd51 00000002 00000002 00000001 6d6f4320
>> > [    0.000000]         00000000 80c97ce9 80c97d14 fffffffc 807bd380 00000000 00000003 00000dc0
>> > [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000020 80010000 80010000
>> > [    0.000000]         ...
>> > [    0.000000] Call Trace:
>> > [    0.000000] [<80008260>] show_stack+0x28/0xf0
>> > [    0.000000] [<8070cdc0>] dump_stack_lvl+0x60/0x80
>> > [    0.000000] [<801c1428>] kmem_cache_alloc+0x5c0/0x740
>> > [    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
>> > [    0.000000] [<80928060>] prom_init+0x44/0xf0
>> > [    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
>> > [    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
>> > [    0.000000] 
>> > [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
>> 
>> The stack means CONFIG_TRACING=n, is that right?
>  
> Yes, from the kconfig, CONFIG_TRACING is not set.
> 
>> That would mean
>> prom_soc_init()
>>   soc_dev_init()
>>     kzalloc() -> kmalloc()
>>       kmalloc_trace()  // after #else /* CONFIG_TRACING */
>>         kmem_cache_alloc(s, flags);
>> 
>> Looks like this path is a small bug in the wasting detection patch, as we
>> throw away size there.
> 
> Yes, from the code reading and log from John, it is.
> 
> One strange thing is, I reset the code to v6.0, and found that 
> __kmem_cache_alloc_lru() also access the 's->object_size'
> 
> void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
> 			     gfp_t gfpflags)
> {
> 	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> 	...
> }
> 
> And from John's dump_stack() info, this call is also where the NULL pointer
> happens, which I still can't figue out.
> 
>> AFAICS before this patch, we "survive" "kmem_cache *s" being NULL as
>> slab_pre_alloc_hook() will happen to return NULL and we bail out from
>> slab_alloc_node(). But this is a side-effect, not an intended protection.
>> Also the CONFIG_TRACING variant of kmalloc_trace() would have called
>> trace_kmalloc dereferencing s->size anyway even before this patch.
>> 
>> I don't think we should add WARNS in the slab hot paths just to prevent this
>> rare error of using slab too early. At most VM_WARN... would be acceptable
>> but still not necessary as crashing immediately from a NULL pointer is
>> sufficient.
>> 
>> So IMHO mips should fix their soc init, 
> 
> Yes, for the mips fix, John has proposed to defer the calling of prom_soc_init(),
> which looks reasonable.
> 
>> and we should look into the
>> CONFIG_TRACING=n variant of kmalloc_trace(), to pass orig_size properly.
> 
> You mean check if the pointer is NULL and bail out early. 

No I mean here:

#else /* CONFIG_TRACING */
/* Save a function call when CONFIG_TRACING=n */
static __always_inline __alloc_size(3)                                   
void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
{       
        void *ret = kmem_cache_alloc(s, flags);
                    
        ret = kasan_kmalloc(s, ret, size, flags);
        return ret;
}

we call kmem_cache_alloc() and discard the size parameter, so it will assume
s->object_size (and as the side-effect, crash if s is NULL). We shouldn't
add "s is NULL?" checks, but fix passing the size - probably switch to
__kmem_cache_alloc_node()? and in the following kmalloc_node_trace() analogically.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f88a5d34-de05-25d7-832d-36b3a3eddd72%40suse.cz.
