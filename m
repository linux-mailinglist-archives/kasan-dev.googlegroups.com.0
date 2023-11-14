Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLVJZ6VAMGQEZ43QMHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 192717EB786
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 21:12:32 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-50943cb2d96sf95821e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:12:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699992751; cv=pass;
        d=google.com; s=arc-20160816;
        b=l0KcNLOUErVpoCQHqRI6CF/QN0FFP4oBYLUIRBipEhYI/fd2/ZUQDRcCK+B2DOIMmy
         cHfAv+j/NFg4aZGkArPTC4nwiqxFvP18qCb49cJA1LvdPtXddKDd78rf3Wl5iB1o0uI4
         /MHaDCoJGYvp0npWkVWuI+6uiFv+K5iSAq+zoDsnlup1rGS2iumYay5AVdD7DaQb5gXf
         oO6WUbsWwoJFRrxY234FNV8nC1/CoTwQavR702F002ODbUt3oCtZqAKpTS1T+MjcoHA2
         lQFdua5PWOFq3ojukF3BApye5v+EYcoC69zUevbtJjloEGKhXh55cDQbJvsy33RG5b06
         ZYFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=yXAiwEKO0+nwV+buEL9VI9dptOLFdZ9neToA436Sgt4=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=shzDWAeRDepS5B/hzCh+rBCUQY3Jg8q9xr4hNrQgpygn3lh0Ss8tojQj6O3AwK1RE7
         omYw+pyZ0uRRKC2gYmvW9tB3JqSna9da4o7U9I7z77xe++U8WINSFHa1EdZmgnu+HPQ0
         4tohtAbY/7EVBuafUi7v/dikV8B6VYY+EiDpQF8jdTiztcfd7KU4fjwv1fOh4u4/YPeo
         muU1XlatzHO+pqQIUASg+xTEp82YyHJe+MdIx4ILMQBmg/Tx6t8m62thgtTu+7CvLmuG
         hslEzvCvV1BUvNAt17HMdnENB65+EvwlF1wYZf27gH3XoNu/VxriOjx26BWaP/XsV2jH
         1ZtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KL32TVBx;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699992751; x=1700597551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yXAiwEKO0+nwV+buEL9VI9dptOLFdZ9neToA436Sgt4=;
        b=Hyc4LGnQHmNrjLLG71E5LqtwCLqZuspdGU931hIvGCHFSUlYzJJxqlJoo1RRnZnVeI
         ATWdw2OXB0DZSmNpgiqdqfNaqJ4HwWu2daot8Lo4oonO0qQCRUbtAy1Dd9r5Goh5fsNm
         DyFDsSx1AJXkQkN7cQkFfbuVcDcZczkAo85ElGAKN876BNp9Hc/5UD5zTMSahwFPjCVn
         uNAuB3c5ONjwzMEyj13pabGzZayUuZ6M70mMqquPZFA6fuxPmXZLN3qb3ApfiNU7nrQx
         60l3IebzMMT8sxevlyU6zJxF4obkg6AACIG4kKryjIs5AbxGZV8rI+Cz+UQMGc29b58b
         2bDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699992751; x=1700597551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yXAiwEKO0+nwV+buEL9VI9dptOLFdZ9neToA436Sgt4=;
        b=V/NsYkAOUlvyjiNahnVAUuGTuSaSIbSe3RN5ZNvly001f71uxOnkiTX6Jb0iAu9+ut
         8qun8Q9JN1WRys83R5bhUfi+TPKm4iQ7QwG13crA/XIwBOaqP8w2wQYhabgHBw4KE14V
         xGy5WzLsQpiLBZUN5r/CYRJpbowMsB7N35jc8QHBSClXu0iWSojQkjDQxypQkGNAMw20
         jHY5toXB6yIRhxpDpfZ5wLDWVn+X2fwoMyUqtADBdJrLgUl84NG1DYKDjOx32Dd2OO8x
         drHWVs3Bn2LcIqJtUuTXQeT1ThcW9FJA3kvdVh3MeIvS9I8wxSodTBmxPAaI15LCqcub
         0xLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyfYgJ2P1qw5HWlKMIkl8lCLDgKb6hqDxytmmr2UvnP8xvsY2s3
	w/sDGI+8opUVTS2Ok5iPGB0=
X-Google-Smtp-Source: AGHT+IF3eUaztKUKy5AXUqY2wSycL13wQB+WWlzoJkJyJe8LfrLN1PzgFSGD0g34i31+mUXCFmAQbQ==
X-Received: by 2002:a19:f704:0:b0:509:489f:5b6f with SMTP id z4-20020a19f704000000b00509489f5b6fmr1235735lfe.11.1699992750357;
        Tue, 14 Nov 2023 12:12:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:159e:b0:4ff:9bbc:f4b6 with SMTP id
 bp30-20020a056512159e00b004ff9bbcf4b6ls1248787lfb.2.-pod-prod-00-eu; Tue, 14
 Nov 2023 12:12:28 -0800 (PST)
X-Received: by 2002:ac2:5292:0:b0:509:51df:c381 with SMTP id q18-20020ac25292000000b0050951dfc381mr1000649lfm.12.1699992748492;
        Tue, 14 Nov 2023 12:12:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699992748; cv=none;
        d=google.com; s=arc-20160816;
        b=D+xuembgY6J2oU25+Zcw5NHLDNgkeaU03YCUoNyha6HsDLvxTaAdy7Xcg4592VR3eI
         TgQSgF4su0Sc91nvPWkf1xzGMaMIiCh1DYPEJ9xNHbX1qcc3MyPjTgtQ1Y508qZP6v8C
         qNIQGP8c/mJ1e37GGsZC6x2CQ0EcRl/sJNzoatEen3Pz6C9q8xfmzfW35dzcXWiTva16
         X8C4oip2+P8NYdvFkGGesGtIL6bq57rhEeqVZIvIwbjg4iZZQJrtkGf57x1+H6oBTGy+
         Ls73/dFx8lEb0n9FrfmsxM9d2H4xjDKiG1MOLphBf+nI15JsB6YAgf4EsZd0Ga36Urm7
         bH0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=3oWHSyp79oNEAgxAW4ytBgCxzKxU2JyVRlj3iU9Pw8Q=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=Ye3lUk8HNBI7b9UgwvyceH2m6vKQhMujwOjblueEssWjpqf/Eg0uN145Fop2Ig6aEK
         +IW6f3fLi9xDeodboJ0IE3DlJajKY4WYfAWaNPb+4+ce+lJfmw0/VZ9kRdusLC5R5oys
         eybQ94ZMs3ucfc+qLpmVJ9WI4E3+Yid55H7+iW2mYU4upXdSuMd8o8GsEOAX1t2fZq3g
         EK/kW7B8NbP/Ja/s25SgjlnwWHBscy4yUGiSuBQVfizzekvKj0W26qmFuoE1wmaTs2HZ
         gM2m1vThwonVEEO+rGq9ThYv6XxXLnjqbm6u2UPWxKiMy4lZDcJSxOEaO8u0SDtdRLR9
         yXyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KL32TVBx;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id bp29-20020a056512159d00b005090fd18c05si324460lfb.11.2023.11.14.12.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 12:12:28 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id A85D6228DF;
	Tue, 14 Nov 2023 20:12:27 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 658A613460;
	Tue, 14 Nov 2023 20:12:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id I44uGKvUU2XOWAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Nov 2023 20:12:27 +0000
Message-ID: <893d2289-e463-dd00-84cc-e77aed93cf53@suse.cz>
Date: Tue, 14 Nov 2023 21:12:27 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 05/20] cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, patches@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-27-vbabka@suse.cz> <202311132020.5A4B63D@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202311132020.5A4B63D@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -2.62
X-Spamd-Result: default: False [-2.62 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-3.00)[-1.000];
	 MID_RHS_MATCH_FROM(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-1.00)[-1.000];
	 BAYES_HAM(-0.02)[51.67%];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,kvack.org,vger.kernel.org,lists.linux.dev,arm.com,cmpxchg.org,googlegroups.com];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=KL32TVBx;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/14/23 05:20, Kees Cook wrote:
> On Mon, Nov 13, 2023 at 08:13:46PM +0100, Vlastimil Babka wrote:
>> The CPUHP_SLAB_PREPARE hooks are only used by SLAB which is removed.
>> SLUB defines them as NULL, so we can remove those altogether.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  include/linux/slab.h | 8 --------
>>  kernel/cpu.c         | 5 -----
>>  2 files changed, 13 deletions(-)
>> 
>> diff --git a/include/linux/slab.h b/include/linux/slab.h
>> index d6d6ffeeb9a2..34e43cddc520 100644
>> --- a/include/linux/slab.h
>> +++ b/include/linux/slab.h
>> @@ -788,12 +788,4 @@ size_t kmalloc_size_roundup(size_t size);
>>  
>>  void __init kmem_cache_init_late(void);
>>  
>> -#if defined(CONFIG_SMP) && defined(CONFIG_SLAB)
>> -int slab_prepare_cpu(unsigned int cpu);
>> -int slab_dead_cpu(unsigned int cpu);
>> -#else
>> -#define slab_prepare_cpu	NULL
>> -#define slab_dead_cpu		NULL
>> -#endif
>> -
>>  #endif	/* _LINUX_SLAB_H */
>> diff --git a/kernel/cpu.c b/kernel/cpu.c
>> index 9e4c6780adde..530b026d95a1 100644
>> --- a/kernel/cpu.c
>> +++ b/kernel/cpu.c
>> @@ -2125,11 +2125,6 @@ static struct cpuhp_step cpuhp_hp_states[] = {
>>  		.startup.single		= relay_prepare_cpu,
>>  		.teardown.single	= NULL,
>>  	},
>> -	[CPUHP_SLAB_PREPARE] = {
>> -		.name			= "slab:prepare",
>> -		.startup.single		= slab_prepare_cpu,
>> -		.teardown.single	= slab_dead_cpu,
>> -	},
>>  	[CPUHP_RCUTREE_PREP] = {
>>  		.name			= "RCU/tree:prepare",
>>  		.startup.single		= rcutree_prepare_cpu,
> 
> Should CPUHP_SLAB_PREPARE be removed from the enum too?

Yep, will do, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/893d2289-e463-dd00-84cc-e77aed93cf53%40suse.cz.
