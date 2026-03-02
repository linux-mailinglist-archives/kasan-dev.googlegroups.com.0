Return-Path: <kasan-dev+bncBDVOZGGKQUGBBIH7SXGQMGQEZEVPA6I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6NtZAKN/pWl1CgYAu9opvQ
	(envelope-from <kasan-dev+bncBDVOZGGKQUGBBIH7SXGQMGQEZEVPA6I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 13:16:35 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 27C021D8224
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 13:16:34 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-483bcfdaf7dsf41919575e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 04:16:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772453793; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mh30RLy+Fmutcpmps6q46MGpZPUVIHsAzPrTp/FmkD3E5kaMrT3/PSuHhum18tU3Nm
         E0OohEY1RDzhy/EvN00zBA3HLhZ6euY3jJsWC6DnaNOahfKhVjN5VdllyC9wmlsM+05y
         Zh2gu/oGgdDF/JjtCdTVshWunHIReeN6GHaeQWn4Ixq4BSbdoXiHOxDNLrfZx0l9z5l5
         h2YDP3ubqiWPD7Q2cb9WtRuaubUHqJm17rkXj1lLyGX7DEXNJm2NbEEuD+NrUU8Y/xcE
         lSr+I73kzIlZMtDcLvjzVPuzwuH0kQb20+AIOUuRJ4GVAyL56RH74WqBumTJUf/2dUZX
         M06A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=ItUpgUFj2F6zsI17uU7C48rT9A5lTVBWK7LNUTSHoRo=;
        fh=OiswVr7A9sexkKSnn+QaPB4SgGUJ7G5CEtsGczaht54=;
        b=gxvU+GHReOHP8GVuZUZhX0WKvoKle8aFjK1ceXNXgUHFZCC91fNwNFHSqNyvu8gNzD
         paWh92CUmyS097U/VZNrXKYNT4oFZ5ioDmW/7KdPWtozWxTXWEMlwKrDLTICcWB0FOaj
         rrrO2pOPzwtDmJ8VkW02CfSmqthe8ppo9YGcHk1Kth75EREhQ05aOB57/L1Pc+YGdPhR
         iFVgpiJAvyaBfQhJnynb/8wSpxOpB6NRJEjl5utA+sDlklofS/JB1wp+KII8pkHHzmNh
         rkeZlvW86VYeukTZuy5T8Mjn2ccbqPuvUjkprsb+lg6jyxxw1LPw1yyUptg3j0UPbdRz
         NCxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=QcxENO+B;
       spf=pass (google.com: domain of vbabka@suse.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=vbabka@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772453793; x=1773058593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ItUpgUFj2F6zsI17uU7C48rT9A5lTVBWK7LNUTSHoRo=;
        b=rnNRQAtaYhTBknkYtarAdyqx4v8z1HOuY5NHrUKyVFMz4AYVWOj0oRuPbgNuBkQhvL
         3WNXWu3r0xkAcfDin4EgQzsevdsX8yc116ZfLzEqQ2r4RrLhAzTShX2R5/5aSJSPb9p6
         8E+aRKo1MLzlcRRoyVAXBf/mXbb1zVCLNi+EMheJiywIsi2HMWHoEuJ9MHBlLkWGbnK8
         eJKLVzIc7MTzajo95Cf8S7vM+zZQSXL2EFsGd0v3LHTNV6L5O7f37hmC/TIv4rs/fTau
         mx/RVgCqiGNvh9iXgw0A5GIwQOIf6DDAGgb5z5XqaMO4D9tyd2oazZ51bLb24UJn5oZJ
         +Kjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772453793; x=1773058593;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ItUpgUFj2F6zsI17uU7C48rT9A5lTVBWK7LNUTSHoRo=;
        b=ftLaKNXwLzEG7KTuDeaUYcxCqdJ/KdlvGbFF5ZQJpEe5pTARxMAigDl4F9oTV3GmRk
         tt4Bwa33u2cc+s97lp3TCZXCoEpmCt/XJBPWbhLL2h/VhehihsDs+7u/hp8zPEErN1yu
         chBqJXjh8uCjosN6NoeEMn14B8ufuBGfvBalpbDFU5B4CFA5dbzxbfWnu3MnuCcRlHyv
         Y2RpjtkFm/ddzUTwJsyA/wA0wg/HFVtXQ4TIaAbTX5XC9sGTBGWrhEm3BJBsYsbJ1KSt
         Xv88rpy7Nyd0jFgH/SDh1e8YCb4Zeq3kxSpz+A3RIzz4sXhAZKOqa8VFVCswDniQpyz1
         bcAg==
X-Forwarded-Encrypted: i=2; AJvYcCV2/t62rdz5sSUqYyMgeOd0lvF2RcidD1Ow/DHpgDsAghuG6MtUqAD1JQhDR04xA0hlM6oi8A==@lfdr.de
X-Gm-Message-State: AOJu0YxssrRdi6F7S80h1/CK0p6IF2ilvD9VYlk1/lawtJBg6cLrQXJx
	8Qdlx/PwkHqup45gAfBJQlbUz5MyrXGM0TnKcm+jvctszm+pGs1JAgWg
X-Received: by 2002:a05:600c:1d06:b0:476:4efc:8ed4 with SMTP id 5b1f17b1804b1-483c9bb1e14mr205508755e9.11.1772453792994;
        Mon, 02 Mar 2026 04:16:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gf/ND33KnXrV86M5tH267R6CRyozKgtaozBJJxvTfKKw=="
Received: by 2002:a05:600c:4f14:b0:480:6ce4:66eb with SMTP id
 5b1f17b1804b1-483bf08fa25ls41104505e9.2.-pod-prod-09-eu; Mon, 02 Mar 2026
 04:16:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXfy1SfEFXv6iIFqOqphq/jooLCqeCecSkjBIa0MnJwi1a55IAV45/kE4Yaraukeoq0WnudwJI5Kis=@googlegroups.com
X-Received: by 2002:a05:600c:4591:b0:482:eec4:74c with SMTP id 5b1f17b1804b1-483c9bf0b3cmr192188135e9.22.1772453790630;
        Mon, 02 Mar 2026 04:16:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772453790; cv=none;
        d=google.com; s=arc-20240605;
        b=RQPHWImu7bzlsaoOqpqBqSxVT14LMnby6TaRN558j3KWeeP4wyYIBi9+qjColWZOV+
         IJfeW/SoxIB9Opw7A2i3jviqzgsb8rio7e5tXFyAf/w/xP5bwui8eIso+Htd5zSUWpv8
         6U0W61bSTPxBHbXzC0q+hCrYf1TRqZCf5wqyImhxjvdi0qKF/xmI8QhV8oIt2T1C6psa
         fzWh6wLx1t2ygWWvYOzQzkGkNGG2JfW3gke1FiCoNqqx6drx6rHmiLsTkGauSHarPPED
         +hRy+n60aJJxG1Sc+38LIsUDot+Tqqt0IEyc7Rl4x6M3++SRCp71iK7WaAviIYzngxQs
         tQFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=3ACTRy9m9DGTE1uM5/GGdszxPz1+1eryLvgjpWOtGUc=;
        fh=uA4qfsZmQWyYN0l3fIJv81FPpZkj+MfFg4D/6z7hd+Y=;
        b=CGEfKkT2mUiLlAwOQC2TOFRLqwwc/h7WjOcTR+Q9rx1N+YuwmBBLTcMQ2Qm4OUQitN
         JCE1fbeeJiZxtG2aDpmYoaXkbzXCDtNd70q4OBFPwd/MDuhNL9O2wtEr/ZlYTT+F5M3Z
         P+MXHlHB15G16PviWrX+F+0oErIWZTxBM4XqExQbDXVzQ2ygZbH+dYoSn2Qrqx3TaiSk
         ITc0498ZMeVmnXGDFzx4zU7Q0HTFvHeZ6A9ci0cZDcUONWhWBKT5SokSouWE5lWGfEM+
         mW1959VSbVCxAiWhTw8OsiGik/n4kt7d5HTk8D7UZ/dERCaq0i4L3dOi+91JpBGyRpgh
         CTtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=QcxENO+B;
       spf=pass (google.com: domain of vbabka@suse.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=vbabka@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-483c3addb13si3024855e9.0.2026.03.02.04.16.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2026 04:16:30 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-43992e06b9eso215494f8f.0
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2026 04:16:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUdGCnQbEzxbmx/EsmX81inU/YwdqRjHqEmK7M88u1PC74Ahwm0C/oG38HG3+5y3dSEsiJGwVI1LW8=@googlegroups.com
X-Gm-Gg: ATEYQzztFNUPP8uxDbbXnCuRIhRgdFUynTHnKgTgFsi3As1pZ/oowDkGfkp33tPh/h5
	0O2eonp4MLwsojH7rpMh77Y7lLBDwafSXuKQB1NP/OQzUodS2Zb8//zI5qVlyJqLBIXbPoMWhoN
	T4im5NPN/SGDZQ+8V/+ZAlLfJ4VxMWZg8xrlqUpU7uRosYlf8lBd7fJa2ZkssqUDsWLDuaPgI5/
	8ToygaDb8f8KnnuKkXh95AE1ZaeJYL465DVMB2UmtuDKYTy9lH1OPxz45ZWrsCuPlGnNG9/j94n
	N6MgoW2+9eww26vi6imsnlIaJ3XISGSARpUFgK73abe3TN2yjgpB48RWBB7l5xW5wKP5XaqhMxU
	EwLQ8qaXAkd8d9xbmxYg3n9Mq1w685iagazRGetukfvyqT76W3ff5163kpbZ3PUKBij3b56Y8NJ
	jML+onue2pKvlPbFiO0UtmMvZwCzRLVXw6Ty+iYTGwN/9o3tZhTiP9FG9ETQ==
X-Received: by 2002:a05:6000:4012:b0:439:bdd7:4258 with SMTP id ffacd0b85a97d-439bdd743a8mr626841f8f.7.1772453789875;
        Mon, 02 Mar 2026 04:16:29 -0800 (PST)
Received: from ?IPV6:2001:1a48:8:903:1ed6:4f73:ce38:f9d4? ([2001:1a48:8:903:1ed6:4f73:ce38:f9d4])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-439b130abfasm11790112f8f.34.2026.03.02.04.16.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2026 04:16:29 -0800 (PST)
Message-ID: <9b0ae03c-8e93-422d-835c-3d4148a7550f@suse.com>
Date: Mon, 2 Mar 2026 13:16:28 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 08/22] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Content-Language: en-US
To: "D, Suneeth" <Suneeth.D@amd.com>, Vlastimil Babka <vbabka@suse.cz>,
 Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-8-041323d506f7@suse.cz>
 <df5a0dfd-01b7-48a9-8936-4d5e271e68e6@amd.com>
From: "'Vlastimil Babka' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <df5a0dfd-01b7-48a9-8936-4d5e271e68e6@amd.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=QcxENO+B;       spf=pass
 (google.com: domain of vbabka@suse.com designates 2a00:1450:4864:20::433 as
 permitted sender) smtp.mailfrom=vbabka@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Vlastimil Babka <vbabka@suse.com>
Reply-To: Vlastimil Babka <vbabka@suse.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_FROM(0.00)[bncBDVOZGGKQUGBBIH7SXGQMGQEZEVPA6I];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	HAS_REPLYTO(0.00)[vbabka@suse.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,perf.data:url,suse.cz:email,suse.com:mid,suse.com:replyto,oracle.com:email,mail-wm1-x33a.google.com:helo,mail-wm1-x33a.google.com:rdns]
X-Rspamd-Queue-Id: 27C021D8224
X-Rspamd-Action: no action

On 3/2/26 12:56, D, Suneeth wrote:
> Hi Vlastimil Babka,

Hi Suneeth!

> On 1/23/2026 12:22 PM, Vlastimil Babka wrote:
>> Before we enable percpu sheaves for kmalloc caches, we need to make sure
>> kmalloc_nolock() and kfree_nolock() will continue working properly and
>> not spin when not allowed to.
>> 
>> Percpu sheaves themselves use local_trylock() so they are already
>> compatible. We just need to be careful with the barn->lock spin_lock.
>> Pass a new allow_spin parameter where necessary to use
>> spin_trylock_irqsave().
>> 
>> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
>> for now it will always fail until we enable sheaves for kmalloc caches
>> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
>> 
> 
> We run will-it-scale micro-benchmark as part of our weekly CI for Kernel 
> Performance Regression testing between a stable vs rc kernel. We 

Great!

> observed will-it-scale-thread-page_fault3 variant was regressing with 
> 9-11% on AMD platforms (Turin and Bergamo)between the kernels v6.19 and 
> v7.0-rc1. Bisecting further landed me onto this commit
> f1427a1d64156bb88d84f364855c364af6f67a3b (slab: make percpu sheaves 
> compatible with kmalloc_nolock()/kfree_nolock()) as the first bad 
> commit. The following were the machines' configuration and test 
> parameters used:-
> 
> Model name:           AMD EPYC 128-Core Processor [Bergamo]
> Thread(s) per core:   2
> Core(s) per socket:   64
> Socket(s):            1
> Total online memory:  256G
> 
> Model name:           AMD EPYC 64-Core Processor [Turin]
> Thread(s) per core:   2
> Core(s) per socket:   64
> Socket(s):            2
> Total online memory:  258G
> 
> Test params:
> ------------
>       nr_task: [1 8 64 128 192 256]
>       mode: thread
>       test: page_fault3
>       kpi: per_thread_ops
>       cpufreq_governor: performance
> 
> The following are the stats after bisection:-
> (the KPI used here is per_thread_ops)
> 
> kernel_versions      					 per_thread_ops
> ---------------      					 ---------------
> v6.19.0 (baseline)                                     - 2410188
> v7.0-rc1 	                                       - 2151474
> v6.19-rc5-f1427a1d6415                                 - 2263974
> v6.19-rc5-f3421f8d154c (one commit before culprit)     - 2323263

I suspect the bisection gave a wrong result here due to noise. The commit
f1427a1d6415 should not affect anything in this benchmark. The values for
the commit and its parent are rather close to each other, and in the middle
of the range between v6.19.0 and v7.0-rc1 numbers.

What I rather suspect is something we noticed recently - v7.0-rc1 enables
sheaves for all caches, but also removes cpu (partial) slabs. In v6.19 only
two caches (vma and maple nodes) have sheaves, but also cpu (partial) slabs
still behind them, effectively caching many more objects than with either
mechanism alone. will-it-scale-thread-page_fault3 is a benchmark that is
very sensitive to vma and maple nodes allocation performance and notice this.

So unfortunately we now see it as a regression between 6.19 and v7, but it
should be just offsetting an improvement in 6.18 when sheaves were
introduced for vma and maple nodes with this unintended ~double caching.

> Recreation steps:
> -----------------
> 1) git clone https://github.com/antonblanchard/will-it-scale.git
> 2) git clone https://github.com/intel/lkp-tests.git
> 3) cd will-it-scale && git apply
> lkp-tests/programs/will-it-scale/pkg/will-it-scale.patch
> 4) make
> 5) python3 runtest.py page_fault3 25 thread 0 0 1 8 64 128 192 256
> 
> NOTE: [5] is specific to machine's architecture. starting from 1 is the
> array of no.of tasks that you'd wish to run the testcase which here is
> no.cores per CCX, per NUMA node/ per Socket, nr_threads.
> 
> I also ran the micro-benchmark with ./tools/testing/perf record and
> following is the diff collected:-
> 
> # ./perf diff perf.data.old perf.data
> Warning:
> 4 out of order events recorded.
> # Event 'cpu/cycles/P'
> #
> # Baseline  Delta Abs  Shared Object          Symbol
> # ........  .........  ..................... 
> ...................................................
> #
>                +11.95%  [kernel.kallsyms]      [k] folio_pte_batch
>                +10.30%  [kernel.kallsyms]      [k] 
> native_queued_spin_lock_slowpath
>                 +9.91%  [kernel.kallsyms]      [k] __block_write_begin_int
>       0.00%     +8.56%  [kernel.kallsyms]      [k] clear_page_erms
>       7.71%     -7.71%  [kernel.kallsyms]      [k] delay_halt
>                 +6.84%  [kernel.kallsyms]      [k] block_dirty_folio
>       1.58%     +4.90%  [kernel.kallsyms]      [k] unmap_page_range
>       0.00%     +4.78%  [kernel.kallsyms]      [k] folio_remove_rmap_ptes
>       3.17%     -3.17%  [kernel.kallsyms]      [k] __vmf_anon_prepare
>       0.00%     +3.09%  [kernel.kallsyms]      [k] ext4_page_mkwrite
>                 +2.32%  [kernel.kallsyms]      [k] ext4_dirty_folio
>       0.00%     +2.01%  [kernel.kallsyms]      [k] vm_normal_page
>       0.00%     +1.93%  [kernel.kallsyms]      [k] set_pte_range
>                 +1.84%  [kernel.kallsyms]      [k] block_commit_write
>                 +1.82%  [kernel.kallsyms]      [k] mod_node_page_state
>                 +1.68%  [kernel.kallsyms]      [k] lruvec_stat_mod_folio
>                 +1.56%  [kernel.kallsyms]      [k] mod_memcg_lruvec_state
>       1.40%     -1.39%  [kernel.kallsyms]      [k] mod_memcg_state
>                 +1.38%  [kernel.kallsyms]      [k] folio_add_file_rmap_ptes
>       5.01%     -0.87%  page_fault3_threads    [.] testcase
>                 +0.84%  [kernel.kallsyms]      [k] tlb_flush_rmap_batch
>                 +0.83%  [kernel.kallsyms]      [k] mark_buffer_dirty
>       1.66%     -0.75%  [kernel.kallsyms]      [k] flush_tlb_mm_range
>                 +0.72%  [kernel.kallsyms]      [k] css_rstat_updated
>       0.60%     -0.60%  [kernel.kallsyms]      [k] osq_unlock
>                 +0.57%  [kernel.kallsyms]      [k] _raw_spin_unlock
>                 +0.55%  [kernel.kallsyms]      [k] perf_iterate_ctx
>                 +0.54%  [kernel.kallsyms]      [k] __rcu_read_lock
>       0.11%     +0.53%  [kernel.kallsyms]      [k] osq_lock
>                 +0.46%  [kernel.kallsyms]      [k] finish_fault
>       0.46%     -0.46%  [kernel.kallsyms]      [k] do_wp_page
>                 +0.45%  [kernel.kallsyms]      [k] pte_val
>       1.10%     -0.41%  [kernel.kallsyms]      [k] filemap_fault
>                 +0.39%  [kernel.kallsyms]      [k] native_set_pte
>                 +0.36%  [kernel.kallsyms]      [k] rwsem_spin_on_owner
>       0.28%     -0.28%  [kernel.kallsyms]      [k] mas_topiary_replace
>                 +0.28%  [kernel.kallsyms]      [k] _raw_spin_lock_irqsave
>                 +0.27%  [kernel.kallsyms]      [k] percpu_counter_add_batch
>                 +0.27%  [kernel.kallsyms]      [k] memset
>       0.00%     +0.24%  [kernel.kallsyms]      [k] mas_walk
>       0.23%     -0.23%  [kernel.kallsyms]      [k] __pmd_alloc
>       0.23%     -0.22%  [kernel.kallsyms]      [k] rcu_core
>                 +0.21%  [kernel.kallsyms]      [k] __rcu_read_unlock
>       0.04%     +0.19%  [kernel.kallsyms]      [k] ext4_da_get_block_prep
>                 +0.19%  [kernel.kallsyms]      [k] lock_vma_under_rcu
>       0.01%     +0.19%  [kernel.kallsyms]      [k] prep_compound_page
>                 +0.18%  [kernel.kallsyms]      [k] filemap_get_entry
>                 +0.17%  [kernel.kallsyms]      [k] folio_mark_dirty
> 
> Would be happy to help with further testing and providing additional 
> data if required.
> 
> Thanks,
> Suneeth D
> 
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
>> Reviewed-by: Hao Li <hao.li@linux.dev>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>   mm/slub.c | 82 ++++++++++++++++++++++++++++++++++++++++++++++-----------------
>>   1 file changed, 60 insertions(+), 22 deletions(-)
>> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 41e1bf35707c..4ca6bd944854 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -2889,7 +2889,8 @@ static void pcs_destroy(struct kmem_cache *s)
>>   	s->cpu_sheaves = NULL;
>>   }
>>   
>> -static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
>> +static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn,
>> +					       bool allow_spin)
>>   {
>>   	struct slab_sheaf *empty = NULL;
>>   	unsigned long flags;
>> @@ -2897,7 +2898,10 @@ static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
>>   	if (!data_race(barn->nr_empty))
>>   		return NULL;
>>   
>> -	spin_lock_irqsave(&barn->lock, flags);
>> +	if (likely(allow_spin))
>> +		spin_lock_irqsave(&barn->lock, flags);
>> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
>> +		return NULL;
>>   
>>   	if (likely(barn->nr_empty)) {
>>   		empty = list_first_entry(&barn->sheaves_empty,
>> @@ -2974,7 +2978,8 @@ static struct slab_sheaf *barn_get_full_or_empty_sheaf(struct node_barn *barn)
>>    * change.
>>    */
>>   static struct slab_sheaf *
>> -barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>> +barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty,
>> +			 bool allow_spin)
>>   {
>>   	struct slab_sheaf *full = NULL;
>>   	unsigned long flags;
>> @@ -2982,7 +2987,10 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>>   	if (!data_race(barn->nr_full))
>>   		return NULL;
>>   
>> -	spin_lock_irqsave(&barn->lock, flags);
>> +	if (likely(allow_spin))
>> +		spin_lock_irqsave(&barn->lock, flags);
>> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
>> +		return NULL;
>>   
>>   	if (likely(barn->nr_full)) {
>>   		full = list_first_entry(&barn->sheaves_full, struct slab_sheaf,
>> @@ -3003,7 +3011,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>>    * barn. But if there are too many full sheaves, reject this with -E2BIG.
>>    */
>>   static struct slab_sheaf *
>> -barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
>> +barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
>> +			bool allow_spin)
>>   {
>>   	struct slab_sheaf *empty;
>>   	unsigned long flags;
>> @@ -3014,7 +3023,10 @@ barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
>>   	if (!data_race(barn->nr_empty))
>>   		return ERR_PTR(-ENOMEM);
>>   
>> -	spin_lock_irqsave(&barn->lock, flags);
>> +	if (likely(allow_spin))
>> +		spin_lock_irqsave(&barn->lock, flags);
>> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
>> +		return ERR_PTR(-EBUSY);
>>   
>>   	if (likely(barn->nr_empty)) {
>>   		empty = list_first_entry(&barn->sheaves_empty, struct slab_sheaf,
>> @@ -5008,7 +5020,8 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>>   		return NULL;
>>   	}
>>   
>> -	full = barn_replace_empty_sheaf(barn, pcs->main);
>> +	full = barn_replace_empty_sheaf(barn, pcs->main,
>> +					gfpflags_allow_spinning(gfp));
>>   
>>   	if (full) {
>>   		stat(s, BARN_GET);
>> @@ -5025,7 +5038,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>>   			empty = pcs->spare;
>>   			pcs->spare = NULL;
>>   		} else {
>> -			empty = barn_get_empty_sheaf(barn);
>> +			empty = barn_get_empty_sheaf(barn, true);
>>   		}
>>   	}
>>   
>> @@ -5165,7 +5178,8 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
>>   }
>>   
>>   static __fastpath_inline
>> -unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>> +unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
>> +				 void **p)
>>   {
>>   	struct slub_percpu_sheaves *pcs;
>>   	struct slab_sheaf *main;
>> @@ -5199,7 +5213,8 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>>   			return allocated;
>>   		}
>>   
>> -		full = barn_replace_empty_sheaf(barn, pcs->main);
>> +		full = barn_replace_empty_sheaf(barn, pcs->main,
>> +						gfpflags_allow_spinning(gfp));
>>   
>>   		if (full) {
>>   			stat(s, BARN_GET);
>> @@ -5700,7 +5715,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>>   	gfp_t alloc_gfp = __GFP_NOWARN | __GFP_NOMEMALLOC | gfp_flags;
>>   	struct kmem_cache *s;
>>   	bool can_retry = true;
>> -	void *ret = ERR_PTR(-EBUSY);
>> +	void *ret;
>>   
>>   	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
>>   				      __GFP_NO_OBJ_EXT));
>> @@ -5731,6 +5746,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>>   		 */
>>   		return NULL;
>>   
>> +	ret = alloc_from_pcs(s, alloc_gfp, node);
>> +	if (ret)
>> +		goto success;
>> +
>> +	ret = ERR_PTR(-EBUSY);
>> +
>>   	/*
>>   	 * Do not call slab_alloc_node(), since trylock mode isn't
>>   	 * compatible with slab_pre_alloc_hook/should_failslab and
>> @@ -5767,6 +5788,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>>   		ret = NULL;
>>   	}
>>   
>> +success:
>>   	maybe_wipe_obj_freeptr(s, ret);
>>   	slab_post_alloc_hook(s, NULL, alloc_gfp, 1, &ret,
>>   			     slab_want_init_on_alloc(alloc_gfp, s), size);
>> @@ -6087,7 +6109,8 @@ static void __pcs_install_empty_sheaf(struct kmem_cache *s,
>>    * unlocked.
>>    */
>>   static struct slub_percpu_sheaves *
>> -__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>> +__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>> +			bool allow_spin)
>>   {
>>   	struct slab_sheaf *empty;
>>   	struct node_barn *barn;
>> @@ -6111,7 +6134,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>>   	put_fail = false;
>>   
>>   	if (!pcs->spare) {
>> -		empty = barn_get_empty_sheaf(barn);
>> +		empty = barn_get_empty_sheaf(barn, allow_spin);
>>   		if (empty) {
>>   			pcs->spare = pcs->main;
>>   			pcs->main = empty;
>> @@ -6125,7 +6148,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>>   		return pcs;
>>   	}
>>   
>> -	empty = barn_replace_full_sheaf(barn, pcs->main);
>> +	empty = barn_replace_full_sheaf(barn, pcs->main, allow_spin);
>>   
>>   	if (!IS_ERR(empty)) {
>>   		stat(s, BARN_PUT);
>> @@ -6133,7 +6156,8 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>>   		return pcs;
>>   	}
>>   
>> -	if (PTR_ERR(empty) == -E2BIG) {
>> +	/* sheaf_flush_unused() doesn't support !allow_spin */
>> +	if (PTR_ERR(empty) == -E2BIG && allow_spin) {
>>   		/* Since we got here, spare exists and is full */
>>   		struct slab_sheaf *to_flush = pcs->spare;
>>   
>> @@ -6158,6 +6182,14 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>>   alloc_empty:
>>   	local_unlock(&s->cpu_sheaves->lock);
>>   
>> +	/*
>> +	 * alloc_empty_sheaf() doesn't support !allow_spin and it's
>> +	 * easier to fall back to freeing directly without sheaves
>> +	 * than add the support (and to sheaf_flush_unused() above)
>> +	 */
>> +	if (!allow_spin)
>> +		return NULL;
>> +
>>   	empty = alloc_empty_sheaf(s, GFP_NOWAIT);
>>   	if (empty)
>>   		goto got_empty;
>> @@ -6200,7 +6232,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>>    * The object is expected to have passed slab_free_hook() already.
>>    */
>>   static __fastpath_inline
>> -bool free_to_pcs(struct kmem_cache *s, void *object)
>> +bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
>>   {
>>   	struct slub_percpu_sheaves *pcs;
>>   
>> @@ -6211,7 +6243,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object)
>>   
>>   	if (unlikely(pcs->main->size == s->sheaf_capacity)) {
>>   
>> -		pcs = __pcs_replace_full_main(s, pcs);
>> +		pcs = __pcs_replace_full_main(s, pcs, allow_spin);
>>   		if (unlikely(!pcs))
>>   			return false;
>>   	}
>> @@ -6333,7 +6365,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
>>   			goto fail;
>>   		}
>>   
>> -		empty = barn_get_empty_sheaf(barn);
>> +		empty = barn_get_empty_sheaf(barn, true);
>>   
>>   		if (empty) {
>>   			pcs->rcu_free = empty;
>> @@ -6453,7 +6485,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>>   		goto no_empty;
>>   
>>   	if (!pcs->spare) {
>> -		empty = barn_get_empty_sheaf(barn);
>> +		empty = barn_get_empty_sheaf(barn, true);
>>   		if (!empty)
>>   			goto no_empty;
>>   
>> @@ -6467,7 +6499,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>>   		goto do_free;
>>   	}
>>   
>> -	empty = barn_replace_full_sheaf(barn, pcs->main);
>> +	empty = barn_replace_full_sheaf(barn, pcs->main, true);
>>   	if (IS_ERR(empty)) {
>>   		stat(s, BARN_PUT_FAIL);
>>   		goto no_empty;
>> @@ -6719,7 +6751,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>>   
>>   	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
>>   	    && likely(!slab_test_pfmemalloc(slab))) {
>> -		if (likely(free_to_pcs(s, object)))
>> +		if (likely(free_to_pcs(s, object, true)))
>>   			return;
>>   	}
>>   
>> @@ -6980,6 +7012,12 @@ void kfree_nolock(const void *object)
>>   	 * since kasan quarantine takes locks and not supported from NMI.
>>   	 */
>>   	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
>> +
>> +	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())) {
>> +		if (likely(free_to_pcs(s, x, false)))
>> +			return;
>> +	}
>> +
>>   	do_slab_free(s, slab, x, x, 0, _RET_IP_);
>>   }
>>   EXPORT_SYMBOL_GPL(kfree_nolock);
>> @@ -7532,7 +7570,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>>   		size--;
>>   	}
>>   
>> -	i = alloc_from_pcs_bulk(s, size, p);
>> +	i = alloc_from_pcs_bulk(s, flags, size, p);
>>   
>>   	if (i < size) {
>>   		/*
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9b0ae03c-8e93-422d-835c-3d4148a7550f%40suse.com.
