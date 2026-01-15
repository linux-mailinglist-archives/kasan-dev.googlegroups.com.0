Return-Path: <kasan-dev+bncBDXYDPH3S4OBBGX4UPFQMGQELEEOOXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AC9ED2507F
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 15:47:56 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-59b78adfc09sf1012155e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 06:47:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768488475; cv=pass;
        d=google.com; s=arc-20240605;
        b=cEQA6BmOhyu3Yw0YCTYazouM20qxN3rmLxJS7q4bauHr4grexCnUKZgOLk3bWt3aE4
         pnlRxsmkk3SQIBVqBmSQJLpM7B87+BuctLChQMxH+berqmPBdVyKuJam8St1e8axGxIK
         UfLjme9yBddiO3zVcvS7VgUcBGUm59wCc+wzF93dGNaRGtKquyBcPKqBmRJaDmsBRDj4
         VCCsueMV3POkcMTQYRo/Yc3otJwvJc0qVff7GddOAsajcMXVWY4ktdnMkyWk7exob5Mj
         EHbm4c6f4+XiAnYl/ivyKYUYIFyAIqQs8i0Jz/6OpJnLRhAxT+AzRlXU2Z7r9UnoXY8J
         2Tig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=7bnYkK7+nS9hc51YeW1kkqcuPFblWRJ4ysb5kdIA7dI=;
        fh=zvAu5mheg2czs87iEplDuYeRbJDOduCFLy9Ch9A3L7Y=;
        b=AZqNMraZnUZUT7wLOksaR2NTACJ1JfKYRLXbITsJH6KRf36fKDD5zzGNLrLeF2YhFz
         Wk2F0GuBv+Wvf9qB63ydlB6X7GLVcFAuNMdj60dYfN10MCPbw11z0q0kktlcXwsPoj0X
         wa3ap0OxcgsA7ZJmnacAqE+pdU5FyNWJvpiGmahcfTmCqPha+9DP1x+Waa1MvqOtFSAh
         G47YCmOsy9PyXNKxguCd7RWaAvJePVzDlBqFSFUXYxziflTXO9QQy6JzzcRRozNROmY8
         kEllntA2RNNqgRVK+vmfsBFMECK61rw9MSLTehlUQuXmDIyTpsojjknt7CQajZTWPBYL
         ojVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ao7OxHHt;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ao7OxHHt;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768488475; x=1769093275; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7bnYkK7+nS9hc51YeW1kkqcuPFblWRJ4ysb5kdIA7dI=;
        b=eExm0IH9e+1h0Zzu6FU+8vjJqyvNC3T4+GH4EppzEWfzSSAYY4+j27gqi35ZlvkMF5
         tZijQ+TGyMf+D70e+g8toNw8yjzaSYUH2+H7rMI0o69/rZA2OatlDXtlWwHTRezDMWTs
         GbMAuN9Xykv0yVM9YVFJy/DP+jjR5fcv5S2jTdZ8Db7eZbre5M0VWv8P/FuaUabwI20i
         vfTPEZDZO0vA/iZNmNrhJkvUUU5q2PDBXE8EbQMT+mWT2RsxNRzkA7fhvp09DZoag+US
         SK3C3ydB4eXPSQFlnzMBEmkgY8c5hFM+/aGWpWhuU2ncpH6dzbWnLOY6YPdxfLlxIS2k
         AieA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768488475; x=1769093275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7bnYkK7+nS9hc51YeW1kkqcuPFblWRJ4ysb5kdIA7dI=;
        b=hUqvofCwMqCv5teCHIVJdBtwJy1+yq+S4tWxEpz/fILXMYE+XWDjhL9fo+0n1elY5J
         /NivCnsmYQywBJp61zSvrJbWwhlCNMcc3lnJUYbFJc8M43Ihg6Q4vI+oA+vDr0kwWBAj
         kbldPsd1tey4wJ+cgv92upc9YVOZKy1JciJRWgTTwSz81KXudlu8MS1ZeAY5b1EWPVBT
         LH98im/ILOsk5k/ih2G00oHAYI+zc9mY/6bh+YQ8HJqIG19pLVde039Y4b8IkEwdaiPF
         Y5TNWXwPPoun3VqmrJ0u6eL2ftcd/UF9eUtv1VZ91av45NNtvTCtrnK753WXnLg/P998
         5VSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnNDw+qqorPOflk8qpVAMM/yW8l5+ffqEywaEKIuRWoUG+iu8YtRXuBiN+nlwmW8M+nhLcDQ==@lfdr.de
X-Gm-Message-State: AOJu0YwF3wh1oYXDgdXH1u7yLHtCxfIb6vXw9AC9pX8B3FnH1juoAiaF
	4qYJyc3Ka13LpfSutlqtmAv4kdiPWYGrzyWNDjSllEQ96Aw+2tnYQ6pG
X-Received: by 2002:a05:6512:2352:b0:595:81e1:2d00 with SMTP id 2adb3069b0e04-59ba0f2bd0cmr2311431e87.0.1768488474966;
        Thu, 15 Jan 2026 06:47:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HLTH0svS545AHoNomJK3lYjfogzYXumZwq+Lqn55as0A=="
Received: by 2002:a05:6512:1389:b0:59b:6cb9:a212 with SMTP id
 2adb3069b0e04-59ba6afde0als431122e87.0.-pod-prod-04-eu; Thu, 15 Jan 2026
 06:47:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX2WkZY7P8WUIpbKL1MRnOGqMvjkLI1NwVXaFojlKcRcKgRJqJYPByGgprKqcZFcKp30jqIUEItTws=@googlegroups.com
X-Received: by 2002:a05:6512:b0d:b0:59b:9ad9:af44 with SMTP id 2adb3069b0e04-59ba0f883afmr1755245e87.29.1768488472119;
        Thu, 15 Jan 2026 06:47:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768488472; cv=none;
        d=google.com; s=arc-20240605;
        b=KZdBV/cQ/ef9clG8LtTXRN+i6SKUMdCENm2gs0knV9OJfkvhjKfSW2FsvS4NmgZQLj
         w9mqSoxuli9Fpf018KDX09MkCSAWjbyBof56JdVmSXggPHEBTcq8BB3vVrUs7f+4eH+F
         ei7tUOKtpCP4nxqLFfW8Y5RqPlMVF0IF4LJ2PE1fPH4V+TNsg0UAJaVCnJU6OkQIW6Uw
         H6aMj/r2pSETZLtwVbVxm7COvYSZ6oUbRbYw+sQxd16lGWpzCQgLZ9DWWE+i+IaLk6M8
         DET4QkDW39nut57s2ZQv5Fc8W9vSKt5+5lJU9fVsutrkBS8e9zPjbzi1X6BXWD3htFXP
         MKLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=MU58J6Us5GE6JKgk7JVJzcX719EO56GJyTLxcovO0Lo=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=cCE6tNaxCC1LbbFd/v3LYid+PC+IK0i9ZkLiMDfBwVC65mlzmAiYKiyD6NA6ML+p4V
         ZO49jJNZYfVQXNae7L/IcCGS8dqk0BaiekrKrrE0cX28fyqk0Wxek8SDX4cHNfSNC+9C
         5LvLzpln9xOhtnO8U4pfPBgLsWVKHYIJU4iNero43nYSCgUtaXjMRIZq+ZB6aG9M5pQC
         vZbrGROLnxXtAhozzT18UAmPE33UrI5Sz8a6uXF7lEpGwJd3CuO3xt0c6ZSK13Y5+epc
         BGVvDM7NO570cU3nytR4aDo0Dj1ECSP9TImap65tZjtXFUAW0rx35/7j/Tv/+ZhnkV4W
         o7QQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ao7OxHHt;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ao7OxHHt;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59ba102f519si93148e87.3.2026.01.15.06.47.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 06:47:52 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5EF7D5BCF8;
	Thu, 15 Jan 2026 14:47:51 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3D2C83EA63;
	Thu, 15 Jan 2026 14:47:51 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id SIeZDhf+aGmCeQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Jan 2026 14:47:51 +0000
Message-ID: <51761d10-2ad4-4c5c-8bb1-5463d42aa31e@suse.cz>
Date: Thu, 15 Jan 2026 15:47:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 12/20] slab: remove defer_deactivate_slab()
Content-Language: en-US
To: Hao Li <hao.li@linux.dev>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-12-98225cfb50cf@suse.cz>
 <sofeahffu5jj5xbre422lelbisfclwdul2i42j7odth3j4yzil@nyxfavdhwmuz>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <sofeahffu5jj5xbre422lelbisfclwdul2i42j7odth3j4yzil@nyxfavdhwmuz>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[17];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ao7OxHHt;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=ao7OxHHt;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/15/26 15:09, Hao Li wrote:
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -3248,7 +3248,7 @@ static struct slab *new_slab(struct kmem_cache *s, gfp_t flags, int node)
>>  		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
>>  }
>>  
>> -static void __free_slab(struct kmem_cache *s, struct slab *slab)
>> +static void __free_slab(struct kmem_cache *s, struct slab *slab, bool allow_spin)
>>  {
>>  	struct page *page = slab_page(slab);
>>  	int order = compound_order(page);
>> @@ -3262,11 +3262,20 @@ static void __free_slab(struct kmem_cache *s, struct slab *slab)
>>  	free_frozen_pages(page, order);
> 
> Here we missed using the newly added allow_spin.
> It should call free_frozen_pages_nolock() when !allow_spin.

Uh damn, the first RFC had it correct. Where did I screw up with git? Sigh.
Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/51761d10-2ad4-4c5c-8bb1-5463d42aa31e%40suse.cz.
