Return-Path: <kasan-dev+bncBDXYDPH3S4OBBSFZY7FQMGQE3W4CAXY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id sBzCEcrccWk+MgAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBSFZY7FQMGQE3W4CAXY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:16:10 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C141B62E85
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:16:09 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b796a0d0asf401717e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 00:16:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769069769; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xl9Z0WtfgRXuxepK867cO0IZ2rWH+ZvG42Ob3rQVqI08U635cPSttloWTwodPmwEBt
         fjGGe5B7QU+yNtArsIUwStfuJaQhbg0Y9wApZbjvVtJeLegA3XEoNl37FPhDSTOFbSK0
         rCoWsFtOYVGKb/3M+e+/mshhqWQqBhvI4HEyw+WzQ5EVroBP0p7JaK54aEDckibq88dP
         RP6lRRJIsFJmeQk2gOkeWzyXsjophDbAYTKWZmQgn9VTmd0jOoAmAXAMJwE0grjGILuZ
         js4j8GnokK6pm0dQYTmqWInIdJ5bxoUUpORkuU2x6NoRHlTVuth/Db18kejrs5GHA/+t
         9lXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=Dp3D+KfRdkkZg/VpbCewYUu6Fa3kaVv84SD7jCZmbDc=;
        fh=S4AmcGVY0+VnayG3OYb6txP2qozOm6TbJx/ZW/8LH38=;
        b=QMMCJVVsRZRfSxKF/cnVhce8Cy6MA6QJ5ruxHXiA8AhWg9vwNlkqwnjYUCymeHiHuh
         bWFziYCr4o10H30YHdDzYu/oN6Zm9MDZiUAW5JAle6KRI0e257tuYvf4cZLK9he4REzV
         f8j32q++gEfn7XqBkZMKt2HvGCusj7xlKqfpSCt/wcY60Ba+Yila8+VKGUJYvmMNnZSz
         zCRpI9Ky2Sd+PNIZIEwwYCW+jZ9fQtp3vv7Wj11rHxZNItgBiUOjTbv7SsBTWu8z5RHl
         eYysallqA2WekjN0qxBS21SCUWyIzgk9UmidYQm1W2XPMXQYKTLvHJq4PEurITMD/PPM
         vbFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="T//lM8Gz";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FejGHDEr;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769069769; x=1769674569; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Dp3D+KfRdkkZg/VpbCewYUu6Fa3kaVv84SD7jCZmbDc=;
        b=t/zXKRVSmfTB3L4Su/vuEhImNn/0HFQAhbWMdwumRq9DLj+JF9ymKjCmDKzDoDA4H1
         Tke7NiebcKaxil4Ln0rkr+Vw22nEgqKNevs2NiWeVve/W2Q3HTKT4TXneZ/Omx8KvtYS
         3DGoBZF1ZuqDTF4SnbZC8aRqu4oMDBnwLwTd25q5T803RBkt7CYk+48VjsVbt6igMEVy
         VEpextX3He7mV6tDVyvMezRmi4EH2oGINIQ0jtfHIVrIp62Ss6GcuO3CXwvCUvCYc3zt
         hvEPlQS9UxrYhOCYygWjgje+xo7dy2pbCsT/L14nY0Geo+MAwM2XQTDDORbS0XBRTb5s
         7Hag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769069769; x=1769674569;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Dp3D+KfRdkkZg/VpbCewYUu6Fa3kaVv84SD7jCZmbDc=;
        b=BrHl44qBT09yQmVwKl1ULgWCw8NUc0MA0HV50yBP88PKmw9s2KXHX1A55i7hJX83v1
         5zIvKuixkxMkPZzsDi1rCyJ7W60go/6rSAW2T99TYpzLfSFvvY9kbrvnGbUZ0xWe0LSf
         LC8ISfuReJ0lpg2S4GzHXQef+GzhtWX8ZOL8wYvotxD14eZ4XcH4WvTnLJy7KQmq+yqv
         pD02RazN3dfWRsKMtoiH5f+IJfwYBVuzxi/8tBjdLNGhS/nyNXj5NeDP9NxrYef/qSy1
         WwylwXWSf6fFRETGkriQyzjggUsY1AVEwbVTj96K/WRKEQVimLNQUGi5O1tGf0YGmwRY
         VfTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV31H7ITN32EdFPFp05Td99WnXgIxtJSlWjfGzt7aF1ZSJVqqef78RMCAGoNE6P9W0ReHDzUA==@lfdr.de
X-Gm-Message-State: AOJu0YwRIS/H5nUEtF3oO1zF0SXobyZ67UNtEm5TcjlUX5ureU7lievl
	nqanqYM0YW9DDCdJGiV/MX6XhZzwxAKXoHqfXQUC7J0xTzSFdV13MF6M
X-Received: by 2002:a05:6512:3ca2:b0:59d:dfd9:2724 with SMTP id 2adb3069b0e04-59ddfd92879mr322508e87.31.1769069768740;
        Thu, 22 Jan 2026 00:16:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eg4q1fF6GVHAm5X5YHho4OEyP3JuqxZOQzD6aGyMeEyw=="
Received: by 2002:a05:6512:2313:b0:59b:7a7f:906 with SMTP id
 2adb3069b0e04-59dd7980b88ls286511e87.1.-pod-prod-09-eu; Thu, 22 Jan 2026
 00:16:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUaxvd2JlGlU/LRGftmZ9vvDFl7+MVgJuL54Fk0UFwIgTqpBMmCinBHBhqaE9ORLIvgKtOHLxHmfUY=@googlegroups.com
X-Received: by 2002:ac2:4bd1:0:b0:59d:d551:885e with SMTP id 2adb3069b0e04-59dd55189cemr1151941e87.32.1769069765869;
        Thu, 22 Jan 2026 00:16:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769069765; cv=none;
        d=google.com; s=arc-20240605;
        b=GcJ7j7uq4j99rs5nA+K+kF47E15ZxisTmZ4z9ZkhyIlepJLJ/8rTnGsa78ChzW2HCt
         A5HcR9gu/+t8DcqgguHiqal8aD0dhQ7g9+X3cT0eJg2UeiNJv6mT3Pe9M7CWvt8fRNx/
         WPDwEEXhs+6KkssBf+b2oXYL6xDsMSpTLcodDGXNk2ZRysjz21TWafaKwWIPYuEShYsj
         gZQ1yaVBkVApSPpG3ZtiSn0UEEU9XgDoCDrexVfxOSFqcRwkPeVuB0/quDgSCOuN9bWg
         AAhjez9vqwrv+W2fv4RpVdF1c8GamGlk2cFxsFi0BjkBtPz71mUbOnEu0/kUaaChv6Y0
         Ez+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Zw7POV/9HzgQ7yJajz8n3KLlnlgcqjnTg/uCdgtJ8J0=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=jhnlEkhXzCRDlETxUj5ngGkV/GJnfIyJzVHx4eUsVS61tbueHuyTNFSJCfUU6ZxAfC
         Dd4I5RPmRscQ95gpheJ2XgLSHQz8fVPsIlVmDkNoSMiKgNBaNze5a3+UJFL//nroNajj
         Znm7iCOSstEXUtqaOk8cfaMltA5hzxx9BKyqhfNMoc2CweDHQGrI0o3mN+WqpECO//Sc
         YJal+c1lD7aCJRgkG5AXn501CIQTZPUjWxB3d3SEuVlVu1fu8LgQC8uhQHqSWkrS5+cF
         A16vcMP8rhzCADx8VT3OqEJLWsX3vaATkj+ecSj+DxmoGVaerO5/d0LX43h4NNA9TrQO
         hAZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="T//lM8Gz";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FejGHDEr;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59ddbd96f61si40506e87.2.2026.01.22.00.16.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 00:16:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D36A65BCC2;
	Thu, 22 Jan 2026 08:16:04 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B20D33EA63;
	Thu, 22 Jan 2026 08:16:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id DJObKcTccWlZWgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 22 Jan 2026 08:16:04 +0000
Message-ID: <3aa8d400-fa6a-48bd-b9f2-3bd6f37e523d@suse.cz>
Date: Thu, 22 Jan 2026 09:16:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 14/21] slab: simplify kmalloc_nolock()
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
 David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-14-5595cb000772@suse.cz>
 <aXGC_JRmz3ICjMHW@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aXGC_JRmz3ICjMHW@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="T//lM8Gz";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=FejGHDEr;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBSFZY7FQMGQE3W4CAXY];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email,oracle.com:email]
X-Rspamd-Queue-Id: C141B62E85
X-Rspamd-Action: no action

On 1/22/26 02:53, Harry Yoo wrote:
> On Fri, Jan 16, 2026 at 03:40:34PM +0100, Vlastimil Babka wrote:
>> The kmalloc_nolock() implementation has several complications and
>> restrictions due to SLUB's cpu slab locking, lockless fastpath and
>> PREEMPT_RT differences. With cpu slab usage removed, we can simplify
>> things:
>> 
>> - relax the PREEMPT_RT context checks as they were before commit
>>   a4ae75d1b6a2 ("slab: fix kmalloc_nolock() context check for
>>   PREEMPT_RT") and also reference the explanation comment in the page
>>   allocator
>> 
>> - the local_lock_cpu_slab() macros became unused, remove them
>> 
>> - we no longer need to set up lockdep classes on PREEMPT_RT
>> 
>> - we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
>>   since there's no lockless cpu freelist manipulation anymore
>> 
>> - __slab_alloc_node() can be called from kmalloc_nolock_noprof()
>>   unconditionally. It can also no longer return EBUSY. But trylock
>>   failures can still happen so retry with the larger bucket if the
>>   allocation fails for any reason.
>> 
>> Note that we still need __CMPXCHG_DOUBLE, because while it was removed
>> we don't use cmpxchg16b on cpu freelist anymore, we still use it on
>> slab freelist, and the alternative is slab_lock() which can be
>> interrupted by a nmi. Clarify the comment to mention it specifically.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
> 
> What a nice cleanup!
> 
> Looks good to me,
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

Thanks!

> with a nit below.
> 
>>  mm/slab.h |   1 -
>>  mm/slub.c | 144 +++++++++++++-------------------------------------------------
>>  2 files changed, 29 insertions(+), 116 deletions(-)
>> 
>> diff --git a/mm/slab.h b/mm/slab.h
>> index 4efec41b6445..e9a0738133ed 100644
>> --- a/mm/slab.h
>> +++ b/mm/slab.h
>> @@ -5268,10 +5196,11 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>>  	if (!(s->flags & __CMPXCHG_DOUBLE) && !kmem_cache_debug(s))
>>  		/*
>>  		 * kmalloc_nolock() is not supported on architectures that
>> -		 * don't implement cmpxchg16b, but debug caches don't use
>> -		 * per-cpu slab and per-cpu partial slabs. They rely on
>> -		 * kmem_cache_node->list_lock, so kmalloc_nolock() can
>> -		 * attempt to allocate from debug caches by
>> +		 * don't implement cmpxchg16b and thus need slab_lock()
>> +		 * which could be preempted by a nmi.
> 
> nit: I think now this limitation can be removed because the only slab
> lock used in the allocation path is get_partial_node() ->
> __slab_update_freelist(), but it is always used under n->list_lock.
> 
> Being preempted by a NMI while holding the slab lock is fine because
> NMI context should fail to acquire n->list_lock and bail out.

Hmm but somebody might be freeing with __slab_free() without taking the
n->list_lock (slab is on partial list and expected to remain there after the
free), then there's a NMI and the allocation can take n->list_lock fine?

> But no hurry on this, it's probably not important enough to delay
> this series :)
> 
>> +		 * But debug caches don't use that and only rely on
>> +		 * kmem_cache_node->list_lock, so kmalloc_nolock() can attempt
>> +		 * to allocate from debug caches by
>>  		 * spin_trylock_irqsave(&n->list_lock, ...)
>>  		 */
>>  		return NULL;
>>
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3aa8d400-fa6a-48bd-b9f2-3bd6f37e523d%40suse.cz.
