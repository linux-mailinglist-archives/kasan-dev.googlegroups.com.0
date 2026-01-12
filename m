Return-Path: <kasan-dev+bncBDXYDPH3S4OBBD5GSPFQMGQEZROL3FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 34F70D12112
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:55:13 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-59b7b7a46a5sf1976116e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 02:55:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768215312; cv=pass;
        d=google.com; s=arc-20240605;
        b=O/nnuyXhmtTTXF0NkKVCi7c8EAK6e8YKDEh9scAJhY1AsDbIvtXlk7aMlAUlEklzQ8
         GAtLAmDKblMin/EOfQk2V4R/TJ10LSpYE3DI0zapzuef9k73WPkiJdy4jvG798/eg6jU
         4WvvrH9xonrt8PJS7/bOS7BD56jRwvTOLKEzA29HYaF5ezYVnLYrylyRZM4rQAz0V7XD
         GY9i0fNDFGOk3YK2Bbw5d8dOZFn8SAu6lqnYUO/0ROFshYCufN+xUoQxJIjJ6VTq2530
         bwtv0+8M1rvY9tQqpHO1KZ0wuV4FnacSgICb/WKDqIUtcEKsC7WOW96/uniplyRhdGkD
         trTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=RSfokQh3FuaCBOC8LaeJyBnsidUH/HpFWv63zgbxMqw=;
        fh=XgO2XpETcIGIYWT3V1/cJFNxC2eKSRtHCJovwoAPZsY=;
        b=MQzcR9nnuwUrTbTUjm+TmLmScEUEgUH19M2CGQes/vGgnndOUf9FG3XWj380zAWs0g
         cXZS46oYHqceRflLiqizcQghmLy//GXO9//SzaLM3QhS2PNy0ekfLlUgrMMsBDgCdBkd
         CyVA/QEKabwuLLb58svfe62TTfV4VHSro+/6ia3f0cJFK3NlSK+3vYRxZUCPL49iUaei
         xP99QZgzpIOv+4AHfBrTCtR1vrjWMh9yjA7J26OOLSCIqdYADaUpqY0K/fdxLAx7n5Vd
         3k4Lo3vSQOsv9dxTa+vI3qbZGXlIkiUknuQSKNj2jMHdFrW+81OIeB921zirZeTXE/xR
         fYxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="pbLM/krQ";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=xMKJOGkD;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="pbLM/krQ";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768215312; x=1768820112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RSfokQh3FuaCBOC8LaeJyBnsidUH/HpFWv63zgbxMqw=;
        b=XWVHlqJ+iT3+vKHA77hBAzrJqhMGxZMeHauysUGKXBRGRg6tbmfkGA9+zDNvpSAudg
         ca9b03iLLnB8rkAlVTWmtLfJChi3F0jip5yW3EX7Xn1oCCtoH8gzmR7AdeO5Qyb18nM5
         UTvJOZea+29LT6zPENtg2JVHVcjdbXlbkmpfrJVRSLBEuLDU3KlurNU/dv9PryP3f3bE
         f+2S9rZuQdsMUOnk9TSGHRXE3NlnZey6hKTMx7v6vf9cO9BJ6jcPcUBUUnL/W/dc1Bua
         rKxrHkMqnSMCAO9aMXzQPAHUlyC+cbqPnnA84ZANSnhIeeHc4wwcaww+2aMoXWO2rRIV
         /V4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768215312; x=1768820112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RSfokQh3FuaCBOC8LaeJyBnsidUH/HpFWv63zgbxMqw=;
        b=uq7bs7uiX03YeN8jJmWaulXg6l2aWHLS0Ltr+qUOy/yxP+vsvuY+J+vRthwJvAK+Ii
         BZnYQFng37dQr4/dwU08IOTvAmuH101os2MuB6o4nWQnb5IZnoyyXRJ8xT8U+KiPYGf3
         iRFkNAgZuW2NxoUqjqmJWW1+p4F86svKSmTB2rGUHz/G/4146Oa06BaudaThDiPnjgLx
         qcyg4PEotOE22yDDe3c0YI6Dlb/LqNBeRwq2+6bsb0ID+5cjvpGRo+p/ByS4oFI0BhUy
         Zemr7ik9DrDL6vin/bC78O6hSCDADzFK3u7onoTICbPZ/iRkg7jKwD+zaEGwL6STAULG
         i3wA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2vxVEfiuD6+QnuktzToajOhHdMge2V03+VVJ/Xa9jqkrkXWB1qxlnB7/CyxKuaTkMR18Ztw==@lfdr.de
X-Gm-Message-State: AOJu0YzNmPf2b2MdGtO6RZLvq/ZQxy4jO/bDnWmYqg1IXLQyw5wmLMV6
	tTOl9rfO9yS972cXHCoHLDFEoQF0Ve6IadzUnRMVUdaA2YThIPxklt9P
X-Google-Smtp-Source: AGHT+IGhVMBNlaZKXoR8sco+I+0XAKJsti2vdHLQ5tIgqgzuBjzontKGXOFNxeoGfih0xubG9NB6/w==
X-Received: by 2002:a05:6512:3da7:b0:594:26cb:fce6 with SMTP id 2adb3069b0e04-59b6f036acdmr6041290e87.34.1768215312199;
        Mon, 12 Jan 2026 02:55:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E50WEnHPKS0iaPk0ZEaTgpzhK6KTZCO7yRZHHYRJo99Q=="
Received: by 2002:a05:6512:4382:b0:59b:67d3:6052 with SMTP id
 2adb3069b0e04-59b67d365f9ls1879412e87.2.-pod-prod-03-eu; Mon, 12 Jan 2026
 02:55:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXy6W/dggbR9yvUY87Uj6cCwx075atNxPqo0RIquBDsrDUoQjTYEMv8Ei5u1e92NfWEr7+fK0ySq4I=@googlegroups.com
X-Received: by 2002:a05:6512:3d08:b0:59b:6c6d:b2bd with SMTP id 2adb3069b0e04-59b6ef222eemr7036498e87.20.1768215309207;
        Mon, 12 Jan 2026 02:55:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768215309; cv=none;
        d=google.com; s=arc-20240605;
        b=PfmhSU2OmcPj2XVGDeleYPOTNSetGgud5FPNorT1D14vi3TqgaLzd+XYHktinxKqOA
         isVFgsqakWj0xE6udkWD3YZa1matrbSZbDhhZKC4rVXbwRtWlNsoUS+zctSYAa0lLHO3
         uywDPY9TZp1HB9W+P4k00I0aqupXxz550TWrBI/hy7kkIurkfgIXgzTYPAo5iOBVk/hG
         G477qeJQcxuhVQcFeGm4fC0JBulSf+smTtEuuM3y/Abn71CYJ0FzKk1NHfODnK5+i+t3
         7bO3Uvunw9qgAD/C72CSLA0pMUJOql/SV7Ct/BMMG7w+q3akRORLS7HnR3emYRAnHqAQ
         T3ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=yQnLU2w7dK6piodCTax/NpreN6qBl/Gte0TSTHMUnzk=;
        fh=jppyNc7TJ3qu5rLS5HJ5RXBFa5dL3B89zLFEK6VAa0E=;
        b=CIXwD5lsqhgCgWcG/1bHWs/KrUOC7CA111zKoih0GUF4ef1erM7nq+P4Jn4OjvxtJK
         1qIRDUColZ9xuiUIfJ4r3djlcRX+K8JbRGlffj6UX4upZ/HRAeyyRO1wf3odW3bruhBm
         T1UALNpQqYXUCSPJuN5uU91mOdWjDr1R1cbzosf2QGajRJBOy5WrEap4RUgY72RNeew5
         f3M4d4jMYfJcP2lrTXZRBL6qY1Jh0DRhIvPdzWL2LUIlbk0XHDQcbB5DBChEBKabiK8P
         6CuX4C3Lflk5SBMQZprFEQWGeiTy9DZow0Bn2Hm71udnaEjzNb660u3GQEGLMmaQy2IW
         8Bvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="pbLM/krQ";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=xMKJOGkD;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="pbLM/krQ";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3830647c24csi2988601fa.4.2026.01.12.02.55.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 02:55:09 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7138D5BD08;
	Mon, 12 Jan 2026 10:55:08 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4DB173EA63;
	Mon, 12 Jan 2026 10:55:08 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ylyeEgzTZGkPEgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 10:55:08 +0000
Message-ID: <3b7b610d-6482-49f0-8e46-6ae553bf8b98@suse.cz>
Date: Mon, 12 Jan 2026 11:55:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 00/19] slab: replace cpu (partial) slabs with sheaves
Content-Language: en-US
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Mike Rapoport <rppt@kernel.org>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <f7c33974-e520-387e-9e2f-1e523bfe1545@gentwo.org>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <f7c33974-e520-387e-9e2f-1e523bfe1545@gentwo.org>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.999];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	MIME_TRACE(0.00)[0:+];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="pbLM/krQ";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=xMKJOGkD;       dkim=pass header.i=@suse.cz header.s=susede2_rsa
 header.b="pbLM/krQ";       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/4/25 23:11, Christoph Lameter (Ampere) wrote:
> On Thu, 23 Oct 2025, Vlastimil Babka wrote:
> 
>> Besides (hopefully) improved performance, this removes the rather
>> complicated code related to the lockless fastpaths (using
>> this_cpu_try_cmpxchg128/64) and its complications with PREEMPT_RT or
>> kmalloc_nolock().

Sorry for the late reply and thanks for the insights, I will incorporate
them to the cover letter.

> Going back to a strict LIFO scheme for alloc/free removes the following
> performance features:
> 
> 1. Objects are served randomly from a variety of slab pages instead of
> serving all available objects from a single slab page and then from the
> next. This means that the objects require a larger set of TLB entries to
> cover. TLB pressure will increase.

OK. Should be mitigated by the huge direct mappings hopefully. Also IIRC
when Mike was evaluating patches to preserve the huge mappings better
against splitting, the benefits were so low it was abandoned, so that
suggests the TLB pressure on direct map isn't that bad.

> 2. The number of partial slabs will increase since the free objects in a
> partial page are not used up before moving onto the next. Instead free
> objects from random slab pages are used.

Agreed. Should be bounded by the number of cpu+barn sheaves.

> Spatial object locality is reduced. Temporal object hotness increases.

Ack.

>> The lockless slab freelist+counters update operation using
>> try_cmpxchg128/64 remains and is crucial for freeing remote NUMA objects
>> without repeating the "alien" array flushing of SLUB, and to allow
>> flushing objects from sheaves to slabs mostly without the node
>> list_lock.
> 
> Hmm... So potential cache hot objects are lost that way and reused on
> another node next. The role of the alien caches in SLAB was to cover that
> case and we saw performance regressions without these caches.

Interesting observation. I think commit e00946fe2351 ("[PATCH] slab: Bypass
free lists for __drain_alien_cache()") is relevant?

But I wonder, wouldn't the objects tend to be cache hot on the cpu which was
freeing them (and to which they were remote), but after that alien->shared
array transfer then reallocated on a different cpu (to which they are
local)? So I wouldn't expect cache hotness benefits there?

> The method of freeing still reduces the amount of remote partial slabs
> that have to be managed and increases the locality of the objects.

Ack.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3b7b610d-6482-49f0-8e46-6ae553bf8b98%40suse.cz.
