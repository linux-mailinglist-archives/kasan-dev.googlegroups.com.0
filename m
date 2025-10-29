Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5PLRDEAMGQELDV5UTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ECE8C1BBCA
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 16:42:47 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59307b95006sf2272218e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 08:42:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761752567; cv=pass;
        d=google.com; s=arc-20240605;
        b=AFMfQ1q5EcIKyZq0w6qaaDImzv4iudNmQmtIPSGyqUcwbnDT0uiNUrkZobeSOHycmD
         y4nMS3haj4reNR7KNXsBclRABWhvqVLBv22Y8XiX4DflIlYimMSfKftohrf3S120lXla
         UEfcSknphV+hPPTQBSu42hSOXMKOqIFbxez/CkDtPA9fjPnEtdHMC8cECs4zRZgRNn5l
         EwEqOfzoEzL/WCsmOtgOq453tXLAxI7iOwkbr7Bb/fKBiatmfyehqoVQyDf0cOmP7+tP
         hVsCAFoNahqwqeSU2xaAvxz2hA3pdh88sX71+15Wo06ng8e3bdWaMEBBN8VAqeYKRjJm
         6vSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=aOYVaOQ7z9e4PCERFyLaQQilpHbJ9HHJjviyO09Lxxk=;
        fh=+dhNCHrpSNBXQBxrRnTbBRDqz1xeWz7pUKkMOzBXlDw=;
        b=YsvINve1ApeouqT6r41apOrPr/egpvb7707SDaw/PuoDLcpiV6TTFhwcQvhausIFt4
         DueRVGgG0nUo/kODdzDenLxf8gj9g+0L0eO7KchfshFTXQ15DJfa+iDBksuWZFe3U0Qp
         BI1vIHrEOSQYwVrTVND0zUHvIoC1MQpO/v3f4AxC/TU/FP/0zF4YMUpk1Czs1UpF8pQT
         ExDuZjwoUFd8xqGZg/plJMqV8m3iz4ekUuilSw7x55CkAeSiHirQIE8J2bXEk529RyBp
         CplhF9Kgs1jFFfCmTmxQ4+CcZNU+yMPOhmuFzgwJj1Au/9833bw3TPe/cxq6rEG9rTby
         MyJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yYmcDfKv;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yYmcDfKv;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761752567; x=1762357367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aOYVaOQ7z9e4PCERFyLaQQilpHbJ9HHJjviyO09Lxxk=;
        b=v0348tIUWYXtCSdpiFCJIHY3Iybm046Q6WWqz41s7/JfLSD8QZBv9t0pIok3+ep1sc
         37Nybbl7kDOS42ms1UD8kFZO52l0VZyFXvcHW5FMAgsQEnstqKUAN6uFs9RaPdIE8090
         I8LABB0PwM5SzI70aHgE2AC9+jWMWc3ssCjx7A3ogMm784TgXSa3KMwwF4CMZA2iYg09
         Dn1ahLzgZg5zqO8QfvjZz5uhsqyyfs0wkc+6JOcPizql3xTM70D+0k4g2u7ftzsMP3hl
         uPbA+3cIVieTHjj6Jm+ZiYeD9eQnsFr+3LVoLBuPT5VkJpY/l8xmOcTvzXTithX7ISCU
         O4zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761752567; x=1762357367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aOYVaOQ7z9e4PCERFyLaQQilpHbJ9HHJjviyO09Lxxk=;
        b=OiDgyL1ajEgY7QUnvGDf4R3JPU9M6x0SY4hrbo89i1B56J/RC++xrpXr6fW93Mrxwk
         DiqTU4GEnFuhc9iW1QxumqWcIEEQZSfYcll6CQ87pHOZ47smyKQ4iTBUKZ2IBicahUQY
         Svo2m0CHzpzqpKQsX6inrjxnxxlTnm21C8mZEn6y+bCj8QCT8qJn9Gf2rRGoM1Xe7uh5
         HtkIBGgUnPBkjyKvObcoyQegONlJJgemHai/6nzNO3fXgmGATw8AGgYMryHxHTMOFws6
         0hOfrqx7r6uthDRoblzazh8JfN3NI/VTQF0lX0hr1rdEuwBWy8ac0YmFsfdWSHJ+6+42
         ZG+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUWz18VFNT4W98h1cqd59A5mWtXKHSRz0z3JU9fM4IK0JSxfWpCgKznhNbhJ3vy05Ev3pzzog==@lfdr.de
X-Gm-Message-State: AOJu0Yycd+C5RmU9rvsZqXoLLBYINmP0YUa/bBLS2jY66DQ1+tDrIXXW
	UYG7CdW3glFevjyWNHWunr6HmvqhfzdZuqjnyxnR5pVcPl+0Y8SDiZ73
X-Google-Smtp-Source: AGHT+IGBjMyRjuoscj6WL3DQecQz7Lt5kQ6kfea8TGdqrzLq2Zgj+9X2p30SmQu4goeXBMcTlXgNDg==
X-Received: by 2002:a05:6512:39ca:b0:592:f8e8:eba0 with SMTP id 2adb3069b0e04-59412873892mr1338691e87.18.1761752566178;
        Wed, 29 Oct 2025 08:42:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bpHAnIxa4ZevnNg2+hPQ7OyTu4WVlM/u0vzuFK7GjZOA=="
Received: by 2002:a05:6512:4891:b0:55f:48d5:149d with SMTP id
 2adb3069b0e04-592f54c094als1504634e87.2.-pod-prod-08-eu; Wed, 29 Oct 2025
 08:42:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDFDHjvE3GU2nFWR9wpYzkE2kiLdl6w7SecybBgauL24aL/gwsg0KD/xl4+Btju6oJJkfyLj518Xw=@googlegroups.com
X-Received: by 2002:a05:6512:3b13:b0:592:f7ee:6dcf with SMTP id 2adb3069b0e04-59412865307mr1239495e87.9.1761752562026;
        Wed, 29 Oct 2025 08:42:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761752562; cv=none;
        d=google.com; s=arc-20240605;
        b=KVOWWJ+p85O3pLJBZmXOLCozBWYxOtn7SqgvkIzVI+ilJXE3qsIAPRv9gDBZaT3xX9
         2WjQsC2tlqsRHSTNf3npnc3omzYf1O6nJXg01UccSWWYJ0dl9GEYjOruiQ9ZEWTC1hmh
         cMJ6/ulUOR0yPztmhPZHW9dc0QDkf1nD/dDK7MT47Mrr4A0Kwe3gk6NCOPeKxyh/X+Bi
         iFSvLZZuuH7wxHzSzoVwMAbz+n6b53+P167tHf8V1tcntpxVnqJewVwuJl2TELS4evsa
         cgilbcTqg+RT95mCA4bjMfjwzFmLtsLbzTmXj8219BJmZNZN7tedMO4FRpV63D2pENM1
         qoVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Rrj//QFmpN6e/2LkQmU6PX1hLwcBM+04iiPMvPfmFWQ=;
        fh=wT+3rUFrxSfWDlIbk/kN62IDJ/K1d10IIhdAHgvNHAE=;
        b=Q1Dgd+7iFQi2MTmM6gEU31ePA7RGwl9Y5KrK4iQMaTu7ewZpnkJZOx0l4c2Y8QN6Zj
         dEJjs3PlVtGltDRPan7UVGV59LKjoDe+qjcY/EMVBhuzHhmqupqx/pvORshF7a3eKBzt
         BybtTvbvZcb/DJtpW6ihlQ/C2DPAq06q3wsP4KuHcW9tCdVsMKMlRcz7yL8yCpncv8VB
         Qv9WHFDpzlWeYBcCCzpjOTzEhd8nki0oVhi6SnWbcJhRXOecuw9wR/5Dwg0OJz54Po4h
         WgJOM50/PewIF2L8TEwgMiV4FEIeT870F5uPkfENFzLUVboddv2HqApfiUZs3LQfKqEb
         CgXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yYmcDfKv;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yYmcDfKv;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5930276e7e7si266525e87.2.2025.10.29.08.42.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 08:42:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2A47A2290B;
	Wed, 29 Oct 2025 15:42:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 103DA1349D;
	Wed, 29 Oct 2025 15:42:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id cbeoA/E1AmmafQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 15:42:41 +0000
Message-ID: <d70962f3-37c4-4410-9cfb-2c0f5c85470e@suse.cz>
Date: Wed, 29 Oct 2025 16:42:40 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 05/19] slab: add sheaves to most caches
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-5-6ffa2c9941c0@suse.cz>
 <aP67sQ2dD73iXubl@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aP67sQ2dD73iXubl@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[15];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=yYmcDfKv;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=yYmcDfKv;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/27/25 01:24, Harry Yoo wrote:
> On Thu, Oct 23, 2025 at 03:52:27PM +0200, Vlastimil Babka wrote:
>> In the first step to replace cpu (partial) slabs with sheaves, enable
>> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
>> and calculate sheaf capacity with a formula that roughly follows the
>> formula for number of objects in cpu partial slabs in set_cpu_partial().
> 
> Should we scale sheaf capacity not only based on object size but also
> on the number of CPUs, like calculate_order() does?

We can try that as a follow-up, right now it's trying to roughly match the
pre-existing amount of caching so that bots hopefully won't report
regressions just because it became smaller (like we've already seen for
maple nodes).

>> This should achieve roughly similar contention on the barn spin lock as
>> there's currently for node list_lock without sheaves, to make
>> benchmarking results comparable. It can be further tuned later.
>> 
>> Don't enable sheaves for kmalloc caches yet, as that needs further
>> changes to bootstraping.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d70962f3-37c4-4410-9cfb-2c0f5c85470e%40suse.cz.
