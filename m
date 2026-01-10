Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHXGRHFQMGQEELEBXNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BA6CCD0D8B8
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Jan 2026 16:41:30 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59b686eaeafsf4579480e87.0
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Jan 2026 07:41:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768059680; cv=pass;
        d=google.com; s=arc-20240605;
        b=J2fMEiVClMxAjucEIK0bhbFOsa1B27dWPO3Sea8qh0ZjCShm6olWiSwdo3IT8QdGb5
         qLP0naKeQKwPhiBk8o/zY6GAox36gByaf28nbhyS1nNsfjFsjAm1BNyL2fWfnNWkqNAb
         kA5M/+ecToNyhq8oDG0of9g2DyZvLmNEKivIY9INsKw+BrZXZUXPY8/AM77tlqGBZnut
         DB04bZCT2vIFi9jML7lFfnDruN3yhCI6FN5bbT/CniGg8FakDSmzmesAxcEaa7fdIX2B
         pCytlP5B0IstWk6M7qHk7PeOBS9q4+e1lNOQHrVA1coXoHe+q77xFe0ePcH6mLHMIvbh
         w1/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=azZfFdDFezbzfTkZjx3YAEqnmw0vmZ2UwBH+wIlFfv0=;
        fh=5DX4l3lhgnnFy1Waac/81BnObFq63a4l0acKKnEGsuM=;
        b=kPXUfleV0TQD6oacDgmF+NFZeiTq5i3L+MsRMsRhLV5JR1x8XC1lfhakyNLneAXiDu
         LZ+m8+/azL9sbARJ8steON1sdUdd0Oi4zrDtpQgxPA/jDz3ZpIkCIl5qGJC9DG6eJoiZ
         Huel2HyeTeZahLGKhpfXNQl01o99OlzdtJ9s2WCq5BuhkjAcLB/RQDRSxfGTGP2HVRhs
         iAIyDgpUD0YK1CWSgnSk3JKB6RDBbaY0V5E4lBSv8zBnESusmLNKGBVbDdgFet6ZNzAz
         tykMbQZoYH1HmFJ6xRjsOKe3i+SzQW9Lif0d9Pb8QE7Qzqkm2vnm8deMgz5WO3LTeqbX
         zSdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cAZlr1/q";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=wNsGH+7G;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cAZlr1/q";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768059680; x=1768664480; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=azZfFdDFezbzfTkZjx3YAEqnmw0vmZ2UwBH+wIlFfv0=;
        b=QkwIC3+iQSMR3YEcJ/Vnkmv2KtxqLd7wM6jOD1eUguma3tmahbxUEh+9VknnC6Or4S
         my04fqdCuuqsKuRcVwKMGvwtdao9cFw62d4i6T6bLLkPrUcKcIP7/hsTgQU2jWR6tBsL
         AqHUW6zKg14adIXfsnAx7Jdg9V16cECI7fQBn3UgSN7HubFjgjmBFD1+8qh/rRMf6oQK
         WJs49iGr7YT91y0VAkRY+xUy1JHuba8NxLku0I6QF1xbTju49cGNLc80drwRd+JVt6gY
         +96W9OxHIAMjc8MHZYhru842N/QF6UdVPvj0VtIeT6U53UGcNiD1ZCUUAEWNjgjx/EHI
         kKOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768059680; x=1768664480;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=azZfFdDFezbzfTkZjx3YAEqnmw0vmZ2UwBH+wIlFfv0=;
        b=GnhajkKqMnCJ/8vZcvBMLVbO0nE8tFkc7ryxTw+0kGh0YCy9UCM1UzLydLSUaz+yp+
         nUWIEN7u+TL2EwdJjyT5sWw0xKf0D1QIvgxdoHn7cXeCftHsRmhZs/P3x5RWQL3NRATQ
         v0L8g63hXL2tTeqEcu5gRtjl0xsu91ouDSoG50HkJEhzemAYGHvn6ITZgNt0bYu8/VZG
         8O3g9y5SoN7mfhDJd1gRgrJ8UZpdI26rvOpQDBGxs0ojTIuydF1F17+mBzVQXSv9pMqP
         69W0IWzAnH+6Mqlk5bQaSiakxQP6Lr13zZ1b+Gpi8G4+EJXDlyFSqOFdX0LrXWCrW65N
         /DVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsaxztzlMGJdSg08bTjDRwisRlak3ptPgO4bGi1JfdNZU6CQhntBALyhce4k7Qm1C8d8LTQA==@lfdr.de
X-Gm-Message-State: AOJu0YzTLH4e3niR8iG3S51C4+lpSIcMo8s/yE96NjdwrSucUkdFK3WH
	d4u98FFU0JI72d/fmiyfXhhSd9EbjUoXIKAKHfZAftCsGqHixzX0m/pJ
X-Google-Smtp-Source: AGHT+IEfvQ4V6s2siLSFA38jHbjOdZjLg1kSDSdSftnR2cQ7NuMNkkVnT4/CsG2h2NvukSMrHaQwZQ==
X-Received: by 2002:a05:6512:1327:b0:598:eb05:c5af with SMTP id 2adb3069b0e04-59b6ef134aemr3983625e87.15.1768059679398;
        Sat, 10 Jan 2026 07:41:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HOjm8iIm5+oXy2U+35AODs+mvtSu/w5Ni1emzAVdv0Hg=="
Received: by 2002:a05:6512:2398:b0:59b:7205:469d with SMTP id
 2adb3069b0e04-59b72054731ls1106355e87.2.-pod-prod-06-eu; Sat, 10 Jan 2026
 07:41:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU2n+fPaP2bGNvpJxqYHQcYt/dFv1rdKnG7nFpEkrF+y3IyPE+hBe5OFlH+dcrNGSSSDhr3MP+rMMs=@googlegroups.com
X-Received: by 2002:a05:6512:33cf:b0:59b:786b:2a18 with SMTP id 2adb3069b0e04-59b786b2b19mr2990477e87.46.1768059676245;
        Sat, 10 Jan 2026 07:41:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768059676; cv=none;
        d=google.com; s=arc-20240605;
        b=KBHZZG07ToKzu7EKeFE6kgg/VmEQQN6lvdZvrF4NlgiY3sHJyXl2wDMpc5TKEQYD07
         Dm9QYDjpcpeUrew2gFyP3609jIm2HnBpMrINNaL562BQB/WsGT0ivTV6kCj/pv4I+wK8
         0XTes3d8zfoGQRQQJuwoTSvCtQqbfDGjpgmwZbLsQjKiWc2E7siXa/fIIo4AUm45uWeX
         ld12iXtrVZF4DsBuiOa8QNB9nnqR2uDfR63OKIyhhtWJqSggNg/TP3IwBjrQUCGqykn+
         C+K9E+FA+3wMXFL5qjMRK3k1LkEJ2Sjq+SOVe34x5IPG1LDc1jGsivfeFyVHD5iRcJbX
         mqCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=DMaASs04EH1I7HUqtZvbF7q1RZcgi+PtUryM4O8whrk=;
        fh=JXcTcagT4qpq4la91joDZG8MPM9MnBisU8vfXW5myog=;
        b=LeK8Qk0X/PDKt0zxKsQoC2vDm8SqxhYVnBnoF7HGAklQh46tu0sY1xs/G9jEX7wruc
         dbCxux+fLKplR3NZoEtIC5XvDrKPDr/ZwLtplkmgi22PK8D/Q+oVY+Bvafp/ZhI8Oo4G
         JeWAJDWkNQxJto+AN8hcz771/+HqO4C1W1YE7k0i2cEBtRMh27znN7m2hGwEzk9J6+1Q
         q5SMTJ9/LksYF8ZnI0jLIyM04Metrw6LIKtHEoQqatc29AuSkTawa5bkKTvH2ZAXD7Hz
         aYYclwVl0/FzEoiGqjEt4jQpFbEc44k8SmU29FSN0UPIEGAL0/d9QO94Efdl+wajKMYb
         +DIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cAZlr1/q";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=wNsGH+7G;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cAZlr1/q";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b6c0e891bsi232069e87.7.2026.01.10.07.41.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 10 Jan 2026 07:41:16 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2D3F55BCF9;
	Sat, 10 Jan 2026 15:41:15 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id F3E5B3EA63;
	Sat, 10 Jan 2026 15:41:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id wxerOhpzYmlFPgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Sat, 10 Jan 2026 15:41:14 +0000
Message-ID: <01cf95d7-4e38-43c6-80ef-c990f66f1e26@suse.cz>
Date: Sat, 10 Jan 2026 16:41:14 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
Content-Language: en-US
To: Chris Mason <clm@meta.com>, Roman Gushchin <roman.gushchin@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 Petr Tesarik <ptesarik@suse.com>, "Paul E . McKenney" <paulmck@kernel.org>
References: <20251024142927.780367-1-clm@meta.com>
 <28e6827e-f689-45d9-b2b5-804a8aafad2e@suse.cz>
 <9a00f5c2-7c9b-44c3-a2ac-357f46f25095@meta.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <9a00f5c2-7c9b-44c3-a2ac-357f46f25095@meta.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="cAZlr1/q";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=wNsGH+7G;       dkim=pass header.i=@suse.cz header.s=susede2_rsa
 header.b="cAZlr1/q";       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/10/26 14:20, Chris Mason wrote:
> On 1/9/26 3:16 AM, Vlastimil Babka wrote:
>> On 10/24/25 16:29, Chris Mason wrote:
>>> On Thu, 23 Oct 2025 15:52:32 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:
> 
> [ ... ]
> 
>> By the way, there was another bug in this patch, causing a severe memory
>> leak, which the AI unfortunately didn't flag. Petr reported it during
>> performance testing and it took me more than a day to find it. Oh well :)
>> 
>> Wonder if things got better since then perhaps, and your or Roman's tools
>> would find it today? :)
> 
> Yes and no.  It didn't find the leak until I changed the prompt to say:
> "there is a leak, find it".  I'll see if I can improve things...

Thanks. Hmm even if it has to be done like this, it could be a substantial
time saver vs finding the leak myself.

>> diff --git a/mm/slub.c b/mm/slub.c
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
> 
> [ ... ]
> 
>> @@ -3592,54 +3549,53 @@ static void *get_partial_node(struct kmem_cache *s,
>>  	else if (!spin_trylock_irqsave(&n->list_lock, flags))
>>  		return NULL;
>>  	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
>> +
>> +		struct freelist_counters old, new;
>> +
>>  		if (!pfmemalloc_match(slab, pc->flags))
>>  			continue;
>>
>>  		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>> -			void *object = alloc_single_from_partial(s, n, slab,
>> +			object = alloc_single_from_partial(s, n, slab,
>>  							pc->orig_size);
>> -			if (object) {
>> -				partial = slab;
>> -				pc->object = object;
>> +			if (object)
>>  				break;
>> -			}
>>  			continue;
>>  		}
>>
>> +		/*
>> +		 * get a single object from the slab. This might race against
>> +		 * __slab_free(), which however has to take the list_lock if
>> +		 * it's about to make the slab fully free.
>> +		 */
>> +		do {
>> +			old.freelist = slab->freelist;
>> +			old.counters = slab->counters;
>> +
>> +			new.freelist = get_freepointer(s, old.freelist);
>> +			new.counters = old.counters;
>> +			new.inuse++;
>> +
>> +		} while (!__slab_update_freelist(s, slab, &old, &new, "get_partial_node"));
>> +
>> +		object = old.freelist;
>> +		if (!new.freelist)
>> +			remove_partial(n, slab);
> 
> Is there a missing break statement here? The debug path above breaks out
> of the loop after successfully allocating an object, but this non-debug
> path continues iterating through the partial list. Each iteration overwrites
> the object variable, so previously allocated objects would be leaked.
> 
> The commit message says "Now we only want to return a single object" which
> matches the debug path behavior, but the non-debug path appears to allocate
> from every matching slab in the list.
> 
>> 	}
>>  	spin_unlock_irqrestore(&n->list_lock, flags);
>> -	return partial;
>> +	return object;
>>  }
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/01cf95d7-4e38-43c6-80ef-c990f66f1e26%40suse.cz.
