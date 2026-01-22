Return-Path: <kasan-dev+bncBDXYDPH3S4OBBSG4Y7FQMGQETLK2OWI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 8AkuMkrucWlaZwAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBSG4Y7FQMGQETLK2OWI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 10:30:50 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B72A64902
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 10:30:50 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-3831426aeb1sf3843081fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 01:30:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769074249; cv=pass;
        d=google.com; s=arc-20240605;
        b=hVYpm6ZhDDI2LM6pvAKFHDB53mUmNtQcXoEjrP+7z1Id5WOBDd34Y8ZIDWdDeVdF2P
         80TqSJa/cVaz6fO4Q2dKpMVwzN/DYi/F2o2YLf2q6WyBj++2WZHWDwxgaWY/w/asRuj7
         gpcoKwxyJRkiHC3OZqGOt4XrXuT3x9gGaxADsHi2HNK/rmmoobGcrq4DvcLLVeIh1G2X
         xJmmcW0C9i2gL6WJ3OysR4INb6ZEj1LTItKtMRfAtp9gUanG/EOBJGARKGeA6ihit8yW
         jBP5QUAm4+bXHY5+KAiapGeMJAyOn5dIDJGdWSMWyjAL8RhiJpVLuIOdgJHqO4tQfEt3
         qL3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=DXUq7jMxRISFw3ale5naAGPFf79sjAnfqNPFwaQQjtg=;
        fh=xPNdoMd1/6oOHPIpdLEmwfALrBJ67uVDvqocsSvNviE=;
        b=jH1CqEfbTX+F6EdQreCaYdG0W3A1BgHwSqzg/lLBSafVCbPa5WKX9uUE83BjZG/5eE
         2LF3ybDQE4pmHMD6GBzpZUveWvDBbKMsraAss4xRhmxKvXSLQwFKRYThpCRa1p2aOka2
         34Vt7wnq7AijvkXeykJ/6Xa6hFKulGuTQ1T3YyjS3SG2nq8hjhi1I35uOlx8Q1buTqQp
         zp2TPg0PuY7+TSuQrvokq5q2tP6G6AqQMRXuKWB2BGhjfiEVVX8kS6NQLnh2qN/lmpQL
         OIWvP+p16tpqqdeKEv5n/vAHdZVIWHuxgFV2e8Hw5t52g6qQq2rgAJWvwpJabpfkcmXt
         9GOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NiVWaxlM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NiVWaxlM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769074249; x=1769679049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DXUq7jMxRISFw3ale5naAGPFf79sjAnfqNPFwaQQjtg=;
        b=Pc9+h9UJD/3QdgZ7HYBK68dVvi3ZMQtP0V2SYDBG8Sa84+Ymj2JUDBskRDXBpIcAhW
         OJr+h0d9E6ajV6+ewBmwxr6C5PydQGmxFSblxPCVIhmYreFABFT1JVTbJvC0R3QpoeG8
         aN12Iez9WFHUKci/sfq82oy7/OBvwzC+ocUr5dU4QZm6QnYhomWQVMvmVHxF7EHrhpTG
         mxwYAf3Wmr5S2qAmVWgZi6plEyhef08SeFW71jwmbwm+SrQ+iR4y+ytO3cJfpHpmrIJx
         S0BQ+zeVhr+bCMwo8TXcBWodqvvUC/uxcvrzNskcnmyMTmBVsvumSN4owhZUIrOaPQsn
         Fvow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769074249; x=1769679049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DXUq7jMxRISFw3ale5naAGPFf79sjAnfqNPFwaQQjtg=;
        b=XDF+artIqdW9uftygXs5vZnE0Z7RySjtiSSIyi8Ruaf77COdiZ8odNy4op/04Xhpyg
         vIha4MLkQrfE1bMk3lc4JNhl6EbR09/ZFCyXN9WQdIU7UB+JJhkOHjI0dxGyySqRgipc
         Pgr6S367LbtTs62H8I16ncwY+P5JLV0TLSEaY8aasR9S9rdce3QMzPMSoYhJm3W4uQlO
         XIhwP0vLh6IDb1vusQJfQYKrBO2J+z3C5cR3r01lH2f9bDFoPp1MSEVTwjkrjJ28n5lG
         YAURLzhiX8jNq+PBIYKcEIKz8U2VbdYvsonWsb32wH9RwrywdYtJVuCY1fnI80R/kPH9
         YZLg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfRxVSL0tUvMakaaN+55P+Sc2heMwWNlcPR5vVvthm7cPdrdFh6vm9RH/5wbwjPTOrk9uQ8Q==@lfdr.de
X-Gm-Message-State: AOJu0YwKhesC0qb1q6dpwazd2nid4M52G/qxvjWvIAyNwZ1L9OWN0xaf
	UeFCpP5W4+jw4lcB2l5fVv3R0Z1bJPV8d5L4asd6ETKC/1rBpHW+Qk02
X-Received: by 2002:a05:6512:1516:20b0:59b:7b85:8ab9 with SMTP id 2adb3069b0e04-59bafdb551dmr4668331e87.9.1769074249337;
        Thu, 22 Jan 2026 01:30:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HsK8WH1Iwuic8T25IDHLupooE48t24AjXWqALyN/Jyng=="
Received: by 2002:a05:6512:138d:b0:59b:7bbc:799e with SMTP id
 2adb3069b0e04-59dd797ab6als287125e87.1.-pod-prod-04-eu; Thu, 22 Jan 2026
 01:30:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXfSlc4YAlXFNh/H0nL2gLPXiZMG+Ob+nbCycFOg6nWfSOACwR7UCVbLtbi9oCnRbSNkFwc3LFXLHI=@googlegroups.com
X-Received: by 2002:a05:6512:b8c:b0:59b:7bbb:6842 with SMTP id 2adb3069b0e04-59baffec4femr6210013e87.53.1769074246422;
        Thu, 22 Jan 2026 01:30:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769074246; cv=none;
        d=google.com; s=arc-20240605;
        b=YaAWDBUs5b4rfKfwtp10KEbhH3H1qIh9n6CyWOm6qGVe1O3DLoPohhDpA39mahW05s
         67TnmKfzxVDd38HR8ws7iVfDvvNn+f1Kp22gw5fQRTv6DlQXj72OSlizqGaKZA3+l2Uv
         xYh8WuUZD7wGX8exZgpUwnHisq9e9wyCqQCq3ysC9XhULLmxzZIYouunkToY8G4NJvml
         5Btf/UWn+hlYc6eCAQbUoDbo/Kj+ErLuAktDbgpzkxMdmCJbqRXPJCDTESDtEEKoBNCf
         sJTiitoFFsVfqrvymJ09GfRQBf07Rv6/CeketqTHPQtE6J6sMg+TkRoFz+0VA1aAfAH4
         jZUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=/rJjXQryTWxycH0kSD2vmf+7/CeUyLleKA6g8e7aaqo=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=SuaVxQDaxrrppZnZQJ7kBXFjRBjY4KVL/7h9pIfqRaFEZhYNcww5Fu+vW5Ig5KUpSt
         LNMuAtYafIXUJwA6ArSwAl6+1PUqK1p8DC9DDtxufL7xXpGagb6+/Nt/6QNdpkE00M7i
         eDs4KgjVPq0941sdesiXSeCsQ0MwTWRyf/CMfknyBBp62eagUKLSv3Vd96mOsVSG7uA/
         /dVDewf/Fsmb7UxaJ1guR2yP82XtMrarAj7XfT+njNdPxv9uXo9aUSR3fGLYXtIwUlM/
         NHVlk9HqJR60Mz4up6T02oDLBMKjrw6jrquEfm7Rm0eECKxXfX0Rq17LSSnOiM+hWax3
         ZBeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NiVWaxlM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NiVWaxlM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59ddec9467dsi15242e87.1.2026.01.22.01.30.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 01:30:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9766A337EC;
	Thu, 22 Jan 2026 09:30:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 99D9213955;
	Thu, 22 Jan 2026 09:30:44 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ehY/JUTucWkoCwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 22 Jan 2026 09:30:44 +0000
Message-ID: <792c6837-137b-4667-8c4e-fdc988ae8878@suse.cz>
Date: Thu, 22 Jan 2026 10:30:44 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 21/21] mm/slub: cleanup and repurpose some stat items
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
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-21-5595cb000772@suse.cz>
 <5rmxfyxuhloucetufg2qic5elgi6frd7onjzdsosmhtjdqglij@5htmiqrdhkoj>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <5rmxfyxuhloucetufg2qic5elgi6frd7onjzdsosmhtjdqglij@5htmiqrdhkoj>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NiVWaxlM;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NiVWaxlM;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBSG4Y7FQMGQETLK2OWI];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email,linux.dev:email]
X-Rspamd-Queue-Id: 6B72A64902
X-Rspamd-Action: no action

On 1/22/26 06:52, Hao Li wrote:
> On Fri, Jan 16, 2026 at 03:40:41PM +0100, Vlastimil Babka wrote:
>> A number of stat items related to cpu slabs became unused, remove them.
>> 
>> Two of those were ALLOC_FASTPATH and FREE_FASTPATH. But instead of
>> removing those, use them instead of ALLOC_PCS and FREE_PCS, since
>> sheaves are the new (and only) fastpaths, Remove the recently added
>> _PCS variants instead.
>> 
>> Change where FREE_SLOWPATH is counted so that it only counts freeing of
>> objects by slab users that (for whatever reason) do not go to a percpu
>> sheaf, and not all (including internal) callers of __slab_free(). Thus
>> flushing sheaves (counted by SHEAF_FLUSH) no longer also increments
>> FREE_SLOWPATH. This matches how ALLOC_SLOWPATH doesn't count sheaf
>> refills (counted by SHEAF_REFILL).
>> 
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slub.c | 77 +++++++++++++++++----------------------------------------------
>>  1 file changed, 21 insertions(+), 56 deletions(-)
>> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index c12e90cb2fca..d73ad44fa046 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -330,33 +330,19 @@ enum add_mode {
>>  };
>>  
>>  enum stat_item {
>> -	ALLOC_PCS,		/* Allocation from percpu sheaf */
>> -	ALLOC_FASTPATH,		/* Allocation from cpu slab */
>> -	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
>> -	FREE_PCS,		/* Free to percpu sheaf */
>> +	ALLOC_FASTPATH,		/* Allocation from percpu sheaves */
>> +	ALLOC_SLOWPATH,		/* Allocation from partial or new slab */
>>  	FREE_RCU_SHEAF,		/* Free to rcu_free sheaf */
>>  	FREE_RCU_SHEAF_FAIL,	/* Failed to free to a rcu_free sheaf */
>> -	FREE_FASTPATH,		/* Free to cpu slab */
>> -	FREE_SLOWPATH,		/* Freeing not to cpu slab */
>> +	FREE_FASTPATH,		/* Free to percpu sheaves */
>> +	FREE_SLOWPATH,		/* Free to a slab */
> 
> Nits: Would it make sense to add stat(s, FREE_SLOWPATH) in
> free_deferred_objects() as well, since it also calls __slab_free()?

Yeah.

> Everything else looks good.
> 
> This patchset replaces cpu slab with cpu sheaves and really simplifies the code
> overall - I really like the direction and the end result. It's really been a
> pleasure reviewing this series. Thanks!
> 
> Reviewed-by: Hao Li <hao.li@linux.dev>

Thanks a lot for the thorough review!


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/792c6837-137b-4667-8c4e-fdc988ae8878%40suse.cz.
