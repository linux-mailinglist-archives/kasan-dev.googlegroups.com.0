Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWG54PFQMGQEILYIOVY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eBKeMdrueGkCuAEAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBWG54PFQMGQEILYIOVY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:59:06 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6814D98176
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:59:06 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4806cfffca6sf728295e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 08:59:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769533145; cv=pass;
        d=google.com; s=arc-20240605;
        b=VtdItE5aGHQqQNgJZ9AhKFPNAefLL1JwczzkzHWfNNY/rsE7rO3tTWig0ACFDb3TjN
         SmLvYm+3vMQIjRQzDRQEt/O3pKy0qwIQMsWpUrTu+Fu4ye5HVDWbxlaDdeRahxwT7zf8
         Fz1bmgt/2tuLjkuplO4jIxYEV7xMkYsT6eW2r7r8jAWuh/aC8nT0ykml07+9dWlKFYE7
         f+InCNg52AXYTV+49CgMODtUiD9khVTpv94KRlt1bhpJkdvHbwJ7e1PMhg2vRYnUaBRl
         sSKERa8wKqcO6FO8RFWWwfCurnOC66gPxioJLhaZ5LkGDlJxCM1rAOBXv5rYdv0uL/SY
         P7VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:to:content-language:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=TWhYNHaaaX4E9hVda5cVfwiY/mEI0ZX3hlZzX3kNEpg=;
        fh=MRd9d7LWp5ZHiFoXGQsNmuMa6sNw/wVEFfCk7oScVlY=;
        b=RcMMU2pudefHJV7IwoUZxyjY5ClC/iff3bPFHCNUuS95AL2nYGxxRj1UuvhuFvwz5L
         8+E8DsKiqRStV7UvgmWZ8AQu+A7/KXVa1JnxfTVFwSw9k6GPLCVHxOyt3oMKsz3HT7L7
         N5tCKVXf/rRnhmvtiRSimrpaiGMu/C2rimcWRgW4QJ6Lk46g0FfmP54Q3/OXbJSr7C6R
         q23kaAbQO4b3gm/zWLwLnLAqIlvlcAzo0C6I9dLFdavxOxFkyhi+rv0My2i68yySz+5v
         PbXIZOgzaR3uzeRdVox+7ttEWTB8awt+MPETdAB4QdcfIOe63ErL5qPfmsyz1kOp03xb
         gwkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wclOPg1p;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gyv8sEDj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769533145; x=1770137945; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TWhYNHaaaX4E9hVda5cVfwiY/mEI0ZX3hlZzX3kNEpg=;
        b=hpXHiCXcBZfLw0lHHuQxZPNdpSrF9pw6UscNSsQDwQSzMfg220QhwQfh64hARffCGx
         O2toL/kjvZE8AzX8bmgKx3HYAKxI0/YxPf1CxOmZXClKr7Hg6e3Z5+h/MXNw+HepR8Al
         xhX5uQ89TrPFjIfA6DIbRvl6owHotaVkkcl95vcH1docAQwr70wFtpUTmiCHyk1qgqb0
         797ht/d2HiUviUOqGV13GRznP2lxVuOnsTpVv0s4X50dfpgJselGjemw/b3lmsRL+TgD
         JmF/GDqtAaqK11W8zhQUsfcvnhjHIj1IWFUQ7PdL8ZEei3o0k4SDOscTN3rmF+yyKjGo
         NrEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769533145; x=1770137945;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TWhYNHaaaX4E9hVda5cVfwiY/mEI0ZX3hlZzX3kNEpg=;
        b=hWtbDPLlG/a4xRmpC0hM+YvetpM4t92GTSkPdWqivCa5rePV16dgvK2Tq+SaJFT/Zq
         zSdFOKY7gZPSHo+OQIZo3BrTSsH7oLDMxy6AifTbyu381tn0H8b5J6vxRID2l3qP4OQJ
         sMQeXJ3J5iQzB1S9g5lLM8Y5WpZGUvDPOoyR8aWGJJodXcSfnuDCNyehZpY89LSiDady
         AR92tcfFRaSKetKmbPp0DyPEGweARqHJngR5cOYP38efOfco69PuALowlbQ9xfd8kyQf
         5SqSARjWJK9ptnssipAnWocyGrq+abyJWrTzlbd9Z1RuaKjA4FfL41VkWfh5CiYfTpk1
         usYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVNy8smC+XCrmMXi8xbcD64xZJk/hXLR25O0gelpdjoicX7gP3FghCERCqbiWpxS6NccvWAHQ==@lfdr.de
X-Gm-Message-State: AOJu0YwAu2KHLXj5Kz+s+PTVYBQK5uEZyvkM2e091ilOzXzvwJYGuzDb
	8+SRfupvkk40UortpTWTtKcIGDSRM6hh5QaqTMlzQm57T15FIueT1ZJL
X-Received: by 2002:a05:600c:83ca:b0:480:4b59:932e with SMTP id 5b1f17b1804b1-48069c1c2e2mr31856005e9.11.1769533145135;
        Tue, 27 Jan 2026 08:59:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fn0ON1bpOBik+S7I4cEPalGe5ftFSzF9gIZTtR7q6y7w=="
Received: by 2002:a05:600c:4f14:b0:479:10b7:a7cb with SMTP id
 5b1f17b1804b1-48046fcd8dcls52238245e9.2.-pod-prod-02-eu; Tue, 27 Jan 2026
 08:59:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV7nNuafKp3SCDxffdq0+bbfzTTTz1w7MN1T1XVsqtzUQWxfRTsKvbsD0PKePpK59dSOjTFfOwWjno=@googlegroups.com
X-Received: by 2002:a05:600c:198d:b0:480:6941:d38c with SMTP id 5b1f17b1804b1-48069c612e8mr30361545e9.29.1769533142896;
        Tue, 27 Jan 2026 08:59:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769533142; cv=none;
        d=google.com; s=arc-20240605;
        b=TeC8W4+Az1rE79VX02MslLhucngobV4dyODvxQiYdh6hFpyiKLEOflPQ5KYRJJyJFH
         ie+3NHO7NutvJ1lvNAm9CIhuYkPmrUbTZoHTCVaAP5IgmjK3Cgd6z8gDO1pxemNZuXje
         1N5yjP72fy+t8YbkDXTDoXyUE4932DbAdGuWvfcmSLvuLgYOnp9wHD/YoduZ+pGElYei
         5HFPpvXyhqQ3nNJKRO9FFndIQuK+xv0I7dEGYiCfbmXxBq0pRt5iVU6ODbVJkUV+8/EI
         kMQjU9kr+uULmF0ycmkxgD9pHPwXIzg7jqTvRL1meOZCCPf5p814JW+zTCeRH5VogGMR
         FXmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=WljwI07n2+POd5G3jOFC1Ra4Hx+nfwNNAlR4m7oDBUQ=;
        fh=pzgFsP8kgfqhIqdVJd6LP0zYmV+bZWHLO4VEstKBt+I=;
        b=MY+YzueEbw/XctwvYXDx3W0+UvOpaLYovl3z7abpcbtB09NZuV82rJ3nrq9OBdsdUk
         8fkAONvUa2UpYWSj8+SWV0NFTBLQ3cXOiP4rINJThTY0TzI5wx7yoZBPwxLdGtwHoP5g
         XUWtHzqSf2oNdHPGFaMQMncpkVK4653bZDL1+a0fX0dZIxOh+qZOgNDFNYX8cKeVYMMW
         iyvoXRY4YvPOTIiZWl/ZZcKMdf59yOeYoZUgmvAqB0Vd5HwDynNIz1XGRiYsntHvE7EA
         byGBEqMNE+5L3r8L4cn7HL+0VA5Q7UrHkb1l3Jqm0l6G7q4bfQ3P1UZSh3b4qp27Gc/E
         Ld7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wclOPg1p;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gyv8sEDj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4806a990d24si36695e9.0.2026.01.27.08.59.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 08:59:02 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7BC585BCEE;
	Tue, 27 Jan 2026 16:59:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 51F9A3EA61;
	Tue, 27 Jan 2026 16:59:01 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id RFauE9XueGmgVgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Jan 2026 16:59:01 +0000
Message-ID: <0c7b552f-c494-4d0e-b956-38b5e235917c@suse.cz>
Date: Tue, 27 Jan 2026 17:59:00 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 04/22] mm/slab: move and refactor __kmem_cache_alias()
Content-Language: en-US
To: "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>, Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-4-041323d506f7@suse.cz>
 <xvdhietnpfl6ait3kjwxu3nrrzdpwvt3zp5ui4l6o7t7yps55g@wygbtepochfg>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <xvdhietnpfl6ait3kjwxu3nrrzdpwvt3zp5ui4l6o7t7yps55g@wygbtepochfg>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wclOPg1p;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=gyv8sEDj;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FREEMAIL_TO(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBWG54PFQMGQEILYIOVY];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email,oracle.com:email,mail-wm1-x33c.google.com:helo,mail-wm1-x33c.google.com:rdns]
X-Rspamd-Queue-Id: 6814D98176
X-Rspamd-Action: no action

On 1/27/26 17:17, Liam R. Howlett wrote:
> * Vlastimil Babka <vbabka@suse.cz> [260123 01:53]:
>> Move __kmem_cache_alias() to slab_common.c since it's called by
>> __kmem_cache_create_args() and calls find_mergeable() that both
>> are in this file. We can remove two slab.h declarations and make
>> them static. Instead declare sysfs_slab_alias() from slub.c so
>> that __kmem_cache_alias() can keep calling it.
>> 
>> Add args parameter to __kmem_cache_alias() and find_mergeable() instead
>> of align and ctor. With that we can also move the checks for usersize
>> and sheaf_capacity there from __kmem_cache_create_args() and make the
>> result more symmetric with slab_unmergeable().
>> 
>> No functional changes intended.
>> 
>> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> 
> One nit.
> 
> Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

Thanks.

>> ---
>>  mm/slab.h        |  8 +++-----
>>  mm/slab_common.c | 44 +++++++++++++++++++++++++++++++++++++-------
>>  mm/slub.c        | 30 +-----------------------------
>>  3 files changed, 41 insertions(+), 41 deletions(-)
>> 
>> diff --git a/mm/slab.h b/mm/slab.h
>> index e767aa7e91b0..cb48ce5014ba 100644
>> --- a/mm/slab.h
>> +++ b/mm/slab.h
>> @@ -281,9 +281,12 @@ struct kmem_cache {
>>  #define SLAB_SUPPORTS_SYSFS 1
>>  void sysfs_slab_unlink(struct kmem_cache *s);
>>  void sysfs_slab_release(struct kmem_cache *s);
>> +int sysfs_slab_alias(struct kmem_cache *, const char *);
> 
> nit: the names of the variables are missing.  I guess because they were
> missing before.  *s and *name,  I guess, although they are *s and *p
> in the other declaration.

Yeah will change both to s and name, thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0c7b552f-c494-4d0e-b956-38b5e235917c%40suse.cz.
