Return-Path: <kasan-dev+bncBDXYDPH3S4OBB6WFY7FQMGQECX4ZVAY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 2Lz9HPzicWk+MgAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB6WFY7FQMGQECX4ZVAY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:42:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id F188163576
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:42:35 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4802bb29400sf9791875e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 00:42:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769071355; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ae0g3IjOw0wHJlPVegRDZ6lM5tkiumXJ3vEhaVnANeucNPdcJnhV/V2ghkGqy7xDLp
         HMjmRXdW0zJqkSQU0q0XH6bnxPvSYcytNGzTJIGBwGb4cwVmJ7cx6k+x2+huCTrHksMI
         76+qY3uy2AuZpw5HU5nBsFTeJSqlzjK4S1qH2CS2froJ1eIt7Ijb/eX/hL7Glwft7Tza
         4hpVpmpeA/4YEbUMZumVsfFzXo99KlE5Z914pwccboA6xJpnSZDz9AKfuY4ova6J4iMl
         pzajLlKbkJ6MxVbzejDbhE8tFQ//ULtWH2ixfnbBh60IsxHBHkehK6cNre+Kjqk6eNF/
         Tz/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=E+BYx+bqFHrDmDhwKYowF9RNZAibZ6Ky4pjjXDxyCSQ=;
        fh=1h2gfHAsg29P6Giu2KOkiL3RRKtg62zeuRXbCMb/Fmo=;
        b=YDPVq+nIMLkzrAFAbs+5FkXMVbDcXY3BvPAunIbN5o95Werd6RjhcIKyr5BAxutH0h
         Kr0J/or+B7cjY9sJPJhi3+AqNgXl2T1aLY/m7WB8deTDRaqgPfGMImGJNw/h9uXZfin8
         lSLuDCFp1cJgLlg07sKCLE64r26advGFGDVbDkKcxU6YvHEJgrKJmsw9KWhctqEzUeAJ
         PBUi6OZ6+/16f43O+gSKloLd9bHnuMDBmxpoeXq/T4b3YN9n0YTDnkTC/dF7nLOd0JhA
         DqlTgeLlIg9BADrIZclcOpA+hqCvsrb1vda0BDWF/iET61wcy6tAz6DFTjxAP8r+dreo
         8peQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uhvEYvyl;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BN1aHwYw;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=beOCQ+fX;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769071355; x=1769676155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E+BYx+bqFHrDmDhwKYowF9RNZAibZ6Ky4pjjXDxyCSQ=;
        b=Ql5dk5PD63CekW2AWERUmvf4KkDJ4Xvd5jMYdoXXlTkm3jq5zfKgwIEmT4LPBqLWEp
         xBENMqq6eSTM/q+dJwGiJDXLPe6PtXqF+s/ZjhZ1mZ6+a95M+BUYcphZ+Mh3Anb/xFEo
         LKORC0uHunyR0Qe391phJdjnjkcq1S9WEnTlgbKNi9wS66ZviXeNvo5p6piR6/80YFRy
         7T/vVezkO8Tdc7K9f7NwgesNSjJ877/BMyCS4V+89Kw8TiGiZuOhaEgTTbYWV++NGV9U
         eKEasPdFuler1BbfzAnfG1IHKv+B2PW7eEinMPOp4lw/Rw/dag/Lin8Vw+EgPbWeuKWe
         +ojw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769071355; x=1769676155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=E+BYx+bqFHrDmDhwKYowF9RNZAibZ6Ky4pjjXDxyCSQ=;
        b=UfGUfd5f/tJUnv61tmIeU+ZfAhtVb7c7GGGuPoni7EcH5PTsv21mnpp+d1ZLPW5Ah+
         2d42OOLuFPYMSvYGJoY55g2RvoaSS+x8oVj+e2cjmHEQHCAwyAR/n4pCEtHEog8MDg1G
         crGBC5OLlsIuj6CqSbKjM7wywwTCduRj1oBdi5GnaauvORsw/TNbyO/tWzrA6yAZ1Vf4
         hBlRX42Jbm4L9xTdf03XLOd8hztxj1vN2UTOaj9NnDXC3JhanZpoeBjgsKyLuCQW1ldD
         QtE/+eK50GbzPKyA59E+r6iYv0js2JrYSb3tv+8LMxIrICaOoesHTkwGTtQZ/q8e3Rk1
         +aRg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1icniPiE9LWgC4kF22GJ2QI3MQxigvwwin6ZSCRS7/LbJhjBHHJG7l/jQrvujrhAWDh+j9A==@lfdr.de
X-Gm-Message-State: AOJu0Yxr0ZVSvSvWCVfXRE6JHoAP092fML/bwqd72K8jLJD0/gpvalxz
	S0Snew3JyYkimI/suizy3dCF0HqoWo0Z2EqSU53ZqpDqZz36DFers18E
X-Received: by 2002:a05:6000:290d:b0:435:ad52:31d4 with SMTP id ffacd0b85a97d-435ad5234ccmr1194641f8f.26.1769071355031;
        Thu, 22 Jan 2026 00:42:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HB1WV9x4pbIHbZCaAgrDR+bBLFAzMSZKKsD88ZTMKaJA=="
Received: by 2002:a05:6000:1862:b0:429:ba6a:3a77 with SMTP id
 ffacd0b85a97d-435a667c87fls350119f8f.2.-pod-prod-02-eu; Thu, 22 Jan 2026
 00:42:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVKiUr3svn5o2t97ni1z5sWpWX4/eS6/ZmnCR5iv7iiKRdfL8slyWi9ZtPHj0w8Dj4m/xLPCkyQ+I=@googlegroups.com
X-Received: by 2002:a05:6000:2485:b0:435:9851:d940 with SMTP id ffacd0b85a97d-4359851da13mr8610758f8f.59.1769071352792;
        Thu, 22 Jan 2026 00:42:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769071352; cv=none;
        d=google.com; s=arc-20240605;
        b=NaZB0b+SiMX9+soaK3CShfMx28ZjyiF+Inph59uC2EbQXfqYBhpEtslE+AKPTDSMpG
         DJguF3LSyJ0VBShcIe5u3Xd5cLK4ok8UcPUbtCBvShjV3U5+k3swhmR/htJ6xhu7T1oi
         eZSu9IEWXi+rIp3RwkLX4vG7jTIZn6yGDV8REc0wPNvniYsL5TM3lPMO+MCnOwgIOFWs
         prjJkl4x2ARQ37hYZsp74OuEq12HZWzieTW/LyE7Rwd4FBhQtm4Ppl18leqJU5NDyLB/
         V+9f9gqKQTefNhkOennrCTTCmV9ZxdVvk54Fg6knL9JhI817N3G+/pCYBArFUGaiLphG
         kNJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=wtkavSVJht+G/RwkNgcjxFWYFwzxqjQgltbZ6uHMgU4=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=BujubI+yqW5nHlwpq/jHJS+mkp/sP/LfNtPaOnd364A8RW5tD1EQQKM6WjkFMyZu+L
         l1hOv31KjswXaL/+RGZWqSGRGpEpgq6d971W4V2GzrPMMnKZLzbDbeaSV/wWKS3ijhvH
         gxXmZLxNoDuU5W6r6/4IxuN3VwxU0d5khudlqhj26VDOuGp4MnEf0J3/47ZCjhVJ2CS3
         sUy3FwJMp4fiaIG8c2uUCfAspW6TZ44YGfIqqM2uZOgb8SO+tXMSI3hM4XYvxv3R4z8K
         iA+6m4X1OfM2kcjoDixWBtSBWqr7IUsPUQtRgdw7CbdleK7FY5rrFMq3HEYxOZXpUEvC
         cTQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uhvEYvyl;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BN1aHwYw;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=beOCQ+fX;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4358dd61998si166126f8f.9.2026.01.22.00.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 00:42:32 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id F021333697;
	Thu, 22 Jan 2026 08:42:31 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C64373EA63;
	Thu, 22 Jan 2026 08:42:31 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id QsbALvficWkRdwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 22 Jan 2026 08:42:31 +0000
Message-ID: <e341d9ef-9ec3-47c6-b5f0-3749c930f477@suse.cz>
Date: Thu, 22 Jan 2026 09:42:31 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 17/21] slab: refill sheaves from all nodes
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
 <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
 <aXHLhF2kJxgy4M00@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aXHLhF2kJxgy4M00@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=uhvEYvyl;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=BN1aHwYw;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519 header.b=beOCQ+fX;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB6WFY7FQMGQECX4ZVAY];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email,mail-wm1-x33c.google.com:helo,mail-wm1-x33c.google.com:rdns]
X-Rspamd-Queue-Id: F188163576
X-Rspamd-Action: no action

On 1/22/26 08:02, Harry Yoo wrote:
> On Fri, Jan 16, 2026 at 03:40:37PM +0100, Vlastimil Babka wrote:
>> __refill_objects() currently only attempts to get partial slabs from the
>> local node and then allocates new slab(s). Expand it to trying also
>> other nodes while observing the remote node defrag ratio, similarly to
>> get_any_partial().
>> 
>> This will prevent allocating new slabs on a node while other nodes have
>> many free slabs. It does mean sheaves will contain non-local objects in
>> that case. Allocations that care about specific node will still be
>> served appropriately, but might get a slowpath allocation.
> 
> Hmm one more question.
> 
> Given frees to remote nodes bypass sheaves layer anyway, isn't it
> more reasonable to let refill_objects() fail sometimes instead of
> allocating new local slabs and fall back to slowpath (based on defrag_ratio)?

You mean if we can't refill from local partial list, we give up and perhaps
fail alloc_from_pcs()? Then the __slab_alloc_node() fallback would do
allocate local slab or try remote nodes?

Wouldn't that mean __slab_alloc_node() does all that work for a single
object, and slow everything down? Only in case of a new slab it would
somehow amortize because the next attempt would refill from it.

>> Like get_any_partial() we do observe cpuset_zone_allowed(), although we
>> might be refilling a sheaf that will be then used from a different
>> allocation context.
>> 
>> We can also use the resulting refill_objects() in
>> __kmem_cache_alloc_bulk() for non-debug caches. This means
>> kmem_cache_alloc_bulk() will get better performance when sheaves are
>> exhausted. kmem_cache_alloc_bulk() cannot indicate a preferred node so
>> it's compatible with sheaves refill in preferring the local node.
>> Its users also have gfp flags that allow spinning, so document that
>> as a requirement.
>> 
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e341d9ef-9ec3-47c6-b5f0-3749c930f477%40suse.cz.
