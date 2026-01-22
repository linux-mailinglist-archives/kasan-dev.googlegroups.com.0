Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQWDY7FQMGQEU4LX2TQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id OJlCGcThcWmzMwAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBQWDY7FQMGQEU4LX2TQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:37:24 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id DEB046345B
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:37:23 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59ddd48f30dsf223064e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 00:37:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769071043; cv=pass;
        d=google.com; s=arc-20240605;
        b=lnrNZWnElx7cOHoO/Hk9FeN9a8SpNH+jkXJd+5eW7Of1V06IP0BHADbXrxmIUag8YG
         JaThssR5CL6D+OESWSx+7f2DBXAKbHOZC2q8BBWvSVmL+h6qQE9a2f3pZqyfkPtDOBPY
         qmvP1qIai+xVja05JZBmmd50A5LJjRHqMHsXdzD1Ws/QU3uLTHUU7DXI2caW1pvwcCNB
         lC4XdTMGMVhDvcRzC0Gn+Byu99d5yTmuP+TgaS2HZt9QYNcg/8fDOX8p+8TF5AA6nStr
         b5uBiY+5Epdd11sbjo2t5bz7FTozdtmNPSQhNZGJHREwrRKnUBgy5dC/vSt89rWEyyen
         Cmmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=ELsvth1nFCyI9GtJLfwnz7YnHbGNhzJkfx7jGtkBU8I=;
        fh=tQs1DrizVL2/Sp5xcid3thP0+QnKDZAaHA5e13XRT10=;
        b=cidvFF4Njg9QThUY/ryu1wTas7ijXDdoHLrE4rDoa6H/y3WqMHY7qiGwPW0UZFLhAN
         VZ9R17lFskyEGh1AVNDodxwRu5xUNUBQJhFYE063lFk950q/PxnV07RARt450RsgkvSM
         XWFTluZp2MPIdpO7exQ1hogVq8LzJA4XI+2j+VhD2YWXgatOPaoBOUCktHfvQq4LFRNm
         c6DsxOF7CVIrtmJfeaLTB3NgW3393pMPffRGovoq/mHFINBVripM59+s5dSh/1UiuvU5
         0c/mE7DIXfr4op9Ir/Qj4tOuTYOuaguJlgrAcqMs14lttQbDTg7p8sctMFlGTEOWdcum
         55jQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HsLZt+Gg;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HsLZt+Gg;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769071043; x=1769675843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ELsvth1nFCyI9GtJLfwnz7YnHbGNhzJkfx7jGtkBU8I=;
        b=CWn97s2XN2JZrynXsy3SQXpRD7aNZONl7q4s1AToSgmzURmflMdqvGToaGtJSVJd+x
         Cz47WBQualmtLS8qAQb8rfwIEpGsyat6A75zlmkGv5HXljqYCJa1Cq9vjKX/B+C7kPUI
         5Pt4rl71HqE8RpDQPkLcKdPDZkSVDDdgUqIN9fDNkAXciDQaP7xOmym5M7yeUmMP43u0
         RLWoIStgC6CZeB4Uuv47TR41RjLu7ED55HqTmC5BnPTrXf400W+VfG0M7NbnA579UQ/6
         4LSWWWYrxtHuqbkIvRBbzQhuhK+Iy0iKJXo3X7FKdTy2YJHvwGKhN53TAvhm3yZekJ2j
         6yjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769071043; x=1769675843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ELsvth1nFCyI9GtJLfwnz7YnHbGNhzJkfx7jGtkBU8I=;
        b=e3VOfTlGknqfXd2pa67BAdX1EkND90kWLIj0hoDAmME+W4PWxZqZBBcAoqdKxym5LS
         6xFsfeKxFaYf8bi5cy7fcIii+ncmvhyXMR1GflKrs380FwzWcyE36iPqMZFAw/QezaOj
         5e0jfD1kOCo4+MstYb22LE2ICYKQ0OkWO0RMuOKAAheCn0CcjmXjHDs3kag73di9EwjK
         goy2VuyXfSQcrU+I1TXm6tlW0oriaprQnNUHvlqQ/bwCVVBb1RHoTTtKfAfa2RbMGdXK
         gdbs8GRb4ioBXGB5z0CS0MYbuVPDTdWF+FDv7OyqA26f1ikiuMvRRbIrsRMqfehuM1p+
         5xjA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgfmjMOj+F3wOxJ/yuyEQWQwdUVJ0sNd12ecwnOIj1qJwUt1ZeI6ZRju8/ABjO3li3Rx8ScQ==@lfdr.de
X-Gm-Message-State: AOJu0YxrLtpUYKswiMMNONavclkNuLkuGkN2jFMPflRgobydpSO42g5U
	2DoqLbwGNzXT4HJjfbIN6WuYDyZV2aIjYXD5Ub+npHSacw744vIQLHWV
X-Received: by 2002:a05:6512:32c7:b0:59b:67b9:3989 with SMTP id 2adb3069b0e04-59baeea08aamr6890510e87.16.1769071043093;
        Thu, 22 Jan 2026 00:37:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F7H+ZEDtZKSZVYyuNusbonxMlpwIfBcUfoZFjSxcz9Ew=="
Received: by 2002:a05:6512:2313:b0:59b:a3bb:9e0f with SMTP id
 2adb3069b0e04-59dd797f506ls255480e87.2.-pod-prod-01-eu; Thu, 22 Jan 2026
 00:37:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUEgshGgMRYwOtuqy5v6URqrtGd2pENImSrsTzgdZCO8Q3q0tWyRmSFoZCORhg5+2Fq28/IHXgBrzg=@googlegroups.com
X-Received: by 2002:a05:6512:33cf:b0:59b:b3dd:996b with SMTP id 2adb3069b0e04-59bb3dd99c2mr5483431e87.18.1769071040355;
        Thu, 22 Jan 2026 00:37:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769071040; cv=none;
        d=google.com; s=arc-20240605;
        b=ZD6frF43T2jdL8ySbuvtzuV/UVU46YYw+k4XP0WfYs+hdNGP/u+Fgnxgt8rMtSAJNB
         MKzgoPPvZl40T8P3stRJig1fSPVYLMBzY8SPOKorXSXIqH+uvxtB8CChDacGnuiF9NLA
         SWipdJ3OLBJsT05h5TvGK9C/Z9UiKrlQXyiamSL+Cuc2JmrR2dNGqqbsvE3xWVwWPeeN
         oYRA2am/MmE3e60DLGtv4P6Y/cq27+A77aw1yxiyzoLuGvJKM3O4e4geD0WkAcufdlxv
         YWdcfjgW3SO+fPNQKGgTWHEu82azE62MpVQmaSi8WkFTue4GbuK+Po4Anc2/Lb5g2ut/
         5v4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=PhMSCpDyh7+8D4BXCTDHoTCid/2RtwqQ20a7TQiUGAc=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=Qsi3pWUWWFOYcqa+ElYTLxBBZp0dCKZVeSkjsCF4zkaePkihomNJsqOvOFsO4fdMjP
         J1wz1XyFroJCf+gqtxnHLjY1bJTPpeBj9kQJC2H02e4rTOjrQkm5Ob2jf02GTtRdmP/P
         YCZ6+theUP9RSiSviSTAHyrFaDasnkS4BqyBsXh2HoCKadzCEi5P88hIy3t/u737d9Sd
         pKzA0qtKmbbIfKGiAPsGMIqRBevYNdVvPcoiWjfZD1ikPWe+sK3C3DpoNgkbp2i8AgX2
         85lZ8O2sZchwfHzsWFl9b6ff3BZnEPZcnTS1G3W9VNKzkFtmG3juj83K8maEvV+hXkcy
         jIGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HsLZt+Gg;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HsLZt+Gg;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf3a1d4asi343542e87.8.2026.01.22.00.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 00:37:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 87B805BCC6;
	Thu, 22 Jan 2026 08:37:19 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 555613EA63;
	Thu, 22 Jan 2026 08:37:19 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 46l+FL/hcWm/bQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 22 Jan 2026 08:37:19 +0000
Message-ID: <4560a13c-a5cc-41ad-ae5e-ac40a0396286@suse.cz>
Date: Thu, 22 Jan 2026 09:37:18 +0100
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
 <aXGrQSOoG_6NdqNT@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aXGrQSOoG_6NdqNT@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.51
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=HsLZt+Gg;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=HsLZt+Gg;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBQWDY7FQMGQEU4LX2TQ];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,googlegroups.com:email,googlegroups.com:dkim,mail-lf1-x137.google.com:helo,mail-lf1-x137.google.com:rdns]
X-Rspamd-Queue-Id: DEB046345B
X-Rspamd-Action: no action

On 1/22/26 05:44, Harry Yoo wrote:
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
>> 
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
> Could this cause strict_numa to not work as intended when
> the policy is MPOL_BIND?

Hm I guess it could be optimized differently later. I assume people running
strict_numa would also tune remote_node_defrag_ratio accordingly and don't
run into this often.

> alloc_from_pcs() has:
>> #ifdef CONFIG_NUMA
>>         if (static_branch_unlikely(&strict_numa) &&
>>                          node == NUMA_NO_NODE) {
>>
>>                 struct mempolicy *mpol = current->mempolicy;
>>
>>                 if (mpol) {
>>                         /*
>>                          * Special BIND rule support. If the local node
>>                          * is in permitted set then do not redirect
>>                          * to a particular node.
>>                          * Otherwise we apply the memory policy to get
>>                          * the node we need to allocate on.
>>                          */
>>                         if (mpol->mode != MPOL_BIND ||
>>                                         !node_isset(numa_mem_id(), mpol->nodes))
> 
> This assumes the sheaves contain (mostly, although it wasn't strictly
> guaranteed) objects from local node, and this change breaks that
> assumption.
> 
> So... perhaps remove "Special BIND rule support"?

Ideally we would check if the object in sheaf is from the permitted nodes
instead of picking the local one. In a way that doesn't make systems with
strict_numa disabled slower :)

>>
>>                                 node = mempolicy_slab_node(); 
>>                 }
>>         }
>> #endif
> 
> Otherwise LGTM.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4560a13c-a5cc-41ad-ae5e-ac40a0396286%40suse.cz.
