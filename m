Return-Path: <kasan-dev+bncBDXYDPH3S4OBBPWQ3TFQMGQE2UAL5LQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id sHQ1LUAod2lzcwEAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBPWQ3TFQMGQE2UAL5LQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 09:39:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C1EB8589E
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 09:39:28 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-3831426aeb1sf11529631fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 00:39:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769416767; cv=pass;
        d=google.com; s=arc-20240605;
        b=TOMKWnGyX7cqUv1RFO91/ahzz1qk41g6xwT+xp/QzIjtGmSD8BytkrNKHQlji5YwAp
         B5yRTJYpiLLWWyYts/IxUeL7HgJVMw3bHa65nkLwFpE7FdRsFQtdgiHMsA967HaIG27L
         TQbD7yMbOX9uUC6atiwTyJ+iVyc59F+ddBA5JpFx9CjSZKxrDSzTDB1iZph6lAIm7BRV
         D6PgYB7c2+694QkR9Yqj2oNosYOK3SFzAVXEbJ1eABmdWPMmnH56tQdozYwVd4ihnkM2
         +UDlMWFLxPW/khPU+6QgXKnovYqYmbBpCvGh7e6LLd45OaHoixWwjn+pJXtxeRpGYmRD
         V+Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=SVat2kpvWcMeTjiu2KzB2/eUUm9up74Kxr7QVmH8T+E=;
        fh=fjMrnvEwxTtryMeFH8NWiu2WrI5g1qbLPx8zhbhjZZQ=;
        b=In2m2qbWl1Cu/vIhCMzBH49maEem3tOA7HFCRKKymy50ZjT+Qw6ME/BhwKGmHrKfTH
         risY1O7uZZPxWgsjIcNLdnl/2OynqLA+WOcMdeNKOcWryHi9ko0Iyo7LfOv9zyQivD8b
         jE4mFf9dmBfUXug+hgMJt3KqzqdmHAHP1odIItQqJ3EqIRwS3T6+qruEzrRiHMmEXd8k
         v61sjknYw8rmImDUJjpBQeRLf3EW5f+U2h9JMfUYTxjRUpP1QgMdOrr6b8wfaPoCYQvV
         /aKRBY70UGOCagOcPEiZBK9ZGOnypKW/j1zJbZ+piX13oEnGfKKmVFeHGg5tzIf4D7VR
         9aIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="t/waB+j2";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CSkTefY0;
       dkim=neutral (no key) header.i=@suse.cz header.b=Ay+WlyzK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769416767; x=1770021567; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SVat2kpvWcMeTjiu2KzB2/eUUm9up74Kxr7QVmH8T+E=;
        b=OS+FV3Cgf/JhhRvgTrYFE5+dODqeVHh8dHDReyeyonoINm+cehIvGNVpVWxmEyHF0m
         b6TRQXuel7yOBpFl+uvxqabAXfzHotj9Wrbr14F+0sy9y6yy87flTOAcHhPGsY8G40FT
         topRYRcFQ2Cvfu4M79X3u9RwDM3W3l7hF1ywcke5Fr/ViZ68nA/Z23b4tQzpmchuwJu5
         RJ6sjNK5H0c+1LI6d3BaWHbtDKV6vKOs3oqhxBXb6Ra+674xEikGuhtKqJ2wkiuPcbIa
         YMOkXO3CZvEnVRKioWj3X2jnlAyv9rKHei2Q5ba7VUjEMgKXuhZBoZ3z5YxUHogUibr3
         bZSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769416767; x=1770021567;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SVat2kpvWcMeTjiu2KzB2/eUUm9up74Kxr7QVmH8T+E=;
        b=KbtQ6UIvV8Ab/Myvj72V0Do9RtTxWuPGL2XK2YwpjWe9OsnVoib8IQRNxYwT8N0nkJ
         iexfxBPoWyIGxP8MdXEFnYSmouZxDx8Jp52YyJKc2Un7z4db59llrgS5Wk5Q4p16dUAq
         gnhzsJpdIZ33XrtxLB9S/5sf0iuwAp12dPKoLS5T+mHtnhS5qMSDuM1X78xuPyHdx+tp
         cFq//U+rp2u7kL2Bytm2Qm1OvgMB134t62dOSBa23bKnDfB+/ZPYls1hkIUB0F8x0hkb
         TrogyJvDC+Z3bWP0K0mD6KzqZgGRSOmTH+y8hIooTI8V0K030hffUaitex4EdzcZDzxn
         GyrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWCovSx6BLFsJwgw+7U5AHN6Gu/17H4IGZGz998ON51M/lXE4Lxf/ZuDCg2f+ZxjMSSqojyzA==@lfdr.de
X-Gm-Message-State: AOJu0YzELOazXlgkdIny9gzjBDTdh2ilvDkF5R1PFTIaEQV19BJV94L4
	JM8zGnNP7O0QkjoiKq7Ss/mbjry6oAtNA96wcSG8BbCRFWQ/ch3vQOGu
X-Received: by 2002:a05:6512:3b99:b0:59d:c4b1:3993 with SMTP id 2adb3069b0e04-59df35d7319mr1023861e87.2.1769416766895;
        Mon, 26 Jan 2026 00:39:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E7CF2Vku4bWjhUryPjpAFjTa9M4FJSVR1MiRbCgBwAEA=="
Received: by 2002:a05:6512:2313:b0:59d:d722:902 with SMTP id
 2adb3069b0e04-59dd798229bls1731519e87.2.-pod-prod-04-eu; Mon, 26 Jan 2026
 00:39:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUcy3TQvyYjzG/vUQSrd1SsEouBqi1lYFRypoAZssYBrmua/AoBp9lT8CFWN2lhgs79UJl/RqNosHg=@googlegroups.com
X-Received: by 2002:a05:6512:110d:b0:59d:e5f3:db1d with SMTP id 2adb3069b0e04-59df390da35mr1248921e87.28.1769416763769;
        Mon, 26 Jan 2026 00:39:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769416763; cv=none;
        d=google.com; s=arc-20240605;
        b=bm0Q8dCoLRrnEAMsJ+qI00Nkcx78UwhrfSABp/ZtCo0557OmRTqv74bEprsPylqNZ/
         z3FoY+T/D3WjzU3jJDjdv7tNkrvhMCJN+yEii8NhsxvINIBDRjFO+TcDH0fB3jCRu2X6
         K5SDC/Glot8xuADv7OIhQsl53UkRLfWUyPiNffAHSe8gCn0VIkr21K7LjKzsIteQ/MUb
         yxzxuTA6JJmMaN42eM0BmAuV2Hxl0IKtRGUKZ2kGEVOdmbqYb8QSLzLTVVnGEr4XijDu
         hB4Ux/56FmWOnM5iMt2ESXlmikCcz2h7wuQec02ujnKqjqDm4/Q73gju9fe+BFg5Ig9H
         It1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=C8apTRjaXyVloWrbPyJGXpF6txJlbz3ZAwUoAcFkvk4=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=QrgQslfZE1ZcF04OUZ7JPQtgNY6fWlZNxD77718bBWcJVBGIy8RMz5gVZ0qw8EmLcn
         97STI9KER476h6Y24cfuSjQolH6nsLxAqq/N+w18WITJcLvHK4ISWlCVWPVRG8lnToqS
         9gtEgQ5Im4nFvehNbqdiNidHb3Aww+Mv6lVd5VwcFAgyvDT6whP6pUcjzBJRG/s16vwy
         jqXZAXizIzZvACqeRuTsZ7edFoUtrCcelG9czg0/YxY/20MpeVOyOeZQjvageOqTsz8O
         SKGWFq9IAEMki3yxAYpqTrRiPZ9IX5STQRoL1b5MVr7fksIFlM8uEAfhsXIeZyitlL2F
         z+wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="t/waB+j2";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CSkTefY0;
       dkim=neutral (no key) header.i=@suse.cz header.b=Ay+WlyzK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385da12e5c5si2290631fa.8.2026.01.26.00.39.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 00:39:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9CCB9336CE;
	Mon, 26 Jan 2026 08:39:21 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 729C6139F0;
	Mon, 26 Jan 2026 08:39:21 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id XSH7Gjkod2kQJwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Jan 2026 08:39:21 +0000
Message-ID: <ff10180f-0b9e-43c0-93ff-b421ff1454c6@suse.cz>
Date: Mon, 26 Jan 2026 09:39:21 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 06/22] slab: add sheaves to most caches
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
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
 <7tds765fsicczreeqckiuwpny2tolotfrnbz6jhpjrch6x5pg3@5irfwnohvsli>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <7tds765fsicczreeqckiuwpny2tolotfrnbz6jhpjrch6x5pg3@5irfwnohvsli>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="t/waB+j2";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=CSkTefY0;       dkim=neutral
 (no key) header.i=@suse.cz header.b=Ay+WlyzK;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBPWQ3TFQMGQE2UAL5LQ];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.994];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-lj1-x23f.google.com:helo,mail-lj1-x23f.google.com:rdns,googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email,oracle.com:email,linux.dev:email]
X-Rspamd-Queue-Id: 3C1EB8589E
X-Rspamd-Action: no action

On 1/26/26 07:36, Hao Li wrote:
> On Fri, Jan 23, 2026 at 07:52:44AM +0100, Vlastimil Babka wrote:
>> In the first step to replace cpu (partial) slabs with sheaves, enable
>> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
>> and calculate sheaf capacity with a formula that roughly follows the
>> formula for number of objects in cpu partial slabs in set_cpu_partial().
>> 
>> This should achieve roughly similar contention on the barn spin lock as
>> there's currently for node list_lock without sheaves, to make
>> benchmarking results comparable. It can be further tuned later.
>> 
>> Don't enable sheaves for bootstrap caches as that wouldn't work. In
>> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
>> even for !CONFIG_SLAB_OBJ_EXT.
>> 
>> This limitation will be lifted for kmalloc caches after the necessary
>> bootstrapping changes.
>> 
>> Also do not enable sheaves for SLAB_NOLEAKTRACE caches to avoid
>> recursion with kmemleak tracking (thanks to Breno Leitao).
>> 
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> 
> Also, looks good to me.
> 
> As a side node, while looking into the test results reported by Zhao Liu [1], I
> ran a quick test of the current patchset with the will-it-scale mmap2 workload.
> In my runs, tuning capacity up or down did indeed have a noticeable impact on
> performance. Hopefully we can make this tuning even smarter in follow-up work.

Right, thanks for checking that.

> [1] https://lore.kernel.org/linux-mm/aWi9nAbIkTfYFoMM@intel.com/
> 
> Reviewed-by: Hao Li <hao.li@linux.dev>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ff10180f-0b9e-43c0-93ff-b421ff1454c6%40suse.cz.
