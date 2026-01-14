Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5VHT3FQMGQEP7UKHXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 70469D1EF28
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 14:02:47 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id a640c23a62f3a-b8720608e53sf374428566b.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 05:02:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768395767; cv=pass;
        d=google.com; s=arc-20240605;
        b=M5ilM8LM103giteb3pkZaVrDcXYXwfVLQAeCf4Y27EseP0tdLyXPacZWycAJGYboC3
         nnPkLN6bd3oe7W8OkOQ+/w4BvZjSB4EHG+zF8A4404JMleIXJODpGu/ofmD8MX9x6/97
         bPdqkWskSLTpubLypKcO80SD1ylXfr9b3RWb5ZOp+kM5+a0ZKmNdY/NBW6S4swTThQJI
         5aSMmxQw1zLnrY9Pe/AZrd6WUERpSef1QuufqISx3mv0OUl2H8oNsS3IT4Oxsk4UPNX5
         5llRBya1vD4CvYsKi8iSPUP2Fxnv7p4NsPn59Utn6Qws1IeEFeNqhJ28X1PzGMnjc65A
         7BiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=SnFiWKXevfsRV0ZNkDNzXwZTWogu6m+MmaUMKiAZovA=;
        fh=tJwe4O9zsLXi4bq/z/CEW0ypgL1w5/ElPpVu93NBsuI=;
        b=beKMoQrTu1jTzdwi0uL7xuG/polZlPuTW6fcd50ulFmepqpTGNAAl36OqQZ1KJiZQL
         AjLG1rJjYZBF4E1pDA8230F76yiyEqtMPqenntOQCaekrfHmGuxm2j2K/YRPwrw1hEVJ
         l4maMOZexh6yahlPHCLccChq1JcVCbASKgaKlfsMmL75H/OEsniuc+Q8bL/LlusIXVDX
         qLK0kTqPTBpE8VQAc7xMahVaBsOveH/0Ql3HN8CtgMzUCDUq5z70LKxzYJiz092a2fY8
         Q8jUbRsZEl2t3L46AuExbFA0zdb2wRPEQlRNtfzst1jE/Kc8T9oynuzWGzJ1zODhijNv
         Xtzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pjublQkv;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pjublQkv;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768395767; x=1769000567; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SnFiWKXevfsRV0ZNkDNzXwZTWogu6m+MmaUMKiAZovA=;
        b=hk2itOxEOF1fLFU84hInyzd3JO6EEoy62nGq2auRcOvPsDoPrFEM/bB0EckxzTKbaf
         Zat1qB9xpE/q7L9wIbZJpuazH2I+N5zkEXyJkgzNQWsi7Sod4YsG2FKV9pveJng7yr1g
         0moY8fJrutESIYIWCF4JjF+svVo17thZY0Vb9vRwnCpKkY2QKM2R8AmUW1syDGqVq5sC
         yL/aYSJdCQjMHxDt5eTM25nDASRTA8SDERTiUC69MIsxOa5YEUmt1ZtRUJKVAYdTUfW7
         jIe2pfbQvxIgFY0lTZDSLFCrjKreSkdrjB/r023Alwyl6JhSLaQSsXYaYWj8yu3wVqAu
         dAiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768395767; x=1769000567;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SnFiWKXevfsRV0ZNkDNzXwZTWogu6m+MmaUMKiAZovA=;
        b=bAAYnCLIwaH3apa1AcJEEVzDz9jn639/O//NTlbsElurZ0nw5VQZBx8ajEVKMi9csj
         81KwZSeyVqcV6jsmEASRuaK7SFP9Z2rUEd68vGKtBmxAIESosoeB+5QOAixga+gmOIki
         oJ5okyIWphitO5Z6yU3zEx6yBjz4bGZb/7htFDT1Suo1y/D9MncZUtT0FiRAyH163sRj
         AcJcvgkJjrHpbfjgzgK8JgsZSAYBhTCZsXiX+a/6Y52hkHwuA0xtsQyxQJrrBW6FoRFq
         wa4Y0M/DW5gpjiAVS2vhpjoq3ptBfadsaSC8DYbz499ajlnSITHI3JOaF/CaSSCX0cES
         RoHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/hoeN4SBJqnaMt6qww/2/qi7jmjj5AHya1OEA6v2Jn84+VSh4gDoD+YFEwNb8VFSP7Mh4wA==@lfdr.de
X-Gm-Message-State: AOJu0YwmrNZEPbP6C1mgnET4WFvzz26yeY15+9t7CdNh9YDYaHFteRnu
	th9uRTL1ZAvkUSirATuV75i2ZkepihIUWWWHqWcwIi5iCMnLBfebcomr
X-Received: by 2002:a17:906:f049:b0:b84:42e5:2b8a with SMTP id a640c23a62f3a-b87612dbed6mr234791466b.58.1768395766630;
        Wed, 14 Jan 2026 05:02:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FUAYfx3pZjmZP7Ep2Lg+Ap5LMwU1lebRj+CYLfml/nrQ=="
Received: by 2002:a05:6402:3049:10b0:647:9380:1086 with SMTP id
 4fb4d7f45d1cf-65074a067d3ls8056911a12.2.-pod-prod-08-eu; Wed, 14 Jan 2026
 05:02:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWFMn6BlhPwbRZP3HWSQ1PB4t3ymBZrc7tJZB/w4iAt/4rVwtXN/0NE6sp4KslkrEHKdZy359tgEJU=@googlegroups.com
X-Received: by 2002:a05:6402:5253:b0:649:aef8:f9c1 with SMTP id 4fb4d7f45d1cf-653ec107caemr2254851a12.6.1768395764324;
        Wed, 14 Jan 2026 05:02:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768395764; cv=none;
        d=google.com; s=arc-20240605;
        b=FoAzosDMPMAmXSJEozbWjwnLtbppSwIkCOUCJG+5R55L05vgesq9I/B1xjWEX9qjqn
         C6jhVuKTN3KdcEo1nfeDxzU31LjHckHpMpV/fTlUBobRQUPA7TIVXy8IY5y1egQq8Lgy
         kfwuoEg8+e7332aFSnUovo7ui3WGy3DkyRdwCz9sZt6ihnTlFq0EVCGZ2rIsYV4LjP45
         AiHp+1Rnl3/uObecWx3X2Rac90g5q8NNDAJJo7h7kePO/fH2IjrYOPafPDHkoZIGEidh
         C0s3zEwfmGz1B8lvTNelifOI/2kzi12Cu9B+MRY/A/08pvAf+1ZYI1NWHc7UQTVJdtDD
         BGPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=p6bMmRw2R7L6Dddrqe3bLvaJdceLum7kKPXQ4mHzLIM=;
        fh=gKwGuPofcdnEMOxvpmVBXqqrScHpnhhBJIGm7hu/giw=;
        b=l1+DLJuMckx6gL+5h8zGljDI+1mYCSJPmbDfrhgZGaQiogSUeX8Xd3EF3MnxYkOEVV
         vh/ykEgA11ujcBiOTDATzNEHn3z67EAe3EgC9uyRFAie+O3x7Bi6XxR2TWpWxPPFfLjW
         3kCdYOlArZ4uxoPt7L3Gke8COY0F1R0MOy8k3pv/cahSXIxkuGhco5BHme7U27NmV/yC
         GC7tExFQMi6xdkQSzwEhAnhIdddI9psBv92q1NnE1Sqyi/b0XQyro0bsp48ykWRw4rhi
         Ys7hphn+2+LVYS8Nfzd/fizNNuh+nMRmL7U9KVQF2nXsWJ36JNSzVqMxuP4lKkqA+5E2
         PWxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pjublQkv;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pjublQkv;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d7230a5si496896a12.8.2026.01.14.05.02.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jan 2026 05:02:44 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 92FCA33A8B;
	Wed, 14 Jan 2026 13:02:43 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 618563EA63;
	Wed, 14 Jan 2026 13:02:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id gRh7F/OTZ2l5cQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 14 Jan 2026 13:02:43 +0000
Message-ID: <3d05c227-5a3b-44c7-8b1b-e7ac4a003b55@suse.cz>
Date: Wed, 14 Jan 2026 14:02:43 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 01/20] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
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
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-1-98225cfb50cf@suse.cz>
 <aWWpE-7R1eBF458i@hyeyoo> <6e1f4acd-23f3-4a92-9212-65e11c9a7d1a@suse.cz>
 <aWY7K0SmNsW1O3mv@hyeyoo> <342a2a8f-43ee-4eff-a062-6d325faa8899@suse.cz>
 <aWd6f3jERlrB5yeF@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aWd6f3jERlrB5yeF@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.51
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 92FCA33A8B
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=pjublQkv;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=pjublQkv;       dkim=neutral (no key)
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

On 1/14/26 12:14, Harry Yoo wrote:
> For the record, an accurate analysis of the problem (as discussed
> off-list):
> 
> It turns out the object freed by sheaf_flush_unused() was in KASAN
> percpu quarantine list (confirmed by dumping the list) by the time
> __kmem_cache_shutdown() returns an error.
> 
> Quarantined objects are supposed to be flushed by kasan_cache_shutdown(),
> but things go wrong if the rcu callback (rcu_free_sheaf_nobarn()) is
> processed after kasan_cache_shutdown() finishes.
> 
> That's why rcu_barrier() in __kmem_cache_shutdown() didn't help,
> because it's called after kasan_cache_shutdown().
> 
> Calling rcu_barrier() in kvfree_rcu_barrier_on_cache() guarantees
> that it'll be added to the quarantine list before kasan_cache_shutdown()
> is called. So it's a valid fix!

Thanks a lot! Will incorporate to commit log.
This being KASAN-only means further reducing the urgency.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3d05c227-5a3b-44c7-8b1b-e7ac4a003b55%40suse.cz.
