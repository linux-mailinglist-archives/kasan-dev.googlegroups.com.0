Return-Path: <kasan-dev+bncBDXYDPH3S4OBBE4ITHFQMGQEFXHL6IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D1F3D19074
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 14:09:40 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-59b6c274d69sf4336679e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 05:09:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768309780; cv=pass;
        d=google.com; s=arc-20240605;
        b=j4PG5V4OXiWAmJDwGFVq7xeTEp5bdjTsSe18/UQtpUVyA2OS5lO8pRIN0gNa72Kove
         WRveVo30zcwucxjhKX7pcTZ3+DSJOKWa6lcsf3z9Sl8/kfjP3Pmguol/WuEJKCeOLjtH
         wIV87z8W5rrAFPa98EJMNJ6e02viirLoqzovqsUx4TECCqDBYVBLe+XjZjdLn4amViTr
         Q0soF7cwo7Mc/x/1Me/bPOqcIS56UlxBnaaR+ixuIXdOjtCsmrCqJvNFQkleRC51Sayj
         /Ng8lLJo/+QJiGgDDUbUXfG2cDmyCNz1r9hPyBIUi/xRgF09vqUIa7lhtd9xh3cOW359
         CbWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ygZWjZeEedJIYAvkZihKB+/z2H1oMpjSALdKEVIp7Xs=;
        fh=NKH2D/aUmE9TdEw3Pd9AUkonq5RfN5vaqr7vE1b84nY=;
        b=cOR9TCzV6kCP9pfF82HtKnIqzSimO54nPKGSwf1uaQeRywRf/ds3wRL00+yEOO+Vg4
         vYbDHiNRtUVOwC2nH9tPrRGcy3hvi5Pgd2ZEyb/gVZD/TG3Lhgj13tkHH+f/CwBKeO76
         ItaTXIrfT1qQ6yCPTfQ+lCpX/OJ5EJ8VquQLlbv+WZUezLzoHX7/AbX1lJwGwsNash89
         9h98OPK02/ee6TOaGwE7e9pmGoJQn2PkV84sbzzPcLTozvkpSa2EBsDDWuN8OF6PzjDZ
         npQ3Yo11mmJDJX/VkllhO8i44mykp0wYMT/7dF3pvpRlCLCTJHK8DM1MGFyRYrm80i6q
         Bccg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=he4nxkmu;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=L3MVY4Fs;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768309780; x=1768914580; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ygZWjZeEedJIYAvkZihKB+/z2H1oMpjSALdKEVIp7Xs=;
        b=Xt3+RcNg2Wdvib5UUoEyRCslKcxgRnXd3QQT3+D2/+wfZtsKR4WCdQTcV9xi/WFZt0
         DlJFeWuOQDb3U23+pfmpt7FRCGOUtXYdN3vVd/CE+lsrZacB463Vanz8HgFkVn3sl6C/
         sePvsmWyzGNTF4cs5vAbM83wf/uz7L0KAA7C6thgWRgpmCwt1oxJTpS+4yGGAe8n4SMs
         /hTKvvwVIJDhvXFGiauommdQ6JcprKP0y16ZKU4bBG7QjesWkXEz0xHVRALEdMnlfdhQ
         BsKLP8aCds0HS6PAlQufOysF6vkTjptokWEucBc1PPgQuwd63AQNHw61s0KczF6ke/OF
         FjEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768309780; x=1768914580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ygZWjZeEedJIYAvkZihKB+/z2H1oMpjSALdKEVIp7Xs=;
        b=nTujqpA5Dxi9XjFMHnfpKg3IlKftsGPrp0JmcyFQ1dW3y9jEozV7bzUkHBW+w/oSlu
         ZE4S6iOZmesIRTUq6ia100+6nf9wxAdYEn2I9L/qYrP58vnA7uVoVd8rCI71qle8BtkR
         mpriMFWk3ukSPp1ACZOsSvhaXjgJmcdxrWfIRdtc5+vPcMWVim9mGgg/16CaWtWa6qQp
         43HRjBtB1nYNIqL9dwt+sjhTgX3qiKMGvApSh1u682PoB0pi8UadbIHRhOo+RpxW9xA8
         hRF/Gozw17nfGQjUZUaDxHee1eVXgpLL+p4zaBkAJKyBRIktHeCiohT7hEKAk5XUo618
         jmbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWyTfj0TtYccB+N3WQl0sjYNV0oFLFp0Gb3KIY1vHlaJ0RM2U2IGJpeQbEt6JXY1NFkyzdC4A==@lfdr.de
X-Gm-Message-State: AOJu0Ywxicd34c64J91M4Sjna1d3BPRx1bNP4FVTgsY30R4mD48cYb5J
	ISeI3UODgW4r6Gj1iN3nCnuFs6z+/cGXXInuzVZxWZRAS3YNs+UpuCYN
X-Google-Smtp-Source: AGHT+IFsM+ZWmRCfhsko/W74v6uj5W/ZQ5muVWfyXUDojfnCscvVlNbiutrxz56mJM8Rju+PNtRCug==
X-Received: by 2002:ac2:44a7:0:b0:594:5f1d:d60d with SMTP id 2adb3069b0e04-59b99402139mr587413e87.14.1768309779633;
        Tue, 13 Jan 2026 05:09:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EwCshhaW7tZkvjwPEwcO0kVbyMnCA0q0Ba6XNPxetdpg=="
Received: by 2002:a05:6512:3e28:b0:59b:6d6e:9886 with SMTP id
 2adb3069b0e04-59b6ebf2c9fls2265294e87.0.-pod-prod-00-eu; Tue, 13 Jan 2026
 05:09:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVtIZG36ed8W3VYM/C3z1zMkPrOIu0LBB5E+3B3rfzSOFfB0Cj4HfVrTy+erHzhRgrioBOwU0HVaGo=@googlegroups.com
X-Received: by 2002:a05:6512:39cf:b0:59b:7804:f149 with SMTP id 2adb3069b0e04-59b9941fe05mr1030654e87.17.1768309776832;
        Tue, 13 Jan 2026 05:09:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768309776; cv=none;
        d=google.com; s=arc-20240605;
        b=YedGth9wrncffqsj+kPosBuuBSO5iFXYwv9oqslGxiPGVoDzadfLrX8WQueQq6XIEX
         z9O8uY4aMWeWne/xBqwYFGMf5J4bw/fYkcIjqgwKG7mbVRMwAxOxLwflNTN3OMrEWQyv
         861WVbX0s3jMJDIZifW+EY0my5zJkrVQX1IGuiZ0SkfDs8EY7wUznZ8BVks/15Enks8q
         93U2xExetx7WDGsWuS5X7rM1nvA6fdGH9D3SzHbfQBWhb9kobJSEnWZY40cwgHolT6Gx
         ++oluiZenkvFt8z9/o9KY6UNHR8n2Pjs9KPTp2ZZ2HQ1I2ufM34i460Ko6YGJOkBR/pS
         vK4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=zIiny1vZ64O9oq3h+HMX+5IRUmdaD2DDrx5wZTHdXc0=;
        fh=gKwGuPofcdnEMOxvpmVBXqqrScHpnhhBJIGm7hu/giw=;
        b=cD1kcWV8ZPM2aKQ3YBeRKyDq+GI6KyFn8hi8dGTCWw6v1vCUOoKkPC89SN2Ldwn1f7
         WT50jgjlui9n0+E8TiYLHKoBGQImsP+loqrQo4E41Qcd5Kp9Qac0KooAOpnrVMsbrZQH
         8UzrvaqsFOo9hKGGvxH31rkwHMUMrGwHGd1ZhwRp2d17oWR75wSFwmwu+o1B4sP+/0m6
         g5RHlQmvLr4s3n0iamN9Eil7nBaxzfLsxFtNZmJunWTz+HU9JO2dba1++USlV3gKxjz3
         0gpUB4znif6vtZ3YYp+e7WIbhWHGrxXRQ72MukgD2P+O5a+9UGxA6VEbNu7IQ3JA3sCm
         WIog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=he4nxkmu;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=L3MVY4Fs;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382ecb22dfbsi3373641fa.3.2026.01.13.05.09.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 05:09:36 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 996545BCCA;
	Tue, 13 Jan 2026 13:09:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 854E33EA63;
	Tue, 13 Jan 2026 13:09:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 5ldRIA5EZmklfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 13 Jan 2026 13:09:34 +0000
Message-ID: <342a2a8f-43ee-4eff-a062-6d325faa8899@suse.cz>
Date: Tue, 13 Jan 2026 14:09:33 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 01/20] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
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
 <aWY7K0SmNsW1O3mv@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <aWY7K0SmNsW1O3mv@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.51
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from,2a07:de40:b281:106:10:150:64:167:received];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	MID_RHS_MATCH_FROM(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DWL_DNSWL_BLOCKED(0.00)[suse.cz:dkim];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo,suse.cz:dkim,suse.cz:mid,suse.cz:email]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 996545BCCA
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=he4nxkmu;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=L3MVY4Fs;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/13/26 1:31 PM, Harry Yoo wrote:
> On Tue, Jan 13, 2026 at 10:32:33AM +0100, Vlastimil Babka wrote:
>> On 1/13/26 3:08 AM, Harry Yoo wrote:
>>> On Mon, Jan 12, 2026 at 04:16:55PM +0100, Vlastimil Babka wrote:
>>>> After we submit the rcu_free sheaves to call_rcu() we need to make sure
>>>> the rcu callbacks complete. kvfree_rcu_barrier() does that via
>>>> flush_all_rcu_sheaves() but kvfree_rcu_barrier_on_cache() doesn't. Fix
>>>> that.
>>>
>>> Oops, my bad.
>>>
>>>> Reported-by: kernel test robot <oliver.sang@intel.com>
>>>> Closes: https://lore.kernel.org/oe-lkp/202601121442.c530bed3-lkp@intel.com
>>>> Fixes: 0f35040de593 ("mm/slab: introduce kvfree_rcu_barrier_on_cache() for cache destruction")
>>>> Cc: stable@vger.kernel.org
>>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>>> ---
>>>
>>> The fix looks good to me, but I wonder why
>>> `if (s->sheaf_capacity) rcu_barrier();` in __kmem_cache_shutdown()
>>> didn't prevent the bug from happening?
>>
>> Hmm good point, didn't notice it's there.
>>
>> I think it doesn't help because it happens only after
>> flush_all_cpus_locked(). And the callback from rcu_free_sheaf_nobarn()
>> will do sheaf_flush_unused() and end up installing the cpu slab again.
> 
> I thought about it a little bit more...
> 
> It's not because a cpu slab was installed again (for list_slab_objects()
> to be called on a slab, it must be on n->partial list), but because

Hmm that's true.

> flush_slab() cannot handle concurrent frees to the cpu slab.
> 
> CPU X                                CPU Y
> 
> - flush_slab() reads
>   c->freelist
>                                      rcu_free_sheaf_nobarn()
> 				     ->sheaf_flush_unused()
> 				     ->__kmem_cache_free_bulk()
> 				     ->do_slab_free()
> 				       -> sees slab == c->slab
> 				       -> frees to c->freelist
> - c->slab = NULL,
>   c->freelist = NULL
> - call deactivate_slab()
>   ^ the object freed by sheaf_flush_unused() is leaked,
>     thus slab->inuse != 0

But for this to be the same "c" it has to be the same cpu, not different
X and Y, no?
And that case is protected I think, the action by X with
local_lock_irqsave() prevents an irq handler to execute Y. Action Y is
using __update_cpu_freelist_fast to find out it was interrupted by X
messing with c-> fields.


> That said, flush_slab() works fine only when it is guaranteed that
> there will be no concurrent frees to the cpu slab (acquiring local_lock
> in flush_slab() doesn't help because free fastpath doesn't take it)
> 
> calling rcu_barrier() before flush_all_cpus_locked() ensures
> there will be no concurrent frees.
> 
> A side question; I'm not sure how __kmem_cache_shrink(),
> validate_slab_cache(), cpu_partial_store() are supposed to work
> correctly? They call flush_all() without guaranteeing there will be
> no concurrent frees to the cpu slab.
> 
> ...probably doesn't matter after sheaves-for-all :)
> 
>> Because the bot flagged commit "slab: add sheaves to most caches" where
>> cpu slabs still exist. It's thus possible that with the full series, the
>> bug is gone. But we should prevent it upfront anyway.
> 
>> The rcu_barrier() in __kmem_cache_shutdown() however is probably
>> unnecessary then and we can remove it, right?
> 
> Agreed. As it's called (after flushing rcu sheaves) in
> kvfree_rcu_barrier_on_cache(), it's not necessary in
> __kmem_cache_shutdown().
> 
>>>>  mm/slab_common.c | 5 ++++-
>>>>  1 file changed, 4 insertions(+), 1 deletion(-)
>>>>
>>>> diff --git a/mm/slab_common.c b/mm/slab_common.c
>>>> index eed7ea556cb1..ee994ec7f251 100644
>>>> --- a/mm/slab_common.c
>>>> +++ b/mm/slab_common.c
>>>> @@ -2133,8 +2133,11 @@ EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
>>>>   */
>>>>  void kvfree_rcu_barrier_on_cache(struct kmem_cache *s)
>>>>  {
>>>> -	if (s->cpu_sheaves)
>>>> +	if (s->cpu_sheaves) {
>>>>  		flush_rcu_sheaves_on_cache(s);
>>>> +		rcu_barrier();
>>>> +	}
>>>> +
>>>>  	/*
>>>>  	 * TODO: Introduce a version of __kvfree_rcu_barrier() that works
>>>>  	 * on a specific slab cache.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/342a2a8f-43ee-4eff-a062-6d325faa8899%40suse.cz.
