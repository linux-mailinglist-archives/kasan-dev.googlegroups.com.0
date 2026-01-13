Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNFCTDFQMGQEENAV6QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 13C65D17A33
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 10:32:38 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-430f4609e80sf3941377f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 01:32:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768296757; cv=pass;
        d=google.com; s=arc-20240605;
        b=PikE7ZfhnrgmgvT2KV4c/K7wP6NIyltTA2TsqLqCtdqfoULi88TCkUuLzA7H6DWHkS
         9T9r3yRrBUZQ0uCENgKWEid8uAgQEDxQzbKQhieRYEieqT7CJpRaXI6f1bRGF4J7/eEy
         4WplNoYT4R72pJD5I8lQb0cShUsQEi6aJNzpG7sfTGV0FIwAuJElbKlzFJvAghWVJxOG
         vkLeCa4upXoYHe59LI/msGzssyK5VHfBvB57Ju+RI77J6m4EAqA9ox3/9+g/kjVsFXOT
         m+Taa7D1jqY2rXQNIYNsbYQ/ECXfbJZDEyqLKdkc/JfWC8bEQQYzYHMWU+hbT9IYAHy2
         gxJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=XGHR7OvBwJ5qVXIWOtgsnvHTIFIzYiRRAidMVD8xUpo=;
        fh=W5wnelMo003t6GAqhb3iyjxaLZ5Senr5zYenVWqFnWg=;
        b=T5IfE0xJRWavwXpDP4WOnnezRmDS30yO9x1hjQx1Uwrr6wbDesKGVRdOCnDZDYbUe1
         eNnFe4Kaud2kTZM/etTUhmkMdfQnuRep+W1Lbn6kpu2bz3yo08xWuOCc38QoGstschk+
         Odee+cn+7xTqOhpjnVfLM0vor49d8jFJbRs3cTkPyoVfx6W6lrlpUYAhT7j/nb4S8wKy
         qC6Rky2ucFm4KioXhFkwQRvOeceAZcS3sDGHGCDg9pabFfl53A+jg+hqif7rqrDnbFzE
         e91nkLpt/ameqs795L7rfZWSVPuoQKFBDqkuYJQz8JO3HVEgY9Leg482302cf8IsYsme
         5+gw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dtSqIOQ1;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dtSqIOQ1;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768296757; x=1768901557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XGHR7OvBwJ5qVXIWOtgsnvHTIFIzYiRRAidMVD8xUpo=;
        b=rQYTJ6gPFEGHBGs99ckpxu2nj2hMUxP3lE5dhVz1Vrab8hdNTazqIiKoJE6D2oE9Ex
         z4x8exrZWnPDd4V4j41GM5jiFwUA2GOjKjb5qUoeaGIvt+PTZ/f4hd0agCuI3PpotD2b
         7ny1f+RcEjThxJa+o6ijKc4WoN1dU6xdCGdJYj3SrmAICb0H7OoC0EQgXrllCm3k/rmX
         BK1l6bj/WAUOosvvlU+iisRrC5DiCJPEA9MmpVpi9WVCDD/GVguvtXDoXBPKCIZBCQUz
         S64VC4NddxJ0FB6gwv5D1K4FSyrhPwQT9/tZ1jnPP6TjcGuf4ejd37ZyD25415S6ruOD
         9PCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768296757; x=1768901557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XGHR7OvBwJ5qVXIWOtgsnvHTIFIzYiRRAidMVD8xUpo=;
        b=m4DeXdW06jsvlZLIsCiKhSBpNKk/rOJ2AM4l7ASlOkzYaCEAGug1UfL4mMcp0yCyQG
         lbCJhORrhjTlYE7917ov+bQbV1R3tj+Qnmw97VRHzpWlD8Gmo89X3tkZTPS96zuS/jfj
         f8/L9PoNwHxmfml68kiK3WI7Dwq2A2fiWLoMK2E/WlYUDTgJ4744B6JgwcB8pHLYonLZ
         LGmX/AYcbkImOGlyzuqvvC/ktAqf5GPK8TWNh7bwtIVwzNGB+5v7yBF3noroaVZyX+y8
         Sb43DFDpArozJJqsMXqpxXTQ6K/7WHS25Tb2VPFJZex8bJDIit7RS3IqrRV60Cey/nRE
         nq6w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEA6BKszgkxloaj/iLShLCkkC7HI+GC0t2PImPGZ/tOLOPb0RbUPQHyGWDsBcQzsY3JjBD9g==@lfdr.de
X-Gm-Message-State: AOJu0Yxo8ZoBSygth4ZlYMH9aHwYI5Xfllf6PpkxRYl6xlshVoQPWk1i
	Tw0dogEZudRPOKwjWW576Olq5xJcRNAvrX0vDETlklducNq8uEZkUZu4
X-Google-Smtp-Source: AGHT+IE18R9IAwaOUBu6HJp/u3ASgGaGtPR5JiMqj8H0z1+LSYOMtnLcPZwdLXbdCg7IaxaZakaKQw==
X-Received: by 2002:a5d:5f54:0:b0:432:5ce4:6fed with SMTP id ffacd0b85a97d-432c3629ad1mr21652414f8f.9.1768296757390;
        Tue, 13 Jan 2026 01:32:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FcM4eDfSsM5sR3JpQ700ZA52CZjMNdZvdo7+MODA8F9g=="
Received: by 2002:a05:6000:40e1:b0:425:57b0:537d with SMTP id
 ffacd0b85a97d-432bc8e24c9ls4131784f8f.0.-pod-prod-04-eu; Tue, 13 Jan 2026
 01:32:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW6O8/qH3yP2z+XktRbJ166nVwpLO30RH8eDruOvmFskPORM4Sqav6wsW25vgiIMcZXvcOXDOpTDL0=@googlegroups.com
X-Received: by 2002:a05:6000:3104:b0:42f:bc6d:e468 with SMTP id ffacd0b85a97d-432c3778de3mr21155088f8f.55.1768296754973;
        Tue, 13 Jan 2026 01:32:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768296754; cv=none;
        d=google.com; s=arc-20240605;
        b=TrGtmWqFhmycdgU9rwFugNkG8ewhTxlUR5i0icNnXqVCXhiuP2YYLQ8x8e+fThbOTZ
         V2mU2ng/zolWVtSf+50JOWon1YNso+K1ET+wAGnJCLJx+BSA8JT5Kz0VLZ2eM08Q3+om
         3i8xKN5fZmH7nW2WGtcWC7DYOEj5PPuyFzfCAyaqsIvPwvfHmInEQhU7tHgwmZiTxbIk
         3nzAvvg06hRHssZWZNMZ9ayS4+ZFkM8GlXYgTpEe7hbTu+oK4lkOvgDzwuzCAuIeMVON
         CX7bvkrSUZRENoRVuXv+Hcj70NrrPSYiCfGJa2F8Bru+I5K7kRnpp6pBsxeKuNjziYAJ
         V8YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Ni5ivzvbOKwDsRa7XDDenum4lALdFzhgJFrmTN2UCmk=;
        fh=gKwGuPofcdnEMOxvpmVBXqqrScHpnhhBJIGm7hu/giw=;
        b=U7a+KbU/bdJ7FenpAE6EwWwYr44a/QAxpwNEmaoqeNgDFtKHPBQoGrzbHiyOD9E9mK
         ZGQD6b4nbHdDmm66w9Ddrgh9HlUw+g0br8q3r2CKi/Wm/ifTQAtFq6xsWAruV4CzB/K/
         k6qLsKtIv6mbY6lRu8pTvomDlWQKxf5oexf7bZ5ibAWs2lUSyV7v9j0IJZ50t7Wb0Ara
         6IVYqaHBTF+2c4wRFMbV1D5Ug4amFAJkSe94G4ym9OenhK+QfDLcDh/X5U2GLpNWaIzN
         MAoS3cQonHOkEu6XmH4GIzBN1cVaPgfvGDuyGcw3IIuWy7i1WsTPBty/G5tzrc2Oz44e
         6XVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dtSqIOQ1;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dtSqIOQ1;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be509c5dsi337004f8f.7.2026.01.13.01.32.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 01:32:34 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6731E33681;
	Tue, 13 Jan 2026 09:32:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4E3843EA63;
	Tue, 13 Jan 2026 09:32:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Eh3mEjIRZmnYNgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 13 Jan 2026 09:32:34 +0000
Message-ID: <6e1f4acd-23f3-4a92-9212-65e11c9a7d1a@suse.cz>
Date: Tue, 13 Jan 2026 10:32:33 +0100
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
 <aWWpE-7R1eBF458i@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <aWWpE-7R1eBF458i@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
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
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=dtSqIOQ1;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=dtSqIOQ1;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/13/26 3:08 AM, Harry Yoo wrote:
> On Mon, Jan 12, 2026 at 04:16:55PM +0100, Vlastimil Babka wrote:
>> After we submit the rcu_free sheaves to call_rcu() we need to make sure
>> the rcu callbacks complete. kvfree_rcu_barrier() does that via
>> flush_all_rcu_sheaves() but kvfree_rcu_barrier_on_cache() doesn't. Fix
>> that.
> 
> Oops, my bad.
> 
>> Reported-by: kernel test robot <oliver.sang@intel.com>
>> Closes: https://lore.kernel.org/oe-lkp/202601121442.c530bed3-lkp@intel.com
>> Fixes: 0f35040de593 ("mm/slab: introduce kvfree_rcu_barrier_on_cache() for cache destruction")
>> Cc: stable@vger.kernel.org
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
> 
> The fix looks good to me, but I wonder why
> `if (s->sheaf_capacity) rcu_barrier();` in __kmem_cache_shutdown()
> didn't prevent the bug from happening?

Hmm good point, didn't notice it's there.

I think it doesn't help because it happens only after
flush_all_cpus_locked(). And the callback from rcu_free_sheaf_nobarn()
will do sheaf_flush_unused() and end up installing the cpu slab again.

Because the bot flagged commit "slab: add sheaves to most caches" where
cpu slabs still exist. It's thus possible that with the full series, the
bug is gone. But we should prevent it upfront anyway. The rcu_barrier()
in __kmem_cache_shutdown() however is probably unnecessary then and we
can remove it, right?

>>  mm/slab_common.c | 5 ++++-
>>  1 file changed, 4 insertions(+), 1 deletion(-)
>>
>> diff --git a/mm/slab_common.c b/mm/slab_common.c
>> index eed7ea556cb1..ee994ec7f251 100644
>> --- a/mm/slab_common.c
>> +++ b/mm/slab_common.c
>> @@ -2133,8 +2133,11 @@ EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
>>   */
>>  void kvfree_rcu_barrier_on_cache(struct kmem_cache *s)
>>  {
>> -	if (s->cpu_sheaves)
>> +	if (s->cpu_sheaves) {
>>  		flush_rcu_sheaves_on_cache(s);
>> +		rcu_barrier();
>> +	}
>> +
>>  	/*
>>  	 * TODO: Introduce a version of __kvfree_rcu_barrier() that works
>>  	 * on a specific slab cache.
>>
>> -- 
>> 2.52.0
>>
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6e1f4acd-23f3-4a92-9212-65e11c9a7d1a%40suse.cz.
