Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWUUUPFQMGQEOR4SJ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 96C78D24103
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 12:07:08 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59b6a320b35sf777485e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 03:07:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768475228; cv=pass;
        d=google.com; s=arc-20240605;
        b=cJRxpOofnJbkXlSPqRWqetSuKKiHQjF63GMDxJjwrJvFULdkS/pXIu6iFXdm1ZFeLK
         uCRT7VFl6KDQYcrW6hADnlRYi8ai1mBt8rpB/qauoD5eM4MWz6J1R02pUKsUEhYxkl3q
         1O9s0C/U+tg+eZaiuFcrbKvzm3GUCDS9yR3WXfxZAysI4nN4Z1gne2kDB4+MNamy6Lit
         4McvJiKM9g2usrmzOb18zvXdwRYP2hYru8uml1eTPVxYB11pLrZDbJxYqjWrzeIz6JWO
         1wR2KQPEBs5QjeFe9NoLJ/XKm15T3bwrYCkQsQPFB5a06bzQAHPyeOrvPyEtl8iR65c/
         tPSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=laUQbYagJCJv73OMlVXJHVHuBEXgZADNwUA0ZXALAAM=;
        fh=DzCLcTQqeL1gzJkwrKO7j7dmlxwJVlC6tCQUINDp9p8=;
        b=SFGIvBVZ/hP9vsfx2F7uxC8hZyR/p4cufuBvJ8Zf2CLE3CCBtX/nRybPBj2HJKHOul
         Xe2kK7jFp2Cru2CnAJ2cRyV73Qz3cWX/GQqjo6rYBaBFl5awojjeYzyGy1+308GdR6qC
         f67ab7L1n5zZgMCRcboDsVWqh0XSJ87lhfWblxacZ2haiBc48+HO21a3AJAyLgfyLYC8
         eP3omsK9j7/yFOn+hGy//Y1Oe08Q56z7sD+gs+BN2e4yBuOL9iophmdoBc7sny5XuEOp
         zLNp3D4LIhYGNp8RUnvnwvKZpQVJ+Ui+nQvZnHB2zGKZ6Jsba186uNIfM/VKmlUCLwoQ
         ldkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DzIHnt6o;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DzIHnt6o;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768475228; x=1769080028; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=laUQbYagJCJv73OMlVXJHVHuBEXgZADNwUA0ZXALAAM=;
        b=bkaJKluE+sAdd5V2CnnU+eBgRQvKhjJFKhkMrfW0HytBDvJF8S3lOJhsNf1aMk61BA
         OGorJPlfP/7HrlLaiDimX6nEgBxMJswNN19cRqK8Jc1oPR01llUb1DAkzWEPnWg0zMjo
         2rbK+AkPmJ3qaYEK6v0DNw/CIVJWkUZIap4hxivvcrHOR45vu/FWVCDBNuunj0Gt34XG
         HVilp9YdnenJ0XNDw1VncJLXdU4M+XU0gkj+NuCvNPhoPCEcqES2YJQq8GAUpEBrEFEF
         FnQrElmaYN37NAk/rGRhiPyPx1Y2u3byMjtCk63eCA5MDx8t8/Lx5MBSgZaitNHF8nKY
         O1Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768475228; x=1769080028;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=laUQbYagJCJv73OMlVXJHVHuBEXgZADNwUA0ZXALAAM=;
        b=k+0NqGHp8DMJ83kjRitf8/3Kzd15Onfmz9L+EKuj3giov/lZs4UzN6PquQhLD8EX5p
         W9IbqHcDXa4dTS2qHERA350O98oAoiTxubamzLqfnmFLdcVsTVR7CgQAMCqAL1oDI+91
         PZ++j0Y+jW6KbD7Ko4QHgPmzRi79hTE6VfFmmWbkbMGLvGTxdhKhZxNLHmRyTrB3NXM5
         sZY9RgAXM9Sxk//NR8Sey8PxyXUm4MD5Oeh9BYecTg1ELzF6HhCCd032gSP5s1UAkROj
         XO/moWykZy4YvfsGS42XCcjJErRKHmnfmVpXWE8l4oq2huL9xJuL121MCp2vl5f5HE7n
         xLeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVMQ6iDxK2kfxfotLMVA0pvNXPdFxJuX0jKmDT34tqEr2dFIPoDY8C7hMRChO+PyG0vT4ffIg==@lfdr.de
X-Gm-Message-State: AOJu0YyCfy0uK35KKAvZEWx4IR50CA0IRoSMm+5V07+UZai/pc4Cp5l4
	izG7pLPFeXr/iNOKCnzyHcNXXpsyfTwmIMpQ16UwE06lFs/kPXR7nYbp
X-Received: by 2002:a05:6512:b09:b0:59b:92a2:19b8 with SMTP id 2adb3069b0e04-59ba71a2025mr969628e87.25.1768475227383;
        Thu, 15 Jan 2026 03:07:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fn5e0MJjO7FU5tftt7RMHTpsTZRk4uLlbtUENpKjH4vg=="
Received: by 2002:a05:6512:23a0:b0:59b:739a:3ae4 with SMTP id
 2adb3069b0e04-59ba718aa67ls336556e87.2.-pod-prod-00-eu; Thu, 15 Jan 2026
 03:07:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVYf2ggvdNuS8+J6aj3cVb4IslKdm6z6gQozk2RMqBtoHTcNNyk8qUerGPyFw/XL5V5tWORGMRwuzE=@googlegroups.com
X-Received: by 2002:a05:6512:1d2:b0:59b:9ab5:71a0 with SMTP id 2adb3069b0e04-59ba715f77cmr666326e87.7.1768475224538;
        Thu, 15 Jan 2026 03:07:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768475224; cv=none;
        d=google.com; s=arc-20240605;
        b=Ibt+sg7FgMj1CCrq8vpy013QCV2T1RPYjFq03Ola+Zy4cqoif5csRYZsgM9V/14eaQ
         22HP/m2EXdgIwODDPgOnmqqrfplslTpH/snIVXOMH33+f14SEm9Cy2CZBu7OVvry3VDz
         Fd7ZIBxVIrz3ze1XvQZhYo0KED9pXBZpblgIrc3smLHyj+nEr3uc8GU+xicyQ/mh7Umw
         aJxCsS+O/q+y7UHpOvJQlWIxCzo0McQSnoOwvfmDtfmSh0W7CMOsNnUjXYo8DQHiWYH2
         I1DAFqyLLN5Qu7Lb2ggw7aW0ildhuqYNpX+lNVch0FdTsQzDnSieKfabLLveOI/Brjer
         ibXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=CMDfavExPfC/FICQX2UPPaUz4Jt0PBH/HWBal9RBdsk=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=PJ6EbWjjRU7WIQTJXw0Y8PCBFjTGTPZOXqIn6iaV9AFB2SykKAXHRUuSskldEBUFFP
         wavfVo1HVomOQy3HlQQ2R3MdTMyCqS3EMgZQbtA5zUG62SrwECY+DK9i3Bsg1FOJJXcS
         Qh3LB33JT327xAjK5p9FbPNeEcXhloboJoZVdmLZWzY/eRJJHzlOiPP56fD4vGpAMQ5I
         fCMr/+L1M6N3+MAYTYNDA9SiUgmmAgSEAiBHfKRB5Mhqr+MbPBj2eJ4c7UsJe/wB0FNH
         jZyEkFec1oRNaNchYr2eNSd/4wEK7fpEvWOKXV1HqPbh8U1PW2mnPh0IGyE+biW/wg/Z
         bQkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DzIHnt6o;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DzIHnt6o;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3831850a898si4216541fa.8.2026.01.15.03.07.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 03:07:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 98CF55BCF8;
	Thu, 15 Jan 2026 11:07:03 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 784253EA63;
	Thu, 15 Jan 2026 11:07:03 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id +OwJHVfKaGlmKgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Jan 2026 11:07:03 +0000
Message-ID: <d0f5f72d-77de-4be7-990c-a5e47f326dd9@suse.cz>
Date: Thu, 15 Jan 2026 12:07:03 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 06/20] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
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
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz>
 <2hsm2byyftzi2d4xxdtkakqnfggtyemr23ofrnqgkzhkh7q7vc@zoqqfr7hba6f>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <2hsm2byyftzi2d4xxdtkakqnfggtyemr23ofrnqgkzhkh7q7vc@zoqqfr7hba6f>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid,imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: 98CF55BCF8
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DzIHnt6o;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=DzIHnt6o;       dkim=neutral (no key)
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

On 1/13/26 16:42, Hao Li wrote:
>> @@ -6129,6 +6152,17 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>>  		return pcs;
>>  	}
>>  
>> +	if (!allow_spin) {
>> +		/*
>> +		 * sheaf_flush_unused() or alloc_empty_sheaf() don't support
>> +		 * !allow_spin and instead of trying to support them it's
>> +		 * easier to fall back to freeing the object directly without
>> +		 * sheaves
>> +		 */
>> +		local_unlock(&s->cpu_sheaves->lock);
>> +		return NULL;
>> +	}
> 
> It looks like when "allow_spin" is false, __pcs_replace_full_main() can
> still end up calling alloc_empty_sheaf() if pcs->spare is NULL (via the

Oops your're right, we can't allow that. Thanks!

> "goto alloc_empty" path). Would it make sense to bail out a bit earlier
> in that case?

I've reorganized the code a bit so it shouldn't happen anymore.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d0f5f72d-77de-4be7-990c-a5e47f326dd9%40suse.cz.
