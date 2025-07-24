Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDMPRDCAMGQE3GDNN6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D7AEB10787
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 12:14:39 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-6083f613f0esf725616a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 03:14:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753352079; cv=pass;
        d=google.com; s=arc-20240605;
        b=DamTV89dg8v9i2x0AbTgEX9c7L9D/iEANUYbTBdSfNgbzQChaAO82M/IoactT0BSpD
         5ie3Ue7XydWGsLmfelc6BvnokT2OO/w7U35kJb6hRrEjZlJAYu3pfqdjXiop/J6XlFDi
         vyuJ5kxsjn16ER0j68/7BFePgtHKPNmbiyYXpWNOEtDSHmUiytlWfpjFtX7vRyfmFv3m
         k0HDDeUc6xxa9nbpdAMiTk4pToWAmVrWhvaN1KyNmjfouOy11R01N9H6WtLEPcXgVx9g
         h9SDw25EhXWIDmXqgMhuSXuRNC+EYms+5RKgWZ3aedlKQ7sQ2iI5/poAVDNYKS/pMiu7
         YsIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=X0eEZ7GDeu23646suKYukR8G0WOfmnEvkkv+X5hPmWQ=;
        fh=zbmbUbqc2tDb4gTH4YqJz9LpAxa67v9vtDADhFHLdEU=;
        b=Yj5Jgbc6xr/0dJPGavw4/UxbZTCm+ErNebnGg1knMG7EdFfSIK1bszFDqpqw5pgwyY
         8/gqAGPJ0LKANSRCnAk8+oPDg+VZ347gxaoX+3cBPh9tlBPrSb1GM4lHlvbXpEsZcEiP
         78gzcger25N341ldDZxhCAb7MjKFyPS5pTnbWSjPcxIxPSqEJqr0Vm2PuKtjG6B0juIf
         sMgIUpBGnf0BY13daTLptD62yClW+ELMJAetLU0MDdC+gS5KpoDA7LFjfyMmuUX6ukob
         jyykHm15s0CV5oOn55dzN8t81pW+0Y7Ln4ROfNbw+X2lkIXR0F1R/bmQTXz8yNuQ1yf5
         Z/Eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nLYGEiFm;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pXb2Y2nA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753352079; x=1753956879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X0eEZ7GDeu23646suKYukR8G0WOfmnEvkkv+X5hPmWQ=;
        b=Enrj1y6Ur8ZGE1lAY2Hu9NL+QYufULkliNm5oAuHMAds714lzIF59LwaAs3+FD4fiD
         octEs4yhXQT4XvafbKUMkSCm4d3MARabf51ytOcVieijy8ZzZjuQf2BXk3BUs4P5Kssw
         RvbyZhEwreXxYVP5U5UVh/AN4rmDRjBWB6op4NP1R6PA5GA7I0pj7OMNe2IdUdtn6KTB
         aaAAB2zAg5Iuit/x5mpT20NP17bJt5G5ZuAZeFgLkEpkO9HYqBcAKFeBn3BhoygrPqzR
         m6P6EthfFqflir6pQKevFDPx37F01RjitmEtLtQEznyr0L/2xrhyC5sdIKSgVXul0xav
         AePw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753352079; x=1753956879;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=X0eEZ7GDeu23646suKYukR8G0WOfmnEvkkv+X5hPmWQ=;
        b=DsIMDXmTs8jc8nbz6pbzEH2jAclLgvkCNwx5YFQBihFq3EZOPmTuI+GEi1w8sUx9wb
         EZ9mF2tIIhCP2L4cY3Xe79fsqah5+Y8OTXRcbByCQPEkomF49oMZ8ii4zo1GZhQmzQBP
         QRMxCbGAVKirsQQ9KxAR4JwdBznKegZJbJ2rIk45Io+AphFEn8rKbVrJr/a0o3GMRL49
         HYoUDZTMP669LZHvHQE0N4OyMrMsebKPGktVtfgFKlM9lj2R+lC75G44xbCdEsgoATMX
         EQtItlafk+cE7ecKOLApk5SkHNEV4UfQlQDhKKe1gAn31/klQp37Af0ZSRHQI4ffPCM8
         B5ag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVH33U/n07m8ZmPKyZqP368//Nu2QFSP1RzzxdZuNPHMCfR4eqa6gdWpy5fa56geihCGJowcA==@lfdr.de
X-Gm-Message-State: AOJu0YzE530g+AI53cT0lOpW6qS9Dym6FHNbqXmjILJBBYfdgWVf74xV
	wesC/p9i8ngJwWZKBcWzKYf0vvLc9HyDD3wiab65MXnOnFuZZInxxFHS
X-Google-Smtp-Source: AGHT+IH2TKHekiYugSkn0I2ZyYLhQ5j2qSo/xLwFd/TJErnnMnuFz/jhAyNOBKLplECssFoGkqGSWA==
X-Received: by 2002:a50:d70d:0:b0:612:bfb2:386 with SMTP id 4fb4d7f45d1cf-6149b5a454bmr4406964a12.28.1753352078393;
        Thu, 24 Jul 2025 03:14:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfSL+KqmkyC8ksMKuYBSxxGPLXK+nBc1iS8FqlxsIR9eQ==
Received: by 2002:a05:6402:1e91:b0:601:6090:416b with SMTP id
 4fb4d7f45d1cf-614c07ffb13ls685740a12.0.-pod-prod-03-eu; Thu, 24 Jul 2025
 03:14:35 -0700 (PDT)
X-Received: by 2002:a05:6402:3491:b0:60c:3a8f:247a with SMTP id 4fb4d7f45d1cf-6149b418134mr6376061a12.3.1753352075381;
        Thu, 24 Jul 2025 03:14:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753352075; cv=none;
        d=google.com; s=arc-20240605;
        b=ZOl7yQQae7AauxW4XRg7FtDTM/pR4czobL+aeVnzekALJSC+dJw3UQ6bHCDjvqentX
         cg86Sset5cZLK8QoP/MTMOYSUcnbHIfpjUD28Mo2zeEX+RXP/OX4/nAZeeiyv+CEKtrn
         ap+v9eo4aF29zRsAhDARGAdeUxP3hGyGl2WDyAV+mVnpPzMLbFIOTky5dzko5rWu8idU
         gmVqfQ9V/uDbfq+4mLGtJG8Ce6ENTZmHfVs4nEUr1UBRuGmmb2La8s3QnU3eHGdH+kiz
         WaFch9xEM7OPqkn0MHdo+ifKSlPDViQHgws4VhBzROzCXhij8Tzgm+0erMgJ7qIr74y7
         ZNsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=0Cb3/++MEwl7Z6VekxEpy01dqQjPmNLRWlpN/hgrJ/0=;
        fh=Z1akeSglz1VnNM7UindtLmbCq84Y8wrvu/XSLABU9l4=;
        b=MDFobjb3RDratJq7JNEu9FY7c/skGpVnXibV/10dyjf7st4M9xB8MEMVJxsY/TD/Z9
         CuOkGRgQ4IFrge0qWsFTNhvTCzlEUha88j0LsabPoZ+lzf3iActSMCVN2du09l4laZgi
         HosQ8FtYDCXw0CyvzkFyS4nzyhNX10b+r2rbRtxsEPg5mTZSb3M1IOu8EEw02z7J/u7i
         Os1BV8qGt4LFuePbavGWn3n6H8bkdlg5BwGnqFDtq7+b3Y0m3mVhaM0qQv/6zaMDRsjI
         BvkN9FS0KkQXmThbd2gIuyVwhkAIQVyeCHMdKftbdxY13NGgp72KP+cGEk6e2Qgy9Z20
         cT0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nLYGEiFm;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pXb2Y2nA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-614cd2ebea7si37245a12.3.2025.07.24.03.14.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Jul 2025 03:14:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E71B81F394;
	Thu, 24 Jul 2025 10:14:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D15D4136DC;
	Thu, 24 Jul 2025 10:14:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id hii9MooHgmiUYgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 24 Jul 2025 10:14:34 +0000
Message-ID: <45cd4505-39a0-404d-9840-a0a75fcc707f@suse.cz>
Date: Thu, 24 Jul 2025 12:14:34 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: skip quarantine if object is still accessible
 under RCU
Content-Language: en-US
To: Jann Horn <jannh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Flag: NO
X-Rspamd-Queue-Id: E71B81F394
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MID_RHS_MATCH_FROM(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo,suse.cz:dkim,suse.cz:mid,suse.cz:email]
X-Spam-Score: -3.01
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=nLYGEiFm;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=pXb2Y2nA;       dkim=neutral (no key)
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

On 7/23/25 16:59, Jann Horn wrote:
> Currently, enabling KASAN masks bugs where a lockless lookup path gets a
> pointer to a SLAB_TYPESAFE_BY_RCU object that might concurrently be
> recycled and is insufficiently careful about handling recycled objects:
> KASAN puts freed objects in SLAB_TYPESAFE_BY_RCU slabs onto its quarantine
> queues, even when it can't actually detect UAF in these objects, and the
> quarantine prevents fast recycling.
> 
> When I introduced CONFIG_SLUB_RCU_DEBUG, my intention was that enabling
> CONFIG_SLUB_RCU_DEBUG should cause KASAN to mark such objects as freed
> after an RCU grace period and put them on the quarantine, while disabling
> CONFIG_SLUB_RCU_DEBUG should allow such objects to be reused immediately;
> but that hasn't actually been working.

Was the "allow reuse immediately" not working also before you introduced
CONFIG_SLUB_RCU_DEBUG, or is it a side-effect of that? IOW should we add a
Fixes: here?

> I discovered such a UAF bug involving SLAB_TYPESAFE_BY_RCU yesterday; I
> could only trigger this bug in a KASAN build by disabling
> CONFIG_SLUB_RCU_DEBUG and applying this patch.
> 
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/kasan/common.c | 25 ++++++++++++++++++-------
>  1 file changed, 18 insertions(+), 7 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ed4873e18c75..9142964ab9c9 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -230,16 +230,12 @@ static bool check_slab_allocation(struct kmem_cache *cache, void *object,
>  }
>  
>  static inline void poison_slab_object(struct kmem_cache *cache, void *object,
> -				      bool init, bool still_accessible)
> +				      bool init)
>  {
>  	void *tagged_object = object;
>  
>  	object = kasan_reset_tag(object);
>  
> -	/* RCU slabs could be legally used after free within the RCU period. */
> -	if (unlikely(still_accessible))
> -		return;
> -
>  	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
>  			KASAN_SLAB_FREE, init);
>  
> @@ -261,7 +257,22 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
>  	if (!kasan_arch_is_ready() || is_kfence_address(object))
>  		return false;
>  
> -	poison_slab_object(cache, object, init, still_accessible);
> +	/*
> +	 * If this point is reached with an object that must still be
> +	 * accessible under RCU, we can't poison it; in that case, also skip the
> +	 * quarantine. This should mostly only happen when CONFIG_SLUB_RCU_DEBUG
> +	 * has been disabled manually.
> +	 *
> +	 * Putting the object on the quarantine wouldn't help catch UAFs (since
> +	 * we can't poison it here), and it would mask bugs caused by
> +	 * SLAB_TYPESAFE_BY_RCU users not being careful enough about object
> +	 * reuse; so overall, putting the object into the quarantine here would
> +	 * be counterproductive.
> +	 */
> +	if (still_accessible)
> +		return false;
> +
> +	poison_slab_object(cache, object, init);
>  
>  	/*
>  	 * If the object is put into quarantine, do not let slab put the object
> @@ -519,7 +530,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
>  	if (check_slab_allocation(slab->slab_cache, ptr, ip))
>  		return false;
>  
> -	poison_slab_object(slab->slab_cache, ptr, false, false);
> +	poison_slab_object(slab->slab_cache, ptr, false);
>  	return true;
>  }
>  
> 
> ---
> base-commit: 89be9a83ccf1f88522317ce02f854f30d6115c41
> change-id: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/45cd4505-39a0-404d-9840-a0a75fcc707f%40suse.cz.
