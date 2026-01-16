Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5GSU7FQMGQEGQWSFGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 58896D2D3D9
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 08:32:05 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-477c49f273fsf12720645e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 23:32:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768548725; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ckum0qmr/1+2EMbuFjeI1HFp4KmjXOEGoH7jF8rv3SxknO0pcYwj8ccnzQ/hwADNKM
         6QNbW8bnWiVlJbajF5DN+FLkCOjIxdEfI68SF9RNKsEHOYzOXpTIwDwZ+DlZq+kaNObM
         VFEpIqnseEE+VPOmu3J8qKX3e6I1QOzJ3MwvD4C//PAJ0oJxvAkgqtphNRe6HksD7LL9
         GN8jfGFxjRqeth13zzPSyHUfHU1eapiDEwCs+tHRqfD0XLtwkq7oZ0i/UVVNvGrT9aI+
         sIoD0r7CL1QUyLX+DthqwMvx9v6dFbKsi65HPKeHmeN6QmRYPrCM1ucrFlWRlFy4Uuw+
         rOYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=qr7jaybWvM54zIdAmiBb5WTdQDXHY0AUjxdmT+d2tc4=;
        fh=L9ibBeI/YMRANSMUxCs8u5vXK8D2chaY+LSlQ1xCFu0=;
        b=ESNJTMsjZI3X6LJnPYIAxIqOQswttCoRru/6Eu+t5yqYg8Ig5YOGXpfjoyAUCG6ewP
         HzhkPhLIDYD6kH00JEZ75oeAlfVlq7xIVgdEC8yRGQVvVJWZtDdmK0Yx71ah4/u9h9Uh
         5daJ6gFm0YE68I5q/+N2eLqBMekBqBKqV528UqE2gQ5fkBiG3hEqyjyTmyLYUohY4GJS
         Q9x2s7xqW7EP10jvDooVc//+YHvLL4p1aY8dTHEKyCxgdQyobuu01YwFOdrt/cD/OEPa
         BK0bcXdveMOBMOiGJw7tjOynlnwKJaFyovgv3rvX4mL6TknF2LR2CeMvz18fZnVnlKuq
         AU4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="hL/jJS0K";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pWRLH+sp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=yYaTRxrR;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768548725; x=1769153525; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qr7jaybWvM54zIdAmiBb5WTdQDXHY0AUjxdmT+d2tc4=;
        b=LEnzjGuUO8aDIRZj3qkgipVKUh0oONwVYqcVUGEesapIevH3qL2DweHF7boUGhcpKy
         68eLoDotyqd5BWR+qnsPBPgw/4qiBnR/+P5vlbGTwrwgJZfbndCGGWABQLfoJObzQD4R
         9EOqlROJJkKcCul3Ty8o7U+U108C1sDW/A85bSKWvpa0wurnqW4SgwygVyNIYg1QGsvb
         Iw9ia2ZuM5D4RERsZOaNYud6HZif8IRsiVJQ+JOgjg4oBVhNg7HdC7FHoz3Tg22NiaAc
         Yav8YbBxYmfC27qUOlT+LiL/QX3MfFKPouCUXQCzrMdvjx6XRS6K08ZZ3cMDSmL4yUhg
         tmig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768548725; x=1769153525;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qr7jaybWvM54zIdAmiBb5WTdQDXHY0AUjxdmT+d2tc4=;
        b=AX77dN1Q3OZWhw5gYW0uZJeH8MEI4japAdjN/SP1+7vjRhQ03DYdvICah6PPhwGRSb
         XC1qeQNjKHz1SAHSKzmiM41vfrQRN9RxRI9P9aMdn8vmy2XQnYd5BHM6Q0uU8kJ6Iyyk
         S9y9P4vMeHVJKu5/E6j+9zbRR01PgI+Hfo9YsricNI7WHaS0IX0Cj9J/MIozWSbql7kj
         YtdnKkiVOVGisIAhC42uvNDe2FA58HOevtmjZtJKxLOQU7PlhQ+DeXNtZxhowDM3r7bi
         tVlRSBZsH1m+Rzy6Ao6s3Enc8k1qXR3JoES4koQ7rgJB+ExXon83FyoN1gvPBMWF8V6u
         dQ2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUejbmIuU6CN+TeGt+HIBNnyz92aoNrnPHQDrDLKTgx7RehP218Ev6hXrxUrLa7Krjz9NOuQA==@lfdr.de
X-Gm-Message-State: AOJu0Yx8FjTE7kkBL29p7LT99zkgolven1k21yf7rteyVHasVFcgJUzq
	n1hbQ/uZf3M/Q9vHnYx02GOTq+AVzwizwZ3fnKuRbffk7ONOgnjCN9pR
X-Received: by 2002:a05:600c:8816:b0:479:1ac2:f9b8 with SMTP id 5b1f17b1804b1-4801e334379mr18074985e9.21.1768548724725;
        Thu, 15 Jan 2026 23:32:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FyhyA37v+g7VUtAe20La6FqT+Be3kFLsTttOVOiTxEMg=="
Received: by 2002:a05:600c:3510:b0:47a:74d9:db with SMTP id
 5b1f17b1804b1-47fb730a4a5ls9000065e9.1.-pod-prod-02-eu; Thu, 15 Jan 2026
 23:32:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUYBL8i7jy1lJiY6pQILASphgpOhatY4lntPmQT/czFqeo9YzISsod5a3bl5LmrLtyXMAQAuS0mp1U=@googlegroups.com
X-Received: by 2002:a05:600c:1d0b:b0:47d:333d:868a with SMTP id 5b1f17b1804b1-4801e349ac9mr24164025e9.33.1768548722457;
        Thu, 15 Jan 2026 23:32:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768548722; cv=none;
        d=google.com; s=arc-20240605;
        b=jksNc5CXk68YLOoU46BUpCbQ4PzC9DfWdKhGh1VOIUGgbLsChg6ijtgOWshJWlDwcT
         FpOHc2NBqk9Do4paIZ09/+WpI9iejYxsz3wASeuzXcCV+1oZCZbc7AEmOdK2593r+G3+
         Ypq5DxKqnZoJtc6hAUiBtdNMX6FvEfThOKKWrFk4E2HkkKqpcTdTTEOIS5jp9rqX5HLE
         LR7Bv2entmEy+63MTjHgQOIRv/LOU2YakGM2nxR9lylNA/qvDpjlYIvH6PS4MvYEKBgP
         jsfc+BBgxDymYkbxJMewTInVuJsCxmxk6+Fg7k3ADvuQiIddqsTLFGVMJuLNcUAl323R
         CG6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=J2wMFYYHoLIThQowW1m8IBwEmgJ9j6LTflF8fZXK/As=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=SU3W2jAy7uO++phQ52I04jVsHUu9UTB1ifxuDedPtyFlh9dh+nk4OmA4I0gb79MpJ1
         7jvVvNJRzUdvslOnS9LqTiXHYnL12bizJkQbi5T390LKHnQM1FNMd55Le6VkEcsS/uuD
         lCzvRpQLHI1KKB5Y6kCy4fgyVrE8HmRSfLCxbphpgY2aLXRpGvvxlhvt3OqCOgjbOhpw
         /U+FMZmsz0fAeTSLQzWmk9EwujWfRHXjRoI6ikYO3WU1RwtIhdCUTaddg62saUBjnef4
         6dZ3twPQDbqqo1LqOgv5bkFGctBqJ4Zq/SF0jIW/ihfwT3zkNzDRCz2We7j7+puBVsRZ
         7AYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="hL/jJS0K";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pWRLH+sp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=yYaTRxrR;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4801e94368bsi94305e9.0.2026.01.15.23.32.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 23:32:02 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9F9D23368D;
	Fri, 16 Jan 2026 07:32:00 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 788233EA63;
	Fri, 16 Jan 2026 07:32:00 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id jQHIG3DpaWlfTAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 07:32:00 +0000
Message-ID: <bb58c778-be6b-445e-a331-ddaf04f97f0e@suse.cz>
Date: Fri, 16 Jan 2026 08:32:00 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 08/20] slab: add optimized sheaf refill from
 partial list
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
 <20260112-sheaves-for-all-v2-8-98225cfb50cf@suse.cz>
 <38de0039-e0ea-41c4-a293-400798390ea1@suse.cz>
 <kp7fvhxxjyyzk47n67m4xwzgm7gxoqmgglqdvzpkcxqb26sjc4@bu4lil75nc3c>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <kp7fvhxxjyyzk47n67m4xwzgm7gxoqmgglqdvzpkcxqb26sjc4@bu4lil75nc3c>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="hL/jJS0K";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pWRLH+sp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=yYaTRxrR;       spf=pass (google.com: domain of vbabka@suse.cz
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

On 1/16/26 07:27, Hao Li wrote:
> On Thu, Jan 15, 2026 at 03:25:59PM +0100, Vlastimil Babka wrote:
>> On 1/12/26 16:17, Vlastimil Babka wrote:
>> > At this point we have sheaves enabled for all caches, but their refill
>> > is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
>> > slabs - now a redundant caching layer that we are about to remove.
>> > 
>> > The refill will thus be done from slabs on the node partial list.
>> > Introduce new functions that can do that in an optimized way as it's
>> > easier than modifying the __kmem_cache_alloc_bulk() call chain.
>> > 
>> > Extend struct partial_context so it can return a list of slabs from the
>> > partial list with the sum of free objects in them within the requested
>> > min and max.
>> > 
>> > Introduce get_partial_node_bulk() that removes the slabs from freelist
>> > and returns them in the list.
>> > 
>> > Introduce get_freelist_nofreeze() which grabs the freelist without
>> > freezing the slab.
>> > 
>> > Introduce alloc_from_new_slab() which can allocate multiple objects from
>> > a newly allocated slab where we don't need to synchronize with freeing.
>> > In some aspects it's similar to alloc_single_from_new_slab() but assumes
>> > the cache is a non-debug one so it can avoid some actions.
>> > 
>> > Introduce __refill_objects() that uses the functions above to fill an
>> > array of objects. It has to handle the possibility that the slabs will
>> > contain more objects that were requested, due to concurrent freeing of
>> > objects to those slabs. When no more slabs on partial lists are
>> > available, it will allocate new slabs. It is intended to be only used
>> > in context where spinning is allowed, so add a WARN_ON_ONCE check there.
>> > 
>> > Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
>> > only refilled from contexts that allow spinning, or even blocking.
>> > 
>> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> 
>> ...
>> 
>> > +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
>> > +		void **p, unsigned int count, bool allow_spin)
>> > +{
>> > +	unsigned int allocated = 0;
>> > +	struct kmem_cache_node *n;
>> > +	unsigned long flags;
>> > +	void *object;
>> > +
>> > +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
>> > +
>> > +		n = get_node(s, slab_nid(slab));
>> > +
>> > +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
>> > +			/* Unlucky, discard newly allocated slab */
>> > +			defer_deactivate_slab(slab, NULL);
>> 
>> This actually does dec_slabs_node() only with slab->frozen which we don't set.
> 
> Hi, I think I follow the intent, but I got a little tripped up here: patch 08
> (current patch) seems to assume "slab->frozen = 1" is already gone. That's true
> after the whole series, but the removal only happens in patch 09.
> 
> Would it make sense to avoid relying on that assumption when looking at patch 08
> in isolation?

Hm I did think it's fine. alloc_from_new_slab() introduced here is only used
from __refill_objects() and that one doesn't set slab->frozen = 1 on the new
slab?

Then patch 09 switches ___slab_alloc() to alloc_from_new_slab() and at the
same time also stops setting slab->frozen = 1 so it should be also fine.

And then 12/20 slab: remove defer_deactivate_slab() removes the frozen = 1
treatment as nobody uses it anymore.

If there's some mistake in the above, please tell!

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bb58c778-be6b-445e-a331-ddaf04f97f0e%40suse.cz.
