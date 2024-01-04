Return-Path: <kasan-dev+bncBCO3JTUR7UBRBNPD3GWAMGQEEMYU2QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id DBB74823DEC
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jan 2024 09:52:07 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-50e7b7c85easf203599e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jan 2024 00:52:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704358327; cv=pass;
        d=google.com; s=arc-20160816;
        b=YWRZFXRO0XCIiQkrYKCs1BnNnh4mvueZuLQmNUYuiIqEQwJIR5srj3MrNzxp/iW9uA
         bPP1PxvRjtjwSL0yYG4C9IZbLdTBtDI6jaGCRZl9v+54oD17vU8wpn4aMnoGBUk1Xt3K
         wlaGlto9aCW1H2qsNZTiMoaw6fzzzRGcMaWIMaFERQKolXxXXeUBr5FlzkXnDktuTJ+Y
         bSZvSNB6WJBfNeRRYjhU5QCgSvmXHWOyLqYjIy2HZ6H6gDQfWRhCwk+kEtzawtHBD3ZH
         +j7CC4kspt6yZNwzR5FzVuGYTDEl3R/yixMPALwx2+UE15N1m4pWuprl3Ytj1L4AaWE2
         mdsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OI8J7IrcIEque4ygEhy7wMS1Qw1ZQ/2KQfjigaTmKko=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=EpSGy420zaCVVfWurafo70wEC1j4aY6RnDzq4XwqZjkKAOx2XvZvWiq9Y0f19Y2VAv
         FRTMmCvGevglkXJiO9I5Uc/1laJTb9FoGDoly2OBwvisA+dJOqwptrzje0EpnOgpTD2v
         34P72hAb8eoXvZoYAH7U5GmiegC3VuVZE6oo0EAqQt9DtJ5aiumypYxeKlii4JsyhorB
         gkeChGObcLUJbFIjYSla+VgKWGf77VQ013L4a4M/YS8NYLn68NQ5+5I47i6O+TgVieTf
         RhkS2SdC/icVBKkylqD/f1hLQNCc3DAuVaD79E7VbmWtStj7ORU0gUyFm8FNKp9hzL/A
         BfTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="1TRI/m90";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="1TRI/m90";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704358327; x=1704963127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OI8J7IrcIEque4ygEhy7wMS1Qw1ZQ/2KQfjigaTmKko=;
        b=TWhJTMCBYK7pL33i9K2ExEs0ww5i179zDav+14PBo/gxdCgsjRBZSsXTX5bpf0zZ5W
         82zUD5TJK05eWhxyueGKITW7+OgBkYaJe22ZNJiQYcSHPt65rFj1BaxYMqKT6lF3s0Wc
         Qv7NTbV8ZvYUN1uoHuLe2WMI97vbn92KCzjq5+f0cSvLMhbYXrFg5iTxE67p9C+evu/H
         F0Yybf7G0p3lUUboRfqW2A5mlphuXhSvuKtgI0Ds3GgVbXaKcP9YU/NDKzWIc5C/lrzf
         7fLtIB+rR+qzWGy7eus6DPo6mVZ9Wc53/deWmaD/OXGH1kZUl+R2jVaM85WpxqO8WGSJ
         uXrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704358327; x=1704963127;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OI8J7IrcIEque4ygEhy7wMS1Qw1ZQ/2KQfjigaTmKko=;
        b=VwR9bhMN3A1xZ6l9ZtI06sut1/rn0lV9CKzq5x0TSzEEDFCn/9tJoBGsDbAD0yOKQY
         MfsdZOqB2TU7LIw8QUxbgRAgliRtvYhp/6ahOJIOGMkMRcNADtYS7PY5d5ZQGzJwJ8Z4
         KjOk/fHiR1BaiGJeZgO2KgbqvIhb8sO6ztxQ3n/RFNw6lUnUx/qUv63wzf4oIXQsWRyR
         eClcgevimm0O4BNumg7+6b34gWGs46BM9drFojLOvFYxAH4b29/EfDWe51+Ck62xDVKz
         VbLxANS99Dt7BCe0W8E6uJfmrflKlP1m9Bqu1mpKVRIrEC//Z0go5AQR+SV4pntoiAOb
         1/UA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwfjCPg0uKit0TndabTq9uE49JnGq98WCYyS43YTuzb881Rz3+F
	c84SG+SUCWXt67W2MVC2jxE=
X-Google-Smtp-Source: AGHT+IGhHnYHPghUBO0ohnikr6YHgtmWhUq7yhkgK5TpNJluwcYZAZRRJn5tiwzBc26FrBnc6bF/vg==
X-Received: by 2002:ac2:47e1:0:b0:50e:39ab:4347 with SMTP id b1-20020ac247e1000000b0050e39ab4347mr142063lfp.132.1704358325784;
        Thu, 04 Jan 2024 00:52:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e83:b0:50e:7c6d:f957 with SMTP id
 bi3-20020a0565120e8300b0050e7c6df957ls1818205lfb.2.-pod-prod-01-eu; Thu, 04
 Jan 2024 00:52:03 -0800 (PST)
X-Received: by 2002:a05:6512:3e06:b0:50e:4fe5:c250 with SMTP id i6-20020a0565123e0600b0050e4fe5c250mr197997lfv.114.1704358323592;
        Thu, 04 Jan 2024 00:52:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704358323; cv=none;
        d=google.com; s=arc-20160816;
        b=a/AuZxG8Hv99NopyLvLjpnx/2mv9esiRQ76z218tek4YeLBBk1zQo/xxmYqmsJcy+d
         Oi747YU8aksnv/RTNR5K6SSe7INBb5BMZdPOx293cWPxKn8jgU4zCXVGT4XDnsyocC6D
         4UTpqYSbIzE3evFmp4FI8If7KgwUtBXkuMFqW2Rb/x4cA4GqF32kahVDPhZHbUNoL4UE
         2N3JAv4dIEntgZhJo3eSmf5o2sYploFf8wxh0vm8kG5MKE+rRrIyYjDNWOEpZIKFuwny
         HLAlJVhODwYoWyDaR8dZzfRm0/YuMb3reoZD8UercLapoMoPceB4TaeKINvd3Ar3N03c
         gIvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=e2YJJ/wHF3T/z8OvARyhcqLm9IAHtRiaRn7YI2Y5QEw=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=0sP6qPBd/HYv8dw7pBzVQ3hCKY44D21zwZkYrpubRYi5pbPyC5VhbGdFutANiRf215
         17lUBgxntL33nW58JRduiS4dOMUUm8+A9+i6SIiBd96GDYwI7ODgG+02ZKYXOyMKV+QZ
         DN74kJmFwoBnt2jOG/HLs+UezbCr6q/3ocU6wHwLe1ys7wie0JhmQWg0rlpdPDU042cP
         IY+DbbriD6tezFYqdtogQVpfGtz7XBuoanqQ4kwWeGVhQpc7zygVzEmDfOj7Jpp6BFC9
         WZAuLAEaqvqfcINAAOOv5AMW15EdOataNPZKuoeebqIvgqT5iE1c7L77bNTdujRU38Ae
         oHsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="1TRI/m90";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="1TRI/m90";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id t3-20020a195f03000000b0050e6b19b855si1403222lfb.11.2024.01.04.00.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jan 2024 00:52:03 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 8DA501F7F6;
	Thu,  4 Jan 2024 08:52:02 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CF48913722;
	Thu,  4 Jan 2024 08:52:01 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id QM5NL7FxlmW7VQAAD6G6ig
	(envelope-from <osalvador@suse.de>); Thu, 04 Jan 2024 08:52:01 +0000
Date: Thu, 4 Jan 2024 09:52:53 +0100
From: Oscar Salvador <osalvador@suse.de>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 17/22] lib/stackdepot: allow users to evict stack
 traces
Message-ID: <ZZZx5TpqioairIMP@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <1d1ad5692ee43d4fc2b3fd9d221331d30b36123f.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1d1ad5692ee43d4fc2b3fd9d221331d30b36123f.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Spam-Level: 
X-Spamd-Result: default: False [-3.10 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 BAYES_HAM(-3.00)[100.00%]
X-Spam-Score: -3.10
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b="1TRI/m90";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="1TRI/m90";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:15PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add stack_depot_put, a function that decrements the reference counter
> on a stack record and removes it from the stack depot once the counter
> reaches 0.
> 
> Internally, when removing a stack record, the function unlinks it from
> the hash table bucket and returns to the freelist.
> 
> With this change, the users of stack depot can call stack_depot_put
> when keeping a stack trace in the stack depot is not needed anymore.
> This allows avoiding polluting the stack depot with irrelevant stack
> traces and thus have more space to store the relevant ones before the
> stack depot reaches its capacity.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

I yet have to review the final bits of this series, but I'd like to
comment on something below

  
> +void stack_depot_put(depot_stack_handle_t handle)
> +{
> +	struct stack_record *stack;
> +	unsigned long flags;
> +
> +	if (!handle || stack_depot_disabled)
> +		return;
> +
> +	write_lock_irqsave(&pool_rwlock, flags);
> +
> +	stack = depot_fetch_stack(handle);
> +	if (WARN_ON(!stack))
> +		goto out;
> +
> +	if (refcount_dec_and_test(&stack->count)) {
> +		/* Unlink stack from the hash table. */
> +		list_del(&stack->list);
> +
> +		/* Free stack. */
> +		depot_free_stack(stack);

It would be great if stack_depot_put would also accept a boolean,
which would determine whether we want to erase the stack or not.

For the feature I'm working on page_ower [1], I need to keep track
of how many times we allocated/freed from a certain path, which may
expose a potential leak, and I was using the refcount to do that,
but I don't want the record to be erased, because this new
functionality won't be exclusive with the existing one.

e.g:  you can check /sys/kernel/debug/page_owner AND
/sys/kernel/debug/page_owner_stacks

So, while the new functionaliy won't care if a record has been erased,
the old one will, so information will be lost.

[1] https://patchwork.kernel.org/project/linux-mm/cover/20231120084300.4368-1-osalvador@suse.de/

 

-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZZx5TpqioairIMP%40localhost.localdomain.
