Return-Path: <kasan-dev+bncBDXYDPH3S4OBBROTRK4QMGQETRSXHPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id CA2D89B6F92
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 22:48:55 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5cbb635c3f3sf303796a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 14:48:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730324935; cv=pass;
        d=google.com; s=arc-20240605;
        b=KiJoNI4Tij26clkWiHWSQNs30lftCURe7mhgQscmrzKgYzNt/kbqioejCEu/s9Cdak
         xf6iINLRW+xsIH/GHHKDLCTZwOGa3brpmghwGJzVTOUOBn3mXmh0PzDVff3yvkKl2trH
         5lvXqz3rpdJcQ40dBEhXamxw/A72PRiOHrgvDtpNwdJk1YU4zo/wv4ET871lHElQ8zRN
         SDu4MWPUic6PtwwhmnxKv93WDpyeKQeW+gw8c3ivyvdDhIxkKX+pIzCWMAMCj4U52NuW
         VwoTb2xBwSCF2g7ZwGKe4UDcthAdc/X0R876yjlqBkobfNpzBAr1Bkju2yQrq3AwGA+u
         bynA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=d4Iq++U6pARnwGH5Eg47JuSsmNbYTsCK5LHCksqq6xo=;
        fh=qVcLCy9ZkqWRjPsq+O1e8gNgrwAGEXeqAPVU92XIUyY=;
        b=K6O1bDZ10UZn1x2hZTb5ZKR456LF34sPpsWJ5/Q7wjR2Q0zLJNRmnNT58RZgSbJA8t
         8q1xEHRjT+Rh7zq48wum1ACWhfj9lLx1Js53k5/e9vbfoMPIIrUFoTgk9fJ6C7e8C26e
         7uvvFJvU0TCdVuU+QJe4y+DirCtDv+BaiHf+FgyZmt5z8wJmlo4Y4TxQakXCXesdX4cQ
         ckm2Y56w7SefUJgYcBekrThJ7pazy7noUbI6+1W7BuHYmpZXOZx/dw86XRwDTT6Ldajf
         QKDLmcXbXbc0ffE9zcwSVSoAd1nZN+IP+mBJeAA0LDk8/cfWNFS+ObmL/I/RPuUoO5h8
         KSIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VmDTSfIh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VmDTSfIh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730324935; x=1730929735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d4Iq++U6pARnwGH5Eg47JuSsmNbYTsCK5LHCksqq6xo=;
        b=B4cKXMXvqUD99cFs7z7kszFkq68u7ReBtnevjkP/eY8z27pROyyY+rWI/ofN07cB1E
         HtNMd3ZF+dyiDWTPcqNtPCyOuGqWxXGLxdUpyHx2qFdPdmZlLdEOsGvmrjoqhcJp5OJS
         E5JkU7WJZ7qxyXifwVhJg0vWiH5Bntplk/covGR9VTAKvFBoZsFJDA2kFPet12ZrDDqS
         k5gE+/re6lD5z5tA6lsZOiMq/d/3/MUnhCq45uSCYQgC4/4VlED06WFwjzgiOoKe2c7+
         v53glO7IA7DSF1gZDxOJU/qhlSMSGa2te+gdwkwucvp50bDHgMZMHvM/4CU8mGiJgCBE
         1n7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730324935; x=1730929735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=d4Iq++U6pARnwGH5Eg47JuSsmNbYTsCK5LHCksqq6xo=;
        b=Os8FKIAeNMQoxZM+SBTWJ8lHtn+Nf101PpOxmmNsPDJbO3BIMKPVeThAH+e8nsXVTm
         lzwHy0YNmyHJwsdsdEqPcVgytb1YY0VVsrSLhU94YHNoLBkHrFMYMl9IirzzdOYb14dO
         UG5f3G5b92TA16Mtw2+nS1ZTUaiyxlkamJn7J1aDhUy2gAAfLkG/mWaJlfyggKJyn+h9
         S6ranrWC4BV1Z3xfD0e8ZHmjxUtjvcgLUch0tNwl5VYYi6rJmS2ZT2kZDkDdCCQCKew/
         jmTy7at6dKMi0+IsG4z/qFa5h5uzBBFoqbc/y8ZC/UdVUBqiA83ANnp9PQjBProMhM55
         f7KA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXs0LG0I2EXdjCDWbLmQGc17yu1HiWmA1SCtYAbTpzyJSuSwpgPq0S+BuBjN9SYAzW+1k1dNw==@lfdr.de
X-Gm-Message-State: AOJu0YwDJOWRU0vLT+JWN4NtsoD8R7x1QLoQRRERVByuQH4Qj2EMFsWm
	N+bYrfwlkiwUSL3aWFwi8weSCxQmkHg8l8zVLdsx9xjBAMU7oFZS
X-Google-Smtp-Source: AGHT+IF5n4N8oAsVTyutdYy7PFzkctwrsPH9HO63tCxR5Vrr9qHqFh+GsmqwgE/Zo6EgwINmdIvZxQ==
X-Received: by 2002:aa7:d055:0:b0:5cb:991d:c51e with SMTP id 4fb4d7f45d1cf-5ceabf40738mr155040a12.15.1730324934437;
        Wed, 30 Oct 2024 14:48:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5253:b0:5c9:5b3:ee81 with SMTP id
 4fb4d7f45d1cf-5cea970bc41ls213555a12.2.-pod-prod-00-eu; Wed, 30 Oct 2024
 14:48:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWGtIPEavt1hpb/yWk8gprVoW+GG7Q2bZhYRsV56T7Y55nZ7xBPjEn8ZljfmOIVqi6zlo1xvR5YuCQ=@googlegroups.com
X-Received: by 2002:a17:907:9454:b0:a99:fbb6:4972 with SMTP id a640c23a62f3a-a9e55ad7374mr16877866b.25.1730324931727;
        Wed, 30 Oct 2024 14:48:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730324931; cv=none;
        d=google.com; s=arc-20240605;
        b=aBGp1l97ct6Mu5QqUTN86qE9Oqq1IcVkbCybRgzJU5QgEFmbgEAsybvtvFvQ4idBg3
         04e7spOVRrPpYIIzfYuBVf7EbTThjgWOXJwOTsi/qdL1I/4zrN1UE8q1k8mnZ9/o3Ud1
         zwZgPhg/afmDI0JupQgC6kO5Hcm6hSiudGxsmJCCEqzIYuVPDgW5gD3OBzfASYm0t2B0
         PjXV0gg6+ffFakjmOsLAqNoIgx7lVOvQwYzA3Yxg61PKzVlnBv6Tg2fGa8bYao9mOrXl
         z85DXeNgVfVNPUstuDHJ0kHK2/XcGQ+haYWaEHz7+/wbSN/PgCpD/yftaO3+G+7opEe0
         o3Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=wS6Qj4yMwAu8JhKUkSlwL1XLNze6T0zoqEv8RVutyPI=;
        fh=9A0KNG4O9C2H9bxMWfPGf80UCXPB5L9LbPwFp57ZgPM=;
        b=NlEfmL1cesi4sGbAX3bx6OimX2wUVtmC0MIxPGxE9cM34+PoVUaekur3u5Yi4YfJFu
         IKllsz1O4DebavVh+yIeKFiRwqPjFAu0Knxfzo17rFdGbYUCcPcDsKcYGUdOcNtdimQ0
         HAlGuvBiQXDGETH9SjyNQj56TIYOTsEyZdOwvD4PP4SNIb9vjEIv9VXaz3Dmde/ZUxxP
         wrYzETg+IzHalBIoFLYV5d/ct3MnYyfmzWAuQPqhTUS0FJtiR85kjXDUFyIrU1LPqtSH
         0o8vAs8tRO9RmKGRqBhh4I5lFXwezV1TvO3hp0/Hc0ofQzwuEDLUD9kFP1CjMFdtdB9K
         vn4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VmDTSfIh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VmDTSfIh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a9e565bfe35si91466b.2.2024.10.30.14.48.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 14:48:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 17EFC1F7CC;
	Wed, 30 Oct 2024 21:48:51 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E03AA13A7C;
	Wed, 30 Oct 2024 21:48:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ZEhXNsKpImfeBQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 30 Oct 2024 21:48:50 +0000
Message-ID: <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
Date: Wed, 30 Oct 2024 22:48:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [BUG] -next lockdep invalid wait context
Content-Language: en-US
To: paulmck@kernel.org, linux-next@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Cc: sfr@canb.auug.org.au, bigeasy@linutronix.de, longman@redhat.com,
 boqun.feng@gmail.com, elver@google.com, cl@linux.com, penberg@kernel.org,
 rientjes@google.com, iamjoonsoo.kim@lge.com, akpm@linux-foundation.org
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_TLS_ALL(0.00)[];
	TAGGED_RCPT(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[canb.auug.org.au,linutronix.de,redhat.com,gmail.com,google.com,linux.com,kernel.org,lge.com,linux-foundation.org];
	RCPT_COUNT_TWELVE(0.00)[15];
	TO_DN_NONE(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Score: -2.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=VmDTSfIh;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=VmDTSfIh;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/30/24 22:05, Paul E. McKenney wrote:
> Hello!

Hi!

> The next-20241030 release gets the splat shown below when running
> scftorture in a preemptible kernel.  This bisects to this commit:
> 
> 560af5dc839e ("lockdep: Enable PROVE_RAW_LOCK_NESTING with PROVE_LOCKING")
> 
> Except that all this is doing is enabling lockdep to find the problem.
> 
> The obvious way to fix this is to make the kmem_cache structure's
> cpu_slab field's ->lock be a raw spinlock, but this might not be what
> we want for real-time response.

But it's a local_lock, not spinlock and it's doing local_lock_irqsave(). I'm
confused what's happening here, the code has been like this for years now.

> This can be reproduced deterministically as follows:
> 
> tools/testing/selftests/rcutorture/bin/kvm.sh --torture scf --allcpus --duration 2 --configs PREEMPT --kconfig CONFIG_NR_CPUS=64 --memory 7G --trust-make --kasan --bootargs "scftorture.nthreads=64 torture.disable_onoff_at_boot csdlock_debug=1"
> 
> I doubt that the number of CPUs or amount of memory makes any difference,
> but that is what I used.
> 
> Thoughts?
> 
> 							Thanx, Paul
> 
> ------------------------------------------------------------------------
> 
> [   35.659746] =============================
> [   35.659746] [ BUG: Invalid wait context ]
> [   35.659746] 6.12.0-rc5-next-20241029 #57233 Not tainted
> [   35.659746] -----------------------------
> [   35.659746] swapper/37/0 is trying to lock:
> [   35.659746] ffff8881ff4bf2f0 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x49/0x1b0
> [   35.659746] other info that might help us debug this:
> [   35.659746] context-{2:2}
> [   35.659746] no locks held by swapper/37/0.
> [   35.659746] stack backtrace:
> [   35.659746] CPU: 37 UID: 0 PID: 0 Comm: swapper/37 Not tainted 6.12.0-rc5-next-20241029 #57233
> [   35.659746] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
> [   35.659746] Call Trace:
> [   35.659746]  <IRQ>
> [   35.659746]  dump_stack_lvl+0x68/0xa0
> [   35.659746]  __lock_acquire+0x8fd/0x3b90
> [   35.659746]  ? start_secondary+0x113/0x210
> [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> [   35.659746]  lock_acquire+0x19b/0x520
> [   35.659746]  ? put_cpu_partial+0x49/0x1b0
> [   35.659746]  ? __pfx_lock_acquire+0x10/0x10
> [   35.659746]  ? __pfx_lock_release+0x10/0x10
> [   35.659746]  ? lock_release+0x20f/0x6f0
> [   35.659746]  ? __pfx_lock_release+0x10/0x10
> [   35.659746]  ? lock_release+0x20f/0x6f0
> [   35.659746]  ? kasan_save_track+0x14/0x30
> [   35.659746]  put_cpu_partial+0x52/0x1b0
> [   35.659746]  ? put_cpu_partial+0x49/0x1b0
> [   35.659746]  ? __pfx_scf_handler_1+0x10/0x10
> [   35.659746]  __flush_smp_call_function_queue+0x2d2/0x600

How did we even get to put_cpu_partial directly from flushing smp calls?
SLUB doesn't use them, it uses queue_work_on)_ for flushing and that
flushing doesn't involve put_cpu_partial() AFAIK.

I think only slab allocation or free can lead to put_cpu_partial() that
would mean the backtrace is missing something. And that somebody does a slab
alloc/free from a smp callback, which I'd then assume isn't allowed?

> [   35.659746]  __sysvec_call_function_single+0x50/0x280
> [   35.659746]  sysvec_call_function_single+0x6b/0x80
> [   35.659746]  </IRQ>
> [   35.659746]  <TASK>
> [   35.659746]  asm_sysvec_call_function_single+0x1a/0x20
> [   35.659746] RIP: 0010:default_idle+0xf/0x20
> [   35.659746] Code: 4c 01 c7 4c 29 c2 e9 72 ff ff ff 90 90 90 90 90 90 90 90 90
>  90 90 90 90 90 90 90 f3 0f 1e fa eb 07 0f 00 2d 33 80 3e 00 fb f4 <fa> c3 cc cc cc cc 66 66 2e 0f 1f 84 00 00 00 00 00 90 90 90 90 90
> [   35.659746] RSP: 0018:ffff888100a9fe68 EFLAGS: 00000202
> [   35.659746] RAX: 0000000000040d75 RBX: 0000000000000025 RCX: ffffffffab83df45
> [   35.659746] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffffa8a5f7ba
> [   35.659746] RBP: dffffc0000000000 R08: 0000000000000001 R09: ffffed103fe96c3c
> [   35.659746] R10: ffff8881ff4b61e3 R11: 0000000000000000 R12: ffffffffad13f1d0
> [   35.659746] R13: 1ffff11020153fd2 R14: 0000000000000000 R15: 0000000000000000
> [   35.659746]  ? ct_kernel_exit.constprop.0+0xc5/0xf0
> [   35.659746]  ? do_idle+0x2fa/0x3b0
> [   35.659746]  default_idle_call+0x6d/0xb0
> [   35.659746]  do_idle+0x2fa/0x3b0
> [   35.659746]  ? __pfx_do_idle+0x10/0x10
> [   35.659746]  cpu_startup_entry+0x4f/0x60
> [   35.659746]  start_secondary+0x1bc/0x210
> [   35.659746]  common_startup_64+0x12c/0x138
> [   35.659746]  </TASK>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e06d69c9-f067-45c6-b604-fd340c3bd612%40suse.cz.
