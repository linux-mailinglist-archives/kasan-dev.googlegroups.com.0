Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXFTXXFQMGQEG4QGMZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id C8937D3C552
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 11:33:01 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-653810ea5cfsf5722635a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 02:33:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768905181; cv=pass;
        d=google.com; s=arc-20240605;
        b=I4Nnts9P55ZpH0xqQzKZeQjIJrdUWCD9+q/E4envJFoHu92ow2l2tDnEiNXW9uoJ03
         1TUD9n8v1lo9jwpgw4lKyWrfLKGpE/5qMG15G3MfFOrq70k2tlB+1BlYc68T+/CisplQ
         hG6kpvHOO5HniZYlZdQRxb6cdunJ7W6H7zCV/LlMHZEl0veeymLpMnkA+UCljE8N3Ftj
         Z70oks5uOYYN1m7VB/h5E6hWcj8vnhjXe6sy+pnud068mH+ZBrqjsCkD6EI6JwC6xyGp
         dT6eAcpuAnbYFw2v4O9PUaMfSEIv1m5maDgLEMbSslI6lRnu197MSxBq2BHe1ENLk9mY
         dM6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=Vx2Bt6Gjbnr3O3lZ6XqluHYnx38F9sbTgIvNaqr+hqU=;
        fh=2K9a6SiFTIXhaC3Nn3Mo7arjfczx5sBcsL8imYnqUpw=;
        b=PJTaAkiAAWk0OW4a2cH8iOV94wkrTeBuWIhb3smq6LAGt2xgCxBSlIPCbqX3E3dm+E
         wvf8IrpxPOKWkcNYY4sjkPxcqeHedlQn7Y3t7QTAENVLbXofAc6jY8P1lpW7vlXuROwl
         +NIbyQNvA3UJae0/huL1n/dIlaC6LA+5o8wYDQQLfmMGftvn5F3AimSkf8hupGT7yxAX
         CJrahDwppJIJN6e9L9lAm0ivhVGafUYBv6QD+py1U2Dj1u4dnUDnjVZhgh+TG8NOsSlT
         wfLPsAs77TkXS51UV2BOB+dZnhQZgoFiGgynefKjadfnNxrKDl4O1ohhq1mI6RPxtjwn
         dXzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ncNBYv1u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ncNBYv1u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768905181; x=1769509981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Vx2Bt6Gjbnr3O3lZ6XqluHYnx38F9sbTgIvNaqr+hqU=;
        b=iUitqHkUlYOZJeGpo4ygQNtC0rSXe+NEKsyXbe/pP5uCBmoUoW+6d9vX9yHXlpceSM
         HWreFaLewnP4oJtzQdspivIh46h2wwI06vongdqbEFFua6oPuQXWL9O+n4wXjVJlq37V
         P2SnJiLnIjmZoEAu9S8T/BYRMfdjaBUG+tMUEoYE0LP5R6yZydA4/oFccXxKHnHbnevY
         ITV5aQJ7xAheh17mHWFqjxwkbPzMefNiWItTtf9rCkDizQQtdwBIR/muENX5gbRiLkFS
         hLU9qZd3aNjEtByvPWRP6dVKJMHmjiowSBfshk7AnymO+MvK8LjooT9dO+1LkAhKzJuV
         GlMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768905181; x=1769509981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Vx2Bt6Gjbnr3O3lZ6XqluHYnx38F9sbTgIvNaqr+hqU=;
        b=N83vgHLGY12QIMCTUN4NxVoYyNtSLbvBoLQrGC4wGkaElbW25pzl5fidr6rgfN0QoU
         ftHbZL5PX/fnbNVI7fZ2eDNrEbh7jfR0nhyckT/1cMOQT5zlhsGKaqKFn3/h5rXB+VyG
         AGy26Ywiw+B6aG+4m7XO/cABw3IGxoWNl18muY2INcy+KxrdQPfIqit1RODHyt5sAUUR
         RfFp9t2vxJdq96NM0XndMAandz2raF3gzsn3L+oCU4bN80cDUGMsp6KUMLOSzWP5uRAt
         1sTJD9jJ0IFXEcDOFJ57eQtrkjiQnFKMUg8kAWzLdX/YksEhMRCcHYKTDcnL1t97K6JV
         8lpw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVYitPsw9WtUbRQuYy/70lUUokINDQGRBfyQSs+LpGr1BicZEPJb2LBdLwqxjVEFyQyI880JQ==@lfdr.de
X-Gm-Message-State: AOJu0YxTsrLlOYcl6NNg3SU8AFQFkrPdw3k1m/gEjZ1r3LUVxCnnr1+T
	rT7qzf8kfr2tH3n9o7/Zj6O1bZ4aFoe8AfJbn+Rj2uFW0X0WO7i1rjra
X-Received: by 2002:a05:6402:1e93:b0:64b:5885:87d6 with SMTP id 4fb4d7f45d1cf-65452bce3a0mr11869512a12.24.1768905180670;
        Tue, 20 Jan 2026 02:33:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H6PCqhxY1L/rXwjWoOX8SppR0YaES2MHHyQdNA5cAdOA=="
Received: by 2002:a05:6402:3256:20b0:641:6610:6028 with SMTP id
 4fb4d7f45d1cf-6541c6e9c85ls5956554a12.2.-pod-prod-03-eu; Tue, 20 Jan 2026
 02:32:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWEtDfeFnNmvj5zPWX3yamFMNQsIvpkDC4Nsdu1VEdxzPbnHdhcI7JL/gtkSpRVOw6a0iwexlaC7kY=@googlegroups.com
X-Received: by 2002:a05:6402:2349:b0:640:cdad:d2c0 with SMTP id 4fb4d7f45d1cf-65452bce41cmr12913903a12.25.1768905178374;
        Tue, 20 Jan 2026 02:32:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768905178; cv=none;
        d=google.com; s=arc-20240605;
        b=JenP6XjqhpW5qgovFAZIC+Cihy2PQHpMVVC4Kt86Xe5mWRtc2t7PYzCtMt66YtdHsA
         OaQplWWjIb7lvjtfNDw9ny6FSghyRyd3MpGW9SViTJUh+51CxoSfKDHhI5B4ZQEAo1H7
         S2qMo/3Hk3ArfBJU3uxD1huncSUWFsuUtgPAM4xQD3jVg0u0YugvOmH4Mk+KLWK1Hq78
         g20Vu4Oq1ZkoiwM4QVDh6EmKszt5RgKkC6NbaFbbUVMNw8Yc4jOBHFUv9FojSerKeux1
         9tdwjYe2npNgzBrXkWPEmoCI8wLLpl13uOtY0lrvdCLbnlr9mQ3EyKJsqEOdREMZx1EZ
         mgCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=XyrDx1MhY3e+hHISP5xpS3IMhu37A0mWxWGFA4RwEpQ=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=aFj6sbwDP+uKmZVdI7YXv7HhYPloATnm85E2EDLwbUQwkbULFcC4MOYNCRH7qoHMaq
         iv8jwS4WVnMpr7W6xctEZjaMkvmM3maVb1Cv0Kx6XTZutn9dH9wKnbNSjbNMXBvxY/vw
         SNYd5f5m+COps2m52yP7uLbY0UDeqDitt9aR1ausn46u35t9K/Tlct3+v25DCot3NUBj
         hkJoq1/itRAHUaIdPlcgJfAfLIULbOhCAFes5leU+aJGtX6pKqWYgfGKxulDmkCBaCiQ
         KhP6aqtPsHD9YBHPAj/HFARd4vQt5nkbnV1w7gXfJrF8TL9CobftD2eUvbDEFNlNzTm4
         jorw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ncNBYv1u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ncNBYv1u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65452cca91fsi191420a12.2.2026.01.20.02.32.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 02:32:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D30305BCD4;
	Tue, 20 Jan 2026 10:32:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A69C43EA63;
	Tue, 20 Jan 2026 10:32:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id yYFUKNlZb2kdbwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 20 Jan 2026 10:32:57 +0000
Message-ID: <1390b9ce-0ed1-4cc9-845f-fa4dd5f3ffc8@suse.cz>
Date: Tue, 20 Jan 2026 11:32:57 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
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
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
 <aW7pSzVPvLLbQGxn@hyeyoo> <2232564a-b3f7-4591-abe2-8f1711590e6e@suse.cz>
 <aW9Yl-nqLjAJyBkB@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aW9Yl-nqLjAJyBkB@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.51
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
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
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: D30305BCD4
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ncNBYv1u;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ncNBYv1u;       dkim=neutral
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

On 1/20/26 11:27, Harry Yoo wrote:
> On Tue, Jan 20, 2026 at 07:33:47AM +0100, Vlastimil Babka wrote:
>> 
>> Right, so the plan was to set min to some fraction of max when refilling
>> sheaves, with the goal of maximizing the chance that once we grab a slab
>> from the partial list, we almost certainly fully use it and don't have to
>> return it back.
> 
> Oh, you had a plan!
> 
> I'm having trouble imagining what it would look like though.
> If we fetch more objects than `to_fill`, where do they go?
> Have a larger array and fill multiple sheaves with it?

Ah that wouldn't happen. Rather we would consider sheaf to be full even if
it was filled a bit below its capacity, if trying to reach the full capacity
would mean taking a slab from partial list, not using all objects from it
and having to return it to the list.
Of course this would not apply for a prefilled sheaf request or
kmem_cache_alloc_bulk().

>> But I didn't get to there yet. It seems worthwile to try
>> though so we can leave the implementation prepared for it?
> 
> Yeah that's fine.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1390b9ce-0ed1-4cc9-845f-fa4dd5f3ffc8%40suse.cz.
