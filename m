Return-Path: <kasan-dev+bncBDXYDPH3S4OBBB5VVDFQMGQEI3N7DKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 66B31D3002E
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 12:01:28 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-47d3ffa98fcsf13535365e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 03:01:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768561288; cv=pass;
        d=google.com; s=arc-20240605;
        b=A5Pbxa1wE+9HJXN6q9LI57gPcpc2P8B55fwPKgoqz8/uhoU25lcK2FJCR0WfjzBzBi
         +726EncJxMVyKFYgDHaLqb7IdYkH4/nEazAllC1wK9i3uhXcGgCfheVi/vpvvXt7uxiN
         TUDBeh50sUyJYANn+JUmbnKm2k/EvRUrpHrtmfZib9sgi9O/KiksHatYkDd+kg6B/x6t
         AckTky6KISd5VA9fCOyzF4OaB8ibBOLDcUJTh2sZ5HYlj/Ts5jMUGb7Aj8FxrstB7irH
         wvvdNiNgU+v3qzq62B5bFljzpTCu5C3EG3UjAyrSgWcbLAz1Be9tcv6kIxyZud1XHDFr
         +0Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=CCfogU27fERzqSqqN0k0d/2Pm3Bpc0SPZ/o8U9eg5b4=;
        fh=/8q0OfJyQVsKMlPm85GOPB2a9vsZy5hK12FCVB9eFsY=;
        b=Nh9XH7etD1bNEqtuZdH9Yg2UBBRDQypTqJjJEM0dQGjjImbeYc04cVXqDJL7sZlG3/
         i61by+qOhZW25npOzM0q0NQsRfvTAm7QyGa+J1ytWBhnwrjtd/h/4wz+WwYy8lffpift
         nvXEL60ctKKXGX+Tskum6nSS4P0T+b5RZ0aXRCx2+aDTcRKWyeqE77UNrSnld0yJwxa/
         D1QaRXq46QTUrLq6YDACRwcZd0wbWQfqnrqrs25MNj/p8IaLiJjKvuBXt7lAPUJNjnfS
         5aJ0FM/autZ8o05kv6bAsceT8Ma+xWS+4e4dVtJiMHYC+l963kNJfWB3eCBLdlz9UbfJ
         6EQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=a9O3Gu2E;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zCnkCSC+;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768561288; x=1769166088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CCfogU27fERzqSqqN0k0d/2Pm3Bpc0SPZ/o8U9eg5b4=;
        b=j5sAUKy3POxghEUnB/QYE2Y2mHaM8xIeEgbADJ8LFISQshX18cZsESnaU/UKytIijP
         +Yyr6eiSW+jdyZY8I3Jokmwclc/eMcGu8rS3uvyQg9MkqAzegGugHpTloVoOa20UT247
         GtBiPu5jaDIVENGLwe1Noppjh+IZ98cUhEAfebB05/RchMvzk40QHXhJ+rRUH7hv1UEi
         3S31bdWt5Qda0PrzqLT8lK1pA3kts55Gmnv6bFivmiiyMHE9vJmj/Ganq2Pg1u+scudk
         xWy2Sws1kQNKgRpBn6KosM65lkFdk6jAIXKP7CEiDodYQQfyB6LOyLntHduQuwHojZQN
         PWpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768561288; x=1769166088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CCfogU27fERzqSqqN0k0d/2Pm3Bpc0SPZ/o8U9eg5b4=;
        b=l5SimUhdFulYnovjHCIz/bDlr/Q47opLlQwCXKQgmgJMpUfSoyyty6XBmxglhsfUnz
         4ctO9JAzOfKfjkM6PAhFlO065gfJvi5Nhj1k3Ahw5l33+C7uOuqQCr3ATkfLseHP6yRR
         wnYnY4m1hj95CM+Fy6tf0Hhu84kW6nwaZN8QAt8GHkWBMpYVzKfbOSgAsMqUiJtUoYpY
         4xnxnrCQ0/jsl0zHQ5YTpmCGiQ+QghwGz83vI+mSENMil37y6Zw3AaddkmBAwQQ/ty8T
         bX1Y99gtj9FAQKDkTFlgXvbC/nE2kO3yhdR2qhpB6h1mnlmv2pKdioD2wIPECnBI6+Ge
         F4yA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVMbIFt4gxkfxRThbmHXoe67Pu2HGk0J9e9ARssRk6vIdg3/4QFfsUHa8VMAG/dZCQoonk27g==@lfdr.de
X-Gm-Message-State: AOJu0Yz4vv3w6myV1FsmfaegvYezWsGOa824hNcW3g4DvG/rTOCxoCD9
	qTZ5r9rRvkLSRviy17/jHiqc6ySNQVlhEdY1HjLoCYleuaAvAdmXDxU3
X-Received: by 2002:a05:600c:3b84:b0:47e:e575:a33e with SMTP id 5b1f17b1804b1-4801eb14eb8mr24255915e9.33.1768561287675;
        Fri, 16 Jan 2026 03:01:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fi4gWxtLq/PF8h4Wdrh2RGz8uuuprCW0XGYvVqkts3UA=="
Received: by 2002:a05:6000:3106:b0:432:84f4:e9e1 with SMTP id
 ffacd0b85a97d-4356417f91fls986999f8f.2.-pod-prod-04-eu; Fri, 16 Jan 2026
 03:01:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXGosFDII/Wbl6J9wTPKNlBv5/3vAHxQNGe9FxFS8qTuVDM7l52MFMdwLnaxNiRIob3i0i9y5Q81x8=@googlegroups.com
X-Received: by 2002:a05:6000:2005:b0:431:9b2:61c1 with SMTP id ffacd0b85a97d-4356a02640emr2867322f8f.6.1768561285362;
        Fri, 16 Jan 2026 03:01:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768561285; cv=none;
        d=google.com; s=arc-20240605;
        b=LJ5NoeOLk4jYFI2T982Z0KNL9Qd7UqiTNpVCj4tZP7OVsmLQAhzoS1caZpigHmukzy
         OnV7Y9BuTV9n+xUr+H8pYesjeIlBSMAo4mDqqry1IZwViNwC7LtVeysMNOSMfLcIr+5w
         1IVtpDIopWDtJTT2F28W9xxI2LHHzt/T0nyfCmDjHsTPQIP54ZEegX3cTo0q+FgV1O30
         QCwky1Bexsn5FDZXzY84FD+iFBimnTpbrxwZFCFo/jSDR3VgmW5V2RhiSapyFpqwQjZD
         Ajn4H+sKdFqUIDjU+AMDw0RfYmOq2we3tvuH9w86/B2gk1ZgMYipfpcXjPXQ3wIc9UpH
         9CHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Ku1XPwrP1SS53/mL1tvFmnSiaEKNhp384TKnyEmC8D4=;
        fh=AbsRP2uRCswQdmIdhSesVdEqAq2m9kclgi+VNSoZxeY=;
        b=jnvx/sZ6DtVLBbqMJ/u9Mazt0cM66euS8kQAA498rOVRkaktpBTc4ZXNj9ifBo8bVf
         Vpg7Y9eAY1mAdRmCQV4fOiJl5WZuOxwmeqXHqf3E1Y7vlPIGAVenmfYFE8fBvA+zOGmv
         jIzK05Qz7JJIpmOhYVqNDqjQBYmy8KHEIO1q1FOZw7ucwqFGsR1T3o9IpJdus/CPoq6n
         uA85bQjo2osqT2EXK88347+Yrbx37E0w+8mv6+3I0q8vLI9FVU6D6qpYQIxVWVgGqBb1
         RZbfnzz/IwKU8y8IMkv32z08A2I2KUuWEdhMqeTR/KpFFYafORUoy7SKBRYMSXlhf55V
         qwVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=a9O3Gu2E;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zCnkCSC+;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-43569980373si37836f8f.10.2026.01.16.03.01.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 03:01:25 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id B84C33369C;
	Fri, 16 Jan 2026 11:01:23 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8E2843EA63;
	Fri, 16 Jan 2026 11:01:23 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id EV4uIYMaamnwGQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 11:01:23 +0000
Message-ID: <bcfe8618-b547-49fb-97e8-e57c2fb4b7dd@suse.cz>
Date: Fri, 16 Jan 2026 12:01:23 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 03/20] mm/slab: make caches with sheaves mergeable
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Suren Baghdasaryan <surenb@google.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-3-98225cfb50cf@suse.cz>
 <CAJuCfpHowLbqn7ex1COBTZBchhWFy=C3sgD0Uo=J-nKX+NYBvA@mail.gmail.com>
 <4e73da60-b58d-40bd-86ed-a0243967017b@suse.cz> <aWn67WZlfnqcWX46@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aWn67WZlfnqcWX46@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -4.30
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
	FREEMAIL_CC(0.00)[google.com,suse.com,gentwo.org,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=a9O3Gu2E;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zCnkCSC+;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/16/26 09:46, Harry Yoo wrote:
> On Fri, Jan 16, 2026 at 08:24:02AM +0100, Vlastimil Babka wrote:
>> On 1/16/26 01:22, Suren Baghdasaryan wrote:
>> > On Mon, Jan 12, 2026 at 3:17=E2=80=AFPM Vlastimil Babka <vbabka@suse.c=
z> wrote:
>> >> @@ -337,6 +331,13 @@ struct kmem_cache *__kmem_cache_create_args(cons=
t char *name,
>> >>         flags &=3D ~SLAB_DEBUG_FLAGS;
>> >>  #endif
>> >>
>> >> +       /*
>> >> +        * Caches with specific capacity are special enough. It's sim=
pler to
>> >> +        * make them unmergeable.
>> >> +        */
>> >> +       if (args->sheaf_capacity)
>> >> +               flags |=3D SLAB_NO_MERGE;
>> >=20
>> > So, this is very subtle and maybe not that important but the comment
>> > for kmem_cache_args.sheaf_capacity claims "When slub_debug is enabled
>> > for the cache, the sheaf_capacity argument is ignored.". With this
>> > change this argument is not completely ignored anymore... It sets
>> > SLAB_NO_MERGE even if slub_debug is enabled, doesn't it?
>>=20
>> True, but the various debug flags set by slub_debug also prevent merging=
 so
>> it doesn't change the outcome.
>=20
> nit: except for slub_debug=3DF (SLAB_CONSISTENCY_CHECKS), since it doesn'=
t
> prevent merging (it's in SLAB_DEBUG_FLAGS but not in SLAB_NEVER_MERGE).

Hm right. But I think that's wrong then and it should be there.
SLAB_CONSISTENCY_CHECKS is enough to stop using the fastpaths (both
before/after sheaves) so it should be a reason not to merge.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
cfe8618-b547-49fb-97e8-e57c2fb4b7dd%40suse.cz.
