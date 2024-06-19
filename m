Return-Path: <kasan-dev+bncBDXYDPH3S4OBBYOWZKZQMGQE5DFB4UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 88DF590E78B
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 11:56:50 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4212e2a3a1bsf41250625e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 02:56:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718791010; cv=pass;
        d=google.com; s=arc-20160816;
        b=R8eBPJN3jKUPVpj4/dNqsiBrp5E+BaxjD7gwT6xHsEAYLoRpctwk/MeLMPWt2Av4zs
         2W9E1dtppcK8W8Dmv+lEmuz49oQ5IndJSizGF+QlhyHXYQTqpNuxvcVd+lt2yYxqWZoG
         dh6gzt1PIFdk/Akc+8qIJw/9cQFwTLQx7dtJVvMl3Yu9+cki5GMSHkRw7yC7deO4nLGv
         mjbdheefrGssFCR0WZfWbOJpnl8SuB3Esjcl/2aNIkIVrhRn13ByzTDSCAIrqYOcsfST
         c7aMTIoLUKYPi5rpKZRwLDXwT4bVmkx2fCUjOg00JTY+hcxdNHf4QiZqVvamTT996f2I
         UOig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=4WuTBaDbkNBIDo7mJ6jUMeXscHt0gDRly0WenktjPjY=;
        fh=LiF1CuPKOFC+SrvsOkN3JYNsAg8nX+Lve70ybaVTv/0=;
        b=TkVd+iER5o879zwvGW0vkF3DVrWkygCa2D0dMFqx++/MXD/S5fedevKzvUjWbvTO5P
         4Cbb8WXZcctJ4u/7ImGkab81M6HUhuTy+027oXWWX6T6W3SPvzQb2eOfolUl/Jycc+5c
         dg5aAaiIWrva9GMYi0Hc69B7WbIVkwDT7gSbDsBCiGWwCcEwsgJHCgZjFYGW13yNJ/kK
         +fqwmy+mxfnN9poFnj6VQxv/0rhqMJ+WZDQCgHNXwoHPAQ9PA95D0xHPXlc3Ov+FcpBr
         OWlwN9bqqGyWg4LSLZnuTH2j8uZYavU1cCsM0jmdZ9mpZ8DY92yBqdP57GGHt8UOn5Hw
         IlcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qofmvByi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fm026ELG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718791010; x=1719395810; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4WuTBaDbkNBIDo7mJ6jUMeXscHt0gDRly0WenktjPjY=;
        b=L70bT8W06qEmBvoqbQdvNkyezC8vGCMRTYxFykQGqtb8oyA6hhh7d40fzHW4z3TcHh
         LQkuq2rHbrRiTZRSpTu2M9WZrCWST+3e7aC38NOlJWYdLbd4C1TJ3qAtp6pcdV5URfPL
         whztvSSYE5UizfgupkSYKGaPgLZlW7jDPBSXXkW4HxOe2kmpG3chZOnMfmiSU136brlf
         ZXmTfYB2jcSBYqWIpV6d4Zm+Hb2//g16x2IKGr4IRLJO6TLLmZlgz8ja0jZUfGM2uggx
         HavCJBtAN0zA1e488qt+xe/wPdTZGh+sykxf7N54sKRydALZn+IZlnAV242DQRpC9TgX
         daMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718791010; x=1719395810;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4WuTBaDbkNBIDo7mJ6jUMeXscHt0gDRly0WenktjPjY=;
        b=IhYty/0aPsdaEosYqgVPg8opYWYAgAqTjPeJS2cZOnzK60Y5sR0PYO7xk/tTJBfLOC
         ROPRm+mMg8JkobwegBong0iRHllpxj456rfU9gGeagw2J+Av2OKktrTjidt7RCwPulWs
         9Ma2UgcurUBfotu4bp7tdhrRKIbL43j28RP+wLlSQBS0j5YeGVEUCo0/fjr8zzClXJZN
         elAgxD645ZyhLM0eoUcQjYXqX82sk5ogE/z0/zEc5G3DKYl6XqtqrWJYMdprrVaSCS1I
         lESFmezyuFg7srRE1+khvFz3xx4np1hv4FwelDGBduz042mOCMBSa7c6eQ6NBkp/Isuz
         nUgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUa0YWm9gsSo/tzcx1YTzWdn/LMPnRjESUtDrtcRrpNhKGHi9EvSuICKop84Lpuus0nETfFRmrgq8kYKxzwfpcKLXEo339Cyg==
X-Gm-Message-State: AOJu0YxKbhC/MlPI858mb+BQLELpZ3iY7po99unn2OKcgrDRN2oY1Wyr
	4F89wym/RLrsgoo2MHzOeBMgIZZ+uvADaKZvWs+/yx4jGN5Sry+Q
X-Google-Smtp-Source: AGHT+IHOiszy/+mur34LznwFtlocfPZ8GBE3hU6tcmZJZLW8inuQw71ceKNbJJ8JGvocrec+B4Hqag==
X-Received: by 2002:a05:600c:1c93:b0:423:b627:e3a5 with SMTP id 5b1f17b1804b1-4247529c2a0mr12247665e9.38.1718791009296;
        Wed, 19 Jun 2024 02:56:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d2a:b0:422:27b5:8466 with SMTP id
 5b1f17b1804b1-422b8da6e60ls26425655e9.2.-pod-prod-01-eu; Wed, 19 Jun 2024
 02:56:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHUwi7Yo2AXDvz3FVnru0B3EiecD+CZh4Q4Ex1bcyeuGTbLFxDbPGT2fASSlWAollJodEhAuZWZQUvBI2OB36DFg3PcFdogS5WfA==
X-Received: by 2002:a7b:cc13:0:b0:424:784c:b13b with SMTP id 5b1f17b1804b1-424784cb209mr6208315e9.13.1718791007442;
        Wed, 19 Jun 2024 02:56:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718791007; cv=none;
        d=google.com; s=arc-20160816;
        b=fkZ2JMt+0TZ2aqUUzuXFMTD4Bv+wcgSBLCqj3laNdEAkT0rua3L7KrH3W189bbLBkD
         FvglQs19UdLwHFhzstpZOWFeaO7WCwWrm4Z43eLsdjOct09yK8mzwo45UAfLxjXsIA5k
         F2CZjHi1AL2OKaW2HY0uLAbyYZYo6KHpUDw29feZMbqGZQydpHJSJzNojf4Y3ESeJYG/
         oImias9rA5OprZCgAE8k78VfnGuFHWPvYsh8mS30T6WM2xb4nLVT/UfivKeEjJc3XkOG
         gCgDt8KLVVN971zpoPQwykTy/S0eZNAdq+UHzRvxMd3sIY3WpeMabPr4+n1KkFnWz1WL
         OVFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=7HsdT/0BmhQCEN4xtZRZ/6IP2e/RgequrjnLXOsGUD4=;
        fh=KLcnCj0N6fB2OfAElb4gtxriq3hSAu4sYAjjlXKImFk=;
        b=kQfd3ZBQX095PjmdSNrWqxXEMIWj6a3xldMuJoFGylzynRlIy0OQIYOk/XCEip4Iwg
         QGI1E+M8NaS3fAtrOYVSq3bbXl9FIbNvQxHgALNg9LKpUhhLk/YcyBd6XCP6MiwX8QL5
         VLISaig63WjM1M+5UwXvwN90vBX2BCC86KvDZbv8Gvpgqi5c75qySxhqKlibl7vvJ5PC
         BoohwVgpt8bhwpJJUHp1lW4vRQz7+VRnoTf3LQkCXk5aJOzep8hL37o433NoxKqGLHX5
         RANWHhNiDZWaB9Uipf8SG0yhPFoyOcrP8Os9Ru/ru4mqY+GyGtB3R/cW36dvGVEO4dXx
         oGBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qofmvByi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fm026ELG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-422f2cfbb04si2275315e9.0.2024.06.19.02.56.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 02:56:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 38C1B21A68;
	Wed, 19 Jun 2024 09:56:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id EE1E013ABD;
	Wed, 19 Jun 2024 09:56:44 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id SkqIOVyrcmbCOAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 19 Jun 2024 09:56:44 +0000
Message-ID: <c208e95d-9aa9-476f-9dee-0242a2d6a24f@suse.cz>
Date: Wed, 19 Jun 2024 11:56:44 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Content-Language: en-US
To: Uladzislau Rezki <urezki@gmail.com>, "Paul E. McKenney"
 <paulmck@kernel.org>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>, Jakub Kicinski <kuba@kernel.org>,
 Julia Lawall <Julia.Lawall@inria.fr>, linux-block@vger.kernel.org,
 kernel-janitors@vger.kernel.org, bridge@lists.linux.dev,
 linux-trace-kernel@vger.kernel.org,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, kvm@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
 ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
 Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
 Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
 linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
 netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com> <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz> <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz> <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <ZnKqPqlPD3Rl04DZ@pc636>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <ZnKqPqlPD3Rl04DZ@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.50 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	FREEMAIL_TO(0.00)[gmail.com,kernel.org];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[zx2c4.com,kernel.org,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,gmail.com,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	RCVD_COUNT_TWO(0.00)[2];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns]
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Queue-Id: 38C1B21A68
X-Spam-Flag: NO
X-Spam-Score: -4.50
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qofmvByi;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=fm026ELG;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 6/19/24 11:51 AM, Uladzislau Rezki wrote:
> On Tue, Jun 18, 2024 at 09:48:49AM -0700, Paul E. McKenney wrote:
>> On Tue, Jun 18, 2024 at 11:31:00AM +0200, Uladzislau Rezki wrote:
>> > > On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
>> > > >> +
>> > > >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
>> > > >> +
>> > > >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
>> > > > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
>> > > > wanted to avoid initially.
>> > > 
>> > > I wanted to avoid new API or flags for kfree_rcu() users and this would
>> > > be achieved. The barrier is used internally so I don't consider that an
>> > > API to avoid. How difficult is the implementation is another question,
>> > > depending on how the current batching works. Once (if) we have sheaves
>> > > proven to work and move kfree_rcu() fully into SLUB, the barrier might
>> > > also look different and hopefully easier. So maybe it's not worth to
>> > > invest too much into that barrier and just go for the potentially
>> > > longer, but easier to implement?
>> > > 
>> > Right. I agree here. If the cache is not empty, OK, we just defer the
>> > work, even we can use a big 21 seconds delay, after that we just "warn"
>> > if it is still not empty and leave it as it is, i.e. emit a warning and
>> > we are done.
>> > 
>> > Destroying the cache is not something that must happen right away. 
>> 
>> OK, I have to ask...
>> 
>> Suppose that the cache is created and destroyed by a module and
>> init/cleanup time, respectively.  Suppose that this module is rmmod'ed
>> then very quickly insmod'ed.
>> 
>> Do we need to fail the insmod if the kmem_cache has not yet been fully
>> cleaned up?  If not, do we have two versions of the same kmem_cache in
>> /proc during the overlap time?
>> 
> No fail :) If same cache is created several times, its s->refcount gets
> increased, so, it does not create two entries in the "slabinfo". But i
> agree that your point is good! We need to be carefully with removing and
> simultaneous creating.

Note that this merging may be disabled or not happen due to various flags on
the cache being incompatible with it. And I want to actually make sure it
never happens for caches being already destroyed as that would lead to
use-after-free (the workfn doesn't recheck the refcount in case a merge
would happen during the grace period)

--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -150,9 +150,10 @@ int slab_unmergeable(struct kmem_cache *s)
 #endif

        /*
-        * We may have set a slab to be unmergeable during bootstrap.
+        * We may have set a cache to be unmergeable during bootstrap.
+        * 0 is for cache being destroyed asynchronously
         */
-       if (s->refcount < 0)
+       if (s->refcount <= 0)
                return 1;

        return 0;

> From the first glance, there is a refcounter and a global "slab_mutex"
> which is used to protect a critical section. Destroying is almost fully
> protected(as noted above, by a global mutex) with one exception, it is:
> 
> static void kmem_cache_release(struct kmem_cache *s)
> {
> 	if (slab_state >= FULL) {
> 		sysfs_slab_unlink(s);
> 		sysfs_slab_release(s);
> 	} else {
> 		slab_kmem_cache_release(s);
> 	}
> }
> 
> this one can race, IMO.
> 
> --
> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c208e95d-9aa9-476f-9dee-0242a2d6a24f%40suse.cz.
