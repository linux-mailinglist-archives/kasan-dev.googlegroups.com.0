Return-Path: <kasan-dev+bncBDXYDPH3S4OBBMGJZKZQMGQEERU4LNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id DF87390E6FC
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 11:28:17 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-363740a6f5fsf229255f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 02:28:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718789297; cv=pass;
        d=google.com; s=arc-20160816;
        b=mPoti2x+L40mQpaOi7lomWTGGuuccw7gHMIOEjR8FaLL+tx538V0U/LxCsUPw2Kq0L
         CpJaoi+xaSi+YdbXD1Iud1XHRyzU25c0s8R8mcIrLXaovjUC68Q+5OgvrK3rWg1zZkKV
         Qm/Hye/8DdRg3U9UaogsAJuX1Tvu2TyIE5KNbYdPpJ6uJScNzJDJnZ6/YO6X1mJ4I16R
         t0qqW0hkFSEqlAilABjJqLSnyu23cE3iMDsBFauWXjgE3IFuWacksdiZRkZ40nEyRIW+
         dna8ARBYNsIyinkkvP/05+7xAuuvn88i+waW/g4QkDQwOG+Yo4ydtrxpbFCFYCaLIjQj
         IFqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=Sh6G48GlvqXhSEmre4hrtXZjZp01n+Xz4Lr48Ch1ano=;
        fh=fSknZwepZZQs0f0gnnCKjPLdnO6G30EQmwP6yJYoHOI=;
        b=aG4OpChZs62UxkrVnwO8MIl9pHH5RW+8S6tQzVKQosAPTX7VsclwMZV6HGs1AlpD6h
         j85rump/S0Ea7fcRk3KzNRF7zA/JKUGI+m2AsLm4aynfNjg3hSZQp8WKzaXlvASd+hg/
         mzx9HsfxWiIZUANrln3Vwrhurb1OkJx4pHTsO/RSFJdb2TrqTURUKgWNOFw1yh4cYeJE
         Yc/TLIWnEciVTcTu80ESfxAiZMAItQ17w9j3JrOultMlbPtkwzeTPkLdM+LD5gluGZ2q
         zSRlChQ1fSSoK31r5LCOlYoMmtgF9LldnU4fngPiI2L+EnHF2nJKoV4MkgNIS/C8E+av
         4HyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="KlCQojr/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=k0SWOEYe;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="KlCQojr/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718789297; x=1719394097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Sh6G48GlvqXhSEmre4hrtXZjZp01n+Xz4Lr48Ch1ano=;
        b=jnKr1FbBGAOgrutEy+yK8ZG1KZdFvizW7e4Yff7ZRCi1lEUF5LJHcReLs7UySQDzDy
         k1dWncdyHfnSM08mq/gCWCRlZAGcGvOYugnrCtJHhXkl4VyH0ZKx8OhLH1F0AXeHGxuE
         ElOPBa5+N+kIwH3ADufrYOSmXy3zFYRzunmB4KwYLaHL374qMqpjMvb5jnHV8v4YJvTT
         FtfdgLiXv4agF8KgioyKQhwFed8pfFBoRkj2Vi5aAj+TxE/DLHEltkHbPAew9LSATjhK
         tRn00INUqsIYXbRoXieU6jDQLezUfeI1J5vyKy/OLDmM0VbeupoJZgCVG/pufv5i9SfI
         xZ2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718789297; x=1719394097;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Sh6G48GlvqXhSEmre4hrtXZjZp01n+Xz4Lr48Ch1ano=;
        b=K1Lhx96CZMyHJR7CeXlAOysQFJlzuFTGTlyVFzPME99SfazGcJ0h5E1w/OvVs9T2ia
         icfWa5/D/HYVJnxwDGWFbaRvoHhwVknogiBXMb6qFk7dJ2QL1NqVGsDIU52IvRT0PRbf
         FUq/az2krJTdNw/lFeTrnt8E4X+LqGWY182ZyqmiUKFm25dyS78iMFqdL/h4NrPppLVJ
         GrNL5jgCNcNsio2zd4psIpuMnxijc5h030FOYJ7hvqcR3DXDsCiVvsIBln9XNmo7eh7b
         1on4HXEcgOYjD3GoL80K6JbAXII6TOkqOo6f6PeOnhv8nIZd5ng45G+XxuDPuD3Vpkdp
         Djsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWDBRnXmh0fxn7Ft+hRq3offWRzi3vfycO0LNyHAl4h4jIUx+2HhV88zkUWVUMdyEqV2ewJUq04Ahpbq0Tef8GutoA+h8hIRQ==
X-Gm-Message-State: AOJu0YytLQemllWLNGk85mYg8Mc99txVVNiujbRrwHrRLNQvXNZiZNR3
	vkgLHZ0ALShVVz5altqpzahsKh4otPUZP4dIFOr4o9kVkW6dbKxu
X-Google-Smtp-Source: AGHT+IFHRPtMxXb7O+OJt8yaaTfiZigl1Y8Ps6ySPRLDmTHuyJIAyfh84pj9z9k2T6heqcDgRmPslA==
X-Received: by 2002:adf:f6c5:0:b0:362:1b1:bdea with SMTP id ffacd0b85a97d-363170ece24mr1380758f8f.8.1718789296938;
        Wed, 19 Jun 2024 02:28:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4307:0:b0:360:9396:6c7f with SMTP id ffacd0b85a97d-36093966dd0ls1221428f8f.1.-pod-prod-06-eu;
 Wed, 19 Jun 2024 02:28:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQL2I2/w55cPyHpnv7DaKKOwXXskWPHSxbdSaiK7A74EE9hlbgk2O4qkQMi+ghwBKptF0Na1eLtbUi10TUSteldKkTRLjLi+MGEA==
X-Received: by 2002:a05:600c:5c4:b0:421:5ada:c137 with SMTP id 5b1f17b1804b1-4247529b439mr13771755e9.33.1718789294420;
        Wed, 19 Jun 2024 02:28:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718789294; cv=none;
        d=google.com; s=arc-20160816;
        b=b2v+r+u5kRIBqy9zfunzH3fhFUNtUmee7SqxckiZ2uCqpyzl+kimNUkYm20ejQbLsF
         DnefW9idi27lLCSPPZLKffYvPBlTeN/Tj2bhoicyN6IWobK9/9i4rkmIj8PWcI8bwRsg
         6YmtDRXdxjgXQLM7sHbESy2q00fiffI6sS/NwUbURsjtEmSAXy08WUKpTlfxDwPZdck/
         MiXt6fx9pY2i/oN3QiWHwN/5+6jqMVdEAWZe9dCTaO8JrF+aqb8pXzh3rzVes2B1FSif
         HW15r0CKYJ8q9jOOCakOqm7Ssp9zNWNOHhdEE/ypCBus3Sch3A4zkh9JeGanaogiU0b7
         ieSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=SLViRhlaF4oe5G++zEWyGT7PD7g10KVXrdRFRTAE8RU=;
        fh=Az/L4DZ7Gk9UJi0OGNsqGxnJTnMNLUog1TSRzF8qb7o=;
        b=N+fMDqKcpXVzXs6vUruITb/xwA9bR5zJuUqmOE9VrbC7e+8fnkwWBtAjPHULJDPyu8
         eik1Jhtby7v4Av4HvG/uwHOddiOL9MPIR3LAq2po/t6NXWjwNAMMoqU600bpK29ouKdk
         8ZQPjc+mSSs4g/5AHWXi28oiKxB83ADgAVt6uNHQBfItwwWQqpxkJQNbHn2jKweBB1ne
         nvoY/eCKd+9OLjuZ3ytpYNDtQxUIlqkOOaZRvgm6dpkvrPD43JZ4cD93LVjr2RwXWE/o
         GASy2iEPjX7z2I6TiGtxYMWdms96VvlXAW6D3SYunMpbWLHv8cSf48toPzuTdvxwWHX8
         HLbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="KlCQojr/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=k0SWOEYe;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="KlCQojr/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42471e66007si2203895e9.1.2024.06.19.02.28.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 02:28:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B8D7D1F787;
	Wed, 19 Jun 2024 09:28:13 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 81A4713ABD;
	Wed, 19 Jun 2024 09:28:13 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id zJ9OH62kcmagLwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 19 Jun 2024 09:28:13 +0000
Message-ID: <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz>
Date: Wed, 19 Jun 2024 11:28:13 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Content-Language: en-US
To: paulmck@kernel.org
Cc: Uladzislau Rezki <urezki@gmail.com>, "Jason A. Donenfeld"
 <Jason@zx2c4.com>, Jakub Kicinski <kuba@kernel.org>,
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
References: <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com> <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz> <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz> <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
 <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.29 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[gmail.com,zx2c4.com,kernel.org,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.29
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="KlCQojr/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=k0SWOEYe;       dkim=pass header.i=@suse.cz header.s=susede2_rsa
 header.b="KlCQojr/";       dkim=neutral (no key) header.i=@suse.cz
 header.s=susede2_ed25519;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 6/18/24 7:53 PM, Paul E. McKenney wrote:
> On Tue, Jun 18, 2024 at 07:21:42PM +0200, Vlastimil Babka wrote:
>> On 6/18/24 6:48 PM, Paul E. McKenney wrote:
>> > On Tue, Jun 18, 2024 at 11:31:00AM +0200, Uladzislau Rezki wrote:
>> >> > On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
>> >> > >> +
>> >> > >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
>> >> > >> +
>> >> > >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
>> >> > > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
>> >> > > wanted to avoid initially.
>> >> > 
>> >> > I wanted to avoid new API or flags for kfree_rcu() users and this would
>> >> > be achieved. The barrier is used internally so I don't consider that an
>> >> > API to avoid. How difficult is the implementation is another question,
>> >> > depending on how the current batching works. Once (if) we have sheaves
>> >> > proven to work and move kfree_rcu() fully into SLUB, the barrier might
>> >> > also look different and hopefully easier. So maybe it's not worth to
>> >> > invest too much into that barrier and just go for the potentially
>> >> > longer, but easier to implement?
>> >> > 
>> >> Right. I agree here. If the cache is not empty, OK, we just defer the
>> >> work, even we can use a big 21 seconds delay, after that we just "warn"
>> >> if it is still not empty and leave it as it is, i.e. emit a warning and
>> >> we are done.
>> >> 
>> >> Destroying the cache is not something that must happen right away. 
>> > 
>> > OK, I have to ask...
>> > 
>> > Suppose that the cache is created and destroyed by a module and
>> > init/cleanup time, respectively.  Suppose that this module is rmmod'ed
>> > then very quickly insmod'ed.
>> > 
>> > Do we need to fail the insmod if the kmem_cache has not yet been fully
>> > cleaned up?
>> 
>> We don't have any such link between kmem_cache and module to detect that, so
>> we would have to start tracking that. Probably not worth the trouble.
> 
> Fair enough!
> 
>> >  If not, do we have two versions of the same kmem_cache in
>> > /proc during the overlap time?
>> 
>> Hm could happen in /proc/slabinfo but without being harmful other than
>> perhaps confusing someone. We could filter out the caches being destroyed
>> trivially.
> 
> Or mark them in /proc/slabinfo?  Yet another column, yay!!!  Or script
> breakage from flagging the name somehow, for example, trailing "/"
> character.

Yeah I've been resisting such changes to the layout and this wouldn't be
worth it, apart from changing the name itself but not in a dangerous way
like with "/" :)

>> Sysfs and debugfs might be more problematic as I suppose directory names
>> would clash. I'll have to check... might be even happening now when we do
>> detect leaked objects and just leave the cache around... thanks for the
>> question.
> 
> "It is a service that I provide."  ;-)
> 
> But yes, we might be living with it already and there might already
> be ways people deal with it.

So it seems if the sysfs/debugfs directories already exist, they will
silently not be created. Wonder if we have such cases today already because
caches with same name exist. I think we do with the zsmalloc using 32 caches
with same name that we discussed elsewhere just recently.

Also indeed if the cache has leaked objects and won't be thus destroyed,
these directories indeed stay around, as well as the slabinfo entry, and can
prevent new ones from being created (slabinfo lines with same name are not
prevented).

But it wouldn't be great to introduce this possibility to happen for the
temporarily delayed removal due to kfree_rcu() and a module re-insert, since
that's a legitimate case and not buggy state due to leaks.

The debugfs directory we could remove immediately before handing over to the
scheduled workfn, but if it turns out there was a leak and the workfn leaves
the cache around, debugfs dir will be gone and we can't check the
alloc_traces/free_traces files there (but we have the per-object info
including the traces in the dmesg splat).

The sysfs directory is currently removed only with the whole cache being
destryed due to sysfs/kobject lifetime model. I'd love to untangle it for
other reasons too, but haven't investigated it yet. But again it might be
useful for sysfs dir to stay around for inspection, as for the debugfs.

We could rename the sysfs/debugfs directories before queuing the work? Add
some prefix like GOING_AWAY-$name. If leak is detected and cache stays
forever, another rename to LEAKED-$name. (and same for the slabinfo). But
multiple ones with same name might pile up, so try adding a counter then?
Probably messy to implement, but perhaps the most robust in the end? The
automatic counter could also solve the general case of people using same
name for multiple caches.

Other ideas?

Thanks,
Vlastimil

> 
> 							Thanx, Paul
> 
>> >> > > Since you do it asynchronous can we just repeat
>> >> > > and wait until it a cache is furry freed?
>> >> > 
>> >> > The problem is we want to detect the cases when it's not fully freed
>> >> > because there was an actual read. So at some point we'd need to stop the
>> >> > repeats because we know there can no longer be any kfree_rcu()'s in
>> >> > flight since the kmem_cache_destroy() was called.
>> >> > 
>> >> Agree. As noted above, we can go with 21 seconds(as an example) interval
>> >> and just perform destroy(without repeating).
>> >> 
>> >> --
>> >> Uladzislau Rezki
>> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4cba4a48-902b-4fb6-895c-c8e6b64e0d5f%40suse.cz.
