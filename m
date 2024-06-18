Return-Path: <kasan-dev+bncBDXYDPH3S4OBBKUEY6ZQMGQE3PPCAPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9698D90DA71
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 19:21:47 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2ebfa13d277sf47142751fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 10:21:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718731307; cv=pass;
        d=google.com; s=arc-20160816;
        b=A1g2B3wOMZ7OOnasBNw5iNTaUHiICDxIL5/TUIZ8zH6DBi8atYcMQ2MaGkNUef+Tds
         BycgZoC2p5PtOy6mLyGDyUwl+IC8zLJ9wxaQBs1v+GAUetUEMu7HUdQiHZL49SCOQcbl
         GLMCk0HpeyXYS+HJDZK9xGnW9q82JBMCtd4FfohIHZYnCEN5fuAk/aFKBAmw/40QqNMl
         z3IFVt8vfBtAIy9qZMaJPVtGsiVGpzonad3zAdQ/7f5xK9GrQEk2nVQmaijy+9Lvf9iM
         6BEVVKUkY3poyrptursQMzZeya91JOr+V7zgzQxKftu92SchZvrtnsYxAoBLoizdHnDN
         /orw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=G2Gr+qMaOhkD054g3l3T2/TLAPBjbGRcAU6zMe4rhPo=;
        fh=+fNHKqJUW4r9XpLnK+a2rfh34P9icVck+y6ZB/3Nbso=;
        b=Chz0hoFS8jnyynFitNzqo1Xp6hGe99PC4ZLxfNvMZ3IbaYWSQhq7h0q4aEKDi+WCMG
         quiD+4KEGxbJjAkVevPriZKFGqGcLs1V22nCFtdHlzN/Mmu9VXuMod2LndKkgLXDAreO
         GTV48RsOQ7ZYE5lwUXwmgGIQszlmC2yVhUSc4MvGQOFBk7JkQnRoyU+nftKoHsskGOHp
         ziNES1K81KtkQz4QmJYIuJOVXw/DbOKaE7ik34JoBVo2fqk/qAVkId7YtIN7dAI77dbY
         7q0aKlZvU2Bkq6mrzOZ4sKKFcB1gD8Izw4msRL0w+j1bPyMd13/ndgyithfH6AZWbkFz
         JArQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=C4DDrVjt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=J6gZIZw7;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=C4DDrVjt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=J6gZIZw7;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718731307; x=1719336107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=G2Gr+qMaOhkD054g3l3T2/TLAPBjbGRcAU6zMe4rhPo=;
        b=bylhxyQCHoD8xPa0xO7Yp67cEGI+PFWcf1vHwvH4taA/NFP4YfPU1GG6ag+DVmtcH7
         2hckStkcxmFn+jvU70np9KE8qm0BHt4gL4K2ld9RFziPcYJ49VG6L05MJij+WfzI69wu
         /C+ajStnFA3d+MKOQloZGwnQz7UI7hB4laUCl2LgLDIKw/XNBrwN19pbijwlrOGPwIss
         1OPXRVXbkEo4S+7S1LDvAmKQIQxe2KvSzLLx3ynGgXEfM7RBb07U9zvKYjCfOIlZfxXu
         kQTdNhoD0v+6jeFiZxYB4hVmlMz42KLHO7KOyFp4Q9n4sZOdNHdArmG5U66ugouAQCJj
         umdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718731307; x=1719336107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G2Gr+qMaOhkD054g3l3T2/TLAPBjbGRcAU6zMe4rhPo=;
        b=gQ1wf5Uws1ji5mK2w70fPtXOkAGYm3I5DCJ0tzhxtvItYtv8QgUQzXN9HR5Kvochjp
         iOrSCy8cRe7ADHOwUgwLAHl1WiDHP3JTRhLE/G0g7ffaS3CFRh2+8MYlAHQrcbh6Ur+n
         shKO3OoLweNG241EFPTfg7Nq2t9taTxt385c/GmNn52h6gArOgbXz7pXvjjh+Rk3bsmB
         tGVm8ze/5p0H7cgvSAQrKTDi3sE82Sg73gI13QmIVXLgi9wIXK7ZNaVkIc77BYDZmuai
         i7skfGyf13bv/Q/eIKJsf6r34kNx5xhhoWE5u3x/CQOJtF5jSZ49Rml/gCKaK4ETBrHS
         /9Dw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVRN9bge9vemPRwdfSKwEDefIHmUjTKrqsvtjN9T7eJFX70PLNMgk2aBuFGwZhm2AF0Oa0k8kbQynY+7SeXewveEl8/o2SXaQ==
X-Gm-Message-State: AOJu0YwDsSYiXQ4uSJiW2EXqTWzSdVpJvkzwzs5yRg60XTsxx8gJIky7
	jSUmn8SGrXlYe74upnQoiXABJkXx3Fx2WAmbT/61cjdyNl9JAeqq
X-Google-Smtp-Source: AGHT+IH7+20VwgBe34/K4dAdo4YHGd3b+rn8/J7PT/iF0GgQXJO3/BcxdG0pMXMHsRhOojefcuZOhQ==
X-Received: by 2002:a2e:86c8:0:b0:2ec:5e6:1c7b with SMTP id 38308e7fff4ca-2ec3cee1312mr3293011fa.34.1718731306393;
        Tue, 18 Jun 2024 10:21:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9983:0:b0:2ec:38f:e74a with SMTP id 38308e7fff4ca-2ec038fe82bls27007151fa.2.-pod-prod-08-eu;
 Tue, 18 Jun 2024 10:21:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5m2XfBepsVqd98slviUYHf7TOuTZjLhK07JqOhb0R2xQ5lqz8bF5HcnC2zlEnzKBx3i8lEFlf5U+GqrkhJXXFEG46etJ98KCmlQ==
X-Received: by 2002:a2e:b0db:0:b0:2ea:e4c1:9f0b with SMTP id 38308e7fff4ca-2ec3cee1233mr3201321fa.41.1718731304096;
        Tue, 18 Jun 2024 10:21:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718731304; cv=none;
        d=google.com; s=arc-20160816;
        b=MUGnfcEgzLkxCzc/inygrYTXWguBZmszC3yRi0Fh9RN9YYss0r6BJ4kS+wIzCTrwTD
         G0AsBz76HRr4qXkObx9XDpHRsnSQzlAezGj6+Q8PWrVctB93YesrCc5BWcmfOD031M89
         70obWdWh2WxfNxuUU9lPRbnb14/t/gWzDEYJ39eLYpEJn+dAn5AF/8JldHQPDDHxwaih
         Gbsepa1HcgQAWIAhjd/8TA4BUMY7uCwaIm/VwuevldQg73f5HlpOmzey0s0VFcB+7CNO
         95FXy5nwLyHabSR2R0uX/4XMQ+lLqHipPnAOzWCOPhTl3kUY11HmRHrTePzE+tp5Uuh8
         hZhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=J1+5aJgyw3CtZTFBGmIikSQ36Vr1CyzpzCCXc9BE0+0=;
        fh=LiMIpkjLoUx/gZ01DfD6sxp6PmPKizrYLwSKnawebHA=;
        b=BxCnzTwO3d9Bb3A8wIobq+5LbdPoNiiW6rWBWsZNidoG+COCGTHqRaEnjm2RyKAD/w
         rPC/0+0j95B1GsfEl+WeDv9SYxjd+B2M5EH6Lk3/kvR19GxrM2qZgNwx1YjUX8FqUtQ4
         GuEXf9/yuHizok091IdUF//MoyW+CAvzH8y+sJve6mY9uNsOeWbe4EDpSpmueS4Y8Ysw
         5jfx0167R7jT1+MpGYLY5TbnsTZsuG2OlxOi6boTRHErZhu8QswGpY1aGIi/2mDTBuhD
         uAQKIIFj2XUa0IaHgEdezqibZjEQOyAthKokCSMpmOnSbqGwaHMOqr76Up20DoAY0A9j
         fiIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=C4DDrVjt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=J6gZIZw7;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=C4DDrVjt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=J6gZIZw7;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4247105d8b1si985485e9.0.2024.06.18.10.21.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Jun 2024 10:21:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 518681F793;
	Tue, 18 Jun 2024 17:21:43 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0CA2A1369F;
	Tue, 18 Jun 2024 17:21:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id +OGHAifCcWbRKwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 18 Jun 2024 17:21:43 +0000
Message-ID: <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
Date: Tue, 18 Jun 2024 19:21:42 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Content-Language: en-US
To: paulmck@kernel.org, Uladzislau Rezki <urezki@gmail.com>
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
References: <Zmov7ZaL-54T9GiM@zx2c4.com> <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com> <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz> <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz> <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -8.29
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Result: default: False [-8.29 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[kernel.org,gmail.com];
	RCPT_COUNT_TWELVE(0.00)[29];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[zx2c4.com,kernel.org,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,gmail.com,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=C4DDrVjt;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=J6gZIZw7;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=C4DDrVjt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=J6gZIZw7;       spf=pass (google.com: domain of vbabka@suse.cz
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

On 6/18/24 6:48 PM, Paul E. McKenney wrote:
> On Tue, Jun 18, 2024 at 11:31:00AM +0200, Uladzislau Rezki wrote:
>> > On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
>> > >> +
>> > >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
>> > >> +
>> > >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
>> > > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
>> > > wanted to avoid initially.
>> > 
>> > I wanted to avoid new API or flags for kfree_rcu() users and this would
>> > be achieved. The barrier is used internally so I don't consider that an
>> > API to avoid. How difficult is the implementation is another question,
>> > depending on how the current batching works. Once (if) we have sheaves
>> > proven to work and move kfree_rcu() fully into SLUB, the barrier might
>> > also look different and hopefully easier. So maybe it's not worth to
>> > invest too much into that barrier and just go for the potentially
>> > longer, but easier to implement?
>> > 
>> Right. I agree here. If the cache is not empty, OK, we just defer the
>> work, even we can use a big 21 seconds delay, after that we just "warn"
>> if it is still not empty and leave it as it is, i.e. emit a warning and
>> we are done.
>> 
>> Destroying the cache is not something that must happen right away. 
> 
> OK, I have to ask...
> 
> Suppose that the cache is created and destroyed by a module and
> init/cleanup time, respectively.  Suppose that this module is rmmod'ed
> then very quickly insmod'ed.
> 
> Do we need to fail the insmod if the kmem_cache has not yet been fully
> cleaned up?

We don't have any such link between kmem_cache and module to detect that, so
we would have to start tracking that. Probably not worth the trouble.

>  If not, do we have two versions of the same kmem_cache in
> /proc during the overlap time?

Hm could happen in /proc/slabinfo but without being harmful other than
perhaps confusing someone. We could filter out the caches being destroyed
trivially.

Sysfs and debugfs might be more problematic as I suppose directory names
would clash. I'll have to check... might be even happening now when we do
detect leaked objects and just leave the cache around... thanks for the
question.

> 							Thanx, Paul
> 
>> > > Since you do it asynchronous can we just repeat
>> > > and wait until it a cache is furry freed?
>> > 
>> > The problem is we want to detect the cases when it's not fully freed
>> > because there was an actual read. So at some point we'd need to stop the
>> > repeats because we know there can no longer be any kfree_rcu()'s in
>> > flight since the kmem_cache_destroy() was called.
>> > 
>> Agree. As noted above, we can go with 21 seconds(as an example) interval
>> and just perform destroy(without repeating).
>> 
>> --
>> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9967fdfa-e649-456d-a0cb-b4c4bf7f9d68%40suse.cz.
