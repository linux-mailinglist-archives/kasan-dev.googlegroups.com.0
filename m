Return-Path: <kasan-dev+bncBDXYDPH3S4OBBD6XYKZQMGQE7XZ4E3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CAD490BCF6
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 23:33:05 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2ebe77b877esf35456861fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 14:33:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718659984; cv=pass;
        d=google.com; s=arc-20160816;
        b=dln3Uw7xo5l4RLRqaWyAfWl630oiE6WNEmn7cfF9C+dZnaeNgWKHCIUD1I4RUZBcL3
         lNdQQFYlhdfzNrgUT39rA177gO4CFg6y17SrSf5U7jnOcoU8Y9LB7zV2SZmbdfuY/ZU4
         FHtNFRKro1ERoO4jmMrpAXfn+VfSG1Osz6H9pf0KqJ17X8rcG6rcCvy01nelRGzamOYX
         PoBAG3n2H/bNKZhFZWftOw64mph3im3j+txYSMtoBuMcylu+fD5BEbagyuOeGb/mHqbn
         uGHE5UAPzTL2Ibf4VW72yW/dp6bskXVMcb0XrqfaPZEPmAVL68myqwf0MRN7GlqlwB1F
         hRgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=4yYCKJyip6Y2iQ2S43LA538yPCqhqoW1LINb8XB9gbQ=;
        fh=dWor62f2BoPJ9LRFIzRBsrYcBoFrVTc5G7YSxKJFM9o=;
        b=klsWjI0LyCFBFBx2ChlrGgU240OiCEFw0ysLOxUVCvDc9jxmzwVx5ySN15H6ZsVtm3
         woTBeWLSYYkD3ym+3vZfTnM4djwt8y34yviV6CNOxkV3+WlsHDYH+7Kc/NjNO4qPfwY+
         W8WDkMZeoVXF/yDtX6Zn1Yx3+Zcdb0Wb35h8g4/qVaBH696r8o711kgElXKK83qQ+JXr
         jNVPOgksukknTVk3jlUCZ2HRL3QQyMEqYWMmt+y+EJpLgs1rBB5WhqP3DKFhw13lliAb
         uqb4VFmi5ugVMYpi+k38pyPe6ubI1uVet9ZSHu6Ybq0T9VSs+7gXRpDeu1TuVxjsIhS4
         Ml5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jXLkls7G;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jXLkls7G;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=awc7LiFL;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718659984; x=1719264784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4yYCKJyip6Y2iQ2S43LA538yPCqhqoW1LINb8XB9gbQ=;
        b=KFEdPoJCDkSCS7njxu5vwA3EzX7FJ28vmF6bwTHpZU/8cnkO20Pin3oIVGIc04R7lp
         Ni6G+VfYN8zyiszXjMPVvk9Liki25hXGeQktx9L7VXXw/JOmRl7vfH6VGTy4J1oQosFi
         9mhZu1WyYUTv44Ift4WEyZ5Z6ISunU7Ry1hCIIdvqDcPUfi++Y5/57ybbMu9zdpejmIo
         vGY6zZAieI1+4mwvATWQvCH3aHWV54eJXTAOWtQXt4PzBowaDBjdSbScivBQqk4+2lCp
         H59eW0a+0nVpmdEuw3rpJZr5lR8yLUcXB6G0247h9PWLosGeg2QaatnfpgTNLF9jJgD1
         Bszg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718659984; x=1719264784;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4yYCKJyip6Y2iQ2S43LA538yPCqhqoW1LINb8XB9gbQ=;
        b=G1dmzCPNDTJbgPVUcml2FkxjV10gMhpY36BxIUfcRsBIBv3eyfUiN5NNelvipwig8z
         VVt0H1FQdokCRQ8CgInEmjTb6Bg/MvRwqPa2+vevRUl3CLLz49PWFLO5zcyewtLbGAJs
         Bgjd2+B1lMRXDJjYxuTGMISfPfJUMu9ZyFqWZSdSWhmtippMUUWSKCH9e4XecoiIt92X
         Czv9ldAv5DGYUIIsWPsyC7a0O1ixKe6eAjdMiig2gLVM2l15d6DbZIL/2grgYGoCYGXJ
         1eanYyIFnNWwJkfo/gJyGJPqVQ4C8ln0Lfn34GoO4jZngs7+qnfvbsEd4NSqgelxQpIq
         4yVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJ72DH4DuuPbikQfktwRSnVGwIbNo6z/j5h2mbhRK1EyTNJ/wC6YMXQOMoaaA/fszRkAyPR8ijo7pvV4NImb3KnWkSG9VFyA==
X-Gm-Message-State: AOJu0Yyi7mPeJzuOdCgcqb5tB7apkpvsBkDB0jPbl8/SogevQojCuDJZ
	dxx6CKkw3V5/IAeryAbz55MnzKYm/ouY0PbdjDiAa8WpPH2W8u3s
X-Google-Smtp-Source: AGHT+IEs6RGOXv2CArH8XzfVI1CVX4d4GHyaoYObB1ydTGCEqpJiAYSJME7LkTe4nwVdnck8tPObeQ==
X-Received: by 2002:ac2:554e:0:b0:52c:8f01:c8a1 with SMTP id 2adb3069b0e04-52ca6e98fd6mr6082771e87.56.1718659983825;
        Mon, 17 Jun 2024 14:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:23a1:b0:52c:a26e:d9dd with SMTP id
 2adb3069b0e04-52ca26edb35ls1977180e87.2.-pod-prod-02-eu; Mon, 17 Jun 2024
 14:33:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5Y4g2CW+9VeB801MoibqpXuKrR+9yHrqgBxJt08Gi01BKqAD0gs5Wr+pxtyFkoaPMgQ/r5E6Zmod2iBKYaxec+4vQFXcHlD40eQ==
X-Received: by 2002:a19:2d5c:0:b0:52b:b8c9:9cd7 with SMTP id 2adb3069b0e04-52ca6e658e1mr5859705e87.18.1718659981671;
        Mon, 17 Jun 2024 14:33:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718659981; cv=none;
        d=google.com; s=arc-20160816;
        b=QNahBgq6vCedfxil1f3SzY8pX0wkPTt++AN/Z88yNiL/t4IWS6ZXVSYs4hPRyPubcp
         FYGRR5B3BVpLi5NUB0SZKzWAOmz2C/RL5bLAnG2drgt6bjyGGocGGty9GDOTgFu9WSJ9
         vuS1PAo5UcKU8iVq/i/OwMmVRxPBX+khl9Gkz7wmQDjRg4hJs79xyu1vVe4IMcYL3GFd
         2umEH5hPLh9owMwi7iX594GbEhpgNZZd+ZopSgAGOFAspKNuwKO52d5q8ch2Zp/Rkgio
         1fEF+s979clVeLRaVeahI+0521M2EeN8YXZjYUzAWOUi0MdwEDoaKyEqKEn69kEpQI4e
         Qh4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=6ZIkcM2Jg5cQeoR/5GuAI6KY2sxiEb8XUmVreSeq1Lk=;
        fh=R8XD0RKu/QCBR7Y+AaF2BcU5zn6ubX9y/1VGk++cA0k=;
        b=uI3RYOy9CB3eoM3LotMhMwjFtwh0nOXGthjaAQU4BzgTrIJlOsqDW+RimWv9IMsUrW
         weiw2V8DDuYWwHPU1SpVGGbk+xJ8SMLXO9LibjHsQEToaUPmonkFs9EtUnGv52rG9H3o
         WYphTrECZvE7OkeUZslWNPiqHR5W2td9H7WulSvM4IzM/xyIzt6KJVYgOH13QsJA2TIM
         TwZuydwWvDhWTpdaqV9swkJgXjaXLTEuLQdYPicG28JKoncLIs+A1s+cKxw/5/mo69DD
         OrxbaWjXfvgMQxG+MMfowkYdri01vj0enkFlW/kDFCUPz6BPUXT9fKdzEdg3v6YAqkRD
         toZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jXLkls7G;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jXLkls7G;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=awc7LiFL;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52ca282f0f1si198370e87.5.2024.06.17.14.33.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Jun 2024 14:33:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 8F3A11F747;
	Mon, 17 Jun 2024 21:33:00 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 428F813AAA;
	Mon, 17 Jun 2024 21:33:00 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id BpV7D4yrcGbuUQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 17 Jun 2024 21:33:00 +0000
Message-ID: <e7cbca4d-9b34-46f8-961a-9f8ddc92be21@suse.cz>
Date: Mon, 17 Jun 2024 23:34:04 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
To: paulmck@kernel.org
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>,
 Jakub Kicinski <kuba@kernel.org>, Julia Lawall <Julia.Lawall@inria.fr>,
 linux-block@vger.kernel.org, kernel-janitors@vger.kernel.org,
 bridge@lists.linux.dev, linux-trace-kernel@vger.kernel.org,
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
References: <20240609082726.32742-1-Julia.Lawall@inria.fr>
 <20240612143305.451abf58@kernel.org>
 <baee4d58-17b4-4918-8e45-4d8068a23e8c@paulmck-laptop>
 <Zmov7ZaL-54T9GiM@zx2c4.com> <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com> <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <1755282b-e3f5-4d18-9eab-fc6a29ca5886@paulmck-laptop>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <1755282b-e3f5-4d18-9eab-fc6a29ca5886@paulmck-laptop>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.50 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	RCVD_TLS_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	MIME_TRACE(0.00)[0:+];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[zx2c4.com,gmail.com,kernel.org,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Queue-Id: 8F3A11F747
X-Spam-Flag: NO
X-Spam-Score: -4.50
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jXLkls7G;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jXLkls7G;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=awc7LiFL;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 6/17/24 8:54 PM, Paul E. McKenney wrote:
> On Mon, Jun 17, 2024 at 07:23:36PM +0200, Vlastimil Babka wrote:
>> On 6/17/24 6:12 PM, Paul E. McKenney wrote:
>>> On Mon, Jun 17, 2024 at 05:10:50PM +0200, Vlastimil Babka wrote:
>>>> On 6/13/24 2:22 PM, Jason A. Donenfeld wrote:
>>>>> On Wed, Jun 12, 2024 at 08:38:02PM -0700, Paul E. McKenney wrote:
>>>>>> o	Make the current kmem_cache_destroy() asynchronously wait for
>>>>>> 	all memory to be returned, then complete the destruction.
>>>>>> 	(This gets rid of a valuable debugging technique because
>>>>>> 	in normal use, it is a bug to attempt to destroy a kmem_cache
>>>>>> 	that has objects still allocated.)
>>>>
>>>> This seems like the best option to me. As Jason already said, the debugging
>>>> technique is not affected significantly, if the warning just occurs
>>>> asynchronously later. The module can be already unloaded at that point, as
>>>> the leak is never checked programatically anyway to control further
>>>> execution, it's just a splat in dmesg.
>>>
>>> Works for me!
>>
>> Great. So this is how a prototype could look like, hopefully? The kunit test
>> does generate the splat for me, which should be because the rcu_barrier() in
>> the implementation (marked to be replaced with the real thing) is really
>> insufficient. Note the test itself passes as this kind of error isn't wired
>> up properly.
> 
> ;-) ;-) ;-)

Yeah yeah, I just used the kunit module as a convenient way add the code
that should see if there's the splat :)

> Some might want confirmation that their cleanup efforts succeeded,
> but if so, I will let them make that known.

It could be just the kunit test that could want that, but I don't see
how it could wrap and inspect the result of the async handling and
suppress the splats for intentionally triggered errors as many of the
other tests do.

>> Another thing to resolve is the marked comment about kasan_shutdown() with
>> potential kfree_rcu()'s in flight.
> 
> Could that simply move to the worker function?  (Hey, had to ask!)

I think I had a reason why not, but I guess it could move. It would just
mean that if any objects are quarantined, we'll go for the async freeing
even though those could be flushed immediately. Guess that's not too bad.

>> Also you need CONFIG_SLUB_DEBUG enabled otherwise node_nr_slabs() is a no-op
>> and it might fail to notice the pending slabs. This will need to change.
> 
> Agreed.
> 
> Looks generally good.  A few questions below, to be taken with a
> grain of salt.

Thanks!

>> +static void kmem_cache_kfree_rcu_destroy_workfn(struct work_struct *work)
>> +{
>> +	struct kmem_cache *s;
>> +	int err = -EBUSY;
>> +	bool rcu_set;
>> +
>> +	s = container_of(work, struct kmem_cache, async_destroy_work);
>> +
>> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
>> +	rcu_barrier();

Note here's the barrier.

>> +	cpus_read_lock();
>> +	mutex_lock(&slab_mutex);
>> +
>> +	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
>> +
>> +	err = shutdown_cache(s, true);
> 
> This is currently the only call to shutdown_cache()?  So there is to be
> a way for the caller to have some influence over the value of that bool?

Not the only caller, there's still the initial attempt in
kmem_cache_destroy() itself below.

> 
>> +	WARN(err, "kmem_cache_destroy %s: Slab cache still has objects",
>> +	     s->name);
> 
> Don't we want to have some sort of delay here?  Or is this the
> 21-second delay and/or kfree_rcu_barrier() mentioned before?

Yes this is after the barrier. The first immediate attempt to shutdown
doesn't warn.

>> +	mutex_unlock(&slab_mutex);
>> +	cpus_read_unlock();
>> +	if (!err && !rcu_set)
>> +		kmem_cache_release(s);
>> +}
>> +
>>  void kmem_cache_destroy(struct kmem_cache *s)
>>  {
>>  	int err = -EBUSY;
>> @@ -494,9 +527,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
>>  	if (s->refcount)
>>  		goto out_unlock;
>>  
>> -	err = shutdown_cache(s);
>> -	WARN(err, "%s %s: Slab cache still has objects when called from %pS",
>> -	     __func__, s->name, (void *)_RET_IP_);
>> +	err = shutdown_cache(s, false);
>> +	if (err)
>> +		schedule_work(&s->async_destroy_work);

And here's the initial attempt that used to warn but now doesn't and
instead schedules the async one.

>>  out_unlock:
>>  	mutex_unlock(&slab_mutex);
>>  	cpus_read_unlock();
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 1617d8014ecd..4d435b3d2b5f 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -5342,7 +5342,8 @@ static void list_slab_objects(struct kmem_cache *s, struct slab *slab,
>>   * This is called from __kmem_cache_shutdown(). We must take list_lock
>>   * because sysfs file might still access partial list after the shutdowning.
>>   */
>> -static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n)
>> +static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n,
>> +			 bool warn_inuse)
>>  {
>>  	LIST_HEAD(discard);
>>  	struct slab *slab, *h;
>> @@ -5353,7 +5354,7 @@ static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n)
>>  		if (!slab->inuse) {
>>  			remove_partial(n, slab);
>>  			list_add(&slab->slab_list, &discard);
>> -		} else {
>> +		} else if (warn_inuse) {
>>  			list_slab_objects(s, slab,
>>  			  "Objects remaining in %s on __kmem_cache_shutdown()");
>>  		}
>> @@ -5378,7 +5379,7 @@ bool __kmem_cache_empty(struct kmem_cache *s)
>>  /*
>>   * Release all resources used by a slab cache.
>>   */
>> -int __kmem_cache_shutdown(struct kmem_cache *s)
>> +int __kmem_cache_shutdown(struct kmem_cache *s, bool warn_inuse)
>>  {
>>  	int node;
>>  	struct kmem_cache_node *n;
>> @@ -5386,7 +5387,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
>>  	flush_all_cpus_locked(s);
>>  	/* Attempt to free all objects */
>>  	for_each_kmem_cache_node(s, node, n) {
>> -		free_partial(s, n);
>> +		free_partial(s, n, warn_inuse);
>>  		if (n->nr_partial || node_nr_slabs(n))
>>  			return 1;
>>  	}
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e7cbca4d-9b34-46f8-961a-9f8ddc92be21%40suse.cz.
