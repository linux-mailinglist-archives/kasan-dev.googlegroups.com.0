Return-Path: <kasan-dev+bncBAABBU4F4SPQMGQE7AB3YRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DD8C26A218A
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 19:32:52 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id b1-20020a196701000000b004d5aee356dcsf35720lfc.5
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 10:32:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677263572; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rf46rCh83cno1Hd54W/CIEcwFESjMEmh6r6JCFrih3jRgqOTsHZSDCnDRSb3UoWFlC
         UE+uSutxpQswoyoPXT7TxQkuOv1lZc+n+pN2iD6NFKmaP60mkMdCOKRC+5hGDKieQgja
         5NYdSOgw2zsEmQD0XejPO8Pv0IzSvWqjSC3AxYHLc1eptGuLAGg6jSVf7RFYbL0x3lGJ
         sQiFk8iGS5qgw4sw/BrvI/XRJ3Cv4WTTBDzjKTlnwAIuPEA2MUkYNfAQ1L+6q60iFoW7
         3iuaCERSubalMqEIWTmnLvScRKW+Eutvwnf8c+SJjQaiZfEQK7WJzu9xMVUq4Cd87bgy
         km/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=XrZ8MkMzkhRagp2WQESWmcZ0c0R+MoXq1KZdZ7phSzo=;
        b=jQ48O3PmT5uEcF5PGKcenel/8TRKGxE5C2zne6hbW7f3GNN+CYoJwP68PSgnjguT3O
         nFdxzkSYejYECAu4MXOUwJnuEApREXDSa+r/qVYoFefMo8910s3P2arodicXjHikz2vI
         0dGLr0KtPf4X3IBiiOoGIQNFv3MuR6XXpST7dexzvIOqZvG/bhX6LFG/Fei/0YwhuLoN
         uSmNCkY8MMmw+LlJElQfzOaBBft9EH2plT91eWFdahV8l5O5tYCNwm3lFIGs3Zi6petT
         xYNfAFobuEGW3yHuP1ydwI9g48vSl0q0RhV/e731o/8ndE1NjYaxvQPQAJq4nMFYvrGE
         ca4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=RwI0RqcN;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=4CqLLgv8;
       spf=pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=krisman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XrZ8MkMzkhRagp2WQESWmcZ0c0R+MoXq1KZdZ7phSzo=;
        b=BX9pxWVC977ImfX188CXToPM77zj3+hu9A5QkY5aP1Wk/D4BxyXe0xK/alvYT2qsEm
         jBgjHnjLLXITwRP1q5WICl8/sRFWKyEi+r+GwF/yiA2zuaeeo7JJ1Fenbh+ChgpZ6rx1
         VRZV33jzKadSX6SzBuVkfaPZqKGyHUkXhXhY7imvxlFLHqFgWX/rxYiwjUSQFM/g/NzN
         hkQei2GoR5wsTEjAYnYCGbxqLB2Louq90ZPhi1RLp/XKck8E4LYaOerpV5VeOjIToPbP
         amHDyE+owpn3pgONsdBknHUvESWCT+BuFZL0R60fS9W822KVL0Q3Gd8bWPX4K8Tx4ukF
         /Lxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XrZ8MkMzkhRagp2WQESWmcZ0c0R+MoXq1KZdZ7phSzo=;
        b=hhDR4VEiBqUWUdVzZXmnWVuyrmjggx8Z6ZiAMvzPt82S5lIgk4DOvaPODsmqvnJb1S
         1j/IuC6mk+6HdA9NWyolmfjGeK2wCju6f/q3TRl5nRsR1YMZS0s3Wl7vtSDgNQQ6qKaK
         rl2ropKufq5CO9lRv/hNeQzRjSdrJIyZ0WJ+eB9KPwTzGcPIPcrvAt+YhUwzvtryAXCe
         NhmUvC2NrJ20oDIJri+UWCh4g1pV4lKILG/cCY2pMhBspcZ/qWNIFHeiMDZzgPMAhvei
         NtKtmRlK7deB9JgpOe/0Kvra/fiR7H5B0+lDrXGsdTAKt+Bhjjf2BxGtSsGdAIdUqiew
         +g5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWpGYdVRKGhrxsfzAeEHb8rzK0ZGs56rfgYfMtE8dl1gAUpgzJM
	6w03u60mZn6oX9UHB7RhY/4=
X-Google-Smtp-Source: AK7set9kTompRCc08dM2Sx6aHSWh1kZPI+D/01WpkGxn0I5F/qN3MBYstaG5s8bRJ2DN4pzQ58GqPg==
X-Received: by 2002:ac2:5316:0:b0:4db:33ed:89fc with SMTP id c22-20020ac25316000000b004db33ed89fcmr5294215lfh.6.1677263571994;
        Fri, 24 Feb 2023 10:32:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e9f:b0:4db:51a5:d2e8 with SMTP id
 bi31-20020a0565120e9f00b004db51a5d2e8ls1247287lfb.2.-pod-prod-gmail; Fri, 24
 Feb 2023 10:32:50 -0800 (PST)
X-Received: by 2002:ac2:4c23:0:b0:4db:398e:699 with SMTP id u3-20020ac24c23000000b004db398e0699mr6049891lfq.12.1677263570870;
        Fri, 24 Feb 2023 10:32:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677263570; cv=none;
        d=google.com; s=arc-20160816;
        b=mMx92eG45Q/BTCH4kzYrmiMeaeIW/3BoPkIVmnkT7/AKEo8YT4/WedwhfJi98XlJYU
         MVL4S/KnR1l1NGHIp8KP2JFtEuwWE4gOdTvliG3ieMt48QP5JdMK5+Y/t7/MlQz/AWT+
         6xPyDfEKd6pEsFqTUkOslTfJeKH0TMZhUh+odLKMP0F0AraP91cmpmJiK86LOuyDV/yl
         Yept0XaPXWNz37/UzcxagqQJzkRaYvYLr2JgUl9pecFPuUsvXq5yorCXaDBawUhlP/0w
         s88ZdVDrdxGN3aOKGrWf7mnNuL2Gzh5AEZQVjrRN4Cs6K5NS8+mJOZfQeetCoYkC1sH/
         sYNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=IwljiIh1fS+2NOwzceHLVqy8Ve5Q5t96iwJ4JuzYLq0=;
        b=i37eAEzcBMhbXKxBoYa9z3AbwuLUt6tv9BQl6l97Mon6ArzJh1Q9H6D1cz1aVMivmz
         c7sH0C9nA9inRtG8rXHzXbcv3becCiFwDsGdUcJIxry5Gej0136z2gcl7BrqVOjan+1U
         gLchoMaxV8KWkrf49D0vPI2NLwzTa6BZbKrq0UmNw4F3oYiy0iCKZKkWqqVOFjXbjVmi
         6v7XKbD1i7/wzCDoi8XQJlD61RXnOBQ4+GNJPjQmKyIQQUsY5F4GwYD9tBFsdhi9Y7wy
         8xHuF47EQhWJSzF2dR9Pe2pa/ecMZeXYh9IxDMPJX6kNxFGzsErp+ye7u9a+ymK2xqJG
         E0Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=RwI0RqcN;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=4CqLLgv8;
       spf=pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=krisman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id d22-20020a196b16000000b004dd8416c0d6si524231lfa.0.2023.02.24.10.32.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Feb 2023 10:32:50 -0800 (PST)
Received-SPF: pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 375DC38947;
	Fri, 24 Feb 2023 18:32:50 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BBA0413246;
	Fri, 24 Feb 2023 18:32:49 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id p64CIdEC+WNvbAAAMHmgww
	(envelope-from <krisman@suse.de>); Fri, 24 Feb 2023 18:32:49 +0000
From: Gabriel Krisman Bertazi <krisman@suse.de>
To: Jens Axboe <axboe@kernel.dk>
Cc: Breno Leitao <leitao@debian.org>,  asml.silence@gmail.com,
  io-uring@vger.kernel.org,  linux-kernel@vger.kernel.org,
  gustavold@meta.com,  leit@meta.com,  kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 1/2] io_uring: Move from hlist to io_wq_work_node
References: <20230223164353.2839177-1-leitao@debian.org>
	<20230223164353.2839177-2-leitao@debian.org> <87wn48ryri.fsf@suse.de>
	<8404f520-2ef7-b556-08f6-5829a2225647@kernel.dk>
Date: Fri, 24 Feb 2023 15:32:47 -0300
In-Reply-To: <8404f520-2ef7-b556-08f6-5829a2225647@kernel.dk> (Jens Axboe's
	message of "Thu, 23 Feb 2023 12:39:25 -0700")
Message-ID: <87mt52syls.fsf@suse.de>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: krisman@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=RwI0RqcN;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=4CqLLgv8;
       spf=pass (google.com: domain of krisman@suse.de designates
 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=krisman@suse.de;
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

Jens Axboe <axboe@kernel.dk> writes:

> On 2/23/23 12:02?PM, Gabriel Krisman Bertazi wrote:
>> Breno Leitao <leitao@debian.org> writes:
>> 
>>> Having cache entries linked using the hlist format brings no benefit, and
>>> also requires an unnecessary extra pointer address per cache entry.
>>>
>>> Use the internal io_wq_work_node single-linked list for the internal
>>> alloc caches (async_msghdr and async_poll)
>>>
>>> This is required to be able to use KASAN on cache entries, since we do
>>> not need to touch unused (and poisoned) cache entries when adding more
>>> entries to the list.
>>>
>> 
>> Looking at this patch, I wonder if it could go in the opposite direction
>> instead, and drop io_wq_work_node entirely in favor of list_head. :)
>> 
>> Do we gain anything other than avoiding the backpointer with a custom
>> linked implementation, instead of using the interface available in
>> list.h, that developers know how to use and has other features like
>> poisoning and extra debug checks?
>
> list_head is twice as big, that's the main motivation. This impacts
> memory usage (obviously), but also caches when adding/removing
> entries.

Right. But this is true all around the kernel.  Many (Most?)  places
that use list_head don't even need to touch list_head->prev.  And
list_head is usually embedded in larger structures where the cost of
the extra pointer is insignificant.  I suspect the memory
footprint shouldn't really be the problem.

This specific patch is extending io_wq_work_node to io_cache_entry,
where the increased size will not matter.  In fact, for the cached
structures, the cache layout and memory footprint don't even seem to
change, as io_cache_entry is already in a union larger than itself, that
is not crossing cachelines, (io_async_msghdr, async_poll).

The other structures currently embedding struct io_work_node are
io_kiocb (216 bytes long, per request) and io_ring_ctx (1472 bytes long,
per ring). so it is not like we are saving a lot of memory with a single
linked list. A more compact cache line still makes sense, though, but I
think the only case (if any) where there might be any gain is io_kiocb?

I don't severely oppose this patch, of course. But I think it'd be worth
killing io_uring/slist.h entirely in the future instead of adding more
users.  I intend to give that approach a try, if there's a way to keep
the size of io_kiocb.

-- 
Gabriel Krisman Bertazi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87mt52syls.fsf%40suse.de.
