Return-Path: <kasan-dev+bncBDXYDPH3S4OBBMW6XS3QMGQEVMODCLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id D190297DED4
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 22:40:20 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5365fd3fab3sf2630242e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 13:40:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726951220; cv=pass;
        d=google.com; s=arc-20240605;
        b=XUFDDLWPz5VOxYK5+2ga92WDYYgDQrvlk1i9PnImw54EkWRH3fVvxbFW/EL37L/Lxs
         o1YrV8iXO3rdGtwpuCeeCYTIInwBFS/ZgStJG5EJMP152791YLTssi5jhnaYMIM5iDjo
         yQFBOtdML4AK7vxnHhJgumhZfcAsnqHSezb3HolxVDoPsndng1JwDVVJKlapKnrhQKZ9
         gY9dCMoTIOZvtTy9kbGWDOOm25/e/wCo4aQXPqqT9W43fCr2t+snjOr9ti8ABnH4fzat
         qTQBFWaTozc4EUkMC3UAoylowBecgixoMdzXizBQw97OwLt7qp2WueBiV+BL+gh22nuQ
         DsDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=8/+WdGY9InS+GmPzTvlF18x/71RR2oO58v9JhcFtLhg=;
        fh=nljQipBliNdQMgBbCJj1MDzM0XWeC096xMRKEzB8EBo=;
        b=jxrARx6p9R9RFcFiUvo7m3L/QMqRSynnP57gObQAc7Ioj39CJmkFKvtxZPZeVC4sv3
         eJHyj4cejaCbM6ngsLMLvI90Nzf5WN9oPy9qeUBdEypZK74eqj8K6w7D2mNltgOVNxjL
         +vRIdQfeWS6RDKrtPzxtP6NAx8KwiajvGlRq5Os6pk5g225WIyp3P8/Bg7o0sDBxRbqy
         mAp8UeTkyP1F3737rBk3G/xkv2EEcbkW6t18YOPvr/sutvsvWuvbTMo4qNkTMSRF4HhO
         lxy0X0lg3tuEyuad9nXamrCWAH0hXh84/Mf1cNCJMS/7Nc4xaR2F1hpACOt1sl+pge4Z
         KAUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tQGYQbYk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fRzdll+B;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726951220; x=1727556020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8/+WdGY9InS+GmPzTvlF18x/71RR2oO58v9JhcFtLhg=;
        b=SDJEzsztev/usqvsAiNuMKaXZyXuyw49K/X8CQUZII61mRTmtlmL7tPRYz/GgQe+k4
         ZEuA8ycoBRmAEFgXf3cUKZQf8qi5mtOaIfpDzaeovwSgQNYWwdvirrN1sbgnGnwGGq3a
         yl3Nca4mkPBG2PYvoSlYxbW4O8u/WV6s1zwwhYiZCl065mMelobWOJKX6WXpn3iUshtx
         F1T3NwQy9sCRODps0woHIEKqE+J3UJu5uJBNg67A0AsfQfTsmnFTwowdSmTO+Z5y7SEM
         JUD562o80Zu/+l5Fu2hT3SF1tumPBTx+OCwIfZffK2muuoU3hTeLZK19AtEu/1CgZWI6
         IZSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726951220; x=1727556020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8/+WdGY9InS+GmPzTvlF18x/71RR2oO58v9JhcFtLhg=;
        b=GQl+hQYYCfXbmt6wVIP4LUZ3GLryjS69l5pDMnTtcrlk3S7/1o64vVM/abtQmonLID
         qUv5V1ZOVCYWoeDCFCWU30ocu/Q9aWQVCJB6yLwNVaKuDD9r2CJn3PffWFnReuYgXQvA
         zmj2sjLcv4aQKNd7QBbIAimq86yW/XBz2KMDU8JpyyDGqYykh99x6WzRcunr/BxQNmSP
         H86v3D83O1HkeuyV8xlFpJ8kF/OeRpiMjCkcnnXySz63Fmvz8MoKVgpS1lbno9YXjC3a
         Cb7mE0nt4Ib4fYH9s3NYaCS1/oGYB9hdCeK+/UCWzAKQKMrstt/lkMEy25ersBim031U
         GF8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3cNFEHyW8cgKMHTH001zR7FXOd6alf70GXSvgFk0johD7lIuoyc01qlUMBNDobUiOo9jN5Q==@lfdr.de
X-Gm-Message-State: AOJu0Yz+GLqniEUMGfzwTv5VbcljDyUJsRtglQeLYBm1fkx9AePNr0pm
	QPvhcYSZL7E3FQ14fsjzVltBMjSASPNHqEcbA4rgYNGNyLLG6OWM
X-Google-Smtp-Source: AGHT+IHa4soOY5VA058IKtBFGbH/JtztY7wnb8HsoOTvW8NyOQ47W8kgTp21Vwrd60tjqMwl2twHUg==
X-Received: by 2002:a05:6512:2251:b0:52c:8979:9627 with SMTP id 2adb3069b0e04-536acf6b73fmr3841674e87.3.1726951218925;
        Sat, 21 Sep 2024 13:40:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:23a7:b0:536:53c2:bc36 with SMTP id
 2adb3069b0e04-536a5b760dcls418403e87.1.-pod-prod-07-eu; Sat, 21 Sep 2024
 13:40:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+yiquiI1dK30406Wd5RoXwbygpUws8loaqQe2K1bAmuVmnT27uaxH/sHBfKL33KgR4TU6j7A+5RU=@googlegroups.com
X-Received: by 2002:a05:6512:3053:b0:52c:d626:77aa with SMTP id 2adb3069b0e04-536ad3e1b4fmr3187493e87.58.1726951216906;
        Sat, 21 Sep 2024 13:40:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726951216; cv=none;
        d=google.com; s=arc-20240605;
        b=UdKP57zN1yiUt70u2t8kVGNwlzsIfJP9QNZP57iS+PvqwyepcCPDyya9aqYzh2JbXz
         kJ/BV7Q+1kUfUFniGankOnZlqxzo4xo5X1tDRjTd6Zhz4vTQeeqpTaEQzBoIsbucJx5C
         3xh59TtfjTX98pF7qCNobWMkCeTOIav5UI4bwz5mv5BMZXtAjLqqAd4rUB0Bicys0KDc
         fD1hM/m/YGLPxZlIYPpDLqnlkmn/H5MdvmOKtzQY3PcmPlWP/RD0zpeYeJVVnBf/i6Ms
         3x/LoQ1gkpV0xst9fIS1rONC0KQLk1wUP/Dc2QOD2C8u2rKSkS2bU3JADkQ0G2Iy0NqC
         GrRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=v7hoIxTHBkRWivT4ZKDH3moNxJriC8ZUDzs1ANxJlaQ=;
        fh=LDmSecLM1cRMm50YlpiLMwlBtuRnQSjclil26OgE4cQ=;
        b=EdYK963bKIlkexlcPX86iogcdsoR5bYt9/67p0FQt+zapUMeGGHzDD4eIKKMfAOhJt
         edTskOLFwAuwhPK9+noQNguaoGsKSyZEWYUYS4YzkvVaKFg6/IoAEM5XV0lEFvzT9Y+g
         NMSC08C22esJrRPfmBFqAzU6on2PF4SeQfV9WP5AHlDTwKyUODYfNJtX3W6FH2f/n5pM
         vHfL2vfKynFLH1GRvYNNat3RDYEu5diJuE0aKavP6B7RSSG4jm4UNt9FfDV9ipTIiAG8
         EnxMVKBjqvlRsNnggzF1rxdHS0axY9y/MmPrmhhHt0TYUZduRWDw0xPuBOpjR3SVKy0Y
         p01w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tQGYQbYk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fRzdll+B;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5368707b95csi404038e87.4.2024.09.21.13.40.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Sep 2024 13:40:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id D78C833B60;
	Sat, 21 Sep 2024 20:40:15 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8CAC51328C;
	Sat, 21 Sep 2024 20:40:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id q1d+IS8v72bMeAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Sat, 21 Sep 2024 20:40:15 +0000
Message-ID: <07d5a214-a6c2-4444-8122-0a7b1cdd711f@suse.cz>
Date: Sat, 21 Sep 2024 22:40:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
To: Guenter Roeck <linux@roeck-us.net>,
 KUnit Development <kunit-dev@googlegroups.com>,
 Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
 <6fcb1252-7990-4f0d-8027-5e83f0fb9409@roeck-us.net>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <6fcb1252-7990-4f0d-8027-5e83f0fb9409@roeck-us.net>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -2.80
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	TAGGED_RCPT(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[30];
	RCVD_TLS_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com];
	R_RATELIMIT(0.00)[to_ip_from(RLtsk3gtac773whqka7ht6mdi4)];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=tQGYQbYk;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=fRzdll+B;       dkim=neutral
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

+CC kunit folks

On 9/20/24 15:35, Guenter Roeck wrote:
> Hi,

Hi,

> On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
>> Add a test that will create cache, allocate one object, kfree_rcu() it
>> and attempt to destroy it. As long as the usage of kvfree_rcu_barrier()
>> in kmem_cache_destroy() works correctly, there should be no warnings in
>> dmesg and the test should pass.
>> 
>> Additionally add a test_leak_destroy() test that leaks an object on
>> purpose and verifies that kmem_cache_destroy() catches it.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> 
> This test case, when run, triggers a warning traceback.
> 
> kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still has objects when called from test_leak_destroy+0x70/0x11c
> WARNING: CPU: 0 PID: 715 at mm/slab_common.c:511 kmem_cache_destroy+0x1dc/0x1e4

Yes that should be suppressed like the other slub_kunit tests do. I have
assumed it's not that urgent because for example the KASAN kunit tests all
produce tons of warnings and thus assumed it's in some way acceptable for
kunit tests to do.

> That is, however, not the worst of it. It also causes boot stalls on
> several platforms and architectures (various arm platforms, arm64,
> loongarch, various ppc, and various x86_64). Reverting it fixes the
> problem. Bisect results are attached for reference.

OK, this part is unexpected. I assume you have the test built-in and not a
module, otherwise it can't affect boot? And by stall you mean a delay or a
complete lockup? I've tried to reproduce that with virtme, but it seemed
fine, maybe it's .config specific?

I do wonder about the placement of the call of kunit_run_all_tests() from
kernel_init_freeable() as that's before a bunch of initialization finishes.

For example, system_state = SYSTEM_RUNNING; and rcu_end_inkernel_boot() only
happens later in kernel_init(). I wouldn't be surprised if that means
calling kfree_rcu() or rcu_barrier() or kvfree_rcu_barrier() as part of the
slub tests is too early.

Does the diff below fix the problem? Any advice from kunit folks? I could
perhaps possibly make the slab test module-only instead of tristate or do
some ifdef builtin on the problematic tests, but maybe it wouldn't be
necessary with kunit_run_all_tests() happening a bit later.

----8<----
diff --git a/init/main.c b/init/main.c
index c4778edae797..7890ebb00e84 100644
--- a/init/main.c
+++ b/init/main.c
@@ -1489,6 +1489,8 @@ static int __ref kernel_init(void *unused)
 
 	rcu_end_inkernel_boot();
 
+	kunit_run_all_tests();
+
 	do_sysctl_args();
 
 	if (ramdisk_execute_command) {
@@ -1579,8 +1581,6 @@ static noinline void __init kernel_init_freeable(void)
 
 	do_basic_setup();
 
-	kunit_run_all_tests();
-
 	wait_for_initramfs();
 	console_on_rootfs();
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/07d5a214-a6c2-4444-8122-0a7b1cdd711f%40suse.cz.
