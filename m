Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCE2ZW2QMGQE2RRIQLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AFDCB94A581
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:31:38 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-52efe4c2261sf2609795e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:31:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723026698; cv=pass;
        d=google.com; s=arc-20160816;
        b=GfX9dD6IyS4n+Ar90uQed6Ms2eiEm+TRNDClkTdqVrFrtJforOnZvobgZ1Ky6eElXU
         nqW07Ex90gCb5Zd8H/Tv1Z2vIxoFaXoVDirHZmiYpTtczd+aHYcJi+6OYExjwl/ZLxaj
         Gt2Cpq5jeYF7n/ayCtw6GBf19BWizxGQDLjulcCXup1zTk5XOz0XB8RBvhkzs34DMDMb
         +ZMXVY4ceaAgzFm99aVivO6h6K9TgisW5zDSrUAJD3VXwXDk2JhUKXgkjThws5XyEL/W
         XKvSz+CP4POJjd4R9Hglg3hPfLNgEHG7XXdFAkYusUmNrYIyrIYCi3td0jBfDSsEFY7V
         gm1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=Ye+2GHDh7kzEQGjwmQ2psxHi0NYXlv3T1CntSPs6NOk=;
        fh=JGEU+p++Nt3DhmfhBQ4VK9sVYdyTIoGNzQxHBQSO7KI=;
        b=L1tNAPPC1Hiiz7CjUHLRCmza0wz+oajdtkE23oLEYwB5Vsg88YOJ9pez3n8QM/O2/G
         ac3x0VqLmw3FQdoWKuJC0gMVMQKETWEznmeoewiPeMeB+PLMCANinTfh+Zw0HYqk8BBb
         tAVo2AepQOsbtX11NwKvzgQutPAjjYpb1EI1qhXDlq6clSU4C0u7fJ2hNY3OPkcKnN6C
         exwzaBquGo8wuNOgz1lrX2OO+O5lf/gmVbvv1muGD/8lyxepgMp+acz+KSlC3BN0Lfow
         wh5w/MPVBLGRTm5JugwuT6pFVvvHUlZTrltwMSPONG+ke7AqDlEi1eAXv9gMoYZ/CIVK
         cm3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cLY3/utF";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cLY3/utF";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723026698; x=1723631498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ye+2GHDh7kzEQGjwmQ2psxHi0NYXlv3T1CntSPs6NOk=;
        b=DBtIuibw1TBWRQaTDXx4Rp5SFG169ty0eHrWqYJnq2JU6mcP9RXZkssXqTRmNSvDTG
         IB689RTaj+W7ljZ75UZREce+679xS19S9St45ZeEQdVdTBHu3RSN3SRjanOr4m87lucN
         gJ2u8UdZBKO7ZjKQDgkw/tlv1TrdrTxv2Ck0MaI7Hjz1NVJTtoJlVtJYT8uHlsxKehEf
         8i3hCn8Z3WNJS3G0XI8ge/841hCs4UbacV34fncBx4zUP3epVKNLQLAT+NRJ0aRiRTby
         SL4P8HNdJz0G0+qtk+qxlqPhqnFjGiyk+1bjfIlVV+DQ6LVc2MULVagwDMSenGw3j5f/
         4X7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723026698; x=1723631498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ye+2GHDh7kzEQGjwmQ2psxHi0NYXlv3T1CntSPs6NOk=;
        b=N3BMbTpeoTXJp1sQhgT2J/C0002G3wCVesEPkpn4DEcDeqaH1aQJH9ayOB+OauRxLX
         BZWdiX2Q/zD+VSIYKmtlyF5O9APrVqfvPgePOIwY/qHIck2IcD379iIOLiVt5rgK/9dg
         yt3RsmHFMw0OSAvo1dMBUWa/S3jObGMOvyIiRqH/Q6OyaRzpwODPC0vrH+hoTFUIhfML
         Dr/lkkVk1AMA6Yct3EOFq237Vw42lpJlMAKszga2Afmpr8+xAEvX73h6H31rIlFeS7Wn
         +eZyeio/14Q5SFPdADxpCBdB2OJqQtvUXKlcukq4gIS8zc4uYsdGPBgTynGYJ08QyD/h
         uU3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5IAmaLTTCDGki6LMSZBzWDAyDIFvfX5fag2DFSPZupxc/tcsUKHLUByVtTOs9KXRXyIi18gTQadeeqyjkf2bBFrUJaKQ85g==
X-Gm-Message-State: AOJu0YxzHVf7cqNenjEXS5KK6soJuRphZViPPywvfXtgJrJk7wA+322b
	kbg+O3XuYUVqjqir7H7Vp6RLjwYSA0GUJt1xyBBZopwA1YEWQ0iS
X-Google-Smtp-Source: AGHT+IFRGS7wZlS3hB/Vi6e14rnzeeuZMnnPNsE9knw+NioJ5+9PnWoYbTcv8+rDtV/Y6AmklVqGjg==
X-Received: by 2002:a05:6512:3b89:b0:52c:cd77:fe03 with SMTP id 2adb3069b0e04-530bb380dabmr15044009e87.14.1723026697058;
        Wed, 07 Aug 2024 03:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c8:b0:52e:9b66:4f8 with SMTP id
 2adb3069b0e04-530c31f24e7ls2267384e87.2.-pod-prod-05-eu; Wed, 07 Aug 2024
 03:31:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWI/UzC5xU5LEQSo/L5tKzfmiOtS+C0FLGIYb3x7Tc+RFp5qWFEyyvQoiD1aEbMhzVeyc7+xeulS0U0/W8e0dSEq3Pcw1M0r9xLlw==
X-Received: by 2002:a05:6512:3da6:b0:52e:73f5:b7c4 with SMTP id 2adb3069b0e04-530bb3b47c3mr16585249e87.37.1723026694757;
        Wed, 07 Aug 2024 03:31:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723026694; cv=none;
        d=google.com; s=arc-20160816;
        b=feGWLBWM3/06W7GLoXBgNHHukoouMCIKv9iUBvngW22Hofo0HbTqbY/llNnROMmlAp
         pEb3eEAFr/KgokS5O7tXiakVe3+v9WatPx74BXGAgrpPF5hgv72IVt06El2pq6uC0Ur3
         yjCVPHiZjmg2ZnpHfvi3yXUL5l2pLxxqDTC/Lk960ffyqmkB4O370jNqEQll/q7pApQJ
         vLQ/Xq6HYk7Yqy2CEJEUN0OUuR7IpWSBoV5FD9CMG4uipc5quxLie/HW9SVhipnuJIi0
         3tFTD+gTCr0Lnldt+gOJcpOQ368L8henIgFLNIXh8kyOyBiY6R+TNE2a010bgYuqG55N
         +FfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=MYAQdZfiQ9b2HS7QQayr4v2PzJCMJBGtNuCobIJ9kog=;
        fh=IkE9nfmJjqF0Gh4XK//npeGH2HkSHIqCgOhfhWJ/CPU=;
        b=mCObDqeOue4z/EQ9fyF8/IePGs2mDtUG8vw5h7PHQUZzkO8+U+bCfYsqBUqxSZF7cM
         /hO388d92QhehzX6iM2tP/UXJckIl3JAWhJdZcxWA6vJZ8gd9J9doyhLxfjaygTvejKh
         UbPeG8SJ26vJrPnCBnPvLtJ2D9BNMcmWom022CxZGMSnbbtHliwc2z+QFSMbG2XHImIs
         A5f/hdZYb39BFnewkjMUDDrPGY9lLvxhjIqLmGfsWKkkqCMiSD2MVVqMbr5rScBz3XGy
         VgcUSs2Tb9CfA375tRliPkKiyhJj0fImS2GRhtCRdPx9fC/pPVv69F8SZ1MH/wyxLGQE
         L/Yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cLY3/utF";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cLY3/utF";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-530de3dbf8fsi24294e87.5.2024.08.07.03.31.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 03:31:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9D1BE21B30;
	Wed,  7 Aug 2024 10:31:33 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7078B13297;
	Wed,  7 Aug 2024 10:31:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id KnTUGgVNs2YsHwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 10:31:33 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH v2 0/7] mm, slub: handle pending kfree_rcu() in
 kmem_cache_destroy()
Date: Wed, 07 Aug 2024 12:31:13 +0200
Message-Id: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAPFMs2YC/42NQQ6CMBBFr2Jm7ZgyKQquvIchhraDNBowM0BEw
 t2tnMDle8l/fwFliaxw3i0gPEWNfZeA9jvwbd3dGWNIDGTImlOWo7Ooz9rhoxHmm/gRA+sg/Yx
 FHgI5ChxKgrR/CTfxvbWvVeI26tDLvF1N2c/+U50yNGiPjsrCeiKTX3RUPvgPVOu6fgGMaZPzw
 AAAAA==
To: "Paul E. McKenney" <paulmck@kernel.org>, 
 Joel Fernandes <joel@joelfernandes.org>, 
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, 
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
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.1
X-Spam-Level: 
X-Rspamd-Action: no action
X-Spam-Score: -3.01
X-Spam-Flag: NO
X-Rspamd-Queue-Id: 9D1BE21B30
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_TO(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[goodmis.org,efficios.com,gmail.com,inria.fr,kernel.org,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,google.com,googlegroups.com,suse.cz];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLsm9p66qmnckghmjmpccdnq6s)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="cLY3/utF";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cLY3/utF";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Also in git:
https://git.kernel.org/vbabka/l/slab-kfree_rcu-destroy-v2r2

Since SLOB was removed, we have allowed kfree_rcu() for objects
allocated from any kmem_cache in addition to kmalloc().

Recently we have attempted to replace existing call_rcu() usage with
kfree_rcu() where the callback is a plain kmem_cache_free(), in a series
by Julia Lawall [1].

Jakub Kicinski pointed out [2] this was tried already in batman-adv but
had to be reverted due to kmem_cache_destroy() failing due to objects
remaining in the cache, despite rcu_barrier() being used.

Jason Donenfeld found the culprit [3] being a35d16905efc ("rcu: Add
basic support for kfree_rcu() batching") causing rcu_barrier() to be
insufficient.

This was never a problem for kfree_rcu() usage on kmalloc() objects as
the kmalloc caches are never destroyed, but arbitrary caches can be,
e.g. due to module unload.

Out of the possible solutions collected by Paul McKenney [4] the most
appealing to me is "kmem_cache_destroy() lingers for kfree_rcu()" as
it adds no additional concerns to kfree_rcu() users.

We already have the precedence in some parts of the kmem_cache cleanup
being done asynchronously for SLAB_TYPESAFE_BY_RCU caches. The v1 of
this RFC took the same approach for asynchronously waiting for pending
kfree_rcu(). Mateusz Guzik on IRC questioned this approach, and it turns
out the rcu_barrier() used to be synchronous before commit 657dc2f97220
("slab: remove synchronous rcu_barrier() call in memcg cache release
path") and the motivation for that is no longer applicable. So instead
in v2 the existing barrier is reverted to be synchronous, and the new
barrier for kfree_rcu() is also called sychronously.

The new kvfree_rcu_barrier() was provided by Uladzislau Rezki in a patch
[5] carried now by this series.

There is also a bunch of preliminary cleanup steps. The potentially
visible one is that sysfs and debugfs directories, as well as
/proc/slabinfo record of the cache are now removed immediately during
kmem_cache_destroy() - previously this would be delayed for
SLAB_TYPESAFE_BY_RCU caches or left around forever if leaked objects
were detected. Even though we no longer have the delayed removal, leaked
objects should not prevent the cache to be recreated including its sysfs
and debugfs directories, so it's better to make this cleanup anyway.
The immediate removal is the simplest solution (compared to e.g.
renaming the directories) and should not make debugging harder - while
it won't be possible to check debugfs for allocation traces of leaked
objects, they are listed with more detail in dmesg anyway.

[1] https://lore.kernel.org/all/20240609082726.32742-1-Julia.Lawall@inria.fr/
[2] https://lore.kernel.org/all/20240612143305.451abf58@kernel.org/
[3] https://lore.kernel.org/all/Zmo9-YGraiCj5-MI@zx2c4.com/
[4] https://docs.google.com/document/d/1v0rcZLvvjVGejT3523W0rDy_sLFu2LWc_NR3fQItZaA/edit
[5] https://lore.kernel.org/all/20240801111039.79656-1-urezki@gmail.com/

To: Paul E. McKenney <paulmck@kernel.org>
To: Joel Fernandes <joel@joelfernandes.org>
To: Josh Triplett <josh@joshtriplett.org>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Steven Rostedt <rostedt@goodmis.org>
CC: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>
Cc: Zqiang <qiang.zhang1211@gmail.com>
Cc: Julia Lawall <Julia.Lawall@inria.fr>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Jason A. Donenfeld <Jason@zx2c4.com>
Cc: Uladzislau Rezki (Sony) <urezki@gmail.com>
To: Christoph Lameter <cl@linux.com>
To: David Rientjes <rientjes@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org
Cc: rcu@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Cc: Jann Horn <jannh@google.com>
Cc: Mateusz Guzik <mjguzik@gmail.com>

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
Changes in v2:
- Include the necessary barrier implementation (by Uladzislau Rezki)
- Switch to synchronous barriers (Mateusz Guzik)
- Moving of kfence_shutdown_cache() outside slab_mutex done in a
  separate step for review and bisectability.
- Additional kunit test for destroying a cache with leaked object.
- Link to v1: https://lore.kernel.org/r/20240715-b4-slab-kfree_rcu-destroy-v1-0-46b2984c2205@suse.cz

---
Uladzislau Rezki (Sony) (1):
      rcu/kvfree: Add kvfree_rcu_barrier() API

Vlastimil Babka (6):
      mm, slab: dissolve shutdown_cache() into its caller
      mm, slab: unlink slabinfo, sysfs and debugfs immediately
      mm, slab: move kfence_shutdown_cache() outside slab_mutex
      mm, slab: reintroduce rcu_barrier() into kmem_cache_destroy()
      mm, slab: call kvfree_rcu_barrier() from kmem_cache_destroy()
      kunit, slub: add test_kfree_rcu() and test_leak_destroy()

 include/linux/rcutiny.h |   5 +++
 include/linux/rcutree.h |   1 +
 kernel/rcu/tree.c       | 103 ++++++++++++++++++++++++++++++++++++++++----
 lib/slub_kunit.c        |  31 ++++++++++++++
 mm/slab_common.c        | 111 ++++++++++++++----------------------------------
 5 files changed, 163 insertions(+), 88 deletions(-)
---
base-commit: 8400291e289ee6b2bf9779ff1c83a291501f017b
change-id: 20240715-b4-slab-kfree_rcu-destroy-85dd2b2ded92

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c%40suse.cz.
