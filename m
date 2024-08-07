Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCU2ZW2QMGQE2KZ4QRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4330094A588
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:31:40 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2f14b6f64d3sf17734891fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:31:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723026699; cv=pass;
        d=google.com; s=arc-20160816;
        b=vpeS0TA7C2gNirP3fiQLBnfEN5r0wZRp/uKXNmjZXIFOo72p2MS5clD0qIf3pafkie
         b8EhefCPIlWZFXhxHy8qFIW70nCUTv4HYxKU+BRChVM5ETuvgTclo5JCPkQ5dw8G51Pd
         4zT5XKB3Gr31zkDYmt8psiHLN7Wjw92eH7B14PIiynpvAEmOLP5EuWeG5PyF7YhTaouz
         D6jBZtEURB81IotwAHZfLbmEqlb8BjXMaa5gDf9FR86dyDFVjxF07qcp7WcwQ8vj3drg
         AZETFjdBXg4HbyxNlFI1ERymLh1p5ZgWAdqHBzV0L+8CtibHU8OppxXcu4AB8jwCQOn3
         BSJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=rV309FEyzcP7ZkhgJ+DoeCMWrvK+ST2exCD5FCDRq90=;
        fh=LR2jk8OCqTf3gj1qGg9yNm71anzGCOLr/GbbQ537sNU=;
        b=SVF4c/r2bK4avZLJiswelsdhED5LmqyKjt/ebO+Fp+u0qxfQVaQss8ERNBxK+5jyzu
         WOdlOvAKabeRcIn3hn65ZEuhPL/6/2Y309hfKUI8/JPXRpyEC6YuUr39DtKL8p/uLipY
         UGI7RIspk770CsOR31J+UYjPW7Dq5DUelDbXPLuzHRHc6YsuwUuIMEVBIVKuk+KzrvtB
         gh9HLNqX2Fxq2x2Tw93JaXIfv64JsCEah06NwFmHynr0KBA6pi4IuYfCfP8NZGNgJN9q
         Lh4npYhWUdkgWxq1S8ciN8UcR5k2IVYk+v4dhifN1i0bc8vDIS4AFYF6AltbGBagYbrR
         YubQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=G9cWwfVr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=G9cWwfVr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=K+AeEX2G;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723026699; x=1723631499; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rV309FEyzcP7ZkhgJ+DoeCMWrvK+ST2exCD5FCDRq90=;
        b=NXLmhRBTLHgFlDargqhd2Qpy84+m4aPxSpmb9v8pXahGEQr9tlV+hgje+cP13TGrHK
         SZpIhXZZcATpoLrj2m019TbVqUh9YFTa6E3XGlM99asqLdXkcvaX92GaDBKU6vX3fHVv
         vwuB/DbkQKDKPzpUpQblG8QDMoBx1AjC4gv8mTum03hpxyc1psRuixdxLkcZCHVTrSra
         i8Uazz5EV2IWzTmavfcL9l6Lz5xlUz/1t9zLghoUZfWqExOjRo/2UtTxPCeDDplM/Ge/
         quPg0acgmEmJgjp7UyOKCJe3LaK8JzSvyNjsaoiZ+EVNCUDzImOrJH68b9DUJjfUHEfs
         v6iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723026699; x=1723631499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rV309FEyzcP7ZkhgJ+DoeCMWrvK+ST2exCD5FCDRq90=;
        b=rdGebpqzdWD+s2CxXTs3Ui4pRmQPPGQq5F8SgnYFVPHoQgzVy2RcXWMoQLF7zdbDyv
         pmcoIv0W/50FwBP7/pJJQ3wyhkopDRLS8529b7bsogKwNMAp9YzhiixseQXthBZBT+pf
         Dw5g350EEtFM6piazzdeLktYMSihMKfjkHWdfM3D7aMUUi4co/GJ86gjoo5FgYIGoF5p
         1c3XzJCdsl4c16JWYbP7apGXkNDR23W8kwtptSHqsS2Ktl3IC4VszmYv3wCvDkWHIErM
         S90VzvL3RnSK4FAJ471lI0iZvOF8TzDDzV7/xJ5pLvMBb9mk9osDavlXMuTvlMjApEqi
         VW3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUMmDHplR1iL8swxGfEsR6e8lsxv6rpKwEwFlBxrxV1iuMJpApECvAvdfeOYyl5uWWzqFXWhLHNbvRSFbSnxKpUBs5GqNeyQg==
X-Gm-Message-State: AOJu0YzrwPm3rotiZy0SbbwEe9L5e9E6E8mVmKxWR0iivjRR0VP2wU7m
	LfD4l2pBz8DOrzfwR1REU/ERRNHTihXCKvqkkxtSRu+pKsft3Dr+
X-Google-Smtp-Source: AGHT+IGyPQwjUaIyRIUvLeWeJXp0LaaFwbxD4w7t4kUT3Oje4CltF+pJ1RORaxExmCDy2KTi4ql/NA==
X-Received: by 2002:a2e:240b:0:b0:2ec:3d74:88ca with SMTP id 38308e7fff4ca-2f15aaaa85fmr114810001fa.25.1723026698813;
        Wed, 07 Aug 2024 03:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f09:0:b0:2ef:256c:a25f with SMTP id 38308e7fff4ca-2f16a610da8ls226301fa.2.-pod-prod-02-eu;
 Wed, 07 Aug 2024 03:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbrIexfhZ2vDS/lswgbRjqO6gu9M5kCZWKd+6mv7zmJwObIeKm6AInKD5LpIf/3wEgVWeEp2VGq2f+QTLuTXkqaAv8Zc4rjdr3vg==
X-Received: by 2002:a2e:9ecb:0:b0:2ee:87b9:91a7 with SMTP id 38308e7fff4ca-2f15aa87cedmr110391421fa.18.1723026696303;
        Wed, 07 Aug 2024 03:31:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723026695; cv=none;
        d=google.com; s=arc-20160816;
        b=vnurt+KbIjrcQFhN4B4nMsb1jcATFv1Ca3HNzEtR5eAkjM7SVhY+ImEpe7Oz3FdZeq
         aElqgL/lvA/MptWUxrz9KOxgX7nw3p7RXWinwoVLdScMzNwVbrFeKaQvCU9jhMRQRnwy
         P3jZBPooL29eDanwBhyfSwDEjbbmM77ddmcXkSwlOl08Nf6g2o0/zCJg8siQu0uSsVd/
         Ef05ZsPq5bFNx+hQtpAp28bnR7DX8t5wTSTNX0nPWBeE7T/9b5yH/YXtfQZ47eL3q2QG
         toNL0ONaL8RoeALugTRVqxJ/jL6ODlm4kBm/hpKkivbe+IYKdQ7kAw5ZoFf0L7Dk8t6O
         q1sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=foIdXKngemBlbTDIsFcIDdiOSQLvnJzh8edzRJqHuXI=;
        fh=IkE9nfmJjqF0Gh4XK//npeGH2HkSHIqCgOhfhWJ/CPU=;
        b=nQrvyZmIKaCQBr+qJAJ0FUyieoU0+MM/mtoGNom81Q/3czoyomGSvZp7lZT9gaAcrI
         g3DRO7HLIWxSd71QHX8wIpYpfLV2TMv3YwmmzrOvsObQsBanInUtnRnBR4EbPtbr7yMA
         fpT0FfsM7tr/xYygT/dNRGL7LQNfOCrQdquN4O0Sg6VBWUY5MnWBrIXHkS7cGT9JoTmL
         16HUg+ytK/UWUIbRbrDNPnc5Q5MXhAjh3V8bscUdg8fsU/V+yGJEDMzNZ74EWrnVfFiK
         5wQWGDMr7RwZq5NbXQGA0o5vLqbOpjSTwcJPUcK0575OnFahHaz4/pOfyOMLHqP8pjRW
         s3Uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=G9cWwfVr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=G9cWwfVr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=K+AeEX2G;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429057e4206si800445e9.1.2024.08.07.03.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 98D2D21CF7;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 629DA13B09;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id GD/NFwZNs2YsHwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 10:31:34 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 07 Aug 2024 12:31:19 +0200
Subject: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
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
X-Rspamd-Queue-Id: 98D2D21CF7
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
 header.i=@suse.cz header.s=susede2_rsa header.b=G9cWwfVr;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=G9cWwfVr;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=K+AeEX2G;
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

We would like to replace call_rcu() users with kfree_rcu() where the
existing callback is just a kmem_cache_free(). However this causes
issues when the cache can be destroyed (such as due to module unload).

Currently such modules should be issuing rcu_barrier() before
kmem_cache_destroy() to have their call_rcu() callbacks processed first.
This barrier is however not sufficient for kfree_rcu() in flight due
to the batching introduced by a35d16905efc ("rcu: Add basic support for
kfree_rcu() batching").

This is not a problem for kmalloc caches which are never destroyed, but
since removing SLOB, kfree_rcu() is allowed also for any other cache,
that might be destroyed.

In order not to complicate the API, put the responsibility for handling
outstanding kfree_rcu() in kmem_cache_destroy() itself. Use the newly
introduced kvfree_rcu_barrier() to wait before destroying the cache.
This is similar to how we issue rcu_barrier() for SLAB_TYPESAFE_BY_RCU
caches, but has to be done earlier, as the latter only needs to wait for
the empty slab pages to finish freeing, and not objects from the slab.

Users of call_rcu() with arbitrary callbacks should still issue
rcu_barrier() before destroying the cache and unloading the module, as
kvfree_rcu_barrier() is not a superset of rcu_barrier() and the
callbacks may be invoking module code or performing other actions that
are necessary for a successful unload.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index c40227d5fa07..1a2873293f5d 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -508,6 +508,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	if (unlikely(!s) || !kasan_check_byte(s))
 		return;
 
+	/* in-flight kfree_rcu()'s may include objects from our cache */
+	kvfree_rcu_barrier();
+
 	cpus_read_lock();
 	mutex_lock(&slab_mutex);
 

-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c%40suse.cz.
