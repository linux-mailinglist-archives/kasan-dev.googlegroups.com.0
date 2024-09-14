Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3VQS63QMGQEQJQ46ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 563F99792FD
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 20:39:44 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-535682ab6e9sf3183454e87.1
        for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 11:39:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726339183; cv=pass;
        d=google.com; s=arc-20240605;
        b=gDp5dA2uq9vDtFPF4/KPsqOm27B9iwWffEVmjIUPh5sIQo+N/8DCOy4jcZOSeariqB
         Pt+hGUKSUvjQgER6G2cPaXEpAxcDjltm7Eh/nup5q3JU36zATQYNixi34+ej3vmi5UhM
         HaH2tBxTGb+62L1chetmGynEQ3FAwAkvvLwKff2iR83EgKSc9XVqK5uYBPMoYp6BdVra
         cJkUPwrKczuL+Dgp/DfXvb7XDzvA+e+Z8uZDUMkZJhGlweFQ5xtrFqjjUJlQQuZAEwrY
         Zkjz02apIZQLjZ2J6FPdzsM69T7w8i0N7GknasLpiYL2lionzbYU4DAwIHFVyT3zLxip
         gAkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=SaXzXPL39woC5aCUi+r0+JsKDXrcoqEvBxzBSmH+JvI=;
        fh=/V5akUsCywxfNB0BVxVi3UXqf9j8TWZVq3VIUwCfO5Q=;
        b=H173KhTuGswLT09mdBwCcQCtk0wD3m2bNUsTDiTiv9dKUny+yztgIhE3rlcrJzP/z4
         t2Uin35U67hrvP8D26Lq9SBQvXJLV2hH/Xcgr56PGJOSHmofotqt44HrB/vHUf7FPkvD
         pvY65J5J9tWBU7lfn+9//XIlSpXMc/vmFSRiXqLIoGIKPch2ZvhEzOsTMQZXvNPIxKwk
         JllPVLpi3UsPKsT+hQqZX2ybC/TEB1lLTuyZbMPCBT6S2ZL9xhSStTtpzxPLgarlDDuI
         pPxf4APIlbolMc6L7uHfxuVXD6g8eosKXQP36ZWdtj+IY5Vldkd8ghzXOPKMfi0C+185
         TpEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="HYta+5/v";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="HYta+5/v";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726339183; x=1726943983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SaXzXPL39woC5aCUi+r0+JsKDXrcoqEvBxzBSmH+JvI=;
        b=QOrb8t6Y+o/CsK7DulOQKpepXHevJkKm7gHJLHhtNLgtRkeIKeLRkjL0ZkLqN20oGq
         SeD83qXOZ8pVi9eBW6Tc6VItlsr5/cSLfX6tQqMfDmEUURwNxpJPs3xTJov54LMVuZiI
         d93M45GHbfX7xcmJGQFVtaMzSTHKZiL/FTUBoMGO5Wwzmb+DtSijlZOKgqER7af8lN/j
         mL7x9vB9+bhAX1/tRuoLFiM/Qkr5Ktbb+yO5MSx4ZSRc2B0SzQaVoGvBsU4cgsAJzBdk
         iYYc1qLEIMAsS1SU4PYbhwYYNV1i4J8nCqTF/0uHnkXMvNN1G3jOkE+K1dsiF+xkX6C6
         MWmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726339183; x=1726943983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SaXzXPL39woC5aCUi+r0+JsKDXrcoqEvBxzBSmH+JvI=;
        b=U6WGK8sq6T0WxWqvrweHWcpiNlXFt7Ci8ikzasdMClJXO1f12Xy3pe57T5trbjLD0t
         WWcp4DZ8TjFga8alsc96m7mjg8DYTBKclWJHqIB4KHZGFPXO33N59EGkXzGi6xGulZSZ
         yZ+l3WMrDYHl8Xwd8aBAxNOUMT6RcPUSo154Dy6Yrq+H8QAalni+X8bPWP/CIGYIOLOS
         U03Et4uLrd501pG229vBrkNJM5EF7ZVMM4WvcSl/mTjRAXRmPhQcLmFBy0xZrVuSY6yp
         MKWMTeZSSS1027M6TF8H2/yrxPl0KZoNVX2+9/XGxkT9sHpXRv/LBVhcRUWpJyPpwGNs
         zk/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVM78QL2H7giS0uImTw5kPvVcZjgbqEvLMFp8oWsGD/sip+53kDWkVeta2ZMVr2lQYo4pYFQ==@lfdr.de
X-Gm-Message-State: AOJu0YwHefEOVNcmap0w2E5CEBkxcHrfPO7yqM7EtKBEhVXteqyTMf6R
	GXkYxSn+DrDqGe0+pKse8JF2Pr3fQkjNpJM0tG9a/6SLP+JsDzOx
X-Google-Smtp-Source: AGHT+IE9F+YbLtMJJTtzmRbkUei/lpjuK2te092FlQjmKx7sepjJ6UBBL0KUCZcq8IqJZTTPq5vrIA==
X-Received: by 2002:a05:6512:3b12:b0:533:ad6:8119 with SMTP id 2adb3069b0e04-53678fbb216mr6277063e87.14.1726339182537;
        Sat, 14 Sep 2024 11:39:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b23:b0:533:484b:cc76 with SMTP id
 2adb3069b0e04-53678e09c97ls466146e87.0.-pod-prod-03-eu; Sat, 14 Sep 2024
 11:39:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZf9A6GRcEeisWNQsiqbdG0GPzoNVVEPxj/Rnmr7ZMIQFrUKy08KUohGi2garLwPGams8sxO01/qY=@googlegroups.com
X-Received: by 2002:a05:6512:12ca:b0:535:3d15:e718 with SMTP id 2adb3069b0e04-53678ff2ed6mr6110291e87.50.1726339180306;
        Sat, 14 Sep 2024 11:39:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726339180; cv=none;
        d=google.com; s=arc-20240605;
        b=aZfEZu9/6TzrKUQ7+nT2v8c/tRWVFnF4zMKThbWGIozXpBu/Nph5v1htaKQLRjyczn
         da79kWMRfcwTrQP38QlK30AWhft4wl8qtkilnyD0h4Fqam0xxnBcPMRxteSKaoRVbbCH
         n4dhg17MhNIscMqlZgXwbSqE1m7vRBj5iKY3kODuFvaLuB6jget5LGHnFaDrSf60aX7u
         u5PmDluiyebkjIiRweU56qP9CSUTdkGpA+11kj+14pLuP+FDfGKCu8SYqLpW0xAmLJrp
         s8ZdsSfPURSDPx+/hnjPdHE9h1I++2XmCk1kpVaKJGWPTp1obBDdxzhulFfWQZ8XEy9x
         saeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=zqYH48BDG1o+pBNq8eXY+DwTztxHAJ/NGHCTo7dJGes=;
        fh=EOnPpFJx3n9Cja8QtRLdA2o80or4wCPbn0qKjzGnkFU=;
        b=NDekBJu9HHB7wI2caVj46gUqq4mxxDtoXLSuBJ5aGhZbi+JK1DDEJPcVweARqDM/xj
         d+1P0pJ6SXtRInFZnwfrdvR94tGFGvdKyBxLXWmhM08Bya6KT4I3LVRxyEKCjIRikdo/
         JEUGLUh6N1+nf2af6hRqzaLAD6bOn6qE5t3WSDP+B9AV92HTSh++oY2Iwp7XfEmYbR+U
         42SecmULUQBrqVXqAAPBIwTLFRKJTgxPj2pIEM0xd+jz6Y9KbcfcLTJploeZO0bGmB6I
         PYoFRZNXKYWB1s2d7Bx2FuMHXyRyHRzS+G+yktUy/sHcMOVvVFOeGNDPwrSv3KTpYtcj
         vGqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="HYta+5/v";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="HYta+5/v";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5368706e4fdsi34315e87.3.2024.09.14.11.39.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 14 Sep 2024 11:39:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 399F51FC23;
	Sat, 14 Sep 2024 18:39:39 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0580B1386E;
	Sat, 14 Sep 2024 18:39:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id WE0AAWvY5WbkAgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Sat, 14 Sep 2024 18:39:39 +0000
Message-ID: <e7d0ca75-82ce-4079-9426-e82e83e38621@suse.cz>
Date: Sat, 14 Sep 2024 20:39:38 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
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
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
 <CAB=+i9RHHbfSkmUuLshXGY_ifEZg9vCZi3fqr99+kmmnpDus7Q@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <CAB=+i9RHHbfSkmUuLshXGY_ifEZg9vCZi3fqr99+kmmnpDus7Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Rspamd-Queue-Id: 399F51FC23
X-Spam-Level: 
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[26];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLsm9p66qmnckghmjmpccdnq6s)];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:dkim,suse.cz:mid]
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -3.01
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="HYta+5/v";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="HYta+5/v";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/14/24 15:22, Hyeonggon Yoo wrote:
> On Wed, Aug 7, 2024 at 7:31=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>>
>> Add a test that will create cache, allocate one object, kfree_rcu() it
>> and attempt to destroy it. As long as the usage of kvfree_rcu_barrier()
>> in kmem_cache_destroy() works correctly, there should be no warnings in
>> dmesg and the test should pass.
>>
>> Additionally add a test_leak_destroy() test that leaks an object on
>> purpose and verifies that kmem_cache_destroy() catches it.
>>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  lib/slub_kunit.c | 31 +++++++++++++++++++++++++++++++
>>  1 file changed, 31 insertions(+)
>>
>=20
> Hi Vlastimil,
>=20
> I think we might need to suppress the WARN() due to the active objects
> in kmem_cache_destroy()
> when it's called from slub_kunit. With this change, the warning below
> will be printed every time
> slub_kunit is loaded, which made me wonder if there's a bug (for a while)=
.
>=20
> Actually, SLUB calls pr_err() is called by __kmem_cache_shutdown() if
> there are any active objects
> during destruction, and the error message is suppressed by slub_kunit.
> However, kmem_cache_destroy()
> still calls WARN() regardless if there is any error during shutdown.

Yeah, there was a LKP report about it already and I wanted to handle this
but forgot. It's not wrong to produce warnings during the tests, for exampl=
e
the KASAN tests generate tons of them. But it's true that we suppress them
for slub and should continue so for consistency and not having to teach lkp
what can be ignored.

But I think it's fine if we add the suppressing during the rc stabilization
phase so will send the PR for merge window as it is, too late now.

Want to take a stab at the patch? :)

Vlastimil

> [  147.546531] Object 0x00000000c09342ca @offset=3D640
> [  147.546542] ------------[ cut here ]------------
> [  147.546544] kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still
> has objects when called from test_leak_destroy+0x74/0x108 [slub_kunit]
> [  147.546579] WARNING: CPU: 5 PID: 39703 at mm/slab_common.c:507
> kmem_cache_destroy+0x174/0x188
> [  147.546587] Modules linked in: slub_kunit uinput snd_seq_dummy
> snd_hrtimer rfkill nf_conntrack_netbios_ns nf_conntrack_broadcast
> nft_fib_inet nft_fib_ipv4 nft_fib_ipv6 nft_fib nft_reject_inet
> nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_ct sunrpc nft_chain_nat
> nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 ip_set nf_tables
> nfnetlink qrtr binfmt_misc vfat fat snd_hda_codec_generic
> snd_hda_intel snd_intel_dspcfg snd_hda_codec uvcvideo snd_hda_core uvc
> snd_hwdep videobuf2_vmalloc snd_seq videobuf2_memops snd_seq_device
> videobuf2_v4l2 snd_pcm videobuf2_common snd_timer snd videodev mc
> soundcore virtio_balloon acpi_tad joydev loop zram virtio_gpu
> ahci_platform libahci_platform virtio_dma_buf crct10dif_ce polyval_ce
> polyval_generic ghash_ce sha3_ce virtio_net sha512_ce net_failover
> sha512_arm64 failover virtio_mmio ip6_tables ip_tables fuse
> [  147.546646] CPU: 5 UID: 0 PID: 39703 Comm: kunit_try_catch Tainted:
> G                 N 6.11.0-rc7-next-20240912 #2
> [  147.546649] Tainted: [N]=3DTEST
> [  147.546650] Hardware name: Parallels International GmbH. Parallels
> ARM Virtual Machine/Parallels ARM Virtual Platform, BIOS 20.0.0
> (55653) Thu, 05 Sep 202
> [  147.546652] pstate: 61400005 (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYP=
E=3D--)
> [  147.546655] pc : kmem_cache_destroy+0x174/0x188
> [  147.546657] lr : kmem_cache_destroy+0x174/0x188
> [  147.546659] sp : ffff80008aba3d60
> [  147.546660] x29: ffff80008aba3d60 x28: 0000000000000000 x27: 000000000=
0000000
> [  147.546662] x26: 0000000000000000 x25: 0000000000000000 x24: ffff80009=
4a2b438
> [  147.546665] x23: ffff80008089b750 x22: 0000000000000001 x21: f9cc80007=
c1782f4
> [  147.546666] x20: ffff800082f9d088 x19: ffff0000c2308b00 x18: 00000000f=
ffffffd
> [  147.546668] x17: 0000000046d4ed9c x16: 00000000ae1ad4db x15: ffff80008=
aba3430
> [  147.546670] x14: 0000000000000001 x13: ffff80008aba3657 x12: ffff80008=
2f0f060
> [  147.546679] x11: 0000000000000001 x10: 0000000000000001 x9 : ffff80008=
01652c8
> [  147.546682] x8 : c0000000ffffdfff x7 : ffff800082e5ee68 x6 : 000000000=
00affa8
> [  147.546684] x5 : ffff00031fc70448 x4 : 0000000000000000 x3 : ffff80029=
d6b7000
> [  147.546686] x2 : 0000000000000000 x1 : 0000000000000000 x0 : ffff00011=
f1c8000
> [  147.546688] Call trace:
> [  147.546689]  kmem_cache_destroy+0x174/0x188
> [  147.546692]  test_leak_destroy+0x74/0x108 [slub_kunit]
> [  147.546693]  kunit_try_run_case+0x74/0x170
> [  147.546697]  kunit_generic_run_threadfn_adapter+0x30/0x60
> [  147.546699]  kthread+0xf4/0x108
> [  147.546705]  ret_from_fork+0x10/0x20
> [  147.546710] ---[ end trace 0000000000000000 ]---

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e7d0ca75-82ce-4079-9426-e82e83e38621%40suse.cz.
