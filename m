Return-Path: <kasan-dev+bncBDXYDPH3S4OBBI6L5G3QMGQEGTHLGBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9364F989D2F
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 10:47:33 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-42cb5f6708asf25367125e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 01:47:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727686053; cv=pass;
        d=google.com; s=arc-20240605;
        b=RMPcWh814Txs7LNqyXcDRXEWQLpIey0ik4S5tfs0QHGf1UGh6dWMqhTnPkVzm33DZf
         NQ6S7lvEHBuShEXIH1UBAwH3B3aYjNywq85WcKMub04ExeFuvfEfHC76//onQvTaJ74+
         GhiiGTworSB9n88v9WZl7CdgmlwzWYrxezKmUV7kiB2odTWRtXsnt7Mrzdv0TxpDaP/U
         JXk8OXSH2RnUX5GRB7kkNtgXTqaaJwMNKwYuiZZXX3z6USVjeqaLoNldd3EzrA1Fc2hP
         u3NeJIFXteeKxIeOvIR+YGmPxGWv5+O4hZzj/AntQxbtsNfcK1BgBwQlSporHovQvX0u
         Xr2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:references:cc
         :to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=s2QdLSMXg6EjppYLoB5njryoRY9q+odVE7L00/uxsRU=;
        fh=Ef3V01SeFk4+iX4/WZuutIc7fPCyAIzIyK20E7yonnI=;
        b=fzfy2JJwPK5QX84VpGE9Gt+wQUKoi+6xRBr0mz3utpzArqnjjnuT7fdpIr4XbcQK2I
         gU8eLd4WtGwyVGOSABWxhxYvalSwtjEsQr1o2nVFC3H3Oc3gFWZr4SFGtsvR5DUREizW
         lTpZWIwb8x87vbutvDfajaLMCQGyaZ+gRGeeqNd2JMBZ2NvyjbqgYqQ8pBCOiEbHz+8m
         1Yp40UiuQsFbVIgoONiQ32b1ozT9QVWhGh5Ya7UIP55A/zXBBkvn7HoU9rDLPIJu4m84
         qyCvr0oLPJ1fuhD+fxNlTgV/Dxz6HHh8XiYrLk5z+MM3Mx6SbjogvbhWSL+Vi1I7sqwt
         x9bA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UUwHR4aM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UUwHR4aM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727686053; x=1728290853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=s2QdLSMXg6EjppYLoB5njryoRY9q+odVE7L00/uxsRU=;
        b=nQBfFTsHz4KdZ+llD9+SeGc/sZfvdYAbOOudSD8TfI6DcpQ2mrgVyZunHsjGmjaOj5
         6lFQLuNRWo9weB4EJ9D4exWKynhvAxCTh+MRb9DQUCntBlBLtN+17gNCNETRwW3eBCju
         rCfa9aKlEY6/F9FG4KfqUKmIc50qJz/yD5MAjUBmN4DebPL18FhImAu3XtzSYQUC9RXu
         nhKBJpJF9yxdzT/2t8lebdUtyDy6DD6+CgEhARajCNRgk0wZqB9sI55Fvm6EIsVelKrX
         NNcgV1kWoAtYrvaMSq3ZueQxp9SNG2RtNCER6icVS/pKkIQz7Rry3924HdEMGvTZ5TK6
         GAPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727686053; x=1728290853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=s2QdLSMXg6EjppYLoB5njryoRY9q+odVE7L00/uxsRU=;
        b=Ro78aM8nvM2ua1FocjwMDLAzkSAxS8RkOItJD6/dbO3g8ns9BxZ0UEXvQNl66DzP/I
         by/Q5E5ifrnKb4r67i0pU7eAXaoqbUFu4srDB4l/e5LpTfAWtAHEmzO4FOvGwbS6L0Ak
         b+PjM5OPTt7Glw02G0Gu4Tq3luaq6Kdf1ILenITsoFRE7gfFGJ/FMp41Ia2wPT2FZFzH
         BGiYuwWY5ES3u9Iz4AHOB0pGNZ4FMVokT3RwIJ3eLUqyI/j/y/WnAl403vw1Dpgvc88U
         HfKhFeXbM6b0uMGP0M7LXTUXZEzZth3zbZ0mFqR2psuC+D5SpSeLBMpS6Gnm+R7htYbq
         B/fw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU9h/L7SETNN0YVwt4MTBbAaqdbQ2Bt19oSteh3h6SHSEQsexS24Uhox2rGr1NNfpxQoJJKfw==@lfdr.de
X-Gm-Message-State: AOJu0YxITT5FjRbcAvQ1LRfir5XxU48kiNFzk4oE2yCWBnYC+/fNBZGh
	MGTcAK6wfAjZMfTEkGu3F6gQo5qfD18t+I6+TdCDiF3OORFp8GvG
X-Google-Smtp-Source: AGHT+IGNj0tqWf8jT+PRAqJeImTAqLIrZJGRL+FDfNgTmGMZ57/Zf4cHvc/Mk/oaITAmwxO/jX0iWQ==
X-Received: by 2002:a05:600c:35cd:b0:426:6ed5:d682 with SMTP id 5b1f17b1804b1-42f58415f75mr79733825e9.12.1727686052215;
        Mon, 30 Sep 2024 01:47:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:511f:b0:42c:af5b:fabd with SMTP id
 5b1f17b1804b1-42f5222aac0ls21003965e9.1.-pod-prod-06-eu; Mon, 30 Sep 2024
 01:47:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxxTWfdfT0p/O8E1qxDKCkEejzdUn5d33iwvVbetTAtiaRPtMyxLHr9vB1C910+ea8ZpbZz1ImC2g=@googlegroups.com
X-Received: by 2002:a05:600c:1ca4:b0:426:5ef5:bcb1 with SMTP id 5b1f17b1804b1-42f5840a012mr74830795e9.6.1727686050221;
        Mon, 30 Sep 2024 01:47:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727686050; cv=none;
        d=google.com; s=arc-20240605;
        b=IlSR9Uc9RI8ew/GY/X8Aub5xmg/3kJv1mJgYb3SeepuBfX1mhBAUa6MzhKB8THluYH
         hHlhgT0nr8V8B+TqVVCTI2uzCSlXJP8WumgaHHVO8/uGAVTcpp+pNn6bRew2aVEy+pVx
         TlBxD1SbwEMfOvtSkci1Ed/ifdaDRr897r/AH3bdtvLt0zA3piyRFgJRmJBiq4d0iwVg
         E9XziXUTJKLQpfP6tzINdhf7n3gbFHS5BZb2mEMQJgyQDoGPVNSdL7um+rWTYA3pSoQx
         G1v2ebdxDk8KcU9dfHE+dPi90X4sHXZ/5KPQeO+AtMZAaYt1yI9db8HrN80Bx5l4xwHJ
         Q7sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=7zXY/Cj2mSI/UmuMlsXE2MqaHNmLVHdLxVvW5hpvAls=;
        fh=LEjuMvkJHzG9a7kQxEw5zdUfo5J4GcAyP/2TjYD9OLQ=;
        b=cs7zJR1Lh9PbtFm10G+qEXZ0ShL35QEnGD+KqJsRUu4BIJUbk/HqLe2kpaXM7CkTKx
         Cpw78uBgp13bvkChChzo4Uwi6EmwK3EY7uGNffEz6CLDPNbZ/MHBLAtPw3dTW9oLHRez
         cCmhKt5GwoI+wIvwM0e6lysgGxji8xeVmlT0dFkb2b0N2GeAGRE4NdB5WeYKCbFD73I0
         Wf17YkNH6W/2RU8TRWd6XvGFxJfmZu1mb82kZKBgEKK/Hpvz+Bbu/OOu90US95Xya39/
         QzQPk6BsUUXB05yvSksMElhtikfuhScDCEwSje3gsTLd5Xxeoct6+1ePUp9WGv8qOHry
         hhJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UUwHR4aM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UUwHR4aM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f57e384fcsi1952675e9.1.2024.09.30.01.47.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2024 01:47:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6CB2D219DE;
	Mon, 30 Sep 2024 08:47:29 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 32A1F136CB;
	Mon, 30 Sep 2024 08:47:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id FML4C6Fl+mY/IgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 30 Sep 2024 08:47:29 +0000
Message-ID: <d4219cd9-32d3-4697-93b9-6a44bf77d50c@suse.cz>
Date: Mon, 30 Sep 2024 10:47:28 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Guenter Roeck <linux@roeck-us.net>
Cc: KUnit Development <kunit-dev@googlegroups.com>,
 Brendan Higgins <brendanhiggins@google.com>, David Gow
 <davidgow@google.com>, "Paul E. McKenney" <paulmck@kernel.org>,
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
 <6fcb1252-7990-4f0d-8027-5e83f0fb9409@roeck-us.net>
 <07d5a214-a6c2-4444-8122-0a7b1cdd711f@suse.cz>
 <73f9e6d7-f5c0-4cdc-a9c4-dde3e2fb057c@roeck-us.net>
 <474b0519-b354-4370-84ac-411fd3d6d14b@suse.cz>
 <CAB=+i9SQHqVrfUbuSgsKbD07k37MUsPcU7NMSYgwXhLL+UhF2w@mail.gmail.com>
 <fcaaf6b9-f284-4983-a8e3-e282dd95fc16@roeck-us.net>
 <CAB=+i9Ty5kUUR1P_ahSfReJAOfhQc_dOdQ=9LBZJ4-=1kEOVXg@mail.gmail.com>
 <f844a422-55a6-494f-875a-b118d1264395@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <f844a422-55a6-494f-875a-b118d1264395@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 6CB2D219DE
X-Spam-Score: -3.01
X-Rspamd-Action: no action
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
	FREEMAIL_TO(0.00)[gmail.com,roeck-us.net];
	RCPT_COUNT_TWELVE(0.00)[30];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[googlegroups.com,google.com,kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:dkim]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=UUwHR4aM;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=UUwHR4aM;       dkim=neutral
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

On 9/26/24 14:54, Vlastimil Babka wrote:
> On 9/25/24 14:56, Hyeonggon Yoo wrote:
>> 
>> I don't think this was a noise :) IMO some people want to see WARNING
>> during testing to catch errors,
>> but not for the slub_kunit test case. I think a proper approach here
>> would be suppressing
>> warnings while running slub_kunit test cases, but print WARNING when
>> it is not running slub_kunit test cases.
>> 
>> That would require some work changing the slub error reporting logic
>> to print WARNING on certain errors.
>> Any opinions, Vlastimil?
> 
> Yes, we should suppress the existing warning on kmem_cache_destroy() in

Done here:
https://lore.kernel.org/all/20240930-b4-slub-kunit-fix-v1-0-32ca9dbbbc11@suse.cz/

> kunit test context, and separately we can change pr_err() to WARN() as long
> as they are still suppressed in kunit test context.

Can be done later separately as it would be out of the scope for a rcX fix.

>> Thanks,
>> Hyeonggon
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d4219cd9-32d3-4697-93b9-6a44bf77d50c%40suse.cz.
