Return-Path: <kasan-dev+bncBDXYDPH3S4OBBM7JRDEAMGQEN66RUJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 30510C1BB3A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 16:37:25 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-63c251265absf6921238a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 08:37:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761752244; cv=pass;
        d=google.com; s=arc-20240605;
        b=XMbbz1dsQXGFQ+OU6bsT75EsoSe7zfXmTASM+rpgfOC5PQRZoyJFI8SIIr77EoeMDd
         0bgLOt7WJHMkEjK0ZoaD1yYqWBhUxy4WtAB+20Z9JfgrHHEhavcYyQEJXReYLmaByYFm
         5rOn9ewKqIMPPrRtkMiI+HtzgJALKKK7cLzQECv222nPc6z86smIJH09AmEm/vM2f9jW
         vrfJ2FKYfd3U4S3OwqVU2cSD1Io748qFr3/j95+O7R3RjZTkR9sitnRkkcF+WrfPezhy
         hRLhWKgj4VMgL/US/a3+RSHoyvEKGOtg2fFMNxvAN5KCxzbule4/VmuMQCnx40a8Sl7U
         wHnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=+aHQn6mATLOtUPHodocKYUul2JTg5MvsNgwX8FTAU1A=;
        fh=CgG4z2sROAJ0YQVyNCj7b7qADn1q+wNHOvUb+eca16A=;
        b=Suu1Q0qhXD1cCaFSrgtsdLhzn1aQxsp3eJqNtlBTi84l52oTdFvXbbpxxrjZ1NJoEq
         y7hRGdP2T7JazNvserPbaeHCOv06Cz28729qapDHEzgM8JOUjNhElgdS3FqD2LWpMFhN
         m3/TBiuMdziIWcrXOCBoG4W680fVmFXiVLiNlhJSkHdoDq+4K91Yjt9LY+/4EBTkwxNa
         DZhPaCTPiBZmTRB4lzbI1b2TZ1RvWNhJsB7Dq3IGIR6HSQ+cUueUTCSgK75HD1RjgyV4
         RZokex8jNdSd7WTS0VPlpN0pMjrTvEyzsv8iT7jebgRxYrFQkUrIhz8kl+Dl1jiUcnfE
         QtGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Fgmgu+IT;
       dkim=neutral (no key) header.i=@suse.cz header.b=Uu6lBP9H;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Fgmgu+IT;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761752244; x=1762357044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+aHQn6mATLOtUPHodocKYUul2JTg5MvsNgwX8FTAU1A=;
        b=mZBF0DmJWrq5bSo4fDrph2qHry1XqhHT5sFq5KZVyBS+iq7qDigQRZzcESmknRD85f
         9ZxIrl+PDiN+gofWN69Q+QQi75wwjcXaxnioI+qpOGk18Eqj9URnN4YAoRjpzY/UXwLB
         j2u+r1n0mp9Bs6NDQHaWpfeu9SnNd0JEtAwmsPPulXFuO3zE93Gsfvl53HPK9CVlAdUN
         7YEtZpLBH+AMEEiLzmfLAkiJFvMqXqLk5r3N87yHOSiTRvsAHa8xhqK75RI/gmsgv1kD
         1P8XvHXcw/uSgiYo+5vuY0hhZQL7x8rqGkkkDhkQ9bD2GVr25JCO8o/8KuvwCKFUNAf2
         d7Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761752244; x=1762357044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+aHQn6mATLOtUPHodocKYUul2JTg5MvsNgwX8FTAU1A=;
        b=QIIYx9LNcp9jhWZjMqfennv2gnvE8EI9GeSjb4zTbTRECfX0BfP7yZ2q42q43KXi7m
         BD2e1MUmZ6WQ68Ix2TIhhYODY2H5KSsM86nrxkl01c4Pdrk7q4B8jcm0A7qVLZu7n1yX
         J3qqKEV32ZboMUXZAOxKcnAAcpz9kesbBg4ZgQRnNBmRNAxTpCzao36CulrGL/JMkDPK
         XF6/F1rmqxG/By9YVEFaTQSsXqsNjC82nchL4tUi64YDHFJ25pJoYc5s4O9c3a7FlAh4
         TVEaHAcIS+mQU0yL5anqLUkKPI9empRmliBya/xUqANq/ecPAg0idkknmDl71zVzc0cL
         3WZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5HSKk3pUm6BgXJ3CHy2uHEjIHdKWwe1x7yDHjqhpcIZ4Q8PV0zFEYH8mxwX/WQYCOr5ON6Q==@lfdr.de
X-Gm-Message-State: AOJu0Ywv4qCh9dDLzo5G2NuTxyV842eK3EHKG3xE24tt22oisg9E5Hni
	KOD3SzcRh30cEbqeZK4xtxUVAOJokf6uMWVeSO+UO3Xp/2WQl32vsDAS
X-Google-Smtp-Source: AGHT+IGCAwiLP9/wOrUQ44Ix5vKk3Tg538Q+7VncA3p0QpyYw7y4ygEnxOGLAtL/68JoI1AtfumC/w==
X-Received: by 2002:a05:6402:13cf:b0:63c:2750:ef4c with SMTP id 4fb4d7f45d1cf-6404424a660mr2224688a12.19.1761752244505;
        Wed, 29 Oct 2025 08:37:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YUIcVo2d+JZ1yQX+xoUjH1IGJmtdxDrRn+Kt3Ks33tEg=="
Received: by 2002:aa7:d153:0:b0:640:342e:51db with SMTP id 4fb4d7f45d1cf-640342e5bf9ls397890a12.2.-pod-prod-05-eu;
 Wed, 29 Oct 2025 08:37:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxB2NaJRrn2O1P/ba7wGrOVhcU2oyTW5orKVJMmVg3WDllko8rQQsOU8qfFT1cuNn02D3Sa22/zn8=@googlegroups.com
X-Received: by 2002:a05:6402:5112:b0:633:4b9f:c741 with SMTP id 4fb4d7f45d1cf-6404425e9bfmr2274120a12.30.1761752241889;
        Wed, 29 Oct 2025 08:37:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761752241; cv=none;
        d=google.com; s=arc-20240605;
        b=PJlO+9Y7qtef1u7l1wdIUFwO0U1nMwZgyV9wMXc2n1CoRf9gNzuijk4jfQjVl2Uxpz
         bC/TKz/0Ku1WxksncKBfHzL/DIz2lFmxn+vfS2PORJr012g/ufuVDAjvlnXqpimYnD5D
         kL8ziRwtN+pGpOw/KpVtYiwHJrPTlUr6I3zaXFZ+aH6Xl1/4N93WwVziP+tBH1K+816Z
         71kSaGM/A8QN76o6PK1KlpyeT9lpt4h6UPov+DbjWDiof8pOkkXykyKqEi8G36xGl//q
         DpIs18IqhOiSATUUKe30O7bEjgI5xvXNdQJ2iLn2XSbl+Ocphjtrrk9oOSDdMwJk3y16
         vkYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=ENJQWumhQFBRbBzZ2XQ78O0uq9YHFwzP1q0R/p8ERLo=;
        fh=ZkncHXpnbLWcLI4CpJ6uugsCcSSvTK4Cn+vNUpK7HFk=;
        b=QtQTywJKn1Uo5Oa27B6mlanRctVqJfv8PbUut6HWI4YjKsizLgNu4kHDhqLbHV7dfa
         0Rzc0hZs6iTpPFUYzPYvthz5rP+YVFQrVhyJuA/vuLghM9SpVm3/Ao6EhGhg/C6Pi4nQ
         JLdjbxXAYYoWM9P23Trc2aa51Xaeo1S4Eu8Q0UdxR7ly2pHHh+EAfgonrUGJTwqWhwTr
         ie1QYSxzz/Dvg7OrlDmU6PPOAh76l9p6oDLY62Zf7gv7ZveV/tA56m+DqTdtkwzOxMju
         WZqIooKdLEPU81IeECmDN1YscpkS2eP3hqLa0hSeGg+/peykBaoh5cJ890ONLdRq6NCh
         tV0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Fgmgu+IT;
       dkim=neutral (no key) header.i=@suse.cz header.b=Uu6lBP9H;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Fgmgu+IT;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63e8147e937si416013a12.3.2025.10.29.08.37.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 08:37:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6BB5120FD0;
	Wed, 29 Oct 2025 15:37:21 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4D5DF1349D;
	Wed, 29 Oct 2025 15:37:21 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id aaF/ErE0AmlyeAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 15:37:21 +0000
Message-ID: <90f21264-b227-4a83-9944-39d3e0ea40dd@suse.cz>
Date: Wed, 29 Oct 2025 16:37:21 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 03/19] slub: remove CONFIG_SLUB_TINY specific code
 paths
Content-Language: en-US
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev,
 bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-3-6ffa2c9941c0@suse.cz>
 <CAADnVQKYkMVmjMrRhsg29fgYKQU8=bDJW3ghTHLbmFHJPmdNxA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQKYkMVmjMrRhsg29fgYKQU8=bDJW3ghTHLbmFHJPmdNxA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCPT_COUNT_TWELVE(0.00)[16];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FREEMAIL_TO(0.00)[gmail.com];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Fgmgu+IT;       dkim=neutral
 (no key) header.i=@suse.cz header.b=Uu6lBP9H;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Fgmgu+IT;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/25/25 00:34, Alexei Starovoitov wrote:
> On Thu, Oct 23, 2025 at 6:53=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> CONFIG_SLUB_TINY minimizes the SLUB's memory overhead in multiple ways,
>> mainly by avoiding percpu caching of slabs and objects. It also reduces
>> code size by replacing some code paths with simplified ones through
>> ifdefs, but the benefits of that are smaller and would complicate the
>> upcoming changes.
>>
>> Thus remove these code paths and associated ifdefs and simplify the code
>> base.
>>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slab.h |   2 --
>>  mm/slub.c | 107 +++----------------------------------------------------=
-------
>>  2 files changed, 4 insertions(+), 105 deletions(-)
>=20
> Looks like it is removing most of it.

The special code, yes. But the savings from avoiding percpu caching are the
most important anyway and they stay.

> Just remove the whole thing. Do people care about keeping SLUB_TINY?

They did when SLOB was being removed. We can always remove it completely
later, but this code cleanup is enough for me not to complicate the further
changes, so I wouldn't want to put the complete removal in this series.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9=
0f21264-b227-4a83-9944-39d3e0ea40dd%40suse.cz.
