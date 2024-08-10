Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRMY362QMGQEXYSLQNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AF4694DE8A
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Aug 2024 22:23:35 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-530ad977bccsf3608125e87.0
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Aug 2024 13:23:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723321414; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZRg6xnnmKVdEG8ATy8j8+a7Jh45KvTRZ3PPfeDNOm8YvBOe/kFL3Fj/GkzZxSYzB/7
         CxJU+Me/bzfSyPcxMrd1A7cTmmBd38oTED4mPCv02dKFDxG8O2dmb9DXMvYhIt4mSq6o
         alGfsE8cjSwllPj6dWCSVnoVNH7Fp2/+iUVnJk9dy+IKVvSaMTTNF5miNN1RC/AW36Yn
         wWFFFlcAdbR1Z/BqZ6s2LDQAODZqEzvQgArwenhjQ2L0LqWnFLu8YFhsy1mkzwneGUR5
         W8Dz4QF3mGuvs5910u0jc5ESUecwmFPoO2ECeQg+xgM9cZmg5z+uTUypkbYi6fdRZxO3
         8Seg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=kZfHn7DvnVJ86kkzvlkUOMJNjC3++EBvrqo3lgmpTvA=;
        fh=GCHiaqrOCiIax1mHk82UcSBVJCC1ev5Q3G2/D6/h2E4=;
        b=CfEbzUplcmjc+a+o3Ia4bP1gfcegf1VPJXalvm2/vacLF6TOTJFHvY3gjjzMatoqZe
         BOX/Vjkr07+PCwBtLC54Y0tO9OkJY5oiyG6qhjiUvJ0/sTrJ2PAt7MDfECQxIfsM3Hdi
         cycc2y1zgnd7XiAHwURcT8/+jL5uOVtx77KQmjZ2uYqGUM+dCANWbknor1BoXo42Pu3c
         aqNPYRtP6DUmFRT+No2Y0c/dEipPRuBKA0HR2xJDVJC5v+AQtlno6ROfMa+1m3aqevmq
         U5vEWDJRxowVXaeiGbTrlErT5JyiTW1LV0X4qCKPEsy5jpfk6wDo+qfLHfXUqJMq1mr1
         C9Sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TGmFIMzF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TGmFIMzF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723321414; x=1723926214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kZfHn7DvnVJ86kkzvlkUOMJNjC3++EBvrqo3lgmpTvA=;
        b=SOsVFO08tvbWEWdtrpIa7FY6uKaU851mzjPZLvqfQsw/LnM5VT9tjWl0oriUKFDpkg
         3rU2QV1SyZklc/IS8xJ8pzKFd3SBNbIoTbpUibACC5nOF0+6bdJ6lbFwfVXVmUUVcKDB
         7pGrw/leBGBRuLkZ3PtTMy22Fm86Gu/KWv1h52Ohf7W865JlPiA4/VymF9Ra08IAA/rs
         JApEPXM+GGgZdhwYGdeMqIimGtoEV3NWOjn1911t1hMpmyLbJfoWdJselHwSXWRPmso9
         Gl838qNJC1Aix+dt/JfFY4YIjra2dOlHH3FOoshkPt8h5tc2nixVALuJ2KSRIct4QnJM
         u+ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723321414; x=1723926214;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kZfHn7DvnVJ86kkzvlkUOMJNjC3++EBvrqo3lgmpTvA=;
        b=a9mHRaO5E627x8JRDs+YyoiKsyh9SrtS26U8GRGdHY2TAkRRowVW5xiqQTr6NZ4Nk9
         0bewNcx439mPYpjsI9fKLTMVl7kFXK1atSXM3Lhoc6jnF0Omb3FecZALIpGI71Ffcgzh
         3nPVxEz/015jMbf6t/3nC2tr2PeKGaCYAX4NSBwMZYovM6voERPiGbHPqX2FduX7lRXL
         JrZZm7VjM7p3ftgUMGuWJHTLW/nz1RMiDZ1mJFl4F/duxqkg9TrxHPHnwoDAV8mfaI+H
         ANt3HABUkuahPJTEx5ltdCb4hHbd2OWpT4CZZ0/qMz8utiCh31VPFudEPzu9ZRveUSMY
         LRzA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/cp902X0FMC2RRpy1PG0XK7Z6jOXE2AfBAZa0I9PWLOzyBZgDyaDdw95ZIvZb9ecudXlsEA==@lfdr.de
X-Gm-Message-State: AOJu0Yyv/DJDwB1RcaQb3mH6kUfmgumrMZFCtN7vsnKbUcUAjoxElS59
	7sDd6HEqh2yLOpqAlH1k6xExWZsNuVLVYt8dTzaM2vH8pm4E3t8D
X-Google-Smtp-Source: AGHT+IEKRDmYfApXEWu+FzUrJua5MgS4JenYCc9+3kTEH34Jx+1j0+JibeBqCSBZhtrU4FUMB+5oEQ==
X-Received: by 2002:a2e:9450:0:b0:2ef:2344:deec with SMTP id 38308e7fff4ca-2f1a6d6ee7amr35602511fa.45.1723321413523;
        Sat, 10 Aug 2024 13:23:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a46:0:b0:2ef:1eb3:4737 with SMTP id 38308e7fff4ca-2f19bb19e68ls14299581fa.0.-pod-prod-03-eu;
 Sat, 10 Aug 2024 13:23:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGGkxJUNb3mpNLnoLzqHR0OmG3QMGXlPsSeZ0d1HlSOQK+UOxAbUBQsF8PVyM164RqmyLfOVgcu6Y=@googlegroups.com
X-Received: by 2002:a05:6512:2243:b0:530:aa05:eb7c with SMTP id 2adb3069b0e04-530ee9d1ac6mr3787018e87.38.1723321411247;
        Sat, 10 Aug 2024 13:23:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723321411; cv=none;
        d=google.com; s=arc-20160816;
        b=wXqdGQg4AUamyF/Ba/vjT6uJPDxPNvIjzR3PMLGZTGMKCfT/rGIMA69vaLOaFKfnC2
         iGH2bIONImmqfEYZa5awbaXeG9Zi5Pb0qiHmoEUjGFJvi8smA3cru7C/JNh918jzmEUr
         OUXDMbssGK2Zd0myXnCCNsdxm3FrMBNBmSymmzMEOM5CVZZZETMiJ4ZQTR/0YZXCqjAE
         vrGKOVn8Pv5QYjDWlAkL2hIrDyn9YOnfCLzRy0nfSJRgXQRN/PZB7QtK5ZvabAstgLE+
         QaHD4DiTwo/j0xwNVgOJXziQrn1M5NuNN584EcsV5PfSNwxYjPvf1kDFkebsZZnaniUK
         ubLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=dU5FpYeZ5zWDwOs2yWnFMVpSiFRDeYnnwFffftni6eo=;
        fh=bYNzqWX0jZRFgkY1gBz1X/oHjqYXClGX4GJe0xYqxlo=;
        b=o/TMrdAIyzmn4bNiY5z6N1Q+t6wrgRFsqWdsJhmeFeq3nek2e3/dxLd43cfth/6+K0
         g++HNVflXUTrWsa3g04I5qEunj2BYZVW/XrM3SM7Y7//jahdP+UCSzVGY7JFzRUntTAY
         vm/TmWH3J1CSwEFQk3vspFVu0AGux8b78PzDBXvrkvcgeNXms/0XRWCGjPtero1YQJQS
         R8vFRU2f0HX+UG45AMZ0G9NDp229JguPbg3052G61gsMcHSEE2xf3RW4Ic6SSzyK7YU7
         FYv98fW23dhjlcr+1mAylH40D9AUcVyub205Kl+Y2m4GjZcPH/OxYAu9z6uwkbsPmgtV
         oYdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TGmFIMzF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TGmFIMzF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200efc3aasi45622e87.8.2024.08.10.13.23.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 10 Aug 2024 13:23:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 516EA1F86C;
	Sat, 10 Aug 2024 20:23:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3997E13704;
	Sat, 10 Aug 2024 20:23:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id O9/cC0HMt2bmQAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Sat, 10 Aug 2024 20:23:29 +0000
Message-ID: <167495c0-187b-4fb8-8de5-63db0aef193e@suse.cz>
Date: Sat, 10 Aug 2024 22:25:05 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [-next conflict imminent] Re: [PATCH v2 0/7] mm, slub: handle
 pending kfree_rcu() in kmem_cache_destroy()
To: Andrew Morton <akpm@linux-foundation.org>,
 Stephen Rothwell <sfr@canb.auug.org.au>
Cc: Jann Horn <jannh@google.com>, "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Mateusz Guzik <mjguzik@gmail.com>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <54d62d5a-16e3-4ea9-83c6-8801ee99855e@suse.cz>
 <CAG48ez3Y7NbEGV0JzGvWjQtBwjrO3BNTEZZLNc3_T09zvp8T-g@mail.gmail.com>
 <e7f58926-80a7-4dcc-9a6a-21c42d664d4a@suse.cz>
 <20240809171115.9e5faf65d43143efb57a7c96@linux-foundation.org>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <20240809171115.9e5faf65d43143efb57a7c96@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spamd-Result: default: False [-2.79 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	TAGGED_RCPT(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[google.com,kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux.dev,kvack.org,vger.kernel.org,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email]
X-Spam-Flag: NO
X-Spam-Score: -2.79
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TGmFIMzF;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TGmFIMzF;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
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

On 8/10/24 2:11 AM, Andrew Morton wrote:
> On Fri, 9 Aug 2024 17:14:40 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:
>=20
>> On 8/9/24 17:12, Jann Horn wrote:
>>> On Fri, Aug 9, 2024 at 5:02=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz>=
 wrote:
>>>> On 8/7/24 12:31, Vlastimil Babka wrote:
>>>>> Also in git:
>>>>> https://git.kernel.org/vbabka/l/slab-kfree_rcu-destroy-v2r2
>>>>
>>>> I've added this to slab/for-next, there will be some conflicts and her=
e's my
>>>> resulting git show or the merge commit I tried over today's next.
>>>>
>>>> It might look a bit different with tomorrow's next as mm will have v7 =
of the
>>>> conflicting series from Jann:
>>>>
>>>> https://lore.kernel.org/all/1ca6275f-a2fc-4bad-81dc-6257d4f8d750@suse.=
cz/
>>>>
>>>> (also I did resolve it in the way I suggested to move Jann's block bef=
ore
>>>> taking slab_mutex() but unless that happens in mm-unstable it would pr=
obably be more
>>>> correct to keep where he did)
>>>
>>> Regarding my conflicting patch: Do you want me to send a v8 of that
>>> one now to move things around in my patch as you suggested? Or should
>>> we do that in the slab tree after the conflict has been resolved in
>>> Linus' tree, or something like that?
>>> I'm not sure which way of doing this would minimize work for maintainer=
s...
>>
>> I guess it would be easiest to send a -fix to Andrew as it's rather mino=
r
>> change. Thanks!
>=20
> That's quite a large conflict.  How about we carry Jann's patchset in
> the slab tree?

OK I've done that and pushed to slab/for-next. Had no issues applying
the kasan parts and merge with mm-unstable (locally rebased with Jann's
commits dropped) had no conflicts either so it should work fine. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/167495c0-187b-4fb8-8de5-63db0aef193e%40suse.cz.
