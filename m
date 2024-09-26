Return-Path: <kasan-dev+bncBDXYDPH3S4OBBFVT2W3QMGQEKUSMKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id D477E9873E5
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 14:55:20 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2f761cfa5c8sf6679391fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 05:55:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727355287; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bie1M6Bz8aZ/dINStxcGt3YScmoKjqgTGgzZix92AS5vcUc5oMwwRDn3Vm9ImRfJuw
         FgPlhbGEAJbV3tvYIBQ7kaaNiMoPBrppatqO/ooFAOvFgty+ApKJ8AF7qcKzMpfPPKRw
         nqIIhUT5wb0v1p4zcADrihJvCwhjvy2GfFNOsIAWfMKqi1eOmHg+A461ZFQVhPLecoxU
         y378PYInSqw+qgFmCo4/qDZtgtCRD9uC6nm8P4N9FplWZ2OIPCb14W66HifTw04QYG3B
         632bIkGqwZqm2Mpdz+1FZXewdgYX1/rwtkO7mSUd5F+znoDdrQgIhgwf3x2749BtVOBU
         oL8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=hv3kusKFpiBhsIpTGzpwYjCHhYkIbaT/w4nabd2uNPo=;
        fh=64j5Rxc4m6Wxo0dgzcc+c5oofF9ggj3VSYFlDb+7b9o=;
        b=TmQ0gD9uMBY5eASZobq/IRr0LWN5Qso4eGKiqNO4qhSj/uVLsKqnm3xgoPm/wISEHZ
         MaLNtmxBD9hQuN69n8e7xJksD2lekOLHPiZJ6jiGwbcCVuRRG3g09imFcgOCKwAIxdZh
         oUygIhznSLDetzKmdEA7PAsBE7Tl8ZGuWwhnBBnixUWyOr032hhEf1b4rI8uQtSkwgkr
         POEK/duQQzikh6nK+KrIVbFglbIru8uedWaUrCBWjKE9IUW/T77TT1FYERZjMss287fw
         R9XsqU/zWx5bkHApEQfPyzR95q9cDSpPbs4GNxfDtGv6xOxzVRAHjCrNP9CphD+H6VW9
         3eXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="P/gG0Shz";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="P/gG0Shz";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9vUikMBQ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727355287; x=1727960087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hv3kusKFpiBhsIpTGzpwYjCHhYkIbaT/w4nabd2uNPo=;
        b=SYu61Xl0DVgB8YY73ajEAdoSAsCPqF+X6qQxcWD0n7SKku5EqGmT/f8ts5stnH8C4x
         Vs4trYpVm69pDUN6nGkwYVOKt+z2FQZxp5QpHo0YeTbAUwhooXKRieCIAqyNu+clhaRP
         /rD3ZOz3W9AUqEG9+WgglvTzKW2Gqdc6lXoHQ7OgQ6HfHCMDr2WtAqgDM+juOE6X3d4S
         nx3BVJsO3Shn3wXVNwG5yIvL5omZBCdgx0TcZZAYL4vadnFyg21mNACeIQwrpDRRRnNC
         X4I45X/38qNYK7O3a43APfI6BZ0j7PsP0KhZpkLmbGgB2RryfcwvPw714aomKcSTktzH
         DdRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727355287; x=1727960087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hv3kusKFpiBhsIpTGzpwYjCHhYkIbaT/w4nabd2uNPo=;
        b=UFryKkdT1Og2TXfKUKnhB+ET0cMHs9Eovjkwt9GpccUf2B9EtI2BAIII79W+jRgeD2
         VTu0HyQXvBijfDl8cBmfycOQan+cdSi0HCBXxD23J+KxEj1KpTBNJ75CN0rAEE2qQlbs
         Tzhdx76bwk6tdjCTWQAroBcfEOnscAsjSyAvZHWkroTvqy6eIasCw+Qhx7Du817bo88T
         VRNCtE4PTPa2ma6tirPh+ldLqH41cC7huI8V2z9X0E4nWlPVjA8uY7d+hYaJyky+6oEa
         VXNebUJdjFtuK/WGH4AAX+vi936lB/IzMIca8tC/CoKhCe6YIJFWGxXZ8m0shyw4INUz
         T/+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUnM5G7HAjoGmst78j0Zj+ElA2DGBUxjHV8XP1B+1HhGscTVExnsEcrXlSlgA75mJ3SlkPuYA==@lfdr.de
X-Gm-Message-State: AOJu0YxMm6kIGF40znG0d8v4XcnbFteiPk+WW5X/AoT9cXpf+2RtNx/q
	JpW9XWADICe2tW05SyYb0sSq2AL9UoNsPq4IUUJTPZVidb+8pXeX
X-Google-Smtp-Source: AGHT+IHhxLxZfQZgAtmsIErWwGjm1WHWlW3o+RhiOVv9CZBPhzmLh5CGJBATSek+ZTOTibJVzPDQBw==
X-Received: by 2002:a05:651c:1992:b0:2f7:6e3a:7c1d with SMTP id 38308e7fff4ca-2f915fde3camr36926351fa.15.1727355286477;
        Thu, 26 Sep 2024 05:54:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2ac2:0:b0:2f6:5e99:1467 with SMTP id 38308e7fff4ca-2f9c6dd732els2763581fa.2.-pod-prod-01-eu;
 Thu, 26 Sep 2024 05:54:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5gLnIOKR1XnAnNHvNpHVIg0mLUZ+EWokDeKW4pKp9XkxATTCufYqsfV/Nz9WKxFvO2o+hbJ40Rtw=@googlegroups.com
X-Received: by 2002:a2e:4e02:0:b0:2f3:fae3:83a7 with SMTP id 38308e7fff4ca-2f91ca70fadmr27117511fa.43.1727355284183;
        Thu, 26 Sep 2024 05:54:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727355278; cv=none;
        d=google.com; s=arc-20240605;
        b=N5iT4PuhWqHbw7sxLeevB0+L4ck9j3Xljrm+GQB5MPv4w8sDKoNSeZGjArNQozEpCY
         2lheqHBiMMuW5bJpbbiuITtR8j0RSFVcx//R4VON7SinlzYcM4mj4NWZr4FKlzlAJhiE
         nGmKGQK2aWuWq/W3x/63pkqpjnAyWzB8CaBzx1buElC4u1cG7ktl0yvlRox2+/xnpoDz
         6l0o5ZbD5flRklxfM9T91UIupLq7pG304FIhGZXHR2/JC+6dhEhGUA2WIhkGy1NiOwNq
         Sz++pZFA5+rA6bLcy33K/hQdVavOOqULu7/Dex+FhGEgerTCDwYlY32DOj0O8HqJl5PH
         6QHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=bMhp2djDzbzLsssLY1csuVYy8r55JqJ66r6qRBhdYpc=;
        fh=LEjuMvkJHzG9a7kQxEw5zdUfo5J4GcAyP/2TjYD9OLQ=;
        b=ZbPPjfaA1FnkpLZN7gc+JUQXM/STRNUIAK4Jk/tRCtlZ0m0E2YBEqrDkYKaP2GSMms
         XRsQWWiMWCciR1u7D4CtZ0INZ5VH+XzHAQz+sZ54iS9jCc0UPFuK5AF8PGlT6tK4gkB0
         zjJjlBfvDfaG4taiFosdEG/E/Jijs7quliWxRiSkqwRYyu6JprxDLl6S2pct9vd+R+9w
         wm5UYMMY4Q3XlVSMmY2iAUBnlsypP4gqnX9djRORTDRy0Hg3ps9YQqvtmG2Hmbd7mMD+
         nET2PmpWeGQ3iTsYd2GA4vOPY1XMDgoe+BxawpCg8gHXUNRk2WT9fa1c/v2ZC84gZHQj
         E2FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="P/gG0Shz";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="P/gG0Shz";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9vUikMBQ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f8d278e65fsi1380271fa.0.2024.09.26.05.54.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Sep 2024 05:54:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 22F3C1F897;
	Thu, 26 Sep 2024 12:54:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D6B6A13318;
	Thu, 26 Sep 2024 12:54:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id jg+rM4xZ9WbtWgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 26 Sep 2024 12:54:36 +0000
Message-ID: <f844a422-55a6-494f-875a-b118d1264395@suse.cz>
Date: Thu, 26 Sep 2024 14:54:36 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
Content-Language: en-US
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
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <CAB=+i9Ty5kUUR1P_ahSfReJAOfhQc_dOdQ=9LBZJ4-=1kEOVXg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -2.80
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
	TAGGED_RCPT(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[30];
	FREEMAIL_TO(0.00)[gmail.com,roeck-us.net];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[googlegroups.com,google.com,kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	R_RATELIMIT(0.00)[to_ip_from(RLtsk3gtac773whqka7ht6mdi4)]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="P/gG0Shz";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="P/gG0Shz";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=9vUikMBQ;       spf=pass (google.com: domain of vbabka@suse.cz
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

On 9/25/24 14:56, Hyeonggon Yoo wrote:
> On Sun, Sep 22, 2024 at 11:13=E2=80=AFPM Guenter Roeck <linux@roeck-us.ne=
t> wrote:
>>
>> On 9/21/24 23:16, Hyeonggon Yoo wrote:
>> > On Sun, Sep 22, 2024 at 6:25=E2=80=AFAM Vlastimil Babka <vbabka@suse.c=
z> wrote:
>> >>
>> >> On 9/21/24 23:08, Guenter Roeck wrote:
>> >>> On 9/21/24 13:40, Vlastimil Babka wrote:
>> >>>> +CC kunit folks
>> >>>>
>> >>>> On 9/20/24 15:35, Guenter Roeck wrote:
>> >>>>> Hi,
>> >>>>
>> >>>> Hi,
>> >>>>
>> >>>>> On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
>> >>>>>> Add a test that will create cache, allocate one object, kfree_rcu=
() it
>> >>>>>> and attempt to destroy it. As long as the usage of kvfree_rcu_bar=
rier()
>> >>>>>> in kmem_cache_destroy() works correctly, there should be no warni=
ngs in
>> >>>>>> dmesg and the test should pass.
>> >>>>>>
>> >>>>>> Additionally add a test_leak_destroy() test that leaks an object =
on
>> >>>>>> purpose and verifies that kmem_cache_destroy() catches it.
>> >>>>>>
>> >>>>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> >>>>>
>> >>>>> This test case, when run, triggers a warning traceback.
>> >>>>>
>> >>>>> kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still has object=
s when called from test_leak_destroy+0x70/0x11c
>> >>>>> WARNING: CPU: 0 PID: 715 at mm/slab_common.c:511 kmem_cache_destro=
y+0x1dc/0x1e4
>> >>>>
>> >>>> Yes that should be suppressed like the other slub_kunit tests do. I=
 have
>> >>>> assumed it's not that urgent because for example the KASAN kunit te=
sts all
>> >>>> produce tons of warnings and thus assumed it's in some way acceptab=
le for
>> >>>> kunit tests to do.
>> >>>>
>> >>>
>> >>> I have all tests which generate warning backtraces disabled. Trying =
to identify
>> >>> which warnings are noise and which warnings are on purpose doesn't s=
cale,
>> >>> so it is all or nothing for me. I tried earlier to introduce a patch=
 series
>> >>> which would enable selective backtrace suppression, but that died th=
e death
>> >>> of architecture maintainers not caring and people demanding it to be=
 perfect
>> >>> (meaning it only addressed WARNING: backtraces and not BUG: backtrac=
es,
>> >>> and apparently that wasn't good enough).
>> >>
>> >> Ah, didn't know, too bad.
>> >>
>> >>> If the backtrace is intentional (and I think you are saying that it =
is),
>> >>> I'll simply disable the test. That may be a bit counter-productive, =
but
>> >>> there is really no alternative for me.
>> >>
>> >> It's intentional in the sense that the test intentionally triggers a
>> >> condition that normally produces a warning. Many if the slub kunit te=
st do
>> >> that, but are able to suppress printing the warning when it happens i=
n the
>> >> kunit context. I forgot to do that for the new test initially as the =
warning
>> >> there happens from a different path that those that already have the =
kunit
>> >> suppression, but we'll implement that suppression there too ASAP.
>> >
>> > We might also need to address the concern of the commit
>> > 7302e91f39a ("mm/slab_common: use WARN() if cache still has objects on
>> > destroy"),
>> > the concern that some users prefer WARN() over pr_err() to catch
>> > errors on testing systems
>> > which relies on WARN() format, and to respect panic_on_warn.
>> >
>> > So we might need to call WARN() instead of pr_err() if there are error=
s in
>> > slub error handling code in general, except when running kunit tests?
>> >
>>
>> If people _want_ to see WARNING backtraces generated on purpose, so be i=
t.
>> For me it means that _real_ WARNING backtraces disappear in the noise.
>> Manually maintaining a list of expected warning backtraces is too mainte=
nance
>> expensive for me, so I simply disable all kunit tests which generate
>> backtraces on purpose. That is just me, though. Other testbeds may have
>> more resources available and may be perfectly happy with the associated
>> maintenance cost.
>>
>> In this specific case, I now have disabled slub kunit tests, and, as
>> mentioned before, from my perspective there is no need to change the
>> code just to accommodate my needs. I'll do the same with all other new
>> unit tests which generate backtraces in the future, without bothering
>> anyone.
>>
>> Sorry for the noise.
>=20
> I don't think this was a noise :) IMO some people want to see WARNING
> during testing to catch errors,
> but not for the slub_kunit test case. I think a proper approach here
> would be suppressing
> warnings while running slub_kunit test cases, but print WARNING when
> it is not running slub_kunit test cases.
>=20
> That would require some work changing the slub error reporting logic
> to print WARNING on certain errors.
> Any opinions, Vlastimil?

Yes, we should suppress the existing warning on kmem_cache_destroy() in
kunit test context, and separately we can change pr_err() to WARN() as long
as they are still suppressed in kunit test context.

> Thanks,
> Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f844a422-55a6-494f-875a-b118d1264395%40suse.cz.
