Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZ7TXS3QMGQET3TPHEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 488E897DF14
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 23:26:01 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-535682ab6e9sf2767185e87.1
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 14:26:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726953960; cv=pass;
        d=google.com; s=arc-20240605;
        b=WVkI0KxXGUfYvxyf5OyUD26kKpeYCs82hIFbJVnqoBtraYuba/+ID1002ps36UDA2A
         jCEBHl2F7uoY32dFS64ATazjz82kqNuczAMCrCEjcjlaXgzkXAVYPFbpYDQgDPP6zX6n
         7+BcE4n4L9mzjN2XA4Z1kbzkznV2APnVQ7/KYfPB1Ua5kp/AOphT9IruA83JPZO6Vn5N
         XZh6hpXxM4pl0xEr++xgu6hItr4I4FIXy9ySTM7ntPcNZESJarcH2nmRcFEIXPsEYpGe
         MZf+uIU7QNavuw/mM0LAPagXGHPHEE4YKsMkKNb+NlF5+C2t/1AP3nOylrawXQmx6GZJ
         TP9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=S1uE+K4V2wEB8r4inVvt+kqHwIOuzYIV65bfnfAjlgc=;
        fh=MnwuFvgviLxPRTAAFzAm5Hjyjbgq6LH/4i4BXfuTZfQ=;
        b=jJfn1gh9ll6Xt3u5UPE1XJSv3/m5wJJUvEHfm/YiV6nnmOM3QNd1/UgNNiR2T4+Cru
         TRD2PPif31eDKPk4UTqRRgUa8Yiv3hW1rPvMYXHxZ5tnJz/EgpMAsh931GnSsu/cGEBL
         ufbpxisM0f+HaVuIbWypZ+txN+tFnGdWjF5ozaoj+x0WfD0AitoL3FwneNZDfrVLE50L
         OraL9JX944Dnxh0xNpe0ehyRqkfU85Tr3boPYhLL7cmKipp+deq2lnKzbnBA2QpNfsu5
         EdPIB7BDtUYwgThO8tOvFbLbZTUz41F+LhdZutX8ke2UEfmhcq0pLo3jqoW5G4YKsjdK
         i44g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2TNlgi5L;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2TNlgi5L;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726953960; x=1727558760; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S1uE+K4V2wEB8r4inVvt+kqHwIOuzYIV65bfnfAjlgc=;
        b=Owsrg4iKKIjLS72fKxIEPv2fnGtABH6rd3Aj5X1VdqH5AelezHN5Wf7e1QzJTzMCDv
         iXbpSuBBpaa2XN3VomOzBH53V88M+MWsvCvzJbv+4t2DXPa4ohDsWStV3KAHgKGDwijX
         TX9E6KYLts1lN5udyI1bt6FnyKJQABk5/zigmGV5299gg4SOf3SISl1X0DHz6a2Gngqx
         mjT64XYP8Ldi8PjEvoeCnaPNc0gNvA2CLFyGGv/520sMxU/yye3W7DdtMlOGDHEhs90O
         yeqOB2LBQ+FjUMdE1eJtKB2LW8H9n7NxWMpQgSJc6Wpe7JsdbG+QoWckCivA7d8ImBzK
         3qLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726953960; x=1727558760;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=S1uE+K4V2wEB8r4inVvt+kqHwIOuzYIV65bfnfAjlgc=;
        b=DA+EDn3xIPadQAbQISygvELT+XBVXcwysSaidXY90PKHk+h/B3Mjb3KU6O1MTFaGRK
         Ta+CFaKLoaQYYpQmMP2cbJxU2kdPTyQSEmpCK07wufeaChuxwm4ibUyOgoidqnQtM6lu
         NshPPZkNfs0D7Jcm4kdoNC794S26iSNO4vHbd+lc0mjIUL0kXSVg0rAY+2ZYQa1vZguJ
         Mw+HwfBSwQ+AJ1Myb2z5R/BRl/Bf3Zkbk+ilPT0X54s+PGAIybDJPfbPeheLUeJZwsS5
         4KDmw2D845KcAUZ3Iq65I3sHLX30OsD/12U9H6r6t4/6vbG5rmTkFhqwGeCwTnJlREaP
         ToSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVmnoaaCRwO5NGY93qW/chTLGFUALOR/aV9cCHyWB8EnHrqQ9L7koroyUyq/lsa9khyCp3NKQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyh5zWqET/qQvhmYn9Dso1ApciqrgDiC7pH28WNwJ7CvnAwy5IN
	U5INX9ur4fkwGKP87Rxsb6fOqLqKM6pQfoD6RRilSA4cQeJ6/LlC
X-Google-Smtp-Source: AGHT+IFmIuFuzxbgKExISuPetWu41+qSak9rRvzezglS1bwrBbTOVjlL80WDxDyIAXtR9M9G5joP9Q==
X-Received: by 2002:a05:6512:3d86:b0:536:5413:2d47 with SMTP id 2adb3069b0e04-536ac3228a1mr3654065e87.41.1726953959460;
        Sat, 21 Sep 2024 14:25:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c9d:b0:52e:9923:a1c2 with SMTP id
 2adb3069b0e04-536a5b74db8ls571252e87.1.-pod-prod-03-eu; Sat, 21 Sep 2024
 14:25:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWb6lEqF1oYTgqni4aARKNt9i/Bgys63uJaoGoAb+k5jgwOrDlZsUAn+zDIF4FKPFk0EWcRVafxIvQ=@googlegroups.com
X-Received: by 2002:a05:6512:15a3:b0:535:6a83:86f9 with SMTP id 2adb3069b0e04-536ac33f179mr3191671e87.60.1726953957275;
        Sat, 21 Sep 2024 14:25:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726953957; cv=none;
        d=google.com; s=arc-20240605;
        b=i7lSlS/yNMJ+cJzlWVVhfQL0Pn3TAW08ewmWPsnzIzqC/e3ohMqC+Ne3srFa4tKBpd
         G5ho5eJ5/mgXNcEjIcvmZ/IG3T2aP7Cx6MDz2RB/WI/0ySNjoa5YA3pj8cK4yfy4GnjY
         0bhSbVwbRIUe7PM30Sf5ZvF82xynmiQzvTuqQhSerEsWMe6f3BH9k+WKmy1ltODOpzDw
         kSerj0BphiwEeGwazN1VU3qLkXDPaYe872QaQFuTIhu3E5a3KEX6sAEXUoTKVwNtnqRZ
         HVTjzmZ1cFBAJJmOkrs70gBEZwFoDfqA2zHpu71v53Ijtr5z5/3VzU92Mw6y4v+vESmY
         76ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=olvukJon87ujc7rw1bmm1AaUxYoPAUTO2bQa4hCvCRE=;
        fh=LDmSecLM1cRMm50YlpiLMwlBtuRnQSjclil26OgE4cQ=;
        b=J7tGjnEnXKn3atgG6dEeqb/A3ntWrgY/vWcd9/33PMNXHYd2TdCB76vhqY5aoVb5nf
         90iTY70ybIEDCzZaBrqtR/AYA+TxR+/1nJFvnFHXFf7aRfdX4oTtqZVl+YtL+E1wn2m/
         KU4j9O0Hse+HlzaGIDFF3/ClotpdVryb17okQiCHFIr9U4DM+z79kgCKIxuGa//NbKWM
         pVMTJHYkKapzaDID5EXc050IkJ/F0xwTi+lxla6G3UkxxFOFlMCtny0/6FpPYG1hyJOp
         yaXtVukZ+qztqrW8BSTpy3YsJ7vaJIuvNi80tuaoc88ncZYTQ4rnV3csYqep51dGMBUQ
         oEmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2TNlgi5L;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2TNlgi5L;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-536870cf7cesi342774e87.12.2024.09.21.14.25.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Sep 2024 14:25:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4D30933AB4;
	Sat, 21 Sep 2024 21:25:56 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0EDAB13886;
	Sat, 21 Sep 2024 21:25:56 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id FZbHAuQ572axBAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Sat, 21 Sep 2024 21:25:56 +0000
Message-ID: <474b0519-b354-4370-84ac-411fd3d6d14b@suse.cz>
Date: Sat, 21 Sep 2024 23:25:55 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
Content-Language: en-US
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
 <07d5a214-a6c2-4444-8122-0a7b1cdd711f@suse.cz>
 <73f9e6d7-f5c0-4cdc-a9c4-dde3e2fb057c@roeck-us.net>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 xsFNBFZdmxYBEADsw/SiUSjB0dM+vSh95UkgcHjzEVBlby/Fg+g42O7LAEkCYXi/vvq31JTB
 KxRWDHX0R2tgpFDXHnzZcQywawu8eSq0LxzxFNYMvtB7sV1pxYwej2qx9B75qW2plBs+7+YB
 87tMFA+u+L4Z5xAzIimfLD5EKC56kJ1CsXlM8S/LHcmdD9Ctkn3trYDNnat0eoAcfPIP2OZ+
 9oe9IF/R28zmh0ifLXyJQQz5ofdj4bPf8ecEW0rhcqHfTD8k4yK0xxt3xW+6Exqp9n9bydiy
 tcSAw/TahjW6yrA+6JhSBv1v2tIm+itQc073zjSX8OFL51qQVzRFr7H2UQG33lw2QrvHRXqD
 Ot7ViKam7v0Ho9wEWiQOOZlHItOOXFphWb2yq3nzrKe45oWoSgkxKb97MVsQ+q2SYjJRBBH4
 8qKhphADYxkIP6yut/eaj9ImvRUZZRi0DTc8xfnvHGTjKbJzC2xpFcY0DQbZzuwsIZ8OPJCc
 LM4S7mT25NE5kUTG/TKQCk922vRdGVMoLA7dIQrgXnRXtyT61sg8PG4wcfOnuWf8577aXP1x
 6mzw3/jh3F+oSBHb/GcLC7mvWreJifUL2gEdssGfXhGWBo6zLS3qhgtwjay0Jl+kza1lo+Cv
 BB2T79D4WGdDuVa4eOrQ02TxqGN7G0Biz5ZLRSFzQSQwLn8fbwARAQABzSBWbGFzdGltaWwg
 QmFia2EgPHZiYWJrYUBzdXNlLmN6PsLBlAQTAQoAPgIbAwULCQgHAwUVCgkICwUWAgMBAAIe
 AQIXgBYhBKlA1DSZLC6OmRA9UCJPp+fMgqZkBQJkBREIBQkRadznAAoJECJPp+fMgqZkNxIQ
 ALZRqwdUGzqL2aeSavbum/VF/+td+nZfuH0xeWiO2w8mG0+nPd5j9ujYeHcUP1edE7uQrjOC
 Gs9sm8+W1xYnbClMJTsXiAV88D2btFUdU1mCXURAL9wWZ8Jsmz5ZH2V6AUszvNezsS/VIT87
 AmTtj31TLDGwdxaZTSYLwAOOOtyqafOEq+gJB30RxTRE3h3G1zpO7OM9K6ysLdAlwAGYWgJJ
 V4JqGsQ/lyEtxxFpUCjb5Pztp7cQxhlkil0oBYHkudiG8j1U3DG8iC6rnB4yJaLphKx57NuQ
 PIY0Bccg+r9gIQ4XeSK2PQhdXdy3UWBr913ZQ9AI2usid3s5vabo4iBvpJNFLgUmxFnr73SJ
 KsRh/2OBsg1XXF/wRQGBO9vRuJUAbnaIVcmGOUogdBVS9Sun/Sy4GNA++KtFZK95U7J417/J
 Hub2xV6Ehc7UGW6fIvIQmzJ3zaTEfuriU1P8ayfddrAgZb25JnOW7L1zdYL8rXiezOyYZ8Fm
 ZyXjzWdO0RpxcUEp6GsJr11Bc4F3aae9OZtwtLL/jxc7y6pUugB00PodgnQ6CMcfR/HjXlae
 h2VS3zl9+tQWHu6s1R58t5BuMS2FNA58wU/IazImc/ZQA+slDBfhRDGYlExjg19UXWe/gMcl
 De3P1kxYPgZdGE2eZpRLIbt+rYnqQKy8UxlszsBNBFsZNTUBCACfQfpSsWJZyi+SHoRdVyX5
 J6rI7okc4+b571a7RXD5UhS9dlVRVVAtrU9ANSLqPTQKGVxHrqD39XSw8hxK61pw8p90pg4G
 /N3iuWEvyt+t0SxDDkClnGsDyRhlUyEWYFEoBrrCizbmahOUwqkJbNMfzj5Y7n7OIJOxNRkB
 IBOjPdF26dMP69BwePQao1M8Acrrex9sAHYjQGyVmReRjVEtv9iG4DoTsnIR3amKVk6si4Ea
 X/mrapJqSCcBUVYUFH8M7bsm4CSxier5ofy8jTEa/CfvkqpKThTMCQPNZKY7hke5qEq1CBk2
 wxhX48ZrJEFf1v3NuV3OimgsF2odzieNABEBAAHCwXwEGAEKACYCGwwWIQSpQNQ0mSwujpkQ
 PVAiT6fnzIKmZAUCZAUSmwUJDK5EZgAKCRAiT6fnzIKmZOJGEACOKABgo9wJXsbWhGWYO7mD
 8R8mUyJHqbvaz+yTLnvRwfe/VwafFfDMx5GYVYzMY9TWpA8psFTKTUIIQmx2scYsRBUwm5VI
 EurRWKqENcDRjyo+ol59j0FViYysjQQeobXBDDE31t5SBg++veI6tXfpco/UiKEsDswL1WAr
 tEAZaruo7254TyH+gydURl2wJuzo/aZ7Y7PpqaODbYv727Dvm5eX64HCyyAH0s6sOCyGF5/p
 eIhrOn24oBf67KtdAN3H9JoFNUVTYJc1VJU3R1JtVdgwEdr+NEciEfYl0O19VpLE/PZxP4wX
 PWnhf5WjdoNI1Xec+RcJ5p/pSel0jnvBX8L2cmniYnmI883NhtGZsEWj++wyKiS4NranDFlA
 HdDM3b4lUth1pTtABKQ1YuTvehj7EfoWD3bv9kuGZGPrAeFNiHPdOT7DaXKeHpW9homgtBxj
 8aX/UkSvEGJKUEbFL9cVa5tzyialGkSiZJNkWgeHe+jEcfRT6pJZOJidSCdzvJpbdJmm+eED
 w9XOLH1IIWh7RURU7G1iOfEfmImFeC3cbbS73LQEFGe1urxvIH5K/7vX+FkNcr9ujwWuPE9b
 1C2o4i/yZPLXIVy387EjA6GZMqvQUFuSTs/GeBcv0NjIQi8867H3uLjz+mQy63fAitsDwLmR
 EP+ylKVEKb0Q2A==
In-Reply-To: <73f9e6d7-f5c0-4cdc-a9c4-dde3e2fb057c@roeck-us.net>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -2.80
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_TLS_ALL(0.00)[];
	TAGGED_RCPT(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[30];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com];
	TO_DN_SOME(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	URIBL_BLOCKED(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid,suse.cz:email];
	RCVD_COUNT_TWO(0.00)[2];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	R_RATELIMIT(0.00)[to_ip_from(RLtsk3gtac773whqka7ht6mdi4)]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=2TNlgi5L;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=2TNlgi5L;       dkim=neutral
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

On 9/21/24 23:08, Guenter Roeck wrote:
> On 9/21/24 13:40, Vlastimil Babka wrote:
>> +CC kunit folks
>> 
>> On 9/20/24 15:35, Guenter Roeck wrote:
>>> Hi,
>> 
>> Hi,
>> 
>>> On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
>>>> Add a test that will create cache, allocate one object, kfree_rcu() it
>>>> and attempt to destroy it. As long as the usage of kvfree_rcu_barrier()
>>>> in kmem_cache_destroy() works correctly, there should be no warnings in
>>>> dmesg and the test should pass.
>>>>
>>>> Additionally add a test_leak_destroy() test that leaks an object on
>>>> purpose and verifies that kmem_cache_destroy() catches it.
>>>>
>>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>>
>>> This test case, when run, triggers a warning traceback.
>>>
>>> kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still has objects when called from test_leak_destroy+0x70/0x11c
>>> WARNING: CPU: 0 PID: 715 at mm/slab_common.c:511 kmem_cache_destroy+0x1dc/0x1e4
>> 
>> Yes that should be suppressed like the other slub_kunit tests do. I have
>> assumed it's not that urgent because for example the KASAN kunit tests all
>> produce tons of warnings and thus assumed it's in some way acceptable for
>> kunit tests to do.
>> 
> 
> I have all tests which generate warning backtraces disabled. Trying to identify
> which warnings are noise and which warnings are on purpose doesn't scale,
> so it is all or nothing for me. I tried earlier to introduce a patch series
> which would enable selective backtrace suppression, but that died the death
> of architecture maintainers not caring and people demanding it to be perfect
> (meaning it only addressed WARNING: backtraces and not BUG: backtraces,
> and apparently that wasn't good enough).

Ah, didn't know, too bad.

> If the backtrace is intentional (and I think you are saying that it is),
> I'll simply disable the test. That may be a bit counter-productive, but
> there is really no alternative for me.

It's intentional in the sense that the test intentionally triggers a
condition that normally produces a warning. Many if the slub kunit test do
that, but are able to suppress printing the warning when it happens in the
kunit context. I forgot to do that for the new test initially as the warning
there happens from a different path that those that already have the kunit
suppression, but we'll implement that suppression there too ASAP.

>>> That is, however, not the worst of it. It also causes boot stalls on
>>> several platforms and architectures (various arm platforms, arm64,
>>> loongarch, various ppc, and various x86_64). Reverting it fixes the
>>> problem. Bisect results are attached for reference.
>> 
>> OK, this part is unexpected. I assume you have the test built-in and not a
>> module, otherwise it can't affect boot? And by stall you mean a delay or a
> 
> Yes.
> 
>> complete lockup? I've tried to reproduce that with virtme, but it seemed
>> fine, maybe it's .config specific?
> 
> It is a complete lockup.
> 
>> 
>> I do wonder about the placement of the call of kunit_run_all_tests() from
>> kernel_init_freeable() as that's before a bunch of initialization finishes.
>> 
>> For example, system_state = SYSTEM_RUNNING; and rcu_end_inkernel_boot() only
>> happens later in kernel_init(). I wouldn't be surprised if that means
>> calling kfree_rcu() or rcu_barrier() or kvfree_rcu_barrier() as part of the
>> slub tests is too early.
>> 
>> Does the diff below fix the problem? Any advice from kunit folks? I could
>> perhaps possibly make the slab test module-only instead of tristate or do
>> some ifdef builtin on the problematic tests, but maybe it wouldn't be
>> necessary with kunit_run_all_tests() happening a bit later.
>> 
> 
> It does, at least based on my limited testing. However, given that the
> backtrace is apparently intentional, it doesn't really matter - I'll disable
> the test instead.

Right, thanks. I will notify you when the suppression is done so the test
can be re-enabled.

But as the lockup should not be caused by the warning itself, we will still
have to address it, as others configuring kunit tests built-in might see the
lockup, or you would again see it as well, once the warning is addressed and
test re-enabled.

Your testing suggests moving the kunit_run_all_tests() call might be the
right fix so let's see what kunit folks think. I would hope that no other
kunit test would become broken by being executed later in boot, because when
compiled as modules, it already happens even much later already.

Thanks!
Vlastimil

> Thanks,
> Guenter
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/474b0519-b354-4370-84ac-411fd3d6d14b%40suse.cz.
