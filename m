Return-Path: <kasan-dev+bncBDXYDPH3S4OBBG7CYGZQMGQECSWVOLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F02090B7DA
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 19:23:41 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-52c989652e6sf3352243e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 10:23:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718645020; cv=pass;
        d=google.com; s=arc-20160816;
        b=xtTkjoaRU6ZIEBHYWA8I6rw7P9ncMchCCUoTPoizdctY7tAiO2O1ORMSA59OYLpb/L
         aI7cXU6/0G65ozfJO+3Bv2pxeX5UGRsHchcUBzK0FatlEa/XIiwn4mZNrfrKN1baXHfZ
         kKwEBd4Oxzq8h5Rd2f3uhBr/+LuOtvc8gmvvsL87fRjjr/8WbNtFVWDrGj3FLW0LkYbb
         /4NR/30UpVUOax7P+XE28nj7gjPq+Sm5/MaLYo3TmWiR1mJRNjSafHELm9/CUnlwJ+yo
         EKgBfpgIgxOXset+Hu0Sj4kI28cqWJ1EQ9qa7V4jbat5EIT7WJTXCyDStLM8e+oumL29
         Rirg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=ftHMomuWkdWDNugW+VztstkOtjlgkZTPJWm2JZUHccw=;
        fh=2KrLfapNCp37Ol6xIuAxtlfkfwOfyP7VRYIoqMv5cgo=;
        b=bM9FedvkSCVd9roaimK/ptD5cD3SPK+g6aVdGzFTlQoIlo7pmDsg4ZpXq0sN1/ktDw
         s47EZD9kWbXew/3JFeKG7SXJzdA83yezRuOeQiuo1gqtOJhdzF6HxsXke80lOic0cooH
         haaFpRcIsHMfUYolmGB9wrL0+F/7CtLGjAF7lJfdPlZ5VpGej0Btazn8diKXZ6jFRcFJ
         ivJTFyxawoiGlVNwzmYYiFDZX03kqpZuTDYWSddBdbwtzHQ3Tgtu5/TNwTQXNsczov6Y
         YAMXF3Rm0Ri47uV8Pjd+50sljsmNxmCLYA4q2RXNx72jDPyWRz0wS4Z7qZkn9GKMemrs
         jKzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wP5MM9xH;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jLHfQO+b;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718645020; x=1719249820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ftHMomuWkdWDNugW+VztstkOtjlgkZTPJWm2JZUHccw=;
        b=WLDP1RnWcMvqQCUTJbHr3d4TPVkwvNYgmNn6pd1xH7hqnG+5oVAd1MfGGeU09FJ2EE
         E2pcqXF7sTX9CYNwmoiYdnDHfPguY8foaADHi1zrhA9UgF3hjQupROFbV7vKkMF92QsA
         /OiDjZPCkjHz21uAdryaXLk2IR10b+FApxzmvTKOg5OvwWaYpMWhoL2YOvWYBO0TvhFo
         zt2oo4UvQzBA/yKklG6LgM8dy/GBwwWkeRAOfO7pcePZ1xvLOJj+pq7yFS9dZSMlHQzu
         g0I1JNfbVoJHHzV215OEiDljLtp0XWWi7cNhvb1U64jHGD1LmvfFPFoaasS5fV7Q90Tz
         o6JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718645020; x=1719249820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ftHMomuWkdWDNugW+VztstkOtjlgkZTPJWm2JZUHccw=;
        b=S5R+1NjZm/phji/0A9f0kMnbsUFkaSuj7LzkDHIT8A3xJ+1ukFZypOgY8O68SkmfTw
         sHWYSETkR9nfmzqPSot2ebZ1qpl92jzNxkjauiGWdSksoaVm6R9FA8XAjyguJ9333aT1
         aVaU/CiOpyAuM1HBU6yni8HCGx4usN4s2O642f6FGo7aW5OegmK2jV0Mk86O7Ih7hynI
         +dFln6Y5tL/43ONEO0/0LXJo8vgUCBny01PtlvTwoWGwV0QSf8S01tjtvBJeAqFJnQCY
         3emIdymXVj8Fsz9WyGyLzAYiPLX+c/KeLoAfJY9bKxm3l373j+mAnRn24Jn67PhkxdFV
         LpvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXKXSmEao83qop59X/ien8hmS9vgvHBmTxiaSbYBRWC+9bxBA1cCXO8LjWSUXfPvaqq8hU2qurH9/lt9NIwaoHI5BF18cvpHA==
X-Gm-Message-State: AOJu0YyhMW+tsHASTzlqtfAfI4msp31+Zfx33vPQJTe/7M12q1Qz10xq
	eZOg6CUCa2GFqIGH1LYXUe4L5JwvcGhIfldTZlIzAQp4h8T3bhUv
X-Google-Smtp-Source: AGHT+IE+2VjeuM3zRj7GbcqZ+w8tZZv23HzZFEn/AcSFwb0vNJq7iZMcoU+YeenWatUCg4hPlDkCBA==
X-Received: by 2002:ac2:5f6f:0:b0:52c:8a4a:e3a3 with SMTP id 2adb3069b0e04-52ca6e9a7a2mr7414981e87.57.1718645019716;
        Mon, 17 Jun 2024 10:23:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5c7:b0:52c:a0a5:c6a0 with SMTP id
 2adb3069b0e04-52ca0a5c6f9ls2086007e87.2.-pod-prod-08-eu; Mon, 17 Jun 2024
 10:23:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUa1dOLgWbtKMzjK0lqhi7hdbwYjnCiouGWC3p9t1NzMPqgRNokafhRmZDc0dCS+uPJpmwAIs3eJepiUtxrsjlpM4KLDtKVdKLqlA==
X-Received: by 2002:a05:6512:3e3:b0:52c:90b6:170f with SMTP id 2adb3069b0e04-52ca6e6dab5mr7327096e87.29.1718645017664;
        Mon, 17 Jun 2024 10:23:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718645017; cv=none;
        d=google.com; s=arc-20160816;
        b=ZgSfqGhyD2BjFQx/NsenVOV8sVJxiFhT8D1osa/+HrKtZrf8C6osKor8cKNBEflZBh
         PnvjOjpIXxLZG/NC1uCbfcraCFZ8inJkop9jFIEIiSykaJDHSaX9nNKlokA4P6WbCz6i
         e8sVSnOm03hfq/qJGQ4fK+KDGr6sEdfNdQceIZd/PtHy5yfI7QqICwSlohri8zuKEeK+
         eI7VnHsRZHKWLW6d5C3UjcY85X1RIMxdKD4BFL+FPNX/ajAyVBx0o8WeTEHlHxZbkv0w
         YhUbTEY2XkFgJ79seg3epPWi0zj8toEhg6rGinIL3vU168fbQPw7xJqpaLvlQe5yJZG7
         DsmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=ngyPU5qU7Xw4mfIB382fEUZqXXHMDeQs5ieSFvFPdnk=;
        fh=R8XD0RKu/QCBR7Y+AaF2BcU5zn6ubX9y/1VGk++cA0k=;
        b=HOWRzDBqdoTAyZ36A9jVncRkLz9F2GK+k3NpU974LnrLGPQ+TTUVACgbumOPkG3grZ
         xd0HcQMMswVlql0EwmhsuRpqaFE+CbGmL47PAZ0c9Z+FBlU+TS2XM06npsOAGic+Jch+
         jpiorEH8kcH+aLhRieDqOUc7BfgwF2x8uYWhykgvhPFuBXB5ZzKW5lD79N4VpQGA/nOq
         TvD5e4QwKKq3ovOO8FKWzlKEvH1lMcEZKhI7KQeDna7jkU1MRnlwD+1b/tFZKwtR6DQU
         Hq9deLAKYUTl4HbMUnJtoPGQPxwfp/adKxBmJnw8uhpX1X5u6stmTA0nMC/G/T5zYJQj
         oVvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wP5MM9xH;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jLHfQO+b;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42285317d3bsi8796755e9.1.2024.06.17.10.23.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Jun 2024 10:23:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C494F1F7B0;
	Mon, 17 Jun 2024 17:23:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9034013AAA;
	Mon, 17 Jun 2024 17:23:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id tStoIhhxcGbBDgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 17 Jun 2024 17:23:36 +0000
Message-ID: <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
Date: Mon, 17 Jun 2024 19:23:36 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Content-Language: en-US
To: paulmck@kernel.org
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>,
 Jakub Kicinski <kuba@kernel.org>, Julia Lawall <Julia.Lawall@inria.fr>,
 linux-block@vger.kernel.org, kernel-janitors@vger.kernel.org,
 bridge@lists.linux.dev, linux-trace-kernel@vger.kernel.org,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, kvm@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
 ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
 Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
 Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
 linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
 netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20240609082726.32742-1-Julia.Lawall@inria.fr>
 <20240612143305.451abf58@kernel.org>
 <baee4d58-17b4-4918-8e45-4d8068a23e8c@paulmck-laptop>
 <Zmov7ZaL-54T9GiM@zx2c4.com> <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com> <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
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
In-Reply-To: <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.50 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[zx2c4.com,gmail.com,kernel.org,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLujeud1qp5x6qhm7ow61zc6bu)];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:dkim]
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Queue-Id: C494F1F7B0
X-Spam-Flag: NO
X-Spam-Score: -4.50
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wP5MM9xH;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=jLHfQO+b;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
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

On 6/17/24 6:12 PM, Paul E. McKenney wrote:
> On Mon, Jun 17, 2024 at 05:10:50PM +0200, Vlastimil Babka wrote:
>> On 6/13/24 2:22 PM, Jason A. Donenfeld wrote:
>> > On Wed, Jun 12, 2024 at 08:38:02PM -0700, Paul E. McKenney wrote:
>> >> o	Make the current kmem_cache_destroy() asynchronously wait for
>> >> 	all memory to be returned, then complete the destruction.
>> >> 	(This gets rid of a valuable debugging technique because
>> >> 	in normal use, it is a bug to attempt to destroy a kmem_cache
>> >> 	that has objects still allocated.)
>> 
>> This seems like the best option to me. As Jason already said, the debugging
>> technique is not affected significantly, if the warning just occurs
>> asynchronously later. The module can be already unloaded at that point, as
>> the leak is never checked programatically anyway to control further
>> execution, it's just a splat in dmesg.
> 
> Works for me!

Great. So this is how a prototype could look like, hopefully? The kunit test
does generate the splat for me, which should be because the rcu_barrier() in
the implementation (marked to be replaced with the real thing) is really
insufficient. Note the test itself passes as this kind of error isn't wired
up properly.

Another thing to resolve is the marked comment about kasan_shutdown() with
potential kfree_rcu()'s in flight.

Also you need CONFIG_SLUB_DEBUG enabled otherwise node_nr_slabs() is a no-op
and it might fail to notice the pending slabs. This will need to change.

----8<----
diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
index e6667a28c014..e3e4d0ca40b7 100644
--- a/lib/slub_kunit.c
+++ b/lib/slub_kunit.c
@@ -5,6 +5,7 @@
 #include <linux/slab.h>
 #include <linux/module.h>
 #include <linux/kernel.h>
+#include <linux/rcupdate.h>
 #include "../mm/slab.h"
 
 static struct kunit_resource resource;
@@ -157,6 +158,26 @@ static void test_kmalloc_redzone_access(struct kunit *test)
 	kmem_cache_destroy(s);
 }
 
+struct test_kfree_rcu_struct {
+	struct rcu_head rcu;
+};
+
+static void test_kfree_rcu(struct kunit *test)
+{
+	struct kmem_cache *s = test_kmem_cache_create("TestSlub_kfree_rcu",
+				sizeof(struct test_kfree_rcu_struct),
+				SLAB_NO_MERGE);
+	struct test_kfree_rcu_struct *p = kmem_cache_alloc(s, GFP_KERNEL);
+
+	kasan_disable_current();
+
+	KUNIT_EXPECT_EQ(test, 0, slab_errors);
+
+	kasan_enable_current();
+	kfree_rcu(p, rcu);
+	kmem_cache_destroy(s);
+}
+
 static int test_init(struct kunit *test)
 {
 	slab_errors = 0;
@@ -177,6 +198,7 @@ static struct kunit_case test_cases[] = {
 
 	KUNIT_CASE(test_clobber_redzone_free),
 	KUNIT_CASE(test_kmalloc_redzone_access),
+	KUNIT_CASE(test_kfree_rcu),
 	{}
 };
 
diff --git a/mm/slab.h b/mm/slab.h
index b16e63191578..a0295600af92 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -277,6 +277,8 @@ struct kmem_cache {
 	unsigned int red_left_pad;	/* Left redzone padding size */
 	const char *name;		/* Name (only for display!) */
 	struct list_head list;		/* List of slab caches */
+	struct work_struct async_destroy_work;
+
 #ifdef CONFIG_SYSFS
 	struct kobject kobj;		/* For sysfs */
 #endif
@@ -474,7 +476,7 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
 			      SLAB_NO_USER_FLAGS)
 
 bool __kmem_cache_empty(struct kmem_cache *);
-int __kmem_cache_shutdown(struct kmem_cache *);
+int __kmem_cache_shutdown(struct kmem_cache *, bool);
 void __kmem_cache_release(struct kmem_cache *);
 int __kmem_cache_shrink(struct kmem_cache *);
 void slab_kmem_cache_release(struct kmem_cache *);
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 5b1f996bed06..c5c356d0235d 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -44,6 +44,8 @@ static LIST_HEAD(slab_caches_to_rcu_destroy);
 static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work);
 static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
 		    slab_caches_to_rcu_destroy_workfn);
+static void kmem_cache_kfree_rcu_destroy_workfn(struct work_struct *work);
+
 
 /*
  * Set of flags that will prevent slab merging
@@ -234,6 +236,7 @@ static struct kmem_cache *create_cache(const char *name,
 
 	s->refcount = 1;
 	list_add(&s->list, &slab_caches);
+	INIT_WORK(&s->async_destroy_work, kmem_cache_kfree_rcu_destroy_workfn);
 	return s;
 
 out_free_cache:
@@ -449,12 +452,16 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 	}
 }
 
-static int shutdown_cache(struct kmem_cache *s)
+static int shutdown_cache(struct kmem_cache *s, bool warn_inuse)
 {
 	/* free asan quarantined objects */
+	/*
+	 * XXX: is it ok to call this multiple times? and what happens with a
+	 * kfree_rcu() in flight that finishes after or in parallel with this?
+	 */
 	kasan_cache_shutdown(s);
 
-	if (__kmem_cache_shutdown(s) != 0)
+	if (__kmem_cache_shutdown(s, warn_inuse) != 0)
 		return -EBUSY;
 
 	list_del(&s->list);
@@ -477,6 +484,32 @@ void slab_kmem_cache_release(struct kmem_cache *s)
 	kmem_cache_free(kmem_cache, s);
 }
 
+static void kmem_cache_kfree_rcu_destroy_workfn(struct work_struct *work)
+{
+	struct kmem_cache *s;
+	int err = -EBUSY;
+	bool rcu_set;
+
+	s = container_of(work, struct kmem_cache, async_destroy_work);
+
+	// XXX use the real kmem_cache_free_barrier() or similar thing here
+	rcu_barrier();
+
+	cpus_read_lock();
+	mutex_lock(&slab_mutex);
+
+	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
+
+	err = shutdown_cache(s, true);
+	WARN(err, "kmem_cache_destroy %s: Slab cache still has objects",
+	     s->name);
+
+	mutex_unlock(&slab_mutex);
+	cpus_read_unlock();
+	if (!err && !rcu_set)
+		kmem_cache_release(s);
+}
+
 void kmem_cache_destroy(struct kmem_cache *s)
 {
 	int err = -EBUSY;
@@ -494,9 +527,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	if (s->refcount)
 		goto out_unlock;
 
-	err = shutdown_cache(s);
-	WARN(err, "%s %s: Slab cache still has objects when called from %pS",
-	     __func__, s->name, (void *)_RET_IP_);
+	err = shutdown_cache(s, false);
+	if (err)
+		schedule_work(&s->async_destroy_work);
 out_unlock:
 	mutex_unlock(&slab_mutex);
 	cpus_read_unlock();
diff --git a/mm/slub.c b/mm/slub.c
index 1617d8014ecd..4d435b3d2b5f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5342,7 +5342,8 @@ static void list_slab_objects(struct kmem_cache *s, struct slab *slab,
  * This is called from __kmem_cache_shutdown(). We must take list_lock
  * because sysfs file might still access partial list after the shutdowning.
  */
-static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n)
+static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n,
+			 bool warn_inuse)
 {
 	LIST_HEAD(discard);
 	struct slab *slab, *h;
@@ -5353,7 +5354,7 @@ static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n)
 		if (!slab->inuse) {
 			remove_partial(n, slab);
 			list_add(&slab->slab_list, &discard);
-		} else {
+		} else if (warn_inuse) {
 			list_slab_objects(s, slab,
 			  "Objects remaining in %s on __kmem_cache_shutdown()");
 		}
@@ -5378,7 +5379,7 @@ bool __kmem_cache_empty(struct kmem_cache *s)
 /*
  * Release all resources used by a slab cache.
  */
-int __kmem_cache_shutdown(struct kmem_cache *s)
+int __kmem_cache_shutdown(struct kmem_cache *s, bool warn_inuse)
 {
 	int node;
 	struct kmem_cache_node *n;
@@ -5386,7 +5387,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
 	flush_all_cpus_locked(s);
 	/* Attempt to free all objects */
 	for_each_kmem_cache_node(s, node, n) {
-		free_partial(s, n);
+		free_partial(s, n, warn_inuse);
 		if (n->nr_partial || node_nr_slabs(n))
 			return 1;
 	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6711935d-20b5-41c1-8864-db3fc7d7823d%40suse.cz.
