Return-Path: <kasan-dev+bncBDXYDPH3S4OBBFNI626QMGQE3XEZ45Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C95D6A43A6D
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 10:57:43 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-54530ca74ccsf4056911e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 01:57:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740477463; cv=pass;
        d=google.com; s=arc-20240605;
        b=d5moc5IPHCFMHKE2lRLWUA/FJaGrvGivPDpa4j4GtlfXOT+aeI8kIuyigTcSNwvs5o
         fJbsRso7N2hjCSWjYI0UevJUrfbDxbXAuHCUcCFULRBGfuxdAi0hLard25riXu85YKnl
         tWdi/M29T8RfkowtSGtIHhJloyvXnjhcOdncDHRXmNjNF+L6K3oyhqXgSapcnXMKR18E
         Vcq60SxcvpGIUd34BGnQUEs5cGNbp7/8I+eYZryDEtEgET48YVSKYPWzi1L6YWemrddR
         vWbrircaw/Bq8glg1IBzqYKyEnUbGYBdeTisGqlQ1aITEhvEYQpTjhg5SwWnGd3p+o3q
         FfwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=pbDccsdvnvXtugRkdlNte2AT/NlC1k+cwn1eFCYH7po=;
        fh=Cc9jSORkdviQgZH109OGHkkz5O06NE8tdaS8WQKE0H4=;
        b=X291kc6RITrKSEnAjlK45ZZZBe0Sf1IOAWl38H23rerZAPLojPa5JNldy9Rp44xd8C
         qqnsGQCpTOodZPc5qa28lzFuLHDcXGoQJEXJL6pPIjtKL9DVys6pLlBnDOhmCpOgkV3k
         Lm3XNv2rhXPY8YbpAz7jsFfRfd0gFZ94eWnXUHs7bONf7sXUt7C1eN/HWX3tH9Ng+LwR
         9Gsx4Tj5fBeY7p0AMyx0YoFqtJiTGqo9pfjNJisKHH4hpDjcKvGSj0KGSUmLt9QV6JNn
         k5Q1ZQrJzMLRk0dhIj3clX92JchnIcJP9TAG99IZpN2grdYGtECIIaJCuwZDR2N8iK8w
         UUPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yUnW2gK3;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yUnW2gK3;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740477463; x=1741082263; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pbDccsdvnvXtugRkdlNte2AT/NlC1k+cwn1eFCYH7po=;
        b=Qd2PScreI92X+5QYAAFGcuRLBeEVbNl4PSST9S1Q1k8Am/lMxMXE7NSB/JeZ20xiTF
         1tsmwT6EfKngBbmra80/mKMq4lnrSjwrsT1GLCtgwnv8K/g3RfK1+3FCS37DZL0HPPXS
         0JE+S3L/4NbBv67FnWIj7Aa/3iq55PmAF4tOwIf5LNcXMMMhbwzRBHkvySp/KHIZmXSh
         8YhThbgjSfUmzacHs7wY1Bj236Lg3Ud0T8JBfEkO5N6kLpJKe+PhZTtwNjadrRvT7B0C
         UMhO3c7SnQyZeBp5D7HJ/0kyFpc7dqaYRv1/yRbd1x6AfZz+gMVmI76x34mUCKcgH1xO
         UBeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740477463; x=1741082263;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pbDccsdvnvXtugRkdlNte2AT/NlC1k+cwn1eFCYH7po=;
        b=U4IpCL5ThyJfK33s6mhqQuw/K93ub7qxXDE1dV2g/mpb7FbEigvq2YyK0nWGaplkui
         eb1H8cM5ANjWGz48MpPlKXl6AXRjCASawXKXwZ023Zj09vVGE+49I65LsY08FgQDq1Ua
         OLYzcDGmKvfsv2U4GJK5waKpPjrsScsHgGl1lO04/kxYBupC/R6bffU8nvTULGKrm6ww
         AXKmC15MIwds6/IGcVaBc/XvN79Nt3VwFjLY0iVh68Pv4f8pR4wV4G2cPTeuo6oXEFH+
         tbnsZ7CZPwLjMpLA+4Ylbim8CPHaXsllWGMlBFPfa2LnwVhY0asJgcsLrcFY0QAuOuoV
         6x2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmxcFmW0Rl8roxLvQFDxkA6n8CgUv+JBk4xkIVXrrFvO+tnGnxBV5VNeSQSWCpXG9vHdNlyg==@lfdr.de
X-Gm-Message-State: AOJu0YyUvXaXL76WurD2WYwAx08KJOQI1ml0anD4waqwcVt6u87XhGCe
	daZj0xIk4s4Ye2ggbdtKLYO/CulY2VVx7M2OsGPy59ZfywBL+G7i
X-Google-Smtp-Source: AGHT+IFN4em487NOljsZEzTGQ0Wos53LO8lIs2gsafR6eXoFTvJz5aB6UOn9+IeZWY8V7actM6ivzQ==
X-Received: by 2002:a05:6512:3503:b0:545:95b:a335 with SMTP id 2adb3069b0e04-54838ee79abmr5442052e87.14.1740477462079;
        Tue, 25 Feb 2025 01:57:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHGQHVT9dDBKzWPBxLh9LuVC/Hc7jjRjjjOcqM4JhV4iw==
Received: by 2002:a19:2d18:0:b0:545:285c:f14f with SMTP id 2adb3069b0e04-546da1bb527ls719816e87.2.-pod-prod-08-eu;
 Tue, 25 Feb 2025 01:57:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW7bsM+MGlfpvnb0GsFCaE2JLDXQ+Gn46GnlM2kePdAW2J2ibzekNI0mE1hPHUIcYBmj22CXiUdbzM=@googlegroups.com
X-Received: by 2002:a05:6512:3f19:b0:545:646:7519 with SMTP id 2adb3069b0e04-54838d3d9d5mr6619272e87.0.1740477459500;
        Tue, 25 Feb 2025 01:57:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740477459; cv=none;
        d=google.com; s=arc-20240605;
        b=Xrd+4I/OP79Wkt1Jc7LpopWUMoJ7xo/meC74XorPnHP9QMQLa/Dna90DV56nbG0aoY
         GTqK7X97WAlqvu6okzGnBkipUSg2StiSJiU5pFXuqKx3lgUb5mkNR/803ehpOd6rNfVy
         VSto/MpJWWcJeCdkX+Us/MFSMTCvAnscs2tSxXYOnXq12i76iYxJfEo/rWYaQ87VMuEa
         0pHRShaNJI4UzHLLa1m1rLm4qrSiVxWVqZ2vX2wrCZItNjs4IOP9xekP98FIDyGiBFUr
         G2RoAy1pTVL2Suaf85H1CEjB4jIZyu/f0olQQh7Wvlh6tH1F9IEJUErRhNsf7xHKnGkB
         R5gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Um4Edc6A4+2zOBvDHaEzY8GwjZotkCtNM20WMP8p17U=;
        fh=tgdRNOnN8pw6zmeFkD4DFxk8Lrbp7cacf0GX3L/QdKE=;
        b=I60B+/EFm0vbwU81sWI4Pd3bqFaCoBcD6k5VE8JOGOLDNiVF0DSwk/FiDugUGNZL8o
         q9rfAf1me9oi7TzK6Ki1f2YSXSVNUXkijqwQvYZ8Lfxk7UqKzrmbqCq/6eKqticzTarW
         GVCGIurC76d7k1mkN8zEFdmQ/xIfT8dYi1Sj4p0kk2EKbi/BhYQwYkeA0Tm7zay8kuC6
         o6KjB9Jp1mraqcrIdwy7Xt23o+WvYIPMBW7ma3+LyeKNzdKnbagtXt//0lRixVI6oA7U
         9D7Od29WaVeIjJCtcmbTj41ZWmQyfncSEFzzsYoadvabXjG8jIqAE4ABa4F025N5HqN+
         dznQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yUnW2gK3;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yUnW2gK3;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-548514eec61si74240e87.6.2025.02.25.01.57.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Feb 2025 01:57:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 856AF21171;
	Tue, 25 Feb 2025 09:57:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4C88513888;
	Tue, 25 Feb 2025 09:57:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id tq1cEhKUvWdnHgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 25 Feb 2025 09:57:38 +0000
Message-ID: <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
Date: Tue, 25 Feb 2025 10:57:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Content-Language: en-US
To: Uladzislau Rezki <urezki@gmail.com>, Keith Busch <kbusch@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>,
 linux-nvme@lists.infradead.org, leitao@debian.org
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp> <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
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
In-Reply-To: <Z7xbrnP8kTQKYO6T@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 856AF21171
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
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FREEMAIL_TO(0.00)[gmail.com,kernel.org];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com,lists.infradead.org,debian.org];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLctujmen6hjyrx8fu4drawbuj)];
	TO_DN_SOME(0.00)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=yUnW2gK3;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=yUnW2gK3;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/24/25 12:44, Uladzislau Rezki wrote:
> On Fri, Feb 21, 2025 at 06:28:49PM +0100, Vlastimil Babka wrote:
>> On 2/21/25 17:30, Keith Busch wrote:
>> > On Wed, Aug 07, 2024 at 12:31:19PM +0200, Vlastimil Babka wrote:
>> >> We would like to replace call_rcu() users with kfree_rcu() where the
>> >> existing callback is just a kmem_cache_free(). However this causes
>> >> issues when the cache can be destroyed (such as due to module unload).
>> >> 
>> >> Currently such modules should be issuing rcu_barrier() before
>> >> kmem_cache_destroy() to have their call_rcu() callbacks processed first.
>> >> This barrier is however not sufficient for kfree_rcu() in flight due
>> >> to the batching introduced by a35d16905efc ("rcu: Add basic support for
>> >> kfree_rcu() batching").
>> >> 
>> >> This is not a problem for kmalloc caches which are never destroyed, but
>> >> since removing SLOB, kfree_rcu() is allowed also for any other cache,
>> >> that might be destroyed.
>> >> 
>> >> In order not to complicate the API, put the responsibility for handling
>> >> outstanding kfree_rcu() in kmem_cache_destroy() itself. Use the newly
>> >> introduced kvfree_rcu_barrier() to wait before destroying the cache.
>> >> This is similar to how we issue rcu_barrier() for SLAB_TYPESAFE_BY_RCU
>> >> caches, but has to be done earlier, as the latter only needs to wait for
>> >> the empty slab pages to finish freeing, and not objects from the slab.
>> >> 
>> >> Users of call_rcu() with arbitrary callbacks should still issue
>> >> rcu_barrier() before destroying the cache and unloading the module, as
>> >> kvfree_rcu_barrier() is not a superset of rcu_barrier() and the
>> >> callbacks may be invoking module code or performing other actions that
>> >> are necessary for a successful unload.
>> >> 
>> >> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> >> ---
>> >>  mm/slab_common.c | 3 +++
>> >>  1 file changed, 3 insertions(+)
>> >> 
>> >> diff --git a/mm/slab_common.c b/mm/slab_common.c
>> >> index c40227d5fa07..1a2873293f5d 100644
>> >> --- a/mm/slab_common.c
>> >> +++ b/mm/slab_common.c
>> >> @@ -508,6 +508,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
>> >>  	if (unlikely(!s) || !kasan_check_byte(s))
>> >>  		return;
>> >>  
>> >> +	/* in-flight kfree_rcu()'s may include objects from our cache */
>> >> +	kvfree_rcu_barrier();
>> >> +
>> >>  	cpus_read_lock();
>> >>  	mutex_lock(&slab_mutex);
>> > 
>> > This patch appears to be triggering a new warning in certain conditions
>> > when tearing down an nvme namespace's block device. Stack trace is at
>> > the end.
>> > 
>> > The warning indicates that this shouldn't be called from a
>> > WQ_MEM_RECLAIM workqueue. This workqueue is responsible for bringing up
>> > and tearing down block devices, so this is a memory reclaim use AIUI.
>> > I'm a bit confused why we can't tear down a disk from within a memory
>> > reclaim workqueue. Is the recommended solution to simply remove the WQ
>> > flag when creating the workqueue?
>> 
>> I think it's reasonable to expect a memory reclaim related action would
>> destroy a kmem cache. Mateusz's suggestion would work around the issue, but
>> then we could get another surprising warning elsewhere. Also making the
>> kmem_cache destroys async can be tricky when a recreation happens
>> immediately under the same name (implications with sysfs/debugfs etc). We
>> managed to make the destroying synchronous as part of this series and it
>> would be great to keep it that way.
>> 
>> >   ------------[ cut here ]------------
>> >   workqueue: WQ_MEM_RECLAIM nvme-wq:nvme_scan_work is flushing !WQ_MEM_RECLAIM events_unbound:kfree_rcu_work
>> 
>> Maybe instead kfree_rcu_work should be using a WQ_MEM_RECLAIM workqueue? It
>> is after all freeing memory. Ulad, what do you think?
>> 
> We reclaim memory, therefore WQ_MEM_RECLAIM seems what we need.
> AFAIR, there is an extra rescue worker, which can really help
> under a low memory condition in a way that we do a progress.
> 
> Do we have a reproducer of mentioned splat?

I tried to create a kunit test for it, but it doesn't trigger anything. Maybe
it's too simple, or racy, and thus we are not flushing any of the queues from
kvfree_rcu_barrier()?

----8<----
From 1e19ea78e7fe254034970f75e3b7cb705be50163 Mon Sep 17 00:00:00 2001
From: Vlastimil Babka <vbabka@suse.cz>
Date: Tue, 25 Feb 2025 10:51:28 +0100
Subject: [PATCH] add test for kmem_cache_destroy in a workqueue

---
 lib/slub_kunit.c | 48 ++++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 48 insertions(+)

diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
index f11691315c2f..5fe9775fba05 100644
--- a/lib/slub_kunit.c
+++ b/lib/slub_kunit.c
@@ -6,6 +6,7 @@
 #include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/rcupdate.h>
+#include <linux/delay.h>
 #include "../mm/slab.h"
 
 static struct kunit_resource resource;
@@ -181,6 +182,52 @@ static void test_kfree_rcu(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, 0, slab_errors);
 }
 
+struct cache_destroy_work {
+        struct work_struct work;
+        struct kmem_cache *s;
+};
+
+static void cache_destroy_workfn(struct work_struct *w)
+{
+	struct cache_destroy_work *cdw;
+
+	cdw = container_of(w, struct cache_destroy_work, work);
+
+	kmem_cache_destroy(cdw->s);
+}
+
+static void test_kfree_rcu_wq_destroy(struct kunit *test)
+{
+	struct test_kfree_rcu_struct *p;
+	struct cache_destroy_work cdw;
+	struct workqueue_struct *wq;
+	struct kmem_cache *s;
+
+	if (IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST))
+		kunit_skip(test, "can't do kfree_rcu() when test is built-in");
+
+	INIT_WORK_ONSTACK(&cdw.work, cache_destroy_workfn);
+	wq = alloc_workqueue("test_kfree_rcu_destroy_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
+	if (!wq)
+		kunit_skip(test, "failed to alloc wq");
+
+	s = test_kmem_cache_create("TestSlub_kfree_rcu_wq_destroy",
+				   sizeof(struct test_kfree_rcu_struct),
+				   SLAB_NO_MERGE);
+	p = kmem_cache_alloc(s, GFP_KERNEL);
+
+	kfree_rcu(p, rcu);
+
+	cdw.s = s;
+	queue_work(wq, &cdw.work);
+	msleep(1000);
+	flush_work(&cdw.work);
+
+	destroy_workqueue(wq);
+
+	KUNIT_EXPECT_EQ(test, 0, slab_errors);
+}
+
 static void test_leak_destroy(struct kunit *test)
 {
 	struct kmem_cache *s = test_kmem_cache_create("TestSlub_leak_destroy",
@@ -254,6 +301,7 @@ static struct kunit_case test_cases[] = {
 	KUNIT_CASE(test_clobber_redzone_free),
 	KUNIT_CASE(test_kmalloc_redzone_access),
 	KUNIT_CASE(test_kfree_rcu),
+	KUNIT_CASE(test_kfree_rcu_wq_destroy),
 	KUNIT_CASE(test_leak_destroy),
 	KUNIT_CASE(test_krealloc_redzone_zeroing),
 	{}
-- 
2.48.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ef97428b-f6e7-481e-b47e-375cc76653ad%40suse.cz.
