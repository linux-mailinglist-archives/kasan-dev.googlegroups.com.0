Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLUW3G2QMGQEVEIN2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 67E7B94D525
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 19:00:31 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3688010b3bfsf1578481f8f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 10:00:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723222831; cv=pass;
        d=google.com; s=arc-20160816;
        b=i0XPUG6gBiwy5+xbVb5vi2Lo4edEhwlGdHjvXXekrunTvknYCWxKQhVNDY8JMt5Jqx
         O1/b5FXbvIwt8/W9G9mlQo/1bZdM6XeUkx3mHTWZChq/89Pj5AJKHckHHjv8A0rUEmPM
         f8LDXgIIRdN/Z9u2pMJgtvpG8jfzisSFZslJrKh6bskTl7RWhvoiXxvBcJyB91U+IBhY
         KrNnx8q0RgIBtqssJJ8uCkTqItlOVVdDw8dR23G6R70jasahYjhyBH94C4dvuxiSqJWY
         nM9SbzTJfH35v/ZCdk4hUnjYv4rrZ78WcyQt5/v6i6iYRUDKHOU1cK7ij7c/bBkARmz7
         TP5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=mG4zJZqGbt2kKUQXCW1B/zkkkp4JLeJDUF0zBTa/cSU=;
        fh=8eRSBGn1oI8Pqy5uYlN6G1npCTAzJUQHjtla3sBgWhI=;
        b=v1DbiwlglLZlrNljKQwReRMv5dLj7+7uICBy2q3ccB6gB0raXzK65Y4oFyKmvdT947
         WY00jF23A6yQsFbeLlHDSGGYoLy0AEKhAoSm4tliSLrI+S05O5ZiDUQZm/Ck0AMF2HvJ
         Ea4LjUg+MvoHItwZ2CFW2VZsJn0sW3N1E67PZh7+RKdb1UC0obLokmOXkFTtdTG36x/8
         zeTvzWxXYJutAuCXU7Q9wWX/u1jVpLTWB+8oTKp8Lbj0Rhc3xNn/f1oFboIV+K6miZyr
         6q3umAMBDcG0DXb+7qNLOeLU5qmLReN1lbaik5lIqG45DsJfp5HqCzuLKERfiOdqrMBZ
         QJzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LVb7AG9r;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LVb7AG9r;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723222831; x=1723827631; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mG4zJZqGbt2kKUQXCW1B/zkkkp4JLeJDUF0zBTa/cSU=;
        b=B3CaIZXk/08zq9QkNC8InDakSjGBXXNvtztGOKNf5YOOyyor+Gl54ZoiGF/MC2dXIT
         hAP6Ev4oA8ODGPRomkHomQ7d3DC5vDkkFAtagrSn0adczfvtVebiFAqhbc9/RYn6pxyk
         a0vReuK9cqIr/a7Wk1BQ5BlFvQFwXkiVYeSEwgNxdRftx1ZHl7XwocDToLveRe4+8E5g
         WEUh/Wpc3cnZS+90ia5n3JXDA3OXKGoblP5//Wv4iLY+B9XMXJk+IQTNg5wA3C83CQ3g
         4nbyuWonfqbgWXNU2a1aElNuutIBv+zPiPACtvaxQaZT7J4ySPX+28ovhz4/QcAVtKli
         qWZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723222831; x=1723827631;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mG4zJZqGbt2kKUQXCW1B/zkkkp4JLeJDUF0zBTa/cSU=;
        b=Gpnod+gjgk68s0RJabLvydr/sV8bWZGG3fZDMrIesY+PQ7X+8hD0savp2dAKsGk57O
         JO5ArRAdPHAk6odya99adbUPIT/e2Y/m0uwZ0VzZ5kCMeqRvfeSIAodTk0rg6PPvPkTB
         1uzFsiPj7/PqSegdt9nQ3JXcXUnITmdGRoyITUeUiub6WrFOVjztQmrmG8cZ3oW5cLzR
         9CsegfXpJpUwcTzphtjhm8iSjz1rh9YVpR3uJNVAzSwA//AU9iAuDV0jU5J5365RdRAS
         SKMyT+RPNAfOC3V0W03akdN/z7z84Re/YX727fwFJb+JSMvAIC3Diu9ub6V3P4btRPMm
         3llg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnUH+Ej/SIdc2Z3e9Oq4nlFzXFQWQD+cHhTqeBzPQ0veprRcR+ClfqqbRv1Z+PhT45GGfe/FdAFvUG4sdVLXh5XQS+m8a91w==
X-Gm-Message-State: AOJu0Yw5U6vQgwtxD+Xnqp9TraUKy6YziyvQrXXDQAt3xrOxx0oYqscF
	WEneORIiFi9f8XM4v8YYNacOxhUfKLgKdnezfWEMjJ47r5XIEgc1
X-Google-Smtp-Source: AGHT+IFd7EQtpyMB0U4EIUzuaUoStVtAA86aXwF4FfOfD2Jzuf+QNpzg5RBV20ml8vRney/f3vbDpw==
X-Received: by 2002:adf:fa03:0:b0:36b:d3eb:17a5 with SMTP id ffacd0b85a97d-36d5e8f2ce9mr2016937f8f.36.1723222830224;
        Fri, 09 Aug 2024 10:00:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ed4a:0:b0:368:31b2:9e96 with SMTP id ffacd0b85a97d-36c813574e4ls882774f8f.1.-pod-prod-05-eu;
 Fri, 09 Aug 2024 10:00:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVUoTGU4UVyotckxOGMTnhCdScfCiE9EkZviU6TIb/P6aoo7ETJU7WlGsLQTETFE76tvEU4QPrErKhM682M8Ao1HhzlbMn/86TpA==
X-Received: by 2002:a5d:4383:0:b0:368:7943:8b1f with SMTP id ffacd0b85a97d-36d5fd7e9c6mr1906862f8f.43.1723222828436;
        Fri, 09 Aug 2024 10:00:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723222828; cv=none;
        d=google.com; s=arc-20160816;
        b=Z2QZaCFtwLoKTPTDiH5Pe943POQVUN3Uwq7MQcEemBGt/9b80/bB24/uXUfanEndjx
         o+F1NVnid6HN5YI02XdWFgtYSOITzM1nG8G5rSEDCPANX5sW+pdCSvxzOONWGyodWJMb
         /196IRWG3p5PG6Faww77HRCKo+gZ+1iyK01OfEr7vNJOskw3qnBe8Hyzu9cf2iWoXO8n
         CCOHNMICRUKkk11B3gL5VZ4diNK1J0YYI40bHGKREBIqjYsP5nVVvjrGPFHxw7CjmdNQ
         IchbUSU4Y40saKMcMkK2E6fMVqqLDhRZ7vQYoHz/lkR4sEFa7KWaLBziizx3cTjKXB9L
         RfXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=UnpsEyaTqfp5mqmiYMWnD58QubCP6KfKObWoXHLeoao=;
        fh=0ytAKrtybo0DJYl5ndxdD6pk5TZJ2fbmETawgz/Fnm4=;
        b=vL9Tao1UVmphr0hTJzxUYd2o9SqcuGGh2R90Bh1oWiZ/LTmkEsPmyfLA+OI3VTch8i
         8MpEtjv0oFJE6u6e0H+aoIMNFv4B9dgeZhybeNoyD5uHkLG957tUPlmj4xmeiy12Fdf7
         eWqXdc4pvlzjHdaCroiW9mmMFoC9v8CpNGBhrT5wTXZEMHL2doBQFkuqsbZrDZMWx4Z1
         nLmw+8tdbqqPOqew4J+GzZVLaIiIHngBVKYXii4eBE70NsgQniutL5MaRQ9qvVV/FHLl
         0hyd+noyIIngy2I62F9gfXymfIbgqLJWS3Hdm2Bxhhbqx5KGdiZTrTEXRrAA6e38FZBT
         7eTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LVb7AG9r;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LVb7AG9r;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36d273140a8si90176f8f.3.2024.08.09.10.00.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Aug 2024 10:00:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C6D961FF9E;
	Fri,  9 Aug 2024 17:00:27 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 89BAC1379A;
	Fri,  9 Aug 2024 17:00:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id FNikICtLtmYXPgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 09 Aug 2024 17:00:27 +0000
Message-ID: <6a6c1c59-eee3-4263-9cad-53b57d78c018@suse.cz>
Date: Fri, 9 Aug 2024 19:00:27 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 5/7] rcu/kvfree: Add kvfree_rcu_barrier() API
Content-Language: en-US
To: Uladzislau Rezki <urezki@gmail.com>
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
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-5-ea79102f428c@suse.cz>
 <ZrZDPLN9CRvRrbMy@pc636>
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
In-Reply-To: <ZrZDPLN9CRvRrbMy@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -3.00
X-Rspamd-Queue-Id: C6D961FF9E
X-Spamd-Result: default: False [-3.00 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	XM_UA_NO_VERSION(0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[26];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=LVb7AG9r;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=LVb7AG9r;       dkim=neutral
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

On 8/9/24 18:26, Uladzislau Rezki wrote:
> Hello, Vlastimil!
> I need to send out a v2. What is a best way? Please let me know. I have not
> checked where this series already landed.

Hi,

you can just send it separately based on v6.11-rc2, as you did v1 and I will
replace it in the slab/for-next. Thanks!

Vlastimil

> Thank you!
> 
> --
> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a6c1c59-eee3-4263-9cad-53b57d78c018%40suse.cz.
