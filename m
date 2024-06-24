Return-Path: <kasan-dev+bncBDXYDPH3S4OBBEOD4SZQMGQEDN4RMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B2B89143C3
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 09:34:43 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-57d157cb3fcsf1796897a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 00:34:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719214482; cv=pass;
        d=google.com; s=arc-20160816;
        b=XoAzZvzMbV0t4OCdpBmmvdeNibJ4BsfsmBVkLO3PByYlg6j+ZlQ52kTvl3a77JAibF
         DuESy6xibHi7CC+cD+AOO6R9F00WE18zUZ6sp0pfbP+zcXxA8EonRnR1LGnYtGSFnMSA
         kcXuneQq0ias/qebfr+pRQCXKHZfKZz4cTRnbcrlCNwt9guqzAXEsiJR5yXOPQ1xIgCr
         YNQr9FKJogJlZy6minyxeqoq1rzQYmHoNRh6nWdZpqJ1Ey5uw+QnVQxhotVT7+ff4l9A
         UuYJltrx8iQ9q9HG1uqnl3wRnbtK1x2WxnYYXchUUHPDdxi3BTvrRAluMyD7o2mNF/Ix
         DUVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=5+o4Rk5gfWtYpQeE5g8OQ/hbkC5KC6qKVkMyryZ7w4Y=;
        fh=HJPafuoSj7f7vL2LGsV01SAIWrKuWWYRCTTEpfpeXsE=;
        b=zpCRColY4BDjzf9CgH2BxCzy12/EERYUYQHmBUxxlCoetpcIbyrK3Hlxxt0rkI10hG
         17LYuFewXZwirVwiP/ekesoj4xSQ9LvK0lth/Fqhm+Umfd8DAoiGTUtQWlJHd5sJwglu
         7MYfEJ8eD/vuH99f/TMdPeVxfSKKPSlQ7IjfUiGgantDxePbSnoZxIHLoGwUFle02dBb
         4T5FGDFWvXmavuO2ey7h1JKk7Qj4Mq9dwhcIgUTFPw5VPI9s59DyUg42Fq31lhD1LJ0C
         BDuYfAX5yKn1t3USn0SZpT9rFRUSUk23JfajaGtdd/v0a0RU7gOqCUIPCP5NRjoJWXvv
         xLfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XVaHNUHq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DKSLEMpj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719214482; x=1719819282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5+o4Rk5gfWtYpQeE5g8OQ/hbkC5KC6qKVkMyryZ7w4Y=;
        b=vOioVY9Rr9eulsgZnnxkS/Qn7oA5zQ+RmIzLS56rTxlk7zlCTfp+Wj4qCQpWpr3I4p
         UqMAq1d1HA1h4LjJ4qZWnpHAZVohy3bK+2DU99YaDmIrpeBIB9PLRv3ETQbUjLp/UlTx
         zE/5w7IUEuYgOLaHq6V5HEyq1fg0pz4uWNLOBM4yGuLqCrPviniVO+BJhS5aq9Dw8yVL
         zeabkRI4i++tX9z/iLcG3QiEX1EBCdBi73IwOJzSrCSw96VbdCRI1nRkygBHMqKbgTvJ
         d8xSNQQuPCuVV5VQKfPT3dTBOeFJ/X2vT2CiR+uEwBd313kVJQaBQyZdOpVyHbuAgdK1
         EH2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719214482; x=1719819282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5+o4Rk5gfWtYpQeE5g8OQ/hbkC5KC6qKVkMyryZ7w4Y=;
        b=Eqsd3ilP1G0FCF8XunJ5IXAvv3M7oVl1YF7WPpllxYnGtYafrNrbOTLUpmiOb0iDZb
         cw5I9C8Cxhmu1mjo8zr8liAxIhTJfBg5g1X2gVz3n/jt7Rl7lKKLCnECGSwTTC4C7RuL
         64OL7/5beXvmfXosJGIzjJ3FXxCGTtpozh9IhjjbntFJlOmO/qmJCR7h60As4JdDYNa/
         hvlZpq7G/k2CXMR0dHqXSjbcgrfue2nro8Uju0wZEi0NLzQz/tBvl/FdtNV4FijZvn0i
         RDCbVa4ipny4Dto0EBFZ7JYSP2eqwgwhN51YnurO40EONhHNRg5S5rb+6BwpAMA/ILaA
         1BKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVVJ6W+yAE4V6J6zoAB3fyQwGueYj2gzoZGAnBRANBsfqKgh1w1bfoOBF7UwPm+pmh4HYHKrNtJcvWftk+NOF8zLHSxzH4nPA==
X-Gm-Message-State: AOJu0Yym5SrrPRNKc+4OHdzcSx8O3dvjwGR9zQjGUt/RGTjxmLde1ACr
	r5G7IzPaRzaRjc/0rghNp45xdq0ZYGWE3a0mCYWG1H1cv3dI0Wg9
X-Google-Smtp-Source: AGHT+IEOUXO7YJhnUdKPCjsVQe0euAurQRC6KZ5PFxn7oqKJzPpHUsJyzqumVhLqGQlb9ENPzakdkQ==
X-Received: by 2002:aa7:c382:0:b0:57d:46f4:7df5 with SMTP id 4fb4d7f45d1cf-57d46f47e4fmr2643778a12.23.1719214481725;
        Mon, 24 Jun 2024 00:34:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:dbc7:0:b0:57d:6579:d340 with SMTP id 4fb4d7f45d1cf-57d6579d415ls105959a12.0.-pod-prod-01-eu;
 Mon, 24 Jun 2024 00:34:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX26gWK54pfLSoI9lJnWE1bUkVWRgTy9LyjPV89IBWQ99gF1W1DSs2fRINBFwCRPJccLqmIFedWnW+IuPFTpy0WrKZ2gQw9gFjblA==
X-Received: by 2002:a17:906:ba81:b0:a72:5f9a:159a with SMTP id a640c23a62f3a-a725f9a19e6mr28943266b.2.1719214479743;
        Mon, 24 Jun 2024 00:34:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719214479; cv=none;
        d=google.com; s=arc-20160816;
        b=Kwx2MSQ/lDhXCk+EevPHZiDOr25Fok9oJ7jKqm9tp922WnB77UDEo1d+4yuYV5KgGZ
         ftZexpu83338bSROxHL5uywb2z8j+xWTTngg5rlFK20GDrqWy86S8T4GYP6dY2Pb7CzK
         vq4rU5VSu29e/7+kQ4/6VhEkNKvMFbVjjv9n7CEyDl7w2SXvhUnmCq6UPnaqob5wb/VX
         uObxyZ6WSa9xRx7/Uc6xFFthNw+ZPhKkTQRr8FE0Nfn7IWDTLDrToSBhppHyZ2Yl6fDi
         t8SMB46aNQQSKz0TbNwEIlu53xWYuOzYeVvjnTKy0aK0lL7TOVCWQUX6rk9PDBBM+lWX
         fMZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=n9uIGGVbJ8r8fxtPRtb3rTWtvj0CS+kX8qbLDmwrsbk=;
        fh=gtwm6qN9lskLrXqGcgQSmKN+lN7yfNQhDGa14RKei7M=;
        b=nmRBuOwmfgI2FwbiKPtr0uXBJqjtXZJm4oaar8TnRd4DtnwTB+uu3XI3YQ0bVtsvJ/
         hk8G2fyk0W3/SiMkyE1Vr0JeFLEtdAP+3T0aHQoTl2zs72fuCBYJ96K43UPi8TRBlFJo
         yMCZ5KNX6nJykmUBRKJ+e3HITz2K2VpjYyPlvq0AIrKOU64/xZyp/wqzGD0WSLf7DRlK
         MUZhjoJxngVKUYO1mCOLakVj2moP4FHo7z11hBUofG2Y8ZQ6rKc5OIes4bop9FzJs013
         abYg/QVH6cL2v0AQTtNcmtzGs7/9w2ecrCvH59kTtPVLL+mEU86iF1ajYn+/sbVzNE7b
         IZAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XVaHNUHq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DKSLEMpj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a7255b1af3csi2832366b.2.2024.06.24.00.34.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Jun 2024 00:34:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E640F1F7C0;
	Mon, 24 Jun 2024 07:34:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B26D813ACD;
	Mon, 24 Jun 2024 07:34:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id qB+lKo4heWb8fgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 24 Jun 2024 07:34:38 +0000
Message-ID: <56e9564d-0b01-484c-a491-acd6d15e0b26@suse.cz>
Date: Mon, 24 Jun 2024 09:34:38 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v7 18/38] mm: slub: Disable KMSAN when checking the
 padding bytes
Content-Language: en-US
To: Ilya Leoshkevich <iii@linux.ibm.com>,
 Alexander Gordeev <agordeev@linux.ibm.com>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
 Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>,
 Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-s390@vger.kernel.org,
 linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Sven Schnelle <svens@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
 <20240621113706.315500-19-iii@linux.ibm.com>
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
In-Reply-To: <20240621113706.315500-19-iii@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-3.00 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	RCPT_COUNT_TWELVE(0.00)[24];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux.ibm.com,google.com,gmail.com,googlegroups.com,vger.kernel.org,kvack.org,arm.com,linux.dev];
	RCVD_TLS_ALL(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received,2a07:de40:b281:104:10:150:64:97:from];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:email,suse.cz:dkim]
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Queue-Id: E640F1F7C0
X-Spam-Flag: NO
X-Spam-Score: -3.00
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=XVaHNUHq;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DKSLEMpj;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 6/21/24 1:35 PM, Ilya Leoshkevich wrote:
> Even though the KMSAN warnings generated by memchr_inv() are suppressed
> by metadata_access_enable(), its return value may still be poisoned.
> 
> The reason is that the last iteration of memchr_inv() returns
> `*start != value ? start : NULL`, where *start is poisoned. Because of
> this, somewhat counterintuitively, the shadow value computed by
> visitSelectInst() is equal to `(uintptr_t)start`.
> 
> One possibility to fix this, since the intention behind guarding
> memchr_inv() behind metadata_access_enable() is to touch poisoned
> metadata without triggering KMSAN, is to unpoison its return value.
> However, this approach is too fragile. So simply disable the KMSAN
> checks in the respective functions.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/slub.c | 16 ++++++++++++----
>  1 file changed, 12 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index b050e528112c..fcd68fcea4ab 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1176,9 +1176,16 @@ static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
>  	memset(from, data, to - from);
>  }
>  
> -static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
> -			u8 *object, char *what,
> -			u8 *start, unsigned int value, unsigned int bytes)
> +#ifdef CONFIG_KMSAN
> +#define pad_check_attributes noinline __no_kmsan_checks
> +#else
> +#define pad_check_attributes
> +#endif
> +
> +static pad_check_attributes int
> +check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
> +		       u8 *object, char *what,
> +		       u8 *start, unsigned int value, unsigned int bytes)
>  {
>  	u8 *fault;
>  	u8 *end;
> @@ -1270,7 +1277,8 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
>  }
>  
>  /* Check the pad bytes at the end of a slab page */
> -static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
> +static pad_check_attributes void
> +slab_pad_check(struct kmem_cache *s, struct slab *slab)
>  {
>  	u8 *start;
>  	u8 *fault;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56e9564d-0b01-484c-a491-acd6d15e0b26%40suse.cz.
