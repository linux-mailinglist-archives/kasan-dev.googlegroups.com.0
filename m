Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5H2RS4QMGQELD666GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 82AE99B7635
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 09:19:02 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-539e294566dsf406615e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 01:19:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730362742; cv=pass;
        d=google.com; s=arc-20240605;
        b=TubIFS0kUNZ6h/nEPaPDhlfDZjd3yybqY54XkzzU/SHVb0xXxtofUXwZXAyr5yiq1A
         /FhTEnp9VJlIa+TWWmsme4phVQWL7skDvAWiBHxpwyCakPRFoos9IHrcIX9bhRWh82Kv
         kI+bcWWaWcU6nKgbFl5WGQalXbAev/5HatvhDUTnvNfOdqCsgQWHdqPpHxJiWlOlLRrX
         pyLsO7YH1IycbWHe6gOa4svmPllyo5A7EwFnVPjBK5r7gITPaUOF2w0RQ71joWYfizac
         qjls5znMsKPlUpIHz1F9FslNCjxbE0JgqTJI7M5lMku58YXPXucysWCDjVSZEii7NcIN
         +UeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=1cunGafad8+TtXSlAxn7B3RIg/ln4hsypXPUppRJ5qA=;
        fh=U3PThyL64gP38dvv6pULNSjLGZ8RRIEqddVexIUoE1U=;
        b=CU8Ov9UA/6vfed2m5R9TqslFxobFWmn7UZ3YXuhnUmpL9nStbOTKDqsca69eiYNdDq
         wrvJIczcBaO1N5io3SVLResqIbG8JxC8DspN/qDoCsgeTCe6pFvxLmU1xkUjI38Nl5dX
         upWJDe4U2aqJKsw0pXnglF89erQkVqSm7oyIQC20e/mFQsLY1yqgrRg3aEvQ2ENLPV0P
         m8IeP7FtqRWuCjM3OTSjXRP/SvxkjGwzSURGVOlCrYolDav6o39P+x0Zbj7E/HkAJ0Nc
         fuV3CZYmjWqFlBHIPqgTdVAT46/yuGCgwrJdCLYe67H6fhZO16Q7gxb5DSB/qQVVC5kb
         vMqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=b9l8qFxt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FYh57hAL;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730362742; x=1730967542; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1cunGafad8+TtXSlAxn7B3RIg/ln4hsypXPUppRJ5qA=;
        b=s9jqrzj1Ksg4V0lmDJFHeU/A0X933tCJhj7mVP5iAR3l4U5SGiFemKlavmmHpmEPXa
         pbVpVLVdqwi77tXhL4qRAM/9aH+q0ugFAOeAKB2xnouTAhkCuvQ5IIGMRHDC15EnZDED
         rWjh4uXaA/ipM4TpAk+9N0d0BDSUkRmcylOs450A5yBG1KxjdQqwWSNg7RS6lHyR+eb5
         bvaTq5FhVVfqUiT4wFpTPQPZlSmfeUiTriBLI3UDWadkgwvFOuH7jbn4/v9pXp2GHk09
         ULixBa3V7rI4xeFY+vZsUxSDD5JN0q9tZ96z+ZBgfNylwdHb4lZsOCG2iVKIbvt8yvug
         E1eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730362742; x=1730967542;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1cunGafad8+TtXSlAxn7B3RIg/ln4hsypXPUppRJ5qA=;
        b=J68q49LLi4MKp3pOxkQOcW5e1Q/CS3gk2vL3G131oJNOXstcNei51dcqNo/g0LiXYR
         nI5ocRlrrxfDYWs9MScXpX4z2xotzo+vJ4iK6S/uVZbXPKNrBMY46sHNCPFumZRqSj5Q
         VEprrVjIXewFnzxVgr2ZvQghDRrFLezxTk/mzTHPD0KYBAwqjuxjG1z9Y2cQ8Xvs4VDP
         DO+o++y2znZ8xn3loFXMyltbSl55nAX2MkLyqTgilmaxpjvtKtHzbeuHHVCSowQzOOw9
         Lk+Oks8FeP2RJJmCG4MDkVjdHXjSY6F4uZl/ds8Bt/A1/FCqxUx3maVyM+ESIL76zFir
         +Bbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUB8O3T0BwiLpGhgfWl040syPCb9QDusFQTvDw0Dzo3uK8vXx2FQ8XdjR9h0eZMmrR5XvbfpA==@lfdr.de
X-Gm-Message-State: AOJu0YxJ4vlf4j9EhWDBM5xeuVhfo8szT1Q8ST/UfPw/c51QJ5F3zONN
	DftcH6n/WpaCH4lM3+wGG/8vP+gytWtI6n239m68RmGQfvxz8/kT
X-Google-Smtp-Source: AGHT+IGXn2U9qtg5ubMGtSHoGwh5ALIqQrdfbFtAbASHSpS03Ei5js1W/9GoJsBviY03ciO7nvYsug==
X-Received: by 2002:a05:6512:3084:b0:539:f371:3279 with SMTP id 2adb3069b0e04-53c79e15811mr1246417e87.7.1730362741068;
        Thu, 31 Oct 2024 01:19:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2208:b0:539:fbe2:28a0 with SMTP id
 2adb3069b0e04-53c791f56fdls217262e87.0.-pod-prod-03-eu; Thu, 31 Oct 2024
 01:18:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVS8jg4Ra9cncsEf1+LJvb2LqP509dxlZLMV8nSNhdasLpN7ppXeocmjNJthUGCv/pijUXLuLCy3hM=@googlegroups.com
X-Received: by 2002:a05:6512:1192:b0:539:f689:3c30 with SMTP id 2adb3069b0e04-53c79e325a5mr1157095e87.20.1730362735068;
        Thu, 31 Oct 2024 01:18:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730362735; cv=none;
        d=google.com; s=arc-20240605;
        b=Ui9mX/IG3iUc+ByA9ARpfz9F7w6jmBjukdc7Xq9sL31TjlJM67xWhTWrys8psBu99+
         k8Elj4B7d7FJdOcrM1U/l+XPNYOVQzvQpsigoTaywDc9rC4DC/i1SRTZpctqZxrxvHVx
         7tzN12C0WfXZ5x64hiiR1oHNva78YnGi8VO4Z5emWucEQzknl3SnPTJuESiljDlGbX46
         lKsaZy6xykFj/teAIfXT3QqmL/N3zahMmqZEHajuP9PRWpo/iyiijruIkYdjpWW/dYhk
         evfbRv2dtIraoismp21eTO9GnlP+yaqcvOavqPyKOdfOtUl9sbg0EhlohAFUtI/gEHfz
         TviQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Fda78ea5TLffiTpu5LKMqDnrbmSivkkPaSV4caIv+hU=;
        fh=Rx8DqahIjjb9FbATRaTpT1a1pZXLJHi3OyrpawS9aNU=;
        b=Ib2lf9hcoXl9nsrix8jnI1JkI63BVVjiQ67gKSamOh0O4dzM4pqZOmAtshuwxIGri1
         xkcyaLd2Pemw+3deEEgWHik+e4wt0fG+x0bJMGlLq5hHEcBJYJWRnJiiqxL4kcxONpdI
         qiCWjHeqK2Xaobl2uuEoDuFIfnSB8ZieIJiK0q3NjyprC7SSD/9PuWXvdtA+KWG0aCER
         NosFL0XBXg7GM30uxcAmHghWV1Kx3dw34bv5gmk4EznHzrER73i+1C2EPNOFxpB04sZO
         vSb0Y5Jx0ADX/3kgoyHFJaUdCwBKdfGbv5rID0SFbnIbGslUYGx+sWj4/Lgx7IrMrKo5
         N1Gg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=b9l8qFxt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FYh57hAL;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bccc6e2si16547e87.9.2024.10.31.01.18.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2024 01:18:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id F2E7A21C08;
	Thu, 31 Oct 2024 08:18:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C604C13A53;
	Thu, 31 Oct 2024 08:18:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 73n+L2w9I2fHFAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 31 Oct 2024 08:18:52 +0000
Message-ID: <751e281a-126b-4bcd-8965-71affac4a783@suse.cz>
Date: Thu, 31 Oct 2024 09:18:52 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [BUG] -next lockdep invalid wait context
Content-Language: en-US
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, linux-next@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, sfr@canb.auug.org.au, longman@redhat.com,
 boqun.feng@gmail.com, cl@linux.com, penberg@kernel.org, rientjes@google.com,
 iamjoonsoo.kim@lge.com, akpm@linux-foundation.org
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
 <ZyK0YPgtWExT4deh@elver.google.com>
 <66a745bb-d381-471c-aeee-3800a504f87d@paulmck-laptop>
 <20241031072136.JxDEfP5V@linutronix.de>
 <cca52eaa-28c2-4ed5-9870-b2531ec8b2bc@suse.cz>
 <20241031075509.hCS9Amov@linutronix.de>
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
In-Reply-To: <20241031075509.hCS9Amov@linutronix.de>
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
	RCPT_COUNT_TWELVE(0.00)[15];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[google.com,vger.kernel.org,googlegroups.com,kvack.org,canb.auug.org.au,redhat.com,gmail.com,linux.com,kernel.org,lge.com,linux-foundation.org];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=b9l8qFxt;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=FYh57hAL;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
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

On 10/31/24 08:55, Sebastian Andrzej Siewior wrote:
> On 2024-10-31 08:35:45 [+0100], Vlastimil Babka wrote:
>> On 10/31/24 08:21, Sebastian Andrzej Siewior wrote:
>> > On 2024-10-30 16:10:58 [-0700], Paul E. McKenney wrote:
>> >> 
>> >> So I need to avoid calling kfree() within an smp_call_function() handler?
>> > 
>> > Yes. No kmalloc()/ kfree() in IRQ context.
>> 
>> However, isn't this the case that the rule is actually about hardirq context
>> on RT, and most of these operations that are in IRQ context on !RT become
>> the threaded interrupt context on RT, so they are actually fine? Or is smp
>> call callback a hardirq context on RT and thus it really can't do those
>> operations?
> 
> interrupt handlers as of request_irq() are forced-threaded on RT so you
> can do kmalloc()/ kfree() there. smp_call_function.*() on the other hand
> are not threaded and invoked directly within the IRQ context.

Makes sense, thanks.

So how comes rcutorture wasn't deadlocking on RT already, is it (or RCU
itself) doing anything differently there that avoids the kfree() from
smp_call_function() handler?

>> Vlastimil
>> 
> Sebastian
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/751e281a-126b-4bcd-8965-71affac4a783%40suse.cz.
