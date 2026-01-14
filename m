Return-Path: <kasan-dev+bncBDXYDPH3S4OBBX6BT3FQMGQEFZVV7LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C0AFD1F3E1
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 14:57:53 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id a640c23a62f3a-b7cea4b3f15sf1160543166b.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 05:57:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768399072; cv=pass;
        d=google.com; s=arc-20240605;
        b=aSMCdpqG8APdvNO0/gm8IQx9YA8WABzwfFUKS0gQo51bkldmkmIKAFDvl+OInsHaRx
         CkWqdgrGFP2ITg4IvE8v9N25OTuXyfETBuec5r+r1rvRDk2X9FdQhRq9lfn16kNpJZFL
         U7uGwe7Idjks+lVfecV9y+HPMpRT4U8s0A1zfVkoer8t19RYAu9OchokscUtrhhetKdm
         eJLGUWUmYwdKY9/0CGNTh4C2zopq42ytqvWk7k5Jl6G/EKwTSkjZFrTkXkoPNwDfAWEX
         GRnc2Kc+dXnq5Ya9vDtVVnsj+CziGVb3e7SmtbsqNDyzXrY3Uak/HE8+gzXIMlqewU8a
         8RtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=LhLra0FF4f3s+FTspyfuI84n8SVL9itJaCMeQc3Mvgs=;
        fh=0MmUJ6lveTQMAs7cHd4xCOYRahVozZwsNqz5/LCq6dk=;
        b=Lx8/rt/klW2aTHBSViN+lI8GgBBTTxE6g6lT6Mqcyyw02VChGBiMye4xzgpD3DjCm7
         A65dSiD8PqWr+iZOtzy28+gHYbcfiYMI4ug9Bu58pAPg+c63J0+3uXMh9tCr+F2bxYZY
         qDycUqCw9zTBih2rXxCgpnbGu7xF339anbN/GywK4nDnm+AsZHV4mQrqje4Y5q/8cFCU
         6BZxmT+6eh6FvTA1MUk+bvtzu7/f9Z2whSlXjKQ19SlvNjz8MQC7EUGM7X5OCcndVYta
         vff0s2DjKPSiVmRKS7VvFGKoDAGWzH/kfr6WOJzYGzE28VhbukKDjEqc6iCvnSElTxei
         suzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BQannB2C;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BQannB2C;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768399072; x=1769003872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LhLra0FF4f3s+FTspyfuI84n8SVL9itJaCMeQc3Mvgs=;
        b=ZIQRIslGK6mIE8hEATWVT4Bmk2KcbTNRTGwyXG/RX8bjSfX148xmViS7wwZJ/7va6k
         9z5DLeB53w4KTp/2gefRhXL75/21g2T2jWiWvy/Xec2C67wwguacA4av6T1cq19ITRLw
         IgzsklDW2MRlfQvIFWhTzIfvRoBQtePmvEnqtsMi1emEGNMwJoY1s94SzxNw6ELKJD9O
         vpx6h62NssWUvzRZvIgedAxDzL2YUfQ/agAYB++VpnCC8vY5ZGxTnDvGoWmfhc2cyXgl
         SJ3jnsgwzKp0K0i/52+He+67ESCwepdIw61OwJuW+/P8Pj7dQ3zr9aeuWFn1wBHIkpPG
         JpJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768399072; x=1769003872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LhLra0FF4f3s+FTspyfuI84n8SVL9itJaCMeQc3Mvgs=;
        b=f7gB8XnQIT6VBsxaHjgvYnHEmw6brO6h+OWqt7QsGukc6Dxjj6euGiJupK3PqDtFEq
         1zT7hHSOZAjXNa7P5lO3gPi4Ive0S2WmxLy0w81fJilLm4t0M13yNzZ9PuUJDjSfxQhP
         CNevXraabo8kEVJSwMSqUrQega0CHQMiP4t/GGgdf2InZB6IZ0m44r3HdQbLTK+B9Wx+
         X0kQqFLxsnUo1E09rKhWWWnPTf9pPsSK+46ObGYj3v7H9o4W9AILuFh7RWlj84o2GEBS
         G/PYiK8V4al1O2nNPlnMT1oF7L1worSNGBpxLQO9mutxztDBXFNRZKwrM2ov9Mua8/6x
         QrOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvbXvCbURe7AYhADDjyKJHGwmZK8x/mgOgcLO18CXhwm+lrVCZ08PRjCCu+jl/bt1YWTE5Ng==@lfdr.de
X-Gm-Message-State: AOJu0YwlIk3RpAw1mNmJyBqeyMpAaCI2/XaXY0UxKKSNSfpEdPVMrit5
	ImkahbluZ6bSUjRkXZCKWIhat6xSJrwGiNh6RCn74+jE6SVNdf3dCvt2
X-Received: by 2002:a17:907:60d3:b0:b76:8163:f1f8 with SMTP id a640c23a62f3a-b87677e4550mr176734666b.53.1768399072397;
        Wed, 14 Jan 2026 05:57:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HGrzERdmQBxa5XzgfjFlh9DrxqMJMVgjGr8WjE9zqEbg=="
Received: by 2002:a05:6402:20c4:10b0:647:a4b1:7993 with SMTP id
 4fb4d7f45d1cf-650748c8f82ls3764333a12.1.-pod-prod-03-eu; Wed, 14 Jan 2026
 05:57:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWImXefy5rv+WCDPpFlYyIjiYvmHDpmm/SrKTgLy/DumPwTK/iZcvi3QEqd3paS5fbqPqzGVD25Se8=@googlegroups.com
X-Received: by 2002:a17:906:6a0f:b0:b87:fad:442b with SMTP id a640c23a62f3a-b876766e97bmr186205866b.3.1768399070034;
        Wed, 14 Jan 2026 05:57:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768399070; cv=none;
        d=google.com; s=arc-20240605;
        b=FHWB3n0EdU+Gz+4EkkvmwEveS4v5gkLbkglQxnti5D2Kjx2Pd6mwW3/73bogFaHgHF
         EuFtNW1DOt8ZsZvTQVaCMvqzBfCQwkIKHdqOJpvYYrP4RkyT1s00cqulpOLmch2dXYlX
         tuwk9/9R6gH8SUzsBcMV0uek4G1MmXDS+KLf32Q3UQy+/pwhMBwy6aJyb6B/PmIhqeZ6
         J7YSk7CdZUPtA0llzQKFH8NJ0hw41GAJHLFe7nWu8QMCQ/6jobYH5n21bqbmlU+2OtLP
         sSxqe6pbRef/FZoqhfqiX6IvJDntdE5D5HS/N0vdc9PfKFk9ILlX2JS70phvvNGZ7ms3
         iL9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=pkLtCD3VeUT4+7u4NR2PnnGS/Xl6g5UrZVDdOLhFDZE=;
        fh=So1Uy5/+WpIrmqaQOS84fH4eAlGwGLueBmod5uHpWrM=;
        b=fDFAbClOppVP9gj1mII24IaAsIr+H00+WYfY58OpX7NTXF33eECqtjg+Xd8VBDIjYT
         80t1A60PV/2d05Q8cgGFRSU+2bzrywGEY7kgsUDPsoqsVXOe/kE7uTT8c9bP9xStLggg
         jq3QGzbsT+vEN2ux8J3lLR1oho61tQrf1cpdrE6FoCiRIJOfNJOB6cTuXsgjJrVkDZuv
         uWFKq08xNK0LaQdpz7gClC/PwbjJc9X6PC+ETAbujMhdSZQRONy0Xs1WDvn0M9TJOVcG
         Z/xGoxyzODXpOWsXVPVTW+x0y1CcvJPufCUSVBqFEX59dVK8IOL8ml2t0T55WN9b1Nx1
         c4hQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BQannB2C;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BQannB2C;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b870d104efdsi22561266b.4.2026.01.14.05.57.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jan 2026 05:57:49 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6605E5C879;
	Wed, 14 Jan 2026 13:57:49 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3DF3C3EA63;
	Wed, 14 Jan 2026 13:57:49 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id EC/ODt2gZ2mZLAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 14 Jan 2026 13:57:49 +0000
Message-ID: <596a5461-eb50-40e5-88ca-d5dbe1fc6a67@suse.cz>
Date: Wed, 14 Jan 2026 14:57:48 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 06/20] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Content-Language: en-US
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>,
 linux-mm <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>,
 linux-rt-devel@lists.linux.dev, bpf <bpf@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz>
 <20260113183604.ykHFYvV2@linutronix.de>
 <CAADnVQK0Y2ha--EndLUfk_7n8na9CfnTpvqPMYbH07+MTJ9UpA@mail.gmail.com>
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
 AQIXgBYhBKlA1DSZLC6OmRA9UCJPp+fMgqZkBQJnyBr8BQka0IFQAAoJECJPp+fMgqZkqmMQ
 AIbGN95ptUMUvo6aAdhxaOCHXp1DfIBuIOK/zpx8ylY4pOwu3GRe4dQ8u4XS9gaZ96Gj4bC+
 jwWcSmn+TjtKW3rH1dRKopvC07tSJIGGVyw7ieV/5cbFffA8NL0ILowzVg8w1ipnz1VTkWDr
 2zcfslxJsJ6vhXw5/npcY0ldeC1E8f6UUoa4eyoskd70vO0wOAoGd02ZkJoox3F5ODM0kjHu
 Y97VLOa3GG66lh+ZEelVZEujHfKceCw9G3PMvEzyLFbXvSOigZQMdKzQ8D/OChwqig8wFBmV
 QCPS4yDdmZP3oeDHRjJ9jvMUKoYODiNKsl2F+xXwyRM2qoKRqFlhCn4usVd1+wmv9iLV8nPs
 2Db1ZIa49fJet3Sk3PN4bV1rAPuWvtbuTBN39Q/6MgkLTYHb84HyFKw14Rqe5YorrBLbF3rl
 M51Dpf6Egu1yTJDHCTEwePWug4XI11FT8lK0LNnHNpbhTCYRjX73iWOnFraJNcURld1jL1nV
 r/LRD+/e2gNtSTPK0Qkon6HcOBZnxRoqtazTU6YQRmGlT0v+rukj/cn5sToYibWLn+RoV1CE
 Qj6tApOiHBkpEsCzHGu+iDQ1WT0Idtdynst738f/uCeCMkdRu4WMZjteQaqvARFwCy3P/jpK
 uvzMtves5HvZw33ZwOtMCgbpce00DaET4y/UzsBNBFsZNTUBCACfQfpSsWJZyi+SHoRdVyX5
 J6rI7okc4+b571a7RXD5UhS9dlVRVVAtrU9ANSLqPTQKGVxHrqD39XSw8hxK61pw8p90pg4G
 /N3iuWEvyt+t0SxDDkClnGsDyRhlUyEWYFEoBrrCizbmahOUwqkJbNMfzj5Y7n7OIJOxNRkB
 IBOjPdF26dMP69BwePQao1M8Acrrex9sAHYjQGyVmReRjVEtv9iG4DoTsnIR3amKVk6si4Ea
 X/mrapJqSCcBUVYUFH8M7bsm4CSxier5ofy8jTEa/CfvkqpKThTMCQPNZKY7hke5qEq1CBk2
 wxhX48ZrJEFf1v3NuV3OimgsF2odzieNABEBAAHCwXwEGAEKACYCGwwWIQSpQNQ0mSwujpkQ
 PVAiT6fnzIKmZAUCZ8gcVAUJFhTonwAKCRAiT6fnzIKmZLY8D/9uo3Ut9yi2YCuASWxr7QQZ
 lJCViArjymbxYB5NdOeC50/0gnhK4pgdHlE2MdwF6o34x7TPFGpjNFvycZqccSQPJ/gibwNA
 zx3q9vJT4Vw+YbiyS53iSBLXMweeVV1Jd9IjAoL+EqB0cbxoFXvnjkvP1foiiF5r73jCd4PR
 rD+GoX5BZ7AZmFYmuJYBm28STM2NA6LhT0X+2su16f/HtummENKcMwom0hNu3MBNPUOrujtW
 khQrWcJNAAsy4yMoJ2Lw51T/5X5Hc7jQ9da9fyqu+phqlVtn70qpPvgWy4HRhr25fCAEXZDp
 xG4RNmTm+pqorHOqhBkI7wA7P/nyPo7ZEc3L+ZkQ37u0nlOyrjbNUniPGxPxv1imVq8IyycG
 AN5FaFxtiELK22gvudghLJaDiRBhn8/AhXc642/Z/yIpizE2xG4KU4AXzb6C+o7LX/WmmsWP
 Ly6jamSg6tvrdo4/e87lUedEqCtrp2o1xpn5zongf6cQkaLZKQcBQnPmgHO5OG8+50u88D9I
 rywqgzTUhHFKKF6/9L/lYtrNcHU8Z6Y4Ju/MLUiNYkmtrGIMnkjKCiRqlRrZE/v5YFHbayRD
 dJKXobXTtCBYpLJM4ZYRpGZXne/FAtWNe4KbNJJqxMvrTOrnIatPj8NhBVI0RSJRsbilh6TE
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQK0Y2ha--EndLUfk_7n8na9CfnTpvqPMYbH07+MTJ9UpA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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
	FREEMAIL_TO(0.00)[gmail.com,linutronix.de];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Score: -3.01
X-Rspamd-Queue-Id: 6605E5C879
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=BQannB2C;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=BQannB2C;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/14/26 00:26, Alexei Starovoitov wrote:
> On Tue, Jan 13, 2026 at 10:36=E2=80=AFAM Sebastian Andrzej Siewior
> <bigeasy@linutronix.de> wrote:
>>
>> On 2026-01-12 16:17:00 [+0100], Vlastimil Babka wrote:
>> > --- a/mm/slub.c
>> > +++ b/mm/slub.c
>> > @@ -5727,6 +5742,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t =
gfp_flags, int node)
>> >                */
>> >               return NULL;
>> >
>> > +     ret =3D alloc_from_pcs(s, alloc_gfp, node);
>> > +     if (ret)
>> > +             goto success;
>>
>> I'm sorry if I am slow but this actually should actually allow
>> kmalloc_nolock() allocations on PREEMPT_RT from atomic context. I am
>> mentioning this because of the patch which removes the nmi+hardirq
>> condtion (https://lore.kernel.org/all/20260113150639.48407-1-swarajgaikw=
ad1925@gmail.com)
>=20
> Right. With sheaves kmalloc_nolock() on RT will be more reliable.

Yes IIRC Hao Li pointed that out before. We'll be able to remove that
!preemptible() check that we area about to add by the patch above.

But I'm not sure we can remove (or "not put back") the "in_nmi() ||
in_hardirq()" too, because as you said it was added with different reasonin=
g
initially?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
96a5461-eb50-40e5-88ca-d5dbe1fc6a67%40suse.cz.
