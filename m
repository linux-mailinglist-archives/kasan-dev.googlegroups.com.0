Return-Path: <kasan-dev+bncBDXYDPH3S4OBB67RUPFQMGQELNI4N4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C98CD24EDB
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 15:26:04 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-432db1a9589sf1006940f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 06:26:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768487164; cv=pass;
        d=google.com; s=arc-20240605;
        b=CIFfnQjS3j61Q9oClaU7sZ1RIYrLvA/bQqNken02dj1lzWZEZdnX6NKG3o5CMWqrY0
         qYxdiafJbbIZUu2zcWlmldjpOgwFcJTLTGuQI59xih3y2GT27yRhpnY9wDUm+vqfF/q5
         /NHXzlC1lIH4+syRb/GpP8gxWvhCEJoW7jN1wgqnjs4Rqf8TMuaw6Xpm8xy0Wx8E+CJn
         XR2bgCqZyC/yhnmANp3iBBxeRaWc5AzHzsWR9FpjW8lFTswYJwTNrtVEwb1c5XNX+IS1
         wOubnj3JWw1upMzfs91af1r2SUNtd9Pg5gzxw1XUos6gyC2Ktfp281koDhAKeGEu7IsO
         Qwaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=v2NTDmYpzjihBc7Sl+6g86UfZqSksH2ckgsQx9HyQRM=;
        fh=SxYvv33pJKTZ64U4wRCVZFTsVBH+bViWD8qKpYEmCBI=;
        b=iU9AbHno1kPOzt0gviDvo1eWJY/1wP3B93WsU5YwmThHSy90/fQxzlZzwgRRDl/RoO
         PYUvmG63c1YVC99uI6E8A0O+EG1ECrE7MfCKwX+CGuN4B6ZbkCxXpbU9r9IkBfTBBex2
         8IWyyiQJG/L1RhUufJcVwsIAASUoP9eQeIEyCvn7IPJbwt6rck5enRAzfpUpbafbcB5q
         rhjVPmlXLk/xy6QUoZLDqwDrjrMJP4iGV7sInVaYOW+kTFFPBrZB+0FMlQUQvoO5WM5U
         4FSzGT3aPMg83x5RTorComydTfs1tNbHzcbTGMViTk9i4LhegW5Zyhh3vF4YZqHCI39w
         gLtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="SjCXVf/h";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=AtRUrw1V;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768487164; x=1769091964; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=v2NTDmYpzjihBc7Sl+6g86UfZqSksH2ckgsQx9HyQRM=;
        b=XkSDn7ptrTWgTBfiGDlIUS13i1ZdI5TYsqnCUgLpBBVvqjYSkX+v72AVNJIsiCLRKd
         BVPezYQC1FIkXN77kz9zrtfRl9IXGLJcpJVkMlmS1l9HyjmE8pfQTvyzf0rB7sURErq1
         gENYvp8gCT7W/YmzFOzEqD3x+4Xk6IhUntRxS/bZh6ATgjxky9gTc+HF2CYserKlqkkr
         P6XP61IyDSnCA4Uur/wcEW5Osw1Xldjw1cfBGY/KZKXQaxwsKGyVCsGefXtbXE8b8zhI
         hzEf+mtn/e3+mEMWlhuzaINCR6wfnJ698m3MiePA9Y375MTkDoLeqEtS0ZR+sXqSiJjX
         zs/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768487164; x=1769091964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v2NTDmYpzjihBc7Sl+6g86UfZqSksH2ckgsQx9HyQRM=;
        b=RLiHpNTifpfrb+e52ONoDwMIi1WLBEH4mzm3LfcScTE9S/2ZAEQQzmefieO4m2oTef
         I4z0aULfvstEhyuB7CY3d4RIjCxaGCTOh73Vw5svAdVlVXMOIV70MfNBi51yNMw3NVbk
         gIuubhYYI6atG72uPNsMmNdLpHBf6DMzFQKZcGnh8h9MtNoPpDUeZ+KkZx6yTp599Vxa
         0deVGqJMRtswZ0/pjTiYKbyy5Yi1M18VrUVwMMeZg9SYb9ZjMK6aZbUTZc++yZcE2SBp
         4rpO1jfHC4GXKT6IyoVf+jw65UnPkjIzWy0k2g4hvBH0nFhpgUWw7j6/gMV7yTAmUA9C
         JN5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWh0yxVt6TWd6Jxh8SX23/N8g+liaeH67v4HIqhg7bcrjUslcBWqupatEtUzXwqc22DnK84jw==@lfdr.de
X-Gm-Message-State: AOJu0Yzdw+3XAnIWfQ2dE2NZWmX7e//ccAPZ9yeoGCaliqJRcamyEckh
	9Kc/iKxVlHhRuk+9JjRyBihYh27KjxfnbSJDdcbepfTqb/1w69Q8W8FJ
X-Received: by 2002:a05:6000:1868:b0:432:8504:8989 with SMTP id ffacd0b85a97d-4342c557477mr8744084f8f.56.1768487163568;
        Thu, 15 Jan 2026 06:26:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E1daBBIbB+F8x31aJ6SYgpCIqnFy8TM87U6tWq7jp42w=="
Received: by 2002:a05:6000:420b:b0:42b:52c4:664f with SMTP id
 ffacd0b85a97d-43563e29c32ls601698f8f.0.-pod-prod-08-eu; Thu, 15 Jan 2026
 06:26:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVKogsyzmUUHvLvvj45MUDyfboe4AyR5u8mHw2H2pEVAEib7G/44+SuLDkCi5fIx92yTSjCf9TbrS4=@googlegroups.com
X-Received: by 2002:a5d:5f44:0:b0:432:c39d:102d with SMTP id ffacd0b85a97d-4342c38d1femr6181233f8f.0.1768487161231;
        Thu, 15 Jan 2026 06:26:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768487161; cv=none;
        d=google.com; s=arc-20240605;
        b=Nxo2S1A2xmRBvUh9zgc4rzHuPZEPiAV/joEk1Bi0PhXk9GK2SLMYPioxSHFHxdnaMo
         VKs0N7IeQA/vxnZvRj5QI/iXAsO6Ix8stzMP2QwC80FPIzxam28KOGAQSHcY8mCvuawB
         tpCSDxAyVfm/P7LrBSXsreKn9wreu/eijOepTIeG963NeQ1UBpURkXhZz6gbrHOFRnzp
         lmeQP1VBO3LNLU3HHTcIAL00trJF+pchxrtcTexOMaq+iF6LYSOy3l4u05qIRMnjIx/S
         Xga5g5qVBDJkCo9x2zjJ0bOCzQkJLtdlyEAv1TEbo1BiXSOzCL0DmT1ImnRCCbuGB+tV
         LD/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=CfTxd2GfKuJ3dsjZX+Qbvihtf44lZSO03FfpQ6Ft3Hc=;
        fh=fUpvCLsmjI/f5nVAVI5Hg//7IrzobtJkorReAhxlaCY=;
        b=cj4q7ECRUpYK1Nh9wZnuR+EW6kRh55wiZ5qDS8+7csXmZZYxOgdD1Q/txdHqP3gZEE
         2RVjBxPwdo7OHSXil+f8L9zAaLgab4crGe/tTABjsW+OVRSbctbaAJ5UQu6LPy2T1NEM
         BESeGTt7dbJD6S89GnWxxCBpGxoPxwplpKcqb1B0wODr/ZXCykZEeYxN8MoYh0CHgoW5
         J6ITg2GOJ0nm18ODXkEW+IpLCtS7w/OizWhcezGQ0xKJWVttJUkCiWpJgh9oDWsYXsPT
         VMS6rFdIjRYOJ7jWNGdYNngu9kKG67Izv0SCL7xb/DkdWpok9ImwTUK8G2Tk0eESQs7P
         sazA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="SjCXVf/h";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=AtRUrw1V;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-434af71bd60si58479f8f.8.2026.01.15.06.26.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 06:26:01 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C403C5BCEB;
	Thu, 15 Jan 2026 14:25:59 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A4A793EA63;
	Thu, 15 Jan 2026 14:25:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 79zeJ/f4aGlOZAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Jan 2026 14:25:59 +0000
Message-ID: <38de0039-e0ea-41c4-a293-400798390ea1@suse.cz>
Date: Thu, 15 Jan 2026 15:25:59 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 08/20] slab: add optimized sheaf refill from
 partial list
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-8-98225cfb50cf@suse.cz>
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
In-Reply-To: <20260112-sheaves-for-all-v2-8-98225cfb50cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="SjCXVf/h";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=AtRUrw1V;       dkim=neutral
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

On 1/12/26 16:17, Vlastimil Babka wrote:
> At this point we have sheaves enabled for all caches, but their refill
> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> slabs - now a redundant caching layer that we are about to remove.
> 
> The refill will thus be done from slabs on the node partial list.
> Introduce new functions that can do that in an optimized way as it's
> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> 
> Extend struct partial_context so it can return a list of slabs from the
> partial list with the sum of free objects in them within the requested
> min and max.
> 
> Introduce get_partial_node_bulk() that removes the slabs from freelist
> and returns them in the list.
> 
> Introduce get_freelist_nofreeze() which grabs the freelist without
> freezing the slab.
> 
> Introduce alloc_from_new_slab() which can allocate multiple objects from
> a newly allocated slab where we don't need to synchronize with freeing.
> In some aspects it's similar to alloc_single_from_new_slab() but assumes
> the cache is a non-debug one so it can avoid some actions.
> 
> Introduce __refill_objects() that uses the functions above to fill an
> array of objects. It has to handle the possibility that the slabs will
> contain more objects that were requested, due to concurrent freeing of
> objects to those slabs. When no more slabs on partial lists are
> available, it will allocate new slabs. It is intended to be only used
> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> 
> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> only refilled from contexts that allow spinning, or even blocking.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

...

> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> +		void **p, unsigned int count, bool allow_spin)
> +{
> +	unsigned int allocated = 0;
> +	struct kmem_cache_node *n;
> +	unsigned long flags;
> +	void *object;
> +
> +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
> +
> +		n = get_node(s, slab_nid(slab));
> +
> +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> +			/* Unlucky, discard newly allocated slab */
> +			defer_deactivate_slab(slab, NULL);

This actually does dec_slabs_node() only with slab->frozen which we don't set.

> +			return 0;
> +		}
> +	}
> +
> +	object = slab->freelist;
> +	while (object && allocated < count) {
> +		p[allocated] = object;
> +		object = get_freepointer(s, object);
> +		maybe_wipe_obj_freeptr(s, p[allocated]);
> +
> +		slab->inuse++;
> +		allocated++;
> +	}
> +	slab->freelist = object;
> +
> +	if (slab->freelist) {
> +
> +		if (allow_spin) {
> +			n = get_node(s, slab_nid(slab));
> +			spin_lock_irqsave(&n->list_lock, flags);
> +		}
> +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +		spin_unlock_irqrestore(&n->list_lock, flags);
> +	}

So we should only do inc_slabs_node() here.
This also addresses the problem in 9/20 that Hao Li pointed out...

> +	return allocated;
> +}
> +

...

> +static unsigned int
> +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +		 unsigned int max)
> +{
> +	struct slab *slab, *slab2;
> +	struct partial_context pc;
> +	unsigned int refilled = 0;
> +	unsigned long flags;
> +	void *object;
> +	int node;
> +
> +	pc.flags = gfp;
> +	pc.min_objects = min;
> +	pc.max_objects = max;
> +
> +	node = numa_mem_id();
> +
> +	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> +		return 0;
> +
> +	/* TODO: consider also other nodes? */
> +	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
> +		goto new_slab;
> +
> +	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +		list_del(&slab->slab_list);
> +
> +		object = get_freelist_nofreeze(s, slab);
> +
> +		while (object && refilled < max) {
> +			p[refilled] = object;
> +			object = get_freepointer(s, object);
> +			maybe_wipe_obj_freeptr(s, p[refilled]);
> +
> +			refilled++;
> +		}
> +
> +		/*
> +		 * Freelist had more objects than we can accomodate, we need to
> +		 * free them back. We can treat it like a detached freelist, just
> +		 * need to find the tail object.
> +		 */
> +		if (unlikely(object)) {
> +			void *head = object;
> +			void *tail;
> +			int cnt = 0;
> +
> +			do {
> +				tail = object;
> +				cnt++;
> +				object = get_freepointer(s, object);
> +			} while (object);
> +			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
> +		}
> +
> +		if (refilled >= max)
> +			break;
> +	}
> +
> +	if (unlikely(!list_empty(&pc.slabs))) {
> +		struct kmem_cache_node *n = get_node(s, node);
> +
> +		spin_lock_irqsave(&n->list_lock, flags);
> +
> +		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +			if (unlikely(!slab->inuse && n->nr_partial >= s->min_partial))
> +				continue;
> +
> +			list_del(&slab->slab_list);
> +			add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +		}
> +
> +		spin_unlock_irqrestore(&n->list_lock, flags);
> +
> +		/* any slabs left are completely free and for discard */
> +		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +			list_del(&slab->slab_list);
> +			discard_slab(s, slab);
> +		}
> +	}
> +
> +
> +	if (likely(refilled >= min))
> +		goto out;
> +
> +new_slab:
> +
> +	slab = new_slab(s, pc.flags, node);
> +	if (!slab)
> +		goto out;
> +
> +	stat(s, ALLOC_SLAB);
> +	inc_slabs_node(s, slab_nid(slab), slab->objects);

And remove it from here.

> +
> +	/*
> +	 * TODO: possible optimization - if we know we will consume the whole
> +	 * slab we might skip creating the freelist?
> +	 */
> +	refilled += alloc_from_new_slab(s, slab, p + refilled, max - refilled,
> +					/* allow_spin = */ true);
> +
> +	if (refilled < min)
> +		goto new_slab;
> +out:
> +
> +	return refilled;
> +}
> +
>  static inline
>  int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  			    void **p)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/38de0039-e0ea-41c4-a293-400798390ea1%40suse.cz.
