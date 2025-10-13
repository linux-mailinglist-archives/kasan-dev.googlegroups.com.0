Return-Path: <kasan-dev+bncBDXYDPH3S4OBBF5HWTDQMGQEHQO2GHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A5E1BD3C5D
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Oct 2025 16:58:33 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-634a73b5966sf3688524a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Oct 2025 07:58:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760367512; cv=pass;
        d=google.com; s=arc-20240605;
        b=j++jccd0vU3hTrau/Y0mxb4CNbxMbfBi4uCwuEgBsR4s83mIgTm2CNGbMxBZ+NRS+Z
         TlniBq5oq82iCOs5E6StMf+u12xlG/CC1oQLLs3g+XJkx9tSimmvaumqHHhXDB6uHqUF
         64e5xVGe4+UMx6r8qOi57P3/mFBCRpa/6uvUa0qstWm57AsQua2tBAQW4BBVf0/x+Nhm
         S3P6AU3XtANTr+Z9tsqBcBG3RZ0rH3rKVsevT90+bI/PoQNANsL+R4onUGPII1RQcuhb
         T6esJj6BmOeiuUcTcaOihkto4DktVAmlGgIDmHyjr3wbJK7SjnszMGiw88xBMzt03CPq
         iFkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=5i8TwH0R3lnqNRXqTOAEN2DIyzY9y0KORvCigEFKFjo=;
        fh=kPrvle+eJZ0BYyYb0DipW2rFUeRdCafiVSOsn567lZw=;
        b=dQuEVkiaqWqzDD+sNSX4vmAadz1O1+0Xsbf2DXAYT6SX2HtXoFrvYMNbG1GdwFMyvY
         iB1O0sdSgY5K17gB7pXVixgeUT0HteVXsLKprLCtWDYyyFY+tiA6RTrPHq9ZkukeSJYA
         8vkjcvdFFNQ9nY0c+fZv5lfklhLj7DhAk6IP8HJwsWI/u/+0hOKhke2GzfgzpcOmrJDb
         96rEdaPfD77bMoyvfmGJj4WNOPmSz30y714rTJyHOiofFjAw1jnqTEEW7LMJ7j3HcGRT
         gfp7X8PRpSABANuuYJLp5cXmTuCyxGqKJMMpHiL4nyvY4gIcn6Pl5CavZgXlU+jdFFK/
         4ByA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yARdaJDo;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=V2Kj+Euk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=1DkU73VJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760367512; x=1760972312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5i8TwH0R3lnqNRXqTOAEN2DIyzY9y0KORvCigEFKFjo=;
        b=jx3p3jdBY7rCbIUMLaPfFLQl5zmIo9kY2AOPhavCELp23uT0T9Vv08PPF1fVxd2W7P
         D1bkqlRyMvzS3pY3/sX65mtKwsoI+o8mxmfOkJBjKpbeO8043epgKB7irT0KKb+SpgfO
         TQ8zNrZSesPkV9PwNw48w5+aH4+6PsPkQN/IzoX040ezntIVjhgVC+Ham/KPPvRSee25
         31ydYja7obG33txPjSnGF3C26z9T8DTF8bDH9XgJT0UccETXt1JHW5X1+Bj5EKhvL1UF
         hy9w1EGYtHtoUiV5PY6+fKjHU8dCRzqktEgXcp0fqh7SsOV/iT58xUo190dNb1pwnEMS
         /b7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760367512; x=1760972312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5i8TwH0R3lnqNRXqTOAEN2DIyzY9y0KORvCigEFKFjo=;
        b=GHyeoq00VnxgeIbnRUAsz/C/ivYK0rclHm1r7gVzUv29/9XiNHdGRDTjk3vPR6xnzd
         FWyKhdUNTn29bi6LC7HoKP6QzgIe44ScaFcvr6tSpIxJ34LhahfPRQREBhmftc9XfN7/
         btcytmqRAGJnZ8CjCkBG7t4fE3uA7ZHmgRHMJxyUpHWahGf3qvW7Kvk59EcG6/uDP8oL
         AleoO91d56JzBwHu0H/cTeKeWBRztqdMynORorBAfEMhYhVA3jHvl/UqJBBgYxKttZep
         qvEi4VE7FV/MNLJS7OmR2zi0G2qIiMTK3s7lH7mGj3GdTtl1vVP461OeJPnmxjTPTqcA
         LNhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdPHk/pKVp02sqROrX1BkYxGzdosIbnBFQ5QqYhF4UrBBviykw9olH4ulCTEEMGUN3EktkIA==@lfdr.de
X-Gm-Message-State: AOJu0YyCrxUhO79kz6t09XweGcaz00imlk1jnuu3eni8TsMM0ICEr+j4
	3A9an/yCnnBOfBANJPQStQ1ZJ/jiJIrUK7GwYkQ5Z8T0VTEdtHujYZhP
X-Google-Smtp-Source: AGHT+IFoEv72th/HydI92n5GWEkPkPJcPC4O52ZT++dIvL+RLHJ4HGlZR2JIOw5LzWo0yOTVGb8a7g==
X-Received: by 2002:a05:6402:278a:b0:639:dd8b:d327 with SMTP id 4fb4d7f45d1cf-639dd8bd6cemr17137390a12.5.1760367512231;
        Mon, 13 Oct 2025 07:58:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6iQiSD0nDHSTTY49fgN+62hysspI0Ae8F6MSDSxhulXA=="
Received: by 2002:aa7:c2c8:0:b0:639:bf3e:35c7 with SMTP id 4fb4d7f45d1cf-639f4c0b016ls3736836a12.0.-pod-prod-09-eu;
 Mon, 13 Oct 2025 07:58:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVG58B2/Ylw+mglgyT7N6C6NrXkbFDijw05Kw+FxwzISft+DS7YNVZdaHMFsZZOBKr53E+zYTcyJ/c=@googlegroups.com
X-Received: by 2002:a05:6402:13d1:b0:639:5f23:5d10 with SMTP id 4fb4d7f45d1cf-639d5c2ada4mr18208130a12.17.1760367509425;
        Mon, 13 Oct 2025 07:58:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760367509; cv=none;
        d=google.com; s=arc-20240605;
        b=PwIwYyTzgY+/P39Qus3CCVnk3jA7IVdyPLpo6F5+3Kt/Ivjlw+isfXEACLhOPVfUe4
         f6Sux6w8XHvCJ/oo7zr2UL9iApDT9HTcmXFB/xQN57yImBFwjiTjHJWV8ytih2k0Bb+S
         UHXVg8bXYs8zoO0GQWWGBaGL++TVYwhlhy+ba7nMx+b3AAP0BpMoEvtP/nHFQNS3uOs/
         JSX7G3g6RtB11zHOxoqSucyxpeLk6J/Si1wWOW4gfUOQ0FB5XokWM7OBlPQhO7pE1e1x
         nIv2BZ13wgNFFudfBe7w3EKw3fHh22v4MwsmBQuMTA3kt0vxXscs5YqVUkMsKdG/J/Yt
         daMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=qcvuerjXx7ZIiFOwSPYkO0MEVGe90oiiAUJVcvRd3Fc=;
        fh=b9JFof0+WlokIv9PQ1HKhKGW0Rx8B3WJq8BgpYXQP6M=;
        b=WOJZZ7rqZFi+seX39j77kcSvYgpswAx1IbuKJ4bJOQJVsNkE2zMfZr9vpQhCqx1OHk
         t5GgA4Hht7LyLe00QB/UWdJV7/1Z77Eo+lJmlmmcq0vcxu4X6Mg6BRNb2A5qxVqCTOBi
         KkMiMtNBQ4OKz2E1BbybNTWmTi6DowNcZgG1DXj2owfz5HEDupJDOO1ug/edo1WWVwfk
         QJobsAAlaOHnN7IWTc9SvWhmvJpUsTqnMLIfVfkz7yJfWdukYLtxp6GKTMPyOl7x34lM
         wMXkkYgl9l4ejzIDjP+QSLsOgb/pNIROlGIxLiEaghCx6BT6XrgcLKnPfH1LpMFlckbU
         ZH4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yARdaJDo;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=V2Kj+Euk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=1DkU73VJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63b96dabd59si107896a12.1.2025.10.13.07.58.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Oct 2025 07:58:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CD49921246;
	Mon, 13 Oct 2025 14:58:28 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B01471374A;
	Mon, 13 Oct 2025 14:58:28 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id d6SoKpQT7WhHNwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 13 Oct 2025 14:58:28 +0000
Message-ID: <692b6230-db0c-4369-85f0-539aa1c072bb@suse.cz>
Date: Mon, 13 Oct 2025 16:58:28 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linus:master] [slab] af92793e52:
 BUG_kmalloc-#(Not_tainted):Freepointer_corrupt
Content-Language: en-US
To: kernel test robot <oliver.sang@intel.com>,
 Alexei Starovoitov <ast@kernel.org>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, linux-kernel@vger.kernel.org,
 Harry Yoo <harry.yoo@oracle.com>, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org, linux-mm@kvack.org
References: <202510101652.7921fdc6-lkp@intel.com>
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
In-Reply-To: <202510101652.7921fdc6-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: CD49921246
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	URIBL_BLOCKED(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:email,suse.cz:mid,suse.cz:dkim,intel.com:email];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from,2a07:de40:b281:106:10:150:64:167:received];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCPT_COUNT_SEVEN(0.00)[9];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=yARdaJDo;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=V2Kj+Euk;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=1DkU73VJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/10/25 10:39, kernel test robot wrote:
> 
> 
> Hello,
> 
> kernel test robot noticed "BUG_kmalloc-#(Not_tainted):Freepointer_corrupt" on:
> 
> commit: af92793e52c3a99b828ed4bdd277fd3e11c18d08 ("slab: Introduce kmalloc_nolock() and kfree_nolock().")
> https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master
> 
> [test failed on      linus/master ec714e371f22f716a04e6ecb2a24988c92b26911]
> [test failed on linux-next/master 0b2f041c47acb45db82b4e847af6e17eb66cd32d]
> [test failed on        fix commit 83d59d81b20c09c256099d1c15d7da21969581bd]
> 
> in testcase: trinity
> version: trinity-i386-abe9de86-1_20230429
> with following parameters:
> 
> 	runtime: 300s
> 	group: group-01
> 	nr_groups: 5
> 
> 
> 
> config: i386-randconfig-012-20251004
> compiler: gcc-14
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> 
> (please refer to attached dmesg/kmsg for entire log/backtrace)
> 
> 
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202510101652.7921fdc6-lkp@intel.com

Does this fix it?
----8<----
From 5f467c4e630a7a8e5ba024d31065413bddf22cec Mon Sep 17 00:00:00 2001
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 13 Oct 2025 16:56:28 +0200
Subject: [PATCH] slab: fix clearing freelist in free_deferred_objects()

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index f9f7f3942074..080d27fe253f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -6377,15 +6377,16 @@ static void free_deferred_objects(struct irq_work *work)
 		slab = virt_to_slab(x);
 		s = slab->slab_cache;
 
+
+		/* Point 'x' back to the beginning of allocated object */
+		x -= s->offset;
 		/*
 		 * We used freepointer in 'x' to link 'x' into df->objects.
 		 * Clear it to NULL to avoid false positive detection
 		 * of "Freepointer corruption".
 		 */
-		*(void **)x = NULL;
+		set_freepointer(s, x, NULL);
 
-		/* Point 'x' back to the beginning of allocated object */
-		x -= s->offset;
 		__slab_free(s, slab, x, x, 1, _THIS_IP_);
 	}
 
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/692b6230-db0c-4369-85f0-539aa1c072bb%40suse.cz.
