Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5UUYLFQMGQESLFVU4Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SIU4BHiKcGkEYQAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB5UUYLFQMGQESLFVU4Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 09:12:40 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id A0BC4534C0
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 09:12:39 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-435a0fb0c9csf145298f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 00:12:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768983159; cv=pass;
        d=google.com; s=arc-20240605;
        b=iN98SdgyVCewtJwGXYlqjwFhXfB0HBH8pVP7RCE7WhpDFDK6/ssDKMq+kj3jz2glA5
         Ew+M3PPEfCajbazkq+rtsmObQm0aCyAxjcihpAjKTBsBajqZmbRjDl/dMx3rms6BjE+0
         HS3sEJHfxjBjiyQXC0XzBhFI3W7vdaXuSI3QIvglKzyGWUOkCnIflt1/3i9h3XcsIxtw
         szlIONkBAgUeaiWKSzqKUx1WtSdIWFHUG/i9Y5nGlx1QU+JLKCM2LZw4jzruWKr4+eP2
         GLJVgT9ln5OVoIvMXd3nW1KWgf4Q+okzVE3i2/CN2nFNADukoRYvTy7z931Rg/tVsjZz
         5fng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=utryVTfo/WVnrCxyGzctTwi9URU2sFQiV3T595Ohz7Y=;
        fh=dWxsvAVuA47yZoXxoFi9iHoDaaGv1wkQbHdDlieYiCY=;
        b=TzYEotqzQiNfRFhLsvhMJV9kUXtJpJOmloEVahauwHdplM94DO/QlMnlcyGz0SgieB
         JGFCYiArlDPPF2+MySokaufKT8rWDzgWCoD1WuVrc/0azR134dBlJ8H1ER4mLRNHE23L
         4V6OPPxTLC2zjMdKQ27KyoBgP/UOc9nWYWN3cjITvD66s0MkpQZb6wD7Paa7OoMIJXRZ
         XSyGAqLvkz9cCd9bA6r9jZht0sE5T2/x7MOgcT1mDRr5c8kKvcj78xOVavDXRY5oJ6HW
         KMB3uylTx1Bq1/jVQ1wHD3gTkLtsI+5VLicJSK14gYLtltIg53zHx3Kx1aRChj5IqMoY
         cgSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="kqJ/CP+P";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ienWLs4A;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768983159; x=1769587959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=utryVTfo/WVnrCxyGzctTwi9URU2sFQiV3T595Ohz7Y=;
        b=Ffcm7lUD1kCzp4CUWf2xTj7RmuNL8mCRAKXNiP6cy6yS5+lOFzWxMticPHYvNAIlvG
         INaanxgf9vFkpzgEVj71rEOGMMP3cVK0xXskHFNkGubN+SRZHRRDYXjUZAUP8nFlrSsQ
         UUX8jZi4xlIynW8/KexYz28Wc8V/7Wv5B5w5B3F+q7IifjTUUPj/EjLaIjLFC8LaCanp
         j0rSyBsY7VTzRwRRkVw4t/gMpBmXaA/e4s7oRzrcypewxLS/w7JvA2k8LyHs5phIjzm9
         ynYkGC4pYGfNu3VZRGwSht+DZMjfldtTIIwhYQZ49ZfdWjWFWpTnEt1zwCHjBQ9rvnzp
         DkDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768983159; x=1769587959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=utryVTfo/WVnrCxyGzctTwi9URU2sFQiV3T595Ohz7Y=;
        b=pXoqdTdv1bDEfYxkTAfFPpjOkP0ioksoDHQyvhasH2r4RpcGYfeoLlTnhFeOw8oyDy
         lw5z7u7ALJlBIgx/tC9WsFVkC01gVNvfUpMcEvmlGHaFZ9wb9og2858Ilu1b8b+vQqWE
         HB3N7skoCRbTtSPfxh7LMsuGIdghFaGq2mZQyVHuOaZySrQmXJLnSHBSagLrH9efY86P
         lq4gx/vferMzMLLuKY8EPGynZw5DNmA9Pp9mdWQqIk0YR47bK7JQUqC/q1TdpNUwOCYZ
         GsQop80t84rggZXLjUuUmfyNgKDv7HYa8h4z1aq4zmCpajzz3P9thPxYy+MmvJDIA36r
         MV4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLPI9db+LJr+Yn495WU9q4FNXkBDNk73HFB1Zs9It/QalTliLkv/osNyDNQTNFxPXpu4Q4Xg==@lfdr.de
X-Gm-Message-State: AOJu0YyPYZ58TXAsiSnx43pJCItHYqfAmOK49Ta/Nw5SaTDIGlBKKVGk
	Z+K7RSZRBgBR6ZZ1nv/N0ONCgTLZYgGrm6EQ4ll0bhI1IjXIzUittZgX
X-Received: by 2002:a05:6000:2c03:b0:435:8a63:b8ba with SMTP id ffacd0b85a97d-4358ff6f980mr7899840f8f.62.1768983158657;
        Wed, 21 Jan 2026 00:12:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FliMkX6t7CZ7Nm8LcIuVrLMJUEwDzknVbXriuholXMvQ=="
Received: by 2002:a5d:5706:0:b0:435:a126:d553 with SMTP id ffacd0b85a97d-435a126d791ls83618f8f.2.-pod-prod-07-eu;
 Wed, 21 Jan 2026 00:12:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUkj1t+rWGu5ngp0cEsF08rhBtBBgA5AsK5mvDTeIn9ixRWXhA6jQBTkdQCjiH8nDZ7iVCFjZKhR0s=@googlegroups.com
X-Received: by 2002:a05:6000:402a:b0:42f:b581:c69a with SMTP id ffacd0b85a97d-4358ff1c1f1mr7144048f8f.5.1768983156153;
        Wed, 21 Jan 2026 00:12:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768983156; cv=none;
        d=google.com; s=arc-20240605;
        b=DANEOiPlP6S4X4dsT86sQ8mFNm82/8rw+mD0ruIVYKDM383nH2k/x5hiA01JO7SNmH
         XUAt3C8Jj7BgqZ7+AxIuOdu8agmTkQtQ7cNEDIOr5TrGlarVYRdDgZ17J596za6LRMsN
         GBSiBx/l4zK9qluNP/mecueJB0tYt/iXJzXaRACJwIOx5OLTCxuO4YRPMzG4kjOHVGYX
         XJ4yKTZpvkGaj74ohTqhBIrCnjC+i2rlvDsazdIV4c7stSWs3BAfms10HZJ/2O6f66Hi
         qfOHA6n2dHRQVUBbuEctpbcZDCDGqZDkb3Rwp7Fu6GWnht+2yOXcVKbxznqIoWC/AZH0
         dd6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=9oU749SDo5J3PWFW4FxuIHDE7h+Fsbj9bTexCfG3H1s=;
        fh=UHA2zLRD14dK+ZrDum1QQv4E7FGYb9xhsmdq9Q4SY58=;
        b=OIfYzBf5adyLZjo2dpKn7yM73AAox414oNjDVyVxxy0/Y1bnfUuinTe/ojs19/Ebg7
         dgfo+KceAW4J74eY21sDaxuNhi97GXWGlgleJih5OqdjpKe2aFAdmvHwjKcBM0dNWtQr
         3ZP5zdS9EQJPL6CD1OX8XMqhxEPBTPb5uPZo3Uaoq/bQBL2H7gvXXyTwElmhggHzr52x
         WADcGOXjnT/9pGk+wnI5uw6Ea8n8ZQQ0NfjBVw5CyuvOPXvFDlLFaBwY3OKW2FzuWDDT
         HltW/1CUCbV/Clmxwjhmk7X19iPvLROYYqlh2RHRWoGPOcUgIkKPT4VElhLDiOzVhU2b
         PGxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="kqJ/CP+P";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ienWLs4A;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356996ed8asi324290f8f.7.2026.01.21.00.12.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 00:12:36 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 46A9933689;
	Wed, 21 Jan 2026 08:12:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1D5983EA63;
	Wed, 21 Jan 2026 08:12:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id LzYMBnKKcGlibgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Jan 2026 08:12:34 +0000
Message-ID: <89a3304d-ee46-4498-8a04-fe48d4644b75@suse.cz>
Date: Wed, 21 Jan 2026 09:12:33 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 05/21] slab: add sheaves to most caches
Content-Language: en-US
To: Breno Leitao <leitao@debian.org>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-5-5595cb000772@suse.cz>
 <aW_NK2NXVgtuzCVH@gmail.com>
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
In-Reply-To: <aW_NK2NXVgtuzCVH@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="kqJ/CP+P";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ienWLs4A;
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB5UUYLFQMGQESLFVU4Y];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-wr1-x43f.google.com:rdns,mail-wr1-x43f.google.com:helo]
X-Rspamd-Queue-Id: A0BC4534C0
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/20/26 19:47, Breno Leitao wrote:
> Hello Vlastimil,
> 
> On Fri, Jan 16, 2026 at 03:40:25PM +0100, Vlastimil Babka wrote:
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -7863,6 +7863,48 @@ static void set_cpu_partial(struct kmem_cache *s)
>>  #endif
>>  }
>>  
>> +static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
>> +					     struct kmem_cache_args *args)
>> +
>> +{
>> +	unsigned int capacity;
>> +	size_t size;
>> +
>> +
>> +	if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
>> +		return 0;
>> +
>> +	/* bootstrap caches can't have sheaves for now */
>> +	if (s->flags & SLAB_NO_OBJ_EXT)
>> +		return 0;
> 
> I've been testing this on my arm64 environment with some debug patches,
> and the machine became unbootable.
> 
> I am wondering if you should avoid SLAB_NOLEAKTRACE as well. I got the
> impression it is hitting this infinite loop:
> 
>         -> slab allocation
>           -> kmemleak_alloc()
>             -> kmem_cache_alloc(object_cache)
>               -> alloc_from_pcs() / __pcs_replace_empty_main()
>                 -> alloc_full_sheaf() -> kzalloc()
>                   -> kmemleak_alloc()
>                     -> ... (infinite recursion)
> 

Oops.

> What about something as:
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 26804859821a..0a6481aaa744 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -7445,8 +7445,13 @@ static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
>         if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
>                 return 0;
> 
> -       /* bootstrap caches can't have sheaves for now */
> -       if (s->flags & SLAB_NO_OBJ_EXT)
> +       /*
> +        * bootstrap caches can't have sheaves for now (SLAB_NO_OBJ_EXT).
> +        * SLAB_NOLEAKTRACE caches (e.g., kmemleak's object_cache) must not
> +        * have sheaves to avoid recursion when sheaf allocation triggers
> +        * kmemleak tracking.
> +        */
> +       if (s->flags & (SLAB_NO_OBJ_EXT | SLAB_NOLEAKTRACE))
>                 return 0;

Yeah that should work, will do. Thanks a lot!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/89a3304d-ee46-4498-8a04-fe48d4644b75%40suse.cz.
