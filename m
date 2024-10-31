Return-Path: <kasan-dev+bncBDXYDPH3S4OBBVPGRS4QMGQEX4K7URI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id BEE959B7572
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 08:35:55 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-539fe4e75c4sf606954e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 00:35:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730360150; cv=pass;
        d=google.com; s=arc-20240605;
        b=PzxMcasdqtUnSBWl+icZl+qdA21tZSymN5vRJrsh3C7Qf0a7PHpsUcRqzBblXMHKpj
         2YYhS7NFK63ppD+4TKo+cPNe6LZi8eA9Uu+5IdmdmfekztHOSES/zyTIzCoCxx0gcXML
         ksxpikEuUyTbF3mgRIqTIeCRegUuHQJLSuELe9S4ZNvmByNyIlihVg6ef9gHuu0WYV4q
         0Dak/EQysrcYeqeLa4YntnxUzWshqQivpLxL4EODFOtnx8suTBZYogphov5iAJRwKwZW
         RpdU7L6re89kVc4JYsDnbYBfhuxWsm60w6GmHRtcj/gO7h8N1WmwNc0BqisAl6qwsOLS
         Bvog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=4g4Ysa9zU3sT12UEr5mrEVj9cgrC/Ar/24Tj9z/lFUw=;
        fh=SMAUxrtTaEu/xPyzzu+rVcUiFF2sSA/ukNfLG8DC32s=;
        b=CXwLYX0gCZCCHyXgUvoyfqovo7v9oVbSBEx+Zg6EjQ0xgnML+aPCHlzDLEQ0KJFin4
         2QqqmSOAGShIvKFl7el6U7KrTrnK3Qltb+wAAe5CQeKNLZ2V7vcep73p2gG67/4/quMe
         9F8fJQuRJ40JwcGJtOa1n2wG9kw5eyPkeGm24+TwdGt9uvsEkXfLEWgJ5i1CN3T36TDz
         /Me12SEsQeog+kWuf1xeJRQAsVPHftvfp1+lrc2MXm9585wQ4DahzoDd7w2iXenbwtMC
         HeBipoAQRYb6YutWb0eMXh8YVGA0FY6x6LT/Yds6uL4irbmkCekrFjWcTcQoGjHdNZS2
         ioPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P5GKGcvh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tPDY9vQ5;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730360150; x=1730964950; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4g4Ysa9zU3sT12UEr5mrEVj9cgrC/Ar/24Tj9z/lFUw=;
        b=c4IPhyDElmPAmAOxrvULMBg4uWMwU8B/xNfh5DdGuEtZY07lvTpC89qO50ts7QJT5j
         j36qgfJOi7hxvCEmWtH2GIHUZb/yfVCl5fJtmzl8RI3AbMR07cSWxW9uEJcrQ717wvxT
         cgriPz+5M8BkDvlaI7JEMPXhcDZ5qYeJOwZITE/c+9zIGEea/Ep3Y1B+2DCGN9ygdBUe
         DfZNb9Iik2h7LYHKLv364cbn6S2ddZpYMmUxy8h1P/rqOn+qJ92iH0lelEB48v/1t959
         XtIbIH2SQY6rJBfiHUI7Q4p0+MjI1qwZ1s3K2j6b4VFnYfri1MtF4y/xx7DH77Lt5GIE
         7puA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730360150; x=1730964950;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4g4Ysa9zU3sT12UEr5mrEVj9cgrC/Ar/24Tj9z/lFUw=;
        b=cbHuK2b/qiKnnXhfXjOG348p6/zKB2me27iyREyN3U6fexHxTu1N03bzAIe+9q4w+l
         qCcOj/cr59E+7Gu/BrswSWQaxs58XUZYuUj1qGWfmk+9jVvrMhhI0IX09nwjT4fjNq3X
         XkIdw11FLSxx2Bmrlb1pWtWr/ZNByXQ1c71uwoOuhb2jiStCSb4hm45JjkJsd4ISYTXT
         AyCJE38+gcJGSQ47jsljEOBR/5P99SJB4JU0oevNbqkoKAyRoeOPtd0yFjB5U2dO0Y8l
         kcijTMJ7VjwLtftIRyh+0kDTLCq3gFFLfpIm8WjxC0NIl4APWsph93q4YjFQVBHfNYQy
         Vtrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW5p9NJJueWmsnjYJ0oxTcysMsayzR1xjwUw8WpPO+BrbtdAzHde9T3XmngHGHydnH2Xc7JJg==@lfdr.de
X-Gm-Message-State: AOJu0YyrONfGYzwzy4/v95N0GEcUgTsILp2/wXpcaQtQLAiS50veq3qY
	/zvqXbAd+YXI8J5+38c/PW3jygRlN9Hs9Ws9+XUx3QKpCarpovLl
X-Google-Smtp-Source: AGHT+IHuntRPGK2a9JuSAp42od+FA78TNzhCbVPeI1vZquiBH4krtwv9oSs/CU/QwYrQcr9zhgoJ2w==
X-Received: by 2002:a05:6512:3053:b0:539:a4ef:6765 with SMTP id 2adb3069b0e04-53b348ba142mr14647672e87.7.1730360149506;
        Thu, 31 Oct 2024 00:35:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:b0:53c:5873:6339 with SMTP id
 2adb3069b0e04-53c7951bbc9ls321338e87.2.-pod-prod-05-eu; Thu, 31 Oct 2024
 00:35:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvzY/niIR5UK4GHM7dY/h+E0gNqmxX0eH8WlqPOsW/ZpLIfXyN7dGjz5px5RqvHEgFrH6+DXMz3x4=@googlegroups.com
X-Received: by 2002:a05:6512:b82:b0:53b:154c:f75d with SMTP id 2adb3069b0e04-53b348dc826mr16863769e87.31.1730360147128;
        Thu, 31 Oct 2024 00:35:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730360147; cv=none;
        d=google.com; s=arc-20240605;
        b=hq3S+jxuL5R0RXQT2fkuUdH3I+mV9GaRjIc9q21hLU/Hv0RWi90+AV1agNe2vozbPq
         9WQXEpNzahUu0jpJkDxUIaB1R/bpdvbwSn6hYpAc0u/tkJaJ4Vk+3+wPwNWHqbc0tPqQ
         KOBejywzVU/888ZMb+GutStB6ZBfjS6jbGdVF3Zqo2HOjG7qBdwTq9bmrPLFmtqvV6yj
         99H5vBGKGXD0uWswteaJZfRStjJwJS43WmQA30kGNYC2y7sSJnpamyN9O9/r2CM+aMUk
         xJoqUyXv+UNYwPbzJh8FueFrU7qpfpeMFwKVm+l453xkAQkEos6L1GDUAbukvO262QsQ
         rZ3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=el/sgjgrtGnKpH9AEJY31lmmh/r2jMZ9h//gi9667CU=;
        fh=Rx8DqahIjjb9FbATRaTpT1a1pZXLJHi3OyrpawS9aNU=;
        b=QOJpzD4Z3KoLhf0C+JZ+v4rf9qXqG3+ivHxl36aw9xRKPnowmdGAuLXCXDfPtQ+QzE
         IL8ElZqQqHesdY3/lJ4eyV2Lx8zfMRbWeNHbMyg+oKFZ1WzuJ+JmedmnV4cYyQXg26MF
         ZhaOSqt4KFpmwcP9z8n/QJk/NClW49EIdefsn+w5VUgSTviqZ4FglLXbIA6qWuehTGT2
         tZ8Z/JV1Iv4t0K8waWT9HD8UNFvpyuiohKevqeDyB7frmGq8QgXAjAJWk9StEFTtkz+7
         46WeB2tVHLmceIfO9pv5K7YDjcIB6hjB2PleOf07iBk9RTEaaMMqyvIlcY/zORALZ3+9
         /wdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P5GKGcvh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tPDY9vQ5;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bc9d574si16915e87.6.2024.10.31.00.35.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2024 00:35:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id ECB6C21DCD;
	Thu, 31 Oct 2024 07:35:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CD49A13A53;
	Thu, 31 Oct 2024 07:35:45 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id RaGuMVEzI2cFCAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 31 Oct 2024 07:35:45 +0000
Message-ID: <cca52eaa-28c2-4ed5-9870-b2531ec8b2bc@suse.cz>
Date: Thu, 31 Oct 2024 08:35:45 +0100
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
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20241031072136.JxDEfP5V@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: ECB6C21DCD
X-Spam-Score: -3.01
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TAGGED_RCPT(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[google.com,vger.kernel.org,googlegroups.com,kvack.org,canb.auug.org.au,redhat.com,gmail.com,linux.com,kernel.org,lge.com,linux-foundation.org];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:dkim,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo];
	RCVD_COUNT_TWO(0.00)[2];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=P5GKGcvh;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=tPDY9vQ5;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/31/24 08:21, Sebastian Andrzej Siewior wrote:
> On 2024-10-30 16:10:58 [-0700], Paul E. McKenney wrote:
>> 
>> So I need to avoid calling kfree() within an smp_call_function() handler?
> 
> Yes. No kmalloc()/ kfree() in IRQ context.

However, isn't this the case that the rule is actually about hardirq context
on RT, and most of these operations that are in IRQ context on !RT become
the threaded interrupt context on RT, so they are actually fine? Or is smp
call callback a hardirq context on RT and thus it really can't do those
operations?

Vlastimil

>> 							Thanx, Paul
> 
> Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cca52eaa-28c2-4ed5-9870-b2531ec8b2bc%40suse.cz.
