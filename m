Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLGBSW4AMGQESJV4QOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4334E9954A5
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 18:41:18 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5398863cdfesf4441552e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 09:41:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728405677; cv=pass;
        d=google.com; s=arc-20240605;
        b=a1HjRsbau3t+wdmSABuJRaRLpz6ySB0sGtkmlq+w7m+poV6hUryPw/ykNC30Av+7Ue
         f8vZdtldFL+V3OvyUdwGeNumGBPNOztZaQ4mjQyXE/jipsTgK8ShUMkXm5DBApmT1BC1
         BaBTZM9y22LW73BJNEPGgXYvSrfqENYqf5KLzOKoqFMvBhpxY9OSfi4xA6ybF910tbt/
         VqMuo5vdcvQ63pmQ0cN6/H/FJ5DaXzYW80VXmzK2rXGoBiRzielVeOhRj2MKXwzXttzd
         FdRIe/BoWV+GEhgsu+CnOoHvCPCwYSHgHG1YoosUhIJubVN4bS55k7q5dxchpq8qVA7M
         8SUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=dEzh766jZaGnzixjAM6epd5uBbkVfkiTXcfBw3CI72w=;
        fh=743VB+qG3qAwfPBsg5V48cwD7DTMCT0wIEOHHGPjJsc=;
        b=kfcqa2qwGE0YKCNMvltn/x6XG253IK1XZXspViIoWVidPyYmX9w5OJEUMmQOjbFxox
         2w+3Cbk/UrSt+OJL3/AlKG8cwVgn+tKJv9BPfPiUfcWmWhTPdGCpWRgdZH0BJosdzV3W
         51QbCbEcB2yyqMckXmQnnRhiDdJTGv/B9GBvHIl0quxn/mZmTD2vfZ2aOMtumZ4Uo2KJ
         tq0NDWGJpzpIzdN98vAayXNxtLhMKlLYHseeyTEJGUrIePTip5IvN1bjHkQtM3JLFqxp
         nsMwuDm0AES6QEjUnnax8siHGy5jVpt8dBMNBkTymMsNuR6Y7F10MZrMCXxGjyv3GDk5
         pTHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Pvsp/E++";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Pvsp/E++";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728405677; x=1729010477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dEzh766jZaGnzixjAM6epd5uBbkVfkiTXcfBw3CI72w=;
        b=Xj4vo7RjSk0bfqCvtfTVezNFe89RxAK8mBObomxeZvMtypGplJLTUNs0v/i4WIoeta
         wRu3d+JiqNJwNoJ0JLw4stQfsza6VqADjj1kNxHhh3tLzPK2rlBlxYpctFrf+zlTN2gk
         DjC/k7K3POSiupRflVWlSbDhHQei8n9wWElQnN4MUPFcTzFhhm6U2VclQtE/fZVwWrbT
         ptbScKxGf8n/SB+QlB9omEauwhACv3slWhQtjI2rxWWctzX2CIuf0ChEECaOUEAKA8zI
         lajWTGtpPx4Z/SZx3CZIIlczZ+vwKFvwdE6s/dq8mfSE76vEgfQlmIdkBnwPKVvtErRw
         b3iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728405677; x=1729010477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dEzh766jZaGnzixjAM6epd5uBbkVfkiTXcfBw3CI72w=;
        b=Zn8azlI7r4vjNkau2b6dXH8FOMMjWQ8czQrx3V4nmyoGJTWXX3wY+4uyFwbsHQdWLU
         8Mm691ulMs9FAXeWdaOKcLyqxHl+GauRwuuZSLUQlyKf8SuWhuoEgStfnIjbYQ9PG6fC
         5A6Bu7xkpqN6p3XHIUm+i7CrkeC1oO81pkx2kB/U2hlCShxRirpcJ/JPWU7xTmdqw1x9
         lZ+YW/Tm67TxR7JU2uF3ROPhARirWlnVss9pcdeArkcKPPvweRyDIHDLNcKi6DPLPIB3
         otzJzCcND6fessP5QF/a5OAASZoYq8k/ZFK03RlL2O2IGNID2pB1OIRK9OnrFBwZPKvn
         Fm0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/i0LkkLGmCUlHRNY8eNsfUbWBUNJ62Nf6+ivEwR+qnavve7mk6QcUHWXlyQGxgEyNxj03IA==@lfdr.de
X-Gm-Message-State: AOJu0YzuoS2aSPEML6ddEVNFjh+51urVQ1l8FPSVrZA6S2rt7W/qhw/p
	+k7g2J+KOnixtyRnLGnV7EKyjS3I9Lvu8rHMFCtqgmC7UQ943sPh
X-Google-Smtp-Source: AGHT+IHtmsdng3SaaicpVex42V+thcRJW6gFi6dupdhx4IAxTVgAHqV4aQmNo0XwB2QimnFji0iykQ==
X-Received: by 2002:a05:6512:3a96:b0:533:4689:973c with SMTP id 2adb3069b0e04-539ab876ca6mr8957995e87.23.1728405676726;
        Tue, 08 Oct 2024 09:41:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b09:b0:539:92ca:8cc3 with SMTP id
 2adb3069b0e04-539a6382d46ls251618e87.1.-pod-prod-02-eu; Tue, 08 Oct 2024
 09:41:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1M1z6IpWaqKh5nfRid6peHBSfivaTcsPPiDiGaWprVqiTuqfspgl9dJgdbpsv1bGwytBkOtUYZXk=@googlegroups.com
X-Received: by 2002:a05:6512:2350:b0:52f:d090:6da6 with SMTP id 2adb3069b0e04-539ab9eb132mr7193157e87.55.1728405674458;
        Tue, 08 Oct 2024 09:41:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728405674; cv=none;
        d=google.com; s=arc-20240605;
        b=EijZyBf5Drjd+eLxmTS4X705dmNoR4WEdkwGv0lSARPrkf8YUqt5+8uZpfVlKcebHs
         4jJDyq+yhPg79pL81tWpDtigytv8+R4isj7XS4o5VEKL/cSTTUy62to09iqnNs76CChR
         6PyD/1N14ik56XZnexoLfYY+8ZZCUqbkQilffvXlVECn4hS9LnAzuMlJ4ZOlsWGYug6t
         w8+j5UGW/tAcEmk+RbikN7/IPMmdfP3bmGLzarpdYcbHMd5D+V0hF9CJt8QVT5pjdOjb
         EeGG5SQkdwWx0QXbZFSwR8SKfzZ1ye4SeejYDEAU8FWI8AQb3GnI5XHlvrKgOrvFUm6w
         zB9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=mtenrswijttyI2TZ+UORBuTHyNb0BxQkIBiJreUH8H4=;
        fh=Az/L4DZ7Gk9UJi0OGNsqGxnJTnMNLUog1TSRzF8qb7o=;
        b=NJ2GDytmmyI+KinpMOYCbE9fK2gBU0A92PMR7C3q3m0gfJLhbHy/9qAqMusZ1Puf88
         c+wdJfkupZSHDJpiqt2ZJHQyaVPgoppgx4YwdTjpvR8w7za584cYDk+sbLoe1YQfWSuv
         f8kbwk8qDq9vryOvODFka3PSE5ZDFUmgwLdNtfwouNgm/SPYDWIOTkfPzE+hFg1m/gXg
         Xxl55AhFUrOv9fSUcWQ0uiTfuiDEg1EfqwR0euOaCuN0wc2+epcErKcn+aHF9cohoCE0
         hVqQk0toq0HsGZc2KQWARBvXRL3hmQcthySiqPPhiLWp8uA0TSqsE3whhxj3p1EYhJ7k
         G2uQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Pvsp/E++";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Pvsp/E++";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539aff1ee9dsi153532e87.9.2024.10.08.09.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Oct 2024 09:41:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 8EF531FDF5;
	Tue,  8 Oct 2024 16:41:13 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 48742137CF;
	Tue,  8 Oct 2024 16:41:13 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 66s+EalgBWcBTQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 08 Oct 2024 16:41:13 +0000
Message-ID: <37807ec7-d521-4f01-bcfc-a32650d5de25@suse.cz>
Date: Tue, 8 Oct 2024 18:41:12 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Content-Language: en-US
To: paulmck@kernel.org
Cc: Uladzislau Rezki <urezki@gmail.com>, "Jason A. Donenfeld"
 <Jason@zx2c4.com>, Jakub Kicinski <kuba@kernel.org>,
 Julia Lawall <Julia.Lawall@inria.fr>, linux-block@vger.kernel.org,
 kernel-janitors@vger.kernel.org, bridge@lists.linux.dev,
 linux-trace-kernel@vger.kernel.org,
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
References: <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636> <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
 <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
 <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz> <ZnVInAV8BXhgAjP_@pc636>
 <df0716ac-c995-498c-83ee-b8c25302f9ed@suse.cz>
 <b3d9710a-805e-4e37-8295-b5ec1133d15c@paulmck-laptop>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <b3d9710a-805e-4e37-8295-b5ec1133d15c@paulmck-laptop>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.997];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	FREEMAIL_CC(0.00)[gmail.com,zx2c4.com,kernel.org,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLr583pch5u74edj9dsne3chzi)];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux-foundation.org:email]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Pvsp/E++";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Pvsp/E++";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 7/24/24 15:53, Paul E. McKenney wrote:
> On Mon, Jul 15, 2024 at 10:39:38PM +0200, Vlastimil Babka wrote:
>> On 6/21/24 11:32 AM, Uladzislau Rezki wrote:
>> > On Wed, Jun 19, 2024 at 11:28:13AM +0200, Vlastimil Babka wrote:
>> > One question. Maybe it is already late but it is better to ask rather than not.
>> > 
>> > What do you think if we have a small discussion about it on the LPC 2024 as a
>> > topic? It might be it is already late or a schedule is set by now. Or we fix
>> > it by a conference time.
>> > 
>> > Just a thought.
>> 
>> Sorry for the late reply. The MM MC turned out to be so packed I didn't even
>> propose a slab topic. We could discuss in hallway track or a BOF, but
>> hopefully if the current direction taken by my RFC brings no unexpected
>> surprise, and the necessary RCU barrier side is also feasible, this will be
>> settled by time of plumbers.
> 
> That would be even better!
> 
> 							Thanx, Paul

Hah, so it was close but my hope was fulfilled in the end!

commit bdf56c7580d267a123cc71ca0f2459c797b76fde
Merge: efdfcd40ad5e ecc4d6af979b
Author: Linus Torvalds <torvalds@linux-foundation.org>
Date:   Wed Sep 18 08:53:53 2024 +0200

    Merge tag 'slab-for-6.12' of
git://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab

So that was at 8:53 Vienna time, and Plumbers started at 10:00...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37807ec7-d521-4f01-bcfc-a32650d5de25%40suse.cz.
