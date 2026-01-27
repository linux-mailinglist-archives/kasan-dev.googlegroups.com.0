Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCHN4TFQMGQEBVZVYNA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WHy9BIo2eWnwvwEAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBCHN4TFQMGQEBVZVYNA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 23:04:58 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E2A69AE4F
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 23:04:57 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-b8863e43fefsf535588366b.0
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 14:04:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769551497; cv=pass;
        d=google.com; s=arc-20240605;
        b=BOhgrhf+ux+kcJ19y15kwffrZSDYVZJR54yrv9gb9YEUxQ48EV0H0kNfAqtJDO3gjE
         WCsamgAppwbMYCJDn7fKmzgdu3IK8lOJ1t7cHBgOrEJxitPPUSEO9JcLRPF/mg1H4ojE
         mC/dKbdRqrxF1rratDo3zF/m+eLNwUpQ/Ilv1jTCIuaP/fVG62jJH79RTBqAxdzR3m9w
         X4jC5sQh44u2TLzi1yBuFn1wAC25S7lzJlIs5zir6PY75h6WMYawuKi8qY5rWYPklQiH
         Mr+WbwtZ+xnpXB7b6tHB7DJf2UdT9VlcQylb47ZJAsyK5nqr5PIQWJru1JAm/4IwpENa
         A0YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=C57HB3ZbBeD9v43WYGfLInVvaJHvtaryBgRUmTyTnFY=;
        fh=TDJ/frn+jvejfY6ndZUIUnxNWSWaWvXYmYlNMrJB5F8=;
        b=WszwOUm2+JIXhxic2OL67qAqZY6seyD05mq/ghplrsqBxz5t/EVHT3gfwjZUjvqFx+
         TcO7sZDszVyAQCnctdUUlcemCBvRCvSDvq8KQ3eItja/EdSw6Xo7Ebf6khfOezugXKV2
         Pxl+xWZ9725kvhPYd2dB5ZWHbHWAZCrE9WXMlaAG1yoXfGF7XZkvYxlhWh8DTv4Gx40N
         cpAAYSdbTYb4LZdozDdqZ32Zak7iODF4Q9quY5Ab142uOGrAQ7hpTYgpSxrq88xSBZvq
         8F2za8eVFirZn4OAgLNIoedZPNlklYtc95rB4H7RH4H4nJJt/thLj6N55N79zIhGuHeL
         bmlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jwwlCpHX;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jwwlCpHX;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769551497; x=1770156297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C57HB3ZbBeD9v43WYGfLInVvaJHvtaryBgRUmTyTnFY=;
        b=gxel7HPmlCE+XZSDWiiZ0vh53W+3kHi0eQDU08tcB7s6uPIW2Yoo/yFaf96oy5VPXs
         8IxZyaQ24OFXhgXnFubPV/FrNC5A4PBZkla+D/og1VwOz/81Rfnis69N1q5SGqdbBJKF
         InxYCArjnwNQpwA5Oy6PNBkoRnG3RObmjvPKfGyCx3gxFXcnuNgKZ4Rl00+4oGOwOb5g
         O6VV03wEcaOCGUzTyx3ir8011MKJKnZbn3REdalx9nwymCoAg0W+aLP4TxBEPludT7aa
         xdPC2eZ5C2C/OqwRJO5UBPx6jgHfU3ribT5K3Gsx+g2qQX4CW8EL8GWaWSeFUP9ymIvu
         8c4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769551497; x=1770156297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C57HB3ZbBeD9v43WYGfLInVvaJHvtaryBgRUmTyTnFY=;
        b=ksZRWFJCOTzbYc670HLCH1tsiv93WB6qxqaK1WYQEZNMJqIduFQlBOILwcnu6teogO
         lEdSidNy+Pma2tfzxwsw4v9KxiVAMiA5XCHXnZa+op6AnxOvzG0PP05q7yDlTqXTSmTB
         Exy0cI1wjnXX1eNDvjpLlbmjH8I/t0z9yvTJUevKByzu91j9r6xuz8ZjVCGpPWnzFJ1l
         Curz7X5eWmmUFRRSIPakW8T6tXD/ZJt3t/0XXIZRePOT0pGIOs8VPKKLO6W7OCqF0N9v
         dGSntRwiIBBS0ZEuFMDa5A5MKR1LZTSsU8MsVgUHhCtk13JBWWqK3/ysMChDQKvI96+O
         AaKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXizPMHPD6Iwsy48rT9eL/0Dxq6GeS0vd1prnalV7iksg66Q2SM/fZDvDMMAuIzZLymKzm2Pw==@lfdr.de
X-Gm-Message-State: AOJu0YxeMfSEZXKea6EgHOV3lEF6WWcz9VT0uvWfENx7nTwxy7HFuw4L
	1TaBIkEiRJK6JvJVhySXzojVY/bkBJ/glACETRpMhq+LUAhTGvrJr7Ky
X-Received: by 2002:a17:907:3c90:b0:b83:1433:78de with SMTP id a640c23a62f3a-b8dab28cbf6mr225350466b.12.1769551496767;
        Tue, 27 Jan 2026 14:04:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fa4Tcyc4qQWcfSsDQK4g38o1iCY5qK5dpjOYNHcm3Lew=="
Received: by 2002:a05:6402:1658:b0:658:3078:75b5 with SMTP id
 4fb4d7f45d1cf-65832d546f9ls5068440a12.1.-pod-prod-03-eu; Tue, 27 Jan 2026
 14:04:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUk8lkmivNiRZ2BeTu5kb51kp0sVLjeMcb2mxftquh7tqPFsa65oHmvZYY9wc4rQXL9B91sR4Mooh8=@googlegroups.com
X-Received: by 2002:a05:6402:3481:b0:64d:1a0f:6969 with SMTP id 4fb4d7f45d1cf-658a605072emr2095817a12.5.1769551494206;
        Tue, 27 Jan 2026 14:04:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769551494; cv=none;
        d=google.com; s=arc-20240605;
        b=c9Dtz7ZGowIIpo/fQGPhtTY3rPzYqDaV5pTEWt8ZaoyxHSISw1cbqZ8hMA+jgD6Oxe
         SNfee+Djnpph6CdYfARmyxgSzWr4OKSInc+BH6NE0kjaRcPzFLUP6odsCMyt/PlVvdZD
         b8JHF81HmwZ9cdsdnwnsrBfxcM4Irf5uGEFSN1eS9OfcgfbTlKjqCbFHxZGjhTmkhBFK
         EnopNRYBTWSy6GxrcUiiMHUjuBDqc8u65j1LnviKQbZl/e8BFLcJJaMX+tFwgRx67N4j
         LJVEKCV+kW4BNA4Epsk9yQ16dBasl3p904MzIf5QTn3fz7XJDgsvEgddhOb/XgRQDKOO
         GBOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=UymD9quzWShDqRhhHiV4+B6IAQlknYB8RVGTscXzVK0=;
        fh=Mp8S2ht7XFVRLccmpoaALWFoG3+5Kxf0Z1XmraW09kM=;
        b=c4kWuOR27g+dPk6qVLdvfbYv46VQPp6bgGXMpFqbunzu6SXlyl5rcEHVw/BU7mMnw8
         liXOuJepeav9dT77C8epsT7rQxvLtM0sUsmoI2s6vmKII7b2HOMQy1F3v5JZf9Mzm2cW
         UrV+a+Qg34yIjR052R7gR9LbG/mTU4xfCCslxRmXUBidB72kClocaOc8OHyMY05s6juj
         JqPZ+ECMknkVzO7omi0MewfhszHLpMGSIyrAniHUM6VTqU/zVQR6YL7GMPgqfnOWA1FY
         HZXl6ySFLeQ2uZE6FabbReahXwe+eYppUC4zVzm98JZmKpw1+xMdGdOfS0mViT9JtP8p
         P+lA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jwwlCpHX;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jwwlCpHX;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-658b47d1c37si17244a12.5.2026.01.27.14.04.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 14:04:54 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 83A6133917;
	Tue, 27 Jan 2026 22:04:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 526383EA61;
	Tue, 27 Jan 2026 22:04:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id n56cE4U2eWnjcQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Jan 2026 22:04:53 +0000
Message-ID: <85d872a3-8192-4668-b5c4-c81ffadc74da@suse.cz>
Date: Tue, 27 Jan 2026 23:04:52 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 18/22] slab: refill sheaves from all nodes
Content-Language: en-US
To: Mateusz Guzik <mjguzik@gmail.com>
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
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-18-041323d506f7@suse.cz>
 <cburjqy3r73ojiaathpxwayvq7up263m3lvrikicrkkybdj2iz@vefohvamiqr4>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <cburjqy3r73ojiaathpxwayvq7up263m3lvrikicrkkybdj2iz@vefohvamiqr4>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jwwlCpHX;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=jwwlCpHX;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FREEMAIL_TO(0.00)[gmail.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBCHN4TFQMGQEBVZVYNA];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,hitm.total:url]
X-Rspamd-Queue-Id: 9E2A69AE4F
X-Rspamd-Action: no action

On 1/27/26 15:28, Mateusz Guzik wrote:
> On Fri, Jan 23, 2026 at 07:52:56AM +0100, Vlastimil Babka wrote:
>> __refill_objects() currently only attempts to get partial slabs from the
>> local node and then allocates new slab(s). Expand it to trying also
>> other nodes while observing the remote node defrag ratio, similarly to
>> get_any_partial().
>>=20
>> This will prevent allocating new slabs on a node while other nodes have
>> many free slabs. It does mean sheaves will contain non-local objects in
>> that case. Allocations that care about specific node will still be
>> served appropriately, but might get a slowpath allocation.
>=20
> While I can agree pulling memory from other nodes is necessary in some
> cases, I believe the patch as proposed is way too agressive and the
> commit message does not justify it.

OK it's not elaborated on much, but "similarly to get_any_partial()" means
we try to behave similarly to how this was handled before sheaves, where th=
e
very same decisions were used to obtain cpu (partial) slabs from the remote
node.

The reason is that the bots can then hopefully compare before/after sheaves
based on the real differences between those caching approaches, and not suc=
h
subtle side-effects as different numa tradeoffs.

But for bisecting performance regressions, it seems it was a mistake that I
did this part as a standalone patch and not immediately as part of patch 10
- because it was already doing too much.

> Interestingly there were already reports concerning this, for example:
> https://lore.kernel.org/oe-lkp/202601132136.77efd6d7-lkp@intel.com/T/#u
>=20
> quoting:
> * [vbabka:b4/sheaves-for-all-rebased] [slab]  aa8fdb9e25: will-it-scale.p=
er_process_ops 46.5% regression

And that's the problem as it's showing before/after this commit only. But i=
t
should also mean that patch 10 could have improved things by effectively
removing the remote numa refill aspect temporarily. Maybe it was too noisy
for a benefit report. It would be interesting to see the before/after whole
series.

> The system at hand has merely 2 nodes and it already got:
>=20
>          %stddev     %change         %stddev
>              \          |                \ =20
>       7274 =C2=B1 13%     -27.0%       5310 =C2=B1 16%  perf-c2c.DRAM.loc=
al
>       1458 =C2=B1 14%    +272.3%       5431 =C2=B1 10%  perf-c2c.DRAM.rem=
ote
>      77502 =C2=B1  9%     -58.6%      32066 =C2=B1 11%  perf-c2c.HITM.loc=
al
>     150.83 =C2=B1 12%   +2150.3%       3394 =C2=B1 12%  perf-c2c.HITM.rem=
ote
>      77653 =C2=B1  9%     -54.3%      35460 =C2=B1 10%  perf-c2c.HITM.tot=
al
>=20
> As in a significant increase in traffic.

I however doubt the regression would be so severe if this was only about "w=
e
allocated more remote objects so we are now accessing them more slower". Bu=
t
more on that later.

> Things have to be way worse on systems with 4 and more nodes.
>=20
> This is not a microbenchmark-specific problem either -- any cache miss
> on memory allocated like that induces interconnect traffic. That's a
> real slowdown in real workloads.

Sure, but that bad?

> Admittedly I don't know what the policy is at the moment, it may be
> things already suck.

As I was saying, basically the same as before sheaves, just via different
caching mechanism.
BTW there's a tunable for this -
/sys/kernel/slab/xx/remote_node_defrag_ratio

> A basic test for sanity is this: suppose you have a process whose all
> threads are bound to one node. absent memory shortage in the local
> node and allocations which somehow explicitly request a different node,
> is it going to get local memory from kmalloc et al?

All memory local? Not guaranteed.

> To my understanding with the patch at hand the answer is no.

Which is not a new thing.

> Then not only this particular process is penalized for its lifetime, but
> everything else is penalized on top -- even ignoring straight up penalty
> for interconnect traffic, there is only so much it can handle to begin
> with.
>=20
> Readily usable slabs in other nodes should be of no significance as long
> as there are enough resources locally.

Note that in general this approach can easily bite us in the end, as when
there are no more enough resources locally, it might be too late. Not
completely fitting example, but see

https://lore.kernel.org/all/20251219-costly-noretry-thisnode-fix-v1-1-e1085=
a4a0c34@suse.cz/
=20
> If you are looking to reduce total memory usage, I would instead check
> how things work out for resuing the same backing pages for differently
> sizes objects (I mean is it even implemented?) and would investigate if

This would be too complex and contrary to the basic slab design.

> additional kmalloc slab sizes would help -- there are power-of-2 jumps
> all the way to 8k. Chances are decent sizes like 384 and 768 bytes would
> in fact drop real memory requirement.
I don't think it's about trading off minimizing memory requirements
elsewhere to allow excessive per-node waste here. Sure we can tune the
decisions here to only go for remote nodes when the amount of slabs there i=
s
more out of balance than currently, etc. But we should not eliminate it
completely.

> iow, I think this patch should be dropped at least for the time being

Because it's not introducing new behavior, I think it shouldn't.

However I think I found a possible improvement that should not be a tradeof=
f
but a reasonable win. Because I noticed in the profiles also:

     54.93           +17.5       72.46        perf-profile.self.cycles-pp.n=
ative_queued_spin_lock_slowpath

And part of it is likely due to contending on the list_lock due to the
remote refills. So we could make those trylock only and see if it helps.


----8<----

From 5ac96a0bde0c3ea5cecfb4e478e49c9f6deb9c19 Mon Sep 17 00:00:00 2001
From: Vlastimil Babka <vbabka@suse.cz>
Date: Tue, 27 Jan 2026 22:40:26 +0100
Subject: [PATCH] slub: avoid list_lock contention from __refill_objects_any=
()

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 19 +++++++++++++------
 1 file changed, 13 insertions(+), 6 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 7d7e1ae1922f..3458dfbab85d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3378,7 +3378,8 @@ static inline bool pfmemalloc_match(struct slab *slab=
, gfp_t gfpflags);
=20
 static bool get_partial_node_bulk(struct kmem_cache *s,
 				  struct kmem_cache_node *n,
-				  struct partial_bulk_context *pc)
+				  struct partial_bulk_context *pc,
+				  bool allow_spin)
 {
 	struct slab *slab, *slab2;
 	unsigned int total_free =3D 0;
@@ -3390,7 +3391,10 @@ static bool get_partial_node_bulk(struct kmem_cache =
*s,
=20
 	INIT_LIST_HEAD(&pc->slabs);
=20
-	spin_lock_irqsave(&n->list_lock, flags);
+	if (allow_spin)
+		spin_lock_irqsave(&n->list_lock, flags);
+	else if (!spin_trylock_irqsave(&n->list_lock, flags))
+		return false;
=20
 	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
 		struct freelist_counters flc;
@@ -6544,7 +6548,8 @@ EXPORT_SYMBOL(kmem_cache_free_bulk);
=20
 static unsigned int
 __refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned =
int min,
-		      unsigned int max, struct kmem_cache_node *n)
+		      unsigned int max, struct kmem_cache_node *n,
+		      bool allow_spin)
 {
 	struct partial_bulk_context pc;
 	struct slab *slab, *slab2;
@@ -6556,7 +6561,7 @@ __refill_objects_node(struct kmem_cache *s, void **p,=
 gfp_t gfp, unsigned int mi
 	pc.min_objects =3D min;
 	pc.max_objects =3D max;
=20
-	if (!get_partial_node_bulk(s, n, &pc))
+	if (!get_partial_node_bulk(s, n, &pc, allow_spin))
 		return 0;
=20
 	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
@@ -6650,7 +6655,8 @@ __refill_objects_any(struct kmem_cache *s, void **p, =
gfp_t gfp, unsigned int min
 					n->nr_partial <=3D s->min_partial)
 				continue;
=20
-			r =3D __refill_objects_node(s, p, gfp, min, max, n);
+			r =3D __refill_objects_node(s, p, gfp, min, max, n,
+						  /* allow_spin =3D */ false);
 			refilled +=3D r;
=20
 			if (r >=3D min) {
@@ -6691,7 +6697,8 @@ refill_objects(struct kmem_cache *s, void **p, gfp_t =
gfp, unsigned int min,
 		return 0;
=20
 	refilled =3D __refill_objects_node(s, p, gfp, min, max,
-					 get_node(s, local_node));
+					 get_node(s, local_node),
+					 /* allow_spin =3D */ true);
 	if (refilled >=3D min)
 		return refilled;
=20
--=20
2.52.0





--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
5d872a3-8192-4668-b5c4-c81ffadc74da%40suse.cz.
