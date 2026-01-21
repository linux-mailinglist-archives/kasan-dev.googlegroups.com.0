Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDOGYTFQMGQETQABEJQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UOCBAg8jcWl8eQAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBDOGYTFQMGQETQABEJQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 20:03:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 977A55BC28
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 20:03:42 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-47edc79ff28sf1127565e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 11:03:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769022222; cv=pass;
        d=google.com; s=arc-20240605;
        b=IMtz6RnBxu6FjvumT4y2HEZYsPgCSD2kiKeLXBpmpgUlJ6CFrhI1UqyvFRKJdMb1RE
         FZn+V60BIYNDYbD7VqpQRnUQpC6HhRtqxvOoeFMGCnEZf5GcwXIAepyhm7BRc4yNaH/r
         nwb27Pznq0zOJYG8LIOxUPtIVrNqRPt5U3BUBKA3p6NV1fImFSw9IL7klaekKHBt2DBN
         hg/wOcRfMAiNQa6Q4agByj7nttsgQRJe8BOg0aHBM1xWXrk3DZK3quBDONPGLOUZD54Z
         yCdYe/Up8oPPQ1ngxTrimkptcH3ClBJJklP9RSh+QjGSJOAzmZpp7ibl5KHNixv1TcpO
         +DXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=WAcWgRqPOjJI3pm6T6fHaRcZt/kg6MkDSX52YtJwGV4=;
        fh=K1IDP85OTDBQn9Ui04MNAXbigU+sCAJf62Uk9GfN6jM=;
        b=eXQeDE7IwfvMt3LHild5toxkRtX0wLOmX0FbV5gsbc0TQeS0lzdfXkckEQnvi2MI0S
         9ScjQzhBArlB2GpUGtpvZ/f/Rkc0mzPLnpKSh7/4k356IDPQk57Lsavf87fILhKLLwgB
         0lFBqKGMvcKtyjQKyzReU4Baou3wg7dr8dswSwJsFl3HejSqVt3/AtWzbTsCEww8Lsmq
         gPFOdEjiy8Jj9/SsiR9LR7vPvp2p15p9mvBpzTbKAqNFG4LVkxHapZpwkb2xHPqEn0rz
         mKnZMBalCJYVdLtgqTvkYdvbjpePeBb54qzNp3EqdPeJc0ywNh7LD/SiFfrKNldc2COX
         QVtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=daIUECt6;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ps48yUo6;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769022222; x=1769627022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WAcWgRqPOjJI3pm6T6fHaRcZt/kg6MkDSX52YtJwGV4=;
        b=u5KRLgxy18jXkwA7AoIviAWPrCavjRrcQo7JznI2BNWDeiEbwRelA98JTQVIYAU3ps
         1m/Q22NQWP4c/zhy4acMIgS6da1HPbN5v7mZaKtl16q2q2aMkvb+VyJv6j2VLpVnnWuk
         yhUe3fIsP8c6jV5ECpDSfN2wy8/oIgSdAv/eTwXtkUXnEItFToeOBG7M3oBPOghPTPsT
         3LV82cdHJGZ2VCmww2RTmkB75y4nLGZy2AQ9er1w6ixwMBNOU2cdnxas9mPvHQP+9NDG
         rLQ8Qy+/nmzAR1NONi3yPxECzu/gbdWTavWRFLUMQDwUFCIRSeDwgle+ZDOUzzU+wUc8
         v7Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769022222; x=1769627022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WAcWgRqPOjJI3pm6T6fHaRcZt/kg6MkDSX52YtJwGV4=;
        b=S5d4Q/tT6wrRF5vto7oM7++1/jHijKGhNO4MVk6XIoJdjXKH5eobLxK0mJrj4VHmno
         yIfhm33Ddrpe/llmdZVKArblRZke2Jw1ULFHzCvilWCxkvjNd/QkfdKN8fEDVG69TLG+
         wz9goGpd0cA/Sibo6pTw1/JjWc77wG6BxZ/yb/qpapKzCTT3SdjcHOv782Imeoq3hUsR
         b6psQL1paPh7ARC+H0gjG0aCvF3t3ODhNJOFTXgTF1OugL8GZXscl/X4tpkT2Qi1EIut
         SbcNAITLsCdOm2Iq//weKf7kNQOvas6ijx9GkkEHY1iBBFabShWQye2OQVPDW8VN9MvN
         TQZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWO9/M7RkigiazIT9A2VZXZkyX/n5YaSx0XYLteRHlAjFBF9Lqj4BwVgzLwhCc2HQvLXcQQgw==@lfdr.de
X-Gm-Message-State: AOJu0YzxSrtLnoSzda27WD15IVQkM0+3wZY50A9JaktzKpWcG1T+u+qD
	TtLcKcmWdDngUT7mTjwLPbKsIaNAs18xP/3F7P2HgnngtFcqBv4zM5Wr
X-Received: by 2002:a05:600c:4fc7:b0:480:41f2:b212 with SMTP id 5b1f17b1804b1-48042f7e0e0mr51589435e9.25.1769022221604;
        Wed, 21 Jan 2026 11:03:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F7sHcCjb9Fdo4oHu3eY0f6WJPE1l8kNccWZjqIFqTFNw=="
Received: by 2002:a05:600c:1c02:b0:477:5d33:983b with SMTP id
 5b1f17b1804b1-48046fc241dls863415e9.2.-pod-prod-01-eu; Wed, 21 Jan 2026
 11:03:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWp9QUoYcki39ja4T5pf5n0/V42bhC1w3OBPyBydLAaPHTMAWxUAII3nVSKiArUawWc02rN+Hkoyyk=@googlegroups.com
X-Received: by 2002:a05:600c:8109:b0:480:2548:6f9c with SMTP id 5b1f17b1804b1-4802548706dmr217558875e9.6.1769022219325;
        Wed, 21 Jan 2026 11:03:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769022219; cv=none;
        d=google.com; s=arc-20240605;
        b=cpAaVFhrXp1m3s4thkRRIHc1VE4DVQribduvJkdf71eMMS6vDdAUoD4HwY3kGHWgXR
         +Ps6aSV3l1Bg2MOPxAxwJOcvMAvtXjc4JItG3HxgCwthVjxWTV0bmyAfofqRHLbVQicB
         Xei5YHJ270jWQOq/b0j8x4Raz70Z27uxo0SkpjGIvFpR+4ZIavYHgB2ghzSJelXmaWJc
         Cn9i+3sfumghWQSJWl89bqU2bdktYZ3p5QCmfMngN6gZ/coI2XJlb80gfSrr8IOx+Vdt
         tAqeYVqBKfnpXrr+/czikOWN1f40U0E27SZoDYa7wDOH1BPnBKS/oeWyn2SHHCx2QV3H
         upjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=wrMzqW5YGuDKPkpZJVNguF5+RS5LJEqkTsioRB+4hwU=;
        fh=W+Rul3cTc5BhId7+u9fj7LzsvvMGPPEanQ/RF5XyM6c=;
        b=k3Lznqv4kTYsD3zQiEwxgBuSr8o2X3f0i8IffSySWCsSwWbNgiThjpcHuZJdHIRk3J
         WXqTDoPf3ZiWRjG4BRpbvMtrwlcdx4WS8RL1RMJIaDB0MOuxYOo4Jits8R3hB/84+xbW
         Ws3Ak5bojz7R5TlAc83e7x6HQyi0Zg4LxTvPma5ZobHsNDZ3bz/ZBttwWj/GVzffcRl9
         5tbXInWKiY4ne3AZIeb6RKveBrEWjDuk/G4UeCS6FDuAOtnPcYxlSDGxvvrroqSmn0c+
         y+Zo1AmaqbA9RqdGRYd11lhSC3mUuwzLJX/KvriOlw/vXa8gtoNKX8pVj1F6gBFOMJpz
         a3RQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=daIUECt6;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ps48yUo6;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435960bdf23si65949f8f.4.2026.01.21.11.03.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 11:03:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id CC68A5BD6D;
	Wed, 21 Jan 2026 19:03:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9A0AA3EA63;
	Wed, 21 Jan 2026 19:03:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 1W0+IwojcWm8dwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Jan 2026 19:03:38 +0000
Message-ID: <c3eefa5d-21fc-4a37-9b48-90701159baba@suse.cz>
Date: Wed, 21 Jan 2026 20:03:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 15/21] slab: remove struct kmem_cache_cpu
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>
Cc: Hao Li <hao.li@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
 David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-15-5595cb000772@suse.cz>
 <dxrm4m545d4pzxmxjve34qwxwlw4kbmuz3xwdhvjheyeosa6y7@2zezo6xejama>
 <6a814aef-7b81-4b9d-a0a5-39f7dd7daf3d@suse.cz>
 <CAJuCfpHRrFS3a8=x4shoNXHLtmvkFgV8xASsQL0-hiUBb-O1Kw@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAJuCfpHRrFS3a8=x4shoNXHLtmvkFgV8xASsQL0-hiUBb-O1Kw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=daIUECt6;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=ps48yUo6;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FREEMAIL_CC(0.00)[linux.dev,oracle.com,suse.com,gentwo.org,google.com,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBDOGYTFQMGQETQABEJQ];
	RCVD_COUNT_FIVE(0.00)[6];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+]
X-Rspamd-Queue-Id: 977A55BC28
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/21/26 18:54, Suren Baghdasaryan wrote:
> On Wed, Jan 21, 2026 at 2:29=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> On 1/20/26 13:40, Hao Li wrote:
>> > On Fri, Jan 16, 2026 at 03:40:35PM +0100, Vlastimil Babka wrote:
>> >> @@ -3853,7 +3632,7 @@ static bool has_pcs_used(int cpu, struct kmem_c=
ache *s)
>> >>  }
>> >>
>> >>  /*
>> >> - * Flush cpu slab.
>> >> + * Flush percpu sheaves
>> >>   *
>> >>   * Called from CPU work handler with migration disabled.
>> >>   */
>> >> @@ -3868,8 +3647,6 @@ static void flush_cpu_slab(struct work_struct *=
w)
>> >
>> > Nit: Would it make sense to rename flush_cpu_slab to flush_cpu_sheaf f=
or better
>> > clarity?
>>
>> OK
>>
>> > Other than that, looks good to me. Thanks.
>> >
>> > Reviewed-by: Hao Li <hao.li@linux.dev>
>=20
> I noticed one hit on deactivate_slab in the comments after applying
> the entire patchset. Other than that LGTM.

Thanks, I'll remove it as part of "slab: remove defer_deactivate_slab()"
where it belongs.

> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>=20
>>
>> Thanks!
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
3eefa5d-21fc-4a37-9b48-90701159baba%40suse.cz.
