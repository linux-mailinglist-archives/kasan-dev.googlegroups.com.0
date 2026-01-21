Return-Path: <kasan-dev+bncBDXYDPH3S4OBBFOMYPFQMGQEC5YLHPY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IGWCAhfmcGk+awAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBFOMYPFQMGQEC5YLHPY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 15:43:35 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 9705F5892D
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 15:43:34 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-38303040a01sf32247971fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 06:43:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769006614; cv=pass;
        d=google.com; s=arc-20240605;
        b=IglwBLVzYz+39KOXCPveqlm0v3ZFpj6F0Uv9FpqoYIKMW89KBuNfW1RCaMhlh7GEKc
         UObjG4SQnSfCyV14+1DV3ft0BugTrDTZjinRZz+q01lh1BpxO3Eik/raPyT4VH7AZvTq
         EuWVkXCXzRWzguyzMTtHshgyN7bQ/K4D/vn/XiF7wcSFTrk2z2xE/uy2OS2F/0zVfjJH
         /XqBGSFWBk1O8MNtXwEZ9B/QPF2wxJHxThDks0wr0ceC5V0zt0qYj8zsjfWBy8OlqtML
         X9KBEG/Qed2juesdWLwageORgHrCt4lmDSykde6zjc0DQVJrSAhkUCDLAOiNApNuQWoW
         QrcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:references:cc:to:from:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=uAw8WyHzLQoZqPa5eHjfOkWqD7zXTHrZFZ3Tp4uh6LA=;
        fh=Pe9jnS4M9pFXBpyExfeBewI92ZiC3M7V099v48Ur7/I=;
        b=cZYUhL5cazNMAfmqq7OLh6tEHslXf+2ahbXhfQyGMJDeq/Q9K2bk3otgCN7ETkBDB7
         +w21Qb4zsNW14jP6eYI0+pG4LzirSlqgMU5znV1P61BCDnvItT9TCiLr5Gm8ezCkhZLK
         aN4RW8AovC4WiZMETh8RItAbZt7MkeozwB+/vQ0yAjQaMdVNOg8LHIDkD53FUdXnEOOi
         8lhozcZUXi0iUG9YRlFB8mF0K7/I/Kqy46bgDkiX35SIb6JFxVw5byRwEtOFtJrevJYl
         hPmBA2Q/FkVNSbUWvhMKb9Ri93Aew0UwpbOkRXclSabuuScjDcyiSSe8q9DeAPBd1YZF
         AxpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0xxDTGYP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KEs+pPW8;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769006614; x=1769611414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uAw8WyHzLQoZqPa5eHjfOkWqD7zXTHrZFZ3Tp4uh6LA=;
        b=MfcD6ypd593MJbFhzazG4DKhEKB41xKcvxdXBJv+bP2Fc99w/bL9oyannC7wdJTDIi
         j5fiiEexU/i71+WcFtVClVsvNYgecPgRYitoJyJwfjfUGz3uXMVO+F3I1c3b8L1PLLbw
         Rt2C2XX+g19Hfrmf6lZ7YMOsITCkSKYXI8huxzXErnxji5BPcj8RBrIyGVrloo/ud3CC
         ohURhYUNFzNrIEH7Tm/9TsFDh2GTxJnj5x1EKoMsdtNZPVINPB1ahFbP50zbE7Vx/iZT
         EN6BzAyBTyoHUbGU4cDvIZPWUvwcQZ1d/oC1bqfR+TxuRD2B6KjetJir4alNhLzD+vTI
         GiCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769006614; x=1769611414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=uAw8WyHzLQoZqPa5eHjfOkWqD7zXTHrZFZ3Tp4uh6LA=;
        b=QgCPp8ymYqeJdhq/4gWbLQzJpP5qbr/CXMLzLRdLA+zRxiqIxjzMgC1kQqfmWtmghI
         FP7ZzQ34beJt4gFm+U85HWUTwu/bNksS5eSamvIzTHVZ8O83QUA/82CAW/QaMSJBoaVN
         X0d+R7gCDcvLrAA+7aKg+MjzXJHIVbBu7qpi4unVvvVf90nd33ABMo8g+m5B+dlf7vUT
         luX77DM13Xb9WzerMyERgCif2BozeCmVsdgAkRtQc6Qk8iNz708VMC3QnD92GRmzsI0K
         0hw2Vtyet5Z9dTrEgbtf9LJRZoWKRylMA0SUftVnka1ycqNpkP/i5G2ZiaJTNT4EI8bd
         hTkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/XsYV7fuduj534LaXBToOW0b8leL9OGZ1JIiYKEuChwsaY/Q3j0M+4kRGOrlwNXO4Y1WU1g==@lfdr.de
X-Gm-Message-State: AOJu0YydRsIk/aA6JJ0ZzqOtJbgH3lLYw2bDziQlPWS8FO2GXvmLlLS4
	RFb5HoiTxHRWhq8Gyr44Ewv+lnACTf1piWuKFk2cVmQWWxWVzHnDeqR5
X-Received: by 2002:a05:651c:3135:b0:382:b559:8336 with SMTP id 38308e7fff4ca-3838692b20dmr61501001fa.22.1769006613648;
        Wed, 21 Jan 2026 06:43:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G5c8MQ/hzrQdbBs+Ib6pJt47c1LFUBGGLZdPxqGGSi0g=="
Received: by 2002:a05:651c:4381:10b0:383:1306:64b5 with SMTP id
 38308e7fff4ca-3836f0a553cls8415911fa.2.-pod-prod-05-eu; Wed, 21 Jan 2026
 06:43:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWTY9iJN28kBMdI/epjsrlKGsMNaMfoJMPXhIj5ItbhMHwu+8S8hlVgwIT6qykpqw+DBbxPjyB76f8=@googlegroups.com
X-Received: by 2002:a2e:a98f:0:b0:385:beca:f6dd with SMTP id 38308e7fff4ca-385becaf91cmr2055291fa.43.1769006610799;
        Wed, 21 Jan 2026 06:43:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769006610; cv=none;
        d=google.com; s=arc-20240605;
        b=BHTmKQTebTud1VSATbfzCEidGF/qHeXtan4A782iPdYzzvD7mVDjNSL+2QvUv2Ln6h
         Lwboe7lIKX9pNjT9YzVnZb7r9BTAK8/XS5oHflvmW62Tk/G5CzeBPYg6FV8AMFGH5kXb
         KJfjTOBPD/cfJSXWzIbSwpujgeJeZlJZSSeNTa/iKj9b/DHLFIgL+xC6YRYBP6V9Yxil
         eUCA+Fq2JlP8FJoScgfxaDKDtnrxayK+cDSvvib2ts6GapEvd51D/5+i4CqvcrVIpTDL
         duTHC5Ebi8S3lv7n48fwwrfVWtL55NYCJRqGggZYsztx/tk/dx0JUb+YJrWth6NXJXF2
         ipdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=EmVjSrgHwt4rC/tyfPn0I3pmKcbRZfmv2nxAbVtf+zo=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=EqUM/dFUHvrcwuV9noMrmOzn/6kvPFKlDyGFEekvo4MAViDOlUw3YKP9w1pYlZJDoT
         nAHNnWcw/x1BE7DH4TtjkpYbz9J9vbYH2BVNZ9Ynq4Wl+bf4rU0WIzY6Y3FGCZncL0JD
         bnoq64SC+xpTkdrc5EHLvjMBGgwskItp3nbm8LA8h4RhxKXvO9KVYs571K24EHUJ0uRH
         GeymJJHZUqRgH5vzGXg5/8gpvGBpnR8rWoM9F9NWkKpfgyZuTFCYYqfki7ZwR2qn+EJs
         CrCUeo21Ddf7Gf1mYFS1kNvHqfhzLl398brgO/ghA/ym2AhzHWim8OeHuGVq6rH38pwb
         H8aQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0xxDTGYP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KEs+pPW8;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e41fd6si2588321fa.6.2026.01.21.06.43.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 06:43:30 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EC3C45BD14;
	Wed, 21 Jan 2026 14:43:29 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C90643EA63;
	Wed, 21 Jan 2026 14:43:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id gXs0LxHmcGlxeQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Jan 2026 14:43:29 +0000
Message-ID: <afc38741-d647-4b28-8ffc-c752ab5bb5d6@suse.cz>
Date: Wed, 21 Jan 2026 15:43:29 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 11/21] slab: remove SLUB_CPU_PARTIAL
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz>
 <CAJuCfpHaSg2O0vZhfAD+61i7Vq=T3OeQ=NXirXMd-2GCKRAgjg@mail.gmail.com>
 <c17d4413-1ffa-4d3e-8d87-0e7c2b022c16@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <c17d4413-1ffa-4d3e-8d87-0e7c2b022c16@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0xxDTGYP;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=KEs+pPW8;       dkim=neutral
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBFOMYPFQMGQEC5YLHPY];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[17];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,mail-lj1-x237.google.com:rdns,mail-lj1-x237.google.com:helo,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 9705F5892D
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/21/26 15:22, Vlastimil Babka wrote:
> On 1/20/26 23:25, Suren Baghdasaryan wrote:
>> On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz>=
 wrote:
>>>
>>> We have removed the partial slab usage from allocation paths. Now remov=
e
>>> the whole config option and associated code.
>>>
>>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>>=20
>> I did?
>=20
> Hmm looks like you didn't. Wonder if I screwed up, or b4 did. Sorry about=
 that.

Seems like it was b4 and did for all patches, damn. Sorry, will fix up to
match reality.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
fc38741-d647-4b28-8ffc-c752ab5bb5d6%40suse.cz.
