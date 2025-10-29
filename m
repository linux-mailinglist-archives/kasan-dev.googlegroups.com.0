Return-Path: <kasan-dev+bncBDXYDPH3S4OBBVVRRLEAMGQEOVKM4QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 73837C1D9B4
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 23:44:39 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-429893e2905sf478487f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 15:44:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761777879; cv=pass;
        d=google.com; s=arc-20240605;
        b=g83nyi2aDjeSbk4jkt++jr1ZnU7tUSsS/tSzF3vqaJ2voaGPGKjjBpYpn6F94DBhBR
         lMgXdEZ6gwbArMwtv+iQvfzoCdHYrism6EUaas6TcQSAYyokwncIlOTq1Q1guKCAL1Jk
         aGg+DpSugnn/i8GVTYm0uvFc11QdS/RfO9zP0hehAj5sy34/SM3bkvdvfgWlMQok+b79
         gOJaCcsNCHfymADEk1c4CGqcFy63/y86lk1vFYmUY3U/anqhjPf0UPBm2CeTg5MVLLgZ
         +4e8EzbWnq00s3TG4r8zW2CicoZx3otjdURZ/pIl1pMvnWZeLwBnAkYAMLdgxDtSsbzk
         J/Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=+xitjK98MplmsJOC5HRpZxicGFc1jj/T4KOb/zNXbxs=;
        fh=q1isv0824J/GSkfvZ2QI3U2ma4X8G552CEiejRrthgQ=;
        b=MwEsFSSjECbFjRVJBOSfpoEED70IiCLHcdNWLKfV4hFdy8tUxb0RiNxllOoxg0z3EM
         1LmPvKFFF1nMe/snms+pibJ5s9aNHXR0fcQHLCQ5p8ZO1SmgPJV2G8nXRyWhOqWv0HTk
         b6G45cQGJnpZ83J9Gn2tBPiIJkZXzRlDD6ys9CtzJmgn3Q4Ymts+IWyJKyt4lqRacOGa
         AfTSJkwm1wpo9Vxl8qVjqpUwimBS2Cg/gn/NXC3lJBWJFMJvgGiDua8WwstvpJ+3r17n
         4EyFPTx5Yt3rLsQwGUvH73iE8+iZ+86AR55Xt83AO4Pilt03DjP2RTeIfbqKVfIpdd6U
         CFZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KuE6dmbh;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KuE6dmbh;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761777879; x=1762382679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+xitjK98MplmsJOC5HRpZxicGFc1jj/T4KOb/zNXbxs=;
        b=v8B5pnLIdxhRrkfKmDYim1jymxax42B3S4cLlUIwALuSKgezslw8jPZ4mLXPk95N3E
         uRlnznf6tEJXSs7feNkb6unmflQcNejIWprlRfMr2d3GLnpKRQ5RdbIJHW06vKJhpX54
         PbVzjuJHZlGzI6SWdGl3vCb+5Qx/xjINkhIFDFuUfc9MBVK1vhdzb6PO6m3bCSw2TAaA
         Z4vZ2m8C8+68isJMWSi6/NPtC0N4AIjKa7JapNXsMcSZ0JPm7sxzynb7tD0agV8YEaR8
         NTM0aF327OpH0AsMliG+Rhfm2Z+a+PK1k6qFnXLSHY5jQcyryqmNmVbEq2C50+SdAKWv
         kANQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761777879; x=1762382679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+xitjK98MplmsJOC5HRpZxicGFc1jj/T4KOb/zNXbxs=;
        b=pjpyKX0FUVnnijf0EYEbdzB2bN9yhvGtYi54kruP9WLBvkdFTQ7RCoTkH492MbC3tX
         kgS0MzNwGnMaZxu/qSqXenAhhANcr46YbN2hwQ4kwqJMaxmv7dlYA/mT5OljdZLegM9b
         isS3BGlKwzfOCVKQUyxcHySP4BMESIzS0caYNIFcSDKnBzp8qAB8PsgdOp6BZhGQxP3a
         bIp3Q96d78hubousIpbWK3wqfzXG5OxSZUOmJkVDDl5WHoo1DIThHNpujcnlo5t8WGZi
         nH5VVq9YIlCGYsvtga+GKxCpDvdNAjEKnps1AVears4uYY0nnUTBokRKbd3atbe1H+Rn
         5m0w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsljgmlfN8jd6VcpQD1Oa8s8JqeEDBw4LoUtz0WlB5V82CP5i+hulA6hBDC1q5DGxifmpTtw==@lfdr.de
X-Gm-Message-State: AOJu0YxuctgogWZ3Hrw+SiZpvbGkNXo/3mCqVUwS4n52TAiOEqsIDakA
	4cfcvXK8WGE/wm6taJPvjt6ED8DrlwzstrwxRHPxd3B6ipDG9yb/TZvE
X-Google-Smtp-Source: AGHT+IFUM+9D4UeI5/cLFQbkPNlLKDvW9jdtojTFRK6C+9v+qU9VdBJGMvn2efrto3S39vtmVDDGsQ==
X-Received: by 2002:a05:6000:2004:b0:429:895c:19fd with SMTP id ffacd0b85a97d-429b4c89f2cmr988151f8f.18.1761777878682;
        Wed, 29 Oct 2025 15:44:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zu74/OktAypf0mbsjBsrtLqJSVsc0G9KMgFPcNfuznSg=="
Received: by 2002:a05:600c:3ba8:b0:475:dc86:85d4 with SMTP id
 5b1f17b1804b1-477274ce89bls2370745e9.0.-pod-prod-09-eu; Wed, 29 Oct 2025
 15:44:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2j6NZoqwchdUMu1K/GvSkmEbptsNNaMgEo60Dt1efDSO6wdYTQsMO1QllowjpPyRbq/XMc9xz9E0=@googlegroups.com
X-Received: by 2002:a05:600c:3491:b0:46e:428a:b4c7 with SMTP id 5b1f17b1804b1-477267bd95bmr8308525e9.23.1761777874623;
        Wed, 29 Oct 2025 15:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761777874; cv=none;
        d=google.com; s=arc-20240605;
        b=bk0FSwqqdeFZCZtlZjSmzh+Dd06BUp5Yrzo8PpWg0uZTfeXZIwy1Pr3+YdB7dm1OeN
         oOsdmdfwBPC+vFIE7qz3TOrJMj3Yfu17rGNXVmnaHt1wvhf7chypzvt0DH4sWg1umySv
         Dc9XQBhln4tZ6vTZHnChwFuMipvy7qENBhgvsd/8tIspka3ynN7j0bSM+t1c045CSXD3
         IwBuY3OAxfDtZBFxWpiOY8LDvgQ0O8ITHUED+X07ai8Q7iCHwntx/3wWD05lQW7lEbhy
         ZmsIvSYXRm7+zLAysyyZuRWl5Rngj/hO5iW06FlMaA/tOEenalMohxuT2iC6Xj272OF7
         NfRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=nGeK7bx3Hm62BR80qyLU/cEzRG1dQ+GIaNgmFFG3WZk=;
        fh=ZkncHXpnbLWcLI4CpJ6uugsCcSSvTK4Cn+vNUpK7HFk=;
        b=XtiKwtGXt9MwegfZz3YsXdpZ2SPsiCscP3UUW0R0o+98GrQUU2KYsdgzsGKI9NClJz
         Im/s99RMsO0AfKXoq0NIwNKxlbBuApn9rW0ngVHO5Z3zaIyEZLBbv4aJ9AEhnvbImi8D
         p3kJ5mO9O4yNffJXIpD1iSm46xvNRE6zsucU9YGv3IJh4osh/nWGg5q789WucA0rwGwQ
         hVkNq7EnUslWfOLR7kzG4TnQcKydfFksB1MPyKq1NKrDeUWDnXyJBIs1FUd3RtFq9Gf8
         gO9aAuj7r6ePg0rsl+H86fgFwiAM8wBmTovBshNVW2x1Drhr3BIhUzW7re8KLDbMYRqR
         yfQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KuE6dmbh;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KuE6dmbh;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429b526c2c8si17087f8f.8.2025.10.29.15.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 15:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id F1EC322809;
	Wed, 29 Oct 2025 22:44:33 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D52821396A;
	Wed, 29 Oct 2025 22:44:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 6jm4M9GYAmlwFAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 22:44:33 +0000
Message-ID: <a110ffdb-1e87-4a5a-b01b-2e7b0658ae33@suse.cz>
Date: Wed, 29 Oct 2025 23:44:33 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 12/19] slab: remove the do_slab_free() fastpath
Content-Language: en-US
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev,
 bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-12-6ffa2c9941c0@suse.cz>
 <CAADnVQ+nAA5OeCbjskbrtgYbPR4Mp-MtOfeXoQE5LUgcZOawEQ@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQ+nAA5OeCbjskbrtgYbPR4Mp-MtOfeXoQE5LUgcZOawEQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spam-Flag: NO
X-Rspamd-Queue-Id: F1EC322809
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[gmail.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_COUNT_TWO(0.00)[2];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo,suse.cz:dkim,suse.cz:mid,suse.cz:email]
X-Spam-Score: -3.01
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=KuE6dmbh;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=KuE6dmbh;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/25/25 00:32, Alexei Starovoitov wrote:
> On Thu, Oct 23, 2025 at 6:53=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>> @@ -6444,8 +6316,13 @@ void kfree_nolock(const void *object)
>>          * since kasan quarantine takes locks and not supported from NMI=
.
>>          */
>>         kasan_slab_free(s, x, false, false, /* skip quarantine */true);
>> +       /*
>> +        * __slab_free() can locklessly cmpxchg16 into a slab, but then =
it might
>> +        * need to take spin_lock for further processing.
>> +        * Avoid the complexity and simply add to a deferred list.
>> +        */
>>         if (!free_to_pcs(s, x, false))
>> -               do_slab_free(s, slab, x, x, 0, _RET_IP_);
>> +               defer_free(s, x);
>=20
> That should be rare, right?
> free_to_pcs() should have good chances to succeed,
> and pcs->spare should be there for kmalloc sheaves?

Yes.

> So trylock failure due to contention in barn_get_empty_sheaf()
> and in barn_replace_full_sheaf() should be rare.

Yeah, while of course stress tests like will-it-scale can expose nasty
corner cases.

> But needs to be benchmarked, of course.
> The current fast path cmpxchg16 in !RT is very reliable
> in my tests. Hopefully this doesn't regress.

You mean the one that doesn't go the "if (unlikely(slab !=3D c->slab))" way=
?
Well that unlikely() there might be quite misleading. It will be true when
free follows shortly after alloc. If not, c->slab can be exhausted and
replaced with a new one. Or the process is migrated to another cpu before
freeing. The probability of slab =3D=3D c->slab staying true drops quickly.

So if your tests were doing frees shortly after alloc, you would be indeed
hitting it reliably, but is it representative?
However sheaves should work reliably as well too with such a pattern, so if
some real code really does that significantly, it will not regress.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
110ffdb-1e87-4a5a-b01b-2e7b0658ae33%40suse.cz.
