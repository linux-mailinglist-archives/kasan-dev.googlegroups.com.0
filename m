Return-Path: <kasan-dev+bncBDXYDPH3S4OBBMOFT3FQMGQE26WDCSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 51C5BD1F4B6
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 15:05:39 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-4304b11a198sf1100582f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 06:05:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768399539; cv=pass;
        d=google.com; s=arc-20240605;
        b=XxT4e9HFY6u49MQ86vZDIAiFPAkR2IfdadfSFltQvrZNyMztP8udJLANTSldLGy1Az
         idR41p8Y/9r1aqA6DEknD6nkkdznlUPtqfwA13iWRuyfnJ9vQyEREiKgPMptAtlOaBcY
         gF6hA03nGeC6eOVkAxQLATKFqT56s5B90/I/8qxakp6iBOeeZNz195Lfz6Gn9mg26WbI
         RH1OK+BeHI9J3CEMVV6N5Ty7Y2DHjTrHHyFQoDzA7BXaWjrpKMQ618/XHYKRI0NV44Id
         TN0RYgInas6yir9cvyaowx0tSasZS8UxMEKB1YHfNqW01v5YnQ1fxLmiA2JGm5nP8FI9
         yw4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:references:cc:to:from:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=1doDuaX2pSpuMmElhObtvd1YO75py1g8cf5lIFBc0M4=;
        fh=6hwHuMwE03+Gv6h+qy79FgI+18iVO9N3vYRdO6AAsuQ=;
        b=HBX5JumSa5Y3ubxTERJsuJCKynY91CcTQ39Y3PjqDNaulu6AbTi0x2KF11/unSlxek
         72td0bafE0p0TvX1+KchYKfXd3W2U/9Dcgu+L6zsvXErPuATF2VDyBUzvBU36+Ez/xA7
         aIuOHNbg+CQLLibve7P4lurW1CD/OKRTEDQZol/5sESXlmv3Kcb4vQB5AOhT5ihIl1Tm
         Umnx36pLa2nevk2qa1q7s/yQ05i9YJrKOk2nOUnoadmpPuoB3QD0kLhV0I9ifcMwv57A
         irIgytzUOAOaBrJ6u8ZbdDLbOIfYlAefOJFfkS6qNZZurJa24dwCk1YcVMPPW4L/VXtQ
         zYog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FS5BqfKk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FS5BqfKk;
       dkim=neutral (no key) header.i=@suse.cz header.b=tAT9MaKn;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768399539; x=1769004339; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1doDuaX2pSpuMmElhObtvd1YO75py1g8cf5lIFBc0M4=;
        b=FzZtJuNJYPXz/vCn88UlEyM2OgUBQ67UXcpJ3hjbF2o9XqWE5LezRmsyw10MfZ6PgN
         KpFo+IZGtA/GsAoIcWunWZD3iO1zfZpbL5QFa3QdxQ/vkxy89PqpfvN5bWb1u4mn8/2p
         apXUmm11djw0nx6L+yIL4d16QZrRMTDei/w2eulKVJGAQYgk57Ca4lpn3ocxunv3lzZk
         MpZDDKmJq7wxIYII2x9ZknBgZBN8pEFEZRogrRKQmgVu5DKpOVxH8dS+aZhxZWSDGhlX
         LcejxVOFH0sLqL4Obw4f08p+NH9RWNV5db9Yyuz1NzmctGrU9B03xfIOvu1OXgX7A99l
         Oh8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768399539; x=1769004339;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=1doDuaX2pSpuMmElhObtvd1YO75py1g8cf5lIFBc0M4=;
        b=owXMmVhKwtnHQKsDGEfa0pgWrye2E4WGYwOrWyecOlBdF/bgW5ehgFAE+X82PknVLb
         QxtYSpid0oGe7thNyy+QwwGf6sdaN1hLlVbSFgrfUkS6K0DVb9bseHUYzbFYIIcdyEZi
         6JEaPe+fExsG/xh1Gds2UBbgMQHp2ma/2xX3sZ1RPTQpcqUGyfUelgPWlGX8j9NoCblf
         WGOTFEzSTAZY9LQUHz1zyniYcLnYbhkgKzj8KKQDDDKx6UfnyxkvnI+1872tcz8pdt3d
         LX8OEo0bSPZ00+XA8YD3EFh+QoiI5s0G7wRutKT+Du/2WfNSHg/EmDDN2Lg3JXzMMYO5
         heBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW98RXqQaLX03Z28uhhOGy0gGwEiDoeN6NTNka+WXIDPhKMiNDEtYHoZneg7A0rwc9Ng8roJg==@lfdr.de
X-Gm-Message-State: AOJu0Yz2qVaQ0E3CDHmYK31kcTv9APM1Vy784OT9re31ZRsSjnxQytV3
	w4L3sEY0jzo2eUr7NXr1giLlA15rhaAQcziTxtOVLjjcNFmqqq3PozXd
X-Received: by 2002:a05:6000:2306:b0:431:66a:cbdc with SMTP id ffacd0b85a97d-4342c54235emr2042033f8f.4.1768399538421;
        Wed, 14 Jan 2026 06:05:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EYuYlZBuhVSXToyamtyRyDSoAw84vmObLQtuTLCyP8DA=="
Received: by 2002:a5d:5f43:0:b0:426:cb20:6c35 with SMTP id ffacd0b85a97d-432bc8eb2c2ls5853724f8f.0.-pod-prod-06-eu;
 Wed, 14 Jan 2026 06:05:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXZYXGUZ3t8StzgmTwHs0D44qCBkTJPWFZvjddk1i03SlMYWWhzJ8eTfEYTLnVVHQTgracXZ14Tdeg=@googlegroups.com
X-Received: by 2002:a05:6000:2409:b0:431:7a0:dbbe with SMTP id ffacd0b85a97d-4342c5474e5mr3137587f8f.32.1768399535852;
        Wed, 14 Jan 2026 06:05:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768399535; cv=none;
        d=google.com; s=arc-20240605;
        b=J/03kDPwYxbu4q4D8aCzfVArGBrjXv9AgdGb3/aXMzdN10cXomSmJ00axRO5/IB4q0
         XF7J1hNv7qjhzSjZuMhf6Rjx80UyGhpH2LTS0AWPGS+GN4lmrCf69rIRqlORQdO3Q/za
         8+5cqGrpxlhUFckVHMsdU5e1pZ+CFGZeh5lWf2B85WeyzTy8dtefMCQPoykkva/V9zPJ
         HxAawkHGjg6fnsPHCJX4N7BBzQlHdAVA1lIQ/6/jDODN6Nk0LkpGwkYSrYj+ds7acano
         D6AcUWFx57fe5gKpHpso3cgdOWyHU31PNyUyyq61Y7/7RntvLai1K2e6tb8YBD49f62W
         /ygA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=7C4MdemR39tmXRA9yl0PqmV94vggPiQ1JGGHQvEbWMs=;
        fh=So1Uy5/+WpIrmqaQOS84fH4eAlGwGLueBmod5uHpWrM=;
        b=fztLIAoF0XyfKtaMkxybtHD5Tbajk6HEDmd9Zg6ZKydZ4ky0z4HDT5okM3Gfsz1FJl
         dNNN5F65WRdrpr3kcnMYZcMEeBmzZjKcv0wr2TGBaWMSSVuaSfJSBNL9yvxnS4AILVrF
         8QEJYBgERVUlgHX63y2SEubxKv/93jHIfqZO7ykOgmhAkJFWaraBcu8cRQboA99K9WyR
         7JyV6TFCNA5ZmDMy6howvxftmYxaD9/2YDQvUcSQe8Hxd1hmtKqsp5D0EuM7p3PB4LHk
         msryvxivS+fIOM3+Im+QOc8otrUJHYhNfRHZqLSDXzvwmJqd5KPJ3rgwN4zidMTKahVU
         H1hA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FS5BqfKk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FS5BqfKk;
       dkim=neutral (no key) header.i=@suse.cz header.b=tAT9MaKn;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be512e98si442297f8f.10.2026.01.14.06.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jan 2026 06:05:35 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 541695C832;
	Wed, 14 Jan 2026 14:05:35 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2510B3EA63;
	Wed, 14 Jan 2026 14:05:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id DBFZCK+iZ2mlNAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 14 Jan 2026 14:05:35 +0000
Message-ID: <d8d25eb3-63c4-4449-ae9c-a7e4f207a2bc@suse.cz>
Date: Wed, 14 Jan 2026 15:05:34 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 06/20] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
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
 <596a5461-eb50-40e5-88ca-d5dbe1fc6a67@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <596a5461-eb50-40e5-88ca-d5dbe1fc6a67@suse.cz>
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
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FREEMAIL_TO(0.00)[gmail.com,linutronix.de];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Spam-Flag: NO
X-Spam-Score: -3.01
X-Rspamd-Queue-Id: 541695C832
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=FS5BqfKk;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=FS5BqfKk;       dkim=neutral
 (no key) header.i=@suse.cz header.b=tAT9MaKn;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/14/26 14:57, Vlastimil Babka wrote:
> On 1/14/26 00:26, Alexei Starovoitov wrote:
>> On Tue, Jan 13, 2026 at 10:36=E2=80=AFAM Sebastian Andrzej Siewior
>> <bigeasy@linutronix.de> wrote:
>>>
>>> On 2026-01-12 16:17:00 [+0100], Vlastimil Babka wrote:
>>> > --- a/mm/slub.c
>>> > +++ b/mm/slub.c
>>> > @@ -5727,6 +5742,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t=
 gfp_flags, int node)
>>> >                */
>>> >               return NULL;
>>> >
>>> > +     ret =3D alloc_from_pcs(s, alloc_gfp, node);
>>> > +     if (ret)
>>> > +             goto success;
>>>
>>> I'm sorry if I am slow but this actually should actually allow
>>> kmalloc_nolock() allocations on PREEMPT_RT from atomic context. I am
>>> mentioning this because of the patch which removes the nmi+hardirq
>>> condtion (https://lore.kernel.org/all/20260113150639.48407-1-swarajgaik=
wad1925@gmail.com)
>>=20
>> Right. With sheaves kmalloc_nolock() on RT will be more reliable.
>=20
> Yes IIRC Hao Li pointed that out before. We'll be able to remove that
> !preemptible() check that we area about to add by the patch above.
>=20
> But I'm not sure we can remove (or "not put back") the "in_nmi() ||
> in_hardirq()" too, because as you said it was added with different reason=
ing
> initially?

Ah right, it was "copied" from alloc_frozen_pages_nolock_noprof() where it'=
s
explained more, and AFAICS will be still applicable with sheaves. We should
add a comment to kmalloc_nolock() referring to the
alloc_frozen_pages_nolock_noprof() comment...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
8d25eb3-63c4-4449-ae9c-a7e4f207a2bc%40suse.cz.
