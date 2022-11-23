Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBAOM66NQMGQEMZ6GRAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 34D3C6355A0
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 10:21:06 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id ay19-20020a05600c1e1300b003cf758f1617sf794716wmb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 01:21:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669195265; cv=pass;
        d=google.com; s=arc-20160816;
        b=ROPnM4ZaxW+j0/qW1y/eWNE3p8vwbJUCzFfKoMo3rHuwNVpu/7CR/zTzB0iFddDy+Z
         qrmjV0GldcQE+q7qF1BvcnqydTryL+1EOLxyC1BXmi1CYXSXFb11Wk89RwLKrkGkIN3Q
         l9lWjqZA9qWZjFxTvW0hqvQCvBPhikOgNQRYmsvROQFX0NsI4/HPJ37HciUvpMG3i2g3
         BgbvMZTql3rm1LYc62XF9unO5j/apwjQtPWX2Ctbxe/NxjysxIhVvrgcQmMp8HzhkMnG
         eqYspLkZ1T0RgEN5rc8ETeQjb6vuXc2i8b5Kr4Z8b+Wm/llzw5fvq4ZZmpsqNlZ6/2nl
         rS4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=0UdAwfmnKglkqGj/ix11Tao4s/7h8IcNmSgnQlFq1Vc=;
        b=JjONw/TkZJjBjnWAyjobvgLiJ5bbwq3jVP/y5CrD3Hu6U2F/FBMkNK4vSkidwyQihu
         2splgghS1fPN03EPRjYjhunR5jJNVobN3SPKmuGnfcq7FuoA2yV7s38U78gzC3hYWfr2
         9UfJS13EA1OSwpbhUIoS4pd2/1fD1IP4tx6C5rc2E0T0mbH1rxKuiWs8NsEwufa6s3qq
         rPuzEg5mQMbaLpnnicg6bCRYgsDKePbQij/lCAEX1eQa/piQgY1r3WbLBBExr+hOEORE
         oR80D+CJZ53AeK6Q93a2zZdamlBeqWrgPDZwoLyFCdBn+X3sdPtahO7CROgJgmD3jmE+
         SE3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WQgMsxhW;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=aSmEAcQJ;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0UdAwfmnKglkqGj/ix11Tao4s/7h8IcNmSgnQlFq1Vc=;
        b=aAMP9MafBEJzefqqrNx03RclLqEA4yqTe5BIQRtZn/Hf86WZb7QrMZPpoXGXb7BCYT
         J7F6Eh9E7ysukw/g6cPnt6dRNqRxCORuJNKaD1qivl8Ntu3t8kifrq/DOH3U6WnSttPm
         p5c8yXuKfu0iWMT3r7nBubOHmb5hI2bksDsmNA3JXKSOwXjGCT9VKrw/Y7B6Olt+UXZg
         MFdWRuYtgk7JpnEPKSdr1kCxkh3Kvgx6NkoRnDZWMqdKZf97iIGLRJXLpYSsBeG/v54e
         179axBy7gv1s4OClvNMjU25Zp/SE2Mbi55MvrMmlQ3DuqM6J+rjuCzUFKsWiCzc6Ehy8
         k4bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0UdAwfmnKglkqGj/ix11Tao4s/7h8IcNmSgnQlFq1Vc=;
        b=x75JGQnaFtHSVwVwiQsNhgwTNMy0/jfwn2qims0rD4pvCKTNzIJZ0behojYHQ/anmc
         m9diGN0GBMKCQ1VaqqaBnzZYU9MwSJeu0onyuh1hBFWbV2gPq+8BxcOKTlAW76SoVCbZ
         711zecu3u1yntM4qTEMGShvfpvkP1SffuPVElStY5kGAf6JMlheqaVOx57aquK8A8/zk
         jj4NH8NeYH0q14eATfGLdOVjOFte9tOD23ffZ4ogTTVMp5LWyrLppAKLsVTHA27QMdqm
         eRlLST9u4EQ6BUay8XuKFLJ3bBvQG4EUMSm4aVe32lz7wggZ0TbR6Z48PqBvzBz6572F
         gypA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmlN2dvIlHu5bSBincD2hzsJ6lwIIV0BajxReHvVpCIG23wA2Gh
	dMr5QLeEJ/HKQp14d0Xx9zY=
X-Google-Smtp-Source: AA0mqf6iUolxAsv9Bx7Lxe5IaF6p9bLe/ULzfTsFOd3SsoRnD5dzm7+N09et8MUFdqNM87QrT+E+7A==
X-Received: by 2002:a5d:4106:0:b0:241:e8d0:7de9 with SMTP id l6-20020a5d4106000000b00241e8d07de9mr2445409wrp.260.1669195265567;
        Wed, 23 Nov 2022 01:21:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20b:0:b0:228:ddd7:f40e with SMTP id j11-20020adfd20b000000b00228ddd7f40els5513191wrh.3.-pod-prod-gmail;
 Wed, 23 Nov 2022 01:21:04 -0800 (PST)
X-Received: by 2002:a5d:5709:0:b0:241:d71c:5dde with SMTP id a9-20020a5d5709000000b00241d71c5ddemr8350808wrv.678.1669195264316;
        Wed, 23 Nov 2022 01:21:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669195264; cv=none;
        d=google.com; s=arc-20160816;
        b=eI6G2asmjdhBb+b2hJ1QrbK780nI2Eq4OVdodrtPjrgwsEq7/dk0nhq5jGxUL5HXis
         HWHVJSnYFTPrfaGroWPr6at+v3mY9zwlregMOvWDSjiUr+p7mk4j1HU5ss+PwNj74EFD
         Cb/dlflbEpKjjljmiSnnw+edcJSrG/EK38ze9+XWObaXWBW/1wXpwNsddz2zaOjE1F9J
         torHihA0OXzYZus3uV7H6m6YJvKWt5Knb47S4EUwd0cwMO9LNuMYn7KNySAcrGoBzu+v
         T0xVViQOz3qnF1NF1K4JsdMEhhagpE0X0tYTGX1Pnh3zvUVJNrnmk3zDwP18mcB493de
         VV9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=6ChOqSLee0rmz2oTzjZlbgB7fmW7X2/L74cYDn2AHg0=;
        b=FOXKBdJkbWU73TtSMQu1SUjwfJxBvc3fEx2Wtiz6J3H4E3Uvb50HRRWyTYQSqNmP2e
         uv3zT1jJ2LlrBwCJMTj759r/fHOHrlw1HEhIp8bydBKgpxBuN/o7ggqXOPyCKOFjKIfX
         rDInKOcB6sNPEq5UMJfiFE/BFqrIgWBfZv8Y79pvhD1QQ8EgU0Td8PO75U/xRJvfFZAw
         m6pD/WuRGDOBHzeb8RCi5+9tXAmaD9x+exA3oTWQX8RjXAXR7+g/jc0HhHMXXqeGccvH
         eKLLnY8QgzMepyBnfzJrkm/D6xWvQmcbtreI+IJNEnGXUp10vYTlTklDuLV7cTDFE4Hd
         HTmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WQgMsxhW;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=aSmEAcQJ;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id m65-20020a1ca344000000b003cfde9030c7si153552wme.0.2022.11.23.01.21.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Nov 2022 01:21:04 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E341F1F85D;
	Wed, 23 Nov 2022 09:21:03 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id A97A513A37;
	Wed, 23 Nov 2022 09:21:03 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id QgwtKP/lfWMEDQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 23 Nov 2022 09:21:03 +0000
Message-ID: <74d14df1-faa7-dc12-d406-ba038682e134@suse.cz>
Date: Wed, 23 Nov 2022 10:21:03 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Subject: Re: [PATCH -next 1/2] mm/slab: add is_kmalloc_cache() helper macro
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
References: <20221121135024.1655240-1-feng.tang@intel.com>
 <20221121121938.1f202880ffe6bb18160ef785@linux-foundation.org>
 <Y3xeYF5NipSbBFSZ@feng-clx>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Y3xeYF5NipSbBFSZ@feng-clx>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=WQgMsxhW;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=aSmEAcQJ;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/22/22 06:30, Feng Tang wrote:
> On Mon, Nov 21, 2022 at 12:19:38PM -0800, Andrew Morton wrote:
>> On Mon, 21 Nov 2022 21:50:23 +0800 Feng Tang <feng.tang@intel.com> wrote=
:
>>=20
>> > +#ifndef CONFIG_SLOB
>> > +#define is_kmalloc_cache(s) ((s)->flags & SLAB_KMALLOC)
>> > +#else
>> > +#define is_kmalloc_cache(s) (false)
>> > +#endif
>>=20
>> Could be implemented as a static inline C function, yes?
>=20
> Right, I also did try inline function first, and met compilation error:=
=20
>=20
> "
> ./include/linux/slab.h: In function =E2=80=98is_kmalloc_cache=E2=80=99:
> ./include/linux/slab.h:159:18: error: invalid use of undefined type =E2=
=80=98struct kmem_cache=E2=80=99
>   159 |         return (s->flags & SLAB_KMALLOC);
>       |                  ^~
> "
>=20
> The reason is 'struct kmem_cache' definition for slab/slub/slob sit
> separately in slab_def.h, slub_def.h and mm/slab.h, and they are not
> included in this 'include/linux/slab.h'. So I chose the macro way.

You could try mm/slab.h instead, below the slub_def.h includes there.
is_kmalloc_cache(s) shouldn't have random consumers in the kernel anyway.
It's fine if kasan includes it, as it's intertwined with slab a lot anyway.

> Btw, I've worked on some patches related with sl[auo]b recently, and
> really felt the pain when dealing with 3 allocators, on both reading
> code and writing patches. And I really like the idea of fading away
> SLOB as the first step :)

Can't agree more :)

>> If so, that's always best.  For (silly) example, consider the behaviour
>> of
>>=20
>> 	x =3D is_kmalloc_cache(s++);
>>=20
>> with and without CONFIG_SLOB.
>=20
> Another solution I can think of is putting the implementation into
> slab_common.c, like the below?

The overhead of function call between compilation units (sans LTO) is not
worth it.

> Thanks,
> Feng
>=20
> ---
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 067f0e80be9e..e4fcdbfb3477 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -149,6 +149,17 @@
> =20
>  struct list_lru;
>  struct mem_cgroup;
> +
> +#ifndef CONFIG_SLOB
> +extern bool is_kmalloc_cache(struct kmem_cache *s);
> +#else
> +static inline bool is_kmalloc_cache(struct kmem_cache *s)
> +{
> +	return false;
> +}
> +#endif
> +
>  /*
>   * struct kmem_cache related prototypes
>   */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index a5480d67f391..860e804b7c0a 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -77,6 +77,13 @@ __setup_param("slub_merge", slub_merge, setup_slab_mer=
ge, 0);
>  __setup("slab_nomerge", setup_slab_nomerge);
>  __setup("slab_merge", setup_slab_merge);
> =20
> +#ifndef CONFIG_SLOB
> +bool is_kmalloc_cache(struct kmem_cache *s)
> +{
> +	return (s->flags & SLAB_KMALLOC);
> +}
> +#endif
> +
>  /*
>   * Determine the size of a slab object
>   */

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/74d14df1-faa7-dc12-d406-ba038682e134%40suse.cz.
