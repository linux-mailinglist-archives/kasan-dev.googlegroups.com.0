Return-Path: <kasan-dev+bncBCQ6FHMJVICRBCFN6CWQMGQEGS66ZOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A073846327
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Feb 2024 23:09:14 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-363ab2648easf6021715ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Feb 2024 14:09:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706825352; cv=pass;
        d=google.com; s=arc-20160816;
        b=tubTGMj3CwU+yJ3eXnIlJyZBmBCXvf8E8PbPgxPABUmpW6EL2AEcYN3AGzKXgstVNz
         6u5VlyYdUm5W/oCnvqw+6w0z8Tpf9+3dweGDfU1gEa7kYQmOxcp3kNBujvw/QPvNUZ4d
         SXpq4frkwxFKxJY8fH6ZLh9ZPGS2fNaGy/uJ7yGVVb2+gb6Zw04O9v/OQkssa23Ysrc1
         qe91sJP0SjsuBPKFiV1vviSAk5et9+Q9lx/leKU6hSBZcI4gWacVVnqg6oCUmHEPz4X2
         86gpZJSE1NG6mbsBRPb3xI+tB+6OSvnp7EF5QOazDxWHFNXnE6VUwo2gvuxE1OCiaFZR
         AFpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=3O+fFnqii8/rSiQIt3UqzszO8gvozTuO0tIOwoUV45I=;
        fh=V/pV6tBv/y8q2kV1ptejKYlATNtWB7Vnbo86CKqbBdA=;
        b=N4iDmXbJjrWCvUwAXfg4/tPufKFBvbWvImWIiqURXRxGByS0+6FUIHtY7y9tuaDnbp
         lzFITyK3z8244GpB/jnJ0+ozT+ygvIkNEv/5Em4Ky9gVIednYirW5pDuSPQ8VLW0DXnB
         TVNCxiD8AAWXbeXvEAiGuDwEJQGHNScxSCxX/1Hyk8XuI8QL8vMRN6grGGbVRAj8L6r8
         onDA5vLVpSPk+x6I0ou6xNDDj/NcdxvD2Rrf1iDXCZLp+U+dlcSRdJr7otFDVpipDv+N
         EBxi1k9uQhqOIFslNxm/4ReuF8yLVxsX3wIN9PqTf49JKp1mkRMB7+uuxDhm9novznKp
         O3oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b=pV8i93ih;
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canb.auug.org.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706825352; x=1707430152; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3O+fFnqii8/rSiQIt3UqzszO8gvozTuO0tIOwoUV45I=;
        b=QEAiVO9/jnyQW+FYTgSyIO7C/2boDbgZvSvSktKJ5eZ3NpNJ1+qbFR3X1j8yy9epWp
         2UP2yu/nArybrp1kKR1PehL2WXvxIxaGwS/5vsJesXoVnbr1VrPz5tacdH3mh4jTqJpF
         kqHJ4uqnrGaQ+pdDPX4BOkesTq4rEwHF6EzQ0iMvo4RsSbpPlWa8EpMMXJMW4hgUqq2V
         bgBWZYwPcch2kHqrq2vk3xEnT74c/RSQbXT/aPM6yjXAicFH/mUtAW93MUZN8plTwsb3
         f235SYQ6MT+D44bcFeLVwwMVdIkCgOuC+AM98iNSgNYFbRuEvXhLP7b8oA7d3hY77hO2
         ehKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706825352; x=1707430152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3O+fFnqii8/rSiQIt3UqzszO8gvozTuO0tIOwoUV45I=;
        b=o7PholAmE9xg3p57WcdaGf/33gCitMGNdLY19qkMsNlJ3hZ4vRp76AWwPpFSO0avRB
         brT2r07rOalcpWPN1M1tlAS5IPj/ZHA0foM9QokOIvp8+mEMfZO6+56nZ8fuyyP7wQ5F
         dSA0p6lxFUMGidu3wp5Wbv1Y8XLFty4TjQSaCbRbC1P4FJ/bLZMr4lCAc/TXJKM08p7S
         VLRSnj3qkXKjOpwxYaJiOEAXRHrZzc6foApK5LtXgBcSlDM8Y6KSNJpuyt7R2dwsoT6M
         UXmPav6WJauOQpMcWHhtxayd1/Unzma9/pTJnB/q+En3JAQlT4lysk61+Zg7MhDwxQPi
         rddg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwsFbZ/lmz+AssDoSR8ErIGFdJzXHDbVgJPoKjr/ttmpjtiQgkT
	WfqQLHzVOeHbIP/iZ0fOstpZcUbPNHGt3FIceGy3ZQBo3/Xd4O4Q
X-Google-Smtp-Source: AGHT+IH1m36qIfmdPhGWSqHdEcx1hmD+UHxOoBgV+wyhh/I8xRRqrBOEE7O2SOCo8kGkXZMZece02g==
X-Received: by 2002:a05:6e02:967:b0:363:7e2a:4df8 with SMTP id q7-20020a056e02096700b003637e2a4df8mr136935ilt.32.1706825352642;
        Thu, 01 Feb 2024 14:09:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2491:b0:363:7d3f:13ee with SMTP id
 bt17-20020a056e02249100b003637d3f13eels155037ilb.1.-pod-prod-06-us; Thu, 01
 Feb 2024 14:09:11 -0800 (PST)
X-Received: by 2002:a5d:850d:0:b0:7bf:ea24:9f5b with SMTP id q13-20020a5d850d000000b007bfea249f5bmr272950ion.0.1706825351408;
        Thu, 01 Feb 2024 14:09:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706825351; cv=none;
        d=google.com; s=arc-20160816;
        b=NRK5x31WoXemhKYEH/nwBNzhtDvxfssU/505G4W8IRCUk018TknJbewkz2Jj3+btje
         TO/GueAYPpHl3A00rTJoxVglu52Tml+WdI5u5yr5U9j28xftenqa4bXh4vtOSBBjgEYw
         yr5SBVDdfVzbF9s7gRkagTcfGNgmsOtICyaBdGSofp97PIa1AMDLR9/G9vwGYJeKkng3
         I46SYxx3fgP6pmgiERV0m6fJ4kTAAdz6xN513pzWwq2ap99nAc0zoPZbmtm8DNVD7tqA
         k3VPot8CbyLIuy7Qc0REzVNDRN/EsC5Im1RBDhMzsfrkHIvk2SU5fv7GT/guAR9/jQeV
         ZfPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=vL7SJZQiX7iBH2yVQNL2VeEYjvGEbCOoRew0Z3DhEek=;
        fh=V/pV6tBv/y8q2kV1ptejKYlATNtWB7Vnbo86CKqbBdA=;
        b=cYMIX+Q/13OcoT7MJfzcb12/fRZ88r7KpfCKbPm29mTHG5U2OiRoCF7HE6i58Ihx+I
         c855QY8yK8dvBayO5Sjfxw9Pt0iNrui7WY6P4vBeyGRzKF5qPuG40gSGZBm9tdDbQew/
         zIJ8ykfIGY8ZkINuLNZ95HpnCdNbIt2pyDdnI9WDC54HwUmA39P6vE0iwlQs/6HunY4P
         JXIXDK+ViTrarrcPcnAb+lTM9lgPw9Nu3JZHN+8HsL+vX8O73uHKkCjlzlB50ojtnaFL
         UhAZ0uWACzpUzgJ8p6O/InliEakAf7nJgujGn0Iwj5ndK6CdPfWQLQ5i93v+SGgEjTr4
         hCPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b=pV8i93ih;
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canb.auug.org.au
X-Forwarded-Encrypted: i=0; AJvYcCXAJQAwl3rdEJGKrTQ/yBiQTB2ui8REyBGrmjoR/qj7kMbTxac/B50/so7T9a4xgF5RVxjEoC0sHvNGUTpQN404hnE61a+86551cg==
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id v12-20020a05663812cc00b0046e3ec8d7d2si59631jas.3.2024.02.01.14.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Feb 2024 14:09:10 -0800 (PST)
Received-SPF: pass (google.com: domain of sfr@canb.auug.org.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4TQtNJ6PYTz4wcP;
	Fri,  2 Feb 2024 09:09:04 +1100 (AEDT)
Date: Fri, 2 Feb 2024 09:09:03 +1100
From: Stephen Rothwell <sfr@canb.auug.org.au>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov
 <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com
Subject: Re: [PATCH -mm v2] stackdepot: fix -Wstringop-overflow warning
Message-ID: <20240202090903.6ba062ac@canb.auug.org.au>
In-Reply-To: <20240201090434.1762340-1-elver@google.com>
References: <20240201090434.1762340-1-elver@google.com>
MIME-Version: 1.0
Content-Type: multipart/signed; boundary="Sig_/E5HTHIzNlHNnd_U1O+bvlVs";
 protocol="application/pgp-signature"; micalg=pgp-sha256
X-Original-Sender: sfr@canb.auug.org.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canb.auug.org.au header.s=201702 header.b=pV8i93ih;       spf=pass
 (google.com: domain of sfr@canb.auug.org.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=sfr@canb.auug.org.au;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=canb.auug.org.au
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

--Sig_/E5HTHIzNlHNnd_U1O+bvlVs
Content-Type: text/plain; charset="UTF-8"

Hi all,

On Thu,  1 Feb 2024 10:04:30 +0100 Marco Elver <elver@google.com> wrote:
>
> Since 113a61863ecb ("Makefile: Enable -Wstringop-overflow globally")
> string overflow checking is enabled by default. Within stackdepot, the
> compiler (GCC 13.2.0) assumes that a multiplication overflow may be
> possible and flex_array_size() can return SIZE_MAX (4294967295 on
> 32-bit), resulting in this warning:
> 
>  In function 'depot_alloc_stack',
>      inlined from 'stack_depot_save_flags' at lib/stackdepot.c:688:4:
>  arch/x86/include/asm/string_32.h:150:25: error: '__builtin_memcpy' specified bound 4294967295 exceeds maximum object size 2147483647 [-Werror=stringop-overflow=]
>    150 | #define memcpy(t, f, n) __builtin_memcpy(t, f, n)
>        |                         ^~~~~~~~~~~~~~~~~~~~~~~~~
>  lib/stackdepot.c:459:9: note: in expansion of macro 'memcpy'
>    459 |         memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
>        |         ^~~~~~
>  cc1: all warnings being treated as errors
> 
> This is due to depot_alloc_stack() accepting an 'int nr_entries' which
> could be negative without deeper analysis of callers.
> 
> The call to depot_alloc_stack() from stack_depot_save_flags(), however,
> only passes in its nr_entries which is unsigned int. Fix the warning by
> switching depot_alloc_stack()'s nr_entries to also be unsigned.
> 
> Link: https://lore.kernel.org/all/20240201135747.18eca98e@canb.auug.org.au/
> Fixes: d869d3fb362c ("stackdepot: use variable size records for non-evictable entries")
> Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Just switch 'nr_entries' to unsigned int which is already the case
>   elsewhere.
> ---
>  lib/stackdepot.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 8f3b2c84ec2d..4a7055a63d9f 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -420,7 +420,7 @@ static inline size_t depot_stack_record_size(struct stack_record *s, unsigned in
>  
>  /* Allocates a new stack in a stack depot pool. */
>  static struct stack_record *
> -depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
> +depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
>  {
>  	struct stack_record *stack = NULL;
>  	size_t record_size;
> -- 
> 2.43.0.429.g432eaa2c6b-goog
> 

I have applied this patch to the merge of the mm tree today.

-- 
Cheers,
Stephen Rothwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240202090903.6ba062ac%40canb.auug.org.au.

--Sig_/E5HTHIzNlHNnd_U1O+bvlVs
Content-Type: application/pgp-signature
Content-Description: OpenPGP digital signature

-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEENIC96giZ81tWdLgKAVBC80lX0GwFAmW8Fn8ACgkQAVBC80lX
0GwEdQf/QnOi4Qm8+1/IkO10QkmuLja/E9BrYs9hA8MrzNS5sUIvOr1HmQEvEP7Y
CdpwEuMEITu9EgLXtwF9LqrddOg3WxHEsMpzwr4XSwJQk+zzyJV9OUMY0LV+OZw2
AT7P083oFYYMhfwvoTHTGMri7LQbB44JMqV+O4814bQCo63YCmDVxvZBc5xEiJT7
qdGhqra4nJpdURCQIpDEBFz49x/NQHsIAeUuqW1mGt963xX7BjfPd/8h7gZFM+PX
rT0n8Nq1YALzqOXO+Q6sG06W2JURy7Pa0Asnc5TQITfD/zL1dV33YF0ljTOD1J8x
qFy9tuJidBXQc4bTX6K7QRA5Mx5TxQ==
=zrpL
-----END PGP SIGNATURE-----

--Sig_/E5HTHIzNlHNnd_U1O+bvlVs--
