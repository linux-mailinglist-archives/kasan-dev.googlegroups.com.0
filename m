Return-Path: <kasan-dev+bncBDT2NE7U5UFRB6GI27AAMGQEGVNAVYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id CC598AA7FAA
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 11:40:10 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2ff7cf599besf2911281a91.0
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 02:40:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746265209; cv=pass;
        d=google.com; s=arc-20240605;
        b=P2eKTvLve/1dCms6mpnXU3EBdROVmc859vINGxwipsxPYGSlboqRvhl1CvgX11Y3EB
         0nnAilE129fMZrZ9mRMuK0auU8Di3rtZQm6PcVsWtb9H6gSzsZG5NkJ9jybsWM2Ah1y+
         fhzWD2LMZFA4mLajNbmiJ4xZdFSiC46lFAO4gcTEtzEOsVKuOlgJJ2428uDgz+w6LtDZ
         lXapXtqNt/DOUAwJ6apHipCdVdbtMdnA0qUVGRUhPI/6UW5QQbv7/+VYcgeUgKs1lS0s
         F5sp7D2xXtLkCK1k/c01fuiOU4eD+P47AERwIB2HOdgkM2s+MD9sJVOkHX4RdOLvHMMy
         NyiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z/2LI0R12yf8c3C2tTX+UyNk8ErgUZQ5/kLZ0SQ/X9E=;
        fh=ei1BulfujC8Wn7b+TB9mQo37cAhmzW5qWamkfcBgBHM=;
        b=Sa/51nP3+VB7NyJc5DRZ+QVAUUotXX7uifZlnQOA8lom+we7RNVvXrJ9FeYAJWLzbG
         jCQIxz34B/bwdhGj2mzTLW0hQNW50SOamXVLiDdpv8RUA6jQoaSbnGU6MTZ/Aq3l7XGi
         ZY6ESNl5QvweOYvXUcmut7wWwSjGWfjgeJVjH+pLnBHOXWMfjKgQL66aSYPk5jUrqJWI
         pioDb69kdo5YcHh0O3NtV5DS3/bJ/6PGTnTUIY9AteLWbkJOXazonUOlsD0GkXbILQlB
         G2IehiUhxagXV0mWSU0/VY5eKfg5bz3YxZPWAF4STqwZig4AFPAMdDLMkwqO+jt4BK3S
         x7+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i7+HXzBL;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746265209; x=1746870009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z/2LI0R12yf8c3C2tTX+UyNk8ErgUZQ5/kLZ0SQ/X9E=;
        b=Lx3c4Mdu7n5MmtoAjn1MiPahGeStKqYmV7odz+XOihan82xir1ubiRzOeeZgtFvBn2
         kVcQJKr8cb+cyjzSW+rqRMPGXU583KsgJyy56WPNJFli/zV1TByfpFIo80ZDHLVwiebT
         s41o3m4b+4te3LTTRc6e0dB0JmNv1VgIToRyY9+OdD01Ib6tcA5TIdIu05ptHkBRHU4M
         dyYKK/7GMHMvGlV05+g61kUsGWIlQMJiPi0zZxNJSkTto7nubfc15VfoWbCky8P8WPe8
         sfteN1pJYlloS9rR4VcYzcmqTfwO0nPy5JH+BbJi62QeXuhtocQel1qBaUx+jpVwfT5R
         IvJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746265209; x=1746870009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=z/2LI0R12yf8c3C2tTX+UyNk8ErgUZQ5/kLZ0SQ/X9E=;
        b=UuCJnVM3mqD5hVksFvAgblDL1YFv009TQDyqztLXH6GzcPsONhrZRVJSJHEyITYKZ2
         hVBUaakjxD+JJs3P+tUWTFr0hqOCWqNNIYZswWuj63mgQTHtOZDLHsnA+Qzll9U6AANU
         ZAfPHUwkhi6qarwphpgzn+1SxWmlAZvvEqyTqLgH2zQvzEFvFnhBAZOYdd8JgqNOi+y+
         fE7VBalIR+M+nKN6LjnbZs1v2+mgGCDu/qFsUV6/Huy97TiEQSNdZpRB2RHnTgaGwQnJ
         K4r5JR4TpxaSOzuhRW/UQbuerXjz53c/TmLuTtzs5J7XvyzTrN7TDsTxIwYKgq7+bYAW
         fIFQ==
X-Forwarded-Encrypted: i=2; AJvYcCVw67CLENLjP6AmpzalEYAgytyp6CTO45+xaIxhjuVVlz5uDnCm/VeIICEmoR5EBzYmqwBX3g==@lfdr.de
X-Gm-Message-State: AOJu0YyhEqjxvVn7XjZixIkn6d00N/MIFRFVFK5Z66BmM6Jyste6d1iw
	E7VELpHJ81kw2OmwDaIc2hzaaPSjm9vVLdi4xeAH+Wc63fdrviLd
X-Google-Smtp-Source: AGHT+IGO7PZg1DR55VkDKTWBjvVoqjvIpoR8zEhx3c1hyQyYwfUzqXepUKbpgOdNo2qInaZehGdtlw==
X-Received: by 2002:a17:90b:4d0c:b0:2ff:7b28:a519 with SMTP id 98e67ed59e1d1-30a5aedb8d8mr3425592a91.30.1746265208907;
        Sat, 03 May 2025 02:40:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGmg2oA4ku4/njgVtEsVk9DTpsrafudh3zvBYNGfHR4Bw==
Received: by 2002:a17:90a:cf91:b0:301:1dae:af6 with SMTP id
 98e67ed59e1d1-30a3e89c32dls2145777a91.2.-pod-prod-02-us; Sat, 03 May 2025
 02:40:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXeu7VQQ/1MWudd0yeviAxprkt+GZ8pScMDqFpZIxAGYnv+IriLKJuLKLszCsnDDH31SDHO405fIcI=@googlegroups.com
X-Received: by 2002:a17:90b:4c51:b0:2ee:b4bf:2d06 with SMTP id 98e67ed59e1d1-30a5ae52d16mr3332407a91.19.1746265207631;
        Sat, 03 May 2025 02:40:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746265207; cv=none;
        d=google.com; s=arc-20240605;
        b=Xyi1t/UP4U3mBAe1aGgzb4bWGAZ1jdjl0lb5eak2ZlAt2LrVFz9zjUwzAIBTVPy7NN
         UbKuogoAliAggcHzol+OE/JzczcjyD706XFEFUDs1XiTA7v5N6BRPDhocWe5Z4yaUX9e
         OEmF+dTKnJwXCPx6Hzq/62cI6CzuaCyJ4Cqvlvvyx44DAlaH+AgK1vVzQ3aMhyPjvSoz
         pRXrv97KgoeHipJtqPSxHTTyancgpg5P3ZIO5I3pLQh+pIhVcuCB0e0XFAAbDXgdn7jC
         H5iKulj1SMhVniwCzaOrVrDZzcGhd1r1W+BQuBjkMF1F/7mG18PU0jznaguPnz8mjxmO
         V+OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tSLkgcB96XS9BX7vu/hw5jEpRm1hGRPZwIhYM/guD60=;
        fh=2yZqHUzJSz3KspWoSiLXY2Vx9B6vQP0NV5ntRTtTdek=;
        b=TJQcJABc/QIiFzhcQWNwgRpkILogiaEAWOYHJKK1qgg7639h5+HMh141zJ0pGcRipN
         89zK/ZJMW0OgVDf2TXGfUTanHkBBhb7EpT0tM2pTf7tTPyUGPZaJgeTX8gFnijLLeyAn
         IR04yI8GwhEflofNevkKTBryQNM72QR3AZ+1AEApi7QAi1BXVja02fZrBPNJApklo/DX
         N+En3vlk4MVJpsumvnli03EJ6730ribpZb2+Qi2RcfXMhiy61HcvxLCpMSUhH8G3Egkk
         cRGiuMTycKS2b43RZyq7Cu+JZsfKPR1Sopix7yPt/pAV+vxFnNQY9qJ6XBZmbw5gDqLY
         QjGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i7+HXzBL;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a475e51ebsi229332a91.3.2025.05.03.02.40.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 02:40:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D5CD95C4612
	for <kasan-dev@googlegroups.com>; Sat,  3 May 2025 09:37:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A8E44C4CEE3
	for <kasan-dev@googlegroups.com>; Sat,  3 May 2025 09:40:06 +0000 (UTC)
Received: by mail-lj1-f178.google.com with SMTP id 38308e7fff4ca-30bf3f3539dso29412181fa.1
        for <kasan-dev@googlegroups.com>; Sat, 03 May 2025 02:40:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/Wd0uF8HxIBvIVJrRv5Zy7ji/zjonmHDIXTDWHm1ny1l6zRWamzpg8xN0Xc3bVUUPULCPSQpjqVY=@googlegroups.com
X-Received: by 2002:a2e:b8cb:0:b0:30b:f0fd:5136 with SMTP id
 38308e7fff4ca-31fbd521738mr25333291fa.18.1746265205431; Sat, 03 May 2025
 02:40:05 -0700 (PDT)
MIME-Version: 1.0
References: <20250502224512.it.706-kees@kernel.org>
In-Reply-To: <20250502224512.it.706-kees@kernel.org>
From: "'Masahiro Yamada' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 3 May 2025 18:39:28 +0900
X-Gmail-Original-Message-ID: <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
X-Gm-Features: ATxdqUHjgwA3zgCEhsY5zu77ZvtX7H9zd8h92syMTrpI0NC3HWoo72zkjE5p6x4
Message-ID: <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] Detect changed compiler dependencies for full rebuild
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Petr Pavlu <petr.pavlu@suse.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Justin Stitt <justinstitt@google.com>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Richard Weinberger <richard@nod.at>, Anton Ivanov <anton.ivanov@cambridgegreys.com>, 
	Johannes Berg <johannes@sipsolutions.net>, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i7+HXzBL;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Masahiro Yamada <masahiroy@kernel.org>
Reply-To: Masahiro Yamada <masahiroy@kernel.org>
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

On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
>
>  v2:
>   - switch from -include to -I with a -D gated include compiler-version.h
>  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@kernel.org=
/


What do you think of my patch as a prerequisite?
https://lore.kernel.org/linux-kbuild/20250503084145.1994176-1-masahiroy@ker=
nel.org/T/#u
Perhaps, can you implement this series more simply?

My idea is to touch a single include/generated/global-rebuild.h
rather than multiple files such as gcc-plugins-deps.h, integer-wrap.h, etc.

When the file is touched, the entire kernel source tree will be rebuilt.
This may rebuild more than needed (e.g. vdso) but I do not think
it is a big deal.




--=20
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A%40mail.gmail.com.
