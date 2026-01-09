Return-Path: <kasan-dev+bncBC7M7IOXQAGRBHV7QXFQMGQEEQS7XDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E6D22D0C22D
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 21:05:59 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-804c73088dasf2313464b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 12:05:59 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1767989151; cv=pass;
        d=google.com; s=arc-20240605;
        b=N7JKhcsU4w2k8jMAMOhvkFP3I9oQwdiBi51Bay0f3nyqFNwodQamsRaHuedGyZXaRr
         aj0DBCDzf/Sv/08+a3SqSQ5mQZVYKLN9vipJFXb63PfxtT14RttNvvcbW/gXR66uOh/p
         5pjh19uZhNZTKLOnNZPGtsZNEibujha9q5Q6Obu4xRho90u9R5tSC3V3+NUI4efwUYd/
         1TA8eYLxo2iDaQORzcWd3c+riWSmo0y5AFlfnFyf+NHWkxsY1gCriP+OR77Fy8/02xXc
         z3mwkjSa1j7yTN08vVPKEapXMKFLSZ5BCNXDSezKGXQbi5mCoR6pufTSXDX9e1EymwXI
         prHA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lwk5Wr4oVnhqn6sjN785/n3nZKTDPSJ/bSmPwPtXJoQ=;
        fh=ge47Z3aIfRvYNoMszeiGW8FPY76SN0J2RbgVP/1DLK0=;
        b=cBT7fpyJhKTGqdXIvlMkMFv5sTxxYYhiIK8txIgH3BN8nfvDTrLT1JbfpdYA8Pn7PO
         4NJLrCP6U6AEj8ITf53ZkyCBp07UQwkhdfF3f7uy4oMWqcdlFe9DqFC4llm3qAvvTr8K
         /UYu+LbGxi7i5FNZxwFohn28fSTdWmdGhUqc2S/yMLvAw+805w4ePlKyhWZLEFIY5JF7
         wsZ99hCHzdQJr7vAytftBiuAaoHcOuNS80X9n6B2cqJ78HUEm6xB3V/MmjX1GdWoYY7p
         vzNi8Tp3w6dvut/mWjsztDa5r56KfrRGpZbT1cRDewMu+smwhKYL2h+/No/QedDqKHij
         9/Yg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=offANE5A;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767989151; x=1768593951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lwk5Wr4oVnhqn6sjN785/n3nZKTDPSJ/bSmPwPtXJoQ=;
        b=OqrkqeQbGRKiPhyiNNokMhVwMq1D4gFriVnoCPm2Zt6Nago6tYbNULADpMDLEJnMwb
         vKVttaX8peKehNlBFy3tE/d6SFZxk3GHtuNq9I7sxN1D7DHKJZYOk0EW6MZjgSmEdXgt
         iXOQZrdOeQC7okkkr+4xelEBuYpIsAgHDojKc70zzbwvinhTy04vj0PdHFKkS313+Rbx
         cQbPoEobFf1OegIsgdGXuWlRlDvgjUH25HJb9/Xi8hWXwHPFC7skQg8qMFxeLwzP1qZk
         bNJn9ZfDUpcpBZnTTtXxUKoLmKdVgEm+6gsx4idHkwaeok2cSCh9iBf4Unn4d+zbM1k+
         26EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767989151; x=1768593951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lwk5Wr4oVnhqn6sjN785/n3nZKTDPSJ/bSmPwPtXJoQ=;
        b=T+6wPDT7JS2jD/9DLSdG4+VW94p4cQu7cOFgLtqj8zNyMnoOElZquViZT/tQYa9MB8
         tFAFv/NS9oYDSuD25oP6ooxD8hOFfYYd+vCyGihPu9GLWAzYqdXDJmLCfMvPyxFAwDZ4
         3c53eM04UJe3clcSqe2RR8BAUbe1uelnO9YyQwSY2h2fUW1ErTGumtGENtOchhPTpPH7
         ZVFW45CMl4/y3/L4+FtiiBA0knIXkVH4jgfvb6HR6srb2/whwj1XBoDE+j2Y+/KuYKX4
         qnRAqkdVv11ahMKwgQO4e7WsCveR5l2jiZw4SuVydfmJgLNw7hJWmCcf2OJJecast+zr
         mn+A==
X-Forwarded-Encrypted: i=3; AJvYcCX1lqsvcGOWcsaGKAcpaniUZfdQK7GESzleIIjOhXjAVa32PJNoQm8isa9LapHMCLIzgMnKTQ==@lfdr.de
X-Gm-Message-State: AOJu0YzCZpTE73iuuEeNO6PX6rM/mfgGr5UL/Ygj2Vt6zdCcEAlTGRrY
	o04ggium6GRRKpvtB093QBLbiUmFvO8RBKwYzjwsLyBSh3ULDcvX9Pk4
X-Google-Smtp-Source: AGHT+IFHtAzS/t1FlneqRtOFMbaG9AbsyFAHJTPnocDIF428T18rN3f5cNu6N8zTfNq4J3Fnxf9eVQ==
X-Received: by 2002:a05:6a00:408c:b0:7a9:f465:f29 with SMTP id d2e1a72fcca58-81b7684e6a1mr10192810b3a.10.1767989150847;
        Fri, 09 Jan 2026 12:05:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb6uUjJs3JRdRgvioVdBdfNWnS9h7Ya2ue8bJp66lMLCQ=="
Received: by 2002:a05:6a00:138a:b0:7f1:305f:5684 with SMTP id
 d2e1a72fcca58-81b79af62dals1743558b3a.0.-pod-prod-00-us-canary; Fri, 09 Jan
 2026 12:05:49 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXi0DBOwujIsxgDjy6wv5//6VIC9UsClB5oGoarURK8l7xEchMMWaggeF8XW+z/uNiQyHq5EVOPTl0=@googlegroups.com
X-Received: by 2002:a05:6a00:408c:b0:7a9:f465:f29 with SMTP id d2e1a72fcca58-81b7684e6a1mr10192760b3a.10.1767989149347;
        Fri, 09 Jan 2026 12:05:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767989149; cv=pass;
        d=google.com; s=arc-20240605;
        b=EtFAGbEvFEA04mWeDYeoMxMvtzGqxaRalvRCxiX2TYt99PRzzsv/Tcmo+6GiVtdv/7
         FTD7OZ3xYVFp7MYxi/4zOTtcqUnt9CSAyCIjSJcagQ/zZurtaqt1HK5xUCaey8wtNXTD
         y7T8JpB1Dqk3lil9bFPZvz47jEocGYopvzOv3Ltl3hGW1QB36vUMDigC83mQl/IFO4aN
         31+0alB1Ok/z3FD+1lsfvsdqS+Lt/5DxOjCvkxv1moJAwk6Ap6xHuZU4i9Es/OTUc29c
         +Y8PjQrbQsMMLrahBSDxYQLTT2L/NnlMCnbRh81L4BnUF6JPoqbZD+hXmelF2XrQszoS
         g/MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ko3JkQ44nAbzOXJyEQ8fT/XizqibmiJrgKY4PUFt/a4=;
        fh=gfZ5w2sioZpFUEumhxrsg7apOY8eZCFEaTILdr2Pnr4=;
        b=IYO6FSJjlAeTM+rOG5mkadRw/aag+XOlztmboUTE2TGxD6avymUwwVjHoLRCR9pvB0
         yy0aH9cBnZxE9XxtkRFW36OwAXcmDgxKDK0RulH24rFGneTWU4LlE682P6Y8F6UBFZF9
         wiU+JVHoyGAeW05vRManoYub4IPvWRii93aQuxWcSBmFotOu1q8oXTy72BhIOtAvI8AY
         wM116J3DSxdnZ+2EBS1c+dCSJPF7RjmUEsPvSJt0HqRtk6AtXvopZjq2sWdEaMAc+O72
         23pHgUTRSBARrbGXK7tiLLKPEA81Lo1+PK0s34jr+4PCTLC6gsLO2a5HRNQrxjpwfD9n
         WILQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=offANE5A;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-81dfe7d1cfcsi125305b3a.9.2026.01.09.12.05.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Jan 2026 12:05:49 -0800 (PST)
Received-SPF: pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id d75a77b69052e-4edb8d6e98aso98141cf.0
        for <kasan-dev@googlegroups.com>; Fri, 09 Jan 2026 12:05:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767989148; cv=none;
        d=google.com; s=arc-20240605;
        b=a2Hu935UZK8BQWrRrxjKOUIILwgrdAXByVohieAA4MI7cG9h3Ig3xVTM7T75ifo25J
         b376hB5ZKDmxgeYZPBu3YnzKJv/sNXmC6QejC/MfKAq3OXacrvsa7uXRhsqHc+hLOAjK
         9i2CrfUSmEx0A5HXT7JGNMEopOnZpVI/rI0tKsg60UpVhNvjALO+VI50PK2PVxil9hqt
         esQVOqG++zTzN2c78GQDxZsMAR0G1P1p5mCxnrt4CPkFoxE74jyMesuwNFhqsKtUjucj
         k1D+bLU+Coi+QkBtebVrW3KjdSmLMZfGArYxOzgdWQNRDmgBgnvYLiEN8DD4ZG84oYnb
         k3CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ko3JkQ44nAbzOXJyEQ8fT/XizqibmiJrgKY4PUFt/a4=;
        fh=gfZ5w2sioZpFUEumhxrsg7apOY8eZCFEaTILdr2Pnr4=;
        b=ga6aCOEaH36C5jGt25HkdBjgvfPR1Ayk7FFq0h+l31qyGL4RqTDeYeBDArOjt8u9Ng
         3R2EzqWjAuWWGy/pYqx4NJE1KRfErorMfvFQSj/AaeCVIoOgYy9jaT8AmSuyZcltsuHY
         b6AUJFTD91U7bOjVkHXXhWS+pxTMJe9ixPhTd6IhQcI61uwe5qSq1JOPPrOf+Ylh37Qy
         nOkFa9Vq1SXMAm7VjLJIRjlUiPmQwWf+Z3gvFIo/qXutN/HsKWl3cK3yQ9+Jb1oLF7Ki
         bxY9iq23n1Wcp6xIEMp+Za5lldZ6TVhagW2u8/PX+U14b1JGcMnhIUQWFMhtHqsjLzz+
         VcKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWQm/qlOlpELVD01MefN30jJh4OAzfKojuS40E0njrOBNw+BuuDt6wEPZmaWE2mKbSKtPeHh56zqpA=@googlegroups.com
X-Gm-Gg: AY/fxX6HHVRsPL5kUgaHSumCLneiF/nmKvtgVC64vRAcGoTLFEybdv22T3SgK1P/Ovb
	2YdydtPTosd8vzeMf1JhVjc4jX5eXkPGK6kQeeZTqFuOeFF15VtHg6jx+wmO65ZbBnyS4kNijga
	j6OEJTGRx0EvwvbqJeFA6Zlp9+cCmyXq17ISTFUUssar+Q0nFsXBiK5xPyz3/aMG6MQMjc/lvXn
	GIzwL0bBn5iURX8S9nOcAP8txuKai6G3/B3/csBJi/cPKkYJeMjOG4tnui7XqJXHG+470tvAiuz
	YmrS5c6cwKeUZwlXCCzg1dWW/r7M
X-Received: by 2002:a05:622a:178b:b0:4f4:bb86:504f with SMTP id
 d75a77b69052e-50118440b8cmr1789941cf.16.1767989144843; Fri, 09 Jan 2026
 12:05:44 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <202601071226.8DF7C63@keescook> <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt>
 <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com>
 <CANP3RGeaEQipgRvk2FedpN54Rrq=fKdLs3PN4_+DThpeqQmTXA@mail.gmail.com>
 <CANP3RGcNFgLSgKYPjmro2s1Es04Pnhf+4wHpnSwRX4M8bLDW9g@mail.gmail.com> <aWFKEDwwihxGIbQA@wieczorr-mobl1.localdomain>
In-Reply-To: <aWFKEDwwihxGIbQA@wieczorr-mobl1.localdomain>
From: =?UTF-8?Q?=27Maciej_=C5=BBenczykowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Date: Fri, 9 Jan 2026 21:05:32 +0100
X-Gm-Features: AZwV_QhLJQSwWan9rfokapXwPD_hH4leOJZCxSTMQjFkB3XO4UgPvfMA1zeQaVc
Message-ID: <CANP3RGeWLMQEMnC03pUr8=1+e27vma1ggiWGWcpX+PcZ=SsxUg@mail.gmail.com>
Subject: Re: KASAN vs realloc
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Kees Cook <kees@kernel.org>, joonki.min@samsung-slsi.corp-partner.google.com, 
	Andrew Morton <akpm@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, 
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: maze@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=offANE5A;       arc=pass
 (i=1);       spf=pass (google.com: domain of maze@google.com designates
 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
Reply-To: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
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

On Fri, Jan 9, 2026 at 7:55=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> Okay, so as I understand it, the issue is centered around adding a size t=
o the
> pointer - because in that case it can be unaligned and it can trigger war=
nings.
>
> So what do you think about changing these two:
>
>                 kasan_poison_vmalloc(p + size, old_size - size);
>                 kasan_unpoison_vmalloc(p + old_size, size - old_size,
>
> into something along these lines:
>
>                 kasan_poison_vmalloc(round_up(p + size, KASAN_GRANULE_SIZ=
E), old_size - size);
>                 kasan_unpoison_vmalloc(p + round_down(old_size, KASAN_GRA=
NULE_SIZE), size - old_size,
>
> From what I've read in the code the second argument should be rounded_up(=
) at
> some point anyway. In the shrinking case we don't want to poison the last
> granule of the new reallocated memory chunk so we round_up(size). And in =
the
> enlarging case it would be just as correct to give up on adding anything =
to the
> 'p' pointer - but that'd be inefficient since we don't need to KASAN-touc=
h this
> memory chunk - so we round_down the lower boundry to get all of the new s=
pace in
> KASAN aligned chunks.
>
> Did I get it correctly? Or is there some flaw in the logic above?

I think:
  kasan_poison_vmalloc(round_up(p + size, KASAN_GRANULE_SIZE), old_size - s=
ize);
since you round up argument 1, you need to lower argument 2 to match.
Otherwise it can cover an extra granule.

Consider p =3D granule (16-byte) aligned, size =3D 1, old_size =3D 31

Previously (old_size) we had 2 granules (1 byte short), now (size) we
have exactly one (very short one), so we should poison just the 2nd
granule.

This means we need to call poison(p + 16, 16);

--

Perhaps you need to just do something like:
  size_up =3D round_up(size, GRANULE)
  kasan_poison_vmalloc(p + size_up, old_size - size_up);

this is assuming p is GRANULE aligned.

likely the 2nd argument needs to be rounded up or down.
Possibly one way for poison and the other for unpoison?

You can only poison a granule that is fully covered.  So you need to
round up the start and round down the length.
You need to unpoison even partial granules, so you need to round down
the start and round up the length.

But really you're not rounding lengths, you're rounding the start and
end offsets, and then calculating length as end offset - start offset.

Note though, that I'm not certain.  Perhaps the tail 'fraction' of
granule at the end can actually always be poisoned safely, since no
other alloc could live there anyway.

Maybe this entire logic just needs to round size/old_size up to a
granule size much earlier??

>
> --
> Kind regards
> Maciej Wiecz=C3=B3r-Retman
>
> On 2026-01-07 at 22:55:21 +0100, Maciej =C5=BBenczykowski wrote:
> >> WARNING: Actually I'm not sure if this is the *right* stack trace.
> >> This might be on a bare 6.18 without the latest extra 4 patches.
> >> I'm not finding a more recent stack trace.
> >
> >Found comments from Samsung dev:
> >
> >But another panic came after those fixes [ie. 4 patches] applied.
> >struct bpf_insn_aux_data is 88byte, so panic on warn set when old_size
> >ends with 0x8.
> >It seems like vrealloc cannot handle that case.
> >
> >  84.536021] [4:     netbpfload:  771] ------------[ cut here ]---------=
---
> >[   84.536196] [4:     netbpfload:  771] WARNING: CPU: 4 PID: 771 at
> >mm/kasan/shadow.c:174 __kasan_unpoison_vmalloc+0x94/0xa0
> >....
> >[   84.773445] [4:     netbpfload:  771] CPU: 4 UID: 0 PID: 771 Comm:
> >netbpfload Tainted: G           OE
> >6.18.1-android17-0-g41be44edb8d5-4k #1 PREEMPT
> >70442b615e7d1d560808f482eb5d71810120225e
> >[   84.789323] [4:     netbpfload:  771] Tainted: [O]=3DOOT_MODULE,
> >[E]=3DUNSIGNED_MODULE
> >[   84.795311] [4:     netbpfload:  771] Hardware name: Samsung xxxx
> >[   84.802519] [4:     netbpfload:  771] pstate: 03402005 (nzcv daif
> >+PAN -UAO +TCO +DIT -SSBS BTYPE=3D--)
> >[   84.810152] [4:     netbpfload:  771] pc : __kasan_unpoison_vmalloc+0=
x94/0xa0
> >[   84.815708] [4:     netbpfload:  771] lr : __kasan_unpoison_vmalloc+0=
x24/0xa0
> >[   84.821264] [4:     netbpfload:  771] sp : ffffffc0a97e77a0
> >[   84.825256] [4:     netbpfload:  771] x29: ffffffc0a97e77a0 x28:
> >3bffff8837198670 x27: 0000000000008000
> >[   84.833069] [4:     netbpfload:  771] x26: 41ffff8837ef8e00 x25:
> >ffffffffffffffa8 x24: 00000000000071c8
> >[   84.840880] [4:     netbpfload:  771] x23: 0000000000000001 x22:
> >00000000ffffffff x21: 000000000000000e
> >[   84.848694] [4:     netbpfload:  771] x20: 0000000000000058 x19:
> >c3ffffc0a8f271c8 x18: ffffffc082f1c100
> >[   84.856504] [4:     netbpfload:  771] x17: 000000003688d116 x16:
> >000000003688d116 x15: ffffff8837efff80
> >[   84.864317] [4:     netbpfload:  771] x14: 0000000000000180 x13:
> >0000000000000000 x12: e6ffff8837eff700
> >[   84.872129] [4:     netbpfload:  771] x11: 0000000000000041 x10:
> >0000000000000000 x9 : fffffffebf800000
> >[   84.879941] [4:     netbpfload:  771] x8 : ffffffc0a8f271c8 x7 :
> >0000000000000000 x6 : ffffffc0805bef3c
> >[   84.887754] [4:     netbpfload:  771] x5 : 0000000000000000 x4 :
> >0000000000000000 x3 : ffffffc080234b6c
> >[   84.895566] [4:     netbpfload:  771] x2 : 000000000000000e x1 :
> >0000000000000058 x0 : 0000000000000001
> >[   84.903377] [4:     netbpfload:  771] Call trace:
> >[   84.906502] [4:     netbpfload:  771]  __kasan_unpoison_vmalloc+0x94/=
0xa0 (P)
> >[   84.912058] [4:     netbpfload:  771]  vrealloc_node_align_noprof+0xd=
c/0x2e4
> >[   84.917525] [4:     netbpfload:  771]  bpf_patch_insn_data+0xb0/0x378
> >[   84.922384] [4:     netbpfload:  771]  bpf_check+0x25a4/0x8ef0
> >[   84.926638] [4:     netbpfload:  771]  bpf_prog_load+0x8dc/0x990
> >[   84.931065] [4:     netbpfload:  771]  __sys_bpf+0x340/0x524
> >
> >[   79.334574][  T827] bpf_patch_insn_data: insn_aux_data size realloc
> >at abffffc08ef41000 to 330
> >[   79.334919][  T827] bpf_patch_insn_data: insn_aux_data at 55ffffc0a9c=
00000
> >
> >[   79.335151][  T827] bpf_patch_insn_data: insn_aux_data size realloc
> >at 55ffffc0a9c00000 to 331
> >[   79.336331][  T827] vrealloc_node_align_noprof: p=3D55ffffc0a9c00000
> >old_size=3D7170
> >[   79.343898][  T827] vrealloc_node_align_noprof: size=3D71c8 alloced_s=
ize=3D8000
> >[   79.350782][  T827] bpf_patch_insn_data: insn_aux_data at 55ffffc0a9c=
00000
> >
> >[   79.357591][  T827] bpf_patch_insn_data: insn_aux_data size realloc
> >at 55ffffc0a9c00000 to 332
> >[   79.366174][  T827] vrealloc_node_align_noprof: p=3D55ffffc0a9c00000
> >old_size=3D71c8
> >[   79.373588][  T827] vrealloc_node_align_noprof: size=3D7220 alloced_s=
ize=3D8000
> >[   79.380485][  T827] kasan_unpoison: after kasan_reset_tag
> >addr=3Dffffffc0a9c071c8(granule mask=3Df)
> >
> >I added 8 bytes dummy data to avoid "p + old_size" was not ended with
> >8, it booted well.
> >
> >diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
> >index 4c497e839526..f9d3448321e8 100644
> >--- a/include/linux/bpf_verifier.h
> >+++ b/include/linux/bpf_verifier.h
> >@@ -581,6 +581,7 @@ struct bpf_insn_aux_data {
> >        u32 scc;
> >        /* registers alive before this instruction. */
> >        u16 live_regs_before;
> >+       u16 buf[4];     // TEST
> > };
> >
> >maze: Likely if 8 bytes worked then 'u8 buf[7]' would too?
> >
> >it will be 88bytes + 7 bytes =3D 95 bytes(=3D0x5f) which is in the range
> >of granule mask(=3D0xf)
> >
> >I don't think it works, but it works.
>

--
Maciej =C5=BBenczykowski, Kernel Networking Developer @ Google

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANP3RGeWLMQEMnC03pUr8%3D1%2Be27vma1ggiWGWcpX%2BPcZ%3DSsxUg%40mail.gmail.com=
.
