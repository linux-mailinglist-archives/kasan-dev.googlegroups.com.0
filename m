Return-Path: <kasan-dev+bncBDW2JDUY5AORBS5I5PDQMGQEREMZKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id CED65C04023
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 03:20:12 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-4298b58bd3bsf685865f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 18:20:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761268812; cv=pass;
        d=google.com; s=arc-20240605;
        b=WOwhtsFIdA6PBaQE8OMPyRlqeDdxjyHA9+/luHi/+7ZCVFJW4LArfLx1hRxmRWBZ4R
         JY797lo+hhXeBDSJgmt7hNyJ2XbLvcxJPhZ2UjpXgdxhW/Dtm7ctSJ5eeOueaS/zbLMy
         /lWUpEefL/jMuaFERVTJKDCWPeiA4EaInisEFJ9rZVucSlVzsbWBNHRaZrcNdXn/oCeq
         BQuf7eA3hi/OuecmX7xrKp2oa1wMSWdhTHIKKCKyqbVzAkcD/tqaN06tVSKSp0lFVS3+
         H1O4aO/zOsis8Rp5Uo9AZ3yIReD4mI2geb8HZnYIHCzAlmoaJoKXr80JRebdolnhE8LF
         kgUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=OY9CLZTu7ko1RP1yza4eqYy14NOzgVL8ujaWx6uaoGc=;
        fh=Z8kCEevhFHx90PMZzhq91namuHXrHBpe3ba5ZQvkouM=;
        b=axsQ7vWzi/llCcqCVa4uikks7qGBf9Fu2U5gma92cChB/owwcK4TMLo4Ml8diKQK3F
         udGusQgClzxc2NjIj2qH2PDSO5bSVs4jrsp1kmdHGMbOJwMIAHytDdew6ckEn/laPvHr
         fk/fMUjXegG57Gdi/IN5s97Kiu1gu5eSIyQnhI4FtNXM46HizxOUtwFaZeaeOP778k9R
         5ROELsx64OZlZokNj+LBVNxzO88UfnxscXcFKRwkcNxsqGfcHbvHo9G8TR6mNhZye+lQ
         oGSSqGEBQh9dghtzFnlmFupzcVmozBYMBucrxik9g1cF+05pWrP5QlHo93GSd7uZ4SZi
         f5vg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JnL0m8j5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761268812; x=1761873612; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OY9CLZTu7ko1RP1yza4eqYy14NOzgVL8ujaWx6uaoGc=;
        b=lSWXkpxPfmJYCigI7clEIbBr2myxmqFGlsEQkdWEpMpJTnuSvOmvQXg1AGiNWVHrm3
         wOf41MD1FzLZIfFIB4fR0syy6kfIsfMYy/FGiUn2RBjYm4/jVZF6a+3kMO8bBZu8VI9g
         BB6yxwmYNXyNk5q7wZUKIb9o10Cu5QPSoLHr9RYUg7Xymai4FY9fZzWz44W959AwY4q7
         vY6T5RSQO3ctKf6IH6z9t2ecsWwaXUqtdCvQQDfeFhKouJGNXH5M1458M+mC0YY9n9Gs
         VBk68/HZ6OM9TBY6/4bjX//Cdwu0mlXJNibR4VY+Sr1zUKodCMV/PZjjjDoLfIl6zI9K
         wvDQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761268812; x=1761873612; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OY9CLZTu7ko1RP1yza4eqYy14NOzgVL8ujaWx6uaoGc=;
        b=XkJPk6p8N5cqtadGPHVVVJTrcxRWNpnmX7cr9G8hYsijWX7FFO5xthJXiMJrtuhyfK
         2CUid/muh/wuV0uTHrCo9W4WKS2kOUjie0OwD4xND/db6nhMz+KZwHzWMClnXHlrLVhc
         22ozKZfQeGa4+bs6q90z+aFIHUL1M/Gkn1nfoUNuHTkIDUP8Z3ecidx6y7o+vvrZ0QcV
         MtZYEvwIwRKvOebuYNWH3fpeWvFZwkB7EKv/ovUEVLn4cIyeAbOhfHc4otDxtw/CdkQt
         f/lDsaofIeQCEQG7IcX0e3vtbIRZnjl7njs5jOxe/DXEBXTezPN08xiGvUGAscFJXbSJ
         V8Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761268812; x=1761873612;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OY9CLZTu7ko1RP1yza4eqYy14NOzgVL8ujaWx6uaoGc=;
        b=mJEOG9xZE+tJxvVQyekEMQSX4WmvRFYVZBwfozipfpKE9sx0hjiT1MdNXY80fjXpE4
         6tccAHI5QT/NerVFwaHjGaHnj9pMhUz/AHWx6MuAcs6mmvf11jL9TW1wi83SMrtlhT8G
         mOfDzj+RsQ7lj+mCJNLKnCWFx+OqPeAzVjsQKeObv5UMfr+bY/v8ZyCCrl0191cPgKUE
         r8mvooWY8T7rGOXpjZfd3NCQfnuseGQtuHBydQcJuVQXdTq68t6NucCF+J35bf+uFOtl
         tlZAaZNiRZN4Vl/7ry01EBIrmhr0wKjbmkxPOMgA70LL4/r+qQ7Ivv10c2KsWBRQlDSR
         henA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUF9ZMBBHC6t1Ct+wYQ2dXWG3oUNLrgx4s/u+kNSFgjHQd03icDRendTlcfQ+3D8AW98UcXBA==@lfdr.de
X-Gm-Message-State: AOJu0YwbUiAds/hFCoEy6FmEnoxM0vCLZJXZnzMgbPQs/RDbj2i5Mipz
	HBqLHJM0aOwAYUP8CiIVHyyZ6Tv2IYh82YwlmoewDDWQ1P8anWLsqjoe
X-Google-Smtp-Source: AGHT+IGZdCjYamGp5KFF/UkHsLEec8KGoCSHcsgXk7reqGSk366rQRkdIUns1PpM51DMUBF/ksptlA==
X-Received: by 2002:a05:6000:428a:b0:427:2e8:fe5e with SMTP id ffacd0b85a97d-4298a0405ecmr3293916f8f.13.1761268812098;
        Thu, 23 Oct 2025 18:20:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd74hdFNKKrvxwW6FTdyt1wuDo7C8P1JccYfmZQ/+jTu3g=="
Received: by 2002:a05:600c:3b8f:b0:471:ab2:7cfd with SMTP id
 5b1f17b1804b1-475ca92d102ls7339325e9.0.-pod-prod-01-eu; Thu, 23 Oct 2025
 18:20:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVx5HD8wuOAURN34fnqAFnSEpW2fejB1gM/bDjCNJqkHuKrekeECyQCBTvBzDPhcq6c1OJ9CN94Izg=@googlegroups.com
X-Received: by 2002:a05:600c:3505:b0:471:12c2:201b with SMTP id 5b1f17b1804b1-475cb044e1amr25344315e9.27.1761268809377;
        Thu, 23 Oct 2025 18:20:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761268809; cv=none;
        d=google.com; s=arc-20240605;
        b=QP1SLXB5jHjqq0c8Ue/XJRAiKa9694rnrwLqQ/OAuoeQdytEIafiHFcB4VyTUcSTTa
         37cNhAC4EITPhWK7MAzGyi96wEt5w52xFBbrQXUHO/0HlWWRycOIKeddgTBrpb+Zehcl
         CfEsFprLwiYcpuDeNiZOrLhf8MY260urLIeZAT+7CCY8yOYddRKrazQYhr2cG40VEkES
         +eLion1hEPOSrg6tRSKImJ0uOZmNif5sVbuazCMjX+MnNdKr+wMLo6W5Xki6CniD+uT6
         oHW2if1JK+CMCgiepOEUyoJK5QUC0elRPrCHnXNtNEHSTQ63mO/Tp2l5Azo/icc562y1
         O3cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Cy50PIQ5NMkORVfUN5Id2ZgmraUO4+QWD/JL9v9VhXk=;
        fh=dEq47XvKRjKAhspDF2PfCjCGLdnByzsCT4+SDbMtK2Y=;
        b=YsS0H+Zty/ujS8Q5DbDL6Fe2vwh4gGOy2Eyj4MznC+yHlJxkzlD63GYbjTtGH1qhOX
         oSs+tbpyl8sLIBD6q0AyifoXQWAv4IFX8yCxgEP58XyMwO8DRu6PDiMMMKGlDfME8d+t
         zUYnHrJ4rSUw1K9P+QSNAOqdXHZwKGF+peWmLvl92Gj1jAtY6kP5Uc4c5crxdLtjxda1
         biyDX7F2Op1WEcWkJDWKDkwJg6jezVgLQFmQWzPe8whIKiavTp6+/6zdL/O4lvWclJpz
         Imlp9fdp2jYBeezyAspaVElEg1mPoyoqPArHgp2k5Wb/SZfKTyWG4R6Ht4CuBGTQnGqS
         Ba7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JnL0m8j5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47496b0086dsi1329945e9.1.2025.10.23.18.20.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Oct 2025 18:20:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3ece1102998so970048f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Oct 2025 18:20:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXzFKxhQqSgEJnSBDJsoxqoTzEV83qxR1XiRljt80W4RfCqN2J536feUdFLAiQucecWCVS1H1TBaAo=@googlegroups.com
X-Gm-Gg: ASbGnctr1S5wlR/5veNy53xudQ41XMzfvor9Ezb43wpSbm43F9pSyDcoW5TKwrEvUX+
	7X6vZ4cwmqA4OS3tV4PXrgePE0WMO7GpBysY+8dOPEewRK0wmRo7tHHU2O3IrpdCBdLISNDtwpV
	TnGLoyKN1QoKWIph/fNZHGjWkH0jH0AdQgLef58uFi151iD9Qta/A0W75dCNHmFqefVEyc2CHAI
	IdadSGc3FghW07gH3zgy2lhMD/NS3msejLpOgD3Eo4IbWxBeSiwAbvYpKNDB1R3VBRDBStGbXMl
	armAdK038hTMwBzYWgKk6qaX/OoqHQ==
X-Received: by 2002:a05:6000:240f:b0:426:d582:14a3 with SMTP id
 ffacd0b85a97d-4298a040705mr2343679f8f.9.1761268808604; Thu, 23 Oct 2025
 18:20:08 -0700 (PDT)
MIME-Version: 1.0
References: <20251023131600.1103431-1-harry.yoo@oracle.com> <aPrLF0OUK651M4dk@hyeyoo>
In-Reply-To: <aPrLF0OUK651M4dk@hyeyoo>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 24 Oct 2025 03:19:57 +0200
X-Gm-Features: AWmQ_bm41GuiWsYtz5XuMNDIQQhr0EMvmp-bLNyUrjc6_dWg-wZ67Ora4xbHgfU
Message-ID: <CA+fCnZezoWn40BaS3cgmCeLwjT+5AndzcQLc=wH3BjMCu6_YCw@mail.gmail.com>
Subject: Re: [PATCH] mm/slab: ensure all metadata in slab object are word-aligned
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, David Rientjes <rientjes@google.com>, 
	Alexander Potapenko <glider@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Feng Tang <feng.79.tang@gmail.com>, 
	Christoph Lameter <cl@gentwo.org>, Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JnL0m8j5;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Oct 24, 2025 at 2:41=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> wr=
ote:
>
> Adding more details on how I discovered this and why I care:
>
> I was developing a feature that uses unused bytes in s->size as the
> slabobj_ext metadata. Unlike other metadata where slab disables KASAN
> when accessing it, this should be unpoisoned to avoid adding complexity
> and overhead when accessing it.

Generally, unpoisoining parts of slabs that should not be accessed by
non-slab code is undesirable - this would prevent KASAN from detecting
OOB accesses into that memory.

An alternative to unpoisoning or disabling KASAN could be to add
helper functions annotated with __no_sanitize_address that do the
required accesses. And make them inlined when KASAN is disabled to
avoid the performance hit.

On a side note, you might also need to check whether SW_TAGS KASAN and
KMSAN would be unhappy with your changes:

- When we do kasan_disable_current() or metadata_access_enable(), we
also do kasan_reset_tag();
- In metadata_access_enable(), we disable KMSAN as well.

> This warning is from kasan_unpoison():
>         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>                 return;
>
> on x86_64, the address passed to kasan_{poison,unpoison}() should be at
> least aligned with 8 bytes.
>
> After manual investigation it turns out when the SLAB_STORE_USER flag is
> specified, any metadata after the original kmalloc request size is
> misaligned.
>
> Questions:
> - Could it cause any issues other than the one described above?
> - Does KASAN even support architectures that have issues with unaligned
>   accesses?

Unaligned accesses are handled just fine. It's just that the start of
any unpoisoned/accessible memory region must be aligned to 8 (or 16
for SW_TAGS) bytes due to how KASAN encodes shadow memory values.

> - How come we haven't seen any issues regarding this so far? :/

As you pointed out, we don't unpoison the memory that stores KASAN
metadata and instead just disable KASAN error reporting. This is done
deliberately to allow KASAN catching accesses into that memory that
happen outside of the slab/KASAN code.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZezoWn40BaS3cgmCeLwjT%2B5AndzcQLc%3DwH3BjMCu6_YCw%40mail.gmail.com.
