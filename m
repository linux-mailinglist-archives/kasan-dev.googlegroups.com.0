Return-Path: <kasan-dev+bncBD63B2HX4EPBBWEDTT6AKGQETHYI6AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 848C328E19F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 15:49:13 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id i14sf2491699ils.21
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 06:49:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602683352; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ohgbm9rxl+WAPOwgSNOkap9LPy5HVtoPjE6nqt2j/a2uMzdaoxIzYnS/97NTiYwlr5
         e62WHaqVndPaYD7hkdfX0Hh37RyHsUaVWli4XYOb03GyCAxHcSmklB6mm4iZuhKaqzn2
         gnfgHNsvasO3RlQJnQDukFAUHW+4RkEJU/dorLZH4Dxis2xf9GvnBKE5etq/V9AnzgHP
         4lWUp2/t4s1IXKn6CV3Kcu+ToKogpi0WVDtcsq7ICizk/0P6mE2fX4V255X7OU9G0MkB
         R149sfMRh+df/MIjCqNGPIu7IjmSbvjdjX+suLjSAmvM1iPP5QewryZI+Vox9vQcIg24
         I6Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=E83C4ioKPQP0V2eBgbBS8EoL4YwHKWGgePixymb65Iw=;
        b=NZeWUyjDyVlEojScL4sEDh/g82St0ScAIbzDAjF+Lr8g6PCvdv9zchKnXpoCRVqIor
         GrNBnJZ9xvsg57pfs1NMPBm1zr1CjjHpUfZdA/gA6tuyxFodyComOo19/NLeA7xHVM5x
         3s/MeKhUL+k6LjlUwJR2Y5ve3SnfZGClyRZiMJNQBkjSibfZ5CwxPOk3dtIzFZlHNBQR
         2r5hkx6cqq76g81rU98Z2cj2oCz+oikZJp3A8wyJHUTIwO7TTzTqG9N/QZK7f7UZvaHj
         0ShcRNuzrNWommmpLV9rhoYWx6a90pfQsmMigDjn126QsKE47DoXWPMQC/1T2J9fzG5t
         JZlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=FW66JkYR;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E83C4ioKPQP0V2eBgbBS8EoL4YwHKWGgePixymb65Iw=;
        b=YVOdFPIPWgcRNjcJ1wyj/PSSoBxhDlw84GGODCgqziUsNFd2Rag+xC2uE33QXc+8FD
         SYHTWeUyUMRV5Gb9XPpwQARhbVOuDWDiL4bDNJ2/dX/IBDX6nTUom4azaBXyAs7PPVTy
         ACOlUC7eZ7W9QtBakPlD+QiHsodwbUyZMEXe0Bo+rwX69GanoXhEP+sVnuhhgbM2+jmy
         POdZa9EFMEQxQCIwBEA273qX4Tmd0/TfzLPruIq6jMJ6TCzsjiil6WjIf0kFXcP9lJHb
         P6lwQMhrl4FTFNCs2J7gKLkypMSRcP//3oW/UANCBjRdzEEL00aENbABe4yrPao+q9k6
         nCfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E83C4ioKPQP0V2eBgbBS8EoL4YwHKWGgePixymb65Iw=;
        b=aoq+WvT2VShYehmfmlhtzYT3jDp7RSM0l25hIOIrdsfR83ZegGEZ3U+O8V9dy1qxl/
         qePd+kWSG9ZvLFwoL1hCeH8Y9pCfa6999TRXAfp2OJztn9HOhj4ndXMIypv3eGAb2NE3
         4oeNcEs6Gxt+0ogsrnnSdrVB0RwL9DBwdZPIrgovc1lz4AnUgiO0HJhokXZqIa6ox3UJ
         bs5monnFh0ZVJH1BjNT4YOFqxo5ZVY4sI4fWAnfyVRiCBdAa6R/nr+LfVjUb1+2FG7o2
         5hHId8e60Xbwk1sHOHe6C2ThtGbFL135tKXD1vH/KAJU2RRJSZP3mPVSrLNkfo7swl4H
         RiJw==
X-Gm-Message-State: AOAM533x2Tr8zwaO2bm3Uqa7c5arBp+yy/7hhejqr/KGygs01YcBKqE2
	f2yj+15SOl4iaibnRVdJcIs=
X-Google-Smtp-Source: ABdhPJzP1QNYcMBH0T/le0XABSNARxjywr1NkwqS7hz1agQU4mFqrJWZV6J+v61xylyYj1AQQI7DCQ==
X-Received: by 2002:a92:3f0d:: with SMTP id m13mr3985705ila.31.1602683352282;
        Wed, 14 Oct 2020 06:49:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:14c7:: with SMTP id l7ls351499jak.0.gmail; Wed, 14
 Oct 2020 06:49:11 -0700 (PDT)
X-Received: by 2002:a02:234f:: with SMTP id u76mr3192933jau.117.1602683351846;
        Wed, 14 Oct 2020 06:49:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602683351; cv=none;
        d=google.com; s=arc-20160816;
        b=N/PZ/MHDE7N1S5PgoQ2JkvVbSS5vzNfLiQTKH9yQjF9BWAnBlFuwuQKk0HdhJ4ABph
         Oa9mCeEGdHtPfTAKHc+z6EH72jlMMYH/wXHoMWLXFCMlo1mtHbmz5G9J/gDYxm6nWrN8
         X/8jhMTzU48iaU1j3NofuE8KOuAbXC3ea0SMIUCXdnNf4y4NvcoudsnR9GDc0G1GVqF8
         w/RrSnPYXUU1w9Wd9UhhQFLqeoWKFOmEgN053Ct13M5gNYVmI5zLTDhs4ThinnmhMaaY
         9b3eBaenw3NI8Nk1FPRFybfmdO6+8PSExvXIesALFhtTbxAD/mUmiOoC+9kcXQIQASlL
         F0Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=grqz7kNecRngPBJ85DDgKTGNDk7wvTOvsYJmEpe7pzY=;
        b=rpOFc1Mip9g8SBBnBU3Nd5KnLzyTmFzRTS0q+UHwY2kVwN/fWXuPdyN4MT/KgOUJut
         bWXBP/orzywAeI2VWVgZgF0NrRRZhlXHXVbt3UnAzqkCwwjPlDEiZGhixO449vdsxqlR
         KvaxV8LAatVU2tZgnDiM2EwZu3IWS1AJhh+u2NDvVVII8P4ppwG5tBBahBkRt97coEFc
         YQ020MFml9qWXfEnQJCJB4uuhizn93gVIOrNUjeI9lh3hYOevgWDgrai7ishhCOQQEFP
         bgRumFf7y6DOEykL3Mw9BYy4KCjTEDOkJIzwApHBUj4WLFEDYtK1Uf44F3SBK2BJo5X0
         YN+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=FW66JkYR;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id j68si139209ilg.3.2020.10.14.06.49.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 06:49:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id ds1so1601383pjb.5
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 06:49:11 -0700 (PDT)
X-Received: by 2002:a17:902:7606:b029:d4:c797:a186 with SMTP id k6-20020a1709027606b02900d4c797a186mr4284500pll.38.1602683351233;
        Wed, 14 Oct 2020 06:49:11 -0700 (PDT)
Received: from cork (dyndsl-085-016-209-235.ewe-ip-backbone.de. [85.16.209.235])
        by smtp.gmail.com with ESMTPSA id a11sm3390699pju.22.2020.10.14.06.49.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Oct 2020 06:49:10 -0700 (PDT)
Date: Wed, 14 Oct 2020 06:49:05 -0700
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201014134905.GG3567119@cork>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=FW66JkYR;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1034
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Wed, Oct 14, 2020 at 02:03:54PM +0200, Marco Elver wrote:
>=20
> The (hopefully final) v5 will be sent the week after the merge window
> for 5.10 closes, so probably in ~2 weeks (will add you to Cc). If all
> goes well, KFENCE might make it into 5.11.

Random thoughts:

One thing that could be improved is the regular pattern of guard pages.
Accesses that are off by 4k get caught, but off by 8k do not.  I suppose
consistent off-by-8k will eventually get caught when the neighboring
object is freed and the address is unmapped.  Fair enough.

On 64bit systems it might be nice to grow the address space for guard
pages anyway, as long as address space is relatively cheap.  That
improves the odds of hitting a guard page when the pointer is off by a
lot.


Unmap could be made cheaper by doing it lazily.  It is expensive,
particularly on large systems, because it involved TLB shootdown across
many CPUs.  It can also amplify latency problems when you keep waiting
for the slowest CPU.

If you do something similar to RCU where pages are queued up for TLB
shootdown, but without sending IPIs, the operation becomes significantly
cheaper.  Complication is that, as with RCU, the address space range
cannot be reused until all CPUs have done the corresponding work.

Getting all the details right is probably a lot of work.  But it would
allow a higher sampling rate for KFENCE - if CPU is the bottleneck.
Such infrastructure would also help userspace munmap operations, which
can be a performance bottleneck.


None of the above is an argument against the existing patches.  Feel
free to ignore.

J=C3=B6rn

--
Consensus is no proof!
-- John Naisbitt

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201014134905.GG3567119%40cork.
