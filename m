Return-Path: <kasan-dev+bncBDDL3KWR4EBRBHPE7XCAMGQEIBAIVEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id F1A20B2854F
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 19:45:04 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70a94f3bbdbsf44455106d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 10:45:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755279902; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z8F58e+USwo863y97sAtiF6ldpxrJ4vy0H49xX20fMmzOpqY+/6QU9VpaIF505+FLj
         ERmb6GwRC+n8YbVks5eZzImHVysglqIegHAof0RF5vc8bWtxW4rMkI1ExRG8powj6Lc8
         NFrRkA/zNTZnpCsOu0rYeevY+mRlpej3uYAH0FX6J81LYfXYy89hVqNIVza7r1s1ZHFi
         NyoMHIn+RfUVTm539OV8Gpv+He5fCS+OVla/NaKZUIvnurJZC24/PMYsLYVt0ob3W5j/
         4peIlOHENzGdM+VHZK/9cN91994OreDDWnvurnq9rkwMcqo8eHhzgspdTu5M9/eqhzOU
         EkeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KRUa1PE8SctbG+A26uoj0p85fmWR0fjtJMp0IIfjitw=;
        fh=KaTjEFEgwURBCTvltPGzQsvMcfqy5zAnpDeYII2aUgs=;
        b=YIBqNNzZE7kH89sjEbQ2IWA9WljxnV2Oob3XkcpGpr88xvTmE07wcNFtN3dmS4FeIu
         OvFMzZ5dtVLmx2QT+h5NqSFxeocFRINlVF9WFZbN36AD8VwWll1eCUsEFdEL3JVBiWwO
         /d4P80ro0IvBQ6dk4d3WQfmgHinZGXt7Vz7DxjVIgBxPW7mju7SsSTdKnlWFlda9dqYl
         OiZiDfcmzA/LvrOl64mDb9sgM72vGd5EUgOp21kZBwZLmPUVUdo9VxOrDFonpPlKxGS5
         zk19HS2/B6Dq5Iqx2wnvRBkLWVXIJXowS1MYuccLAuKLq6antjIZNr5mysoOXt+bSNGm
         ykAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755279902; x=1755884702; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KRUa1PE8SctbG+A26uoj0p85fmWR0fjtJMp0IIfjitw=;
        b=nSLrQD2hBYB+6jjUAw1mGfIMdIE83x5DiFD0HFY0Ydq9uo1+wwGvkAr1/8GA4dMkey
         x2+kpEFu/K1E1N3jCJeuqAUXmNd2rd9adLNxjyIvoKgnY/wAZEZYS4/zwrTeE7CxbyAH
         ATyL1C7ARpZJzTF14/NrJQHdX2sATtUQpR9ypV5IKM9D6DgekGoxK7QkjNN2Mk+xV3lX
         ntapaZqMctxzjC7wajqk/Qyo4lhw4P7+4O20X7r0q0SIcG2v3c6Gfn+a7nhRKHpSXB6R
         pQll6WCNN5oOmbYkYL/tFwTUosv9Zzmeq92e7Whv9SxYMHYRHzpRx13UnZDe16R6SNZw
         mvgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755279902; x=1755884702;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KRUa1PE8SctbG+A26uoj0p85fmWR0fjtJMp0IIfjitw=;
        b=MK4Hy8ut2irXIKlURuGgNFBfoz7Xl3bNT+7HALApY3sh0rafNYt6kXA9AmlDHqR6Lp
         Qr7d/JkndWM0Mr7vFoRuDKAKHhEiL+bwGjZCqU9+36IgmHEIypfA1HWqDNGokGAxpVM5
         f+EMs23Wo4b7AIdLhn08eXUZ8f6UMM0jetLB2e7xdlXSe4bF2UoYhXfOYCUPoi6gNQqu
         s69gWyGFPO3A/dJx4HLpUYGy19ZqEpjU+tjhHPAcyoWKdue3DpXqVYbwD0YDxdIj9FWF
         SpNy+uc/resyV4EYp8VNBdU4+Jg2mu2uENZbHxVL66I7VjxQp/3zYZ6aaMHGvpaXmo0Z
         PfUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQRlHRVJJ1LoEFaTv1d5ZMxjQIj6aECRqVUpM8iz1aOQY1dgsgiPD0WuYAvE2NM82wHOOCEw==@lfdr.de
X-Gm-Message-State: AOJu0YyBxvN7VU8aeHr7xi53jF0lG9S2o597Y7STR8FPtiLCas4Z/Pyi
	+Jtcn+sks2rZ32E8At++LVSLblOa9erncDvyOlXMuY5VVtTdD9UZYgsM
X-Google-Smtp-Source: AGHT+IEMEKZmjcAGRKDP9vNroyW2A13rmWXK4OKQR2j+koosrAlZA10F7tU2QY+90rltyUqv417fWw==
X-Received: by 2002:ad4:5ca7:0:b0:709:9b8e:da0c with SMTP id 6a1803df08f44-70ba7cb4f98mr33023456d6.44.1755279901965;
        Fri, 15 Aug 2025 10:45:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcBQL5rtcbl+XyjHvP+xPSJ/YRVV6J09pGwtr0Ci3IPmA==
Received: by 2002:a05:6214:27ec:b0:707:56ac:be5f with SMTP id
 6a1803df08f44-70aabf244c2ls26163216d6.0.-pod-prod-05-us; Fri, 15 Aug 2025
 10:45:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWaXqpnzlgt2RQPUImeR3z+r5DKjOehiR0yJTZZm562lIqhNSMZ8ygsuVJ7iGgcsMCYK3QbRgcibOk=@googlegroups.com
X-Received: by 2002:a05:6214:4015:b0:707:71d9:d6da with SMTP id 6a1803df08f44-70ba7a75f77mr37218196d6.10.1755279901137;
        Fri, 15 Aug 2025 10:45:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755279901; cv=none;
        d=google.com; s=arc-20240605;
        b=a6nbQyC1k21qL3o5qCJ3Qa6yLhKRJ+Q3AyoWnmiWS8O2A/zu2+7efKZfQ3vaua//V1
         e9nzxjVjK8Av9vJZ8dHrjMA+QJvJis6tIJk7yp7RfTMbMWi4DUHUfBmVDcWWOOGhVVhV
         7yw4CDpm4xgvp1FI8vcXW7NULg7MlT17xA+hUphPiWceIjRaZkswrR0vG+owdnstMx9O
         PCZrwJ6EDxHXGXtLm+PZ25CyTdMsP+qYpw1015WUw367oddJoCV1qwBR5iOnuCZTFAV/
         gdu0C/qeXb5gXOh8cmhJi+MIw5BTlWXcD98AZ+TNrtthNDB9Ao1Iio0/BlDN3k32pe7v
         Hg+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=2aFcE/n+jYq3wIvYWDgDgimCNZtY5B4eYaY7TUpTtR0=;
        fh=EzR/B+1KMqNd9XTm1o6Oe7qwChDN7wGXNwHOALRhjRs=;
        b=GGeBMd8+WAQWD/o1QnVhrQ3QCYzX0g87Xu3vXvFS8KCqKyUN/k7d2EhRa9ngMueq7K
         2tkPWmr9oyoUo+6jH2kgUYwB5H/3eRUT4Z9hpSbeAWz+UmrVmtwQ+429Z4DlP3lSMK5F
         WlzlK1QbxaDOJ7vQz5B8ClaoUvcUgs+iah0+BpKgB/CYB+mXKEBmizWPzyEWHEMTRWVg
         +T6QyUbz0DsceFlCpClJ/X97VmFQLH/VG2eWpDGCn5Wik73nNkuklyWKP7RTXWEmU7UL
         /UmPVd/9bVVdn+hgO85ugSNBSooqoyWthy47HU8S5J674XBZzHc0ai2l8g+Xu/GGrx18
         ku0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba9220586si606836d6.7.2025.08.15.10.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 10:45:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3A08143EDA;
	Fri, 15 Aug 2025 17:45:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A235BC4CEF1;
	Fri, 15 Aug 2025 17:44:55 +0000 (UTC)
Date: Fri, 15 Aug 2025 18:44:53 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v2 1/2] kasan/hw-tags: introduce kasan.store_only option
Message-ID: <aJ9yFZ0aobVUPDip@arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
 <20250813175335.3980268-2-yeoreum.yun@arm.com>
 <aJ8WTyRJVznC9v4K@arm.com>
 <aJ87cZC3Cy3JJplT@e129823.arm.com>
 <aJ9OA/cHk1iFUPyH@e129823.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aJ9OA/cHk1iFUPyH@e129823.arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Aug 15, 2025 at 04:10:59PM +0100, Yeoreum Yun wrote:
> > > Like we do in mte_enable_kernel_asymm(), if the feature is not availa=
ble
> > > just fall back to checking both reads and writes in the chosen
> > > async/sync/asymm way. You can add some pr_info() to inform the user o=
f
> > > the chosen kasan mode. It's really mostly an performance choice.
> >
> > But MTE_STORE_ONLY is defined as a SYSTEM_FEATURE.
> > This means that when it is called from kasan_init_hw_tags_cpu(),
> > the store_only mode is never set in system_capability,
> > so it cannot be checked using cpus_have_cap().
> >
> > Although the MTE_STORE_ONLY capability is verified by
> > directly reading the ID register (seems ugly),
> > my concern is the potential for an inconsistent state across CPUs.
> >
> > For example, in the case of ASYMM, which is a BOOT_CPU_FEATURE,
> > all CPUs operate in the same mode =E2=80=94
> > if ASYMM is not supported, either
> > all CPUs run in synchronous mode, or all run in asymmetric mode.
> >
> > However, for MTE_STORE_ONLY, CPUs that support the feature will run in =
store-only mode,
> > while those that do not will run with full checking for all operations.
> >
> > If we want to enable MTE_STORE_ONLY in kasan_init_hw_tags_cpu(),
> > I believe it should be reclassified as a BOOT_CPU_FEATURE.x
> > Otherwise, the cpu_enable_mte_store_only() function should still be cal=
led
> > as the enable callback for the MTE_STORE_ONLY feature.
> > In that case, kasan_enable_store_only() should be invoked (remove late =
init),
> > and if it returns an error, stop_machine() should be called to disable
> > the STORE_ONLY feature on all other CPUs
> > if any CPU is found to lack support for MTE_STORE_ONLY.
> >
> > Am I missing something?

Good point.

> So, IMHO like the ASYMM feature, it would be good to change
> MTE_STORE_ONLY as BOOT_CPU_FEATURE.
> That would makes everything as easiler and clear.

Yeah, let's do this. If people mix different features, we'll revisit at
that time. The asymmetric tag checking is also a boot CPU feature.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
J9yFZ0aobVUPDip%40arm.com.
