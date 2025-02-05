Return-Path: <kasan-dev+bncBDW2JDUY5AORBGPOR66QMGQEIGLTGHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 159D0A29D99
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 00:41:16 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5dce2e916basf271766a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 15:41:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738798875; cv=pass;
        d=google.com; s=arc-20240605;
        b=eYw8HCourvZJdWua6jyQ/gLMRBMagAkSQpMrx9XxWdn2u463bN789r2AAGVjo5pDnR
         y3gfEOBlLyhNx4zQb0ToV15zsnUUE/WGvEC3phGFVO7svaWWyAmRpimGHIf7X8JwhuBw
         CRlKS/2b+3I5yUSWwJPHZbXFvvljNyT6deyOyQJuziOmrbZyb77pDQVGVilVoxCovm+C
         KLiJpKC4UuOhyqzswhs+6kiRZYAGNNrlR2Q5O1hcn8iZrAcpEfLwVvyzGvaQ/FM1r8X7
         Cc+6Kk8k8rzKwjUwwZmk8LEssSN5V7SznpNm7iYSkotsKxmUpoJlKQ9t6MFfE8GXVWyS
         9ELg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CoTb9KDkyAfM7OKG6dP2wB1Y1PzIsBbpygWHo/OuRD4=;
        fh=5n0o3t+jXJ4EP86MDjOi1DHyWENiqaUKdRhUgBwiKF0=;
        b=iMqQ4SaenmFTEddzx7fRVulzZnPbUFC68Kw8VqMAZq1A8RSQ3B0mCk/J51eh9tj4mW
         WyuABFQeo1iarGpKlACO95npi/sVQwMPaTEf1GJ1F475GG+w+D0q2ASZHmmBOWCOjq4t
         j/km2gSKKWGJUaxkZFtfrWPyULU8ov855MEIRtmmn9nwRcgRMQwXqs5k/lJj52IFOjqK
         ICaSSCHYMrKVqzsdbZ8HyrDD+u779alcXIdJ92BE7qgAr+Nv7B3h2EDGCfg0QPxo1suB
         oL8iJ8/YPThDaGR73EUANiSyb0PX3PVyCzIBxLj1hc0WsZdaAjV4iP2qosjT3rvJThub
         3R1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HG6g+p7m;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738798875; x=1739403675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CoTb9KDkyAfM7OKG6dP2wB1Y1PzIsBbpygWHo/OuRD4=;
        b=k1QcemHnzctDA9cdCPsfLGSrOxmoDizYYLlOt9wqyR9GMBOCLa56ltJFPRMQ0ORLVF
         7j/QuRqtrGL54nbyEYU0UU14EtpW05K70vx/XKIbAoXqDO9wqqeYXmBYjTqBYycfp/sJ
         n3mR8ItGRFsNMdGqL4ni0IHKPgsBm4z3ls2I+vpt/vHbfEGqONfULW1jWm2Kyxsrt2WU
         lW5D1e6XvPOeoKsO1p85AtwOeoJcnzDYyEv+ZhpCo06hz2QDm/TXsRBMuKymYsiBYs/H
         O6MpQzRjys81csxCQyLkWBBAJotclehGya0FhVrfg9F/ASAvpP9X/ZDc1ze38G9nxv0G
         wA6A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738798875; x=1739403675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CoTb9KDkyAfM7OKG6dP2wB1Y1PzIsBbpygWHo/OuRD4=;
        b=ZTjjHmN70REwglrc1x627feANcYZ/zVB6Uo8ldP80UWq1JjL3R6PDK5fTNBuD/AclA
         Ite7GRqafllU69Y+hbilfOE1pKTeQm1ppAtws/pIsIJNElgK41A3x3JDC0pCehWd3EII
         +Mu4uX41rlKWqZD4Wdl9Imqt3M80S95bO/JqkvvnkjPowiUBH0IqcxLDqcnEY++o+6AQ
         51nsZa+uQsWSHqboHIztSZDggu8girVb32U7P6lrL+r5VmU/PNjXmoiwj5nT+ES4mHtb
         ACcglzE0aQ6cWaGTJdTlADqhD0fI4fD5b9s0xYKyR8Rse8fVn0avrR58icZTDxLH0ta4
         5erQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738798875; x=1739403675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CoTb9KDkyAfM7OKG6dP2wB1Y1PzIsBbpygWHo/OuRD4=;
        b=MIsnHRfAXttoZzr+rqDi1loqSRfAMR8tewd8zt48B46ZgG0HU/GtXDQ4V+uDHcwndq
         u/vAVdZIzJtHcTScXUqxx84V8/20WxnGirpwIsTIDRCw2DvxSZO4Nzw9Zh7csTt2dYIU
         qfeLmRZo4aQ2qjGT5GHG10xaXu6JVLuzL66JolnW0sEvgHO/7s3xutpmVYbvO0SuT/6m
         FzD5MxWUBXHhMyz5jaTfS4OhISPLyvQdWdCdalh9qxis2bx+v/SRl/AdtgcQ14IusWLt
         vPF8CmfzCk6cwFhA7h4SZsulDV6eNPrp75lv2VRTeF/qhDZgJId8ZptWjHTK3dtrucaP
         V7Qg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJ121y6gAqJ65E7DRyR0F3vpypXYyFcyM+gESanc4DgzrdAZEWU9zfC8MjSI/rg6qbb0IRgw==@lfdr.de
X-Gm-Message-State: AOJu0YwHDXIsT5QQMldD5KQ4DkFo+Ihtumg/GGAlw4G2e87f++fwl25/
	/XGPJRR41hDFkNgsJqM7T7Y2JC10m9BSl4rEQv6/ixOGoRQgU4V7
X-Google-Smtp-Source: AGHT+IF52DEXxZGL3LQIHntzZBfsKsY0i9wutXPku8vvCHXzuOBKYor+gD9RJF8zKRmdeNlbafyGnw==
X-Received: by 2002:a05:6402:3899:b0:5dc:88dd:38b3 with SMTP id 4fb4d7f45d1cf-5dcdb7128b1mr5738746a12.12.1738798873510;
        Wed, 05 Feb 2025 15:41:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:9f8a:0:b0:5dc:de5:3e0d with SMTP id 4fb4d7f45d1cf-5dcebdadf81ls352663a12.1.-pod-prod-02-eu;
 Wed, 05 Feb 2025 15:41:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXtwEta2jcmUu3q9GJS4Sk7UwLK+4X1stNJ9dl7oeXsd4O/bUUaz96xKArSloRSJbDQuidP3qbPGO8=@googlegroups.com
X-Received: by 2002:a17:907:2d8d:b0:ab7:5a5f:113 with SMTP id a640c23a62f3a-ab75e248afbmr516669366b.23.1738798871305;
        Wed, 05 Feb 2025 15:41:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738798871; cv=none;
        d=google.com; s=arc-20240605;
        b=TTSMJmlt3Jykt9/qDq2VE2xBCAwzlmujyImTdBDPoTxeB8dAxQl77F6nBV5Vny+T6x
         zKpBRQWNqHORBlPGSDPAezXSGl/BhSAQAYKkBGuO0a5HqWRggoXCZSJQkz0mIv1rZSvw
         t0fm7tFt5e27Sfsk78wb1z6nvbVwPmsOLOuTl9t9FJRlcoOH1qX0gVAgl9xlZ5ZP9e+V
         naKyqU4UAoSSL4syxgzHEnPO5z6A2XMLxr0kBgGvi6wnXGY2ZjKFB5AmSWUYbc+SHMcb
         Cg9AdA0sDiwMgZknL88zSxTLr4ocer08Hv577z0b34/+oS1f/pSEl8esrLA14MEW7YJf
         k4MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WKEgMyHfPWTlLLqqrmnwtvQK3GmysT72SpoyvC2gz8E=;
        fh=Sb92/IoWE0Q3RKz5sOINLspEMbuJrTr3vhXF4OfDtzM=;
        b=kguBVIG6HF0sKVqBoh1B9pszBDpF6411thYz3+P3uTDDniau7zUDGfzKAbXXlL6XXr
         fD8E6WlYpdWzq1dv6A1I2Zm1pg7xkpPnrdn7wAMERXRDQ6nH5Dq5fEw5Ystx3NFXrQTy
         Ti3DgEtqVIrp4Cl2+eVwZLDTFPGsvMTpITZVOmUPTMnGmP1VVLvQZFGguPG/Oqgws8dB
         LREf6J36vz8JYNHjLNVsnlQBVTgVoJx3qWaX/ysVow7Airlwm00jCLEy04GS0/VizOpv
         1cPjC6pyH3Jr1WWUkX2eSVvcXt2JSIlBb1P2XwoKh51UsvW2jaj44ebhT6TQ7RP0Tb6S
         o2lQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HG6g+p7m;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-ab772f73025si232666b.1.2025.02.05.15.41.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2025 15:41:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-43622267b2eso3170075e9.0
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2025 15:41:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVrmmrL6orfWE91VB40S+PNDI9gm59NrucKgVQXUcdAvxHePqwmrs8DglF1NUElikd6gZtBOJDLVzM=@googlegroups.com
X-Gm-Gg: ASbGncuHJY8qSJDTou0kMkvrU889hF7XrLwG3W4gBTJ0sAhMwxCI9ixFCH4Otv4vdno
	Nx//v/oAaD6mPx1H8yLTnSSpNIVZuAP3godcCunRNpSqMZ8s//9jVJRXB0sQgLytenQY9VjvP0Q
	==
X-Received: by 2002:adf:f1d2:0:b0:38a:8906:6b66 with SMTP id
 ffacd0b85a97d-38db492abc4mr3094863f8f.38.1738798870580; Wed, 05 Feb 2025
 15:41:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 6 Feb 2025 00:40:59 +0100
X-Gm-Features: AWEUYZlz3dbMNs5uaCuCxvHCPA1V_UbROZFgxVVkwngTO-akZcC0zg4IFPaM-WQ
Message-ID: <CA+fCnZd1dpqv+rM2jD1fNGvhU_0+6c8MjzsgEsi2V-RkHVteJg@mail.gmail.com>
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for x86
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com, 
	palmer@dabbelt.com, tj@kernel.org, brgerst@gmail.com, ardb@kernel.org, 
	dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
	akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, dvyukov@google.com, 
	richard.weiyang@gmail.com, ytcoode@gmail.com, tglx@linutronix.de, 
	hpa@zytor.com, seanjc@google.com, paul.walmsley@sifive.com, 
	aou@eecs.berkeley.edu, justinstitt@google.com, jason.andryuk@amd.com, 
	glider@google.com, ubizjak@gmail.com, jannh@google.com, bhe@redhat.com, 
	vincenzo.frascino@arm.com, rafael.j.wysocki@intel.com, 
	ndesaulniers@google.com, mingo@redhat.com, catalin.marinas@arm.com, 
	junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com, 
	dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com, 
	dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, 
	peterz@infradead.org, cl@linux.com, kees@kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HG6g+p7m;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b
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

On Tue, Feb 4, 2025 at 6:34=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> =3D=3D=3D=3D=3D=3D=3D Introduction
> The patchset aims to add a KASAN tag-based mode for the x86 architecture
> with the help of the new CPU feature called Linear Address Masking
> (LAM). Main improvement introduced by the series is 4x lower memory
> usage compared to KASAN's generic mode, the only currently available
> mode on x86.
>
> There are two logical parts to this series. The first one attempts to
> add a new memory saving mechanism called "dense mode" to the generic
> part of the tag-based KASAN code. The second one focuses on implementing
> and enabling the tag-based mode for the x86 architecture by using LAM.

Hi Maciej,

Awesome work! Great to see SW_TAGS mode supported on x86!

I started reviewing the patches, but this is somewhat complicated, as
the dense mode changes are squashed together with the generic ones for
x86 support. Could you please split this series into 2? Or at least
reorder the patches so that everything needed for basic x86 support
comes first and can be reviewed and tested separately.

I will post the comments for things I noted so far, including for the
dense mode changes, but I'll take a closer look after the split.

Also feel free to drop the dependency on that risc-v series, as it
doesn't get updated very often. But up to you.

And please also update all affected parts of Documentation/dev-tools/kasan.=
rst.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd1dpqv%2BrM2jD1fNGvhU_0%2B6c8MjzsgEsi2V-RkHVteJg%40mail.gmail.com.
