Return-Path: <kasan-dev+bncBAABBFHD6HCAMGQEP2NRWGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id EA6CFB247F4
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 13:06:00 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-7c5bb68b386sf2061961985a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 04:06:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755083156; cv=pass;
        d=google.com; s=arc-20240605;
        b=X7HhoizjjYNsUmp5rtPpbyQHZj8T6GMKtEY1qONanexbY6HWbNFgXBO/BwAzkEtydA
         hYKkUfCw6BCwHgq236tpFmZlPX7PAxNCdhmi5/Hq8Rjk4CExaYy2ciHTxoIrQrGU679/
         06sCyVxwtaDKPw3Q8HdKFKiwol1VTdFkHZSR9o8qzU6BOsLg4tasi/ed4osmS0PMKyWg
         /v7zztI9Fv1R0DeZoN1Mdq4Te7kDd8iyc/H/9nfK/ruEEfFZkIIcxe5y5KwoiskjWzig
         jq/wbun1iaVnSLsJRbrW1hZK12BnGE10xEPNOKmeE16qCmITJ3q6a9HuczrcQaaW+Djr
         OTDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:dkim-signature;
        bh=CoqZNRmYxTj+QZOiT60U2IDXXsxH71/WPIp9yMqJ4hA=;
        fh=qG3aEspov+N8DaXtz8EMGRdfLvDlT/szX7wNuLkRB6M=;
        b=I0lvGNl5dftSJFdBAWTq+dW/yAjdaM2i3wxiZJ9YRLpCblFKKRDy0rot7l2ZTUJ+zA
         TK5VgtTNa58MPMS3q1nPhQ0ycRHH7S0fZ+bYqzZKvOUcHCTOWtIKR75rt911sOWDHyTI
         SmMqZWN9Ds4GPwmJvp+GLSvCWBku2VJMFKX+CTRt/nphA9+vLpzeI7D6qN5XPtxWucjs
         9WOjqLbtCGJQGhUOgNemYZz4zeppSZqCk9sMSoeocFvzx7pmhshc457pq01YNuqCYcJ0
         re/lhMVY6NuBJiFgLrG3728xk7ecSWeiWIiwdrA1I3bCukyt2JMbCK5oelR8IG5TmA2O
         tUGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MVTzChft;
       spf=pass (google.com: domain of kas@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kas@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755083156; x=1755687956; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CoqZNRmYxTj+QZOiT60U2IDXXsxH71/WPIp9yMqJ4hA=;
        b=K7vXSkYkTir+taVo2LMHgivRqHHDnZTWikrtnhrxM/2r0c9IUn6Fe90U0Y+SB99vbg
         +eyMU+FbHmV13cQHAmPA/P8SUCMig5R6ZMOxLy4CD36THpcrZaXCEwWzx/p7oFcW2YeL
         PlJUenRwL9WcvDvjnEbPvOtEIG6/lJmds78RHN3ALJBPeGUVTJZqsmNqJV+ZDSDRievu
         9bviunkH6lo+PIAXS3LzLnGvbdnTCddvozMAxyWs8pQC+TQR4k6tzt75YgioNMUVfHve
         2V9/YbeMS+drP4gjgmzyc8K1eQzYkE1ZK89ZPC1/yUufq+BPU8PqTqYEfIbspjlLD9jv
         zm6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755083156; x=1755687956;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CoqZNRmYxTj+QZOiT60U2IDXXsxH71/WPIp9yMqJ4hA=;
        b=YaVgRmehcEMCCzVUzft6fN3r1Fljope68bxAsNVdek4jVSiM95wF+2bi57003HHlks
         lbm6QN6n7oBYWFea8B6BJF1eGm3MBXOUhIyTeRIVa9KyCLsMKK3aizdSVDm0uqFNweM5
         6QT7zR4lDa1c3vY0bOezoM+rLq7uIk2MEOzGimk2TtQ+dUjjtlC3bRGifmezgCLoql1j
         fRUDaMEWJqcCavmzsR+j+NeDI/XHMljF50m+PJiV1P0IimyscNzfXNsVCBJtfrrPtpKE
         EQ7mypzZUalFwJzh7dZU3weJzm//AWNR6NWWGgGaeDNsOVun3E5I0b3dSATNvF4bO5wh
         UgKw==
X-Forwarded-Encrypted: i=2; AJvYcCX6F+MabNtKE0wOwKxOFC4rDwdTtRr5e39FXs3CGiooS/ID65NfO8oXJn1JBc1pBaXG27DupA==@lfdr.de
X-Gm-Message-State: AOJu0YwcLEoe25Klmi0QfvDS6BLOk6ouPye1Nure5QYFDmIa5XtBudXa
	TsRGHfBjexUPpBJDFFlxqAsaaygoRi/JoWfyP1bytlUiqaxeP4oxUqYS
X-Google-Smtp-Source: AGHT+IFwBeSLAFBtkxstGhvGNVx6LXfNIV+L4NMom3/zSRboO4Z/EOfxDpkahgjUbnTRJSV1/xS+/A==
X-Received: by 2002:a05:6214:ca3:b0:709:c827:4db3 with SMTP id 6a1803df08f44-709e89d3ed9mr35602866d6.51.1755083156413;
        Wed, 13 Aug 2025 04:05:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdxRQATp4XLWUMZlO0wkhEQav6o/OdlGUqBHBBh7dN2pQ==
Received: by 2002:a05:6214:4ec2:b0:709:ad61:7fb9 with SMTP id
 6a1803df08f44-709ad618986ls60031656d6.1.-pod-prod-04-us; Wed, 13 Aug 2025
 04:05:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtPN5rcjT0AxeZtFdYMYneNBlA/OzRu+aCwkkYeIh2jXdB34Tvrbfj/JoUx0gtZxrlZGmZuY36h84=@googlegroups.com
X-Received: by 2002:a05:6122:2526:b0:539:364d:f1b9 with SMTP id 71dfb90a1353d-53b0b46b00fmr741153e0c.1.1755083155573;
        Wed, 13 Aug 2025 04:05:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755083155; cv=none;
        d=google.com; s=arc-20240605;
        b=PS6eBvEvlfnQ7gQ4vAmkoR0nutBpINZi2oXlK6fT7drBzpJEdWNWxflPmg4ALjW2m8
         iVXLoLkELEi0+v/uOidmlKrwivvjU1poND/YcJejZLIH7ojk9uqT5/fZoCE1SPLaWTGq
         ouiFnfjbUXMrOE9xtwpEgMhkKz9HKcVOuUw58eu8VKutIcEruzmcsTpWxoRvM8NCaglZ
         niEPK1PVWxWqDYsjsPgtsWXavBff2gQigVYD4v6rEvfi6pV4Q0Uke0+QdP4xfKgKj0jR
         MR+UKEZbhH39DWWKfyHFafjTwWYlb/ilKBUEgh3y2vONseLCiHgOP1MkEnzU7BCQP0q8
         c1tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=hM+Slp2YEWSOnKVLukwoyPz7xqtb3tc2PHy5G90+KBA=;
        fh=VPyqErpNkF13D1oXsgHI8rKJNrG9mxsauybaErXOlMk=;
        b=Gl+HFp8dTuNnIJZlHh4eWISxj1MTQrEM3KQLSFFVAd5cmzYqf8O6+OGIu8eU3sp+Ae
         9AE466j04Uf2LeFrSsw8ASqTcLibH5fe33YGsrk0T8UL9vKkERqRt/YYaB7xBhj+1vCR
         7HvY0ifrLCNJnEYcm42vSPxZOwDVuoVZL7gYxx+fq7UM4ZfSg7I6QZTgchH1HNLvUCMj
         C/VmrjO3D/YZ4LfcuXIBSQx2+ShNsuXL/Z+KS1Zf8v4lvz8S64RVdZVX6InlRlcLfWrf
         0SzEh61H7AVCyLnF09jLkmIm6WQjMYuoNdKeKuHGOLLmHL/J0Csj/XMk949vkcFnNF0x
         K14Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MVTzChft;
       spf=pass (google.com: domain of kas@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kas@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b02e6ad6si637559e0c.5.2025.08.13.04.05.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 04:05:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of kas@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 445A145C02;
	Wed, 13 Aug 2025 11:05:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C651DC4CEF5;
	Wed, 13 Aug 2025 11:05:51 +0000 (UTC)
Received: from phl-compute-10.internal (phl-compute-10.internal [10.202.2.50])
	by mailfauth.phl.internal (Postfix) with ESMTP id C67FBF40066;
	Wed, 13 Aug 2025 07:05:50 -0400 (EDT)
Received: from phl-mailfrontend-02 ([10.202.2.163])
  by phl-compute-10.internal (MEProxy); Wed, 13 Aug 2025 07:05:50 -0400
X-ME-Sender: <xms:jnGcaIn1p1K9MU1fRyGWzjV0QaDIUTi1zfT2zv7WE8pQiJPkWaIniw>
    <xme:jnGcaDirxVSukN94gQyZs3OTr1Hv2zcp7-fY0tX4suwMW5O1Tc05PrOfPH8osxTk-
    DZ_Z53N-m5mWnXpi4M>
X-ME-Received: <xmr:jnGcaGiopsJBn_DNCn5MLY1IKyfdRiKLiB--lqw0M91wsxo3D_kQT-Rhkv4A>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdefgddufeektdegucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhepfffhvfevuffkfhggtggujgesthdtsfdttddtvdenucfhrhhomhepmfhirhihlhcu
    ufhhuhhtshgvmhgruhcuoehkrghssehkvghrnhgvlhdrohhrgheqnecuggftrfgrthhtvg
    hrnhepheeikeeuveduheevtddvffekhfeufefhvedtudehheektdfhtdehjeevleeuffeg
    necuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepkhhirh
    hilhhlodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdduieduudeivdeiheeh
    qddvkeeggeegjedvkedqkhgrsheppehkvghrnhgvlhdrohhrghesshhhuhhtvghmohhvrd
    hnrghmvgdpnhgspghrtghpthhtohepudejvddpmhhouggvpehsmhhtphhouhhtpdhrtghp
    thhtohepmhgrtghivghjrdifihgvtgiiohhrqdhrvghtmhgrnhesihhnthgvlhdrtghomh
    dprhgtphhtthhopehnrghthhgrnheskhgvrhhnvghlrdhorhhgpdhrtghpthhtoheprghr
    nhgusegrrhhnuggsrdguvgdprhgtphhtthhopegsrhhoohhnihgvsehkvghrnhgvlhdroh
    hrghdprhgtphhtthhopehlihgrmhdrhhhofihlvghtthesohhrrggtlhgvrdgtohhmpdhr
    tghpthhtohepuhhrvgiikhhisehgmhgrihhlrdgtohhmpdhrtghpthhtohepfihilhhlse
    hkvghrnhgvlhdrohhrghdprhgtphhtthhopehkrghlvghshhhsihhnghhhsehgohhoghhl
    vgdrtghomhdprhgtphhtthhopehrphhptheskhgvrhhnvghlrdhorhhg
X-ME-Proxy: <xmx:jnGcaBXUyqFUPMfew4Z5OWLnQYxm0ELK4l60pGN0JZUamPnkFvEXsg>
    <xmx:jnGcaJyWZOPfBrlyFhEBMM7Izc5tbQBmTrmwEKpAcSs1ax97Lv_30g>
    <xmx:jnGcaCZ1SA6oP89KZrD-pcDTmqZEteJLkTO4D3FxGwNjGKkQTMcQ7w>
    <xmx:jnGcaPdCHDN46QC0c0e8jPbv5rGJ_dGyrlROhniLqDa5XRLH8zB5wA>
    <xmx:jnGcaK8yJwFwK7u2RhqfCBJLM8kFptKWxfpX2bimCMLEY2zof4O9jhyL>
Feedback-ID: i10464835:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 13 Aug 2025 07:05:49 -0400 (EDT)
Date: Wed, 13 Aug 2025 12:05:47 +0100
From: "'Kiryl Shutsemau' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: nathan@kernel.org, arnd@arndb.de, broonie@kernel.org,
 	Liam.Howlett@oracle.com, urezki@gmail.com, will@kernel.org,
 kaleshsingh@google.com, 	rppt@kernel.org, leitao@debian.org,
 coxu@redhat.com, surenb@google.com, 	akpm@linux-foundation.org,
 luto@kernel.org, jpoimboe@kernel.org, changyuanl@google.com,
 	hpa@zytor.com, dvyukov@google.com, corbet@lwn.net,
 vincenzo.frascino@arm.com, 	smostafa@google.com,
 nick.desaulniers+lkml@gmail.com, morbo@google.com, 	andreyknvl@gmail.com,
 alexander.shishkin@linux.intel.com, thiago.bauermann@linaro.org,
 	catalin.marinas@arm.com, ryabinin.a.a@gmail.com, jan.kiszka@siemens.com,
 jbohac@suse.cz, 	dan.j.williams@intel.com, joel.granados@kernel.org,
 baohua@kernel.org, 	kevin.brodsky@arm.com, nicolas.schier@linux.dev,
 pcc@google.com, 	andriy.shevchenko@linux.intel.com, wei.liu@kernel.org,
 bp@alien8.de, ada.coupriediaz@arm.com, 	xin@zytor.com,
 pankaj.gupta@amd.com, vbabka@suse.cz, glider@google.com,
 	jgross@suse.com, kees@kernel.org, jhubbard@nvidia.com,
 joey.gouly@arm.com, 	ardb@kernel.org, thuth@redhat.com,
 pasha.tatashin@soleen.com, 	kristina.martsenko@arm.com,
 bigeasy@linutronix.de, lorenzo.stoakes@oracle.com,
 	jason.andryuk@amd.com, david@redhat.com, graf@amazon.com,
 wangkefeng.wang@huawei.com, 	ziy@nvidia.com, mark.rutland@arm.com,
 dave.hansen@linux.intel.com, 	samuel.holland@sifive.com,
 kbingham@kernel.org, trintaeoitogc@gmail.com,
 	scott@os.amperecomputing.com, justinstitt@google.com,
 kuan-ying.lee@canonical.com, 	maz@kernel.org, tglx@linutronix.de,
 samitolvanen@google.com, mhocko@suse.com,
 	nunodasneves@linux.microsoft.com, brgerst@gmail.com,
 willy@infradead.org, ubizjak@gmail.com, 	peterz@infradead.org,
 mingo@redhat.com, sohil.mehta@intel.com, linux-mm@kvack.org,
 	linux-kbuild@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 x86@kernel.org, 	llvm@lists.linux.dev, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, 	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 00/18] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <ebl5meuoksen5yzpzbc5lcafcgzy3esfq7c47puz4tefeskkos@f5wzzg4fjrfz>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <mt3agowg6ghwhvcjqfgqgua3m3al566ewmvwvqkkenxfkbslhq@eun5r3quvcqq>
 <rzlimi2nh4balb2zdf7cb75adoh2fb33vfpsirdtrteauhcdjm@jtzfh4zjuwgl>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <rzlimi2nh4balb2zdf7cb75adoh2fb33vfpsirdtrteauhcdjm@jtzfh4zjuwgl>
X-Original-Sender: kas@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MVTzChft;       spf=pass
 (google.com: domain of kas@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kas@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kiryl Shutsemau <kas@kernel.org>
Reply-To: Kiryl Shutsemau <kas@kernel.org>
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

On Wed, Aug 13, 2025 at 12:39:35PM +0200, Maciej Wieczor-Retman wrote:
> On 2025-08-13 at 09:16:29 +0100, Kiryl Shutsemau wrote:
> >On Tue, Aug 12, 2025 at 03:23:36PM +0200, Maciej Wieczor-Retman wrote:
> >> Compilation time comparison (10 cores):
> >> * 7:27 for clean kernel
> >> * 8:21/7:44 for generic KASAN (inline/outline)
> >> * 8:20/7:41 for tag-based KASAN (inline/outline)
> >
> >It is not clear if it is compilation time of a kernel with different
> >config options or compilation time of the same kernel running on machine
> >with different kernels (KASAN-off/KASAN-generic/KASAN-tagged).
> 
> It's the first one, I'll reword this accordingly.
> 
> When you said a while ago this would be a good thing to measure, did you mean
> the first or the second thing? I thought you meant the first one but now I have
> doubts.

I meant the second. We want to know how slow is it to run a workload
under kernel with KASAN enabled.

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ebl5meuoksen5yzpzbc5lcafcgzy3esfq7c47puz4tefeskkos%40f5wzzg4fjrfz.
