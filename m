Return-Path: <kasan-dev+bncBAABBZMT6HCAMGQEYDURTCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2058EB243F2
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 10:16:39 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4af18aa7af8sf169298781cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 01:16:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755072998; cv=pass;
        d=google.com; s=arc-20240605;
        b=BswXVMbDUWbKNQp+LV6HgePyr0EvQPMp0p9y5NUgQnx4X2ISnwAXulSqCjnmeEBOAA
         uvllGvpM89Lx4lDS0NWaUUkW0F3Qy44nHFNGWiL1DIlIzWsb3XR0v9VJVSbu2GpRCVtH
         Y8w/dqSHm19kooIZBSduOUN/ltdshJj0lKpz6IUO6kxTzXeUz/W/7JQaGWFmNFOAC6ff
         5RF0UtuiYPecgwRUNQDLM0MWpKDOHg8V03Xx4MRjHJRFOOfLTg20g3tDv6GYt26kz3i+
         JNHWeKq8c8CY2AtUw6Vu9NF79wV2DchkREZicQwofD35dOOwChPHDi+XZR/hV6RaFyB9
         7esw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:dkim-signature;
        bh=5FAEuHfkQ4HR0eBVzi8NIoe4uDIl5hYWFOCZNd62Hs4=;
        fh=GEXruJgSWwerc8sIbXHUlAsP0sHYDRDggXer79l2/qQ=;
        b=eg13D/ZQRcE5Kmr0crbmIaMxiYRhuDAk9B3Q3/tKMttEISgBSLcJln+5LU+O/cBXd7
         hQZsroS9PhDUvFiINtdxShtFypqHE8zK8ZTO7FQWBErLeTsNim02EwnEKM3qZ9fecCR5
         NH0ixOoxrTeAFL6VsTYwJ6728JJJ1PiKyVdqN+TIbUSJ4nPIDm8F32qlxA7nbFAH+kJ/
         MFXVUhQT11W8leR++9l/k32KUIs+KnL2nlaIF/cAlZB2I4K3qENN6Jlhmd2S+kcpoHTu
         AA9s93retuDrjoWsiRdGC9SpCpw1QvfejkuNqjjT4Ih3KF2FZzZeVBpsFb9yUE4NTN8i
         XwVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ORDi55VV;
       spf=pass (google.com: domain of kas@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kas@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755072998; x=1755677798; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5FAEuHfkQ4HR0eBVzi8NIoe4uDIl5hYWFOCZNd62Hs4=;
        b=KQ4oKp1Y4bIDmI9Ck0Vrx3phdKu/AAaoUGPd/faPBbhBuKFUbXV0cs4PiJHYgWsITY
         DN3NZ4kvE9b38f1YleibYa4+Z2yQGEKNCAub/VSKoLZmj92WNhELcs0NYEjsn6X9+ieg
         QKNz3f1bYTdxrt6zvAF2P2MItqdEJ6Dkz3K6XScIIBJmCeXLJbrwvqHkurFpzUR6+ecV
         wSocCkMavuj85zd+yoEFxfav8ke+miK8MGmKgYY+SyQa9xwkmYHNwK7HlDbpHmP7ZBsO
         84QfmwGid7D5fGlv3R7NHEzQO1yCI0W2R6EJEGNG4/KlS/QrmzS1DMrUqF5BSfnDV7F0
         +9gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755072998; x=1755677798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5FAEuHfkQ4HR0eBVzi8NIoe4uDIl5hYWFOCZNd62Hs4=;
        b=Y9dAs3b4/h7kpHHI+0RipxQdmEgoIc7mQRkK6+YTn4dcLh4DePopKPIttX4djyqvzu
         ijlAfRUmOxbar7s2N2MHz14ojYkjWw/XGYta184S5tbKuebyQFzrJoY5mCrVJnSdQRv2
         ue4quMe01/71xUoUNMnKOSh8oovruhJN1s4KmxuXWYTF86rhFTdLYWaWPzuRFXzB67JH
         8VADPHrTrMT5MJsHq6bAy59yHPtVxIdrx3gVrl10VZJicVCJVDOHP2whj3f4xpUNukwn
         kepa/YBBsdRGjoehbHTlTgxg3yMtoSy3LJyJDNTE9vSKHejo3AaNhmVdcAmBTB46j5a9
         oNpA==
X-Forwarded-Encrypted: i=2; AJvYcCWs/XavmJ47SJTxVKg5z3TJgPmxpr8dsUOzu8tSmBtDrE7DpfFn3SUI953+i5dR+OcpQmG9bA==@lfdr.de
X-Gm-Message-State: AOJu0YxQ4HDUXEyreWYfG2OSMZ8r5dwaa5ZXc3N6JNfx8ALV/MXA4+Uy
	bCgL4G2DTJc22GDUrwyfLYNYusyNtjKh2JrnWZOgpXuKKpPeHpu7RM3c
X-Google-Smtp-Source: AGHT+IEA7b+lYJqMR9qdkR01JJ74pb+Ox2VaLfCGOIgtiqH8uUZqHT+eP64Cdqv1GELfzjwRfupZ2w==
X-Received: by 2002:ac8:7e96:0:b0:4b0:6965:dd97 with SMTP id d75a77b69052e-4b0fc89360dmr20659721cf.44.1755072997709;
        Wed, 13 Aug 2025 01:16:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdzJEgAnSuAebOHe6tVfCeJN17zrW0tVmVclA0IAAItqg==
Received: by 2002:ac8:7d82:0:b0:4b0:9935:4645 with SMTP id d75a77b69052e-4b0a0484a4als84847321cf.0.-pod-prod-05-us;
 Wed, 13 Aug 2025 01:16:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDWaN42QUaJf0piblRrqACDio9YWMJsdqkXjRFCZOHOWUnF2du2vOn8eMzaeCI+vrbNKxHwktpYjo=@googlegroups.com
X-Received: by 2002:a05:620a:2609:b0:7e6:440f:50b5 with SMTP id af79cd13be357-7e8652242d6mr312382685a.11.1755072997019;
        Wed, 13 Aug 2025 01:16:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755072997; cv=none;
        d=google.com; s=arc-20240605;
        b=GujXfJA31+8cAp6V2pXlUMHVDLVVy+9MEXOgG5k9scy7RVoKKAxoc4E7kYFKdHpzYZ
         BPQxG5N8M7UC7NgOlTfleZ7bpdpuvSQwrjiL0cPFmDJvXYfbjlD6j3moUVSwBxYPap/7
         TNmOUEERQdNendaxeQAPFleYD7Bg38sEvyrnxbel+bcCmYyekmFqM/hGMzPn//i/M991
         YBRoJ9nzY2Lo7PNAryUQrHWm9YP8kIUYxrYIlm/tiP4d9KAwmjOTuSdPTHO+4hjg5EIo
         svnzR/flWFnnbUDt+mIvi603as5aobDXFO1fP5zfO9yRBgR19kFx1X7lBH0iVXVZBaXP
         IZFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=B+u0wmRt6PJvGdFQtCZAI1oS3UKAenlpPK7AYmnU7pY=;
        fh=VPyqErpNkF13D1oXsgHI8rKJNrG9mxsauybaErXOlMk=;
        b=Y1Ceh/yx19hgUbZKTmVuSc9+MP3OHM5SP5raX+eo6UziT2lhVFK69E2XbNDRbPDrRP
         43g9dulJRyq22s8fsSZ1IeSOKpYZimOymUre91un3KyQ3+UMN4Z+QyA7rDlJ72wl19PI
         rGKv0dq9v0yeDZW71OUmoAhtd4d/o5SBOKl8jeBgDrvQ8P5892GGZGVZZ8JDSTWZPXZo
         vsCJGG2B94aYORHm/MdZtMd9peFVVj2B51gS9JxA/IGPPCX/b/LNVLU0U3KRJUUmiQBw
         wrxucLXTz71kMWwyAQv/HrvaYbb+ULhytCHxvbMlxVEyfacPPeZFJxqv8MyEzI1A1AVu
         LTcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ORDi55VV;
       spf=pass (google.com: domain of kas@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kas@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e817288223si60649785a.5.2025.08.13.01.16.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 01:16:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of kas@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 28375601D3;
	Wed, 13 Aug 2025 08:16:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9CAB9C4CEF6;
	Wed, 13 Aug 2025 08:16:33 +0000 (UTC)
Received: from phl-compute-06.internal (phl-compute-06.internal [10.202.2.46])
	by mailfauth.phl.internal (Postfix) with ESMTP id B8421F40067;
	Wed, 13 Aug 2025 04:16:32 -0400 (EDT)
Received: from phl-mailfrontend-01 ([10.202.2.162])
  by phl-compute-06.internal (MEProxy); Wed, 13 Aug 2025 04:16:32 -0400
X-ME-Sender: <xms:4EmcaJ9bYlqpENhWu9ZM3b1rkWpwlG0ejAGfN5hl5gpmWDsXJZb2dg>
    <xme:4EmcaENOzt1tVLSLCMXrultW8L17ql7E4FM4HK4IpxV0IwbEtdp1obf0VUusmmMyw
    IcwitAMdbROBw4JosY>
X-ME-Received: <xmr:4EmcaFQ0k6CLoJc_wiBIEX78Ie8QrsLWwJlSGdc_NpJQrnqaDtOjJI6MFkkG>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdefgddufeejjeduucetufdoteggodetrf
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
X-ME-Proxy: <xmx:4EmcaG8rQsE8nkO8Pw7BXFUXXd-RiXJNyqApIZXatEwUdlY2ztWfjA>
    <xmx:4EmcaP1k2sWKIPsVnixXMBMnZq2BC4N6nxNUox2x8df5vJ19bCsHAA>
    <xmx:4EmcaIKL7gUAWTyNuo8HT5jw93fJosAdbDIZuVFUt4IZ5EQd4puIQA>
    <xmx:4EmcaN73ABzTnA_tXNVpp2lcwvZwZx0hbVCFteVB1zox2VpbNSuCPA>
    <xmx:4EmcaEjpfrJQy1TacPbbA7uC_HvJWGEvLn3o1pPc_tSJJSAJSSn_V_gA>
Feedback-ID: i10464835:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 13 Aug 2025 04:16:31 -0400 (EDT)
Date: Wed, 13 Aug 2025 09:16:29 +0100
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
Message-ID: <mt3agowg6ghwhvcjqfgqgua3m3al566ewmvwvqkkenxfkbslhq@eun5r3quvcqq>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
X-Original-Sender: kas@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ORDi55VV;       spf=pass
 (google.com: domain of kas@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kas@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Tue, Aug 12, 2025 at 03:23:36PM +0200, Maciej Wieczor-Retman wrote:
> Compilation time comparison (10 cores):
> * 7:27 for clean kernel
> * 8:21/7:44 for generic KASAN (inline/outline)
> * 8:20/7:41 for tag-based KASAN (inline/outline)

It is not clear if it is compilation time of a kernel with different
config options or compilation time of the same kernel running on machine
with different kernels (KASAN-off/KASAN-generic/KASAN-tagged).

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/mt3agowg6ghwhvcjqfgqgua3m3al566ewmvwvqkkenxfkbslhq%40eun5r3quvcqq.
