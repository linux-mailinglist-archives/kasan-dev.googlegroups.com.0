Return-Path: <kasan-dev+bncBCP4ZTXNRIFBB57J6LCQMGQE2KY4Y2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D031EB477FC
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Sep 2025 00:26:00 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45de13167aasf3990385e9.1
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 15:26:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757197560; cv=pass;
        d=google.com; s=arc-20240605;
        b=eRxMknikVSC0E3vd9J/z3peQQ1GembSlmRVdFm+xO8UmQ/O3ULJZltcpsja8lD4de2
         Z2pDUKdD+K9cLUaKknVzWiZepiXqcWVZeT53i/NZLazEYFq9Q+j/yWKwVGIvcqynQe0H
         xEAT8CifD2FdgJTq7hncuWnxk3Eet+gcuyUHMmis1B+hGTjNGRSDJDqgq2kB2GFqpgG/
         InYjYB+0j0kNXNeivj3bm86XuRdB9StQ7kPLfnzH2ZCtK+aW/x0MFtXhWarT5EWfjuqL
         M7B9PV5+yl1e8t3CTnTx5O+hVFxRk78AHlYG+x7ia9Z/h4k/MRkXI2f+eCG+Bgjs02G8
         HJbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ch+zr7xocihl3/SsHpXOQz2qpv0tn0EPwfvD0ERRId8=;
        fh=w1jGiUxO0WXlECAWfD/ipHnEldTjQAb3pRcXM8eXYCs=;
        b=ZKMKFs+D0WOVXLcl+Lu/aFjRob7wOWRxmcGPmOk9hh2UBl/mW3a4526Gn6vwuwa6SB
         v1ln5w8vhr3r5JWyAUdk1jGBIaEgHI9EUWkAHceb6rLPp9e+mmwjvIHIF6D1bADqbodZ
         GBRIb3X+11IA3CpTp3sXJk1W0gAqnLT5Jnm5b/IvJEL8mWzX2CV5v5xULvcY+bEtKWKa
         h9LyAFb6DyafS4EAPW3+QS5xCm2a6NLSBRfby0/L9XT5E8KlvDYkQqxxPS5nKF3Y6nLZ
         pF9aoAFRBt06v0YgP0IkUVm0HFxMGdkP7PfnYqKsKcNBTdmkJLndXDmhVTC8jzgZV/bP
         WWMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=WD3MTiEV;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757197560; x=1757802360; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ch+zr7xocihl3/SsHpXOQz2qpv0tn0EPwfvD0ERRId8=;
        b=jDB9Y3arohKW7eoND7dRT+OmAN7M1C8/A2gosP27LoQgNJ5yf9cZkSlpZnTs0WKpBd
         KSSxYsbc++u/EtpxcEPy9meT868ow9xGImiYJqYlCLWgyTneRETKW3581gAlLqWOvd/i
         7wtb48agmSjuxXOY6NT8NEpKIsVNXIFoFSrMmv0eXF8tp5gAEf8WOtyG69IYU1STZNqX
         B9rEyvNUVvKfqxI2zmwXFuXNHPVGYpW7+LA/ghLjXfoh+eGoIOT8kb+CdFHkV8HMBKpU
         27/UB3QCszundqFpOTM4X5y+NRjbWzzxE2Vwk+09gYyY5AO0c+SfITT5TU3GUy42lq3i
         T5Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757197560; x=1757802360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ch+zr7xocihl3/SsHpXOQz2qpv0tn0EPwfvD0ERRId8=;
        b=NNy7ZbGJOoliqtBr/11arX/GDRZ4hvSCiDB2/tvAyn7Z+U2jslvMbjhVRLpBLhiB4+
         E5l8C9QJkiqr3YMPCtFRZ+DOZRpejaejx2GMTCEz6S5ferMmhtGe9TzlTIHivIih3w4r
         cHtkj/jLo2bCz1XUPVrjECCEE/U0A1lwvrlSKxe3YH1MommPf0efWYHN5LP66YH/tsEP
         4jivrS1h4j8Sz0ahOZ3IxYH0i7Ys+kHJypyk55k6FcjLwZsHTkc7DQftIZbj+0V+bPsa
         19MZ1+1IAfuaibvgdv++f/ozt4eTY1H1IdgfeeSR1IhNuSI1GW3GP7E62AyV0NK9j931
         GD2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXJjoSXfFR0dXFPdDCOe6JPT6z/Ba6zzcodxMZ2JApFsOsorqP83Nw1JOM4sbRRwjlF9hU5w==@lfdr.de
X-Gm-Message-State: AOJu0YywDTxDweTRCd0twNcfzl4fpK4fuJsPM7PbzcgGQJFZFsVcmWzK
	ks+1yOciCH5Vr52XMzgJg1y61z7/nM5wDOB8/kImXuTc9IX+z5fmUYKe
X-Google-Smtp-Source: AGHT+IExlnHn85g59tZcN/ULcYbQ7sFVlSfMBaHMfX/ed/4k/asvQxrIjvApNb9I0+19UGkEirEX/w==
X-Received: by 2002:a05:6000:1a8d:b0:3e4:5717:3684 with SMTP id ffacd0b85a97d-3e6462581a2mr2671278f8f.40.1757197559874;
        Sat, 06 Sep 2025 15:25:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5cRmmWeHDfxtniGQsMD7gGVRYA7Chm49Lz3NJr5LMOKA==
Received: by 2002:a05:6000:4308:b0:3d7:a150:6efd with SMTP id
 ffacd0b85a97d-3e3ae77d5d4ls1117911f8f.0.-pod-prod-05-eu; Sat, 06 Sep 2025
 15:25:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnKzWNEV2cGw3lJ/N+pvCmxNFjSUJfTqgCAHzSyddkTn/5rFhMSF6Jt3uR3WUNPkhIi4W+6d6LPNo=@googlegroups.com
X-Received: by 2002:a05:6000:2508:b0:3e1:addf:58f4 with SMTP id ffacd0b85a97d-3e64cd57780mr1921924f8f.57.1757197556622;
        Sat, 06 Sep 2025 15:25:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757197556; cv=none;
        d=google.com; s=arc-20240605;
        b=Ye7USXObBawmPevhavkRJlmmxHbu+3MRSJA06g6FZUcdE32o3cqnSCZeuCnMbPOJYf
         16VDFje8ap2ra7V5HuHVCf0pOf+pT9lH4GdmTkW0Q4dK6XON619kX1i3pifM3+GzGXQC
         yl8T+RZvtvt/2n6NnVTBx3GDP/v4kGNC1VouNBmd3j3ZR1FkdAXiYqDwkT3MUAnWxcVe
         cownGwDXMEtnnl1A+qkKe1QzONepsqE/5iU/h0aEFbjxK4DbKeD1RY1ubyaNdegRt0/A
         gZ0We/041aI5lMwviari9iU5X/GqX6NKUAfnJk15ODOv2tnt3OZx/oqhux5D0rZ3LwNg
         2f3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+xt7zC4IHQ+iWsE/ZnrUTR3tvhZamW/XzIhStal409Q=;
        fh=HweiDJRgY0ZHuEWi3GC/bRt0OpcTcuu0QG0mwGKdjaQ=;
        b=BitL4SOfBij1RwJWtjxRhc/PYWkydNDuMMF6M4mjIQBo6sAbUqej8mz4+0N7+55fxA
         SQIn/3b1Bt5Ll+4HX7TIRl+XOFnLTc1okng6hjx00exa6G0UGPiQIvuyAJOdeDwwgoGa
         iKlIXQpE0RUREyO0atilVHDagp3kQnXm/66XcLg3SY0iIrIEwKnjm/PEMJYs5T+2HQxH
         wLbddFAvWCV0P0kFNgEv/UCml7O/k10u5PkPT7KeTO0ep2bBzJMohSmAjj5TaCla2j5K
         D3oww74VNJpxIErvIwFE23crukhoOOCOL3Gs4OQcuryDdEINrEsMwupSr7zz4QveiURk
         Na8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=WD3MTiEV;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dd9992521si864025e9.0.2025.09.06.15.25.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Sep 2025 15:25:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 5D1C440E0174;
	Sat,  6 Sep 2025 22:25:55 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id dk2lFWfXvPj3; Sat,  6 Sep 2025 22:25:51 +0000 (UTC)
Received: from zn.tnic (p5de8ed27.dip0.t-ipconnect.de [93.232.237.39])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with UTF8SMTPSA id AA3B540E00DD;
	Sat,  6 Sep 2025 22:24:29 +0000 (UTC)
Date: Sun, 7 Sep 2025 00:24:20 +0200
From: Borislav Petkov <bp@alien8.de>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com,
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
	trintaeoitogc@gmail.com, axelrasmussen@google.com,
	yuanchu@google.com, joey.gouly@arm.com, samitolvanen@google.com,
	joel.granados@kernel.org, graf@amazon.com,
	vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org,
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com,
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz,
	kaleshsingh@google.com, justinstitt@google.com,
	catalin.marinas@arm.com, alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com, dave.hansen@linux.intel.com,
	corbet@lwn.net, xin@zytor.com, dvyukov@google.com,
	tglx@linutronix.de, scott@os.amperecomputing.com,
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org,
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org,
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com,
	mhocko@suse.com, ada.coupriediaz@arm.com, hpa@zytor.com,
	leitao@debian.org, peterz@infradead.org, wangkefeng.wang@huawei.com,
	surenb@google.com, ziy@nvidia.com, smostafa@google.com,
	ryabinin.a.a@gmail.com, ubizjak@gmail.com, jbohac@suse.cz,
	broonie@kernel.org, akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com, rppt@kernel.org, pcc@google.com,
	jan.kiszka@siemens.com, nicolas.schier@linux.dev, will@kernel.org,
	andreyknvl@gmail.com, jhubbard@nvidia.com, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v5 11/19] x86: LAM initialization
Message-ID: <20250906222420.GBaLy0lL5lHcVlYU0C@fat_crate.local>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <ffd8c5ee9bfc5acbf068a01ef45d3bf506c191a3.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ffd8c5ee9bfc5acbf068a01ef45d3bf506c191a3.1756151769.git.maciej.wieczor-retman@intel.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=WD3MTiEV;       spf=pass
 (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Mon, Aug 25, 2025 at 10:24:36PM +0200, Maciej Wieczor-Retman wrote:
> diff --git a/arch/x86/mm/init.c b/arch/x86/mm/init.c
> index bb57e93b4caf..756bd96c3b8b 100644
> --- a/arch/x86/mm/init.c
> +++ b/arch/x86/mm/init.c
> @@ -763,6 +763,9 @@ void __init init_mem_mapping(void)
>  	probe_page_size_mask();
>  	setup_pcid();
>  
> +	if (boot_cpu_has(X86_FEATURE_LAM) && IS_ENABLED(CONFIG_KASAN_SW_TAGS))

cpu_feature_enabled()

> +		cr4_set_bits_and_update_boot(X86_CR4_LAM_SUP);
> +
>  #ifdef CONFIG_X86_64
>  	end = max_pfn << PAGE_SHIFT;
>  #else
> -- 

Also, for all your patches' subjects and text:

Pls read

https://www.kernel.org/doc/html/latest/process/maintainer-tip.html#patch-subject
https://www.kernel.org/doc/html/latest/process/maintainer-tip.html#changelog

and fixup.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250906222420.GBaLy0lL5lHcVlYU0C%40fat_crate.local.
