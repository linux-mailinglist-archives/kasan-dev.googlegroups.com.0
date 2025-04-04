Return-Path: <kasan-dev+bncBD22BAF5REGBBRU6YC7QMGQESJABZQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 759B0A7C1E3
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 18:56:40 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-7c5d608e703sf366387185a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 09:56:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743785799; cv=pass;
        d=google.com; s=arc-20240605;
        b=OToFsyv0zpxDFtpTBqEytA/z+JhjPuNf8e/xTJpCBe8+/xRnzOiNb+BGuxmgU9GOW+
         d0qmgnQZlul5VePsNId5CPHHpnzpmCNjyn9BDs/xJdAPQQsGwg843o/+ZiS4ePyNEGNA
         145nwO0JPfdDf6dHB7ta6WRy/8xdxJByQKlEo3HDAwoBSNcEid+JKE9ZlzAxNjDrsFrg
         19KJeJGNcNEYLhMAnWVejo3Pmg2BFGnlK4Ctx32eghExa0+6xRjurizKPUOZXVgBhaKw
         LgKygSKVOqHhFuBSEJU/JKTJMTqpqYMCZxlfqzWNcgR7pK8RvXQRg7KRdRVt58QRm2IZ
         qxdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=zMDbiZXYbCbGeW8nMPETteNEMBohZYUwMgXPuBLSow8=;
        fh=80FE/0hrKshD1S50PvqT+UnRZE/AOPNWYL0CJB2qmcg=;
        b=S0myYPDdExa99EZIBFsO8dYFQGk4TXEEPLQtr7gIJDzYBZtpE031omWp8fXUi4ZlyA
         go2VK/HEqshBJnIkoAXbKibhyePRSecTPbyc4WS+DbTqKcXmAP5eGkc5TGrJEcEj6d1p
         c7PTUISBHdQeJrptD5E1xFjvjI0OZxvokdkcPVigdui/yZNKJXsPmMlcMlFY3OV2hUln
         KsKwjfrx9mg7nbf+LFx3hrPLuhNIxzaR3kqA8QAN5ANVuR7TyWTOWAjvQ0SgtoX7PzwF
         3tCiFV/0OaNlVHDtFboKaVapdbVzQpxooaayerWIXhJNEqTfltg6ETadMI0/kTOsoprP
         tpxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KYgTyC9y;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743785799; x=1744390599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zMDbiZXYbCbGeW8nMPETteNEMBohZYUwMgXPuBLSow8=;
        b=dqGcdlknI+/blhp/kky/Z57XJJmlePjoIkDVJ3pnLmsSimxmaYeCrNVyMqLTNIMPYZ
         5zlB3UncbxidyweIdVPxr0YJ6Zec6pxZHSbSsed5Sc7eFssLcWIYSVBu7Zn9q5X21DCY
         4J5saHXzlpbcZ/UuyhKCtHLMsDugcmfu9iH3l55x9AYS4+VcSpuFtMPCLDW4lae9xOPC
         rgXRYG1jcxaoaUrovJ5yDHcdGkAzVHUGJvX3880lTkuC1SEls84TUHlYz2MnbzOdl2Uk
         K9m063jS7r9MJ9DwxfoG088nSXGW01epXrBcIDTNKShcD7WtSIDDav+zAZaakxhIylLM
         gYPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743785799; x=1744390599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zMDbiZXYbCbGeW8nMPETteNEMBohZYUwMgXPuBLSow8=;
        b=lm/DbY4rqpTlYHGHaKzAYXJ1JjBT6Zgm7Mj9EcDC+MLrsaVec81A5uR6mVvyNl2McQ
         JCezxV6ZlBRZemcyDCProoHPVd1Yy7A6O+Toz+vDuOT4qgNld5pW9YY1XMJRkooCnMiU
         ou9mk+mQPpYeDfUddaPKnfccsAspSyss6/oLP29pp0S9Qe+ywIbT6NAxlpIAEzOwhlFR
         2D/RDynVWsrqK5Qjz4hNKa/XZoDTVxgsHofv7gxrhHPI2ifTkEb4xDcEMvwM3tfw/TA9
         ELHfZFwHtKbcxpTMhN2hoWbwrPoHBMAmN441bvB37AB+31BXJfawx4a9wKHI8lPb6pj8
         sF4w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWtESsi0GZnvYe8ElBkje3no+KB0s6iX1gbECSA+NjuGPJS6DMT/7+5dmrQsV9Ls0EPUdVT3A==@lfdr.de
X-Gm-Message-State: AOJu0Yy1gcpmjD/TM6R3gEGVBfKdWQBNorZaX3Ht9Jx70Udm2UqtjXu6
	PUaC18Gd6paTGUVkEfVUFKVTXQNutByANOYNpsvpLqu2Ehy2EiZU
X-Google-Smtp-Source: AGHT+IECMi4EWygx6wMJxbGe8MVz07aonmwFiLk7T1k7ayW1kBB5ludfozafam5GpCAg3pPale4DVw==
X-Received: by 2002:a05:620a:319f:b0:7c5:642f:b22c with SMTP id af79cd13be357-7c774d32c7emr535656385a.20.1743785799082;
        Fri, 04 Apr 2025 09:56:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ1RD/gfFutm3miQUZ0NEFPoSrdJt9s0U5WTIYxLhAZgg==
Received: by 2002:a05:622a:27cc:b0:476:7bf7:255e with SMTP id
 d75a77b69052e-4791636bf01ls14849361cf.1.-pod-prod-05-us; Fri, 04 Apr 2025
 09:56:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYvRJbBKgcTG8/yWClxWY+sZU1IqtNzFii5G9ZZtWXni2l7JCUhmBgV4d/J8gtSFKrIbFtA9RKkMc=@googlegroups.com
X-Received: by 2002:a05:622a:cf:b0:476:afd2:5b5c with SMTP id d75a77b69052e-4792494c0c8mr67287991cf.30.1743785798132;
        Fri, 04 Apr 2025 09:56:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743785798; cv=none;
        d=google.com; s=arc-20240605;
        b=flhEnFNYoQ1b+DRnrYgTYCnea3bKmyWFRNWqNGWQ+ntC0SCTP88PVsSubQMpa/GeSc
         6Z4jDlm0hw7K/ezhN67I4CGqFMbrxI72DrN9sPon2fieK8APpIRsxVrU3kx0CYyte6HU
         E2ot//YMjntk+rBJiXMAutbeE2EonQZPelwhTe1dpT6uyzAI8lQnHZn9XBL3FJkCvXew
         M28TRjRqWoE2tfVje7q85U8h/qC6+KloJJJ0uP55uDjFnX9I2B1bCGSAJOZoS22Y9709
         Wii0jNrmLXmlSkCIRrosHt4gj0uyt/gCkFdb0ur59RZYXoO3YTKGJT30cWbL4dXJ9GVt
         5JPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ZECnDiub07zAGiJebytNOBSlRftv//2dV9FqWXMpaB8=;
        fh=qAclqxczifa7kqZeY+RB5PN2iG3DrlxE7ZoinyFrUhQ=;
        b=NqN/oQ2RXVtPy4z4rQrnTPNZ5V73tVHFeyJCpL0WgBgxjuuCpvuUGaPm8aKWVzo2Nm
         6Ld+tIdCtNcG24pElB/XFg5yIjfDorLp+ZUkVTVlJnAyLz/tFy9gBPS7cpSQA1YRrAJ2
         U+imbS0IeEzeKq5AtiKu7vUnheipj7vdCzEnO35jMIru7/WzCTh3SDz5CVYEDFImwNLr
         Ji/KduQCp7Y98rpSuBUFkRUZYwUHdbJ/AtQR3O/STJzHlHsguqd3PZnwGomCuI2zltZU
         H5HAALtwxth/R64YkOCcmV4AWmRNn5v/JzLnk92RPmtvxgid1Xpzl2oqDcqJYWb51Z5z
         XoYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KYgTyC9y;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4791b06c211si1837281cf.2.2025.04.04.09.56.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 09:56:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: Gmk00qQCRDiV85Cn+RljMg==
X-CSE-MsgGUID: IwzANdlBTZOXYD54a210PA==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="47944689"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="47944689"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 09:56:36 -0700
X-CSE-ConnectionGUID: Y7QpnuiMSQu9Veya9py4Qg==
X-CSE-MsgGUID: 5LEvsRX7R6CbR5uFxiPhsQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="127875138"
Received: from daliomra-mobl3.amr.corp.intel.com (HELO [10.124.223.29]) ([10.124.223.29])
  by orviesa007-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 09:56:33 -0700
Message-ID: <c4971a5e-1c17-4daf-8af4-804d07902fe4@intel.com>
Date: Fri, 4 Apr 2025 09:56:31 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 06/14] x86: Physical address comparisons in
 fill_p*d/pte
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, hpa@zytor.com,
 hch@infradead.org, nick.desaulniers+lkml@gmail.com,
 kuan-ying.lee@canonical.com, masahiroy@kernel.org,
 samuel.holland@sifive.com, mingo@redhat.com, corbet@lwn.net,
 ryabinin.a.a@gmail.com, guoweikang.kernel@gmail.com, jpoimboe@kernel.org,
 ardb@kernel.org, vincenzo.frascino@arm.com, glider@google.com,
 kirill.shutemov@linux.intel.com, apopple@nvidia.com,
 samitolvanen@google.com, kaleshsingh@google.com, jgross@suse.com,
 andreyknvl@gmail.com, scott@os.amperecomputing.com, tony.luck@intel.com,
 dvyukov@google.com, pasha.tatashin@soleen.com, ziy@nvidia.com,
 broonie@kernel.org, gatlin.newhouse@gmail.com, jackmanb@google.com,
 wangkefeng.wang@huawei.com, thiago.bauermann@linaro.org, tglx@linutronix.de,
 kees@kernel.org, akpm@linux-foundation.org, jason.andryuk@amd.com,
 snovitoll@gmail.com, xin@zytor.com, jan.kiszka@siemens.com, bp@alien8.de,
 rppt@kernel.org, peterz@infradead.org, pankaj.gupta@amd.com,
 thuth@redhat.com, andriy.shevchenko@linux.intel.com,
 joel.granados@kernel.org, kbingham@kernel.org, nicolas@fjasle.eu,
 mark.rutland@arm.com, surenb@google.com, catalin.marinas@arm.com,
 morbo@google.com, justinstitt@google.com, ubizjak@gmail.com,
 jhubbard@nvidia.com, urezki@gmail.com, dave.hansen@linux.intel.com,
 bhe@redhat.com, luto@kernel.org, baohua@kernel.org, nathan@kernel.org,
 will@kernel.org, brgerst@gmail.com
Cc: llvm@lists.linux.dev, linux-mm@kvack.org, linux-doc@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, x86@kernel.org
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <926742095b7e55099cc48d70848ca3c1eff4b5eb.1743772053.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <926742095b7e55099cc48d70848ca3c1eff4b5eb.1743772053.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=KYgTyC9y;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 4/4/25 06:14, Maciej Wieczor-Retman wrote:
> +		if (__pa(p4d) != (pgtable_l5_enabled() ?
> +				  (unsigned long)pgd_val(*pgd) & PTE_PFN_MASK :
> +				  __pa(pgd)))
>  			printk(KERN_ERR "PAGETABLE BUG #00! %p <-> %p\n",

This one is pretty fugly. But I guess it's just one place and it
probably isn't worth refactoring this and the other helpers just for a
debug message.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c4971a5e-1c17-4daf-8af4-804d07902fe4%40intel.com.
