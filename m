Return-Path: <kasan-dev+bncBD22BAF5REGBB7GZ22ZQMGQET3IOD6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CF13912B8B
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 18:40:30 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2c6f1c0365esf2113998a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 09:40:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718988028; cv=pass;
        d=google.com; s=arc-20160816;
        b=gyh2RwVatZELXORRjBeQfi4Tg8ta1qnRY3+GN6etCbAxtLHy9/i3M4TDmYPnW/7tFA
         akhmTtG3mpvcX71PSrk3YQayCFcJbp9je1LQcAuVpxa4uGzdPASpi5Gto7QRveSVDBXw
         hSaMD2N9WYXR1e8mkN1or6i0U1vYy0VSouS3s/Zy4TCHdDTETzBa74PVi4Xs/j8UielF
         Bn8DrxoF4+Uu4d0PimSjKMSMlKJMXevR3KffoYjDNYU07VG4HpDaXDdMTJLtNJeQ8vXi
         gCTVVO4LMf+xvmTX8KLxhIB7s6ufcTHKJu6dm0WCNjMhkvRxIbNAYn+ZT1Rj9saa2Qen
         ENKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=Q61lxit/kbhEFb+/3b+WYjKVKt9uKAquf8QUGeaFWao=;
        fh=f5GbwamXwYsB79RP2qqvJGKJDTwNcoXu5X0aN/yggMo=;
        b=txcInmDSWi2hnaZQnVdnNIMNa7/xWFeVnBn6XEeT5Kc7+OaBsF3YVvjs2gTx5GqCyZ
         ieC6wa/Ay9fw8ZU1DApml1Zx5A4m67GHMB/hLp+OUXyXfA3U9Fz1MVLi/O4CCcDc6bJU
         1exDh81NERiC4+oP5sRozeNfBJS5XNeiaYCsCYJrs7WLNg3lxLSOIh6hXaehqYudhuCv
         4hnuyHM8m6ocNgAq6umeW9n9hYbUVSNWLr//7nmj18VROSJxIYX+pQ/HsRBN9iIfRqG4
         /tQ1R8gWk+aPlLv/5JgQkmrY8Y1DamagAHTo3uscIf/ksenRNdcPM15AlaGRxgkqE8Ef
         Celw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DI0uK3Zf;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.9 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718988028; x=1719592828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q61lxit/kbhEFb+/3b+WYjKVKt9uKAquf8QUGeaFWao=;
        b=EBMqOKUDUtssCMRv4Unl0YuSuJHxswlVjL/40MIDhbQUW208F9Hz4RKAG6V4dqOgdV
         B0RROFQD7e90wAskXkQqUvFrBeL80UWxqxjm0a0pEbcHZHvRXp3UQnrFz/IP23bmx8dl
         gQC/MSW5dXOw8sk35fFH4zOnRWL/1cPHhaSQMl1VL/tykKSFqotKeeKxA1suj0xcMw9a
         oLS1j6eLYtAMALw2Fm76rP/TyoZUWD7LW5MC+9P03kGKO1xZhjb4wb0qPmmSpnOIGnSk
         a3w3iXfWPWIx5fFb4qHdgPtQi9UMVYv6v6AlCNF1EGh3l0ro+Rx+j7KcWKBZaiSKRYOm
         TVZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718988028; x=1719592828;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Q61lxit/kbhEFb+/3b+WYjKVKt9uKAquf8QUGeaFWao=;
        b=hU0UpoA8xcgtfpMsFUqxJJ18flP4QtZaitZbYDf9sIH8ItEEYPeXNpNE5x7Vgd0+Ra
         aWg3vXvaBDHrYcKROiAI1q5YL+FTQe0tJNIgTGwhTTwwEo0f0mO90DzFPyyeSwOu6NDg
         sK9L/tJB816O1R3dIpojEMuGv2UGzR8qCOZqMToGvp+xpIAzeytZLvwVEPY4dSVhZTGC
         p42clVvKzLCGe5VjbvG66d67K6ckk+qn79wV/3h3d1LaSn6Z5JcgrhcxWyv2VWlr5M5c
         nZRBkuX8iOl/c7BirBHg2gIHxhHofFyNwTbTdav/dYUnFZ3XlVBwozv6rQIq/rCUrum2
         XvKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+Xwj4OlS+TEARzO7TpqYG19a2fb3AHQD90NSxOqHHF32Zhkf7D/J9dnLiXivz4JwDO3KPkpRcpyodvcvUPuS8o8Hm/+Lcew==
X-Gm-Message-State: AOJu0YzUVb9PgJFARcRLpyGkYJcY0wFkosYBq2d4+Krti/73EE24flyX
	mpGwJqaAmSt0FJcXaIM5MFt3g7Ak+fi7nrvIrgU/xKe/CxkqgPvR
X-Google-Smtp-Source: AGHT+IFqmhFVyL01iEHaE+StC8Mgn06ZAlGsKcFNwcpTycnJ942bkMWGmSgBDl8Ctulhu9bLFHHsIQ==
X-Received: by 2002:a17:90a:7848:b0:2c8:633:4a37 with SMTP id 98e67ed59e1d1-2c806334bbdmr3915906a91.13.1718988028478;
        Fri, 21 Jun 2024 09:40:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a4c:b0:2c5:128e:23f with SMTP id
 98e67ed59e1d1-2c7dfee7277ls1252859a91.2.-pod-prod-01-us; Fri, 21 Jun 2024
 09:40:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWa+HcvBS7/s3Pygf5BBxDfKFMJNwp3dailCS8BhwPlm3PjfPDCac/h1W5T3TVPSgs2v2Bv532TX4R5KOwB3ulitzRKnx9C02QYLA==
X-Received: by 2002:a17:90a:d58a:b0:2c7:c6a1:42d9 with SMTP id 98e67ed59e1d1-2c7c6a144d7mr6680276a91.49.1718988027309;
        Fri, 21 Jun 2024 09:40:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718988027; cv=none;
        d=google.com; s=arc-20160816;
        b=TbpmIuU7Na5+dZAkau8D7fc2wVCcDSWGUHYErps3L32TwHiKSr+DXwK61EWDB2IwaT
         7eEY4DqmgB1VvsWVhDaBQwAwNlBfJo1D3UtuoKVf1C/5NnvVfbCQrgjoqyArxqOnSjmB
         NRh67BjhpOKQb6dIGPDB921+1cuNfpBS+Siadvocx0X+7MnHveL3TYP96gThbC1J0pcV
         yrofA2zWqRjJzw85GsHJ9Mxb+SUzG0TMTRDp+7wCZmJBzZ+U2K/v6lcLIc5lpIynTHQU
         FlxC4yUralye4ElPKYIDWr5yAIwpE2b/y6nIGf2xcIvDBwvOUf1IH54kVyeifNE+17/7
         QpTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=GGM5xwTe2cxJiw/On5DXGdrNfiGQRPJStAIUWFKVP64=;
        fh=kK0JR9utuTk5HzRkNM50cLutRmJB2ESL32HM03l3D+Q=;
        b=lK96fmqw83LZa/t8X3GBbehzdzkZTSxzc5EhabFN5pNFnE2VnMpVm5kSyU9VfvrTkw
         Zt6kp0M1ngx6EhHfmspSATgR+yeGUopuT+z/r6SEKEv0FMf92AlzxlW3vHQEpElxG+3c
         mz32Tvz45xlGawPa5I0WLJo4ZuxnINkuJZ5KEalzakI5DHiTC4jVJRB6BEFGi9Li0Tdk
         MbQ0SUvfEVRj5aOI+hMOPHAKYpKCGjMO3s7Onu/fSmoBAvIy02Xr3am8M4MUjrXN+hGY
         nlAf9fxzJ6p+ry09sDtacGUEXH4LBs7tUNdiHaV+tgGF2r8roUwzB0ETZs02jYylOamL
         VVag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DI0uK3Zf;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.9 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.9])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c806446a8csi182308a91.1.2024.06.21.09.40.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Jun 2024 09:40:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.9 as permitted sender) client-ip=198.175.65.9;
X-CSE-ConnectionGUID: EYzeym9hQ6CTlk/mpxAZgA==
X-CSE-MsgGUID: BNCayqSzQp2zlfwavy0ZUA==
X-IronPort-AV: E=McAfee;i="6700,10204,11110"; a="38549228"
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="38549228"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 09:40:25 -0700
X-CSE-ConnectionGUID: zr5/jxCSQv+X+JZf2iKC2A==
X-CSE-MsgGUID: XtVe/A3qT4eXt3UUOUq/BQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="43315176"
Received: from bmurrell-mobl.amr.corp.intel.com (HELO [10.124.221.70]) ([10.124.221.70])
  by orviesa007-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 09:40:25 -0700
Message-ID: <a2e7b9a1-15ff-41c3-a6b9-bdab4ead904b@intel.com>
Date: Fri, 21 Jun 2024 09:40:25 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 1/3] x86: mm: disable KMSAN instrumentation for physaddr.c
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com,
 peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240621094901.1360454-1-glider@google.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <20240621094901.1360454-1-glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DI0uK3Zf;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.9 as
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

On 6/21/24 02:48, Alexander Potapenko wrote:
> Enabling CONFIG_DEBUG_VIRTUAL=y together with KMSAN led to infinite
> recursion, because kmsan_get_metadata() ended up calling instrumented
> __pfn_valid() from arch/x86/mm/physaddr.c.
> 
> Prevent it by disabling instrumentation of the whole file.

This does seem rather ad-hoc.  It's the same basic reason we have
"noinstr": code instrumentation infrastructure uses generally can't be
instrumented itself.

How hard would it be to make sure that kmsan_get_metadata() and friends
don't call any symbols that were compiled with -fsanitize=kernel-memory?

I do also think I'd much rather see __no_kmsan_checks on the functions
than doing whole files.  I *guarantee* if code gets moved around that
whoever does it will miss the KMSAN_SANITIZE_physaddr.o in the makefile.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a2e7b9a1-15ff-41c3-a6b9-bdab4ead904b%40intel.com.
