Return-Path: <kasan-dev+bncBD22BAF5REGBBUNOQPGQMGQEF5PYIKI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +KaMAVTXoGl0nQQAu9opvQ
	(envelope-from <kasan-dev+bncBD22BAF5REGBBUNOQPGQMGQEF5PYIKI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 00:29:24 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F98C1B0E9B
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 00:29:23 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4806b12ad3fsf11234885e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Feb 2026 15:29:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772148562; cv=pass;
        d=google.com; s=arc-20240605;
        b=ATBv8kC5ze169hE3CXJqax4xZDRrgGQfjg3NekWMdnlvdp1XP1phMDlK0xtHt48Vrc
         2eoN2q4GKHA5eDglC91eIK4l8nou6hySlfBU8lIGjJG2t8DqTUVcCkj87hnZ8eWj2K8F
         FhrPyu5veLwBBVEXVNLsS0Z1LHBaL9F4kzMSqrtianR91g8umgIS2rpTkXzs0l/RSpqe
         umx7ZYr/GnIB/rVmIIjS8JsDmdCvFHN2sw/QCr7DI/JsvWfs3fpmCNsTMX56HcZPcSAH
         t6zhq7JjsdFeGzvWkVfHi3hSqaoFVCXRoKAyLl8NPFvs0pu5uqVqjyjPKR/pDqE3dPFf
         rqYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=lugtoUkix2+SLqqTuhnVUrZCtUR6RyelQjau/YogJQo=;
        fh=vQ5ivzNIoWbg6k7kYC0/pnR70e9z5LDINI9NGfvu1BE=;
        b=VMKuVdqQAVTzADIMFN8drOTBy+ae1xFoyCBo0HJGHWT0lpeCpzMmGAhQ04tq6PsW06
         W6gnTgXJm0nHkOWgwYEh7E0I6iO3W7uqq545mSTobJ7+xeDDfiEdP9cxcGPoc59np87w
         B+MjZ5c8rW/5w679nEaEbui9qmQQtcMJINVRFT9X5PVCwydbYp0+gzvkY8s6enZH/EKD
         AV2AbMLwZIsmpOspTJlv/zQAoJFe/CcCBtXkvg2TnHqaQSrPWgkR2jJjkOZ2SzEaFIBQ
         6rOChn7m+mX2fCPQ7IdttjIKeiBLR0YQrrdhlPgTEmufmBG9i52lWxiM/xh9Cc4jAOUl
         W+RA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EgerAtwH;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772148562; x=1772753362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lugtoUkix2+SLqqTuhnVUrZCtUR6RyelQjau/YogJQo=;
        b=k6MaIFgrDEe8V7DDYVmhvsJeLpFRV/As6efAQ/sO4R7eS8cUqXIrCFjqjuH9bQr821
         uHOpERQOAu2K+SlNHzyOjCpWqwEIISt6S885cJKIE3utrvlG1EsFJMKHTeQ7MYV/yQ45
         82HOfpUNL8Ue0SH7BK+ljbpDQVGKmT2PWV8xteXjbhUt4kQWoO27apmtJieOzUMq48bu
         fYiUWxH/ZQ5YKIq5sXafBV97R0rPgKDqKcGPp/mT3cnq923T9h6DCEiGm2HvWk9K0Q6E
         d+qjKTCLcLu/Uy7u/5p6sQa4V5ZR8u8WGI4AX2W4zdQmZzBxVLoqGJlJMY00VDiKDFG/
         +GWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772148562; x=1772753362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lugtoUkix2+SLqqTuhnVUrZCtUR6RyelQjau/YogJQo=;
        b=K8QEFmnE0GAvTrhiIQUCjSDcJoC1m5Dwl/fXah3qeXs3U0Ia5Vz1UEoXo4K6Xwwwpy
         UUDi1Dh68EoQnPKzanN7TvgRSMEwvm1RhY+FLou/1Ew5DHTB+A1RFAoYscwzuUinWfsD
         lsRJaAGLRFHVvX0pkxC4OFCcMP4DVTR2kodT7NPl9SHZldk4l069JzJtzVgLfDdUYAGM
         W9Vho4whJOs0FQVYLb94t9+8xmJZx66OMHH17UDtEcJPGXz2DFhEUHOTbHZ3ZngfKE3D
         P52hlmYgySQkHVl9Ul/PBHaSSOErFUCw5BSojGdHl8FFVY2t0uSBYUcKCdPccgqaK4WT
         Z01A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzi82ovcHV7lQ4QvYTYpotHqkQz13NBNabFWbMWhbOqcaqSw2v7nkJbaKT/t0Cmt2vWl6OWw==@lfdr.de
X-Gm-Message-State: AOJu0YxEPqQifngKnI2XK51V0X06ZE4xKYAzjD6eNGv9IWtj2mtxVW5g
	yf6HM5bzgv+sxJ49ivN3BN1E89bZTikptDtqwJdV+KMrQs0UpqclL1/V
X-Received: by 2002:a05:600c:6989:b0:480:68ed:1e70 with SMTP id 5b1f17b1804b1-483c9c32cb5mr9317085e9.35.1772148562323;
        Thu, 26 Feb 2026 15:29:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GMx4BOOBD9Xl1v457js58langyIowra+zHVMjBgiSS4A=="
Received: by 2002:a05:600c:138d:b0:480:4b5d:a2a with SMTP id
 5b1f17b1804b1-483bf080cc6ls17870835e9.1.-pod-prod-03-eu; Thu, 26 Feb 2026
 15:29:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVGTt8YbYfITUk/8/FrNFEjmLZ8lVM57zfO9qFEfNbwM9VgoEoAOa0HDOpsWKFN9Me08fWomSm9+VY=@googlegroups.com
X-Received: by 2002:a05:600c:548a:b0:483:c12b:fe46 with SMTP id 5b1f17b1804b1-483c9bdb2edmr9386605e9.10.1772148558350;
        Thu, 26 Feb 2026 15:29:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772148558; cv=none;
        d=google.com; s=arc-20240605;
        b=PtgXKF83wyM8cqs+9WVN+zUlJgckdzWpaR0nS0Kg8WXKfkruYfSgMwwkU8TtQERou0
         GabLIEc1lB/59alYvFL6Bw6Bz4jPuNF67vcQGZDS+mlQ7b03clXrdiiwSpSBiR9sbinC
         yFczxIvv9ZsgWDvYJZRle2LxsOlmLVnv75/m+DbHog1RBD+qXBiWyqlkkfaE5CBtS6Rc
         0EKjO2pdQ/uDiDjSq5bJq1PDC1GgjCpOwnA59GO5qt+sH5b6g2fN1ASYbvde1VTRdFjN
         Ql2ZOTPyJ4nTwEHhbWuX0ahZvICLb2BhYLWzD+THj4WdmI9kDndKy98hKKzL4oqLfsUk
         /bpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=u8DyUWKEuANQ8nFewrKh37wAqGnYtfMUP5HuwkbcvAA=;
        fh=snhNM2zvJTmwLOjl06/PKC3cX0r036sSotrQ/GoWRck=;
        b=BhMhdmpQpesoNVh5BgqOrxbHR9mI54ZrHd9J/gpOquf6McRcwUU5pf11P0jIx9N42X
         UDlEcqDzu3j/TQgJ3FwSgnonU7Cj929/4bpnVhc3J7tDghSuyCx9+/mBVGHkqgdYoMhm
         xdENuKVStQQOKtmJM6eBng9WdEtx61d+0EOlA0a7Uwd5eMCPU3RynEJnWqN/riHKClOY
         T0irsf9pEwEp97C/9ndv1BnNI4NzesAJfuJ3u7lBBfNGHOhIH2jBjpvpYyiu1r+NSBP4
         CmyIusEuUkWwOvaolIb2g2SZJ6pkeuR5htLNrOr7eptP9D6P+Xh1uLBvoYLt415gRxvN
         FuiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EgerAtwH;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-483c3b52248si742225e9.1.2026.02.26.15.29.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 26 Feb 2026 15:29:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: AfplqDwASBio23JsretoZQ==
X-CSE-MsgGUID: JlwovxUWQ/aXWqnHEiDUNg==
X-IronPort-AV: E=McAfee;i="6800,10657,11713"; a="90633365"
X-IronPort-AV: E=Sophos;i="6.21,313,1763452800"; 
   d="scan'208";a="90633365"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Feb 2026 15:29:16 -0800
X-CSE-ConnectionGUID: ay3roe4mTTic1BW9cirtRA==
X-CSE-MsgGUID: Iv2StXH2TliI0IAhYN4ATg==
X-ExtLoop1: 1
Received: from spandruv-mobl4.amr.corp.intel.com (HELO [10.125.111.172]) ([10.125.111.172])
  by fmviesa003-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Feb 2026 15:29:15 -0800
Message-ID: <fb8d8d51-66c8-4cb1-8b14-bc670c629afa@intel.com>
Date: Thu, 26 Feb 2026 15:29:15 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v10 13/13] x86/kasan: Make software tag-based kasan
 available
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
 Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org,
 kasan-dev@googlegroups.com, workflows@vger.kernel.org
References: <cover.1770232424.git.m.wieczorretman@pm.me>
 <8fd6275f980b90c62ddcb58cfbc78796c9fa7740.1770232424.git.m.wieczorretman@pm.me>
 <f25c328f-4ce7-4494-a200-af4ba928e724@intel.com>
 <aZ1qOpMc9PohArcL@wieczorr-mobl1.localdomain>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <aZ1qOpMc9PohArcL@wieczorr-mobl1.localdomain>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=EgerAtwH;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.10 as
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[intel.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBD22BAF5REGBBUNOQPGQMGQEF5PYIKI];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[21];
	FREEMAIL_CC(0.00)[kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com,lwn.net,gmail.com,google.com,arm.com,infradead.org,linux-foundation.org,intel.com,vger.kernel.org,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[dave.hansen@intel.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-0.969];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 9F98C1B0E9B
X-Rspamd-Action: no action

On 2/24/26 01:10, Maciej Wieczor-Retman wrote:
>>> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
>>> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
>>> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shadow memory (software tag-based mode)
>>>    __________________|____________|__________________|_________|____________________________________________________________
>> I think the idea of these is that you can run through, find *one* range
>> and know what a given address maps to. This adds overlapping ranges.
>> Could you make it clear that part of the area is "generic mode" only and
>> the other part is for generic mode and for "software tag-based mode"?
> Boris suggested adding a footnote to clarify these are alternative ranges [1].
> Perhaps I can add a star '*' next to these two so it can notify someone to look for
> the footnote?
> 
> [1] https://lore.kernel.org/
> all/20260113161047.GNaWZuh21aoxqtTNXS@fat_crate.local/


I'd rather this be:

  ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory[1]

...

1. talk about the ranges here. Maybe: Addresses <ffeffc0000000000 are used by
   KASAN "generic mode" only. Addresses >=ffeffc0000000000 can additionally
   be used by the software tag-based mode.

Or, list both ranges as separate:

  ffdf000000000000 |   -8.25 PB | ffeffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode only)
  ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shadow memory (generic or
										    software tag-based)
and describe the same use (generic mode) twice.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fb8d8d51-66c8-4cb1-8b14-bc670c629afa%40intel.com.
