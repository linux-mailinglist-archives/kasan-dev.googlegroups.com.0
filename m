Return-Path: <kasan-dev+bncBD22BAF5REGBB6GI22ZQMGQEGENYIEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id E70A0912AD1
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 18:04:09 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-70ac9630e3asf1997205a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 09:04:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718985848; cv=pass;
        d=google.com; s=arc-20160816;
        b=oe2ufVfoRzszGrVuxQxCeRrIugCD5C901+BnALN2QZIVnC4Rs+Fu07GRrys1EwhTHH
         BAzhAN18kKnhaySY8M0PI0TH0h/rjy3oQ47G7H02+8Snq/paOT/ZvTz8Wtve0kFq+iet
         sVTK2u4YluoC/Go5RiHCMWw1/J8uxlZFJAkJ+GZVd9PAY/0cy5aT5U0a66XMplH2kwHx
         k38cMXRWiddQRQtVTbeatdWjDcsLx9c6H7z1JBLV/+5GtzKtAZUR2lLt8fYIuSS8kEQF
         PC0Xr5vWgQLX8xi46gje3yZRk48AZ8N/wpl//2lxvWoFTyd8uq2BKB+LqJ78nvJMxED4
         G+qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=aHdb+kEZIPkYgoaDkvHJwJVRaSPsUn7HeXTK1KDSfI0=;
        fh=TufeK6oZviVaR9wyiNTR41C57gy+1MkowZbkMIGwrOk=;
        b=tHVrg9Y6ky/Xq7SReXOC+5FBqgOQ1dfaXnogmBE6dgMZgByOxa9+HEJzSH0t+joan1
         IHjdsPJEvHzEP0P0IpMTzN/ydxb4th/YykZHYdPNDy4Heap7FSeBwEPt76k9OWuZ2M25
         W0dwO15035Nz6hBHK3N7otjK84bjQ+ky1tCtv7HOSGVUdVwvywtJjtiE/ZMZlePYiLeD
         vmo75BFjzdtZNZeDQqL5AZH/nGjuq4VWWVs+oRdkgnS7LORL2urmjc/sR+dtWM5gU9/Z
         SpWI2i82fIrsh/ahMp6YaB6maVZkBHvSEGB1ve4s/RKn5ISzgVOT7jS/MgfikOzhCOhz
         3LLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lHV5GHRx;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.12 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718985848; x=1719590648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aHdb+kEZIPkYgoaDkvHJwJVRaSPsUn7HeXTK1KDSfI0=;
        b=a30PK6ety81tkl2k9xUCPoskNt+qK3a0lqLZGmq5hODD3Nwr9afxRuVS+ciWQK4IC8
         sJlTjRM3QipK8GqeVPSN9LlW4SibaE5isT8XlYbPldMa1UsiwYb3jfegFjzT40X4M6NJ
         xgOgp32CMtXjgZFI7POIuyVxREH6BsuVne10ZFDOEamFnHgv8QOgU6qNFRPwjKPWDLtf
         kZr+V1aySvFytdkH/QD7NgPBU1dAPlLeUVseYX2su6dojPWqk8ztio2M/ERDjh6uFr8u
         PMxjGks1BcBDJjweRi7ujSKzFj4WYB9W0ES6jsT1BGqeZ5+GtCz8QoZTlcRq6XteMbPP
         Mzww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718985848; x=1719590648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aHdb+kEZIPkYgoaDkvHJwJVRaSPsUn7HeXTK1KDSfI0=;
        b=R1h6RkzBvmX/ztElKqwkqZyOJdtmcajdjJnMMoSyLqSU60pKYzSTb9kDmCBhuTtLEO
         +y1EaygbGvsvGXK7aFKFXesB1cD/p0WIYyAWho+lgNjBsFIiyIkI8KSah/5Fg3ZLvb8Y
         2RvTYnMC+YPlIzglvXeL8+4JUXVykMGbbR8cM3HnRjdYvuDlf0trdQPjmrYZ0W1u6jCq
         dTcpAauW0dkYDVqsGCCggWaYGj1aAwxj0fbseOpcTgx5jGTum7/RzJfJR3z3pRAY5pTc
         Vw9QWOaHZv9xWpFauJVq0hKyM9whOKuRRHXSbrAJvDFPD2u0gm2fh7+s6SqSwtE2nQDX
         1hRQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUo3UAToWX/KkN72JrZMrKApfZTSsj19wTjE/l34jyHNgDYfurFJaFUarHAMW95pP0G2owxhplD+5b3v+a0bR87np4iS7Y+VA==
X-Gm-Message-State: AOJu0YwqnQx3wrP7KJM9Ckj/+nETYHH+IW9GC0O7YFHuPVKQCFU9b7GB
	YAWTsmHT8pHTgwK/uCZsXQWaCAiOXXqlf9dop9KvQOk6bg6Bv3dY
X-Google-Smtp-Source: AGHT+IGjXoHAOQvnyqSI2RpdkSOcOgK5uT7+fnkNMoR+/OjMbfRtnCwc+ketU/BGUUQcAN5VCiCNvA==
X-Received: by 2002:a17:90a:ac0f:b0:2c4:aafe:75e9 with SMTP id 98e67ed59e1d1-2c7b4e4f66amr9794932a91.0.1718985848393;
        Fri, 21 Jun 2024 09:04:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1bcf:b0:2c3:159f:cc9b with SMTP id
 98e67ed59e1d1-2c7dfedbbe8ls1296093a91.1.-pod-prod-02-us; Fri, 21 Jun 2024
 09:04:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcguAfDmtJ7RYnm5R92mg7Ey9uEgnGyuzGY09wG1H5IH2ZxIWpquQc1jQOCxUKnbwCx5S50QszinPN/X3T77SZ2FUprU+KETtAMw==
X-Received: by 2002:a17:90a:bd8f:b0:2c7:22d6:98e with SMTP id 98e67ed59e1d1-2c7b5c82772mr8290403a91.19.1718985847182;
        Fri, 21 Jun 2024 09:04:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718985847; cv=none;
        d=google.com; s=arc-20160816;
        b=l0iKsRiN1K4qNR+5UtW5+gpVJI1FuFHt1yGqMcuCKZplCADxtIIMk4OBLRf2IapyFq
         e/5Fe/Iptycwd6oKWqHxICSsJhvm+p0Xh2tTQku27LtUBHz9cf9+/EAzxCTno+i5hNxs
         3MQma+0YMWkUzbrS8eIpybX65XAJ+zxUu3degJ81a9CU0GGv7ZGCRTytIcDMvPkMNvNw
         Me957h6VM69J7aozT7XZ5gu1zy3kxNhz9y/Z+uz3MinoEKfD3QgY8puyVzqa/LsCoTH5
         ivZP2xEp60FzS9RLUnewXQxpR3Epij8/sH2IWKaSK9ssega5p3dbsFBTcdPsCy9cufSX
         9yqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=yFagjIw6G+jcrh3JeQg6r9QINVi3BKlyNu/+qcYqFi0=;
        fh=wq7AIx1Me16hwPO0gxT6phCpxJWOVUP6pyEFwfsH5zg=;
        b=R9HyP2c+48P6/VgShB3HD3iLjG5B6RY57R6RuqTwLx28mZbBLsDPBGkXLThzekUA//
         MVHyohELxFtWAqR+SR29VULcKkCMoipA/NLpXREw3cLdU2lX5E1vHFyEPNq6YHOs0bpe
         CCvdhZeoWkUSiuy3j+hyqUygCpGMYrf3T83Q1HkwpXEaeMQOFa1HsoMIydvyS6t3R4Of
         62n7ENZozhRJ3dY2MePCVKR0ltA7pYXVRJ4s0hzcLH8rDtKZkxqYW3i23B6uuBwsDp3g
         gqgD/1HQUstKffjGrNAq6AjGmwsqOqyHb3DxiIVw+o2vNk0fcoKldirC6iJSfgNloGgL
         Pf+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lHV5GHRx;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.12 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7e945195fsi202210a91.2.2024.06.21.09.04.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Jun 2024 09:04:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.12 as permitted sender) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: BWWJoSV1TJutC9WDS1ebgA==
X-CSE-MsgGUID: TA//LwFWQiqtIYz03u6W/Q==
X-IronPort-AV: E=McAfee;i="6700,10204,11110"; a="19912000"
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="19912000"
Received: from fmviesa002.fm.intel.com ([10.60.135.142])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 09:04:04 -0700
X-CSE-ConnectionGUID: 0JGSjkzvTn+lmv7MIHBYlg==
X-CSE-MsgGUID: FRAJ8aagRUy86jbRx9rCEA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="65882974"
Received: from bmurrell-mobl.amr.corp.intel.com (HELO [10.124.221.70]) ([10.124.221.70])
  by fmviesa002-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 09:04:01 -0700
Message-ID: <6272eb74-ac87-4faa-844b-8a76faf14f6f@intel.com>
Date: Fri, 21 Jun 2024 09:04:01 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: KMSAN stability
To: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, x86@kernel.org,
 Dave Hansen <dave.hansen@linux.intel.com>
References: <dgsgqssodokkzy6e7xreydep27ct2uldnc6eypmz3rwly6u6yq@3udi3sbubg7a>
 <CAG_fn=WvsGFFdJKr0hf_pqe4k5d5H_J+E4ZyrYCkAWKkDasEkQ@mail.gmail.com>
 <wlcfa6mheu2235sulno74tfjfxdcoy7syjqucqt44rfqcmtdzu@helxlktdfjcy>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <wlcfa6mheu2235sulno74tfjfxdcoy7syjqucqt44rfqcmtdzu@helxlktdfjcy>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lHV5GHRx;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.12 as
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

On 6/21/24 08:18, Kirill A. Shutemov wrote:
> On Thu, Jun 20, 2024 at 04:12:28PM +0200, Alexander Potapenko wrote:
>> Hi Kirill,
>>
>> KMSAN has limited support for non-default configs due to a lack of
>> extensive testing beyond the syzbot config.
> Thanks for the patchset that addressing reported issues.
> 
> There's one more problematic option I've found: CONFIG_DEBUG_PREEMPT.

It seems like testing using clang as the compiler is a bit lacking.  I'm
a bit surprised there are so many bugs here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6272eb74-ac87-4faa-844b-8a76faf14f6f%40intel.com.
