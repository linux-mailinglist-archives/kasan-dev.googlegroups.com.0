Return-Path: <kasan-dev+bncBD22BAF5REGBBOOF5OZQMGQEJZADHAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F72D916D17
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 17:31:07 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5c219ca8e9csf572110eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 08:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719329465; cv=pass;
        d=google.com; s=arc-20160816;
        b=U26Jvmrnyi4O4ck6SjAXi24cyUnWHeQ4hoj6rSqC8xDNvEAXixTOwVkB4MEU8a4CWQ
         lOsC8k41nu1dUNASM2TcF+JbEL6KyKFewWtKKJuMXt4icp9vrmbIMujzf3SrNsahuuFO
         LBUDu9JJrgx0Lk5WzGaZEJatBomzfRIe+w9HZnRGhtWPIdwNMHMs72z438PjvO4Bv6pY
         T4AB19mI2XBUwbZOfnchS1pgdTuk0vKCRFEMvSBOjhVtcJh398yleyaQXH0wWByM8wXo
         77piFD6IcGy8juPpWqS2nCdkzj7pC1bW33RrridnaBJdNX8Rbggd1vO0NaT1TdX6avtF
         S4zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=LZmIOHDKzK47tYQJ/O468pnvV9ARSJ5kqqdpc2VFa2k=;
        fh=3NPQU7vIVCxS/J4BeOW/Ii5gY//yDtLemSQ9JIar55U=;
        b=0c6+7q4nHcn3qCULPUtwTiUFR9RLTToaJhV7kCOmFmV3B0CZdCxL+3TsUn8aaFFTn8
         SMl9zkgpOK3gm6Fen1y1MCEXVB5wMD0DeUyZfHnFoqbPwPWHMVdggKNTKrea2McMmdJt
         rTufFD8b1kVcvu7F+Z/M/RuI0K+7u3iRHcCvdcm4QqNeHj1+lmTjj4OJWjrN48GkpC/u
         y1jV/XO8WEh503jNaSo80O88zlsbrNuUQKTthlqwfIvvrr5NlbHSD0V2cyVZmc8Q/r51
         KIdGiyFFYUCROgaRGuxHstDVzBZLDYCsajcKgv8fJApkymPVk0+cxQsvqEBluWqw05YT
         I4vg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=hrbjp3SC;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719329465; x=1719934265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LZmIOHDKzK47tYQJ/O468pnvV9ARSJ5kqqdpc2VFa2k=;
        b=thprNkISEltynFeRQeRDDjRyXuEfO0x5K9rd4OThbLRVubc/o83NlP8W9sD9z08+km
         XAvSV+xH6ROC7rEEh1v4TVf4EEmelE4XOJmqNSxGBHk5qD5k0TpK3vk6l7zyaw5A76k2
         hbX2/+yjdCAw+8AGUtoOlIPZpi1It5VBCMNtTanek4SZ6QUCi38eBrMAQKRfO4JZKt7Y
         4Jsu6vajbwmjqwtUtH6LZA40lwSOjvJE2pwkCs3EKJ1TbfqtVt+mB+e9fvv0bbBf0kx3
         3rW3cGcPIVW81sziXOdPdAOGmvVmvow+q/QZ/uGhs5aumTseAkuWdIbA7dE+xBZ7y78p
         0/9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719329465; x=1719934265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LZmIOHDKzK47tYQJ/O468pnvV9ARSJ5kqqdpc2VFa2k=;
        b=OAG+nInaVHKnE7L/9+vn47amoNmNxnrDScmglGTBu0dBwBV/2WIcYxoGKdVHc/D89t
         zOYJlCWp1cMjPr+9sqXC38mxQfcuTd+xSskiWTbTGRhaw+DpZ8iUT0d9L5rXrTjDpUrv
         AWsSyEfX0etbrLqEBmmxzf5oMU3/Uiy4eijdfjgRkODtS+ixZJJq/RHFe8Id1iIrAhEw
         BgARPQbtwJCj4TVDTSWAf54OrNcQs1pa5pw+tNsjrf/ct92rnK8BoUSPEmKU0sNNggEu
         0A5fYPpFMD9DoUWvTBAi/gRpJLeWTP5x00jD85yXpvRuRykKW0dgFjHRhTHbD8g4Imo1
         pvag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUjOf278ubUj1hF+Uza90e2c0JE0ODyefwYjQPMtLgzaS9Xj8dcsnTZT9TVI2EIU5NX+UA/c7fT5EL4Np1GJnCBxdyN6zaqzw==
X-Gm-Message-State: AOJu0YxAXTkCMORSXIQOi/HMR39DcJR9ah+9Bi3oPruW++8qEbbUMXSO
	FFM5fRQKSSm8eiep2W50PgR5jFiiRHLqgHUuZWcxBLff4uka1ABo
X-Google-Smtp-Source: AGHT+IEYrb6mKJlNQVvw1n4YZt8sbhI9QhJ4DeN0p2VdyXpsRLrLmqaOeuSMJyYG2szAhm4kQnh3zQ==
X-Received: by 2002:a4a:921c:0:b0:5c1:b998:a85a with SMTP id 006d021491bc7-5c20ec26578mr1828874eaf.3.1719329465354;
        Tue, 25 Jun 2024 08:31:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9284:0:b0:5b6:60e7:a68b with SMTP id 006d021491bc7-5c1bfce2daals1616706eaf.0.-pod-prod-00-us;
 Tue, 25 Jun 2024 08:31:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXnD/QLRl6zaYjJZhBATQkLSnbyPPc3fK8tQxxNJzeCbhBAezgZr24iHXlmqT0117KNZ438JDT6aLcdon1+PlNzkoVG3nz3Kr9CA==
X-Received: by 2002:a05:6830:6202:b0:6f9:d203:8d13 with SMTP id 46e09a7af769-700aa4de4cfmr5148264a34.0.1719329464590;
        Tue, 25 Jun 2024 08:31:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719329464; cv=none;
        d=google.com; s=arc-20160816;
        b=VM1lnwfq1qg3JG1vK/o/IvjPo+wIXBftKQ6VLuntfEC5B3aRpT1yNhz2Avu3lfkW87
         VHiC8nLtTW2v6jgsSPwv1W0A1pGJETXyRbrEEBFVVNfrGBpfYcpjyrsCBqTZKMFsOeuG
         Vx3x1GVvC/9AN44L7gRcpGudK/Qm6NVcok5+cadlYa7aO83yzITYPdhBArWeFAVFehUj
         npBoDsZ9+63Pz05ktDpYVpLcEgqd0x4Jmdmh5JgjFVv4BjGzBWCpNPp8nzgl6298EH3Y
         gcVSNs2X7MJ5GD7c+aUGU1k1qfb5etidh6tfAmLYS5DKyxO+1uEapPataKykCHnXcvas
         jJ6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=VoiSbMu350BRg28eDf+9yVOpbObNbqlRMoIEoLcU44s=;
        fh=GwtQrKhzZMXddfFKJBJN79HUnvlNyGskdXxUy2l7IyY=;
        b=enRF2amSVTWEOT99TeycTKpqXE90RzA4ISyflBeeU+934P6xwcZ9l/LeBN1zEng8Ur
         jLr+LVZKn3qF3Ulj5AV9H7vBG8VyFq9TRxbFY+wBVr7u8wO5SAl6ML3xFk1Q3sQquZiI
         4yBra8hFdPynslq+Det9mID2KZ8zZuxdAJoujlljHKoxdtA7QfmNUyefyHSQPk1C2y3t
         eQhwA0kXwjGQlt4Kb8i2pJ3oIpwK14V1PBo2An7QVabck1riKPvTX3+EDo38p2VLF1LD
         WITYqNjzEYqm0p8kRNuxYlioKSXCwlOkMf7BfKdw6s/pD0GCaKxNTdZlVcJyOM0UjtRx
         2kbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=hrbjp3SC;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7009d5e51d4si290569a34.1.2024.06.25.08.31.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 25 Jun 2024 08:31:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: o+mHVT5+Q92szRigQP+0Uw==
X-CSE-MsgGUID: m6cpKQteQguw+toXUxw91g==
X-IronPort-AV: E=McAfee;i="6700,10204,11114"; a="26946543"
X-IronPort-AV: E=Sophos;i="6.08,264,1712646000"; 
   d="scan'208";a="26946543"
Received: from orviesa008.jf.intel.com ([10.64.159.148])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Jun 2024 08:31:04 -0700
X-CSE-ConnectionGUID: +3Wk90IsSMK1hg+n//hphQ==
X-CSE-MsgGUID: peb+A56kTT+7xoCyv94XsA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,264,1712646000"; 
   d="scan'208";a="44395977"
Received: from kinlongk-mobl1.amr.corp.intel.com (HELO [10.125.109.47]) ([10.125.109.47])
  by orviesa008-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Jun 2024 08:31:04 -0700
Message-ID: <98589095-3cde-4767-b2cb-2240032420c8@intel.com>
Date: Tue, 25 Jun 2024 08:31:05 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: KMSAN stability
To: Alexander Potapenko <glider@google.com>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, x86@kernel.org,
 Dave Hansen <dave.hansen@linux.intel.com>
References: <dgsgqssodokkzy6e7xreydep27ct2uldnc6eypmz3rwly6u6yq@3udi3sbubg7a>
 <CAG_fn=WvsGFFdJKr0hf_pqe4k5d5H_J+E4ZyrYCkAWKkDasEkQ@mail.gmail.com>
 <wlcfa6mheu2235sulno74tfjfxdcoy7syjqucqt44rfqcmtdzu@helxlktdfjcy>
 <6272eb74-ac87-4faa-844b-8a76faf14f6f@intel.com>
 <CAG_fn=WN1T-jo3qL3aCbCGXZ2fh7aGSkfE4WhBEqznY-G1savw@mail.gmail.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <CAG_fn=WN1T-jo3qL3aCbCGXZ2fh7aGSkfE4WhBEqznY-G1savw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=hrbjp3SC;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.11 as
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

On 6/24/24 04:35, Alexander Potapenko wrote:
...
> 2. Provide simplified versions of primitives needed by KMSAN without
> debug checks (e.g. preempt_disable(), pfn_valid(), phys_addr()) that
> won't be instrumented.
> + Covers all existing and future debug configs.
> - Code duplication is bad, we'll need to keep both implementations in
> sync. (We could refactor the existing primitives though, so that there
> is a single version for which checks can be disabled).

Creating refactored, single versions of these functions that KMSAN needs
would be my first preference for a solution.

But, honestly, anything is better than what we have at the moment.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/98589095-3cde-4767-b2cb-2240032420c8%40intel.com.
