Return-Path: <kasan-dev+bncBD22BAF5REGBB5GU3K7QMGQEI6KJEVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id D11C7A82D5B
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 19:12:21 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4768f9fea35sf166026671cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 10:12:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744218740; cv=pass;
        d=google.com; s=arc-20240605;
        b=CzZTuGlo7tej1jhvrR/07rFFehJu8J5DZVNC88454eSlf1PMTBCPsAwhCdiDJNrgE8
         Io1OhmoYnQST65vSgV5lOy1EnH0xaCvPWz2JrvEVWgr5YGhdFvQj+iUkUTX9cxO8emPv
         PfCdtDqKvSw2ItNzpWib6zaVo51pNZIl9X+2MY/KtNumQXX5PUxWSd5RsSZMttK2G95G
         Ru4TjeMFGejP71Ndz4KdxfpR9BS0jWAIXT2at9Wyt9l4LsI6E0R9TxJEN8DXn3qh/jGN
         Ii9BB/Y5exioFm+7/YmnE2WdAX9VAO6VdTE2qldsEbCLDJP5TDeoJfOTEhAS4IicqlIK
         uTvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=b12bP7yi7d6X/HK3T5c4NcTW8Oh37csPhKe6c8BjkYg=;
        fh=XThmQaDgIZv2sNlmXr0u1+YXif1a8534oddLahLzTJk=;
        b=G2W0+r3v140xenJ1Pri8hSJg6vFjK5tLxaK3kQhPILvs1gQpXFmJBHhag8jYa/6NH+
         LjO+JGoNzkwqTxWLlwypuFbHKVglr+Lj+O/dkhlYq7Rj8v9X3Ss0tvp5B6DzZkmrRN3E
         HnEQ4BUboq7ZX/qmLDyjD1K1SxXKbYhAYoXsFaUkSbFWFm2RZ/hRbAbuh62sE/N5WDLs
         8q91JnZSZlejKJEL4eitWcUzeKpal6HQaBMBlSuZd/lcP9qY2oTBUuR9OldSJiUnOxfb
         msKTf/aVzwCQdtFneVjQl4MzBWpzAP75Dxss5oXBt4oqXZiE67sR9hiLgkx0MZlgI5F2
         fpPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bPvbKghH;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.18 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744218740; x=1744823540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b12bP7yi7d6X/HK3T5c4NcTW8Oh37csPhKe6c8BjkYg=;
        b=XxNJtb8OJlcVUVrT90iwa7XbiV7X3T0sCQfWJ8fzAK8dixVA9ZOpxGRkfqf2CersCb
         TCOCw67MAZZccOK9YkptNqmI/GJs2QfDnlKHKBCxHnQxZoYuw18bplE5s43/ldaztAJq
         IN1BEH0j/reAYYQHR7xTw9NqU2Kn51LN68pwXE7Kl2lnhqVW0EBYXHbf5g7055wc88zM
         u5DNQ1vw3SsQsTq34HhnpHfiSyZ0HIIj0wlt9uVNZjZQrACLXyZ76Sh/BkUyz011g18+
         r0iazMyF3vgDhl3Lm65QlZA6jlXYjTv/ANEyIO+PrymqtskTbnBKCEBi2WdwUUVTjAVB
         EkGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744218740; x=1744823540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=b12bP7yi7d6X/HK3T5c4NcTW8Oh37csPhKe6c8BjkYg=;
        b=gr3sJcV0punGdT0rPhuFdcgdAh4cFVe0Ik4xJq2RwmwwY0UX/Nz/flas15+wF6uTHy
         Cu7t2dgg+da7hLaOEG8iGy+CFzXt7MJLdTHIRBtUpExuXxBv2PfVG/xV3rsrxb7c9B+0
         m6Pqg7XDdGcRLC83xjEdVtv0eplsmnmLtOA+pC8YQFylcLbpsCmX34XO7LiRfsKntvqG
         SlsUtgdW2jsUMBc6q+W5epc1beFF54/5pVG3lZMkca4z+YVaufS0FrpTQ9kJGLfoxM6x
         T7PqAtixxt3KfPxOmI+c3CjUyqa2FxJFBeiFBK3mB/pvIl56BcXCOj5E0Sc7oy+3H/aK
         n42g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZCHXegbfBqk581VFnjB28RlRIoiLvCgOz2mETDf3JsgYeRXwAN/kOdIVzppVM8C1er/KCAw==@lfdr.de
X-Gm-Message-State: AOJu0YwqyrEzA/mMni5b8xpRaJERxlmHNOI52LBuv7r/v0jTc1V1MhOi
	TivNhHSx7Eu2Tz6+6gOS0cTpWBbTv6S5o9qD4x8FBjQa7pAmEJFc
X-Google-Smtp-Source: AGHT+IHDZdgISU7XhjZ89WkcbQ3SiDGZJasq9AVdSxeghlZsRskWzYEWx26jdSl6wf5LmVAi9YWFbQ==
X-Received: by 2002:a05:622a:3cf:b0:476:6189:4f30 with SMTP id d75a77b69052e-47960137ac0mr51424121cf.36.1744218740255;
        Wed, 09 Apr 2025 10:12:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKPeH+H5ocIJqYm2o15Jcy4iUAtB4sc031bgPvuG23Akg==
Received: by 2002:a05:622a:2282:b0:477:72ad:1cc4 with SMTP id
 d75a77b69052e-4796b32189als2404231cf.0.-pod-prod-06-us; Wed, 09 Apr 2025
 10:12:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpkWXqOR8GKJk1QawyJk6JxShVcxTdr3XWhdn60NxjKC7nJpnhfZmCyCXl3qBiin8GClJG4q/UYE4=@googlegroups.com
X-Received: by 2002:a05:620a:1989:b0:7c5:4a51:238 with SMTP id af79cd13be357-7c79dc5da4cmr488156485a.0.1744218739117;
        Wed, 09 Apr 2025 10:12:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744218739; cv=none;
        d=google.com; s=arc-20240605;
        b=GkwApQ9ryUU6IOvwVBhsCdd/rINSckZE+tEaAWVhQQASgOVqi4h0MWwW4S+i9n79b4
         XiKGKGGxTOy0/ItlJLSzSTW+VWTzGfJkIekXaduEHyr+WJAfbc4gcUJEJfX3Tm5os40Z
         aL/9LLUu7ow4zXayx1YEslJiuD5I22BR7Wi24akhFgVa7yq9mgPRfxTSaPClIT9e5MMk
         9SQ/gydGO8Z1KAcmcwKBoBc2QRtnIhH6lUVIBDDqz38jDCQsU4jLYrnR8WHn652O/BDI
         B4xp9L2xoTrv7Yw99LixExOr4KzgNh6vVa0TYypzJBQIyhik2zRX5tSOtwbXbLSn66m5
         i5aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=rMaFchJcz6j9TxgZxUNyUBffmSIxcvFjaUkyyQVtObU=;
        fh=gGPVKbHUX2Omcvuc8J48EMglbdecp5b+AI6gox0GcQM=;
        b=imHMNo3KVq57RRBqQk5lc/iXJNEx9d1ojCZ8tADBQ/tO0cWnC4TLhLu981bd8krgOk
         yRYiB5sAGZGe/KCKuqKXLiKKhkmu6COEnZVmYmYB2c8wURGNs6PrYfesKvXp7FWIzYch
         RiWsN1IlJ34eZTD19mTnCDZ3DP6RAr1S9Xl80TxYfDAFkY+wCYhSSGVVp2HjvJ0/NUeB
         9/m0ewPyGgSMZxuK7lKWjNtRoYPndgOLF6mzBWUITI5NXAJPY7AFW8PGHIB9g8zXFKyR
         yevIcpTOnvN1jTuPM9MSVFEx2crSCgp7N4qab4hv8An8URlRHpZmi5fJx246+sEgxEEY
         +fHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bPvbKghH;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.18 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.18])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c7a11dc9f2si7977085a.7.2025.04.09.10.12.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 09 Apr 2025 10:12:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.18 as permitted sender) client-ip=192.198.163.18;
X-CSE-ConnectionGUID: qRbuy5G5QyWzePbD8XacbA==
X-CSE-MsgGUID: 4N1W3wU0Ru6gWXRVNuxFoQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11399"; a="44952536"
X-IronPort-AV: E=Sophos;i="6.15,201,1739865600"; 
   d="scan'208";a="44952536"
Received: from fmviesa010.fm.intel.com ([10.60.135.150])
  by fmvoesa112.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 10:12:17 -0700
X-CSE-ConnectionGUID: mi8o2LJPTq2WEbMiBYvzQQ==
X-CSE-MsgGUID: i54YUDKXRgOeQ4aHOdozlw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,201,1739865600"; 
   d="scan'208";a="129170078"
Received: from sramkris-mobl1.amr.corp.intel.com (HELO [10.124.220.195]) ([10.124.220.195])
  by fmviesa010-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 10:12:14 -0700
Message-ID: <a7713487-cbbc-430d-8028-ce9ab1f6f3e1@intel.com>
Date: Wed, 9 Apr 2025 10:12:12 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 13/14] mm: Unpoison pcpu chunks with base address tag
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: hpa@zytor.com, hch@infradead.org, nick.desaulniers+lkml@gmail.com,
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
 will@kernel.org, brgerst@gmail.com, llvm@lists.linux.dev,
 linux-mm@kvack.org, linux-doc@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, x86@kernel.org
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <61033ef5b70277039ceeb8f6173e8b3fbc271c08.1743772053.git.maciej.wieczor-retman@intel.com>
 <fb0d5f33-4636-4de0-82f4-93a9def63a26@intel.com>
 <ynl7b325d5jo52n7cpy64v6bvqhzlbkphqsbs3jrgtji4v4yoz@cjpytwlwc6kt>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <ynl7b325d5jo52n7cpy64v6bvqhzlbkphqsbs3jrgtji4v4yoz@cjpytwlwc6kt>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=bPvbKghH;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.18 as
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

On 4/9/25 09:32, Maciej Wieczor-Retman wrote:
> They don't seem to be virtuall contiguous. At least from testing on a live
> system, QEMU and Simics I never saw any be contiguous. And I double checked
> today too. But your version is nice, I'll just drop 2 and 3 and I think it still
> will make sense, right?

Yep, it still makes sense.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a7713487-cbbc-430d-8028-ce9ab1f6f3e1%40intel.com.
