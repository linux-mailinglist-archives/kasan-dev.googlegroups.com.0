Return-Path: <kasan-dev+bncBDGZVRMH6UCRBY53T23QMGQEO5PNSEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id C9C0F9799FA
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 04:54:29 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2d8817d8e03sf4923495a91.0
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Sep 2024 19:54:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726455268; cv=pass;
        d=google.com; s=arc-20240605;
        b=KA5/Gc6ojhwYR1CUfLXLE60RxF5d14O1LUohD2Y2xnpwBnub2ppDS6s4J5iT7ZyhQ1
         JUu37S21pCo0v8dDOmuwOa0w9V8YYhMoMGaHnvpKzUyeM6ilPViSc4PdNxt1KL2cI/Qa
         WR2h4IKRNse3QpqA6XpyM1CPohI8ymelVJeBXUZuS6HFlOwUtzT4BBdJvu/Ke7zq8IgO
         HPU7xcqesx3a0cKB6J/RL0SzUc1iCK9czeGZl+PmTlhz5wrkLkucXR474tQwynoH6vuB
         Yq1NBnZaOJwwPN5BI4+Fs5iT0R/chcIebdzSKZYVai9laYmILl0O1NpjPq6eiMH0/uVJ
         oKAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=cU0rlGLEcGDxWqTzHm+wGXaaYImKoEE2rwT2V1lREsw=;
        fh=QBknwIwYC7Ga6D61EViLMNHT/skrEPFXtX4hwx/7VzE=;
        b=iZjbMwAC9QLXAcYT37oLpUgo/6II+JCPpdz2PrcgjxEOF5200CTObME9L973GvnUA1
         cYCb8b9biOdC9clWEwakZyEfxFiphArkXrYiAH7Zg2o7hZ5qHvFmMJqwvT1zMWr/FqGZ
         JPbjy3lawuiJwLjoJYLUeJNYfqLeOPd5PyjGC5F5lw6jyudZ4DHf8/y3ayrZqiGEddOP
         k07XtKXasJoBkdIIVVjwMM1TzLuLj82xTCh5U04o6D5sJSxx7fStGjVSwHgQIhwLdoXv
         HzBfNPCN+OyxcY413h5hWehXEdS4ugfOimoArVy5FHjoSyruG3zU8Yvuh00aLryqwGqx
         YrKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726455268; x=1727060068; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cU0rlGLEcGDxWqTzHm+wGXaaYImKoEE2rwT2V1lREsw=;
        b=ExEi54TcKM3+FAM4BxDtZmwQHR582Gz6fa8o47LRow61ZyppO7zOrZapulNkGi60+I
         7iY26fNIMWM3iA3k5QT4xb9cQ89hzkO5G4ucmmlQvyAp4uc5ctR3fjp7gCO/7F4uPyea
         HeATRfxeKrs4HWDGG3bG2cKtX4oVdjag/eQUB9TJyEpaAjaOmc+ZsS5ECCpcH5Y6whAh
         vTXTK5TbsJqUQvMnsOGSs1UoRm8yvi02yjooQZ8P+hhARpliPTc2DpnBCUkapqw2kfXo
         SDbxZsNV0W1c2YwpOi3qxphNMLzQznnPBeU79f2Ed8ZN41IvWb0gUSESIPvmNUZa3LYO
         lVow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726455268; x=1727060068;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cU0rlGLEcGDxWqTzHm+wGXaaYImKoEE2rwT2V1lREsw=;
        b=vyXvcImH4RyGFsixRlUpKOCL3fuqicAUOFxPqdkuq7WU5PAABGMwGZdZ5g14gVdA/i
         D+zgu1MTvAA/zSSQhkqwTjz2pcvZJqW4FX24Mx0YWgl0992J5MUJAZM+b+wiVKw4DyJT
         gAm3HQkDD6NH3kByuD8lvWqNp1anJtVhRD5+kHq2lp7hHRghe5VG0Hjm6u9zX2dTNms7
         imJvw9XG3Eisrr5gsIzvGsBf+98WnmYQNKPpnIzmn/QRYTDBGL+QfkAHfyPhXnbxqDY/
         3KKllH+Q7j8Hpo8lOkila0mbdA4KxF6SdbNbZiD5qzVQFaP8q5Suj3rLW1fQ62lSeatk
         ZX1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWjJY0k9IjDFNcJXeBB4gur9oeetYQRQCT/q1iCswLNjJGNn8U4Npb4+tZg5cyNXa2jDi8bQ==@lfdr.de
X-Gm-Message-State: AOJu0YwVmea99LtqTaGn1Z1mzgqIVx+FVok0uTs4V2qME4zJlVNZxJAm
	K4PwQFO5RaQBFLyG3IFJ7tDkJc3Jn5JFOIqRT9fn/iDGNgffVRKy
X-Google-Smtp-Source: AGHT+IGCZR6LsGt8A3MbnbR48l89IbMXoa1NA5fhWEalTo/W2VtbsZcL4ig45puAzCdFOxNGhYs4IQ==
X-Received: by 2002:a17:90b:3b4b:b0:2d8:89ad:a67e with SMTP id 98e67ed59e1d1-2dbb9dc7906mr14065423a91.1.1726455267719;
        Sun, 15 Sep 2024 19:54:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5792:b0:2d8:8cca:31b4 with SMTP id
 98e67ed59e1d1-2db9f63f17bls2929386a91.1.-pod-prod-06-us; Sun, 15 Sep 2024
 19:54:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX9Netokt+lMHMo+nfW0uGAdnBX5Tml2lWIZmDZgxahc+qQLJo8cudB8qvy2sBeR43MlwTuVv8SwAw=@googlegroups.com
X-Received: by 2002:a17:90a:db82:b0:2d8:7182:8704 with SMTP id 98e67ed59e1d1-2dbb9f3a6d8mr13024101a91.31.1726455266341;
        Sun, 15 Sep 2024 19:54:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726455266; cv=none;
        d=google.com; s=arc-20240605;
        b=iZ802vOcDVwl7CAMauSXLGyyQH57c3DLnRndnAqScyc0TLpMeU9YaJR//j4uxcNc7t
         PeEdU16qfs3KjY0thDsS/ln2I7tffsi1nNVyrznjslEnosYGD3fzxJvchL4n8FBLuZ3F
         iB4xPdE7kQyOzVsBxgh0ySXKq8LkhM5u1ND/N2vngwUPFGZCoeyYYANHgLQ4OqLBdgEE
         eKUjtptlfkxuqaDpSrvUvTTK0CLDHgcat8W1z2oer/0dvkn+MVK29q4HLHI+/pjX10fS
         xB7fHmq4W2wVlhlZtsF05fcS/txiwkOpnsC7wocsmBNt/t+QNMC6Ftms5I4g0WCCVAXK
         YR9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=aSGQffOnlhi3sEaefWqk72mIRc2988CMejH485cXMlc=;
        fh=tGrD3M7hGvXEkQBpviy74/QXxoKT3zBRUUF9Zfk1MHc=;
        b=VPiCCc2d6rfLO1MnsAxxxNpGF4ayUVpH/bePrvyLkRUiE+oxLHtI9qxv8MPrdbvTLm
         3t6qW86M+u4+p63abqCRmnHgha6kRseUs0DI8c16ZmQerl1P1jdHKJfp05dGfY2aZmXr
         mrKDPzALp7Z9CgB/IQzUiMOlBcoyOYCyM5pkXOxgVBnR4jfGAS1p8wYGpr4pZ6P2+LLv
         pu+FnYp3MYq6iZJKO+ZwoijSUyHcrnjcEr/XwpQ16D4yt/LvSH8ZH7vbCR9qliepI0j9
         yIiO54Ueh3kY0kVpbOSYdXKtvzkWetCMwlCgH1VZI9Gpftd1cz8I3M+RctC2tLqobLRl
         Uoqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2db6dc9977asi978943a91.1.2024.09.15.19.54.26
        for <kasan-dev@googlegroups.com>;
        Sun, 15 Sep 2024 19:54:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 85C611476;
	Sun, 15 Sep 2024 19:54:54 -0700 (PDT)
Received: from [10.162.16.84] (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5DAB73F64C;
	Sun, 15 Sep 2024 19:54:20 -0700 (PDT)
Message-ID: <9d3286bd-7ad4-4472-aa26-2fb7d166fceb@arm.com>
Date: Mon, 16 Sep 2024 08:24:17 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/7] x86/mm: Drop page table entry address output from
 pxd_ERROR()
To: Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Ryan Roberts <ryan.roberts@arm.com>,
 "Mike Rapoport (IBM)" <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 x86@kernel.org, linux-m68k@lists.linux-m68k.org,
 linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
 <20240913084433.1016256-3-anshuman.khandual@arm.com>
 <8e8a94d4-39fe-4c34-9f5d-5b347ca8fe9a@intel.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <8e8a94d4-39fe-4c34-9f5d-5b347ca8fe9a@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 9/13/24 22:51, Dave Hansen wrote:
> On 9/13/24 01:44, Anshuman Khandual wrote:
>> This drops page table entry address output from all pxd_ERROR() definitions
>> which now matches with other architectures. This also prevents build issues
>> while transitioning into pxdp_get() based page table entry accesses.
> 
> Could you be a _little_ more specific than "build issues"?  Is it that
> you want to do:
> 
>  void pmd_clear_bad(pmd_t *pmd)
>  {
> -        pmd_ERROR(*pmd);
> +        pmd_ERROR(pmdp_get(pmd));
>          pmd_clear(pmd);
>  }
> 
> But the pmd_ERROR() macro would expand that to:
> 
> 	&pmdp_get(pmd)
> 
> which is nonsense?

Yes, that's the one which fails the build with the following warning.

error: lvalue required as unary '&' operand

Will update the commit message with these details about the build problem.

> 
> Having the PTEs' kernel addresses _is_ handy, but I guess they're
> scrambled on most end users' systems now and anybody that's actively
> debugging can just use a kprobe or something to dump the pmd_clear_bad()
> argument directly.

Right.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9d3286bd-7ad4-4472-aa26-2fb7d166fceb%40arm.com.
