Return-Path: <kasan-dev+bncBC7PZX4C3UKBBGGYZDCAMGQERW4FKWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 637EFB1B7F0
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 18:06:55 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-459e30e4477sf5814105e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 09:06:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754410010; cv=pass;
        d=google.com; s=arc-20240605;
        b=MOiUN+MuTxmd+ZoHnYp5ZcEf7x8R7j0XxDN9dxuzTstVQbIm2tNl0Y+YbWkrOI1TLg
         JklO6cFL50Rs2bL7hN9t/NYUiUYeRwwqw3KDjB1xGUgCZ6vEBd2Qsr7HehSEHVUuqsJP
         aszwX5Xss3TyL1zhro7opddAQYAaHH9Ugk7/OH/apcfj11IVNzmt+Te9RmsWRmEwJV15
         Q9NC9ouEqS/3nHYrnI/V7OuifHbt/MQ8Wl7HjxA5zoCMZ20NzJrsbeQ/Vr8V2tQx2k7t
         pf9RN6qAxdGHQRQ07WWREcyx0THuCwAabJSwvjpkCce8fmn9rTv9Aw/BBOzEToyXY4Qj
         8z/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=NpwUXbXhTAceb7Cm70nLa7Zn2+aPBhFjLCxWrOfl0SI=;
        fh=rzt0TYwnn6YxJU0LaLRjDlei/rzZuNwZzj4ZDTT2z9g=;
        b=RIwIpMMc9Fzu+haYo5qrHmn7DxlSIVfzgB1tnUq9lIHWaHK4SZq8rIsdzcFjg+1VoC
         hZWcys1dHWmYhxCMEZpRDLE/aLlCJM7epcmDJMbN2XI49yYh+qZHLts6EcQpJ8TC3br1
         PuyICIyJgd54YniPCOazILqMWj8LaOoW4PlGQgRBEWM/r4kOYVh7uct1bmqXn8Qw6Jym
         nevVEuwgD+xowPkg6G1BT2/OhzUq5kCG9fSH7NVlA6LEONicUEU1uz8h1r8y6YTWGSi+
         AIdygdP240Jzea+T7manZLXrI6aKvP9qsevYANtUD6x+0m6qR9Mg6BPGyA4yN+hBAJ0q
         aNcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::228 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754410010; x=1755014810; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NpwUXbXhTAceb7Cm70nLa7Zn2+aPBhFjLCxWrOfl0SI=;
        b=FHoAJHOwiagr5I9qFfQl4NlDpr+Qp+7kC76ISEo3FP81mKjQqZzNpC6/9Qtu2d9a+W
         YCejgSNpBMHUwym1xinMMdvDQch5ovNpbXh/JNSFcJkJJOnYjFChxh8KPw57XZPWJZRN
         rpCox5X6QHCfEQuTHHJ1ZfvaTXvebKyFSm2xB9Nqi1ZilSpRYhOeloo19urx2AP95pBp
         ksdaDfrSwrKYNZuk5nvzy7BAjHoZmT1Zd3o/BSYrd9O2JW0NmtrzEVSCbfHLFPvjSpAR
         y4UbRApCZP/PnqrhqT4OMIe8iufStnf8jnltcdCGiyoO/+1O6knOrsUNNA1JAhRKh6g+
         d4/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754410010; x=1755014810;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NpwUXbXhTAceb7Cm70nLa7Zn2+aPBhFjLCxWrOfl0SI=;
        b=gk+JxjtD8kIx+K8BYhRa64I2TGBM1uzBBaVT2RIKY594uBbwuntXigIpYSPkvmiwTD
         a3Deb/uvvcIF4jDKyRYwr01Qq44EaW4Wj0BmSHGA8MPNqQoGMcnYvT0gyH+8rudK/7VZ
         MDqMW2MdR3TuYz10omw4cIbwJlXjoQj04qDQkat63sq+R+MDpYWjoKTY7lr2loLgq8KG
         dpv/k7Y2yEuf2PvWtbF11AThenUgrQV9jgmdoredvUc4iuLjZUS6C5NLehLgsKof+0KQ
         AnDXipI2/bdlYzKsyYiJElgreIvvqwXbeKPtbm3pPUjvs3PsO3AaYNercNRMzppfDSap
         6mcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZ2fmbT4twkzDmELV/cafayWOwOeKNrsHi1Ym0ebrsyPBJ9feIbT+RGpNGWkCCQEc4zyIK2A==@lfdr.de
X-Gm-Message-State: AOJu0YyKYpgJ6mHfy6jY7fm+9MelJXr+ZcyRT84AqrfZJed4/pIk/x3r
	2Vj1yEo/TNiVcgHjeELT49aJn22JE+pTh3ddo0mA4u3XPm8H5hMk2hbS
X-Google-Smtp-Source: AGHT+IF11nEsgpdYCyjTQ2tehR3fgyO/3K6Yfg7OEl7LZ/uEc3jtfbyee7PTq7w2z7GcRXjzEFMqfA==
X-Received: by 2002:a05:6000:381:b0:3b7:9bfe:4f6f with SMTP id ffacd0b85a97d-3b8d94c47d0mr10174261f8f.44.1754410009457;
        Tue, 05 Aug 2025 09:06:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeIPyZjT9X4KgI2PdIXRgS55cg5Ty9GtMldSqr7lTzheg==
Received: by 2002:a05:600c:1d1a:b0:459:e1a3:c3bc with SMTP id
 5b1f17b1804b1-459e1a3c66als5724065e9.1.-pod-prod-09-eu; Tue, 05 Aug 2025
 09:06:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjSD8cuQgkZUR+mHsJqvRq9b7QdWpCUyApZgw6KERj4NEB+9QCV4CmzPr3ZrC8sKHc5L0lVkrWNLY=@googlegroups.com
X-Received: by 2002:a05:600c:634e:b0:458:bda4:43df with SMTP id 5b1f17b1804b1-458bda4468amr79411755e9.17.1754410005636;
        Tue, 05 Aug 2025 09:06:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754410005; cv=none;
        d=google.com; s=arc-20240605;
        b=Fxvm1Kp8BEjmqer5kR0SmJFPFIazo4DlsrgkeDOtBXVN9mHTLtEW1sJpKuySsgJ+0S
         8pNxVpugPbBVFbvIYKSaXpFDxDmVXiEdnQNdv6wtFGD6X14s/vqqwfk9ISjO8bXGEkR6
         lniKS5VO5urgAwP6ovbfwNace4Ed+sMFiI+BBe0CwlDZbWXgFA4aF6+yV4fGO85Y/rqI
         nykYEPcl5/tyjBQAJAovN8Hl0h6f0/fKtXlSfW2MzNIyq2ewgJhpbIxWiA3prwmOw2EZ
         I5O01w3cKj+lW7b7tRMVg9fzaAn3xWDh1xbQVV0GfdaJrGZixWwXrG1LMiD2LGzWXirc
         h69A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=YKKJDDtdxUXV0lV5aN6SeraxUcBFKLa1fTZ3jSmMfEc=;
        fh=0LdT809docbaHCTYtTGhdoHS1iP3Mb8dfEGi3J206Bs=;
        b=JEZk50IcTGvCzCKKgRvjbKJVM3Dj+ITu864HzxtZE8qAwsRqLhNbBCa2wa1QMAXega
         UUOgpHpGfynczDMBTQNedAUgF5EaCaxwSgMg8Gu21LRlnt9rQZXF0LpJ4SpqHz0sQiVf
         ApdqyWpk0O723ddqses5vGw65NCopFj6y/YW5FwOL45lJSGfDOI7xn1GhKM+YL8BlkMu
         JyhPhuioYfmGfSFK7D6bgaXh+TWlrvRljtURxt5ihyLX9Z9sNgZUHvAPyw+Tby0wcKp4
         JRYJs+OsXRkyY7WlEYY7kAn7yDx2UN9fAGiLG/2HGD1yE4hi4Rie/O2ywK51P3VZeIkv
         Oomw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::228 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay8-d.mail.gandi.net (relay8-d.mail.gandi.net. [2001:4b98:dc4:8::228])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-458b75c5450si2018445e9.0.2025.08.05.09.06.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 09:06:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::228 as permitted sender) client-ip=2001:4b98:dc4:8::228;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 417DE44427;
	Tue,  5 Aug 2025 16:06:42 +0000 (UTC)
Message-ID: <20c1e656-512e-4424-9d4e-176af18bb7d6@ghiti.fr>
Date: Tue, 5 Aug 2025 18:06:41 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 9/9] kasan/riscv: call kasan_init_generic in kasan_init
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com,
 agordeev@linux.ibm.com, akpm@linux-foundation.org, zhangqing@loongson.cn,
 chenhuacai@loongson.cn, trishalfonso@google.com, davidgow@google.com
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250805142622.560992-1-snovitoll@gmail.com>
 <20250805142622.560992-10-snovitoll@gmail.com>
Content-Language: en-US
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20250805142622.560992-10-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-State: clean
X-GND-Score: 0
X-GND-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdefgdduudehiedtucetufdoteggodetrfdotffvucfrrhhofhhilhgvmecuifetpfffkfdpucggtfgfnhhsuhgsshgtrhhisggvnecuuegrihhlohhuthemuceftddunecunecujfgurhepkfffgggfuffvvehfhfgjtgfgsehtjeertddtvdejnecuhfhrohhmpeetlhgvgigrnhgurhgvucfihhhithhiuceorghlvgigsehghhhithhirdhfrheqnecuggftrfgrthhtvghrnhephffhuddtveegleeggeefledtudfhudelvdetudfhgeffffeigffgkeethfejudejnecuffhomhgrihhnpehkvghrnhgvlhdrohhrghenucfkphepudelfedrfeefrdehjedrudelleenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepihhnvghtpeduleefrdeffedrheejrdduleelpdhhvghloheplgduledvrdduieekrddvvddruddtudgnpdhmrghilhhfrhhomheprghlvgigsehghhhithhirdhfrhdpnhgspghrtghpthhtohepvddupdhrtghpthhtohepshhnohhvihhtohhllhesghhmrghilhdrtghomhdprhgtphhtthhopehrhigrsghinhhinhdrrgdrrgesghhmrghilhdrtghomhdprhgtphhtthhopehhtggrsehlihhnuhigrdhisghmrdgtohhmpdhrtghpthhtoheptghhrhhishhtohhphhgvrdhlvghrohihsegtshhgrhhouhhprdgvuhdprhgtphhtthhopegrnhgurhgvhihknhhvlhesghhmrghilhdrtghomhdprhgtphhtthhopegrghhorhguvggvvheslhhin
 hhugidrihgsmhdrtghomhdprhgtphhtthhopegrkhhpmheslhhinhhugidqfhhouhhnuggrthhiohhnrdhorhhgpdhrtghpthhtohepiihhrghnghhqihhngheslhhoohhnghhsohhnrdgtnh
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::228 as
 permitted sender) smtp.mailfrom=alex@ghiti.fr
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

Hi Sabyrzhan,

On 8/5/25 16:26, Sabyrzhan Tasbolatov wrote:
> Call kasan_init_generic() which handles Generic KASAN initialization
> and prints the banner. Since riscv doesn't select ARCH_DEFER_KASAN,
> kasan_enable() will be a no-op, and kasan_enabled() will return
> IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.
>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>   arch/riscv/mm/kasan_init.c | 1 +
>   1 file changed, 1 insertion(+)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 41c635d6aca..ba2709b1eec 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -530,6 +530,7 @@ void __init kasan_init(void)
>   
>   	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
>   	init_task.kasan_depth = 0;
> +	kasan_init_generic();


This is right before actually setting the new mapping to the mmu (which 
is done below by setting a register called SATP). It does not seem to be 
a problem though, just wanted to let you know.

It boots fine with defconfig + kasan inline so:

Tested-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Thanks,

Alex


>   
>   	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
>   	local_flush_tlb_all();

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20c1e656-512e-4424-9d4e-176af18bb7d6%40ghiti.fr.
