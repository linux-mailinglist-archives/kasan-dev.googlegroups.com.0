Return-Path: <kasan-dev+bncBDB3VRFH7QKRB76L6LCAMGQEKQVYQOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id F1F20B24C66
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 16:49:37 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-b46ec2ebf19sf2852078a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 07:49:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755096576; cv=pass;
        d=google.com; s=arc-20240605;
        b=XRHUyU+smZT6Ql0R7CGsPTZhm5w3Sqd7y4Yj0CREsXy3v8UXvg7cr4YcBNq5CdqCLl
         13PKJqB2b16UqeENab9X8IH2ghrCszRJ1GzIkf/3+8mdnJKKEmtmwktyZdixEtzjP94U
         h1+gxuCslazlnfwS+OUw+IDyZINHS1MGZcTaOsR0yOtH9liQ3gMP83AN/Ug2UMxLfXKZ
         iZvfWsotys2z93RNh393mqMpqySxDPBFHXJ/4fEc9QH8Uz+wpOke/ebUIq/zpZ886U6L
         XM72s3T9HkdxiVtbGGsnNYQjqdiucE6i6tieJK4rrHHNp9L+PqoIjMtguGW1+EkJc1h+
         0eeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:organization
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=Fx8i3O/yDz054d31jZXeFunmEKb/NJREsNsL/zW3/18=;
        fh=ZEaAkrmn0CbPuFhuRNe3ssiNQUzaVyVt1aKQoLBMZuY=;
        b=GQt4jJFX9vCi97EVNSO1c26y/6Ugg0xWmYp+MBAO8M1nvgV2PiTrx717ng1rF9j8S6
         Gb6TFBtAu+OOPXjYC0M1/qpsk0Hq4Co0wHEIUyTuk1X+yD0J+lUfvDX057Z92iROMoht
         jCdRHn4TY0aQ0XpWZrGYcBp10cDajTQrcs4FwIEI6MGgTEdcwkJiCnZuCsF+VISHeBuv
         /+7DnCuQbLMA+dW9Lr+Bps0NLosLyqakTy7v+1OXB7p5rOxjNOis9afP9IpFWP8v2Mtx
         0JN3nGWZ+sysxr8nsKK9OT2Y3Q94S/BQ/i7bEqAYkQdtMvPx46N3bKYWvYgAeRe72nHu
         vwAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755096576; x=1755701376; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:organization:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Fx8i3O/yDz054d31jZXeFunmEKb/NJREsNsL/zW3/18=;
        b=ktERNWz/N0RkW8x4nNhEzZEO70k9aYZxgcX2eg3yaSTT330Cskol0BUFBWcbJqQAmq
         XXg7lkQahX39DvL8cj8HdnCVHjx7RV89fssm9YYMzWUyOozQ41L8EBM1q3AtpWj71ksO
         PWka3isxnTzwjbZirN9HTFUdJe6dK0nlIXX3DaZWPSb7l+OTlxNNuQMmyDC3DUiabI/r
         8biX04CqisQhdvRDZN9LqrHZYlGPphXLU7kbDpqhuNuh8qTcrKDv3zCYdVlplGmWUpEd
         HrOETVypx9hizx+a/+eAitBoLDynvlsO5Z9/CovU1HmuaYNDSBPPn4oYag9StoBd0BYR
         YBug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755096576; x=1755701376;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Fx8i3O/yDz054d31jZXeFunmEKb/NJREsNsL/zW3/18=;
        b=SHXRDiB64v3RAxhzgPhybMrn++2Q0f5cgoORjxJxrh8jbt7wL9s2jfP2e4Esj8wOwn
         0ElBm28tAmZauXMw/kTcpyqNHCGhGe3tMk380b1ZB9tqnX25dSiCnh4DlfSfrg281xrT
         7lv5hpfGSzVTiRSmxPmedUvQOH65bVZBqHWVHDx3W++9uj1SH9tYQaE00Og/3emmxxa7
         r9ARA5Mep+8Iz10Q1y6fLLRqDntnW3xVg7NsmyrV8jkt0+ZmbIZJwB6bLIU24NBhl34V
         jUUNCZR+ggQih0N+3DtYDhLXmjoladEwhHPjmPwhuAyQEaV5KtVqly08aj9vPS3ATszq
         o0RA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWC0+raZC4rf7/SwAA+gKByAelDPxDmUxz1Vmr7kZtuBPaQWOnCyHEWVqKIV1eGydySlEqDrA==@lfdr.de
X-Gm-Message-State: AOJu0Yy80NyPLAVjgiBEta0eO3WqKoaeFxyMQnc8RWB8yYrPnp+Q7aWZ
	PoPb1D7+WDmF4Dfxsqiupitv6Y8RwNzDpKSwIUtCVqFZ2DulE6XzJovD
X-Google-Smtp-Source: AGHT+IGiu+W38WN32boEPigYLdgYhWn5WR9saHPxAbBBHMSLTIO/nzuei0vcDD5viVRWLH8+bsB7YQ==
X-Received: by 2002:a17:903:1965:b0:240:2145:e526 with SMTP id d9443c01a7336-2430d10e2a4mr44694795ad.6.1755096576173;
        Wed, 13 Aug 2025 07:49:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeubrncDP4Wm9mzyeXY0kaJjennUwZ1BtoIOvr85pv9Vg==
Received: by 2002:a17:90b:52c8:b0:321:c247:f862 with SMTP id
 98e67ed59e1d1-321c24826c6ls2018632a91.1.-pod-prod-04-us; Wed, 13 Aug 2025
 07:49:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2l5d5J1dU16BqJ4sw6UHJToNYtyoF7ST6Xg+5Db2G54R19y+LA3S+86+c0SMX0UDmDqLDHGYMK1g=@googlegroups.com
X-Received: by 2002:a17:90a:e18b:b0:315:9cae:bd8 with SMTP id 98e67ed59e1d1-321d0eb2af4mr4061760a91.23.1755096574782;
        Wed, 13 Aug 2025 07:49:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755096574; cv=none;
        d=google.com; s=arc-20240605;
        b=cg2Tj2IM+iF1qJQ1Ly9xWh55VIDiPO+5YR9MCugZXBXmUhYc92upuG9bi+OKLlv+JI
         4wO0bp3byoXdlvoJAR+Vwg4DBufCcOCcs44AnmMWxUAU7aLfNPMCSF7sQLrMqCMxqCTd
         HGVQCI+zNupDyRwW/lZ+QJER4kC8oishuUMz1k4WdcjMA6Pzyc05dtWfZRQBLdfjKa00
         DkFtVCLCp7eglcElpj+o0Gwoiba8cpXPU2zSxwKTIKuho5XeqzmFLrAXdLGVGyWkdhGf
         NXztZUFSjWNr9jyxjsvIeyon57pAsz/whUafbixO33hxHdTQ3iCscuAF4pTbHzZFij1E
         W1/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id;
        bh=0tb+++lwvt7o4dnuA540qtPzkugVZMdbKd++k8Qh7w8=;
        fh=oaeHw1qMwC0mU/ri8FxDkoEgtWwNrwPpkGfOYJsYqwM=;
        b=HN4JED3BLcjsnpdz1Gvss9IO9yp91Wj7sfNlT7rRguW03OOFZ1Uq1cYQ4sZBahxFLp
         J7kp6S2xIEboD+kL8zewb9dPwnRw7RV9lMHAQJm0UI/GEOkSmWiXwEV+5mltzqx0ELK2
         ISNmfwR3PFr/fHiDVuU9MvfIJhRKoYzt+PKGRUCgcdS8mZO+clsVwddKZyfQlSX+bnGy
         +tNBmqKRkj21gLMdXqErP9+UzCUzOjoB5Cqb5wDMnI7/G2hi3IQhf/8Y/GsOFke1z7cm
         L+W06oIlZkJoXhORGeEFb/bqXQIHmSJfc8SIbL8GZklmQg2pyEGYgtSwiCn4URMrgzm/
         9LMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-323257d9990si17782a91.2.2025.08.13.07.49.34
        for <kasan-dev@googlegroups.com>;
        Wed, 13 Aug 2025 07:49:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A172F19F0;
	Wed, 13 Aug 2025 07:49:25 -0700 (PDT)
Received: from [10.57.1.244] (unknown [10.57.1.244])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4CB263F5A1;
	Wed, 13 Aug 2025 07:49:17 -0700 (PDT)
Message-ID: <31bac00f-7903-46f7-a5a0-1e8f5fd8b9ab@arm.com>
Date: Wed, 13 Aug 2025 15:49:15 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 13/18] kasan: arm64: x86: Handle int3 for inline KASAN
 reports
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: nathan@kernel.org, arnd@arndb.de, broonie@kernel.org,
 Liam.Howlett@oracle.com, urezki@gmail.com, will@kernel.org,
 kaleshsingh@google.com, rppt@kernel.org, leitao@debian.org, coxu@redhat.com,
 surenb@google.com, akpm@linux-foundation.org, luto@kernel.org,
 jpoimboe@kernel.org, changyuanl@google.com, hpa@zytor.com,
 dvyukov@google.com, kas@kernel.org, corbet@lwn.net,
 vincenzo.frascino@arm.com, smostafa@google.com,
 nick.desaulniers+lkml@gmail.com, morbo@google.com, andreyknvl@gmail.com,
 alexander.shishkin@linux.intel.com, thiago.bauermann@linaro.org,
 catalin.marinas@arm.com, ryabinin.a.a@gmail.com, jan.kiszka@siemens.com,
 jbohac@suse.cz, dan.j.williams@intel.com, joel.granados@kernel.org,
 baohua@kernel.org, kevin.brodsky@arm.com, nicolas.schier@linux.dev,
 pcc@google.com, andriy.shevchenko@linux.intel.com, wei.liu@kernel.org,
 bp@alien8.de, xin@zytor.com, pankaj.gupta@amd.com, vbabka@suse.cz,
 glider@google.com, jgross@suse.com, kees@kernel.org, jhubbard@nvidia.com,
 joey.gouly@arm.com, ardb@kernel.org, thuth@redhat.com,
 pasha.tatashin@soleen.com, kristina.martsenko@arm.com,
 bigeasy@linutronix.de, lorenzo.stoakes@oracle.com, jason.andryuk@amd.com,
 david@redhat.com, graf@amazon.com, wangkefeng.wang@huawei.com,
 ziy@nvidia.com, mark.rutland@arm.com, dave.hansen@linux.intel.com,
 samuel.holland@sifive.com, kbingham@kernel.org, trintaeoitogc@gmail.com,
 scott@os.amperecomputing.com, justinstitt@google.com,
 kuan-ying.lee@canonical.com, maz@kernel.org, tglx@linutronix.de,
 samitolvanen@google.com, mhocko@suse.com, nunodasneves@linux.microsoft.com,
 brgerst@gmail.com, willy@infradead.org, ubizjak@gmail.com,
 peterz@infradead.org, mingo@redhat.com, sohil.mehta@intel.com,
 linux-mm@kvack.org, linux-kbuild@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, x86@kernel.org, llvm@lists.linux.dev,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, Ada Couprie Diaz <ada.coupriediaz@arm.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman@intel.com>
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
Content-Language: en-US
Organization: Arm Ltd.
In-Reply-To: <9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi,

On 12/08/2025 14:23, Maciej Wieczor-Retman wrote:
> [...]
>
> Make part of that hook - which decides whether to die or recover from a
> tag mismatch - arch independent to avoid duplicating a long comment on
> both x86 and arm64 architectures.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> [...]
> diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
> index f528b6041f6a..b9bdabc14ad1 100644
> --- a/arch/arm64/kernel/traps.c
> +++ b/arch/arm64/kernel/traps.c
> @@ -1068,22 +1068,7 @@ int kasan_brk_handler(struct pt_regs *regs, unsigned long esr)
>   
>   	kasan_report(addr, size, write, pc);
>   
> -	/*
> -	 * The instrumentation allows to control whether we can proceed after
> -	 * a crash was detected. This is done by passing the -recover flag to
> -	 * the compiler. Disabling recovery allows to generate more compact
> -	 * code.
> -	 *
> -	 * Unfortunately disabling recovery doesn't work for the kernel right
> -	 * now. KASAN reporting is disabled in some contexts (for example when
> -	 * the allocator accesses slab object metadata; this is controlled by
> -	 * current->kasan_depth). All these accesses are detected by the tool,
> -	 * even though the reports for them are not printed.
> -	 *
> -	 * This is something that might be fixed at some point in the future.
> -	 */
> -	if (!recover)
> -		die("Oops - KASAN", regs, esr);
> +	kasan_inline_recover(recover, "Oops - KASAN", regs, esr);
It seems that `die` is missing as the last argument, otherwise
CONFIG_KASAN_SW_TAGS will not build on arm64.
With the fix, it builds fully without further issues.

Thanks,
Ada

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/31bac00f-7903-46f7-a5a0-1e8f5fd8b9ab%40arm.com.
