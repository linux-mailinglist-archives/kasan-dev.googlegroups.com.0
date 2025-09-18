Return-Path: <kasan-dev+bncBCSL7B6LWYHBBDFXWDDAMGQETDO2XJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CEF37B85530
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:47:41 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45f2b9b99f0sf6545915e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:47:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758206861; cv=pass;
        d=google.com; s=arc-20240605;
        b=gfDGQhxEbwdzvmKN1M6MVB+6UXnI7+IBXvqKBzRwdZyqFL/HO5vyfX8nMOrLSYLmBM
         fNGZ7OsUEIUFpqDygRxiIeitM5XY4i046iAVvhNrurAQkmNtCJoeRdx2wXJJip0PLvzU
         WDdstElMTSRrXLB3qvUf+xCCUhZfTCOIWKkJ7PtSDtS7gkWphXRWAYAm3cbrHidIOmGE
         /wf7hT2YV5VzfnCn4ecH5Qvqj6mPYa1wUgriHKnrO2zn1dDn2S33RWVKf46xamTZFyZa
         R3Wov50vmz0qH+rkj6eISKIIWI6HbFNL053eyfh3Kj2V76hNtWgKwppSY0+lRk6N7GdB
         i0Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=vOd6txHpYUxrDIZSsLmnPTSDBQJTCmXYlhijcEhdeBk=;
        fh=bsfJM6trLqJ42mqD2qCM+LqTeO35UDuXk7lhZ5flxSU=;
        b=ZEIo8n+E+FJGQAlJ+vELagx7Bv4IpFncwbczUPKnKPiCcCevFwGwEEBwTpoBDjWoSz
         GT1kvmyJe0fBfVKbIGbVVQoybChXMPZV/s0lpqB9LWUsQMAOL0UILAls2mFdHxKqaMPU
         XqzvNTTH/AqMwxLt93slh75OL0RgbYWvGD4rHilAMnvHisdpq2F7K3HExkHnmg1QPip4
         uwLWMMl8Gd3EqFmpkvJn7SY24OExiqb7sSk21dQZFnQjVmEUbuFji6AWS72NjsamdxUJ
         Hvc+cSjMtuRYjzQqRsvfc5BcTGezkBTU1o2aZES4cr7OCcvC4Ob8b288TycET5kKEsEg
         MRXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=naejQzPi;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758206861; x=1758811661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vOd6txHpYUxrDIZSsLmnPTSDBQJTCmXYlhijcEhdeBk=;
        b=Qg5SKmut+h5YNojOKs34EmZdTNABGjEvlfAPtPQGNKDuAQII2IQxeG6A1yBP62lvJh
         xQPM9RQtSMuxOyAfW8RBC97KxpWnhfgQipz66reczfS9DBq5PT0vMWkiMsaQkZK4iqVV
         GnBSYZENdzwKY9sMr7oBk84llXVPPlbUwbCHT4aseO60J+/NORIFO2ajk2eO5yP3WD0z
         FOCPjASXe+Db29kbiSVjzeWlax8/aRL5a7D9HJeMjQDKgyO7O4UzMG+1FVwySfLn967N
         i+tHw//MNWwAT8GqEoL0dkVEnAHxJctpJqaRP/aWv7KGaloQDdNGVvMw3EAXx6F2z+DX
         KABg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758206861; x=1758811661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vOd6txHpYUxrDIZSsLmnPTSDBQJTCmXYlhijcEhdeBk=;
        b=BOlqFrrXE9ch9UcZYXonV2fYJefmv6zEo/SyYCc4EcgCmx1msvSSTSmc0caOdxn7v8
         cKNi9MLmSd1Z8Ew8UeIN1PtORhB5YHVubs3qF4wmKNOGCdtVOePyA485ZQRAd7f/OjlY
         TC8o53IrY0HmlYPDgOrPdj/kDtNIM3vY6v74WPtaBrxkDJfJEIsZS8afZBxQkm3EM9Fk
         BkymLoi6g9GaS9SBbq9Pg3dTvUU/vXYWcNXcfQQwl0WqHiyDSlUkZQJfj4cNiQu+ejwM
         oKJh9lDUH1V3WgRJhR5aIz1YeZjQhy1wA5PpRB/NGV9aT7g9xnKcvYxF/tp0gL72Nw3N
         Fh4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758206861; x=1758811661;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vOd6txHpYUxrDIZSsLmnPTSDBQJTCmXYlhijcEhdeBk=;
        b=ji4NhQIoznTcavrMo9QTN8BBZt8wheVoNo3HPi0q/AFVGrOc644N2aXSjUMb+hrgyW
         UOz3NAONQQMlNyaUUU7WjDq6AqoNpla51x5ugk4n+9cDKWThJ+avDUyXKvqfG5J/BC3J
         zotqnlK7A1BsxqfVXk4lXqtR4hactcmW6sKb92Z1VH0L7J1t9s6ykAvt4Z7KENbv7Bdn
         QPoR6442n7prQrYsuK7htJdVH3mYHlp1KgvuYe3usgdznHIbko9PFgMhaTjUa7hGqH9P
         EzC2emeDVMrIW5SoaG8qf6UdUdW5OWJnMMnfCTjx6U8LYoark6szmhjuo9Ca8jV+s9ID
         ZC+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFE/oNjtc/1q8cYcAqg0ss2XUJc8nkH3vdkClCTqE13w8G1saHX85AWpH4h2g7uMo9vc9O+w==@lfdr.de
X-Gm-Message-State: AOJu0YyaNKPHsp1ocmvFCoheIj0jh8dVbB06bPqaXipEHj7oveA0MlHB
	iDq78TwieRPyBb0PWp1CE3rBXC57C5CLkGiK8DaOgQ4XnioA0m6sz2UM
X-Google-Smtp-Source: AGHT+IFBxFYDE0Ra6kGhZ4KJDQyDexX+5ZVqW4ch8aP6MRyuxazQ3v6fWlAczeDF2r6gpwr8qBaj6w==
X-Received: by 2002:a05:600c:1f92:b0:45b:9c97:af8d with SMTP id 5b1f17b1804b1-46503850145mr34827925e9.4.1758206861143;
        Thu, 18 Sep 2025 07:47:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5sSAgT2cTXXEe1hBbN6ego99UgS1KtONDI+3dxPg065A==
Received: by 2002:a05:600c:3e87:b0:45f:2b5e:865c with SMTP id
 5b1f17b1804b1-461322f7b0fls7746985e9.0.-pod-prod-00-eu-canary; Thu, 18 Sep
 2025 07:47:38 -0700 (PDT)
X-Received: by 2002:a05:600c:1f92:b0:45b:9c97:af8d with SMTP id 5b1f17b1804b1-46503850145mr34826715e9.4.1758206858365;
        Thu, 18 Sep 2025 07:47:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758206858; cv=none;
        d=google.com; s=arc-20240605;
        b=M8/50LYd9IgCKwhyxlkGt7ROJbMuslUpiKcvvLIfwY6MZ+1YGv2VE6gRVGbnNyYOK7
         JMsqXNsjdxAYUqegAd2bGTjqgEzEJOTU8Jz4wCMD092cccvtFd9MCqwH4ZdFR/mcP7Y8
         xoe8xS5u05mCsPLn+jGmBtZSfT697oYZ1x4nMC/0qB01GqSYe3Oz/u2jQH2Wpy2Z4M64
         UcMfyCye4rl7WfZX1Sn95w3BkpJlzu4BSUrusONS20kLBKfI8+dZIx4x+0tU5glOlSxI
         CmMIemzCwmKiMIdCgY3RBWNn/16tKjESskYltAR+dJrOQda4Gogvz9wetCuAjzq2f8Nh
         0TvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=UZUVA/eN8y4jUWH55g8+vAZUWm6iD5IWuaZ9B1DTE0Y=;
        fh=rwFBE99VPDXa/7mOBaqINSwNKDVTF369FkahNOFjaPY=;
        b=OlL+GOtHy6XxayXU6CP7dZpJX/tsN8YxliMk09kHauKKHYso7qoWMyQxCCKyCNyJTo
         Veis1XiicPiWUjZLg4Xo/A6WqVzEQMST5dyHihLb3xCJH6huvhBy+k4yNvp60MYYLIWM
         jrd1MKGHvAa3tQsBHYvWSP4g+m/22d7J3HuCegPfvGD9ju1Zb22FTn8+eOcFSKHyupI/
         wZG5e3jegGzQIWPzIkT+YZgBcyYIbl9FHRcMJoOaf6EyainY/6nJ+fp7nwD7ouB14NYV
         JmMG+asCg2Tyn/oIefNaxkza0iNuFyPbIpjFfFqHHY1iDhfqkSbbIewGBY9PoHPMwKqG
         QhkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=naejQzPi;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee0fbcabecsi44273f8f.8.2025.09.18.07.47.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:47:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-5796051ee6aso86727e87.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:47:38 -0700 (PDT)
X-Gm-Gg: ASbGncu8HwZCaLYMWuNKDtRKdVOq8DeAkFxpbO0Brr0v8akIDXD0NwEJb7MnCgLL8fm
	YlNQigBFECaHrPTdUE4cZmH+uzWu917P3ae+8pYCgnBm5my2iXtBhJhN34qNfFfEByQiaA5hiC+
	1zMs+EgUPY91fR41k35PzVBqX98/ksvU/SZK+Av9p5jl6kCZ9AqHSsefjjfsIGpC97pYl1+JbyJ
	sPdv0QhnNdhbDCVDz6BSvRk4Vmt8CuFPf4nkc+lSIli30Th38FIPbwBf+WZl0Iy2dCKWVUfPGYO
	Z4go6kdT/MiCV2lzoIhQo7yms+D/2OVnmsC+hd1kWEn4n1Or6qRs3QRGu5dyysznFd7MFLSBYst
	qiXOE4gW8NafevWcuLc8vDTgecm9eyVg+DSlx3Vb87Qi983E=
X-Received: by 2002:a2e:b8c5:0:b0:336:7747:72e with SMTP id 38308e7fff4ca-35f66df191emr9476411fa.3.1758206857314;
        Thu, 18 Sep 2025 07:47:37 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-361a2f7ebcesm6234871fa.29.2025.09.18.07.47.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:47:36 -0700 (PDT)
Message-ID: <dcd0c9be-5a52-480e-8447-ebb0a028edec@gmail.com>
Date: Thu, 18 Sep 2025 16:47:33 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 1/2] kasan/hw-tags: introduce kasan.write_only option
To: Yeoreum Yun <yeoreum.yun@arm.com>, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
 corbet@lwn.net, catalin.marinas@arm.com, will@kernel.org,
 akpm@linux-foundation.org, scott@os.amperecomputing.com,
 jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org,
 kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org,
 oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org,
 hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
 yang@os.amperecomputing.com
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
References: <20250916222755.466009-1-yeoreum.yun@arm.com>
 <20250916222755.466009-2-yeoreum.yun@arm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250916222755.466009-2-yeoreum.yun@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=naejQzPi;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 9/17/25 12:27 AM, Yeoreum Yun wrote:
> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.
> Introduce KASAN write only mode based on this feature.
> 
> KASAN write only mode restricts KASAN checks operation for write only and
> omits the checks for fetch/read operations when accessing memory.
> So it might be used not only debugging enviroment but also normal
> enviroment to check memory safty.
> 
> This features can be controlled with "kasan.write_only" arguments.
> When "kasan.write_only=on", KASAN checks write operation only otherwise
> KASAN checks all operations.
> 
> This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
> ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
> with other function together.
> 
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dcd0c9be-5a52-480e-8447-ebb0a028edec%40gmail.com.
