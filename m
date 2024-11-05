Return-Path: <kasan-dev+bncBC7PZX4C3UKBBOWHVC4QMGQEBVJBALQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id AE0129BCE5C
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 14:55:10 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-53b1eef7359sf3711591e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 05:55:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730814908; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qt2JX7A+dc1+FSs//FgKg7tlokqRtDL1Vp6JlIUldMPfjytOCzAjOev5La5AtHWL/t
         LVkIylmggg8F/fz0rK/GAkF+CguRIH57EE85qVOtevzLuFSM1PjXuoNj7GItc7OLo7gm
         4xHl7Y4sV4xqVZ/d3tuYCupB73txFR3+4HfagfGHscKuWkscAaPmQqeTO2IghoQ/e6sG
         eOEIfCi8Gz/5iLEZ84TQwrV4d/Yz9ir4AK8kqXopGgWWGyy4Z3v5orUUNUccgLpkJ0qt
         VOBnuS5VSEako3kKWZTfpZV180kPfrBb/o+JiZTF+2WuIz4mUPnKTlW/5PabfVlDZIae
         Ge3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=P5na5ra+r+oq/uFmFDoO1w4QwB1zFQdi3tEqi+2rqhQ=;
        fh=DxIjhDyZjk/pCOgapzASNV1iwFzgVWKDvobiXVa4cgM=;
        b=GlxgfTZvvOqJ9dZ9TdUsxE71hqwHOSBYO/ZUPhmRoUuUOjJp86hgbHzSVMtFu1ID69
         /4hWlFJpe0Pxdcjgu5BeJsc5Bpmzn8TDjFPIQFRp4+RbYsWiFFdM3Hdod5AiNIdp4yMz
         PiOpsCZzBGEbPgLNPOERTC84R3q/Vje10d8+VQ0nQsX8wwhsrT/gNoTjcmchZoK/eCI/
         tpCjAc78SmjksZ1B8LG0TjSVieLAyVvd+1rc/Xb9LF9/WBxgZHHqRUuJnQLq+wI/Kv+x
         1A80XJ1DC3f1f4MX//UhcYQFFSYVefhkF6O0ggqDg7gfxCOpg/fVP2N1PleqUg49E2FR
         FvHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730814908; x=1731419708; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=P5na5ra+r+oq/uFmFDoO1w4QwB1zFQdi3tEqi+2rqhQ=;
        b=djisgdX/TX08W81DqQ+XujdU2esRvCddwvIqhsi+IpTJRBNenWHlfGksWiej52O6xO
         8XqLNB4qDshNuafdN5uL9YMPYZSluFVj25gobzQk6L3Rsm/9PsswfnqSwZWz2VdIKlUn
         LeR6xPAzWWbTGfZqPzrg2VvbJ7P3VHCYVsXntwlVkZATpLiSODA5uFbd/mfR8k97BsR1
         3M+MWNYwARezbt7sfXyKtBtsLmAjJMITr9laytnxSOeSahHBgIUNZ05sY6TteLbyKwSI
         AYxbAt+3GnBtiGMeMXD6mZItF/NHxnZmtXdwKiVobAd3whMnF39xZmzydLnQnJ1pFYqr
         XiOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730814908; x=1731419708;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=P5na5ra+r+oq/uFmFDoO1w4QwB1zFQdi3tEqi+2rqhQ=;
        b=D0r1Lrg69/fXss66PKNiDi70PLx0H7TAe0HhwuOGJuVawfUZopcIer+gvm6UUKRbps
         2RfELz7T15pxmny0U5pPuAOsx0v7QxznyRL//LsBy11xcZKgip9Ds7+9PLoVYJIvCN9B
         a8zqZ4EAUPku3YUEqKzQ5f2hs5yzn5owTk61db2glFqPdw+cZcw5AudEVJSBmXiLxfp4
         Wqad+f+elwQezLeNSaFEQHacnwoi+umOfl9ZgusqvZb022F9F6xIbODkB/C7sP8Y+bt3
         REhkKfsU81Q9uhcJwhO4V9hN0SogvnMke7EuFDazXyOQbhQr0mr9A3BpmiHtHOWMDyMH
         +IKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW+aJrGfEp5Q5TMpXSUPcvUDp2iFiAeI9OHk6seEqpcoGoJJyt6Rt61QHx4AlA5woOImwbI5w==@lfdr.de
X-Gm-Message-State: AOJu0YwKvDVRclu5DdOs3h33747tLaHKpp17FENBILQqWi3S/CIoQ9+0
	kyuEhE0wqzNirgctRY4jPsZ3wChkpNK+XR3D0hBajRfQwUp+B+G6
X-Google-Smtp-Source: AGHT+IFB2aYh5Wvwv2UP7gQr5wWRWccdM+epnFsk8B+44+7mR/Jg37TaxVGJSBS0QIC5W9UpeLntyg==
X-Received: by 2002:a05:6512:e99:b0:539:f760:6031 with SMTP id 2adb3069b0e04-53b348ec12fmr18274871e87.4.1730814907369;
        Tue, 05 Nov 2024 05:55:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e98:b0:539:fb9f:e573 with SMTP id
 2adb3069b0e04-53c791f8ab5ls656080e87.0.-pod-prod-09-eu; Tue, 05 Nov 2024
 05:55:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU8eRyMZCpKAhb0rysKJOhZdkAftM/+uf9EdrvcRvmLMjrkqSFIGF5r2X1jljqAZ7kF/k86eCp95OQ=@googlegroups.com
X-Received: by 2002:a05:6512:3ca4:b0:539:ea54:8d28 with SMTP id 2adb3069b0e04-53b348ec033mr17193308e87.11.1730814904781;
        Tue, 05 Nov 2024 05:55:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730814904; cv=none;
        d=google.com; s=arc-20240605;
        b=kevsT7dMhn8NvtcgT2UYImf255YRrvrblUDTxYgEnTaVkZbB/3x3Mx4yW05Vcibrqi
         psbgYfcjmdetL+W3gPYlijWEtn+YDZdhlWR6XlpBiBQE8mLbx2W1BTQXn/Yh2k5t3OHU
         giXRniOvoVgIONK501OTTW+SyMY1hgXDUkv5oIppOVa4IkMX78F7o2swLvfIWOEFOqLf
         PQCPmL7FIRWpGHLeU5HQS2Vqj8YOUTDd/SfULfe4GWzaAdJr4IHEsTLZZqcviX/DuJyA
         c5pAhAr94MOQEvSywVhOx2ExWvEkN6O7Nnfq003w6VWCjlnsc6IEvrbBQz7m1ajURhO1
         EtVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=rrdb5XyLg7NsqMJ99KX/uWDwOQC+nCMkJMaoujk6gls=;
        fh=wvldyurcQnVqad/CC8p6Yx1BbEAKW7gpyVOiaFd/g48=;
        b=TWdDAxsZ/YknhUHPIc3NDdPwVGDHVOdtWrETvIE45HTJzLJJB/Zc3++wCPaDJpzjgl
         6avTrGF8Mn//qqcocbRZcMkGibmc/8X3qdxZWSis8ivg2XXSD4gNBqarBcsj+4YRU09M
         CqLUR15S2VuCI4CkIz05qTfvrpnB5yGF5Z2TWjkdniXCdA6uEoXp31JxKcPhYxWdRt1J
         8jmP7vtNsz1hVnUn+ojEDSzXnMIWsZQvX7FSDwq6Xs+qi9uVPv/zCvVI1BajDXMul/Kq
         K2McLsUUllDHOstMSKTHuCJI71uzpU0UVHYvuZunThX6mhOvWAsRIiJC2pCwcDBUQreF
         dYXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [2001:4b98:dc4:8::224])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bccc6e2si197826e87.9.2024.11.05.05.55.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 05 Nov 2024 05:55:04 -0800 (PST)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) client-ip=2001:4b98:dc4:8::224;
Received: by mail.gandi.net (Postfix) with ESMTPSA id DFB34E0003;
	Tue,  5 Nov 2024 13:55:01 +0000 (UTC)
Message-ID: <e8cf563f-d840-4e33-9ca0-2fa734c9f6c2@ghiti.fr>
Date: Tue, 5 Nov 2024 14:55:01 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 7/9] riscv: Align the sv39 linear map to 16 GiB
Content-Language: en-US
To: Samuel Holland <samuel.holland@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon <will@kernel.org>,
 Evgenii Stepanov <eugenis@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-8-samuel.holland@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20241022015913.3524425-8-samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as
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

On 22/10/2024 03:57, Samuel Holland wrote:
> The KASAN implementation on RISC-V requires the shadow memory for the
> vmemmap and linear map regions to be aligned to a PMD boundary (1 GiB).


PUD boundary


> For KASAN_GENERIC (KASAN_SHADOW_SCALE_SHIFT == 3), this enforces 8 GiB
> alignment for the memory regions themselves. KASAN_SW_TAGS uses 16-byte
> granules (KASAN_SHADOW_SCALE_SHIFT == 4), so now the memory regions must
> be aligned to a 16 GiB boundary.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> (no changes since v1)
>
>   Documentation/arch/riscv/vm-layout.rst | 10 +++++-----
>   arch/riscv/include/asm/page.h          |  2 +-
>   2 files changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/Documentation/arch/riscv/vm-layout.rst b/Documentation/arch/riscv/vm-layout.rst
> index eabec99b5852..c0778c421b34 100644
> --- a/Documentation/arch/riscv/vm-layout.rst
> +++ b/Documentation/arch/riscv/vm-layout.rst
> @@ -47,11 +47,11 @@ RISC-V Linux Kernel SV39
>                                                                 | Kernel-space virtual memory, shared between all processes:
>     ____________________________________________________________|___________________________________________________________
>                       |            |                  |         |
> -   ffffffc4fea00000 | -236    GB | ffffffc4feffffff |    6 MB | fixmap
> -   ffffffc4ff000000 | -236    GB | ffffffc4ffffffff |   16 MB | PCI io
> -   ffffffc500000000 | -236    GB | ffffffc5ffffffff |    4 GB | vmemmap
> -   ffffffc600000000 | -232    GB | ffffffd5ffffffff |   64 GB | vmalloc/ioremap space
> -   ffffffd600000000 | -168    GB | fffffff5ffffffff |  128 GB | direct mapping of all physical memory
> +   ffffffc2fea00000 | -244    GB | ffffffc2feffffff |    6 MB | fixmap
> +   ffffffc2ff000000 | -244    GB | ffffffc2ffffffff |   16 MB | PCI io
> +   ffffffc300000000 | -244    GB | ffffffc3ffffffff |    4 GB | vmemmap
> +   ffffffc400000000 | -240    GB | ffffffd3ffffffff |   64 GB | vmalloc/ioremap space
> +   ffffffd400000000 | -176    GB | fffffff3ffffffff |  128 GB | direct mapping of all physical memory
>                       |            |                  |         |
>      fffffff700000000 |  -36    GB | fffffffeffffffff |   32 GB | kasan
>     __________________|____________|__________________|_________|____________________________________________________________
> diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
> index 32d308a3355f..6e2f79cf77c5 100644
> --- a/arch/riscv/include/asm/page.h
> +++ b/arch/riscv/include/asm/page.h
> @@ -37,7 +37,7 @@
>    * define the PAGE_OFFSET value for SV48 and SV39.
>    */
>   #define PAGE_OFFSET_L4		_AC(0xffffaf8000000000, UL)
> -#define PAGE_OFFSET_L3		_AC(0xffffffd600000000, UL)
> +#define PAGE_OFFSET_L3		_AC(0xffffffd400000000, UL)
>   #else
>   #define PAGE_OFFSET		_AC(CONFIG_PAGE_OFFSET, UL)
>   #endif /* CONFIG_64BIT */


Other than the nit above (that I think should be fixed though), you can add:

Reviewed-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Thanks,

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e8cf563f-d840-4e33-9ca0-2fa734c9f6c2%40ghiti.fr.
