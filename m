Return-Path: <kasan-dev+bncBC7PZX4C3UKBBP6CVC4QMGQE4DEDZRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 716919BCE38
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 14:44:33 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2fb58980614sf33123441fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 05:44:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730814273; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pfj5HdjGtOgieFg3w3a1gkBd4LxDUQAztvQpf5iiBSPijAGANYSBeZGdnlJtfscQoQ
         ga/qdKJGrac5vpRK8ZW/J13Z86f4GFSo4xSKAYVuuoEvEwnbStlWW5lfv8MIYDIFbyDQ
         JwaxGLtbOjjyhCw/bjfUZN+pnQ/zN1KjEfw4qUhkPDq76d3e25wtxVEjVaqa4nhIKVcO
         TJCsKdO9XwVfzYeqVKQ7EmD4KHWwDBipGUikU960fWj/arutrgHlXaqf5qIBu4imLEnL
         Q+Br5isE0wi6vWc8CKa1gbxVW1tYZbdryOZHEWkNCbAK57RXhlppelIEMr/F1mUOSNHN
         qANQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=VmVSza15UqxK+SP+RWo6iP4WgEfAx/AONhKtmREDVTU=;
        fh=QVGKHClhONdoURGlH97/F6qWKHfLobGsaRJLSI4q7g4=;
        b=jGFnzSeo6i2cEHANf7xPWIJuVCaXeJGFKC6V0GSGS+G2ER2Erl3DBOc9G8va0ihpn8
         XBSe2TZwG0sbxU48lSuhSpAkusZ7phlHZSd0hu/FZzB7+5QnHKtaAKru4Echewhf3j5E
         ahby13/VPHXgIq7tRiX/KxvMSEDoKoOqj/mQ1xEx9YkSQHQhzeK5espikvgu6OIcLUsM
         hThc2Q+qXLyoX1A9JTFGSrGgSqekLKa7zMdXuUv1tTvONeGARKYQb6BzzNMXuxUXKxyu
         WXz1bRoeHw3KwS9kUZx8Runhr9NEKJyuDf1rTrs+H24PjO6HDYtSo8F5UUVX4UeILdc6
         ypOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 217.70.183.193 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730814273; x=1731419073; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VmVSza15UqxK+SP+RWo6iP4WgEfAx/AONhKtmREDVTU=;
        b=gMYg3EcU9CGvGC+ZUd3ICch822BF0OJNNhxcnuSLK/cYdgUZwx1+Bl9AA+mogvEyTy
         6JLfFqRdu9aI81iPRzzzSsfqLMiVwz5uQclCKx5nnjfGJW2VLJAnvA0MrwxAOgeACk3i
         4lu9nORkLgA1mPLw9vdVnBjbH2ONywP3RTabpAiTSFSwHjnZ5SuLeRzz0ga1kg9WR/fr
         Ct89l6FQd7tE+hQZ6mE9NCfuUbu+BV5q5P9nG2WyD7LI5flRqY/rwBby7W6S5sSXm2C1
         3wAddThLyov+l8pNg6VBxlZxsIKeKCNbdBy6UeB/mNuvAY6Bc881p8UUzJvrwc7SGYuK
         aX/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730814273; x=1731419073;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VmVSza15UqxK+SP+RWo6iP4WgEfAx/AONhKtmREDVTU=;
        b=E9+OtbWFD7DuayL5ED7pr//AuoA2+TFLSqDTCT6/j1MiV0uTfOy7BShDAUd+/qSxSW
         No6YJgEixco73WnBEzlv4a8vhnpn4w81jqNfNtU2sg+roNo4rcBFCrPD1vStHCn2UQ7n
         3FkQG2FplkQftoDB44Hr4hlJgiZy8UbJ20ykra2jwDHDzsg8jHpHrJw8NJUCnWMy2rJV
         ndZPimLo5Iyg+FqSWiQNkFA7h3p+y2/MWbkjQhR9KVfscwP2kOfD+Ese6vkwjtxgFUe3
         ncojTxVwr8mYZHHnidGaOFNZ2WcZlmLnjYaIgK9oXkzerueYmIXRBcCaku8bgk4lbinO
         CQIg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4QDagPy0Q8dvHN8kF1kv6Y0Na+G51zEhMJxBkLswb1MUU2Puj6S95y2MKkhpwmHiTwtRXuQ==@lfdr.de
X-Gm-Message-State: AOJu0YzHNyzuEq45KzWd/E9+jXLZpm8hThB7MBt/H2s3qb+0pdMkn3eH
	Z1ISJ8YC9myJKqcOYCBdsPBRal29hKy1Sdv62HWFqumfujMR/gxK
X-Google-Smtp-Source: AGHT+IFsZ+MSmMFgqScI20OAzQgnGCeQT4HCiF4XFTbVSgmnmvEjlMywL28L43NK0dVaMaLhpZr4Iw==
X-Received: by 2002:a05:6512:2393:b0:539:e3d8:fa33 with SMTP id 2adb3069b0e04-53b85e9ca56mr10447191e87.54.1730814272169;
        Tue, 05 Nov 2024 05:44:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ca5:b0:53c:5873:6327 with SMTP id
 2adb3069b0e04-53c794f84dcls806868e87.1.-pod-prod-01-eu; Tue, 05 Nov 2024
 05:44:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUe9QDQ2Ht+KbFy0nB4dvnSbRYwbdkqDDRs/WLESxYiBSK0IIAJLQLBlJl6RT/gHEnJQkmreIL5p3k=@googlegroups.com
X-Received: by 2002:a2e:510a:0:b0:2fb:5014:c939 with SMTP id 38308e7fff4ca-2fd0df8461cmr86595231fa.41.1730814269645;
        Tue, 05 Nov 2024 05:44:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730814269; cv=none;
        d=google.com; s=arc-20240605;
        b=BVHj/DHiFIeV7Vb0ed067mSkKVgtrTiJIDNhnDPQ+2btKiCl3BYGKxMFar77wLd2xn
         uKenCQp+1bpgfiswBMtSAYIZnkC9StLRbNRGDsNFICqMSk0o3+kb9IIC0kt5+uj/2Wcf
         aRTRVHbO8KomAukuGZYobaGNiUTq11e2C093Vi7se+10dp3GhxltrbTgOpJ+Smrt75gT
         mj0Cv52AG6vvp+mPrpSOFRn+/qeg+UlwCcJMpgOBtdxKk0UBtEsK0g7+adnAdgYnxhBn
         exHr86peVqxuH11OvHAyhj52mP+1QJ9S4oaG3slvlm7FtGkLji/9J6PnjK3E3HhJl+PB
         HEjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=TetSS7jFoBp6Tin3h7L23IRUGsf90Xa/sZ5eLbt1uIE=;
        fh=wvldyurcQnVqad/CC8p6Yx1BbEAKW7gpyVOiaFd/g48=;
        b=c3R5nv2crnDCbwjgZ+lE3J8cuX1iDDiZIsD/PmQrQTNYtFKcrdP4STskomdFx67muu
         l4ddub4UDDJ/bXPcdhl/8wC8YVUyzgKwi0JiDyfOKJGN/Jvcr/9qNyQU5fuGDQomMzI7
         mVVXDAhtFyIjHI9DrWfj3bu4Mnmbsexgpk3qhLAg5luRTC1MbBuU0nQZx41mfzmfuX8q
         85jlegm7NfaeOpTpQazZ0h7v7jrTI54SeNeaEbfHGcyyyExwjb8LHFE+l2csy3KdjiLY
         zF3JCEvbUk7o0GS/84/wzAzBmi+l+0SY13FyjgkcJDjnD1nHngatZTWymPzo5iOODYMr
         mUvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 217.70.183.193 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fdef68cce5si2370431fa.3.2024.11.05.05.44.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 05 Nov 2024 05:44:29 -0800 (PST)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 217.70.183.193 as permitted sender) client-ip=217.70.183.193;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 21972240006;
	Tue,  5 Nov 2024 13:44:25 +0000 (UTC)
Message-ID: <5dba5a49-91e5-4988-9018-63b146b5e26c@ghiti.fr>
Date: Tue, 5 Nov 2024 14:44:25 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 5/9] riscv: mm: Log potential KASAN shadow alias
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
 <20241022015913.3524425-6-samuel.holland@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20241022015913.3524425-6-samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 217.70.183.193 as permitted
 sender) smtp.mailfrom=alex@ghiti.fr
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

Hi Samuel,

On 22/10/2024 03:57, Samuel Holland wrote:
> When KASAN is enabled, shadow memory is allocated and mapped for all
> legitimate kernel addresses, but not for the entire address space. As a
> result, the kernel can fault when accessing a shadow address computed
> from a bogus pointer. This can be confusing, because the shadow address
> computed for (e.g.) NULL looks nothing like a NULL pointer. To assist
> debugging, if the faulting address might be the result of a KASAN shadow
> memory address computation, report the range of original memory
> addresses that would map to the faulting address.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> Changes in v2:
>   - New patch for v2
>
>   arch/riscv/mm/fault.c | 3 +++
>   1 file changed, 3 insertions(+)
>
> diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
> index a9f2b4af8f3f..dae1131221b7 100644
> --- a/arch/riscv/mm/fault.c
> +++ b/arch/riscv/mm/fault.c
> @@ -8,6 +8,7 @@
>   
>   
>   #include <linux/mm.h>
> +#include <linux/kasan.h>
>   #include <linux/kernel.h>
>   #include <linux/interrupt.h>
>   #include <linux/perf_event.h>
> @@ -30,6 +31,8 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
>   	pr_alert("Unable to handle kernel %s at virtual address " REG_FMT "\n", msg,
>   		addr);
>   
> +	kasan_non_canonical_hook(addr);
> +
>   	bust_spinlocks(0);
>   	die(regs, "Oops");
>   	make_task_dead(SIGKILL);


That's nice, I used to do that by hand :)

Reviewed-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Thanks,

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5dba5a49-91e5-4988-9018-63b146b5e26c%40ghiti.fr.
