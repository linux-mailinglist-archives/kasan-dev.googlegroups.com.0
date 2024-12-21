Return-Path: <kasan-dev+bncBCKMP2VK2UCRBFUZTO5QMGQERMDVVYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id AF5489FA0EB
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Dec 2024 15:11:36 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2ef79d9c692sf3697782a91.0
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Dec 2024 06:11:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734790295; cv=pass;
        d=google.com; s=arc-20240605;
        b=gOwmDBsj24dRpKpNUGGqAC5iU95UvE1Mnrkrgp9jq5H/+zYOEAEDC6g5lsE8DGY08S
         KVoD/tqR1vfhhG6iQZMvNpGlW41VvL0SKu/xpLMRD7HNLyu+CBDrR2bZl+h02iXtilSm
         8zbzPXByE2nHeNePrG4IV/6nRO3gfV/gNbNnozgtkXou+DgTXpLbZhWWIm/dPN+cpwTu
         2JKk3V9HcuFIEoaiQwUMqexTtaKFf1AdnrV/HXu02ZcS+qVs6Ux8Su4km/+imvTcDJVl
         uuwwBiAMdhNun2ixf9w9BMshq5CXtM38Qf6SOGLBiXctml41Pjc+3ZKNWxy01iX/+h0V
         QNaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=9eHrxzgxcAE2iFj9HaxjGlBPhnUSrd+ZTOCm4secCNI=;
        fh=qC7PgLRvXq3TOea7yja3lt2eeIE19UMnX6cf+BUJi4w=;
        b=MpD5KbxSWLalVuFMXhenaPKffHWQGhfT46D3S69wsVYZpebXChENOZio5eZTRL4L7g
         PWZ8fPrA1mZjHhVAXqp9b6eTGSuH+QHF0VwY120ejNkhdFnFDGUqexIZCXPnc5CQzKI5
         q4k4JWA/fsVXBz77MqBLedt7MQiYiKs9/ymKHpvSqZik0Sv++bLte4whL/1VGQ4HJ6jb
         AvEGcMexkUaG40GLbxnTwZ1WKhf5BlmJSaodeDjK/8M0JZ8GgCXYvoMmbCxiN+6E805z
         3L+3VRM9Qw71O6Vj6lFhpGyMUQKqlJ06piHoUI8c7BfJZeeiWlpkfCEgr/J86qtwG5Y3
         8Jdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.210.44 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734790295; x=1735395095; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9eHrxzgxcAE2iFj9HaxjGlBPhnUSrd+ZTOCm4secCNI=;
        b=Tm8c1I3BfBSvs7rm04QtWVJUgjrvt0zz4hFTtl6eoy1jd3UG5jkVvQ6E60fxNX4e7V
         a39wPHmE6SrHj6vCwZbgwGepdsZJkJZ+Pj5PqpYlcrlUFzyTBbcxTGZi3X1Kw1YnEFEJ
         puUUlAJShV4fYwxjQUq3fXjeWNC+NCsrhKyftwE52JZfqDVMEpaW2VK03nRdjcY8Hq8P
         Fy2qwbthUbeqUeE2czA7UvH9pCiZZFEKLN6H5qWVwbUjagt8+wpahD+/C/0KZMZ6q6to
         3uzxMr6+ftiquurXy7mW2GhXRVYp6TLs3gOhdu3Rka0t521Bp4wR7P9Dbn4ffbXkp4p/
         xOag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734790295; x=1735395095;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9eHrxzgxcAE2iFj9HaxjGlBPhnUSrd+ZTOCm4secCNI=;
        b=B0Obp1+c+eZ5Dp9NLIhhsYb7lhBtR6uLV2jO6IOWT3GXe6gEKmrLn6iRrhT5OQZxII
         QpbMbhkBbn8Dam6GrdvCDRz8YuymwM7uZIurtMD4tvIkDqDZKPymZ0rGVFXwNAq6UFKF
         diJnONLdZRPr6rJCO2oAhBy89J3vyc1+zbYHYjMyDGtWY7k+5VxQF7RfFLORUTYINeVI
         RBlTeRxwp2xYzG/5+SysDa4Z3QiiPGQS/KyohMjfm/jlOWyW1KVrdyQVVtYiClQSomgu
         wVwY96E7hbImce4NFbGe1oExLCpn2uWvy8iXroVKbtwcbmQHQr7e7cI1uY4Ke+H5MQ7R
         x5AQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeiZC3rYggzOvMt43f4XNrteNTx5ugIXouwbEobXTpvPw1lLQBpLy2RWXjuuk2f9rXuVAFCQ==@lfdr.de
X-Gm-Message-State: AOJu0YxfXfrqLPZ7Lze5VgTV8A64UffPF7b8fy9fK9t0oqRJTEihtZoi
	NA3HThoZAtvZOt2SFuObgzUKfXaMqMR1lJ7eaOsGqUBuhyRSKRtq
X-Google-Smtp-Source: AGHT+IG8AoCetKWJktijZ1H5QI18gs3Yvv0tt09SC3+zI07DKu5lFYWWbXNaoR8kQt6gORFzdG/gMQ==
X-Received: by 2002:a17:90a:d004:b0:2ee:f687:6adb with SMTP id 98e67ed59e1d1-2f452debd5dmr9229362a91.3.1734790294954;
        Sat, 21 Dec 2024 06:11:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:5250:b0:2ef:703f:6f3 with SMTP id
 98e67ed59e1d1-2f4430cb2d5ls1002334a91.1.-pod-prod-08-us; Sat, 21 Dec 2024
 06:11:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCULMcBPDbg8xiQZvy8+Wx22yf2Yp1qy6P+ax1IYjQXEzFoNhtXq4nzygFYt49TsWbKOYnZNCMa1uJk=@googlegroups.com
X-Received: by 2002:a17:90a:d64f:b0:2ee:70cb:a500 with SMTP id 98e67ed59e1d1-2f452de8f57mr9867773a91.1.1734790293099;
        Sat, 21 Dec 2024 06:11:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734790293; cv=none;
        d=google.com; s=arc-20240605;
        b=LOwB0XTvDS6ZokLHA2L7GFNGGbBbCcudemoXB1hRHZWgeKMVHeg5ZWkK9lW4P6EhOc
         RbGNG5tncphuHNvabguHVZv9YPd/2uYAqYHKcfAIzbf2ftVjxkNOmv8Uu94tZ7nVQ8xl
         LWEhTZe437E/AP7lEJfbMpCFUthLUPROEi0AcoF6fOrMR8mKWhIj3eP3rELu4Bsv7i+J
         Zh8LeoigVIsm/K1SfoKqIBGpEkq28dtGezJNkJElxnEfzx8gUR5x1ibLkvfu7v+m3C+S
         jV+QB0mSZVQ9TO5wpuBbDc5nFFkC4kZKZLUq00/Vl6mLdOv9HhCO1uTwiM8K8BhZRu+9
         s1sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=GpBog1LJdntPo57cyHdGkHydPz04prdcJbkki5MzpWU=;
        fh=efd6/aMKkw+iFSXbp3fT9ym6/x8Z6QFc1srNxhkYJDE=;
        b=Z2UoDzdKhf5+cdkR5hWMXm+HUFovKldPrfB7NSyV2R5EftzEDR3j+ZF32fizQ7Josl
         s/oYX4Y0tPjSDC/oz1XfNGTqNW50ErbLUjawopuVBtKrokaBLmkyFrb/4McLh3GPvOo+
         e1voczt4cpMqg84sCEgTHJZUIPNTH8tf6sEj/0QFZpRGd/zDyciamc0pRCKWeLO69xii
         MZ4hoXq8T7yUz2ZVdzDe2Pvo6kKTiYa302qOj0ayTvOhfsyzkDTjNN+czbVfCcAEK3QI
         BbE3lbt306W6+mKTCxOklSNmnsMH65fQd3dhSI4unu8StnjJ/pq9gE95CdXekrv+5FhK
         F1gQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.210.44 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-ot1-f44.google.com (mail-ot1-f44.google.com. [209.85.210.44])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f2db99ef30si440842a91.1.2024.12.21.06.11.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Dec 2024 06:11:33 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.210.44 as permitted sender) client-ip=209.85.210.44;
Received: by mail-ot1-f44.google.com with SMTP id 46e09a7af769-71e15717a2dso1469682a34.3
        for <kasan-dev@googlegroups.com>; Sat, 21 Dec 2024 06:11:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVdFqP9LFk2PcCmXAlc1JG3uWq7LKBJcMvS2x8FGFqfYH8ZauaNBvkbYvT/dD7Dws22Z1As5TFCwZs=@googlegroups.com
X-Gm-Gg: ASbGncve6WvFZx6pQ1RKue6CuB0dmejMG7roWAMwprg8I6TcykA14rsu8sUKeghf0DO
	JIvPwZO4vJIapC/0BCaqnETkxXqsDU8Kmf+KDGi+WERqyAu9TqUqwJsAXR6ybAWj63Q6+uc5Dbq
	jiscf04IP6UtA4POeqvLdX410GPi81ThLjze3H6Z20RIxMPuA5e8lTAWgY1lo9jhb0/CMBr9GZS
	buXTML1IWWJVCPMjsakD56EL0iS8ZHgtlvGMaGFNDNYGjWX97SxhckjzoWGpEHExcatrbeWqxfr
	uhJ4sLyfdRPY3evLu2A=
X-Received: by 2002:a05:6830:3744:b0:713:ce15:d4d1 with SMTP id 46e09a7af769-720ff954d14mr4080993a34.26.1734790292039;
        Sat, 21 Dec 2024 06:11:32 -0800 (PST)
Received: from mail-ot1-f42.google.com (mail-ot1-f42.google.com. [209.85.210.42])
        by smtp.gmail.com with ESMTPSA id 46e09a7af769-71fc976635dsm1274269a34.9.2024.12.21.06.11.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Dec 2024 06:11:31 -0800 (PST)
Received: by mail-ot1-f42.google.com with SMTP id 46e09a7af769-71e15717a2dso1469680a34.3
        for <kasan-dev@googlegroups.com>; Sat, 21 Dec 2024 06:11:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV5noX0Z8blhAVSikNlCg0AgsyzX8U7DBglt1wjboiHtCBQFsRFnZ1m1WHAONwyyVOMCUOHbU6AM4A=@googlegroups.com
X-Received: by 2002:a05:6102:cc8:b0:4af:ef85:dae4 with SMTP id
 ada2fe7eead31-4b2cc313a2cmr7064126137.5.1734789822327; Sat, 21 Dec 2024
 06:03:42 -0800 (PST)
MIME-Version: 1.0
References: <20241221104304.2655909-1-guoweikang.kernel@gmail.com>
In-Reply-To: <20241221104304.2655909-1-guoweikang.kernel@gmail.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Sat, 21 Dec 2024 15:03:30 +0100
X-Gmail-Original-Message-ID: <CAMuHMdXbB-ksxZ9+YRz86wazPGSM09ZFX7JZoyH--=UDndS=TQ@mail.gmail.com>
Message-ID: <CAMuHMdXbB-ksxZ9+YRz86wazPGSM09ZFX7JZoyH--=UDndS=TQ@mail.gmail.com>
Subject: Re: [PATCH v2] mm/memblock: Add memblock_alloc_or_panic interface
To: Guo Weikang <guoweikang.kernel@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>, 
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, 
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Sam Creasey <sammy@sammy.net>, 
	Huacai Chen <chenhuacai@kernel.org>, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Oreoluwa Babatunde <quic_obabatun@quicinc.com>, 
	rafael.j.wysocki@intel.com, Palmer Dabbelt <palmer@rivosinc.com>, 
	Hanjun Guo <guohanjun@huawei.com>, Easwar Hariharan <eahariha@linux.microsoft.com>, 
	Johannes Berg <johannes.berg@intel.com>, Ingo Molnar <mingo@kernel.org>, 
	Dave Hansen <dave.hansen@intel.com>, Christian Brauner <brauner@kernel.org>, 
	KP Singh <kpsingh@kernel.org>, Richard Henderson <richard.henderson@linaro.org>, 
	Matt Turner <mattst88@gmail.com>, Russell King <linux@armlinux.org.uk>, 
	WANG Xuerui <kernel@xen0n.name>, Michael Ellerman <mpe@ellerman.id.au>, 
	Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>, Stafford Horne <shorne@gmail.com>, 
	Helge Deller <deller@gmx.de>, Nicholas Piggin <npiggin@gmail.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Naveen N Rao <naveen@kernel.org>, 
	Madhavan Srinivasan <maddy@linux.ibm.com>, Geoff Levand <geoff@infradead.org>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Yoshinori Sato <ysato@users.sourceforge.jp>, 
	Rich Felker <dalias@libc.org>, John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>, 
	Andreas Larsson <andreas@gaisler.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, linux-alpha@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org, 
	linux-mips@vger.kernel.org, linux-openrisc@vger.kernel.org, 
	linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org, 
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org, 
	linux-acpi@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-omap@vger.kernel.org, linux-clk@vger.kernel.org, 
	devicetree@vger.kernel.org, linux-mm@kvack.org, linux-pm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.210.44
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Guo,

On Sat, Dec 21, 2024 at 11:43=E2=80=AFAM Guo Weikang
<guoweikang.kernel@gmail.com> wrote:
> Before SLUB initialization, various subsystems used memblock_alloc to
> allocate memory. In most cases, when memory allocation fails, an immediat=
e
> panic is required. To simplify this behavior and reduce repetitive checks=
,
> introduce `memblock_alloc_or_panic`. This function ensures that memory
> allocation failures result in a panic automatically, improving code
> readability and consistency across subsystems that require this behavior.
>
> Signed-off-by: Guo Weikang <guoweikang.kernel@gmail.com>

Thanks for your patch!

> --- a/include/linux/memblock.h
> +++ b/include/linux/memblock.h
> @@ -417,6 +417,20 @@ static __always_inline void *memblock_alloc(phys_add=
r_t size, phys_addr_t align)
>                                       MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_=
NODE);
>  }
>
> +static __always_inline void *__memblock_alloc_or_panic(phys_addr_t size,
> +                                                      phys_addr_t align,
> +                                                      const char *func)
> +{
> +       void *addr =3D memblock_alloc(size, align);
> +
> +       if (unlikely(!addr))
> +               panic("%s: Failed to allocate %llu bytes\n", func, size);
> +       return addr;
> +}

Please make this out-of-line, and move it to mm/memblock.c, so we have
just a single copy in the final binary.

> +
> +#define memblock_alloc_or_panic(size, align)    \
> +        __memblock_alloc_or_panic(size, align, __func__)
> +
>  static inline void *memblock_alloc_raw(phys_addr_t size,
>                                                phys_addr_t align)
>  {
> diff --git a/init/main.c b/init/main.c

Gr{oetje,eeting}s,

                        Geert

--=20
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k=
.org

In personal conversations with technical people, I call myself a hacker. Bu=
t
when I'm talking to journalists I just say "programmer" or something like t=
hat.
                                -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AMuHMdXbB-ksxZ9%2BYRz86wazPGSM09ZFX7JZoyH--%3DUDndS%3DTQ%40mail.gmail.com.
