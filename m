Return-Path: <kasan-dev+bncBCT4XGV33UIBB5PQS65QMGQECYDVPLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 916249F9CFA
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Dec 2024 00:06:31 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3ab68717b73sf22229325ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2024 15:06:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734735990; cv=pass;
        d=google.com; s=arc-20240605;
        b=UZtJsPg+RFBABxxGnlWbodgF6GWhesaz+40N3Lnq4+EutuD1YDzEM4LgUZSGK5Ju9w
         VGDnuS/c4X+vDnlyYga49sdKLf4DxO8FYaVmRrQCpwKdCXeivV5OceXnJxeKNi670C+h
         ky9BDAlKex83SJWLj25IPY0N+upR5Nvua7qbqK1/h7T5o2OzOVvmy/NqW9OXqfqnfNoL
         qMvoHNFWAQr0Rpbd5ZiprqjIqlhEGw0QWidTnKbWdlYfjLRCgKieT6sPqeg7ePy3bUO9
         L+ALn2tKQNpZOqbeq19ziZpuLs+K7KvH8B1ow6YEjrdMyOyvdmoKshkgBXz51AoywL1S
         hjMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=cVWz5vVgNIaLLMDtQd3BouiiJXAo0Jcg+v9Z1ZlKJVk=;
        fh=rYh6N8CPMhtDB5XPTtwUxcCWI4jTboYlL8JhnSryu2Y=;
        b=jcnDzJIvnXN0FjkZrxWxSRgKWwsx8u9ES4XheomosQfqRxhGy2y9M/F1MNWzRIyxnA
         pi6GkPTbkR8Wwv4N2PuyfdI4NIK35Pa/8ifIjnOouK9fGyK5aX2YcFgXlooOUqkvU/dG
         4yDggn/j1oN3kak1bgkbADF9cW8JIM2WC1kF8yu1+IkeJI34mzVNP+uGKBwrZS4qWcDO
         PbhTiokBj/BZn/UxpeBb+9OeJ6nkNvcUauJrfbfa4Er6y72A9Rz0MtM+Hc/26dXNNFuU
         8k0YnTkFqknDG1ZVfN0GC4Qivxngxh5Q9XmB1QyrQWIqmU08hFRSfGMS5FnOlfmJ7x44
         rkLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ko0NoC85;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734735990; x=1735340790; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cVWz5vVgNIaLLMDtQd3BouiiJXAo0Jcg+v9Z1ZlKJVk=;
        b=N9m8cNu4sPMWMeSMW3czuXvrtW94IcyQGlWjsRjZ/786ZaAMEj9UxNbtW9o63u6bUR
         zabl/n1EXdOWU/rKPxSXNbwk86tSAfNixfvEqLjOyOQxuGNuiRNUeyEd+niqZr7wPZvg
         5u1PPoaouAF705WuMsmkzPLAoVu6plpCAjtYQ0v9Q9YvF8uSfQG/OGRgKCjQoYYAMceU
         h91KCj7w6SYpDKRP9sfRH/SV+S3QTVkIU+CAo4726MAXwLnZxUaa3UdeoXGmcyas5isk
         V+RdwjFB6skWDn11TFlMhtl0/j1L171ZBY5K9m+UJjTo7RoBmO7A+CCes7A0JxSFdI0V
         guSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734735990; x=1735340790;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cVWz5vVgNIaLLMDtQd3BouiiJXAo0Jcg+v9Z1ZlKJVk=;
        b=xB4VteeSS+Y7ZXd5/aEB8XesuwgsdRCTvSkd9rc6RdQf8b46MZ2KTmuckcrfxAKwef
         /z5IwF5JrlPdhXw8Jp3Fsjdd9e4SB6BenszHr2qrzPipUl8lgjR+kCQ0dgn3ebfn0e7C
         D1j9ZtKge+fwsjpDyvzfBgCRAYoUKekQ1msj7jYusQb1lolmEQjsa78Av+UDPCN5heOw
         rqP4Nj5lfIwyUcedCH0SH8Um+2DGuwvBFMKVd1rXLCvhZe2nedC4ztfCXzlTNcObihxX
         6hk81t/W9UqcPVp7E1wtMePXDHWQQ02mNfiPkOdv7caCZ0Lf+pKnvyEFjgKd2YS7rpWa
         /ATw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQtfX9t0hVISi7be1lsPnpGi0pDHvjvJlCT5EOEhmuKHdGDPz74kyZeSgeUEIskXZWrVjNGw==@lfdr.de
X-Gm-Message-State: AOJu0YxKcrTExu03++b2PUU7XSQ8jiw1o0nl1jAjK+PXhFeWKhXLFi8G
	eUQ12gLBO17vzsuCuGrNKiftvH3E0F7NwVdre2x5lmcskgsnb9y6
X-Google-Smtp-Source: AGHT+IF2pzEERiIO9yA46iVg9FMkMcngIENrNW8vgd1I2EURb9ja1pPQyucvP8FA3TQMoXzYzcLApQ==
X-Received: by 2002:a05:6e02:20ca:b0:3a7:86ab:bebe with SMTP id e9e14a558f8ab-3c2d514f966mr49201485ab.16.1734735989839;
        Fri, 20 Dec 2024 15:06:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1582:b0:3a9:d878:72dd with SMTP id
 e9e14a558f8ab-3c026118060ls2968105ab.1.-pod-prod-07-us; Fri, 20 Dec 2024
 15:06:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUcPPe/750opK5V8AKc8acaCZK8HGiFknnYLm9hVtZsBEbGXXGtBUsO0FD3mtp6tPLsC70WeuEW5M8=@googlegroups.com
X-Received: by 2002:a05:6e02:20ca:b0:3a7:86ab:bebe with SMTP id e9e14a558f8ab-3c2d514f966mr49200985ab.16.1734735988609;
        Fri, 20 Dec 2024 15:06:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734735988; cv=none;
        d=google.com; s=arc-20240605;
        b=V8+5+dzvscf5Jk41Q4bjde7/Jyn1jyIVo0uemexaypi+r02V12IBa6JB/YW3v07dEo
         vSCDLLmkIKneJB6qQ3WmyCzKDKKlihJwtkwjwoK8aBGQS81t/ZUuCG4NDfcAhEPXPLtN
         vHbRPOrANvw2/3ud5h7iV569vC+EnrZJ+FBN8bavW28lFA0Jo4yM98MuZzgYvorrxuoX
         13xqLSr63DoCuA0GV6VJd0kwXPnYSQQo2HAp3PI3zCUp/lh5qBOTr8jvXHQYDHOSxju6
         D6R4BiBL7ikT/upOSN94VT8cpX51pl/Y0dC1jJs9BmXHruYNQ5vGYFbwaWC5z1ZSCNuh
         r/nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EwcaWmbpAr7Tt6bNh0ZEoMJ/C6ZMgwB9Hii3xy1Ro3M=;
        fh=V9wSnA2eeIZLkOEyUdNVgX9VeD2LxF/p6Yl4jfh3FBk=;
        b=Shl/dIzzwq8ZQz7Q8mtYaSr3uajE1Q0Qk1RqSkHfDvMaOshfeLC69GLn8qoO3kPaXo
         5f3wZnK0wpJZmdZH+OV06Rb4sw7+W08pu/onRISi4XrPC0xTTvOpTq1EEYM3HJswUZIo
         WO91f2HM4uK4bIOQKRvc8jDf9JDpN656vrV0jhXjwcK0mFg5OO9D8S71Zk0Am41osGeS
         ls2mrotg/g4RnVo79rtM50vy2tVP5in+lP/ZK74u3nHggbouVtRJwc59414rXePObGHa
         ZRFb2ipIIEOGSjiY554rZRJksLFnnOjcBH/IzywDzue20AU3gyPW0vSbZkPK6RRYzyCS
         Dihg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ko0NoC85;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4e68be23fedsi184273173.0.2024.12.20.15.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Dec 2024 15:06:28 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 683895C3B27;
	Fri, 20 Dec 2024 23:05:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 51D4DC4CECD;
	Fri, 20 Dec 2024 23:06:24 +0000 (UTC)
Date: Fri, 20 Dec 2024 15:06:23 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Guo Weikang <guoweikang.kernel@gmail.com>
Cc: Mike Rapoport <rppt@kernel.org>, Dennis Zhou <dennis@kernel.org>, Tejun
 Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Sam Creasey <sammy@sammy.net>, Geert
 Uytterhoeven <geert@linux-m68k.org>, Huacai Chen <chenhuacai@kernel.org>,
 Will Deacon <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>,
 Oreoluwa Babatunde <quic_obabatun@quicinc.com>, rafael.j.wysocki@intel.com,
 Palmer Dabbelt <palmer@rivosinc.com>, Hanjun Guo <guohanjun@huawei.com>,
 Easwar Hariharan <eahariha@linux.microsoft.com>, Johannes Berg
 <johannes.berg@intel.com>, Ingo Molnar <mingo@kernel.org>, Dave Hansen
 <dave.hansen@intel.com>, Christian Brauner <brauner@kernel.org>, KP Singh
 <kpsingh@kernel.org>, Richard Henderson <richard.henderson@linaro.org>,
 Matt Turner <mattst88@gmail.com>, Russell King <linux@armlinux.org.uk>,
 WANG Xuerui <kernel@xen0n.name>, Michael Ellerman <mpe@ellerman.id.au>,
 Jonas Bonn <jonas@southpole.se>, Stefan Kristiansson
 <stefan.kristiansson@saunalahti.fi>, Stafford Horne <shorne@gmail.com>,
 Helge Deller <deller@gmx.de>, Nicholas Piggin <npiggin@gmail.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>, Naveen N Rao
 <naveen@kernel.org>, Madhavan Srinivasan <maddy@linux.ibm.com>, Geoff
 Levand <geoff@infradead.org>, Paul Walmsley <paul.walmsley@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Heiko
 Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, Alexander
 Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger
 <borntraeger@linux.ibm.com>, Sven Schnelle <svens@linux.ibm.com>, Yoshinori
 Sato <ysato@users.sourceforge.jp>, Rich Felker <dalias@libc.org>, John Paul
 Adrian Glaubitz <glaubitz@physik.fu-berlin.de>, Andreas Larsson
 <andreas@gaisler.com>, Richard Weinberger <richard@nod.at>, Anton Ivanov
 <anton.ivanov@cambridgegreys.com>, Johannes Berg
 <johannes@sipsolutions.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, x86@kernel.org, Len Brown <lenb@kernel.org>,
 Juergen Gross <jgross@suse.com>, Boris Ostrovsky
 <boris.ostrovsky@oracle.com>, Chris Zankel <chris@zankel.net>, Max Filippov
 <jcmvbkbc@gmail.com>, Tero Kristo <kristo@kernel.org>, Michael Turquette
 <mturquette@baylibre.com>, Stephen Boyd <sboyd@kernel.org>, Rob Herring
 <robh@kernel.org>, Saravana Kannan <saravanak@google.com>, Pavel Machek
 <pavel@ucw.cz>, Yury Norov <yury.norov@gmail.com>, Rasmus Villemoes
 <linux@rasmusvillemoes.dk>, Marco Elver <elver@google.com>, Al Viro
 <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>,
 linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, loongarch@lists.linux.dev,
 linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
 linux-openrisc@vger.kernel.org, linux-parisc@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org, linux-acpi@vger.kernel.org,
 xen-devel@lists.xenproject.org, linux-omap@vger.kernel.org,
 linux-clk@vger.kernel.org, devicetree@vger.kernel.org, linux-mm@kvack.org,
 linux-pm@vger.kernel.org
Subject: Re: [PATCH] mm/memblock: Add memblock_alloc_or_panic interface
Message-Id: <20241220150623.278e8fa9f073b66dc81edfe6@linux-foundation.org>
In-Reply-To: <20241220092638.2611414-1-guoweikang.kernel@gmail.com>
References: <20241220092638.2611414-1-guoweikang.kernel@gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=ko0NoC85;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 20 Dec 2024 17:26:38 +0800 Guo Weikang <guoweikang.kernel@gmail.com> wrote:

> Before SLUB initialization, various subsystems used memblock_alloc to
> allocate memory. In most cases, when memory allocation fails, an immediate
> panic is required. To simplify this behavior and reduce repetitive checks,
> introduce `memblock_alloc_or_panic`. This function ensures that memory
> allocation failures result in a panic automatically, improving code
> readability and consistency across subsystems that require this behavior.
> 

Seems nice.

> ...
>
> --- a/include/linux/memblock.h
> +++ b/include/linux/memblock.h
> @@ -417,6 +417,19 @@ static __always_inline void *memblock_alloc(phys_addr_t size, phys_addr_t align)
>  				      MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_NODE);
>  }
>  
> +static __always_inline void *memblock_alloc_or_panic(phys_addr_t size, phys_addr_t align)

We lost the printing of the function name, but it's easy to retain with
something like

#define memblock_alloc_or_panic(size, align)	\
		__memblock_alloc_or_panic(size, align, __func__)

> +{
> +	void *addr = memblock_alloc(size, align);
> +
> +	if (unlikely(!addr))
> +#ifdef CONFIG_PHYS_ADDR_T_64BIT
> +		panic("%s: Failed to allocate %llu bytes\n", __func__, size);

Won't this always print "memblock_alloc_or_panic: Failed ..."?  Not
very useful.

> +#else
> +		panic("%s: Failed to allocate %u bytes\n", __func__, size);
> +#endif

We can avoid the ifdef with printk's "%pap"?

> +	return addr;
> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241220150623.278e8fa9f073b66dc81edfe6%40linux-foundation.org.
