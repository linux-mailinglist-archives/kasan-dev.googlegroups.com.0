Return-Path: <kasan-dev+bncBDZ2VWGKUYCBBEWRT65QMGQEQNA4LGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E2B899FA535
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 11:23:16 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-725e4bee2b0sf4757906b3a.2
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 02:23:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734862995; cv=pass;
        d=google.com; s=arc-20240605;
        b=EsTzZALzO3oHvb68lxTRcsXXvgV4U/8t/fJnEfnT/qnzScM1N3/AYQOXRq5D+mmZb2
         22mdkwKDWEeXhlhjstAjg5gmonbX1usrnUPWfCZX/fitgweglMq/qF8wsVWwffh3jxWZ
         IUf41J5YCnvCQVSyfxcDwX6a+/X/DnEQKG3SVih1xQi4iU1mA02Y8jz+6ui2xz8D9kBo
         4x4La7JFbzdqnyqn4kv5h/qZXov1PnIaONVAl2pFMkmKSd60swCY+fSifreY+ayN6ED1
         28D4oHwF01UWKDPVlveKxRr3JXCsBT5OVY3q4bde6ml4HIYBT0BUWyfbq2peNWQQNXu6
         8yVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=LOevxHcE9y5vVQu0elUug72U2HbngzfEyhq6IgBWbs0=;
        fh=XyaBhAUYp2lF5PzTds+2gNwdC0tDW2eI3/YkDw06yzU=;
        b=Va7Xeezz3BDwvnDiK+MR8ksaTwmFpaouin8EYelptTujoOIn/aCg3tQDPmLOhO5MX3
         l8vNue4LhPynhadlC0EXh9TlmXFMRsML5HU8CxXdaIIUM26P6XgTlsPbDh/B3CrY2eYI
         5nMNzSSMo97eUivybmLOqqS5AqKKmg/tchzYI/PThTpW3Cha5vJ2V5F4qz3HXkSfpAoC
         ycjnpDdueEx9Mus4Qcf0Ds1hqiUYlWhjc6HKJ9Pcwvyr4GOQz0MY+hLvCgt6OjjDJmA8
         sGqEkHRgM9/2dKr2+w/FWHL/abHbUXID8o6DGW1LGp3SdZqoGUGv6XQPCYCXMZjM3SgE
         WfSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dH2O5SkD;
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734862995; x=1735467795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LOevxHcE9y5vVQu0elUug72U2HbngzfEyhq6IgBWbs0=;
        b=r5Y3EKBHgo8CZXn/947MbW8D8uO54jCuP+ybBMCAKXI96bOZucRMgBWja22IadUUo2
         NLk18CnKBCOlOLDPuRXxtp41L+y+i04Z33a8ktbjpsMy0icqcKkhPZu3iOg25LfHwexg
         zf0P1iYeO+b3U/GtuNLe9n5WIq6vnstoquNRYsBk+yY9a7Gp2ck/azKCXwCxdE3sNCWA
         nXSRgSloYz0/gsSUE9p1yMq2IZIO53QlHGj3+3/XCeur5PILgxRl5M3GZ/ZBNgy4KKsL
         C1OoUv90BDw+nv2hRa36DIn/Mj/2qO4nlOKsWHABUh60b10HIJmNEmCUMPWrJgYGCJFT
         EYog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1734862995; x=1735467795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=LOevxHcE9y5vVQu0elUug72U2HbngzfEyhq6IgBWbs0=;
        b=nauSVOBQkNXEbSRCOkwDslbMRsSFR9eralXXctM29O+6eM4QF6Eno2OmvcX86JFXeI
         jcebmtwa09M9Lx0HQ2YScDnRHNGfMRihsaGnAUrRMheJNqsq+ANxmbTulTvfoIqafNMc
         mNAOjDRpZO/OZRfwLa/TpzUvjnR9BSWEK9JIascz4FdfzvM4sNapS7+9SEr9LXuKKfAb
         +mmbjjOtUrnuqSO1Qj9ToVXZLfrw4hAb6BjpmgX60AFk4QT91xQObBXO1k6gaX9ZuLQ8
         tY0cTJtLAPXpzovqTAgSn7SAcE/YUpJBDyAxaiZroEXRcpb+m9fSEt1wD5EVK0TZC6qC
         4kLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734862995; x=1735467795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LOevxHcE9y5vVQu0elUug72U2HbngzfEyhq6IgBWbs0=;
        b=QLsV1qrE4ZHTGc6HR8qkbICe/ywAnwHqy2VbOJgYbIw5B6YX760w0iHfOP4oQWHjFH
         betFNHTPtTAYS6397qURIUeit1QGzDNWXbYponm7vRveW3jZ8n2IozHyUIhOnHWghA5F
         t/uPyV3mjJf/2qCzLanTA+x9jonCCV2F8gzLuD4t6B3+FUYmrpsF6No7v1oClUZiNPvA
         PqR4cpgFwdco1eNhwTmI27QpEpQFoEy9mVrWzhVFYkxoD1lElzBt/J8NKfL1ouy8lfGl
         8tC3AEkBIFiqH4KvqOpx8iekcSmunyMWOmwcHht9CUjvSPdUANofmi6gBeX7+3z9IVKY
         n9vQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQjbS9fBWJ2PiyoAXmqK15SYdkqau00HOb4WW6ByeEYGXgrXmoLSJ5JfMYMZwX4raTja9R0w==@lfdr.de
X-Gm-Message-State: AOJu0YzlKiskOxHi8RkhLB9cSAMzTNUUe3SmdT9byUl3ZZAO7DbBVJAB
	cDLU/KbJ4Shoqhdsn1pXFDYKkiNnTAffDCNgxIdFA7GxltYJUpm6
X-Google-Smtp-Source: AGHT+IHi8XnUpqClgr+ClDfB8foThWRgy4Ri5UAWLE5SHpW7ct3rVjaigJSDKUNEdjbt8HWcTtQpsg==
X-Received: by 2002:a05:6a21:680d:b0:1e1:ac4f:d322 with SMTP id adf61e73a8af0-1e5e0484559mr15009960637.14.1734862995260;
        Sun, 22 Dec 2024 02:23:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:6802:b0:725:f409:d1f3 with SMTP id
 d2e1a72fcca58-72aa994c9eels2437105b3a.2.-pod-prod-06-us; Sun, 22 Dec 2024
 02:23:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU/IoqzDtT7oQOBnxBDQYzhP25XSxoUQ+zLxJnBDqDsr/Mf7QyrTAnoUAfyd9GtPxQFUG3zGTlgitc=@googlegroups.com
X-Received: by 2002:a05:6a00:410d:b0:725:f376:f4ff with SMTP id d2e1a72fcca58-72abde0b086mr13191543b3a.13.1734862993641;
        Sun, 22 Dec 2024 02:23:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734862993; cv=none;
        d=google.com; s=arc-20240605;
        b=YHCbmRWg8XFWM+csdQ5zMlLPkRVGg0QXSSwIyhTArAto3Q1r0YtgkPia1rUi0W9QSL
         +YcX6lHBlhvawq0wLBfkiwgtl7quE57auvYjhs0G0jK5ka8z9uc9XlJUwpXFtI6epuRe
         9NudXF2GyrZpjYkcgQ4efNKhvrXwcRMS+MSF0fkFJY6A8W25NI44X+uqJ//bjyru1cil
         eNbwQS/YDU4XaBpio84vNh2MBc0G3NxV44DY4zHWKXto8TSoTwGzhZVT96TibN4zKb/l
         KExxBS4YwkqK3WqlCH3b64Cmla/lrGitrEQ8wMrk6KptUKOcrRuO1vhOmw2K0ogZbhAj
         7Kdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/ONVNbxYIwyadSLDvwLNaPGVW+13KFD/yyNlBVYXNzc=;
        fh=Ks9NbKUojkutLzUSnJMS64YQ7rPc1/I06zCqUjfzGPc=;
        b=iXPH7pS9t++L+7QdlzTsLnP3pPxNEa1yud9sSD/LSspN3NCNDC8ecLRZmVXmEErO3Q
         lZ1dWCAuZUvhIYFSUojJmeLdNHrp4BV2crTelG6AegV0Vjw6+86GXzJY5LT9gJ92ZCAZ
         B558V7vDYT6qmi2gDmda9iVdLLbJnA7+eR8z/ZKiRU3noD5lwvc3njAgwNE0fVT+YoXw
         wPBb15cPDF1qO3IC+ZGCyAh3aWNqd5pYaQ+zKsKtVkwa1YIdDdsocI0eaFFbi1LBXm/K
         Cqhjthw5p46BLa9rTVs5ruf88xYNIdpYTUzq8cV+mWb49+ckd60ca9aPdzC8OmZC6DbM
         /7FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dH2O5SkD;
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-842c42f8faesi265798a12.2.2024.12.22.02.23.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Dec 2024 02:23:13 -0800 (PST)
Received-SPF: pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-6ef7f8d4f30so26337517b3.1
        for <kasan-dev@googlegroups.com>; Sun, 22 Dec 2024 02:23:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVetxwxe3Xr9PTG0BFGM27ftIqAmztKAXUBx/Kqf7qWLSt9Em2huomdqqyDS4rE5r05EiG1myxQHyk=@googlegroups.com
X-Gm-Gg: ASbGncslJjTsqozxCzcinXL+rUzOskKbm30bIqnuKVUCH4FULJ9ThRZlMPiua+wGeZJ
	sD5uW6HJFTwrg8QT4XCxHEs+UwgRfO2TrqsPcHbo=
X-Received: by 2002:a05:690c:360c:b0:6f2:9704:405c with SMTP id
 00721157ae682-6f3f8125edfmr74773997b3.15.1734862992817; Sun, 22 Dec 2024
 02:23:12 -0800 (PST)
MIME-Version: 1.0
References: <20241222054331.2705948-1-guoweikang.kernel@gmail.com> <Z2fknmnNtiZbCc7x@kernel.org>
In-Reply-To: <Z2fknmnNtiZbCc7x@kernel.org>
From: Weikang Guo <guoweikang.kernel@gmail.com>
Date: Sun, 22 Dec 2024 18:23:02 +0800
Message-ID: <CAOm6qn=L0GzX4z4Mak1LH6R4wD282dz6qafMFmA39ADaBuLJJQ@mail.gmail.com>
Subject: Re: [PATCH v6] mm/memblock: Add memblock_alloc_or_panic interface
To: Mike Rapoport <rppt@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Geert Uytterhoeven <geert@linux-m68k.org>, 
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
X-Original-Sender: guoweikang.kernel@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dH2O5SkD;       spf=pass
 (google.com: domain of guoweikang.kernel@gmail.com designates
 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Mike Rapoport <rppt@kernel.org> wrote on Sunday, 22 December 2024 18:06
>
> On Sun, Dec 22, 2024 at 01:43:31PM +0800, Guo Weikang wrote:
> > Before SLUB initialization, various subsystems used memblock_alloc to
> > allocate memory. In most cases, when memory allocation fails, an immediate
> > panic is required. To simplify this behavior and reduce repetitive checks,
> > introduce `memblock_alloc_or_panic`. This function ensures that memory
> > allocation failures result in a panic automatically, improving code
> > readability and consistency across subsystems that require this behavior.
> >
> > Signed-off-by: Guo Weikang <guoweikang.kernel@gmail.com>
> > ---
>
> ...
>
> > diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> > index 673d5cae7c81..73af7ca3fa1c 100644
> > --- a/include/linux/memblock.h
> > +++ b/include/linux/memblock.h
> > @@ -417,6 +417,12 @@ static __always_inline void *memblock_alloc(phys_addr_t size, phys_addr_t align)
> >                                     MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_NODE);
> >  }
> >
> > +void *__memblock_alloc_or_panic(phys_addr_t size, phys_addr_t align,
> > +                                    const char *func);
>
> Please align this line with the first parameter to the function.
> Other than that
>
> Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
>

Got it!  Thanks for the feedback!

> > +
> > +#define memblock_alloc_or_panic(size, align)    \
> > +      __memblock_alloc_or_panic(size, align, __func__)
> > +
> >  static inline void *memblock_alloc_raw(phys_addr_t size,
> >                                              phys_addr_t align)
> >  {
>
>
> --
> Sincerely yours,
> Mike.

Best regards.
Guo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAOm6qn%3DL0GzX4z4Mak1LH6R4wD282dz6qafMFmA39ADaBuLJJQ%40mail.gmail.com.
