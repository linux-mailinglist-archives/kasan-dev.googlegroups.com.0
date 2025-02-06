Return-Path: <kasan-dev+bncBDW2JDUY5AORBF7YSO6QMGQEDXIAQHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AE81A2B012
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:14:50 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5440b4eb6b6sf705386e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:14:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865689; cv=pass;
        d=google.com; s=arc-20240605;
        b=dtd/mzA1fXmREMawzOd9YKOdUFu4HcPktadMZpQGEm9dB9lW7UMQpb8RdamYW6Cqwe
         gE43my7pKDMhYkfFeSDoY508XwAMPL+syfmoMWlxpOkn3bw6Kn0pRCPstbtF6E53aCDe
         hIgVKB/toSdYR7JWDyjGH7zbdF7xapApgu9fneHSfIIGHM9vaJ7igmYTpApSRHnF9Nh9
         DZoZwJCubuzcIl/zZ62U4prntsfom1Vyv8F/6abvR0yJ09qx5lG5No2FsTG5VsuJBbsi
         OBXItmbe7qZEupH7CVpTXoBqR08qSwFSDBjdQUkUF/kl+9ZPDL6f8DgUUE5ev3lrJrQP
         djew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=0aP+pliMhjIWql59UZRmok8gZc2bsYDxmx5v5Y86304=;
        fh=mBklsAVgBnSZ2knsaXO5jVqu9DDMcNq6Orxg+CQusIQ=;
        b=LR0ZVg/2u04dNKPLSjJmo/4fja/HoIA7V6jaFRF/o028kAYF7Y1h73Y3EL6LjzNoPe
         wRh/Cj+LRNTVFJu6n8ddSl3jMqbXUrtYrD9wbhkoBji/7U56m981UyUNvd8utQwi2r/j
         GId83vRv0BHJfT8usyS0sLXdqsgkjRLQEOJGUDvlBZOYpLTRGYMOeTLgGspWWhg6HHGy
         TS24Ub1ogs3syva0t1nTNBtTZdbO7p904Aeitoa2W1a2A6ukHIzW58r2b/CvN8MRUkcu
         2QiDcRbcEGh7wxPidiVMtqtHDjG87MRJA2xWkzyXQgJSDv8J+21Qg846JJt+eyMwHOCx
         hZDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q3jEY5iA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865689; x=1739470489; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0aP+pliMhjIWql59UZRmok8gZc2bsYDxmx5v5Y86304=;
        b=ZYswPUT0R3t4rjtTxnzG1ydKrT/Yy1dZO2hEuaMFkrH3/eAkxSTHCuRywyTO8hIZm1
         OO2yBT+OZJ5F+Zz46FDaParpSFHHruLZo6pAbiAzixkYcMgIBVDQoj0mHc+epXuDF9LI
         1DMZgyNJCleTpkaw1/sGiIkziheKwGplvBVpDR8uOKpgDXUcMozvkdLyP4j1PiSq8vIs
         8gjaaIhjuosQPDVYoMs+oF7/d4kCtu+kAmF/wYSpXwvn838SLp7c48PYPjuWJ1RK4Ivq
         +GGjgt9M/4E8rHalIwNuJkhDsSbBQvJELf5JsfjXoOClWnRLKKo6IMxKxeTTFNy7uKkB
         bNsA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738865689; x=1739470489; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0aP+pliMhjIWql59UZRmok8gZc2bsYDxmx5v5Y86304=;
        b=jVR2Vqq43jV283IZUeDHgtTlD1syzmw0GJ1WXU/FjrFazpXdMHXQKig9IjrmywWvxm
         LMzB5fV3EApKbbPU3/aacVDiRzncIi/TRR7DVgWrx6wXK76UhkxiaHjfl4AWSRadUgqy
         dlVg88BRfX3X69ad2QiZSPmapGvGaKM4fg/HVWib2QT2bqMhohuYj7r14UYdQDTN7txQ
         e7l0vXOihtB6JoBzp66LQ4yYL/TVtQ7udHVSg7UGrfYswG6hQTBLdNX33mP2YjO90EVv
         2n5MoZbkbh5RN7AV6whSiPjZ58VBTwT9uGCcjdV6RWiqzH7EwyM8qOFy0ubpXOL1Hx4S
         YJzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865689; x=1739470489;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0aP+pliMhjIWql59UZRmok8gZc2bsYDxmx5v5Y86304=;
        b=jZtP7ZjKdtfAXozgA8Q7KkHMcCQvY2swBOFZXPZ/zFIt5v3Dd7qaW+Cai10JHvoo8E
         K41/twSiKBfqaU98sUi2yUhQnvLVEfylgcIyvo5ng3NMEp4jJm2rV0RonwXInrTH69Vo
         gSkcHzTLoWrjBdvJc4/5ckx+ThUoxNyiE3fgDcoNrE1G9EFtMQDCr4DkgaZI0JfZwVoY
         Zi8HdOmKVImtMwXkC7PeMBGWcznKAFrc9e5yTSY5PSc2bJiSWBG99d4jyl1xPSkvNSpj
         9xZ9CHAe36a3Jy4mvfdWnNeIuIv36YlczRN6M5GY+JqVF21txg41QjJeHxOJtNJFjlwN
         6pJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAdqKdDSPlCGt/ts50/IRnbOJe/Z39GBxG7N9/WKPkdCUmxIFhqBNjqtJ0Nac4YQFPeCDqvw==@lfdr.de
X-Gm-Message-State: AOJu0YyqFdd+mop2V9yipFYLiZXV+stsyKWkNr7+GvC1kxDWRxG+s/FU
	V834dU9YgXdJCgTAIEX1IQ/J9H2HROAreLxAd16du9JvcHiQUpOX
X-Google-Smtp-Source: AGHT+IFLNnpzoo4TYys0hX+nx5BFWobjU2fyxkLUqhFw+W7Lsbem9P4WwcTsKPfAshsSigTG+3KCgg==
X-Received: by 2002:a05:6512:a92:b0:540:206b:c355 with SMTP id 2adb3069b0e04-54405a0c624mr2933793e87.19.1738865688285;
        Thu, 06 Feb 2025 10:14:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d25:b0:540:c34b:91f3 with SMTP id
 2adb3069b0e04-544142c92c3ls8428e87.2.-pod-prod-02-eu; Thu, 06 Feb 2025
 10:14:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVDmSxrZOkyuiAHpluCNc2yYiVmQUff4uQiSMVStSAGf+0CCr4E1nfUvnVUzhlVl5q7Sfx57ofsD4Q=@googlegroups.com
X-Received: by 2002:a05:6512:3b08:b0:541:3587:9d4d with SMTP id 2adb3069b0e04-544059f7c15mr2591993e87.7.1738865685731;
        Thu, 06 Feb 2025 10:14:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865685; cv=none;
        d=google.com; s=arc-20240605;
        b=NlTac3bDIAsW7Zsmqp9wgP7evUfBno+h64ew0CkPxgHRGYn/Yxp/xRUcuT2nDH8ElX
         2BE3JZgBDznRooDKBg1PfF0CGuwLtcHtjVio3jqIQhqBmX7Dcg6jiRrlP1THseb3IykH
         e8+clEXfjvjj7yv947HVC0dziceDXdiBIEX+Tz/NySObDals9AQ4qjoiLgstDpMf/Z+N
         QqT/S6ZqL3hMh6uWHbNsu7zZQkbtv4F8ViOFPl8PpB0Q4avxlqx0VyDIT6o1qMh+7RXK
         LePSlnYfTgde1GopGbo8YE+qAYDSIxf5CHivrKcdxc7DcZHjBo0urQAFxL3h1q6puAJ1
         sMDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wTbbT4CsuJ/iXGmiqeOEuQTztaWXsApJ6CIEHLfEbjE=;
        fh=N+2c7dJb8xjj3xgfJ9xoFTxPOWcqTOUhci2StW34oeQ=;
        b=kh5so3qXpsE4Fr9m+DdCtkDI1+LUS67V3c+E/i7UUo5xCKFBNyfKRS25wisYCyrU/F
         kWaNmX7LhnwJhQVjCSAMLI6D8Tv5aDOR7RIjnhkv/z9cn9/S2B5y3PtEv1+gIAAxNcME
         AMtxAqNZcVm1pBjS/IQtuAQ3Oel+O9rh0D5sJepgndWjRG8sKZAngG4M0xEz4mSm5rDi
         YWIH3zF4jJ0UHc8RrBsOXfBtL2+rTiwgEsjdV9MfgYB0nMJQpH52QEvKD2wIqzwZIT4v
         z9gGd9ZbtD8t0uCq0uytNguK5wWO6oJXFCjNTX9gTr0iqeKT6h/YtmvZd6tvoUq5YIh1
         tH9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q3jEY5iA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5441053eae5si26913e87.1.2025.02.06.10.14.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:14:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-38db909acc9so935537f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:14:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXFq8I+JE+QV9kaNb0KeXX81cJV/NsY/m4SvtcXdOKckhL8xMF12u8K3WfpEx+yVFrDGXW1GZ0S8Jw=@googlegroups.com
X-Gm-Gg: ASbGnctpq+fOJT0dObPdnkKGOKOJ1iBi0PaWAG6CXFedB+ebyAhkk+xH+4bt1hsp5t0
	53sieirqe33plejkUnieJd8sd1eC+vD6FQwzvRaZuYUsZ+OKlZnpn7L4NBwGyjJjqGvEwB+AQIQ
	==
X-Received: by 2002:a05:6000:1acc:b0:38d:c2ef:e291 with SMTP id
 ffacd0b85a97d-38dc2efe475mr1873314f8f.39.1738865684758; Thu, 06 Feb 2025
 10:14:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <808cc6516f47d5f5e811d2c237983767952f3743.1738686764.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZd3sP1_x2c5FvztA6LzsBY3Fq3cD5cJ6FQ+FAnmawe06Q@mail.gmail.com> <zwug3yr7p7x7276g5tpwsvuxefkxn2pwggozgq7krdaquqktc5@eefn3vi3tynu>
In-Reply-To: <zwug3yr7p7x7276g5tpwsvuxefkxn2pwggozgq7krdaquqktc5@eefn3vi3tynu>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 6 Feb 2025 19:14:33 +0100
X-Gm-Features: AWEUYZmr-sZ7H7rQ5pJvdgslU5r_pD-83ZAYiTMD0XxDDSXEdCYqWWqGvarMkGQ
Message-ID: <CA+fCnZfsT3jO96rewM3wZw7n4hHJ44wRDG8g_55NFS5VG34grg@mail.gmail.com>
Subject: Re: [PATCH 01/15] kasan: Allocation enhancement for dense tag-based mode
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com, 
	palmer@dabbelt.com, tj@kernel.org, brgerst@gmail.com, ardb@kernel.org, 
	dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
	akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, dvyukov@google.com, 
	richard.weiyang@gmail.com, ytcoode@gmail.com, tglx@linutronix.de, 
	hpa@zytor.com, seanjc@google.com, paul.walmsley@sifive.com, 
	aou@eecs.berkeley.edu, justinstitt@google.com, jason.andryuk@amd.com, 
	glider@google.com, ubizjak@gmail.com, jannh@google.com, bhe@redhat.com, 
	vincenzo.frascino@arm.com, rafael.j.wysocki@intel.com, 
	ndesaulniers@google.com, mingo@redhat.com, catalin.marinas@arm.com, 
	junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com, 
	dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com, 
	dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, 
	peterz@infradead.org, cl@linux.com, kees@kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Q3jEY5iA;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Feb 6, 2025 at 1:58=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >Is there a reason these definitions are added to
> >include/linux/kasan.h? At least within this patch, they are only used
> >within mm/kasan, so let's keep them in mm/kasan/kasan.h.
>
> Parts of x86 arch use these later (minimal slab alignment, kasan shadow s=
tart
> address) so I thought it was convenient to already have it in place here?

AFAICT, KASAN_SHADOW_START only relies on KASAN_SHADOW_SCALE_SHIFT,
which is defined arch/x86/include/asm/kasan.h anyway.

And ARCH_SLAB_MINALIGN is defined in asm headers, so the definitions
from include/linux/kasan.h shouldn't be visible to it?

I think that we need to do is to define KASAN_GRANULE_SHIFT next to
KASAN_SHADOW_SCALE_SHIFT for x86 and then use it in mm/kasan/kasan.h
to define KASAN_GRANULE_SIZE for SW_TAGS. (Similarly as with arm64,
where ARCH_SLAB_MINALIGN depends on either KASAN_SHADOW_SCALE_SHIFT or
MTE_GRANULE_SIZE, both of which are defined in arm64 asm headers.)

Btw, I think ARCH_SLAB_MINALIGN needs to be defined in
include/asm/cache.h: at least all other architectures have it there.

> Since I'll be reordering patches I can just move these changes together.

Otherwise, if you need to expose something new in
include/linux/kasan.h, please do it together with the change that uses
it. Or you can even put it into a separate patch with an explanation
of why it's required - at least from the review perspective having
separate smaller patches is often better.

In general, if something doesn't need to get exposed to the rest of
the kernel, keep it in mm/kasan/kasan.h.

> >I think this should also depend on KASAN_OUTLINE: Clang/GCC aren't
> >aware of the dense mode.
>
> I wasn't sure I fully understood how inline/outline interacts with clang/=
gcc on
> x86 (especially that I think some parts are still missing in x86 clang fo=
r
> tag-based KASAN). So I understand that compiling with inline doesn't do
> anything? If so, is it not doing anything because of missing compiler cod=
e or
> something in the kernel?

With inline instrumentation, the compiler directly embeds the
instructions to calculate the shadow address and check the shadow
value. Since the compiler assumes that one shadow byte corresponds to
16 bytes of memory and not 32, the generated instructions won't be
compatible with the dense mode. With outline instrumentation, the
compiler just adds function calls and thus all the shadow calculations
are performed by the C code.

Or did the dense mode work for you with KASAN_INLINE enabled? I would
expect this not to work. Or maybe the inline instrumentation somehow
got auto-disabled...

> >Would it be possible to move this part to kasan_poison_last_granule()?
> >That functions seems to be serving a similar purpose but for the
> >Generic mode.
> >
> >It might also be cleaner to add a kasan_poison_first_granule() that
> >contains the if (addr64 % KASAN_SHADOW_SCALE_SIZE) check.
> ...
> sure, I'll try to move these checks to kasan_poison_first/last_granule.

For kasan_poison_last_granule(), I think the change makes sense. For
kasan_poison_first_granule(), please check whether it gives any
readability benefit - if kasan_poison() is the only caller, maybe
adding another function is not worth it.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfsT3jO96rewM3wZw7n4hHJ44wRDG8g_55NFS5VG34grg%40mail.gmail.com.
