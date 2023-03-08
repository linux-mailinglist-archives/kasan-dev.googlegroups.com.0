Return-Path: <kasan-dev+bncBCSL7B6LWYHBBO4JUOQAMGQEETTZT4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 24AB66B1021
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Mar 2023 18:24:12 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id v14-20020a2e9f4e000000b002934fe0289bsf5626726ljk.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Mar 2023 09:24:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678296251; cv=pass;
        d=google.com; s=arc-20160816;
        b=yy0FaF1Ghf7r0Fk5M5gEEQGrdBQApnQj+gil69kAYwbrhFFLRKQeezHKTJm5L3Z48m
         OYx2FbDqHTiDSbibRPlr8qYdl5WoefI9y0h27/Y9Yq4ed18pI3DW2qyfrwbMcclTcM/u
         PIUc2f87jD2V6og7hpZjA6bMx9DxhVQWABcv4ls6BpPb0OOFKnXEG47IBH8ovT+MSsDp
         bGJ6Rus6vCv/ycJeJUG7BNmGq3VDgsiisg2aXT7usFt7H8AV1Dh2YKkv0fnSBrOBCM11
         7qKkWLPyTO7cJ+gT6ZefPNvRdH/cWXmqZqAKrtwbhGBjzXItkrifmxXaXrPMEMLcb+26
         dZIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=i8DH7mPi05sdw+Sm8ZHwHQysVADC2MIXLBMYrefg1qM=;
        b=ldYqzyrVveuKHt8jfb96P8OJHbIt8P1m7ph8SMrxl9thFowSFe4ol00Tk402p1XBiP
         TueftWh61hm0BPc+H/0kbiLe7qu8Kx9M8QyS7KrRI+4kxdtgab/cR5HS+IqLzb0uil+3
         e75izJSuirlaOIX5WgUHr8u90awHiOnbWOLoAxL+vr+JoleQkn2BbLjFLr1OtGFfW/ay
         3Wxr38pZDuHyl4XJKDiEEEB2hFiE6n+3SulvBuvfk8R624qiKWY5qs8Uf2KVX8agqvFH
         h9XJZiyIU8rE1cyW1OHL9sNHdURSrTxA+aPzShfPza+wOL7e+dikOGQKVrqh5q2EbY2W
         Bhtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZU6ZJGzD;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678296251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=i8DH7mPi05sdw+Sm8ZHwHQysVADC2MIXLBMYrefg1qM=;
        b=lTPRyViAh3n/MwmvY3DBEvQo81N1EpVyprjiyRKae2Jhhphys80EBFwVCval64MoBO
         7REBk0EM7zIrh9WQZbzGMMWtrBhlZj0teBBWGq7BPp04hET9rwl34lGrMwcbxXxKwSiP
         zwBKjlKm0gTumq0GTMwFet0i20yohWLcL3PJszd/+qz9qkraDSwJ3CCky400nX3e+t5+
         yymMNmLF1QkSoqlBR4ADZssYjlbAna0j+OZL/Np/6lX90biFasWnFPUbFLQeM9MUkRaJ
         54lObOtEMNbjKxshcyE4nSuWYsfg6kmEuxLKP1pBjAyqHnIVxiEiE0VHxNYtWLlLHD/r
         6mwQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1678296251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i8DH7mPi05sdw+Sm8ZHwHQysVADC2MIXLBMYrefg1qM=;
        b=KOz0By+lllIPwR1pugcyGEwWCMcsrpE7nG89vE3199kU/936XegMUNObzdNVJuwK4s
         1hlF92OSYKeGe1gazLxZWtabPcEPl77TIFqQpmfF/DXgoN8ujqWp7P+SaRx5UC0RzFUB
         Rj8SDyftrGVUPPVc92/++cTZ9886f4YsY3FErRbBAcTyIesnyjg3H08//UfhhZBKfciD
         zT6Y7VKQEEOadpf1RZUwDNcO9tv5vYqvDuaovB8FtJXRQVJZZIKxQ1DcEFUGKtIEG2H6
         LVJhPMI1nNDEW5cNeeTZ0pkjqpmVWBxLOKu5ujNJvJ/GjIyVG683FPGEGpzmsHVurMQu
         pwqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678296251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=i8DH7mPi05sdw+Sm8ZHwHQysVADC2MIXLBMYrefg1qM=;
        b=Lm+kDI/oT+lc3JMM22Gmxar6MT/E+KroGMg4WIC65b4S4u58lVXnbHwIxZhxrTQwff
         rYKicATBpL3x6+ZLS+3XV0ouOgbmp5xRKqhRqW6VCqWGOcAZ2vrWP+bRteCrjc4di1xv
         /eZT3f3+ptJBDqU4xfSxGX49s4XtFUnfKnUuYiJOSaOxK3RJWl3yKy41JZpDJ9cpUTeE
         nDG4WC3mii2UaVTBqu6bTOPQ7dQKF4cDljAvoZic6MEbo9d5ASCbFyaw6tXVX6h24DeY
         6LtmHPqmmEi80XKxk/aAzCm11+2d+QFvCRufATWDH0DUdVronvlWLRKUkYJPf9uy3Zgo
         A17w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUTmp3O+Xd5ZaquwqmCbNcCf2RGmAzCiLJtq4aFi/nbKr+RFU6P
	kPtP0dUXLOfpjpkZkI4Zd2A=
X-Google-Smtp-Source: AK7set+P4fbwcdG0j7PdftBmbaP/5bh9ut4UwOlTtzHmo0S9EzKXaQndKJGNYGSVwl7SiLUuOSQpFw==
X-Received: by 2002:a05:651c:200e:b0:298:6bb0:f2e6 with SMTP id s14-20020a05651c200e00b002986bb0f2e6mr1087889ljo.6.1678296251305;
        Wed, 08 Mar 2023 09:24:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:220b:b0:28b:d53d:2e29 with SMTP id
 y11-20020a05651c220b00b0028bd53d2e29ls2882265ljq.2.-pod-prod-gmail; Wed, 08
 Mar 2023 09:24:09 -0800 (PST)
X-Received: by 2002:a2e:8e33:0:b0:293:4b9b:1f6a with SMTP id r19-20020a2e8e33000000b002934b9b1f6amr5343288ljk.7.1678296249549;
        Wed, 08 Mar 2023 09:24:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678296249; cv=none;
        d=google.com; s=arc-20160816;
        b=dgi7DBc1occgOecki3Ei/+CsQC+grcrfLXmpNESiLSDIjJC/S9XSU9ZSxlOX9vfJwo
         7nuaPVygmzjT3SCsRkE/nSsVAWUO1RGmQIM/qftVixzC8/nc5UrLhVpb6GO2NVMTOhOx
         p+HoclC6y3jKl6Urn+c7LHoqb3fgG7zoHMt7Q0CPoKMOrrd+XQq7JgaW4f8Fgv518VqS
         ohW9gdO0NQjrvC0HtUI3GjO0VX1UXNuXLISXghd91jYD9w9Pk7uqPEVNeBdZMbKzUmrH
         Zj5Sw2KHNys6Y224siL+C7+IwqSO58Ardt+9I8VcwYvetko1YAnZETzbiZZ7qgrT2qC+
         KHeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DcGUcMsaep9Sz9s+gH/VvnsZCqctQ0iZxaFub1OCSCw=;
        b=ZFzdtNOsS0H0Y/XrJoZv326hz1U9SDmYHjnBUjuuQYq/IZ9+ZmRwylBFthizMcCCkq
         8TuUVtkueR1N+cVUmFpOimgBrbZQyKnn6JjMiNXgsiHU0ZtBS/0t/659b0A/zH2y2KPW
         6S97omkG22P5TllBsvWE+pi9cx67nUfFtO0sBXisYTTUMg1BQEKViJMTPPzuJigfXgO+
         pIiGw/cs1JDFVmNAr4GAK1H0U8Pv8Mk6C080UJWE9iRCcaPHqkIcmRNSh4B6Cc8J8+Km
         GYmyc1X1hpk2ib/2g/WecwN97Fq1Tj/leoLzPm6nBlJDwAZQyOTOMx3E262dP5mPSYLw
         LLEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZU6ZJGzD;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id s3-20020a2eb8c3000000b002934b9b1f69si682277ljp.4.2023.03.08.09.24.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Mar 2023 09:24:09 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id p16so10260768wmq.5
        for <kasan-dev@googlegroups.com>; Wed, 08 Mar 2023 09:24:09 -0800 (PST)
X-Received: by 2002:a05:600c:997:b0:3df:97fd:2221 with SMTP id
 w23-20020a05600c099700b003df97fd2221mr4000756wmp.7.1678296249000; Wed, 08 Mar
 2023 09:24:09 -0800 (PST)
MIME-Version: 1.0
References: <299fbb80-e3ab-3b7c-3491-e85cac107930@intel.com>
In-Reply-To: <299fbb80-e3ab-3b7c-3491-e85cac107930@intel.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Wed, 8 Mar 2023 18:24:05 +0100
Message-ID: <CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDkrV1XxQ8_bw@mail.gmail.com>
Subject: Re: KASLR vs. KASAN on x86
To: Dave Hansen <dave.hansen@intel.com>
Cc: "the arch/x86 maintainers" <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>, 
	Thomas Garnier <thgarnie@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ZU6ZJGzD;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::332
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Mar 3, 2023 at 11:35=E2=80=AFPM Dave Hansen <dave.hansen@intel.com>=
 wrote:
>
> Hi KASAN folks,
>
> Currently, x86 disables (most) KASLR when KASAN is enabled:
>
> > /*
> >  * Apply no randomization if KASLR was disabled at boot or if KASAN
> >  * is enabled. KASAN shadow mappings rely on regions being PGD aligned.
> >  */
> > static inline bool kaslr_memory_enabled(void)
> > {
> >         return kaslr_enabled() && !IS_ENABLED(CONFIG_KASAN);
> > }
>
> I'm a bit confused by this, though.  This code predates 5-level paging
> so a PGD should be assumed to be 512G.  The kernel_randomize_memory()
> granularity seems to be 1 TB, which *is* PGD-aligned.
>
> Are KASAN and kernel_randomize_memory()/KASLR (modules and
> cpu_entry_area randomization is separate) really incompatible?  Does
> anyone have a more thorough explanation than that comment?
>

Yeah, I agree with you here, the comment doesn't make sense to me as well.
However, I see one problem with KASAN and kernel_randomize_memory()
compatibility:
vaddr_start - vaddr_end includes KASAN shadow memory
(Documentation/x86/x86_64/mm.rst):
   ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB |
virtual memory map (vmemmap_base)
   ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused =
hole
   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN
shadow memory
   fffffc0000000000 |   -4    TB | fffffdffffffffff |    2 TB | ... unused =
hole
                    |            |                  |         |
vaddr_end for KASLR

So the vmemmap_base and probably some part of vmalloc could easily end
up in KASAN shadow.

> This isn't a big deal since KASAN is a debugging option after all.  But,
> I'm trying to unravel why this:
>
> >         if (kaslr_enabled()) {
> >                 pr_emerg("Kernel Offset: 0x%lx from 0x%lx (relocation r=
ange: 0x%lx-0x%lx)\n",
> >                          kaslr_offset(),
> >                          __START_KERNEL,
> >                          __START_KERNEL_map,
> >                          MODULES_VADDR-1);
>
> for instance uses kaslr_enabled() which includes just randomizing
> module_load_offset, but *not* __START_KERNEL.  I think this case should
> be using kaslr_memory_enabled() to match up with the check in
> kernel_randomize_memory().  But this really boils down to what the
> difference is between kaslr_memory_enabled() and kaslr_enabled().

This code looks correct to me. __START_KERNEL is just a constant, it's
never randomized.
The location of the kernel image (.text, .data ...) however is
randomized, kaslr_offset() - is the random number here.
So
kaslr_enabled() - randomization of the kernel image and modules.
kaslr_memory_enabled() - randomization of the linear mapping
(__PAGE_OFFSET), vmalloc (VMALLOC_START) and vmemmap (VMEMMAP_START)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDkrV1XxQ8_bw%40mail.gmail.=
com.
