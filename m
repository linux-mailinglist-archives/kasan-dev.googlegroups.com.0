Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBWXT2XXAKGQEVGFIEPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D5B6810423A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 18:37:30 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id q186sf53597wma.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 09:37:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574271450; cv=pass;
        d=google.com; s=arc-20160816;
        b=JdumkK49vzNeP1p2y5BnqvXACedDstBkmSMug0Tln1LM1P1mNY8+fy3huZKYHVUEnT
         s4nTSY9QDPNEmGx/6sSojXtw+w356uLN913ntSjms4Ypf90lecWE6KV3TBj9qvAZOesL
         H5r9r0vZMuFHj7OITRfy88mtd4FuKzzKVQfAQr1xOL4vbSu0Lc4WMp7mhC0BdtaWx+FG
         N2E4jP9llpWPsbkCGHRzI8SDcuguXHd3AwPEUVWJSNEmcjAS5vfXYsdng6AfSbvi778m
         ZsPUYTqZY3LIqspWETCabus3rkgsIWEZWOP2f0ctoNV5k10rf9zoW2GQCWRCkvbFWe4F
         Mqfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=fScQXpOFnvfJOyins0Y97YpvWeD0hrfXR+c2l0iGIhk=;
        b=dULEqEH7AnEI6ZaCjCTtc+2PG0W3aWgrUDTN/Dv2ZuuSzyZNv1Z4JjHaxCpBrvS1l3
         JFPlwelxcDmfEoSxx0XopbuGK6fBhNR1t58OK1zv7OVyhLrWJgrNYs3eWgxc+V07s8Ht
         Qhbm+xVJ6L7T/197jfWJOcOm11sNqMuJACm6f9lyMaIOM9paTopgb5RTjkc6RXau/UpA
         2o3NkIxy3y9ncz292BZZHNzStjWpebtYnsLl/Ktdld+vafNdMDimt0gU0cmTeXz4XjRa
         /DHcSfIxWbo5ryBb1f6kCSdQfef8hMuSsRg8v0irkh/Srnepy/w0TU7r4j/jO92pBovo
         HDLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=gQHFgTgS;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fScQXpOFnvfJOyins0Y97YpvWeD0hrfXR+c2l0iGIhk=;
        b=B5EjrGOcagU2qUz6ZtdQ8BRQHxMuAWl+8oJQunkxP0qW8smvO4AIE1t/is24I6TMp3
         iuN+m0dZHYll7KZPWcN8Q3DcRtJgGwN1An0sd0PWYUnnhgcTLvFQ0M9zkH+HDAfEDgDs
         IoOfRn5Ui4eeBcPlaS5dsglKrLE+fNjHKkYXrVg8onr+ZhjiZ/ILA1dgTa//9BPK051U
         rBfQ6QtK29zyfxWCvqSwxWsgiBQO+MHmq9/0wSHYyEjh6lyCIIw7yD9m8JD/Q+F0pefL
         L2kzL1AEFgCvP0vgUcmafZBpywXzs4eMJH+14g+7ALKCG6xunOqpMva6gAfbBFLqg304
         cYnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fScQXpOFnvfJOyins0Y97YpvWeD0hrfXR+c2l0iGIhk=;
        b=h1bse+wYrytV2O6BeUi2tC01kZKpv46OYlfMSgpIR56dznxkifHI06vAUekOeVd+M1
         h2gsttWqQ+RYY40NHaXTTe3ioMhW2DSqYfQlTGLbyk5R8PJbBKZUlMh31AthKwwvihgQ
         2iYGPWQPy0H8rPB7LiFLQ+qyboao9I3hUNz10Wr+EMCj8IMI8Ft8/5mybNr101b0ruAC
         9sIJb4MdHNQRWisSmoeH4fPWh0JDX9ZrSTxzmvzxBXdW0EIwGQGjJV7tQYxFbC/tjLP9
         zoui0SkT6KM09BrYB+XahSyXQ8lAl28AK1EKHT5rLC6R5feAi74AQaT9TDwLIFdYqilC
         cH8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXFlin5FifeYBtKz2dB5eCJ/aTfIsfAxuUGJACvpmeh6dWPEiGa
	KHrz+fVKLf5tJGWbIKt8m0g=
X-Google-Smtp-Source: APXvYqxSueTjiW9a7tWCKKuSzr/NcAy7GDwS0d+y4XUn91HH5NsoG0tKluZyYqV5XujjyzKlimKOIA==
X-Received: by 2002:a7b:c776:: with SMTP id x22mr4528285wmk.144.1574271450501;
        Wed, 20 Nov 2019 09:37:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4050:: with SMTP id w16ls914819wrp.13.gmail; Wed, 20 Nov
 2019 09:37:29 -0800 (PST)
X-Received: by 2002:a5d:6350:: with SMTP id b16mr5113373wrw.357.1574271449922;
        Wed, 20 Nov 2019 09:37:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574271449; cv=none;
        d=google.com; s=arc-20160816;
        b=bKMDWNWvGZHQuGV8D46gnfQcpdql0taYLtQXZKL99RaxTKgRAMHnU30w6Ae495fWAO
         cbVPwRecsyHq2EQDuRnBPqFCuEC65E70Out0Z/Gymei+NDOQ/acfl7FU8kmJeWvyNsGO
         8BD6Wct5AJSdHFWGlHtCn6RLkL398PD2fr56ijJ2rbYzvfDnD84T87GaogADfhuGNFIS
         4ZpDzeObGV7LicKG7LyBCKUqcxsVtNXCdVh/XvNbn/P+n+8VWrfvTWCEfi6dBqzWeN+Q
         xNBIgxLE9Nc46ve22+0wRnaQdWxQS6mUVPSu+sOcDj2EZlyOSMovSz1ePCbA+J/tUoy6
         WcqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dt0skX+t5TApZIf10QlyBTuMhhHdR5oeyUG697yEIWI=;
        b=wR+tSGjkXhbPZeZvZk/CAPxHeCNXsaeLb/c+0DqLtinR5vVxqmts8/g4s+K3Zf56qF
         e2Kl+RX4FZcdGV0Ec+HmWUT/nyj0Dm7pDBrk+kf7ma8skWeW/GS6gkDiTmNqsM0UadNX
         Q2TCuKBEA+QaZf//tk7nmXGsJ9yrvfBNyuKMYK540dv/S3cDT3+pjoOrGGkHxGBH5nLc
         hnAcIMF0MgwI9VgPY8IN1J+d0l1bloE3NwO1mzwaaaDqfnMy32C6ZSNEcwxw88V0yQMg
         Ge+Qj7ZKc482WL9gpVrJqZKXw/xrAJiZIpLnMO4N7FOVIebsZWfR9hj6zBpjbSWL7SPU
         pTbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=gQHFgTgS;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id q128si1172wme.1.2019.11.20.09.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 09:37:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F0D8C00F553B94F3FB99B80.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:8c00:f553:b94f:3fb9:9b80])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 4B40D1EC0BEC;
	Wed, 20 Nov 2019 18:37:29 +0100 (CET)
Date: Wed, 20 Nov 2019 18:37:22 +0100
From: Borislav Petkov <bp@alien8.de>
To: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120173722.GH2634@zn.tnic>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
 <20191120123058.GA17296@gmail.com>
 <20191120123926.GE2634@zn.tnic>
 <20191120132830.GB54414@gmail.com>
 <20191120133913.GG2634@zn.tnic>
 <20191120162143.GB32572@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120162143.GB32572@linux.intel.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=gQHFgTgS;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Wed, Nov 20, 2019 at 08:21:43AM -0800, Sean Christopherson wrote:
> On Wed, Nov 20, 2019 at 02:39:13PM +0100, Borislav Petkov wrote:
> > On Wed, Nov 20, 2019 at 02:28:30PM +0100, Ingo Molnar wrote:
> > > I'd rather we not trust the decoder and the execution environment so much 
> > > that it never produces a 0 linear address in a #GP:
> > 
> > I was just scratching my head whether I could trigger a #GP with address
> > of 0. But yeah, I agree, let's be really cautious here. I wouldn't want
> > to debug a #GP with a wrong address reported.
> 
> It's definitely possible, there are a handful of non-SIMD instructions that
> generate #GP(0) it CPL=0 in 64-bit mode *and* have a memory operand.  Some
> of them might even be legitimately encountered in the wild.
> 
>   - CMPXCHG16B if it's not supported by the CPU.
>   - VMXON if CR4 is misconfigured or VMX isn't enabled in FEATURE_CONTROL.
>   - MONITOR if ECX has an invalid hint (although MONITOR hardcodes the
>     address in DS:RAX and so doesn't have a ModR/M byte).
> 
> Undoudbtedly there are other instructions with similar sources of #GP.

Right, we currently put our trust in the insn decoder to handle those
correctly too.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120173722.GH2634%40zn.tnic.
