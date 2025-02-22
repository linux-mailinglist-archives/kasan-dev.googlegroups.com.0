Return-Path: <kasan-dev+bncBDW2JDUY5AORBZ6P466QMGQEP3K3VOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 68984A40951
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2025 16:06:17 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-38f4e47d0b2sf1428364f8f.2
        for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2025 07:06:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740236777; cv=pass;
        d=google.com; s=arc-20240605;
        b=hYpHJ/C00E9scAeDiufSGLg9WDRaEW0S3wRw70m6wJu3w2X5KBKlpyXUxxXJ0CeVvc
         Xw+0SImuGMLkHxU55oZ4hzckC90A9Gylpdg0yDU3QzXiO4/aWuorOmsT9ERu/shYsG96
         VjkT+EUS/RYawtNL3AaN+dsxORYuRG/PJjHkobJLmPSV0wtHqeBA3tuZvgeWux0jEylD
         RVO2cNxk31j+6WrfcRDkYnTFIyzPPQNi7N/i8bpcHOjaw9vV2qepG5BWW7uGZgdSOFkO
         UzPsRfJTvTi7d/FbaYA123GFUDxG72gQ8CNwY4/RrQ6n5TV4Wllmzp1TsTSJK8T0D60R
         x5jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=FzDus8rSK5B6O1NdwnzsIDDIFKHOit8DTqvpEYAamOc=;
        fh=VAtIEZDorTGqYspQeEdlZCtYVFYvDIDSQFS2i1V+uO0=;
        b=GY0/2eUVzDnB6fcv5oO3cI6x1004YkgPRjXYJ0h9iiDdo+dWmPdIvOnspHDdfHtKfC
         B2PaLQrJ4lCHFMT8ij40yHq4heUohxXZTRQ0Oi6a9aHrkATB/ph4Kw57cJHxV/NxJRc5
         t7fRIwRJWKxnn8Eu+Lx7G5Br/QhjKPERh/C6B09A4kXPD2jeFEiDUpIfPRjrN/9479vj
         APheQdbk1C4LBpjvAQjUwaVl7IflwR2VglCyRWxFoltQYccWsFDqbXVtq3a1JHapADO0
         dy8PnFAq0E9A92PLOcxNY+1tguY0JyM0yWvytheYYkdFCE7YhbQmgtyB5tIuZm0Mw/Fl
         oxBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=h6hZmlo4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740236777; x=1740841577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FzDus8rSK5B6O1NdwnzsIDDIFKHOit8DTqvpEYAamOc=;
        b=sBtmQA3NxIIJ18pDkOzy08QCPY6hVIfIiDjeOzSYnnEZXrh1RxlBZtg/YW6p43v/Ga
         esDmgG14e+qU6zqsX98tz2Hv35dFzTCpnAHSNL9o1uUFBXqclf8NsXX6s9w9E+gH5AGw
         TkspZbYerFL5ZAwpH7nL97DeAuhT6ajDHzOyqLR9bmvRRxfw31RMOlplgKG1mjHKjjSS
         lodVGAL4LKrkdBQI8TwuUl3nBCNva+I4UQNtZAW0WXW/zDrDUX6iHljwkm2Zxy/6nQm9
         EbrjPzvXiL2oZfoWpWdlQ4jlle0pqe7uBhLImMkngNG426rQXHCUILiyITcT35x47pg+
         mrjQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740236777; x=1740841577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FzDus8rSK5B6O1NdwnzsIDDIFKHOit8DTqvpEYAamOc=;
        b=apIRexr5CKUNT4twAu2Zok5WQ+aNvPmpSy/FRozZYV4JqMo8s9jadg9+/hDq/LAJ8f
         /lhW410nVfo3ZSSTjJrEdU6H9NwIRMjkzj4Vl+BvUvE3CGozyVlQ9eDVOljjxEiEZnCu
         VgjPM167Vmz3V1F03Z+UujPUF0n5T+FcAfdaPB1EQfaJ/9OTIj9ILSEfcvuHmSWclG91
         rZyLyEC6qcnFli9HriffyHr7wWk7bN0M455hxzAaq4WjKFMFtI4kda9fXVjS5L3wCdKK
         hoNfVg8QBgX60imaFKmg+sPogu/xWOJPqQA1spl2ATrGtNIeFza9OAwNZ0D3oqBkLGTz
         edWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740236777; x=1740841577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FzDus8rSK5B6O1NdwnzsIDDIFKHOit8DTqvpEYAamOc=;
        b=w4JPAJML8tCZOb9C49tZLjv0jsy0kmJfcZocW4L67gPqaOGZRulGcV8AHLN1X+poO7
         TDIuQtp+R28iMHhG4d5jzf+OELHka2XUGdyg6UMQhCa9jAXCrNLIBjCUSnLSRtK8lkww
         MW6SRyz9KlRP9qP5mYxyJBuaDqTRQjybuC8mMlrpG+nc2KdqfSnb7VlknZ8gvJBtXSDp
         uswdq/sTCGs2c/cspygU/2EWq5kZeQvaPw2nbvyVVcardAV7QnL5KJgMBNb45SZYTbuw
         jSL8SUpERKURr08oS9VcPcqRzPhLvRTRIVXz2PnWai3l7B6n0kGbhcyUOV322MCoGBYm
         t9UA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbBMLeyfk3FLlkb7mXfGNUN6tyOp67bw3wb7a/Gs/CWmC0cV1mdRXe78XU5gaq5dmiTdAukA==@lfdr.de
X-Gm-Message-State: AOJu0YwE6GNTq6R/hAbZXkbXhKXIy6o5uzIDGqE9R8o6W6+2MDkdvM17
	2Aj8+jC8nuY+lj0xWsT2lwkItkukpVnjpO78PHi0N/vMbUaroGGY
X-Google-Smtp-Source: AGHT+IE7UK8MOIK7x9UE0vcyP+lmfFIRDyMh5wP2vcm/83hHQMgfEnS6+BFCUp1PRbUfl2G9tj+y9g==
X-Received: by 2002:a5d:59a3:0:b0:38d:e15e:17e9 with SMTP id ffacd0b85a97d-38f6f0b2161mr8207849f8f.35.1740236776196;
        Sat, 22 Feb 2025 07:06:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGjf6jKzDOGldg2svUoCb6SFjHHuVvcZRJ1iYPMRkRbjw==
Received: by 2002:a5d:6d8e:0:b0:38f:2204:701a with SMTP id ffacd0b85a97d-38f614a6261ls1541508f8f.2.-pod-prod-08-eu;
 Sat, 22 Feb 2025 07:06:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVTS+bC89Hr0XIQiTlUoBBjzucocdsZkTfdQIMkqOvtWO01DqqV13EZuXNEWvL9rf3NwHzQibIM4RU=@googlegroups.com
X-Received: by 2002:adf:e8cd:0:b0:38f:2b54:874e with SMTP id ffacd0b85a97d-38f6e95f67amr5485267f8f.16.1740236773763;
        Sat, 22 Feb 2025 07:06:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740236773; cv=none;
        d=google.com; s=arc-20240605;
        b=LmhD2K98RjEhpikLl2OR1MNvnQg01U64rlN/FxlZvq8icQ/c01xU8+IiJ3IWK2m2bF
         6hrmvKjWn8WbSV6W9CSGpx8sH66HvHuOpwhSVX+xsRG2oszHBQBbusXuOY5OTVFviaqG
         jxxS/92Ith/Cs+ElZCj4WTBBtdQoDV1+A2Wu7bnRb7hNPpIyvgQZreRRFx+6LBAD3MNJ
         GJuwSj6ZIIBaPOPDfVF+masi8W2RJ9EDQ6miNQhAbk/1+o8IDqatWtS0BQ+HdJX/hSEh
         w24FIkk7TYRzIIgtEyei4Wfbeku98vpWFwSS2bmRzIZ1tetPPntPRP7Wy3S1yJLGISmQ
         RLvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nzMYHvrv9HpWCutgVpnHfFN6zecH/fwJ8xUtPbSALWo=;
        fh=nTn1Seqd7QdE9OYqfFyX+wDOC86yTnpbc+xQ5vq2Vw8=;
        b=JzOUAhH038szRdBEwyYxnHQWAxEroymgYe/XQnMfZst9WgOZb9p91WcReGaRN8XBp1
         lgCrK7+H/iQruIxtrXNVN/JDFuyuvbOh1Yn/44nz6y603r870QykLRUbHMYpiX0TMbHU
         TCjVhF1Sa6HZT/Q4FFrlDinK18/jhFX+zoBlqZ29loa4JLypFWFEQLhESl6skKG4AdiY
         Z/4+TAncbuBCRQC+PNuvqKNHdmveSldRjB32qpxOSCuu+FGcafZCuc707M6EnzG369I2
         bw0qJw6QXqFlN9iw7wWo+gVIttuYO3dLRkavaO4SED8JNATaiwwPeac81XvU9eNYe7zE
         yvag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=h6hZmlo4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4399bea9edesi6343255e9.0.2025.02.22.07.06.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 22 Feb 2025 07:06:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-439946a49e1so19227945e9.0
        for <kasan-dev@googlegroups.com>; Sat, 22 Feb 2025 07:06:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCViYOap162dBZlviPPCFnQVOLLsBed2y/BES7zafx4Wf3miAvdCCQwf8SnwXdyr+q+5xZ5CDcFEcS8=@googlegroups.com
X-Gm-Gg: ASbGncvj+c6xFTgnxwn8NHo7TeE5VQ6+MryDhOu8DMXWSduPiRxa4zCLldMJdSRkyKr
	PoH/0Tmsv0iZXO6YTuo6g9M1actZi66e5eAnlCSTB5i8Rre0M0XtTWPLPt/SPyCpE+/vS2PPw7y
	xue1d4blPn7w==
X-Received: by 2002:a05:600c:4f84:b0:439:955d:7ad9 with SMTP id
 5b1f17b1804b1-439ae1f145cmr75369895e9.14.1740236772914; Sat, 22 Feb 2025
 07:06:12 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com> <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
In-Reply-To: <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 22 Feb 2025 16:06:02 +0100
X-Gm-Features: AWEUYZnFqlAhlbFhk_9-WAra7TCYMXPYd8CyySx1oX6HAXsK_aRCuDKHtzc0hoo
Message-ID: <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, mark.rutland@arm.com, 
	broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, rppt@kernel.org, 
	kaleshsingh@google.com, richard.weiyang@gmail.com, luto@kernel.org, 
	glider@google.com, pankaj.gupta@amd.com, pawan.kumar.gupta@linux.intel.com, 
	kuan-ying.lee@canonical.com, tony.luck@intel.com, tj@kernel.org, 
	jgross@suse.com, dvyukov@google.com, baohua@kernel.org, 
	samuel.holland@sifive.com, dennis@kernel.org, akpm@linux-foundation.org, 
	thomas.weissschuh@linutronix.de, surenb@google.com, kbingham@kernel.org, 
	ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, xin@zytor.com, 
	rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, cl@linux.com, 
	jhubbard@nvidia.com, hpa@zytor.com, scott@os.amperecomputing.com, 
	david@redhat.com, jan.kiszka@siemens.com, vincenzo.frascino@arm.com, 
	corbet@lwn.net, maz@kernel.org, mingo@redhat.com, arnd@arndb.de, 
	ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=h6hZmlo4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
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

On Fri, Feb 21, 2025 at 2:12=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >Is there any reason we need this change for x86 SW_TAGS besides the
> >optimization benefits?
>
> I wanted to have the shadow memory boundries aligned properly, to not was=
te page
> table entries, so the memory map is more straight forward. This patch hel=
ps with
> that, I don't think it would have worked without it.

Ok, I see - let's add this info into the commit message then.

> >However, I just realized that this check is not entirely precise. When
> >doing the memory-to-shadow mapping, the memory address always has its
> >top byte set to 0xff: both the inlined compiler code and the outline
> >KASAN code do this
>
> Do you mean that non-canonical addresses passed to kasan_mem_to_shadow() =
will
> map to the same space that the canonical version would map to?

No, but non-canonical address are never passed to
kasan_mem_to_shadow(): KASAN always resets the tag before calling this
function.

> What does that? Does the compiler do something more than is in
> kasan_mem_to_shadow() when instrumenting functions?

Same for the compiler, it always untags the pointer first [1].

[1] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tran=
sforms/Instrumentation/HWAddressSanitizer.cpp#L922

> >                   Thus, the possible values a shadow address can
> >take are the result of the memory-to-shadow mapping applied to
> >[0xff00000000000000, 0xffffffffffffffff], not to the whole address
> >space. So we can make this check more precise.
>
> In case my question above didn't lead to this: what happens to the rest o=
f the
> values if they get plugged into kasan_mem_to_shadow()?

We will get some invalid addresses. But this should never happen in
the first place.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q%3DfDkdYYXQupX1NA%40mail.gmail.com.
