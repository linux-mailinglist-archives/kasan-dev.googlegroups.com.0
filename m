Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMP7VWBAMGQEX2IICXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E39B1339052
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:50:26 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id o17sf9400725otj.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:50:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615560625; cv=pass;
        d=google.com; s=arc-20160816;
        b=QOE7WT77ZUF3J7OZkDlhRbhIeWy6GhrqmJmeazD4xf0wVN6eQfc2tlL5+PsUBjE7tX
         3zEsB4WeOZDI5vHb7w7tfSTfMZpJPAG4h/zn+smqzGj/XHrQcon4iBrjVt4KELSxiRZ5
         JAztiAUJWzCtdGTXc4j1asBC8kS/vY3OVaQ2rdIkj9j0YqXmxV4TR++2aCMxOqBsMiJo
         1TPje7pOGsNpKk7CUXh+Cl4Vd5RMJXEu94+EA+spvgTlkCJmNr5RtXT20JT9QGXLQRky
         bGTfxqhLDWfX2rLvoOR7UXx0vPhaY3QM1jn5Ryc6fXQGr0n2hYp45GX0gDvlPOQHX87n
         s11Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6acIDO/yLSHaTBJ3UgoAIFwVfQIAQ9KQI0uf47PHDFo=;
        b=EEvH3LQDn2wpZDYS+MsYg9hyC8NnfkQLB5ALCUH2o14l6VjZGTMpAM4BHU7oFvrUJ8
         cd2DoPIlE/KaRDtHJA9qeDCXvqsNQrFH4Y3zUipUwKPJUe0jM/leT72jmTRRM0xs4/xi
         piDef80aL4qH01NGbTvcupIfdph3h2LFtWRclez7J+A5tbtLVs76GC62K3HTN8Fd3Q8C
         SAiSg75qrIV07rrP9qXrIN1k9EY9kNz6DUINeXszcF+Tyt40Kkr+Y8pwJCpXNkkRdLbr
         o2Ib3tKejbJ/VYZEP/8aO82xYjWoxN3ZbN3IVXKTb4vRtV6czKfbXFlLHbbt/8rKljWU
         2S/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dVgWbHwn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6acIDO/yLSHaTBJ3UgoAIFwVfQIAQ9KQI0uf47PHDFo=;
        b=ABcPGzIV8fhW4GY3f/opi5KpTnP4+eQzTnscw6LYIrM0t65EogHiIQTrAz+0TV2d/y
         mcsIOU+o7lBJIa4vfUk5THIMFsUcG/WQtPQHc3OkqQYd79xtb36bmZdVodMtd1NVa/NT
         cmUJCSObdN8Mq+TocR07SlSE16Wq4cPFXaUtoFbsdc2ZNMi1uTU4IM68lByACES/sI8u
         Bg/H+cnvJ68IdvG3SRtWv29SfU3OJWGIMCq25xaodEhlc4fzCswbMBerva1NQZZ6lXF6
         /tjg5GSQnjGQZkS53kSNQqkooAXglbqNxG2bgqbJU2/6mJT6sU0J+kmKIWKELAOcwT26
         KHhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6acIDO/yLSHaTBJ3UgoAIFwVfQIAQ9KQI0uf47PHDFo=;
        b=oUdA85wG5c3U/zRioJAOCRUs61eCeGO9G/SXzj7JpPTzNcehEOeQ1m8rs1jQDv17C1
         tI/9lWU1u9thnkrVb7JoZG/2tDVD+gy6dUYkj8I+da/FXOenBrsMivgbgDCrBUZtPKwg
         EqSpw7U9f1HbyaGxsh4nDQ6Pl9dMjQtLfl2Qwev55OgN32GfCno9ssZ1NGDIGwe9+kKK
         dEfMPCbdmwg2E3me0hr3hjrxCMF5LkJ8V92GEDR0A2PxkiaDJxYREMEbmIfblNHVQznr
         8pD9fsWCS6yENAf4GoV8FNOQG4qAUgi5TQzgt7We7bOsVnBogqOAqHR7bgRwVsMx/7q6
         0h6w==
X-Gm-Message-State: AOAM532y8XPOo+SuwbhlqtmAGrUjVIToJVx4oJdBWKEJUNnpxzZakVAP
	xItfRwNsxF1Ge5tCXvhYmKE=
X-Google-Smtp-Source: ABdhPJwUOqBoLRoJvMyAVbXjm2LiLBP4jQL4qaXWpIjqIImNilHFx8cDBfAy+mAiADuxV+9inYJU8A==
X-Received: by 2002:a05:6830:1644:: with SMTP id h4mr3713508otr.349.1615560625797;
        Fri, 12 Mar 2021 06:50:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:f043:: with SMTP id o64ls2233261oih.10.gmail; Fri, 12
 Mar 2021 06:50:25 -0800 (PST)
X-Received: by 2002:aca:5b02:: with SMTP id p2mr10195781oib.90.1615560625509;
        Fri, 12 Mar 2021 06:50:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615560625; cv=none;
        d=google.com; s=arc-20160816;
        b=Cx8xOt3auB0ihAnfn0nvV5k8n4XUSePq3to4OMF+wRW6WA16v6VCmOtsoF/Cap8ehX
         bN7DYRnYkLXDVv1efgtWIZNl6Oe6/O8xftyV8DLG/2vZQSs9mH8oMuItGZteVo/tjxmX
         TnoV/4oOCimwlBbR8Lt2cB/jWVqIMCopnyV831A7mjsvAPYyabluNcsgp4G4DmNL51a0
         scuUPZOFdpcgU09JuLpi2WWvBS+AaBz6pAPPiwIgcqxqo/KbpG2vaS8nm8KMHgywjYEA
         ED6NFD20MTs4UJLZbsn+cjbvJ4iSVdxSBbIFu4CAM8FJw9G9Z1IM4dblmMjwfrtOlI3a
         sLhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dWHnToSwExfied/vlTN3Sdg2BhGnFt56vTuAsL518GA=;
        b=ByCKuBmr7TNx3dDyErvKCKY4PNBg8yBjpVz49Ao+4KDoogLxeZkYQTZ2xVZ1dUhH37
         ROqmH3XCbZ4SFPMYnckOBG//4ili5/A4g3oKxpFPZZQiS4zRY5+WsRp8TwBTTnsak+49
         zARERWOFEbibM3XQ/FwTWtEmCDvaBbBpGPlJOsNMdxECtd6A/3foQjnqMMdPtfJ3njUg
         X3svZWL7XZx0u0K4PfNTStjrJwk0OGDVMbBHzXXR1xAEjWKmYBHK8cHwQuJdQP3oMjdG
         7sgdj9dINZEbJbgJXM/fJ294Ydf6HKM3fdyrsXuZ4z1U19iAFjtaK+adRp3xkhQLcM0g
         i7vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dVgWbHwn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id i14si309151ots.4.2021.03.12.06.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:50:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id q5so3356125pgk.5
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:50:25 -0800 (PST)
X-Received: by 2002:a63:455d:: with SMTP id u29mr11898210pgk.286.1615560624740;
 Fri, 12 Mar 2021 06:50:24 -0800 (PST)
MIME-Version: 1.0
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210312142210.21326-1-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 15:50:13 +0100
Message-ID: <CAAeHK+wFT7Z5_Jg-8afdu8=mVqTwcnZY65Cgywxbd_0ui+1BEQ@mail.gmail.com>
Subject: Re: [PATCH v15 0/8] arm64: ARMv8.5-A: MTE: Add async mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dVgWbHwn;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Mar 12, 2021 at 3:22 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> This patchset implements the asynchronous mode support for ARMv8.5-A
> Memory Tagging Extension (MTE), which is a debugging feature that allows
> to detect with the help of the architecture the C and C++ programmatic
> memory errors like buffer overflow, use-after-free, use-after-return, etc.
>
> MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> subset of its address space that is multiple of a 16 bytes granule. MTE
> is based on a lock-key mechanism where the lock is the tag associated to
> the physical memory and the key is the tag associated to the virtual
> address.
> When MTE is enabled and tags are set for ranges of address space of a task,
> the PE will compare the tag related to the physical memory with the tag
> related to the virtual address (tag check operation). Access to the memory
> is granted only if the two tags match. In case of mismatch the PE will raise
> an exception.
>
> The exception can be handled synchronously or asynchronously. When the
> asynchronous mode is enabled:
>   - Upon fault the PE updates the TFSR_EL1 register.
>   - The kernel detects the change during one of the following:
>     - Context switching
>     - Return to user/EL0
>     - Kernel entry from EL1
>     - Kernel exit to EL1
>   - If the register has been updated by the PE the kernel clears it and
>     reports the error.
>
> The series is based on linux-next/akpm.
>
> To simplify the testing a tree with the new patches on top has been made
> available at [1].
>
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v13.async.akpm

Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>

for the series.

Thank you, Vincenzo!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwFT7Z5_Jg-8afdu8%3DmVqTwcnZY65Cgywxbd_0ui%2B1BEQ%40mail.gmail.com.
