Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ777S4QMGQELVU4MOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B2299D4E5B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:12:21 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2e5a60d8af1sf930099a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:12:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732198340; cv=pass;
        d=google.com; s=arc-20240605;
        b=GxyP5MeGmCWIe3FMxqMD8LvaHo4E1IIiVq2zSobwjTLD2URZ6jpcehKtcHBp1Jdr+Z
         78aLhbsh6RaorqE70J/NOgg1KJTHj7I5cfR7cfaexwFHjst2loFdAn+jubx95SFXjb36
         ASyuwPPMOwhm8tnCxVW3OjGSFCy4ITeOVXJn7ObaYYiB5pRwccVRDnymAWl27AmjZPKL
         7Lce/rYl8l0JAC+UymLhk0SFeEUAEoh6q5A6Ke1KE61RO/pDc8IpIniWubsdxzKS23ne
         ZgxEgyRJqi4fX9xdiv5Z/sM/F1Nxz/wqAcnCN0gTtMZviEqjqbJadUUkHOcaiBSmlkYn
         mqQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zAUJ92gkXhjxHcDdxC/M630kimXdpaaVkLyazrivPWg=;
        fh=JCTKkmhTOwVPrdF+mvbSnPY8fVd1eupq4NeeJ/litsw=;
        b=XV2jXC4v6QOqUYWSo4CjYEQTIS5GJ040jX3ULTuc399yI7FplfFEL6pi0nRINILeb6
         GM881TnffiO0I6Zjg1rXymoBzC1TuAj35OB5Ahub9E8eY971U5MsfPS1GQaeeT/SKxmk
         9MqbLtDNbgrrQIiSf5nv7ZlfUmFmdPHOxjzeYr9M7CmpbFSsFdtTlac5Ke1an41iW8p0
         haA4QACMnTrudZzTipidPIpDD+C65Dq3SN29YLXIO4Qd96dbpMnyry4/0q50W8XUMlFt
         CvGrg7k+Fkm+hYlcLeu6a21D2m6JhRrR4FpRrbGS7Yfpmal7W9LhWErNNZtXMqWnkLWG
         KpDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uhacbdny;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732198340; x=1732803140; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zAUJ92gkXhjxHcDdxC/M630kimXdpaaVkLyazrivPWg=;
        b=m69GEVanwyggjQ/lAhMFtaznRKyjnn+Meylnz783ZYGHvM8aFgIivVGjn6Ku4UsgpR
         MzmN2UyGpr2AcWQvgfS68ZVOHqBoBkB0DmWKWyMNBJlBZpF3Tr/8ib27rjgv+yo1aBgj
         aHhJd4bIaY4gTJp1KPulc9DxG57cZ7hT2zveGMGXteWka6ey7hqSDAcxmSG+Yb1LUaDp
         jf4sIYAl75JVKNVyfB5s1XQgOg95o6CBXahXwhZgLp0YZuxaqaYRs2IvtsN/LfMdeB3h
         Fhc/Eupv4wbqmjJ8m2QpRmZEf3O/QtBgDLouJgkZzbAWvcChRXyStIRBEvIzg1aPceRe
         Yj+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732198340; x=1732803140;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zAUJ92gkXhjxHcDdxC/M630kimXdpaaVkLyazrivPWg=;
        b=nU2NWWHOXPZFzka3tg7XMTbqJBGoUIM3+eiBvd60/Q/Ui2p1Iu62Du0qmr6tIDt6OR
         5HuHQdMuKiNVgApy+peey4d2T5VGTMbcafJrdc7YLfS3ZPxi3tvDwiHipyMY+e2uYL7V
         A0FWn1+iCGLOHzzbyKw3ErCuc9JgnS0DmdYz1UST8aR2EtSbtMD/YgN0H7JJIzExJLcE
         swdQhccnqJghciwKGDjX8gdthZURwnAXfSwDu2TjcflKAJ0QzuO8NrUPF0R3K9UFp8kF
         vj4ujVOZ03+IV56GnziWaTzsm1VRBfcLqC+r9TVU6Th6bRKZbGc51/NsUnpHj0m3MMcl
         9GcQ==
X-Forwarded-Encrypted: i=2; AJvYcCVpEQYy5mzGSuoG36arEHw5TQjM4wKFGMUkzWNlq/ms94tzSqDtndb/y/x8qaJNfIpC3Bf8+w==@lfdr.de
X-Gm-Message-State: AOJu0Yz+fTnmoEOjQlzVsFMTT+KgqqKRUpIDhzT4R3qAvqBKxo0e83m9
	eeHmjhwYH3o+py6LbaADkM11CM0jHiqEu+5M4gNioIvQ/Q4012Oo
X-Google-Smtp-Source: AGHT+IFCErLtt12IMmRSU0/3ZSklLpUt9vsC8kMJU+gEky54QXQBoRP2Ede/akSh6wXmkJLc7K/XLA==
X-Received: by 2002:a17:90b:37cf:b0:2ea:5485:9cad with SMTP id 98e67ed59e1d1-2eaca7ec2f0mr8390567a91.37.1732198339630;
        Thu, 21 Nov 2024 06:12:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a48:b0:2e0:830c:9410 with SMTP id
 98e67ed59e1d1-2eaebc3e9e0ls753566a91.2.-pod-prod-04-us; Thu, 21 Nov 2024
 06:12:18 -0800 (PST)
X-Received: by 2002:a17:90b:3146:b0:2ea:3d61:1847 with SMTP id 98e67ed59e1d1-2eaca7eb664mr7071230a91.32.1732198337833;
        Thu, 21 Nov 2024 06:12:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732198337; cv=none;
        d=google.com; s=arc-20240605;
        b=A6tnHbtITpnJYGR1tf8hp6badkUYt0hzHffBhG+HfrJGDNRNNQTFzTPAIMi21Tur7z
         +31Ji1vVll+R8ZM/OeH/o+opUQ0HEL1eZD0Xg82I/EKUz2tsWGY1v1koJKMiF/flx+ut
         BfxUwT3SiKK2KDCJ4E0ZyRz1rB3RQ6fcu0N4RiLqSigvLsw4WRMkiBlT5RRzdG5xkmVD
         ZFtRtKe1vrNGxmARbnWHTNihkBAU2Ymmi/Dw+NGIbnk1UjOU8S+wzkGqUU19KMXudcHi
         aMGgKy3jWkEVL+X6BCI0wEHYU3oLEdf8BxcPNyKU2J5g4tdKXckdUFXvOsTXT2fo5rs8
         etBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aivyQMPMYdcek9UTr2/mGQTkOks6tzNJ0DhZj1hoM3k=;
        fh=RFwShgq0QJL05RiZt0A5CLRXZAsP1H30PcBFDXZjC9k=;
        b=FJL67+UPfdBPypBmTZaMsU5rifHHh5utLzHn1XZNudLSAMlp9zJfWLRWgt6i9thkLD
         TGUZbvGcUtbiWV8c5t2bpuJMU1j5fpB8Moz5/89QkvbaFd5n7T/lAG4SSOJP9J/uVUX9
         G9y20AHybxBoDE9geZIwMWfsr4fBcZzfmn0Wg0wDfeQX8lGHm3Xc/uALaih8UQd9YLOv
         jNu53ypJLobeYEo+RXAOTrHSsDNwrmiujts/N5ld8tyolE2atyuD1Qho98YtC5oBUbrq
         g/zMcjOFhjEVgtX6WLDuoDsIdcjp4wdJPfPCLF2eGbByTPdqmudOxme8L7YVaoDy5LTT
         sYGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uhacbdny;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2eaca6f6b91si266897a91.1.2024.11.21.06.12.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2024 06:12:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-724d57a9f7cso391591b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2024 06:12:17 -0800 (PST)
X-Gm-Gg: ASbGncvFCTRItYztplijzRQTezUWNZmV9yQ6n2aU8ycTvwjLcNtXDwcGrOh0aDKCtXa
	WR21sDkNBR3AVrZt3wYVTprS7l0xnTheKO8Iery5+0RpkAAHNwiVYaE5xFw9tFg==
X-Received: by 2002:a05:6a00:cc7:b0:724:5815:5e62 with SMTP id
 d2e1a72fcca58-724beca4220mr10479357b3a.8.1732198337134; Thu, 21 Nov 2024
 06:12:17 -0800 (PST)
MIME-Version: 1.0
References: <20241121135834.103015-1-andriy.shevchenko@linux.intel.com> <CANpmjNNzFykVmjM+P_1JWc=39cf7LPuYsp0ds0_HQBCzR+xOvQ@mail.gmail.com>
In-Reply-To: <CANpmjNNzFykVmjM+P_1JWc=39cf7LPuYsp0ds0_HQBCzR+xOvQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Nov 2024 15:11:41 +0100
Message-ID: <CANpmjNO8CRXPxBDFVa5XLYpPuU8Zof=7uvUam9ZFVPP9j8+TEQ@mail.gmail.com>
Subject: Re: [PATCH v1 1/1] kcsan: debugfs: Use krealloc_array() to replace krealloc()
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uhacbdny;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 21 Nov 2024 at 15:04, Marco Elver <elver@google.com> wrote:
>
> On Thu, 21 Nov 2024 at 14:58, Andy Shevchenko
> <andriy.shevchenko@linux.intel.com> wrote:
> >
> > Use krealloc_array() to replace krealloc() with multiplication.
> > krealloc_array() has multiply overflow check, which will be safer.
> >
> > Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
>
> Reviewed-by: Marco Elver <elver@google.com>

Unreview.

> Do you have a tree to take this through? Otherwise I'll take it.

Whoops. We got rid of that krealloc() in 59458fa4ddb4 ("kcsan: Turn
report_filterlist_lock into a raw_spinlock"). And the replacement
kmalloc() is already a kmalloc_array(). I suppose this patch is
therefore obsolete.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO8CRXPxBDFVa5XLYpPuU8Zof%3D7uvUam9ZFVPP9j8%2BTEQ%40mail.gmail.com.
