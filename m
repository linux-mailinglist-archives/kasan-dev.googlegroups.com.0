Return-Path: <kasan-dev+bncBDV37XP3XYDRBJWK4CKQMGQEDARKMCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AAD755B0C4
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Jun 2022 11:21:43 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id i3-20020a056512318300b0047f86b47910sf3332294lfe.14
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Jun 2022 02:21:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656235302; cv=pass;
        d=google.com; s=arc-20160816;
        b=tOhaTGDKdnWAgeO0Dq/KIaiboIDdv0VsM4ZqaNW09gD7FyN8GfgAUv2L93PA71hHTa
         75WM5TcRbvn3aAuLJWBXBNUVj4UUH9CV24UzRgHavXNmKRHgi1DEWi4ENFC4tVEpl9W4
         guJE1aU/QYWcAkVOMwvQRia6gwSdzMlgyReTPlVOgDhM0g1ztLByURz329/1P6YicbEn
         beR9Dywqn6OY+kGtfoZ4MHfP46sFQbTAEhLV2qKvtShIFAqVrG2obiLJl9tV0bILE28T
         bDfF7pu3fgMnxDZ20R7GDbYbsw2ym/kgFBCI3VVH28CouX/QK84qhCzZJkUGKM5JHKW2
         tNcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NVOcQEDdAkuUP8wGuTCClp9NCLMmBvwJV2NmtPt/8m4=;
        b=yyz+7edv8d2EEfQFXzBHHm7WiiIt0lKQ26YKaGictwQFX6eWgT80BPzoIIE42pJLUW
         fg6yGZmaaBR4NDYmiEKW/xg4aRmeU+IVw3OmE9NNICIoGuSmZUYfVhFUNl/DnNv9saF/
         fSKJ/kNp3WmjDA0/JuNhFeXMOPEW6tJkIctQkWnZvrmH92UKybIhMYE50jxfcxyyfLbi
         wrCNl0sjy6uFnAyrq8wm8Ik/xUHGc+i9GUxnty0fBy8tSzZhsmFgfP/MVQcOvedbFj79
         wen7nMqJUOiUa0ZJQ5E11H9XboD+GxNvSnG6rj0weVEKuYvstYPVV8wTws9eJgD0Xh6L
         ri3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NVOcQEDdAkuUP8wGuTCClp9NCLMmBvwJV2NmtPt/8m4=;
        b=oWoNacYBets9yQhnltmO+lDWbcDw+KO4p/M5O5Lhu1GeQXqAmYP4Huhih+3nyPyAp7
         jrw8vtkzD47MiS7Q5fr5qRKc2AHUzo5Iw+SpYct04MHgzGe50XT3DTvn+Yyy6YpcGFIW
         dkB6DlwV++vuEoteb2LZfHEeCT2B05Ztl+uhZ6t4Ii0k8FUbpUrHJgowEsQbREjGyo1x
         36lGSxjclDsDKmYK+xOpky6cPDanMg4rXm2qjBA4DgpCrry1Z6dd0MgCKqkROuiO2rkb
         fd4kNOzqFgLMTy+PTZVSF5mNJ7Xp1H5ZCPc2pbG4xp6veDwDufKGJbac3lkWPloOurep
         5vSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NVOcQEDdAkuUP8wGuTCClp9NCLMmBvwJV2NmtPt/8m4=;
        b=v5bijIG8Yy4DKo4gBD1cmnPzmzRvKRIGjhQBjCmOzteT1ee2qlrnL6korQMsUallwF
         PtSaNCyzQDi/7Ahg3gFuf7jP83Ss0i1IIfIPzDuo/kdE4D58L6IPlSEk/U991QX0fG07
         7NWsxPdK1DYS1Q5oBdZMhc1Ikpjaa5dNhPmnPYyrig5wTzwT3+IuL4p9wh9x3EStKIjz
         hwkTbTzsSXDaQg/dXHiV4gdmQwVS9bJmnyJAZqyrQAdDN2LVLBei5jRi4DvttHSNMfsA
         Cx6TYvEdYsDEQyGL6qTHXGgKrIM/Mg8wyX8xAD/IuJ0PN2+mCEjt/CSJ89ReSJ08NfZ0
         ON0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8Yr49hA+VGhMtpcxZFksLhYCdoUFFX5KkUHNQRxQsi1ehM8JWJ
	ZjyQL259IlBqz2z+IwAoz0g=
X-Google-Smtp-Source: AGRyM1u72IpYLrDnHXN6N9UBzU2woviT40vCQmAuF4QbHPjk/5fU6gxchjJHJvV59c2AxH5pp4xKrQ==
X-Received: by 2002:a05:6512:3d08:b0:47f:6efa:4965 with SMTP id d8-20020a0565123d0800b0047f6efa4965mr4676083lfv.363.1656235302545;
        Sun, 26 Jun 2022 02:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls2248249lfb.1.gmail; Sun, 26 Jun 2022
 02:21:41 -0700 (PDT)
X-Received: by 2002:a05:6512:3e2a:b0:47f:7549:e3f1 with SMTP id i42-20020a0565123e2a00b0047f7549e3f1mr5047215lfv.386.1656235301059;
        Sun, 26 Jun 2022 02:21:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656235301; cv=none;
        d=google.com; s=arc-20160816;
        b=moM3tiwv1Fwyi9ZDenARw0zJjXHcDf0OsXVuxciNSFeeCbY8lDSDjqcb8t09sNVklG
         IWV5kmgXk9z7kJJWLmlZd7e3oBgTAZyG1WjtlT4Qqb2r5GUPcFu1w/YuYZeneACZdYj4
         ddRpoO92PnmuxWlx20RFK7TozaGMbCyWBfQhyxHHVn7HBuXBTbbTxfPLmYnklKs3Nn/1
         ApIhw6yzISK0Eh20SAzTIgVJGf7QM8kh+HVZ/XN6XpWrlu9JFvfPXq2Ydb7pXA5A8rNj
         N86h0b+OXQOPSRuMCQoFUE1eQA6PhOar3dqXh9FKPS4VRdFPO7YH20FXkAfTmlV8T/CV
         FsPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=d1GTVrafSGnwLmKWH9V43K2i1jgUD9/OFW+pPUXMEsk=;
        b=xkd3lQZVpFx+Eoq2HtXjIYdsY9jVQy1o22Q/0XWdPQa5XrRkXTWGFN7IpQcHn9E8X+
         1eTZDy5mtNCqrA4Uf39SmYB6s4HSFGNIM7QOwVSjrnSh8iWtGx9VAqwVbuoEfta9+zvY
         KuKOCwwlcMl/A3qWNuemzpY6XqCLln75268gzzZltUYzsJLcm52S/hou9au0W8Yho8GK
         JXbM30W5yhYBNS6vKXEjEFxtTWqv0ykudi0C23MtyJMTTS6T1qBQZF7pC/21xSNXMeTm
         SRFkkorCVuWksGIhhOhuRFNZ4C2THXtAxqNH2GVyE3OmY575U2hVZZI0ZE2zxrmPxk7U
         Fnew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o19-20020ac24c53000000b004810d3e125csi84814lfk.11.2022.06.26.02.21.40
        for <kasan-dev@googlegroups.com>;
        Sun, 26 Jun 2022 02:21:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8F9402B;
	Sun, 26 Jun 2022 02:21:39 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.71.61])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 43DBD3F792;
	Sun, 26 Jun 2022 02:21:37 -0700 (PDT)
Date: Sun, 26 Jun 2022 10:21:33 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Will Deacon <will@kernel.org>
Cc: andrey.konovalov@linux.dev, Catalin Marinas <catalin.marinas@arm.com>,
	kernel-team@android.com, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
	Andrey Konovalov <andreyknvl@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 1/2] arm64: kasan: do not instrument stacktrace.c
Message-ID: <YrglHeC9NPKsC2/7@FVFF77S0Q05N>
References: <c4c944a2a905e949760fbeb29258185087171708.1653317461.git.andreyknvl@google.com>
 <165599625020.2988777.9370908523559678089.b4-ty@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <165599625020.2988777.9370908523559678089.b4-ty@kernel.org>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Jun 23, 2022 at 08:31:32PM +0100, Will Deacon wrote:
> On Mon, 23 May 2022 16:51:51 +0200, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> > 
> > Disable KASAN instrumentation of arch/arm64/kernel/stacktrace.c.
> > 
> > This speeds up Generic KASAN by 5-20%.
> > 
> > As a side-effect, KASAN is now unable to detect bugs in the stack trace
> > collection code. This is taken as an acceptable downside.
> > 
> > [...]
> 
> Applied to arm64 (for-next/stacktrace), thanks! I had to fix conflicts
> in both of the patches, so please can you take a quick look at the result?
> 
> [1/2] arm64: kasan: do not instrument stacktrace.c
>       https://git.kernel.org/arm64/c/802b91118d11
> [2/2] arm64: stacktrace: use non-atomic __set_bit
>       https://git.kernel.org/arm64/c/446297b28a21

I take it that was just the s/frame/state/ conflict?

FWIW, that looks good to me; thanks for sorting that out!

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YrglHeC9NPKsC2/7%40FVFF77S0Q05N.
