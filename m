Return-Path: <kasan-dev+bncBDW2JDUY5AORB6GQ466QMGQEXV3QRYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id F382BA4095C
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2025 16:08:47 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-220fb031245sf54630625ad.3
        for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2025 07:08:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740236921; cv=pass;
        d=google.com; s=arc-20240605;
        b=NV4Zqdffebh1263SmuLEyKWVoYngQIc4/fmm9hd8ud4nEVFKppcMxZ93RxLt48gDFX
         azi+kH2v9XxGaFeQBC1oQteMWgqQ91dWSHYlBHcs12/hYsoPJMDHZtualRyguvog7rCB
         8/Xtvo+hU2Lejch5bIe4DjXHYfnFG91/fUAkBeFQR55tzl7/uYl+ZNLu8/aVEtH7QExl
         viZbsqYUAjCXUcQNXVjwkfq9iejCt5DK5eyZCe5Q/hC7qNR70JT+76pVNJ+Ik3fxxkzd
         fzDo8NZzW5HKNnaoaGQwiUJwiLd1q39DBlieWJa9Y7N+OWH8m8uGYWNRQoE/UXI722dT
         gnKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=eBo54CWNNzFmONQZVrDuvlUprTrAcFCMi7ptZ8+kzMg=;
        fh=doPfqS0fiFvCY9YlHnNxuCPeAXSZUxyunf7aIBH2zew=;
        b=ix70kEDLf9PxtGRbYMDyfLBj46Mc5jHE2gM6Z30Z1sWH5UUThNfFSDcZAM84/RJREg
         d2Dqy0RKJ9NY/xBwFmzNuD4Ojv6zSIwPPZPuD3QLGdR2/7PWL1diqmnDnH+em0MhayB/
         z9wVWnW4n9MuSv80p0toqt+YKqg3AW+SGL32Dtd9gLABvcn8oG5Iuxi8/KSUEg2s31+D
         IaFS6l6+pF4eme5ksBmuGFSCfiNMYRBhNVzfma/sJFkitZcnJz3SW+m5O5M512/kDTnr
         BZQcLQS5gl0g+faqR4zFNHTH+O8G/jjEr8MBnLuZYlcsmzbBjvjpktV62XRUQN2HnI3m
         xErg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OlWxVCvZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740236921; x=1740841721; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eBo54CWNNzFmONQZVrDuvlUprTrAcFCMi7ptZ8+kzMg=;
        b=CWidWZxr3kXlGTvM3vDJGU6eiQSO07Ll91KXLppDuNsE86AE18z8cl9nok3U2orFGp
         gFRIqcqNakFSDUqxLO/3oHZB9R4JrZMbF1Jpxux36b/XOfew7qlfdiT91HKtBo+qZEhZ
         VmM/g8AXuRXBCx59Jtrm06JeeydznH/49yeLs28FIdKoQJKHETh0OENGAeKyO5ivbfOE
         YOFRLnw4SH/vceZo8QR/MsCyrJsPiLWf2h8LxZOM/YnJW+25WoFUUgjIKMrbNBivzURC
         O8X070ImIXQH6lcVHS+JyZKbr7NI0bAwi6dD3NKhXTSm6a68d2AosoemfEjT4ypkccsS
         z4OQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740236921; x=1740841721; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eBo54CWNNzFmONQZVrDuvlUprTrAcFCMi7ptZ8+kzMg=;
        b=gnMnV/+OtLCRX7g2BK0RI/tCK5GKqm1jGQRZWB8BjLB913fc1kDzuH3TamG4QaKMd5
         WSdj2Z0x493/PTEloAiJEiYfd6KbZLUfJuRnK/Y5GhfVjX6dwcttJXtYnHPlOyitSi92
         /qffPmgqFROzcDzDMoEENPRDIsqE4EtxHOdpbLsGoX+msN4vJbaPibP/XtjJJ93OpfsM
         XxeRm33qMZIb2/wjktYNEBW4CXGP9X/gGRb6oWam+DAbYMYdEfgxFBGfLP11wYARM/+r
         yxy0jX6FcKzlF5o6ISNopEHGEGx4V/jp3g4DW3YaQkSR2tZJ3ACn0udKlA0w+Dh0UTMa
         AHDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740236921; x=1740841721;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eBo54CWNNzFmONQZVrDuvlUprTrAcFCMi7ptZ8+kzMg=;
        b=uBrYYomI9/xMG0tT/iZNwYyk0i55xNFOwum49GyJxKBBgv1TqntMbx/8fjYVega0OD
         q/p7vnz1A3nS+QEYfwy6OGF9IUEd46hAryaL90hYrxGSkHDRrJlmzhWscjdHfZSGo8+3
         0ohA2KY3rvHrgWltDc2VTQjoqS7RzYYywYXjGmH30UevP9rMj50rC62tgBHQLSX0sPcR
         DdAgXa9pZrwy36JNxOdcvTpo/J+qzePFlFRvm4pW140KQMIULX+T0MrGcHZdxZW6oChK
         ATysaF3SWjRo5dZjoxPqSWM5vaHPisXile5vK9q9FYSbjUZ1dYWRaSTkBVTGaQkJTrOb
         fKUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqGhpRCtqsVJ1J3+brWHaPoCFREEpPLZc4u+FDCgBWc1qWYDcP6oV8Cy3VFjhT7VjTyJo2PA==@lfdr.de
X-Gm-Message-State: AOJu0YwD1OlItjUfxENHzgr4RK7MCO4ftcMiW1hWp/Im4GJoTb19WHDv
	19ciEHTKfpOxGQy7DNPtRgrXwk2U9CwWmbF39JrTbqU4dD2IM/vL
X-Google-Smtp-Source: AGHT+IH9cwXHsJ2ZhIx1OEWQrn5vNzeq5OkLXbiTr+SxJbwb2yACJOwXG3nLNOp7fTPuQoa9X2lMIA==
X-Received: by 2002:a05:6a00:3cca:b0:732:5a0c:c1b9 with SMTP id d2e1a72fcca58-73426cebab7mr10766875b3a.13.1740236920747;
        Sat, 22 Feb 2025 07:08:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEAh+nUO1Tn38VqoSQ1aQAKE9uY+HmnJIev8j6ra3Ogqw==
Received: by 2002:a05:6a00:7390:b0:734:3a50:e902 with SMTP id
 d2e1a72fcca58-7343a50eb0dls761728b3a.0.-pod-prod-01-us; Sat, 22 Feb 2025
 07:08:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUR6vtWXq7JZwX7LVx3fFpO6fntuoCWYfzmvLg767+Vix/dsnMl43BdOBM5FiLkJtzjdWhvXd3/MAc=@googlegroups.com
X-Received: by 2002:a05:6a00:92a4:b0:730:9446:4d75 with SMTP id d2e1a72fcca58-73426d77e8emr9468482b3a.17.1740236919520;
        Sat, 22 Feb 2025 07:08:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740236919; cv=none;
        d=google.com; s=arc-20240605;
        b=ZGayLZJcRy3ZLwHkNbBr25EwnnBPRhSpnh4nGKRYhordwnDyGQOB4KsJs7VHEQhgvw
         kTKMCsDCM3Yswa3QflospdRnwXkGpWic3q1ZlA5sGdFt95eAtIT0oW04LMQpihC+tASA
         niaqQtDicwMJMcnOTdQgo3iI2Lu9o5WJ5aDnPGzW10dRNxNbxvdISN90CgR710eTytzT
         7OcOZbzdEO1HsGRPTYp/gb+DSLwmN5BBvGmVPxLmhohzbKP0xVEnB1tFseCahfTZf3Dv
         HY+Kcn+kO6U42KgZzLUGgiVrvR1KFBRBirWWvvxNKCpC/zM1y/EcGOR1mhMFzEZ8uhLv
         cazg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QtuG/5BcoUsjSrbU4qpV+q15VbeQ71cUAi9kEK9SiH8=;
        fh=9v7prh1x+Wn5pXwy0SsVVNDM20MxY4tXTk10ZfZGx8c=;
        b=UC3VDtlC0O6APRfV22XwdLSV0wcMeyCWsK3dKA2vWe1JnR+UqgnVzR2VtzXWE/fCPt
         NT8MgvSESSwIPlsdkocFGelQ828LXgMG8lUXZZCGRiqzjXReauHQev5owhaAIaUT2F91
         XQfWgKqYpYZrkY5s/Hxaz3zVFAzpaniSemxMurrdJemU9QbML9EexrHgtNnD4Uh3A/VI
         +9N96f0MSpivuDmgPW35yekEIswpbPcRWYYyWDoStXhE1JTzzQ+G0KcnH/cn7l8xvvvt
         +cxAqt5y0RTBVmVgMpsQFX+vmP065JdrROHJBhVNABA3Xiu0Rbl7qco0HrjvfSWfR3Eh
         xlmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OlWxVCvZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-adb57c5e0aesi907813a12.2.2025.02.22.07.08.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 22 Feb 2025 07:08:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-6e65baef2edso26441586d6.2
        for <kasan-dev@googlegroups.com>; Sat, 22 Feb 2025 07:08:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVAH07WgQn78rgtGq66OT9/LJnLxxNQtcjMMVbGbPxsGD/gBDBVJkzP7DHA9+J/rpOMJsXcPdrJDrU=@googlegroups.com
X-Gm-Gg: ASbGnctuxY+7u+91gxbC8a7amD2RcD1nsk00DZAiRAV3ggUL7todqWNR0cqjO4C5e65
	7M73XezUI7CgijIdk16GtaLl6g40eWQlrAcCYiiGiA0ipnvxnzDte+K2U//x7ZCiWPQod/K8hfI
	u5ruFc6GyRNw==
X-Received: by 2002:a05:6214:400d:b0:6e4:3de6:e67a with SMTP id
 6a1803df08f44-6e6ae967571mr77225696d6.30.1740236918641; Sat, 22 Feb 2025
 07:08:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb> <ffbyaler57cdwgs5axtdpnwg52jtwx7tx2rykjro755c45mihl@czmbriuhg3to>
In-Reply-To: <ffbyaler57cdwgs5axtdpnwg52jtwx7tx2rykjro755c45mihl@czmbriuhg3to>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 22 Feb 2025 16:08:25 +0100
X-Gm-Features: AWEUYZkHzCChafiSRX_ILBVkyvuq6LP-GPRD5NbeLAJBmqWSC9A2XvM186wgsYI
Message-ID: <CA+fCnZe1U_nV_ByK2+XjBdXq0WNYzB0f30BsrsZKcxyOSu9cTg@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OlWxVCvZ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36
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

On Fri, Feb 21, 2025 at 4:27=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> Also I was wondering if you know what "hwasan-mapping-offset-dynamic" opt=
ion is?
> I noticed it in the llvm docs but can't find a good description what it d=
oes,
> even from looking at the code in HWAddressSanitizer.cpp. If
> hwasan-mapping-offset is not implemeneted for x86 I doubt this is but may=
be it
> could help in a cleaner makefile for x86 at least? Especially once these =
options
> will be working in x86 llvm.

Yeah, reading the code [1] works better to understand these options.

My understanding is that specifying
-hwasan-mapping-offset-dynamic=3Dglobal without -hwasan-mapping-offset
would make the generated code get the shadow memory address from the
__hwasan_shadow_memory_dynamic_address global variable. This option is
in the common code, so it should work on x86 too. But I believe it's
intended for userspace, not sure if it would work for the kernel.

Even if we use this option, I don't get how it would make the Makefile
cleaner - to me it already looks clean tbh :) But it will possibly
make KASAN work slower.

[1] https://github.com/llvm/llvm-project/blob/llvmorg-21-init/llvm/lib/Tran=
sforms/Instrumentation/HWAddressSanitizer.cpp#L1929

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZe1U_nV_ByK2%2BXjBdXq0WNYzB0f30BsrsZKcxyOSu9cTg%40mail.gmail.com.
