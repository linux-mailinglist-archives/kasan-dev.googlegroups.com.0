Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVEJVHAAMGQE7Z5N3XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B3256A9B014
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Apr 2025 16:04:06 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2cc760e316dsf695186fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Apr 2025 07:04:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745503445; cv=pass;
        d=google.com; s=arc-20240605;
        b=BcWXKpV+sM7RsVKP2GIQsJrFG7BpZb34RNQ4HGrt4RCT5HmVscRMv/HNO0Jx8Cm8nn
         FxT4lljXrjrFGgKX8MXYpZJp3IBWVZ3KqTMDdTMlgwXSCI/NmOtzQtJWAlnjr47WE4VC
         Jr2JfGUIQJqLmQO06EsTXNnleqva8RNAJG9JFL/QYuFLbI5sysH9deo0I/ZtdZWmb4Ov
         UApHr/OPg1MHVfNAPDRSqKRZXorrwG1v6q6erzt4ZleFLTjB1Jw4UtWYFZpDeJv7Wyj8
         kkun7k5Q6A+EXpE5ebav4KDgdTn/degDQMWuY+i1Nipa0WYyawCINY1xWVQKyMXrwXOk
         JmOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KbEqEe2XDVs6ZCSr2EylUmtxIwTAMzkKAjavksTFriA=;
        fh=Pya98L7/rGn2ChJRX9DencwXNCSOZmNlEd1pBfKzUdQ=;
        b=cLec+BjhjpbvpMowjjf4edlb3LEZzHaVC8TNJmIiELqlBiNX9sOvTh2GB17Je1dIDV
         JWUXe98mI83caYgDrRgTpuEQtieFM5OhRFvv82R8zBwmz+zhyE8tqKEwlIkSiuHrsDed
         529i0UjnWjaShNpj/MMUPLdZymlOMwNaF2meUcJ3WX/Xdp+gq48EzuopQI7ed9OKxxFW
         YacsZlu/ZjJEFxKw5zho4wv5opuwhqmFmjby02o8fzE8vQQ3x6q9ySQUOaU6Pn1/i4w8
         V3hlHE+bouU4FsKUzsBN6fGo/DpejgqRmokqa+Dxo6MsQt14Q1likFBQLquGiOLGpihL
         X/3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=x8+THR0R;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745503445; x=1746108245; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KbEqEe2XDVs6ZCSr2EylUmtxIwTAMzkKAjavksTFriA=;
        b=QXgJXtZVFFTC1RyhjDXrO2lYUihkMB1O+A8swK5Chmx7apmEiOCcQlzEJbe9qTjDbd
         wPPc6gln8tgvkaEQg6R1W+UBnFfxeYfDnVsAyeTNQxspWywE3wjwHvbsvcgJNCuqzTM5
         B7koPgk725EPuPTVay+21K9s9aEDVM201iDmQcPIBPUeKWd/wf9sCYnWj/8xvKkHEXAm
         vUi8qlc6zGlQP1g7xakvV9K2UUWi8/f0KE27iwKi5AhMORqE9WJxErzS0hnqhFvVj4T7
         lf5CM2dG55qXGNCSH9XdSPNkaEjR4auXW/2BXUmnDndnVN+9dcXyjXsaD3Lo4lZYe5uT
         tjYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745503445; x=1746108245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KbEqEe2XDVs6ZCSr2EylUmtxIwTAMzkKAjavksTFriA=;
        b=jO4Ap5cqM2nX34QfzHMtAUwhi5f6lb+eKByn5T/a9eer/z9t18mmvrfco+Z0ERAGTa
         ot2yNxfxU0En2+Br5e7Kc3hq7k3udGkUosTUPG81NLGb3HVoj87A0sRoZNUY7E//R03s
         QmaD5tHOzJASg/6NoC3L+3+V5t6zDruZJ5NcZ8gUEpywntG5LAz23FU9hy7wghLmEnvi
         LNO47gID2ksV75j7w0ClK/8KKOwRYhEzOgSEiQu1FTEWsGDaexC9ki75+oD0GqNUQVhR
         yF3NEXemrTkE/PQnEHD7HeLkvM0H0fGXCAkr+s1O0kEP7yZKmQ92kXoPPVs3X2fA5HX6
         K6GA==
X-Forwarded-Encrypted: i=2; AJvYcCWXjzOWVg2SrepgigtVUf18CDw2bN+yZSaGQApd2kp538q0CVwe0JCR3p8U//4RneTACb15tw==@lfdr.de
X-Gm-Message-State: AOJu0YyC6PbbGPdu5jnP6m1HlNHBkUIt06lPWxjcRafkk8kwVoguBwAS
	y+KTZN5FaoWR3cFoRHnNH/YUzaSqOkIicN31bBCRm19ZjeSp/Gdy
X-Google-Smtp-Source: AGHT+IFwZCajtpXH5YauxMFhtMxyqTRhtUGDc8bEcYhniCfpqlXChfEguFQXbVWEUKmqtkHT/uD0EA==
X-Received: by 2002:a05:6870:2381:b0:2c1:a810:d697 with SMTP id 586e51a60fabf-2d96e444ddamr1497644fac.15.1745503444715;
        Thu, 24 Apr 2025 07:04:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALEKD+lsh1ntgPVA3O78aV6r/HFRRePqm6Vr4OZ7DYAPA==
Received: by 2002:a05:6870:241d:b0:2c2:33d9:946e with SMTP id
 586e51a60fabf-2d965a84deals433839fac.1.-pod-prod-08-us; Thu, 24 Apr 2025
 07:04:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXkUgjqbxUC07yXmIbt4Ry1vm+6UH0G+FZygWn1U+j98XpKh1pA/ORXsyibxAgvjYMbcAuW8FWXvTM=@googlegroups.com
X-Received: by 2002:a05:6870:701f:b0:2c2:3fad:760f with SMTP id 586e51a60fabf-2d96e89f3f7mr1316932fac.37.1745503443780;
        Thu, 24 Apr 2025 07:04:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745503443; cv=none;
        d=google.com; s=arc-20240605;
        b=k7laC4CQJKOWHjMOyyt60p17vrslI3E7wwZRDNOpQ2+4LjFej8cEYgcDp+aeJGAwP5
         VTcsxDNgiEX0pf6j9MP+pUTLVGEdrkAbwRKWqSw6llo6y5JMpfrnPbvhXF1mChDD4uJK
         6V9Rf/WJJK5JhTlELrWAI9OM5TudgupKp4M5CITU3TQ6qHgP9kBYiHDF3B90pjxB9uBv
         n8rKorhjq2iFL1AXvcMfVMmug+HoVDkicQPl51W5OGmCc2BDBvh+huoIoj6VgJz3uEJ5
         AcbZcGSJkNbr9VdPGmL2FpAp88Z5E8v3ZBq9y/LY4uAkud687qD64EbRiulsf63Ix8/e
         +MQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6ngV1N+K2wLCHm2Zau2mYRJ29Fj0ceXNMX7YLmapOIk=;
        fh=etYAzXExjCFJSNevzksjv5LJOu2ddjHSX4mS6/16Duk=;
        b=VzwjcgUje6RHI4tAbAUeVBf1383ziPw23dKsJjaosyIZDGIWSsOHn1BEhVst8IntgV
         iXDMq09hpH9M05oe2XS7HacSNf4QwxjH/OsNKm9KquXpuPM6WFYTCN2OmnmisU4k+/5O
         LVNzyyOnjB9ph889eNNXAlrxJuUm48lBFaAHMXeeVkfQNGRzM9o5nDmWK86lBOLkq2Gv
         BoTdJ5TcUApnS/NgvLkc4Ek+kgl9QS2+6VeVV1tN+o7rtuigb0t3AcOeLebZlrzY01mL
         wak+ZttBDvR63shfIB/KCfKaz5ErPlt+9ROUF74+TdS/8A0Rz8jqb/kXSpVplLsdGoel
         82dg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=x8+THR0R;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7304f165b6fsi20275a34.1.2025.04.24.07.04.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Apr 2025 07:04:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-301cda78d48so1259620a91.0
        for <kasan-dev@googlegroups.com>; Thu, 24 Apr 2025 07:04:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW5Piar2WbMH6KKMjnhtmi95HzylVhURmunGIbVNSkwP10fz0hXHCQUfEbiajj/cHOxL9Nd7cpnFHM=@googlegroups.com
X-Gm-Gg: ASbGncuAAo1dyNXQU4ddnhBWQJ1uiLIr8YV1YGHOAdTZ7//h4pmuNREIdmyaKWWF/ji
	K23xt3Z74ToVs/MkJjQEs1eoRXs8T0cbHYPjXM4G/RZ83QWCw5BlcP6Z2n0NZzi6dLOOmcl/QLq
	KkHemNgqmmInEzcAIvw4ex15Dp1kPzcUr0WKXwA8DL01MvS6S+E7Oj
X-Received: by 2002:a17:90b:2b46:b0:2fe:b016:a6ac with SMTP id
 98e67ed59e1d1-309ed29d050mr4311829a91.15.1745503443200; Thu, 24 Apr 2025
 07:04:03 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-4-glider@google.com>
 <CANpmjNNmyXd9YkYSTpWrKRqBzJp5bBaEZEuZLHK9Tw-D6NDezQ@mail.gmail.com> <CAG_fn=UBVzq3V4EHQ94zOUwdFLd_awwkQUPLb5XjnMmgBoXpgg@mail.gmail.com>
In-Reply-To: <CAG_fn=UBVzq3V4EHQ94zOUwdFLd_awwkQUPLb5XjnMmgBoXpgg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Apr 2025 16:03:26 +0200
X-Gm-Features: ATxdqUGU-siYw04IIKznlGV5anGHNOlCDPYBUIfwFfw_Fq57MHjDZ_h43sRjrBo
Message-ID: <CANpmjNM8W67r2W8FNbcDzjaV1HVE5R77ZFgbUABYusgWBzqpTA@mail.gmail.com>
Subject: Re: [PATCH 3/7] kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=x8+THR0R;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as
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

On Thu, 24 Apr 2025 at 15:59, Alexander Potapenko <glider@google.com> wrote:
>
> > > --- a/arch/x86/kernel/vmlinux.lds.S
> > > +++ b/arch/x86/kernel/vmlinux.lds.S
> > > @@ -390,6 +390,7 @@ SECTIONS
> > >                 . = ALIGN(PAGE_SIZE);
> > >                 __bss_stop = .;
> > >         }
> > > +       SANCOV_GUARDS_BSS
> >
> > Right now this will be broken on other architectures, right?
>
> Right. I'm going to make it depend on X86_64 for now.

This needs to be done with a 'select HAVE_KCOV_UNIQUE' or such from
arch/x86/Kconfig.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM8W67r2W8FNbcDzjaV1HVE5R77ZFgbUABYusgWBzqpTA%40mail.gmail.com.
