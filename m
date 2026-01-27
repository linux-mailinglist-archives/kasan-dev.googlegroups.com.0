Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCMR4XFQMGQEWE225HA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IH0uOYtIeWl0wQEAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBCMR4XFQMGQEWE225HA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jan 2026 00:21:47 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 755179B5E6
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jan 2026 00:21:47 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-40414b6f18dsf13311186fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 15:21:47 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769556106; cv=pass;
        d=google.com; s=arc-20240605;
        b=LS9hxlFFu3DwQkhXSv1TnZ8I/5zHIZn2nQvbbCgZ2kVEfyRH35AnbiNUkl/l6p690S
         BbzzVdgLwzbCoDTpe9AwWuIycXMDjEp7/4w3IbGeEngOii5oWhKzcKXcLywfi/sBMNBc
         fCLdXeS1gvSuWQf8/URX1EfnWa1X4IJvdVN99bDTGksG6KR8YmKOdzumUc3jV4gSGg3A
         shiVDhcw/niTf5DS9XoaXXoSXxej0shKJLwsnJbSWs/c9AYRAfnq/cY64Y1+bywUHtQb
         SBw/EKnVCA//fEAYQOhobhPQOtf+mAz7xPAIoO61JP+jgqmQG+bOd82NUP7DwSEKfJ92
         4owQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=y+ctrvGl9D4pHvjvlKV//jR6WvFzyeez1ST4iP4GXE4=;
        fh=AQUx3IVsaZomgyFTLgP2gArYu4emOUt+ZxWSdlnLRWE=;
        b=I49TmidGCWj+PNsuyfrnvdnhMHC4Goam3FCMkN+M8qduVrqB87y91icnAsi8DP/KJd
         PXHL+VUk224DOFqgj12KuK5Xj56+9lod1Ck1add3GSY4QKOMjKYuu2W/Z4ay1Cdw3s4m
         MiLMjPEwDT0jCsZLqnnLk3msjf0ey9l7up0VxNjCsr6U9OU0nEfvh+YMZH9GJ+OhlWUf
         rpXS86kOCM0GfGsoyGDDXDy172NUEAROBVXi/nhs/vwSDux3WyAp5p0xDaSm2RjjICZ7
         kJ/x7Sl/hGaQ+Hpngw9b7QJYxk4b9Acxm84QtZV1YrDZok2kYBYge9TJlKmikS+mHScy
         HaXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XS6A1K+s;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769556106; x=1770160906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=y+ctrvGl9D4pHvjvlKV//jR6WvFzyeez1ST4iP4GXE4=;
        b=NNStUCnVyqSB7lgwhzV+qg8jsnvIT4TBLBChDTSEYtQNgmrcveadIKkyC8vftRNtbP
         QISvFhrRrH5CWRiA9LcaUVbbJGFsq1XePUrLrlA+qUImCH+LtfKkEt77pkrrtXQk7s+V
         7fjOwppGHDhmhYpKBTJ9llKrVA3H/mIaffknERGNd9Q59ZZ5fsZpEBOuxFi9hTnBDK1X
         tqB003OfPa95UGJW5g6MFaelHt9rHXAz5VKRl0xBkIWOwjgltLe2oVZf7VPfnNYZ7M+U
         yHkJCC1nem8eDEd6aGnP9UZ6+xLO+/f31/UV6XtJv17K6s8V5s8Qn8mu8SLA86+4XjO4
         6yCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769556106; x=1770160906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y+ctrvGl9D4pHvjvlKV//jR6WvFzyeez1ST4iP4GXE4=;
        b=SVyNLj6yBxSB2rHgwIiqeWUHvAOvF00sKgjH6LKhkjs+3rLpnrRZCvXGhz8vnR1dv2
         Cd6hMyPWa1qCstXYSusBQsLXPMQ5qJuBghWDHjcnWkKgNwjToDLlzmsOa0MtivOyR9QV
         RsfdumE/XNoCj/wAITYWQ5QtyUCLvdUc3hxeWhA7uk5EAfmVrnzLJkv4GeTS9MxWKE22
         +WqVJDCys1WoYlycgYgvawzOQM+pWzAymsJDRUcVdx1JM5RK5QJIykeRwPsX+ll6AyWj
         EoBvs3/fJTvvWhg3CDzRwLDWpjj0FsC9fXOydYwe+c9Z0k6vjpJyYR4SII1A+22w40DQ
         ULRA==
X-Forwarded-Encrypted: i=3; AJvYcCWls8lZsGkHaTqGAC/b8qlXemDN9oBqiaT7XyAxGYlhS0z+c/1t/obmCC0LHhDEikuzoM3kaQ==@lfdr.de
X-Gm-Message-State: AOJu0YxoLcObSWowFM5e4jK/YbM/Y3Kj+f252GjoazlLSNJIGAoqy/XB
	XHa6wzFeo15amHRCBa9T6XhoefdQI4Jt2NyfN2jGsNgJsb1om/Q5q0Xu
X-Received: by 2002:a05:6871:520c:b0:3ac:5502:b501 with SMTP id 586e51a60fabf-4093fcfeff9mr2267991fac.23.1769556105651;
        Tue, 27 Jan 2026 15:21:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FNgubdXFgoBX2KP6iAW7NAikM+wsZEi2zcexqCc6w3SA=="
Received: by 2002:a05:6870:176f:b0:3e8:2785:9a19 with SMTP id
 586e51a60fabf-408825b1060ls2858749fac.1.-pod-prod-08-us; Tue, 27 Jan 2026
 15:21:44 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUsuWAN8AMA/KHsBTjWm82LSo2NH1pLy+eveC8pjwawvtiToBAIf0aYWUIGv2KPW8Kca+CsOn8Kd6M=@googlegroups.com
X-Received: by 2002:a05:6871:2311:b0:3ec:a4ed:cf57 with SMTP id 586e51a60fabf-4093fce5fe3mr2063263fac.15.1769556104592;
        Tue, 27 Jan 2026 15:21:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769556104; cv=pass;
        d=google.com; s=arc-20240605;
        b=hcNSFycVIriOUMZIuQQE3eZuOdeigQB0LQ7A+0QZIx9/32QqXacIbLJJIzN18E0u2H
         qbuNUx7ms281a14O2NeqW+WHntrHKosvYMGQSUQfHME3fcSC5GFveUQRMWyuwaDd3sVw
         4KSY6NH87mBqeZs3sHgSJsiJXu6KPENVk79ewN18coKDsS5qFh4BB2HifY3o3/uXSXh/
         wySZAEHGHcbAk7eTylbkK1GArCdZsRauGitImz8L8dIrc1jDyWVIWpNpkADqZH8jGV2A
         4EfTGWufMsd0h7fKd5MDHIDxfp+FWSQBWX7eI2WGcNGpOB09TYTB+xC9xiV5PKZqgn/8
         jGZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VjPulWO4gZ18ncST52kid0OKSCrR3TSEDMRF2R/YJcs=;
        fh=IfC3TGWlSBQLo+Kw21UKVFZkJ+68o5vH2WXqx7Q3SOM=;
        b=S51WnSs6+ppvSAxBqQX74jK0b19WBLb2RZAjHY3dvFBR3Oq+PTVxOUVfpkZ4ZeXrkn
         +wNs+oZYwufoxZnSnL6fICHw76ZGPrtuQW+uWwIRiEw/9Nl8FKY++Xxc2JC0m0YZYywT
         MsDdIsxrrkWYQU6W1q5Ub1BeP/9u2yL+iwTVYyxOQ56Qdr0oABO778AgA9cXy+5fCdhj
         7Bw5cEORUvhENC0Y15Fsq+Aumsfbj/199osKeGJPsTEBfFsN2IclYd6YtwBeu3fzeVXH
         kCQY00pYE1NqLMc11Q2Lc3RH8Zez1rQ4/pkgsT0zUyYoSczsATmq5E+SrwjIecygmR3t
         gkFQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XS6A1K+s;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1234.google.com (mail-dl1-x1234.google.com. [2607:f8b0:4864:20::1234])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4095756adc7si39696fac.6.2026.01.27.15.21.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Jan 2026 15:21:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) client-ip=2607:f8b0:4864:20::1234;
Received: by mail-dl1-x1234.google.com with SMTP id a92af1059eb24-1233b953bebso2101352c88.1
        for <kasan-dev@googlegroups.com>; Tue, 27 Jan 2026 15:21:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769556104; cv=none;
        d=google.com; s=arc-20240605;
        b=MZLTEDyfth03Wh2gurZ2lbGWdFuQdY85q/uW0YsWT1Ht4Y0hGFWqq+b2BnNoRNvPlZ
         E7h1VEXe1aZnwXzEcDEGPZkvx3SRYvlTSnUsZD9KMH76LjYMl13V2l9kVy7MqoaV9ere
         mgGi26AS4Slhn5Sx5jA78+qGk6jzlCKUyVDzGSmkKPKVGZxlB+3GGHiVSsR2jlaMx9n9
         ZFUMIaoTNqlH1ysrv/Arw/CNy4ICwZ3ydBfRV4liMJkIE0v265t/HjxOeu5ih+ZMRFiS
         xKixuO2GQFoIUEyfbd1M51npN20E2Ik6csPg+ALVvSgcs8pDgidDEeiDNALfXhcIzUQr
         P0sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VjPulWO4gZ18ncST52kid0OKSCrR3TSEDMRF2R/YJcs=;
        fh=IfC3TGWlSBQLo+Kw21UKVFZkJ+68o5vH2WXqx7Q3SOM=;
        b=V5fdgnniXdIbfuZ4aSvwTRlmjog1bFdF93bZN3jTc3Fld66/FMt6tYOUx+wutHBZ4L
         Ce75WmpWnei/ALXNPYC26QHV3BzcEvUHhZ/LLPpiZAlL5IOPUiCfIr8WLUxwK1AwkZm8
         UG1TQ7KR0PSGDP+cwIuUrM75C7IFC+XB2SjJZz8yEoy9SY5iRRI90pmILAD2BGogW34l
         tbyS+kIFii4uIydNSoys4TNyUEvlyGx9mCgBRZ0f6w1PuI8m8OW1C5wwc7tPWCk7HK19
         THEaF/G8ZMPS5/e01GPcO5NeGkFmmne0zvdhY1yYpNPDXW11Hw7pv2MISUiHA6V8O3+u
         +ulg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCX6Fr69kh2bJ77Wk8ICoi9gHKFyla9o/EyVpUcDz5Y0rf3vrPu82Yw84dEYtrXPbgTgSscKTqaWixg=@googlegroups.com
X-Gm-Gg: AZuq6aIukgOFnvzrQesEn+t3vpdiHV5U1s0QtNPY+JUeR4+9+ul18tCjvAi0Q2tiP9C
	JEHX/wcHcuigvxBc3siiqD8NuP1bpGUTTsbOUuczGnCbIzwlbVBMEEqzA5zgbzL1IPLf/WzZyzN
	SBBNd2uks2zhIh9+1ktjH/leV60fCrshNyJNWcHs/e4Qcq9BSs8qBLmlJPBAeULf7I1rNMhxw2b
	+wD5q6L2E2HAT3UMU1MkEPliAaFIURMNxvxxkJji2IkOrVcjVi73DHulfwrDldIoCbOST7tWh9x
	6P9PKT1j/UUrJ1nXeiyR9LgO+jJbNhH4b+jgJw==
X-Received: by 2002:a05:7022:69a6:b0:11a:126f:ee7d with SMTP id
 a92af1059eb24-124a00df147mr2399425c88.35.1769556103293; Tue, 27 Jan 2026
 15:21:43 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com> <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
 <DETBVMG30SW8.WBM5TRGF59YZ@google.com> <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
 <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com>
 <20251218095112.GX3707837@noisy.programming.kicks-ass.net>
 <CANpmjNOQJVRf5Ffk0-WMcFkTfAuh5J-ZoPHC+4BdXgLLf22Rjg@mail.gmail.com>
 <aUPsdDY09Jzn3ILf@gate> <20251218121813.GA2378051@noisy.programming.kicks-ass.net>
 <aUP5j7W8S7koM13M@gate>
In-Reply-To: <aUP5j7W8S7koM13M@gate>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Jan 2026 00:21:07 +0100
X-Gm-Features: AZwV_Qi9po6Uc_Dks16j8YjXQU1xeqC7k7TJSARCA7BmXfXaDznSmFoC-rn2mNY
Message-ID: <CANpmjNN5q0r6FEph2P1E2DvBTgFrWFgWkV_kyxiUQwbouLj4+g@mail.gmail.com>
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
To: Segher Boessenkool <segher@kernel.crashing.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Ard Biesheuvel <ardb@kernel.org>, Kees Cook <kees@kernel.org>, 
	Brendan Jackman <jackmanb@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XS6A1K+s;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBCMR4XFQMGQEWE225HA];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_CC(0.00)[infradead.org,kernel.org,google.com,gmail.com,arm.com,googlegroups.com,vger.kernel.org];
	RCPT_COUNT_TWELVE(0.00)[13];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[elver@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,llvm.org:url,mail.gmail.com:mid,gnu.org:url]
X-Rspamd-Queue-Id: 755179B5E6
X-Rspamd-Action: no action

On Thu, 18 Dec 2025 at 13:54, Segher Boessenkool
<segher@kernel.crashing.org> wrote:
>
> Hi!
>
> On Thu, Dec 18, 2025 at 01:18:13PM +0100, Peter Zijlstra wrote:
> > On Thu, Dec 18, 2025 at 05:58:44AM -0600, Segher Boessenkool wrote:
> >
> > > You might have more success getting the stuff backported to some
> > > distro(s) you care about?  Or get people to use newer compilers more
> > > quickly of course, "five years" before people have it is pretty
> > > ridiculous, two years is at the tail end of things already.
> >
> > There is a difference between having and requiring it :/ Our current
> > minimum compiler version is gcc-8 or clang-15 (IIRC).
>
> Very much so.  If you have good reasons for requiring it, make sure you
> voice that with your backport request!
>
> Nothing we (again, GCC) do is *only* motivated by procedures.  We can do
> unusual things in unusual situations.  But you need extraordinary
> evidence for why extraordinary things would be needed, of course.  Does
> that apply here, you think?
>
> > On the bright side, I think we can be more aggressively with compiler
> > versions for debug builds vs regular builds. Not being able to build a
> > KASAN/UBSAN/whateverSAN kernel isn't too big of a problem (IMO).
>
> Absolutely.  Just document the feature as needing a recent compiler!

For future reference:
https://discourse.llvm.org/t/explicit-sanitizer-checks-with-builtin-allow-sanitize-check/89383
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=123442

Clang 22 should have the builtin.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN5q0r6FEph2P1E2DvBTgFrWFgWkV_kyxiUQwbouLj4%2Bg%40mail.gmail.com.
