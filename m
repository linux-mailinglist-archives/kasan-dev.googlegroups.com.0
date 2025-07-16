Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWEK37BQMGQETQOKZNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 737AEB079D7
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 17:29:31 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-311ae2b6647sf55138a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 08:29:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752679769; cv=pass;
        d=google.com; s=arc-20240605;
        b=bm4lLlqPVdqzUX49EntlgFByhEJybX0L1gAsMv65vogmqHN4OpkRUNcjCBhLJ9poqq
         FNrc3YfyCLJhiEXWMyqdmygyVN430pBV8VdqdsVDnqm6zjuCJng4gB3Xt3mEwK0fnNWH
         3vJaPD0Cw7j3e9l6KYL0FyhK11W6ZfS+Pl5eB7XIhzLqr8aZfpXORdu4exuW30ZXku9e
         tk6Qs4XeXW1vdf8BMImc3TfmJLWH5kSfrFdcvd4kuQKn960quNwwhATIsfpI74O6SlGt
         3hH9Wu7v/g737iURpph9XriYO/k+98VeSs1SW4HIcf6RqjVAIz4NeMqykFqz+NNZcKLX
         3tkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wX02HVxom5kfkXdxOnrmS1IvL0Vz3mHntfxm/zrPYoQ=;
        fh=MV4IHLhOHjzIE2OLO+tFI42/adAJ4n96NHaUjsIzGKc=;
        b=gK8MkJxEqV1B7YhhI9keGIq/SfTd/f3gGvePHbMojs6bsKwODkYVwBHSY4z+nVUeRH
         E+36jRPCLTeYwZN5ReE3xOVvO70RSEqBm56oP6kYm7w0gI85uIGM80EcV+fGOspUW/x7
         3uoe+16+kHqRFj7QmaLdOHuKdr0/Sl+PHuDLwezQig2UcGWAv5nwbU3wvEF9SZue1A7p
         kzIY0SW451zWciTANFQah9YdgYVVOuYQeUiCW46yX1UkbdAsrog30jgzMse0EGsnX9Vp
         vGOXj/2B1kXMugThuv5j5z1gPMweLc0YBL2oUuduR4pSFDhhsqIQs3p64G1rRkZ6Ipyr
         cibw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JKhYE+rp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752679769; x=1753284569; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wX02HVxom5kfkXdxOnrmS1IvL0Vz3mHntfxm/zrPYoQ=;
        b=W9jjVPAhq7Us+gB6WD55zouYW7SWg8ksxLyRDmpaWtH0APCWWHgdxuSEgWK++vGECY
         LEEGQVT+8iQpvbGjLirj46a/XMG5Z+VweUaBljbQovT3qUQabiKwIdA+XR8RGmGui1PP
         J4/ltZywRj//m1OLp/m+uqQviaPe1snwyKuYQS24GhBhcSwS0Xix4OxAUI04CpEcZYG5
         VPmGx29VGHag2HtiHOuVa8BsSjouB7rbsXHQ3207ZK09HfHQ8/ocPkbvcGm7SWIXex78
         WOqWL2AX08r4OpAwvDjOXEp1R4el9lopjsBbKzNfV+K7q0sjTmaSUmVQIKPmqDvX6HzX
         Z+yQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752679769; x=1753284569;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wX02HVxom5kfkXdxOnrmS1IvL0Vz3mHntfxm/zrPYoQ=;
        b=S0/6iqTdBvgBUYgGhmZ79WXZQsfFjtY7gqahfkqJBekfo3w+YG0ULYXrXvZ821LbdY
         vDrWxcAXOYoVN84Usf0khE1J+MiL8yrSh7yFDPfHiaBU7HOMeVtO8X1eUb00MErboZsX
         84/yVbJZof8nnHImLpwLZRgeat9XZTk8WAMXiqDjyea80u3X0J6jvy5yc17efPWYcVE/
         ON2uvQHosQaxB57rIgxTq2QBW3yNRSuPRe5yZ3AVuCuy0epnYP7c/AATIoySNuE6IWux
         5mBPsHgEwIMQYn/THvL8PPc+XU/OP2FQHzPXYnDIt+p/FEooBYWU+pB1jNTYP9Yhxxzf
         vd+Q==
X-Forwarded-Encrypted: i=2; AJvYcCVS6RIe0XiX7fkbpKAqTSupspIgNlL/dpxR2Ul1FvxZSHzhzFrvzkG9Ja/myttCtYOzhcdrlA==@lfdr.de
X-Gm-Message-State: AOJu0YzAgo+HdpCtp4lFVbskm2c5ZEDgaX80LiWgzrarizNZmvjdtHEO
	gO0/e6bwYdsvl/SurvKlVuAqBTjSDDgyBK8um+K1A7Qyr015MhO9Vowf
X-Google-Smtp-Source: AGHT+IGbSuE5a+pdjBnLqRJGI9/VvjyKNgOHUQD216ZQX42gt7uWIRzMkZAweD/kbhkPdsJZ1l0Z+Q==
X-Received: by 2002:a17:90b:3b8b:b0:313:5d2f:54fc with SMTP id 98e67ed59e1d1-31c9e6f13cfmr5110929a91.10.1752679769382;
        Wed, 16 Jul 2025 08:29:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfUFGK3MDSsKQN/5akjjYK4TVXYTpUDChcLZsW3gGbgDg==
Received: by 2002:a17:90b:3609:b0:30e:8102:9f57 with SMTP id
 98e67ed59e1d1-31c3c8b6489ls5589878a91.2.-pod-prod-04-us; Wed, 16 Jul 2025
 08:29:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUak1qA3qUoyOU597az6AnDEHXlxf0+AQ3lnVsjd12CCmg4BR9oxuzSsejlA1eRzwzIrRsDGAinFG4=@googlegroups.com
X-Received: by 2002:a17:90b:4d:b0:311:eb85:96f0 with SMTP id 98e67ed59e1d1-31c9e76be29mr5199413a91.29.1752679767145;
        Wed, 16 Jul 2025 08:29:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752679767; cv=none;
        d=google.com; s=arc-20240605;
        b=HW7n2j71lM97nuj9kl7DNQ5oKDKRKgHDJU8Ke3eiBwHLVY/1kZRHygM2axAItL+5Kc
         kQGaw628QltCPZQVkg2ypliYJLq2yd0LjhtDNgmLqINOCD/ayo/uF8IfdUGEUHpg4eht
         2RUF98y9vHB+69T/9BcASZktYsaTUdXvH5U1dsgtnG40fAZ8xJyysRYraPVI2nCidxe2
         xKOw1O2wIrZ8+5xDC0jI9Su1TPZw+4hMYxywLesKeB41kQnhe26Xegci7VSczSYYFSSG
         4fwwdHevxlf2UBV+FDAmamBygrNSjHkReF4FnY3JjuDr7BpW0jncTTbTML+VIjzAhjQ1
         VDVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DXRWy2GORatQ4WDqzRgN/A7GONpktQqNYMaPCTvZVp8=;
        fh=6/DApKVlACuEUUaXKOp6+LkwLwD8yehDSgJfNcILEN0=;
        b=fpaIWMriStZoyUMOzZqB+38YRaC1PGNsWSAZIox/RRveIjKvzGMvGl1BJLoRTWFlKx
         yKvzyjBAL464J1ZaoNxXEoKh+0+jMYnBTdoPRH0cxjhHwABPj2dugBRuAPeTh/sE0tX6
         pA0nZf1IrLshEsqi+g2BbdJtq5+Xu/k3cUFaONWcW/TiSURiWUCHlTZmpgLJSIIW23QP
         y+iRdN/iNQQP9vLzyS4pvNj55+JfOYjiafB38AAkJvvTR2z3AUC86/FAZgkxmkxE7vPt
         n/8I5zjb6Swu0O/Wq20g5KB64XBJOAEGFGO3Fc64iQonmXtpxYmbXEaCyegQLClSy1+K
         5a4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JKhYE+rp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c9f11828fsi120588a91.0.2025.07.16.08.29.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jul 2025 08:29:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-31393526d0dso67642a91.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Jul 2025 08:29:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUk/Bkk/kQ7hvQR7+CAKlG1dMSRwgBVDJoBEUyuFB/YLEgd9tuDwvt0rFmaEabB1YXIwHYYAzGaymU=@googlegroups.com
X-Gm-Gg: ASbGncvL3F/BDXcEiwqbZfksP9W9KRir7iNfRG7Mwd+SFWKMJNMJaISSUiCTVmfFzXh
	5dN0c2ujW4DjLlN6qar6xcJBqVZG15wx5pK3nVa2Tpa6L+TcncAQWz6ZLBRFHEEv3wn7jKkyoQ/
	Xk9Z7T9xtexfp4pwMo8jGgG+NcdNXMQh1EaSJKPhJShdkTiQR+pgh9B1teJItFW6VX1UecsosP5
	Z3C0EOio7ToUndW/sT+yNMIPO0lYcNjdUQq6w==
X-Received: by 2002:a17:90b:1c83:b0:315:9cae:bd8 with SMTP id
 98e67ed59e1d1-31c9e76b79dmr4902000a91.23.1752679766392; Wed, 16 Jul 2025
 08:29:26 -0700 (PDT)
MIME-Version: 1.0
References: <20250703181018.580833-1-yeoreum.yun@arm.com> <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
 <20250711020858.GA78977@system.software.com> <20250711021100.GA4320@system.software.com>
 <GV1PR08MB1052126BB553BD36DA768C998FB4AA@GV1PR08MB10521.eurprd08.prod.outlook.com>
 <20250713232740.GA18327@system.software.com> <aHdsQYvKN-dLQG2O@pc636>
In-Reply-To: <aHdsQYvKN-dLQG2O@pc636>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Jul 2025 17:28:49 +0200
X-Gm-Features: Ac12FXyd4otKpgnEaXRLmajtTI6ex6Uy6iZQJFcEjwrCoLj_OCKFTg4M7FvyGmE
Message-ID: <CANpmjNM96MCD-JY=+OkQ4PZK3jV4027PCPRQ0bMVm9kvhGC=4Q@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible deadlock
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Byungchul Park <byungchul@sk.com>, Yeo Reum Yun <YeoReum.Yun@arm.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, "glider@google.com" <glider@google.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, Vincenzo Frascino <Vincenzo.Frascino@arm.com>, 
	"bigeasy@linutronix.de" <bigeasy@linutronix.de>, "clrkwllms@kernel.org" <clrkwllms@kernel.org>, 
	"rostedt@goodmis.org" <rostedt@goodmis.org>, 
	"max.byungchul.park@gmail.com" <max.byungchul.park@gmail.com>, "ysk@kzalloc.com" <ysk@kzalloc.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-rt-devel@lists.linux.dev" <linux-rt-devel@lists.linux.dev>, 
	"kernel_team@skhynix.com" <kernel_team@skhynix.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JKhYE+rp;       spf=pass
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

On Wed, 16 Jul 2025 at 11:09, Uladzislau Rezki <urezki@gmail.com> wrote:
>
> On Mon, Jul 14, 2025 at 08:27:40AM +0900, Byungchul Park wrote:
> > On Sat, Jul 12, 2025 at 03:46:10PM +0000, Yeo Reum Yun wrote:
> > > Hi ByungChul,
> > >
> > > [...]
> > > > I checked the critical section by &vn->busy.lock in find_vm_area().  The
> > > > time complextity looks O(log N).  I don't think an irq disabled section
> > > > of O(log N) is harmful.  I still think using
> > > > spin_lock_irqsave(&vn->busy.lock) can resolve this issue with no worry
> > > > of significant irq delay.  Am I missing something?
> > >
> > > I don't agree for this.
> > > since in PREEMPT_RT case, it has the same problem.
> > >
> > > In case of PREEMPT_RT, spin_lock_irqsave() becomes rt_spin_lock() which is sleepable.
> > > But, KASAN calls "rt_spin_lock()" holding raw_spin_lock_irqsave() which is definitely wrong.
> >
> > It's another issue than irq handling latency, but it's about lock usage
> > correctness.  You are right.
> >
> There is vmalloc_dump_obj() function which should be used IMO:
>
> <snip>
> pr_err("The buggy address %px belongs to a vmalloc virtual mapping, dump it...\n", addr);
> vmalloc_dump_obj(addr);
> <snip>
>
> we use trylock there to eliminate an issue if invoked from the IRQ
> context.

Something like that should work:
https://lkml.kernel.org/r/20250716152448.3877201-1-elver@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM96MCD-JY%3D%2BOkQ4PZK3jV4027PCPRQ0bMVm9kvhGC%3D4Q%40mail.gmail.com.
