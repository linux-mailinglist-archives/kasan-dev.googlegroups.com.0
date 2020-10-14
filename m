Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMU3TX6AKGQEKBFSLLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 53F9C28E70A
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 21:12:52 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id q126sf386733iof.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 12:12:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602702771; cv=pass;
        d=google.com; s=arc-20160816;
        b=DUS0Q8/cRTUJuXfDEvyJoHIi4SeylKXSJcHUXTYrtZK9d+2Bqcb3UE3OA7f10d0mhc
         uRf1X2iGOl3txtJ1DR5tOhMykmwfHoDBzKJhNIxljd8GYudM49KHxnx4wbsi/nLdwlAF
         ec0R4UU/azOJoR37l2KtOsafiQuuCcTNP/P+8oXLD/gkiWxat+6FMagjTC2PDvS0b3in
         Kw2rESRV7PGPOB3Uxa9YSMbr8EXJGdDzgV56dTCzUb1e042M5Aw7nPAjedE6vYRLDAOu
         SlDLNQ4DIsGI7aFbSGuXRwQDb0EH1Kqtkn7IiCw6n0Qf9SIfq5TTireqm7d1K04iSJ+J
         xXIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EQC4Co/spkuXqYrzslHGQMPAldOWjXi5zaSg22/zyuo=;
        b=0mWCp4croDLHMwSdmDX/GAFEKBzd+duDL69zI0VnDu8YSB3Vt7f70nDQiIpN29TZIm
         z4+QZKW1231v1B8smy3EB6CUlE49qeZHyvV7biQb6uNba9zhx9luHfMes4jCCCCAI/l0
         +JLJmPSemjky+ZQSEEmJkmsdZDdWLZxx0PXRoU5Mj60XY7y7V2imEUjgCRYXpB1xFi7z
         w0jgZTd9LC2fkolk8pIe2p7cdPDir+DT4jBlMnTW97Ckcy1Mv+pzL2bzJBgUSny7mSMd
         kdF8/2XxxyXQH9BKKPE4SM0hGoRJZnqNENv0+0S04rhE+8MV9EW6hY5G0Q+ueCkFFAtg
         BW7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QoXiKIK/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EQC4Co/spkuXqYrzslHGQMPAldOWjXi5zaSg22/zyuo=;
        b=gb3sphlogXRhSS5a5rceQYW469Ml6ZbfKwc3e1zDlJKkzDQqeeO7LEr94G+ohXIcKq
         5n3iQgj/IRsd9zgyItZgD+PGFXWEEusAMexX47Tqhfi0AO037QgX21CKg0AGJtjUBj6r
         g6YDHjC3KfqL2qc5BIL/qQVavt3WNULyxAp1J9NRPd6swQAaI19Gf8g0e+uBbIO9Kwz7
         I8ZvkPJJeZuxyWhjCLski4ENT32ZjEQQUtRMTkRV3Of5o0J9DnZUhlSPUkicXq3KhOWt
         bn9By3t+uJMhTLvXKCCHAH2IIZb2fTT4q40MEy5Y2cyK/B1rKhdWy21gF36UHUORNaPV
         LAFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EQC4Co/spkuXqYrzslHGQMPAldOWjXi5zaSg22/zyuo=;
        b=FHSushcAAy8NAdHPiGWkrz17boMuoQKe1usCHlS5f8TkZbHXK9e+EMPanGFp5NgHBq
         3yQXD5qleznBP7ljYnRhI2PAsOsGaUXCx6z7WdbrlkMYJcEg3silnpyFDNubemYjuXqc
         1+RCWN5wIYcMey+dT6aWM0Gmg1+1b9TaWf6gaZ6TJpf8RJhqKlKvCuy1OayZb4ja8giF
         0pg1wMtYfY9FBjS7IxGgrKOG5mYoqp5CfpY3t41c7T5aHRKLl0yB8BdEcD1yrEFcTN3Z
         wAux9aREVOYVoANR1vOavnHJZpDgq9EbTKDRs/guEbrJS453WQYmsT08g0eLNHr5g+Tl
         G6vg==
X-Gm-Message-State: AOAM530zhntAnugkpZqGy8yNJbFvlZ/uJfQrAABxLD/wkm9sTDpCiQoF
	wblm8EwLT1zGNfcjg4m5iqE=
X-Google-Smtp-Source: ABdhPJxRtzx9wrb/es12nf4YO6XSzWNo49XAjuO5Vt41p0qrtrUhuUQLljTcVChZflnC2/rVLQATBA==
X-Received: by 2002:a05:6638:606:: with SMTP id g6mr898857jar.0.1602702770964;
        Wed, 14 Oct 2020 12:12:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1b42:: with SMTP id b63ls44066ilb.6.gmail; Wed, 14 Oct
 2020 12:12:50 -0700 (PDT)
X-Received: by 2002:a92:5a08:: with SMTP id o8mr560946ilb.32.1602702770565;
        Wed, 14 Oct 2020 12:12:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602702770; cv=none;
        d=google.com; s=arc-20160816;
        b=HsRvyijItaF0zhPMFfZaiXa1dDQEFc3X8yvEiyDQEC3I09Z1nvfrN7moCKT7NAA84r
         AGbIL9KR/LN/peWkZEttEYSSNnjtRG9zr7chyL0HK6/uRFIpUZCoh4obHcmc/G9GZHzC
         6t/uLzZbrEkKl6FAfelrUIuQxSxWBqivUNosn+XAMl7gMfWxkpiS6UBIHSWHJ94imOrU
         epK2UeV2R5hnU52VkW4rN3meGl2FiZIsdVCppkj8kSLF+UA9lbmLs8FDdL/N8iLYpjlq
         Vao282ACfS6P3r0vQHJY2rN8arzL1AZXZ3fR0h4qXF+inGftCX8gM917Qxe0u6cJf2EH
         1T6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZeIyBZH1DlMazqL3WPQEWDzdrz72p5JAZek4MEGZox0=;
        b=W575MCFswIQZkTZsIxLEw9Bi2IQlk2OTK3ivTm5KEDyDavrGp5KLyjkp3LnY7G2sIw
         av1C+KRcI4KhHkkRWD/j0ipg5zQMaYrXVCOU07mzc98DZUCgYn3ONMU6M1Tv0AyQkP60
         DWZFTX7mMxKHroft72t5Oegyq+wjoD7A0FxKRhBtUFIBlNMleT78NCU3swQMaVMd5UbA
         aqPRajSUqxCJa6V6L/Wpt7jh2WQ0YYWn1OdYS/8CnY2T5WZ0X/4NbKM/yx9NxheDBK1B
         BNZ7KXGzwq36KWS1vbv8YsOmuaqei/hDoQ8Kf4M7VfKcjKzZUOYCWWrdZXhnVkYBo8i5
         F/5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QoXiKIK/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id g20si50599ilk.4.2020.10.14.12.12.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 12:12:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id s21so379933oij.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 12:12:50 -0700 (PDT)
X-Received: by 2002:aca:3d07:: with SMTP id k7mr537643oia.172.1602702769984;
 Wed, 14 Oct 2020 12:12:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck> <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
 <20200929140226.GB53442@C02TD0UTHF1T.local> <CAG_fn=VOR-3LgmLY-T2Fy6K_VYFgCHK0Hv+Y-atrvrVZ4mQE=Q@mail.gmail.com>
 <20201001175716.GA89689@C02TD0UTHF1T.local> <CANpmjNMFrMZybOebFwJ1GRXpt8v39AN016UDgPZzE8J3zKh9RA@mail.gmail.com>
 <20201008104501.GB72325@C02TD0UTHF1T.local>
In-Reply-To: <20201008104501.GB72325@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Oct 2020 21:12:37 +0200
Message-ID: <CANpmjNOg2OeWpXn57_ikqv4KR0xVEooCDECUyRijgr0tt4+Ncw@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Mark Rutland <mark.rutland@arm.com>
Cc: Alexander Potapenko <glider@google.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, "H. Peter Anvin" <hpa@zytor.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="QoXiKIK/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, 8 Oct 2020 at 12:45, Mark Rutland <mark.rutland@arm.com> wrote:
> On Thu, Oct 08, 2020 at 11:40:52AM +0200, Marco Elver wrote:
> > On Thu, 1 Oct 2020 at 19:58, Mark Rutland <mark.rutland@arm.com> wrote:
> > [...]
> > > > > If you need virt_to_page() to work, the address has to be part of the
> > > > > linear/direct map.
> > [...]
> > >
> > > What's the underlying requirement here? Is this a performance concern,
> > > codegen/codesize, or something else?
> >
> > It used to be performance, since is_kfence_address() is used in the
> > fast path. However, with some further tweaks we just did to
> > is_kfence_address(), our benchmarks show a pointer load can be
> > tolerated.
>
> Great!
>
> I reckon that this is something we can optimize in futue if necessary
> (e.g. with some form of code-patching for immediate values), but it's
> good to have a starting point that works everywhere!
>
> [...]
>
> > > I'm not too worried about allocating this dynamically, but:
> > >
> > > * The arch code needs to set up the translation tables for this, as we
> > >   cannot safely change the mapping granularity live.
> > >
> > > * As above I'm fairly certain x86 needs to use a carevout from the
> > >   linear map to function correctly anyhow, so we should follow the same
> > >   approach for both arm64 and x86. That might be a static carevout that
> > >   we figure out the aliasing for, or something entirely dynamic.
> >
> > We're going with dynamically allocating the pool (for both x86 and
> > arm64), since any benefits we used to measure from the static pool are
> > no longer measurable (after removing a branch from
> > is_kfence_address()). It should hopefully simplify a lot of things,
> > given all the caveats that you pointed out.
> >
> > For arm64, the only thing left then is to fix up the case if the
> > linear map is not forced to page granularity.
>
> The simplest way to do this is to modify arm64's arch_add_memory() to
> force the entire linear map to be mapped at page granularity when KFENCE
> is enabled, something like:
>
[...]
>
> ... and I given that RODATA_FULL_DEFAULT_ENABLED is the default, I
> suspect it's not worth trying to only for that for the KFENCE region
> unless someone complains.

We've got most of this sorted now for v5 -- thank you!

The only thing we're wondering now, is if there are any corner cases
with using memblock_alloc'd memory for the KFENCE pool? (We'd like to
avoid page alloc's MAX_ORDER limit.) We have a version that passes
tests on x86 and arm64, but checking just in case. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOg2OeWpXn57_ikqv4KR0xVEooCDECUyRijgr0tt4%2BNcw%40mail.gmail.com.
