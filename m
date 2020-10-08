Return-Path: <kasan-dev+bncBDV37XP3XYDRBN637P5QKGQEGGUQJVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E5C042872AF
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Oct 2020 12:45:12 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id a6sf2225328oid.12
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 03:45:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602153911; cv=pass;
        d=google.com; s=arc-20160816;
        b=eWFEI+Kl4oIVSGiuDqIV5hUBMOXXvEm8P48vhKe+aio5CathjugVDa+jrfZYSNiSzX
         SLUR6LK/kFgUKkOFYl5FRL+ig8ScPJO5oh17Ym4jXKer2yDAy+UraRjQwNQq5USc3d2r
         5ce+YsjcB10FqL9s2ntos0AstHCR2eR6oi+UrlWXgV8Ya2ezb7V41pJ9EY5ac0Dyb01k
         Sn1IjozPfYEnkbH/P1s+Dw3DLvy9FLHMCpqc1cOtIVjv0077iWmpLuKOKcKaTKjFXc3t
         85ggY4D1yfPFwSFqI308wO/EeS2uwrkKVSyH/Nu1s/Gl/A6xiDqoVJr7cFPkeEAUN1Yh
         efdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cgU5lsb/cCY6kipGXY4NRXuKpWATOG/kiJag8PIOzvw=;
        b=nl/4oi2TzycZAwzNH91wbZk3Ekzn0jKbaSMEzVd2uTemDsmMx2bu4IgGtAu5SeDO+Z
         CrjOqVEMsV29nILh+zaOqE2+HDe8N2K3XHDhFp1HlXDnt/j0eJyc7sccpg1uFJ6rUVrR
         7PDRNZTlAdCk17xb8V6gfCNv4YSgKZZFAON/xGvo1P08IAue2K+N6w+t4J06eFhc3Qt6
         r542TQr5T/dYv5dYOG13XDnLUn/19t2Q8gJbU5HWeNWA+XPmJ5yYzRgiKtlCvpb4hC51
         lSuRrNhwGvnwXYFkS6P4fgYg+K6vwYCRJut1oC2HLgs2WeK1pog0QTWzJAE8WXyqAn7z
         525Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cgU5lsb/cCY6kipGXY4NRXuKpWATOG/kiJag8PIOzvw=;
        b=D6EqbC/CXM0z1YHf16JUd0ePbc5QfrBoVlmIQtWE/BBL92WbH7LVtlnxsl88F62aDe
         KfqTvE8qIuKXSDlPF8DeQp4d2kJ9ZGwnhiRe8x5tbhpeRtIu8M3FZKl8ZO24Red1WP2j
         fWGdC9589sLUQ76GNyriVBT9X4pPQJJYU4MB3upY1N2HwO8kroYktJ73cXHwCuBYWOxQ
         PLUCKN68josqFC7pYVn5iWjAnHITicBlu52z/w2j0f+AXojrJSw49IHnNt9pxJtitPYX
         5LC/AR1/6QjNER0X0D+SHHXreSqijUQYGPeQToivHq2+Ny/6yxoIgsGSfmS2i7st5Kn6
         piJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cgU5lsb/cCY6kipGXY4NRXuKpWATOG/kiJag8PIOzvw=;
        b=QbGw83njKQ7ZRn7SNEMsNXj4BZUrhLL2TVG2BV3Z3ZfTnJOk2g5ACZYsOaBh73u5bq
         D3pzsq/dhTbVHXP99ppqpUhXrHyQbKzyfxNbwz5sFnoK5JYUPoFmq2VwE+Ghg6qwwv1m
         4akr28ARetxo5ojtCaIoGWLCSDmDNmXjNLyQw+vX5qsNKSxGKe8DfNoNd0wb279gpG3u
         h4hB8LQV5JlnsypFAXTfKmS4DrSuGRKYkPuGc1vxEdGnaUWP1AaEGeFZII10Gs7kLO67
         nwG13Qnqh0beCuj56TSTnrTFR83488tmPdCYIB3pHLzE8olxcSIJSrp5GFNtdnTAhelM
         CqGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ky3SFfuKiN21R6u28nnhSlUUbdHIZHxuY96cgHaUUdqDK65QV
	DS39tDUrO1KsV/2Tz9hg9DI=
X-Google-Smtp-Source: ABdhPJwNWTp+RjhTMPzzUdYiHGlMfwTwnJI+a+uwHBFmgSgncW66xEdpjx95atDudmZ+FvdblH2mhw==
X-Received: by 2002:aca:3f09:: with SMTP id m9mr4878197oia.1.1602153911733;
        Thu, 08 Oct 2020 03:45:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4d2:: with SMTP id s18ls1186809otd.0.gmail; Thu, 08
 Oct 2020 03:45:11 -0700 (PDT)
X-Received: by 2002:a9d:77d4:: with SMTP id w20mr3081925otl.310.1602153911365;
        Thu, 08 Oct 2020 03:45:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602153911; cv=none;
        d=google.com; s=arc-20160816;
        b=de5mdBVwzpvFVzrzmRf3/d0LHfxxN0fC1uIjPJj6e5IbC7m8eTbFpvVbV4lwwjYkt1
         RWCNkbyB2NIdOMc4rY3W0S3t1XyI+eavExRApbphNRxOGIuPJKIoHEZVWi5mhqRN2WQH
         a5QIWkt5NK9tRIO4yqDNDtcNQxbWzpRNT3Ga1dHzm4syVr+Tbq1IxDcbE8iIoeDd/P1L
         Wz/rranbIOds9eydYRHIdx2Fryxn2BBXdQc/zspUuzzXfN58Pqm0hrBbxidhpcVyWCvY
         a2gf1V0EtS3YjvYx9tCMeDk54i3KbvahwZKfAE2svHn1z2SXsv/usX4Qku/e29KKlpUF
         Cpnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=1jK0FulwQ5Ppc/gGW9wLUwq/hBio/cEOXBceu8f6RWI=;
        b=MVj2wqGCyxDPkP+q5LCNND255PJpn6uKutFPXvMeyBxrZNL1Q636lUadwex2mycb/H
         rvbXfdmq6agoY7sk1CKW/92r7py6EPForJPLnfnZ88OHKtfFK9APR2ukeYd8qsxp173w
         QApzFz4S8/mikyqufGMktTFke7Q6zFXpjdvQPFMahHpi4l8VdhXt2RofbHNqtLxcVPNj
         aVz6YiwvSAo96PcAdqgBrKSZatY3197xlwDV+o1Nd+c70s4RplHep1XWp72iXGPYYe0M
         syXo70nKI23yjxN6y4GpGsKkWDjMS6FPvLyUjTv2227hPkIxyJ4N4RJCbMUTbHV0Wg5J
         DZiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e189si291561oif.5.2020.10.08.03.45.11
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Oct 2020 03:45:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 21CCBD6E;
	Thu,  8 Oct 2020 03:45:11 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.52.79])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1EBF83F70D;
	Thu,  8 Oct 2020 03:45:03 -0700 (PDT)
Date: Thu, 8 Oct 2020 11:45:01 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	"H. Peter Anvin" <hpa@zytor.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitriy Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jann Horn <jannh@google.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	SeongJae Park <sjpark@amazon.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20201008104501.GB72325@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
 <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
 <20200929140226.GB53442@C02TD0UTHF1T.local>
 <CAG_fn=VOR-3LgmLY-T2Fy6K_VYFgCHK0Hv+Y-atrvrVZ4mQE=Q@mail.gmail.com>
 <20201001175716.GA89689@C02TD0UTHF1T.local>
 <CANpmjNMFrMZybOebFwJ1GRXpt8v39AN016UDgPZzE8J3zKh9RA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMFrMZybOebFwJ1GRXpt8v39AN016UDgPZzE8J3zKh9RA@mail.gmail.com>
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

On Thu, Oct 08, 2020 at 11:40:52AM +0200, Marco Elver wrote:
> On Thu, 1 Oct 2020 at 19:58, Mark Rutland <mark.rutland@arm.com> wrote:
> [...]
> > > > If you need virt_to_page() to work, the address has to be part of the
> > > > linear/direct map.
> [...]
> >
> > What's the underlying requirement here? Is this a performance concern,
> > codegen/codesize, or something else?
> 
> It used to be performance, since is_kfence_address() is used in the
> fast path. However, with some further tweaks we just did to
> is_kfence_address(), our benchmarks show a pointer load can be
> tolerated.

Great!

I reckon that this is something we can optimize in futue if necessary
(e.g. with some form of code-patching for immediate values), but it's
good to have a starting point that works everywhere!

[...]

> > I'm not too worried about allocating this dynamically, but:
> >
> > * The arch code needs to set up the translation tables for this, as we
> >   cannot safely change the mapping granularity live.
> >
> > * As above I'm fairly certain x86 needs to use a carevout from the
> >   linear map to function correctly anyhow, so we should follow the same
> >   approach for both arm64 and x86. That might be a static carevout that
> >   we figure out the aliasing for, or something entirely dynamic.
> 
> We're going with dynamically allocating the pool (for both x86 and
> arm64), since any benefits we used to measure from the static pool are
> no longer measurable (after removing a branch from
> is_kfence_address()). It should hopefully simplify a lot of things,
> given all the caveats that you pointed out.
> 
> For arm64, the only thing left then is to fix up the case if the
> linear map is not forced to page granularity.

The simplest way to do this is to modify arm64's arch_add_memory() to
force the entire linear map to be mapped at page granularity when KFENCE
is enabled, something like:

| diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
| index 936c4762dadff..f6eba0642a4a3 100644
| --- a/arch/arm64/mm/mmu.c
| +++ b/arch/arm64/mm/mmu.c
| @@ -1454,7 +1454,8 @@ int arch_add_memory(int nid, u64 start, u64 size,
|  {
|         int ret, flags = 0;
|  
| -       if (rodata_full || debug_pagealloc_enabled())
| +       if (rodata_full || debug_pagealloc_enabled() ||
| +           IS_ENABLED(CONFIG_KFENCE))
|                 flags = NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
|  
|         __create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),

... and I given that RODATA_FULL_DEFAULT_ENABLED is the default, I
suspect it's not worth trying to only for that for the KFENCE region
unless someone complains.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201008104501.GB72325%40C02TD0UTHF1T.local.
