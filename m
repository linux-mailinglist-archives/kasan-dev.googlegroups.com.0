Return-Path: <kasan-dev+bncBDV37XP3XYDRBLVCUH6AKGQEGROK6AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id B4C2828F375
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 15:39:59 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id y18sf641445vkd.14
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 06:39:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602769198; cv=pass;
        d=google.com; s=arc-20160816;
        b=ggx67DFLRbWJvPM0f3jjeDYeipQ5xtqNsI64iD44vfAMWAJXRSDTvgADy0gtFU4CER
         1Rj3CFviWXw4MZu7bsl1TzK4mWiqiI0s4ItlrltsZ0qzJ6fO66twf3A1x7O0FTG4OrrL
         +hVMWqcXRJaNXcXQeF3VPvHELmFvrkaQJjSWlr/ITWei0h24gFAJzWsQxu+6qaY+h+ky
         SvXT6qjP8alkP6Sk2oKshxSTChiKop5uvgh5SdOoyrtsWJ+WUWzSMSUbc+kUgGIzeV+u
         WC576c3Aze3Hw3ybCYx0HzczDENYKXf26uO8ydGTnNNN92/9b2pl5t2t2URPGViIyMzR
         h+Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cxJQDgbcFRNQvDuXMj58bG+3E5UarvEKa9MKVbdgJI8=;
        b=fTyRzu9r+wpLvSOItvKc9T2hdV75/G3Zo4NrtCzWanGpKFwjoejzLDjKMpa7zJbICr
         8dyCOpZaC75e4XedCjPOVIQUFQ5uxVJnGW6IXNQr8MpdsCOw2mS5cHFliGIg1SmQggPg
         qOrj7be6pCSdvPAN/polQJlNLWAjpf28dilL8bLkq8fC6tXagls5/t6s5hKMpu493cAE
         9fD1xNXXnN3GlXQiPWt8fh+rXmPn/g6OXjirJNVAY1C39Awv3rdT7lnF6ng+v0YFCcrW
         9Nzu0o+ZpR+pbKMzWzZsjimt82cvBwllwTjJ/n5vt1Tsfz+vCnR7pE3hWvr5EEfISxXp
         Gj3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cxJQDgbcFRNQvDuXMj58bG+3E5UarvEKa9MKVbdgJI8=;
        b=aig+z9n/WlpOYrUesNz855mhtiDkqb5wkqPBSs4MVL+GTQDyg8aCvd1P/MoTJsNwvf
         Wq0dPuutA2kbsD9ODuoPOLEWooWSfe6bhKxvfLCdmdFZ3vmW5EDj0EIHQCS9cTk1TjNz
         PzzKYdvWNPbd0hMYNSdS4gHB5Em7k8qr9mh52Q0D8hNjFzC6MSXRNcfQzsYrx17wh57/
         3vUfqM6ct0lscwIX3ItcGYwvWopCK9V4QiaxrrQa6n4YVBdPwMNEbMQNAiVCQmWS0GGY
         DJHko8m0DWwIP086cavWCTKmvfaa+Gx81HCaGgr3RgiF4kVnQsZ4GuTUja8aVRYROG8c
         XglA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cxJQDgbcFRNQvDuXMj58bG+3E5UarvEKa9MKVbdgJI8=;
        b=gF9GOMiNbpj6b4+RjjE2IG9JZAEhlxM0W//YmIuPzEldWf/12v4XCT3UlxgMMx5Mbj
         AHZYE3K55hR/PkQ4LVPPJ5kykFxTnhwuYXfNw1v0KBILIOgHrxdYHHtO2CxQygS+Q4fM
         JjZy1nsWZ7YXnKZyBFSpKnoPAPPm4fsbxRIRhAygXxw4vMy40F7XMsoptywm+vnn4BKQ
         K3soI/wTPzkIIqeXq0vtWtMx8gzd6OeXP0EdfS2rphtUK0h8iKPUeoo+Xu+tZyCklLV0
         TGuMcdP19Lt4Yx6jGxbgbgyz3ntl5DUC/SE8PQB66xuoJLWBfImbxMF8VpDKPR8kTbdA
         +/9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jN5jctFirVvhDvRFhfjliDEseabkmvkGiiaO0SCfxjDeTxBVE
	tA1B89XzSKscKKa+gN/KGHA=
X-Google-Smtp-Source: ABdhPJz5nKVHZpcarPw7eC6e/tsiebYhxpS64HxdWDe12f631hAIGZ14zDf+nlnkOVDFPfLWlUMwIQ==
X-Received: by 2002:a67:e9cd:: with SMTP id q13mr2325023vso.18.1602769198682;
        Thu, 15 Oct 2020 06:39:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3561:: with SMTP id o88ls169539uao.9.gmail; Thu, 15 Oct
 2020 06:39:58 -0700 (PDT)
X-Received: by 2002:ab0:b1a:: with SMTP id b26mr1849821uak.123.1602769198140;
        Thu, 15 Oct 2020 06:39:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602769198; cv=none;
        d=google.com; s=arc-20160816;
        b=psIIl7PPCcYcI/pJZ2g3+eterSonMbMRHWylTaxBgHi3N66WgJAF5g3cbGCAddA/dF
         hA7/XJTwS5TdpIMOkLbohF/oFYXvCK6qKka0+Gb2q6Yf4di6VkTjExujUdyCNz4RKWFT
         FmbM/7QrTI1TmvzeY6+8hOaFE69cL1XMMYU1csVCZzUBwjjKpq/1OtNCTIj4bRYkAAWu
         aJXAttQdSP1Ly4hAfQlJbc8rF8FyMKaGD7f+7izA674CVOS1NTz5HXwqDnMVFnGUh1Hi
         8/su6KU6uTufuCqNuTOFGOodXz3iH1/Tre7jVgHdfCBF+rnniXbH/Dg9+Rn8ps+ylfKZ
         u+zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=tMBdVD7OKhIC3ci0bLAJhMYJOJKQVbkF/Id6z/zKZcE=;
        b=Ag3kvMQuA8yR8bLWrlc490I7Y1HiCCZnkaEquaTQqh18hcUQa/LOnqxAiZR6jQdaWI
         5Xx1zKmYdBq6EZLU9V16QnMQnVIWzhkhqn0va2Bl9d+4bSdMG9+65E58uAB1m500bVnu
         cuG/TKp1LRglTSgwIwy9qJ/G35rQGcIiOBH+IrBWL4CueE7mz6ccBwoqlhW54Q1FvNDU
         nvBzKKYdkcWk41IrW7AmwINX8VxMbEiTOzq8MLwy+tj/nlEemPq2WZ+kIelXxdJN8JnC
         OobhEdoonZzIRjoNMkzEXhPtWUtreAZ6gL7u+cj1p6C72uI/qnJOJj9KWvyXy6Tap8J5
         K+Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e21si201482vsj.2.2020.10.15.06.39.58
        for <kasan-dev@googlegroups.com>;
        Thu, 15 Oct 2020 06:39:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8CFC013D5;
	Thu, 15 Oct 2020 06:39:57 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.4])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 58A683F719;
	Thu, 15 Oct 2020 06:39:51 -0700 (PDT)
Date: Thu, 15 Oct 2020 14:39:48 +0100
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
Message-ID: <20201015133948.GB50416@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
 <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
 <20200929140226.GB53442@C02TD0UTHF1T.local>
 <CAG_fn=VOR-3LgmLY-T2Fy6K_VYFgCHK0Hv+Y-atrvrVZ4mQE=Q@mail.gmail.com>
 <20201001175716.GA89689@C02TD0UTHF1T.local>
 <CANpmjNMFrMZybOebFwJ1GRXpt8v39AN016UDgPZzE8J3zKh9RA@mail.gmail.com>
 <20201008104501.GB72325@C02TD0UTHF1T.local>
 <CANpmjNOg2OeWpXn57_ikqv4KR0xVEooCDECUyRijgr0tt4+Ncw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOg2OeWpXn57_ikqv4KR0xVEooCDECUyRijgr0tt4+Ncw@mail.gmail.com>
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

On Wed, Oct 14, 2020 at 09:12:37PM +0200, Marco Elver wrote:
> On Thu, 8 Oct 2020 at 12:45, Mark Rutland <mark.rutland@arm.com> wrote:
> > On Thu, Oct 08, 2020 at 11:40:52AM +0200, Marco Elver wrote:
> > > On Thu, 1 Oct 2020 at 19:58, Mark Rutland <mark.rutland@arm.com> wrote:

> > > > > > If you need virt_to_page() to work, the address has to be part of the
> > > > > > linear/direct map.

> > > We're going with dynamically allocating the pool (for both x86 and
> > > arm64), 

[...]

> We've got most of this sorted now for v5 -- thank you!
> 
> The only thing we're wondering now, is if there are any corner cases
> with using memblock_alloc'd memory for the KFENCE pool? (We'd like to
> avoid page alloc's MAX_ORDER limit.) We have a version that passes
> tests on x86 and arm64, but checking just in case. :-)

AFAICT otherwise the only noticeable difference might be PageSlab(), if
that's clear for KFENCE allocated pages? A few helpers appear to check
that to determine how something was allocated (e.g. in the scatterlist
and hwpoison code), and I suspect that needs to behave the same.

Otherwise, I *think* using memblock_alloc should be fine on arm64; I'm
not entirely sure for x86 (but suspect it's similar). On arm64:

* All memory is given a struct page via memblocks_present() adding all
  memory memblocks. This includes memory allocated by memblock_alloc().

* All memory is mapped into the linear map via arm64's map_mem() adding
  all (non-nomap) memory memblocks. This includes memory allocated by
  memblock_alloc().

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201015133948.GB50416%40C02TD0UTHF1T.local.
