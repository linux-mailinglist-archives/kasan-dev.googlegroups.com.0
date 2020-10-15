Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5FSUH6AKGQEXPKUS4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C65028F485
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 16:15:17 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d22sf2035074qtn.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 07:15:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602771316; cv=pass;
        d=google.com; s=arc-20160816;
        b=tGzaReTLir8twApC1HJzHrNXwgEQIn131qPa++dJZf1fOfyHkpo76rLlXtIgLxbwN9
         uR/+mkWvnkmXh6cA7M2Bm1qQNTstMJxgJCCa+g5mEThwOUfKrYGB4aFZuCl1vSAKv+gA
         3slZNi5+3KudBMkd+JELw6iSCc4xwnVKtmKh51Pv19VJdHsvjwonC7EETghnKnDqVEDg
         lk6v22booq+ZoNWQImrDJxize93qjZ49epsQGMKiaBd4ZjyJutV+XXErqgNx4HjPbE1H
         IMtihgqOREp3fXh2xiIX4shE3HI/0HiHkxX6mJub0cIHGjgI3LJrAeHe3wbELTSxOGcU
         qS7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=23grdDS5PbJMgorznO/BHi3C1Vg4c7s4l0RWYMuT8Po=;
        b=L2mscsPG2BvPNf2J9vsJxgAFEoh/o/kU3ZHNi9kwD1Uy917gSOTw5108BLVtFRe365
         YySIUkEy4CmV9EKPYf9XJwf1gBzGFzJEXg/0ajbvSizqdgU21e2Y1UXMra/WcmVYWzG/
         tPeKTugg2vYQ5g51w0YXqzhxxzd6ImiUlZ95E+xXt6eqPR2GHkaZnf2cJ4WnqSfWAzA+
         giQmw0tPqeJfp1TUuOPEWLk+2UOFZza8y0p29kDQtKZKIzCM61pyv5hX/ZhYKjJDz8Su
         tmdOKzMVRzuyOWOY2qWVOSypHPqwHs5zmoPmuhEs1myCYRBHye7BYX02pV3LIlJxGODD
         qOSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ENts0Dm6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=23grdDS5PbJMgorznO/BHi3C1Vg4c7s4l0RWYMuT8Po=;
        b=jgUjJ2QUimDRbqsxBXUgUbwuih7ErgKDWANKkQKZF68+HUK9BnI0I9E1KErgS2A3hu
         q1ofHr3q3ffQyf15i9ehnH7BXfiSi8YUx3qSvoRHve9H6pli4klfYazGmCbCoNIXpqeN
         J2cQYNljrIhm/2AelGYYZrwUJ6htGjClTAWjt4zqwYCB9e5TU/hSXfaOQ4yP+peiiKZF
         ncuEqxf5TbB8fBX5N5ANTHMPLiYpZNMW964XtEUOu5X5juUIUwMRsC4aN4QrQ2KlmLZ2
         33Jw6ChnX5FXiehHhB87qdVb3OQY/CNrAIOK+JGwwu/wjc+zdcyUZwE07Fh7fjFEEeEX
         SS/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=23grdDS5PbJMgorznO/BHi3C1Vg4c7s4l0RWYMuT8Po=;
        b=MiGHJpPwrYXHkEQAzTrfB/kaG1fKSZzi7aTW6R/1NLzZWZ4oevNj8WhTl20klUwqe2
         f317xE7/LP/SAjtkNx4PZJjDkd6vEwDMiiZzm65VsIOpyBZwZPNZ4s9tZC5we9WJRBK4
         zOxU/9AzUqNCkwDOIeX7dhand4Ww15H4X5hZZ+ga2LlvHnWLtw2Y2KOlnooSFrGs+oxE
         Edtcvh2DYCnSXCYD5rwcTb3nMQq2g6ji1q3eNHm2DiLiSEV8OjL3hqzFWhGTn1L6jvQF
         fn392tsNy1TVBH8azb9Ln+d5bFmGTWTynHMHcxsUFOhU1zaifCVK30ekUQTxQ8Xk4edg
         beeg==
X-Gm-Message-State: AOAM533LtJaXrT5lqGnybqcvz+xxaIpbpBPPNJ+U6RMFgpbSJHRsC3IZ
	uYuhr5cAZSBgP7yu6mFwpNE=
X-Google-Smtp-Source: ABdhPJxLioVDaW5o6NDbKi/6+0UhcNK2Dp1fJOFFzWE5ftcQl/r1kDlFfdrE2oz7xzZIaiAaxt6cIQ==
X-Received: by 2002:a37:4bc5:: with SMTP id y188mr4195162qka.429.1602771316173;
        Thu, 15 Oct 2020 07:15:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:d07:: with SMTP id 7ls1342844qkn.3.gmail; Thu, 15 Oct
 2020 07:15:15 -0700 (PDT)
X-Received: by 2002:ae9:c211:: with SMTP id j17mr4282418qkg.458.1602771315427;
        Thu, 15 Oct 2020 07:15:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602771315; cv=none;
        d=google.com; s=arc-20160816;
        b=ngJMOdTJY1bbJslBwSkw72Fq81i4x5fNEhI2708Hwrh814/7nZ1d422n9rwVkYoHaW
         pQsn3qqT17+DOOnvwqy/QhULZSy+pR8Ancv1G0dnwBr9azSDBpvgYAUULwUrWuzSg6Wb
         JTVfUexkppoMSLJ9vN9s1xere2PcphEHfugjOUOcA91RanyE0oB2LM7mJHXZDVZB0MgL
         f2JdvBKDY8QisqGqiiWO8/NjpNMOVrlJbWmvn4r8rNE/yrYT08mfwOvernHjYWXNzcG7
         THrt/lBKMdi9lbWDQiD/w1UfdtKRhr9qnqtK47lm5LH1vTzJpqqN84E5TSzxGyLSv9Iz
         aNIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=myXCOQxC7yXdiZx9nG9HTWtecWE6QzVgfe61cEeMHyM=;
        b=Molzksxw2QXoi9b+79cgAsnOG9HULOrBxSqfW0gswPoOKCi9edsr6d40Robeb9P4xI
         37Z0xuQtGbZyJmJ8ajfDQHDO0lxlZMB2xXr1MZjWn6e9t/l5sIae96mTAqSj52fvEJWE
         9ADjevFJkzwUYn9abwfBeU5B3PE/ZMVZv+p69MzQ7a0N0fup31AVhTZxG5Hy6sdoiehs
         t4WLNFbeHxujgdn8ud0JgMc4WArVoMt67XFxu/lcGF79J+kD2HsJ2Mk075Bh0dq6F440
         fUJf299Wncyx+xyN7960A/kFaVLhCk7B3aHmaLY2fWXpcb4NK1QRl92RE2nAYKWfGqLv
         U/fQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ENts0Dm6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id s76si148768qka.5.2020.10.15.07.15.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Oct 2020 07:15:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id w204so3282539oiw.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Oct 2020 07:15:15 -0700 (PDT)
X-Received: by 2002:aca:6206:: with SMTP id w6mr1155830oib.121.1602771314808;
 Thu, 15 Oct 2020 07:15:14 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck> <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
 <20200929140226.GB53442@C02TD0UTHF1T.local> <CAG_fn=VOR-3LgmLY-T2Fy6K_VYFgCHK0Hv+Y-atrvrVZ4mQE=Q@mail.gmail.com>
 <20201001175716.GA89689@C02TD0UTHF1T.local> <CANpmjNMFrMZybOebFwJ1GRXpt8v39AN016UDgPZzE8J3zKh9RA@mail.gmail.com>
 <20201008104501.GB72325@C02TD0UTHF1T.local> <CANpmjNOg2OeWpXn57_ikqv4KR0xVEooCDECUyRijgr0tt4+Ncw@mail.gmail.com>
 <20201015133948.GB50416@C02TD0UTHF1T.local>
In-Reply-To: <20201015133948.GB50416@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Oct 2020 16:15:03 +0200
Message-ID: <CANpmjNO9Gw0-U+QynFWPPZYEVgnZA84VHi_XrXfa5aiAq3kPuQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=ENts0Dm6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Thu, 15 Oct 2020 at 15:39, Mark Rutland <mark.rutland@arm.com> wrote:
> On Wed, Oct 14, 2020 at 09:12:37PM +0200, Marco Elver wrote:
> > On Thu, 8 Oct 2020 at 12:45, Mark Rutland <mark.rutland@arm.com> wrote:
> > > On Thu, Oct 08, 2020 at 11:40:52AM +0200, Marco Elver wrote:
> > > > On Thu, 1 Oct 2020 at 19:58, Mark Rutland <mark.rutland@arm.com> wrote:
>
> > > > > > > If you need virt_to_page() to work, the address has to be part of the
> > > > > > > linear/direct map.
>
> > > > We're going with dynamically allocating the pool (for both x86 and
> > > > arm64),
>
> [...]
>
> > We've got most of this sorted now for v5 -- thank you!
> >
> > The only thing we're wondering now, is if there are any corner cases
> > with using memblock_alloc'd memory for the KFENCE pool? (We'd like to
> > avoid page alloc's MAX_ORDER limit.) We have a version that passes
> > tests on x86 and arm64, but checking just in case. :-)
>
> AFAICT otherwise the only noticeable difference might be PageSlab(), if
> that's clear for KFENCE allocated pages? A few helpers appear to check
> that to determine how something was allocated (e.g. in the scatterlist
> and hwpoison code), and I suspect that needs to behave the same.

We had to take care of setting PageSlab before, too. We do this during
kfence_init().

> Otherwise, I *think* using memblock_alloc should be fine on arm64; I'm
> not entirely sure for x86 (but suspect it's similar). On arm64:
>
> * All memory is given a struct page via memblocks_present() adding all
>   memory memblocks. This includes memory allocated by memblock_alloc().
>
> * All memory is mapped into the linear map via arm64's map_mem() adding
>   all (non-nomap) memory memblocks. This includes memory allocated by
>   memblock_alloc().

Very good, thank you. We'll send v5 with these changes rebased on
5.10-rc1 (in ~2 weeks).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO9Gw0-U%2BQynFWPPZYEVgnZA84VHi_XrXfa5aiAq3kPuQ%40mail.gmail.com.
