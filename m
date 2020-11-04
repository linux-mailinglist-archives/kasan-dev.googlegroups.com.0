Return-Path: <kasan-dev+bncBDV37XP3XYDRBCUCRP6QKGQE2DVON4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C97C2A66D9
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 15:56:12 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id f9sf1995461ool.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 06:56:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604501770; cv=pass;
        d=google.com; s=arc-20160816;
        b=f7ywGHrtwhbCQQ7oGmGry7nV/xPGGiryQlCwaUPCtIQcfbBBOmhP4TGyusq7p5qMjc
         LEexBeJKiKrVT60kS8WVv8UMil4loAauzvbkjgDmIlkBszz7gkzlDzIi0d/6mfIzMG9i
         qP7Ccktdniw9v1ln7f4y69SCiNcVU2RNE1GtA+VdUc9WtmR99+g20iz8IVuTB3EMA9WC
         GSogaCnHIqJLhEOtXYxW/ouO1ZJT8BNz8nSx41jwTBFPJjmXhWDV+uY0wZkJeeDy7pDg
         G/cU43AXCNz/7mq6Ip/NL8bXg7wKufSChURORXyvuJh69SHdaxzx50iFWkyzeQxDYUuB
         IfxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cOygEF8T4XPekjEm3QcNXoOdDOl37xqEDL0UWi0kFlQ=;
        b=lRw3gVrY5eBhXgxD0qCnTLXPS3lq2yLr/yFpVlNYxVVf4iXA0bNNzTEf7LCC3ECMX0
         OSQjorqjcRE3hqmrSzpcNXMVEKBLw7ANGD/MCD+rV+kfGcN3XBh5zFBtJSC6bNN+wgl2
         Wt7zQxp8pams7xgh9cNKRc/Uzzjm94y1QrxKegGnwaOAtYnSNnqBCu1RJu1lTsPReNnU
         h6UmosooD/HjDdw7IiDJkYTrMkSwJg6GeU4oTV3HYxdwOwcq03qG+SQiU5ZMTuyDDLtM
         kKcSbGwmhvpJoGPzdOYn0phz+lJfNs3JJEviizpVCZc7fNBjR2xp2VxrPgMyQ5UvQWOW
         ISxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cOygEF8T4XPekjEm3QcNXoOdDOl37xqEDL0UWi0kFlQ=;
        b=TUSaElU6UIFbgEMhD3EHRoMPZSoSK/fjP50URH8ZpHK6XIROvOBBABLXMnK2ds257R
         5kXlTXTvrug3grvCF4524EfoE8trnan/86bq1gNuxu9aQw42cxyQzfH5q42UB8F79Wky
         VFeOFXeza5l2HM1C1uyxhyoRkGkxuVZzMmcE5kJ58dCYP1LVdAOMqIRC0uJBQfzAuFD9
         rDPbZjbpTeQ42wU43nasWJL2KNP0W+idNz+VIGJ3uGOm8+BUMGD2/xLQwraHc9WpfHst
         pgxwcf/D0WINWobZMhBJP/OML3TWF/8nDf5Ra1tU9dk/whmqYXj8AyOOTNnduyju7nOo
         68Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cOygEF8T4XPekjEm3QcNXoOdDOl37xqEDL0UWi0kFlQ=;
        b=DhEg+IpyA2uq8UcYwgP19UCg1Of4GpeVuqK2vWxFqwiy19Vz6rLXwh1NeVrfOu4Z8m
         H8gkOPQo+w8BfZGRniKEQMoM9T30nQuqU9ZPWgWp3KHB7AD/vlaKAMNWUi0g3fPEjR4A
         QMLW/8N7YGVQyRiO+BEhvdng/xMrLyMl0R6Lc+X1lR6bOsbRw1KDxj00E2789qUFhOel
         4Ey+PpuBrMISdmdM71ADoMEBXB9c07WdxEeVbk6jx3zXWRdXhv3vxSJK4f8P/pDfVgYx
         N3xo2jIPg+GELytBqZARjdgExjkRvIE0CweMGkHSalKqLtYk1CvpmF+v69ogdNqsbPi3
         eE3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ejSydjjFvfx45TL8PfX810JWk6blaL6iSJluOe+YVm0pN3SZ9
	YkW+RxM3sYUPeZCTDS46sm8=
X-Google-Smtp-Source: ABdhPJzVWpbTK7n+yR/VrfEgQspShLqedfvE9tGgX7vG9KNAwsCwRIrqCVXXCE7c2sd4zkTitSrvXA==
X-Received: by 2002:aca:aa90:: with SMTP id t138mr2912909oie.171.1604501770532;
        Wed, 04 Nov 2020 06:56:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5c0b:: with SMTP id o11ls565159otk.2.gmail; Wed, 04 Nov
 2020 06:56:10 -0800 (PST)
X-Received: by 2002:a05:6830:151a:: with SMTP id k26mr7766449otp.144.1604501770139;
        Wed, 04 Nov 2020 06:56:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604501770; cv=none;
        d=google.com; s=arc-20160816;
        b=sDchd1VCS1C7qdSmKp0W1kqUEiI1FGmf5n67g8tIo4j6HilN2QmCjHkEDVTCdyCMAW
         rdSHUfTrQYnnbBDGIYFubdIbNcBNtkvBl2tZ95I2g3rXFRet4RAI90L95buDjRMR/Fjx
         CI5DjbKZKZYEUdUjgDIeMAwq2PfeZryHxREPY1LQDHdV9NJgQOBX69No3gAUpi7/mhmX
         tS95YAEIBX3gX+sPb0mp3VA0M1u25e+vXyrQUWR0uZIVv6xLp+K9eo0xtSs3GCp/xhoo
         q2BXKwG0TvttoUDEXNWdO7U3AEGy2kdq8rNMcysxsYHypb8nrvGd5AZHV2K2Z/v7bOc7
         vQZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ctgVuI2WzWuLNSsVtP9t1O/ZNnmXGm3NLFiCjNDraUM=;
        b=zn7q0qQGkexV+GB4Q/XmYJCqdwly4a5PZjDz/zhG8L9TdJarfLE42B9kMK58QOpb2w
         imtlz7muvegVVMRAcWTZUkOhCiwun0wRC9NhjsGsUPDK4xVO3SdkP3APATJvK9F6LqPM
         1nI+IIVBwR+DHJbbuDKWmCQZuNnQwiyOOR+NRM7RW+aX+3BRat8Pybu+1A3z2L+AX7vW
         JslwY0DYR8qqIlsfKFou74s/LFPC6Gegh5x8M/owjfpYI4HndLcwqY98WnB7gxgJ2J3R
         4Uq4mmIOy9xJ2RdYT/FJnvtfSDOIEnilEZBNOl2kWFrvGtoINVZ0XduqWG62jRmBELLd
         Hp9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p17si226585oot.0.2020.11.04.06.56.10
        for <kasan-dev@googlegroups.com>;
        Wed, 04 Nov 2020 06:56:10 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C1F0E139F;
	Wed,  4 Nov 2020 06:56:09 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.57.109])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DBD8C3F719;
	Wed,  4 Nov 2020 06:56:03 -0800 (PST)
Date: Wed, 4 Nov 2020 14:56:01 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jann Horn <jannh@google.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	=?utf-8?B?SsO2cm4=?= Engel <joern@purestorage.com>,
	Kees Cook <keescook@chromium.org>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	SeongJae Park <sjpark@amazon.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v7 3/9] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20201104145601.GB7577@C02TD0UTHF1T.local>
References: <20201103175841.3495947-1-elver@google.com>
 <20201103175841.3495947-4-elver@google.com>
 <20201104130111.GA7577@C02TD0UTHF1T.local>
 <CANpmjNNyY+Myv12P-iou80LhQ0aG5UFudLbVWmRBcM3V=G540A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNyY+Myv12P-iou80LhQ0aG5UFudLbVWmRBcM3V=G540A@mail.gmail.com>
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

On Wed, Nov 04, 2020 at 03:23:48PM +0100, Marco Elver wrote:
> On Wed, 4 Nov 2020 at 14:06, Mark Rutland <mark.rutland@arm.com> wrote:
> > On Tue, Nov 03, 2020 at 06:58:35PM +0100, Marco Elver wrote:
> > There is one thing that I thing we should improve as a subsequent
> > cleanup, but I don't think that should block this as-is.
> >
> > > +#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
> >
> > IIUC, the core kfence code is using this to figure out where to trace
> > from when there's a fault taken on an access to a protected page.
> 
> Correct.
> 
> > It would be better if the arch code passed the exception's pt_regs into
> > the kfence fault handler, and the kfence began the trace began from
> > there. That would also allow for dumping the exception registers which
> > can help with debugging (e.g. figuring out how the address was derived
> > when it's calculated from multiple source registers). That would also be
> > a bit more robust to changes in an architectures' exception handling
> > code.
> 
> Good idea, thanks. I guess there's no reason to not want to always
> skip to instruction_pointer(regs)?

I don't think we need the exception handling gunk in the trace, but note
that you'd need to use stack_trace_save_regs(regs, ...) directly, rather
than using stack_trace_save() and skipping based on
instruction_pointer(regs). Otherwise, if the fault was somewhere in an
exception handler, and we invoked the same function on the path to the
kfence fault handler we might cut the trace at the wrong point.

> In which case I can prepare a patch to make this change. If this
> should go into a v8, please let me know. But it'd be easier as a
> subsequent patch as you say, given it'll be easier to review and these
> patches are in -mm now.

I think it'd make more sense as a subsequent change, since it's liable
to need a cycle or two of review, and I don't think it should block the
rest of the series.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201104145601.GB7577%40C02TD0UTHF1T.local.
