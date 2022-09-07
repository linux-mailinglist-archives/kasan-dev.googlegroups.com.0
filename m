Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI4W4GMAMGQEY3QM77I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id C40525AFDB7
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 09:41:24 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-34577a9799dsf39548287b3.6
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 00:41:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662536483; cv=pass;
        d=google.com; s=arc-20160816;
        b=e0dca0farBYs1024LMeZY1BQgnAWDqot6V+hlNaWrUS2Bz+G6VkpB7LhTYMsMek/Db
         9zfSv8i0YF1GTLL2FEF60FbsHA+bHCkvuC7nVl9LLfbVxxYWLP5zCA+Sbc4y5G9HrwzV
         aQVMni7QegfAo+hIa9kW4ktf4g1XsSTS0Bn5JTBpzkbLlM5H1GDx8Vqa1+6HDeN4YAXg
         U/vCf6KTZurF1K3MQTXxmGiK+yEO7iM/Z8DQ+byePQ5p9B/2SPpbcoXGDiWE6PEPaJk7
         0HcX060xXsqa/WigiRQF9Q71iaB98XNtEIGGI0fGxI16GaDAmO0epN1l+bpzPmdnt8VG
         psjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x2gLd1/c4lxga8fBGt7l5QPyEkUBllFhpbcuKBMbvg0=;
        b=tGWjGh6xG4D1t3+cvKqu4I2e+oA1SWxkL39kbQTn+rVg2eHCp/+nfRQouqNEZ13KuK
         hB7TzfvnODCSVVMO1/8mI1iyxBHv2vhu4XdoBea5xn0bFQOP8xSudX9S2oDVkF7+LbGS
         4WRbEleIxteSpuiatpLuJlpLsEVAHHcWcc8JG/Cn06/vBMWabAYTMOoMeX7j6kzvE5PD
         ohwF0Z/xsELvsRkca0XPfR0sX//bTwig/CYzRTpC8P+CrF/idog2iTNiSXhXwHjuGJyJ
         F3W1Sa4Ko9hpoCaZE2Su0egq3at7N4xk8moYKiIgTyrSYaaCIwUxkKOL4UPi6m2Ey8r1
         TxpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LvMU6mMR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=x2gLd1/c4lxga8fBGt7l5QPyEkUBllFhpbcuKBMbvg0=;
        b=e5xtsq24HqlislTHEIcdDemA7+y0qzx8a43/EOS1xoKYDaG1c7traHESbRbJY/SZY4
         YzPitnwyTjvxXgj3ZaxXBPxmWzsucuEfjYAk/WyxcOgeYRGAjrFB0In6br3pVugB87z3
         fklMIAUxlVoAhFtM+X6RFO8pdZmBOHIzVbuKPBbW18xuR7uo5fLg3nKoX7o4jXl6Xwiw
         NqN01Ey/Ho3bcdxl1BsTOfZr3gCo4RwPBv3gRupFKBaCypRbWXpcvohnsYE6Ueaz//pJ
         h3JqYS45h4v1qIIQJiUkYeP6X0KTTH9PEJPuuNAC0pg2UX8mOc9Uk15vmxjqMUtIcOxg
         ea1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=x2gLd1/c4lxga8fBGt7l5QPyEkUBllFhpbcuKBMbvg0=;
        b=CxdtClyelv0F3CLlZyMogQ7N+NLw6HHnM9EeXOqHghHfabCYJtLs8XukHxnDVsw6zb
         EgPpofhFKcUbXfXNeMveh1xS626aH3xvmupheMGjckkS8CxQGOy406rEYY5ZWH7kJ2x8
         k3edCUD0X4zJPTNiAbaEze6kZYK0sQVjyT2KP8+kzO1rra5HDfGn8HEaRSFMLbaJkk60
         ngKXjfqj+B7gEqbwfugJAhyDZkxIKEhuw1T1Z3Wh9sWSaX21H8/1o0QvIRfktipvMV/P
         5E6yrTG87rBbAvbgQQR7rDTHqCMIKJ6OGiT10gsy62/JbD0vuWgCeyvD830it+1eNcIF
         C89g==
X-Gm-Message-State: ACgBeo0PgzBkNBxC2TDgoEr+l23OLuLwCn45LttdAlmfg1qgicxE4IxU
	a3LMcGdhyTJCQK5ql6gWmw8=
X-Google-Smtp-Source: AA6agR796xevgmBtHlFghDfn885wyH5UlvSD9LqUfuuuxEKPWlDcU5WEm59ioUkbnEbm3vRh5Z16lw==
X-Received: by 2002:a5b:848:0:b0:683:58d:ea95 with SMTP id v8-20020a5b0848000000b00683058dea95mr1700971ybq.565.1662536483434;
        Wed, 07 Sep 2022 00:41:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:b8e:b0:345:895d:35eb with SMTP id
 ck14-20020a05690c0b8e00b00345895d35ebls1593355ywb.2.-pod-prod-gmail; Wed, 07
 Sep 2022 00:41:22 -0700 (PDT)
X-Received: by 2002:a81:34f:0:b0:340:bb88:75ff with SMTP id 76-20020a81034f000000b00340bb8875ffmr2058667ywd.398.1662536482789;
        Wed, 07 Sep 2022 00:41:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662536482; cv=none;
        d=google.com; s=arc-20160816;
        b=vIRd7HKLPMXwvSSz58ncAR+QeX/VfsmscDZVS4Xwu6y5EabZPZNyqhdGAg3CbImNsO
         Il7fvdAYaf56/4btMAUn/eBjvpI/Dd/Nhonj0oVVi5mA3uhpetGj3Kq7BXCrzH0Ny3As
         9YulXtupc4ot/7DaX9Tj8e8xxqhY7UflEJBkjBTiDhwovKHNEZbyftd6e3ylTxHgukNT
         iKNwA10AO5VQ/bpibQI3UM+aYTEv1HNwehaPh5Qxv6OTdegEe9sQ+sH8+KpqLFAKpx64
         BWRyrXLYvzXL3H8KLqwoS+7H4YtUUkTj84WPl7jqYKagFn02bLz07lpguWaKqEhGkD1Z
         Lc3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E9pidXGct5S8ms/KlIXlwMVVLVf0nTiLM3OKPd0GOQQ=;
        b=X5MOLau1Z2F4n9MWySehpFJZHvlKNnl6Wl9y66td9g2K5RdH+JeZzPQrRVKKuIZ6Br
         7RyEa0EtG8U1kGiO468bTjG1BeCwIHKL8VBsUeuMdPP2Toemx09PvZ4fbL7RKq8zblei
         XmdGRuy5g+CBdQ/2PTv8ToQK0/KjdOUVvH2sIOMlxaDC3xwbTnlOussjZ2JgI8dFncTj
         YbScnfe/mnoqW21SCqpVCzhOvnH3hT1SMcMsdB2bZkRveHVt4kCKbBO82xpvqm0n2cVI
         N1Zl+joQK/qfRjzo9PbmAEUenwS9GnNUJUeIn71xeGYqEx6f6WsyDwpTRJsudHLKqOGJ
         toSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LvMU6mMR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id m2-20020a81d242000000b0031f111d36bbsi1841616ywl.1.2022.09.07.00.41.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 00:41:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-344fc86d87cso104462957b3.3
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 00:41:22 -0700 (PDT)
X-Received: by 2002:a81:a16:0:b0:345:afa:5961 with SMTP id 22-20020a810a16000000b003450afa5961mr1953865ywk.11.1662536482427;
 Wed, 07 Sep 2022 00:41:22 -0700 (PDT)
MIME-Version: 1.0
References: <20220902100057.404817-1-elver@google.com> <YxevqB2OpJ9BLE+s@hirez.programming.kicks-ass.net>
In-Reply-To: <YxevqB2OpJ9BLE+s@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Sep 2022 09:40:46 +0200
Message-ID: <CANpmjNMbnG2KcSoqmCkPTcSkdsgHcfTSaXDSKti3uHGz6A=bsQ@mail.gmail.com>
Subject: Re: [PATCH] perf: Allow restricted kernel breakpoints on user addresses
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LvMU6mMR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Tue, 6 Sept 2022 at 22:38, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Fri, Sep 02, 2022 at 12:00:57PM +0200, Marco Elver wrote:
> > Allow the creation of restricted breakpoint perf events that also fire
> > in the kernel (!exclude_kernel), if:
> >
> >   1. No sample information is requested; samples may contain IPs,
> >      registers, or other information that may disclose kernel addresses.
> >
> >   2. The breakpoint (viz. data watchpoint) is on a user address.
> >
> > The rules constrain the allowable perf events such that no sensitive
> > kernel information can be disclosed.
> >
> > Despite no explicit kernel information disclosure, the following
> > questions may need answers:
> >
> >  1. Is obtaining information that the kernel accessed a particular
> >     user's known memory location revealing new information?
> >     Given the kernel's user space ABI, there should be no "surprise
> >     accesses" to user space memory in the first place.
> >
> >  2. Does causing breakpoints on user memory accesses by the kernel
> >     potentially impact timing in a sensitive way?
> >     Since hardware breakpoints trigger regardless of the state of
> >     perf_event_attr::exclude_kernel, but are filtered in the perf
> >     subsystem, this possibility already exists independent of the
> >     proposed change.
> >
>
> Changelog forgot to tell us why you want this :-)

Oops.

> I don't see any immediate concerns, but it's late so who knows..

Similar to motivation as
https://lore.kernel.org/all/20210408103605.1676875-1-elver@google.com/:
Low-overhead error detectors that rely on detecting memory access via
breakpoints/watchpoints. For example for race detection, but also
things like data flow tracking.

By allowing in-kernel breakpoints on user addresses, we can detect
bugs that involve kernel accesses (e.g. for race detector, racy
read/write vs. syscall somewhere; or tracking data flow through
kernel).

Shall I go and send v2 with some motivation?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMbnG2KcSoqmCkPTcSkdsgHcfTSaXDSKti3uHGz6A%3DbsQ%40mail.gmail.com.
