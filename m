Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY53R76QKGQENE5GNKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EC8D2A7CA2
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 12:11:33 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id j5sf612854qtj.11
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 03:11:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604574692; cv=pass;
        d=google.com; s=arc-20160816;
        b=rN3h5fDqgl++6IDEwIbFcC9bxpVPlMV9CEyKayMVevoK5Vf7+N4s0R2xEWLZ5cygg8
         kUNgu2AKo7YCKxRcbIdGNRTsSxKcJTPDkReMseAYhRiS2Eo33cTR/L6AgCnIkLhtf8og
         nJmdNlZMFowe8rsYDuM5CSAEni66DwU/3vDT1OA+RsTHwJl3OWHffCfvNUOlHlNAbovN
         YiJtXwqoiwBXUne/YJ6vEDvM7oGfnmcj+jzi1jYuKBhQNYeNzdJph65/tmw6RIcDNRtw
         9G7iYrHztwbUH7tTscXCCAmdyW/wkDgTmxfqoejAS3cFmGch5n4Iom6V9dW7Muq+vqIq
         QKqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ldFutdfXs5tndWUVCLNXlyx+sYo5vZ1SPcHzfNOJBLk=;
        b=LBfGp3AbmM3x3yUc0FfP2swMKao81KQV/KRRCcYjKjf6WEh+nAf9xe9j6tFV5jXvGb
         z9DSvamAN5lSmWMRVmu5bUEJ/65dqSu4a0csR+PtSRW5AokoE2E5p5MBo/I6g+1y3qpQ
         PhYEZM6heYSwluV9yV24P3wZwmOUtjOEUoaFsNop/9m5rI3j8u7p7Sdeh/Qi0XGSpmCd
         QObq1OxE7BCF46Q56FWyJvLk3IMo4/ZAo9wVC1XM6v4M6FpPmwMnI9hnmA7Nt77kBdf9
         W3gH2e3v674TFWBbzxdJfXlGvr8hrPpK0LOAyv4TP85nod+KKT9jv3tTmiQf7fZAsKDo
         V3mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UgAG4I4R;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ldFutdfXs5tndWUVCLNXlyx+sYo5vZ1SPcHzfNOJBLk=;
        b=dJyPn6GxNoX9+4peMGa0ceeyBqskqpVU8PVAsraWhIH2VbGBu+3m+IuQ1i3GsqaNmm
         6zi5PpgrPMJsVYZo05S7blXqhJxXKiLOjsXwdm/qjBX8X4v3wMYHowAxc8Rh+ecSBUtx
         8pFDUi+Z6p1wHAjivpaMWQ/Eb8h/CS7p0dKuDpWOLLqMFzPw3U7672OODDB0IW5RCj8W
         R3vG18VmFQ/n0z9oQhupBt6Wx7RQXT545NaenYri5dNbQV0n0NULobdP8YHx0aG/bP1Y
         Ck/xYOmtPdzPqjd6FWbq+dXLwKMII/5BpQod222mqyLV+Gi1dGHCp62ngsJ2K2KOE0ft
         wqew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ldFutdfXs5tndWUVCLNXlyx+sYo5vZ1SPcHzfNOJBLk=;
        b=fADOF8S+a0Ol6rD0JeUygrccTedYIR2Sukr+Cypu2+NTIhRYgC+SkMOlrnp5sALchK
         IZkSz1dy3kMGgxzPFX67bFPvGuqoXRQDWIzr/mi+FhHs0Ln3UtPeP06Mhv/KB4MX5XJB
         Hy2pBhWRN6WzQe60JqY53SDVuwrpOf84uaFYEd2aFuFa2T1Pd383jEjGFnBK8CfYPjJW
         ptfhhOpgWh9kDwLs1RFRRitQMbPcrjxDgAv2YlrQ+9khYudqCRtwp3ZdYEgdMQOz7HnV
         k99qNgBhw9sQ+hhlA9a7Zs+nLfc8Qa8JkUZB5sxW8TFnDg+XROF8UHeRb7iN2bk/egkr
         z0PQ==
X-Gm-Message-State: AOAM531ozFqAvVEMhReFc0BaC+iUIxxzfVs9Bmv8yImT2wL/Du6zliIr
	SZ7WQFjbsElH33vPyD1yf1I=
X-Google-Smtp-Source: ABdhPJzd8zhoopF5ZvqAYsuhJOEGIbgciDDvFlvxmIi9mG26O2LsCgt1fqAiPk72KbXtaBAn3J6lsg==
X-Received: by 2002:ac8:ecb:: with SMTP id w11mr1331285qti.113.1604574691960;
        Thu, 05 Nov 2020 03:11:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1352:: with SMTP id c18ls608739qkl.5.gmail; Thu, 05
 Nov 2020 03:11:31 -0800 (PST)
X-Received: by 2002:a37:6187:: with SMTP id v129mr1469332qkb.31.1604574691506;
        Thu, 05 Nov 2020 03:11:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604574691; cv=none;
        d=google.com; s=arc-20160816;
        b=ZW3Zgo5X3LLMfNjZmB6FgzKztBjufH40sGzfOjmq7GrVP7Dt++LVe76P6ceRoqT4S4
         62Mhq5m43reN7QknpMqczaIRqLri5Mwgi/vewdaK92BXqyLbuAtzjtI8QavYf4hkHLMv
         2zsJ6U14Uogw0P2wlXYNaZdX8r1Qd1GRdaPYBeoKGr/rVnZ20FJH5N02hf85Y4SPLFDQ
         AVSHYxhPeZgc23cmGb50YG9VMcn+2+h+H5m7TzIBE/djpODnFvRrZKeThGsfjK66yXZ3
         kPsObFUw5KbA8Vi+qtNE6qMwd6obs+f6DvJNmK01RwpgqJf0cd7xALOmmK+CiuWruxhW
         r/gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p0c7rtJJXojaI2Rh6wYkHrsZ57LiUlQdb8npxhv/hGc=;
        b=ttFsUJfQ/QUMa7CbvyIBp+UAk4gabLt1bktpCqYvtMARmEyGiee6ABTwJT9TZ7mCXK
         n+cA7i1HmodrT7DpwOymNHEemuw+Rt82gHGdX0/5V+vOtiZQr1losYz5ancMSBxQ/g3q
         uLhRpA3oRllCo0xlt0A8JRIShelmiu/d3Y9vv8gdk9mpUuWeKpZrY0BeZpORgBRuwzrg
         7O1LXO/di5r33aCmTUt3aZ3hnfjhwz+VX/4YzObY6sTMLxaYmaKUCbAVTKY0IaYEifM8
         QrAsgGxSC9bBtjhZUhuBmCI7lHJLSbWaprQI2gio9QQ+6NiFi3nofxuaF4DzSZXljfNm
         xiAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UgAG4I4R;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id h21si63719qka.7.2020.11.05.03.11.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 03:11:31 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id m17so1278564oie.4
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 03:11:31 -0800 (PST)
X-Received: by 2002:aca:a988:: with SMTP id s130mr1214512oie.172.1604574690901;
 Thu, 05 Nov 2020 03:11:30 -0800 (PST)
MIME-Version: 1.0
References: <20201105092133.2075331-1-elver@google.com> <20201105105241.GC82102@C02TD0UTHF1T.local>
In-Reply-To: <20201105105241.GC82102@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 12:11:19 +0100
Message-ID: <CANpmjNP+QOJrfJHC2P-9gFfB6wdnr9c9gPDgVFdgzbrCcG-nog@mail.gmail.com>
Subject: Re: [PATCH] kfence: Use pt_regs to generate stack trace on faults
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UgAG4I4R;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Thu, 5 Nov 2020 at 11:52, Mark Rutland <mark.rutland@arm.com> wrote:
> On Thu, Nov 05, 2020 at 10:21:33AM +0100, Marco Elver wrote:
> > Instead of removing the fault handling portion of the stack trace based
> > on the fault handler's name, just use struct pt_regs directly.
> >
> > Change kfence_handle_page_fault() to take a struct pt_regs, and plumb it
> > through to kfence_report_error() for out-of-bounds, use-after-free, or
> > invalid access errors, where pt_regs is used to generate the stack
> > trace.
> >
> > If the kernel is a DEBUG_KERNEL, also show registers for more
> > information.
> >
> > Suggested-by: Mark Rutland <mark.rutland@arm.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Wow; I wasn't expecting this to be put together so quickly, thanks for
> doing this!
>
> From a scan, this looks good to me -- just one question below.
>
> > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> > index ed2d48acdafe..98a97f9d43cd 100644
> > --- a/include/linux/kfence.h
> > +++ b/include/linux/kfence.h
> > @@ -171,6 +171,7 @@ static __always_inline __must_check bool kfence_free(void *addr)
> >  /**
> >   * kfence_handle_page_fault() - perform page fault handling for KFENCE pages
> >   * @addr: faulting address
> > + * @regs: current struct pt_regs (can be NULL, but shows full stack trace)
> >   *
> >   * Return:
> >   * * false - address outside KFENCE pool,
>
> > @@ -44,8 +44,12 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
> >               case KFENCE_ERROR_UAF:
> >               case KFENCE_ERROR_OOB:
> >               case KFENCE_ERROR_INVALID:
> > -                     is_access_fault = true;
> > -                     break;
> > +                     /*
> > +                      * kfence_handle_page_fault() may be called with pt_regs
> > +                      * set to NULL; in that case we'll simply show the full
> > +                      * stack trace.
> > +                      */
> > +                     return 0;
>
> For both the above comments, when/where is kfence_handle_page_fault()
> called with regs set to NULL? I couldn't spot that in this patch, so
> unless I mised it I'm guessing that's somewhere outside of the patch
> context?

Right, currently it's not expected to happen, but I'd like to permit
this function being called not from fault handlers, for use-cases like
this:

 https://lkml.kernel.org/r/CANpmjNNxAvembOetv15FfZ=04mpj0Qwx+1tnn22tABaHHRRv=Q@mail.gmail.com

The revised recommendation when trying to get KFENCE to give us more
information about allocation/free stacks after refcount underflow
(like what Paul was trying to do) would be to call
kfence_handle_page_fault(addr, NULL).

> If this is a case we don't expect to happen, maybe add a WARN_ON_ONCE()?

While it's currently not expected, I don't see why we should make this
WARN and limit the potential uses of the API if it works just fine if
we pass regs set to NULL. Although arguably the name
kfence_handle_page_fault() might be confusing for such uses, for now,
until more widespread use is evident (if at all) I'd say let's keep
as-is, but simply not prevent such use-cases.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%2BQOJrfJHC2P-9gFfB6wdnr9c9gPDgVFdgzbrCcG-nog%40mail.gmail.com.
