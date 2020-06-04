Return-Path: <kasan-dev+bncBDX4HWEMTEBRBG764P3AKGQE4QV35JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 879A11EE63C
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 16:03:08 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id o140sf344927yba.16
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 07:03:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591279387; cv=pass;
        d=google.com; s=arc-20160816;
        b=0+xvrJbJ5KxT1YNgwZrijqnFhLtlcrFyHui7tUZ9uOYKQ4z1/nBXR2ft9fSynD7Ik9
         w9msQUZ9fZqfykAOsP2JTw2ALkDlpM2wWXI1uNfIRyIzfn0Ry5Qkz3v7to5Ve+rDcCDr
         A9OGcIOHnS3Oeik7MMe5o9q4coUi5pJ30x03nLduVos99PE3U3kbr6i5TZFuadsh5mOr
         mFNcQGQnFMFpNb3l3Mx7UXwBFf5gz8YE2ABPC7NCKXM21azno5Tt8P8WAA5Mp0UsMVTF
         UPd0EfYCbm/EgykrXXzHn4sG23NH8Jp1IpkxWuxGMtYowDJ6KkbRB7QUG7KE2Vj7enXe
         aWIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qGWY1JPG5HORi0AGxbhdBJb/UQT+WSJfNZGUqgHReTE=;
        b=bSsLzC3FD5B9kYaCKgVotsxHLLaklIqDtBK1bb2Cr7yQgQ+tUOsagWiD5eCx2jrIYl
         Opw1rFyRj0vhv6oMU1scnFHQRP8qd8/E+brwl0ggk3OxnWAim7Jekb6NfnPaJz8I/yu0
         B19KJh00lESaHKn3/WlV9Jfe5hHL7AgFZCv7lrLGV9sJdO9mzVCR3gILzWXUlRdfiVGy
         9q05mgt+Oyota3n3vVmYa1XACM2eWukhQkNL3Q/uwR2v8MUimWBijrV73ss1btCQFxal
         W3hArrtsy8gLl5Lin6Q+vA4zcb4FTo848E4mdMEc3Kz1o8Q3i0KSt/tt9pHDO533Uex4
         Okgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wK7E14tk;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qGWY1JPG5HORi0AGxbhdBJb/UQT+WSJfNZGUqgHReTE=;
        b=nkKNvmyiric5QlQuc0cQYOSBTqE3oixOHS+v87Os2ZDQbGC+jqVGaSqGNHCArj6ZR4
         Im1Gr2yMWHATrXi9S+6DnlV0au0w3SPUhHsajl7GpZAFYl85Z0aaHBxvK9A6xM+aOSGd
         4hSGqDU3e6l+V7bsjHotO+0wz17mHzYQoBlw1L3TVj8g7LsUSoPE9V9C9/d/DRml+M7c
         +xjVoAITwsLp0YdzlvEUpNgotc4E4sLWBa9AFxypKIOmhKHKjS6Alrxy0wAGuY9SLaSf
         X5UMECPpDTEu6i7QpPSUxfFehZfCdhz/lsDNx5b9VzGb3228o3U8P/1uJHWPw9+isTq9
         aIag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qGWY1JPG5HORi0AGxbhdBJb/UQT+WSJfNZGUqgHReTE=;
        b=fTsM35u4ge22tPbuRWRTDU1YO1M20VlnLQf5XtuWO915fktG+W7yKUozkXLx78aCVb
         qL7yFjR8NqGq9kMKYxq5yhZPzkvFKdFLe6DZtbQdhzrPgGZyYr6AkUg30JVWeoT360xs
         J/kM6sgWWVeOUEiTu6Pt4TbMkl4XtlYa0bhsjUhTYrePWdj1UkQEpXhcO3C8d36yVmGZ
         segcrxlWm+5PqbdGnZNiT7fCW2RJ+mAU4X2tChXBlQJSlA9AEZWM1ex6FdFVg+73BYCB
         6TW5saRlxIzMXnNVSOxFHM8HG3qZNeULhGdpUSmnTdhwIoDhqCcMYzR/Etfl0hYvIq4n
         CcSQ==
X-Gm-Message-State: AOAM532lDMIaNRhpsTo2EgzRgxd0m/6cU++n8groD4hQsLcNsN8kxArZ
	94UtsSPOOP5tAU06Bwyfp+E=
X-Google-Smtp-Source: ABdhPJzMMlVLqkvtPA5qGjcsRIa2myfueaZv8C4ZFhdylPkT1Of0Q9xmh2xXfmYoopvUREiTY2GXmw==
X-Received: by 2002:a25:99c8:: with SMTP id q8mr8877713ybo.261.1591279387224;
        Thu, 04 Jun 2020 07:03:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cd43:: with SMTP id d64ls2521055ybf.6.gmail; Thu, 04 Jun
 2020 07:03:06 -0700 (PDT)
X-Received: by 2002:a25:8b83:: with SMTP id j3mr8171001ybl.318.1591279386888;
        Thu, 04 Jun 2020 07:03:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591279386; cv=none;
        d=google.com; s=arc-20160816;
        b=ZmA8wGmjo2q3JzHna2fACva75d/g0cBGX3Di85BvhEe7XCqyXjXJAmhFqm8gInuLxC
         4KMaeJsN6L+GGQ6+vK7IQtjtNim6B71DKevlM//ZTsw7mMY9AMRskFI+v93P2OWzPCqg
         1EJlYc/35unYjyHumTlkIjsoaH6RN/mgtpw1GnB2FPH1WAJ3MJiERw8hdEouB7+7ThbJ
         qKgurREtgL0AQ47YEY6nbLI5sJAKVvQWLno10HUcra9ov57wtE7Z/2umpWxarSVVHikO
         d4e9uqYatPf5Z3s29ZSBYdCbGL4630Qwg7UKPymqbsRaxjOGpv5qdyRThdUoHYGphMvA
         rUUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ImRfD2cqJ0tQ89Ygd7DHH9ExVVNMqaoCZMhHXpLzooU=;
        b=fq8a0jdEyRn7J3WW9vM/U6ywRU5OQ3Ynk9Hyp0M0+FewcGXGOVgxoQZTwciV3ykgs+
         ZGUA9FZJ6yOf8+C0Nf5pWyavfh152ANZ17rI/vFJJyJkL4lWorYD15h1YKcEIG0k9wyQ
         BqBDqKOFgHAWwg86fFgsGVN5v93u/4Hg/n5dqMA6LD4HiWZuWWpPhCsRzvAJ3U8XYjpe
         YoJ69oV61ajyZl1eugd5YEYXWAdPo4VJSI+81daQFA51ghUVtF5CcU+Zy7OPfWYU/yV4
         bTQh0+wy7T+0jrWBw3bj1wLKJ6lAmQholnt1OL6I5GfB1YXVjrcUypUvIROhwKA+lEmb
         4FlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wK7E14tk;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id s63si381992yba.2.2020.06.04.07.03.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 07:03:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id bh7so2208990plb.11
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 07:03:06 -0700 (PDT)
X-Received: by 2002:a17:90b:1244:: with SMTP id gx4mr6178570pjb.136.1591279385737;
 Thu, 04 Jun 2020 07:03:05 -0700 (PDT)
MIME-Version: 1.0
References: <20200604095057.259452-1-elver@google.com> <20200604110918.GA2750@hirez.programming.kicks-ass.net>
In-Reply-To: <20200604110918.GA2750@hirez.programming.kicks-ass.net>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 16:02:54 +0200
Message-ID: <CAAeHK+wRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ@mail.gmail.com>
Subject: Re: [PATCH -tip] kcov: Make runtime functions noinstr-compatible
To: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wK7E14tk;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Jun 4, 2020 at 1:09 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Jun 04, 2020 at 11:50:57AM +0200, Marco Elver wrote:
> > The KCOV runtime is very minimal, only updating a field in 'current',
> > and none of __sanitizer_cov-functions generates reports nor calls any
> > other external functions.
>
> Not quite true; it writes to t->kcov_area, and we need to make
> absolutely sure that doesn't take faults or triggers anything else
> untowards.
>
> > Therefore we can make the KCOV runtime noinstr-compatible by:
> >
> >   1. always-inlining internal functions and marking
> >      __sanitizer_cov-functions noinstr. The function write_comp_data() is
> >      now guaranteed to be inlined into __sanitize_cov_trace_*cmp()
> >      functions, which saves a call in the fast-path and reduces stack
> >      pressure due to the first argument being a constant.

Maybe we could do CFLAGS_REMOVE_kcov.o = $(CC_FLAGS_FTRACE) the same
way we do it for KASAN? And drop notrace/noinstr from kcov. Would it
resolve the issue? I'm not sure which solution is better though.

> >
> >   2. For Clang, correctly pass -fno-stack-protector via a separate
> >      cc-option, as -fno-conserve-stack does not exist on Clang.
> >
> > The major benefit compared to adding another attribute to 'noinstr' to
> > not collect coverage information, is that we retain coverage visibility
> > in noinstr functions. We also currently lack such an attribute in both
> > GCC and Clang.
> >
>
> > -static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> > +static __always_inline void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >  {
> >       struct task_struct *t;
> >       u64 *area;
> > @@ -231,59 +231,59 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >       }
> >  }
>
> This thing; that appears to be the meat of it, right?
>
> I can't find where t->kcov_area comes from.. is that always
> kcov_mmap()'s vmalloc_user() ?
>
> That whole kcov_remote stuff confuses me.
>
> KCOV_ENABLE() has kcov_fault_in_area(), which supposedly takes the
> vmalloc faults for the current task, but who does it for the remote?

Hm, no one. This might be an issue, thanks for noticing!

> Now, luckily Joerg went and ripped out the vmalloc faults, let me check
> where those patches are... w00t, they're upstream in this merge window.

Could you point me to those patches?

Even though it might work fine now, we might get issues if we backport
remote kcov to older kernels.

>
> So no #PF from writing to t->kcov_area then, under the assumption that
> the vmalloc_user() is the only allocation site.
>
> But then there's hardware watchpoints, if someone goes and sets a data
> watchpoint in the kcov_area we're screwed. Nothing actively prevents
> that from happening. Then again, the same is currently true for much of
> current :/
>
> Also, I think you need __always_inline on kaslr_offset()
>
>
> And, unrelated to this patch in specific, I suppose I'm going to have to
> extend objtool to look for data that is used from noinstr, to make sure
> we exclude it from inspection and stuff, like that kaslr offset crud for
> example.
>
> Anyway, yes, it appears you're lucky (for having Joerg remove vmalloc
> faults) and this mostly should work as is.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ%40mail.gmail.com.
