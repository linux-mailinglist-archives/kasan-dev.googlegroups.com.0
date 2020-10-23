Return-Path: <kasan-dev+bncBCT6537ZTEKRBYNPZT6AKGQEKXBVQJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A89EE297619
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 19:50:26 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id b14sf581227vka.21
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 10:50:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603475425; cv=pass;
        d=google.com; s=arc-20160816;
        b=JBxG5OTmKt42zm8e1WFxY46prfq5FFa0E4uxbPNvaxauJkEXa5S+X8yR0dPrrDCZMI
         d3bMNBetzP52tZBvg8qQtF4ZJnXfAkXWz6xu7cb7z3/h6JE07GVHVgNiIq/1Etlj9lzB
         2kPm36RoU8N7UFhOCyDAlhBtke3I+4UKH1NQjkM5fBn6D28ZUkH5mY4OsTU6fX9ZKGy2
         IP/m33exDIMU3lTbLeLSI20fGuKFb6WHK9cpF5GWQUGknBeqMtcSDd8SSsYbOjifbsHn
         mOjNYoM/H2YPphnTyd7bZjaWPKzpuiE2MeTvkhedjtAJOCnvyW7DOJgZMu6OV/DjCMvf
         c5VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=f7axBbf1HILdeg25PmQaQ8wQcpnPCXlKVjTVH8Q0rpQ=;
        b=QVmqYCAIJWYPEqkWmDvqLF5/tbts7jwkT70RijS2GPpnueg9MZ+HPrrZ3AUuDIW5pO
         P45L+WerSHPmHBcGVfTUMs8PoNp63eQhgrcHCf1dFLVs3cHJR62sY6OIiRzWtx3fsKLS
         0k8me9f7H30IycPhptk7wfSh27f9JqbEejzpdx086OpKGab/LhtYz76gylTPtQhj5Yrw
         BI6qXx3Dnc49aBFMyvdbiRlCeX8eXxXv1ttAqiEo+3ptI/YvhkrvYu37KV1dWsBfj1xD
         wPs/3mO9HjR3hC2KeWZwqe+1UaQjl8fE5tdjUXjtlszLh4lD8M9FV1bstjXvMsabVPWj
         aJSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=zC+oRhFa;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f7axBbf1HILdeg25PmQaQ8wQcpnPCXlKVjTVH8Q0rpQ=;
        b=tcKtFmMJO+IjkqZqjRHJzhvl3eyiYrr2Uq81M7pcxo9aY38vjPEkqcnO9pfiJRUVDT
         jfK8pQj0hT2ZKfwAAnNvAeQSbEsNT/R5XP0dqW1xB1U3w6GyZspquol2KrEb9X1eaxwK
         WWKNSBZ/IEmwiox7tt3BSRgbxnmTH3je6Brr3epag7QivjZcQi0dlJY0IeebquLz/iRf
         2BC8c0xhqurMsWv9s1a1hbZ/A0nn3Hw9TYesHGFHU210MptRAmdpKZljOOQf3iRzwXls
         iGk5f00Ay3OYZsVqTu2uvSBwYTFEBSVNDb3IfnSRXd0S1Lj6AHEr45TWwu6Ee+IPw8Pf
         44sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f7axBbf1HILdeg25PmQaQ8wQcpnPCXlKVjTVH8Q0rpQ=;
        b=GyTvwXG+4+MGq8gHpQy6GPfIv8JtjYPwZ536xKcDqNuH9rp4KD938tGC8GHn87Vo5h
         mG+/vOigY4pNXr2wF1u5Bvk56iHPQ+2nIGMHptib0eX0jHdagaYdPKa2kCUMzPrQQDfC
         wahUAAZhiGX138qS3gqXeYtvzDZ49bSFZDYM1AQsSVaUGckjSh7s6b+LxHkrJ/DJMyKC
         6JrMTldW87yjsf30G/wRfpdmGUX29TttpdPUsUsd7esG+26GhFRuS2n7DRTnQKhbNrPj
         ujj0ovdZ6o2Aw9fZUpmLVm8D17J+cEe2spRA1SlgU57D+wrSpva8I589m2huS0kSmOEi
         9qHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PDwnwUnZK2gWvBAW3kdYPoODws6H8TeUPh2+2+Ny5J9psr4rV
	YL3Ps0efhAT98rF3mFBVL7w=
X-Google-Smtp-Source: ABdhPJwKX+bDUtX82A5s66FdOCoFyfpXcLpz5LBDPqSqNeq1a2XG2WjCV9brNKU9Yhj1VVo6iYhDXA==
X-Received: by 2002:ab0:21d1:: with SMTP id u17mr2307018uan.85.1603475425594;
        Fri, 23 Oct 2020 10:50:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:45c9:: with SMTP id u67ls111801uau.4.gmail; Fri, 23 Oct
 2020 10:50:25 -0700 (PDT)
X-Received: by 2002:ab0:25c7:: with SMTP id y7mr2426463uan.137.1603475425021;
        Fri, 23 Oct 2020 10:50:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603475425; cv=none;
        d=google.com; s=arc-20160816;
        b=QncyIbFmj3NvRRFNR86FxJRa95D6PdzQsPFjzXDDJGjuhTAhK+N7i/wGlE/PUWVF4z
         sp5EaPBFvmzu6idba1d/4Io0lbT79ICov4kZWVEdu10B6a8oyDWi8JuwO/5DZW2/u1hh
         rsheNh3z3xMeTm7rzrRwEGUJzce4xwpntruXGAd81BrBXdmsDoSCHXM24goCsli56dsy
         wGvIj+JF1SoPt6lii7BPkKm6FYVdc+rf3r5OvZE865cpcGpWx7z7vwTh3+kxKtlBFooO
         tzmvq2o24R3IqgBl9oU36MxsaMfehAqXKrnWMXlQ3P+XziTf8nxKWU+4v48k2hh0ohGq
         eaHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VHLmS2i+xk5cy1+Hh+6vgNtXSGGSQNTTVydbxoIIvxM=;
        b=Ri4iD6ThoLlZvrQB5Aei0P5Xpa4+8jnAhWgzmMP12VTtTacCnb5J//518jxZxMcRf4
         6Ldk+kADO8mceTdbHw5ozCb5MP9w9zwgR3+ZHGOSqdzIDWUX6crHJiPfHBwKwPppb+GP
         gxyKQ+XLQxrrvLOtTapV+lGdUCrVi12G7G1Rv3sN7ab15aYQxk095U8EfuEsTgI6C9QU
         7hm0DSgGX945VcQUD9OrJHoMB8nn5QtfNjVtCAHna+G7uSkRi3F9wJE+uW4t2jIc7We7
         CHj/Xl9P6tBYYetHRlFqjJdrWKNcRF3eHiY0jTv17fcNGa1u0/RwMgBkYcFKdt8RcH40
         vNSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=zC+oRhFa;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-io1-xd44.google.com (mail-io1-xd44.google.com. [2607:f8b0:4864:20::d44])
        by gmr-mx.google.com with ESMTPS id b16si154866vkn.5.2020.10.23.10.50.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 10:50:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d44 as permitted sender) client-ip=2607:f8b0:4864:20::d44;
Received: by mail-io1-xd44.google.com with SMTP id y20so2826672iod.5
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 10:50:24 -0700 (PDT)
X-Received: by 2002:a02:a910:: with SMTP id n16mr2826341jam.35.1603475424367;
 Fri, 23 Oct 2020 10:50:24 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
 <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
 <20201023050214.GG23681@linux.intel.com> <356811ab-cb08-7685-ca01-fe58b5654953@rasmusvillemoes.dk>
 <CAHk-=whFb3wk0ff8jb3BCyoNvNJ1TSZxoYRKaAoW=Y43iQFNkw@mail.gmail.com> <CAHk-=whGbM1E0BbSVvxGRj5nBaNRXXD-oKcgrM40s4gvYV_C+w@mail.gmail.com>
In-Reply-To: <CAHk-=whGbM1E0BbSVvxGRj5nBaNRXXD-oKcgrM40s4gvYV_C+w@mail.gmail.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Fri, 23 Oct 2020 23:20:13 +0530
Message-ID: <CA+G9fYtR9p_OqYNT6=tKh=hsQDXC_1m1TgERPFH0ubuZGcg-DA@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Sean Christopherson <sean.j.christopherson@intel.com>, =?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, zenglg.jy@cn.fujitsu.com, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=zC+oRhFa;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, 23 Oct 2020 at 22:03, Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Fri, Oct 23, 2020 at 8:54 AM Linus Torvalds
> <torvalds@linux-foundation.org> wrote:
> >
> > On Fri, Oct 23, 2020 at 12:14 AM Rasmus Villemoes
> > <linux@rasmusvillemoes.dk> wrote:
> > >
> > > That's certainly garbage. Now, I don't know if it's a sufficient fix (or
> > > could break something else), but the obvious first step of rearranging
> > > so that the ptr argument is evaluated before the assignment to __val_pu
> >
> > Ack. We could do that.
> >
> > I'm more inclined to just bite the bullet and go back to the ugly
> > conditional on the size that I had hoped to avoid, but if that turns
> > out too ugly, mind signing off on your patch and I'll have that as a
> > fallback?
>
> Actually, looking at that code, and the fact that we've used the
> "register asm()" format forever for the get_user() side, I think your
> approach is the right one.
>
> I'd rename the internal ptr variable to "__ptr_pu", and make sure the
> assignments happen just before the asm call (with the __val_pu
> assignment being the final thing).
>
> lso, it needs to be
>
>         void __user *__ptr_pu;
>
> instead of
>
>         __typeof__(ptr) __ptr = (ptr);
>
> because "ptr" may actually be an array, and we need to have the usual
> C "array to pointer" conversions happen, rather than try to make
> __ptr_pu be an array too.
>
> So the patch would become something like the appended instead, but I'd
> still like your sign-off (and I'd put you as author of the fix).
>
> Narest, can you confirm that this patch fixes the issue for you?

This patch fixed the reported problem.

Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>

Build location:
https://builds.tuxbuild.com/uDAiW8jkN61oWoyxZDkEYA/

Test logs,
https://lkft.validation.linaro.org/scheduler/job/1868045#L1597

- Naresh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYtR9p_OqYNT6%3DtKh%3DhsQDXC_1m1TgERPFH0ubuZGcg-DA%40mail.gmail.com.
