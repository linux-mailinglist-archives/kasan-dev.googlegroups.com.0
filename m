Return-Path: <kasan-dev+bncBDN3ZEGJT4NBBAXIQ6NQMGQELHZ6K2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 76466615B86
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 05:37:24 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-131f323c158sf8312377fac.5
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 21:37:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667363843; cv=pass;
        d=google.com; s=arc-20160816;
        b=q2+lUNujePX8Il+1IlNS7r45/kwsoVQIxB/nHL0ayAGVkN3qF0ONBjn4GcRvWqk15j
         40zvZddrRiDNA3l8nXgRqE7UkpcmLqcvJAN3OlyHdRqoPUJQXyJXrjQ71Kh+0gkD/ZoE
         PrmnsIxviMwtpsbZFmaoDmoduc/RurweGXqwkJEaEIGhHNTWwmxxznZfc5YcNm/1WF0L
         T9qYpQTH6k9VrIxWZIpJSpIvaEaA2DiuJksKdkdiT0ScdyTh59rmVkAvu/8/HHGkcStf
         K1RVIInZgbrhakEIcjVArHZLioWfsfCk0swPswxhflSrHtUDLOYLGaexywD/WxLiKiKw
         pIQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1VhCXEe1ynOiWweFzJ9qOEQe1EWUJLd6zjEfPlsxVNw=;
        b=v4TCKtpODPuzPEe0igh1xGJF6Ryyz9dfrtKbBeFh7zvD4fMnd0aibcr2uVT+y0zEBd
         7VbJWog0Bdzh79xBiRRup22By20yg9ORlewA7yfeeOVxgeyH8NvuqbGNUF5O1v0Qt7fq
         2plrPzppZ/2uPnUXaKOI1/Z7/ZnSCEseWrgvJc06ZEI1j0hSv/YmuUzys63ju7tznbgV
         n5EVgufmjIVikxHQL41uKfFuLgnLnVV0gPECdJxcBGgucPJjjXtEdYtoVqyXpRuZnFg/
         jINWIWReGwM6hW/Rp9AnYJGV6RZ9x74Um6w8P+5uiMtjdKgKuHY58o5+EKY+mIyUEUib
         KveA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q0MGEOK+;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1VhCXEe1ynOiWweFzJ9qOEQe1EWUJLd6zjEfPlsxVNw=;
        b=hDap00lCJC9hD+w/tRD/4Mg1A50Cz2FQgr4lHUH/c8LedVBtNBDOHHvUR0UD1ZVhkC
         eRkXjGRcNAN9L9xKyFRLwW0ck7QOeRohruYVdXgk8lFrvmQ9L/OX+GZ1UBj3gaLy31x2
         yAaEuPApoo5k+KSUvOjqjp62uLBFrgrmUW+7VMS1TnW0gm7Co/G8XKsIGwiwEi+Ad2/D
         0egvbCvdQJ41sFAa9UbWtaCGugwj5nRzszXzreU1NRkmT8JV/5a7/u6o+fDzrgIn5C/R
         tUEN7F/U4tK1zQ9bzz80Uwl1TPQSuvyT/C/WxkDGR7C4xCF4PelL5XAvZ5vVtQbUOOXR
         ag5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1VhCXEe1ynOiWweFzJ9qOEQe1EWUJLd6zjEfPlsxVNw=;
        b=0gpRpwF/mz/B+lZRDgYeTz9Bbvdq4YH4eyY19fwRk4/8IOGDohFQLbmrDZbGQ9BJti
         kcQeRgkSZkaonzF/7U3W8LAxi68uUS7iuHeYdqTv8CnIqmmUG9jfHx0iHDZoXB631cob
         jP/yn5BhpPoL3YyNEEcliFCktooS4CU6UvDiku5BTmo66injr/UPhWSos1jLLSPLwfwk
         YfMPzdCWuJ2YlnL9LgyhRD8bNAYTidR829VeTcCzM2TO2tx0Uu+NAirrNikQwp6SAfQE
         nm23wfQK3AYUHUp2oNJuhPLzgYA8R9oVGCD4XHsiVg1dI60ygPlqLr8wUoFd5OLM5u0W
         VCsQ==
X-Gm-Message-State: ACrzQf1qsuDkGHihzv6ViNcWxZAzcXTzUurv4HsC0/N0sX6gw2mqGKUQ
	ThEB+0qFxfUKTn1u8ccqsAA=
X-Google-Smtp-Source: AMsMyM4bbZTNge7qPsiXz50xlvlJNY7zgd8qjFkpT2g6noOwQZXNwKXfPH3dOJKHDFHjBeLFvEQvew==
X-Received: by 2002:a05:6870:304e:b0:13c:787e:657d with SMTP id u14-20020a056870304e00b0013c787e657dmr16609118oau.108.1667363843152;
        Tue, 01 Nov 2022 21:37:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c7b1:b0:13a:e471:20c5 with SMTP id
 dy49-20020a056870c7b100b0013ae47120c5ls4893937oab.1.-pod-prod-gmail; Tue, 01
 Nov 2022 21:37:22 -0700 (PDT)
X-Received: by 2002:a05:6870:5b89:b0:132:1241:fb5f with SMTP id em9-20020a0568705b8900b001321241fb5fmr13370325oab.74.1667363842560;
        Tue, 01 Nov 2022 21:37:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667363842; cv=none;
        d=google.com; s=arc-20160816;
        b=nuTdoIi7L9otZ4CJM4m6LDLfsNsq8EUcHcxfMePs0yCtcS3POpIYMX2hUP6olSiyVh
         eQLgGra4UXOQGla3gkaH6o0Whl9jq8dQ2nXE5Y0NWOTTojDmEWMTGYAxQ1UTOsTUNZI0
         AjVuKagjUDXaGroJgfjduooAULO0Kq2YGz+IWCnu2y+kiXYu7XDxtFuQY48zArx3I0O2
         sOHedbh721jczeHm/9BjTrXXybxaN1SOash9lPdXHO62VxTtnISQutWq1DtExvpsQ0IR
         pL14H/489UZFx6nsiIDHfpQOW2PGsLyjOFz4bFeUWA5fVt2kNaAsLhUIWyxkU1d16o6S
         RreA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kl7jVJ5y1oJ5tW7Nuyev1s6MjsKIGw83WGsKI/onrLQ=;
        b=jJW31cnVwBF99rsldDD0rBgjBcqb1i1oav9DrUqVvuBw0ln2v9AG+3sBfVHAtqMQ2c
         oRzn4qyQZfQLfH8SA/Z2dMarjVYxvnrBaItb9ETUnG8AGZnl+hX7EwQgUXtsLknrLLL8
         xWmLuBjPr0Hi6UUy3LLK4ZLGIqSqzzxYGsMpLNSBzqeL0AFLgDiWNpW22zJu99VVmKI4
         TTeORPFryXzUD03o+eVVwqCSoeWe73EOIODcJA36XAiKrcr/dNW8snltKnJ+NQyyT7tP
         W9SU3NogSCQPiKeJlSFAJSTcGWLwA1xs4PyPCOcKZ5WFfpP6eNLD3p9Q1UGLAVmVjfsR
         7yHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q0MGEOK+;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id l3-20020a056830054300b0066c2e26ed88si712757otb.5.2022.11.01.21.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Nov 2022 21:37:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-367b8adf788so155733697b3.2
        for <kasan-dev@googlegroups.com>; Tue, 01 Nov 2022 21:37:22 -0700 (PDT)
X-Received: by 2002:a81:7585:0:b0:368:28bd:9932 with SMTP id
 q127-20020a817585000000b0036828bd9932mr20627557ywc.332.1667363841841; Tue, 01
 Nov 2022 21:37:21 -0700 (PDT)
MIME-Version: 1.0
References: <20221101040440.3637007-1-zhongbaisong@huawei.com>
 <eca17bfb-c75f-5db1-f194-5b00c2a0c6f2@iogearbox.net> <ca6253bd-dcf4-2625-bc41-4b9a7774d895@huawei.com>
 <20221101210542.724e3442@kernel.org> <202211012121.47D68D0@keescook>
In-Reply-To: <202211012121.47D68D0@keescook>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Nov 2022 21:37:10 -0700
Message-ID: <CANn89i+FVN95uvftTJteZgGQ_sSb6452XXZn0veNjHHKZ2yEFQ@mail.gmail.com>
Subject: Re: [PATCH -next] bpf, test_run: fix alignment problem in bpf_prog_test_run_skb()
To: Kees Cook <keescook@chromium.org>
Cc: Jakub Kicinski <kuba@kernel.org>, zhongbaisong <zhongbaisong@huawei.com>, 
	Daniel Borkmann <daniel@iogearbox.net>, davem@davemloft.net, pabeni@redhat.com, 
	linux-kernel@vger.kernel.org, bpf@vger.kernel.org, netdev@vger.kernel.org, 
	ast@kernel.org, song@kernel.org, yhs@fb.com, haoluo@google.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Linux MM <linux-mm@kvack.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Q0MGEOK+;       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::112e
 as permitted sender) smtp.mailfrom=edumazet@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Eric Dumazet <edumazet@google.com>
Reply-To: Eric Dumazet <edumazet@google.com>
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

On Tue, Nov 1, 2022 at 9:27 PM Kees Cook <keescook@chromium.org> wrote:
>
> On Tue, Nov 01, 2022 at 09:05:42PM -0700, Jakub Kicinski wrote:
> > On Wed, 2 Nov 2022 10:59:44 +0800 zhongbaisong wrote:
> > > On 2022/11/2 0:45, Daniel Borkmann wrote:
> > > > [ +kfence folks ]
> > >
> > > + cc: Alexander Potapenko, Marco Elver, Dmitry Vyukov
> > >
> > > Do you have any suggestions about this problem?
> >
> > + Kees who has been sending similar patches for drivers
> >
> > > > On 11/1/22 5:04 AM, Baisong Zhong wrote:
> > > >> Recently, we got a syzkaller problem because of aarch64
> > > >> alignment fault if KFENCE enabled.
> > > >>
> > > >> When the size from user bpf program is an odd number, like
> > > >> 399, 407, etc, it will cause skb shard info's alignment access,
> > > >> as seen below:
> > > >>
> > > >> BUG: KFENCE: use-after-free read in __skb_clone+0x23c/0x2a0
> > > >> net/core/skbuff.c:1032
> > > >>
> > > >> Use-after-free read at 0xffff6254fffac077 (in kfence-#213):
> > > >>   __lse_atomic_add arch/arm64/include/asm/atomic_lse.h:26 [inline]
> > > >>   arch_atomic_add arch/arm64/include/asm/atomic.h:28 [inline]
> > > >>   arch_atomic_inc include/linux/atomic-arch-fallback.h:270 [inline]
> > > >>   atomic_inc include/asm-generic/atomic-instrumented.h:241 [inline]
> > > >>   __skb_clone+0x23c/0x2a0 net/core/skbuff.c:1032
> > > >>   skb_clone+0xf4/0x214 net/core/skbuff.c:1481
> > > >>   ____bpf_clone_redirect net/core/filter.c:2433 [inline]
> > > >>   bpf_clone_redirect+0x78/0x1c0 net/core/filter.c:2420
> > > >>   bpf_prog_d3839dd9068ceb51+0x80/0x330
> > > >>   bpf_dispatcher_nop_func include/linux/bpf.h:728 [inline]
> > > >>   bpf_test_run+0x3c0/0x6c0 net/bpf/test_run.c:53
> > > >>   bpf_prog_test_run_skb+0x638/0xa7c net/bpf/test_run.c:594
> > > >>   bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
> > > >>   __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
> > > >>   __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
> > > >>
> > > >> kfence-#213: 0xffff6254fffac000-0xffff6254fffac196, size=407,
> > > >> cache=kmalloc-512
> > > >>
> > > >> allocated by task 15074 on cpu 0 at 1342.585390s:
> > > >>   kmalloc include/linux/slab.h:568 [inline]
> > > >>   kzalloc include/linux/slab.h:675 [inline]
> > > >>   bpf_test_init.isra.0+0xac/0x290 net/bpf/test_run.c:191
> > > >>   bpf_prog_test_run_skb+0x11c/0xa7c net/bpf/test_run.c:512
> > > >>   bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
> > > >>   __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
> > > >>   __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
> > > >>   __arm64_sys_bpf+0x50/0x60 kernel/bpf/syscall.c:4381
> > > >>
> > > >> To fix the problem, we round up allocations with kmalloc_size_roundup()
> > > >> so that build_skb()'s use of kize() is always alignment and no special
> > > >> handling of the memory is needed by KFENCE.
> > > >>
> > > >> Fixes: 1cf1cae963c2 ("bpf: introduce BPF_PROG_TEST_RUN command")
> > > >> Signed-off-by: Baisong Zhong <zhongbaisong@huawei.com>
> > > >> ---
> > > >>   net/bpf/test_run.c | 1 +
> > > >>   1 file changed, 1 insertion(+)
> > > >>
> > > >> diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
> > > >> index 13d578ce2a09..058b67108873 100644
> > > >> --- a/net/bpf/test_run.c
> > > >> +++ b/net/bpf/test_run.c
> > > >> @@ -774,6 +774,7 @@ static void *bpf_test_init(const union bpf_attr
> > > >> *kattr, u32 user_size,
> > > >>       if (user_size > size)
> > > >>           return ERR_PTR(-EMSGSIZE);
> > > >> +    size = kmalloc_size_roundup(size);
> > > >>       data = kzalloc(size + headroom + tailroom, GFP_USER);
> > > >
> > > > The fact that you need to do this roundup on call sites feels broken, no?
> > > > Was there some discussion / consensus that now all k*alloc() call sites
> > > > would need to be fixed up? Couldn't this be done transparently in k*alloc()
> > > > when KFENCE is enabled? I presume there may be lots of other such occasions
> > > > in the kernel where similar issue triggers, fixing up all call-sites feels
> > > > like ton of churn compared to api-internal, generic fix.
>
> I hope I answer this in more detail here:
> https://lore.kernel.org/lkml/202211010937.4631CB1B0E@keescook/
>
> The problem is that ksize() should never have existed in the first
> place. :P Every runtime bounds checker has tripped over it, and with
> the addition of the __alloc_size attribute, I had to start ripping
> ksize() out: it can't be used to pretend an allocation grew in size.
> Things need to either preallocate more or go through *realloc() like
> everything else. Luckily, ksize() is rare.
>
> FWIW, the above fix doesn't look correct to me -- I would expect this to
> be:
>
>         size_t alloc_size;
>         ...
>         alloc_size = kmalloc_size_roundup(size + headroom + tailroom);
>         data = kzalloc(alloc_size, GFP_USER);

Making sure the struct skb_shared_info is aligned to a cache line does
not need kmalloc_size_roundup().

What is needed is to adjust @size so that (@size + @headroom) is a
multiple of SMP_CACHE_BYTES

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANn89i%2BFVN95uvftTJteZgGQ_sSb6452XXZn0veNjHHKZ2yEFQ%40mail.gmail.com.
