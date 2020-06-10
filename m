Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBXFCQP3QKGQE5EN55KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 95F761F54B0
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 14:26:05 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id h10sf779051uao.4
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 05:26:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591791964; cv=pass;
        d=google.com; s=arc-20160816;
        b=hR0TWvXdG8k2svdtBMS0pwev9yRP4w7BnlsY3NB9vBdc98Yha6Mfg4zMRxkjErcgAI
         t6B83kmXLdQRFwutEI4IbEOki9v4t3Qco4iq9DqQxzlwdUG5q9aN9cXuKayAa5dkXHHR
         frFR5PFKGmVMRrw5qJRsr3pWAGdhDX2Hr0KuR7wSIrU8+3DglUZDfnN/C0yW/lE+WBKc
         7ulHajSV9q21U5YO7kjxrCgVqfGpK4oLQzp4F6ZEbZXuONR8+jPHwi9DCHOPSVjVKDNd
         c1vn2KZuqxlmvkO5UKq3rNpx/qA+/9p1Bkc/w9chvZYM7RRUByZ6jUhoNyGllo5tuHqX
         eqRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8buUP/Oj0Pv6a1K3OC7pKvMVZjt9nzG3tAGFUuOdzOA=;
        b=Dz8PFOdJyFd1mszeKaj0fgyfLquzqEP/yPZ1CsnLAxMyVJsCL0ZT2FrvomMuLivz27
         D1CNN28ytzYYGSfz4GyO0ISmPieKyY3rXvfy5L1ZRQvWuCb8kOapUY59aPijlsGYpXBf
         dIh0K7/Z6uUfUtKoQkFX0Df6kEeiX20YuPd0qLKb6C2k0bUGorRXbqhNwz5Uv9tpVjo7
         fwbYFJZjvcu5Q39lQ1equzzGFBPXiiZ54r9TEYbZgkQ6ykcO34aSYt+4kk0CT6sG630x
         EBYJIQhEi9XprnZgmO3S0ajVZQQ8SarTLANqxNZpoTXPyOd5YKNNT/yxDxgyQKhTjnqM
         HyLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=UwTLaOrW;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8buUP/Oj0Pv6a1K3OC7pKvMVZjt9nzG3tAGFUuOdzOA=;
        b=pAgH+WOPNwzkEkmLLgxCjWvWKsTGWBpMImclLSs7YuBFXv2tKt8sVZh4HO9EtPyKLD
         UP0STqajBP7WS06pNCNDBFxYnKQJI2lKObMKyGaVlIRxCQa0ekenDYsQkG90hQkvH44O
         x68/p9x8KWBoPLFwo6gr6XEjE18KfAjGDkjg93y1D7hsuYNhGhgNlyYNNbGU1pFgoMUT
         CtQcb1F/jxhA+JBlPB4N2J4s/gdlV6jKq3iO0NfkJGXWHkJu57K+GfiMWDvFQxKZTFS7
         n2Fyc+cx+GdNP3UR11SMkisJlQzU7GQWspFSt2+MPKDFEtGs1Y1nWAjaoAsWj1JuK0w3
         QoWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8buUP/Oj0Pv6a1K3OC7pKvMVZjt9nzG3tAGFUuOdzOA=;
        b=BmLY4OR+8fWtxSNXRZ/yWMG/UYaHUhd+ngjl+J+Vd9n+h3n/lho2Y6ZCsY8ci1QIZr
         /hih2XJe8VSLPwU669mvz+YRWIOQqKaBKGhXxBWTCWu+GqFRCHssMJhK9zF1CwYWsE5x
         N7xoVDvv9mMcjfPkl3JZmH1jSWv/UMAvpaHRY20pjOPtDK16MIYoe8XXX3vEFd+z/GNp
         c/8BYk58mdCAUiAUl1T/06AwpDJ/XGxtxKqRxOmou6H8I34kvnhkoV2axpd+mhdrkQmW
         9h5C9/NVqRVeiB1zCt1gOgzrq/gjMnAAcFtW8eYtWK2OPHLmxtt9Yl0fON/p3m4Lk89r
         aJcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531z2R+PrVbasNO+6UasyOAUmnnQIKPU/mdDnski2RLbZE1Ny4bC
	xHs7rjAHIQ4ZaJ2dzPu1GMY=
X-Google-Smtp-Source: ABdhPJzeADHC9enGde/2D5yd9sU4dC4acF9MjX4G9qdQ8HAGlxIgtSeE2MZ/4ybwadQ1EgYluVr8AA==
X-Received: by 2002:a67:db90:: with SMTP id f16mr2076166vsk.132.1591791964555;
        Wed, 10 Jun 2020 05:26:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7d8e:: with SMTP id y136ls2120323vsc.7.gmail; Wed, 10
 Jun 2020 05:26:04 -0700 (PDT)
X-Received: by 2002:a67:7c94:: with SMTP id x142mr2215231vsc.192.1591791964153;
        Wed, 10 Jun 2020 05:26:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591791964; cv=none;
        d=google.com; s=arc-20160816;
        b=ufNAdqyISNvDS2y/S13Ix8rLlFB3ah7yCEGMuopLn+V1l60l+yNzDEpX6UUKWiQzeM
         cwdVdkfLylkm7dy7Ao3yH8ZrOY9rVzt0E9r9YNhLqcMcNuH5Eg2FCjIR3FhvSL+F0fTt
         PCebWe7Qf1weDu1VR/XA9rwh5u9/3iNBuT9dJfo6j++MR5yiwwxKznYUzUuTNDl5j5Fz
         +MO72PlMi/MQS2wuPX5nWDkkbyZX/a3TG+K9ZT+UXbC+fwcAQra0WMy5dfPzzHWnIjJs
         M8KIy11TAuj8Ttkg28Uox1QbyTBkYGMhH1x2PPfHntqoqKNHwY8aBrfsyQXez+qSQ9+7
         Q7PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xNoh9u1q9fbWqVtSlCDwrQ/3B0eRAU+tf8g5idD9RH8=;
        b=mdAwv9E9gaiRU/mNbcFcaf73Ci4Eo8z4IVL664xVY9GVeOUw8U/oWV5t7Z7jaz1unx
         8rntNLR97FFtfNdAussso2pORXgeSePXCOztWyqDmlh/i3Y3JjJ50uQWMfHuYbWHQoZr
         RS7i7YtBpDHY/LFL3+bBfAuu+7UwJqEUDhESAJg/svUEffOD49FtsvXUjC0Q42aznwpv
         I4zPqEPJT6xQBFC64h/At5dR0DFaK/7Dc+Fh3GkZy022E9oSyusi6lymRXysYko0Eq5r
         mZYKFKgHr3kVRvswJVa3TamU0jLqBQHdIcYQlmiQzOA584G3UjNQhxaICR+sAS1IDD0Y
         WHug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=UwTLaOrW;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id t24si264919uaq.0.2020.06.10.05.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Jun 2020 05:26:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id c14so1721562qka.11
        for <kasan-dev@googlegroups.com>; Wed, 10 Jun 2020 05:26:04 -0700 (PDT)
X-Received: by 2002:a37:7d45:: with SMTP id y66mr2582137qkc.484.1591791963659;
        Wed, 10 Jun 2020 05:26:03 -0700 (PDT)
Received: from lca.pw (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id y54sm13368128qtj.28.2020.06.10.05.26.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Jun 2020 05:26:02 -0700 (PDT)
Date: Wed, 10 Jun 2020 08:26:00 -0400
From: Qian Cai <cai@lca.pw>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Christian Borntraeger <borntraeger@de.ibm.com>,
	Alexander Potapenko <glider@google.com>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>,
	linux-s390 <linux-s390@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Heiko Carstens <heiko.carstens@de.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>
Subject: Re: [PATCH] mm/page_alloc: silence a KASAN false positive
Message-ID: <20200610122600.GB954@lca.pw>
References: <20200610052154.5180-1-cai@lca.pw>
 <CACT4Y+Ze=cddKcU_bYf4L=GaHuJRUjY=AdFFpM7aKy2+aZrmyQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Ze=cddKcU_bYf4L=GaHuJRUjY=AdFFpM7aKy2+aZrmyQ@mail.gmail.com>
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=UwTLaOrW;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Wed, Jun 10, 2020 at 07:54:50AM +0200, Dmitry Vyukov wrote:
> On Wed, Jun 10, 2020 at 7:22 AM Qian Cai <cai@lca.pw> wrote:
> >
> > kernel_init_free_pages() will use memset() on s390 to clear all pages
> > from kmalloc_order() which will override KASAN redzones because a
> > redzone was setup from the end of the allocation size to the end of the
> > last page. Silence it by not reporting it there. An example of the
> > report is,
> 
> Interesting. The reason why we did not hit it on x86_64 is because
> clear_page is implemented in asm (arch/x86/lib/clear_page_64.S) and
> thus is not instrumented. Arm64 probably does the same. However, on
> s390 clear_page is defined to memset.
> clear_[high]page are pretty extensively used in the kernel.
> We can either do this, or make clear_page non instrumented on s390 as
> well to match the existing implicit assumption. The benefit of the
> current approach is that we can find some real use-after-free's and
> maybe out-of-bounds on clear_page. The downside is that we may need
> more of these annotations. Thoughts?

Since we had already done the same thing in poison_page(), I suppose we
could do the same here. Also, clear_page() has been used in many places
on s390, and it is not clear to me if those are all safe like this.

There might be more annotations required, so it probably up to s390
maintainers (CC'ed) if they prefer not instrumenting clear_page() like
other arches.

> 
> >  BUG: KASAN: slab-out-of-bounds in __free_pages_ok
> >  Write of size 4096 at addr 000000014beaa000
> >  Call Trace:
> >  show_stack+0x152/0x210
> >  dump_stack+0x1f8/0x248
> >  print_address_description.isra.13+0x5e/0x4d0
> >  kasan_report+0x130/0x178
> >  check_memory_region+0x190/0x218
> >  memset+0x34/0x60
> >  __free_pages_ok+0x894/0x12f0
> >  kfree+0x4f2/0x5e0
> >  unpack_to_rootfs+0x60e/0x650
> >  populate_rootfs+0x56/0x358
> >  do_one_initcall+0x1f4/0xa20
> >  kernel_init_freeable+0x758/0x7e8
> >  kernel_init+0x1c/0x170
> >  ret_from_fork+0x24/0x28
> >  Memory state around the buggy address:
> >  000000014bea9f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >  000000014bea9f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > >000000014beaa000: 03 fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> >                     ^
> >  000000014beaa080: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> >  000000014beaa100: fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> >
> > Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
> > Signed-off-by: Qian Cai <cai@lca.pw>
> > ---
> >  mm/page_alloc.c | 3 +++
> >  1 file changed, 3 insertions(+)
> >
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index 727751219003..9954973f89a3 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -1164,8 +1164,11 @@ static void kernel_init_free_pages(struct page *page, int numpages)
> >  {
> >         int i;
> >
> > +       /* s390's use of memset() could override KASAN redzones. */
> > +       kasan_disable_current();
> >         for (i = 0; i < numpages; i++)
> >                 clear_highpage(page + i);
> > +       kasan_enable_current();
> >  }
> >
> >  static __always_inline bool free_pages_prepare(struct page *page,
> > --
> > 2.21.0 (Apple Git-122.2)
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200610122600.GB954%40lca.pw.
