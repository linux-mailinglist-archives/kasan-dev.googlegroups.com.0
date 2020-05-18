Return-Path: <kasan-dev+bncBDYJPJO25UGBBIEVRP3AKGQEBSPRVBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 140D71D8194
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 19:49:22 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id 68sf4896262vkx.22
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 10:49:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589824161; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZkKHXetH7Tf5fZc7hjIjwPXjrSlTK2tFnRRqGECPU6mNB2Kfl7CtCZV0dOj2Dr7FfO
         mawWJ2fMMVpzqM3eCfTWUBzMKL2KKdfgA+DtVSy/zKm0RYgygT6Lyz1IsM/+vX5qNE4L
         jW0ia5GB24dl9GE8Wi/ztJ0MBdpwgX1CDcQB8Q93oVsawjf43XBCW1JjAeL8j41A77r7
         P662UJSKRGkK67jx0q8SJvykXjxV18xMobgsrTPkcYoMP3CMKmUoogKaVKko+fpsaGW+
         zM7tN6S/CGHqyUZY+5qUwXFagCOKFiebpZEiArhK4CQgMN918ofosJu+vl8deQrotq36
         g5Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YLRijoUgaQ4Sd2b7RsxULOXdiWdMaSY1tpZdBQk+lNc=;
        b=cfl7LuttbvH0RtHNBFJ1yvbYEBxQhi5+NvACI2M2xjlB7H7PkIq6Rf/jTHVzozbppg
         UDHpWhkk7wL1I9qIM/7VueN5h2h0SwhY5ccL7FtqhkPQTv1l1YuGY002xslr4I4g32jv
         a8UuIjfCAD9AFEnhr9xax0hVDiMGLauWfaFQXHhmrKhk3/rf/+2IkvwNzqHu4/ktVLFe
         zIGTd1obYdllboKDyLytvUx3cL63ghYdkOeclxCMHbogu+uxzxFWLRsjzpUnhi+Snxx7
         C0qS0qdDd3ZA8DyI+q35V/5JuhOUZzb2wN1yHZXzlwDIu5Zi8y7NvEaRrWRNEjaw5TKE
         QdjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VZ/6zRNA";
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YLRijoUgaQ4Sd2b7RsxULOXdiWdMaSY1tpZdBQk+lNc=;
        b=UXkDs6JgYSM0MZ5TOdXzF8JJNWgbFLIsRwnmVQ0qSK3LCTJYpTPnITA0PRAMmkejq9
         RAr4r+Y84Rvfgr75tk8kODuVcCmN3fpuWyrBZGQio2JeNSl1GIw7fQiy66qvYzqhYhVZ
         xSV8BWMR9RjsmHFGv44ndF/oHpCkack0mR/UZpwWwKBXL7ij+iZpd0uNjQbZU5CyMLu2
         39EbL2w4gr34OCTLRixgtOAPUgM6K/CTtGHRRNY66OJ9n9BWmgxa/gFEy2lqlBAk/nUf
         Bihi0XEmMbz+K1yUGeetMKFvSqj+PfVU8iPuiqhTfGh8IfE0eLldhK9LYwK7cLFbji85
         88wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YLRijoUgaQ4Sd2b7RsxULOXdiWdMaSY1tpZdBQk+lNc=;
        b=T3okB7kb6uwivvDdcIM/ksLDF8nER70mF1B331MYEfIqeTq6y7vZYZMXh2EcaUJSsw
         NSRYHxlFzattgH428Oze4hryGgbExpOmiS+5PNIspy4s3SXk2tMLk9C5+zOIRvrpKZjH
         JmM1LPbgq7eZjrkrrUcrwYguYUjCmfaPxXyggSjqvPJ0K9py2161Bj7QS0anDOokaAwf
         ntkfikGgl4mSHk3HFKew+rTgaCGOB3d5GMmhE8YzBsSvxshtzqbOE0RszflzoSzqeHNV
         2/9xP7EDxvhLdI7/5w996Au9ygN2D1YkHKJcbkJY8OD0Hx96qXCZt55VmUCi/RBglTPo
         ttyg==
X-Gm-Message-State: AOAM531wjUrmWA31s/ZXai+91nwYzdGIsY2gxoY8BZ/IqOXlAittDg5F
	/ffw27hWiVLcVnr70eABvkM=
X-Google-Smtp-Source: ABdhPJynldkrBBtnoQfGZOHWg7ZqFBfwDsJ2EOfCh0KloEn4IevJNmjQiuQOIOS0yV3iVnzLKjm4YQ==
X-Received: by 2002:a67:342:: with SMTP id 63mr11200857vsd.11.1589824160902;
        Mon, 18 May 2020 10:49:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:af0e:: with SMTP id v14ls1103536vsl.7.gmail; Mon, 18 May
 2020 10:49:20 -0700 (PDT)
X-Received: by 2002:a67:8d0a:: with SMTP id p10mr12902313vsd.45.1589824160567;
        Mon, 18 May 2020 10:49:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589824160; cv=none;
        d=google.com; s=arc-20160816;
        b=bzzZKDrLtnQmPWMo1tlofcl5IHo8YNnptycLjDkaEkz9wSKL+Cl03IypHwCISwzccY
         o0u9fz5O9NUIYmGyKPPqu5PULRcD64nicC0A9sif+vNkD1RlqR2iAStnpMaQtv3Vwzhl
         EagYYem5QfQObDvOS2RSOqdsp3LmOLsGwsUS6kIUWgKoY8E0YBHRsoWJlDBrEC5oUzMt
         LgaaRnUdPhCGrzqB9tR9m7dvy6lR5hZjPKZFB4+pUEagR46342LFLYxjT9wDJsK5MVZt
         ZALZuCZS6l7aQw9oqNFLqcmCijDGdHgqK8CgMaGdPKNLWBj/Ui7H79XWhpvPri8yHRoV
         3qjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mBq4CNh2SzaiNVBNhEkzgkxU7yRKv+pxY1QX3ny6bNo=;
        b=RSF6m+mQGLVNG7cFTwbnJ7p2Uahj3EEKOo/mhW4WBhgoVzctv4kL+GmKAdP13quKvk
         /tK9GZyTjg+h6qcgmEMtGaUlvmgjM1rY1wCO6+/qdehljOqlaB5uAYreqSkVANCSLywg
         PSjmxV3cbWL/uFBCgdtlii7ZaBfGDTys+BRfXAYJNf63JCW5K7oUmgK24/cc8FsM8u36
         sVMZToM/oGE/X9OM/D31EBxgxf9hK/frNcE0TuyM1zZofKQoaCIbUaOoB+gOeQU74Uxw
         +zmtgAm3SbYc5FYfQHqU+nhqTzVVjU+Th5yHsmNhcU2YBH1E8T6272p9wRHGhW4LVg3/
         5//w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VZ/6zRNA";
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id a65si691550vki.2.2020.05.18.10.49.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 May 2020 10:49:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id n11so5163545pgl.9
        for <kasan-dev@googlegroups.com>; Mon, 18 May 2020 10:49:20 -0700 (PDT)
X-Received: by 2002:a63:d010:: with SMTP id z16mr5906980pgf.381.1589824159213;
 Mon, 18 May 2020 10:49:19 -0700 (PDT)
MIME-Version: 1.0
References: <20200517011732.GE24705@shao2-debian> <20200517034739.GO2869@paulmck-ThinkPad-P72>
 <CANpmjNNj37=mgrZpzX7joAwnYk-GsuiE8oOm13r48FYAK0gSQw@mail.gmail.com>
 <CANpmjNMx0+=Cac=WvHuzKb2zJvgNVvVxjo_W1wYWztywxDKeCQ@mail.gmail.com> <CANpmjNPcOHAE5d=gaD327HqxTBegf75qeN_pjoszahdk6_i5=Q@mail.gmail.com>
In-Reply-To: <CANpmjNPcOHAE5d=gaD327HqxTBegf75qeN_pjoszahdk6_i5=Q@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 May 2020 10:49:08 -0700
Message-ID: <CAKwvOd=Gi2z_NjRfpTigCCcV5kUWU7Bm7h1eHLeQ6DZCmrsR8w@mail.gmail.com>
Subject: Re: [rcu] 2f08469563: BUG:kernel_reboot-without-warning_in_boot_stage
To: Marco Elver <elver@google.com>
Cc: Kan Liang <kan.liang@linux.intel.com>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel test robot <rong.a.chen@intel.com>, Peter Zijlstra <peterz@infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, LKP <lkp@lists.01.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="VZ/6zRNA";       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Mon, May 18, 2020 at 7:34 AM Marco Elver <elver@google.com> wrote:
>
> On Mon, 18 May 2020 at 14:44, Marco Elver <elver@google.com> wrote:
> >
> > [+Cc clang-built-linux FYI]
> >
> > On Mon, 18 May 2020 at 12:11, Marco Elver <elver@google.com> wrote:
> > >
> > > On Sun, 17 May 2020 at 05:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > On Sun, May 17, 2020 at 09:17:32AM +0800, kernel test robot wrote:
> > > > > Greeting,
> > > > >
> > > > > FYI, we noticed the following commit (built with clang-11):
> > > > >
> > > > > commit: 2f08469563550d15cb08a60898d3549720600eee ("rcu: Mark rcu_state.ncpus to detect concurrent writes")
> > > > > https://git.kernel.org/cgit/linux/kernel/git/paulmck/linux-rcu.git dev.2020.05.14c
> > > > >
> > > > > in testcase: boot
> > > > >
> > > > > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 8G
> > > > >
> > > > > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > > > >
> > > > >
> > > > >
> > > > >
> > > > > If you fix the issue, kindly add following tag
> > > > > Reported-by: kernel test robot <rong.a.chen@intel.com>
> > > > >
> > > > >
> > > > > [    0.054943] BRK [0x05204000, 0x05204fff] PGTABLE
> > > > > [    0.061181] BRK [0x05205000, 0x05205fff] PGTABLE
> > > > > [    0.062403] BRK [0x05206000, 0x05206fff] PGTABLE
> > > > > [    0.065200] RAMDISK: [mem 0x7a247000-0x7fffffff]
> > > > > [    0.067344] ACPI: Early table checksum verification disabled
> > > > > BUG: kernel reboot-without-warning in boot stage
> > > >
> > > > I am having some difficulty believing that this commit is at fault given
> > > > that the .config does not list CONFIG_KCSAN=y, but CCing Marco Elver
> > > > for his thoughts.  Especially given that I have never built with clang-11.
> > > >
> > > > But this does invoke ASSERT_EXCLUSIVE_WRITER() in early boot from
> > > > rcu_init().  Might clang-11 have objections to early use of this macro?
> > >
> > > The macro is a noop without KCSAN. I think the bisection went wrong.
> > >
> > > I am able to reproduce a reboot-without-warning when building with
> > > Clang 11 and the provided config. I did a bisect, starting with v5.6
> > > (good), and found this:
> > > - Since v5.6, first bad commit is
> > > 20e2aa812620439d010a3f78ba4e05bc0b3e2861 (Merge tag
> > > 'perf-urgent-2020-04-12' of
> > > git://git.kernel.org/pub/scm/linux/kernel//git/tip/tip)
> > > - The actual commit that introduced the problem is
> > > 2b3b76b5ec67568da4bb475d3ce8a92ef494b5de (perf/x86/intel/uncore: Add
> > > Ice Lake server uncore support) -- reverting it fixes the problem.
>
> Some more clues:
>
> 1. I should have noticed that this uses CONFIG_KASAN=y.

Thanks for the report, testing, and bisection.  I don't see any
smoking gun in the code.
https://godbolt.org/z/qbK26r

>
> 2. Something about function icx_uncore_mmio_init(). Making it a noop
> also makes the issue go away.
>
> 3. Leaving icx_uncore_mmio_init() a noop but removing the 'static'
> from icx_mmio_uncores also presents the issue. So this seems to be
> something about how/where icx_mmio_uncores is allocated.

Can you share the disassembly of icx_uncore_mmio_init() in the given
configuration?
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3DGi2z_NjRfpTigCCcV5kUWU7Bm7h1eHLeQ6DZCmrsR8w%40mail.gmail.com.
