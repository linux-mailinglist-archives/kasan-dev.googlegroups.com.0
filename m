Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3NZRL3AKGQEMLMFL6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E9C91D7B57
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 16:34:22 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id gk8sf971303pjb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 07:34:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589812461; cv=pass;
        d=google.com; s=arc-20160816;
        b=dnJtK+Hi5Yr5jWkWzsNtfCx3pdtNyO9gkGw/bmdJ7TfmGi1oAGNdnvYOyTmSwlgAHq
         LGJ21Agx4V8dgV6K/6nPDBDhqo4Y4wIBtCGAggEZEhTMedlI1dmgQCdsnY2LWhkVUwoO
         44Rzi5ETZCt8vo/Bzwr1h5dqSVxvvzBsDO63it3MjYb4OjIqnd5tot4zkLOocFYzDoCR
         Q40NbHuGTmZZiYB8j0Jb9/UtkKDkvBX3HLaoL/PkDUUtoal0REQ95fXO/71BzcxgeTo8
         KMWl+glEfHKkr2CdJqu7Bs17mjbVTcLpWIDgQ2wueZeezvNWOVFuDlMhM5zGLSFV0jv+
         K8NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bPaJBaEa+zOr1eU+nacINk8cAacmeJEyYImlCeePmm8=;
        b=BK040pTjQbe6/GGTWuCB8VZQ3GwrUPMuXehJMaIYToqVcS+ldvqwAoHc/N171K8/Ls
         4mHDs1FpFDWJep2AcpkIshXsDAo9bH8FEcz5MWBRvjMcCLGBL5echfCJ3dVKLNB4F8Ja
         d6kt/Uu0J4iYtPFyKd8Tp5hK+r0mrh99Lfi/dQOC9cXXFr7VDEkzlwHEvcMSr7v0E9Qf
         F0RZudfNNEIfI9/1k1Mct1P401r0Q6+0wIsObsUNzFAch1psh90r1SkG4dl3qwlVKJg5
         YkKXDrdVAjt4jskqscrJyGhyE/9DHghWZfRp5/Q4mrpyyPLD27/e6qDR92BXvBJ7/IFb
         1rEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hyxzuMqE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bPaJBaEa+zOr1eU+nacINk8cAacmeJEyYImlCeePmm8=;
        b=Noa3IA8EUbPC2Ov8ojaR7av8SLMMviWHibb0AgVmhDeAvZXd5nCTZkCJr5HQSqSZqo
         BT14FzyD1h3nkxB7yAZltYv5Dm1ILClQXpA7A21JO2CrcO6qtLgAk5/OKorV2FyhIEr9
         VAR4NP0wAybY6i0wNMyoARVS+t5zW3s+OcwdZivrxaGbg7hxMgVARNs82PHdGzOOmdmK
         8Sq+ZjazJfeWRikxEB0C0l4BtOAimOrZlevPgPvga9W9eflASnQWSLOnr+dsJlH5s2BA
         oWtM60QGbSymU3769lfkRVkpM9o13iZ0Sj7Xu1w1TFqBfEyrG/pbV0ZJC2kirKgfEA8+
         qI9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bPaJBaEa+zOr1eU+nacINk8cAacmeJEyYImlCeePmm8=;
        b=nRdUvHXJYJ4cqlxA+YX0GyD+vnMTzvdk0oRmnZmJ2Ye4KtG/+GsAEGbPzV9XGthAWn
         sp+xs4EH2Enw+7Bva6OG0QglQqIH5cPYeNqgRJ/q0oR5jTXxocm4DkcrMdqwuIes++Eq
         liuwvATltiK+o+ey3k7TywHLua9YDo2oQ2En6xsJ1xekrgUPGd8yziKZ4VdsQjSLlT1/
         G8buJ5zTXP1geiV5c1Dbpe1r48WMKoBsDVoEViJoUGsziitvv16qEI0BBOzXo0vlx2Ju
         4bgfSPWUwORsQ7gEukbpzS/IYIRqoRKV8hxmC5uK8o2BcIcSWIlW5zuBrdvalTIPtedi
         o0OQ==
X-Gm-Message-State: AOAM531BH04G2jjSSHA7rBx3Pj78UjRZVRtMAW8z3LDfC4NXIPs1LXzR
	Gs/ly4yoxBkJBtFsAcVBYcc=
X-Google-Smtp-Source: ABdhPJzn+K8AGue5FM+eYWHC6kBp/YCOCOke28lSnB4OCYuOxMFkT6ZRG1bPMDcM26cNQLxQAgm7JA==
X-Received: by 2002:a62:1d4c:: with SMTP id d73mr16693573pfd.226.1589812461253;
        Mon, 18 May 2020 07:34:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b702:: with SMTP id d2ls3462449pls.6.gmail; Mon, 18
 May 2020 07:34:20 -0700 (PDT)
X-Received: by 2002:a17:902:be08:: with SMTP id r8mr7385110pls.260.1589812460739;
        Mon, 18 May 2020 07:34:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589812460; cv=none;
        d=google.com; s=arc-20160816;
        b=EqNR0aLWykxNvDY9aXxdGGemU9QIvBKjZDVvSztQXRbXP8OQeG+B7Vjrw/jvTknbW6
         hK5zLleW+ZbUzN2oV8NY1bZXeGlHQetTuyoRll5ZDp88rJ+B6+j+Sz29SXn9BzSx8K0f
         DAeNrwy8rne/6LwZYfb8DyKihxPNzVEtbNyt57v9jyJkBb6RckczHQqsNncvmV8p77sB
         0S6kcZKBxCEM2RZeO7c9v7vTZeyYs8e2/InwiFNPwKfi0zzhOUXO60g/YJqGAceCj+kL
         DEBa5n55Di6byMuF8WDuzo4RDzprX2sP+xF0FoKg9uu3Gx/wJjwrq/+OOScylYIiqY65
         MwsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DCFSvoO5nHEFutdDZ7u001WboaSd8JW+ksXM71B70LQ=;
        b=Gk7WI+Av7EQKj/WEZLvQaexesVpcXrXWBI9XybvXkQrQbHy2eWFAEitoIae4NbgfTG
         J/k9plrVK7VLQdiknKSb/fsQK8aDw+V45HMmpuUJqJpMDDlqnxxHdfpkBIU2I4h8xz82
         pNt4s3jKBAL8v/WoiYNLvyGctpeIAA/1BoUXmZTQgzFe2zPRxmiTCLQMxKbOjJ9Yy58D
         nbDUsJGrmljisWqXoBtCZVu5xDuV2aB8TPR4anGS+R5B1JlFXZBqX4u+81C57BT89lJQ
         RG0lb6hJBgzFDadQl2aM76C6+cnlQw3mRyWUsY42Gsdc8/gaY8nKWT2CzNV7KC84+nPT
         sXiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hyxzuMqE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id g11si718289pgj.2.2020.05.18.07.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 May 2020 07:34:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id r1so2070043oog.7
        for <kasan-dev@googlegroups.com>; Mon, 18 May 2020 07:34:20 -0700 (PDT)
X-Received: by 2002:a4a:2809:: with SMTP id h9mr13202991ooa.36.1589812459734;
 Mon, 18 May 2020 07:34:19 -0700 (PDT)
MIME-Version: 1.0
References: <20200517011732.GE24705@shao2-debian> <20200517034739.GO2869@paulmck-ThinkPad-P72>
 <CANpmjNNj37=mgrZpzX7joAwnYk-GsuiE8oOm13r48FYAK0gSQw@mail.gmail.com> <CANpmjNMx0+=Cac=WvHuzKb2zJvgNVvVxjo_W1wYWztywxDKeCQ@mail.gmail.com>
In-Reply-To: <CANpmjNMx0+=Cac=WvHuzKb2zJvgNVvVxjo_W1wYWztywxDKeCQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 May 2020 16:34:07 +0200
Message-ID: <CANpmjNPcOHAE5d=gaD327HqxTBegf75qeN_pjoszahdk6_i5=Q@mail.gmail.com>
Subject: Re: [rcu] 2f08469563: BUG:kernel_reboot-without-warning_in_boot_stage
To: kan.liang@linux.intel.com, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Cc: kernel test robot <rong.a.chen@intel.com>, Peter Zijlstra <peterz@infradead.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	LKP <lkp@lists.01.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hyxzuMqE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Mon, 18 May 2020 at 14:44, Marco Elver <elver@google.com> wrote:
>
> [+Cc clang-built-linux FYI]
>
> On Mon, 18 May 2020 at 12:11, Marco Elver <elver@google.com> wrote:
> >
> > On Sun, 17 May 2020 at 05:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Sun, May 17, 2020 at 09:17:32AM +0800, kernel test robot wrote:
> > > > Greeting,
> > > >
> > > > FYI, we noticed the following commit (built with clang-11):
> > > >
> > > > commit: 2f08469563550d15cb08a60898d3549720600eee ("rcu: Mark rcu_state.ncpus to detect concurrent writes")
> > > > https://git.kernel.org/cgit/linux/kernel/git/paulmck/linux-rcu.git dev.2020.05.14c
> > > >
> > > > in testcase: boot
> > > >
> > > > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 8G
> > > >
> > > > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > > >
> > > >
> > > >
> > > >
> > > > If you fix the issue, kindly add following tag
> > > > Reported-by: kernel test robot <rong.a.chen@intel.com>
> > > >
> > > >
> > > > [    0.054943] BRK [0x05204000, 0x05204fff] PGTABLE
> > > > [    0.061181] BRK [0x05205000, 0x05205fff] PGTABLE
> > > > [    0.062403] BRK [0x05206000, 0x05206fff] PGTABLE
> > > > [    0.065200] RAMDISK: [mem 0x7a247000-0x7fffffff]
> > > > [    0.067344] ACPI: Early table checksum verification disabled
> > > > BUG: kernel reboot-without-warning in boot stage
> > >
> > > I am having some difficulty believing that this commit is at fault given
> > > that the .config does not list CONFIG_KCSAN=y, but CCing Marco Elver
> > > for his thoughts.  Especially given that I have never built with clang-11.
> > >
> > > But this does invoke ASSERT_EXCLUSIVE_WRITER() in early boot from
> > > rcu_init().  Might clang-11 have objections to early use of this macro?
> >
> > The macro is a noop without KCSAN. I think the bisection went wrong.
> >
> > I am able to reproduce a reboot-without-warning when building with
> > Clang 11 and the provided config. I did a bisect, starting with v5.6
> > (good), and found this:
> > - Since v5.6, first bad commit is
> > 20e2aa812620439d010a3f78ba4e05bc0b3e2861 (Merge tag
> > 'perf-urgent-2020-04-12' of
> > git://git.kernel.org/pub/scm/linux/kernel//git/tip/tip)
> > - The actual commit that introduced the problem is
> > 2b3b76b5ec67568da4bb475d3ce8a92ef494b5de (perf/x86/intel/uncore: Add
> > Ice Lake server uncore support) -- reverting it fixes the problem.

Some more clues:

1. I should have noticed that this uses CONFIG_KASAN=y.

2. Something about function icx_uncore_mmio_init(). Making it a noop
also makes the issue go away.

3. Leaving icx_uncore_mmio_init() a noop but removing the 'static'
from icx_mmio_uncores also presents the issue. So this seems to be
something about how/where icx_mmio_uncores is allocated.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPcOHAE5d%3DgaD327HqxTBegf75qeN_pjoszahdk6_i5%3DQ%40mail.gmail.com.
