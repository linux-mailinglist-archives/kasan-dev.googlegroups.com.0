Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSG6UD4QKGQEAXVQWEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CC7C023A980
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Aug 2020 17:37:45 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e4sf14001837ilr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Aug 2020 08:37:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596469064; cv=pass;
        d=google.com; s=arc-20160816;
        b=wj9vUXdKfdl8lfh6EnwIhLoy/0QlEsWMGWVu6YaJFtdJJK37GIJUzihPWy4TWO9RcC
         ht4GvyMtFpMz+xySpVhS2JZVJ0LYN2ZjXSTSRt8VsTHVAONjjABU+JHNQRdhR/pqYPGZ
         1oqOgVfMgNFsvuGCl8Oh9ElDNJogmhpamq5mm4cWcjXhUL/cOxXCZmV8anpqQZBL54yz
         xtg2gDKcpcyJo+6yfMy9KG5n7DXiXnQI9a4EVeFyMk3BSrmdXmESXe5GJKfH4NsqQiYi
         Z21FNiluSB3HhwHNtDxxMF03EfMrFUMenXc4Nw9KJF1aDZGzbHbbDtLilGBaq9BZGsBJ
         cRvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+dVY78ZwKQ/J0gylD6AyZeLL6clvP/UiQEZ20MLhukE=;
        b=W9qRoU2f2PkD+wIfdGc4jA/IU2T3C6GOm/vVfRCQO5dZeW/C73XelqIhSNnJakeYlQ
         +q+oK/d3DTG0mYBgLEjQzrTWNF/dIBJnUE6tddjgCNaijO3kVg4OH7cdPXF3tGNgqqzZ
         S3/V34JKjexYOfhIC/U40n1yroCCnk4qr6sTTNan4OKzonlbU2F3jLvZq/OCnzJFbmE0
         A0Zc6uFtaZKSMASSRPFFObd8uWMSG1I0F5Rgtus3nPS+3IK//0coq8wdDYneM4S/3NzZ
         mHqV8UvxnmwNINQp1bJbpQH8J2Y0RUqEPG7lPAzELZ+mKhk+fiKfo/3/frK8hdQ8Fn47
         g+PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W7lLcF0H;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+dVY78ZwKQ/J0gylD6AyZeLL6clvP/UiQEZ20MLhukE=;
        b=GBXF81oLPJsBZvdYUIFIoajPGPfObWgSI4nor6iYPE8j0vtbkeK1ds8y38WqVhHkHt
         Kp8etUpV2WgBloPp8jz/RbmVYCbJx4zcvx0ixonIF7clXmFMD6dc2ccg0j0ibWjpSf5/
         3FwWgCIh6cC0UFIXw6IE4t7kSVF8/W2feOHcxqeaE0QtUNICyMLXo2jbosrE10QiWu7K
         mXfSKMgUkWzS7phkYobBwwavCnBr+FfZvh3fIOI/m6Kj7kldkzwrD6FZua53BvmaqXpu
         bXC97fvnvBmp+C4X4lt5y1tHY0SxEkKsd9mhu8JST67tBJ0ZPiSO/UgSMo9VQZkeLSnn
         a10Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+dVY78ZwKQ/J0gylD6AyZeLL6clvP/UiQEZ20MLhukE=;
        b=ZIBw2XiCCV0HZzKoph8jf6hGAWi+SOppb+6PMO7uI++oQXwqEN1yIjxQAetEAbQpBu
         4B/bw+7fl6c9TwM4KPgvZdS47YJnDM1PNI2K0nmYENv5yN663+SrIrYvTURTPPUaat9r
         H6u6P1s4+n/nu7QDlrQ9HBVQu7zweH7FDftw70gctFO15bfYSkDRCRRbvEtRySpvF3PL
         4jqVolMfImYuI3eMcTscLKloRQkJWXMEp9gIqKG87nao+ugVsdg82/t5WRJnBt3ilRBk
         xAybGrY47uTbd3zOhFzX69DaswOKDKTQK7wzW2/hssE8VApEwwQbhSjSOtboFBLWUrtO
         Y4fA==
X-Gm-Message-State: AOAM533Ma8V+dJSccXCULKsO9mD2KcwhYZRVhsdurF1V3mvyFZJuJpW9
	PFDODQXpGXXbaJlmV00CBWA=
X-Google-Smtp-Source: ABdhPJwSy1X4QU1xrsBd7DY11hXL1okwrmpYUJxTr2n8vXAVMJFHTbUgpfO53RnmNOHHRw0wo2YKOg==
X-Received: by 2002:a05:6e02:54e:: with SMTP id i14mr6439094ils.33.1596469064495;
        Mon, 03 Aug 2020 08:37:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d34c:: with SMTP id a12ls3806400ilh.5.gmail; Mon, 03 Aug
 2020 08:37:44 -0700 (PDT)
X-Received: by 2002:a92:9a84:: with SMTP id c4mr18213481ill.1.1596469064094;
        Mon, 03 Aug 2020 08:37:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596469064; cv=none;
        d=google.com; s=arc-20160816;
        b=lCFsW36D4I/OI21nNkBinvCzfbpcc8VCebIidai1E1B6YbesWc3OrRtwCGU2SRjZiJ
         2fryoEokuPhqZweTPTWvW5TPFXLabLuLvS7xGoTLa1pYDzCes+6ChC/PBnIMZsuJKK4Q
         b/bC6JcL8nylgraEfOvq0tPMIB0aNoXKUAcsbOwNs76WmZgOxTrRE52zzV/XZDpYehL0
         xwy8R5DPjuKJ2a9hEMew24WmzAaXmvmqmUY1RspJH188E/nP+qbgn6D3qctaDQ+tBGGc
         /vOD4uCjq8cadlogooOzeFQsGXmX5jKpRGvxY/HNqxEmVUN5ikX+s0Z0QfmHntmPBRS8
         zCKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UmX7pB6yi6itJGZjNe/1neOiyvbDkoAdg0wCqdj9cMU=;
        b=TvDoRwsrwHgRrD0GEg3nUwn7pI5+doOhPB/MFQAEFHS7GhIYInXLQcGWhmNO/XL2Qq
         rTqxhErFWJb9hSC/jBD8vQkIILPNciZHiA0oOeHI1kaIdjs1II7u3IG/dYQEAw3iiCqq
         QRSxZQGfSd79DIMfyPUIDY0u9s+lyMUblMPAgK60xSOABX29MC3hjzFTE1dISiU9BES/
         5yMs2I75iyqa/dC1yr8VZNqmUhw3Hb3oOZdMXGBSlR/HfpjxH7NViWxvKIxji/0cDW0E
         78cfs7D036HdiNecIAkmY+GMIaPLOrlzCEMoFeTDPaUWDp/trilrXOyKultkvVgV47Rz
         zYDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W7lLcF0H;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id t6si945407ioi.1.2020.08.03.08.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Aug 2020 08:37:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id g19so8288556plq.0
        for <kasan-dev@googlegroups.com>; Mon, 03 Aug 2020 08:37:44 -0700 (PDT)
X-Received: by 2002:a17:902:904c:: with SMTP id w12mr15912972plz.147.1596469063049;
 Mon, 03 Aug 2020 08:37:43 -0700 (PDT)
MIME-Version: 1.0
References: <202008020649.TJ8Zu7ei%lkp@intel.com>
In-Reply-To: <202008020649.TJ8Zu7ei%lkp@intel.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Aug 2020 17:37:32 +0200
Message-ID: <CAAeHK+zbBF0YVveGNZo0bJ8fWHVZRcrr6n90eYLDCov2vcfZyg@mail.gmail.com>
Subject: Re: [hnaz-linux-mm:master 168/421] init/main.c:1012: undefined
 reference to `efi_enter_virtual_mode'
To: Ard Biesheuvel <ardb@kernel.org>, linux-efi@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: kbuild-all@lists.01.org, Johannes Weiner <hannes@cmpxchg.org>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W7lLcF0H;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642
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

On Sun, Aug 2, 2020 at 12:25 AM kernel test robot <lkp@intel.com> wrote:
>
> tree:   https://github.com/hnaz/linux-mm master
> head:   2932a9e66c580f3c8d95ec27716d437198fb4c94
> commit: 7c0265f304de3c3acd02d0015b56a076357bcce3 [168/421] kasan, arm64: don't instrument functions that enable kasan
> config: x86_64-randconfig-r036-20200802 (attached as .config)
> compiler: gcc-9 (Debian 9.3.0-14) 9.3.0
> reproduce (this is a W=1 build):
>         git checkout 7c0265f304de3c3acd02d0015b56a076357bcce3
>         # save the attached .config to linux build tree
>         make W=1 ARCH=x86_64
>
> If you fix the issue, kindly add following tag as appropriate
> Reported-by: kernel test robot <lkp@intel.com>
>
> All errors (new ones prefixed by >>):
>
>    ld: init/main.o: in function `start_kernel':
> >> init/main.c:1012: undefined reference to `efi_enter_virtual_mode'

Hm, I can reproduce the issue, but I don't understand why it happens.

+EFI and KASAN people, maybe someone has an idea.

This is the guilty patch:

https://github.com/hnaz/linux-mm/commit/7c0265f304de3c3acd02d0015b56a076357bcce3

The issue is only with efi_enter_virtual_mode() AFAIU, not with any of
the other functions.

Thanks!


>
> vim +1012 init/main.c
>
> 53c99bd665a2649 Martin Schwidefsky       2018-08-31   829
> 7c0265f304de3c3 Andrey Konovalov         2020-08-01   830  asmlinkage __visible __no_sanitize_address void __init start_kernel(void)
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   831  {
> dd4d9fecbeba893 Fabian Frederick         2014-08-08   832       char *command_line;
> dd4d9fecbeba893 Fabian Frederick         2014-08-08   833       char *after_dashes;
> 033ab7f8e5c655f Andrew Morton            2006-06-30   834
> d4311ff1a8da48d Aaron Tomlin             2014-09-12   835       set_task_stack_end_magic(&init_task);
> 73839c5b2eacc15 Ming Lei                 2011-11-17   836       smp_setup_processor_id();
> 3ac7fe5a4aab409 Thomas Gleixner          2008-04-30   837       debug_objects_early_init();
> 420594296838fdc Ingo Molnar              2008-02-14   838
> ddbcc7e8e50aefe Paul Menage              2007-10-18   839       cgroup_init_early();
> fbb9ce9530fd9b6 Ingo Molnar              2006-07-03   840
> fbb9ce9530fd9b6 Ingo Molnar              2006-07-03   841       local_irq_disable();
> 2ce802f62ba32a7 Tejun Heo                2011-01-20   842       early_boot_irqs_disabled = true;
> fbb9ce9530fd9b6 Ingo Molnar              2006-07-03   843
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   844       /*
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   845        * Interrupts are still disabled. Do necessary setups, then
> 1b3b3b49b996140 Viresh Kumar             2017-03-23   846        * enable them.
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   847        */
> 44fd22992cb76dc Stas Sergeev             2006-03-23   848       boot_cpu_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   849       page_address_init();
> ea676e846a8171b Andrew Morton            2013-04-29   850       pr_notice("%s", linux_banner);
> e6b1db98cf4d54d Matthew Garrett          2019-08-19   851       early_security_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   852       setup_arch(&command_line);
> 7495e0926fdf302 Steven Rostedt (VMware   2020-02-04   853)      setup_boot_config(command_line);
> 30d7e0d466b3ac0 Alon Bar-Lev             2007-02-12   854       setup_command_line(command_line);
> e0982e90cd1ecf5 Mike Travis              2008-03-26   855       setup_nr_cpu_ids();
> d6647bdf98a0de1 Tejun Heo                2009-07-21   856       setup_per_cpu_areas();
> 44fd22992cb76dc Stas Sergeev             2006-03-23   857       smp_prepare_boot_cpu(); /* arch-specific boot-cpu hooks */
> b5b1404d0815894 Linus Torvalds           2018-08-12   858       boot_cpu_hotplug_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   859
> 72675e131eb418c Michal Hocko             2017-09-06   860       build_all_zonelists(NULL);
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   861       page_alloc_init();
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   862
> 51887d03aca101a Masami Hiramatsu         2020-01-11   863       pr_notice("Kernel command line: %s\n", saved_command_line);
> 6041186a32585fc Dan Williams             2019-04-18   864       /* parameters may set static keys */
> 6041186a32585fc Dan Williams             2019-04-18   865       jump_label_init();
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   866       parse_early_param();
> 51e158c12aca3c9 Rusty Russell            2014-04-28   867       after_dashes = parse_args("Booting kernel",
> 51e158c12aca3c9 Rusty Russell            2014-04-28   868                                 static_command_line, __start___param,
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   869                                 __stop___param - __start___param,
> ecc8617053e0a97 Luis R. Rodriguez        2015-03-30   870                                 -1, -1, NULL, &unknown_bootoption);
> 3438cf549d2f3ee Daniel Thompson          2014-11-11   871       if (!IS_ERR_OR_NULL(after_dashes))
> 51e158c12aca3c9 Rusty Russell            2014-04-28   872               parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
> ecc8617053e0a97 Luis R. Rodriguez        2015-03-30   873                          NULL, set_init_arg);
> 1319916209ce8f5 Masami Hiramatsu         2020-01-11   874       if (extra_init_args)
> 1319916209ce8f5 Masami Hiramatsu         2020-01-11   875               parse_args("Setting extra init args", extra_init_args,
> 1319916209ce8f5 Masami Hiramatsu         2020-01-11   876                          NULL, 0, -1, -1, NULL, set_init_arg);
> 97ce2c88f9ad42e Jeremy Fitzhardinge      2011-10-12   877
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   878       /*
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   879        * These use large bootmem allocations and must precede
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   880        * kmem_cache_init()
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   881        */
> 162a7e7500f9664 Mike Travis              2011-05-24   882       setup_log_buf(0);
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   883       vfs_caches_init_early();
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   884       sort_main_extable();
> 83b519e8b9572c3 Pekka Enberg             2009-06-10   885       trap_init();
> 444f478f65c7ca4 Pekka Enberg             2009-06-11   886       mm_init();
> de03c72cfce5b26 KOSAKI Motohiro          2011-05-24   887
> f631718de3ca24a Steven Rostedt (VMware   2017-03-03   888)      ftrace_init();
> f631718de3ca24a Steven Rostedt (VMware   2017-03-03   889)
> e725c731e3bb1e8 Steven Rostedt (VMware   2017-03-03   890)      /* trace_printk can be enabled here */
> e725c731e3bb1e8 Steven Rostedt (VMware   2017-03-03   891)      early_trace_init();
> e725c731e3bb1e8 Steven Rostedt (VMware   2017-03-03   892)
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   893       /*
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   894        * Set up the scheduler prior starting any interrupts (such as the
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   895        * timer interrupt). Full topology setup happens at smp_init()
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   896        * time - but meanwhile we still have a functioning scheduler.
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   897        */
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   898       sched_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   899       /*
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   900        * Disable preemption - early bootup scheduling is extremely
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   901        * fragile until we cpu_idle() for the first time.
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   902        */
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   903       preempt_disable();
> dd4d9fecbeba893 Fabian Frederick         2014-08-08   904       if (WARN(!irqs_disabled(),
> dd4d9fecbeba893 Fabian Frederick         2014-08-08   905                "Interrupts were enabled *very* early, fixing it\n"))
> c4a68306b9c0939 Ard van Breemen          2007-01-05   906               local_irq_disable();
> 0a835c4f090af2c Matthew Wilcox           2016-12-20   907       radix_tree_init();
> 3347fa0928210d9 Tejun Heo                2016-09-16   908
> 7d229c668a114e8 Tal Shorer               2017-11-03   909       /*
> 7d229c668a114e8 Tal Shorer               2017-11-03   910        * Set up housekeeping before setting up workqueues to allow the unbound
> 7d229c668a114e8 Tal Shorer               2017-11-03   911        * workqueue to take non-housekeeping into account.
> 7d229c668a114e8 Tal Shorer               2017-11-03   912        */
> 7d229c668a114e8 Tal Shorer               2017-11-03   913       housekeeping_init();
> 7d229c668a114e8 Tal Shorer               2017-11-03   914
> 3347fa0928210d9 Tejun Heo                2016-09-16   915       /*
> 3347fa0928210d9 Tejun Heo                2016-09-16   916        * Allow workqueue creation and work item queueing/cancelling
> 3347fa0928210d9 Tejun Heo                2016-09-16   917        * early.  Work item execution depends on kthreads and starts after
> 3347fa0928210d9 Tejun Heo                2016-09-16   918        * workqueue_init().
> 3347fa0928210d9 Tejun Heo                2016-09-16   919        */
> 3347fa0928210d9 Tejun Heo                2016-09-16   920       workqueue_init_early();
> 3347fa0928210d9 Tejun Heo                2016-09-16   921
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   922       rcu_init();
> 5f893b2639b21ff Steven Rostedt (Red Hat  2014-12-12   923)
> e725c731e3bb1e8 Steven Rostedt (VMware   2017-03-03   924)      /* Trace events are available after this */
> 5f893b2639b21ff Steven Rostedt (Red Hat  2014-12-12   925)      trace_init();
> 5f893b2639b21ff Steven Rostedt (Red Hat  2014-12-12   926)
> 4e37958d1288ce9 Steven Rostedt (VMware   2018-03-26   927)      if (initcall_debug)
> 4e37958d1288ce9 Steven Rostedt (VMware   2018-03-26   928)              initcall_debug_enable();
> 4e37958d1288ce9 Steven Rostedt (VMware   2018-03-26   929)
> 65f382fd0c8fa48 Frederic Weisbecker      2013-07-11   930       context_tracking_init();
> 0b8f1efad30bd58 Yinghai Lu               2008-12-05   931       /* init some links before init_ISA_irqs() */
> 0b8f1efad30bd58 Yinghai Lu               2008-12-05   932       early_irq_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   933       init_IRQ();
> ad2b13536ace08d Thomas Gleixner          2013-03-05   934       tick_init();
> d6dd50e07c5bec0 Linus Torvalds           2014-10-13   935       rcu_init_nohz();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   936       init_timers();
> c0a3132963db68f Thomas Gleixner          2006-01-09   937       hrtimers_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   938       softirq_init();
> ad596171ed635c5 John Stultz              2006-06-26   939       timekeeping_init();
> d55535232c3dbde Kees Cook                2019-04-19   940
> d55535232c3dbde Kees Cook                2019-04-19   941       /*
> d55535232c3dbde Kees Cook                2019-04-19   942        * For best initial stack canary entropy, prepare it after:
> d55535232c3dbde Kees Cook                2019-04-19   943        * - setup_arch() for any UEFI RNG entropy and boot cmdline access
> d55535232c3dbde Kees Cook                2019-04-19   944        * - timekeeping_init() for ktime entropy used in rand_initialize()
> d55535232c3dbde Kees Cook                2019-04-19   945        * - rand_initialize() to get any arch-specific entropy like RDRAND
> d55535232c3dbde Kees Cook                2019-04-19   946        * - add_latent_entropy() to get any latent entropy
> d55535232c3dbde Kees Cook                2019-04-19   947        * - adding command line entropy
> d55535232c3dbde Kees Cook                2019-04-19   948        */
> d55535232c3dbde Kees Cook                2019-04-19   949       rand_initialize();
> d55535232c3dbde Kees Cook                2019-04-19   950       add_latent_entropy();
> d55535232c3dbde Kees Cook                2019-04-19   951       add_device_randomness(command_line, strlen(command_line));
> d55535232c3dbde Kees Cook                2019-04-19   952       boot_init_stack_canary();
> d55535232c3dbde Kees Cook                2019-04-19   953
> 88fecaa27f398d9 John Stultz              2006-07-03   954       time_init();
> 9e6302056f8029f Stephane Eranian         2013-04-03   955       perf_event_init();
> 93e028148fce0be Heiko Carstens           2006-07-03   956       profile_init();
> d8ad7d1123a960c Takao Indoh              2011-03-29   957       call_function_init();
> f91eb62f71b31e6 Steven Rostedt           2013-04-29   958       WARN(!irqs_disabled(), "Interrupts were enabled early\n");
> c3bc8fd637a9623 Joel Fernandes (Google   2018-07-30   959)
> 2ce802f62ba32a7 Tejun Heo                2011-01-20   960       early_boot_irqs_disabled = false;
> 93e028148fce0be Heiko Carstens           2006-07-03   961       local_irq_enable();
> dcce284a259373f Benjamin Herrenschmidt   2009-06-18   962
> 7e85ee0c1d15ca5 Pekka Enberg             2009-06-12   963       kmem_cache_init_late();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   964
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   965       /*
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   966        * HACK ALERT! This is early. We're enabling the console before
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   967        * we've done PCI setups etc, and console_init() must be aware of
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   968        * this. But we do want output early, in case something goes wrong.
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   969        */
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   970       console_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   971       if (panic_later)
> 499a4584d7f817d Tetsuo Handa             2014-01-23   972               panic("Too many boot %s vars at `%s'", panic_later,
> 499a4584d7f817d Tetsuo Handa             2014-01-23   973                     panic_param);
> fbb9ce9530fd9b6 Ingo Molnar              2006-07-03   974
> c3bc8fd637a9623 Joel Fernandes (Google   2018-07-30   975)      lockdep_init();
> fbb9ce9530fd9b6 Ingo Molnar              2006-07-03   976
> 9a11b49a805665e Ingo Molnar              2006-07-03   977       /*
> 9a11b49a805665e Ingo Molnar              2006-07-03   978        * Need to run this when irqs are enabled, because it wants
> 9a11b49a805665e Ingo Molnar              2006-07-03   979        * to self-test [hard/soft]-irqs on/off lock inversion bugs
> 9a11b49a805665e Ingo Molnar              2006-07-03   980        * too:
> 9a11b49a805665e Ingo Molnar              2006-07-03   981        */
> 9a11b49a805665e Ingo Molnar              2006-07-03   982       locking_selftest();
> 9a11b49a805665e Ingo Molnar              2006-07-03   983
> c7753208a94c73d Tom Lendacky             2017-07-17   984       /*
> c7753208a94c73d Tom Lendacky             2017-07-17   985        * This needs to be called before any devices perform DMA
> c7753208a94c73d Tom Lendacky             2017-07-17   986        * operations that might use the SWIOTLB bounce buffers. It will
> c7753208a94c73d Tom Lendacky             2017-07-17   987        * mark the bounce buffers as decrypted so that their usage will
> c7753208a94c73d Tom Lendacky             2017-07-17   988        * not cause "plain-text" data to be decrypted when accessed.
> c7753208a94c73d Tom Lendacky             2017-07-17   989        */
> c7753208a94c73d Tom Lendacky             2017-07-17   990       mem_encrypt_init();
> c7753208a94c73d Tom Lendacky             2017-07-17   991
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   992  #ifdef CONFIG_BLK_DEV_INITRD
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   993       if (initrd_start && !initrd_below_start_ok &&
> bd673c7c3b1681d Geert Uytterhoeven       2008-07-29   994           page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
> ea676e846a8171b Andrew Morton            2013-04-29   995               pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
> bd673c7c3b1681d Geert Uytterhoeven       2008-07-29   996                   page_to_pfn(virt_to_page((void *)initrd_start)),
> bd673c7c3b1681d Geert Uytterhoeven       2008-07-29   997                   min_low_pfn);
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   998               initrd_start = 0;
> ^1da177e4c3f415 Linus Torvalds           2005-04-16   999       }
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1000  #endif
> e7c8d5c9955a4d2 Christoph Lameter        2005-06-21  1001       setup_per_cpu_pageset();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1002       numa_policy_init();
> 9c71206d060d4e8 Dou Liyang               2017-09-13  1003       acpi_early_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1004       if (late_time_init)
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1005               late_time_init();
> 857baa87b6422bc Pavel Tatashin           2018-07-19  1006       sched_clock_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1007       calibrate_delay();
> 95846ecf9dac508 Gargi Sharma             2017-11-17  1008       pid_idr_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1009       anon_vma_init();
> 11520e5e7c1855f Linus Torvalds           2012-12-15  1010  #ifdef CONFIG_X86
> 83e68189745ad93 Matt Fleming             2012-11-14  1011       if (efi_enabled(EFI_RUNTIME_SERVICES))
> 11520e5e7c1855f Linus Torvalds           2012-12-15 @1012               efi_enter_virtual_mode();
> 11520e5e7c1855f Linus Torvalds           2012-12-15  1013  #endif
> b235beea9e996a4 Linus Torvalds           2016-06-24  1014       thread_stack_cache_init();
> d84f4f992cbd76e David Howells            2008-11-14  1015       cred_init();
> ff691f6e03815dc Heinrich Schuchardt      2015-04-16  1016       fork_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1017       proc_caches_init();
> 3ea056c50476f87 Alexey Dobriyan          2018-04-10  1018       uts_ns_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1019       buffer_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1020       key_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1021       security_init();
> 0b4b3827db386ec Jason Wessel             2010-05-20  1022       dbg_late_init();
> 4248b0da460839e Mel Gorman               2015-08-06  1023       vfs_caches_init();
> 62906027091f1d0 Nicholas Piggin          2016-12-25  1024       pagecache_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1025       signals_init();
> 0965232035cfa59 Alexey Dobriyan          2018-04-10  1026       seq_file_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1027       proc_root_init();
> e149ed2b805fefd Al Viro                  2014-11-01  1028       nsfs_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1029       cpuset_init();
> 695df2132cfe378 Zefan Li                 2015-03-04  1030       cgroup_init();
> c757249af152c59 Shailabh Nagar           2006-07-14  1031       taskstats_init_early();
> ca74e92b4698276 Shailabh Nagar           2006-07-14  1032       delayacct_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1033
> 4fc19708b165c1c Nadav Amit               2019-04-26  1034       poking_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1035       check_bugs();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1036
> b064a8fa77dfead Rafael J. Wysocki        2015-06-10  1037       acpi_subsystem_init();
> e7ff3a47630d951 Thomas Gleixner          2016-12-09  1038       arch_post_acpi_subsys_init();
> 6ae6996a466e14b Feng Tang                2009-08-14  1039       sfi_init_late();
> dfd402a4c4baae4 Marco Elver              2019-11-14  1040       kcsan_init();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1041
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1042       /* Do the rest non-__init'ed, we're now alive */
> 53c99bd665a2649 Martin Schwidefsky       2018-08-31  1043       arch_call_rest_init();
> a9a3ed1eff3601b Borislav Petkov          2020-04-22  1044
> a9a3ed1eff3601b Borislav Petkov          2020-04-22  1045       prevent_tail_call_optimization();
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1046  }
> ^1da177e4c3f415 Linus Torvalds           2005-04-16  1047
>
> :::::: The code at line 1012 was first introduced by commit
> :::::: 11520e5e7c1855fc3bf202bb3be35a39d9efa034 Revert "x86-64/efi: Use EFI to deal with platform wall clock (again)"
>
> :::::: TO: Linus Torvalds <torvalds@linux-foundation.org>
> :::::: CC: Linus Torvalds <torvalds@linux-foundation.org>
>
> ---
> 0-DAY CI Kernel Test Service, Intel Corporation
> https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzbBF0YVveGNZo0bJ8fWHVZRcrr6n90eYLDCov2vcfZyg%40mail.gmail.com.
