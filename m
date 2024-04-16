Return-Path: <kasan-dev+bncBD6LJ6GMUUPBB75A7GYAMGQETA3JQWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C3DA8A6822
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Apr 2024 12:18:41 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6962767b1f8sf64089436d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Apr 2024 03:18:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713262720; cv=pass;
        d=google.com; s=arc-20160816;
        b=g2E6M438mAEgC0R3A5wbH1KY4HtNKio1Q4vipIJmb0aLAQ5AOBwz+nnt2y1IY6CEcL
         JxJm1OknWDP/uIejwyLMvr0VuE7FlueH7PZpaPUEJz6ljMoUjGaOgW96bmjo8lruOR4J
         gp7MbfE7Yg9MhzwA6ZaTUAPQ7EI5yRw5UO5AetXrFn1FMuNYbNMoLl6jGKCJT2WZz821
         ItVUoV/XZU5NnEQblDzlnxcPvYkskfKZ/l8llj/IQRnigOjLlpBQxDmpnCH2cOdxcxev
         6YEjGJNUTQdLkaZ/3Gc9T+Wmv/IaZQmWE84lyL2rJv6gyIKeQ2tkGC97WfCOg9Gu63Ob
         Ml6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=akHTd/NDJxMjVkKPiCp+zRLD/c7I60tUUWiLr6IZvrk=;
        fh=LlE6RYy/7sk45kn2vF40Ppu0XwjMs/In8vK60IC4190=;
        b=q8/H87haP9GdnI1omeJmnKDBhhM2VXD+Yb7x+97vrCwVVvhE+DBj8ZyQUPR90oUGrp
         9y7Rygk/wQtaZNAup41TY+WXIxAffXOwa9mtK60qmLC0PexpD30LVbrrqsJYE+HjdMoq
         X8f+Wnc8brH7taTFFYXffukPTNN7lrmjR5aICJIPWuQGZ5BF6hxSjwnDKJzguRAeQcqp
         xLNmQhxaDCIA58NK9GzUsVPcsqHb77aeRDCqeWKO+B87/F1IRettLEfCSUcb128/WNdi
         x5v0CYE2V1nXMCci0sGCdf1BoFwWgi9XoMPMsWPHlSLqrAjbpK+PXAkl8DV3S8WbpFtJ
         QcMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MtHRuHmM;
       spf=pass (google.com: domain of adrian.hunter@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=adrian.hunter@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713262720; x=1713867520; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:organization:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=akHTd/NDJxMjVkKPiCp+zRLD/c7I60tUUWiLr6IZvrk=;
        b=Org1+WgwexUX82JtkGkjXjzuN/mR1APZlUZ+PY0Fo/8x2GLKIoZYhd5+yZbSsL4nwg
         6Xbg5uBgwosfG7opxxJJLpRNkbQjCUbnC3jvrejR9P0Ua0pC6pYlVWqJGcxwUtq9v3hg
         t/3cgWG4PjzMIvKQlr3Z0IxvTGCOUqH+rwqaXGzf7HPXmpGa2plCjWuOuBcASz5r0C04
         MRRQLjWLkF5WZQ671UqUCMCNx0JayBSz/l2dDpm/1NXHAfUhsdZ+E4I3T8QCtkexx1xh
         i2rodOcy3yYubLI4lEv8fJOlELfhaXCJjcKUF6Vn+m7ePj4nkbk3oCtkTeBjtBTfd6+N
         wtGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713262720; x=1713867520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=akHTd/NDJxMjVkKPiCp+zRLD/c7I60tUUWiLr6IZvrk=;
        b=NlastO73gC3wZjpmSOy+M8sOIaI2XtEpo/0RPqxLdRYltS9H30aHP7/H0AVNcMPpkA
         a6chBNwpECVx620Gim6kFrP6Np9QQ6O0H3ih+AkNT/7vfPPRtlTnJSzhMr7zkIb+cyxY
         S1wkrhaxIdzrkecMJN3FORrS5T9So97peq/N6kQf1CuE9bwZr2TuliUCa/588tNu1cdL
         vO/mLUg4tBI9bSpMGvdBoBoqh85bQMJMboifOq4U7FZjvaBtAkaJM7kX1cZQEg1lS4Wy
         982AydqTH36cbINOS/1r2OhQZNj+T23sCil8s/R3Yw6O4C7Ft9M7AkufPkZXGeGwys8P
         /HlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVF8lWe9jK0WYYAq6oxMj4ZCXm4TOvXj6If1g2UlQSEY/7YWMhbeXVyLRaPUNjniOg5ZwUo5Frfw35M/vcfN/iZahwDRz2TFw==
X-Gm-Message-State: AOJu0Yz/nL0te07hmYlTvqLpwLd9hup0x58iN79URehyCUyunq/gnbNa
	vcSV6/fvM2SzKFRlGzJamAOQhqYRfLegHq+Ft2HL/xt4S45FZzdG
X-Google-Smtp-Source: AGHT+IFsdAWIEakDVC9Ae82G/rlFk29kvd1gR54grRLYmWF3C3UAbyVHWxXQV3NeXGLG4eyDDH3MSA==
X-Received: by 2002:a05:6214:d46:b0:69b:6afa:f15f with SMTP id 6-20020a0562140d4600b0069b6afaf15fmr9253706qvr.33.1713262719880;
        Tue, 16 Apr 2024 03:18:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:194a:b0:699:27da:1247 with SMTP id
 q10-20020a056214194a00b0069927da1247ls162155qvk.2.-pod-prod-08-us; Tue, 16
 Apr 2024 03:18:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcQs2ShhM8FS6Rc1OyduOunac3KGO1DmST5DTzHuYxFk12B4YotI/Z7pXaR937x1TxaLqMq9ymHpfQEsqBu48bXQB2wLUQXPeP8Q==
X-Received: by 2002:a05:620a:2181:b0:78e:ddfd:7864 with SMTP id g1-20020a05620a218100b0078eddfd7864mr7359083qka.34.1713262719086;
        Tue, 16 Apr 2024 03:18:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713262719; cv=none;
        d=google.com; s=arc-20160816;
        b=w1lOOmxXLECs7hnZXC9iMJxYckdYpUPaBrdr9GL9qhc/tvSB5GWZg+NR3C11Dl4a4R
         xeOBj9HWNvA2Na5oW1/eMjZseIi/I0UAP9FIXmZnW7nmFDlI+axgU8jaqeiq6aMWw04d
         yF0r5tsGX17jD0/Z27UwUUY0AsnKFDdJ/vtfI2CGE7td5BGAuBgFcc5nI3E9Iigc6vdq
         NovUzznw6ge60d0/mWGfOzCAql3t/n08207UpjNkrQRC12Ret+QjWY67zxAvr69tGANw
         drSikkbHSm/oV/9KkLnd+1UhfFKRKWHbGfGfTj6MY+MxpVWk1QvDW3zFL/xpMH+BF43H
         ml5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=MnYCK2bRJne2+xgs18/i5BsOphG0QULRX70lmh7Mdgw=;
        fh=IfxFAG5biqwGGpZ7mDn+wNWp+VwnCU6oGlfQ3tLcT34=;
        b=LeSiH661wdSWpgoeGkqB8Dx/Ub4+9pfOIu3998+D/hR2vvJLRxhsOMlewpEnjfEPbP
         dIwmKnKz/5Ml1+Dgno/fCyH+hEq/3H/MXekTr8E++HAeKdU7XjOQ4uJfJRAftkQvZyXW
         jvcu1z13e7J6Be/QuxbuJ/ft8Ep1F2AgFoQnTMTaWV5lGTcbC8ILB2hMMsDlcuV8iuNs
         aqqAMCKFM+ZbPPon3SvYZwgTxPj4MQQfk35kND/S14YRo2gwSWL3oZ0lCsatL2zrTit0
         Yvn80QSQuE8DmzPgoEVmsmyj+cpxgGcjDMtVacs9cu2FE1NYR5vStCkQqWvXviBolWBa
         UduQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MtHRuHmM;
       spf=pass (google.com: domain of adrian.hunter@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=adrian.hunter@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id c42-20020a05620a26aa00b0078ed7451cccsi354954qkp.4.2024.04.16.03.18.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 16 Apr 2024 03:18:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrian.hunter@intel.com designates 198.175.65.18 as permitted sender) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: arIum9KtRCOzfOXgtW+VHw==
X-CSE-MsgGUID: h6hGs+fWQ7mhQeLEsOXl5A==
X-IronPort-AV: E=McAfee;i="6600,9927,11045"; a="8855465"
X-IronPort-AV: E=Sophos;i="6.07,205,1708416000"; 
   d="scan'208";a="8855465"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Apr 2024 03:18:39 -0700
X-CSE-ConnectionGUID: DS7/gA9nTAOsgY5OLxPwnw==
X-CSE-MsgGUID: qBGWO/5DR7yzpSOtsh6aFQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.07,205,1708416000"; 
   d="scan'208";a="22114286"
Received: from ahunter6-mobl1.ger.corp.intel.com (HELO [10.0.2.15]) ([10.252.61.239])
  by orviesa010-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Apr 2024 03:18:35 -0700
Message-ID: <cb8ae96c-12a6-4945-96ed-7f68f01d69aa@intel.com>
Date: Tue, 16 Apr 2024 13:18:31 +0300
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [tip:timers/core] [timekeeping] e84f43e34f:
 BUG:KCSAN:data-race_in_timekeeping_advance/timekeeping_debug_get_ns
To: kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, linux-kernel@vger.kernel.org,
 x86@kernel.org, Thomas Gleixner <tglx@linutronix.de>, elver@google.com,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
References: <202404161050.38f1c92e-lkp@intel.com>
Content-Language: en-US
From: Adrian Hunter <adrian.hunter@intel.com>
Organization: Intel Finland Oy, Registered Address: PL 281, 00181 Helsinki,
 Business Identity Code: 0357606 - 4, Domiciled in Helsinki
In-Reply-To: <202404161050.38f1c92e-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: adrian.hunter@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=MtHRuHmM;       spf=pass
 (google.com: domain of adrian.hunter@intel.com designates 198.175.65.18 as
 permitted sender) smtp.mailfrom=adrian.hunter@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 16/04/24 09:27, kernel test robot wrote:
> 
> 
> Hello,
> 
> kernel test robot noticed "BUG:KCSAN:data-race_in_timekeeping_advance/timekeeping_debug_get_ns" on:
> 
> commit: e84f43e34faf85816587f80594541ec978449d6e ("timekeeping: Consolidate timekeeping helpers")
> https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git timers/core
> 
> [test failed on linux-next/master 9ed46da14b9b9b2ad4edb3b0c545b6dbe5c00d39]
> 
> in testcase: boot
> 
> compiler: gcc-13
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> 
> (please refer to attached dmesg/kmsg for entire log/backtrace)
> 
> 
> we noticed this issue doesn't always happen on this commit (63 times out of
> 111 runs as below), however, parent keeps clean for this issue, but has other
> KCSAN:data-race issues which does not happen on e84f43e34f.
> 
> e8e9d21a5df655a6 e84f43e34faf85816587f805945
> ---------------- ---------------------------
>        fail:runs  %reproduction    fail:runs
>            |             |             |
>          16:60         -27%            :111   dmesg.BUG:KCSAN:data-race_in_ktime_get/timekeeping_advance
>           7:60         -12%            :111   dmesg.BUG:KCSAN:data-race_in_ktime_get_update_offsets_now/timekeeping_advance
>            :60         105%          63:111   dmesg.BUG:KCSAN:data-race_in_timekeeping_advance/timekeeping_debug_get_ns
> 
> 
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202404161050.38f1c92e-lkp@intel.com
> 
> 
> [  108.068027][    C1] BUG: KCSAN: data-race in timekeeping_advance / timekeeping_debug_get_ns
> [  108.069188][    C1]
> [  108.069511][    C1] write to 0xffffffff95672dc0 of 296 bytes by interrupt on cpu 0:
> [ 108.070559][ C1] timekeeping_advance (kernel/time/timekeeping.c:2207 (discriminator 1)) 
> [ 108.071242][ C1] update_wall_time (kernel/time/timekeeping.c:2222 (discriminator 1)) 
> [ 108.071883][ C1] tick_do_update_jiffies64 (kernel/time/tick-sched.c:149) 
> [ 108.072638][ C1] tick_nohz_handler (kernel/time/tick-sched.c:229 kernel/time/tick-sched.c:287) 
> [ 108.073235][ C1] __hrtimer_run_queues (kernel/time/hrtimer.c:1692 kernel/time/hrtimer.c:1756) 
> [ 108.073840][ C1] hrtimer_interrupt (kernel/time/hrtimer.c:1821) 
> [ 108.074430][ C1] __sysvec_apic_timer_interrupt (arch/x86/include/asm/jump_label.h:27 include/linux/jump_label.h:207 arch/x86/include/asm/trace/irq_vectors.h:41 arch/x86/kernel/apic/apic.c:1050) 
> [ 108.075132][ C1] sysvec_apic_timer_interrupt (arch/x86/kernel/apic/apic.c:1043 (discriminator 2) arch/x86/kernel/apic/apic.c:1043 (discriminator 2)) 
> [ 108.075821][ C1] asm_sysvec_apic_timer_interrupt (arch/x86/include/asm/idtentry.h:702) 
> [  108.076657][    C1]
> [  108.076982][    C1] read to 0xffffffff95672de0 of 8 bytes by interrupt on cpu 1:
> [ 108.077994][ C1] timekeeping_debug_get_ns (kernel/time/timekeeping.c:373 kernel/time/timekeeping.c:383 kernel/time/timekeeping.c:280) 

Looks like the nested seqlock in timekeeping_debug_get_ns()
results in premature kcsan_atomic_next(0), so the subsequent
access via timekeeping_cycles_to_ns(), although still under
seqlock, does not look that way to KCSAN.

> [ 108.078766][ C1] ktime_get (kernel/time/timekeeping.c:394 kernel/time/timekeeping.c:838) 
> [ 108.079325][ C1] tick_nohz_handler (kernel/time/tick-sched.c:220 kernel/time/tick-sched.c:287) 
> [ 108.079995][ C1] __hrtimer_run_queues (kernel/time/hrtimer.c:1692 kernel/time/hrtimer.c:1756) 
> [ 108.080740][ C1] hrtimer_interrupt (kernel/time/hrtimer.c:1821) 
> [ 108.081423][ C1] __sysvec_apic_timer_interrupt (arch/x86/include/asm/jump_label.h:27 include/linux/jump_label.h:207 arch/x86/include/asm/trace/irq_vectors.h:41 arch/x86/kernel/apic/apic.c:1050) 
> [ 108.082241][ C1] sysvec_apic_timer_interrupt (arch/x86/kernel/apic/apic.c:1043 (discriminator 2) arch/x86/kernel/apic/apic.c:1043 (discriminator 2)) 
> [ 108.083014][ C1] asm_sysvec_apic_timer_interrupt (arch/x86/include/asm/idtentry.h:702) 
> [  108.083849][    C1]
> [  108.084183][    C1] value changed: 0x000e771a64000000 -> 0x000e959ee4000000
> [  108.085518][    C1]
> [  108.085775][    C1] Reported by Kernel Concurrency Sanitizer on:
> [  108.086563][    C1] CPU: 1 PID: 265 Comm: sed Tainted: G        W   E    N 6.9.0-rc3-00015-ge84f43e34faf #1 ddd7212d5d239f10e5f20ca1605d3d23d4ce80eb
> [  108.088374][    C1] ==================================================================
> 
> 
> 
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20240416/202404161050.38f1c92e-lkp@intel.com
> 
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cb8ae96c-12a6-4945-96ed-7f68f01d69aa%40intel.com.
