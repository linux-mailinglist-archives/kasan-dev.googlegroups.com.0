Return-Path: <kasan-dev+bncBDOPF7OU44DRBCVISGFQMGQE6RERMDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B8204292DC
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 17:11:07 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id cy14-20020a0564021c8e00b003db8c9a6e30sf3772099edb.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 08:11:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633965066; cv=pass;
        d=google.com; s=arc-20160816;
        b=V6rx6kaA7Jif4LNEbNkfIa5sz7EU0lOZ2uyIo6FBmGvHCAuSJ92BYHEiJkoxnPAG4P
         7WD3NQw8e3xPCQbb9mwtwuQBtFxWPNOdpIUkrj+E19DxfA/qm2gPQ/qOrKdHmISUloAj
         WqhAvgduJxABJBv7v2j4qhjtiH651bu+kV0+a5chhLrycCuB41GsVqWyZd9wVWFgCTpH
         8tyeOZuX1A+0jS5tn9392No9DHZ6/cpotBDPRPU4nbViNq6O05LTK9MB1oqMriKu5rce
         WVGL9FH5GHpdnbjivXpDpH3LwYHz+5AuGPvs36APlHoBv1Gk4SZ1FT93Z2JuBG2cyBxu
         oGSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vA4/wVG1qAfgAgE8DYy67J6+8ivrrl7cr5xQhemfMT4=;
        b=E/QHE/M29GEktZ866Bnbx/vyhl17Kro8nuA6k/5hLseClHYnDKa42A/+GaTQlaATQP
         2s74dalH6efweOwPac/0XxGrE1/8mlOvz6FLCtzslnlgljjcb1FPpa+q8205n8c+eIrs
         hkZq/cYnnRBoRbmfEHTbcRBxDmxABF4nHJLNKi7mvoOTLyUKtXi2NHgS2FMAhe+lutmD
         K2R/lWAOdbmdTWAtp9B5REcF/xI3ChE55fMuSgDGsKylTmj6nqwHYRR0fczYQROU+E+N
         iOQF5UdMLqx1/9CAQgTmfQY1JilKMawAMedOCKez7sgkgyvB4bUpju3TTEucSWtPK915
         KorA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=N5NTidrj;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vA4/wVG1qAfgAgE8DYy67J6+8ivrrl7cr5xQhemfMT4=;
        b=iPLVyo4tqctauvl/o7VO2MDSP1+2Y29hPBTCp5QN1BggMEkLppUSWclhLnYJaOXzEl
         ofH2BztyFMehsJoVB3rfPMJ/EePwvlwjQtW9p+mEwnhaJFQTUPvXBnQNNLievvnQWwTm
         92BclSFQF7/CXBiwB76uaaZMP9hOZlLeF6c8hBaJUgwKPG1SMsBR5MckdzLu1McYeXBa
         JQxiLxDR6oVLyMEbt7ghmH1PN/dTVf6FwOwdFs5EJlHz5UK056TSmwEjC6lbklJgIZBq
         TzZcK22buhZFMiKWWJQBGf+q9yz2KvXjNxpIwoCXMhQzek9zgFd6DxfMCrNYiwfAZ6TC
         R0UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vA4/wVG1qAfgAgE8DYy67J6+8ivrrl7cr5xQhemfMT4=;
        b=cO9KVwuP5iNNAQbyRzkUrent40ZJ9GBsU//bbKaOoRswryfkuzEECCV5SIMgHi17hy
         mAnqLlJE75Pi8Z2dtjTdvkS9wv3ksaPYaUV2ONUx1sd7y6YrjM/hTBa86k47Q1AO/ayG
         HNvnD1VPfRPhvFQAvjIHRycQRYh5EpLZ7OYAer2cu8S8stANTn4yPhwyvoVdxXLV+kLu
         RrAJyXTzj7XZkfi7JQygKdE+C5dyQnUMYlpdHZ6BYMYxvO+rvZgjqPtm7K1oJGuW6Uh2
         CP2Emiasw8i39r1S7LlENbmu4zKA1+3qEEio2VLzoyRa97DX7fYDwmTTTCk6OVWUnHsW
         eAuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OUNvw642fzNe3tOqdyydBcjq2Qf0EiBvr7Rhb0lT3zNvxasAf
	QBLHFhLPBhGce6c9f2rHXRI=
X-Google-Smtp-Source: ABdhPJxQfv6/NPT+bE2WoQNoVnC0kjtHznz7xNHhjYr7sVY+b6EmSbKaes5UDvqfa+NCzF/ShLJHUg==
X-Received: by 2002:a17:907:1741:: with SMTP id lf1mr18153815ejc.225.1633965066892;
        Mon, 11 Oct 2021 08:11:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d39a:: with SMTP id x26ls4200470edq.2.gmail; Mon, 11 Oct
 2021 08:11:06 -0700 (PDT)
X-Received: by 2002:a05:6402:5187:: with SMTP id q7mr3864438edd.374.1633965066015;
        Mon, 11 Oct 2021 08:11:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633965066; cv=none;
        d=google.com; s=arc-20160816;
        b=KCoQf6iivXO7RQ88Q6CgFrmuTIpEYBWfXIFnazUZ9cLbuqanAoAOv921J/z5+mTwwb
         kPGPTbKIetG/4j/bKS+wjCst1mp12KxPbOoFNwElcZVAUfEOS+Qmw1dymGjVrsajvKPV
         0mY1jIgwfsMFpNgD9Ps0XwfaFBpDwOv4/LvmJCM736ouDRPsf/b4flsIU71nr00feci+
         UNMDkrP4+ucjcA9rgwMfjzVwJH0JQelbsaBPVwfL8ntcqMzH8tZioEVqm60H/S6W7cr1
         kXmTt3KKuacx5H2ZUqVm9uyPIti8yWL+SC6OmuepulVeg2VhyYmgvhZryaGFdVeeBfnj
         ioMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oIZOZFIV6wLH5vs6Sr4d06KNIPJAKrI5nM0ImXd31qc=;
        b=PYL+33pgC9uhil4hT03mvDWKwObmy86hEi6rZPJlRb7p7ZQYOpYLP/q5erEI+RMI7a
         MT59y24579zOKIlGXcK5b7dqp/nvrW+HXzlpJLJAVLir0IBEEnc086RwZCUCfg1rkoX3
         cxGwNbFbFPzi+vST5Ddrfh5MhPbHxD7YfFohhcFEny1mXqVQB//sh5ZGDySlS3TGOWYb
         ApuC1F1oVv+u0SQ6XEnA2en2JIzhF++IvnSTxyMTjROm3BFoxlKxW+mFGH8EGu95dOnv
         j1bnv6DXlNSUj7ZordLtonYTKncRDEkVDS/U2GEL1YiYfpNcfFJ6uHGuvCmVi9fGLN3W
         acCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=N5NTidrj;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id r21si602495edq.2.2021.10.11.08.11.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 08:11:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com [209.85.208.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 982724000F
	for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 15:11:05 +0000 (UTC)
Received: by mail-ed1-f72.google.com with SMTP id p13-20020a056402044d00b003db3256e4f2so16259748edw.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 08:11:05 -0700 (PDT)
X-Received: by 2002:a17:907:118d:: with SMTP id uz13mr27392958ejb.382.1633965064936;
        Mon, 11 Oct 2021 08:11:04 -0700 (PDT)
X-Received: by 2002:a17:907:118d:: with SMTP id uz13mr27392925ejb.382.1633965064718;
        Mon, 11 Oct 2021 08:11:04 -0700 (PDT)
Received: from localhost ([2001:67c:1560:8007::aac:c1b6])
        by smtp.gmail.com with ESMTPSA id d25sm4399465edt.51.2021.10.11.08.11.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 08:11:04 -0700 (PDT)
Date: Mon, 11 Oct 2021 17:11:03 +0200
From: Andrea Righi <andrea.righi@canonical.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
Message-ID: <YWRUBxS0hGGDkeU4@arighi-desktop>
References: <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop>
 <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop>
 <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
 <YWQCknwPcGlOBfUi@arighi-desktop>
 <YWQJe1ccZ72FZkLB@arighi-desktop>
 <CANpmjNNtCf+q21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B+fKA@mail.gmail.com>
 <YWRNVTk9N8K0RMst@arighi-desktop>
 <CACT4Y+bZGK75S+cyeQda-oHmeDVeownwOj2imQbPYi0dRY18+A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bZGK75S+cyeQda-oHmeDVeownwOj2imQbPYi0dRY18+A@mail.gmail.com>
X-Original-Sender: andrea.righi@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=N5NTidrj;       spf=pass
 (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122
 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Mon, Oct 11, 2021 at 05:00:15PM +0200, Dmitry Vyukov wrote:
> On Mon, 11 Oct 2021 at 16:42, Andrea Righi <andrea.righi@canonical.com> wrote:
> >
> > On Mon, Oct 11, 2021 at 12:03:52PM +0200, Marco Elver wrote:
> > > On Mon, 11 Oct 2021 at 11:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> > > > On Mon, Oct 11, 2021 at 11:23:32AM +0200, Andrea Righi wrote:
> > > > ...
> > > > > > You seem to use the default 20s stall timeout. FWIW syzbot uses 160
> > > > > > secs timeout for TCG emulation to avoid false positive warnings:
> > > > > > https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d863d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
> > > > > > There are a number of other timeouts raised as well, some as high as
> > > > > > 420 seconds.
> > > > >
> > > > > I see, I'll try with these settings and see if I can still hit the soft
> > > > > lockup messages.
> > > >
> > > > Still getting soft lockup messages even with the new timeout settings:
> > > >
> > > > [  462.663766] watchdog: BUG: soft lockup - CPU#2 stuck for 430s! [systemd-udevd:168]
> > > > [  462.755758] watchdog: BUG: soft lockup - CPU#3 stuck for 430s! [systemd-udevd:171]
> > > > [  924.663765] watchdog: BUG: soft lockup - CPU#2 stuck for 861s! [systemd-udevd:168]
> > > > [  924.755767] watchdog: BUG: soft lockup - CPU#3 stuck for 861s! [systemd-udevd:171]
> > >
> > > The lockups are expected if you're hitting the TCG bug I linked. Try
> > > to pass '-enable-kvm' to the inner qemu instance (my bad if you
> > > already have), assuming that's somehow easy to do.
> >
> > If I add '-enable-kvm' I can triggering other random panics (almost
> > immediately), like this one for example:
> >
> > [21383.189976] BUG: kernel NULL pointer dereference, address: 0000000000000098
> > [21383.190633] #PF: supervisor read access in kernel mode
> > [21383.191072] #PF: error_code(0x0000) - not-present page
> > [21383.191529] PGD 0 P4D 0
> > [21383.191771] Oops: 0000 [#1] SMP NOPTI
> > [21383.192113] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.15-rc4
> > [21383.192757] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.14.0-2 04/01/2014
> > [21383.193414] RIP: 0010:wb_timer_fn+0x44/0x3c0
> > [21383.193855] Code: 41 8b 9c 24 98 00 00 00 41 8b 94 24 b8 00 00 00 41 8b 84 24 d8 00 00 00 4d 8b 74 24 28 01 d3 01 c3 49 8b 44 24 60 48 8b 40 78 <4c> 8b b8 98 00 00 00 4d 85 f6 0f 84 c4 00 00 00 49 83 7c 24 30 00
> > [21383.195366] RSP: 0018:ffffbcd140003e68 EFLAGS: 00010246
> > [21383.195842] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000004
> > [21383.196425] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff9a3521f4fd80
> > [21383.197010] RBP: ffffbcd140003e90 R08: 0000000000000000 R09: 0000000000000000
> > [21383.197594] R10: 0000000000000004 R11: 000000000000000f R12: ffff9a34c75c4900
> > [21383.198178] R13: ffff9a34c3906de0 R14: 0000000000000000 R15: ffff9a353dc18c00
> > [21383.198763] FS:  0000000000000000(0000) GS:ffff9a353dc00000(0000) knlGS:0000000000000000
> > [21383.199558] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > [21383.200212] CR2: 0000000000000098 CR3: 0000000005f54000 CR4: 00000000000006f0
> > [21383.200930] Call Trace:
> > [21383.201210]  <IRQ>
> > [21383.201461]  ? blk_stat_free_callback_rcu+0x30/0x30
> > [21383.202692]  blk_stat_timer_fn+0x138/0x140
> > [21383.203180]  call_timer_fn+0x2b/0x100
> > [21383.203666]  __run_timers.part.0+0x1d1/0x240
> > [21383.204227]  ? kvm_clock_get_cycles+0x11/0x20
> > [21383.204815]  ? ktime_get+0x3e/0xa0
> > [21383.205309]  ? native_apic_msr_write+0x2c/0x30
> > [21383.205914]  ? lapic_next_event+0x20/0x30
> > [21383.206412]  ? clockevents_program_event+0x94/0xf0
> > [21383.206873]  run_timer_softirq+0x2a/0x50
> > [21383.207260]  __do_softirq+0xcb/0x26f
> > [21383.207647]  irq_exit_rcu+0x8c/0xb0
> > [21383.208010]  sysvec_apic_timer_interrupt+0x7c/0x90
> > [21383.208464]  </IRQ>
> > [21383.208713]  asm_sysvec_apic_timer_interrupt+0x12/0x20
> >
> > I think that systemd autotest used to use -enable-kvm, but then they
> > removed it, because it was introducing too many problems in the nested
> > KVM context. I'm not sure about the nature of those problems though, I
> > can investigate a bit and see if I can understand what they were
> > exactly.
> 
> This looks like just a plain bug in wb_timer_fn, not something related
> to virtualization.
> Do you have this fix?
> https://syzkaller.appspot.com/bug?extid=aa0801b6b32dca9dda82

Yes, it looks like I have this:

 d152c682f03c block: add an explicit ->disk backpointer to the request_queue

-Andrea

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWRUBxS0hGGDkeU4%40arighi-desktop.
