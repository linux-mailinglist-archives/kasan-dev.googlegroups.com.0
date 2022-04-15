Return-Path: <kasan-dev+bncBCXKTJ63SAARBSXQ4SJAMGQEE6IEDII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 22D36502743
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Apr 2022 11:18:04 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id l11-20020a170902f68b00b00158a978a3a8sf1433477plg.19
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Apr 2022 02:18:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650014282; cv=pass;
        d=google.com; s=arc-20160816;
        b=GL0nyfUNFPH/2Q+zTTylZewYUg18gxqHVqaIjWt0YwQXCsJaPKC3h/66u93HVr7dl1
         evqe4kivcS4Zo0qjRoj4W37izG6nVgy243MERn6Pt92PgtKUa6KRbSMQqNRn/FKBZ7XS
         Ug9AvXm818VagVM51mrITKAYJpDNnfJqINFZXEEoHaB5NLZ8NegIdRA1EcolY/sG9xrp
         BUL12aLaNfuAs450y6+vt4RgCd20VOm78ecR9JQldF6YxvvgLQ1MDRst3CgNUtvvd6yC
         9WUXAT7zwM82h9HgNAACDAlSZtK8YJMZ2m8f0/n+713Gt8cQbFXSnj2ggTO8OHrVgfSE
         +ACA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z0rfjAcY8yBFzlSrvMoMole2y1OtMNmnDb6kLi7cilk=;
        b=Emv89YholLS0v71taZh9rZEzT9QEyvtcrGG/7Fs9VRUQI9Xcllr14U/N1MAXmBTxRS
         fvOjcJCuJ1r+13VCOc2qmi5kDAygaDTjzguAeXqHUrMN8keWTdAKQaz3JwbxzxDGlXsk
         yJ2PwlmQJQjobJq7KDrf5dfWgw/xWSAqQP8hUT1MfaVWBGxSmDLnE4AP4yybUGykG4Bl
         opVxSaOtxSx2U3wBmC2LBSCJCPUqP+tpZ1IGjZT07KCyxrxDwnFNYvyJDXHxMEytGCG0
         vkF3CmAtHMhC1AFM7YuDXIBEhtXJ0odisLNQ6CeBj9vpG5EMXR397N9G/jpF6K4vvniJ
         fqUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=p6h5RxQz;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z0rfjAcY8yBFzlSrvMoMole2y1OtMNmnDb6kLi7cilk=;
        b=SqWyZxmMYId9sNCY7EzY4lMhW0YH+pgNkbICh1/W6GjALCg83BWbQr/79agxGsu4q1
         R7GCdBaoCXwvZZnRvrsbPlLL9lGA1rX4kUI0Bsm9X8kIwyFpvvQPwt7HvyrWNy6eZw7i
         XUXa2IUJt8houAVDe7hQYx8Bbf81YudWd3QONtIr2iCLGPYXGrHPzBrJzMfSCeC4a8Mi
         Kw8Fc/hLpFQEo8qjReLHghY5yVlnKxIZWW2VQ7/7YEsPP8/Tngm+OgLiJMHwwmwMKVnZ
         OZqEHWjCBjiCjEYQzg2KXkOY6AJ2snOVJvTE/BG61WaCdT2e1jSCV+hLe2tXdkUqTM6o
         1dug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z0rfjAcY8yBFzlSrvMoMole2y1OtMNmnDb6kLi7cilk=;
        b=VXzHXga85N0qik7P0LNkNlPALfxyTRgtjDlAGuYzEA5HfzGKKreUx7dhwVgwW30bZb
         6vX5dBdGHeWosEbYPl67BSp+EJltwGzTar/ppED22ZZsjMKkfnpqIQhm24I4DMWXEqIO
         wNOyvh0SEYcy3s/U0vpIw3CIgh2DWyvaxnkcgleZbeqOoTy9bsdjQrbpVfBaZxf1/Kqs
         +Gkv3117v98eNv3TkU76VahY+e7y0R7Cmzx+qflkl5JJ2/4VU71FhVGPQFq5eBX2GOPw
         qMR5jGPNgompZsEfILSuw2ZRHkhgsdE8H9tEwgAuyAjmcf1egoF68Lut0P3FjmWspXEn
         BWVA==
X-Gm-Message-State: AOAM533gqeo0cTUZ7jec1FEMOf/dsKONMMq8GTMBJHCYm7SHHUtqnjcB
	L6moJEvtN4poHf5JZsdnA7I=
X-Google-Smtp-Source: ABdhPJxQgEm4PefRj0E/v8b++U4rnfRn6diwVCD5n1PNyCfP4gkutNyX3xfLI1O15+Y+5pzl1iihZQ==
X-Received: by 2002:a65:57cc:0:b0:384:3370:e161 with SMTP id q12-20020a6557cc000000b003843370e161mr5596992pgr.364.1650014282110;
        Fri, 15 Apr 2022 02:18:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2282:b0:158:7966:f16a with SMTP id
 b2-20020a170903228200b001587966f16als8021573plh.3.gmail; Fri, 15 Apr 2022
 02:18:01 -0700 (PDT)
X-Received: by 2002:a17:902:bc4b:b0:158:a22a:5449 with SMTP id t11-20020a170902bc4b00b00158a22a5449mr11554344plz.50.1650014281498;
        Fri, 15 Apr 2022 02:18:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650014281; cv=none;
        d=google.com; s=arc-20160816;
        b=r0ysGGu8yQvAqmTmpMBPjBN0KB2GdpDVMun3fWqPUj1qHTHZPL1zhhtPKXMgjuceEg
         KDPt/oKU+tGsZXCEqax7r8q+Z8uKAZ2rYF2mGx2QBBtr2WcPim6798uzH3LPfx81yAGN
         +Y3MOtVQ+j3aATgfT4cWe6AtLNxArmDPSaxHWYjaXeTnbtdzXSYMkX0Ns3eoKClItcWb
         s9Pp6M1aFtWOXjhqjxFXXZKi6og6mME2UUO2qN9vMF0O1QuTNtI5hAXjX/liVn1uoUEN
         GjCV//ZtelFc6rBV+9aKVkvBbI+C22ugGyDyHuoy8HNRJ3efpET7pXYFl9tw1xoKvUTu
         5Ycw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k941AYOO2t7LtokllmOIeH8IQ1ddJzfk+UJa9dbxTPg=;
        b=j9HCWeoXBRVJDFskYYJwq3GSFeFA0h/4fiXudSVqz5lij0iiY/O1UBOu+ot7FM/HiC
         zCi1WjXDhQhYV44bWAbwsSS+UyBOjKTI3+0jNpimRiPFGTYDATt1vLPpqFF6JIIds0dN
         yzfz850SHj4M2qWof6enYQ/Ew8eU9B6lf4awJ7d+ePGopurw6z4R9pgdwLZXKlFH1s1Y
         kt6V4FQfT4SvaK7C/hZmfhj88Rh8TbAC6BS6qy/cHaB2ozy8W9x+MgDwVZJygH2zSBwN
         q97/17wcSmYyHEklGHYI6FxG7WGHDD2gT0r5zq3xuDmH7uP66UjPS9UPEt9FcMLY1Xew
         YTjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=p6h5RxQz;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id j126-20020a62c584000000b004f6fe5417cesi124095pfg.2.2022.04.15.02.18.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Apr 2022 02:18:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id i196so2472806ioa.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Apr 2022 02:18:01 -0700 (PDT)
X-Received: by 2002:a05:6638:4e:b0:328:58ef:944d with SMTP id
 a14-20020a056638004e00b0032858ef944dmr438873jap.259.1650014281007; Fri, 15
 Apr 2022 02:18:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220401182512.249282-1-nogikh@google.com> <20220414142457.d22ce3a11920dc943001d737@linux-foundation.org>
 <Ylkr2xrVbhQYwNLf@elver.google.com>
In-Reply-To: <Ylkr2xrVbhQYwNLf@elver.google.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Apr 2022 11:17:50 +0200
Message-ID: <CANp29Y4ZkN92wnaWew65L_K5o6WZFXEFCVSQiVhDFkY_fKUB=g@mail.gmail.com>
Subject: Re: [PATCH v3] kcov: don't generate a warning on vm_insert_page()'s failure
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Taras Madan <tarasmadan@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=p6h5RxQz;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d32 as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Marco, thank you very much for these answers!
I was unfortunately a bit overloaded lately, so was postponing a reply
(given that the patch is very good to have, but not urgent).

On Fri, Apr 15, 2022 at 10:25 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, Apr 14, 2022 at 02:24PM -0700, Andrew Morton wrote:
> > On Fri,  1 Apr 2022 18:25:12 +0000 Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > > vm_insert_page()'s failure is not an unexpected condition, so don't do
> > > WARN_ONCE() in such a case.
> > >
> > > Instead, print a kernel message and just return an error code.
> >
> > (hm, I thought I asked this before but I can't find it)
> >
> > Under what circumstances will this failure occur?
>
> It looks like syzbot was able to generate an OOM situation:
>
>  | [  599.515700][T23028] oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=syz1,mems_allowed=0-1,oom_memcg=/syz1,task_memcg=/syz1,task=syz-executor.1,pid=23028,uid=0
>  | [  599.537757][T23028] Memory cgroup out of memory: Killed process 23028 (syz-executor.1) total-vm:56816kB, anon-rss:436kB, file-rss:8888kB, shmem-rss:48kB, UID:0 pgtables:88kB oom_score_adj:1000
>  | [  599.615664][T23028] ------------[ cut here ]------------
>  | [  599.652858][T23028] vm_insert_page() failed
>  | [  599.662598][T23028] WARNING: CPU: 0 PID: 23028 at kernel/kcov.c:479 kcov_mmap+0xbe/0xe0
>  | [  599.900577][T23028] Modules linked in:
>  | [  599.904480][T23028] CPU: 1 PID: 23028 Comm: syz-executor.1 Tainted: G        W         5.17.0-syzkaller-12964-gccaff3d56acc #0
>  | [  599.956099][T23028] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
>  | [  600.092674][T23028] RIP: 0010:kcov_mmap+0xbe/0xe0
>  | [  600.097559][T23028] Code: 48 81 c3 00 10 00 00 49 39 dc 77 c9 31 c0 5b 5d 41 5c 41 5d 41 5e c3 48 c7 c7 e9 4a 5b 8b c6 05 5a fc 28 0c 01 e8 bd c6 a0 07 <0f> 0b eb d2 4c 89 f7 e8 66 28 e8 07 b8 ea ff ff ff eb d1 66 66 2e
>  | [  600.117319][T23028] RSP: 0018:ffffc9000c1cfc30 EFLAGS: 00010282
>  | [  600.135794][T23028] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000
>  | [  600.163986][T23028] RDX: ffff888051f40000 RSI: ffffffff815fce18 RDI: fffff52001839f78
>  | [  600.188615][T23028] RBP: ffff88804fc6e210 R08: 0000000000000000 R09: 0000000000000000
>  | [  600.196616][T23028] R10: ffffffff815f77ee R11: 0000000000000000 R12: 0000000000200000
>  | [  600.214229][T23028] R13: ffff8880646c2500 R14: ffff8880646c2508 R15: ffff88804fc6e260
>  | [  600.252864][T23028] FS:  00005555570e4400(0000) GS:ffff8880b9c00000(0000) knlGS:0000000000000000
>  | [  600.283249][T23028] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>  | [  600.335749][T23028] CR2: 0000001b2c436000 CR3: 000000004ef16000 CR4: 00000000003506f0
>  | [  600.390781][T23028] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>  | [  600.430312][T23028] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000600
>  | [  600.441698][T23028] Call Trace:
>  | [  600.447877][T23028]  <TASK>
>  | [  600.451890][T23028]  mmap_region+0xba5/0x14a0
>  | [  600.486043][T23028]  do_mmap+0x863/0xfa0
>  | [  600.490544][T23028]  vm_mmap_pgoff+0x1b7/0x290
>  | [  600.505607][T23028]  ksys_mmap_pgoff+0x40d/0x5a0
>  | [  600.522165][T23028]  do_syscall_64+0x35/0x80
>  | [  600.526655][T23028]  entry_SYSCALL_64_after_hwframe+0x44/0xae
>  | [  600.532936][T23028] RIP: 0033:0x7f5be4889092
>  | [  600.537407][T23028] Code: 00 00 00 00 00 0f 1f 00 41 f7 c1 ff 0f 00 00 75 27 55 48 89 fd 53 89 cb 48 85 ff 74 3b 41 89 da 48 89 ef b8 09 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 66 5b 5d c3 0f 1f 00 48 c7 c0 b8 ff ff ff 64
>  | [  600.560042][T23028] RSP: 002b:00007fffde76b318 EFLAGS: 00000246 ORIG_RAX: 0000000000000009
>  | [  600.569079][T23028] RAX: ffffffffffffffda RBX: 0000000000000001 RCX: 00007f5be4889092
>  | [  600.577107][T23028] RDX: 0000000000000003 RSI: 0000000000200000 RDI: 0000000000000000
>  | [  600.587064][T23028] RBP: 0000000000000000 R08: 00000000000000db R09: 0000000000000000
>  | [  600.596119][T23028] R10: 0000000000000001 R11: 0000000000000246 R12: 00007f5be499c1dc
>  | [  600.604977][T23028] R13: 0000000000000003 R14: 00007f5be499c1d0 R15: 0000000000000032
>  | [  600.613026][T23028]  </TASK>
>  | [  600.616066][T23028] Kernel panic - not syncing: panic_on_warn set ...
>
> > Why do we emit a message at all?  What action can the user take upon
> > seeing the message?
>
> The message is mainly for the benefit of the test log, in this case the
> fuzzer's log so that humans inspecting the log can figure out what was
> going on. KCOV is a testing tool, so I think being a little more chatty
> when KCOV unexpectedly is about to fail will save someone debugging
> time.
>
> We don't want the WARN, because it's not a kernel bug that syzbot should
> report, and failure can happen if the fuzzer tries hard enough (as
> above).
>
> > Do we have a Fixes: for this?
>
> The WARN was moved with b3d7fe86fbd0 ("kcov: properly handle subsequent
> mmap calls"), so that'd be the only commit a backport would cleanly
> apply to.
>
> > From the info provided thus far I'm unable to determine whether a
> > -stable backport is needed.  What are your thoughts on this?
>
> The main problem is it only makes fuzzers try to report this as a bug
> (which it is not). Backporting to kernels that have b3d7fe86fbd0 would
> be reasonable, but wouldn't bother creating backports for older kernels.
>
> Thanks,
> -- Marco

I agree with all these points and don't really have anything to add.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y4ZkN92wnaWew65L_K5o6WZFXEFCVSQiVhDFkY_fKUB%3Dg%40mail.gmail.com.
