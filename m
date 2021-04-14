Return-Path: <kasan-dev+bncBCMIZB7QWENRBMNJ3KBQMGQEZXFEEZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF44035EE01
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 09:07:30 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id v5sf402837pgj.7
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 00:07:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618384049; cv=pass;
        d=google.com; s=arc-20160816;
        b=ihGmawED60REAe7J5b4H4miOmXhEFHju4/+YRCAlARbc3jWAEU2wPbwuj6EW8opu81
         1jsMUBk8jLpDkNWvQLh/K6lKtuxHzVXeiFYj03Sla8tgi/Csj2hjj60v5miCdGGM4yjy
         sVW6aP8jeknkcHn/mAtrSfxK70zBWapRkICLy31vGBRZKnOIbuELEjcdUFkT5ylrAYK/
         pjD5anDgM7F9CLmYBSXxYB2rvH4udtNFVS17TdbZ8MTQWqEoTl5a1d+fMmRD1DKtyHBX
         tMpeCgH8V+x1nKIXi+lVJSttxs5wubZsZErs5+LvhUQ09CgkZp3dnsjHBXyh77yVAMdd
         iCuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DDzV9FysJgo2/PafjKg4ip0AN1COplowNGlspgbc4qU=;
        b=qLbTrRj3Haepd/xtVHmWjzGRL0nosmdeWk00dL2CdiVCCG8KZPN7/E0EVkldYObaZk
         +AKlGz9BsIyF6JJk7cOesj2EvMSbZ8uG6Kw8mKwBelietcy+KtiW9M/XUTqy+jFDRHe3
         r4DoR8+hiZVk8lx3+JQDtiy1TVZyI+a85IXev99POjQLLm1DlOlb/QpFp0esIXr7MsGS
         iOyymu65OMWYxxoXIk6qtFQ2k15gzoVn5DaVszme+HJtrjpYP0dEpXsN/Ja0XGQzkSzB
         t1BLs3gfSJ6/n/N0IIJX1/rATTxLDdTtN3gycibD+h25bik0uhwDIn6ZJJbGrnB9mJLy
         VJgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Srj6zP6S;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DDzV9FysJgo2/PafjKg4ip0AN1COplowNGlspgbc4qU=;
        b=QFufmKjR4m0bWv1iqwppj0Fy8N/+KJsjYhJwMI99zWKv0m5zyLGbBU3/dEL5zXzqEx
         x44jGWumUe79QkKWQ59PlY7juTFXNZDzXFaDN6Pew+OheQReFrMd2PxFvbF5ljyxJR+f
         yrqmirQJbRemvXfz4wKxAsk/NE/2HphTRCd8FvybyJB96q4+/tg4jp2WaVLDxfLCF/B7
         IJsg6zjR8XDNcMFPhNJMC35gfk+nJVU5Oypx22vpc4aBeuJR3EWUCFa/9F3oalWMH5rK
         8mMS7IbmBIrxUTL2nBoq3urzFamElhNgkWpG9bNk8kxNK0IkuT6tCUzgBVCXnrMHxTFU
         35Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DDzV9FysJgo2/PafjKg4ip0AN1COplowNGlspgbc4qU=;
        b=F58e7VPgq9RNaEVoubD2SH5WY4jwlnjqc64HbDWJo7mR10F3NTHvWOOeOiGwM4dieH
         auQixWPymufmHPjmIMlpKiSDEhEYtnWzK2/9zp8VRJJgQR4t+bPMLDYYGTGITYyPwjlm
         MCHVVbzfH7jMSYD1/WXXSvUlqLJubK/9HE1djucdCTaXMCfn82J5YoM86Em7puPbGcnY
         Jb5G41Z+St064X3poh/gO90EGzLvPUDZPLOcJIoW44iiEe7fW/EQRdAvHHIkQ5045bh/
         oyZwXBGg8HMpPNg9pYJKlNJkvOJKsHtx2uYotexmCaOm1NBqjvAQi9NHRBovJnLJpdfy
         07BQ==
X-Gm-Message-State: AOAM531Xziz6PRoLGCdlHqyDuADWDi+w8BX8SOtF+jJIoAANrBnK+M1j
	CBnwi9mLWVZiHmeMkMCeU9g=
X-Google-Smtp-Source: ABdhPJyEeeEPDaJIdoNbh5hIby07H6uEnt3kE7GLnVUHbURNIHFrJZaxuLZ6M3rUPYbkuPeCbMPMpg==
X-Received: by 2002:a63:64c6:: with SMTP id y189mr2909970pgb.267.1618384049324;
        Wed, 14 Apr 2021 00:07:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4853:: with SMTP id x19ls674048pgk.0.gmail; Wed, 14 Apr
 2021 00:07:28 -0700 (PDT)
X-Received: by 2002:a63:1f06:: with SMTP id f6mr26335832pgf.441.1618384048774;
        Wed, 14 Apr 2021 00:07:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618384048; cv=none;
        d=google.com; s=arc-20160816;
        b=AZh47QyTObrNFw0dVv62VkMzREa0W9Oq2LD8LIuDfoikQYyGoM1HTz06dcwstABD4O
         YjI78oAeFmB5sBBpNmMFt6HuZn2/PlBgKs7jyO+Gs+hz56BG41sF/0DBnStmKC/oNtb6
         ef8IzbO2HtV0hodA8gHKgGxCned0r+t2SIiH2hb7HBr+w4Z7/qswknFbn/WTzMQF0R2o
         dhqBWGQQQMOQKN+xkGAN52VMAgh2ETmv5OR+9VOOx/lzxro24pErgmnXNuK3e+lHy//B
         SXhpvMDKqt1GZVEcu7vbplu7qLTocrpmbDwcWOoDvkfqsVu1nhWP5RjVqaw9hp93h+gk
         +Jfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=P6hiw8keT+mJ14/6B/ZNNtm4SRsN+Z+zw9UvJ6sbBIE=;
        b=bAfz5z3APTLHM7rQvlZX6V9Q3VHwDANZ+C7nBU1mgIg0vCIfoQ06MSWvBVYzhGAT9C
         xQl5vj/w8XhFrvCxtXzxjLR13k9Xnse6HjffHZ9Lc5fv7EdKNJtOU/Ztvsj+HmSZMHdh
         hf/UiPy4OJFONBkMjcIRq6y6gZbndu70nrbyaKUhCLa2DgocPihO7RaRRpp5FEUG+xPU
         3F6Aai7Rx8o1tCAxmwaK69kIUEmaII0UM6UaIkUojIibYc0epUnPqvV/501rJw6FcwL/
         hFl6sIDWO5rxiTk5iT4x0DrxL9wF9hxquo9ODdr/HemrK4JdgKXWT7Cz8X4MsGMd+8+5
         KGqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Srj6zP6S;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id t19si345674pjq.3.2021.04.14.00.07.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 00:07:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id y12so14754977qtx.11
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 00:07:28 -0700 (PDT)
X-Received: by 2002:ac8:110d:: with SMTP id c13mr33564230qtj.337.1618384047727;
 Wed, 14 Apr 2021 00:07:27 -0700 (PDT)
MIME-Version: 1.0
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
 <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com> <DM6PR11MB420213907FE92BF6B6B5EB44FF4E9@DM6PR11MB4202.namprd11.prod.outlook.com>
In-Reply-To: <DM6PR11MB420213907FE92BF6B6B5EB44FF4E9@DM6PR11MB4202.namprd11.prod.outlook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Apr 2021 09:07:16 +0200
Message-ID: <CACT4Y+Z5i+MOc+in9DuFj0b6cyyuHur5fpgu4e9-_6i4Luiygw@mail.gmail.com>
Subject: Re: Question on KASAN calltrace record in RT
To: "Zhang, Qiang" <Qiang.Zhang@windriver.com>
Cc: Andrew Halaney <ahalaney@redhat.com>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Srj6zP6S;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Apr 14, 2021 at 8:58 AM Zhang, Qiang <Qiang.Zhang@windriver.com> wr=
ote:
> ________________________________________
> =E5=8F=91=E4=BB=B6=E4=BA=BA: Dmitry Vyukov <dvyukov@google.com>
> =E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2021=E5=B9=B44=E6=9C=8813=E6=97=A5 =
23:29
> =E6=94=B6=E4=BB=B6=E4=BA=BA: Zhang, Qiang
> =E6=8A=84=E9=80=81: Andrew Halaney; andreyknvl@gmail.com; ryabinin.a.a@gm=
ail.com; akpm@linux-foundation.org; linux-kernel@vger.kernel.org; kasan-dev=
@googlegroups.com
> =E4=B8=BB=E9=A2=98: Re: Question on KASAN calltrace record in RT
>
> [Please note: This e-mail is from an EXTERNAL e-mail address]
>
> On Tue, Apr 6, 2021 at 10:26 AM Zhang, Qiang <Qiang.Zhang@windriver.com> =
wrote:
> >
> > Hello everyone
> >
> > In RT system,   after  Andrew test,   found the following calltrace ,
> > in KASAN, we record callstack through stack_depot_save(), in this funct=
ion, may be call alloc_pages,  but in RT, the spin_lock replace with
> > rt_mutex in alloc_pages(), if before call this function, the irq is dis=
abled,
> > will trigger following calltrace.
> >
> > maybe  add array[KASAN_STACK_DEPTH] in struct kasan_track to record cal=
lstack  in RT system.
> >
> > Is there a better solution =EF=BC=9F
>
> >Hi Qiang,
> >
> >Adding 2 full stacks per heap object can increase memory usage too >much=
.
> >The stackdepot has a preallocation mechanism, I would start with
> >adding interrupts check here:
> >https://elixir.bootlin.com/linux/v5.12-rc7/source/lib/stackdepot.c#L294
> >and just not do preallocation in interrupt context. This will solve
> >the problem, right?
>
> It seems to be useful,  however, there are the following situations
> If there is a lot of stack information that needs to be saved in  interru=
pts,  the memory which has been allocated to hold the stack information is =
depletion,   when need to save stack again in interrupts,  there will be no=
 memory available .

Yes, this is true. This also true now because we allocate with
GFP_ATOMIC. This is deliberate design decision.
Note that a unique allocation stack is saved only once, so it's enough
to be lucky only once per stack. Also interrupts don't tend to
allocate thousands of objects. So I think all in all it should work
fine in practice.
If it turns out to be a problem, we could simply preallocate more
memory in RT config.

> Thanks
> Qiang
>
>
> > Thanks
> > Qiang
> >
> > BUG: sleeping function called from invalid context at kernel/locking/rt=
mutex.c:951
> > [   14.522262] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 6=
40, name: mount
> > [   14.522304] Call Trace:
> > [   14.522306]  dump_stack+0x92/0xc1
> > [   14.522313]  ___might_sleep.cold.99+0x1b0/0x1ef
> > [   14.522319]  rt_spin_lock+0x3e/0xc0
> > [   14.522329]  local_lock_acquire+0x52/0x3c0
> > [   14.522332]  get_page_from_freelist+0x176c/0x3fd0
> > [   14.522543]  __alloc_pages_nodemask+0x28f/0x7f0
> > [   14.522559]  stack_depot_save+0x3a1/0x470
> > [   14.522564]  kasan_save_stack+0x2f/0x40
> > [   14.523575]  kasan_record_aux_stack+0xa3/0xb0
> > [   14.523580]  insert_work+0x48/0x340
> > [   14.523589]  __queue_work+0x430/0x1280
> > [   14.523595]  mod_delayed_work_on+0x98/0xf0
> > [   14.523607]  kblockd_mod_delayed_work_on+0x17/0x20
> > [   14.523611]  blk_mq_run_hw_queue+0x151/0x2b0
> > [   14.523620]  blk_mq_sched_insert_request+0x2ad/0x470
> > [   14.523633]  blk_mq_submit_bio+0xd2a/0x2330
> > [   14.523675]  submit_bio_noacct+0x8aa/0xfe0
> > [   14.523693]  submit_bio+0xf0/0x550
> > [   14.523714]  submit_bio_wait+0xfe/0x200
> > [   14.523724]  xfs_rw_bdev+0x370/0x480 [xfs]
> > [   14.523831]  xlog_do_io+0x155/0x320 [xfs]
> > [   14.524032]  xlog_bread+0x23/0xb0 [xfs]
> > [   14.524133]  xlog_find_head+0x131/0x8b0 [xfs]
> > [   14.524375]  xlog_find_tail+0xc8/0x7b0 [xfs]
> > [   14.524828]  xfs_log_mount+0x379/0x660 [xfs]
> > [   14.524927]  xfs_mountfs+0xc93/0x1af0 [xfs]
> > [   14.525424]  xfs_fs_fill_super+0x923/0x17f0 [xfs]
> > [   14.525522]  get_tree_bdev+0x404/0x680
> > [   14.525622]  vfs_get_tree+0x89/0x2d0
> > [   14.525628]  path_mount+0xeb2/0x19d0
> > [   14.525648]  do_mount+0xcb/0xf0
> > [   14.525665]  __x64_sys_mount+0x162/0x1b0
> > [   14.525670]  do_syscall_64+0x33/0x40
> > [   14.525674]  entry_SYSCALL_64_after_hwframe+0x44/0xae
> > [   14.525677] RIP: 0033:0x7fd6c15eaade

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZ5i%2BMOc%2Bin9DuFj0b6cyyuHur5fpgu4e9-_6i4Luiygw%40mail.=
gmail.com.
