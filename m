Return-Path: <kasan-dev+bncBCMIZB7QWENRB67R22BQMGQEYDFVZ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 46F1235E2DA
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Apr 2021 17:30:05 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id m15sf3183304pfh.4
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Apr 2021 08:30:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618327804; cv=pass;
        d=google.com; s=arc-20160816;
        b=mfDeJaG6qi2EZzTp2fOQ4b3THY7UDQbzIscVBTA7nali2aYRkusKn33xwlv1hedft5
         XKvteUJKEvW6wa68ul5nWn4VKVDzwiIbrbNtpHgLsbF47h2XLe1p+Ex2+WmYu4d5Ynoe
         L/tRthTe9GoEFhwj5imFYUeWsIleY5duYyVkELYURuMRqUPHZlH66QJPbmPcFgpcZoH8
         seicuEZeBhf2AR6/v7DdulGbI6PXhsknIdkMNLLkqE7ExjJ1Cbv4r4uvqrwLY3vgsHAq
         zMoQAFUhwL7kCcUQIJizifhaECk+QLvi5A+mVOgKujsnhmudB8E2aDwo1NuwfQnPky16
         vYfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jifpqyFKG82QiCtpLfmtb4FjBeMrKXc3Ry6s4RVKObY=;
        b=vMYY2LgN7kPFgHgxs/guX5bIaxn8Wo8inQxaXMbyN65Lq6ZH5E/EmQJkjmg+DJz4Yg
         QFK1hvTmHXfL/BLqYVEKfP3AJ78z3Rm0SlgCzJVDQ6svG3NypGSdRITU6MymoYZRDQnG
         j7tbDAitMEnT8tFm85o4B6ooEvKkZc+UWSqV7iRZzGN/LZNDPzJRE+YwyjVamw1yQ0aX
         5uhJLkOSIjo/VdTMsxL08FGwAWQfqr79ToVi9SoblmlPu2rwh8Jw1fQFQRmdIdxGeTiO
         /7oG992qt03AYMQuz6sBxx0VjJP/nT8rDzHQY+UZ51hUrZ/NsfBxAdaTo9aqKvoB6KRG
         R0+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tsaXa40x;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jifpqyFKG82QiCtpLfmtb4FjBeMrKXc3Ry6s4RVKObY=;
        b=PEsRpswKtrqU6uu4yf1NEbfDwuGLz8bfjjqKQ9Y79AVcv9wYMoBF9p7MOQ5Ipx7pCm
         43wCD0uKWISm6RYHN/5VDIu5G/RQK7C5vG+o2YZl5bJN+rDb99hPjF3+1iH3V61Dxt6k
         EvaLKNw6we51WFl1FlKjOxaRN+yQpbJDtaXSavT601n1f5DkVqIzPKs0AXUHRmnGRYdF
         gNyjTQGgDzWEpGp9cPFbE2uSp35x0LNUgDvKekwDsKFgjED3/dTMsukV6yYqax0ojLvf
         1ozhU4qY4+Ozbb2D8IjuOAahmivfCC57ZeJj/ASSitkoCrD+NrIZ++/RxLcV9NXC1Sja
         j5pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jifpqyFKG82QiCtpLfmtb4FjBeMrKXc3Ry6s4RVKObY=;
        b=YI0fFygLq9kqNEc0mUIC5iHpSB/yMDASE9ykq3m3FVQ/A5yupw9x/ZwZSULCz3VUKm
         PeTEeaHCZEsrAjKilB1ORTQxuEbod6CTqExxQhXsK//B/YjMQJh833UW/eAOV6gQT2Lq
         xxtMyeyLyLZHB1vMe1WXV5Iiszy4DRyIudra1+fHBbDo3t7W9kWAKDcb/+f/udXbOyB7
         LvC0znftkIBW6Lelc/M/UhNIpAmt5kR0kndvAK2A++5Jbg6YEJFUIg5ZDvI+CCV9MDDe
         z0q0DNNl6XUcrnLW3lMT6sZh1MuTdFnDIJneHk6lbR1ed269r6Mx+VVD1jc1Lhd65SOB
         7CfA==
X-Gm-Message-State: AOAM531mFQI5JQDJ0ymMT8YsrRq4YknnY3KP16hjeVpzLS5Cwr8G0qhW
	ynmAr5xlgAeb4Q2XIjgP/Ho=
X-Google-Smtp-Source: ABdhPJwAJD+Zo8Wod8MT2XZrSJMloWs5x3T87O1fEb1SH6Y8BDq2jwFM38X4u2vVw8eS6viIMmKdzQ==
X-Received: by 2002:a17:902:7246:b029:e6:78c4:48d8 with SMTP id c6-20020a1709027246b02900e678c448d8mr33552191pll.18.1618327804032;
        Tue, 13 Apr 2021 08:30:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:144:: with SMTP id 62ls9771775plb.11.gmail; Tue, 13
 Apr 2021 08:30:03 -0700 (PDT)
X-Received: by 2002:a17:902:e74f:b029:ea:f2b5:1add with SMTP id p15-20020a170902e74fb02900eaf2b51addmr4022493plf.29.1618327803371;
        Tue, 13 Apr 2021 08:30:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618327803; cv=none;
        d=google.com; s=arc-20160816;
        b=xJtyxmNs2UjCswuT4qF/bmUKy+wMG9RCQFNsc9iK2o5lkaU4B31UAUjxURlgvInGBx
         R/ux2XPvwWh8luTBXR2lEiyk9nIR6AdvQm9x6IaPNdMEcC7GF9i1OA4e8/gSV1QdQwsr
         89sau2CMZ/fTMUaSczVkhKWhbum2MeR6QGK2kLmzNv8Nt4n94/Efv01V3AyMflFX7xO9
         4ehlD/TeNiDXD0qpcoM5FL+Wu+amq8W59J/+oiPTFTiVvSKoAS8ELVPSyOaO5jqvp8AF
         QMuWaR6f2vCWjAKr3Gu2e02QffaDQbiBYnp9W2EiJZijQZS9qZW0mHwC7cfqt0pQf16R
         aD0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=geviKhSpp//SLXloa5I/OkRgIMxwnyZYsap+HJuZfKg=;
        b=nenAP5xSmDnxqWIZ0p2nhJSmwYY361ODsIgP3PTKUDN8eK2SmOuWjHMcznj1mIZU2J
         ifViMVcvBa0DaI6MFfqSQGZxl8+8oCgIbAr0GJLqrMXIYERvr7qHYNmC41L8Hw9v3j8S
         aKLwGq/01go3GHskLQrDhevgid+Af4pU/ONW5s5y2gzZmQWT4wx4CaakXW1vdtFkmmHL
         zOAcnhOXoV1wEgba7dChrIV1Zgh44fJBqxRJjDNPVex4JzdIbzVnPBIvQAMPPUjmBHts
         pCC+oBPBYJTJnFdTu+b8/BcKs21IM9PizGZBMLcRgvzr1IwoMNL/WJPFFejMGFvM+JA3
         nzGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tsaXa40x;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id j184si1061548pfb.1.2021.04.13.08.30.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Apr 2021 08:30:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id u8so12978586qtq.12
        for <kasan-dev@googlegroups.com>; Tue, 13 Apr 2021 08:30:03 -0700 (PDT)
X-Received: by 2002:ac8:768c:: with SMTP id g12mr15536745qtr.67.1618327802617;
 Tue, 13 Apr 2021 08:30:02 -0700 (PDT)
MIME-Version: 1.0
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
In-Reply-To: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Apr 2021 17:29:51 +0200
Message-ID: <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=tsaXa40x;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835
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

On Tue, Apr 6, 2021 at 10:26 AM Zhang, Qiang <Qiang.Zhang@windriver.com> wr=
ote:
>
> Hello everyone
>
> In RT system,   after  Andrew test,   found the following calltrace ,
> in KASAN, we record callstack through stack_depot_save(), in this functio=
n, may be call alloc_pages,  but in RT, the spin_lock replace with
> rt_mutex in alloc_pages(), if before call this function, the irq is disab=
led,
> will trigger following calltrace.
>
> maybe  add array[KASAN_STACK_DEPTH] in struct kasan_track to record calls=
tack  in RT system.
>
> Is there a better solution =EF=BC=9F

Hi Qiang,

Adding 2 full stacks per heap object can increase memory usage too much.
The stackdepot has a preallocation mechanism, I would start with
adding interrupts check here:
https://elixir.bootlin.com/linux/v5.12-rc7/source/lib/stackdepot.c#L294
and just not do preallocation in interrupt context. This will solve
the problem, right?


> Thanks
> Qiang
>
> BUG: sleeping function called from invalid context at kernel/locking/rtmu=
tex.c:951
> [   14.522262] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 640=
, name: mount
> [   14.522304] Call Trace:
> [   14.522306]  dump_stack+0x92/0xc1
> [   14.522313]  ___might_sleep.cold.99+0x1b0/0x1ef
> [   14.522319]  rt_spin_lock+0x3e/0xc0
> [   14.522329]  local_lock_acquire+0x52/0x3c0
> [   14.522332]  get_page_from_freelist+0x176c/0x3fd0
> [   14.522543]  __alloc_pages_nodemask+0x28f/0x7f0
> [   14.522559]  stack_depot_save+0x3a1/0x470
> [   14.522564]  kasan_save_stack+0x2f/0x40
> [   14.523575]  kasan_record_aux_stack+0xa3/0xb0
> [   14.523580]  insert_work+0x48/0x340
> [   14.523589]  __queue_work+0x430/0x1280
> [   14.523595]  mod_delayed_work_on+0x98/0xf0
> [   14.523607]  kblockd_mod_delayed_work_on+0x17/0x20
> [   14.523611]  blk_mq_run_hw_queue+0x151/0x2b0
> [   14.523620]  blk_mq_sched_insert_request+0x2ad/0x470
> [   14.523633]  blk_mq_submit_bio+0xd2a/0x2330
> [   14.523675]  submit_bio_noacct+0x8aa/0xfe0
> [   14.523693]  submit_bio+0xf0/0x550
> [   14.523714]  submit_bio_wait+0xfe/0x200
> [   14.523724]  xfs_rw_bdev+0x370/0x480 [xfs]
> [   14.523831]  xlog_do_io+0x155/0x320 [xfs]
> [   14.524032]  xlog_bread+0x23/0xb0 [xfs]
> [   14.524133]  xlog_find_head+0x131/0x8b0 [xfs]
> [   14.524375]  xlog_find_tail+0xc8/0x7b0 [xfs]
> [   14.524828]  xfs_log_mount+0x379/0x660 [xfs]
> [   14.524927]  xfs_mountfs+0xc93/0x1af0 [xfs]
> [   14.525424]  xfs_fs_fill_super+0x923/0x17f0 [xfs]
> [   14.525522]  get_tree_bdev+0x404/0x680
> [   14.525622]  vfs_get_tree+0x89/0x2d0
> [   14.525628]  path_mount+0xeb2/0x19d0
> [   14.525648]  do_mount+0xcb/0xf0
> [   14.525665]  __x64_sys_mount+0x162/0x1b0
> [   14.525670]  do_syscall_64+0x33/0x40
> [   14.525674]  entry_SYSCALL_64_after_hwframe+0x44/0xae
> [   14.525677] RIP: 0033:0x7fd6c15eaade

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw%40mail.gmai=
l.com.
