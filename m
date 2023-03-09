Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL6TVGQAMGQEWY7JO2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 571656B3203
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 00:20:17 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-17714741d9dsf1858122fac.4
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 15:20:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678404016; cv=pass;
        d=google.com; s=arc-20160816;
        b=DIEcB0Qc020VoyssvBQb9BITMbnKOXjBSEYtPNaHwiNiGBeRvJCRWDYHp0sLrq+hd6
         7VbzvBuTrAVZ5SitEPzmXsUnqZtQ3HJbD+hLFVI8XJKmexlCCymbsQXJRO0hh4lZNywI
         Gk+vEwzH91ZhBewmoGXkRkISSS8YbLADrjJ2lsDXfvHVKTK+hYIe8yOv7mkh8HuX9Ftu
         acR7ZMKuvPeNeUJz+ogFdM1PeUVWtJ+ZeEVILwftZqX0YdUEIMB5TtXHSAHXX+T4up77
         uIGQWmGvfrAjYHDxpGb7abUFHygIe3n+n9TSFrYIYsvp1DlHoHp0IeXmdkfh9QAjueCq
         arhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sJKovLeYEUqsrdcpxty2jg9IaW+npYlIy541AMuzcIo=;
        b=jMqjXJVBdKNlylnJawRs5Junpyb+Rjw/m16yD5c4EescaD0Y2G38VbV7AUxji9UncR
         Vtgs2BK11xt4vJjClXjZd4V9RtYrd3mheYlYiLFEVn8R9Hsg+UT2akUXge8u0ZIU8nMe
         PxxQzg4AeX41ShglWfMlyBnxIC3liIfo20yRfqjbnq4on5BNZXvOwrRlJ2PdYbRBRFNU
         r2vjIM7TE8mSu7sDfx3G9yBou1r9SgJUAiPwpElW6cv7skSnHoO64Cg1/A9QMp/llz6o
         DSSAdBgBOVtXTQqy0gQD1P+T1MSLItC1dvAH0XiyCQFLZ2ImGU5DffypDM5vu1FLp60+
         99uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TQ5NV6TQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678404016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sJKovLeYEUqsrdcpxty2jg9IaW+npYlIy541AMuzcIo=;
        b=mupoOOBXVqrcRVzFFUjxC7RPdXOfncIXLcLbIlN9nBH9sSFBwTw99X5oOKkyD0EpJE
         C2matu6nphPXVxZ0gb3dlzPX8yKYMbm9+AsU5BQmCE/sIuZV+B5q0KXV4bbO97qys8H5
         VwGmm2e7OWVATQohHSRrYTBHgTxhl1XrmGmVWFa8YLAV1+w65U2S11dIGKKcYfePCW3K
         iCpW1IZ0+n9qbyh+UT0BjKOAz/+FZeyupCppHdNF8JBc20BTjVlCHwdKgwIXUzfARttQ
         cyd5MCx9g3LX5KQYyIfgEP2qHXs6OQhugWXNomBLAWDM3Mk8teKsjwsFMYNft+SxSgGQ
         kL0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678404016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=sJKovLeYEUqsrdcpxty2jg9IaW+npYlIy541AMuzcIo=;
        b=hWu6hLcYkBEEyIk9xGB5MUB8HUNelGxoRkVw2zHVR+uKyUbFMUyZXwM4KT/NHkLt7d
         44OGXKedwx97CoLDrChUe/AErSFjEzTykAdGQ8RCuD/OgivbIoesi9FFK9xr6lLVO+4B
         QzWSm+wzYkBwj6Ij1YJqOEp5+qYlPWyPMKSdGTCuIIaNRgaU6OwlWLsfbp3FpIU8HTs+
         qK+qLNS3qjsv4UVSlRkENJmQQBnbCp7agqnXS78vfU35OejC2RBi3vgskFtUDPnMDxwS
         onlN0YWb1dLzNfiXjEstEdkZoRAzDwLHklnCCcqX1+amRgE0QcuII+1eN+D9vu4E3Itx
         NFiw==
X-Gm-Message-State: AO0yUKWQLF9RsZQg6JoRPm4xJKcFPtRRMOxH+jc8anGQWoA2b847BsSx
	WBpVOCP1De+Ljfrh4KGhpYg=
X-Google-Smtp-Source: AK7set87ivPIreynqzR0rW9CrwVAIX2CyG9i4GRzS8Z0yWWIZjiyf1WT+4PfXA0ASZ8L0hzmuYIwsg==
X-Received: by 2002:aca:1216:0:b0:383:c688:a8e0 with SMTP id 22-20020aca1216000000b00383c688a8e0mr7974932ois.9.1678404016054;
        Thu, 09 Mar 2023 15:20:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:6b0d:0:b0:525:1c37:858a with SMTP id g13-20020a4a6b0d000000b005251c37858als157481ooc.11.-pod-prod-gmail;
 Thu, 09 Mar 2023 15:20:15 -0800 (PST)
X-Received: by 2002:a4a:1586:0:b0:517:a7d1:9762 with SMTP id 128-20020a4a1586000000b00517a7d19762mr3259946oon.7.1678404015394;
        Thu, 09 Mar 2023 15:20:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678404015; cv=none;
        d=google.com; s=arc-20160816;
        b=JCsryFn0g4Q1hDAcZaPjFMdPIEo4TjeOgKJ5nGAY5SL5NvG63uHHFOCkxbUW9tpYk1
         RPqyPkdCa4V6JgzjmerKfgEfFsu2YxhHI/X5+AMirZcuf+KK0OznMsXWuSnXENuNHmxX
         +ETtCOuP5MpfzZEihkyuXHJic7RYWNGfNCIgMeSoKBg1UJ3jEcnctis00X9i8EVnCeRT
         ap0muENhi8ep2K5xTscgX/9ni9NRH8JTVOUdbQtOMwPWmSNmx2PaWWER6Bi7GKngB6Al
         5UXTqN59g6WUQFWvMON+MKpcd+n7hhEBOmODdCatgzjKWMl2oAKYRYJKWLANxSdMhYe+
         l6Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rnSlv/rmjMDZUxybeJVifkYNGPUHnfVxFIfeq1kf7IY=;
        b=y4CPPYt7O+jDV2aj0Sr5NMHyC7OrBGXcr/4I1st+U5SuSUUDW18dt/yZyKqXsAMXGF
         JA12NgM7T4AJoAIskcUpCFnhNyLA59Qjxhb35/EV/brE3OX3V/U/ggBt5DG5B/dAYV27
         u5j+6I+M7s6robBBUYBFMNOxXdWVcSiMOLDpsNXV1Zr5w9srvx6P6kDFJMTauDInxP5C
         846qerP5USymgsRzeQPzTRcJU2m3D/7nzTSbQOaSejxqpjNb0773vVe7JQuT4QTi3tyR
         Hyq119Q0CsK5p6xHP4UXzGAfvA00ep1hproW5XhMSNGF4Q7LpxsvsHliqXtoPdyiL7Q/
         GzkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TQ5NV6TQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x932.google.com (mail-ua1-x932.google.com. [2607:f8b0:4864:20::932])
        by gmr-mx.google.com with ESMTPS id r65-20020acaa844000000b00383d1b15a2asi25018oie.4.2023.03.09.15.20.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 15:20:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) client-ip=2607:f8b0:4864:20::932;
Received: by mail-ua1-x932.google.com with SMTP id x1so2339766uav.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 15:20:15 -0800 (PST)
X-Received: by 2002:a9f:3001:0:b0:68b:817b:eec8 with SMTP id
 h1-20020a9f3001000000b0068b817beec8mr15421336uab.0.1678404014773; Thu, 09 Mar
 2023 15:20:14 -0800 (PST)
MIME-Version: 1.0
References: <20230309101752.2025459-1-elver@google.com> <510ecaa9-508c-4f85-b6aa-fc42d2a96254@paulmck-laptop>
In-Reply-To: <510ecaa9-508c-4f85-b6aa-fc42d2a96254@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Mar 2023 00:19:35 +0100
Message-ID: <CANpmjNOGbSsXLqM59HQJ04T4ueMWjQjzpt4QqyKpne=KbHWREg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Avoid READ_ONCE() in read_instrumented_memory()
To: paulmck@kernel.org
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Haibo Li <haibo.li@mediatek.com>, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TQ5NV6TQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as
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

On Thu, 9 Mar 2023 at 23:08, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Mar 09, 2023 at 11:17:52AM +0100, Marco Elver wrote:
> > Haibo Li reported:
> >
> >  | Unable to handle kernel paging request at virtual address
> >  |   ffffff802a0d8d7171
> >  | Mem abort info:o:
> >  |   ESR = 0x9600002121
> >  |   EC = 0x25: DABT (current EL), IL = 32 bitsts
> >  |   SET = 0, FnV = 0 0
> >  |   EA = 0, S1PTW = 0 0
> >  |   FSC = 0x21: alignment fault
> >  | Data abort info:o:
> >  |   ISV = 0, ISS = 0x0000002121
> >  |   CM = 0, WnR = 0 0
> >  | swapper pgtable: 4k pages, 39-bit VAs, pgdp=000000002835200000
> >  | [ffffff802a0d8d71] pgd=180000005fbf9003, p4d=180000005fbf9003,
> >  | pud=180000005fbf9003, pmd=180000005fbe8003, pte=006800002a0d8707
> >  | Internal error: Oops: 96000021 [#1] PREEMPT SMP
> >  | Modules linked in:
> >  | CPU: 2 PID: 45 Comm: kworker/u8:2 Not tainted
> >  |   5.15.78-android13-8-g63561175bbda-dirty #1
> >  | ...
> >  | pc : kcsan_setup_watchpoint+0x26c/0x6bc
> >  | lr : kcsan_setup_watchpoint+0x88/0x6bc
> >  | sp : ffffffc00ab4b7f0
> >  | x29: ffffffc00ab4b800 x28: ffffff80294fe588 x27: 0000000000000001
> >  | x26: 0000000000000019 x25: 0000000000000001 x24: ffffff80294fdb80
> >  | x23: 0000000000000000 x22: ffffffc00a70fb68 x21: ffffff802a0d8d71
> >  | x20: 0000000000000002 x19: 0000000000000000 x18: ffffffc00a9bd060
> >  | x17: 0000000000000001 x16: 0000000000000000 x15: ffffffc00a59f000
> >  | x14: 0000000000000001 x13: 0000000000000000 x12: ffffffc00a70faa0
> >  | x11: 00000000aaaaaaab x10: 0000000000000054 x9 : ffffffc00839adf8
> >  | x8 : ffffffc009b4cf00 x7 : 0000000000000000 x6 : 0000000000000007
> >  | x5 : 0000000000000000 x4 : 0000000000000000 x3 : ffffffc00a70fb70
> >  | x2 : 0005ff802a0d8d71 x1 : 0000000000000000 x0 : 0000000000000000
> >  | Call trace:
> >  |  kcsan_setup_watchpoint+0x26c/0x6bc
> >  |  __tsan_read2+0x1f0/0x234
> >  |  inflate_fast+0x498/0x750
> >  |  zlib_inflate+0x1304/0x2384
> >  |  __gunzip+0x3a0/0x45c
> >  |  gunzip+0x20/0x30
> >  |  unpack_to_rootfs+0x2a8/0x3fc
> >  |  do_populate_rootfs+0xe8/0x11c
> >  |  async_run_entry_fn+0x58/0x1bc
> >  |  process_one_work+0x3ec/0x738
> >  |  worker_thread+0x4c4/0x838
> >  |  kthread+0x20c/0x258
> >  |  ret_from_fork+0x10/0x20
> >  | Code: b8bfc2a8 2a0803f7 14000007 d503249f (78bfc2a8) )
> >  | ---[ end trace 613a943cb0a572b6 ]-----
> >
> > The reason for this is that on certain arm64 configuration since
> > e35123d83ee3 ("arm64: lto: Strengthen READ_ONCE() to acquire when
> > CONFIG_LTO=y"), READ_ONCE() may be promoted to a full atomic acquire
> > instruction which cannot be used on unaligned addresses.
> >
> > Fix it by avoiding READ_ONCE() in read_instrumented_memory(), and simply
> > forcing the compiler to do the required access by casting to the
> > appropriate volatile type. In terms of generated code this currently
> > only affects architectures that do not use the default READ_ONCE()
> > implementation.
> >
> > The only downside is that we are not guaranteed atomicity of the access
> > itself, although on most architectures a plain load up to machine word
> > size should still be atomic (a fact the default READ_ONCE() still relies
> > on itself).
> >
> > Reported-by: Haibo Li <haibo.li@mediatek.com>
> > Tested-by: Haibo Li <haibo.li@mediatek.com>
> > Cc: <stable@vger.kernel.org> # 5.17+
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Queued, thank you!
>
> This one looks like it might want to go into v6.4 rather than later.

Yes, I think that'd be appropriate - thank you!

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOGbSsXLqM59HQJ04T4ueMWjQjzpt4QqyKpne%3DKbHWREg%40mail.gmail.com.
