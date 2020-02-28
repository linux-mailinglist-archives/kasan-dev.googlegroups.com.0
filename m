Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXA4PZAKGQEUFKODVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id D794E1735A0
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 11:49:19 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id c8sf2550402qte.22
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 02:49:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582886958; cv=pass;
        d=google.com; s=arc-20160816;
        b=QbSL1QbjMtJsyYYCQc8+YfWEqaynCgswTbstS9jaYIQyGw/kmau1yZNWEfkeBlPT+O
         uJw3/RfYZvvmxSZ0ATxKtBegzklX/d2u8sZVe2ClBHir2Ss3H/OU539t50Es+UwQ8Ehe
         uPR6hzsWFVqyTJ8XU1UzJyr/hihJ96c8Jv9TewShp0ZBScoZrsC/Wn0yWl6yF/OhLaE1
         sMLYvVEMPM2N5i6E0YvHl33CCrMGC9XY7SqNfJKefmt5GjarRS1qXVRVCRi0u6bEu4dL
         m+6Qs6/IH7X5EuA1hWvBGQ8xNpg9BuLspV/xSFcbI2Tv6+2siQzWjQWX5zLC24C6KgpC
         d8kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=J5UluEJJzEJJDKI5rmrJY0uOTg4RZaTyy3Rd/vxy3Iw=;
        b=H51hsZoCv8Fleugjc29rgIgygqvGBuvlCaJ1Qo3eIXFbg0LQd530JhKjKu3cqCXQp6
         SruFfLM+C40+J5HL+5hzbxcWrk5hL3tDRk0kisJxDxBwqJNV3YiXAoX6y+1TVJBUn8Fh
         B/p2U2r7xJSDpl/r23cdRduj3C1J77gA/uh3zd4iNqcsKoDuBDFcrpR3svj2h/CSYNYn
         PeHRbb7Y6B9SBq4YFm6B/JwmdHp0quugF7xxlz8+Ch1j4U21N/5s1QvXD9fv3g7f8ssS
         4OFT616R2CDh8jRH86knXBU4oG4Cn2NRHiZ4m+j5tCENZK3Qe97YEybE8Pyyt35nekHn
         LaDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iaQwtQAw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J5UluEJJzEJJDKI5rmrJY0uOTg4RZaTyy3Rd/vxy3Iw=;
        b=n9q6FpE9wWG/q2NWJOqFA3Kr+Em7Hfm2Lb0FGPHNOQbeOQcJo9NtWkW65QYFkdXbDY
         X4O7bwv+0trVKl6HvVJCTaRamaOpd4BEy/NbVmBPFoT3nDOlelam9aB8p+ETizKUsdvY
         tSZHHm+AlwgQHz8AiNBCig+AcT0lvDoDIFf3VlL5hTGW5fbIfMtyBki7M401bzrm+obe
         Bksj6c/n46QeEJ8tTTiR6nxp0J9LF8DPHsLzRNyeYxa7tiqX2UnNz+QmlnTJ3CbBb6Ab
         WI0Uf0A5W/ZdK1mf5fcWdFd+lqhO7y+1+UAzYM0w0lx5iEY30pMBGaMwEk7wrlvubAZa
         MRHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J5UluEJJzEJJDKI5rmrJY0uOTg4RZaTyy3Rd/vxy3Iw=;
        b=eXlcs9tD+soq6szbQpD1Kngn2lznjyS19RhDgZc0w6VbQ+6roa1+rDYuCNhk4oI+GI
         ZofXO8gcMY9h7KM/TyZOQOszfntcLvxHgwK3YztLCWTfAOUEafjhGqQg23aS0AHplTqC
         GOgKJywlo6lNBKHHlQaXCiz/boxORc4y0tNmN+4gbZjZmgm59Wyfg/BWr9B90weEexJl
         h8aUrJXZ56XSRdp6ZUtwRtlxzX9TIfLz5qLrsMoxkflewwGgz1dchq0KeExrThPfRSLQ
         sL1kN+ATKPAnUfgjWa9xZSJBhlevjozs8V0Z1+ozwh//lXI2JyWbPyy2K3HNqUBWUeK4
         xbLQ==
X-Gm-Message-State: APjAAAWzPRfyQUyswN+q0UDMuekyUe8QF5NAaeMTBsxfEe03qNIEzOd/
	LrsojHrvO1MxsB1rnnbx3l8=
X-Google-Smtp-Source: APXvYqwr3YpMRujs9A1oWbF7+khx0dEDcd7iRx4virnB4F/vpcKlAWJ7iU4SDkCIrFy5y8+ZNTT/7A==
X-Received: by 2002:a05:6214:17cd:: with SMTP id cu13mr3029219qvb.192.1582886958691;
        Fri, 28 Feb 2020 02:49:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:58f1:: with SMTP id di17ls673334qvb.5.gmail; Fri, 28 Feb
 2020 02:49:18 -0800 (PST)
X-Received: by 2002:a05:6214:166:: with SMTP id y6mr3342910qvs.120.1582886958292;
        Fri, 28 Feb 2020 02:49:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582886958; cv=none;
        d=google.com; s=arc-20160816;
        b=sEPyjeeCEfvYJAoQhlPzqgiNXAH7AIxd5THSDgsEHYhU/8bXP8S5lAFyBIwjAC+afN
         BuDfKEw/IYaF5Cc21O4mlKV16Fi/MN+YzfgXyfQvkdZjifu68V/4y4epnYuwnzupRAF7
         OYlB4pTOM29oCso1IuIWmSVCoy9LxuvWVV7ccb9kA/WwESfXC6PdN/4t6Bv4OFMxDZ0h
         MCZq57rdM2bAcUyNjCCF2DKVZxaTX/YObkIjqzVFSe0lTpVqnleIVhdGHULAa4Pt1x7e
         ZBZ6iZfFY6vc+jt3OqRwU4RtE3G18RY7VCk9oIWocWNMJso4u1FGnQR+bdoAJykVgGkU
         B5qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aqdR1FawIDcIjcDWnx2zMMW5yAMtp4uyQmYJLmHNyd8=;
        b=wKQUlcKbvKwkP7A5dvoAxdUPWugMoWjRMR8qLOEcng9d/4Oc/4EbQeXV46eLhb252z
         37DNsNcXFx5RV86JR1j27l/p7bJjQkJjDJtUUbTWRFlsSXbZWH3RaasNtz832wxIKBCl
         1KkNIE6Sf1lgrMNZmW3EbH2WF5Om9m0zAKnsLffTBKqBx/qLCeHymO0PbJt7gqiB9+H7
         xhziOs8CU4DUOxUZNX8F8d7rwkaMFtJRCWgXIlA9AKLOgfey0LREN2r49ROxHn2njVFo
         jd843pwCH8PDVFcaWkqMQ8iH0uaORUfdcpDQXjJXwawMWVrCzuiCspDsK+gqiaaSKe78
         V01g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iaQwtQAw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id w10si142992qtn.1.2020.02.28.02.49.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 02:49:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id r16so2418170oie.6
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 02:49:18 -0800 (PST)
X-Received: by 2002:a05:6808:8d5:: with SMTP id k21mr2640215oij.121.1582886957457;
 Fri, 28 Feb 2020 02:49:17 -0800 (PST)
MIME-Version: 1.0
References: <20200228044018.1263-1-cai@lca.pw>
In-Reply-To: <20200228044018.1263-1-cai@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 11:49:06 +0100
Message-ID: <CANpmjNNe4OebUdTR5Z=23FK55gXOJmzdnEfXt8_3xjQ0P+foFA@mail.gmail.com>
Subject: Re: [PATCH] mm/swap: annotate data races for lru_rotate_pvecs
To: Qian Cai <cai@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iaQwtQAw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Fri, 28 Feb 2020 at 05:40, Qian Cai <cai@lca.pw> wrote:
>
> Read to lru_add_pvec->nr could be interrupted and then write to the same
> variable. The write has local interrupt disabled, but the plain reads
> result in data races. However, it is unlikely the compilers could
> do much damage here given that lru_add_pvec->nr is a "unsigned char" and
> there is an existing compiler barrier. Thus, annotate the reads using the
> data_race() macro. The data races were reported by KCSAN,

Note that, the fact that the writer has local interrupts disabled for
the write is irrelevant because it's the interrupt that triggered
while the read was happening that led to the concurrent write.

I assume you ran this with CONFIG_KCSAN_INTERRUPT_WATCHER=y?  The
option is disabled by default (see its help-text). I don't know if we
want to deal with data races due to interrupts right now, especially
those that just result in 'data_race' annotations. Thoughts?

Thanks,
-- Marco

>  BUG: KCSAN: data-race in lru_add_drain_cpu / rotate_reclaimable_page
>
>  write to 0xffff9291ebcb8a40 of 1 bytes by interrupt on cpu 23:
>   rotate_reclaimable_page+0x2df/0x490
>   pagevec_add at include/linux/pagevec.h:81
>   (inlined by) rotate_reclaimable_page at mm/swap.c:259
>   end_page_writeback+0x1b5/0x2b0
>   end_swap_bio_write+0x1d0/0x280
>   bio_endio+0x297/0x560
>   dec_pending+0x218/0x430 [dm_mod]
>   clone_endio+0xe4/0x2c0 [dm_mod]
>   bio_endio+0x297/0x560
>   blk_update_request+0x201/0x920
>   scsi_end_request+0x6b/0x4a0
>   scsi_io_completion+0xb7/0x7e0
>   scsi_finish_command+0x1ed/0x2a0
>   scsi_softirq_done+0x1c9/0x1d0
>   blk_done_softirq+0x181/0x1d0
>   __do_softirq+0xd9/0x57c
>   irq_exit+0xa2/0xc0
>   do_IRQ+0x8b/0x190
>   ret_from_intr+0x0/0x42
>   delay_tsc+0x46/0x80
>   __const_udelay+0x3c/0x40
>   __udelay+0x10/0x20
>   kcsan_setup_watchpoint+0x202/0x3a0
>   __tsan_read1+0xc2/0x100
>   lru_add_drain_cpu+0xb8/0x3f0
>   lru_add_drain+0x25/0x40
>   shrink_active_list+0xe1/0xc80
>   shrink_lruvec+0x766/0xb70
>   shrink_node+0x2d6/0xca0
>   do_try_to_free_pages+0x1f7/0x9a0
>   try_to_free_pages+0x252/0x5b0
>   __alloc_pages_slowpath+0x458/0x1290
>   __alloc_pages_nodemask+0x3bb/0x450
>   alloc_pages_vma+0x8a/0x2c0
>   do_anonymous_page+0x16e/0x6f0
>   __handle_mm_fault+0xcd5/0xd40
>   handle_mm_fault+0xfc/0x2f0
>   do_page_fault+0x263/0x6f9
>   page_fault+0x34/0x40
>
>  read to 0xffff9291ebcb8a40 of 1 bytes by task 37761 on cpu 23:
>   lru_add_drain_cpu+0xb8/0x3f0
>   lru_add_drain_cpu at mm/swap.c:602
>   lru_add_drain+0x25/0x40
>   shrink_active_list+0xe1/0xc80
>   shrink_lruvec+0x766/0xb70
>   shrink_node+0x2d6/0xca0
>   do_try_to_free_pages+0x1f7/0x9a0
>   try_to_free_pages+0x252/0x5b0
>   __alloc_pages_slowpath+0x458/0x1290
>   __alloc_pages_nodemask+0x3bb/0x450
>   alloc_pages_vma+0x8a/0x2c0
>   do_anonymous_page+0x16e/0x6f0
>   __handle_mm_fault+0xcd5/0xd40
>   handle_mm_fault+0xfc/0x2f0
>   do_page_fault+0x263/0x6f9
>   page_fault+0x34/0x40
>
>  2 locks held by oom02/37761:
>   #0: ffff9281e5928808 (&mm->mmap_sem#2){++++}, at: do_page_fault
>   #1: ffffffffb3ade380 (fs_reclaim){+.+.}, at: fs_reclaim_acquire.part
>  irq event stamp: 1949217
>  trace_hardirqs_on_thunk+0x1a/0x1c
>  __do_softirq+0x2e7/0x57c
>  __do_softirq+0x34c/0x57c
>  irq_exit+0xa2/0xc0
>
>  Reported by Kernel Concurrency Sanitizer on:
>  CPU: 23 PID: 37761 Comm: oom02 Not tainted 5.6.0-rc3-next-20200226+ #6
>  Hardware name: HP ProLiant BL660c Gen9, BIOS I38 10/17/2018
>
> Signed-off-by: Qian Cai <cai@lca.pw>
> ---
>
> BTW, while at it, I had also looked at other pagevec there, but could
> not tell for  sure if they could be interrupted resulting in data races,
> so I leave them out for now.
>
>  mm/swap.c | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/mm/swap.c b/mm/swap.c
> index cf39d24ada2a..c922f99dab85 100644
> --- a/mm/swap.c
> +++ b/mm/swap.c
> @@ -599,7 +599,8 @@ void lru_add_drain_cpu(int cpu)
>                 __pagevec_lru_add(pvec);
>
>         pvec = &per_cpu(lru_rotate_pvecs, cpu);
> -       if (pagevec_count(pvec)) {
> +       /* Disabling interrupts below acts as a compiler barrier. */
> +       if (data_race(pagevec_count(pvec))) {
>                 unsigned long flags;
>
>                 /* No harm done if a racing interrupt already did this */
> @@ -744,7 +745,7 @@ void lru_add_drain_all(void)
>                 struct work_struct *work = &per_cpu(lru_add_drain_work, cpu);
>
>                 if (pagevec_count(&per_cpu(lru_add_pvec, cpu)) ||
> -                   pagevec_count(&per_cpu(lru_rotate_pvecs, cpu)) ||
> +                   data_race(pagevec_count(&per_cpu(lru_rotate_pvecs, cpu))) ||
>                     pagevec_count(&per_cpu(lru_deactivate_file_pvecs, cpu)) ||
>                     pagevec_count(&per_cpu(lru_deactivate_pvecs, cpu)) ||
>                     pagevec_count(&per_cpu(lru_lazyfree_pvecs, cpu)) ||
> --
> 2.21.0 (Apple Git-122.2)
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNe4OebUdTR5Z%3D23FK55gXOJmzdnEfXt8_3xjQ0P%2BfoFA%40mail.gmail.com.
