Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS5G76DQMGQEGQYUEPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 174083D7216
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 11:35:09 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id rj11-20020a17090b3e8bb02901771fde8676sf1807796pjb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 02:35:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627378507; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZifjuzF0kKDb/6FHoQRQQoj13+h0Z1udm+FRlIPkdiryHrkaeKD46oTsJRru5ncGfo
         BKo1oLiNjheYkhqtdlcbXqGKYCyf7fjQfXp/gGLHRwsGH3Jag6D2hCPuG2PY9KNou4E6
         F7H1AwBuMdY1IkDcg7cgdT1Xg7cHSwlgXp3Pa01Q/OsE9TMVTEA/MHBGk8KGt0G11vOc
         4soLWF+eEa7SZRwLYhHMwuf7ExKMic1SJvGXBM2OiYQAq3YH7rLkuXCzkZ9sYfCa7SLE
         pBAY8A4tRubB0JQd/rtZ9G/a43k4dmMD8VZ3Nr3z/Gwj2ui84IEvzHVqj1kZQcRmRsOV
         8diw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VEYTlgwU9GuHuxVEwik6pMfckn6WVDOud48OUFa7wL0=;
        b=DpoAWT6VjaGARtQwVOdzsoVxkAJ63rEav42eaXTt3gxmhJI3WQoWOG28tAofxP5WBM
         vxN7ltl3UQwVxXLPV35YH9R1bObuG3MwkjnlI/X/xXCeJpIArGpO41Rl2j8yIrHGM5yn
         8L6mjrNcj57r6He6CC+W39WUm/ajc9N9ZFaciDovhTnZNB9CgXx8kduWTtCxrnc2mHZe
         9gyQbGcEUfHc0Tq2o0JFPYTFOE7vav+12JF0Iz47NqYEmNQz+8UR56nJ0cCJRt9HjTrk
         jbBZ1j+0q7V65Tr0jyOjWA3XiUHFUbjZPHzS42Zk3nBiFoA/mWFDTVqa16OE1ok23+NX
         JYkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C6alpqeG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VEYTlgwU9GuHuxVEwik6pMfckn6WVDOud48OUFa7wL0=;
        b=Aj1512VYToPfxMgBxclIVF+yJbFnn3q7TNOSJc3xo8UP1OSRxUN8jjEYiitiz2+EOC
         rGLrF+loEI0kadFTORqgXFdoyO4z/S5MUXp9GDxfNslJPaS81yZBV4cmGhpCg/FvYRdK
         DP0sWeb9O2XuMau21zGbEAvSkN37FZAfeZriVjIcdOTOZtDMSnRoPfRzySHajwBkPmHv
         BzyWwPlhGxRI1kVCnMW15fBCQpjyV1EZEGU/dLOnwP86U4MZaGQ8VdQnqC6biMSypqx4
         THFU7Z5JgFMTtUOpfgpEvhHa9Q4wvZGin5Pfx9XZztoQP7BdpIfnV91pd00n+NRJuLJw
         RMsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VEYTlgwU9GuHuxVEwik6pMfckn6WVDOud48OUFa7wL0=;
        b=moIVYP5ur7RXQr/sSEJcLkwzWXJiLlg6mviFOMIUAkb3nmRGCBw6V0SpkN8/ISB0a0
         SaQHHTtPXT3anTXCD6IGIvSuFpwEkDQb5FQSXPu7sE+YyQSCBc4j51EN62ZDz+32VyjJ
         F/iw8kSTJIJz5T0wErU68tH0BKNCXqskxLSiYzANCHv6mkC0SNI9mHGgonBJqi7IyExV
         CwniPYp1f9tPy0vy5dRduKt14dA3uwRWt3ba3XeoDG1iVhkxx8T8I1UVnsYE53cBY2T9
         WBPFkOPRkayBUkwmFUOXlyzeoMyOJILvGnoYfRrt8mRNP+OtDvL0T/7TOCOVat72QGLM
         Uzog==
X-Gm-Message-State: AOAM5306KRQ5kjQlJzUvm/gKUmQqIsarn2H6ZijgXzj5RAaNPp4N34vC
	6XFiG5PNzU5PKAOEU0nD9WM=
X-Google-Smtp-Source: ABdhPJzGa4i0iZjTglcvwg4U9QehRFSufhjU4cTyM5isrhfm+DyZkzIk7tEDdzxG6u9YufjjR4I3CQ==
X-Received: by 2002:a63:505d:: with SMTP id q29mr22773064pgl.137.1627378507806;
        Tue, 27 Jul 2021 02:35:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed82:: with SMTP id e2ls10399426plj.2.gmail; Tue, 27
 Jul 2021 02:35:07 -0700 (PDT)
X-Received: by 2002:a17:90a:5d8a:: with SMTP id t10mr3463164pji.6.1627378507189;
        Tue, 27 Jul 2021 02:35:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627378507; cv=none;
        d=google.com; s=arc-20160816;
        b=MbwRJR68wHrZEX0h6B4UNypHrCFD0hyIN5dt/ERB5fJYrXwtN9kZcyTywoAnMWq0W/
         gEfkzUfhK7Tch/ezCZ9x4s1a5hi4HG5NlDRPuW1T6h7We5evjsGbM6TybWbAm0c7cdAr
         7emjI557LDxyq+9pnpwGoWG4Qy9t7XDSj1H0ARL+jF1CQ1P+j3W5FfcnEUN1EWdTDfNy
         D3MycJX5tOCoDm9fGf6m03lA4/rCRLhHBokG5p+HHNHIV9N5T2q06nnf1QvSn7DRc+om
         D4cI26hKavTDg8FXr5nzU3eVt5i3SS/MLjincexthM+UuMW8TMS2gLl/mek2Qk4rIkt5
         vtRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tLt+aSNQ5Gb3uT3hTHMrtPbqAxvcc/LgUpLk9Zqb864=;
        b=nDkPUnL8qv98alDJDO3Ow5yLwZH1kPSOYIGNyWY/lbGz9E2FThurSSueTIDomoFhJ6
         N0yq45uUF1CnudEeiUIKsgNmK5urK/dX8nwSoBTo4OLbxaOVUHkTKgF7gi1/jeeE6kc5
         Xg2IFq9R3dSg9QQ7Z5NHbsC+uI1JkniWiuOV6FwB+3wEWzZxbVA4ht0wCUS/jhnQ0bQ/
         3tbEDVEMjkKrguPjm088wye9mT1zjbh/6jUPfMsb8B3oda9U+6wYfRWSM2gfMNUJPtJH
         UDhjfyJpKUEot5jZz4m13zNxkW5yYF84mhR2Giyy+K8jWxhYE5vN29AgWW9/2P/w6EiG
         DsTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C6alpqeG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id nv15si106808pjb.2.2021.07.27.02.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Jul 2021 02:35:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id o2-20020a9d22020000b0290462f0ab0800so8159171ota.11
        for <kasan-dev@googlegroups.com>; Tue, 27 Jul 2021 02:35:07 -0700 (PDT)
X-Received: by 2002:a05:6830:23a7:: with SMTP id m7mr14848974ots.17.1627378506348;
 Tue, 27 Jul 2021 02:35:06 -0700 (PDT)
MIME-Version: 1.0
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
 <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com> <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
 <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
In-Reply-To: <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Jul 2021 11:34:54 +0200
Message-ID: <CANpmjNPDSqokrHHVGkKHBFRe379xWUsF9CpECK=Eas375Wjj_A@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang <andrew.yang@mediatek.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Chinwen Chang <chinwen.chang@mediatek.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C6alpqeG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Tue, 27 Jul 2021 at 10:32, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> On Tue, 2021-07-27 at 09:10 +0200, Marco Elver wrote:
> > +Cc Catalin
> >
> > On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> > Kuan-Ying.Lee@mediatek.com> wrote:
> > >
> > > Hardware tag-based KASAN doesn't use compiler instrumentation, we
> > > can not use kasan_disable_current() to ignore tag check.
> > >
> > > Thus, we need to reset tags when accessing metadata.
> > >
> > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> >
> > This looks reasonable, but the patch title is not saying this is
> > kmemleak, nor does the description say what the problem is. What
> > problem did you encounter? Was it a false positive?
>
> kmemleak would scan kernel memory to check memory leak.
> When it scans on the invalid slab and dereference, the issue
> will occur like below.

Please also add this info to commit message.

> So I think we should reset the tag before scanning.
>
> # echo scan > /sys/kernel/debug/kmemleak
> [  151.905804]
> ==================================================================
> [  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
> [  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
> [  151.909656] Pointer tag: [f7], memory tag: [fe]
> [  151.910195]
> [  151.910876] CPU: 7 PID: 138 Comm: kmemleak Not tainted 5.14.0-rc2-
> 00001-g8cae8cd89f05-dirty #134
> [  151.912085] Hardware name: linux,dummy-virt (DT)
> [  151.912868] Call trace:
> [  151.913211]  dump_backtrace+0x0/0x1b0
> [  151.913796]  show_stack+0x1c/0x30
> [  151.914248]  dump_stack_lvl+0x68/0x84
> [  151.914778]  print_address_description+0x7c/0x2b4
> [  151.915340]  kasan_report+0x138/0x38c
> [  151.915804]  __do_kernel_fault+0x190/0x1c4
> [  151.916386]  do_tag_check_fault+0x78/0x90
> [  151.916856]  do_mem_abort+0x44/0xb4
> [  151.917308]  el1_abort+0x40/0x60
> [  151.917754]  el1h_64_sync_handler+0xb4/0xd0
> [  151.918270]  el1h_64_sync+0x78/0x7c
> [  151.918714]  scan_block+0x58/0x170
> [  151.919157]  scan_gray_list+0xdc/0x1a0
> [  151.919626]  kmemleak_scan+0x2ac/0x560
> [  151.920129]  kmemleak_scan_thread+0xb0/0xe0
> [  151.920635]  kthread+0x154/0x160
> [  151.921115]  ret_from_fork+0x10/0x18
> [  151.921717]
> [  151.922077] Allocated by task 0:
> [  151.922523]  kasan_save_stack+0x2c/0x60
> [  151.923099]  __kasan_kmalloc+0xec/0x104
> [  151.923502]  __kmalloc+0x224/0x3c4
> [  151.924172]  __register_sysctl_paths+0x200/0x290
> [  151.924709]  register_sysctl_table+0x2c/0x40
> [  151.925175]  sysctl_init+0x20/0x34
> [  151.925665]  proc_sys_init+0x3c/0x48
> [  151.926136]  proc_root_init+0x80/0x9c
> [  151.926547]  start_kernel+0x648/0x6a4
> [  151.926987]  __primary_switched+0xc0/0xc8
> [  151.927557]
> [  151.927994] Freed by task 0:
> [  151.928340]  kasan_save_stack+0x2c/0x60
> [  151.928766]  kasan_set_track+0x2c/0x40
> [  151.929173]  kasan_set_free_info+0x44/0x54
> [  151.929568]  ____kasan_slab_free.constprop.0+0x150/0x1b0
> [  151.930063]  __kasan_slab_free+0x14/0x20
> [  151.930449]  slab_free_freelist_hook+0xa4/0x1fc
> [  151.930924]  kfree+0x1e8/0x30c
> [  151.931285]  put_fs_context+0x124/0x220
> [  151.931731]  vfs_kern_mount.part.0+0x60/0xd4
> [  151.932280]  kern_mount+0x24/0x4c
> [  151.932686]  bdev_cache_init+0x70/0x9c
> [  151.933122]  vfs_caches_init+0xdc/0xf4
> [  151.933578]  start_kernel+0x638/0x6a4
> [  151.934014]  __primary_switched+0xc0/0xc8
> [  151.934478]
> [  151.934757] The buggy address belongs to the object at
> ffff0000c0074e00
> [  151.934757]  which belongs to the cache kmalloc-256 of size 256
> [  151.935744] The buggy address is located 176 bytes inside of
> [  151.935744]  256-byte region [ffff0000c0074e00, ffff0000c0074f00)
> [  151.936702] The buggy address belongs to the page:
> [  151.937378] page:(____ptrval____) refcount:1 mapcount:0
> mapping:0000000000000000 index:0x0 pfn:0x100074
> [  151.938682] head:(____ptrval____) order:2 compound_mapcount:0
> compound_pincount:0
> [  151.939440] flags:
> 0xbfffc0000010200(slab|head|node=0|zone=2|lastcpupid=0xffff|kasantag=0x
> 0)
> [  151.940886] raw: 0bfffc0000010200 0000000000000000 dead000000000122
> f5ff0000c0002300
> [  151.941634] raw: 0000000000000000 0000000000200020 00000001ffffffff
> 0000000000000000
> [  151.942353] page dumped because: kasan: bad access detected
> [  151.942923]
> [  151.943214] Memory state around the buggy address:
> [  151.943896]  ffff0000c0074c00: f0 f0 f0 f0 f0 f0 f0 f0 f0 fe fe fe
> fe fe fe fe
> [  151.944857]  ffff0000c0074d00: fe fe fe fe fe fe fe fe fe fe fe fe
> fe fe fe fe
> [  151.945892] >ffff0000c0074e00: f7 f7 f7 f7 f7 f7 f7 f7 f7 f7 f7 fe
> fe fe fe fe
> [  151.946407]                                                     ^
> [  151.946939]  ffff0000c0074f00: fe fe fe fe fe fe fe fe fe fe fe fe
> fe fe fe fe
> [  151.947445]  ffff0000c0075000: fb fb fb fb fb fb fb fb fb fb fb fb
> fb fb fb fb
> [  151.947999]
> ==================================================================
> [  151.948524] Disabling lock debugging due to kernel taint
> [  156.434569] kmemleak: 181 new suspected memory leaks (see
> /sys/kernel/debug/kmemleak)
>
> >
> > Perhaps this should have been "kmemleak, kasan: reset pointer tags to
> > avoid false positives" ?
>
> Thanks for the suggestions.
> But I think it doesn't belong to false
> positive becuase scan block
> touched invalid metadata certainly.

It's how kmemleak works, so we knowingly access invalid memory, and
for all intents and purposes it's a false positive.

> Maybe "kmemleak, kasan: reset tags when scanning block"?

That's fine.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPDSqokrHHVGkKHBFRe379xWUsF9CpECK%3DEas375Wjj_A%40mail.gmail.com.
