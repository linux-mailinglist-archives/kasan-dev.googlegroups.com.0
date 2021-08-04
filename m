Return-Path: <kasan-dev+bncBDW2JDUY5AORBL4XVKEAMGQE736DMKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D125F3E015B
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 14:44:31 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id m4-20020a2ea8840000b029018ba0baeb6esf386595ljq.5
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 05:44:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628081071; cv=pass;
        d=google.com; s=arc-20160816;
        b=UfpV99M3ktBVaGvgaxP6rD95Cggure7Qov1Vg1/ZH5lZ55vfL0JP3zNkza3nWYQ2ar
         QsIaz71TElR5SQqdkc7m/v0WtGubKo0lFP5oSugXrc5PQndVMMmDOEmKhNYTSe7FA2uF
         tl4e8r2ouwt9TWwKiO7bjO/tXqG5G9ueTQdvuHOtC6x/avRS3cLiecUJlDK2zAwS4r9n
         MNnU3WdNciovyJCj1XbiPbL1rS7o3dgurgraVa4hhEfO/48mlLK64JaCQJEYhHs2PHMG
         1bVUmRQ6im0FJBiEN1qFn6YD3rWhQxzjicYB3Z3XHZObviIz0+JzMtCiTA7v2CLZfS3i
         B37g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=gO6tiGyRo4ziPGjrsd1Z37ctXTGjU6+Pj1cCDlrNS4E=;
        b=AyanG+h/OUtyqHAurXDeM2kISi6IvG4/n8aqXh7hZ/8DVQ3kKounVs+6cMYBxuD9wh
         FniIJ7obB/XU1j9/MC/o6L3QRRtueAWRsbpO3S3xAoyZLy3tvYHQ56205mRVn6o5YtNd
         BCZA4xBfDXZ+Muzy8b7qNvAdahXQKWbiNoOTigr8aWKMfvFtVf0nT9XdqhOTmRos2+xd
         3MNBKcXgqWpi7sYJCbGTzTAkhDbLAapsXjX2WQOPH4BVQsLSVjmPP0LzqJniJUe1zxbm
         30BLXwgrlJcng0YyVg3pCYpxwyyVEx6d8za2gjjTmqnFYMSNLjYo9UXPKAV/J7iZw9rS
         Lt8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=KB7qH+Qi;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gO6tiGyRo4ziPGjrsd1Z37ctXTGjU6+Pj1cCDlrNS4E=;
        b=N8giEo6dAYe/lxmyD2ndLLjrQ/vNdCuRJ76oL3LDmTC4IPC7xU61y8yb/Kskc8zDA2
         +n1HCjSyg95IxhWQlw+K1Jsf0WUaYMHS+UEAqKPURouPP0USxmjAxOmGu5FmYe4724KW
         d+sEZBk3hlfRC7vbgb+Gime/qWz02qVigpx2Y8DoR7CjV4NBu0oROZsb50d7gOmQ5jY0
         cd1RWv2Qwnvsa1CQnQcIeimYebubd7nsYr5yN/Z7FKSH5DI+r3RrKkP2JoH89yPt/yMs
         YXjXs8R5psMC9tzZ+SqTrQnUhC7wIrD9wRpyf5VOgC1uYXMJ+GUtQOOcdT0tpEt0nMkf
         mzEg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gO6tiGyRo4ziPGjrsd1Z37ctXTGjU6+Pj1cCDlrNS4E=;
        b=NEDPsaL29UBIwXSMxWZDRuVTF6Qk6zkgetLNKTMIYQa83AV0Axs1HbQJSfTV0cp+Jo
         XR7tBm05DAtt/B3yDxFunT9SYUF0Wa+6n9wKpRIve1wfHuwhIAPXh7KNzxkUvkD1QQ6s
         QhkB1ccDhdmDo+d73V2Kdk93OFnKtEnVFA68gYRiWhZaq5bhdrEznNg9yzw7N0iPI2UF
         tzAND2vtGsjTfV5v98/admWPQ4cDjcAbaIoL2nQ8OmWHVVh7edsDg90GLPyIOz++Bm4r
         sb/tCmhjVgjGcQTQZTY5sWd8zb6SsQnbAraPrtFd8qlQcWMNyl8xOpUF0X2DVQ7Cs31X
         AfKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gO6tiGyRo4ziPGjrsd1Z37ctXTGjU6+Pj1cCDlrNS4E=;
        b=KtjA4P1B3IE4fvHtxRuCBwwdV/Hq7LV6gGBN1njdNNh8bzAjd7Ckzfr6e3YOPThXnx
         x+8Tcog8B1ZXRucc/vasQy9Y/kgDukClB0BL/Zb4id4GTuz8aG4Oz/Jkhg8yF3tkECQl
         ZYKrpu12vhyZWqlN8DipU0XOP+KqWpTqmuylPD39iNtHJI+mQxdS8nUxJ9gfSe2ME66z
         aSjI/Ph1d5iHo6hY3eGg4q43jJ188hyxO0yDRA+LEVOqWDjxvnf2YMuSoGTl8sS6yxK2
         NdMj3+tknhGC3QGN/1/944CWojWgaetJ86rHHLY88pp9HQ6I+oOIEhNwAdGDuopUubju
         SYig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zp98to7gE5v+FqCuuG3f48fEK6DzutaBF+cjACtmX3i/is5y6
	WS9M9XNIC3xD5W5vvGD/0KI=
X-Google-Smtp-Source: ABdhPJy7vFuilzF/AVjuKGUJ8F0iL5zhxVyMTb0QDMYpLg9FivcjcjG8sktdrEuIW0vSc/82X1w7tg==
X-Received: by 2002:a05:6512:1145:: with SMTP id m5mr21135864lfg.37.1628081071356;
        Wed, 04 Aug 2021 05:44:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls1558803lfi.2.gmail; Wed, 04 Aug
 2021 05:44:30 -0700 (PDT)
X-Received: by 2002:a05:6512:3905:: with SMTP id a5mr20111536lfu.406.1628081070369;
        Wed, 04 Aug 2021 05:44:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628081070; cv=none;
        d=google.com; s=arc-20160816;
        b=Mnb+prBvhcjXqcUba3cnXJ6Fy3wGmJjJq7Z6Y30CAcgNu6Z6uuDqaAKQpkBcWnGvtC
         d9E7hG5d1e2ayFdcDBVndRdhaUrlX0WU3wHAiDYH0tMthlizcqnMKa/KaQzLy+CPh58/
         nKH9u9AGoh8GjB9qGM80UL/MGI9SfyIYSRm5NAKzNtHan9AjuIx42g58TNud6/+/Wvyy
         wHRH4jd4S8MPoa3DC+2dZSWmRugDZY1XvRoMZh9fek4vFH5gC4gKowq+BVqMfgPjJoG7
         v1ec++69P1b5LgqavNrd27skYL8tnJxUxysbKNj3e08AkqDeC8JuT+fboxxZEjU55Vti
         sILA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rHpM1wB8GC7B0gndgKLXatkqmK6m0EnOPisfXQMQMVs=;
        b=QK5LE8m7ZSe9FkkkbcWWln7V9n5qTWJzYUiiBNcOJbrQSOg7aRj9GvIMwzcKQo541L
         tXvBJdakGGF7UsWwHirJJRFPAKecuzCWajUBTFVnj2DquPI2WXhhDmao/6IxqHGct6jY
         JUTiCY6UQkMSrSkf55nUON//FtEhHsdSmrAPFJYwnmCVDr+xKvs1DccXTlaTbUcnhsGt
         CHrV0+Zq5a1xTk3U8MBzhy9xSZXIdRacr0GaUw/negFnvFi8CxZTcnGwvcOjwIz5hjJc
         RYjTrc5rnvqfKq89KmVo1Hi883EarBCm9FOSnH5Ok1T9JmM+fgLhBrGkkhR5W/4D2SjG
         Oa1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=KB7qH+Qi;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id i5si153483lfl.2.2021.08.04.05.44.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Aug 2021 05:44:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id h9so3518060ejs.4
        for <kasan-dev@googlegroups.com>; Wed, 04 Aug 2021 05:44:30 -0700 (PDT)
X-Received: by 2002:a17:906:f112:: with SMTP id gv18mr25819921ejb.439.1628081070045;
 Wed, 04 Aug 2021 05:44:30 -0700 (PDT)
MIME-Version: 1.0
References: <20210804090957.12393-1-Kuan-Ying.Lee@mediatek.com> <20210804090957.12393-2-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210804090957.12393-2-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 4 Aug 2021 14:44:19 +0200
Message-ID: <CA+fCnZfTfXt9_invV=wfyf_Z-Db_nutGjzf_MiFpnfdbm487Ww@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kasan, kmemleak: reset tags when scanning block
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang <andrew.yang@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=KB7qH+Qi;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::634
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Aug 4, 2021 at 11:10 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> Kmemleak need to scan kernel memory to check memory leak.
> With hardware tag-based kasan enabled, when it scans on
> the invalid slab and dereference, the issue will occur
> as below.
>
> Hardware tag-based KASAN doesn't use compiler instrumentation, we
> can not use kasan_disable_current() to ignore tag check.
>
> Based on the below report, there are 11 0xf7 granules, which amounts to
> 176 bytes, and the object is allocated from the kmalloc-256 cache. So
> when kmemleak accesses the last 256-176 bytes, it causes faults, as
> those are marked with KASAN_KMALLOC_REDZONE == KASAN_TAG_INVALID ==
> 0xfe.
>
> Thus, we reset tags before accessing metadata to avoid from false positives.
>
> [  151.905804] ==================================================================
> [  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
> [  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
> [  151.909656] Pointer tag: [f7], memory tag: [fe]
> [  151.910195]
> [  151.910876] CPU: 7 PID: 138 Comm: kmemleak Not tainted 5.14.0-rc2-00001-g8cae8cd89f05-dirty #134
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
> [  151.934757] The buggy address belongs to the object at ffff0000c0074e00
> [  151.934757]  which belongs to the cache kmalloc-256 of size 256
> [  151.935744] The buggy address is located 176 bytes inside of
> [  151.935744]  256-byte region [ffff0000c0074e00, ffff0000c0074f00)
> [  151.936702] The buggy address belongs to the page:
> [  151.937378] page:(____ptrval____) refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x100074
> [  151.938682] head:(____ptrval____) order:2 compound_mapcount:0 compound_pincount:0
> [  151.939440] flags: 0xbfffc0000010200(slab|head|node=0|zone=2|lastcpupid=0xffff|kasantag=0x0)
> [  151.940886] raw: 0bfffc0000010200 0000000000000000 dead000000000122 f5ff0000c0002300
> [  151.941634] raw: 0000000000000000 0000000000200020 00000001ffffffff 0000000000000000
> [  151.942353] page dumped because: kasan: bad access detected
> [  151.942923]
> [  151.943214] Memory state around the buggy address:
> [  151.943896]  ffff0000c0074c00: f0 f0 f0 f0 f0 f0 f0 f0 f0 fe fe fe fe fe fe fe
> [  151.944857]  ffff0000c0074d00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> [  151.945892] >ffff0000c0074e00: f7 f7 f7 f7 f7 f7 f7 f7 f7 f7 f7 fe fe fe fe fe
> [  151.946407]                                                     ^
> [  151.946939]  ffff0000c0074f00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> [  151.947445]  ffff0000c0075000: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> [  151.947999] ==================================================================
> [  151.948524] Disabling lock debugging due to kernel taint
> [  156.434569] kmemleak: 181 new suspected memory leaks (see /sys/kernel/debug/kmemleak)
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> ---
>  mm/kmemleak.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> index 228a2fbe0657..73d46d16d575 100644
> --- a/mm/kmemleak.c
> +++ b/mm/kmemleak.c
> @@ -290,7 +290,7 @@ static void hex_dump_object(struct seq_file *seq,
>         warn_or_seq_printf(seq, "  hex dump (first %zu bytes):\n", len);
>         kasan_disable_current();
>         warn_or_seq_hex_dump(seq, DUMP_PREFIX_NONE, HEX_ROW_SIZE,
> -                            HEX_GROUP_SIZE, ptr, len, HEX_ASCII);
> +                            HEX_GROUP_SIZE, kasan_reset_tag((void *)ptr), len, HEX_ASCII);
>         kasan_enable_current();
>  }
>
> @@ -1171,7 +1171,7 @@ static bool update_checksum(struct kmemleak_object *object)
>
>         kasan_disable_current();
>         kcsan_disable_current();
> -       object->checksum = crc32(0, (void *)object->pointer, object->size);
> +       object->checksum = crc32(0, kasan_reset_tag((void *)object->pointer), object->size);
>         kasan_enable_current();
>         kcsan_enable_current();
>
> @@ -1246,7 +1246,7 @@ static void scan_block(void *_start, void *_end,
>                         break;
>
>                 kasan_disable_current();
> -               pointer = *ptr;
> +               pointer = *(unsigned long *)kasan_reset_tag((void *)ptr);
>                 kasan_enable_current();
>
>                 untagged_ptr = (unsigned long)kasan_reset_tag((void *)pointer);
> --
> 2.18.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfTfXt9_invV%3Dwfyf_Z-Db_nutGjzf_MiFpnfdbm487Ww%40mail.gmail.com.
