Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6OAXK7QMGQEAS2NWLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 809D7A7A5B1
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Apr 2025 16:51:40 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4766c80d57esf15299101cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Apr 2025 07:51:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743691897; cv=pass;
        d=google.com; s=arc-20240605;
        b=aGAbyXkIgWEClBxp3dWd1bk2bmbPiwMsdHgy0yykWUcHNTvC0ELwTWtBDjrHjKaCeX
         ENOZFBXmoKD+QHqRMxb1izPU23Nm6m1k387ik7YE5z1QqStmIZI5MKVuQPk0wdTgN/nx
         rT4FTuNqhYJNr448RctV/YH1AWHjtiUZluh4EP3MvBTskwmfzs3Glx2pSdmNF1+CKtQ/
         I0X4guHxdYY2fmJ5Qf/g+ElN2LA1tarWzUgtpTy89U3Q1jHTkB3ngOALqt0ZlNHk0W7i
         1KN3Moy0yHq46qNa/4IP8cb2s8u0EuxRvbwTCAxbJ3NIHBPahpPXN44njNKE6gia87DT
         +pOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3dCgr/kn2M51cvVWF19cauLbSvL2OWj9DMQLPvga1ow=;
        fh=RRvAEKTb6wIVqGUWya3EOo9anxrc/s4Bbc9QYH7iCWE=;
        b=MgjKhpDmX39wymXr61IcF/EEFF7UXEPvsQYCBtWyIK6OhgDBEjDUwH8vrZl+s11KtM
         qDARLieD9jUtrkhXZY3H1u4I7qngeJ/43dcNEFB4k5JrA4eI4Z4FuUAg6WUdtkPuYO8C
         qVHUjrug4ew6GMh5cQX8FXDGwcNiq16NC4qz8GIeS5FuHAUuO2GTxWiERwahnv1CcIVS
         cXYcR3+PQBJ20LgNu4mQ6TWQVKRudQeku/YKSvF1Z5RLK57SED72O/DOugQvhoavdowI
         bzSmQIeM0YzfKGCgyOYAm5bJ7wt1aY3EtFWFUWQZkpmh0HET1n6FdDcUalkSTxnKArLS
         OPkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xspjoM+G;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743691897; x=1744296697; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3dCgr/kn2M51cvVWF19cauLbSvL2OWj9DMQLPvga1ow=;
        b=TSSNthGzXbvCL1KQjXN2X1gEh+20vZghtp4xTBOe8PPYYh4oW52CWD+sqJ5lxETCa3
         4PS94ZWBFlOPNX1aBkMTAOkkZ6Mr5PHDeS1rU+kqWnxmNMAS2pEjFZm83ZCmBe1esEXD
         lmzksBmADNqzTZiHo5VgDwN8dahel+40cpMpvMXDeTF6PnPNcU8tPnukJE81pjysWD/k
         atv6r4oLZFISLlRJDwvPYhgjYFCvYVYRcf5raScZf+nN9M8tLdA1Yv7D1dHFxmP72lsE
         cFmlyCIA5cSNyy+lXGcpBvYXY8Toz1Viz1IQFMHMQFVBX9lrNtjugtqPIEvZnm1UKumx
         FT/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743691897; x=1744296697;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3dCgr/kn2M51cvVWF19cauLbSvL2OWj9DMQLPvga1ow=;
        b=hiskHxUiZPSaS7JP7TsXiHs7Z/fYUpEYQ0Wlq4XjxrZPX+1AguHfnVnF+5WP9GyX+I
         mwpFTcLeAGDadKt7BW01b0epKgJKtbnNwdIlKUth5zePknVtI0fPVobykWS9HjO9RVVj
         10thNlPLyo2VE7sfTgE7tYuwbF6/r3RicwweImHb/pxMpqWmAOZb47/7qXesh9v1J4Kr
         ghTBL644zLuxFChWhBbjBRvdo6Rg6/Q13DvrAWc7bbt0Lo9CE2zOKs5CJlZ/L35+vIMu
         qdN8tr6tdCl3XPhzJMppDJ0Bzay97dfvLyU9pTPX47SnZILZa5V+TjmtFT02r263uyaP
         KdZQ==
X-Forwarded-Encrypted: i=2; AJvYcCWKd4Sp5IyHehf68xD8GRCGmL25CE3JWN1D/3yHjdiEX7nAgXAOzr/tfxJwD44EdMHDc+8Fig==@lfdr.de
X-Gm-Message-State: AOJu0YxCP/XSYdFTjAGg0EBfUNg/3Z21QhxkjzQ1/NCyulBnUYWHazmF
	mLJtcQaSAfNspoc3grxZ51btY9lBKAMeMZZXfU8dFIXS8u9Y1+e7
X-Google-Smtp-Source: AGHT+IEh1dRWkzGQS6c5LTCOZQp1ziIRD5l1JyZc0Sj5QtzI722SvhEEUQkn3lJeDIcNkuUrrsvMmA==
X-Received: by 2002:ad4:5c6d:0:b0:6e8:e8dd:3088 with SMTP id 6a1803df08f44-6ef0f68d8d2mr40969846d6.37.1743691897376;
        Thu, 03 Apr 2025 07:51:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ5VnzH5gzF1rf0jzKvqP09DqGp6Ios6f4BfIUdhJjEzQ==
Received: by 2002:a0c:c587:0:b0:6e4:4503:bac4 with SMTP id 6a1803df08f44-6ef0bd70188ls7222726d6.0.-pod-prod-01-us;
 Thu, 03 Apr 2025 07:51:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXkBft+9kJivtOg7qFGEjkOx9COofyQ+uThsc9sySwin0p2Yx7tddgEds3KOm3iRP5NM2fG1ARwC7Y=@googlegroups.com
X-Received: by 2002:a05:6102:3ca1:b0:4c1:9695:c7c with SMTP id ada2fe7eead31-4c84a08197fmr2399678137.24.1743691896509;
        Thu, 03 Apr 2025 07:51:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743691896; cv=none;
        d=google.com; s=arc-20240605;
        b=ZHzX9xfuO0E/sWRD9VCqyrLF/XpVX4K7zLeCFgQHoCh62XV0U/ddSrM2TU7i38tsxM
         JxZTQh6CZQwfZp2+akfC8S3AMRrG0dr4Xb4PVCnzz5G8/ozsyfzjNWryti+UDwLRj09F
         wJSju94+IaGRdxEgUJ1MLF8USbeIznsy/6iIhwpJaMLDT44eoUzqJ83u9xrxZqFtaoeI
         0Yhn0fZYdyzzuL9eDKtDih2iOEA+GPjDVZCOxuLz/KHOcNLlINdTGgN4gAzHnRGOOtXG
         usyvpwH8JDlK8QKguj81vDslWUZrRkBZVTf6AKAfuXbZ22HWguaj21BXOL2zIKjVU6WM
         IrkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/801BK3gg46trbNVYHKVbmii4Kl/4WzYkNAcEgGrBB4=;
        fh=Ue6U+JzdxexbbunoK+PYTyCCG2hzFHlKE93B5LZBO7w=;
        b=Q4qVhe1sC2nWd1y+qIXHLSgL161zuD8TECkOmOxPZoYSLhDKf/chVhLUvrhk6Pr0Og
         Di/bK/Dxjl5CGwysHCDOVOgDBUR2acPa7BnBkmipESyOhxwqclBMP7S3JUIF3rFDWJDi
         ultwj7RZlZZnhXJ1m/rZZoOhBtjTOw97IrThdcLyyQw13VUEEfLVdz+NplUUPIbFevQy
         oMO5Ah3cvEnhcEt73BaWPZBWg5gpqYqgoB0BSf5941oMQoe5CjQ8ogLIM2dkjdV6DYYP
         WqoL+rfjN0v4zQMtPXq8JYHpwV1CZp0MEqSXW3bpp5aeqjCil64yXGtrFcpECRCEE6ZS
         Fo3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xspjoM+G;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4c84919aac2si77434137.0.2025.04.03.07.51.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Apr 2025 07:51:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-6e17d3e92d9so8606196d6.1
        for <kasan-dev@googlegroups.com>; Thu, 03 Apr 2025 07:51:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxiN5zKJHB1lYrDuj5IRu7Ec7iFqSjVjiXwYfwBBd6N9UOOde2by7+w3FxClmYWFA+Ak9p2uhxo4A=@googlegroups.com
X-Gm-Gg: ASbGncsbQrDR4nf7+THH5EPgrRUBxczgpTsPJ85W2YnavG0LZikYnJBu1BB/82/0ewW
	iOic9TwkDfaTh9XxwSNPNHakJ+0FBv+BlkFHRotDnrDdGk8KXNZZcrQD0e//15xj6b+t7XCnSRq
	zBJXdI2+TSMzeR5mVQj3oMSH1pFj+sp68KK7iUPdeBtwkTm3xaqMUrNs8e
X-Received: by 2002:a05:6214:482:b0:6e8:fac2:2e95 with SMTP id
 6a1803df08f44-6ef0f573b0bmr37493646d6.11.1743691895883; Thu, 03 Apr 2025
 07:51:35 -0700 (PDT)
MIME-Version: 1.0
References: <20250321145332.3481843-1-kent.overstreet@linux.dev>
 <CAG_fn=WmyMug7mkD57OubPz31mH_W7C1u-VStCQ7UeYh_CCtPg@mail.gmail.com> <vd736huqp7kfy3gbzeowm2kzk72nst2s37knhuwlqvncwpsl22@oxilwothvgta>
In-Reply-To: <vd736huqp7kfy3gbzeowm2kzk72nst2s37knhuwlqvncwpsl22@oxilwothvgta>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Apr 2025 16:50:59 +0200
X-Gm-Features: ATxdqUEEz3A9XZEc54ThHMoquCtX_p3ddEqC75438ynrhO8XgHp6ip35bInFLac
Message-ID: <CAG_fn=UM27-8G8XsWEHSGACEwOyeuKzdTf1benQEtZ1WwAWg+Q@mail.gmail.com>
Subject: Re: [PATCH] kmsan: disable recursion in kmsan_handle_dma()
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xspjoM+G;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> If you want to reproduce it, use ktest:
> https://evilpiepirate.org/git/ktest.git/

I encountered a minor issue setting ktest up, see
https://github.com/koverstreet/ktest/issues/38

> btk run -IP ~/ktest/tests/fs/bcachefs/kmsan-single-device.ktest crc32c
>
> (or any kmsan test)
>
> And you'll have to create a kmsan error since I just fixed them - in the
> example below I deleted the #if defined(KMSAN) checks in util.h.
>
> The thing that's required is virtio-console, since that uses DMA unlike
> a normal (emulated or no) serial console.
>
> > I started looking, and in general I don't like how inconsistently
> > kmsan_in_runtime() is checked in hooks.c
> > I am currently trying to apply Marco's capability analysis
> > (https://web.git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/l=
og/?h=3Dcap-analysis/dev)
> > to validate these checks.
>
> Yeah, I was noticing that.
>
> Would lockdep or sparse checks be useful here? You could model this as a
> lock you want held or not held, no?

This is basically what CONFIG_CAPABILITY_ANALYSIS is doing:
https://lore.kernel.org/all/20250304092417.2873893-1-elver@google.com/T/#u


> WARNING: CPU: 1 PID: 451 at mm/kmsan/kmsan.h:114 kmsan_internal_check_mem=
ory+0x317/0x550

I managed to trigger these warnings on kernel 6.14.

After enabling the capability analysis for KMSAN and fixing its
reports (https://github.com/google/kmsan/commits/kmsan-capabilities/)
the warnings were gone, but there was a KMSAN report, after which the
tests started OOMing:

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
BUG: KMSAN: uninit-value in __alloc_pages_slowpath+0xe6e/0x10a0
mm/page_alloc.c:4416
 __alloc_pages_slowpath+0xe6e/0x10a0 mm/page_alloc.c:4416
 __alloc_frozen_pages_noprof+0x4f2/0x930 mm/page_alloc.c:4752
 __alloc_pages_noprof mm/page_alloc.c:4773
 __folio_alloc_noprof+0x51/0x170 mm/page_alloc.c:4783
 __folio_alloc_node_noprof include/linux/gfp.h:276
 folio_alloc_noprof include/linux/gfp.h:311
 filemap_alloc_folio_noprof include/linux/pagemap.h:668
 __filemap_get_folio+0x7f0/0x14b0 mm/filemap.c:1970
 grow_dev_folio fs/buffer.c:1039
 grow_buffers fs/buffer.c:1105
 __getblk_slow fs/buffer.c:1131
 bdev_getblk+0x1e4/0x920 fs/buffer.c:1431
...
Uninit was stored to memory at:
 __alloc_pages_slowpath+0xe67/0x10a0 mm/page_alloc.c:4417
 __alloc_frozen_pages_noprof+0x4f2/0x930 mm/page_alloc.c:4752
 __alloc_pages_noprof mm/page_alloc.c:4773
 __folio_alloc_noprof+0x51/0x170 mm/page_alloc.c:4783
 __folio_alloc_node_noprof include/linux/gfp.h:276
 folio_alloc_noprof include/linux/gfp.h:311
 filemap_alloc_folio_noprof include/linux/pagemap.h:668
 __filemap_get_folio+0x7f0/0x14b0 mm/filemap.c:1970
 grow_dev_folio fs/buffer.c:1039
 grow_buffers fs/buffer.c:1105
 __getblk_slow fs/buffer.c:1131
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D

Have you seen something like that? Perhaps this is related to me not
using the top of the tree kernel?
Anyways, could you give a shot to the patches above (except for
"DO-NOT-SUBMIT: kmsan: enable capability analysis", which you won't
need)?


> Modules linked in:
>
> CPU: 1 UID: 0 PID: 451 Comm: kworker/u64:5 Not tainted 6.14.0-rc6-ktest-0=
0264-g78d9afd5262f-dirty #158
>
> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.=
16.3-2 04/01/2014
>
> Workqueue: btree_update btree_interior_update_work
>
> RIP: 0010:kmsan_internal_check_memory+0x317/0x550
>
> Code: a2 1c 59 03 00 45 89 ef 74 ca e9 44 02 00 00 0f 0b c6 05 8c 1c 59 0=
3 00 83 3d 88 1c 59 03 00 0f 84 26 fe ff ff e9 2b 02 00 00 <0f> 0b c6 05 71=
 1c 59 03 00 83 3d 6d 1c 59 03 00 0f 84 93 fe ff ff
>
> RSP: 0018:ffff8881ee4727d0 EFLAGS: 00010002
>
> RAX: ffff8881d41365b8 RBX: 0000000000000000 RCX: 0000000000000001
>
> RDX: 0000000000000002 RSI: ffff88827dbf5400 RDI: ffff888105337a04
>
> RBP: 0000000000000000 R08: ffff88827dbf6000 R09: ffff888105337a00
>
> R10: 0000000000000000 R11: ffffffffffffffff R12: ffff888104b37a00
>
> R13: 0000000000000008 R14: 000000000d8c007c R15: 00000000ffffffff
>
> FS:  0000000000000000(0000) GS:ffff88827cb00000(0000) knlGS:0000000000000=
000
>
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>
> CR2: 0000561140a700d0 CR3: 000000020b88b000 CR4: 0000000000750eb0
>
> PKRU: 55555554
>
> Call Trace:
>
>  <TASK>
>
>  ? show_trace_log_lvl+0x2af/0x470
>
>  ? kmsan_handle_dma+0x99/0xb0
>
>  ? __warn+0x24c/0x5b0
>
>  ? kmsan_internal_check_memory+0x317/0x550
>
>  ? report_bug+0x5e6/0x8f0
>
>  ? kmsan_internal_check_memory+0x317/0x550
>
>  ? handle_bug+0x63/0x90
>
>  ? exc_invalid_op+0x1a/0x50
>
>  ? asm_exc_invalid_op+0x1a/0x20
>
>  ? kmsan_internal_check_memory+0x317/0x550
>
>  kmsan_handle_dma+0x99/0xb0
>
>  virtqueue_add+0x36c8/0x5cf0
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  virtqueue_add_outbuf+0x93/0xc0
>
>  put_chars+0x37e/0x890
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? get_chars+0x270/0x270
>
>  hvc_console_print+0x28e/0x7d0
>
>  ? kmsan_internal_set_shadow_origin+0x71/0xf0
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? hvc_remove+0x1e0/0x1e0
>
>  console_flush_all+0x762/0xfe0
>
>  console_unlock+0x104/0x560
>
>  vprintk_emit+0x6f0/0x970
>
>  _printk+0x18e/0x1d0
>
>  ? _raw_spin_unlock_irqrestore+0x1f/0x40
>
>  kmsan_report+0x90/0x2a0
>
>  ? kmsan_internal_chain_origin+0xb6/0xd0
>
>  ? bch2_btree_insert_key_leaf+0x231/0xda0
>
>  ? kmsan_internal_chain_origin+0x5d/0xd0
>
>  ? kmsan_internal_memmove_metadata+0x173/0x220
>
>  ? rw_aux_tree_set+0x2f2/0x420
>
>  ? bch2_bset_fix_lookup_table+0xa81/0xd20
>
>  ? bch2_bset_insert+0xb6f/0x1540
>
>  ? bch2_btree_bset_insert_key+0x991/0x23e0
>
>  ? bch2_btree_insert_key_leaf+0x231/0xda0
>
>  ? __bch2_trans_commit+0xa05e/0xb430
>
>  ? btree_interior_update_work+0x191c/0x4000
>
>  ? process_scheduled_works+0x88b/0x1730
>
>  ? worker_thread+0xd2c/0x1200
>
>  ? kthread+0x9c7/0xc80
>
>  ? ret_from_fork+0x56/0x70
>
>  ? ret_from_fork_asm+0x11/0x20
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? bch2_bset_insert+0x14a1/0x1540
>
>  ? filter_irq_stacks+0x47/0x180
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? __bkey_unpack_pos+0x5ac/0x780
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  __msan_warning+0x8c/0x110
>
>  bch2_bset_verify_rw_aux_tree+0x8b3/0xa00
>
>  bch2_bset_fix_lookup_table+0xa8c/0xd20
>
>  bch2_bset_insert+0xb6f/0x1540
>
>  ? bch2_btree_node_iter_bset_pos+0x130/0x280
>
>  bch2_btree_bset_insert_key+0x991/0x23e0
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  bch2_btree_insert_key_leaf+0x231/0xda0
>
>  __bch2_trans_commit+0xa05e/0xb430
>
>  ? btree_interior_update_work+0x191c/0x4000
>
>  btree_interior_update_work+0x191c/0x4000
>
>  ? bch2_fs_btree_interior_update_init_early+0x1c0/0x1c0
>
>  process_scheduled_works+0x88b/0x1730
>
>  worker_thread+0xd2c/0x1200
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  kthread+0x9c7/0xc80
>
>  ? schedule_tail+0x125/0x1b0
>
>  ? pr_cont_work+0xb70/0xb70
>
>  ? kthread_unuse_mm+0x140/0x140
>
>  ret_from_fork+0x56/0x70
>
>  ? kthread_unuse_mm+0x140/0x140
>
>  ret_from_fork_asm+0x11/0x20
>
>  </TASK>
>
> ---[ end trace 0000000000000000 ]---
>
> ------------[ cut here ]------------
>
> WARNING: CPU: 1 PID: 451 at mm/kmsan/kmsan.h:121 kmsan_internal_check_mem=
ory+0x22f/0x550
>
> Modules linked in:
>
> CPU: 1 UID: 0 PID: 451 Comm: kworker/u64:5 Tainted: G        W          6=
.14.0-rc6-ktest-00264-g78d9afd5262f-dirty #158
>
> Tainted: [W]=3DWARN
>
> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.=
16.3-2 04/01/2014
>
> Workqueue: btree_update btree_interior_update_work
>
> RIP: 0010:kmsan_internal_check_memory+0x22f/0x550
>
> Code: 00 ff 88 b0 0f 00 00 0f 84 ef fe ff ff eb 1b 65 48 8b 04 25 c0 d0 0=
a 00 48 05 78 09 00 00 ff 88 b0 0f 00 00 0f 84 d2 fe ff ff <0f> 0b c6 05 59=
 1d 59 03 00 83 3d 55 1d 59 03 00 0f 84 bc fe ff ff
>
> RSP: 0018:ffff8881ee4727d0 EFLAGS: 00010002
>
> RAX: ffff8881d41365b8 RBX: 0000000000000000 RCX: 0000000000000000
>
> RDX: 0000000000000010 RSI: ffff888105337a00 RDI: 000000000d8c007c
>
> RBP: 0000000000000000 R08: 0000000000000007 R09: 0000000000000000
>
> R10: 0000000000000000 R11: ffffffffffffffff R12: ffff888104b37a00
>
> R13: 0000000000000008 R14: 000000000d8c007c R15: 00000000ffffffff
>
> FS:  0000000000000000(0000) GS:ffff88827cb00000(0000) knlGS:0000000000000=
000
>
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>
> CR2: 0000561140a700d0 CR3: 000000020b88b000 CR4: 0000000000750eb0
>
> PKRU: 55555554
>
> Call Trace:
>
>  <TASK>
>
>  ? show_trace_log_lvl+0x2af/0x470
>
>  ? kmsan_handle_dma+0x99/0xb0
>
>  ? __warn+0x24c/0x5b0
>
>  ? kmsan_internal_check_memory+0x22f/0x550
>
>  ? report_bug+0x5e6/0x8f0
>
>  ? kmsan_internal_check_memory+0x22f/0x550
>
>  ? handle_bug+0x63/0x90
>
>  ? exc_invalid_op+0x1a/0x50
>
>  ? asm_exc_invalid_op+0x1a/0x20
>
>  ? kmsan_internal_check_memory+0x22f/0x550
>
>  kmsan_handle_dma+0x99/0xb0
>
>  virtqueue_add+0x36c8/0x5cf0
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  virtqueue_add_outbuf+0x93/0xc0
>
>  put_chars+0x37e/0x890
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? get_chars+0x270/0x270
>
>  hvc_console_print+0x28e/0x7d0
>
>  ? kmsan_internal_set_shadow_origin+0x71/0xf0
>
>  ? kmsan_get_metadata+0x100/0x150
>
>  ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>
>  ? hvc_remove+0x1e0/0x1e0
>
>  console_flush_all+0x762/0xfe0
>
>  console_unlock+0x104/0x560
>
>  vprintk_emit+0x6f0/0x970
>
>  _printk+0x18e/0x1d0
>
>  ? _raw_spin_unlock_irqrestore+0x1f/0x40
>
>  kmsan_report+0x90/0x2a0
>
>  ? kmsan_internal_chain_origin+0xb6/0xd0
>
>  ? bch2_btree_insert_key_leaf+0x231/0xda0
>
>  ? kmsan_internal_chain_origin+0x5d/0xd0
>
>  ? kmsan_internal_memmove_metadata+0x173/0x220
>
>  ? rw_aux_tree_set+0x2f2/0x420
>
>  ? bch2_bset_fix_lookup_table+0xa81/0xd20
>
>  ? bch2_bset_insert+0xb6f/0x1540
>
>  ? bch2_btree_bset_insert_key+0x991/0x23e0
>
>  ? bch2_btree_insert_key_leaf+0x231/0xda0
>
>  ? __bch2_trans_commit+0xa05e/0xb430
>
>  ? btree_interior_update_work+0x191c/0x4000
>
>  ? process_scheduled_works+0x88b/0x1730
>
>  ? worker_thread+0xd2c/0x1200
>
>  ? kthread+0x9c7/0xc80
>
>  ? ret_from_fork+0x56/0x70
>
>  ? ret_from_fork_asm+0x11/0x20
>
>  ? kmsan_get_metadata+0x100/0x150
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev=
/vd736huqp7kfy3gbzeowm2kzk72nst2s37knhuwlqvncwpsl22%40oxilwothvgta.



--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUM27-8G8XsWEHSGACEwOyeuKzdTf1benQEtZ1WwAWg%2BQ%40mail.gmail.com.
