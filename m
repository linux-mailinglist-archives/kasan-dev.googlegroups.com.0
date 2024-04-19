Return-Path: <kasan-dev+bncBCRMF4OWZYARBJNXRCYQMGQEV2HXOIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D5B48AA908
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Apr 2024 09:22:15 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1e438f8dd99sf23273235ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Apr 2024 00:22:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713511334; cv=pass;
        d=google.com; s=arc-20160816;
        b=V9lIQ5b2k0UufDMfMGmNTGeuV3YfrGcg/BfmTIL0KOoDpqKHuPW4Kkx0uZ5nBv8BVN
         uXxO1R/BbTKhBMhobgU0wmxVOf4ObgdSQj9zlsJGJCX1HEBiUGXR/3PlO2qr8Y/Er1K2
         ND6D9v7A3Xibd1a5srbchnpG3vz8ApTpKjB4g9pNM/VW/xkkGPPDuXaMfMSI9pA/92b2
         D3pS8bNcl3449NmWc+m0gb69wIpsCrwCwWucD2oGz+XspCKRR4VAIsAMKcAjSBJIgV1c
         wWLDiUMBi6/eUcbPOoEe461nr5BNafourDOrcSQWgG77dts7MIWmbA2sFBWwVYBvFx0K
         eCrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=XMrtqqb2ZQTFg4kPdj+Wup+xgFyAudc7KjwA+kIbjSU=;
        fh=vZpZDGTMBmh8vgJoFo0Fgi83V9hY+AaX84klgPYJVrU=;
        b=MhN3RdSHroGV65iRuddmXHGYQYGdLJhdJC9BDr1gE+ZiWPq6wd5GHkyH8AkH9/snbO
         d0OXFm5MaktaARP0t2/A0J4aYhz2uH5OYKwK1ZRshSe1NKwUfM84UQ7mGD4N2BoE+Fti
         b8tbKqrOl0sbmnOpJ5cadGmLCIsM3NSi52KG13EN+KFJ6MpIzVIynkvK3dAYQCNnZjl6
         runTWHiDmRkCFK4NZkbFSJanE/HYqx7b/4eegtr2/+IlVDlbNj1BdphuK0YLqxbgPdlZ
         UhieSLFTzWUhr5qc0JSWc1XK22C3lRtx4UMJrEFzF5Kp+snIeCUTRlwyCXqMd/KLTuyV
         golA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dZM8nHLn;
       spf=pass (google.com: domain of xiubli@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=xiubli@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713511334; x=1714116134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XMrtqqb2ZQTFg4kPdj+Wup+xgFyAudc7KjwA+kIbjSU=;
        b=LffvqyIXo4CrevPwc5GYkN9y5bnCWT/eXo9gGHtlSdGB0AHU8n4DCQ+KNBzvF/bH9C
         UJ/2b1WZb3qPhQioNS8s4W4mjfWFtd46qjjmcXVGL6HfsB0i/aW6tNZ4fQfWtSIrejla
         d6EquTuN8n/2TBctH1Hh7MzSM56o3y/73+gneEXIHRsRD41L++3poPekPSEoBDlAYGLS
         KqcfZxJajetNbhomUZheWu1oZc3kv+FSYGXeKUQwjc0JchehfSGX6jyr4RRXdqauuBZs
         Vm/kHFjY19G/MlREGrAeHaNGZQvM/j8Gv2uy7UKWyj/OPueZZF6ZRtxpNlQtUt04WEFY
         iN9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713511334; x=1714116134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XMrtqqb2ZQTFg4kPdj+Wup+xgFyAudc7KjwA+kIbjSU=;
        b=UunRQsQpiagR3wYb0WgKqUjCR47XfHwvKPK64g6CnOeqUhPqI6O6skN9J9XCUJQBty
         XW29rGgXxyzbN84QC21zgKWEnYjpUzbeXZFoyez0T3E4yIhDzBX3r4To559W47wRs+E6
         YjvNASAaw1XD/1WugJk2JpRjWIF6WTjY5ba9NURVE/pV/wuzMF/2sDq0cKJwFnBcx650
         HJXXWQxa6wBf4ntLH/Eg0iTdpDoNHeRumAf0YViu+BqkGShwuytrau2sNky8q0ecBwt9
         70Hk+J8RNoU5H0lLRBtiZjm6OYTdOP16SYq+uRtontzJCPkLfwyo2CuiuJl4Yku5DjRl
         ZdDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUyrA4DEHuVDDhELMkka9WiIvkIcOkGNfGtUJUTOWWmKxJSx5D015GvU+5FFtpUXvUqctIERipvuVcAd4jvlHJlJ4erwPkkuA==
X-Gm-Message-State: AOJu0YzRK5OsjIf2R8AH2kKYy0coPsncN6390Pp6yZs3LXBE7+6T2F7B
	4OJjY2f1gVyIzz8Y5aOi/NJCydeITsbNavDkFhk76ohhmX9fcCrM
X-Google-Smtp-Source: AGHT+IFxKKbzFdP+PevK0ABM0satMaUAjS7TStvE7ysWEq34Q2+JXVrIc0Cj6RlnA5oWfU/Xz4SK6g==
X-Received: by 2002:a17:902:f790:b0:1e8:cc30:b527 with SMTP id q16-20020a170902f79000b001e8cc30b527mr1546284pln.2.1713511333670;
        Fri, 19 Apr 2024 00:22:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:32d2:b0:1e5:1108:afca with SMTP id
 d9443c01a7336-1e8bb1c51d2ls5301515ad.1.-pod-prod-03-us; Fri, 19 Apr 2024
 00:22:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQ2KvOdqDqmpwFbGBOm13dGk7aSNhmN7fanHmMJGgXyc3Et7OAICT8T3BDtGVSXK3yIbta60eKHDR3mjITnvR7CzAaqVSIyqNMsw==
X-Received: by 2002:a17:902:7041:b0:1e2:c1fd:7bc9 with SMTP id h1-20020a170902704100b001e2c1fd7bc9mr1126800plt.8.1713511331911;
        Fri, 19 Apr 2024 00:22:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713511331; cv=none;
        d=google.com; s=arc-20160816;
        b=LeMKsXXjFEDqfz7TCNnUs2mkn4SrZD8ox1GPqlCLUR9XiAVlhtMOR6OPAkEk6yX72z
         O8we6G/RhVTVdBw38JmTT5SolCzICtb+gXDK0d1gWAskagSEgY6E7Af2HACC+ypvt2PE
         ddh3f0a4qw1eDYWF+iXyu1cbu2rzCofs9KuMD6xSwROivrHEoZiCAzOdCMKTyQLMz2et
         tmjn7PstQsmJNCSX1RoMOIaSAx4OBfmKcSqHUZ2vc24cw2o4K/GdCNYhnQ+naJzQuDum
         JmLS0dpYStpNwOf0Rgu71IELVAacHMDDS0R2LFu2IEf13QKWHoIUUIplygiz0P+bYhqP
         0f0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=9ufghlX9X/YZxYGKjwh33+ZH4tDDTY460s6418shg9c=;
        fh=kDgTUXEcEezKJZhCER3f1DSQT/Vro2nSYc0kq/CNnWw=;
        b=cMdufLViLcYdGunwtWxPQAnoV34qFWjLfH5urDVY91894UGqz6kEID4p5UfJsSKivW
         JEo9xTlTWWeJDOzbC6mqIVuUnUWtFDMV3e3BGCHVmbniGWvc03JV3JKjQN1PSRIJChgq
         33bcm/lR5lp5Qmy1E2WeJdIUp8GZRAlupKcFam9C25t44uyQD9cVeDI7gwiWWUPasmLC
         n/rAvzJpGPwHt1cEpohiv8UyZ+N/aIbWAogXBhkhKFTHkg0yG9OCVgAM2j70n/1wenzF
         jzklDhe/1Ozp7xSsksUKIko04+3eiCb814kOpYwBlRdS0HjKoU9uFMnV1uim28MMzg12
         ivsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dZM8nHLn;
       spf=pass (google.com: domain of xiubli@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=xiubli@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id f12-20020a17090274cc00b001defa30ea2bsi185922plt.9.2024.04.19.00.22.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Apr 2024 00:22:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of xiubli@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-pf1-f198.google.com (mail-pf1-f198.google.com
 [209.85.210.198]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-591-a-gRYIiyN_qn4fhxGGN9Fg-1; Fri, 19 Apr 2024 03:22:07 -0400
X-MC-Unique: a-gRYIiyN_qn4fhxGGN9Fg-1
Received: by mail-pf1-f198.google.com with SMTP id d2e1a72fcca58-6ed2471eda0so1644514b3a.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Apr 2024 00:22:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV3CbanQcOvcqUgPzM7iqbzuIj4gcvvmj1p21G/Aav3oOGC3NyLiiyZdN976zrQLgfeTGWzRm0BUEMlR0BCqhq77447pyfdDKmqUw==
X-Received: by 2002:a05:6a00:2d87:b0:6ec:eacb:ecd2 with SMTP id fb7-20020a056a002d8700b006eceacbecd2mr1350366pfb.33.1713511326068;
        Fri, 19 Apr 2024 00:22:06 -0700 (PDT)
X-Received: by 2002:a05:6a00:2d87:b0:6ec:eacb:ecd2 with SMTP id fb7-20020a056a002d8700b006eceacbecd2mr1350355pfb.33.1713511325662;
        Fri, 19 Apr 2024 00:22:05 -0700 (PDT)
Received: from [10.72.116.75] ([43.228.180.230])
        by smtp.gmail.com with ESMTPSA id k124-20020a633d82000000b005f7d61ec8afsm957338pga.91.2024.04.19.00.22.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Apr 2024 00:22:05 -0700 (PDT)
Message-ID: <3ddfc8e2-8404-4a50-861d-a51cab5cd457@redhat.com>
Date: Fri, 19 Apr 2024 15:21:59 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] stackdepot: respect __GFP_NOLOCKDEP allocation flag
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
 Damien Le Moal <damien.lemoal@opensource.wdc.com>,
 Christoph Hellwig <hch@infradead.org>, Dave Chinner <david@fromorbit.com>,
 kasan-dev@googlegroups.com, linux-xfs@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <a0caa289-ca02-48eb-9bf2-d86fd47b71f4@redhat.com>
 <20240418141133.22950-1-ryabinin.a.a@gmail.com>
From: Xiubo Li <xiubli@redhat.com>
In-Reply-To: <20240418141133.22950-1-ryabinin.a.a@gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: xiubli@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dZM8nHLn;
       spf=pass (google.com: domain of xiubli@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=xiubli@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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


On 4/18/24 22:11, Andrey Ryabinin wrote:
> If stack_depot_save_flags() allocates memory it always drops
> __GFP_NOLOCKDEP flag. So when KASAN tries to track __GFP_NOLOCKDEP
> allocation we may end up with lockdep splat like bellow:
>
> ======================================================
>   WARNING: possible circular locking dependency detected
>   6.9.0-rc3+ #49 Not tainted
>   ------------------------------------------------------
>   kswapd0/149 is trying to acquire lock:
>   ffff88811346a920
> (&xfs_nondir_ilock_class){++++}-{4:4}, at: xfs_reclaim_inode+0x3ac/0x590
> [xfs]
>
>   but task is already holding lock:
>   ffffffff8bb33100 (fs_reclaim){+.+.}-{0:0}, at:
> balance_pgdat+0x5d9/0xad0
>
>   which lock already depends on the new lock.
>
>   the existing dependency chain (in reverse order) is:
>   -> #1 (fs_reclaim){+.+.}-{0:0}:
>          __lock_acquire+0x7da/0x1030
>          lock_acquire+0x15d/0x400
>          fs_reclaim_acquire+0xb5/0x100
>   prepare_alloc_pages.constprop.0+0xc5/0x230
>          __alloc_pages+0x12a/0x3f0
>          alloc_pages_mpol+0x175/0x340
>          stack_depot_save_flags+0x4c5/0x510
>          kasan_save_stack+0x30/0x40
>          kasan_save_track+0x10/0x30
>          __kasan_slab_alloc+0x83/0x90
>          kmem_cache_alloc+0x15e/0x4a0
>          __alloc_object+0x35/0x370
>          __create_object+0x22/0x90
>   __kmalloc_node_track_caller+0x477/0x5b0
>          krealloc+0x5f/0x110
>          xfs_iext_insert_raw+0x4b2/0x6e0 [xfs]
>          xfs_iext_insert+0x2e/0x130 [xfs]
>          xfs_iread_bmbt_block+0x1a9/0x4d0 [xfs]
>          xfs_btree_visit_block+0xfb/0x290 [xfs]
>          xfs_btree_visit_blocks+0x215/0x2c0 [xfs]
>          xfs_iread_extents+0x1a2/0x2e0 [xfs]
>   xfs_buffered_write_iomap_begin+0x376/0x10a0 [xfs]
>          iomap_iter+0x1d1/0x2d0
>   iomap_file_buffered_write+0x120/0x1a0
>          xfs_file_buffered_write+0x128/0x4b0 [xfs]
>          vfs_write+0x675/0x890
>          ksys_write+0xc3/0x160
>          do_syscall_64+0x94/0x170
>   entry_SYSCALL_64_after_hwframe+0x71/0x79
>
> Always preserve __GFP_NOLOCKDEP to fix this.
>
> Fixes: cd11016e5f52 ("mm, kasan: stackdepot implementation. Enable stackdepot for SLAB")
> Reported-by: Xiubo Li <xiubli@redhat.com>
> Closes: https://lore.kernel.org/all/a0caa289-ca02-48eb-9bf2-d86fd47b71f4@redhat.com/
> Reported-by: Damien Le Moal <damien.lemoal@opensource.wdc.com>
> Closes: https://lore.kernel.org/all/f9ff999a-e170-b66b-7caf-293f2b147ac2@opensource.wdc.com/
> Suggested-by: Dave Chinner <david@fromorbit.com>
> Cc: Christoph Hellwig <hch@infradead.org>
> Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> ---
>   lib/stackdepot.c | 4 ++--
>   1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 68c97387aa54..cd8f23455285 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -627,10 +627,10 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
>   		/*
>   		 * Zero out zone modifiers, as we don't have specific zone
>   		 * requirements. Keep the flags related to allocation in atomic
> -		 * contexts and I/O.
> +		 * contexts, I/O, nolockdep.
>   		 */
>   		alloc_flags &= ~GFP_ZONEMASK;
> -		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
> +		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL | __GFP_NOLOCKDEP);
>   		alloc_flags |= __GFP_NOWARN;
>   		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
>   		if (page)

Tested it and this patch worked well for me.

Thanks

- Xiubo



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3ddfc8e2-8404-4a50-861d-a51cab5cd457%40redhat.com.
