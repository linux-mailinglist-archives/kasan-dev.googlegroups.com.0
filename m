Return-Path: <kasan-dev+bncBCRMF4OWZYARBWVXQ6YQMGQEG3NRRUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D0D3A8AA70D
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Apr 2024 04:50:04 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1e278ebfea1sf20714655ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Apr 2024 19:50:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713495003; cv=pass;
        d=google.com; s=arc-20160816;
        b=QyCmIrtXvK4J+O9hMb8n8a0W7Atq6XmzJYgtDbWudyRiZa918L1XEc++AhHm5JxJAJ
         wq6Rag2L8I3kVIZSR7xN9dDJw8DXQO8gbPGlTc5ZHKZ6CstZa/IZLRhlZq2oA8UfDVke
         OfnVcebpFQOod/XXgMAttp4JWarsVFSUxT58RCTvPkRBJKaZZwAwhklfKiLC1BNtubvJ
         2ESJydL/RqbNQOGAsykbsdKln9jL4lJHh7NFU2LTtDitPz7Fp8ZnwjVpljnSCcUIL33k
         OlH/ZGeO5iPB9tCz6Rer/s2w4Hxfq9m0VxTyVNbKVaYbLPqw/nCuTCGgln8xf257mTlM
         AeUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=vD5GpDJNYv4/4hDNp/570bCiIDl+O6ZFcEBVBQmy/X0=;
        fh=g8oXlczMJpjcDX5WmaZcoqHb6MMECFlqMobWbunYzc8=;
        b=TpHKzVR6WpJB5u9RsxGrlatoj25c/WRiQ9zBjLgnSdfNMMoqL3tPoPiH2+Cup/tHnn
         P2XRW/AmHAglunS7bPBNBvC2CrAjNCofPx3HRRif2JZHAfyYOLzlLf8NseGBuaTHlQUY
         Q9SeYKD8fwcm/y0RB/cvKcgAhnohjpmINAq5ZNkE9pkhYtvKRtjNlxoxX4YomyJhfqTI
         DrbphSyou+1LiyacB8/F4HzY35sM7lP2OXOe8kbVTkaiAlkrezAgbQUmpdiBJmHJpXGM
         gFC5fqedUVuFC2+pEszLLugdsjYMuFXr8tzTnooYT9pC4JwthrOTD4G6tklFgsTvlk5F
         G2sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Tp7dKfZO;
       spf=pass (google.com: domain of xiubli@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=xiubli@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713495003; x=1714099803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vD5GpDJNYv4/4hDNp/570bCiIDl+O6ZFcEBVBQmy/X0=;
        b=com6ziiGToYU2ttnmdhn3edaKeYBaFJiq2mLHlvgXL/7ND7AIFCSX0++AmxL/ZSIDf
         7l8Sb2rIZDlk79SvCWH9Id9sGSO5YEjStcgj7YXPL++rdlg6zd+uQfcgbS2GIl8NzkTT
         2nsSV2mHyIejAoaCiVzuqFcV7mE9MjqhcY5O4Dy9Wb64/5E5MwMQA4p6zZfrWLkK/mUc
         Su7sThvzlGgC6DhQK891VlqiMk4/Ug9hVJ753vNrz1E4qtmGp9I0eZxyl8TL0RN72Tph
         jOolQQwurwXJClU76ttpMCAjIPVIoNZYZRp/BMl0I1c1pQOP6tgz2D/vNXimcTp1Vf/u
         togw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713495003; x=1714099803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vD5GpDJNYv4/4hDNp/570bCiIDl+O6ZFcEBVBQmy/X0=;
        b=LCYOgTRkWe6ydyOa16WgWsSs8ESb8ajhK87GGjbFj2e0DdGipjdyimecLjqM7SYyXG
         58T4y7cJPXhvz4aNdk3fYcDtu2bfft+hTuPlwvpwJBl7BIzGIMxtqvkf7q1Mb/EtjbN0
         rsjqyia8sfW2p1c1ofyfSCw7cqALHJgala08GZu24G6ApahU+cNQ+in02xHmUM5RFcu6
         +j3aGULzKzXWQ3PDh114Jjqdfk4iJpchiq7m6WGU5DWEyOmt2fYntiGNsgwK7220ym5w
         jigQGJvqJc7UXFxk9HxbRETqSmBP2F/WdGYTqdNIIAKWG63GcJSiRmKcv1qvHHt9GhrX
         0iSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTbPzdDvZn8MfAIHr0k8bhvxtqfH7jgfHcMXx/zurfqd+poxYxk4hFn895htXH2Xky5QkdXAUSgk4vVT/PEYaNL2x45ap4fA==
X-Gm-Message-State: AOJu0YyxWBntbXCkB3p+8A5uutPaXL0D9MQrrVNpNUA9hObyf397LVQi
	ivf3DYCaQMR/sBeSFkjxjJ1pf1rMc6Xjr5sZ+wuQTiqG/LDbTt1d
X-Google-Smtp-Source: AGHT+IGckUwk3yXmxMeyeg/gLMLYuicH+4ymkUVKnDKnkBMmThpuQoqxj37YuqlieDWowL6rUzwKSg==
X-Received: by 2002:a17:902:9881:b0:1e5:963d:963 with SMTP id s1-20020a170902988100b001e5963d0963mr758838plp.68.1713495002776;
        Thu, 18 Apr 2024 19:50:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:32d2:b0:1e5:1108:afca with SMTP id
 d9443c01a7336-1e8bb1c51d2ls3951595ad.1.-pod-prod-03-us; Thu, 18 Apr 2024
 19:50:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVClE/aeVGTE6lJTFRzRe2fz6or2vZdaCcSNblUvCGkCPxunV6Fo7eYmeW+tq/IkCgkbgRt88XWAFhLsYetAeKbEZWKySsCPW9vg==
X-Received: by 2002:a17:902:aa09:b0:1e8:380a:4c9 with SMTP id be9-20020a170902aa0900b001e8380a04c9mr884542plb.36.1713495001137;
        Thu, 18 Apr 2024 19:50:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713495001; cv=none;
        d=google.com; s=arc-20160816;
        b=zqbuAmS98PSUtnaH2VbG2k0aOcQYI/svlyUkD8JVPfB44HaXRqo/QH8HDOaTZuZJfv
         BZ3qLZjLOUeMBpgvloIJ5tUt7u7stZE9k8oVZy900otKMRaoar1fxIHxEHIEcTc1BQ/+
         O/wUsIpmoB9Gn2B5A8N9ZS++mQ/7rkGzfyxYUbLTZgPo8ihAZXYmoXMi3FyT7f6jsTv3
         /ITURQ6WY+izVoLHaIprfEISWQUtq964iZ7F3NqU3Zuo3x1I9VzpRV1gBgHuixP5k517
         /A15Z/z2oRWK6fxXSjF0qotnhQbK0plvPKQp35raG7+Nx2Y/Q+GFTVAo6xJXGTkD3dO5
         DKew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=d1Tjr14BdvOl8V5MxjQ4hi2dx9l67KXMdwhIGgoSO6c=;
        fh=MID11lSMyoCGa9t65pha9mzcPX6ZD0AgE3U1QkkxMmw=;
        b=c+ViBKskSvG+XnJEsNNcIOi3mnjvHEm90T6q2+WFX1Ap6+m1JiYQKiWsN7NPJFBKPG
         Jdz8ld+g8DzbEv1pxmggVWdxu1a/eeQ0c0XRnSprGFqRVgeaIpHPy2qbitCUedAsWkLK
         2q/tL8sSliejIJSOC30VnRqhd9lFHSvKtoDgF0RyuFPJAQORxR9I+Wvnbp22a9PVN5u6
         wnCmZAdkzhRqUXbpdyW/NEo9dSHvIQ7UeEtsdJsyvK2fhHXUSUKfDDfVv98E3dk1ZYh9
         al3NHAMCawXBHi5nNUjkZJr5ELRA9VglfXwySObya+KqO8hbn3HMROFn6rVIiSwXlcqG
         VKFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Tp7dKfZO;
       spf=pass (google.com: domain of xiubli@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=xiubli@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id p18-20020a170902e35200b001e2c4ecc402si193121plc.8.2024.04.18.19.50.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Apr 2024 19:50:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of xiubli@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-pl1-f199.google.com (mail-pl1-f199.google.com
 [209.85.214.199]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-387-iAvuAMv2NhCOw7GiXNM9qg-1; Thu, 18 Apr 2024 22:49:58 -0400
X-MC-Unique: iAvuAMv2NhCOw7GiXNM9qg-1
Received: by mail-pl1-f199.google.com with SMTP id d9443c01a7336-1e417e43c13so20673955ad.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Apr 2024 19:49:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXKfzaXe6PJbTYXmL89YTcUhD4zFSNLu3PyyxTblXT6ZOEOO6RqQNjPnkvNwtmrszq+UHZMKu0a8eShI+3Nv32Z180Y8j5meJojsw==
X-Received: by 2002:a17:903:244b:b0:1e5:5041:b18a with SMTP id l11-20020a170903244b00b001e55041b18amr1069300pls.40.1713494997561;
        Thu, 18 Apr 2024 19:49:57 -0700 (PDT)
X-Received: by 2002:a17:903:244b:b0:1e5:5041:b18a with SMTP id l11-20020a170903244b00b001e55041b18amr1069285pls.40.1713494997171;
        Thu, 18 Apr 2024 19:49:57 -0700 (PDT)
Received: from [10.72.116.35] ([43.228.180.230])
        by smtp.gmail.com with ESMTPSA id n6-20020a170903110600b001e668c1060bsm2239799plh.122.2024.04.18.19.49.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Apr 2024 19:49:56 -0700 (PDT)
Message-ID: <54b997a0-a04b-44a0-9d40-205267f949c2@redhat.com>
Date: Fri, 19 Apr 2024 10:49:52 +0800
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
 header.i=@redhat.com header.s=mimecast20190719 header.b=Tp7dKfZO;
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

Thanks Andrey,

I will test it soon.

- Xiubo

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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/54b997a0-a04b-44a0-9d40-205267f949c2%40redhat.com.
