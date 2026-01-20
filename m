Return-Path: <kasan-dev+bncBAABBRFJXPFQMGQE76WPQ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id AA353D3BCB3
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 02:05:09 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-430fd96b440sf2956061f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 17:05:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768871109; cv=pass;
        d=google.com; s=arc-20240605;
        b=DYirhaH2W3bWtHx3msIObezWVGO9/Mor2Ag8ykjroiqOHrahUF3exDrOJ4Z5P4HB07
         gumy6+vEbHUL+I+XAtPEhMc7/DoCPDbqNd/1gbSVtKbTf/T0g5de955lmODZCnuk0ifM
         3JMPv8oxpJQev6Iz1Q9Ac1LW0mlOC+NaqS8XuWkjfdBWfQjrwLQm4mhA9bFFWXU8cjip
         PcXJGTolF1UpicATMAt0z/DflozUAwiVCKjH/LWZR1c38OX+pVVQVazTKfu+ILHMTWz6
         lr6QTBL3W+kXzr3TV5aJXv1xSOy3jtHapUqd0HeI+7KzY1uTQSfmFJ3xQJTCKL4oF9Oz
         WtKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HpKFI0ne0XIadNPaL435W+kcnNciO0cygswPVO4GCgg=;
        fh=T7qx3rYB83TAxxV0SPUnPY595ePIB4cQ8k7QV7++Kow=;
        b=NH+xHSOyX7DHQiac9nY01YN7P5ege/uPQhRm5sy8Wzh+M3D3OzLXdg5kW+xmuBn1dj
         NxjhEmPMgISIkPOkunrYfLSUoB8rGaNN/SiCtPeS0lw4Hu9fbPlZs7JZZPKD2DgXWM3/
         FNJDF9+q/b60p3GFkJnk0URQxFJC2jWtSesMMoVc8x2dRTkrzZ8Qo1xaIhqmvrNbB/6E
         856zvJoOwVNzOum4DfOQH8qsFtexI+wxENTOpBsNBZi3Nh0pMxZH2UZDxDzaZ7E2aho8
         r564sTrSaGnu10kM6vYD/UkDjxcYwjUJNVGfyc5CxfAs1WKVPADVYUuIwlLt5afFG1v8
         g3eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IgvM1HwB;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.186 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768871109; x=1769475909; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HpKFI0ne0XIadNPaL435W+kcnNciO0cygswPVO4GCgg=;
        b=GZforoUH/4pnTV3OsxPE5JiY54d9t6vBOd16KChgIWTntbbinn3D8O0raGH1+/NIQ/
         ZGkOtTyvgWbG33rHH4gr02B2EjetbppEP5vLMVhS7JLnh2IG8f/mHdAH9qzH2ylaYBSd
         rtEE4W8iWpAksBJ+vlTrT3st63iPNSjFgib+TK0PHokuf9rrn7aaA2ixuv4aZ/culhlN
         IhlwwY5KniuBYSbh7HvXxSnbi//H8JoIO666Z0KcyIvqph9GTmbVJptDCVPDPYnhsX1m
         n3sSqjh7u99z/AR8cqyXWGed5YLLO9ZrRVXCGsskhbqQ9KsTi0XOuBMAKtFBw+Zu8ikN
         GTXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768871109; x=1769475909;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HpKFI0ne0XIadNPaL435W+kcnNciO0cygswPVO4GCgg=;
        b=I0zvte4H1cF6DtqsJLG9HXfppYBz6BfrFyRV2XXeZnEg2Oj9Xsatv2wYSbbyWFZ5VK
         EPGVLG0rz0CUbRb24b+P3p4TkFUoZBmHaXhIdzI/12pYSG6iE5JVU3mqM75CnM4B3sZv
         9Qceehn/XY3HYIuTvnFHnDNTg63L7OICAszAuhgzqbIXr0WH3k/GcPQTWyvd5LjGv92t
         9WjpO+Mu820MJDsRRzqQwQIo9tSn7k7XWZ3VdHu2TthLDvMShm5AxPOLyX4uzNRy8nR8
         1DxEbqI6jDAUMvJj1KO4CVGBARJRe6Sf1OipdEmB9Wd2zweywfx0BAcWIEr283cw1FJW
         1jeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhqHHGAdscZDSj6lZawb82ARksqpavHMdQwVv/31qLMtfmv017UrWpdkLFe4BLLliMU+Xkcw==@lfdr.de
X-Gm-Message-State: AOJu0YwmSffPvGkDeFzA9NjyZMt8pbaOgoboLDn3h3SI7pu7GlqZ7nrr
	IxH2lWRnb3d792qKQzULCHfcuFwIlpqIBgDtv8MQrrfDToqXuyFuxVqN
X-Received: by 2002:a5d:5f44:0:b0:42b:3246:1681 with SMTP id ffacd0b85a97d-4356a02c4cfmr15944134f8f.18.1768871108739;
        Mon, 19 Jan 2026 17:05:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E8pp1XS+jWJ2G6kBA3wN+l+yWq3qkqVBg2CPeJgAtAYw=="
Received: by 2002:a05:6000:2388:b0:425:57b0:537d with SMTP id
 ffacd0b85a97d-43563e27607ls2768292f8f.0.-pod-prod-04-eu; Mon, 19 Jan 2026
 17:05:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXsi6Lab9ILHPEhZrHT9PpDQw4pFBqo1VI+4YYMkvDqqRavEex8osK6BKLTAQm3oSJl/e2hKbkLzj8=@googlegroups.com
X-Received: by 2002:a05:6000:25c8:b0:431:8da:11aa with SMTP id ffacd0b85a97d-4356a071edbmr12543698f8f.59.1768871106944;
        Mon, 19 Jan 2026 17:05:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768871106; cv=none;
        d=google.com; s=arc-20240605;
        b=TijUrDrIUWw7MShRfVqzwi45FJeNoYui9BspNtqsTgFGchNXlOtwFyLDaTPzaq5r+c
         RuNVKSRt4VZJbff6dQWX5QrwXSfB3+yayLcLs5dC7fpUiObIJ7ejO/XoxYSBGijIJxJp
         ST7n0LlI1gReauMNA7SmNd5ta4Qd3+eKi1uRrvuxWrZUtCRtbKNIaCyPMFWZu2OcdGO2
         fLynDRuXsncDj4+qaK6ZuoIBRQ7s7hbhfGiTh/MzdZVKcEn1f22z7S+h9kocIypzPYc7
         aouT1xICXkuCKk6MnjEvu/LB6VFR/Zhq+DulyuxsuM3QijeUwpP3tYLT6CVT94SPKb8x
         BEvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=9BSJ4ovorQomCz+1Da1Tddw6wlufJXzsgj4XlYQhj7Y=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=IzF3BXdTJ5u3QnX1dqC4zkXVwYFEE0gvSkTATUz7c44tWlm7QOJjyI/gQ3hs+WkjdM
         suu419UTcIFGpQsJG2nQ1sTQTp1TioG/77pX31VvUoyEgaMsd8eIqXsXMTkvrkX0yhwC
         CsL0krZy1SexjSos+BRbC1UR2KgkHjQPb7c+t56TSG/DrWrVksRt+q5heWr+v1D5c3KI
         pVZTxM0ttCuuA5BjiREE8AwEb6ubd18yHs9JLNcO1/rSskKRKpCCRFxH+doWWabT6zlg
         ha8mkHs4XgZ6GBNx0ilCRP/c7IhGGeUP4p4+/S/HXbGajLwgkVx2zwyvh6UX5lhiCvLH
         48Ng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IgvM1HwB;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.186 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta1.migadu.com (out-186.mta1.migadu.com. [95.215.58.186])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356994f0dcsi293145f8f.5.2026.01.19.17.05.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 17:05:04 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 95.215.58.186 as permitted sender) client-ip=95.215.58.186;
Date: Tue, 20 Jan 2026 09:04:49 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 08/21] slab: handle kmalloc sheaves bootstrap
Message-ID: <knn6gyidf6675wzt63hjsoxixqp5x65x3nwqsoi5gizqa76bog@kcvsazfh2lgu>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-8-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-8-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IgvM1HwB;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 95.215.58.186 as permitted
 sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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

On Fri, Jan 16, 2026 at 03:40:28PM +0100, Vlastimil Babka wrote:
> Enable sheaves for kmalloc caches. For other types than KMALLOC_NORMAL,
> we can simply allow them in calculate_sizes() as they are created later
> than KMALLOC_NORMAL caches and can allocate sheaves and barns from
> those.
> 
> For KMALLOC_NORMAL caches we perform additional step after first
> creating them without sheaves. Then bootstrap_cache_sheaves() simply
> allocates and initializes barns and sheaves and finally sets
> s->sheaf_capacity to make them actually used.
> 
> Afterwards the only caches left without sheaves (unless SLUB_TINY or
> debugging is enabled) are kmem_cache and kmem_cache_node. These are only
> used when creating or destroying other kmem_caches. Thus they are not
> performance critical and we can simply leave it that way.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 88 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++---
>  1 file changed, 84 insertions(+), 4 deletions(-)
> 

Looks good to me. Thanks.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/knn6gyidf6675wzt63hjsoxixqp5x65x3nwqsoi5gizqa76bog%40kcvsazfh2lgu.
