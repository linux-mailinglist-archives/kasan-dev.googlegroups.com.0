Return-Path: <kasan-dev+bncBDK7LR5URMGRB64R223QMGQEYPCQ56Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C0BF987767
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 18:17:00 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-42cb2c9027dsf8589755e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 09:17:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727367420; cv=pass;
        d=google.com; s=arc-20240605;
        b=TmilUzIiVv+F2M0skTYb5D4byIjk7Fvj4bgv3EoXEZMDW/RMDDpQ6wmfwxCAvtF0Vr
         B5GV22CjUyW83gU1KNhlrisHHYCMBh3xWTxGXgOHtXlAHWqznW5pzXVkJy4QjbvBdejd
         C9ISUEdMPOmqig0uOA5TLLQBbUb1R2OCcqvujzBHgTTkADwOajjrKzhs4k+ze65h+gzb
         WTYVq/CLYw2rWdzfGrqKh+y/nBN1i6f5ySri5fynz9CPbNXUspl2pluR5YJ6h+TH1P7e
         tN+vz6YRDQyPJlVzqBiY3P+EbqyrdVP/vkKmyJNb/oIUGTT9zX0y6oCaC8yixc1DM43a
         Ap2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=6yEd+szXC3dkTieaYJaJas4lceT+qrUfojQiWN1sLO8=;
        fh=4Gqwt9K1XvAIlrMTcdmx4iPXtxNFvKBogHJDkB9MJNs=;
        b=hhdyRH3eUcAQQmxSXroTtF0QKNudkf+Lpx2nQgX13685P+FY7BKIgKxzdMqKY+AqnN
         TvospmdO8SZEhoTywoupXe7+0rYGsX7c8EtQdeTY8+Fqptgnlyqbd2YWEsIUrhe/hygG
         yhFRrmkH5jL0GCo80DktHNEUFnA59CbHjid1gOsoZ5yeJ3aLinDvUXWE7/EwBZbyAIyx
         fJ9ozkXOzSyFURhbCDYLTSz4wusyjvtXqZKBrof/UEl58f8OHhzGOYQW1l8uHAzR/QzH
         wNxU2tDKRDdjCPuY9GRAGXb04wcBZ3MgqNjxZL3C8XpQFa5NbCZPbg5F8kNtIK7MIo6g
         iP2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="a4i13/8D";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727367420; x=1727972220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6yEd+szXC3dkTieaYJaJas4lceT+qrUfojQiWN1sLO8=;
        b=edF1ZhYBKMO/OWwkyWdNXEtfoZIgHbm9xfq9id50+iCEabIfbThIXzPwypWZGTnKwe
         xrbLmO0JbSD1YVKZp7N2hSQfng/tFXnp/Av1AB5XMewbqPwKVQtdl0HgdD3foWv3RBJ4
         erA4Ly9H+tZm30NNl2aqutuF+AN8tMpdI1OfS8qQEpDZQ9qBZHEnxgPBzLs9auFNoKMY
         MMyK6HSIsFJCaj9D/hWjic6UOXZ4wpQFNjc8+Qw93VtJdf12at8CFcVKWL4wgJdtXLlK
         mJZhuo0JskVSJmoyfc11uRSCpbbgJ8V/SQrH0RgasNpHWqCqplIb/IhwsjO4jg941sy2
         DHbg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727367420; x=1727972220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=6yEd+szXC3dkTieaYJaJas4lceT+qrUfojQiWN1sLO8=;
        b=AQGusCLB2NtYzRed9o9Zz0C7l/LhRESHN7WAQS6MrittyqYomayWZl6BcY/G2sKttH
         vdpAW0yOwBUM8WbBG/MjAdiMTjWpK+KBhI4Q8BkMf9v4XU7VOIz0CdyxefBogZxw5GeY
         rbcctPCJxc+NdAOhYg79BmpLhJMmnhwJvc7JMLbzMYb5HVhKkcvBQkd5FPp7uPH0F3x2
         2F3m8Xnk329xyy2/NWJ6z4IOFGcH00HmezcRmuvXmyO4ViTdBBTFBdA8MSQZsLsyz7LY
         F/p7TLu7nr/kAMA0Vpzs8zQv1FohhURQm29JAPozPG7VOjX8ZOwjr7pKeCm+JoJ0FoxM
         YhPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727367420; x=1727972220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6yEd+szXC3dkTieaYJaJas4lceT+qrUfojQiWN1sLO8=;
        b=dfgc40/UjRyaM+iXNZo5UBurWRA+Ez3zvLW5tvEw5lvARhqCADFCj9YjJ6188xVDko
         /cNBx5zXfKRb9r+sNzhrC8jIbWTblVgnGWebGLqoTtrM87LqKO2aYvCsePQDWs2UQlT6
         TcqxuIGL2v7oyDybTTUu3ll98h3ZecSBCNw3xASjlHKQVXD/lQK3P4+7YV2q82qcfDdr
         HGSnAYElBbLuS7WiAkS6ByzlsUyyCko//Uv3wbGvKaT9kIN4tY/+o6ukYe/9hJRZwttQ
         D8+KhbZWpH/ky757tjEDsfhuYu1iDhzJ/bpy85ajd8LNbB0DxE2gzUEHdq8bYzXtgsMz
         ca8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9bdi652MXdJPyh5pTFMa+uiHqfs7XHRLC0JkQ/3oVzTjQknr2VWicSgqy0K/++1K+yN56pQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxisx4NFvSMRtqsgFheX7pbL0BOPNxiPQY4DiROCLJd1GJdb9T2
	+9eJuCGC+YKMbv21XcRO7UnKMh+57+PLXVW8MC9zOrSncsfihu6x
X-Google-Smtp-Source: AGHT+IFeAr9cjpV+FVfzESyo/IZWmwazMzwARofVoQXCIlIyPKL/peUvXMcCIKNPvnZq0KngbJDOOQ==
X-Received: by 2002:a05:600c:1f91:b0:42c:e0da:f155 with SMTP id 5b1f17b1804b1-42f584349a4mr170805e9.11.1727367419426;
        Thu, 26 Sep 2024 09:16:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f85:b0:42c:b1b4:db22 with SMTP id
 5b1f17b1804b1-42f52234f5dls5636655e9.2.-pod-prod-02-eu; Thu, 26 Sep 2024
 09:16:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvCW+meG1QMnK2exB3UmvLPuUG1rAODkdqnGdt4r38d9F5GEUWTzHuZz2et5gCguRVwvnrZV6H+Lw=@googlegroups.com
X-Received: by 2002:a05:600c:4f86:b0:42c:bae0:f066 with SMTP id 5b1f17b1804b1-42f58434768mr141315e9.13.1727367417413;
        Thu, 26 Sep 2024 09:16:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727367417; cv=none;
        d=google.com; s=arc-20240605;
        b=a2gDHOFm2YA2+AuXniW46Yrr7ZKMpYWpd1/UvSIOQudCygcYjtsu/r7/C7tZ1U/UD9
         tQv5D9D5SdNMvhW08Sqld6WvpCjhttFmxpdaFaLOKbjPb9Ychj6wBhEzPO9F9Vur9WzT
         Fwlwrcw6kb18VzrKqZrzLwQHPnovtviD9I9pS0gcsAtJyd5elRKIv6SHfbY9OFz4nIfg
         +M2DF+pMW8Gx+0VIm3Tq4cy1mCNm4KILUKMd2ZlzyiUOb1VcIob8VvgIT/+5fyFSefRK
         cmIyeGrqKR//6pRo9RJoCAxCrcEoaEbRYpfzdMj3PISKuCKLRMPv4dNPWrA1+mrWerH7
         Fufw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=LFxdlhcT77M863PodHeuS0sWay6s4jC4n9D3lU8otZM=;
        fh=8foHwf1eHu7Ted09d+2Yv3f2SrDmR6PNrgEBfnYu1VQ=;
        b=jk6aRCRa4w9NMqLZEyQhBZyedNONvTlkBeV5azoIsQPcYt2liGEUHnvsluw6xV5M5G
         z22NB1bx2Mq4jLC8TAN6iLe2zE8xAZBtsG2C0y5T6kcFrR9oqIysn70lOhBrlNX5ivm6
         7i5FSpFYHADVVFfY77b2uJq8osohtHHUM2oJ07d/LjqgpZMD32k0jcmcbvZ9QximcYAZ
         ZitQ9K0sgnz0eN4kx8XMWLE/pkFB3jYvwmRBWhOOjC4lskWiQAwPQ/wZosQgtKVZ5+vI
         S+WTFGGAXWaZ9KpFtvkLjTB5NndidZ1KE8jG+D5p3u49GT6FXj2kDAWUK7CopheEUELr
         bICw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="a4i13/8D";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e9025c19esi3878935e9.0.2024.09.26.09.16.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Sep 2024 09:16:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id 2adb3069b0e04-53568ffc525so1538935e87.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2024 09:16:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWvL4gAAqSk39hjPZXlS/ALPvCQGBRLQLxt168hDUu3sLTIb+1jQka8tNHc9U9RGZtwK7LeQo4ckbQ=@googlegroups.com
X-Received: by 2002:a05:6512:10c4:b0:52e:a699:2c8c with SMTP id 2adb3069b0e04-5389fc64385mr118423e87.45.1727367416312;
        Thu, 26 Sep 2024 09:16:56 -0700 (PDT)
Received: from pc636 (host-90-233-216-205.mobileonline.telia.com. [90.233.216.205])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-538a0441777sm1359e87.274.2024.09.26.09.16.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Sep 2024 09:16:55 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Thu, 26 Sep 2024 18:16:53 +0200
To: Huang Adrian <adrianhuang0701@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Uladzislau Rezki <urezki@gmail.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	Adrian Huang <ahuang12@lenovo.com>
Subject: Re: [PATCH 1/1] kasan, vmalloc: avoid lock contention when
 depopulating vmalloc
Message-ID: <ZvWI9bnTgxrxw0Dk@pc636>
References: <20240925134732.24431-1-ahuang12@lenovo.com>
 <20240925134706.2a0c2717a41a338d938581ff@linux-foundation.org>
 <CAHKZfL0D6UXvhuiq_GQgCwdKZAQ7CEkajJPpZJ40_e+ZfvHvcw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHKZfL0D6UXvhuiq_GQgCwdKZAQ7CEkajJPpZJ40_e+ZfvHvcw@mail.gmail.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="a4i13/8D";       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12b as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hello, Adrian!

> > >
> > > From: Adrian Huang <ahuang12@lenovo.com>
> > > After re-visiting code path about setting the kasan ptep (pte pointer),
> > > it's unlikely that a kasan ptep is set and cleared simultaneously by
> > > different CPUs. So, use ptep_get_and_clear() to get rid of the spinlock
> > > operation.
> >
> > "unlikely" isn't particularly comforting.  We'd prefer to never corrupt
> > pte's!
> >
> > I'm suspecting we need a more thorough solution here.
> >
> > btw, for a lame fix, did you try moving the spin_lock() into
> > kasan_release_vmalloc(), around the apply_to_existing_page_range()
> > call?  That would at least reduce locking frequency a lot.  Some
> > mitigation might be needed to avoid excessive hold times.
> 
> I did try it before. That didn't help. In this case, each iteration in
> kasan_release_vmalloc_node() only needs to clear one pte. However,
> vn->purge_list is the long list under the heavy load: 128 cores (128
> vmap_nodes) execute kasan_release_vmalloc_node() to clear the corresponding
> pte(s) while other cores allocate vmalloc space (populate the page table
> of the vmalloc address) and populate vmalloc shadow page table. Lots of
> cores contend init_mm.page_table_lock.
> 
> For a lame fix, adding cond_resched() in the loop of
> kasan_release_vmalloc_node() is an option.
> 
> Any suggestions and comments about this issue?
> 
One question. Do you think that running a KASAN kernel and stressing
the vmalloc allocator is an issue here? It is a debug kernel, which
implies it is slow. Also, please note, the synthetic stress test is
not a real workload, it is tighten in a hard loop to stress it as much
as we can.

Can you trigger such splat using a real workload. For example running
stress-ng --fork XXX or any different workload?

Thanks!

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZvWI9bnTgxrxw0Dk%40pc636.
