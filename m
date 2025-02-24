Return-Path: <kasan-dev+bncBD56ZXUYQUBRBQ5E6K6QMGQEI75FXGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EE17A4266D
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2025 16:37:41 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2fc404aaed5sf15139037a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2025 07:37:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740411460; cv=pass;
        d=google.com; s=arc-20240605;
        b=OqdBtr+zZnat9fE7qNpZFGuQwReqqCSvZgQLybdQiBtVM/2AzoWEVgEpJSVob6Pc/z
         6Nmv6nXse5qCCZDPmegrk8YjKJUMY4NdJ/1BM9uvenTR0MCFDaK8Lf4AF9vOFkg0zS3+
         uUJMDzfqTZq4vRRvkBCAhfA3YRskrmDEVamld6n0S9XPRIf/iVCC9tpXY9UO+E2MM9jN
         O/1OuBxT9sL5PWPtW28pKwvGCoTarVUNNM0TYHH1CLokehaBVCmtRYZVismrtkIKVvLR
         He4bIql9SeeHEjgjonffLuBSoZZNiWnyLLgebaYzV+OjEgxhOYEtTTNqtY88JfLU0H6J
         okZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rca4iaMy3lOI8yp5Bh8kxOZO4eav7LuGnqy9QXsbX+M=;
        fh=SNko+fvbKiBwTrwot0pXCWYXDAMn6yKeNgcolxbQdzU=;
        b=Bkq8JU60GVn9Vnrz+QwUHdmTlFSwACFlDZDvaXo2TTmEhP9jwN8O+kWOH4rhz5E69e
         T4XXGxwkR9OPelV1lDvw1igVkT5OjpkyL+96cFLIfPXT4+80+ZxlmSbxDQX/9wUTIlPt
         DVo6CBhca6j2ySTB5ZKk2SnmtkzBV9K5aI3AfaQLaKNL4gGKED1COkyp9V3udjwxz+M6
         WCQgwp4KwMNcGX88/DfR+tk4yERUb5yNcfh+yArhLW2H4apOa1Hoe8lr+S+C9gKZa4sv
         YdzG5p3ilgrkBz5ucl0sZSg3tIsXcEVX8dp0D8LaEtr51t+sr9gZt+iYViCfFNODED9j
         EI7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n26tiAiP;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740411460; x=1741016260; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=rca4iaMy3lOI8yp5Bh8kxOZO4eav7LuGnqy9QXsbX+M=;
        b=EEVBq5CLIDezNVm43lW6+h4GNl+SwI/BhUh9QtCn8uJHWc8VjTraOyh9odbKLTiM+Q
         lZ/xNbUDYbgucISRrPP+q/yzlMdGCyLbeNco/FEYosgWRsLMTLgUbVCZuPTEOto0+WuU
         2UC5Jup6A8nsl6Sk4Fivc5FjjfIBkJno59DMon5EaLYx4shGQ9YhJLfF9MiCwdsImqzO
         y8SKs8rApWqc/CZVnx1T4R4S5yc8qo16vZtujQdu+zkDTLFduxFMmW5YAvNA4R8h6tDm
         ltbnXXIewFzKE+n9X4KfFzRnv2/l5ermrWOxhLBI5Fyqz2ItcZtDrgXjxfV6ZomSTS7O
         qsGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740411460; x=1741016260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rca4iaMy3lOI8yp5Bh8kxOZO4eav7LuGnqy9QXsbX+M=;
        b=XTrNePIMEA8Hf07O1mWMgsSPERp5+icly3Jc1zKnEKewq97komh265kg1ISh6axUUS
         qu2ZXDZQe8HfQWJCtgrpEi3TdYXaBUgIQi6hHIJytl/Ym5THK7YyvQHDF8+8ni6eMgY1
         g2QAhUnQj7xL2iQ+AUfirTQU4Mpeecp7OTXCLw20VOhl82bbNr0j/6FkKwWQOBGLReID
         GI3ifnGJ1xH3I0t0yYCI3pdyRkS3YZCz3ccMUvWiRHHE+cvgc7U1qmxXUk1OjK4x87i+
         I0QWMfviIjTSvsxT1BUUQxJF58eq2FmkTpJPX8Uu2lbgLhc+18immtZraJtylmj8Mumo
         /Ubw==
X-Forwarded-Encrypted: i=2; AJvYcCVLXUOq+7DdrtMKWiCFIawkeefCp/g/+hLk3B9Z+R4DgDiOJ0GS++M0SeJSlBJh6JfoOthAVg==@lfdr.de
X-Gm-Message-State: AOJu0YzATPtweASjU5HHi6Ohq8C+78VNZzG1wQ8DqUpkO4cz08owXHIC
	YDgi2grngOdVgq8TqmIboFEIzZIE9v+NPlX/wrKbl2tCBfYWxEq8
X-Google-Smtp-Source: AGHT+IEufTRcnETYAW3MG9ySkaxYJk84wt+P+xXoPDsuoXb26aFCdrRMyBPaX7NXZYjoZK69D/ZwyA==
X-Received: by 2002:a17:90b:3b4a:b0:2ee:9902:18b4 with SMTP id 98e67ed59e1d1-2fce7b237e6mr23043175a91.27.1740411459660;
        Mon, 24 Feb 2025 07:37:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVERmtyFkdUWFpKPlOLz3NHSqvHbH+QubYX1ws58fk0iSQ==
Received: by 2002:a17:90b:2750:b0:2ee:eb83:1eb0 with SMTP id
 98e67ed59e1d1-2fccbee61b6ls4647755a91.0.-pod-prod-08-us; Mon, 24 Feb 2025
 07:37:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVOrKgbLMFL6e6NZRbNTm4Rfh8tpZ6KaPTZPyumLmLIMor/8gJXbyO6B1Tp0znlOwvVvIoyMA7BAFc=@googlegroups.com
X-Received: by 2002:a17:90b:3b4a:b0:2ee:9902:18b4 with SMTP id 98e67ed59e1d1-2fce7b237e6mr23043062a91.27.1740411458195;
        Mon, 24 Feb 2025 07:37:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740411458; cv=none;
        d=google.com; s=arc-20240605;
        b=OPzgNDk9iFopr6eK4nl5QoB/NdZB8elpwjRxiokSEMgdI5VmqE4lYPzoGDNqDcAq92
         92+GcQO+sFpK4DcUr/xmKh3OPG7QRkzqmvdLFatDDVyXQz4kZFPoTR/lSfHtFSFQVN1y
         djbX2Sln+Tfg7a/wCIFXoYEkEIDBf6wBvPM+Ck+MreQ88ho/P6+RXqfuvsNqEh4fE7F8
         owtLT8/SNYOUAbrUZaNNWUziTWgmSKmm0pROJjVADM/Crx+U1pPu46r6DXo+lEBpaX3g
         eo9wiWOJCNGpP1j9oeNVWsvNWafmatubaWmXj6bSh0KveJy/L3KXXV15S79500sSHCl9
         A4Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KDaVhUlblnEguLdPYS8Pr9ZzC8T1XM3TdpsKGFZcVtw=;
        fh=1wow3HayQGa/5iQEPunvy+urvC4pJQBFzKvhlmEodEo=;
        b=ccW0E2by2rNqf23I/DVLoHWQblGvOG90QP5diB9FvT6Bule1yKzjOXXLXza0hSvU3G
         6NxA4/NiTUae3wMRzOBPWmP6e6EyiPEo09NdaQito6MqwnY0/94ib7oh5g5u55uHOp7E
         foCqgyyrT2h6pfezmimU7yuJP58SPN/xd4Je3fYxmWmLnStv0IsGiCBRA8h1UxA9B11A
         WNTznY6F+GHOiU++Hrbcol3fweODJgaLAUH0hVH6jyFrrZD0CGdN47cLEgI8wbIO5n8x
         sYPNJC82VYd4B8xJucr3/RVf78Qa96PmYynTTxj5li+lkSRtGxQbeovTp7fbtiT6bpR+
         YYQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n26tiAiP;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2fceae303c8si273125a91.0.2025.02.24.07.37.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Feb 2025 07:37:38 -0800 (PST)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 41A945C4888;
	Mon, 24 Feb 2025 15:36:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 12E79C4CED6;
	Mon, 24 Feb 2025 15:37:35 +0000 (UTC)
Date: Mon, 24 Feb 2025 08:37:32 -0700
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z7ySPC32oKBccunx@kbusch-mbp>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Z7xbrnP8kTQKYO6T@pc636>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=n26tiAiP;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Mon, Feb 24, 2025 at 12:44:46PM +0100, Uladzislau Rezki wrote:
> On Fri, Feb 21, 2025 at 06:28:49PM +0100, Vlastimil Babka wrote:
> > > 
> > > The warning indicates that this shouldn't be called from a
> > > WQ_MEM_RECLAIM workqueue. This workqueue is responsible for bringing up
> > > and tearing down block devices, so this is a memory reclaim use AIUI.
> > > I'm a bit confused why we can't tear down a disk from within a memory
> > > reclaim workqueue. Is the recommended solution to simply remove the WQ
> > > flag when creating the workqueue?
> > 
> > I think it's reasonable to expect a memory reclaim related action would
> > destroy a kmem cache. Mateusz's suggestion would work around the issue, but
> > then we could get another surprising warning elsewhere. Also making the
> > kmem_cache destroys async can be tricky when a recreation happens
> > immediately under the same name (implications with sysfs/debugfs etc). We
> > managed to make the destroying synchronous as part of this series and it
> > would be great to keep it that way.
> > 
> > >   ------------[ cut here ]------------
> > >   workqueue: WQ_MEM_RECLAIM nvme-wq:nvme_scan_work is flushing !WQ_MEM_RECLAIM events_unbound:kfree_rcu_work
> > 
> > Maybe instead kfree_rcu_work should be using a WQ_MEM_RECLAIM workqueue? It
> > is after all freeing memory. Ulad, what do you think?
> > 
> We reclaim memory, therefore WQ_MEM_RECLAIM seems what we need.
> AFAIR, there is an extra rescue worker, which can really help
> under a low memory condition in a way that we do a progress.
> 
> Do we have a reproducer of mentioned splat?

We're observing this happen in production, and I'm trying to get more
details on what is going on there. The stack trace says that the nvme
controller deleted a namespace, and it happens to also be the last disk
that drops the slab's final ref, which deletes the kmem_cache. I think
this must be part of some automated reimaging process, as the disk is
immediately recreated followed by a kexec.

Trying to manually recreate this hasn't been successful so far because
it's never the last disk on my test machines, so I'm always seeing a
non-zero ref when deleting namespaces from this nvme workqueue.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z7ySPC32oKBccunx%40kbusch-mbp.
