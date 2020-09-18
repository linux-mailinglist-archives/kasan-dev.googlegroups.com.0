Return-Path: <kasan-dev+bncBDKJVFPCVIJBBQFOSL5QKGQED7GR3CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F83826FB3E
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 13:17:22 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id e202sf1574050vsc.4
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 04:17:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600427841; cv=pass;
        d=google.com; s=arc-20160816;
        b=oQkWmmei47lscXl5/3nq9m9BXv2ppct7+sbSYKv50o+GUaWmNN97YuL32Et7ccPjSD
         E/0QznxduRTgeETvjCF/pFSxn8c/cOEIlNpgkFSEa+G26n28ZSNw/OqQcpNoQkm8XfWt
         8ttkgeDBAce2+bXQwBwQe44pRl1iH7zlHWCfFCTehAl1y7iNALpOz++1uGthGj+6i+Jz
         bIcDaFoU/OIJUzjU+S0Ynn5DyErwzny2qIo6BPYklEcUil36xqANi+ZlLEoJKUfsGtcB
         66eO8Ktr43kUEQYNdkB1FiKt+RBMBVZTrjEqbSjMgyr/QJ5tVKxbd0e3fzcYVLvf0oXE
         yz0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=/3lOZGDzVcPK16sMEkGoDyvu+oRrHXyASqD3NtVbGZY=;
        b=CZjcJ2SU9UWRxlj0RGhxtVE/zF/h9ePPX4mWWsUiO/ywZf9gkqHZSWpS3S8oh1y6wA
         d/cmTFW4eeHfW4FLzxMYa9NR3G+kGsWGOwead5xzCB5XifLT6jMHxNgK1ziW+We3zQ07
         zgvbTcS8uhuQ1GU4LiW3sRjkbVqN/qJPPUwQZILj9+sH7W1VOnqGkCaByalrhhq1Kdj9
         95X63r5kC9QQXA2ejosGcCan4YNEmThKO1uJ2B0iCLXOnT+1CMywUo7tMSyYX9fgLn43
         mL9+19r8rLIrhsPJ8xPYbPlatwvXn7p5sCoz3zLY5RzFgE7tFyOOdBP3QDlEii3ydvLs
         G2gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=VYV+5Dnk;
       spf=pass (google.com: domain of cai@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=cai@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/3lOZGDzVcPK16sMEkGoDyvu+oRrHXyASqD3NtVbGZY=;
        b=QE236Q5PL0fUFguhTydaksfmoo9YrD6AD/rgAtAa+vaALsZgLAZFXnhfn2qD3bRIrU
         fc9ucCGY05+Kym0khWKJmsB0VF+sg82WGCyIR1LfdCw+2lvhL+ASbWC4YxSrSbykFTs0
         r77t4Zv1pYVr6UXvGZdeQ17ctd+CI6KG4h82NlRIXUaXDDkwwQvvsqSLe5oUQRr9ybOM
         5xRnnQgQd3Q0Kk5qkjiiFJsqtbRaPCN3nZZDiZU0fnWsWRcVsmZuoEILynPl0O2zNt/m
         j4iWoE2m2f1YWwdhxvWdtqP93RI+C9SoAVJILku5YRonfoA1JoctZ91bC6UO64Pb1Fca
         bNAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/3lOZGDzVcPK16sMEkGoDyvu+oRrHXyASqD3NtVbGZY=;
        b=e4bDyUqiBO1nuLahCgauTZtfQu2DlSztmwyeI7NkRQYCOZmZ63IbTdS3m5zkd3n6q+
         gvLHmM8WKN2UiOq1MoOSv0CdHDo+mIROtNBZNFIGvoYjXBNaBCv+ki5d47/TasRQg6Lu
         tv0JMTBGV0dzcIRiiaEt4cYsODnWbcE7TC23N9e1JK1NNAk3mCyY0kVOBTBcnrhyk+RC
         jRCkqr1yf0KS220Jc6T7aXB/FXNooluEg533LdzikIVAH2bOgfF6qg7ZXFdcaVqIl6ii
         k1b1lWlrl9mHJz8MUCAGtiV+/f42ZpA9j0KMIQaZLdnLbciCLE5a3Kbc0B+Nty1ZRlU0
         LwNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530HeftgCp+WnHH43wc1UJ7vopwtWBQDf99PHMBbCe/080rP2sjf
	JoR8qvwwXKOxe/PLKhdLRJw=
X-Google-Smtp-Source: ABdhPJzOg0g7g9mfW5qIC4pyD+GoaOdvTMEAbM7N/BZ4uhSzPS3S6jUaWVc+95iSxZyFIATgX6+YcQ==
X-Received: by 2002:a67:b34d:: with SMTP id b13mr11135834vsm.31.1600427841149;
        Fri, 18 Sep 2020 04:17:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1f6:: with SMTP id 109ls342010ual.2.gmail; Fri, 18 Sep
 2020 04:17:20 -0700 (PDT)
X-Received: by 2002:ab0:4387:: with SMTP id l7mr18169661ual.133.1600427840554;
        Fri, 18 Sep 2020 04:17:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600427840; cv=none;
        d=google.com; s=arc-20160816;
        b=lyScfDQz8rEc92KJLW77s4uQKUdSmzhxfMWZFDvpltA/iSUbIAT6l1R8Qrw34Ji3La
         A1lSs3Bl5kJgPTQ2n+J+Xc3XWUHiQ1lGcBGn6/8KBb7QlspvkkIfwrzloN7AoLDfZXd8
         7qyFoK39nhs5LZSZJGArYonUi6wLi1GyWbseCgZ5j/DOhHDNAeQrOlYHMcmmjMWYcGPi
         iEtqohXLuuGok/FfAe+FRhHlSapRN9nrr5kCL4aQMxH8uuNCta0+QGsoA3wDNFuKByzb
         slyj9IqfHr/+Xl9pdjIZU4RwpJb+UsRMbDzbFbBxmy3BXOU1M4JPPpcVlGMkSU0m3eYm
         cZLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=JZQ2aUpYbOfI0OBbojrEaiyX2uk+A76utcy0JxZ4CmM=;
        b=kZEjkpZTHP/63LbqKMFEhX/4+ec8Q7dBX2jTY6g/gO7BtuYpZK8qDprxiwZBiPhXIj
         RvrjvtJsrpTUkhQK5AAsYM8lnEvuqGISVBuZcosD/wJ968t/9+G1qda4BwxCSeekjkZM
         2UGN7Lg6/GF2mIDF1KLivNZWRwzQ4LiTFQabnPHsuad2Bs7lS7Pu/cw+fFb1kfV2W7SN
         5E72JR/m6+U1V4BMo1G2XDNPZfuCj7bWZzbwoCKxhXlPPXwKGf1kMuO+3LcGfkGPLr2P
         07lkv/aGULNfqlEZgjLwxOOjSxibe5HpAClpY/R3d6fpnxfHPa/KNOd7ECCz+xyEXCLM
         9COg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=VYV+5Dnk;
       spf=pass (google.com: domain of cai@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=cai@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id p129si167743vkg.3.2020.09.18.04.17.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Sep 2020 04:17:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-204-qLTXgoXWNA2FodMSDim9VQ-1; Fri, 18 Sep 2020 07:17:15 -0400
X-MC-Unique: qLTXgoXWNA2FodMSDim9VQ-1
Received: from smtp.corp.redhat.com (int-mx04.intmail.prod.int.phx2.redhat.com [10.5.11.14])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 0BC5D186DD41;
	Fri, 18 Sep 2020 11:17:12 +0000 (UTC)
Received: from ovpn-113-208.rdu2.redhat.com (ovpn-113-208.rdu2.redhat.com [10.10.113.208])
	by smtp.corp.redhat.com (Postfix) with ESMTP id C09C55DEBF;
	Fri, 18 Sep 2020 11:17:06 +0000 (UTC)
Message-ID: <115e74b249417340b5c411f286768dbdb916fd12.camel@redhat.com>
Subject: Re: [PATCH v2 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
From: Qian Cai <cai@redhat.com>
To: Marco Elver <elver@google.com>, akpm@linux-foundation.org, 
	glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
 aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de,
 catalin.marinas@arm.com,  cl@linux.com, dave.hansen@linux.intel.com,
 rientjes@google.com, dvyukov@google.com,  edumazet@google.com,
 gregkh@linuxfoundation.org, mingo@redhat.com,  jannh@google.com,
 Jonathan.Cameron@huawei.com, corbet@lwn.net,  iamjoonsoo.kim@lge.com,
 keescook@chromium.org, mark.rutland@arm.com,  penberg@kernel.org,
 peterz@infradead.org, tglx@linutronix.de, vbabka@suse.cz,  will@kernel.org,
 x86@kernel.org, linux-doc@vger.kernel.org,  linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,  linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org
Date: Fri, 18 Sep 2020 07:17:06 -0400
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
References: <20200915132046.3332537-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.14
X-Original-Sender: cai@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=VYV+5Dnk;
       spf=pass (google.com: domain of cai@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=cai@redhat.com;
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

On Tue, 2020-09-15 at 15:20 +0200, Marco Elver wrote:
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.  This
> series enables KFENCE for the x86 and arm64 architectures, and adds
> KFENCE hooks to the SLAB and SLUB allocators.
> 
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. The main motivation behind KFENCE's design, is that with
> enough total uptime KFENCE will detect bugs in code paths not typically
> exercised by non-production test workloads. One way to quickly achieve a
> large enough total uptime is when the tool is deployed across a large
> fleet of machines.
> 
> KFENCE objects each reside on a dedicated page, at either the left or
> right page boundaries. The pages to the left and right of the object
> page are "guard pages", whose attributes are changed to a protected
> state, and cause page faults on any attempted access to them. Such page
> faults are then intercepted by KFENCE, which handles the fault
> gracefully by reporting a memory access error.
> 
> Guarded allocations are set up based on a sample interval (can be set
> via kfence.sample_interval). After expiration of the sample interval,
> the next allocation through the main allocator (SLAB or SLUB) returns a
> guarded allocation from the KFENCE object pool. At this point, the timer
> is reset, and the next allocation is set up after the expiration of the
> interval.
> 
> To enable/disable a KFENCE allocation through the main allocator's
> fast-path without overhead, KFENCE relies on static branches via the
> static keys infrastructure. The static branch is toggled to redirect the
> allocation to KFENCE.
> 
> The KFENCE memory pool is of fixed size, and if the pool is exhausted no
> further KFENCE allocations occur. The default config is conservative
> with only 255 objects, resulting in a pool size of 2 MiB (with 4 KiB
> pages).
> 
> We have verified by running synthetic benchmarks (sysbench I/O,
> hackbench) that a kernel with KFENCE is performance-neutral compared to
> a non-KFENCE baseline kernel.
> 
> KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
> properties. The name "KFENCE" is a homage to the Electric Fence Malloc
> Debugger [2].
> 
> For more details, see Documentation/dev-tools/kfence.rst added in the
> series -- also viewable here:

Does anybody else grow tried of all those different *imperfect* versions of in-
kernel memory safety error detectors? KASAN-generic, KFENCE, KASAN-tag-based
etc. Then, we have old things like page_poison, SLUB debugging, debug_pagealloc
etc which are pretty much inefficient to detect bugs those days compared to
KASAN. Can't we work towards having a single implementation and clean up all
those mess?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/115e74b249417340b5c411f286768dbdb916fd12.camel%40redhat.com.
