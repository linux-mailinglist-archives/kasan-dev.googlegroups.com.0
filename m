Return-Path: <kasan-dev+bncBCT4XGV33UIBBGPH7KGAMGQENTKZQII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id D674E45CF76
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 22:50:18 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id g14-20020a17090a578e00b001a79264411csf1570994pji.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 13:50:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637790617; cv=pass;
        d=google.com; s=arc-20160816;
        b=bah/+AuSixVCOx+3qgpTY6hdrsKRG0EY9JF4KH6DZJwgE5JxQCNwXF258QU51CC5HY
         YW/xgRa6FPbsbNWFHJcgowmYZQKNqZp/SGAe0WNU3kAflsL59sJHejAs/PFFR46OJsIc
         EK5jKBaFeUW0CVPoiRKJ9y0EfK/8rmTTsdh6htNWyxLEmVziVxdMyp6/O1RCDfx8zbFy
         j8XJdvwETW0pILEH+cOAVAvCFdgOaN9WITY1pV+6kZqdL94y1N6TS0r7ZV5lRLO1BHk7
         jNd0TSS9eMgnRxTA3MrG8Ef1rK97qUPLX/i8c5DxaTIKueN8iDGSXmm5un7FIssliqN+
         eKfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=xzMqy1jx0OMjZGwLB4dTCMkfFf3KAEI49w4o40/Y9VU=;
        b=cT6m4AZCqdUqkeeXvXy364zuiTCZchENXKBA9TyfU1nJKGj/UrxLH5k3FMARELWOkq
         9hLfeuPDBu7ixCYAJwKPk08rmh4Pf/9AoPzU5PSzGTCbKFd3JDEcggz08m9FZkcXkqvz
         K7VyRdU9aQrOStp06hFMJvx+Futoli3yTmliGQQ88HKxv4knVfbfI3VzeKwAfxEX44Zl
         UcuzcEyYHLD6SeYhWXWdnKes58mReN83osLnzSERBoXJFGNnPQO/8SDw+AdyQr0VRUE6
         Z4FckBeEqg5V0s26dIU75ygoUokgJUDdmH/Sqp8FXKAZ29c0YKi79JtH196Qw4BbHI1Y
         opFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Cm5wrged;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xzMqy1jx0OMjZGwLB4dTCMkfFf3KAEI49w4o40/Y9VU=;
        b=BlGipsgoRaboiHlP9PeTBeyu3oNqaB4bkERewguQGZ+tNKIVyWyRS/GWR7plEOMhdn
         zslwTw+HpbegIBheMCEPSemLs7LiC+zWZf0/PGe2C6f7IBzCKK+DDsuDSAV3R2B5rx9t
         CusbTDX+g1IInS6/dOscwZFiUhGq+9/7XI9pE6td4IhyuLjysamY6IxEc73QJ0LvbFDA
         ktdm5o2Dj6MlTXulVTiT0QbD4v5KvJqCT9V4Zmj9y+Y2xpvwjj9MLQGzHZIP2UwwKVrP
         h4GHosyIEqyaBhdEAVl4HJRqyVzexjFAL7BN6vvQaYk971y+K+rzA6+ES798VrJwRonS
         WccA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xzMqy1jx0OMjZGwLB4dTCMkfFf3KAEI49w4o40/Y9VU=;
        b=0rTnTlXtdEfYhcSvi/s9iG90n4mp69z66G7UbVZQ7rOrZZV60s9bHgUh0jNPEKToUR
         6r6oxW3Ghu0AQmPHGC9H5GqnY7fxa6w+lAO839VvS+4a9dLV1FN7/dUt2yYDp8L1ONE2
         GpjMkZtJQm8oSZ+pKkT8iUdprympfAlRAPMFHzes3yo0UaYhnD9BGCI2xQ9f0xMLBSkr
         tRxKHYqeebugxpxzG/AQNgE0AZB3+gxdurJPTIaImbOiP2VYkmIIjG5LWITDygT7dzCt
         eqXYlFCvX7b1FQbDimJE25m0qAIKUaqVwLJ5wUyGV7VPDbp2yVlFW4QbwHo5wyfZxFIU
         x4BA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QYfz19+P3kKyfZFDJESGSH3hJIqEEd7+J9B3I3ICZJr1NVZQJ
	Ez5azySHh7jTYLbnUaRQi2A=
X-Google-Smtp-Source: ABdhPJzg1X6/a3S3du3zEKUAotVt3TDQpbnvfRwcUeaGefHlzGEZI38fcZHkWi5vCb7qp1mebn4FOg==
X-Received: by 2002:a17:90a:7e86:: with SMTP id j6mr356707pjl.25.1637790617431;
        Wed, 24 Nov 2021 13:50:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3ece:: with SMTP id rm14ls2817032pjb.2.canary-gmail;
 Wed, 24 Nov 2021 13:50:16 -0800 (PST)
X-Received: by 2002:a17:90b:4a0e:: with SMTP id kk14mr429956pjb.42.1637790616785;
        Wed, 24 Nov 2021 13:50:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637790616; cv=none;
        d=google.com; s=arc-20160816;
        b=GZ3Q04OVdtxp1UniDmOC7I6yrBBKPpKn3k2tzaOK2osqc3tLU+40aOmf3+LIx0p5Ex
         iQVAdctqbr1oe1/qz6FgWI4Whay5rs/vD/Zm1PeLNeYxrws5HOBjaVfEUYyS3nnt4hMT
         uO+xV/h6JcuABEqJh22iV1S1S88IgTiVgODxlcnPI0xXYtQI1nWcy6z9w8ePOJrXSC9M
         C7Kr0qXh8pzd70d+fmSBBG939wqN9DWFd/loTrWUM1DIfcxF94GgqgMuTpjvPM/KY3Os
         tteNHBfHTfcXW3T06yGhA0erFt0h9bzypfcmZxhDGwXjKsjOtHF+w9efoqVHGOeSp0yI
         7RKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0H6UPDMTiPc79deExBf+RYxn2589u42WudJvR20mUcM=;
        b=IdtLkZe+YHM8BMvU2bYtHQ4kuGjxbLGmhZb0LZJHs+tkzRTPQwRt5X28E3l354SosE
         GRe+0B6ywdgdMEZLknnK8W5z0NzJGVIBrjx8EqUwkRS6OGdgiFSCPDoRxmTobzB75Fxo
         KTJmEHZq338vZMldnGexWAA8twb7IOeiJYad12w53RUJMalrMQ+cRAUaFQuj+Bb6cudk
         Grkn2Q9MQJTOxW9dMieX81oCvvBtAMlmUjdVWrkjoiCYfZI3r3VPsvCWaznoyGNdAftk
         70kUhIvGKP892gYebo/DOtigVGqyReur2sakdPpvzJ7QhP+ErLNbkMY/VBJv5g6yEtPu
         TOxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Cm5wrged;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l5si63326pfc.2.2021.11.24.13.50.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Nov 2021 13:50:16 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D88DB61039;
	Wed, 24 Nov 2021 21:50:15 +0000 (UTC)
Date: Wed, 24 Nov 2021 13:50:14 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
 <linux-kernel@vger.kernel.org>, <linux-s390@vger.kernel.org>,
 <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Catalin Marinas
 <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Heiko Carstens
 <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, Christian
 Borntraeger <borntraeger@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar
 <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, Alexander Potapenko <glider@google.com>,
 Yongqiang Liu <liuyongqiang13@huawei.com>
Subject: Re: [PATCH v3] mm: Defer kmemleak object creation of module_alloc()
Message-Id: <20211124135014.665649a0bcb872367b248cef@linux-foundation.org>
In-Reply-To: <20211124142034.192078-1-wangkefeng.wang@huawei.com>
References: <20211124142034.192078-1-wangkefeng.wang@huawei.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Cm5wrged;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 24 Nov 2021 22:20:34 +0800 Kefeng Wang <wangkefeng.wang@huawei.com> wrote:

> Yongqiang reports a kmemleak panic when module insmod/rmmod
> with KASAN enabled(without KASAN_VMALLOC) on x86[1].
> 
> When the module area allocates memory, it's kmemleak_object
> is created successfully, but the KASAN shadow memory of module
> allocation is not ready, so when kmemleak scan the module's
> pointer, it will panic due to no shadow memory with KASAN check.
> 
> module_alloc
>   __vmalloc_node_range
>     kmemleak_vmalloc
> 				kmemleak_scan
> 				  update_checksum
>   kasan_module_alloc
>     kmemleak_ignore
> 
> Note, there is no problem if KASAN_VMALLOC enabled, the modules
> area entire shadow memory is preallocated. Thus, the bug only
> exits on ARCH which supports dynamic allocation of module area
> per module load, for now, only x86/arm64/s390 are involved.
> 
> Add a VM_DEFER_KMEMLEAK flags, defer vmalloc'ed object register
> of kmemleak in module_alloc() to fix this issue.
> 

I guess this is worth backporting into -stable kernels?  If so, what
would be a suitable Fixes: target?  I suspect it goes back to the
initial KASAN merge date?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211124135014.665649a0bcb872367b248cef%40linux-foundation.org.
