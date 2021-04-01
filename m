Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRE4S2BQMGQESHJ7X7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F368351191
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Apr 2021 11:11:33 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id g62sf3302976qkf.18
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Apr 2021 02:11:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617268292; cv=pass;
        d=google.com; s=arc-20160816;
        b=XBpNRt4FMluBDoNUQAdwcywJIo0BBvxj6rrRRKdGlC8m7drVNqB264fZQpzpb2VEwJ
         PYX5t0CgDP0t1SLnJepWKL9Pi7FHQDiQXLtMQ/3PkJVD8q3fiMc6GwmtPecGKEUhQ1KY
         Nn3xAFf3cKe/ajR++Uk1MM3RXSJPhOmHwl7PiYozQCCmn6FupHuTiZXb7Wyq9+jymR1s
         OgDfMFFsu2UGBUuYDQ/0SBzwMYM90nq5aIOHOHpvMAK5eyR0epfse7HBUOCW1X3Kywpm
         463M9t5aitliiCusNj2QVq3hhD9xi0B18XvIirsXrJ4EfSdVV8FihWjOBeuq7ARAojfx
         c4qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9KoZ9qCwOVDHB+zBDy0bPoWOU9o4755VQdbF6mSNGN4=;
        b=dDa4vOv0T86EBEwRVhNhG8NEfktltdYEm7bvxUkr7Ag6haEXZlKiNlvCk7NmkBvwsD
         cby4O7pKfV1eDatVbXT7miZoqOJdFhxjQt/Rneak5Cd3MIqQwSWRjSowyp6G7qbCwNlr
         5mb/rtIj+vywDu1hnB8iYU3jhavIiYlVUCjsc03IGZmvCqVMyrb3TVY/510lIwn2eGB/
         8EFul+wYd/XTPagzB//xY/answMmax7MldhsTY6XG939GEdmEvwbMxI1n0acaGfBUgnr
         m94sXTOUDa/wmD3NBQc58DEGp/T2SG7DJGnofL4y2XPDFZ0v+UJUW812EqzOqWnHjD3J
         /Skg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=azUvCNBE;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9KoZ9qCwOVDHB+zBDy0bPoWOU9o4755VQdbF6mSNGN4=;
        b=pH7nn74yQ/rj63+DX/eLMHtmYt2UWIocfidTSKVshrDkngI/tl1yAXtU52Ckc8Pmvb
         gex4BBuDXQz5sfjgWsyIKyThu2MbiDycwjHHbmwcYQTCzgIJur7rm6lTdi3xAGIvZb4j
         tV8XDJHzw9xkOGI2rwVzZPTUfSrYisGs+54Nexkr500xuJ8tikmsKQTHQItYMlYiDxo2
         eaZpmfb+uNH9uu4vh1BbCKDV6VquGWSqL/ZUKTYZPVdCYHTWmTgHhhEyVuzV7BtGqXFc
         jin4kIbW2OBWeSsykynRh3XuXZ8gHE/L3PTWYYz4ypW91sZBXmC8WmYS2frObA9Rtdty
         Ps1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9KoZ9qCwOVDHB+zBDy0bPoWOU9o4755VQdbF6mSNGN4=;
        b=bHZaJJ+uUmpObYN1WR7Ujjtpg4DQqPGzYeLum+TpMigMorU74sZgqmv4ldJ1u8vGHM
         UKV58qKMIGQs6uP8V2Nfcy6ziSF5QyOKiI/WTDOplTwwFN03f8SRjdddlus6Pgoawymt
         eXah5w2Xcn5RaulWgDeR2OhQC0+qDq3zYs38avFhY+sqUyNHk8B6cmqW2uSHXI3gQLWA
         /caFfI74JRuuobCWZczFJtzD5XgC4B8/D4TJGme08naBO8jvFT83uxpR+GC887zpvvXi
         qdlYylTAU8MIP2qUwbkzHgy1eFSMaTzXrCwk6KSLGGAbBwtC7bKBTlbNMXUD0fY1ttma
         ibhg==
X-Gm-Message-State: AOAM533Li0YRniPT2xVLp68/kpOPys8wcmuN115jqecwr5TqVOdXEwku
	woSxz1ASe3+SQJ2Wv3fOrSE=
X-Google-Smtp-Source: ABdhPJzBDp7vciZe86Xjq/cfnAkLKbc2lDYaNEDLOoWuZO2rq65GSi/994EhXn2MCiDjRpUlxtnIKw==
X-Received: by 2002:a05:6214:184e:: with SMTP id d14mr7191822qvy.30.1617268292120;
        Thu, 01 Apr 2021 02:11:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:262c:: with SMTP id gv12ls1398112qvb.9.gmail; Thu,
 01 Apr 2021 02:11:31 -0700 (PDT)
X-Received: by 2002:ad4:4bc7:: with SMTP id l7mr7217100qvw.36.1617268291711;
        Thu, 01 Apr 2021 02:11:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617268291; cv=none;
        d=google.com; s=arc-20160816;
        b=xwLHhDUxYvoWO5/08p9flt4SAOAWZNMt8EcEaCCXgeklV1X+OCNnkFuNx0GO3S1d4j
         Cv+9bqjjTCMLwldKD2xnjIrvp2oGB+Ahvw+RXVova7RYrIs7rI2hdyn8YqjcKzu57gBW
         YipaP9i1nCzKA9ocbhyup/HSpNNpvexTYbU58DVK9nesPRdZghI4jiS1orwcte/I+kv/
         NH7d803aLEVDmaXq/Zxc5Olo/e6JyfsT1Cl8xewbd6ZU++jevuJ8qFOEsWVIq7BtFntu
         Bh0vSiLnM3i97lPnHKvAxnIJvDye0gTH09PKzcCIMO2txuT2/6JBAsEingSKZ1kVyTik
         PISw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FRTdyxga9+xU4X0UPyyuU5rgsxj5AmXn/YlJB5Gr9oY=;
        b=IRP6ruORp4d/5JuCbfKFxBhZEGC53s5CgI+j/4iSjzxBz4TGfN/1OgKQz4ouFujrRd
         zsCpcfLp1CtkPMTkhsjvbRcIpvDNlDRF94I2F2SwpE93Gq6qxIqUFGWW7Nsx8EB1c+E2
         hbeDtCbIK1zLzHbb4vclZtEepPXFxufNyDhwfhK+ZabWinN1fHp/G4ygwdsl1mVBuxbw
         Qfc8ocuhKuM3j9j7RB3McVdnRw2ye6OyE71vLlr3pjsuHA2rh7LyBOMn89HSMGd30vnu
         5MuI4q6aYxZKOfCeNvRSS3IwVrmWdhZtIOVVXM7VlxruIXdqWIe2YQnCV9zJdHqN+cKu
         PXOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=azUvCNBE;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id r26si495344qtf.3.2021.04.01.02.11.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Apr 2021 02:11:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id x11so1479509qkp.11
        for <kasan-dev@googlegroups.com>; Thu, 01 Apr 2021 02:11:31 -0700 (PDT)
X-Received: by 2002:a05:620a:2013:: with SMTP id c19mr7238842qka.403.1617268291223;
 Thu, 01 Apr 2021 02:11:31 -0700 (PDT)
MIME-Version: 1.0
References: <20210330065737.652669-1-elver@google.com>
In-Reply-To: <20210330065737.652669-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Apr 2021 11:11:19 +0200
Message-ID: <CAG_fn=W7WZBCSozOuMWzr52Ri_htrmkTOkcF5nvMs9icH=StoA@mail.gmail.com>
Subject: Re: [PATCH mm] kfence, x86: fix preemptible warning on KPTI-enabled systems
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jann Horn <jannh@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Tomi Sarvela <tomi.p.sarvela@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=azUvCNBE;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Mar 30, 2021 at 8:57 AM Marco Elver <elver@google.com> wrote:
>
> On systems with KPTI enabled, we can currently observe the following warning:
>
>   BUG: using smp_processor_id() in preemptible
>   caller is invalidate_user_asid+0x13/0x50
>   CPU: 6 PID: 1075 Comm: dmesg Not tainted 5.12.0-rc4-gda4a2b1a5479-kfence_1+ #1
>   Hardware name: Hewlett-Packard HP Pro 3500 Series/2ABF, BIOS 8.11 10/24/2012
>   Call Trace:
>    dump_stack+0x7f/0xad
>    check_preemption_disabled+0xc8/0xd0
>    invalidate_user_asid+0x13/0x50
>    flush_tlb_one_kernel+0x5/0x20
>    kfence_protect+0x56/0x80
>    ...
>
> While it normally makes sense to require preemption to be off, so that
> the expected CPU's TLB is flushed and not another, in our case it really
> is best-effort (see comments in kfence_protect_page()).
>
> Avoid the warning by disabling preemption around flush_tlb_one_kernel().
>
> Link: https://lore.kernel.org/lkml/YGIDBAboELGgMgXy@elver.google.com/
> Reported-by: Tomi Sarvela <tomi.p.sarvela@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW7WZBCSozOuMWzr52Ri_htrmkTOkcF5nvMs9icH%3DStoA%40mail.gmail.com.
