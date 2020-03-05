Return-Path: <kasan-dev+bncBCMIZB7QWENRBDFIQLZQKGQEEUPWP2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 40056179FA7
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 06:54:22 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id b1sf3041277pft.11
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 21:54:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583387660; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cw751c1I5mO36fbd6szfdFbn1HWwcWFiZVM/t+/4az4CvoLNbcDhoOrD1Ank2HqX3n
         aA/Bxlf3K/PpTJw3gtBCRiUMs6RuJJKggEsxKe1dNEtSw4IGCz8r6Ejh5GyKOIxrQHo7
         cf7AeQemP0cB5t0JKwV9TWFSF+1q2ifvhp67QR5uBNRXHsQw13b8gj0P6IhD+kHKd2e+
         J2WaVK3JDkXiWfrT7PIlJlnnpj6XsRFLk6n/01UDEZ9wSm4+p8y63sXoF0p0wZAxhHb8
         c6x51t8RsKV7ZgyicM5wkCaCzGUOV17yFuNfxAyOQr/nPCBEhy/pUcqlUXHHn0zCf+Qq
         QoIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dKpidyWba78hM19N1CgbLeXwHIt9NwBJr3dEaTldqOI=;
        b=E61E/P2FyxOSbJEb/8qV7jZ0/CUcNO775lllEPWc9W88gqQooCdkxTjaJx6nxXzSKS
         gh4h9trp2eQjiVetsafJYwPMdHrGvrkt00s7JIsF4P1KGJIvSEUtSiEEJdoo4L94QmwJ
         QjvJ8jIx9ao82Pyd80Qyf8NPOTl+w5CMqYfsmizSQ894PiKCrKXXEJ5nHtMImuyTYX05
         Z20XBwW5HaGHfjB9kj+DtH/UkilfHlhmem2y/IRi1cfWfoSLisJPTlmy5srnDH7EqHVk
         Xw1qZjZsuqAzwbn1jweYK1yTdbXJxJtGZaCSo2aPOHiLKaXkkzYdA/7Rz3I2/5Th4k35
         K42A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dY9g6SaF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dKpidyWba78hM19N1CgbLeXwHIt9NwBJr3dEaTldqOI=;
        b=my8xIPeQgXLgDCswY1oVgCBz1rjAXc+/ARLaa6myV7HiQyiQa4qm8QAzuXeR5zWceC
         LHHacRRPh34xHm20pPp69AusNYu/IWvbMvm/zksFbQPLuYgn89/0b3n0HwIrIwztWE4l
         3QkgUCiK09Ygn7Vm+ZP+JkAQqPEJr2+6gXxqIZvjupRH0fjcLfIgzYbP3/GT3vItPrP2
         fD+QSOIxRWkz7sI5yeJz8Q1yrpagEO7zcQwXDCS+REJY+BKJEejf+jEgBlk4O3dkm88f
         EZFXCuyF+badeNLm3La3NThX5NSqzwzKWvchph1v7WStpzvTq25I/plpBiFQIgEo5aHI
         ygjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dKpidyWba78hM19N1CgbLeXwHIt9NwBJr3dEaTldqOI=;
        b=D8T9u01oA0y2rfDemtc4eO9TBANfANAiKEVNRBcO0LIPBCMi/vz1/LK+5XKumekllF
         JFvdlWUCs2N2WZ3avZsWz4l1KDDdaTjLhYhiDJTeMT8/buqLFoXMTLbyclCNYiQ2YZgs
         Heqm3XVm7P+j00cvLyfzZpkUWipXp84iD34M4D0KXPgj1UDh1LjCjQzdk8hFcFJDPVdZ
         /D/QOBjEIVTFHvQinhzU3nZSoVynfBWIX/cN8qypKkZ9WgTtvCkMZ1yxeJ0zv16B3pxk
         CHShNqZLydu7bzoDqC7M8FTAwmPmYCQ3FQYLsyXdZKL9i+STRhhimqRm8BoU5tiogSPC
         Xdgg==
X-Gm-Message-State: ANhLgQ2zUaoLb+Mc3Kwy6JUW6wuDk2y+ToZ5w9JX+Yaz+nmP4nKWfbh7
	/s1GtXAjC+03dpvEjU2/EEc=
X-Google-Smtp-Source: ADFU+vvMEApshu9TF5W6YmbglX1jYgYaSWug373+7zpfBu9BoQfcDxaMhYNfcrJm/3SQd1GC1MJrdw==
X-Received: by 2002:a17:90b:490e:: with SMTP id kr14mr6951894pjb.21.1583387660774;
        Wed, 04 Mar 2020 21:54:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:868f:: with SMTP id d15ls637653pfo.5.gmail; Wed, 04 Mar
 2020 21:54:20 -0800 (PST)
X-Received: by 2002:a62:3892:: with SMTP id f140mr6551323pfa.190.1583387660197;
        Wed, 04 Mar 2020 21:54:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583387660; cv=none;
        d=google.com; s=arc-20160816;
        b=ydkDpraJhckhxUtjXw1Z7pMIQvKQ6hH5z30QauxnNFUP/zcO45kEn4bNm4/hexl0RH
         Eu1Tzu86tSGyBHVI1UQAv/yk2i4yNns5mIlYm2mFwQZDv9cgwccdo1lJfTueGYpvbAQ1
         kQMhQEtQFTCVY4l5eLgI9pq66F/TPa4Rfgqpp10XTIfYyfXN4AI/mSiPElfMcD6eoI2F
         +9jLgCcUfe5qG7h10rqzALEKPoC32ojFGA42MBY1G/LE0qKmNJZm7fKY5sFkwxILf+B9
         3VlsjCYo0zG7M6w2tqjEmLSBA8FqXyZf1uU0Yc7EwfVOUfX+U3vx2VoJBIocrNkMHkOV
         m9Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+7mgcJIet7qBayZZcIdFHC3F2O5NeLmq5vShyrq3W0w=;
        b=atwXpDPZpjTIc/Vna+7DO16U3yvGgvLZbgYCqepZpc+KZP5LOttAAm+WzSR6w9mqL7
         Zy8pAbOAK74iDgfiMZmme+/d9NIsKMqN+ZFpltKwPzm2mJtyLTz5RhxUiDqtPEaYKNUy
         USRN6TCpZMV12EnzC9U4W6m8nNWlkT5li2vV1h9qvO833fxmiTaSYAfhhVWmTUsZUCtj
         qhLgv8Umnk1usBTAXuxM9GRJVMYrsFUoN9R4CjalkM7Ofp4TN2y5NjfcLVgW+LMsBSy9
         /TdcGgxd8r2yz6loPwVZkKAtfMLeFXmzJEAwSqVWgNtiBerKSJbpHuOYtU/pSB6+/YzU
         XaIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dY9g6SaF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id c13si240068pfi.3.2020.03.04.21.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 21:54:20 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id j34so3318315qtk.4
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 21:54:20 -0800 (PST)
X-Received: by 2002:ac8:3778:: with SMTP id p53mr5648903qtb.158.1583387659031;
 Wed, 04 Mar 2020 21:54:19 -0800 (PST)
MIME-Version: 1.0
References: <20200305163743.7128c251@canb.auug.org.au>
In-Reply-To: <20200305163743.7128c251@canb.auug.org.au>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 06:54:07 +0100
Message-ID: <CACT4Y+ZX0xaZNnNqOzassKi2=NSPz-9K4VpxdL6FGx_Y4vWSUg@mail.gmail.com>
Subject: Re: linux-next: build warning after merge of the akpm-current tree
To: Stephen Rothwell <sfr@canb.auug.org.au>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dY9g6SaF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Mar 5, 2020 at 6:37 AM Stephen Rothwell <sfr@canb.auug.org.au> wrote:
>
> Hi all,
>
> After merging the akpm-current tree, today's linux-next build (x86_64
> allmodconfig) produced this warning:
>
> mm/kasan/common.o: warning: objtool: kasan_report()+0x17: call to report_enabled() with UACCESS enabled
> In file included from include/linux/bitmap.h:9,
>                  from include/linux/cpumask.h:12,
>                  from arch/x86/include/asm/paravirt.h:17,
>                  from arch/x86/include/asm/irqflags.h:72,
>                  from include/linux/irqflags.h:16,
>                  from include/linux/rcupdate.h:26,
>                  from include/linux/rculist.h:11,
>                  from include/linux/pid.h:5,
>                  from include/linux/sched.h:14,
>                  from include/linux/uaccess.h:6,
>                  from arch/x86/include/asm/fpu/xstate.h:5,
>                  from arch/x86/include/asm/pgtable.h:26,
>                  from include/linux/kasan.h:15,
>                  from lib/test_kasan.c:12:
> In function 'memmove',
>     inlined from 'kmalloc_memmove_invalid_size' at lib/test_kasan.c:301:2:
> include/linux/string.h:441:9: warning: '__builtin_memmove' specified bound 18446744073709551614 exceeds maximum object size 9223372036854775807 [-Wstringop-overflow=]

+kasan-dev

We probably need to make this 18446744073709551614 constant "dynamic"
so that compiler does not see it.

Walter, will you take a look? Thanks

>   441 |  return __builtin_memmove(p, q, size);
>       |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>
> Introduced by commit
>
>   519e500fac64 ("kasan: add test for invalid size in memmove")
>
> That's a bit annoying during a normal x86_64 allmodconfig build ...
>
> --
> Cheers,
> Stephen Rothwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZX0xaZNnNqOzassKi2%3DNSPz-9K4VpxdL6FGx_Y4vWSUg%40mail.gmail.com.
