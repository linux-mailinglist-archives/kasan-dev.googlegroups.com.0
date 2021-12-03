Return-Path: <kasan-dev+bncBCV5TUXXRUIBBVVMU6GQMGQEPKU7DIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5796F46734C
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 09:33:27 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id g19-20020a2eb5d3000000b00219f21cb32bsf838296ljn.7
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 00:33:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638520406; cv=pass;
        d=google.com; s=arc-20160816;
        b=R8tzrwuNnlGDMJQyhSXbh9JbZ37Cd2jYMlDzCHc1poc3MehUNfnbzsAwmMgLLoT+RE
         s8+taVttyFlXsbBZqvY4wrRCQJIXdkr+u+FWZRnDiPp0gptYTfGgnP13sAXmfvoSYHiJ
         GTHBTIuaAsPa1ciumHAvzvJv8XPoJOtOh+/vU+ysnFGlMkAK5MTuZ8jzzJ2hr2cP14Ll
         0EPkagd/uqlUDmWEi116MoJmM7pQvMHM+0Zsf/neUZtadtch5Ur/+4uHGzXY8G0k/+xU
         2B9Lm4NmkL1ZeMRPktjL7eagwHhKIW1eIEhqHugRv5h8KFfoiYtGEcM+l3mgELlIMauV
         2EkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=69HCu/TewAfO36VGGcVGqptv2TeCD5duMKMU1m90OcM=;
        b=F4VUpTPE8FKl8bQ+owMIayAro3LbFtMsGoUIuGeW+R8koksSHJr2x+l+sNN6M+u0WH
         +wAUiwcV4w+rdhGpTTufTdbnpBvKW/tcxA271LGvHY8FWWgCu0AvfDO2eBK43nTgonTq
         YMwCriLPCdOsoyhpD92LouZJh8f9YDmbJuadbWoVYIyObtoDPUHLLLo65OxR4VysQZkW
         j8KGFv5JNkOYiYAXrw5OicONJ4d4kzRHjqPraorLzalrH5b8yZhpeLqiADy5djM/F071
         RICf/61OBBInSCX238BAzXs8BHrYkmWYsUdw8uysNcrlCKw7m2GZflBCk3okYZBIyMvh
         EURg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=W2jwhSZw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=69HCu/TewAfO36VGGcVGqptv2TeCD5duMKMU1m90OcM=;
        b=UbZVUq1fGTZmcuSFfvDJa4batWwCAK8mvs9R2DrtKiDn9I8/lmW2qNvy8hMaUMg8nL
         FBdCbq3ow6OWe4Xytw1RLisvwR80EyslgJXD64X3FecL40WLVRGfGesZBl8uWKKwDX6N
         TV/I1zNVUEUXOVaFRHTKQfDAPPR6hyCR6nTsfmZtrYr+YCL/Rnya4FkAorOq02EFfOvb
         vK2LpFYhk61naPF203E/HCTQzjggluXPpY6zzkL+peBm1GNDTFBBf9fd3gh43+g2+zf5
         FWc7ZkXI8RcJtvL+n+HuVXBI/mCyS/G7SnplyTQ0cTLYjyph2qtTYHFBENfLd1fpE36f
         g30A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=69HCu/TewAfO36VGGcVGqptv2TeCD5duMKMU1m90OcM=;
        b=eLPBO/7M/+2EBJFlIyi3Z0/KM2llVfkMk5Mrl093fRTEjgrH8/gCIAoKVtgJZiv6fO
         9/5c8dCCrKZRfS+zM1VTxkLV4zN7wkhtnhVq9PH2misfzBtULDbXIBwXBSqcSfRvyqer
         ENnqDMKUOl5aLWOXPF2pYItu6nozjK5QYbHpUt6CIrxi2F6L5O1vPnHuDeMVFGjCBLzi
         3aAUqdecSyV3PDPHttfCFW+9vTtnU0tNONd0d6D8KMHuBegmMBWJnQspxu3pehxxHpJX
         VW2sktlgs/gKcs3hwrQmPWB9fJEDfqjfRsx0ZtSWL8Hx5dm2P/sZ1ot6UmTVx/qQLtTo
         bcGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dTCRoQj9KONTDsPGvL8xHoLWIELG6QuyceYo+xtKjtAApOWOo
	DulpKdnm5phlBx9s3Ewp7+U=
X-Google-Smtp-Source: ABdhPJxJLf0dstSVfkfAG0qxy36Na06GY8hXVZX0bj/u3N0AWDap9Kg+YHnI3LTAL5WVIRUTyzM7wQ==
X-Received: by 2002:ac2:4e0b:: with SMTP id e11mr16531188lfr.208.1638520406626;
        Fri, 03 Dec 2021 00:33:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1251:: with SMTP id h17ls1456793ljh.6.gmail; Fri,
 03 Dec 2021 00:33:25 -0800 (PST)
X-Received: by 2002:a2e:9903:: with SMTP id v3mr16729206lji.143.1638520405442;
        Fri, 03 Dec 2021 00:33:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638520405; cv=none;
        d=google.com; s=arc-20160816;
        b=cn3Egx/2wSyBKrICHHNL6iL8pYmpCG1tpH/vuekJdE3M7ooVK+Gc/V9irJmOM6yEHA
         APOWs+p4HzbjH54mxdH/PeP9BoLPIgCpo/PLJrAtwky5K7zInZcdSvEuWuIUpfmLvJO+
         c3lYPriz58ycspaAWhOU1vXAGf0t9BQeqiwZ3bEJJhsAX7q0BMrTOrlc6xcQ/V5pOy1h
         Val6Qe0NoX7+3fCM1VxWHK1q+M9gMP1BSMlmKQ7/dBoy9UcLmwC9tPfWDM/3MWEhVDyV
         W+NJphBYL72oRCZyQVGqZkh3bHwYAtXXorKAlUd0OUcTRMzV54qoz7ynkktL1epDq8oa
         X1pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=a395hufFAaA8i2KMNT8vcKv0fNMIa85KJAEXQSVEeSM=;
        b=ZLqo6mjNgOO6kmc5t6AkOFgjYVl4g1B3Hm7LE+VHvID0DCTHnDIZhNJ+10L7ksHtyV
         Lbqfj2RmNzzerztupi90dl9zAHwNUR9n3n6vgXZBVdnVQZrJhHQZ+w2UK4VYU7gEN9ix
         TzlYJXqFpl20Btn0Z95qzO6g/VqVqKkoHS7C+BnSgUnMWn4ilf622BzdWGwUv0MwR9ij
         ZnGlKAUegsduumtFIjiIBOpfPf7Z8VAfC6lkJ1ANcqYu4Dvtt+FdgwCOuTt5+b1X8tEp
         NYXSlk+l+6717oO7twJFwSyQdjrtoXb96FsZnGX0/jWM9xZa2BC5YIkC5ozzjT0fdVdU
         o9zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=W2jwhSZw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id c12si138517ljf.4.2021.12.03.00.33.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Dec 2021 00:33:25 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mt40K-001xnK-0j; Fri, 03 Dec 2021 08:33:16 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2F8E4300243;
	Fri,  3 Dec 2021 09:33:15 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id DF18830321BA0; Fri,  3 Dec 2021 09:33:14 +0100 (CET)
Date: Fri, 3 Dec 2021 09:33:14 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 0/2] locking: Fix racy reads of owner->on_cpu
Message-ID: <YanWSh2miL6E+aZR@hirez.programming.kicks-ass.net>
References: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=W2jwhSZw;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, Dec 03, 2021 at 03:59:33PM +0800, Kefeng Wang wrote:
> v2:
> - adding owner_on_cpu() refactor, shared by mutex/rtmutex/rwsem
> 
> v1: https://lore.kernel.org/all/20211202101238.33546-1-elver@google.com/
> 
> Kefeng Wang (1):
>   locking: Make owner_on_cpu() into <linux/sched.h>
> 
> Marco Elver (1):
>   locking: Mark racy reads of owner->on_cpu
> 
>  include/linux/sched.h    |  9 +++++++++
>  kernel/locking/mutex.c   | 11 ++---------
>  kernel/locking/rtmutex.c |  5 ++---
>  kernel/locking/rwsem.c   |  9 ---------
>  4 files changed, 13 insertions(+), 21 deletions(-)

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YanWSh2miL6E%2BaZR%40hirez.programming.kicks-ass.net.
