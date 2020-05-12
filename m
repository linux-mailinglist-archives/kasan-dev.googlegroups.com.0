Return-Path: <kasan-dev+bncBAABBIEV5P2QKGQEUOFCKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 409651CFA30
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 18:11:14 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id w3sf11136341pgl.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 09:11:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589299873; cv=pass;
        d=google.com; s=arc-20160816;
        b=XidTgcQH4DZQr1SU7hLwNHh/qewpVEUw+95AUqDci8jjkM+1Ac1S//IxtGkncjiflR
         M1ZIyeSFY3No/lcnivXQQeTwLt3WWyWlt8z8Mvc1JKhBLqQQqcaz9k0sAkCNxhX3AvRd
         3isRMgtDbPqoT9e6YxwV2sibdAZ3AoevVMqioWnL/QmFOcYdQa2vNTD74ZWZhLDI+Ag7
         IPgh2Qt6PaANjhPYYgg3hKC/wAbfH9My2KImv4jV6RaMYbG9pvPz+PNNFHNI+jrvReLr
         FLzy2pQ+wHIpOPSNItyZz3UtlLBgGN8VhHMnFHPhS/t6fW8xF7JwfwnrbgW9UzbgVSqP
         5vvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=R+pgplP560/LvnTo6z+RzTvzPKiW8aJkjf22kJjoKas=;
        b=m2iDoy6eO3It1oDldAC+PtX1P895k6UGdiRZ3TtAS4A6li25Xujb/OYeZhnP825zaP
         5EOkyBrX56Dv2rYnHAbY0j0QjU2hEykol03/OTRQrsuTsiN82vulYaS1+XoORA5kvKYS
         LONT12T+qYItiBQtSUYYll5kd7wuKNQisVUtcaURKoujJZ6qA4KYycrhvrAEkjzbWRtY
         jWOYgct6DPKsCiJoztA7JgTpJimz4EvjQ676TJFnI+hFeh5dA1zXqgg1kaeXaZ9E38VT
         GoZKz83CZ7CYIaj0D7PNXqTsHWVEqYYgPu5DClNCYE1NPfzxplHJLrhP6g3gEmZPA9Qk
         faIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=WRrmWf9c;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R+pgplP560/LvnTo6z+RzTvzPKiW8aJkjf22kJjoKas=;
        b=rcSs6H+yRejasHFKVzClGyHr/W5NiXl1jfT04VKcRMLqdvyEej7NuVOXFcZXKLXmQv
         mPsak/6FSCrgD0md3oyBc1zPVJAEzFnoe+D1cuRPy8mvOaNJI8Plo7LtslCJo5BQKDK3
         YMg/XDLMSrjVQaMqoJffrtLuP2t88elgGn64k7X0mQ21bK+0RttVwMcvHY9RDilK5iLK
         2vmYDYCnBoPb4K1Hn1mm9ZuAgghSSoO58DAhNOJTCU9HIwLGf9pnqyfrKCPaRjaNnrjP
         eAJ6i4pv1K93SFgpDe+h8tYe5p9g1hLJohe4+6rq/rV7Pfxqk2NxndG6qClAHD+N6NDe
         BVFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=R+pgplP560/LvnTo6z+RzTvzPKiW8aJkjf22kJjoKas=;
        b=n/pJQhnjARBQSrWuFEh+YbzDmdZLKl/wcLZMp95ajDPytAiOe5AbC/vOBh/Yp+rc+1
         blv/JJes82+dNARbCQftee63Xn4oDrfyQuuOlIUKFCLADfIhzoP8iLeetINI2OdcualG
         breODwsZ1U+GBMqXnGsugOGtnm3BCxCuLEC2xJN9Cdz1ojUhYlWr54sMm4BGOjDywRdP
         BpRWxfg31xdVgboRYyYV9PQSbyS5QJI0JOEfsXTeUKZ1AUZPrQe0FVYapZOZj7QG+EwL
         qXGzsxJtgRRjV5w8z8Av/SyrSLUSE3ZBx5z5dbs0cgmL/blmLoYNaUq/0ww31ncwBO0v
         BejQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530h9An8ywdecGsbz11x4+DNDIVve8wRo1nFHu1Q3Jw8BcOa3KmX
	wNTp5H7J+Z//4UWmddK7tbU=
X-Google-Smtp-Source: ABdhPJyIrhyFPk9C8SELom4UQFqjD2GbEWYjJpd3JnlXu6p4nk2clxJjkoahYcEVYA1wjhdqAaIrsA==
X-Received: by 2002:a63:5f41:: with SMTP id t62mr1501748pgb.252.1589299872938;
        Tue, 12 May 2020 09:11:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f04:: with SMTP id p4ls1609274pjh.3.canary-gmail;
 Tue, 12 May 2020 09:11:12 -0700 (PDT)
X-Received: by 2002:a17:90a:2b8f:: with SMTP id u15mr29832755pjd.137.1589299872631;
        Tue, 12 May 2020 09:11:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589299872; cv=none;
        d=google.com; s=arc-20160816;
        b=KRtYUnZEHP3l7Qge21EWV7CiRMNo1tpMfvYV3c/Qj9LXIoC/8quTzocc5VZLSVX0uj
         DjQLRF2Cn4hCE5dtuV8gtcOyofa+vgboXOcfl0vDx1HuJgaLIlASSDABDp0LD1cEjzk/
         1gPmmjLS8JEf6oLxUh5Ita2RpjoyQKXbvgye0BMNPZP2fIYTI5neyrKHqndWFRIWTwHX
         FDajypLoVbmPMR8lRpH3t1jvM2jstFkPJFLv6hC+bgZTZhxypup2sstQigIzJmfaLZjf
         VD6BQTQraQ+t57g0XC6FeIzW4C884fWuBHfV/olV1XKjcYY4RAD9XMxzh6eHsIEaZKgi
         5D8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mR4ivD+uIVDW/s5qQA8Ihq4vxf2hTRcfPlbA+cDLWm4=;
        b=eTVNxxb+Gz9XGud56fUD8HVyeAmIQph6aX3uau51MkYcRGs46CVVFoMX/uTzbv6wxU
         2H0t1bVjXyUNchq6uDQdVnlGaRb1nIzxCxy6W+MxGfW/4hXZORhNrgMDLltjxgmKfmRm
         6CGWS7JbApzYxYekNaP64XwF3D6L09lzV+7Rq8bSPDhV+TY22xEKTVjycwpaCKXfZYU/
         IlzD0zgeCUh9pb6H75tIQUoUsrQuSQg2205aX+vzTw20U0+egBmAq6cAekiP/PS6Uu9P
         XM+9uAu1vp4ctXQdZ3tA78eq5ZCQmmj/zkZGA3HTkatrjGisV88g6nI4yYA3DXDn7hW0
         4naQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=WRrmWf9c;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e17si209950pjp.3.2020.05.12.09.11.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 May 2020 09:11:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (unknown [213.57.247.131])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9D86D20736;
	Tue, 12 May 2020 16:11:11 +0000 (UTC)
Date: Tue, 12 May 2020 19:11:07 +0300
From: Leon Romanovsky <leon@kernel.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <adech.fo@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Ingo Molnar <mingo@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Michal Marek <mmarek@suse.cz>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH rdma-next 0/2] Fix kasan compilation warnings
Message-ID: <20200512161107.GL4814@unreal>
References: <20200512063728.17785-1-leon@kernel.org>
 <CAAeHK+zFDoykmS3KD88hD3S8R09n064c7n1gLDurMr0KOhte5A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zFDoykmS3KD88hD3S8R09n064c7n1gLDurMr0KOhte5A@mail.gmail.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=WRrmWf9c;       spf=pass
 (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, May 12, 2020 at 05:34:10PM +0200, Andrey Konovalov wrote:
> On Tue, May 12, 2020 at 8:37 AM Leon Romanovsky <leon@kernel.org> wrote:
> >
> > From: Leon Romanovsky <leonro@mellanox.com>
> >
> > Hi,
> >
> > The following two fixes are adding missing function prototypes
> > declarations to internal kasan header in order to eliminate compilation
> > warnings.
> >
> > Thanks
> >
> > Leon Romanovsky (2):
> >   kasan: fix compilation warnings due to missing function prototypes
> >   kasan: add missing prototypes to fix compilation warnings
>
> Hi Leon,
>
> I've mailed a series with slightly different/fuller fixes for these issues.
>
> Thanks for the report!

No problem, thanks for taking care.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512161107.GL4814%40unreal.
