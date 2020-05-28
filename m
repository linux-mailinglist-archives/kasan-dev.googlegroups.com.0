Return-Path: <kasan-dev+bncBCSJ7B6JQALRBUEXX73AKGQEFYFIGEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id F34981E640A
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 16:33:53 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id k10sf5098484pjj.4
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 07:33:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590676432; cv=pass;
        d=google.com; s=arc-20160816;
        b=z9MaxGasLrcVfiFTeo3Gs67z5mvpMyE4xM1jjWjQPwFGYHeyK/wkSJ6kRKc+DCRiga
         CefRoNi4xvXtqD6pxhXKIPjqCY7+mPFZ3Oc0ceXUZqnrdS51g3eonBIE8p9JT+pQvaUO
         zeXUyOo3niKNJge/Z4OUcWXH1pOxmI7fNraccufNlo7pTGOe4MZaNnxZAJejSkm1nbjf
         3bp4SRVB2DmRizfaAL2F5zvEMadzjbihZ5/TpoTU4ECT22Cos8vmm4thoXMo+E27qPhV
         1BcTbtI0GlI7vqWWYIYXKm3e0Uh7HFw90yy+Jtvc0lAbkdx/Ie2iIINggqNqMPEFOf1y
         OJ9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Fvtton2T+l5Vs63TgfuYj5Lj1SOR33jDAgCvqgNR5r8=;
        b=bQwoTs/wblZY2et5Y3EWMqHF77mOrXt2NrzlE47UDVXMkQm3ZHspCn9GpMBlZ220e9
         rSB0dRMa/D27B7e8zT+ruWblIYL6BG+HWv032hFMJnLPLBsiqK96XhzaYoijb8IFmlmF
         gOQfaUXPP8UNYk7q1SN/jnRZH8x0eksatMj2j+K9P8PGRpIk/SfK/H0CySMWktoBqBSq
         SwEu0N9NB6Mxb7QXxvvTCA0XeqOHKayYH+67UzbKthfPdqVLBRyv+u4Dxr0HijzTHzEb
         +IVwO9KE/GT0oAxSr3XRXBhP5Ne6YWDyVYTW/3jISeAedBhbYPYNX/HjpwS4PQl5T6Xl
         hS4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Z+MG4QnO;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fvtton2T+l5Vs63TgfuYj5Lj1SOR33jDAgCvqgNR5r8=;
        b=inNNtuP0VgW1GAFKsX5QSZhep8c6DGNGD5yr0sUMxM0JOannT+kiEPs0grNb3ufbcH
         ihWrN/Im/HrUvbcvhEPH4G1TnhKYdork3cpOp+SZ56Aq/f4wdOGHQcz/mwwSLmnEDn4W
         75OsnpEtXzL/k1GMWIrctcz7ge4mQMPJZXjpF6omex+yzDUZTX+lyL/i37j7rIPR9UFR
         4UE2C1h2vqHZKrQ5FDT896L4vo78Z2sSg4UG1T/nflTEJkO+/qSy+rYqvfdlYNF+UQT6
         3Bxa81JIT6NA/vYOyUbje6mvJXXc8p1gzAb/7j/UMvm64iYushSuXnmnil52CkkeiFw4
         +JAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fvtton2T+l5Vs63TgfuYj5Lj1SOR33jDAgCvqgNR5r8=;
        b=YO4qPC/k8A0WlHsa3qvKZ3rKheQrZVFuGgiklD9Sj2BPIqyCQDpLzWIU3M2g+GwClk
         cx8jgUA1QJWZQsQa6aytXMPugA5awuFuHx/uqB7QsFBxo/nCeiL9ePY+Q8EBzPq9TK0o
         4ESqJTfMb5jM6XPS7GiQtECez6i720TyRILldReC7nNUfUfYYf6iPLwyD7Bn05SMnWur
         /twTwQq6q9HY0//9wFKaKDNNvGtPr3Z0Yd6qx7PMO0FqiNUsN7en7qBXAj/Hndt3ivHj
         J7yznOhuJM+ardORb3+TuupP8AKnsvNpaWDyDffmO5zrBjumDuUKdBgITgw5JAt+QU9F
         GD1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+E+bhZt+yDuD/tB546L4hxC/lHfa3Soz2xvgRLvr/QUt9LeRQ
	01UbLy+EYpmYpKb9Rjv+3kw=
X-Google-Smtp-Source: ABdhPJylcJqiOzRDidMV+yYbQFAv9d8jsAIchFDccNJ4w4CecpuE+LRySvU7786/t9AR7qQcIUhWkw==
X-Received: by 2002:a17:90b:4d06:: with SMTP id mw6mr4377446pjb.190.1590676432453;
        Thu, 28 May 2020 07:33:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7697:: with SMTP id r145ls879200pfc.1.gmail; Thu, 28 May
 2020 07:33:51 -0700 (PDT)
X-Received: by 2002:a63:de06:: with SMTP id f6mr3379548pgg.238.1590676431850;
        Thu, 28 May 2020 07:33:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590676431; cv=none;
        d=google.com; s=arc-20160816;
        b=GZ385CQknxQB3IMvGQeqinpCcZGt85BW2eucHoJq4hzW/K1cxvaPMJfObwQdaCbOUl
         QDVKw32MDqnBwZZv9I7i9TMgHvZJO/vgSeN+OcDWfcluhTtMCp5zUrtYVPtS/6VQ+0U5
         Yu5C7HGR+GRY5kQoANrjp5g9JVhnFV35V2dPnIBgtsUyFxAvkL6c9UApgOPUXeuOosd8
         xO3puxtO/WrwwBg3OuhXCVhDIpZzcbkc0XDl7C9sYwrLxn1wMRorUdiqH59kXJw4GLLq
         qtFuOPdCGnYor48OPR7rbkG7D2Sn6iMLWutyteeAauUhwWcD+aMvfuoK+qlcBqR4F7i9
         Z72Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pBQOiMcyjxJF5KMUzY58hCHngjZNJvMhsoqslwe6gEA=;
        b=c7/z1enpBPQv5Z6zjVLkyV9WzCiRYUMDVOeLt7aPAA7pNC8lpZUXuePP6/OGCWIbi3
         Q3JhU8xYT5fkiw3cBGWgFXqfcLwF6k6FPJ78C776IpyC60OaDVsOGZ2HgBieLT9U/pWN
         GyIIXcB8E0zkUTGBVvYd8gckGCp0+blkFH8PlY4mTddnpNi9SN8Co6FroJ49fJFzumfP
         dv2YPHOqndr1X5F1bOqpupGZvuQYa7QUH5tzqnY/A+mOGvKt09RSTKaMTeA4+K7ILd5J
         SaVQ9HL1wiDWBw0MFvzhIfkWJkhZhGdWUURnBo6v/6/NCYNThn/roKbn6SMsEmjArCNC
         gBCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Z+MG4QnO;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id ba3si432290plb.1.2020.05.28.07.33.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 May 2020 07:33:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-144-MJXjkSsVN8mXu_JMQ8LJVQ-1; Thu, 28 May 2020 10:33:46 -0400
X-MC-Unique: MJXjkSsVN8mXu_JMQ8LJVQ-1
Received: from smtp.corp.redhat.com (int-mx08.intmail.prod.int.phx2.redhat.com [10.5.11.23])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id CDE4083DB39;
	Thu, 28 May 2020 14:33:44 +0000 (UTC)
Received: from treble (ovpn-117-65.rdu2.redhat.com [10.10.117.65])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 3B5692C24F;
	Thu, 28 May 2020 14:33:43 +0000 (UTC)
Date: Thu, 28 May 2020 09:33:41 -0500
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Qian Cai <cai@lca.pw>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	Leon Romanovsky <leonro@mellanox.com>,
	Leon Romanovsky <leon@kernel.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH 2/3] kasan: move kasan_report() into report.c
Message-ID: <20200528143341.ntxtnq4rw5ypu3k5@treble>
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
 <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
 <20200528134913.GA1810@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200528134913.GA1810@lca.pw>
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.23
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Z+MG4QnO;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
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

On Thu, May 28, 2020 at 09:49:13AM -0400, Qian Cai wrote:
> On Tue, May 12, 2020 at 05:33:20PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> > The kasan_report() functions belongs to report.c, as it's a common
> > functions that does error reporting.
> > 
> > Reported-by: Leon Romanovsky <leon@kernel.org>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> Today's linux-next produced this with Clang 11.
> 
> mm/kasan/report.o: warning: objtool: kasan_report()+0x8a: call to __stack_chk_fail() with UACCESS enabled
> 
> kasan_report at mm/kasan/report.c:536

Peter, this was also reported with GCC about a month ago.  Should we add
__stack_chk_fail() to the uaccess safe list?

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200528143341.ntxtnq4rw5ypu3k5%40treble.
