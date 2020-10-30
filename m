Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAXD576AKGQEQGXCFPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 8481D2A0376
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 11:57:07 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id h16sf3681539qtr.8
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:57:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604055426; cv=pass;
        d=google.com; s=arc-20160816;
        b=oaW0AR3f5R5kDrGEYOmb9xnyq04Ly3xTEN5QA0sex1WFvz1o3vvKm5am6pcsnMwVr9
         5EYyGpgOnDAhgIrICIyMzbVPHRuCII73SFC0bqBLAlXkgimu4e8bhoN2HIEVQ0PniJ/c
         snb0uso4FYoYQmNS+gg5F+7dpX9HZc0pINzonsDpBuCRIBLwSEofWlfwhSRiWy2Ace/q
         jO1C90By+d2Pqi2v5hqp7XYYVZgFioxGRXYj5MykMTWHcnNHrYVuGEKg+Pa/+dm8PyPm
         1sySo2uslowJu/lfFG+rZYtk44g3PG+k6OIyMBoatRwhQIYvRPEfgOeYZ5MvSwu5iOH6
         H/YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PRsrHFJPOwx5qfvEx+33xxHWRswnWvFwJdwgyncF0FU=;
        b=RwuEpuF4XUy9DaufTOzBWXidU0pA0VYbHLS0kvsoWqyTV2DTLOZKTyelqr7uXz3iAq
         nHFmoiXRUTxbtfLOWSBhrJzgU0SVWyPKx/kwCKTSpkUkipVs8JgSu2OYcTAA2CL1JLd0
         6Wm6MYRXVWCrC8DI86jxh6vWhZwyVT1vkK0jiG8S/JcM2DUkIb+xb8I2AayAqPc0j7/a
         KcV1zfUennIUUGa+39ZuEgSFybqukqpo+GbOTA9LAGXEpqGyobuvyfxD8/rXwI08uMCR
         f+PEYzRB+/0dVWH6q0dQY2H24LQ2hcQYtVfVeEvQ0Uh2Db3DVuG8Nva+QIrLuN/lsdN5
         ANkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TfYtmrep;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PRsrHFJPOwx5qfvEx+33xxHWRswnWvFwJdwgyncF0FU=;
        b=Lo+/lwzf3qXlbz6Px8wMV93gkoNtKGk2gt2XtPov0uFYKz3YVp1BpbckglNS3TxqFr
         Gcb2U2/1kzZyrQ6GjEvSOHPN9mBHELmGiDBMq5dnQkrqGUhGqyuPQhiVKsTcEBgqU10u
         XP3AMBzEWf40auIcZVfchA5aFvHAewVqTPEAi1VcBUu2/93p2mg7wP289gihRWDvsqqk
         UDBReeNwe9ilT4wa/1VreYke5/OTlggpVeJuxRJWmtIqmBiLFFmy+zIn4ISgN5IY/RGT
         G12zxGSwwqfsXfBeOh4XgolXHofZ9h3g1EquBnJKIIWkNk46xVu8R8xYZwhkOTS2FJYJ
         R9XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PRsrHFJPOwx5qfvEx+33xxHWRswnWvFwJdwgyncF0FU=;
        b=PmDQAi3dvOgdmAwQBL1LjZ2Xfp8EsWUjBs7hqx/0zcxG/OQCs39UMT2fiORYl08A5X
         KXl6y+YnOWpWSxQKMuEWgBdLkQkGzwCB4GGqNR1w/E1puU8SmbBo7hRm7Nqae9RguPbn
         bPMdRWUgRkN2LtiAGPCTo7pYFHeNKNWQpE1Mqvm3EXjLjXmuRotN9riwyTEWIZ2dJv+R
         mhX90sgX01yeJzH8/9Ga7ZteZ1fN83MBcjaNXmmmsBLxkPjYYg/DJtGK7Gi8sZR4ug5+
         maZLEK1XWEeyCwelByyBSAPJ7v9iFf+6I8X4ftG05Ar60udVyKcYpEShO1OEbZFjY3dj
         S7dg==
X-Gm-Message-State: AOAM533X09DUuZqlgiUkea2n6Rv9+moAXGkz5gHJTXTgXBX0trPuxc2D
	ARSUxqrxsd01XaJKrkObwOY=
X-Google-Smtp-Source: ABdhPJwUij4b7qltXG6YoOibOLZhBhhmRepsu325MYAyDCAaIi83CUtYu10SKSUaBvIMenrrXcWEgQ==
X-Received: by 2002:a37:4c2:: with SMTP id 185mr1522750qke.40.1604055426521;
        Fri, 30 Oct 2020 03:57:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:543:: with SMTP id 64ls323848qkf.2.gmail; Fri, 30 Oct
 2020 03:57:06 -0700 (PDT)
X-Received: by 2002:a05:620a:756:: with SMTP id i22mr1521536qki.172.1604055426053;
        Fri, 30 Oct 2020 03:57:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604055426; cv=none;
        d=google.com; s=arc-20160816;
        b=dwgLZIr/p04UEzMu5yrq1YtsM/ZhGE7LtSwLD0tu/CH151BgB97xIvoReJ6z66MULY
         7KHZXIOsGX09u7jFihwEEH3gOsuK0b8nUUTs/VDiTjG5PHIYKp2Cfa5qTkJpfQ7y4x1W
         vuRXGmIVxJ6AQSM6Sm9j6NNK8TR5Kq9H/+pPuoDH5cj2QUXnlzWYuaTINz7saMwCGl6Y
         xKy5OnnpxyKaIdjeWKxQpUNmhAN7b7Gj+hjN0NUnO9erl29FE3ptMR1gXb7+Xsww+2FD
         VFzX6oAQLgIRYtq7uJC+B7IpmOgI/h/+9K+l2YwQrc00WiVT4wlT+GGGaBCpDG3syAow
         XetQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x083AjvGF0zQfoi/Zp4lR99mcm5WG8qTkAtv8ezIp6w=;
        b=Rmj2eC2ViWp8eN2odkVyUGSMXFzcq+7K9lmq8Mv0LWC+J3+4jffD6Zw3zPHNXGYtbD
         uEzaTX0KU4tzFVJ/7K+oLuQdeSh1VA9DzCEIWXkNbzwnvaOE9SxGntBKZwBjGd0Go5C3
         LrdOrwJdZHiS5ZxgNGqTrVucQcDz9WwMceN72pRZsQg5WhD57AkTETawNJTC9F8s2rmQ
         9teWpX4wJ/4vwkYulGlOca7Azn+PPIzmr2f4jsqSJhmjGW2zhL5LzgQSFeWPDxE0zr/v
         LJ4YSMckxOcufkwFetgXT0sSotRWXPgADrNt1yOYY/WKqi/T78Y0VctMuev7CfqLUIAh
         FL+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TfYtmrep;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id g16si320962qtp.0.2020.10.30.03.57.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 03:57:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id l62so579735oig.1
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 03:57:06 -0700 (PDT)
X-Received: by 2002:aca:4f55:: with SMTP id d82mr1153951oib.172.1604055425438;
 Fri, 30 Oct 2020 03:57:05 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <CAG48ez1xg0uRV6LqYOO-ibVqOO7jNRJGLVLrQfGW=s8TcbPGoQ@mail.gmail.com>
In-Reply-To: <CAG48ez1xg0uRV6LqYOO-ibVqOO7jNRJGLVLrQfGW=s8TcbPGoQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 11:56:53 +0100
Message-ID: <CANpmjNOx=6ZRUC-Gkx=RqX4EPtuLe=AMshGSMcnd6a3=2iNtkQ@mail.gmail.com>
Subject: Re: [PATCH v6 0/9] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TfYtmrep;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 30 Oct 2020 at 03:49, Jann Horn <jannh@google.com> wrote:
> On Thu, Oct 29, 2020 at 2:16 PM Marco Elver <elver@google.com> wrote:
> > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > low-overhead sampling-based memory safety error detector of heap
> > use-after-free, invalid-free, and out-of-bounds access errors.  This
> > series enables KFENCE for the x86 and arm64 architectures, and adds
> > KFENCE hooks to the SLAB and SLUB allocators.
>
> I think this is getting close to a good state, just a couple minor issues left.

Thanks for your comments. We'll address all of them for v7.

> Now that the magic "embed the memory pool in the BSS section" stuff is
> gone, this series looks fairly straightforward.

Good to hear. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOx%3D6ZRUC-Gkx%3DRqX4EPtuLe%3DAMshGSMcnd6a3%3D2iNtkQ%40mail.gmail.com.
