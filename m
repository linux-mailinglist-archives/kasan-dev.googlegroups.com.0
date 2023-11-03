Return-Path: <kasan-dev+bncBDW2JDUY5AORBQGQSWVAMGQELHQUG4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C77B27E0ABD
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Nov 2023 22:38:09 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-670b675b2c5sf28420976d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Nov 2023 14:38:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1699047488; cv=pass;
        d=google.com; s=arc-20160816;
        b=V4bVDZ9NYIxmOW7fCtCb6lUehCcsG9bCGB9TbFvjLhYd92cdbUmcLjXfsx+YfVyzWl
         ejQiw3APgXVsQ6dc9zxCzJpSOryHEwvy/swD97OC7JlGt9xeKJ/cBoC+ILMC6Pey0DAS
         y9ehYPv74Q/l1UWmoCYkJI/c0FamIzD8mGK+W5mCuIegYiL/jbJL0M7D3NKZynHo6TEj
         zOO7HY58NrJgrtO7dSYc/4AaJ6pZTiTtTQpZU37brEOMvbXmixdKm8cUXA4n+n/EAxKi
         W/bjiqOUAo8JyaSEGwRDkIQI8EvZg0Sy/ii7EFYleHbD/Vs1QPmCUnZqxPMRmyKqZDtQ
         7wZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=2W+9e6Lg8654/JIFQeknLXogI/TkeE1MJLjmJsS7jK8=;
        fh=5+L7uDpD4jkJrN4RKVrHhQN237X0qFSnK7EFFw/OBkI=;
        b=nfa4v+o1RzUNo2BAGyJ4jDOON1ZdLIkNa578uKlxWeVgI7eiMD5hVHO7KO7zGSe1tm
         KLBnJWg72vKEzcOKvrsz0/PqwZcpm5j0gq9ykeEJ/IhNUwfnOdxP4SLzQwFrXY7JQh39
         AuTF+39kWTtctZKDm5CgBVAFhb59+cNo6uDv2Ficr/M8Go2qrtPIs+WU0MYqxX15Zkje
         HmKzO3aeYlEXbpVdIDD4db6RniJgpykhxSIVG28lp6QGSyEiH/88TR/3ZGxWSCtaBBvG
         OUHYNxmBWEuWPf7ZvYUGakAq2p8g/xO59e1y2n3b6bG3paXkDgUSuuxtQOg4WOijCq02
         sS5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nbxZeq8t;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699047488; x=1699652288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2W+9e6Lg8654/JIFQeknLXogI/TkeE1MJLjmJsS7jK8=;
        b=dGkEW4l3jggre0DAlNDDADAqmHvFq6jooROc1Rwa7HC0y/5HgPZvdEwEd6y3KVk+AM
         CgSrJ2hHCkwPtg4fF+gSCM8A1j0zxVus+PwgWY3UgYCsNtRWuc2X7tZzw9LEra9u3d+5
         +IPM6q25+oE6hmQDgip8aKqfXsHsUN9xKuAxDEK0lLpD0ZLudQw/cH1DEjjTqLXHXM5G
         6XoKNQqVWFJIu5oG/c6ICf7SAM7w7M8WrT54pqjlTFwO0Lc69cxi86ABlsRikXr/HBX1
         7iAHOo3Sr6vVdDXxDsQ5XBXZKKyOlpyN9zXFLzsqW8igQQ1ZNn7OUrvLrgB3Zgut5zLA
         NshQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1699047488; x=1699652288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2W+9e6Lg8654/JIFQeknLXogI/TkeE1MJLjmJsS7jK8=;
        b=CnJURbWrDBcYMRXEJy6uoNVmS/z7S4J1EiowUOjv1jg7gpa1KEOuCPjKNpWHiBUd8N
         KVmd40qUOOX7/4YBSq4EbmKfQ1j6qMkvWJsS5lCdwAXkBoz0otLC2FJ4zNql1Uc932uj
         Pxi9mXg4kg5BZHuHB2u6rW8H2QpFnKfgUSPtvOxIVc9YI05mN4GEQjI3TWsx7em51S3M
         Xh1uKypW3nrsR5TjtpwASBzYdqlmNO53l5e6FlXpm6W/7XWmmgxaHXfPUOgdqF/umUYp
         V/QlKGTjojriTVL+olBLKNBYXM6/OIYVrWNM3jUO6rdXR+IwBqKSObbJ89yQf/zNY9at
         9GuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699047488; x=1699652288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2W+9e6Lg8654/JIFQeknLXogI/TkeE1MJLjmJsS7jK8=;
        b=Td2GN96l8s7lbkPRf5Pueaf0BluuY8AIjmlQkg5Nu59pcyKJvV7NPFklnByjYHjKFV
         Urp+VCctxpeVpEnO/qhBLcBmQcPsRZbN4nnWMc3l/U63Npx3QwHXhNEjgKqx+IAsMQam
         uGk4pVbjmdMVFNY9PN6FRx+rqxt/euKlWXeF7j34PuxLNtsnJg2G1bwPe2xy2a2hMc3o
         iJE9ht8eEaTg+U10UTxb2nyqPDX6Q1z8jzTKjtF6iR+K/lyhwdEu5zVoa6D9DwDpwboh
         XJHs49HLkwWfYyHv/Rs+63Zkl9B29reiDBKx2bhUucqeqIyJZ4ZSlCYNOYES02WWtEb+
         avQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy9lwCr6mCgysAq3/zQtXaJcN9cJE1ad3x+VazrPzmNh3pFHQGB
	zhCYQzdcWyT2Jk+dlMox+PA=
X-Google-Smtp-Source: AGHT+IHVbWU6OjR2Cmzfl7h999wmtx4lqM3zFBRv4HOm30S51psrG5cWmP8PlEVw0Kd9J75gZA0STA==
X-Received: by 2002:ad4:5bab:0:b0:66f:ae60:8c51 with SMTP id 11-20020ad45bab000000b0066fae608c51mr29308937qvq.11.1699047488499;
        Fri, 03 Nov 2023 14:38:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5227:0:b0:658:93db:e755 with SMTP id r7-20020ad45227000000b0065893dbe755ls1478881qvq.0.-pod-prod-01-us;
 Fri, 03 Nov 2023 14:38:08 -0700 (PDT)
X-Received: by 2002:ad4:5f8e:0:b0:675:47ad:3be with SMTP id jp14-20020ad45f8e000000b0067547ad03bemr12329970qvb.45.1699047487839;
        Fri, 03 Nov 2023 14:38:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1699047487; cv=none;
        d=google.com; s=arc-20160816;
        b=iD+NrW/9//F/2rhk+uloDlXlrFMZFAWhE9uWJcAr7xTPo2XKLbqEUCylDvOvBSaLTT
         r9ZznSXnX00XKDzxlEEKKJQGTpX4rOab2OalPkFEjlODbWY6RTM5hlufOiPx3s4rHrrj
         pAV7jRu93qc5xNVCiWSKQHVdiO3KNGcQvAtHSaxWsL1MkIQClUn1sXJ6168UMSOhA27E
         PYC95NmRMaTPl5SIwpB7OU1gcbVhPDLExpm2hQO3enwCq5NLIv3XbP/c4xxkS6IHkIcl
         VuTXmw2LosWjagMu2MvLIHP7prsxa1QKOtjDyjE/FJcY62P1XJo1CnPxCLEN5/Oyn1rQ
         T3VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TwErFEOvRqH77tvd+byjAioyY68nFad6bltFM5K+5yM=;
        fh=5+L7uDpD4jkJrN4RKVrHhQN237X0qFSnK7EFFw/OBkI=;
        b=ugd1YXzr3F3rZbzUzCPSMjFZkMfOOocV18L40h6KkkQD/kW9nQltHEi4Yduw3cwyVj
         1T+H1vv1wHKRzWE9uRImDC1PAS7IDnO76qrS1ikJ2ZoSG9E9WmHL6nG9wqpcakgDaWpJ
         Y2I6M1AGssBFaok2RYA/pO0A4Gh2XC/Z+DkJJ+Ch9UBD0M8C7HB28QqI78sBx9j4ed29
         yRbFjbkgCFoxbr2oBu4hjoyp86Il1wjiUXHuiERypqRjxL8kWIZMDOIdPrH7V5K2YIuh
         1UDssa9q1fdJi6gz5imPPN9lu3vivadTwCuwNe+BYXvCuDEwASARCeu/3ePFd/bOPzNb
         /7RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nbxZeq8t;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id dm20-20020ad44e34000000b0065d001394bfsi216318qvb.7.2023.11.03.14.38.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Nov 2023 14:38:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 41be03b00d2f7-5b7f3f470a9so2049165a12.0
        for <kasan-dev@googlegroups.com>; Fri, 03 Nov 2023 14:38:07 -0700 (PDT)
X-Received: by 2002:a05:6a21:a5a8:b0:15d:d73e:e398 with SMTP id
 gd40-20020a056a21a5a800b0015dd73ee398mr25322907pzc.16.1699047487145; Fri, 03
 Nov 2023 14:38:07 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1698077459.git.andreyknvl@google.com> <CANpmjNNoJQoWzODAbc4naq--b+LOfK76TCbx9MpL8+4x9=LTiw@mail.gmail.com>
In-Reply-To: <CANpmjNNoJQoWzODAbc4naq--b+LOfK76TCbx9MpL8+4x9=LTiw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 3 Nov 2023 22:37:56 +0100
Message-ID: <CA+fCnZeQ6nkCbkOR4GqGQ9OzprGNNrXvrOqqsJP0Vr3uJKLdrQ@mail.gmail.com>
Subject: Re: [PATCH v3 00/19] stackdepot: allow evicting stack traces
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nbxZeq8t;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::533
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Oct 24, 2023 at 3:14=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> 1. I know fixed-sized slots are need for eviction to work, but have
> you evaluated if this causes some excessive memory waste now? Or is it
> negligible?

With the current default stack depot slot size of 64 frames, a single
stack trace takes up ~3-4x on average compared to precisely sized
slots (KMSAN is closer to ~4x due to its 3-frame-sized linking
records).

However, as the tag-based KASAN modes evict old stack traces, the
average total amount of memory used for stack traces is ~0.5 MB (with
the default stack ring size of 32k entries).

I also have just mailed an eviction implementation for Generic KASAN.
With it, the stack traces take up ~1 MB per 1 GB of RAM while running
syzkaller (stack traces are evicted when they are flushed from
quarantine, and quarantine's size depends on the amount of RAM.)

The only problem is KMSAN. Based on a discussion with Alexander, it
might not be possible to implement the eviction for it. So I suspect,
with this change, syzbot might run into the capacity WARNING from time
to time.

The simplest solution would be to bump the maximum size of stack depot
storage to x4 if KMSAN is enabled (to 512 MB from the current 128 MB).
KMSAN requires a significant amount of RAM for shadow anyway.

Would that be acceptable?

> If it turns out to be a problem, one way out would be to partition the
> freelist into stack size classes; e.g. one for each of stack traces of
> size 8, 16, 32, 64.

This shouldn't be hard to implement.

However, as one of the perf improvements, I'm thinking of saving a
stack trace directly into a stack depot slot (to avoid copying it).
With this, we won't know the stack trace size before it is saved. So
this won't work together with the size classes.

> 2. I still think switching to the percpu_rwsem right away is the right
> thing, and not actually a downside. I mentioned this before, but you
> promised a follow-up patch, so I trust that this will happen. ;-)

First thing on my TODO list wrt perf improvements :)

> Acked-by: Marco Elver <elver@google.com>
>
> The series looks good in its current state. However, see my 2
> higher-level comments above.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeQ6nkCbkOR4GqGQ9OzprGNNrXvrOqqsJP0Vr3uJKLdrQ%40mail.gmai=
l.com.
