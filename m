Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHZWWLAMGQECYS2BVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E16C571BBA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 15:52:09 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id q21-20020ac84115000000b0031bf60d9b35sf6905798qtl.4
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 06:52:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657633928; cv=pass;
        d=google.com; s=arc-20160816;
        b=EezY6tOsBOOgEleMEPOQX8/k5My/qsA4VFbpE7GDspCsMgEXimOZBiK19B5xkPByVG
         ZrPXSnSk9DNXJSuYVvmr1yikcNbapl/mztglTNnxqBCb37o09MHMVfReVfD8re3hpuS7
         u/wroLNz93xjVUVf4d1/O3dpkCVWhPrvuBPzoGIPeI1+D9Pj7Anct3gcxKrbee9octlo
         +dcNK6erZSoWGKqvQI2q/V7/5/l9NEMnhTGaNKuvRLEg8/m4zzsaxo8N3lqxGDmd3ifh
         TSleXCzhd3iWF+DeYWad9WwiPIcSV19A2HDuLEkdvvfXaUcq+zm12W0U1tTweTlINNCr
         oLhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hzsv3MjhFzVh8hf5VnoXNcwmUZMG2us5MQoRjTPl6xE=;
        b=EMsW5/d8zXqIDc/IExK6fyzGtJVUVmEmRdc1TWAIhVbRosDiOKi2161i55uPUKPt1N
         lMK6p7Zol+s9zuCs+0zffoGtvDfbIyMCKfUAQlu85Jqvi4EeIBjUNhp2cM8+sTP40oT3
         SHXiulpxhYv1gfAPiOjGeoJx6bl7a4ykPo0ZbEaXwj8fcukAx5Zh4hg2/TPGuK5OiPuJ
         +zRn4mIe4iVdcegH3tWaBg/CnazdxUWQjUgSma1dMTNM1no+wIPShZfhhyJ0SiPpHbDx
         g1VjHlsiXuvXKfYXJZ4rNkFphfIHYq0GIbYdh1yZl8JlUPINBso/cQorZGF7flqN4it0
         qLAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fLRarT5d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hzsv3MjhFzVh8hf5VnoXNcwmUZMG2us5MQoRjTPl6xE=;
        b=ERMA59vsB6BrMTQWGgAbh5AqsUlfViNKS911yyADxRlnRw4LjUin344ZZYpsjTN1dB
         O1UIgRgT7OHaq29c+a/jpC7GJPUr8cEodr5s4kwDb0rPr4Je2RR6l0J0A68V2SjvGUV1
         oSuFjtfJhDinsHNxyO9SgVfEDBKY1Qd2suxmzTAqhWGn3cmHMbG/UWsl44gtQn1HA8HS
         WQ1yuG7DDI7kIAqgZe/eX+g7sC5dX1L7mggkzZFAucLpi8hKNbQopHQAURtJwkmTgsJ+
         j0re80BJJS0Krn2dEvRKaTnRXG3K4jPzBMD67oTCzyL3wWCtc6rdQBdfvncR4ay51jaa
         smyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hzsv3MjhFzVh8hf5VnoXNcwmUZMG2us5MQoRjTPl6xE=;
        b=JFTy0Jy9OW/WloSxdY0G1DYjXK9CN2GOBgFGHoGlg6Q7B6W1hXwKQkZP1qa4eYFWga
         mBUVuMYlrZmCqnoDu4Q8U0WY2HOT53tCOxAKrIX4W5lGWGlUvvmv3gs3wWthOkEoon+r
         441tKjJ9ZXnrnoHvPhzdIA4apEsfXwuwwo0gXGBctqQ3/wb7907P52i+A2OL+spvK70M
         6BX1DJ1nWYuvP+YFzxOBtXn4p2Lt6nsorDrpen+b+yXa2xgNXJrD3FqQAsAkNX10OiCj
         0L3N/VC1LiOQXNuW9vzKbtkDB+/Mhfl3ySxWDYd8Kl++o5mKFJFolpxg31+dKx6IbIiH
         DuBQ==
X-Gm-Message-State: AJIora+6l2xuQtA3CrFCb3NsE5Orn9PqMfFPaeYkj2HaVQQItPyP4eEJ
	W5q9yGkNP+irRXEq7hg9xnY=
X-Google-Smtp-Source: AGRyM1sgdQcI5XfpN2MS8A+GYMXOmuKJfozsZT7hiDIPEFsA+QgSCzkyJ7xRNVLcIjdtAXjsAtkpGQ==
X-Received: by 2002:ac8:4e88:0:b0:31e:b05c:47f5 with SMTP id 8-20020ac84e88000000b0031eb05c47f5mr11439501qtp.64.1657633928197;
        Tue, 12 Jul 2022 06:52:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:40c5:b0:6b5:877a:1f44 with SMTP id
 g5-20020a05620a40c500b006b5877a1f44ls1898955qko.0.gmail; Tue, 12 Jul 2022
 06:52:07 -0700 (PDT)
X-Received: by 2002:a05:620a:c43:b0:6a9:77ef:e000 with SMTP id u3-20020a05620a0c4300b006a977efe000mr15314387qki.396.1657633927662;
        Tue, 12 Jul 2022 06:52:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657633927; cv=none;
        d=google.com; s=arc-20160816;
        b=exlKtRdunbKgrYssHEM+n1FsWETIH2uKZcMK0lQ/jlMYkWLN/vn9IdJoA2OekBrkYO
         U4P28XdFr4V5muTCRYw5Ip2w2o2xhlxVF66K7giDeY3AzTKXlitEzE9HfcRy78EPxOyW
         EDpJxRQyhyRUSUKAoFdvq1zJ+pIn9A/Y8zKwRGWaH6P846Z3+4U+hfYhDrkcCqtHlt9i
         5VZj4tpWW0MvQSQ+R2DN5tGpdLoe/eaJg8JtEvDnt0kg1QKKIXc0/19elVketQVc7s0M
         kgYe+c8+veeWIMhYogVpNKFOJOjBdA5VYsv9p4MrPXJKTm7J3ZVus/xXbiOySxKsJ2gl
         A9yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hWp5/64or+mP5imIMCPIUbpfNaM35wXtmKXqwrNhd14=;
        b=mOsCoNbsQY89rS8zPf77GJQ0ywCw9WXSkBkB94tSyrGeBskOHbyEkhC8nSP6zu6B9H
         BBkercf7U1L8d71YqkAPTePPlofDrveNRlXojx26y3gLVQeE0OLojo4ltfv8XXLRzZmE
         HVC+5lsUUWIkbV94KSuvl1GFC1ra2uZ+7xdP38fM+B4Bwhxx/IgVGlvL2J4oudP240pd
         5N/NeQlIJX5gW4bCQk5hkIZTkOAO9Ev38shnO/VlWq1P3e8O37dio+O4XbW1pCsAHcao
         /+W16aAKwy1gzb3npAKDcv0SlQM7RbabGNOqkCPFPQwgIKfGQbwhDGNNNGHpwvbuItQs
         LMig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fLRarT5d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id 27-20020a05620a079b00b006af266a394fsi282820qka.3.2022.07.12.06.52.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 06:52:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id e69so14048871ybh.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 06:52:07 -0700 (PDT)
X-Received: by 2002:a5b:10a:0:b0:66d:d8e3:9da2 with SMTP id
 10-20020a5b010a000000b0066dd8e39da2mr22834061ybx.87.1657633927213; Tue, 12
 Jul 2022 06:52:07 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-19-glider@google.com>
In-Reply-To: <20220701142310.2188015-19-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 15:51:31 +0200
Message-ID: <CANpmjNOPJL7WAUh5CUZOYO8hY-dHTHMUMJzd9OGbmWES+smtrQ@mail.gmail.com>
Subject: Re: [PATCH v4 18/45] instrumented.h: add KMSAN support
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fLRarT5d;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as
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

On Fri, 1 Jul 2022 at 16:24, Alexander Potapenko <glider@google.com> wrote:
>
> To avoid false positives, KMSAN needs to unpoison the data copied from
> the userspace. To detect infoleaks - check the memory buffer passed to
> copy_to_user().
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

With the code simplification below.

[...]
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -212,6 +212,44 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
>  }
>  EXPORT_SYMBOL(kmsan_iounmap_page_range);
>
> +void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
> +                       size_t left)
> +{
> +       unsigned long ua_flags;
> +
> +       if (!kmsan_enabled || kmsan_in_runtime())
> +               return;
> +       /*
> +        * At this point we've copied the memory already. It's hard to check it
> +        * before copying, as the size of actually copied buffer is unknown.
> +        */
> +
> +       /* copy_to_user() may copy zero bytes. No need to check. */
> +       if (!to_copy)
> +               return;
> +       /* Or maybe copy_to_user() failed to copy anything. */
> +       if (to_copy <= left)
> +               return;
> +
> +       ua_flags = user_access_save();
> +       if ((u64)to < TASK_SIZE) {
> +               /* This is a user memory access, check it. */
> +               kmsan_internal_check_memory((void *)from, to_copy - left, to,
> +                                           REASON_COPY_TO_USER);

This could just do "} else {" and the stuff below, and would result in
simpler code with no explicit "return" and no duplicated
user_access_restore().

> +               user_access_restore(ua_flags);
> +               return;
> +       }
> +       /* Otherwise this is a kernel memory access. This happens when a compat
> +        * syscall passes an argument allocated on the kernel stack to a real
> +        * syscall.
> +        * Don't check anything, just copy the shadow of the copied bytes.
> +        */
> +       kmsan_internal_memmove_metadata((void *)to, (void *)from,
> +                                       to_copy - left);
> +       user_access_restore(ua_flags);
> +}
> +EXPORT_SYMBOL(kmsan_copy_to_user);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOPJL7WAUh5CUZOYO8hY-dHTHMUMJzd9OGbmWES%2BsmtrQ%40mail.gmail.com.
