Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSNHWGZQMGQE3RSJVPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 70194908D60
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 16:29:31 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-63265b6ea7fsf11226687b3.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 07:29:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718375370; cv=pass;
        d=google.com; s=arc-20160816;
        b=gBPmIY99nrQwpvB9sJ7Th/9NGOrtF59v3+rSulg3TFjkGbsX1Ie5DkId4HcpVcluu5
         AardbQJ3f+FbvtgI1Hes0fIAdSLKJ8zSOxqJ9hQhtYv8PWQKZ+5Q8vWCR1YmUqlBqEZE
         OkhpNrtjHMy5wyfiC6MCntr9wXaww8ezlcsmJDKbmdjhctPFOww+D1gNOyWlinUpB0rJ
         GWLBGf5QciO7oGTQXRKgo9SSNOsrC3b2z1+wTnIkVHpsRY+TmD+wJKWppGA4rRBlv3+J
         TFacRFlL/cqkqnB7LWnBFWwvKQza7J5S7K4YNIoB+XfUwzJZ4+TvK3L0N+o1cRctSzVE
         KvEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4OyWhjT8UahLJztM1QR/0+AsY+WHIbBRGuwYVJQubAQ=;
        fh=ElhDa/lfLeNPVVzJYTfY+s/CfEGhFIFvRG8/muH4BGc=;
        b=ZdXpE6vxtRhq0uL61nL0jGeVnGDKXkgfEGXYc4Qy6rdhdhRVz0qjjkyOJqQ76rKFA6
         9pXLQHb8hpFasF8A25l5MwACEtI/XfnHDHEAsARsq7+FuqA9HSyChnj4zZcFE028o7GS
         Bo5ClDGffta1zPbiY+AQzM/jiLAUaeCTf6uxoczwYX7geLHjSpb1t9abEpY4nvPwHT5i
         dWNtF5VMLp4LUgqubOMkayFI0wvphZAWziRlRyNyR/WQxVMl38EG4FsVqjnjmGrH7G4F
         MRfTTihz2qSkUI+fZxu9JzPtvWN4nulaz4g6rqgkIuXhem7IjKa4ONMHcmp62v0CFppP
         pbLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=buuk3+Pf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718375370; x=1718980170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4OyWhjT8UahLJztM1QR/0+AsY+WHIbBRGuwYVJQubAQ=;
        b=a4mWwV3yRQtn4ZH2FjEKPjjnTfrIO9ZZoSVtttwP8tchANp4NTMfKNjHsgeu2DS5vn
         A9lwgF5ZT4p85Ffr3EG/2uuJ9q37PEOsQjbU7SAxv6vjbh9xKTXUgQ3Gflg8pW/Djjxy
         NyRyfkl9wFBXhLe0zNtvnA3blGjtfpXvNdpOUe2qMyzYIb++9gUQZhA+yyryRBOVnOXM
         MgCGtDQbpt7TQxCuT0oAybjqtF/LKmyEmyhX5hWDAv4Wq4n/sxBtbYbrjc+I/al++VRh
         Mvmh0IsFY3c+K1hwH4ohKyFnw+Ykprkw7hS4EHylyT1k9ZOfOcYn9c/iy6FgbL4ypz2N
         AGBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718375370; x=1718980170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4OyWhjT8UahLJztM1QR/0+AsY+WHIbBRGuwYVJQubAQ=;
        b=uD6TvXk1R9QMRTRCekEvYscPhpRXoisVGRWMqNKHUkjHR2DKo4fPAMGHSnhqFiNDw/
         /Is2l6clrXESXM6syx9pbWVPFxxGeO+hefFFj7pPRvbo0cwNtjx6pi3zXlcQ08+4C5f/
         0jWFXIzev3uFwFNcG7sT5/GyWqjviGDORGZa3MSjsc0xNYnkREGuvY4JEujvL4ZwkR0U
         qt2RYhbGCkQvAZdOeiW6ZRTbrX1J4p8gbJM9QbAHNmnBuoMy+nVDuVnDUsQWJpxDvAe/
         56I9rxW5Dyq3oUvOQwZUp9I5iejtxwNswKwpFTy17CQa7GEk6Y1M4pfR4TRMjhmqSuFf
         0NyA==
X-Forwarded-Encrypted: i=2; AJvYcCUdY8gbanfDKt2ac9BsrPUWELy5Q5alLM6Q2vuAeaaT6NNcbaFJmDdNrUlc7pq9Gd0mKPdkpImbTxKOYL5WUqyQN/L3siWrNQ==
X-Gm-Message-State: AOJu0Yzq6GknyVejk3ERBRw042P0c+NvyuBeN6Ho23iKre/u/H47kHWg
	jLzfU26r9RgZ7Wx5fQmmanLaltptGxugEzGKwgI/xMmMO0sJWQ8J
X-Google-Smtp-Source: AGHT+IGMZEj+3nI5vfgMQx3Kr9U/uJAR7GdfiCI9Bs+2nzMIHeGGg+I7661iY4edqIwU+qAITW5usg==
X-Received: by 2002:a25:ce41:0:b0:dfb:5e8:66c4 with SMTP id 3f1490d57ef6-dff153d8cd8mr2721749276.29.1718375370045;
        Fri, 14 Jun 2024 07:29:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1893:b0:dfe:f69f:99 with SMTP id
 3f1490d57ef6-dfefe9f1263ls3657684276.2.-pod-prod-02-us; Fri, 14 Jun 2024
 07:29:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcDfdmbACB4GjVTkh7i3R2WHz455HTuAMfsjkQLHR7+xz+Kcw4SjI5ac113X+5uvnE+Jfyo1uHEDgwCOZ98Bq8tNof08Y6N5GfnQ==
X-Received: by 2002:a0d:fd45:0:b0:61a:ed1e:ecd with SMTP id 00721157ae682-63224710984mr21676477b3.50.1718375368682;
        Fri, 14 Jun 2024 07:29:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718375368; cv=none;
        d=google.com; s=arc-20160816;
        b=JF9xSufavURyJNLFq1p7y53WcAkkKcmY9TE4QSTBbx/A7F3mZtr8QbJcqa+MnDZYT9
         16v9aikq/wrpqEJUkk6YKSVBwxhGEjUGCbtd7W0EBSYGmdWdQOs1zVIZcqSDzaf9GGl6
         QZJYQV5OmfbjrunqTlR79ENRd6I+YvmEOrizCgtj1kjSd5oaoJ2a7xT3Qujt85/IZ/JN
         jcOFLBtRTBlW9nm/kd0eG5AL+lZAB6tp0fJ8dCSUXR8QiXvwiDwGVsdmei0kBhs0M5R7
         6lIETU6/PI0SE1t/5CUanS/FGSyM4CuP7DVhkrSAWE0Mcgk8KPBAS4eAtmPzQ9xxgKKR
         Ym/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+M4MVfQsxov5VdJSZaNFx/kfeT/vurY02zgZoKqlOZY=;
        fh=UQ19LXEpBR9pbxzoEYGKEWrGK2a1Vbav2GzNv4szv5s=;
        b=Gu2beXY137mFoYhYOZNwGHxEnMLoN6+oh2Ycq/ud1cVsJ8Q/4xGHBwFdy7OradzzZ6
         CVfzlART5M2f2stdBZjobYflHYD896gI+BzIG862VKtmhO5HH8pyVu/2vigmmWRe++cr
         Rm5+5IZrNmFyaZlbFyUoxpetMUuJmK8DHWhSmNbUF4Z4/hAfa25dliVm94a1RBy+w60N
         Yy0DRDFUkDBw2G0uJxxqHmUUSWWIABknP45F1kqs7PezlGwozcEgtJGVHM5r62XQlCj/
         Hshqhx4mYGrl0FzPkBuiKhRdYzAcfSrKBOaEONj3HsPoPIhydyXnAx+P59eNJokln6C8
         WhvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=buuk3+Pf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92a.google.com (mail-ua1-x92a.google.com. [2607:f8b0:4864:20::92a])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-632587b97adsi663847b3.0.2024.06.14.07.29.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Jun 2024 07:29:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) client-ip=2607:f8b0:4864:20::92a;
Received: by mail-ua1-x92a.google.com with SMTP id a1e0cc1a2514c-80ba034bb3fso712843241.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Jun 2024 07:29:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYFmLLtDqfYgf8QsFU1cpQqtXMu+yh9MLhGgNmgxwc0PrxmJAL8BbKaWvBZddwCu71TCLySNj/ELuaOjXfI+ATL2thX61MgOpi+Q==
X-Received: by 2002:a05:6122:1d8d:b0:4d3:3a0f:77ce with SMTP id
 71dfb90a1353d-4ee407328c8mr3639955e0c.13.1718375367706; Fri, 14 Jun 2024
 07:29:27 -0700 (PDT)
MIME-Version: 1.0
References: <20240614141640.59324-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240614141640.59324-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Jun 2024 16:28:48 +0200
Message-ID: <CANpmjNO0T-sooJYs2ZCAzFUs6NVkV7iacY=hzB0JtGAyKhEmzw@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix bad call to unpoison_slab_object
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Brad Spengler <spender@grsecurity.net>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=buuk3+Pf;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as
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

On Fri, 14 Jun 2024 at 16:16, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> Commit 29d7355a9d05 ("kasan: save alloc stack traces for mempool") messed
> up one of the calls to unpoison_slab_object: the last two arguments are
> supposed to be GFP flags and whether to init the object memory.
>
> Fix the call.
>
> Without this fix, unpoison_slab_object provides the object's size as
> GFP flags to unpoison_slab_object, which can cause LOCKDEP reports
> (and probably other issues).
>
> Fixes: 29d7355a9d05 ("kasan: save alloc stack traces for mempool")
> Reported-by: Brad Spengler <spender@grsecurity.net>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Oof.

Acked-by: Marco Elver <elver@google.com>

mm needs explicit Cc: stable, right? If so, we better add Cc: stable as well.

> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index e7c9a4dc89f8..85e7c6b4575c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -532,7 +532,7 @@ void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
>                 return;
>
>         /* Unpoison the object and save alloc info for non-kmalloc() allocations. */
> -       unpoison_slab_object(slab->slab_cache, ptr, size, flags);
> +       unpoison_slab_object(slab->slab_cache, ptr, flags, false);
>
>         /* Poison the redzone and save alloc info for kmalloc() allocations. */
>         if (is_kmalloc_cache(slab->slab_cache))
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0T-sooJYs2ZCAzFUs6NVkV7iacY%3DhzB0JtGAyKhEmzw%40mail.gmail.com.
