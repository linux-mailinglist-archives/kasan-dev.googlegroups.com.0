Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZW4S6JAMGQEMHQXNOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D55A4EE02A
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 20:09:44 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 15-20020a9d080f000000b005cda8416ea9sf265669oty.13
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 11:09:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648750182; cv=pass;
        d=google.com; s=arc-20160816;
        b=uHsmH9LPZvCreL+qRUyPCI5Z4zIZ6v8Ug2wvh5sd3D3J/EybcY8Z01kFA6c0rxyytq
         5mbqodq0FdV6ArexInib8NEc6Lz5SuZjg06pQSfgPZ55ILgP1vVouhFMt6GVVBVKO23I
         en5iCkFbkitytHk5zUpA53YFFT2xKLSL3QjXPDyNJkwTw4UoZBPpL6AGjBtNvsOrrbKz
         M2FO/aJGIdArxU8Xq0qBbcJ+T9sr7QcZLiliU7GKv94cHujkumx4DmuUM7TXhqPbXF2n
         fbvM5YEZw1pVSIQv1byXaZ4CDEeb65uqg+yWDNWk5wvU1sc12zkInXxDsNb5URD5HFV1
         jU9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2rDUp7iOJtQ9CEqLa07nh0YHVUpMQYFHpXMtrnzVzhI=;
        b=NL2RXAbkCch0g+2WmmjAVS/d5rv1MI5Y0fRTIiFcOmgT/e5B7L0ZlwU/oAMTwdZssX
         DNzz5hp+gTthKQ1wlWHT7zfeEWR110esPmI2H4yLRe2JdnPothZxPfWbKx/NkOWXaEuC
         JRzCI3y+XSa3xdFZRjH7NFTohpqBIhqR+O/pti3ybwta8FnWNevYSPjuiVO+KH96y1Co
         3rnzr8bI2+pa5Ekgn6yIaMXONhTkv1QmMRyJF5btNJGlQkiL3EfQDK4656Jj/reZJPcV
         H7KgTdgIBTkonBcMzQXlZsjOfi8P2npqjap3kxKhXiSJ8NcxcOlxBUP49UJaiwEBYjo7
         9SDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YTYC2Ebq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2rDUp7iOJtQ9CEqLa07nh0YHVUpMQYFHpXMtrnzVzhI=;
        b=iTFhEeuxmFE/0X4LfMhIJiFOS7s9T4RUA4ndq4DOEZCXEdx4DiWs4FdqjtUqw10m0q
         5ptCCqHjI9gdGoDiED7ea0yC2MkbgFk0cE4Ikr8k+hvlaQWvOAsBHc1DZvX0Kr9oYvEq
         pOCL7Fvmp8mMyx2oVSBlVuypFkpB1ba49N8/HjmyYfTerg1YY9DtoLEoMjBGei7ztF/8
         PFH3BmRCsXww7HXp+FPyDkPfcs05EPQVZHFRiGv4YZUQGvufe8ZWejNDIMGUcKcerEy9
         eViV6DGcRE4AxA2jzM06Z57a9fOUjFB74mhf+5O/wbCS98xr+GdfgrE+GnfpWlnFwNu3
         r1FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2rDUp7iOJtQ9CEqLa07nh0YHVUpMQYFHpXMtrnzVzhI=;
        b=zhJzKMQp6XU842hIBX7m5QXw76fu/JBQJILxFo8XtJSVV5XuIj63jwOXDmnKnL1MNs
         eSzb8GeP3+5LmPgYzdbQ1vl1mqWyy3OV9zNPHTjNwKT+Xf7xzXlIYsV56K+rhcL+Mhyj
         w2X1Gj3w6ALtL0hGtl5XFffTM+5MmR0YUi9YhmU/3T29Lxa4WFKwktETj+qMeJFZz7T+
         f7Avvtde+KbbapQZ7fDgm+99CXpNgWr8nVAXVJsMkk8xcjFfRKBcOEkiwGn+vFWfVd6w
         NHvaqszCBagzXK6+p2EZMYhekdhxNXfBSVrXRqR6QnPixKeACOEQVZNE7gOJQ9eL0oEC
         IIXw==
X-Gm-Message-State: AOAM531OuwS9FGXhy4tdvvdpiwmNoudJ36feLvWMb2H4HwMmIxfuV6Vb
	PpLgee01kbrjogw6Y0EnVOo=
X-Google-Smtp-Source: ABdhPJycGHizLenV3A8mASvkEw0plgQB5Chzwnzj31w0t9dX1N/4lI8KoRpjaHWGTVUpbTB/5yWRTA==
X-Received: by 2002:a4a:b6c3:0:b0:327:dc60:8d68 with SMTP id w3-20020a4ab6c3000000b00327dc608d68mr5433531ooo.36.1648750182421;
        Thu, 31 Mar 2022 11:09:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:13cd:b0:de:c1c1:ac0e with SMTP id
 13-20020a05687013cd00b000dec1c1ac0els2509085oat.8.gmail; Thu, 31 Mar 2022
 11:09:42 -0700 (PDT)
X-Received: by 2002:a05:6870:1601:b0:e1:9f71:29b8 with SMTP id b1-20020a056870160100b000e19f7129b8mr1670558oae.125.1648750182057;
        Thu, 31 Mar 2022 11:09:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648750182; cv=none;
        d=google.com; s=arc-20160816;
        b=VgQ0sliVH0chsIPrbEOYkSBRZucUWfV3Bc9odIxycLD+xntHTePRi1FBcLv4boFsLD
         dasB2A8n+W1/IYt8nFj5DEQqzS8cqRCznkXW6O/xa9TCODIJJat3HHM89jznLnWQlyDf
         f+y2HkFKgYUddN8l3STaBj4INPG6RdbzcN2Jt25r7qqXzw4ZqNxbRXyGIu4R5cAJp2Ix
         ZV0UbxjN6u6gWOxdGv7Z9v/IYnv6mYc3iQGLo6D07K3EErRVn+OCXjErb9p+CVLD5BaY
         4bUOWJM3oDXxu/nmSQsZPE//EH4ZOpvucKJWg6XWSnzzNTqd8aMhgTcfAO16AnM4SQNn
         JBVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v9BQfqx+QR/8GDRGh/dAUoF4sFhZTDX8u5cvw9HwmsI=;
        b=KORe6qUDNecY34ADOWXq3/BAA/2OnK3a6CIPzdRb5Ncq2pxWexdQqnVJ4P2jkdklH9
         1RIXJpWptIN1S51/1iTVDCogvgxWYYOgQOF48MP3f2oGjBunAaERObhJ9sYWYluBNXIl
         6PNEyXcxxONvi8Ocvxm7OLKZrJD1KnXGXC6pprsRasYD99OMJBQK6DOv6BhamfT5i21C
         MiuTmfbLO431uOCP2G/jsGTmf7aRnwbNEFYrYB7VRrpe5aoROaXp9+vP4sKeIAxYD4Fj
         fh2qh1WoZD2BnZx2b9vBaVuytWglrff4KH5l3Ach2pGFczhJ8FMnMSwt90eFFll9+Wir
         UlDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YTYC2Ebq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id s16-20020a056830149000b005b23794cb50si4754otq.5.2022.03.31.11.09.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Mar 2022 11:09:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id j2so958537ybu.0
        for <kasan-dev@googlegroups.com>; Thu, 31 Mar 2022 11:09:42 -0700 (PDT)
X-Received: by 2002:a25:9b89:0:b0:63d:20e4:13e7 with SMTP id
 v9-20020a259b89000000b0063d20e413e7mr5362323ybo.168.1648750181427; Thu, 31
 Mar 2022 11:09:41 -0700 (PDT)
MIME-Version: 1.0
References: <20220331180501.4130549-1-nogikh@google.com>
In-Reply-To: <20220331180501.4130549-1-nogikh@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 31 Mar 2022 20:09:05 +0200
Message-ID: <CANpmjNMcjocJfA_8Qmg+Vx2FBQ7+m8JUXdQm4aAj-zeb4B35Kw@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't generate a warning on vm_insert_page()'s failure
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org, dvyukov@google.com, andreyknvl@gmail.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YTYC2Ebq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
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

On Thu, 31 Mar 2022 at 20:05, Aleksandr Nogikh <nogikh@google.com> wrote:
>
> vm_insert_page()'s failure is not an unexpected condition, so don't do
> WARN_ONCE() in such a case.
>
> Instead, print a kernel message and just return an error code.
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> ---
>  kernel/kcov.c | 7 +++++--
>  1 file changed, 5 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 475524bd900a..961536a03127 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -475,8 +475,11 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>         vma->vm_flags |= VM_DONTEXPAND;
>         for (off = 0; off < size; off += PAGE_SIZE) {
>                 page = vmalloc_to_page(kcov->area + off);
> -               if (vm_insert_page(vma, vma->vm_start + off, page))
> -                       WARN_ONCE(1, "vm_insert_page() failed");
> +               res = vm_insert_page(vma, vma->vm_start + off, page);
> +               if (res) {
> +                       pr_warn_once("kcov: vm_insert_page() failed");

pr_*() should be terminated by "\n" -- sorry, I missed this.

> +                       return res;
> +               }
>         }
>         return 0;
>  exit:
> --
> 2.35.1.1094.g7c7d902a7c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMcjocJfA_8Qmg%2BVx2FBQ7%2Bm8JUXdQm4aAj-zeb4B35Kw%40mail.gmail.com.
