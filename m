Return-Path: <kasan-dev+bncBDW2JDUY5AORBW7M32GAMGQET4OSVCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id C9CA24570C2
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 15:36:12 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id i82-20020acab855000000b002bcea082cf7sf2952532oif.22
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 06:36:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637332571; cv=pass;
        d=google.com; s=arc-20160816;
        b=AUKVnXbHDuU37kdMzYf/JxgPpuiCgx9HkmHdRmZPsulelnBaS7JYc6vS6xbRHqtQJF
         2JaPw4IF7GTilkRBHp+qAtrnr6vAorz98W0MDMsBcy+nmImTOExhlFbz5oaxBaEtbOX0
         QPpshhyFzwuiyY4sZ7lN1EMP7vAr1lJ19vM/Q+Klw3HG/6TIiaq7quxhrjGmH1FwQP/E
         RkGtC494m6dwTBMi3aBvIo5OFz5b1s9RwefS5/k+TBQ59R0AKbLEblG5k2EK1siDfSqU
         SAN8IbJJgPOXJZ8fOWDvIOM7D8V4vcoQgxn+91aRhqxOEWfWb3Q3V2Lji5Pw6aqFY9NB
         1q1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=yVxzEdRQJ2fZmeSaEyxw8uEpODGQAgxCPC+cO8MEROM=;
        b=BHwD1BBsWBLhw4ZbEMRSil7dkKFx7S8+4PWRYsVgALZcCqYXCBNZYmNcqQ6MiN7aJx
         CwMr476LjPwA8aptFjoT9St4Q+T5s7R+ED2yBtO+smLJhk2sYbccVDWJnx31ch1qFgmR
         QdXQX75FjR0ttWpk2fAmumSzn51BmlX/MdatGiD4fYa+AlpUOUdB8uO57ML2ecNLMwZj
         he03TnCc31hNZg0WO6Yvru9GNFZwXII6Y4ZIjiFHut0DcU7VzSUA9feY4/83YdEoMd04
         hYyCiX4HSYLggt5C3gye4CqqBsRzYdZ2h/Erezpwt/wJb26lAsZ4G5MBoIYllr9dU3EU
         4Pbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=S09SVRr+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yVxzEdRQJ2fZmeSaEyxw8uEpODGQAgxCPC+cO8MEROM=;
        b=llqyfUf8NTBA6STQW1E6dziw+JIMYPNFZXmZMBQzdeCTgpwgkDJnhtwMwFjfkw8PXK
         x1oj9LeDRPti3zwcrBbKPAIn33xhXTbNFfsTRpQwZkw/bj9iZqA/D3w40G4l9RQRocC5
         Z6MEloNMA2WMEY+UJegI59sgPqZjOKyRFG8d+PNZt4V3ZS7IidQKBciJ/7Tg4YAxloyG
         hjahToDBs04aWJF7CFLUQ/jxczl7j1EfwvHwVAoIuyvDVTj+iO/dc6t99+vJHwkWW+WU
         rO+f9cJd+5n6BuCxT5B6F9GqXm08diHyJe77jOMwrxcwaWIlDjWfc1A/M9ij9na7UvqR
         Pm8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yVxzEdRQJ2fZmeSaEyxw8uEpODGQAgxCPC+cO8MEROM=;
        b=NGZ3AJyzRALS1hQDk8pLysRGLJQQRie7X62lEghOkVXYuGeJFHzzL1peGe0XSkAiuK
         YDkhXxL20HHk8hK+Z8IcL2zKYmdwK82glvKwHz44rtv4sNAJst5n041rROsY5IEnf0Vw
         lrXONy8ESwh0kfXe778b9whdvjEmLWJWcumVEYMB//jWzmwlvZYfk0b4pWLBcYzwmcr4
         UUl5Jcldz+y+GQeM3N7GOwVepI/ytWzAt3LE6hRvDxvLkz6327fL3Pw7ghIoBRAFQlJP
         LUeCrGxqjrMuL/LJYh5eyacVW1hCzyn3LsnBmxFew+Kyh+oWrQcBlc+nMHuKE543EgoD
         JqXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yVxzEdRQJ2fZmeSaEyxw8uEpODGQAgxCPC+cO8MEROM=;
        b=yzhxgb9Wx7wib3m3AM9SeDlzAVur5Z2Q1WSMlHxd9S9SkwDx/lL873x6Y6GcyNb9Cz
         k7I/n8YsWY7/RsIwOf6cFcarOGCY4XMNmc6EGCfOs23jugewGis9k5YMFtXAShySjfjM
         DWyDzm8VZfAE8C3789aWp8ixk8hfOaCNdku1E1YWb992TOWSdchIQFAy5b4gQuvDf+wF
         f+UUJ6oPRkTKE8P73l8iaFfcx0kCfOGzg0SUUKE83izmtlzT8/MTXMZ134qgWuzNTyfx
         YookVdz3vdmm1lnXINEon0WmK7RfpmIsSXncEnqP/z0gLTDOGGsDs+9XkbKCE+RIIWFE
         PWbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NhORwze6hdu5v2OYPjFd4XHu/NiF2srVCjjU9f1NMeiNkhjip
	S65BaAUt3doek7tao3cc2YM=
X-Google-Smtp-Source: ABdhPJz9w0UdhTWlET6tCBle21VGXRnlNKeoFrDz0eSKpAj7jg9VPk6YaZ7qCyX/+KQPi7lcUAfmoQ==
X-Received: by 2002:a05:6808:2014:: with SMTP id q20mr86691oiw.9.1637332571743;
        Fri, 19 Nov 2021 06:36:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ad44:: with SMTP id w65ls1400977oie.5.gmail; Fri, 19 Nov
 2021 06:36:11 -0800 (PST)
X-Received: by 2002:a05:6808:1642:: with SMTP id az2mr37017oib.179.1637332571373;
        Fri, 19 Nov 2021 06:36:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637332571; cv=none;
        d=google.com; s=arc-20160816;
        b=FVL+KvWsyl0B9gDX3aPclVFwHoQgqMyw5Tx59H797aUChgDq33Myu3HBj5fCIZvSuT
         nElACwzhydeUppCtYB0OdTgX3WASNjcpWCJhRqVrbDrjKDIkbzZFGpHDin65vNjJeNfa
         RLZrmB0ZMFTaa0E81/ghhqIarNsW49xBeu0x6krLIWbwjDz8JUZMEyOlD1PgBprozXon
         3mWuqbl1+djFaYzc9BfYecVpKBhkE33k8FU9FA+CAR8LOF/GGZwINqPnPytuopswRvE3
         uPideVm5rjbGixmlxH8Krr3wVCqajJUqhHS0rcPzrN2HL0eYc+Q3IP9okQW8dKc/gAEa
         hlHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n+RDH+9iEIrcuUvczXJii8lb9lf6yHmXP37Xa9ufdcY=;
        b=uplxiST8NVyuNzeghj3M6IyHyZXCTzj4O2zOBo6OB+77PT3soS7/aJq+uXvPbXoMlt
         8/u1nY/lavJBa0WMEe0V4cze6qxWAF5RyVHEJqCnhbS55F6/l+0+PISWxGFCSXi6Cnw7
         8fAoXe9j9NuSQKYsUYPvYqTmHUHh/ORJWMwraLa2CB/MJtKZ6R8RSw7rCzgfTPOyk42K
         oFe/h6rrplFwEFY/a/VpJUfsaPLKDoQILX/0r0rkcIV6g8bBIDN0/myhiPyJ8kJs/oxB
         4SGNfNGunNpEdxQx4A0T1MHBLa4ZZcb/eyMUSUT6DprLzU7ZjOk4k6rvODVurEY0P6dp
         4KFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=S09SVRr+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id g64si6672oia.1.2021.11.19.06.36.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Nov 2021 06:36:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id x9so10394192ilu.6
        for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 06:36:11 -0800 (PST)
X-Received: by 2002:a05:6e02:1d1b:: with SMTP id i27mr269533ila.248.1637332571116;
 Fri, 19 Nov 2021 06:36:11 -0800 (PST)
MIME-Version: 1.0
References: <20211119142219.1519617-1-elver@google.com>
In-Reply-To: <20211119142219.1519617-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 19 Nov 2021 15:36:00 +0100
Message-ID: <CA+fCnZfL_XKVhK1HxjyWzgxC1o0U76M0DK5CkOQJAGcPL3zt0g@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: add ability to detect double-kmem_cache_destroy()
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=S09SVRr+;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b
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

On Fri, Nov 19, 2021 at 3:22 PM Marco Elver <elver@google.com> wrote:
>
> Because mm/slab_common.c is not instrumented with software KASAN modes,
> it is not possible to detect use-after-free of the kmem_cache passed
> into kmem_cache_destroy(). In particular, because of the s->refcount--
> and subsequent early return if non-zero, KASAN would never be able to
> see the double-free via kmem_cache_free(kmem_cache, s). To be able to
> detect a double-kmem_cache_destroy(), check accessibility of the
> kmem_cache, and in case of failure return early.
>
> While KASAN_HW_TAGS is able to detect such bugs, by checking
> accessibility and returning early we fail more gracefully and also
> avoid corrupting reused objects (where tags mismatch).
>
> A recent case of a double-kmem_cache_destroy() was detected by KFENCE:
> https://lkml.kernel.org/r/0000000000003f654905c168b09d@google.com
> , which was not detectable by software KASAN modes.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/slab_common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index e5d080a93009..4bef4b6a2c76 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -491,7 +491,7 @@ void kmem_cache_destroy(struct kmem_cache *s)
>  {
>         int err;
>
> -       if (unlikely(!s))
> +       if (unlikely(!s || !kasan_check_byte(s)))
>                 return;
>
>         cpus_read_lock();
> --
> 2.34.0.rc2.393.gf8c9666880-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfL_XKVhK1HxjyWzgxC1o0U76M0DK5CkOQJAGcPL3zt0g%40mail.gmail.com.
