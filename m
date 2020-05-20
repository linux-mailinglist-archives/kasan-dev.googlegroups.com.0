Return-Path: <kasan-dev+bncBCMIZB7QWENRBOXOSL3AKGQE6GPX7EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 975F81DA97B
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 06:51:07 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 186sf733864ybq.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 21:51:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589950266; cv=pass;
        d=google.com; s=arc-20160816;
        b=UCbdV0TtvooFWRWFJld0UR0hqd5fxfPPm+lzt5AOqOyYnZ8lsPC7tjZ3QXhPmQty0x
         o52wExGh8A6hQJkEmCr/BwIqXOxWw0fG8BwEgdV3E7oIlnQdrh9GxitdM2FDXh3qLF5o
         7mq9HSv+7mrGbjhRbRuI8pkQvBZEwPstSOpvVEM+MDSubpr3MHRqDOnQjDh5sOMckbvy
         /qg8bvyNBrUBsXlRRaAilXgtLUAxZ2PcAm4cBC06rmQiIjrGl1tbkToxSTYDZy4Ohu2/
         qPW0MvsRxXqwsR1gyKxRmWltUHa3ygVoo7k/BreZKp9yByX5Ht4OYAdjyoviGlZtNN6z
         tmHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=o3RxDq1NsQPuK0kyEWnqGgjvn8rIJV/BTRASQYy6CnM=;
        b=td5g82ABqybwt0J9+e+DbAJXbgDIeX2dFRWkJbMJZNVpqXS/NQlvmCoorvkSomW1IX
         Om49+cSAZ6XdAOdgpH9RQ7bWkTSS0+JqbjooarBTgBgL6UdSL5Z5NMNa6ZlqJN8I52kz
         v8/RC1sa0y74g9YBK27396g/arNFPzIyJmBG317bhk52/vcqnqAbItMo+WNiMGXGxiJR
         XFjWxxwJ23GQIl5rY57m9TrhXHuaOVyr2NAHHGL16eJL4VJIxoh+AIUyBYFg12okwm48
         kLW6QXobzfNVtXSBUW8FGgkdBYwpLbQ9rDIFJ0a2GOc+yslP5Rq2zIZvXJPKNY2j0EyQ
         3AZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cyy+w8HV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=o3RxDq1NsQPuK0kyEWnqGgjvn8rIJV/BTRASQYy6CnM=;
        b=PB/1Impd+rQfjTWAiPCLyhha8plRdZstl6Twer1v5EtS6+H0V92Z7Da/3sSsjQPNzX
         ljO20iDDrgx5/kshzwOUdWkA4NT3UTtCMBa+b37Lf0K71O7ddpm4Tc31WBfxGZO6g/6p
         9qihw2dUKdfo1OaE9MoZxyezgP1dRDKvQqKjLqtqp3OPz75syHMNi6kLiWZTXbPMZQRP
         RGfOzDqjNqgibj6w0Eu2QHj407mi6WzePhJFfXdGFv8MmtuDm25dBCMmxM3HpoULWrJl
         y4HYzRZ2Re/Y0Gn5pqHGKzvym+I4wPRnd7urHNuY7iVaPLIdaZykvBxwwySePe4Hi1Dt
         BgAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o3RxDq1NsQPuK0kyEWnqGgjvn8rIJV/BTRASQYy6CnM=;
        b=rFDsLR/b74x7drm647jba0LZsp9yOeLvwEn+QDFiCJItg5Yfo0HVaHGTeT8NrDAbfh
         xubozMOivNxF+3Tg5KxYRKJB0Q0Ux7O9AnqxoS6AnoD7s7nN3HPxiG6SDFsPvkSBn7ox
         STMWeMPtjK2gFpIKCWOvg4RX63VRx1qzKAdWQ5v1LOPpz2+jsogAjERJnGrbRQk4pgeG
         vDc7WKUAnhlYIO5jx1qzQ9Th9a/0JR0iggtxl/jdcSkSBA3WD5J9ZGVd5BW352s6s1f/
         F1vLJw5x/2d3f24VlOW3ixphsrhN1CZVQR6dPXsev6MDqgXEtf1djMVqfTf8uqtT2iwd
         KY7w==
X-Gm-Message-State: AOAM532U4QVDnE58NRZl0UmfTrcrOFoL8baKOaGT9WpQ9YzHxd5oV1pX
	eDB9NaII4nKGlJBBlEqpSZw=
X-Google-Smtp-Source: ABdhPJzg5FvH5N9vPMntoeC+PfePIOqUbvOECSKshXuxBqN7RL7Rw4UezPx/MFQgFInIb7dzVPjjkQ==
X-Received: by 2002:a25:d495:: with SMTP id m143mr4535935ybf.348.1589950266327;
        Tue, 19 May 2020 21:51:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:41c6:: with SMTP id o189ls726690yba.1.gmail; Tue, 19 May
 2020 21:51:05 -0700 (PDT)
X-Received: by 2002:a25:9d86:: with SMTP id v6mr3833004ybp.322.1589950265868;
        Tue, 19 May 2020 21:51:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589950265; cv=none;
        d=google.com; s=arc-20160816;
        b=ooxfVgEHIk71zbY8dkKKrK4+ex+MvrlcHkJSFneuAcJUCbrdCCRpgpvTPDYSph9wiu
         3zoOC1yY78s3wq9+BukdN3jd8iFPffrzwiOJ5P2TKKYLwi0RUlMMfWLeUOQ0Orjb9BNx
         s377DxSbI/tI7yzXBL/GmS0JSXUAxoVL/IEUv/2ISm+9mH+cz4k44UNV7IEu5Z3/cqjs
         7wCP+6S/D5jJTPgZvBsOodxqpyJ1V+fQT0b7MSV0tipe+o3SeWJKw1Cl9Lghh85Eg315
         qyYmT3Ys0BusqneJeUMBv6tMvQNmKVdVp6BtvcjipGgIBRJ8RpASefewOJnn/P5hA285
         rzcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pEdjNXmBjTI1S5BmlfhHbRWCmpTKSw4LQBXLSnQicVs=;
        b=HVAFhNBYb/B7eELTGIZqLRACZYNx9QVOk980gS3BzuHQuIdmD6UTa72Wc2yQS0+Z6g
         VVTdP1U8rx7oP9gtv/zdeTzWsjnhKTq438+4l90UafwEI29TOuSSc7U9bkr142X/kQ9Y
         ig9T9MjIc4yBBH+rosy9cYtkMQr/15XCScVC4kktFmi+MYKQMnSwOjllleXuoOoirUKc
         SHPpjv141Sn54efUUpkTskhOcZw0YlSSF5d5QckT0NcfbSC4rVTkN2K4MMZvPs6eYd8M
         ASIBZZ18KWYtM3IdtV8fHbeCcFejCFAol99ozfz4VOy5RH8/OWetPcOlViX1ADf/qHC6
         S8FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cyy+w8HV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id l199si112110ybl.5.2020.05.19.21.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 21:51:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id f83so2300882qke.13
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 21:51:05 -0700 (PDT)
X-Received: by 2002:a37:4b0c:: with SMTP id y12mr2754771qka.43.1589950265292;
 Tue, 19 May 2020 21:51:05 -0700 (PDT)
MIME-Version: 1.0
References: <c9ef35d4-5365-4e37-9e7e-68bad7355c21@googlegroups.com>
In-Reply-To: <c9ef35d4-5365-4e37-9e7e-68bad7355c21@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 May 2020 06:50:54 +0200
Message-ID: <CACT4Y+aMQhQEaDmWGSu0x+h6d43RCHuVfzR=O44dwVeZ8mWKog@mail.gmail.com>
Subject: Re: Doubts about bug types reported by KASAN
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cyy+w8HV;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Wed, May 20, 2020 at 12:01 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangab=
cd@gmail.com> wrote:
>
> Hi all,
>
> I have some doubts about the bug types reported by KASAN.
> 1. In Line 126 of "get_bug_type", it verifies if the address has the corr=
esponding shadow memory. However, from the description of KASAN(https://www=
.kernel.org/doc/html/latest/dev-tools/kasan.html), all the kernel space sho=
uld be mapped into the shadow memory region. Why there are some accesses th=
at not mapped into the shadow region? And in the code of "get_wild_bug_type=
", what's the logic to distinguish each type?
>
> 2. How does KASAN add redzone(e.g., KASAN_PAGE_REDZONE) for Page-level al=
locator?
>
>  60 static const char *get_shadow_bug_type(struct kasan_access_info *info=
)
>  ......
>  76
>  77   switch (*shadow_addr) {
>  78   case 0 ... KASAN_SHADOW_SCALE_SIZE - 1:
>  79     /*
>  80      * In theory it's still possible to see these shadow values
>  81      * due to a data race in the kernel code.
>  82      */
>  83     bug_type =3D "out-of-bounds";
>  84     break;
>  85   case KASAN_PAGE_REDZONE:
>  86   case KASAN_KMALLOC_REDZONE:
>  87     bug_type =3D "slab-out-of-bounds";
>  88     break;
>  89   case KASAN_GLOBAL_REDZONE:
>  90     bug_type =3D "global-out-of-bounds";
>  91     break;
>  92   case KASAN_STACK_LEFT:
>  93   case KASAN_STACK_MID:
>  94   case KASAN_STACK_RIGHT:
>  95   case KASAN_STACK_PARTIAL:
>  96     bug_type =3D "stack-out-of-bounds";
>  97     break;
>  98   case KASAN_FREE_PAGE:
>  99   case KASAN_KMALLOC_FREE:
> 100     bug_type =3D "use-after-free";
> 101     break;
> 102   case KASAN_USE_AFTER_SCOPE:
> 103     bug_type =3D "use-after-scope";
> 104     break;
> 105   }
> 106
> 107   return bug_type;
> 108 }
> 109
> 110 static const char *get_wild_bug_type(struct kasan_access_info *info)
> 111 {
> 112   const char *bug_type =3D "unknown-crash";
> 113
> 114   if ((unsigned long)info->access_addr < PAGE_SIZE)
> 115     bug_type =3D "null-ptr-deref";
> 116   else if ((unsigned long)info->access_addr < TASK_SIZE)
> 117     bug_type =3D "user-memory-access";
> 118   else
> 119     bug_type =3D "wild-memory-access";
> 120
> 121   return bug_type;
> 122 }
> 123
> 124 static const char *get_bug_type(struct kasan_access_info *info)
> 125 {
> 126   if (addr_has_shadow(info))
> 127     return get_shadow_bug_type(info);
> 128   return get_wild_bug_type(info);
> 129 }

+kasan-dev is the proper mailing list for KASAN questions
BCC syzkaller

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BaMQhQEaDmWGSu0x%2Bh6d43RCHuVfzR%3DO44dwVeZ8mWKog%40mail.=
gmail.com.
