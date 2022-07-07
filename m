Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY7DTKLAMGQEQTJ7PAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 00460569F40
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jul 2022 12:13:57 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id x123-20020a626381000000b005254d5e6a0fsf6609758pfb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jul 2022 03:13:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657188835; cv=pass;
        d=google.com; s=arc-20160816;
        b=JCggLPCSCdk37QQuZ9m+VjP75RkR7g9cR/lFro9MqDvazEfBdfNt2+xMzWSLmjLRjx
         8RAvO6AWLQ3QxQvXKehIpTOItNuYhSZcAJJxc7phoYtU30E/kyW9trTTs7UHJ6ywxcN5
         FoTN/8H1b8CN9hb7gCHiDkRQxTbLp8DrU3A5NecTmEsy0U0ogZ+7GFZCN6f4yZmbDCZ4
         q6L14M1pRWN4OXBpCjyh0++WupK6n4xGKAAZl5OS6cqf37CJshKYjVv2b5L03+Yk9yOv
         L+N11BdFZPgdzuCY+Y29xfLaDiyIqta6nKcBEzWMDQJotCu/C6rlUByqDRMpYtIWYj/f
         y7uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jbqdIDhDRHnunMzIm1JwD7epMi6lG9xeoeYAqI5h0Tw=;
        b=yqDuH4GIg94mHpZ9rdvDgn/4atcLj/ljz57DvfX4e0tNM4PeQXHNeNLVFHis54jN+6
         AttLOEKIdcXqZ66fEkbGubcm2aDzbHWXukE9AtCOpBOZqJSgEgfOeNquG2JOfrN/ct3u
         f5qXFVrqiqxqZCE+iRyOe/+IQdTWQz+EJi21Wo39lQV3UI+KkxJ60MCcpa/NQbNsL/Vf
         pBdmgPRTmpOgT8yqLIPpQNmKR+ItSgHdk5UXr/i7WHZKwcrpNnXyTyncPc1zfqUu3uEp
         EPJTEGN9Sufq9ogyTq+QtVcBPzSD2no7uoyYBpK7OkpbRBgm7q8HeewKkTKhBLMcL5E4
         3uiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NQ9bRvc9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jbqdIDhDRHnunMzIm1JwD7epMi6lG9xeoeYAqI5h0Tw=;
        b=B5G4vgBClDPiA9JS/c41VLuTcvYDrsO17Uq6ItdNBrEciIvWBj8SAPBhI4Ne1bh+TY
         mFIQ72K+OHdj8nDtXxlmkHnOkh4J7ldliO3TyvD1Uw/aUbxdY6drB6C0dlZL/BYAIA/N
         F1xuhaXTlbwCl6lqKCuGYjwFkJY5e5nN1T4jd+vpbr2Qf7p6jdHMy5r/Aw2XYCKtVdeP
         7ihNvwrpENcUFyGCrkVN48lcmZ5IF9lo3JmoMJL32ca9gRApzP0404IIZPXsbdjhOZLA
         kDn3eNlI2GrxHd3VB3+rb/Bx/i+j3vP7mbj+D0dJtVsKlixBCRBahOI+U84Yr+QZqG0h
         1/ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jbqdIDhDRHnunMzIm1JwD7epMi6lG9xeoeYAqI5h0Tw=;
        b=fnJ74lHTCNx3AbBci03coaMJtBSxyftAlGoS2aPOr0ETUN2jb8sa3XHKu7tA7vCFpK
         jFrLPFF2ppIjw9C5OE5ma7ZIlKY3+x80qs/Ru0rYwMyPpsJvbpIAlFIdrzaokHQtX7ui
         wSmxUt6GBxBRXkO0sqsE0lH77BWZyJ6+D11dzuC5/uJxTVQ8LUlIFwozLXGSJQt9HjmD
         Zxa6yG/KPdkcLfjwqwBPtaf6N8sDzYATjOb3zTpRMjd24KGeB4HuZHhj8RAGk9v7vSOH
         LNDQGfVE/u6pmHKkZNrkNULrT5+Om1NeAH8loabt5QY8u+2kd03cQ5uR7eGPK3KIGGHy
         LpAQ==
X-Gm-Message-State: AJIora8/HJcqLKaPVblf2hZhLRZI7seM4ZrMJsp2LBMxxNV4TLX4mrl1
	irSMnOBYu8VEtRqYLJDATMc=
X-Google-Smtp-Source: AGRyM1tvRzPbshan5v1tU4l91H0UXzlxjY2LXj79Bf7xGKnEv6f8mwkm2sc04ccE2QxRdBDbSMtzZw==
X-Received: by 2002:a63:8bc3:0:b0:412:b13e:ae27 with SMTP id j186-20020a638bc3000000b00412b13eae27mr4362118pge.590.1657188835253;
        Thu, 07 Jul 2022 03:13:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d4cd:b0:16b:e3e1:c00a with SMTP id
 o13-20020a170902d4cd00b0016be3e1c00als4974874plg.9.gmail; Thu, 07 Jul 2022
 03:13:53 -0700 (PDT)
X-Received: by 2002:a17:902:e885:b0:16c:408:9317 with SMTP id w5-20020a170902e88500b0016c04089317mr7606026plg.62.1657188833747;
        Thu, 07 Jul 2022 03:13:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657188833; cv=none;
        d=google.com; s=arc-20160816;
        b=0XmUwGouzeKgG/YSmjrUhQKcRHZWSdSnbWplrt9dOPAWPgYz2YPNHl7N4EikMVQRmF
         F0+0Y8fKKl3vDEQ+Q7THQjnQDgEt3TYec4cfDoer/N8mSOPe6W+xLmMBL8h+EQrJmaUj
         nK1LDoJhJtNj9TSNUG4jdSQY6U4uAIllzIyX0jwEeHgFPvueInup4VoAdRJumQu0yqo1
         YnzsZuiEOs3cG3LrN7q3cxlaM62KdIBzbkb2p874+1vuoHbb3W/6LR3jymB5P0Lj/tsZ
         oAVGRsDmMObm50F2bEEUpyvNGwjZGl2hyL9HOHOcgyczHyd3B6gjRUmsBCBrf8/qB9en
         1Rjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kPWo2TmGl+9OHVe70g4XsibJyi/n5Q+LOKMuqK03HYA=;
        b=vclbXuOVMvBrEdO6a92znnKqnv3/v200uhrsjn77wou99fvjCjcxsmFuRLDW+UlZBM
         ZTLMzPr83HIvNS3mAcFd69bRzARa4URRGTUIau2STCLx3mWgmF37FpgMDtwg0QcR50dJ
         vcHBKaeFGbK3GhzH5138KO+T6zvo92RNz7fglBLO8wbN9Z032Lt5i1ATJEgKic6MSE7d
         Xey3qO+GnPVM8CdZnRk3+qym4RpzA/E25hj8cwdLJvXLySV0F5Bt/t7lm2ZdorGBHnjn
         8zXwLoCMJSvJqqHp0ZPX5eQ9tSrekT803QbijL3asplOYxj2Ev4TJmh3NBaAMnzEryOv
         lsNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NQ9bRvc9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id y15-20020a170902d64f00b00168a12d520csi1220465plh.3.2022.07.07.03.13.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Jul 2022 03:13:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-3137316bb69so164960387b3.10
        for <kasan-dev@googlegroups.com>; Thu, 07 Jul 2022 03:13:53 -0700 (PDT)
X-Received: by 2002:a81:e17:0:b0:31c:a24c:9ee6 with SMTP id
 23-20020a810e17000000b0031ca24c9ee6mr21067667ywo.362.1657188832898; Thu, 07
 Jul 2022 03:13:52 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-5-glider@google.com>
In-Reply-To: <20220701142310.2188015-5-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Jul 2022 12:13:17 +0200
Message-ID: <CANpmjNN28k3B1-nX=gtdJxZ4MS=bF+CuPG1EFp5fC2TDQUU=4Q@mail.gmail.com>
Subject: Re: [PATCH v4 04/45] x86: asm: instrument usercopy in get_user() and __put_user_size()
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
 header.i=@google.com header.s=20210112 header.b=NQ9bRvc9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
>
> Use hooks from instrumented.h to notify bug detection tools about
> usercopy events in get_user() and put_user_size().
>
> It's still unclear how to instrument put_user(), which assumes that
> instrumentation code doesn't clobber RAX.

do_put_user_call() has a comment about KASAN clobbering %ax, doesn't
this also apply to KMSAN? If not, could we have a <asm/instrumented.h>
that provides helpers to push registers on the stack and pop them back
on return?

Also it seems the test robot complained about this patch.

> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> Link: https://linux-review.googlesource.com/id/Ia9f12bfe5832623250e20f1859fdf5cc485a2fce
> ---
>  arch/x86/include/asm/uaccess.h | 7 +++++++
>  1 file changed, 7 insertions(+)
>
> diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
> index 913e593a3b45f..1a8b5a234474f 100644
> --- a/arch/x86/include/asm/uaccess.h
> +++ b/arch/x86/include/asm/uaccess.h
> @@ -5,6 +5,7 @@
>   * User space memory access functions
>   */
>  #include <linux/compiler.h>
> +#include <linux/instrumented.h>
>  #include <linux/kasan-checks.h>
>  #include <linux/string.h>
>  #include <asm/asm.h>
> @@ -99,11 +100,13 @@ extern int __get_user_bad(void);
>         int __ret_gu;                                                   \
>         register __inttype(*(ptr)) __val_gu asm("%"_ASM_DX);            \
>         __chk_user_ptr(ptr);                                            \
> +       instrument_copy_from_user_before((void *)&(x), ptr, sizeof(*(ptr))); \
>         asm volatile("call __" #fn "_%P4"                               \
>                      : "=a" (__ret_gu), "=r" (__val_gu),                \
>                         ASM_CALL_CONSTRAINT                             \
>                      : "0" (ptr), "i" (sizeof(*(ptr))));                \
>         (x) = (__force __typeof__(*(ptr))) __val_gu;                    \
> +       instrument_copy_from_user_after((void *)&(x), ptr, sizeof(*(ptr)), 0); \
>         __builtin_expect(__ret_gu, 0);                                  \
>  })
>
> @@ -248,7 +251,9 @@ extern void __put_user_nocheck_8(void);
>
>  #define __put_user_size(x, ptr, size, label)                           \
>  do {                                                                   \
> +       __typeof__(*(ptr)) __pus_val = x;                               \
>         __chk_user_ptr(ptr);                                            \
> +       instrument_copy_to_user(ptr, &(__pus_val), size);               \
>         switch (size) {                                                 \
>         case 1:                                                         \
>                 __put_user_goto(x, ptr, "b", "iq", label);              \
> @@ -286,6 +291,7 @@ do {                                                                        \
>  #define __get_user_size(x, ptr, size, label)                           \
>  do {                                                                   \
>         __chk_user_ptr(ptr);                                            \
> +       instrument_copy_from_user_before((void *)&(x), ptr, size);      \
>         switch (size) {                                                 \
>         case 1: {                                                       \
>                 unsigned char x_u8__;                                   \
> @@ -305,6 +311,7 @@ do {                                                                        \
>         default:                                                        \
>                 (x) = __get_user_bad();                                 \
>         }                                                               \
> +       instrument_copy_from_user_after((void *)&(x), ptr, size, 0);    \
>  } while (0)
>
>  #define __get_user_asm(x, addr, itype, ltype, label)                   \
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN28k3B1-nX%3DgtdJxZ4MS%3DbF%2BCuPG1EFp5fC2TDQUU%3D4Q%40mail.gmail.com.
