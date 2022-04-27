Return-Path: <kasan-dev+bncBCCMH5WKTMGRBN4HUWJQMGQE3LDSTUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 03FCD51183E
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 15:23:05 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id g20-20020a67e214000000b0032cdb80e1ffsf125093vsa.17
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 06:23:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651065784; cv=pass;
        d=google.com; s=arc-20160816;
        b=sd6hoNrD6xfAEXWLMAQMxCHa6tM2PoRBYa9Zy5mdowRUbDd2HTf9SadYiOYOUF+IWK
         T7T1t7FNdSfQHBpIMIR71saml2AT1gdnVdrsr750LotNDnJ76YZoufawfq7YirghRlgW
         T3qO4K+7ETNeYq9geWgoWUltdff0qBcrj4ufy+rmBWEi1J11pBwCFzcX7J9PWXEqjDG7
         h/OizWxO2dKlC4yjAXlfJYAbGo53JwHyiEmCakYeOgDWTC9tWo8OLCYo8SwCfRgcJN5B
         i2gFRTCphrlfkgXd6V4iaUI2Y7vOwqFsRXsMc9gVqLW5NJ04sK+Nd/J1gg47rBoobrIm
         9vXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MIFGfgB5w1GeAVGkCxvKaPKeAKZ7tcaOU43eYuimUJI=;
        b=aoiw+ss2UcDAJAQ4tJI6O4opvYXAw+/Ca6PE2MqDK0gglHfkR1NqBil8v+gdI0ReGM
         +759jr2CMexkEevXrFnaaODRf3GrBsJKQbem4lhLDpgzj9kuA7hj3fb+Y/Bj9rbwgdFr
         UBC7d9L2CBKJxrKNbq5yCtIf6D4Bc7Zk+9JMv/hW8C32ka0dxh//ipJDNpEx70BgQ3M1
         eWErF7cpfOhffKth/0KsWbkZnMmJpGE7Db9tQ6DtlW/RgNVwtLIy/DbqR5+DF1k4o0WR
         IjGMlPYTglXn1csoCaAwYDWLqRg+nuUgVcamWTLn+OthqMp2BGdY/mrFMbNJp6PJkmMO
         4gXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="jemas5/k";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MIFGfgB5w1GeAVGkCxvKaPKeAKZ7tcaOU43eYuimUJI=;
        b=SiBtINZaAVD+oo9VWeeu0ntOR+JIPd/ykfm6CqiQJy6sZsxSPwArD1fD1ajz18JXlj
         TGq615dgVFo96OXxxbPdR8U9le8ZhRalFNmX67Kr1zTRCv/4D2uy2Q3xAUZ9m4K98HqP
         jJhfpYcoQvdrYWHKQiURlqg5iVVuAjyg1/Q+RDCuFUI+SnbR6kBnhMo9GVekw0+u1A5f
         X85yPE5ivfFfPgmJgQusdY6cZi/MD/5/iTcTZUfgcYmNsuYAGrcdiCEE1bh85CIyzAJu
         wuqiOrm8jaH7VoPve/urpzC9pZx9TiJ9IplrZMQVkui2Vkgcti2yfTVO0u5DsUy/oQoI
         6RaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MIFGfgB5w1GeAVGkCxvKaPKeAKZ7tcaOU43eYuimUJI=;
        b=3ucr9FdgDb8Uz1kecNZjZ0/H0ogUbofySHmcQtsfkG+yyYnRhwj5u47gDy/ajGJk77
         HG6CwqO7BCDcTeU32cauN++8diZtgaJlBuZqXuHGKWI2BGyCUm8Lx2DJlWHHXsRFXGy4
         8jiIdaZqjKJUShKG1aHpEGmG4Iu86mJcCMGL9C8NXFSxHAf1ClaTohe4itC9Et2Ykguo
         jdBodto9c51GGptvBEs2CJSTUNJn34SXFDfkc4oGc7ZHlvRES7sHuC0Kq0qFUeSjMgIH
         zIiFj8AUM7IV9TMsHfwEQ8TA53XA4LyPnC/Cx15r99DJSBvMGv7GX/VZH3Ok1Z5fGmBa
         lgFQ==
X-Gm-Message-State: AOAM5326mFzh9zRL7dkGpk/evBZTvEDZa6Q4YYBkK2ImHY97plf1R9ux
	oP+8DfCD56EKcDVp6FdBKH4=
X-Google-Smtp-Source: ABdhPJz+JPflWCaJUg/Xk6S7SsF01+N2wZexyt7v5M3pTNqsyfxmCst7oAfrhLDfCKU1C+va6QVRzA==
X-Received: by 2002:a05:6102:34e3:b0:32c:ce9b:9507 with SMTP id bi3-20020a05610234e300b0032cce9b9507mr4730695vsb.27.1651065783799;
        Wed, 27 Apr 2022 06:23:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:136b:0:b0:346:c4d0:f639 with SMTP id h40-20020ab0136b000000b00346c4d0f639ls224285uae.4.gmail;
 Wed, 27 Apr 2022 06:23:03 -0700 (PDT)
X-Received: by 2002:ab0:77d5:0:b0:352:42d7:88c2 with SMTP id y21-20020ab077d5000000b0035242d788c2mr8407650uar.1.1651065783112;
        Wed, 27 Apr 2022 06:23:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651065783; cv=none;
        d=google.com; s=arc-20160816;
        b=Gch6irpGn9hF8zjMBmMejca7OBKOk7RsiTXADzqhKYniB+HJxuWqqvSwaU4qZQzQsX
         +jymBgY2mmt0W2xiUBrgJ8EeI3Ixv0axKB3hrRHNyZOdGZAhexPEw32V0j+dAFAPzZdb
         JIuJS7IkHeHXBXl4PdlUyY9uVEHyD9WYBcL1djrXHtG0T4/0p+160cRwIgatoYAoH8eM
         2rB0CTClmLwH6KAElp4XM4E0yg3VPvH+fngE3HZxEqSxjGnLS1wKbBmTWwJAzfnmxyJ4
         cLXzMSKQQuWeDSdC+6jMaU8h8EPn4fFLuqzTyufnSIcAS6hux2FkGw7FUWmj77WNGm/t
         isGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lTChzR1l6Fyb/9cgX7AZvSL07PrKsVlUDY8Ot51JsZM=;
        b=y2K9Dq2IdAXY66WW9ogMrj0TFHE1mW32EvRueAGE72c+sTfy7uV2MsyIXLw+UBlyru
         kw2h+rhaOH92tjMkD+FgOvHejmQ9QsnQEWDzBsGANCF7NkJwaiFJKHyO8zHQAN58RPbv
         dAUe69FIfT6HLYquyKRuz5sri0Mkkg263CvIxOAO+DVvqAeLP5uTpNI9smCoUgJ9j4GS
         QGBxWWSu5XIMvEQikprWqflgWus8CSM4ZpKf+fmGpvlRgwSOcety2amLfzQcj8FwG41H
         jREClguBlR61tr5qJsH4w3WNkxnpYzwA7IDdSMunGhOp1RLg3+O0QBTjUiWbBCX07ByV
         gkfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="jemas5/k";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id x14-20020a056130008e00b0035d35a0f706si150554uaf.0.2022.04.27.06.23.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 06:23:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-2f7d19cac0bso18094437b3.13
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 06:23:03 -0700 (PDT)
X-Received: by 2002:a0d:d615:0:b0:2f7:cdc9:21c0 with SMTP id
 y21-20020a0dd615000000b002f7cdc921c0mr18939638ywd.486.1651065782601; Wed, 27
 Apr 2022 06:23:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-2-glider@google.com>
In-Reply-To: <20220426164315.625149-2-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Apr 2022 15:22:49 +0200
Message-ID: <CAG_fn=UPWj1H0ScAQsDKM1WobHiFdbJc_u0hMuMVSiGgQTNXZA@mail.gmail.com>
Subject: Re: [PATCH v3 01/46] x86: add missing include to sparsemem.h
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: multipart/alternative; boundary="00000000000079773105dda2b5b6"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="jemas5/k";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

--00000000000079773105dda2b5b6
Content-Type: text/plain; charset="UTF-8"

Sorry, I somehow failed to update the commit message as requested by
Borislav in v2.

On Tue, Apr 26, 2022, 18:44 Alexander Potapenko <glider@google.com> wrote:

> From: Dmitry Vyukov <dvyukov@google.com>
>
> sparsemem.h:34:32: error: unknown type name 'phys_addr_t'
> extern int phys_to_target_node(phys_addr_t start);
>                                ^
> sparsemem.h:36:39: error: unknown type name 'u64'
> extern int memory_add_physaddr_to_nid(u64 start);
>                                       ^
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> Link:
> https://linux-review.googlesource.com/id/Ifae221ce85d870d8f8d17173bd44d5cf9be2950f
> ---
>  arch/x86/include/asm/sparsemem.h | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/arch/x86/include/asm/sparsemem.h
> b/arch/x86/include/asm/sparsemem.h
> index 6a9ccc1b2be5d..64df897c0ee30 100644
> --- a/arch/x86/include/asm/sparsemem.h
> +++ b/arch/x86/include/asm/sparsemem.h
> @@ -2,6 +2,8 @@
>  #ifndef _ASM_X86_SPARSEMEM_H
>  #define _ASM_X86_SPARSEMEM_H
>
> +#include <linux/types.h>
> +
>  #ifdef CONFIG_SPARSEMEM
>  /*
>   * generic non-linear memory support:
> --
> 2.36.0.rc2.479.g8af0fa9b8e-goog
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUPWj1H0ScAQsDKM1WobHiFdbJc_u0hMuMVSiGgQTNXZA%40mail.gmail.com.

--00000000000079773105dda2b5b6
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto">Sorry, I somehow failed to update the commit message as r=
equested by Borislav in v2.</div><br><div class=3D"gmail_quote"><div dir=3D=
"ltr" class=3D"gmail_attr">On Tue, Apr 26, 2022, 18:44 Alexander Potapenko =
&lt;<a href=3D"mailto:glider@google.com">glider@google.com</a>&gt; wrote:<b=
r></div><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border=
-left:1px #ccc solid;padding-left:1ex">From: Dmitry Vyukov &lt;<a href=3D"m=
ailto:dvyukov@google.com" target=3D"_blank" rel=3D"noreferrer">dvyukov@goog=
le.com</a>&gt;<br>
<br>
sparsemem.h:34:32: error: unknown type name &#39;phys_addr_t&#39;<br>
extern int phys_to_target_node(phys_addr_t start);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0^<br>
sparsemem.h:36:39: error: unknown type name &#39;u64&#39;<br>
extern int memory_add_physaddr_to_nid(u64 start);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ^<br>
Signed-off-by: Dmitry Vyukov &lt;<a href=3D"mailto:dvyukov@google.com" targ=
et=3D"_blank" rel=3D"noreferrer">dvyukov@google.com</a>&gt;<br>
Signed-off-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com"=
 target=3D"_blank" rel=3D"noreferrer">glider@google.com</a>&gt;<br>
---<br>
Link: <a href=3D"https://linux-review.googlesource.com/id/Ifae221ce85d870d8=
f8d17173bd44d5cf9be2950f" rel=3D"noreferrer noreferrer" target=3D"_blank">h=
ttps://linux-review.googlesource.com/id/Ifae221ce85d870d8f8d17173bd44d5cf9b=
e2950f</a><br>
---<br>
=C2=A0arch/x86/include/asm/sparsemem.h | 2 ++<br>
=C2=A01 file changed, 2 insertions(+)<br>
<br>
diff --git a/arch/x86/include/asm/sparsemem.h b/arch/x86/include/asm/sparse=
mem.h<br>
index 6a9ccc1b2be5d..64df897c0ee30 100644<br>
--- a/arch/x86/include/asm/sparsemem.h<br>
+++ b/arch/x86/include/asm/sparsemem.h<br>
@@ -2,6 +2,8 @@<br>
=C2=A0#ifndef _ASM_X86_SPARSEMEM_H<br>
=C2=A0#define _ASM_X86_SPARSEMEM_H<br>
<br>
+#include &lt;linux/types.h&gt;<br>
+<br>
=C2=A0#ifdef CONFIG_SPARSEMEM<br>
=C2=A0/*<br>
=C2=A0 * generic non-linear memory support:<br>
-- <br>
2.36.0.rc2.479.g8af0fa9b8e-goog<br>
<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DUPWj1H0ScAQsDKM1WobHiFdbJc_u0hMuMVSiGgQTNXZA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DUPWj1H0ScAQsDKM1WobHiFdbJc_u0hMuMVSiGgQT=
NXZA%40mail.gmail.com</a>.<br />

--00000000000079773105dda2b5b6--
