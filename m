Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAHJ26VAMGQEXDMT6ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id CAC557EDEE3
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 11:52:49 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6d656fd896dsf630432a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 02:52:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700131968; cv=pass;
        d=google.com; s=arc-20160816;
        b=nC68ZMTDTSCnWhmB+jKuZwe4lMN14pSq/jsYdGprD0URA5/+b3xVFj0mhE6+Bs/4Vt
         r9DNJXMnpV2E4t8wblKwoYOExo63YJUeDlhoj0kQdz7TcuKaCMdTuQlYJqibFGMk8UVQ
         b7BY2djhjdynbgYZl/Ns9qWSqx/v0SKetuMhKUeGLx9YM/7H9HYc4EnhGXb1oA4MxCgB
         tHk4SedxVVwNXxyEQQEkdjUkGJ99O318eDbFUDlTRKRW7EkOsPqN4CawH8u8KqzqdE2V
         NkblwTjHKpHvSDJoq7NFDe8V5dpBscqVCrdy1HCIpogAhjFDNDzgllPZa5D64Ogmx0GQ
         MDRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7r7G1ezbSGFXdqNpf4GlZXep7VI4IGH5CxZWM9JcYNU=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=syg6ZbKZTeC0X/qrT89kranr9U/I5ta0KKqk+9ve7PZvpDIdt1RY8DN5oImNwpnRrN
         79RVikQUMyN//YumLehzjjmHBdEC4GwsMEOokEFhclA7zBshmo3Ai9u0BU7aCsQtQar7
         nbmX3DM7ue9AiWe720dsL1WZEsKJTKSeCiZ5MGPVKs3QJZy13M0aV9JNa/cxBjI5j4Kb
         a7kiSyjreoeIdONOLXG4p/8S46PvmN/xP9yD0SptWrzRzWX9bbzYdROUsnK3eWHUmSiN
         PL37Z6beYh0TNqKuAYv3p+6SI1aMe8GVprnbZX87MLBZP5Hx4W5bQIna88BNpLpfSqYm
         z7MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GAj6vmjS;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700131968; x=1700736768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7r7G1ezbSGFXdqNpf4GlZXep7VI4IGH5CxZWM9JcYNU=;
        b=BmQkE3fHyS+9DCTvk3AhhOfUEre96JKhg82pOFf2P9PKOKB8MkCyVBNieJVDcT23/H
         PJlzFTFQoZHLGK+Txqur5Svv0qcCf68IthcUgsRCuhN9UNY3kSooMP7XHJtGWH5+cT52
         gES1/YKL/EpejNdANSzpIg5WNgwnWpy6O5/chDckqpUkQGieC44kxDbkMjPrz/UWvshO
         vKNCIJW0DgiIt3Rg6aLNrP6HXeUkOYJjCxHGkzNWIAWi7I4JyedSVt8uF2IRw4HMA0SK
         3k/Sm+Y1/l93IgRJiPHrVUZ3Yo2ohAWjJnfHbwLmRbLAz4H/QZVh0oHiVgbLJWoG9gCE
         OgIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700131968; x=1700736768;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7r7G1ezbSGFXdqNpf4GlZXep7VI4IGH5CxZWM9JcYNU=;
        b=IRvrb2eJ3VldhONEudSTpevfayHxUiIhssPmvZQIlnbkoJUbxNPS1RZJHecRRJ680D
         pTaeIb060QZuXSr9jI79oLHEyQ22ba3JnK9qi/fZkncsPjTPdtR3f9AGcw35pR0AmfED
         70MQdtXbImCzL9RLb0QjDcTxWPK2gxIaf1LI5xgvc/xhKBJTDWbUC80ounyRmb285FIL
         w0u0dJCrcJNnT6TvPOepAL60oApLZTATD/FYLfWPfWfGuIjHZHakBq4rnB5Pg2hq52K5
         p5YWFuKREjrr4PoOr+NpwjZSTCDfqlE815ErLPWJoKhs97tJcuwFIf/9YHZWS0Y5qtrO
         Q7Nw==
X-Gm-Message-State: AOJu0Yy3dadCDEz7nnYdyvuvjqBnaoyHMs9UFrI3i6CjAYOPCYHd0pWK
	pya3zF0Q1Rh6i6BcIrU7i1c=
X-Google-Smtp-Source: AGHT+IEf2NvP0k91LGTNvxxugY2qe1n5bmEJ3VwhRBdcUbiNjqXjVp7nXeVuHW/zVoFjapYs4O/y7g==
X-Received: by 2002:a05:6830:8a:b0:6d3:1f3e:4c4 with SMTP id a10-20020a056830008a00b006d31f3e04c4mr7983183oto.0.1700131968405;
        Thu, 16 Nov 2023 02:52:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5507:0:b0:587:9477:19 with SMTP id e7-20020a4a5507000000b0058794770019ls551213oob.2.-pod-prod-07-us;
 Thu, 16 Nov 2023 02:52:47 -0800 (PST)
X-Received: by 2002:a05:6808:1a08:b0:3af:9851:4d32 with SMTP id bk8-20020a0568081a0800b003af98514d32mr20960618oib.7.1700131967553;
        Thu, 16 Nov 2023 02:52:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700131967; cv=none;
        d=google.com; s=arc-20160816;
        b=KjlwTOr7Bd5ObRTB0cmYq1FOygy24TEufjDKVLuAd+7PomCmzSvUtNbd1zCLRt/WB4
         /aoZEvJI8Deu4AOJ27QGKchZdnEXlags8p0ZogZokwjDgHQIs/+g2z8BCbYXbdhVB2JE
         Abj/iNIOLP/SuP1wWoOkFtpdxaIJz0FfI2+0KQbfND/IY05Ng7Xa5s/KPYxsvPlRY1aY
         8QK+LhmSa8VNW8LclF+puCYtaE3FZHBZBwZvuJmxI5EPF0+RSIeq60p1tNeCZ6hL9lHn
         RHYXlWeVnBy6POtJJwzQN8J/avs7VAwJawG9B+oYTdjm4aUwUNKa6XkfZssrK6F771J5
         s9RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QqJIzLc+e20w+CyJG0SPGKCmTSYxEHr4GKar1orgi4U=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=p2l+e4FZqqvuuOr5p72O4Ub9N1tOuwM3lr2r7IHaZO+EVMNAygMiE3FRH90FPVRYJJ
         TF8nc8p5jp994+rx6L03NjKSvRQzScTzpzGQp/cDqDPRUMHlAbh+vFYljXSKAx9oJGIK
         L7jVmCM9BJr10eWqb+Oplqn/w9Y9l8LTbyabudKaGyB9oujpK8JeopnU/aMBGRb6HAC1
         IinFQ+pFFZE2P4ra5b9a8xECk2CMqBqfLcmBMZEGoJsRzgpRBIgdoIAo8d7k64qaWbWx
         uCkbJ4pd+rWTe5vZBVtVRpTs9gEhN959lWRMdArh/TdwgAev5IWCiCA5Um75SRvSUKR6
         D9pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GAj6vmjS;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id v10-20020a05683018ca00b006ce2f207148si732550ote.0.2023.11.16.02.52.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 02:52:47 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id af79cd13be357-7789a4c01ddso36691485a.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 02:52:47 -0800 (PST)
X-Received: by 2002:ad4:5990:0:b0:675:58de:b59a with SMTP id
 ek16-20020ad45990000000b0067558deb59amr7530365qvb.65.1700131966900; Thu, 16
 Nov 2023 02:52:46 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-8-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-8-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 11:52:10 +0100
Message-ID: <CAG_fn=WcuQxB6ZRKwi221EM-QsEfJ7udyQg9W_z0jv9nFCB89A@mail.gmail.com>
Subject: Re: [PATCH 07/32] kmsan: Remove a useless assignment from kmsan_vmap_pages_range_noflush()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GAj6vmjS;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> The value assigned to prot is immediately overwritten on the next line
> with PAGE_KERNEL. The right hand side of the assignment has no
> side-effects.
>
> Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operati=
ons")
> Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kmsan/shadow.c | 1 -
>  1 file changed, 1 deletion(-)
>
> diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
> index b9d05aff313e..2d57408c78ae 100644
> --- a/mm/kmsan/shadow.c
> +++ b/mm/kmsan/shadow.c
> @@ -243,7 +243,6 @@ int kmsan_vmap_pages_range_noflush(unsigned long star=
t, unsigned long end,
>                 s_pages[i] =3D shadow_page_for(pages[i]);
>                 o_pages[i] =3D origin_page_for(pages[i]);
>         }
> -       prot =3D __pgprot(pgprot_val(prot) | _PAGE_NX);
>         prot =3D PAGE_KERNEL;

This bug dates back to 5.1-rc2, when KMSAN didn't exist upstream.
The commit introducing vmap support already had it:
https://github.com/google/kmsan/commit/3ff9d7c640d378485286e1a99d85984ae690=
1f23
I don't remember what exactly required the more relaxed PAGE_KERNEL
mask though :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWcuQxB6ZRKwi221EM-QsEfJ7udyQg9W_z0jv9nFCB89A%40mail.gmai=
l.com.
