Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCFTVGLQMGQELZLMIMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D1BC588AFF
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 13:18:34 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id y23-20020a5e8717000000b00680064a707esf107082ioj.7
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 04:18:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659525513; cv=pass;
        d=google.com; s=arc-20160816;
        b=FAy6HpzhzB+VRePPAuNKxCVTEGT+UuMcoOWqhz3I5kW9McAtsfAgzw7PBMIJmMQZdL
         b1tRpObyfaPPrQBugkU38BEwgqShWewuEvHPdP37Waaq+KysStnlmIomBmXUVfWb8asK
         70H0603zxUpJQpxA83oItAE3vjIcvrE9wD0stm4Dczc3yoOvbKXKbcm1BrkKsi4afytD
         ZcgTaDLKQuKrkBxllde9xNlTC0rPmoA6s+H8I8VWGfQwXXsquQBcqbCYyXuxM4mJPidj
         ahrXmKftkj74Hco6pr5q+BinB1tQ2a399mspFmVCKMdvDAA2ygS7rszPj3H9qUU+DNGL
         pVNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mnUmZshq2d2wCiY9oT2++uDl7knspW5wwcsWLhN6hh0=;
        b=vq93KKy3N0rvXCqzWixNUdpnK+i3sAJ/AiJXns2eBLDhHylunI/lcw10rf/lgIcPDS
         w0QFR6QHu4JpctgoZDoxSK1Bi6TNuH0aqZYj8Qstx9FGrYjkSrnFMf52ZuS+9bEDZHeB
         7dLlLGx3pydAIriHZFhVTeeA3hCcmzbVUgIJSbAm5X0dxUXeVJZ00wjTgRAu8RrEl4xQ
         336TW2yvRCbwMOLDTgFjRn6TiCBjgo5HWFPmeMRR0u3cmk8YrNz/odpdhcvCw1iUkbQj
         0eobuDjZ+OpY1R+02ZtXvnPzlGmEMdUbpZx/eUldxR4rI1XyQwR5HxlYNM+VXvzRA7A9
         2DnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bMHRKq5s;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mnUmZshq2d2wCiY9oT2++uDl7knspW5wwcsWLhN6hh0=;
        b=C+rE/nFfHkqHDKlzKS/PxD0l5HRVJhAoo0Fu2Up7puccpesdCBnIcYS7INN0pOV3T7
         ZoA/SV1Yvjm7I8f6ZOfuWulbL1ZYmyqZAMERYo1HjYxMvdQamDVKd/8Oarg4bMpCRMDe
         jbEiI+A5t4PxYD5rnprTax5csz9lEtb5LO0/rGaA24g/JkxHk1dKh3UAy3oaMQ+kfy2p
         teZoXbM+gkh/L+iNmI6LsZSN+uiXS7/pSNer8cHS3fzMMc5gkSGGyKjINgdUdgrEOx2A
         Rg55RsmGDRrZohcbYI3WDMF8KQCOW+23HQYOllreatb/1FJUC0E1XvDn01n7Rbka6xxW
         nQ9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mnUmZshq2d2wCiY9oT2++uDl7knspW5wwcsWLhN6hh0=;
        b=3WxQF6GHOZvtG1YXBglqH0a119z5iRSABm5OkQWZxjdoml9/4BcMDj522WdtDCqI8f
         Q6Gxfd5ik1EnkAjPI5X8tk6KCWmcQT4L3nguqK81P6QgmdK6ReoXwEwf5S+X0Hhh/QQR
         f8LzFNhkM1fcMPB9Sw7zsxmIVmX8AhsHpSnseq0QbU6b8j69jInLYqZSnQbkiCiTd2mS
         T0qD9nZYFuVQJqZriksR/4qLSzMaJmk/H8feYEO4e0+ETZVAUTqFSIaX2hvfFGy3pahd
         OX0L75T/wjCvdWzolH9JvZpO84BE/tMQ8JkV+7DO29lNBcL/G6QsNnPwlyqjixswVdlO
         sVIg==
X-Gm-Message-State: ACgBeo0Z9YiEJlqBBTB4VEkzhpWicnkzbXLAD4IZ1LiAvnnDnDeGHlbx
	U8+34dcNIqB1s5E8pe1FVjE=
X-Google-Smtp-Source: AA6agR7DbzNvLVRB41NiTjzZWl7E0PL3aRr8X+Z2IeNQeqCEk9qfJaviXkq4kHjObk44oFrruyCQLg==
X-Received: by 2002:a05:6638:3e85:b0:342:8663:cf6b with SMTP id ch5-20020a0566383e8500b003428663cf6bmr2764775jab.6.1659525512969;
        Wed, 03 Aug 2022 04:18:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:229b:b0:342:770d:a659 with SMTP id
 y27-20020a056638229b00b00342770da659ls1622207jas.10.-pod-prod-gmail; Wed, 03
 Aug 2022 04:18:32 -0700 (PDT)
X-Received: by 2002:a05:6638:1b08:b0:342:6f3a:73fb with SMTP id cb8-20020a0566381b0800b003426f3a73fbmr6834918jab.152.1659525512501;
        Wed, 03 Aug 2022 04:18:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659525512; cv=none;
        d=google.com; s=arc-20160816;
        b=LVUAwhAj7lpfLMEUxfXfjTvMilj36QiFqx50t/hbt74Gfle9j+crD4mBq95TeoTqjU
         r7ns+NbJB7JT1kwzK+eFQmwgLik49LQTYDh7iPLsBvjMdsAITtfyE+5oOMyRCY8d1gkb
         wF/TkAoLmTeZohkE+TPcBoD5o59bXnueznoefX3zDihtqs0WUTrQKIcrqNSbJHzUwEz7
         tK5PZt2LbVCXDi92cqlnwPcAmu/rw4JJk3F2iPQFEPzJnUJGxELl3v63VT33aD4ldrv0
         h4XXuVx5ZVaFGOGGnmHNWtSdT114vxoUGxatwIN5fPmPkJ9dF8+easagkl92jpwZ78ni
         HqgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PSBSqSCCzFolep6UPGhOMMv5cemuy3j+hc8VPw5MalM=;
        b=zTUjR9djbRUuk+CvDDuTXd+MqPJ63ozj/pm2T9gLulxG52SV42ox3vidCTwjX3Kftx
         QRVnCDXimwxuW91o7qwoOAq/UkgVWxLDMojHpKgFthMtHJbqj1g7c1MNQPsdlo2DX0C1
         DHzpSqn/BtQmo1x9ChZYonzP+y3aaVrZlU/rfU3yNtpj11xFoUU2MyMbwU+87Xf0NQyg
         thvaH3ycWwy7qS8w3w+y5v1x+QcTnRXbb+o4npdXYS/xQJauDik2CAbqF6CIiYQRe573
         TDChGmqAiNZrvYYCiol38J8fYtGMXzrjRAmuU/7OtPo2FPeLLGjJw+vJ6JRvFWW2ms4k
         B3Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bMHRKq5s;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id y16-20020a056602165000b00675593cc6acsi904461iow.4.2022.08.03.04.18.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 04:18:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id o15so27719836yba.10
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 04:18:32 -0700 (PDT)
X-Received: by 2002:a25:1687:0:b0:671:8241:610d with SMTP id
 129-20020a251687000000b006718241610dmr19350594ybw.250.1659525511896; Wed, 03
 Aug 2022 04:18:31 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-19-glider@google.com>
 <CANpmjNOPJL7WAUh5CUZOYO8hY-dHTHMUMJzd9OGbmWES+smtrQ@mail.gmail.com>
In-Reply-To: <CANpmjNOPJL7WAUh5CUZOYO8hY-dHTHMUMJzd9OGbmWES+smtrQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 13:17:55 +0200
Message-ID: <CAG_fn=W0bfUZBc-tDMFgeEzgZgezse+mOjQnoO3vBALm9+1Q3w@mail.gmail.com>
Subject: Re: [PATCH v4 18/45] instrumented.h: add KMSAN support
To: Marco Elver <elver@google.com>
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
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bMHRKq5s;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as
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

On Tue, Jul 12, 2022 at 3:52 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 Jul 2022 at 16:24, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > To avoid false positives, KMSAN needs to unpoison the data copied from
> > the userspace. To detect infoleaks - check the memory buffer passed to
> > copy_to_user().
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> With the code simplification below.
>
> [...]
> > --- a/mm/kmsan/hooks.c
> > +++ b/mm/kmsan/hooks.c
> > @@ -212,6 +212,44 @@ void kmsan_iounmap_page_range(unsigned long start,=
 unsigned long end)
> >  }
> >  EXPORT_SYMBOL(kmsan_iounmap_page_range);
> >
> > +void kmsan_copy_to_user(void __user *to, const void *from, size_t to_c=
opy,
> > +                       size_t left)
> > +{
> > +       unsigned long ua_flags;
> > +
> > +       if (!kmsan_enabled || kmsan_in_runtime())
> > +               return;
> > +       /*
> > +        * At this point we've copied the memory already. It's hard to =
check it
> > +        * before copying, as the size of actually copied buffer is unk=
nown.
> > +        */
> > +
> > +       /* copy_to_user() may copy zero bytes. No need to check. */
> > +       if (!to_copy)
> > +               return;
> > +       /* Or maybe copy_to_user() failed to copy anything. */
> > +       if (to_copy <=3D left)
> > +               return;
> > +
> > +       ua_flags =3D user_access_save();
> > +       if ((u64)to < TASK_SIZE) {
> > +               /* This is a user memory access, check it. */
> > +               kmsan_internal_check_memory((void *)from, to_copy - lef=
t, to,
> > +                                           REASON_COPY_TO_USER);
>
> This could just do "} else {" and the stuff below, and would result in
> simpler code with no explicit "return" and no duplicated
> user_access_restore().

Sounds good, will do.


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW0bfUZBc-tDMFgeEzgZgezse%2BmOjQnoO3vBALm9%2B1Q3w%40mail.=
gmail.com.
