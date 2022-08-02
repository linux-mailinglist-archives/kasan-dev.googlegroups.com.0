Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7NGUWLQMGQEI5P74QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 78D12588069
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 18:40:31 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id i16-20020a17090adc1000b001f4e121847esf3257117pjv.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 09:40:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659458429; cv=pass;
        d=google.com; s=arc-20160816;
        b=YPC2ZqWVPGiCxqDvuAwci8HnoDitoBBNwnZR+AGU8Xjld6MFJvApG8GSBrCX+ww4gE
         Gn4tFjIffoOw+ZRReaQsXYxRuhrXpwSfgnWX8Raku3UyBNptlGQ08Ota3xVFYwfXOhXy
         Lkcq61f04M6+iR8ME9q05nmOy2dXR0TW+bN3C3iYaN7FtANmiFseRgv91694JS1jfVaN
         m0GnCjfYtDtNprAmaE8R0obZhCDCdrkbF5J3qj1hbA/DFAiRF+FhTu6lggtrh62FS8cA
         SNxgRno6LBEgLk8SDZ1KGoiYD1avmwBoqtefIkAe9PwFsD1xHkbLTMAfM9SuBIZmmPZR
         VQ1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=POcGZcRPXJya1ppkVk6wYBiujpszwhrCexTqGoMwxBw=;
        b=Rr91HGBuhjmfYnyUEBYhBQdFH5BIpc0fmrauOv3kEiBAkFTpZyLOE+Ali1gslMiCxb
         g/mwb+wAXFx20z72/XDWFZk0tfZ/gBvQ/bO9FFANhacd491wseRHzCrci2SLmrWeXqWm
         uOwfF46LkyRrnv2tlr19ZCgmexxdeKJQYNSdyCuJfRpUXhwKQKUy+hlEyy7pQbASAusK
         H0fGF7AVDwjxcdEgKWWE4f231admYjElZOd8b5amLBdm3vlDTAHr9A0ksFjJI/LsxFpk
         KLL1YqIH34CFxz0JLd4MQyBPQJ/qAszhzk5UH0RSrWEH+J+w6Ksi4M9ilNbpysG+NnvX
         qOYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fQz6bCpB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=POcGZcRPXJya1ppkVk6wYBiujpszwhrCexTqGoMwxBw=;
        b=gkz6nZOk/20g4Q4dvpSOe5mKeg/87M3go/gAW7gXe6eiSzF6JAI8undvXupUAdppHV
         q+1apeWAcaRx3n0/HBUIh6epw9sSWRahdZ6nCxjcNdSsMZyDGEEUIiPvwt+42A0nVSvH
         rzhTQapw0/pxKlEbNxhqm5hN5iI0PwkQNtITnbY98Nhlo29Di0O+kogHfz9wqoQISUjy
         PEGF0ZwQAJPz50InN/EodnIKVF1JCxxFcPd+30F5B8TMD+x2zD1SZuf3urQ47SUFw/ra
         JulPQ7/PWNn3v3vLRcV2qjqKm9Pb1KhdPsLf+SHt+oqeo9qUz65IIulfM8MbMCWd7xEd
         OcVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=POcGZcRPXJya1ppkVk6wYBiujpszwhrCexTqGoMwxBw=;
        b=TBbq6usJasA8y8mGF1vuKK4wjmFghiaShWT6YyZPJGpsuxoWDdAHCZuuc+8vg1bh1Y
         nk2cgQVfmCACvsAt7CPNyX3VLgguYL2Fz9NWkjljyibzQIDXEtOOJqv9vNHrxHWrmbkB
         GV6qlZUxplB1i42DCiuvDOi+lk/3U0rEl9JtC0uWete8xqG3B2qpaQMEQ6IXB6dLoTfH
         A4QfqUAuEkxng/c1cH/SqH/+dGXwa+b+nALAA7DljbKo2VUXRAQ+wsoPN8sGTapxsgT9
         vCfuaXILjBacoULX3mlxv/+vTvu5PhG2sQwq8c+XRK8e8Pv+zG9wxc2aoPtVQou8dQ4G
         8UKw==
X-Gm-Message-State: ACgBeo3l4/OVmON5tJERa/cc+5xeE2lYyHZkaw8WBtuRfEJjeCN/Hln4
	2qGzbviZqVdbcQfzdi8yxwg=
X-Google-Smtp-Source: AA6agR6oaeEtEtJvE3qDaVc8F/yPw0QQ/eiZw5v8joX9K1yFgL+SpcpOIZ5OTFK/M4VpRSSNmv0eLQ==
X-Received: by 2002:a17:903:22d0:b0:16f:2ef:77e5 with SMTP id y16-20020a17090322d000b0016f02ef77e5mr4952958plg.28.1659458429658;
        Tue, 02 Aug 2022 09:40:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6c48:0:b0:41b:c350:732f with SMTP id h69-20020a636c48000000b0041bc350732fls4166810pgc.4.-pod-prod-gmail;
 Tue, 02 Aug 2022 09:40:29 -0700 (PDT)
X-Received: by 2002:a63:6942:0:b0:41c:9261:54fd with SMTP id e63-20020a636942000000b0041c926154fdmr217726pgc.34.1659458428916;
        Tue, 02 Aug 2022 09:40:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659458428; cv=none;
        d=google.com; s=arc-20160816;
        b=cmR/ZwU/oxRRgMdSpJ+HFB5zuXbF+hJXDwJSgBbt3I/X5eFc6IfcXN+IKNDs6tKbKB
         pruhiy/xZg7y3saRDfw9KKbx3bq4PfPOud44LJF/TTT9pSRMyIkFvRliyvDFQLHy8v3K
         W8EuCeHs4JBsmMlgowJIx97sB/LaNzzyPrjXXKGUB1Ojfiuqdpa1SKODKqdY8/03hHvD
         aJooE+QXnpseq7TxB8e13bQSxCvBt/2FRrd4HjRBu1TXGsSxqji0VhyJhyvQlwv3x13F
         g+kx/EJWjrwioozjZdDsdyCiDXY/p9uMvxedi4QRJERJOQbKjNenrAA1BNDIvgh8UEui
         PG6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TKCfFaRwxtnk/rQVtVgmwJGR+kFqLe+E3ZNMs5uStiU=;
        b=XRefLhhdy6o5bM2ApTLzpy0BcJ05kQrprfB/MH+LBTfyhes/b0h1y+SQZR4LxTIh3j
         TYUhYXDbzTyqzwmMgDAv+auGQw/udKGHqc887Jrs2ilUMiA6eFV20fzBz1LejXaz2dle
         swIvS2lC8Qv4zpF7A3L7UWUOM6wyblGTxeS25KDVrv1BNs3XBL6r5KhyYQ0jUrf+z8vm
         fIKCCo1ONQScRxJE0yn51rLRYbMgUxBD8+BnFgOnKUc2KOQSdGYdOvHvNewRvdJLcEK6
         eTLiomz8EGgFEeigzCPjz0neAUEsPLqa066IEZLcN5HQbZsCZdwjWLx2IaORbCU5UOsx
         qL/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fQz6bCpB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id nv1-20020a17090b1b4100b001efde4c6699si478569pjb.3.2022.08.02.09.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 09:40:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id o15so24322337yba.10
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 09:40:28 -0700 (PDT)
X-Received: by 2002:a25:bc3:0:b0:673:bc78:c095 with SMTP id
 186-20020a250bc3000000b00673bc78c095mr15523307ybl.376.1659458427960; Tue, 02
 Aug 2022 09:40:27 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-14-glider@google.com>
 <CANpmjNN1KVteEi4HPTqa_V78iQ1e2iNZ=rguLSE6aqyca7w_zA@mail.gmail.com>
In-Reply-To: <CANpmjNN1KVteEi4HPTqa_V78iQ1e2iNZ=rguLSE6aqyca7w_zA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 18:39:51 +0200
Message-ID: <CAG_fn=WDr1HnQG+Np9Q4waurnJgiS=3Z-ww2M1oW0To=1LivZg@mail.gmail.com>
Subject: Re: [PATCH v4 13/45] MAINTAINERS: add entry for KMSAN
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
 header.i=@google.com header.s=20210112 header.b=fQz6bCpB;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as
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

> >
> > +KMSAN
> > +M:     Alexander Potapenko <glider@google.com>
> > +R:     Marco Elver <elver@google.com>
> > +R:     Dmitry Vyukov <dvyukov@google.com>
> > +L:     kasan-dev@googlegroups.com
> > +S:     Maintained
> > +F:     Documentation/dev-tools/kmsan.rst
> > +F:     include/linux/kmsan*.h
> > +F:     lib/Kconfig.kmsan
> > +F:     mm/kmsan/
> > +F:     scripts/Makefile.kmsan
> > +
>
> It's missing:
>
>   arch/*/include/asm/kmsan.h

Done

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
kasan-dev/CAG_fn%3DWDr1HnQG%2BNp9Q4waurnJgiS%3D3Z-ww2M1oW0To%3D1LivZg%40mai=
l.gmail.com.
