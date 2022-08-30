Return-Path: <kasan-dev+bncBCT4XGV33UIBBHNNXKMAMGQEIJIO22A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id C386C5A7146
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 01:00:46 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id j192-20020a638bc9000000b0042b23090b15sf6069843pge.16
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 16:00:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661900445; cv=pass;
        d=google.com; s=arc-20160816;
        b=p7FmBJvXBy6XcWpPc3TxbU21hT+r2f8B7h0UlCW8OGfYftOO6MPAj93O3ecLj6K+MW
         JD2s0fCqKQrwapXIr5KQze677mfPkq7CXAno5VbdLjjf0gq+lh3x4B9Z4YWi/9klagMA
         GDG9jg8QvOZ+6BCIxnc7DOdUum4UmhPbuiUJTYhfUMHjKI1EFYmHmNaYapi4FwZMJjmL
         anbQLM5m9n7Y9SKb8x9SleZZeGynW/bS13CJgp9sEtnyoMCEPTYH8iMXFfb2BhFPQsLD
         IJ+XmdL1pm3MXc3gZmSPz3NIft2OLJe7hmT3uLNz9RK0X2Kbh4oWwR9NRPIrhQb87XkM
         QIfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=Q0kTxgnXaEqozHrgRnxI0igzOTpTljRt59/zEJ7a9lQ=;
        b=fNkX4mtaXN2hVH2SV4v9yio2oydbzkStHVd/HC+FVqA1H6gB4PbVmvnCsFhawxeoTd
         u/xHm+Tn2zc0nicHrylUU94RSk5jtMdulZUV7sGt6PLZ3uicT2hMKJcBvVTX8cThMaci
         u37UofFxVF4yCmeGFA9Y7u2i1Smb/+yzhWGd7MC9xjN/JkL2DYWXDqKgvGheWUSdQD/7
         CLMuboRr4Ztw8fcmXPjr/mPv3nCWVKSzJ3g8o+5FktWdh5MJWhqt0IkrGZdvebCT0LPE
         HZ2B02ABbyMnBH0ZQjHoCU9AUFtElyznzcTyeeJPN0VKq0XphOszDY5FMi2bnBFc0kH3
         aAhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ohIDGa98;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=Q0kTxgnXaEqozHrgRnxI0igzOTpTljRt59/zEJ7a9lQ=;
        b=N9MYeKS9jtPQYR1twOJ33hS3+jHPScJWWiqZyl6pV8elkNf2WZ1DCpE5qbi5ffRax6
         PxFqQwWAlf60ED6Rgt01c0JtaDKGc5VvESRnMxhvkjPl/Bj9zXOZlqSAS2YTcS7edDgN
         Z7G0RZfLsaAJlhgd2RXaJfDus2/dCwsT0TsgBjwBoJ0J5ZY/c0h7ckl7iatYxBpSGsqf
         yXR+LGvX3mmgcDgTobJmZGrzw6mVMfOfzfBOAjGcSwa8cA+o9CV03KZYuBMgtouV6kcS
         fZQtuLFnMtSRFUKcXX5DrvXKfQxWMI61PRtu0hp8lKw9q88ftkgDDEjs0KE9z9PpP0fc
         17fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc;
        bh=Q0kTxgnXaEqozHrgRnxI0igzOTpTljRt59/zEJ7a9lQ=;
        b=gVcpx7wRGXO7rzfBW94Ez1b1PVXFu8yn9LrkxLLv24N2P3xEAQLrawXYqQ6EuOxrUC
         MP214MQtmk2oKE/d3agOYMhzt6fIUDpyc+16DxbZctRHnt03MoQBrDIVTymttr2olMc1
         fkEjPCaM8RrHFiehEEK2qTXTpqG74OI5PXLJkh8nsymS2dtKZlm4mvVePSQnPXTyoPoa
         Y1nh3krU81iprCBFqqL03K08ELjEql9v5BUunhArLSgutTdSbBcYUkCxYjhsCLcVnn57
         1cPO3fgvTs74aHfSDeuIsOWD4rAfN1J8jJf/QKEHACnkYzNg0Y8S9ykaVY4Y6tq+2haR
         0C5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0WAVJnIsDwiUz9+Z7tKed9jThheKKyw7fU8RfcK0AH3UC6ZKFE
	HufVgkFXwTIE28wlf1Y/jgU=
X-Google-Smtp-Source: AA6agR7F2ua+yFAeQVTETtV5Gq9anLhVDc0088btRqdNuLNUKaDTZFtZNzHDG4OT+SizN5lLyBTqSw==
X-Received: by 2002:a17:903:260a:b0:174:9115:ae6e with SMTP id jd10-20020a170903260a00b001749115ae6emr15092231plb.55.1661900445331;
        Tue, 30 Aug 2022 16:00:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f8c2:b0:1f5:81e:89e1 with SMTP id
 l2-20020a17090af8c200b001f5081e89e1ls8808758pjd.1.-pod-prod-gmail; Tue, 30
 Aug 2022 16:00:40 -0700 (PDT)
X-Received: by 2002:a17:902:ab8e:b0:174:11d5:b2ec with SMTP id f14-20020a170902ab8e00b0017411d5b2ecmr22515282plr.18.1661900440068;
        Tue, 30 Aug 2022 16:00:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661900440; cv=none;
        d=google.com; s=arc-20160816;
        b=y99j2ZhDKF2vhmaxWIW3yDd2ap1ebxNihtt1Swkb9s2TdF/FhePOIFqMS1S0hx7l2q
         Nc1YoNXwUemFGlur02j127Y3tkmUxy1YDxz0eeZEUm522OpHCrKZA/7uQq9vhFY1DOE0
         9z8Hsijvvp/qdHv9b+s3VqH5I4Ovc8xKHnQJYeMLm2NH9AiFoOOcabzhMr3HQq+csCNk
         vPCygnZCISrAMgjsfD5PZx8axeY63ESJ9K5KPgvpOazVrNqIfFDxo+pN9O+69A8n718g
         kNkx3t0ftC/32AdZwrfMbQdE5O/nKj3Pzswsc3YTXKccT5DXn+LhX03Jjs4L6zfx4woV
         XNmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DZXjBpZXzsmssgwbCH2s5bKWphDcrZYCyPKndIhQ/I0=;
        b=nadCqgvpu5puNruFDtCmmqvxrpu4GY6x5tqdme5EXzgDtL1f3lXH2PCo65cJBlfwvo
         NP2+icSX85FCWNBiW9p2NmsyfAffyc9c6C544cxQQGk9pb7HkaKAPIaD5pxrLDU/aS7g
         ePohkkYYpeAtxr2mcVlB9vbUKnFlcY3zIw6yRC+cRtqb76V0VlH8VJ47+NQhZfeyNdQz
         IEmg8FeGBmdTav//pNFgD4TM22ZBv+H/spiN6mtoslqNF6FUDJA5Mro4flIwvYmaiGAd
         iXhb45rUWeO9Pwz+sB1cmdlwYT3fZAYJD58g5yl4wlF9tNmNnM60gK4vsXWVrMccl8DN
         XoRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ohIDGa98;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c1-20020a170903234100b00175099477b9si161266plh.2.2022.08.30.16.00.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Aug 2022 16:00:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 79A83615F7;
	Tue, 30 Aug 2022 23:00:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 70B2AC433D7;
	Tue, 30 Aug 2022 23:00:36 +0000 (UTC)
Date: Tue, 30 Aug 2022 16:00:35 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Yu Zhao <yuzhao@google.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
 <ast@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski
 <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov
 <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Mark Rutland
 <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>,
 "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>,
 Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>,
 Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum
 <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev
 <kasan-dev@googlegroups.com>, Linux Memory Management List
 <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, LKML
 <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user()
 and put_user()
Message-Id: <20220830160035.8baf16a7f40cf09963e8bc55@linux-foundation.org>
In-Reply-To: <CAOUHufZrb_gkxaWfCLuFodRtCwGGdYjo2wvFW7kTiTkRbg4XNQ@mail.gmail.com>
References: <20220826150807.723137-1-glider@google.com>
	<20220826150807.723137-5-glider@google.com>
	<20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
	<CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
	<20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
	<CAG_fn=X6eZ6Cdrv5pivcROHi3D8uymdgh+EbnFasBap2a=0LQQ@mail.gmail.com>
	<20220830150549.afa67340c2f5eb33ff9615f4@linux-foundation.org>
	<CAOUHufZrb_gkxaWfCLuFodRtCwGGdYjo2wvFW7kTiTkRbg4XNQ@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=ohIDGa98;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 30 Aug 2022 16:25:24 -0600 Yu Zhao <yuzhao@google.com> wrote:

> On Tue, Aug 30, 2022 at 4:05 PM Andrew Morton <akpm@linux-foundation.org>=
 wrote:
> >
> > On Tue, 30 Aug 2022 16:23:44 +0200 Alexander Potapenko <glider@google.c=
om> wrote:
> >
> > > >                  from init/do_mounts.c:2:
> > > > ./include/linux/page-flags.h: In function =E2=80=98page_fixed_fake_=
head=E2=80=99:
> > > > ./include/linux/page-flags.h:226:36: error: invalid use of undefine=
d type =E2=80=98const struct page=E2=80=99
> > > >   226 |             test_bit(PG_head, &page->flags)) {
> > > >       |                                    ^~
> > > > ./include/linux/bitops.h:50:44: note: in definition of macro =E2=80=
=98bitop=E2=80=99
> > > >    50 |           __builtin_constant_p((uintptr_t)(addr) !=3D (uint=
ptr_t)NULL) && \
> > > >       |                                            ^~~~
> > > > ./include/linux/page-flags.h:226:13: note: in expansion of macro =
=E2=80=98test_bit=E2=80=99
> > > >   226 |             test_bit(PG_head, &page->flags)) {
> > > >       |             ^~~~~~~~
> > > > ...
> > >
> > > Gotcha, this is a circular dependency: mm_types.h -> sched.h ->
> > > kmsan.h -> gfp.h -> mmzone.h -> page-flags.h -> mm_types.h, where the
> > > inclusion of sched.h into mm_types.h was only introduced in "mm:
> > > multi-gen LRU: support page table walks" - that's why the problem was
> > > missing in other trees.
> >
> > Ah, thanks for digging that out.
> >
> > Yu, that inclusion is regrettable.
>=20
> Sorry for the trouble -- it's also superfluous because we don't call
> lru_gen_use_mm() when switching to the kernel.
>=20
> I've queued the following for now.

Well, the rest of us want it too.

> --- a/include/linux/mm_types.h
> +++ b/include/linux/mm_types.h
> @@ -3,7 +3,6 @@
>  #define _LINUX_MM_TYPES_H
>=20
>  #include <linux/mm_types_task.h>
> -#include <linux/sched.h>
>=20
>  #include <linux/auxvec.h>
>  #include <linux/kref.h>
> @@ -742,8 +741,7 @@ static inline void lru_gen_init_mm(struct mm_struct *=
mm)
>=20
>  static inline void lru_gen_use_mm(struct mm_struct *mm)
>  {
> -       if (!(current->flags & PF_KTHREAD))
> -               WRITE_ONCE(mm->lru_gen.bitmap, -1);
> +       WRITE_ONCE(mm->lru_gen.bitmap, -1);
>  }

Doesn't apply.  I did:

--- a/include/linux/mm_types.h~mm-multi-gen-lru-support-page-table-walks-fi=
x
+++ a/include/linux/mm_types.h
@@ -3,7 +3,6 @@
 #define _LINUX_MM_TYPES_H
=20
 #include <linux/mm_types_task.h>
-#include <linux/sched.h>
=20
 #include <linux/auxvec.h>
 #include <linux/kref.h>
@@ -742,11 +741,7 @@ static inline void lru_gen_init_mm(struc
=20
 static inline void lru_gen_use_mm(struct mm_struct *mm)
 {
-	/* unlikely but not a bug when racing with lru_gen_migrate_mm() */
-	VM_WARN_ON_ONCE(list_empty(&mm->lru_gen.list));
-
-	if (!(current->flags & PF_KTHREAD))
-		WRITE_ONCE(mm->lru_gen.bitmap, -1);
+	WRITE_ONCE(mm->lru_gen.bitmap, -1);
 }
=20
 #else /* !CONFIG_LRU_GEN */
_

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220830160035.8baf16a7f40cf09963e8bc55%40linux-foundation.org.
