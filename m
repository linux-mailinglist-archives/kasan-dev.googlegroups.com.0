Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVVTRSLAMGQEFI5MGKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F67E565C5E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 18:48:24 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id x2-20020a6bda02000000b0067590503c08sf5716229iob.5
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 09:48:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656953303; cv=pass;
        d=google.com; s=arc-20160816;
        b=CfkrQv/8QkVHq3HpoGF7S7LW7BpL1WHSf1i82NyXv4LkJQQNs4hc/iKARZM/vYSuvT
         kz3BYs2wycXS26xXey4CyEodDW78Yp1sr3LN6i2yOJXps0ANaVOiWVRrK4AuCoNyc47e
         yp2acrcsh8sKDCKYZyI5BKvysp/8/6OBEBsnbeEH6xupNjN7JZJPhF5fyK0ZNUwSivSr
         p2mmBzIHyqWvFUfrdhqj/Za6RHn5LAw2gmw5WaPPNpfBfL5RGfhrTSs7Y0VOKX8j7FtQ
         m3aY+kZOGL79sXbIucw2wsAbaUllYCk2W1cdWRhgk9b4lg+cJ3MwjC1voFJ3QuU+4xPM
         vdEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ABzcLAZ93qWkDdgWuyaKK+0h9lcBhTEBKIeJSwvhelU=;
        b=nh0hUfuDUo8ilefAluoYpZxW9mGo4gLoMgOPRpE9egSTI0S04gtaLp+pmUvKHilJZ0
         0/1O3iEQcK+liEiqOU3xVl3SJn7U5dottAhTvY1sm1GinlJHmzO2D/78wWzLlSLRtezm
         D1WIzCyOKWx/XW3D0KfTRoNE1deyP90eKPyGyEPID4CIQvJgvjPP+M8HlnWfxE5zvSxF
         smbD9sRao1IYuC6FsXr+TopXQ28t5ARJNrl+USqEHZvpYTlO1+qt4RfDvqLIZD2NNZJg
         1JF4AxPUdX9LGTczu8M6d4pMooPUIR62Gk6w+bI01vJSAgrGAezdTuAp2a7ISy0Z9rl3
         fUQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="c/CZzhgW";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ABzcLAZ93qWkDdgWuyaKK+0h9lcBhTEBKIeJSwvhelU=;
        b=qiWfOwKBfS2qEecVoJiEzxCOunbnoxbO6+nlrXgRM5NyffodBvf9xYNDJHz3tT4GDO
         0ANBs0sQZie+RpZyNoPhfMZmmArwV7DUg8SAHANuStrx2j7dlxhipGDHkEDi/63NLQn2
         FbNeO38uHlTI+Pu9EdSkQWGPjl/ZeosOSdyCAcmv+8DAjJlRqMUPsPBpeLPiHI6Xoj3m
         En4EZABQwtH2XeQPFUK485j/Bd2zjHtK1nssj4T85uFtxRUFYTKIl5fOjYVHfesIRNll
         POiktoki5w34hIjguNDBwtHQ40Yit+3SsbwYPUNdrHVhWXi7KbvVFPrkzGWVEXcQS+9U
         KKfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ABzcLAZ93qWkDdgWuyaKK+0h9lcBhTEBKIeJSwvhelU=;
        b=vKHZ7IHPgqm/BYehQfSd4uEiYiRjT3k0dpxEdDZrd7AuFCw/ZswwtMuCyN1izuieW6
         OqDTLhKeTsAtAgOhbSz7aC6kowWFsVd47UowK0ZqquOdfB+wSJw29OFr4rrzT4tb/Yca
         TEdd53hr1TRKviZCk7Rl7WWM60pCGtBfM1CkjnAA7p77Kb0pvS3ywwIyB/fIfiE5wkED
         0RxYcXtoRNY5vnEar1mvOWWFlveMBPoV4sSoWZOhSg7IZSzy8Eyr9et1NTWV1oikmyPK
         U86z+/iu3WymsXWrY94NStSMOA7zoH53aFc9ZtTK7IaWVUftDqOY5Y3Rq9XQm2OvjD+5
         hVMQ==
X-Gm-Message-State: AJIora9jKeVXZy+RMzsBkIxhKbx0dOxAoiz+2QEAKAVfLsWk/MPaYtO3
	8mEGi8m0nwzDFaXvMhRV7vQ=
X-Google-Smtp-Source: AGRyM1sg/uoOi2T6JQlmGDw+aKTOgnuGNUoqyYZ3aYkEowiE0DhrCDsO+F8Q3EMfL9DdzzfmdioCAQ==
X-Received: by 2002:a6b:6a07:0:b0:66a:2e5f:2058 with SMTP id x7-20020a6b6a07000000b0066a2e5f2058mr15514050iog.72.1656953303096;
        Mon, 04 Jul 2022 09:48:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:887:b0:2d2:6c8c:45ac with SMTP id
 z7-20020a056e02088700b002d26c8c45acls7293494ils.4.gmail; Mon, 04 Jul 2022
 09:48:21 -0700 (PDT)
X-Received: by 2002:a05:6e02:d4c:b0:2dc:1e09:c813 with SMTP id h12-20020a056e020d4c00b002dc1e09c813mr750130ilj.123.1656953301760;
        Mon, 04 Jul 2022 09:48:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656953301; cv=none;
        d=google.com; s=arc-20160816;
        b=yoeb8KiNozI/1VUEzIj1IZwl4YC92J3b1xbHP0KtVYLdHMHVLqkScG9mLmcyoVVmzg
         lcVVcFO1yfnnJtkINz94MPOH9AQjofSIRpT7Y2K4q8DwnrClewHVlChzNrCK/Jg8BgIX
         OjoIoUrCASDLzMhmDkttWO2GzWMAqVfvKtXrKTXLDw+nEnqQaQaO2+SOr+TVaLd1DAOx
         /lcRNk8Zi4DDM+SGrgTHOwDlNcl2zit77ren5CEABDxboUIBvGqqGCExzc9x5V7kri85
         08yMfD5Rvz72H6Rt1TbZop0AGhSt/WoAvM6AIw4LkTQVcwgmaF5Usp5ie5a61gZgCkc3
         2+4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=L5bopA3LB1XHVOlLQfcH6XEn+sIBVPJTuLNRtswn9CI=;
        b=Pns0zaokh68aIp65n/EjedK9izVCnRdG4k2vxe/VlflrZg+6t+A02osPBI5MrAVIrP
         aMoVAIZxgQDc7jhyVixrTdxfctQ/1JXQqRt/DBsnRwHl7+gQsa1jncbB+MoHF5uW2+lp
         5CvbO4ZrnTxFzWequk6JiuvQmkhaapuRLt+DbJZeNmSyon5djs4X+ioSy5DApHKsQiHo
         TLo+9jlgEpGU7/WwOjXXHKZJrjRuzTmPVCL3BCQeZdDSaEs4R1Vs/rh6RXTYiYJDNkmK
         rfVnsJMEJjhf1SbFmohE4uxOn3eMWt1UIBpNoFQywrZ7ICfen5VW3bp39JreCWe846Bz
         1IQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="c/CZzhgW";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id a6-20020a92d106000000b002d77420723csi959220ilb.3.2022.07.04.09.48.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 09:48:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id l11so17736130ybu.13
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 09:48:21 -0700 (PDT)
X-Received: by 2002:a25:a345:0:b0:66c:c670:6d13 with SMTP id
 d63-20020a25a345000000b0066cc6706d13mr33311155ybi.307.1656953301274; Mon, 04
 Jul 2022 09:48:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV> <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
 <YsLuoFtki01gbmYB@ZenIV> <YsMOkXpp2HaOnVJN@ZenIV>
In-Reply-To: <YsMOkXpp2HaOnVJN@ZenIV>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Jul 2022 18:47:45 +0200
Message-ID: <CAG_fn=Vbq59-zDG=JdOi3DXh29tXNRNQhPJ3PxTZBiY7Ph=Jug@mail.gmail.com>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
To: Al Viro <viro@zeniv.linux.org.uk>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Evgenii Stepanov <eugenis@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Segher Boessenkool <segher@kernel.crashing.org>, Vitaly Buka <vitalybuka@google.com>, 
	linux-toolchains <linux-toolchains@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="c/CZzhgW";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as
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

On Mon, Jul 4, 2022 at 6:00 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> On Mon, Jul 04, 2022 at 02:44:00PM +0100, Al Viro wrote:
> > On Mon, Jul 04, 2022 at 10:20:53AM +0200, Alexander Potapenko wrote:
> >
> > > What makes you think they are false positives? Is the scenario I
> > > described above:
> > >
> > > """
> > > In particular, if the call to lookup_fast() in walk_component()
> > > returns NULL, and lookup_slow() returns a valid dentry, then the
> > > `seq` and `inode` will remain uninitialized until the call to
> > > step_into()
> > > """
> > >
> > > impossible?
> >
> > Suppose step_into() has been called in non-RCU mode.  The first
> > thing it does is
> >       int err =3D handle_mounts(nd, dentry, &path, &seq);
> >       if (err < 0)
> >               return ERR_PTR(err);
> >
> > And handle_mounts() in non-RCU mode is
> >       path->mnt =3D nd->path.mnt;
> >       path->dentry =3D dentry;
> >       if (nd->flags & LOOKUP_RCU) {
> >               [unreachable code]
> >       }
> >       [code not touching seqp]
> >       if (unlikely(ret)) {
> >               [code not touching seqp]
> >       } else {
> >               *seqp =3D 0; /* out of RCU mode, so the value doesn't mat=
ter */
> >       }
> >       return ret;
> >
> > In other words, the value seq argument of step_into() used to have ends=
 up
> > being never fetched and, in case step_into() gets past that if (err < 0=
)
> > that value is replaced with zero before any further accesses.
> >
> > So it's a false positive; yes, strictly speaking compiler is allowd
> > to do anything whatsoever if it manages to prove that the value is
> > uninitialized.  Realistically, though, especially since unsigned int
> > is not allowed any trapping representations...
>
> FWIW, update (and yet untested) branch is in #work.namei.  Compared to th=
e
> previous, we store sampled ->d_seq of the next dentry in nd->next_seq,
> rather than bothering with local variables.  AFAICS, it ends up with
> better code that way.  And both ->seq and ->next_seq are zeroed at the
> moments when we switch to non-RCU mode (as well as non-RCU path_init()).
>
> IMO it looks saner that way.  NOTE: it still needs to be tested and proba=
bly
> reordered and massaged; it's not for merge at the moment.  Current cumula=
tive
> diff follows:

I confirm all KMSAN reports are gone as a result of applying this patch.


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
kasan-dev/CAG_fn%3DVbq59-zDG%3DJdOi3DXh29tXNRNQhPJ3PxTZBiY7Ph%3DJug%40mail.=
gmail.com.
