Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCWGRKLAMGQENDBQD2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 46439564F9E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 10:21:35 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id v19-20020a17090abb9300b001ef7bbd5a28sf2846139pjr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 01:21:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656922892; cv=pass;
        d=google.com; s=arc-20160816;
        b=JN7Y9pSeHKXx/9lMkfKUG3TNSrwm4R2Ec028wH3sYlaRHBma9NqbnEtU2O0HgHJM2N
         HsMQbmJxCSXEB7+aMe3Q6hK1MMGdqCzH9lgI3rQrHzceRyVAyyEJVWUyZbl2WKIk26Dx
         IrZLpYWvFva27JI5kXJLbJSQY1kYn18fYF+ie92cS6DFYeKB+k0jv7acrovJNt1iobXV
         A8rANtNNHNP5Mm83AwsublndmguXX80ZBC4Dj9yQtmvK74Ajm0+6tS/ItX0zBUZjW2zW
         jQs8MMxtP1B5nSTMw9X3cAVxQRJ6I1QGXeDZWj4VGP4DNsupdct0CCTXgIkas2KaUIAL
         WZ1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sxTrI7QpjgZp+oWGBQEoqKxja+vZOhRgzKc8I5vWwDY=;
        b=0RI33XFSp7ho3MYVefyJjI4keO2B5WJS2eVTWGefYypCottHJfj2C4YzpGFnXM4pxi
         ExK65XTnTHuXH6Scomzb/xxIunIEVFOENbXJieJa+BgUaDTfdZXSiEyC9z7SNsWIyrM0
         ISHytAaBe8jIW80YjfTTVs7nVfxjYfd1X5WKRb8sNxfcniDbdnnG+OWeR61/Xjxtvkrv
         OpXRPOtppwrSomn3+vvpxcdVyTsM9+wBPAbJi68ZjLXoigk5vQkg/Azvba4o0DycJQU+
         f8JTnnEpAo/EsEDihuhdY8iIJ5cbM3lxFZD8SrQyRmcVQw40i2OBVQbtiAUAV4GPULVK
         mmng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UXFZDwr6;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sxTrI7QpjgZp+oWGBQEoqKxja+vZOhRgzKc8I5vWwDY=;
        b=ATSLyt3iyaW8rIa3Jy6Z6Yr0w6EOU5NOTQ+WVOYXurK2TbdZIQx5GAskknXClRIeYg
         TU15ulwas8pVOo1gz47wrYR2gyiGGxPzWvOtzVRl+jrSn2S4yL0fmAdciObx8ZyKN/z8
         pTNinouiQqw55DYHNQBaluYXAJ88WRG/hFLnC/dAVZo/Pa4aG/acbJwq6yYsOliuzkRR
         LXwsABlbY+5Ey68pwHyUHZ4gztIlsWmwvf4x5ZQ2uDukBr70Frx46gPyxKkWZ4LvHIGa
         RToEi/FuCwhDEKz0NB8tZK9I1e2TShF5NKIJHR2li2AqqGHRlfPzOolh/tiYcC9lOvsQ
         FrkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sxTrI7QpjgZp+oWGBQEoqKxja+vZOhRgzKc8I5vWwDY=;
        b=sKxEcUPuWBLsdna4rtQ9Qrn4m5KhU5WnXXbyfq/csGxBwuuGXbPz7a/q5mKhydpQqX
         NXsOCYuO7QI7j+lYK3CHpsTnY2jKVpzv8Zj/ekDek7FgHBo1K7gKVERwkmBuPGuFh+ao
         s4cFRo7+42rrMDAdT2SG51zR1dgJM7r5sPbqu1l4mbNlC3Nx+vx9505dAfCm6KFKJtd1
         B7QToU1nnAEhcy7ROF9qa+KS5j2dVUBFd8vGOGWiGNatvPl91oZW849ip0iKwVtNul3u
         OSnMkCgt0h0tBbXYdESllDIvY53Y4xX0LXG2OROQIUkLUmPwGZ2AjDglER2gRDK1yYUU
         f9VQ==
X-Gm-Message-State: AJIora8B/towgGR6cOmtC/dqla8QH2BSws37+imqBY+Gbn/Sm25/68ji
	WtRg/Zv3PoFIuo+4XtdWYtw=
X-Google-Smtp-Source: AGRyM1vZa2Kf6F1F79/3ld+Wm+///LSkCHwLPLLiD+zVIg472AhOkIBCPsmVODwYbi/12ZLSnQWsOg==
X-Received: by 2002:a17:902:d395:b0:16b:e5e9:ac59 with SMTP id e21-20020a170902d39500b0016be5e9ac59mr2666147pld.74.1656922890717;
        Mon, 04 Jul 2022 01:21:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:884:b0:525:23f4:c380 with SMTP id
 q4-20020a056a00088400b0052523f4c380ls17479464pfj.5.gmail; Mon, 04 Jul 2022
 01:21:30 -0700 (PDT)
X-Received: by 2002:aa7:9823:0:b0:525:15b1:3297 with SMTP id q3-20020aa79823000000b0052515b13297mr34542518pfl.13.1656922890062;
        Mon, 04 Jul 2022 01:21:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656922890; cv=none;
        d=google.com; s=arc-20160816;
        b=IArsNcyoAuZlPb/5Bb2sfYHbCc4HtfJobmPMcCj7rnA0S3jWJpeYQTyv5ZAYawoUI6
         qpyeX751uknt0JNcgzE0iMgYm0V5xudOHb8hX1/oov4/cNH2o7cpsESuCaHXjMPHtry1
         kzo9+65K4FfPKm5pIEtDvRfPzHCX1vrtylmwOKeNuo+nskGkQEqDQMYTn+nbwGaJuWCs
         3JLp+dmTb0NMvL2rTCscJU1uKXEbUPGdF0yK39HUJ3Q3mUkgq1ppIzR8SPOdBsIsM+Sv
         8R5M51Uyq0Zlp2dfSxk7/RPhAcBPOTSKRAAxOisr6tW4OBiNmA5OONud+/AysjGVA+Fg
         EtFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oAjJ2G+6gAo3NoQXMKWlZ5LJd5LqVOnZ6pcF/XS/a/o=;
        b=tVaFe4TpgNEzQ5zjwSYeUlWhpehSx7y8PuEVIGQAmD3BhMzFX26zdVem/UiYSAVzWv
         KsPCiWgtw7xzd4wMKumdrsX2r9/2/ZnLwaMiZLUw3aqnbHCB2LdrIziy5dI1JGldcWm1
         KFqyICnafT66PVgdTOzBc/9GLDpjgA1Oc5ZzT5L4oVof1yDdXprvXdeFa/SFswegixQY
         UP5ZcsqbMW1l+E4tmoQCTQEoCjM/usOJdOs+Ynyh1oTxcIUdxGjiaiuoEG2TuVqfcyuh
         beM59rH/9FnZEVjpk/NBl05XJiSWeWbgfKU0klEi4G2BX9KirH4/XW0SVcHOcwUdDsHs
         8JVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UXFZDwr6;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id z7-20020a63b047000000b0041205226217si184940pgo.2.2022.07.04.01.21.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 01:21:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id r3so15578504ybr.6
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 01:21:30 -0700 (PDT)
X-Received: by 2002:a25:6b0b:0:b0:66e:445a:17bb with SMTP id
 g11-20020a256b0b000000b0066e445a17bbmr5396058ybc.147.1656922889083; Mon, 04
 Jul 2022 01:21:29 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com> <YsJWCREA5xMfmmqx@ZenIV>
In-Reply-To: <YsJWCREA5xMfmmqx@ZenIV>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Jul 2022 10:20:53 +0200
Message-ID: <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=UXFZDwr6;       spf=pass
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

On Mon, Jul 4, 2022 at 4:53 AM Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> On Sat, Jul 02, 2022 at 10:23:16AM -0700, Linus Torvalds wrote:
>
> > Al - can you please take a quick look?
>
> FWIW, trying to write a coherent documentation had its usual effect...
> The thing is, we don't really need to fetch the inode that early.
> All we really care about is that in RCU mode ->d_seq gets sampled
> before we fetch ->d_inode *and* we don't treat "it looks negative"
> as hard -ENOENT in case of ->d_seq mismatch.
>
> Which can be bloody well left to step_into().  So we don't need
> to pass it inode argument at all - just dentry and seq.  Makes
> a bunch of functions simpler as well...
>
> It does *not* deal with the "uninitialized" seq argument in
> !RCU case; I'll handle that in the followup, but that's a separate
> story, IMO (and very clearly a false positive).

I can confirm that your patch fixes KMSAN reports on inode, yet the
following reports still persist:

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
BUG: KMSAN: uninit-value in walk_component+0x5e7/0x6c0 fs/namei.c:1996
 walk_component+0x5e7/0x6c0 fs/namei.c:1996
 lookup_last fs/namei.c:2445
 path_lookupat+0x27d/0x6f0 fs/namei.c:2468
 filename_lookup+0x24c/0x800 fs/namei.c:2497
 kern_path+0x79/0x3a0 fs/namei.c:2587
 init_stat+0x72/0x13f fs/init.c:132
 clean_path+0x74/0x24c init/initramfs.c:339
 do_name+0x12d/0xc17 init/initramfs.c:371
 write_buffer init/initramfs.c:457
 unpack_to_rootfs+0x49a/0xd9e init/initramfs.c:510
 do_populate_rootfs+0x57/0x40f init/initramfs.c:699
 async_run_entry_fn+0x8f/0x400 kernel/async.c:127
 process_one_work+0xb27/0x13e0 kernel/workqueue.c:2289
 worker_thread+0x1076/0x1d60 kernel/workqueue.c:2436
 kthread+0x31b/0x430 kernel/kthread.c:376
 ret_from_fork+0x1f/0x30 ??:?

Local variable seq created at:
 walk_component+0x46/0x6c0 fs/namei.c:1981
 lookup_last fs/namei.c:2445
 path_lookupat+0x27d/0x6f0 fs/namei.c:2468

CPU: 0 PID: 10 Comm: kworker/u9:0 Tainted: G    B
5.19.0-rc4-00059-gcf2d25715943-dirty #103
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/=
2014
Workqueue: events_unbound async_run_entry_fn
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D

What makes you think they are false positives? Is the scenario I
described above:

"""
In particular, if the call to lookup_fast() in walk_component()
returns NULL, and lookup_slow() returns a valid dentry, then the
`seq` and `inode` will remain uninitialized until the call to
step_into()
"""

impossible?

> Cumulative diff follows; splitup is in #work.namei.  Comments?
>
> diff --git a/fs/namei.c b/fs/namei.c
> index 1f28d3f463c3..7f4f61ade9e3 100644
> --- a/fs/namei.c
> +++ b/fs/namei.c
> @@ -1467,7 +1467,7 @@ EXPORT_SYMBOL(follow_down);
>   * we meet a managed dentry that would need blocking.
>   */
>  static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
> -                              struct inode **inode, unsigned *seqp)
> +                              unsigned *seqp)
>  {
>         struct dentry *dentry =3D path->dentry;
>         unsigned int flags =3D dentry->d_flags;
> @@ -1497,13 +1497,6 @@ static bool __follow_mount_rcu(struct nameidata *n=
d, struct path *path,
>                                 dentry =3D path->dentry =3D mounted->mnt.=
mnt_root;
>                                 nd->state |=3D ND_JUMPED;
>                                 *seqp =3D read_seqcount_begin(&dentry->d_=
seq);
> -                               *inode =3D dentry->d_inode;
> -                               /*
> -                                * We don't need to re-check ->d_seq afte=
r this
> -                                * ->d_inode read - there will be an RCU =
delay
> -                                * between mount hash removal and ->mnt_r=
oot
> -                                * becoming unpinned.
> -                                */
>                                 flags =3D dentry->d_flags;
>                                 continue;
>                         }
> @@ -1515,8 +1508,7 @@ static bool __follow_mount_rcu(struct nameidata *nd=
, struct path *path,
>  }
>
>  static inline int handle_mounts(struct nameidata *nd, struct dentry *den=
try,
> -                         struct path *path, struct inode **inode,
> -                         unsigned int *seqp)
> +                         struct path *path, unsigned int *seqp)
>  {
>         bool jumped;
>         int ret;
> @@ -1525,9 +1517,7 @@ static inline int handle_mounts(struct nameidata *n=
d, struct dentry *dentry,
>         path->dentry =3D dentry;
>         if (nd->flags & LOOKUP_RCU) {
>                 unsigned int seq =3D *seqp;
> -               if (unlikely(!*inode))
> -                       return -ENOENT;
> -               if (likely(__follow_mount_rcu(nd, path, inode, seqp)))
> +               if (likely(__follow_mount_rcu(nd, path, seqp)))
>                         return 0;
>                 if (!try_to_unlazy_next(nd, dentry, seq))
>                         return -ECHILD;
> @@ -1547,7 +1537,6 @@ static inline int handle_mounts(struct nameidata *n=
d, struct dentry *dentry,
>                 if (path->mnt !=3D nd->path.mnt)
>                         mntput(path->mnt);
>         } else {
> -               *inode =3D d_backing_inode(path->dentry);
>                 *seqp =3D 0; /* out of RCU mode, so the value doesn't mat=
ter */
>         }
>         return ret;
> @@ -1607,9 +1596,7 @@ static struct dentry *__lookup_hash(const struct qs=
tr *name,
>         return dentry;
>  }
>
> -static struct dentry *lookup_fast(struct nameidata *nd,
> -                                 struct inode **inode,
> -                                 unsigned *seqp)
> +static struct dentry *lookup_fast(struct nameidata *nd, unsigned *seqp)
>  {
>         struct dentry *dentry, *parent =3D nd->path.dentry;
>         int status =3D 1;
> @@ -1628,22 +1615,11 @@ static struct dentry *lookup_fast(struct nameidat=
a *nd,
>                         return NULL;
>                 }
>
> -               /*
> -                * This sequence count validates that the inode matches
> -                * the dentry name information from lookup.
> -                */
> -               *inode =3D d_backing_inode(dentry);
> -               if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
> -                       return ERR_PTR(-ECHILD);
> -
> -               /*
> +               /*
>                  * This sequence count validates that the parent had no
>                  * changes while we did the lookup of the dentry above.
> -                *
> -                * The memory barrier in read_seqcount_begin of child is
> -                *  enough, we can use __read_seqcount_retry here.
>                  */
> -               if (unlikely(__read_seqcount_retry(&parent->d_seq, nd->se=
q)))
> +               if (unlikely(read_seqcount_retry(&parent->d_seq, nd->seq)=
))
>                         return ERR_PTR(-ECHILD);
>
>                 *seqp =3D seq;
> @@ -1838,13 +1814,21 @@ static const char *pick_link(struct nameidata *nd=
, struct path *link,
>   * for the common case.
>   */
>  static const char *step_into(struct nameidata *nd, int flags,
> -                    struct dentry *dentry, struct inode *inode, unsigned=
 seq)
> +                    struct dentry *dentry, unsigned seq)
>  {
>         struct path path;
> -       int err =3D handle_mounts(nd, dentry, &path, &inode, &seq);
> +       struct inode *inode;
> +       int err =3D handle_mounts(nd, dentry, &path, &seq);
>
>         if (err < 0)
>                 return ERR_PTR(err);
> +       inode =3D path.dentry->d_inode;
> +       if (unlikely(!inode)) {
> +               if ((nd->flags & LOOKUP_RCU) &&
> +                   read_seqcount_retry(&path.dentry->d_seq, seq))
> +                       return ERR_PTR(-ECHILD);
> +               return ERR_PTR(-ENOENT);
> +       }
>         if (likely(!d_is_symlink(path.dentry)) ||
>            ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
>            (flags & WALK_NOFOLLOW)) {
> @@ -1870,9 +1854,7 @@ static const char *step_into(struct nameidata *nd, =
int flags,
>         return pick_link(nd, &path, inode, seq, flags);
>  }
>
> -static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
> -                                       struct inode **inodep,
> -                                       unsigned *seqp)
> +static struct dentry *follow_dotdot_rcu(struct nameidata *nd, unsigned *=
seqp)
>  {
>         struct dentry *parent, *old;
>
> @@ -1895,7 +1877,6 @@ static struct dentry *follow_dotdot_rcu(struct name=
idata *nd,
>         }
>         old =3D nd->path.dentry;
>         parent =3D old->d_parent;
> -       *inodep =3D parent->d_inode;
>         *seqp =3D read_seqcount_begin(&parent->d_seq);
>         if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
>                 return ERR_PTR(-ECHILD);
> @@ -1910,9 +1891,7 @@ static struct dentry *follow_dotdot_rcu(struct name=
idata *nd,
>         return NULL;
>  }
>
> -static struct dentry *follow_dotdot(struct nameidata *nd,
> -                                struct inode **inodep,
> -                                unsigned *seqp)
> +static struct dentry *follow_dotdot(struct nameidata *nd, unsigned *seqp=
)
>  {
>         struct dentry *parent;
>
> @@ -1937,7 +1916,6 @@ static struct dentry *follow_dotdot(struct nameidat=
a *nd,
>                 return ERR_PTR(-ENOENT);
>         }
>         *seqp =3D 0;
> -       *inodep =3D parent->d_inode;
>         return parent;
>
>  in_root:
> @@ -1952,7 +1930,6 @@ static const char *handle_dots(struct nameidata *nd=
, int type)
>         if (type =3D=3D LAST_DOTDOT) {
>                 const char *error =3D NULL;
>                 struct dentry *parent;
> -               struct inode *inode;
>                 unsigned seq;
>
>                 if (!nd->root.mnt) {
> @@ -1961,17 +1938,17 @@ static const char *handle_dots(struct nameidata *=
nd, int type)
>                                 return error;
>                 }
>                 if (nd->flags & LOOKUP_RCU)
> -                       parent =3D follow_dotdot_rcu(nd, &inode, &seq);
> +                       parent =3D follow_dotdot_rcu(nd, &seq);
>                 else
> -                       parent =3D follow_dotdot(nd, &inode, &seq);
> +                       parent =3D follow_dotdot(nd, &seq);
>                 if (IS_ERR(parent))
>                         return ERR_CAST(parent);
>                 if (unlikely(!parent))
>                         error =3D step_into(nd, WALK_NOFOLLOW,
> -                                        nd->path.dentry, nd->inode, nd->=
seq);
> +                                        nd->path.dentry, nd->seq);
>                 else
>                         error =3D step_into(nd, WALK_NOFOLLOW,
> -                                        parent, inode, seq);
> +                                        parent, seq);
>                 if (unlikely(error))
>                         return error;
>
> @@ -1995,7 +1972,6 @@ static const char *handle_dots(struct nameidata *nd=
, int type)
>  static const char *walk_component(struct nameidata *nd, int flags)
>  {
>         struct dentry *dentry;
> -       struct inode *inode;
>         unsigned seq;
>         /*
>          * "." and ".." are special - ".." especially so because it has
> @@ -2007,7 +1983,7 @@ static const char *walk_component(struct nameidata =
*nd, int flags)
>                         put_link(nd);
>                 return handle_dots(nd, nd->last_type);
>         }
> -       dentry =3D lookup_fast(nd, &inode, &seq);
> +       dentry =3D lookup_fast(nd, &seq);
>         if (IS_ERR(dentry))
>                 return ERR_CAST(dentry);
>         if (unlikely(!dentry)) {
> @@ -2017,7 +1993,7 @@ static const char *walk_component(struct nameidata =
*nd, int flags)
>         }
>         if (!(flags & WALK_MORE) && nd->depth)
>                 put_link(nd);
> -       return step_into(nd, flags, dentry, inode, seq);
> +       return step_into(nd, flags, dentry, seq);
>  }
>
>  /*
> @@ -2473,8 +2449,7 @@ static int handle_lookup_down(struct nameidata *nd)
>  {
>         if (!(nd->flags & LOOKUP_RCU))
>                 dget(nd->path.dentry);
> -       return PTR_ERR(step_into(nd, WALK_NOFOLLOW,
> -                       nd->path.dentry, nd->inode, nd->seq));
> +       return PTR_ERR(step_into(nd, WALK_NOFOLLOW, nd->path.dentry, nd->=
seq));
>  }
>
>  /* Returns 0 and nd will be valid on success; Retuns error, otherwise. *=
/
> @@ -3394,7 +3369,6 @@ static const char *open_last_lookups(struct nameida=
ta *nd,
>         int open_flag =3D op->open_flag;
>         bool got_write =3D false;
>         unsigned seq;
> -       struct inode *inode;
>         struct dentry *dentry;
>         const char *res;
>
> @@ -3410,7 +3384,7 @@ static const char *open_last_lookups(struct nameida=
ta *nd,
>                 if (nd->last.name[nd->last.len])
>                         nd->flags |=3D LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
>                 /* we _can_ be in RCU mode here */
> -               dentry =3D lookup_fast(nd, &inode, &seq);
> +               dentry =3D lookup_fast(nd, &seq);
>                 if (IS_ERR(dentry))
>                         return ERR_CAST(dentry);
>                 if (likely(dentry))
> @@ -3464,7 +3438,7 @@ static const char *open_last_lookups(struct nameida=
ta *nd,
>  finish_lookup:
>         if (nd->depth)
>                 put_link(nd);
> -       res =3D step_into(nd, WALK_TRAILING, dentry, inode, seq);
> +       res =3D step_into(nd, WALK_TRAILING, dentry, seq);
>         if (unlikely(res))
>                 nd->flags &=3D ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
>         return res;



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise
erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie =
mich
bitte wissen, dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by
mistake, please don't forward it to anyone else, please erase all
copies and attachments, and please let me know that it has gone to the
wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV_vDVFNSJTOErNhzk7n%3DGRjZ_6U6Z%3DM-Jdmi%3DekbS5%2Bg%40m=
ail.gmail.com.
