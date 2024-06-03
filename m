Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMMS62ZAMGQEPOSRIUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 510FB8D7E34
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jun 2024 11:13:23 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-6f8ea7f4501sf3658648b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jun 2024 02:13:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717406001; cv=pass;
        d=google.com; s=arc-20160816;
        b=e1KAAxNtT/g/E7g38Xpu0G0xrhyfY8OUw0fPWf08CRN0TezWwR9rzMAy/3IpiLdxl5
         erjhQ9MdCdnz+2un10KKtthSKRXcmzMhqVSRMNWfn1WI3B1DCHoCJxeZ9j8oh99ojfp4
         tT0Snjq8eOOxS5AkZ4R4f2C4OtOgTX0feWx+du70atSw1XB6oO9CkIhgHUdHrdkQ44+1
         g8qvlw7zNpXr34AmvPEAicMvq0ZOkYbHm5uU6g4i8DQYAQh/SJzF+30IchvVMOafkzNh
         m8jepAnqljqEp5J47bYhA5YT/INFcaowdbaMCkQ9szJFsyls2KCTgkgc75kULjSXyi5d
         rbHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nupOwkhIEupQNSqTqaC5ctIVAkjh2zqDPPI9tVzQWvc=;
        fh=8zBEnRmJ6NXgy4PFkvrC83/wyY4PvMLx0sBpesrq9jU=;
        b=NhiyrD/pFYfbSjdL/whhn4ifuwgyh76fc9BExHOZSPMg87WASD4FJowkofd46pG/5Z
         XCuU6ExlYduPpJroQA+pkWEWyilZKS1D/fL4tVAQfevbvvJyz3H31v//kAKIfku4yLoQ
         tHTegST+tyEKyxSmz/HRB4HU8z7qLSayooPYrbnxGLhEi1m7DPtEHqoOMNKFgDAWCX/2
         6r+p0OkzdOMdlWWMzJenII9pAPogPUYAM9OGcnk5JhmjlNo6UUm/ew5dr8+vzVjwG7il
         0svf0Wa7eQnzxC9xOtLx4+tWSszcdnxMPxk2TqFSNc/I1UGHPY1N56Mp0UXAlzc553gI
         nr3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YuyOcKJu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717406001; x=1718010801; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nupOwkhIEupQNSqTqaC5ctIVAkjh2zqDPPI9tVzQWvc=;
        b=JhtTAEJHrnVWHXDZb96/htolKSu1VCQf35+mEK2v3VzbXFo1uYLO24mZf3f5M1Ig6u
         2WH+AXsBu+cIu5DGxHBuK28NnzPvtmfRQkPf+pFUuZ55lByfxBPC4PXJInYSsMZg0H/s
         b7zEpJ3HKlWrCSIIaFCF8cgQz1a2MJx2hBgXwBGq9r+Yax6sam7P0ryrtoVvacPU4I1T
         grezA+nADdpNN1iTTdnOKOpOfAH2tLl2vC6dkx67I2g1VzautUsn0soS3gapBmjFBnSb
         LiKPCzNt/7lolCT+rVCZXDiijpGD1gyXCRcgPUf7YMVUXdo2xLTAs4O4uWGGA7XPuoTv
         TCLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717406001; x=1718010801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nupOwkhIEupQNSqTqaC5ctIVAkjh2zqDPPI9tVzQWvc=;
        b=Y2MAB+0QUxo0iw3Hniao5sNHpxk8YslQSmJCTj8avURFUh69PponokkUCsiI6RylHj
         XLwIzbNt30nNHbf1FrPXUh2d5du42QrsPtKirTmaNxiSLbPnpJ8jX4foWlULtwAjlPsz
         8gitkMOHhxa2oMYicYenZafD3QC0Z2iE4bK41ZOyL4OkBDenhxTwtU1rHV73FCUa+hfx
         oOuF+SPuzf7GaN6hCKMZHB5/sIAsfhz9Red5NW8um1JujHr+tfydNQPzPDI8uXi0cxPb
         ESm4N40QHYLcFuIRbj4cQxRvdJ/L3D7A9U3lKO9JvYPweoPJ2HBulVK4IjB6CqnxciCD
         o69g==
X-Forwarded-Encrypted: i=2; AJvYcCXUBlpIIEHgNA3PHBUuWhvJ2dy9Vu6lUIzRKqblcE0WemI182Yfybw5+hfEICehW0inoDgXjc5VFv9TPniGLeNFXorCxELssQ==
X-Gm-Message-State: AOJu0YxTQ2qpo739E4Zpabpiy+u1U5Adw0S1qwMyJF1a2FqKHxFBH3C+
	3/k8DH4OUF/AG50zMxFMio4AVkyKwNLeSLlMJrXRP6r8WyJpGMhm
X-Google-Smtp-Source: AGHT+IGaLKKLfImRFbhjOwhQSl1TFZ3lMbe2QVy0jR6fV1onyiYAop85qW+gmkIIfe56HWNwU85Ovg==
X-Received: by 2002:a05:6a00:2ea0:b0:702:2f9d:ee8c with SMTP id d2e1a72fcca58-7024789c873mr9518533b3a.26.1717406001318;
        Mon, 03 Jun 2024 02:13:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2e21:b0:702:6998:770c with SMTP id
 d2e1a72fcca58-70269987e4fls552917b3a.1.-pod-prod-02-us; Mon, 03 Jun 2024
 02:13:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbHxS4wD3G9XKuSIU+QAeZ5D1G0BHnx5tfE+FJusq/xROc/stTcQrZTPtZS/ltvXnihL1iJ0FpZ6X0zrYNIOZCklNk5MFA2WWdOA==
X-Received: by 2002:a05:6a20:3206:b0:1af:dae8:5eac with SMTP id adf61e73a8af0-1b26f23d501mr7381129637.46.1717406000035;
        Mon, 03 Jun 2024 02:13:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717406000; cv=none;
        d=google.com; s=arc-20160816;
        b=Z2D1/vcTopQiMmAsOlHi1BoUoMk+QfjBiIZqsZjPVYa9wZ7E9eVDgynsW/ffVIlFMt
         h+HCnzJZU9pGJKBDJC8An0Wie17RD4C9QZnsHjxw4AfOiss0DQwmrc/g2390wbwuEdR+
         Rq+l3yZX1MxvYedUf0gI0w1fWLYLU5ZGUQLTJe6orkApVFkQs3gN1TktMV2M0ixMreKC
         z14G2us/pqBwLcegyOY/EPlidYDtpUpYIMAIHhnO9NaPWBiAL78ReGMY5p2jv9fn5pwv
         cWXbHLvVAl9HUcemymHliDEcqrbZqDbhOR+MNbtjj72kXuMy0+kvIgD70YT84Qh51nqD
         7nVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1vAMkiFmM1PgwLYJXTqfVoK4qXe/84aecwt6VcYF0jA=;
        fh=l4Mu1ZZ39u4VZVrKwwmMcVS64dPzVCdB8bYdw0vwsDU=;
        b=ymetzdnefXj4VhcLrTFCwj0+0ZTPZ1wzqp6Qo7eHWsxe2ErgkJt7gSDtcgKgJz6zOR
         wDWsegYA1TzxkDwS0oPCvo+J+cKaJ3TXBu1u7E0n3dt7KJtVbIRcoEeINFUTOtVDRZVw
         Qc2MhHQ/6W36cQt1bqhsDu+o+IoSeSYemSSZLBjlKp8nP9ty419imXlixuPdwKszTvMj
         CMOZWV/ucRQd3cUvWFGlgbBFU6TB1mCYcw96TbzAVdbhKvsyP14JfXWhtEJCkVljUkdv
         gWYLhr6HtBCJE4woqO1lCW4FZKTSTNh9MKe6tc5y52pHJD3lp2HPCLZUvOUWgea+3lah
         viWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YuyOcKJu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70242e71318si367911b3a.6.2024.06.03.02.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Jun 2024 02:13:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-6ae2e6dba36so19062256d6.3
        for <kasan-dev@googlegroups.com>; Mon, 03 Jun 2024 02:13:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWqhwSEOCB7sXejaWcFrqhRhS5wriEQV0BdUrxFE+52qApatYZbTqcJ379EN0Xp5HjJc9d26T8cvP44Sn/YpH7VAMQvNwZ4579UAA==
X-Received: by 2002:a05:6214:5890:b0:6af:c308:ee31 with SMTP id
 6a1803df08f44-6afc30938f9mr25119606d6.49.1717405999358; Mon, 03 Jun 2024
 02:13:19 -0700 (PDT)
MIME-Version: 1.0
References: <986294ee-8bb1-4bf4-9f23-2bc25dbad561@efficios.com>
 <vu7w6if47tv3kwnbbbsdchu3wpsbkqlvlkvewtvjx5hkq57fya@rgl6bp33eizt>
 <944d79b5-177d-43ea-a130-25bd62fc787f@efficios.com> <7236a148-c513-4053-9778-0bce6657e358@efficios.com>
 <jqj6do7lodrrvpjmk6vlhasdigs23jkyvznniudhebcizstsn7@6cetkluh4ehl>
 <CAG_fn=Vp+WoxWw_aA9vr9yf_4qRvu1zqfLDWafR8J41Zd9tX5g@mail.gmail.com> <63zx2cnrf5u2slmabde2wptxvq6a3opvrj2zrkcolw3gdkjdpf@bttdonbctura>
In-Reply-To: <63zx2cnrf5u2slmabde2wptxvq6a3opvrj2zrkcolw3gdkjdpf@bttdonbctura>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Jun 2024 11:12:37 +0200
Message-ID: <CAG_fn=W86C4F=nqYqrOCbNgioN5QjOrMjmU9jXYmx-fnZXQXag@mail.gmail.com>
Subject: Re: Use of zero-length arrays in bcachefs structures inner fields
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Brian Foster <bfoster@redhat.com>, 
	Kees Cook <keescook@chromium.org>, linux-kernel <linux-kernel@vger.kernel.org>, 
	linux-bcachefs@vger.kernel.org, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YuyOcKJu;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
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

On Tue, May 28, 2024 at 5:02=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Tue, May 28, 2024 at 01:36:11PM +0200, Alexander Potapenko wrote:
> > On Fri, May 24, 2024 at 7:30=E2=80=AFPM Kent Overstreet
> > <kent.overstreet@linux.dev> wrote:
> > >
> > > On Fri, May 24, 2024 at 12:04:11PM -0400, Mathieu Desnoyers wrote:
> > > > On 2024-05-24 11:35, Mathieu Desnoyers wrote:
> > > > > [ Adding clang/llvm and KMSAN maintainers/reviewers in CC. ]
> > > > >
> > > > > On 2024-05-24 11:28, Kent Overstreet wrote:
> > > > > > On Thu, May 23, 2024 at 01:53:42PM -0400, Mathieu Desnoyers wro=
te:
> > > > > > > Hi Kent,
> > > > > > >
> > > > > > > Looking around in the bcachefs code for possible causes of th=
is KMSAN
> > > > > > > bug report:
> > > > > > >
> > > > > > > https://lore.kernel.org/lkml/000000000000fd5e7006191f78dc@goo=
gle.com/
> > > > > > >
> > > > > > > I notice the following pattern in the bcachefs structures: ze=
ro-length
> > > > > > > arrays members are inserted in structures (not always at the =
end),
> > > > > > > seemingly to achieve a result similar to what could be done w=
ith a
> > > > > > > union:
> > > > > > >
> > > > > > > fs/bcachefs/bcachefs_format.h:
> > > > > > >
> > > > > > > struct bkey_packed {
> > > > > > >          __u64           _data[0];
> > > > > > >
> > > > > > >          /* Size of combined key and value, in u64s */
> > > > > > >          __u8            u64s;
> > > > > > > [...]
> > > > > > > };
> > > > > > >
> > > > > > > likewise:
> > > > > > >
> > > > > > > struct bkey_i {
> > > > > > >          __u64                   _data[0];
> > > > > > >
> > > > > > >          struct bkey     k;
> > > > > > >          struct bch_val  v;
> > > > > > > };
> >
> > I took a glance at the LLVM IR for fs/bcachefs/bset.c, and it defines
> > struct bkey_packed and bkey_i as:
> >
> >     %struct.bkey_packed =3D type { [0 x i64], i8, i8, i8, [0 x i8], [37=
 x i8] }
> >     %struct.bkey_i =3D type { [0 x i64], %struct.bkey, %struct.bch_val =
}
> >
> > , which more or less looks as expected, so I don't think it could be
> > causing problems with KMSAN right now.
> > Moreover, there are cases in e.g. include/linux/skbuff.h where
> > zero-length arrays are used for the same purpose, and KMSAN handles
> > them just fine.
> >
> > Yet I want to point out that even GCC discourages the use of
> > zero-length arrays in the middle of a struct:
> > https://gcc.gnu.org/onlinedocs/gcc/Zero-Length.html, so Clang is not
> > unique here.
> >
> > Regarding the original KMSAN bug, as noted in
> > https://lore.kernel.org/all/0000000000009f9447061833d477@google.com/T/,
> > we might be missing the event of copying data from the disk to
> > bcachefs structs.
> > I'd appreciate help from someone knowledgeable about how disk I/O is
> > implemented in the kernel.
>
> If that was missing I'd expect everything to be breaking. What's the
> helper that marks memory as initialized?

There's kmsan_unpoison_memory()
(https://elixir.bootlin.com/linux/latest/source/include/linux/kmsan-checks.=
h#L37).
include/linux/kmsan.h also has several more specific helpers for
various subsystems - we probably need something like that.
I was expecting kmsan_handle_dma() to cover disk IO as well, but
apparently I was wrong.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW86C4F%3DnqYqrOCbNgioN5QjOrMjmU9jXYmx-fnZXQXag%40mail.gm=
ail.com.
