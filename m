Return-Path: <kasan-dev+bncBCXKTJ63SAARBYPUWGZQMGQEJAPGPWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 44E4F909126
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 19:14:11 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6ab80cb23besf20217206d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 10:14:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718385250; cv=pass;
        d=google.com; s=arc-20160816;
        b=JneA96T2qF4euuX3j5qDpeT+J3sHbfihX1GZnBrtQ+0ClitckTZg99ckHNOrju6NfL
         ga+DNW+38OwjfPPEqLRvTnKIosnD3+sEY44R+Z8s+QhFWlTPEqkOxUHmZ08eUCCrlnI+
         Vp29wxIbupP4e9J2P2uBSed4tm2ROCAPf5aoG+gu6tkckE7hVub1Kyl4SJktY8nlJWAe
         8l2+Xk6zQt6P6XmflNQmTGBLtywao3/XEwp87dm38MyiNb60gDvdAyxoTdiWwftaaBNU
         /qtgun+6OVJ5qHg1YmxBxvNSDDTbpaaWI+qun8OVqR7WNIlaHTI8ivgtsp87jgtX9ZXI
         g1Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o6kRwUZGHI/Apk/rcA5Prd3cpqmwymVwRRNTLEsPCgU=;
        fh=09TocLnFf/ouoF9LUKwoIPZ/gwCnxIhVK6cXOygpN94=;
        b=e3LcSNn+VjmgTJ3RcS7Dw0aNtSfiVPEDbd2GMrH8Sa1hxTU+5BQ5L9KSJGyPTmpJmh
         P6xGwIBa7f0W7fPLy8MgzjO6qio2OY4wX8/uIswVXcbq5xceWfq5yzIVSu3OW82CUw+W
         nJyvuhDeJb9NPaMjUekg+nQzBAnHP3Pebm7vDxVx+MzKjV06F3BFx3Um0UxiOOVgJ3XJ
         L+Vkj9I1AXiY/hJFmDH7YW4DqWGyNKSnLKp466bI5q2bT5hgqIao1zTXI8T+1eZXU/M+
         37aLcCHbKvmR2d5sd2yvwNiVrquhtE2gVg7jVp8+aPVT44RHTgMDH9c4cY9nWYtYT7D+
         imiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=heosO+V6;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718385250; x=1718990050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o6kRwUZGHI/Apk/rcA5Prd3cpqmwymVwRRNTLEsPCgU=;
        b=iDeqhPE2anzQefV/AmWWU2u2zD8dK5Lkojxjc3RFq3jHR5DxpRRxZva6RG4NepVVUA
         6PmxKRAqg8vbgolzcYHB4ERYA0rfWQaZe7jMXo/Q0pBtOTORmDx1ziQIBEZ6sXcLQ39p
         yLWfbfBUDzPFzQGNnXQN2wIzGDLXY35SFJBakVNZuMIW5rZPIxXi+pt50d8Dl2N+U1xC
         ltpirBYmFBLLzK8FUuwkKY1JfB/+IgV0Y7HEoxVeqZwmRyT7qUgleVJaPvBtdDE3AQzs
         0NUZNZUQjQlwhEOj5dgLmt4dzi3BCIC1+ahdvccmS/Sb8UC+M+tl6d8KLXeBJY3qTthy
         CZLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718385250; x=1718990050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o6kRwUZGHI/Apk/rcA5Prd3cpqmwymVwRRNTLEsPCgU=;
        b=jG/3F0/k+ohBrIuBTXCX1j2QJmv9YTjRyx6wD732C7YMFpA2ZCFTVFhDjX1bLAKaJx
         UeDimv36aqtq4t3yIWR5Hj8RrMPRNun5/owQWouyHdppxu+74c17r/Rf9FRGUvhpQqN4
         Bz36BSD8RV7wTfoxeNSxo+VZpBK5McwDgOQfnVWEvep6KwdLlA/+Y0QP6Y/dntn/NsB/
         eJmKYlGkYZswW/9TjOJWwpNtDB/jVOEJ50hAXBrx6r8Cu795zAaLxOKT9GPDqmovW1wL
         W09I9BJYwCznU7M+Jk6lI3hC3vsQ9WgfQnHF3hEkyu8fd78Jx2vUVqzApjGY51rCdfVM
         1C1g==
X-Forwarded-Encrypted: i=2; AJvYcCUfp5Oxj1BR1ndJZSrOC88HUfQtJXz1oYHO/gr17Dq0kN+MotMAtqou+L+BswSNTUnB8mzuxmd0rxwq8LeclWSLeHaAYjsIag==
X-Gm-Message-State: AOJu0Yz1mDKLLELT8W4dDIwmvdTjO/3aEHZkwQrgt9i1tdox16oWBRSs
	jPNaxrGhoRt5ddiX0Iyz3iNuaLalHCltOGPrxZ/z8dwX5T2pkMJs
X-Google-Smtp-Source: AGHT+IHcDQHIPs8US/KQ5mmheuE396lQLCJPOhjjjh/r7uxFfsbqXD4qS7LQCYgmjTOu33M+hzk74Q==
X-Received: by 2002:a05:6214:2507:b0:6b0:815a:5ca2 with SMTP id 6a1803df08f44-6b2afc793d8mr44005616d6.5.1718385250047;
        Fri, 14 Jun 2024 10:14:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5d8e:b0:6ab:7910:c571 with SMTP id
 6a1803df08f44-6b2a43e3c25ls30993336d6.2.-pod-prod-02-us; Fri, 14 Jun 2024
 10:14:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgiFc6b+jpXHxDCZxUOvqnM1/JSnzt+BKdxzi/Qb3i1TKkFUS+Bdd/bltOuviENK0yithgputqyKZ2bLUHFcTW1gTL3V7jDKvOmg==
X-Received: by 2002:ad4:4f8f:0:b0:6b0:7d9a:79f1 with SMTP id 6a1803df08f44-6b2afd6158bmr29024696d6.42.1718385249338;
        Fri, 14 Jun 2024 10:14:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718385249; cv=none;
        d=google.com; s=arc-20160816;
        b=NmS0m4P0kEMr5gikTyCk7uhY5bJx0SMNiEkYFblDVhcxG5Lr1mglY2b2jW4PbqlOfL
         8Xqh//o6xTjeqd2e4zoqofisDHDbTdbvYNEbp/El2QRIZAwyBi+TAVzOIrox6JRBo1L+
         9qiDARdaBsExv1f3yDiaK1RIutN7gu0bKF/0KadxUGIpN7or0g5nas0oViyAL1u1DoIM
         Dszn60xlVn8oid7hgE8v0XbsjK86SfQZy3buvfUDzokokhtMZaGAnMjRPyxxQ1F01B3j
         GItiO/05m1KWI8aWpb5C1MOhWBJKZ055qKAfZDew6Xx4njdXVRvdWxLVz3puFh4i8raM
         VjBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=95IQjCUrHkCT3SiS0CIW9AdJHC2xCd1IW8jzRM+4DVM=;
        fh=FiP9iEYGyLtGdgsEj8hn5Qk/Y+ubVV853YueoHM0xxE=;
        b=tg7jIGILMfO3UvIKTiHOM9F6QU0WxpJjJ65MBIXASswRUh5ULO00ddEG6RcYEz+qIQ
         Zkh6n0gNrAq7d776lbXl907swNBcgz3q6VDGBGwGtyAQWEfRZRfmI0rY4eCym+O3vXzU
         6AZssKmXaSd0zWMblmUSe/RCtMrkU4JUDKPSgOKg8JcllG/6q5e7IG9JF6uKp+L+8e/p
         7qyTimDH+Dlu98U/qZH6f8I2QUI/aPrFMhZFmmgh+fmGLby5eG3RClwD+xoVi3VgnAWW
         id8qYS0qcAHgSQL9QWxoX+3g8CGXMBcU+U9hqUXksBXUeN865YfNqNniU6rGxQqkzaYl
         Z7Rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=heosO+V6;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b2a5955aedsi1414536d6.0.2024.06.14.10.14.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Jun 2024 10:14:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1f61742a024so7275ad.0
        for <kasan-dev@googlegroups.com>; Fri, 14 Jun 2024 10:14:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW9V9lWefcHB4rFhQPC6bQve55sfqJWKbxHXG0Ar4sMcDMv4MeoJgJvxKxvXJ25/KBT/QJgKZCOkZrLxBo87wontkl6r4j09Ww//g==
X-Received: by 2002:a17:902:6b88:b0:1f4:33a3:4b8f with SMTP id
 d9443c01a7336-1f8642c21edmr3825675ad.8.1718385247948; Fri, 14 Jun 2024
 10:14:07 -0700 (PDT)
MIME-Version: 1.0
References: <20240611133229.527822-1-nogikh@google.com> <CA+fCnZdfB206Bjw=MAkZ9qbKUtf-KeGrrqJnOJ1ZrgH6fGXRhA@mail.gmail.com>
In-Reply-To: <CA+fCnZdfB206Bjw=MAkZ9qbKUtf-KeGrrqJnOJ1ZrgH6fGXRhA@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Jun 2024 19:13:56 +0200
Message-ID: <CANp29Y6x4Xx-a8z1DhR1NYh9SMuv1ikV1x=JXR5sKUFiqH6w8g@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't lose track of remote references during softirqs
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: dvyukov@google.com, arnd@arndb.de, akpm@linux-foundation.org, 
	elver@google.com, glider@google.com, syzkaller@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=heosO+V6;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62c as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

On Fri, Jun 14, 2024 at 1:02=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Tue, Jun 11, 2024 at 3:32=E2=80=AFPM Aleksandr Nogikh <nogikh@google.c=
om> wrote:
> >
> > In kcov_remote_start()/kcov_remote_stop(), we swap the previous KCOV
> > metadata of the current task into a per-CPU variable. However, the
> > kcov_mode_enabled(mode) check is not sufficient in the case of remote
> > KCOV coverage: current->kcov_mode always remains KCOV_MODE_DISABLED
> > for remote KCOV objects.
> >
> > If the original task that has invoked the KCOV_REMOTE_ENABLE ioctl
> > happens to get interrupted and kcov_remote_start() is called, it
> > ultimately leads to kcov_remote_stop() NOT restoring the original
> > KCOV reference. So when the task exits, all registered remote KCOV
> > handles remain active forever.
> >
> > Fix it by introducing a special kcov_mode that is assigned to the
> > task that owns a KCOV remote object. It makes kcov_mode_enabled()
> > return true and yet does not trigger coverage collection in
> > __sanitizer_cov_trace_pc() and write_comp_data().
> >
> > Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> > Fixes: 5ff3b30ab57d ("kcov: collect coverage from interrupts")
> > ---
> >  include/linux/kcov.h | 2 ++
> >  kernel/kcov.c        | 1 +
> >  2 files changed, 3 insertions(+)
> >
> > diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> > index b851ba415e03..3b479a3d235a 100644
> > --- a/include/linux/kcov.h
> > +++ b/include/linux/kcov.h
> > @@ -21,6 +21,8 @@ enum kcov_mode {
> >         KCOV_MODE_TRACE_PC =3D 2,
> >         /* Collecting comparison operands mode. */
> >         KCOV_MODE_TRACE_CMP =3D 3,
> > +       /* The process owns a KCOV remote reference. */
> > +       KCOV_MODE_REMOTE =3D 4,
> >  };
> >
> >  #define KCOV_IN_CTXSW  (1 << 30)
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index c3124f6d5536..5371d3f7b5c3 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -632,6 +632,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, uns=
igned int cmd,
> >                         return -EINVAL;
> >                 kcov->mode =3D mode;
> >                 t->kcov =3D kcov;
> > +               WRITE_ONCE(t->kcov_mode, KCOV_MODE_REMOTE);
>
> Looking at this again, I don't think we need this WRITE_ONCE here, as
> we have interrupts disabled. But if we do, perhaps it makes sense to
> add a comment explaining why.

Thank you!
I've sent a v2:
https://lore.kernel.org/all/20240614171221.2837584-1-nogikh@google.com/

>
> >                 kcov->t =3D t;
> >                 kcov->remote =3D true;
> >                 kcov->remote_size =3D remote_arg->area_size;
> > --
> > 2.45.2.505.gda0bf45e8d-goog
> >
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANp29Y6x4Xx-a8z1DhR1NYh9SMuv1ikV1x%3DJXR5sKUFiqH6w8g%40mail.gmai=
l.com.
