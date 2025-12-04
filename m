Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFGYY3EQMGQEUF2IJ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 26652CA44EE
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:43:18 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-88236bcdfc4sf25697516d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:43:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764862996; cv=pass;
        d=google.com; s=arc-20240605;
        b=EWtXFogvQoB6m07L+YA+WgT40iQ6t46o3sDyoK3C/Na9vu7IByBJlRQcYrQsrPE16l
         LVkZCKOcDQT9StQCdpD9DDg1w9ATINCSQm076uIV0pV8o7nByTBicd2Tr6aPD5a3fuUo
         Jmps3UFnbWWdNf6TJnLr0TqInlOev7Zv1Q+qfxeZ0C2vx+ahGpIqqBSDu1ioVjbu/p7K
         slb8n1HAL90rT7tSKl/b/8BvPE2wNu/ifQnOed51GAwuDLarNLde1SG+ug3BL2rP2PA7
         EV2lfbC2Yp007I/hwO2Oy5IlXtW9q1Kzipdlaw/QsEFyefRsplBl0yMAjdqq3qDmfayO
         QVXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=InNv0n5DLRuOir4NABtTy/5h1kOWpxYdZs3iM17/1yU=;
        fh=PGV5xsUuVo48NbLjOOQ4wKzI3/dC7ePo7kuozKDowyQ=;
        b=Iy0uY8K2R1E8YKe3XZDG27DZ8YlxJLdhKwQ41mdrl9QhdvXwQ0tfWFEzbqGFjTUEvw
         8KrwDNKbuK2hV2toCTqPotXWpfgUf2jo86Fmxa/aYPkEsWtJxYKPfKkCc2ZMXjsl02X6
         JyESquFZAxixB7PEschL1n4+aVB8E+YaEN/nRPT8avNocZ5XsO0CEfuBFuxfZkLCrdI0
         KFOqyLqrtoCvOpU+gIONR/GDpS8YLNC5toaiWUBYjGcbY3CZkdTpsXetiJWC4KObimVX
         4/qKP//onIzXld2BOCik+ogUx+CMldMo5mZmXyVRGHu9A+sB7yyn8a92oTWnUd9fkN8P
         t2hQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ioEh3wUw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764862996; x=1765467796; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=InNv0n5DLRuOir4NABtTy/5h1kOWpxYdZs3iM17/1yU=;
        b=POilA/bmGrm6tjV9TBbtMjbI8tashDhDtrVvlooTXJ7WAESQGNDQYInUotiqxxpEdL
         59IDMnd0RKQS+bEZW7rI+dRKuSYeVEHIM3iti3tsXynTOc3ks1+0mH5dslDVvuELbwTU
         AshSGLX5lxhSs2ZYKdyyGqv7AV8J81MpecNa3+rYTan27zYdguS4stIsawVYNqcIzKa6
         8nbo8u4CqJAiVyULiUQHp8+X/Qnx98WzVVXba7e/q4RyZVz3VxINdmDumLyEp0HX3eZt
         3WY7RFe7KxQH3EDQUeCGAkzPwpNijLEnw1DAicykVMRU/+e1v7AZ4kVv3ZBuWYcZjtVp
         BNCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764862996; x=1765467796;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=InNv0n5DLRuOir4NABtTy/5h1kOWpxYdZs3iM17/1yU=;
        b=v4dR8D4VOhhAuhB+Z9WoCmw5aYsOAa+YQkrXOy/l083DzMnGD8us3BXW4h4lGeIXIk
         RgXsmZ0+tr7LvEOMpxqDjncXe2P+miDHPmI71cR7w15gAB70Qlk9GCR7/naikYbPbDOx
         mhVLMEU7+MUmdPs4q65+hQuHAAYDahzz5VWVQmBxmWE5vEMA2Zx5dDyKKSUKM0BknTGc
         sV2HuBKSKh5bGKzsHYRqf6pLTDqJ+L9IHKbpxoYTj2+LqosMjR4OgjQSasUaj58zZcIf
         9MYs1GOREjOgl2vy+GFECJphAhMYPCW8Gh2jhkDkDtmYVof0wOInTgZfQDatHRv3rOIu
         WKTg==
X-Forwarded-Encrypted: i=2; AJvYcCWxs7my2wmDoKGlKaYCqyFn39im7wgIF3bexoNDj5Bx4ty+gbYU0kcMzXA9AkELwgd2otYrIQ==@lfdr.de
X-Gm-Message-State: AOJu0YySa72J1T6QSwWfzENo8LZO2fe319SEbpzy7sAGQ22yYjA2jNgZ
	+7a4yFZYfjffSNMA6MIsLk7+wmiOplGzlken5LH3RPEXXOQRorzpNEYv
X-Google-Smtp-Source: AGHT+IHm+GUnrQdIw5UZYSdrwMdA7F/Le7Z0LjiRh+N+yGvKuURTWWF7guQVUj0mQPN2BKY+oazeMA==
X-Received: by 2002:ac8:5a44:0:b0:4ed:e0c1:44d5 with SMTP id d75a77b69052e-4f0239e20d3mr49335331cf.19.1764862996307;
        Thu, 04 Dec 2025 07:43:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YSexQXPUHACWsrakFNiMjz27yadWYfxD7XAJyM9hhy5A=="
Received: by 2002:a05:622a:2d5:b0:4ee:1544:bc7e with SMTP id
 d75a77b69052e-4f024c2466dls20173761cf.1.-pod-prod-07-us; Thu, 04 Dec 2025
 07:43:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW44QtCu/uOxBRES3NDppn9ZWrD8qShLHbbOO/lA70fCvOmXJlYC1ICHdLOa1ULUNAy41ypY6t4Jrk=@googlegroups.com
X-Received: by 2002:a05:622a:4:b0:4ed:a6b0:5c39 with SMTP id d75a77b69052e-4f023aa8bcfmr41891121cf.63.1764862995219;
        Thu, 04 Dec 2025 07:43:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764862995; cv=none;
        d=google.com; s=arc-20240605;
        b=a7pRNgq/+I+LTAgk1TnnC1uY1f9nqC+9gOyCnAs+c0pN53CVssLikKJN/CbztBK2FE
         2GWR5RzSeKfC5D7qIM37NlNF7yU23QXcksS4woSgKZkgGQpw4jeMt5AAp6o6Ut15Gyz0
         px0jjus8mxUc2ZFQgZsWCohoVnxMRXkcOQfdpo6Eo7PsBA7NOwkkdbhYa1C64wQa9jZm
         DGK9qDhqWK47RAeMvOvUG3zbMp09Nhm3gW7tLC9H2fOotHX2keypwoey++mfgEXM8l2q
         ONZ0t3tCbWOQ7aUwdIc82TAPb5Lmm/lhtGcuVcV16Ynrkmew6p4ABC7V58RW6V9axcFB
         AMeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wMOP4GkDr5ijMp2y62W7yYKXyYdN/GF/oZk8QJQ4apc=;
        fh=6RscAFXDsjM05SXPc5EeFG4Z3Rs7yTOMDUIwARg8Y/M=;
        b=W8pmlClv53FIREf/EsJjKq0wHRWHdxOXJoAymJvwE+5TI/ub/oiIoSO2+5yDltXsGu
         OUYgIgmiVoLbyrjpyPMFdKbXTseoxiJnsI1JZKdKkTJBEeVC5S9F7/oYlpenKDZsxnM2
         LSbeEN+Fc+vEJozgkbSv6JeLuhRL9UcNoLCQDFP7761pV18Wq0MJqTEJAw/6GxC5PM+P
         aXT1DVV5YG1XEi93rf46e5nxHDMwAYkFn0PpX245KBjs7K01JXlBVHZ0lc2NWFAUde09
         WOW4LBj4+jd3tjAoMhEdo/8FNJ8U6TKAgD2cCA2XUBp2hJ3lvvXhk6QBQypv/txM2qLF
         151w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ioEh3wUw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88828289524si823826d6.9.2025.12.04.07.43.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:43:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-7b9215e55e6so791575b3a.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:43:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWkT9Nw3qUoiVSK3hb22xv3Y0LMJI7UVDX7md6xxO6rcXdDUe558ZdP9Komc8Bh6PFDKPgAqmHseGg=@googlegroups.com
X-Gm-Gg: ASbGncsmlcbZOjjyfI4q+8pmBrJMlCep+EyK9h964M2m5t5PF1o9zpACzrSVC4l1Ry/
	Z3OOQGzvShIc35/mdLoVYj9dzieP4DicVLgkqX1ObFYgcXlZPFfd2lg5VRyKvsqcjB+Mo2ViWJQ
	qwpqjBPERSQKt6vZJ87O6V7f5Q64XjZIi2pr9nSiKH6Uujwptw5720uPieNYgWYwBJVtizkAEVd
	KamQcObq18TWIVujwhMhVzambphV/vxgppuwYbSUVJhqMCoXiJgCRKWF4FotrsrcsQMpTxHiND5
	QYDMAhqJ/cSvJeRGvfPL61d0VA==
X-Received: by 2002:a05:7022:f511:b0:119:e56b:98a5 with SMTP id
 a92af1059eb24-11df6463cf7mr1323360c88.12.1764862993857; Thu, 04 Dec 2025
 07:43:13 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-10-ethan.w.s.graham@gmail.com> <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
 <CANpmjNMQDs8egBfCMH_Nx7gdfxP+N40Lf6eD=-25afeTcbRS+Q@mail.gmail.com>
 <CAHp75VfsD5Yj1_JcXS5gxnN3XpLjuA7nKTZMmMHB_q-qD2E8SA@mail.gmail.com> <CANpmjNOKBw9qN4zwLzCsOkZUBegzU0eRTBmbt1z3WFvXOP+6ew@mail.gmail.com>
In-Reply-To: <CANpmjNOKBw9qN4zwLzCsOkZUBegzU0eRTBmbt1z3WFvXOP+6ew@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Dec 2025 16:42:37 +0100
X-Gm-Features: AWmQ_bnyN22mbvWc2oz66fpJ7IbcLfdYObxM0FDhKEtXf6ssNmrNTIWoxgBISDw
Message-ID: <CANpmjNNqCe5TxPriN-=OnS0nqGEYd-ChcZe6HQxwG4LZMuOwdA@mail.gmail.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Andy Shevchenko <andy.shevchenko@gmail.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com, andreyknvl@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, shuah@kernel.org, sj@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ioEh3wUw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 4 Dec 2025 at 16:35, Marco Elver <elver@google.com> wrote:
> On Thu, 4 Dec 2025 at 16:34, Andy Shevchenko <andy.shevchenko@gmail.com> =
wrote:
> >
> > On Thu, Dec 4, 2025 at 5:33=E2=80=AFPM Marco Elver <elver@google.com> w=
rote:
> > > On Thu, 4 Dec 2025 at 16:26, Andy Shevchenko <andy.shevchenko@gmail.c=
om> wrote:
> >
> > [..]
> >
> > > > > Signed-off-by: Ethan Graham <ethangraham@google.com>
> > > > > Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
> > > >
> > > > I believe one of two SoBs is enough.
> > >
> > > Per my interpretation of
> > > https://docs.kernel.org/process/submitting-patches.html#developer-s-c=
ertificate-of-origin-1-1
> > > it's required where the affiliation/identity of the author has
> > > changed; it's as if another developer picked up the series and
> > > continues improving it.
> >
> > Since the original address does not exist, the Originally-by: or free
> > text in the commit message / cover letter should be enough.
>
> The original copyright still applies, and the SOB captures that.

+Cc Greg - who might be able to shed a light on tricky cases like this.

tldr; Ethan left Google, but continues to develop series in personal
capacity. Question about double-SOB requirement above.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNNqCe5TxPriN-%3DOnS0nqGEYd-ChcZe6HQxwG4LZMuOwdA%40mail.gmail.com.
