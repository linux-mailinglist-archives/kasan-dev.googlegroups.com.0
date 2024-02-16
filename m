Return-Path: <kasan-dev+bncBC7OD3FKWUERBOE2XSXAMGQEIRYTXUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BF608576C1
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 08:22:34 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5d8dbe37d56sf1749009a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 23:22:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708068152; cv=pass;
        d=google.com; s=arc-20160816;
        b=vwM2g2KiHAveK2h0yTjDuXGKoq92oeP5cjAK9hgiZvMmzTuwajgSJV7HdHcaf1EQ83
         b/zgt/MRIEokw4Mzrrn1WHBEkowTA7S78mQ4D149QgOU5tV5T99t5BQJ5LPe8LWk8s6o
         7VJmXI0VAMqizP63uOyj0tmKSiJ9i+9gLwpL2VfG4OHCuV40Ucv96hCafknOdzQqPUZl
         YqcOMm6QVYDtMzZ+RZ4eqWI3YZ6NTYB4D7KKKPC+PBPwzQ3lPfW82LMpUJFnU0/rYjsO
         b7dh37fCzXB250bD4SppJxbcfqOjqDry1WWZD9iNeeMhvLn8/WTS6D/+h0HCmI2U834K
         ultA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1f1A5m9RaA8T1KFdJK7IyVvbnyb2OitUsb//7GUWYVI=;
        fh=F/X4303x/vmcJAcu09XS2AejbR5QIT4NrVk3zpgk6EU=;
        b=RtfLbJbXwoOrEQ4l8Hhpb4HNhdplTwkJWvVQhSUfJ1Uu0Mj6s3kH8SfKh1Zhv8m+sE
         IIjO6x8plW2loFvMn7OZJYHGFXc+EDGatxhXuzHrAq6f1Q+gN4GsCWcvMcKAHSAtUpmP
         9NYmo918bh/ckv0qnWg+jrDxdWvP/qSA6f/ZmfW3qsdmCZP0LHl9ScJfdvgEyjW0CyOL
         Z1yAsmHBQgPMM61yo03TONg72zBeQClOmTuUH3Kyyd6MBUkhxZKRZomwe6+M6PLJgQJP
         rqlNpD8buXi8IeDcs89YNvzuwb2e3/9ODwcLgpzSMV8NgqscZ2FuMMv4zNSN+oardHhF
         amfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qHSZXyyC;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708068152; x=1708672952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1f1A5m9RaA8T1KFdJK7IyVvbnyb2OitUsb//7GUWYVI=;
        b=eo4P00JJSqU346vMJ+tNux810w+55xm2mav2tf3Cobofz79HrBq2dYmG05RbiAIcn5
         wOc5Nxbs6/CgHQLbBQUOtpriEK5JM44idD7QMK+ydlfbGHkxfh27jR0jD625yL3iYZw/
         gApgKkJbfg1nWOWgV34yzI3UqKUmBW56nMa6+Zawpzhwy3psDazuefqzSo+9m+1GohME
         El11rGTof5E3sc7l18IMc0ttokDN24ijU6v5Zrie1Z2RbDWz+LdIQUvnZz5ZyO6yvYis
         FZJObnRmVgSMPNFroPHP+Oi8h9RG5ksY1VfQ57HLFgNbAAzm7omzxEP1ksg8qHSjV7a1
         WNMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708068152; x=1708672952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1f1A5m9RaA8T1KFdJK7IyVvbnyb2OitUsb//7GUWYVI=;
        b=dnmO4XM6JminxdPA0op5z9eyl13bWGafK4UQY3MxRC10Xe2dGSqux+sYaYwAH4U0ty
         JKhnj8Ahn9uYhD0EtkF7XLjX+op0rdjJXufYe9/oYGPRF3b2A9XVGCUC8Cooh8cRT95E
         6zw7c3gLDz01UmWX8AMVeSr7bq98KFv+J0O2sxj25o1b4X6n3i6+uWcpMwrkOfs64w7Q
         b7kn8xWk2hBklAezpbzdmGL/s8MfwTIPRJv07wgymtS6RRFoKoL7nL1CL1JxDz5n3SsK
         JU3hbRmlkvxLBwASvSyjuZvsd+ClZrp9G7aFamyp0cMG9sdx9w+QfZie8Pds5/EI650Q
         mvBg==
X-Forwarded-Encrypted: i=2; AJvYcCUXBLw1Tj28JWifu2FEoMY4QVOdfuiL40J38L3VWP03MMibMxnyg3MNhL2lCRApe+4G1C58yHxSaTDTaWB/eSD7nC4zMKcwGQ==
X-Gm-Message-State: AOJu0Yz+N1N48vLXTEmjAyCvCr9nBbu0OOodokJ6130/d7pcZt+CRXpx
	UFpxzUFejDA71plAXxxdIlCe1oRapZ6UVAJYLJn03P7UpXXrZ1kK
X-Google-Smtp-Source: AGHT+IErNcOM+dOiIflxmXqKVI7Xvw7c0JiUz3YhhIfmgK9e4/PvnwoVXfqkzsfBOl6BxargOjn4vA==
X-Received: by 2002:a05:6a20:3713:b0:1a0:7197:57f2 with SMTP id t19-20020a056a20371300b001a0719757f2mr3241504pze.26.1708068152302;
        Thu, 15 Feb 2024 23:22:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2ec5:b0:298:f468:dc46 with SMTP id
 ss5-20020a17090b2ec500b00298f468dc46ls532591pjb.0.-pod-prod-02-us; Thu, 15
 Feb 2024 23:22:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWgNvNtyQwTdHlA5wiwPrqX+NVDH3pGqQFZtCUgr6G7qMSo6dvvHCkoeX9MBXseSNaFQDO6+23vQwVY66Nc4/a+ku6thZw5fPtaew==
X-Received: by 2002:a17:90b:46cc:b0:299:2fef:a22e with SMTP id jx12-20020a17090b46cc00b002992fefa22emr1473256pjb.15.1708068151177;
        Thu, 15 Feb 2024 23:22:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708068151; cv=none;
        d=google.com; s=arc-20160816;
        b=G16CXikVAHudWccYvLC/CorljL0FMY+niSYtP06tLQLIhjEb9gSQugLNZB+JcH6SdH
         G5htI24sxvkcUewAhWGyYdIcgCQs3CoYfPIzP/13gG2+VXmOcP7XDGa3pBQkeIuzDmbP
         GxE9TUQFOc2MHGmggH7ubdVj/b2iPbaRunD/Tt03Ga6L7J7ZLr6DD7Jb3l+E+JOXAGsI
         ev2oJiL8KKj1Zn3XUNkNEBjUM43PQ0i8PgNobU39cipS92VZ9gj2IWZQ7mttEqeTIdQ2
         uoC6Tmzb4CeRKIntreUjtW2f/BRc/t6guUhxaxesYqcuGYX/SShJ42VlQw95v9aOOIaD
         gWpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+9+B+H3K0W9pJd8bNryL7B75GoSzScPALIXqjy44UEE=;
        fh=ALUdZyJ2T05VZOqC+0BOSTVdEeXBo/YqpA94cpoZhPU=;
        b=QBVqvBplf6nziUaprnUMMXU2Y5/sh8929Wt+6m9qQEZnOpzlyssNnJ2lxiDqe9AJt9
         gpZMxnlnqwr2QFsV+xAXJk/1I4YJQl0nid6eZrgu4d0BOLJcadNgh13flNumAHBPIMAR
         o2uqPIfRGC4pW9QLWax9tFSe8E50upgVmo2sJMaLdtWumcJzSwWkQyaRURa15vRZ7Xsz
         DLK4Ub++9zN2OmuhW/xZLqpV8TNs1TyWo0gzPNrx6vT3CtWtn9JzjCpX6jRwkeWNasGV
         vEeaf2P+w54QQRW5lDuQ2++5ytr6lVzb9QCkkCvOvqoDCeV6fiG8FFfvrL8zh86hJKB0
         YkcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qHSZXyyC;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id p5-20020a17090ad30500b00298d35696d6si353987pju.0.2024.02.15.23.22.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 23:22:31 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-607e41efcf1so11212187b3.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 23:22:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXpsJR5PQHChnQlhF/zt9itk27rDoBk9xN469M+n0U/+e81zCyJzAVU+Jvo5RrKN39oIDFREEgj+BEINXMc2qoz+eren0ZBB82Dgg==
X-Received: by 2002:a0d:cc81:0:b0:5f6:d447:b85a with SMTP id
 o123-20020a0dcc81000000b005f6d447b85amr4793609ywd.7.1708068149910; Thu, 15
 Feb 2024 23:22:29 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-11-surenb@google.com>
 <202402121419.7C4AAF27ED@keescook> <CAJuCfpFpKKqCtU2EJM28fbYRYUbBLR9XuDONmS21zeTc2Z6nxw@mail.gmail.com>
In-Reply-To: <CAJuCfpFpKKqCtU2EJM28fbYRYUbBLR9XuDONmS21zeTc2Z6nxw@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Feb 2024 23:22:16 -0800
Message-ID: <CAJuCfpF3ZHkuBejRp_2BBcC-Lp8achfaosVu0SfBNAA0Y27+vA@mail.gmail.com>
Subject: Re: [PATCH v3 10/35] lib: code tagging framework
To: Kees Cook <keescook@chromium.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qHSZXyyC;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, Feb 12, 2024 at 6:04=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> On Mon, Feb 12, 2024 at 2:27=E2=80=AFPM Kees Cook <keescook@chromium.org>=
 wrote:
> >
> > On Mon, Feb 12, 2024 at 01:38:56PM -0800, Suren Baghdasaryan wrote:
> > > Add basic infrastructure to support code tagging which stores tag com=
mon
> > > information consisting of the module name, function, file name and li=
ne
> > > number. Provide functions to register a new code tag type and navigat=
e
> > > between code tags.
> > >
> > > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > ---
> > >  include/linux/codetag.h |  71 ++++++++++++++
> > >  lib/Kconfig.debug       |   4 +
> > >  lib/Makefile            |   1 +
> > >  lib/codetag.c           | 199 ++++++++++++++++++++++++++++++++++++++=
++
> > >  4 files changed, 275 insertions(+)
> > >  create mode 100644 include/linux/codetag.h
> > >  create mode 100644 lib/codetag.c
> > >
> > > diff --git a/include/linux/codetag.h b/include/linux/codetag.h
> > > new file mode 100644
> > > index 000000000000..a9d7adecc2a5
> > > --- /dev/null
> > > +++ b/include/linux/codetag.h
> > > @@ -0,0 +1,71 @@
> > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > +/*
> > > + * code tagging framework
> > > + */
> > > +#ifndef _LINUX_CODETAG_H
> > > +#define _LINUX_CODETAG_H
> > > +
> > > +#include <linux/types.h>
> > > +
> > > +struct codetag_iterator;
> > > +struct codetag_type;
> > > +struct seq_buf;
> > > +struct module;
> > > +
> > > +/*
> > > + * An instance of this structure is created in a special ELF section=
 at every
> > > + * code location being tagged.  At runtime, the special section is t=
reated as
> > > + * an array of these.
> > > + */
> > > +struct codetag {
> > > +     unsigned int flags; /* used in later patches */
> > > +     unsigned int lineno;
> > > +     const char *modname;
> > > +     const char *function;
> > > +     const char *filename;
> > > +} __aligned(8);
> > > +
> > > +union codetag_ref {
> > > +     struct codetag *ct;
> > > +};
> > > +
> > > +struct codetag_range {
> > > +     struct codetag *start;
> > > +     struct codetag *stop;
> > > +};
> > > +
> > > +struct codetag_module {
> > > +     struct module *mod;
> > > +     struct codetag_range range;
> > > +};
> > > +
> > > +struct codetag_type_desc {
> > > +     const char *section;
> > > +     size_t tag_size;
> > > +};
> > > +
> > > +struct codetag_iterator {
> > > +     struct codetag_type *cttype;
> > > +     struct codetag_module *cmod;
> > > +     unsigned long mod_id;
> > > +     struct codetag *ct;
> > > +};
> > > +
> > > +#define CODE_TAG_INIT {                                      \
> > > +     .modname        =3D KBUILD_MODNAME,               \
> > > +     .function       =3D __func__,                     \
> > > +     .filename       =3D __FILE__,                     \
> > > +     .lineno         =3D __LINE__,                     \
> > > +     .flags          =3D 0,                            \
> > > +}
> > > +
> > > +void codetag_lock_module_list(struct codetag_type *cttype, bool lock=
);
> > > +struct codetag_iterator codetag_get_ct_iter(struct codetag_type *ctt=
ype);
> > > +struct codetag *codetag_next_ct(struct codetag_iterator *iter);
> > > +
> > > +void codetag_to_text(struct seq_buf *out, struct codetag *ct);
> > > +
> > > +struct codetag_type *
> > > +codetag_register_type(const struct codetag_type_desc *desc);
> > > +
> > > +#endif /* _LINUX_CODETAG_H */
> > > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > > index 975a07f9f1cc..0be2d00c3696 100644
> > > --- a/lib/Kconfig.debug
> > > +++ b/lib/Kconfig.debug
> > > @@ -968,6 +968,10 @@ config DEBUG_STACKOVERFLOW
> > >
> > >         If in doubt, say "N".
> > >
> > > +config CODE_TAGGING
> > > +     bool
> > > +     select KALLSYMS
> > > +
> > >  source "lib/Kconfig.kasan"
> > >  source "lib/Kconfig.kfence"
> > >  source "lib/Kconfig.kmsan"
> > > diff --git a/lib/Makefile b/lib/Makefile
> > > index 6b09731d8e61..6b48b22fdfac 100644
> > > --- a/lib/Makefile
> > > +++ b/lib/Makefile
> > > @@ -235,6 +235,7 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) +=
=3D \
> > >       of-reconfig-notifier-error-inject.o
> > >  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) +=3D error-inject.o
> > >
> > > +obj-$(CONFIG_CODE_TAGGING) +=3D codetag.o
> > >  lib-$(CONFIG_GENERIC_BUG) +=3D bug.o
> > >
> > >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) +=3D syscall.o
> > > diff --git a/lib/codetag.c b/lib/codetag.c
> > > new file mode 100644
> > > index 000000000000..7708f8388e55
> > > --- /dev/null
> > > +++ b/lib/codetag.c
> > > @@ -0,0 +1,199 @@
> > > +// SPDX-License-Identifier: GPL-2.0-only
> > > +#include <linux/codetag.h>
> > > +#include <linux/idr.h>
> > > +#include <linux/kallsyms.h>
> > > +#include <linux/module.h>
> > > +#include <linux/seq_buf.h>
> > > +#include <linux/slab.h>
> > > +
> > > +struct codetag_type {
> > > +     struct list_head link;
> > > +     unsigned int count;
> > > +     struct idr mod_idr;
> > > +     struct rw_semaphore mod_lock; /* protects mod_idr */
> > > +     struct codetag_type_desc desc;
> > > +};
> > > +
> > > +static DEFINE_MUTEX(codetag_lock);
> > > +static LIST_HEAD(codetag_types);
> > > +
> > > +void codetag_lock_module_list(struct codetag_type *cttype, bool lock=
)
> > > +{
> > > +     if (lock)
> > > +             down_read(&cttype->mod_lock);
> > > +     else
> > > +             up_read(&cttype->mod_lock);
> > > +}
> > > +
> > > +struct codetag_iterator codetag_get_ct_iter(struct codetag_type *ctt=
ype)
> > > +{
> > > +     struct codetag_iterator iter =3D {
> > > +             .cttype =3D cttype,
> > > +             .cmod =3D NULL,
> > > +             .mod_id =3D 0,
> > > +             .ct =3D NULL,
> > > +     };
> > > +
> > > +     return iter;
> > > +}
> > > +
> > > +static inline struct codetag *get_first_module_ct(struct codetag_mod=
ule *cmod)
> > > +{
> > > +     return cmod->range.start < cmod->range.stop ? cmod->range.start=
 : NULL;
> > > +}
> > > +
> > > +static inline
> > > +struct codetag *get_next_module_ct(struct codetag_iterator *iter)
> > > +{
> > > +     struct codetag *res =3D (struct codetag *)
> > > +                     ((char *)iter->ct + iter->cttype->desc.tag_size=
);
> > > +
> > > +     return res < iter->cmod->range.stop ? res : NULL;
> > > +}
> > > +
> > > +struct codetag *codetag_next_ct(struct codetag_iterator *iter)
> > > +{
> > > +     struct codetag_type *cttype =3D iter->cttype;
> > > +     struct codetag_module *cmod;
> > > +     struct codetag *ct;
> > > +
> > > +     lockdep_assert_held(&cttype->mod_lock);
> > > +
> > > +     if (unlikely(idr_is_empty(&cttype->mod_idr)))
> > > +             return NULL;
> > > +
> > > +     ct =3D NULL;
> > > +     while (true) {
> > > +             cmod =3D idr_find(&cttype->mod_idr, iter->mod_id);
> > > +
> > > +             /* If module was removed move to the next one */
> > > +             if (!cmod)
> > > +                     cmod =3D idr_get_next_ul(&cttype->mod_idr,
> > > +                                            &iter->mod_id);
> > > +
> > > +             /* Exit if no more modules */
> > > +             if (!cmod)
> > > +                     break;
> > > +
> > > +             if (cmod !=3D iter->cmod) {
> > > +                     iter->cmod =3D cmod;
> > > +                     ct =3D get_first_module_ct(cmod);
> > > +             } else
> > > +                     ct =3D get_next_module_ct(iter);
> > > +
> > > +             if (ct)
> > > +                     break;
> > > +
> > > +             iter->mod_id++;
> > > +     }
> > > +
> > > +     iter->ct =3D ct;
> > > +     return ct;
> > > +}
> > > +
> > > +void codetag_to_text(struct seq_buf *out, struct codetag *ct)
> > > +{
> > > +     seq_buf_printf(out, "%s:%u module:%s func:%s",
> > > +                    ct->filename, ct->lineno,
> > > +                    ct->modname, ct->function);
> > > +}
> >
> > Thank you for using seq_buf here!
> >
> > Also, will this need an EXPORT_SYMBOL_GPL()?

Missed this question. I don't think we need EXPORT_SYMBOL_GPL() here
at least for now. Modules don't use these functions. The "alloc_tags"
sections will be generated for each module at compile time but they
themselves do not use it.

> >
> > > +
> > > +static inline size_t range_size(const struct codetag_type *cttype,
> > > +                             const struct codetag_range *range)
> > > +{
> > > +     return ((char *)range->stop - (char *)range->start) /
> > > +                     cttype->desc.tag_size;
> > > +}
> > > +
> > > +static void *get_symbol(struct module *mod, const char *prefix, cons=
t char *name)
> > > +{
> > > +     char buf[64];
> >
> > Why is 64 enough? I was expecting KSYM_NAME_LEN here, but perhaps this
> > is specialized enough to section names that it will not be a problem?
>
> This buffer is being used to hold the name of the section containing
> codetags appended with "__start_" or "__stop_" and the only current
> user is alloc_tag_init() which sets the section name to "alloc_tags".
> So, this buffer currently holds either "alloc_tags__start_" or
> "alloc_tags__stop_". When more codetag applications are added (like
> the ones we have shown in the original RFC [1]), there would be more
> section names. 64 was chosen as a big enough value to reasonably hold
> the section name with the suffix. But you are right, we should add a
> check for the section name size to ensure it always fits. Will add
> into my TODO list.
>
> [1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.com/
> > If so, please document it clearly with a comment.
>
> Will do.
>
> >
> > > +     int res;
> > > +
> > > +     res =3D snprintf(buf, sizeof(buf), "%s%s", prefix, name);
> > > +     if (WARN_ON(res < 1 || res > sizeof(buf)))
> > > +             return NULL;
> >
> > Please use a seq_buf here instead of snprintf, which we're trying to ge=
t
> > rid of.
> >
> >         DECLARE_SEQ_BUF(sb, KSYM_NAME_LEN);
> >         char *buf;
> >
> >         seq_buf_printf(sb, "%s%s", prefix, name);
> >         if (seq_buf_has_overflowed(sb))
> >                 return NULL;
> >
> >         buf =3D seq_buf_str(sb);
>
> Will do. Thanks!
>
> >
> > > +
> > > +     return mod ?
> > > +             (void *)find_kallsyms_symbol_value(mod, buf) :
> > > +             (void *)kallsyms_lookup_name(buf);
> > > +}
> > > +
> > > +static struct codetag_range get_section_range(struct module *mod,
> > > +                                           const char *section)
> > > +{
> > > +     return (struct codetag_range) {
> > > +             get_symbol(mod, "__start_", section),
> > > +             get_symbol(mod, "__stop_", section),
> > > +     };
> > > +}
> > > +
> > > +static int codetag_module_init(struct codetag_type *cttype, struct m=
odule *mod)
> > > +{
> > > +     struct codetag_range range;
> > > +     struct codetag_module *cmod;
> > > +     int err;
> > > +
> > > +     range =3D get_section_range(mod, cttype->desc.section);
> > > +     if (!range.start || !range.stop) {
> > > +             pr_warn("Failed to load code tags of type %s from the m=
odule %s\n",
> > > +                     cttype->desc.section,
> > > +                     mod ? mod->name : "(built-in)");
> > > +             return -EINVAL;
> > > +     }
> > > +
> > > +     /* Ignore empty ranges */
> > > +     if (range.start =3D=3D range.stop)
> > > +             return 0;
> > > +
> > > +     BUG_ON(range.start > range.stop);
> > > +
> > > +     cmod =3D kmalloc(sizeof(*cmod), GFP_KERNEL);
> > > +     if (unlikely(!cmod))
> > > +             return -ENOMEM;
> > > +
> > > +     cmod->mod =3D mod;
> > > +     cmod->range =3D range;
> > > +
> > > +     down_write(&cttype->mod_lock);
> > > +     err =3D idr_alloc(&cttype->mod_idr, cmod, 0, 0, GFP_KERNEL);
> > > +     if (err >=3D 0)
> > > +             cttype->count +=3D range_size(cttype, &range);
> > > +     up_write(&cttype->mod_lock);
> > > +
> > > +     if (err < 0) {
> > > +             kfree(cmod);
> > > +             return err;
> > > +     }
> > > +
> > > +     return 0;
> > > +}
> > > +
> > > +struct codetag_type *
> > > +codetag_register_type(const struct codetag_type_desc *desc)
> > > +{
> > > +     struct codetag_type *cttype;
> > > +     int err;
> > > +
> > > +     BUG_ON(desc->tag_size <=3D 0);
> > > +
> > > +     cttype =3D kzalloc(sizeof(*cttype), GFP_KERNEL);
> > > +     if (unlikely(!cttype))
> > > +             return ERR_PTR(-ENOMEM);
> > > +
> > > +     cttype->desc =3D *desc;
> > > +     idr_init(&cttype->mod_idr);
> > > +     init_rwsem(&cttype->mod_lock);
> > > +
> > > +     err =3D codetag_module_init(cttype, NULL);
> > > +     if (unlikely(err)) {
> > > +             kfree(cttype);
> > > +             return ERR_PTR(err);
> > > +     }
> > > +
> > > +     mutex_lock(&codetag_lock);
> > > +     list_add_tail(&cttype->link, &codetag_types);
> > > +     mutex_unlock(&codetag_lock);
> > > +
> > > +     return cttype;
> > > +}
> > > --
> > > 2.43.0.687.g38aa6559b0-goog
> > >
> >
> > --
> > Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpF3ZHkuBejRp_2BBcC-Lp8achfaosVu0SfBNAA0Y27%2BvA%40mail.gmai=
l.com.
