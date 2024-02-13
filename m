Return-Path: <kasan-dev+bncBC7OD3FKWUERBUM4VOXAMGQETM7IG5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4494F852739
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 03:05:07 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-295aaffe58bsf4495068a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 18:05:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707789906; cv=pass;
        d=google.com; s=arc-20160816;
        b=NmjaEjr0JriBUQqHOXgvYDXpboIJBQDM1zUJXf98ybi2T9iS1se7J0JRFK3fleP+dZ
         9GFDxsc1ato7nfhOE4ZU4dz/AjAYjBtpoQaGrrsPyuSk9LEt+mSt8SmLvGN2QSDUSsSL
         Gkwmbghmi4dY8imyCI41gLse/nCLbtaO4/5DEMuiijV+u+rkTnF3S4KWpCkc2UvZ/nVW
         gwvAfyywnJ0//SNLUHQHGvkk9EgMfURSn0MByUaIJHXS3H8VCBxYPiZj5JhYPHgOTBrg
         nmH3kdTcwnKFs184EU2K9YlIXWUqpF/E4O5ejoVWyuPiASWyBeRnNb5JCRrI2B3777FP
         Gidw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5gvhMVhhUa+ebuoQKIuN/aLBIWrOpywtuQ8+ug8TTCU=;
        fh=I+kGjNpQIdDM+gMak8Jqmz5Og66liRC89oCDNSPk9MM=;
        b=UjMmKvnaGs8/NnbpXAz+K+qiz21Aymk2gR+Xl8DI2abUGciCPYCyuUivCCvBSuCCk/
         HFEAT8pUffkAR3Ct4FTGLAxI6WL9bdHOKS9a6b9Ox0rxzn89FVc9u4sIDCTFv7DOeC++
         z2M4hPM1sHFCtoZCTreBYYLfjRR4fAAGI9fJTFeonAJsabZsDLwBX3jJ5fK6c+0jnEzn
         V/4T4qXV5rze+aezn8544JvMfYHnlVC1EeNPzpZmzcrIP8tYjW05so0b4AsxERtBSVGi
         EYhqptK7Aekppt6keTJDmqQLDbQEZVQruKP++IOwJETFV01dder6dPqMFzeULQXJGMq7
         COyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OdKAN8Y3;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707789906; x=1708394706; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5gvhMVhhUa+ebuoQKIuN/aLBIWrOpywtuQ8+ug8TTCU=;
        b=TzoQO8it5Gv+4/SZZpc7tpR1d0IahjF5Yc75wnU/eD0FPZFllLmALxiL/XXIbJclzv
         Zc9tH7F6SEv0Fvq0a9BqjbJGSZuNaX67nElJ5Ke540ycZ3ZNk4ZfnnpapYUeUtUAxZk0
         tueACKK/DkQEdXv9QulEWHcbDqWt8nUsxsUgxTlTHb5LQ4A9bnEI6v4Q4LtHpjGUxx8u
         mNG0DZnLWTGG+fgr2+a09/0eGq0A4vqeebhSJdyIfm3Sfd+dK8QF5ke3oC9VMTpD4Kl/
         X3lIzipZCgcv+p0pcf3nn2QYlkgLwtJZCU08eD+HExgd5ZjpGxnGDVNnVCdzj7hNJPlo
         26Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707789906; x=1708394706;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5gvhMVhhUa+ebuoQKIuN/aLBIWrOpywtuQ8+ug8TTCU=;
        b=Ni+CWQlI6+Pu9gxRznVT1aYpZ6OA/Its55eEJ37kltYYwsGo/oIBVxpqIsMrn0dXML
         Hp9jgih4uuhDiWu2NwIM2UR/XmfJxw6dZhcI3IQFOk4wnhCRksy3xjBfcXDExbRw8p56
         LmqjXUE5MdOhQ1oS6EZHuUh0RFgcTwpLoeKLrsZVobk8gwwIy2hNeeEvsRRn+y5kecwK
         Jy3zI3KbsWMikHpwuuZlBcy4UZ9n2g7QbOl83IfZkeyGSxaW+DEzUSLOqTV9j3VHOaNE
         gOCtBHvYiVDLjCI1E1A/TDoscpcrUXMRlTL1jF2M1dZC11H+zcUW7UlJ7OT+z6XU2Xdb
         L8Tg==
X-Gm-Message-State: AOJu0YwLygYeQ+fMBDxnjy9/tk2Dvrbfzr51I/HsrMSG/YQ+FcSO3V8l
	ETRK03jHSxClZxpwZ9UQcvEvFvtX0RSvYX6+kdriFSTpGTrfccWk
X-Google-Smtp-Source: AGHT+IGZmduUO2ieQCJ9ix3VCX9L8vPf7mchPCNgbbxH8yT/HBVYWT8ibw7tyd5nlm6yEdb2VfthFg==
X-Received: by 2002:a17:90a:7786:b0:297:2abd:cf54 with SMTP id v6-20020a17090a778600b002972abdcf54mr1714381pjk.5.1707789905679;
        Mon, 12 Feb 2024 18:05:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b908:b0:295:f338:440 with SMTP id
 p8-20020a17090ab90800b00295f3380440ls2519405pjr.2.-pod-prod-00-us-canary;
 Mon, 12 Feb 2024 18:05:04 -0800 (PST)
X-Received: by 2002:a17:903:40c1:b0:1da:2c01:fef3 with SMTP id t1-20020a17090340c100b001da2c01fef3mr1913799pld.5.1707789904572;
        Mon, 12 Feb 2024 18:05:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707789904; cv=none;
        d=google.com; s=arc-20160816;
        b=mNQYnbRgquZgywHjD27C5DMRT91ffULXF1u7dfYL1d85jlB32GQSrW2GPyaZKWGcd6
         0SuOKYaxG0cKDw8caeqrN9kGJI0M2Taw1Tqi9ShCepcYqk9bood8rHkmRMaJ0gezU64p
         FMgmrKCVmDbCfNltehShEGxbnTcakzKm+gYy9QOBOTx6nC5xWlcyFliopEJ9DPaF6p6X
         lGLn1lqnexAW0l37PVg+3VZfmDSdmtRS/hI3/2mdJfVeLNZ9q9TVWcwD+1FTcc2eEQvX
         SNIxgQT9lVkkjVTjybI7cuVXsgFVnWddyfLWS1uMXLmFgdh/5AGO6etXONiHRhzuYjK6
         vs0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=t18iwUPgrIMFqF00PxZ8iIKrNS4wENWkpnpySINaofY=;
        fh=I+kGjNpQIdDM+gMak8Jqmz5Og66liRC89oCDNSPk9MM=;
        b=pyW0sO1DPRgjHkycCUwJLYuPXRsO0abBnKxkKGp4IgQZ9nqz+JazIvUhyUzb7+RPTO
         Vf2KAY8zMyVhSo3eJ/dRlEOfkaRbND/y+Ya7VbXF1M6FqXFuPrdTu5+L+s7iLrh0pT0B
         PzmZYRGSfGWdUu2aBXRHlv34EhvybD60n6Oc9GXOTdDN4dCteqTggnyYQbUI5FMqLeC5
         Dnx4LcOFeMTBeUC4ceclLFobOCF0mxWXcKuqtSmlBA55FO5J/W4Dw/O7wjM76PWTUCmn
         Bl8wsnQJOCs0VfCFucSRRNvkZjEOEAn7yQUGNxrey9+waXq0CLT/kh+AN3o7deU93K5K
         ptfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OdKAN8Y3;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUMNr0FShq2X4hqEjXn45HFyLS9w2MgI020B6f2xXjupkpia9uOCp60fEXxv6G5ICgU4n5wU7a8Zz/x/1+9GWOGRbxV1jxd14n+qQ==
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id kj7-20020a17090306c700b001d8cea8344bsi117975plb.7.2024.02.12.18.05.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 18:05:04 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-dbed179f0faso3411336276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 18:05:04 -0800 (PST)
X-Received: by 2002:a25:dc06:0:b0:dc6:d1a9:d858 with SMTP id
 y6-20020a25dc06000000b00dc6d1a9d858mr1004949ybe.8.1707789903306; Mon, 12 Feb
 2024 18:05:03 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-11-surenb@google.com>
 <202402121419.7C4AAF27ED@keescook>
In-Reply-To: <202402121419.7C4AAF27ED@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Feb 2024 18:04:51 -0800
Message-ID: <CAJuCfpFpKKqCtU2EJM28fbYRYUbBLR9XuDONmS21zeTc2Z6nxw@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=OdKAN8Y3;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Feb 12, 2024 at 2:27=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Mon, Feb 12, 2024 at 01:38:56PM -0800, Suren Baghdasaryan wrote:
> > Add basic infrastructure to support code tagging which stores tag commo=
n
> > information consisting of the module name, function, file name and line
> > number. Provide functions to register a new code tag type and navigate
> > between code tags.
> >
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  include/linux/codetag.h |  71 ++++++++++++++
> >  lib/Kconfig.debug       |   4 +
> >  lib/Makefile            |   1 +
> >  lib/codetag.c           | 199 ++++++++++++++++++++++++++++++++++++++++
> >  4 files changed, 275 insertions(+)
> >  create mode 100644 include/linux/codetag.h
> >  create mode 100644 lib/codetag.c
> >
> > diff --git a/include/linux/codetag.h b/include/linux/codetag.h
> > new file mode 100644
> > index 000000000000..a9d7adecc2a5
> > --- /dev/null
> > +++ b/include/linux/codetag.h
> > @@ -0,0 +1,71 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +/*
> > + * code tagging framework
> > + */
> > +#ifndef _LINUX_CODETAG_H
> > +#define _LINUX_CODETAG_H
> > +
> > +#include <linux/types.h>
> > +
> > +struct codetag_iterator;
> > +struct codetag_type;
> > +struct seq_buf;
> > +struct module;
> > +
> > +/*
> > + * An instance of this structure is created in a special ELF section a=
t every
> > + * code location being tagged.  At runtime, the special section is tre=
ated as
> > + * an array of these.
> > + */
> > +struct codetag {
> > +     unsigned int flags; /* used in later patches */
> > +     unsigned int lineno;
> > +     const char *modname;
> > +     const char *function;
> > +     const char *filename;
> > +} __aligned(8);
> > +
> > +union codetag_ref {
> > +     struct codetag *ct;
> > +};
> > +
> > +struct codetag_range {
> > +     struct codetag *start;
> > +     struct codetag *stop;
> > +};
> > +
> > +struct codetag_module {
> > +     struct module *mod;
> > +     struct codetag_range range;
> > +};
> > +
> > +struct codetag_type_desc {
> > +     const char *section;
> > +     size_t tag_size;
> > +};
> > +
> > +struct codetag_iterator {
> > +     struct codetag_type *cttype;
> > +     struct codetag_module *cmod;
> > +     unsigned long mod_id;
> > +     struct codetag *ct;
> > +};
> > +
> > +#define CODE_TAG_INIT {                                      \
> > +     .modname        =3D KBUILD_MODNAME,               \
> > +     .function       =3D __func__,                     \
> > +     .filename       =3D __FILE__,                     \
> > +     .lineno         =3D __LINE__,                     \
> > +     .flags          =3D 0,                            \
> > +}
> > +
> > +void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
> > +struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttyp=
e);
> > +struct codetag *codetag_next_ct(struct codetag_iterator *iter);
> > +
> > +void codetag_to_text(struct seq_buf *out, struct codetag *ct);
> > +
> > +struct codetag_type *
> > +codetag_register_type(const struct codetag_type_desc *desc);
> > +
> > +#endif /* _LINUX_CODETAG_H */
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 975a07f9f1cc..0be2d00c3696 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -968,6 +968,10 @@ config DEBUG_STACKOVERFLOW
> >
> >         If in doubt, say "N".
> >
> > +config CODE_TAGGING
> > +     bool
> > +     select KALLSYMS
> > +
> >  source "lib/Kconfig.kasan"
> >  source "lib/Kconfig.kfence"
> >  source "lib/Kconfig.kmsan"
> > diff --git a/lib/Makefile b/lib/Makefile
> > index 6b09731d8e61..6b48b22fdfac 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -235,6 +235,7 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) +=
=3D \
> >       of-reconfig-notifier-error-inject.o
> >  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) +=3D error-inject.o
> >
> > +obj-$(CONFIG_CODE_TAGGING) +=3D codetag.o
> >  lib-$(CONFIG_GENERIC_BUG) +=3D bug.o
> >
> >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) +=3D syscall.o
> > diff --git a/lib/codetag.c b/lib/codetag.c
> > new file mode 100644
> > index 000000000000..7708f8388e55
> > --- /dev/null
> > +++ b/lib/codetag.c
> > @@ -0,0 +1,199 @@
> > +// SPDX-License-Identifier: GPL-2.0-only
> > +#include <linux/codetag.h>
> > +#include <linux/idr.h>
> > +#include <linux/kallsyms.h>
> > +#include <linux/module.h>
> > +#include <linux/seq_buf.h>
> > +#include <linux/slab.h>
> > +
> > +struct codetag_type {
> > +     struct list_head link;
> > +     unsigned int count;
> > +     struct idr mod_idr;
> > +     struct rw_semaphore mod_lock; /* protects mod_idr */
> > +     struct codetag_type_desc desc;
> > +};
> > +
> > +static DEFINE_MUTEX(codetag_lock);
> > +static LIST_HEAD(codetag_types);
> > +
> > +void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
> > +{
> > +     if (lock)
> > +             down_read(&cttype->mod_lock);
> > +     else
> > +             up_read(&cttype->mod_lock);
> > +}
> > +
> > +struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttyp=
e)
> > +{
> > +     struct codetag_iterator iter =3D {
> > +             .cttype =3D cttype,
> > +             .cmod =3D NULL,
> > +             .mod_id =3D 0,
> > +             .ct =3D NULL,
> > +     };
> > +
> > +     return iter;
> > +}
> > +
> > +static inline struct codetag *get_first_module_ct(struct codetag_modul=
e *cmod)
> > +{
> > +     return cmod->range.start < cmod->range.stop ? cmod->range.start :=
 NULL;
> > +}
> > +
> > +static inline
> > +struct codetag *get_next_module_ct(struct codetag_iterator *iter)
> > +{
> > +     struct codetag *res =3D (struct codetag *)
> > +                     ((char *)iter->ct + iter->cttype->desc.tag_size);
> > +
> > +     return res < iter->cmod->range.stop ? res : NULL;
> > +}
> > +
> > +struct codetag *codetag_next_ct(struct codetag_iterator *iter)
> > +{
> > +     struct codetag_type *cttype =3D iter->cttype;
> > +     struct codetag_module *cmod;
> > +     struct codetag *ct;
> > +
> > +     lockdep_assert_held(&cttype->mod_lock);
> > +
> > +     if (unlikely(idr_is_empty(&cttype->mod_idr)))
> > +             return NULL;
> > +
> > +     ct =3D NULL;
> > +     while (true) {
> > +             cmod =3D idr_find(&cttype->mod_idr, iter->mod_id);
> > +
> > +             /* If module was removed move to the next one */
> > +             if (!cmod)
> > +                     cmod =3D idr_get_next_ul(&cttype->mod_idr,
> > +                                            &iter->mod_id);
> > +
> > +             /* Exit if no more modules */
> > +             if (!cmod)
> > +                     break;
> > +
> > +             if (cmod !=3D iter->cmod) {
> > +                     iter->cmod =3D cmod;
> > +                     ct =3D get_first_module_ct(cmod);
> > +             } else
> > +                     ct =3D get_next_module_ct(iter);
> > +
> > +             if (ct)
> > +                     break;
> > +
> > +             iter->mod_id++;
> > +     }
> > +
> > +     iter->ct =3D ct;
> > +     return ct;
> > +}
> > +
> > +void codetag_to_text(struct seq_buf *out, struct codetag *ct)
> > +{
> > +     seq_buf_printf(out, "%s:%u module:%s func:%s",
> > +                    ct->filename, ct->lineno,
> > +                    ct->modname, ct->function);
> > +}
>
> Thank you for using seq_buf here!
>
> Also, will this need an EXPORT_SYMBOL_GPL()?
>
> > +
> > +static inline size_t range_size(const struct codetag_type *cttype,
> > +                             const struct codetag_range *range)
> > +{
> > +     return ((char *)range->stop - (char *)range->start) /
> > +                     cttype->desc.tag_size;
> > +}
> > +
> > +static void *get_symbol(struct module *mod, const char *prefix, const =
char *name)
> > +{
> > +     char buf[64];
>
> Why is 64 enough? I was expecting KSYM_NAME_LEN here, but perhaps this
> is specialized enough to section names that it will not be a problem?

This buffer is being used to hold the name of the section containing
codetags appended with "__start_" or "__stop_" and the only current
user is alloc_tag_init() which sets the section name to "alloc_tags".
So, this buffer currently holds either "alloc_tags__start_" or
"alloc_tags__stop_". When more codetag applications are added (like
the ones we have shown in the original RFC [1]), there would be more
section names. 64 was chosen as a big enough value to reasonably hold
the section name with the suffix. But you are right, we should add a
check for the section name size to ensure it always fits. Will add
into my TODO list.

[1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.com/
> If so, please document it clearly with a comment.

Will do.

>
> > +     int res;
> > +
> > +     res =3D snprintf(buf, sizeof(buf), "%s%s", prefix, name);
> > +     if (WARN_ON(res < 1 || res > sizeof(buf)))
> > +             return NULL;
>
> Please use a seq_buf here instead of snprintf, which we're trying to get
> rid of.
>
>         DECLARE_SEQ_BUF(sb, KSYM_NAME_LEN);
>         char *buf;
>
>         seq_buf_printf(sb, "%s%s", prefix, name);
>         if (seq_buf_has_overflowed(sb))
>                 return NULL;
>
>         buf =3D seq_buf_str(sb);

Will do. Thanks!

>
> > +
> > +     return mod ?
> > +             (void *)find_kallsyms_symbol_value(mod, buf) :
> > +             (void *)kallsyms_lookup_name(buf);
> > +}
> > +
> > +static struct codetag_range get_section_range(struct module *mod,
> > +                                           const char *section)
> > +{
> > +     return (struct codetag_range) {
> > +             get_symbol(mod, "__start_", section),
> > +             get_symbol(mod, "__stop_", section),
> > +     };
> > +}
> > +
> > +static int codetag_module_init(struct codetag_type *cttype, struct mod=
ule *mod)
> > +{
> > +     struct codetag_range range;
> > +     struct codetag_module *cmod;
> > +     int err;
> > +
> > +     range =3D get_section_range(mod, cttype->desc.section);
> > +     if (!range.start || !range.stop) {
> > +             pr_warn("Failed to load code tags of type %s from the mod=
ule %s\n",
> > +                     cttype->desc.section,
> > +                     mod ? mod->name : "(built-in)");
> > +             return -EINVAL;
> > +     }
> > +
> > +     /* Ignore empty ranges */
> > +     if (range.start =3D=3D range.stop)
> > +             return 0;
> > +
> > +     BUG_ON(range.start > range.stop);
> > +
> > +     cmod =3D kmalloc(sizeof(*cmod), GFP_KERNEL);
> > +     if (unlikely(!cmod))
> > +             return -ENOMEM;
> > +
> > +     cmod->mod =3D mod;
> > +     cmod->range =3D range;
> > +
> > +     down_write(&cttype->mod_lock);
> > +     err =3D idr_alloc(&cttype->mod_idr, cmod, 0, 0, GFP_KERNEL);
> > +     if (err >=3D 0)
> > +             cttype->count +=3D range_size(cttype, &range);
> > +     up_write(&cttype->mod_lock);
> > +
> > +     if (err < 0) {
> > +             kfree(cmod);
> > +             return err;
> > +     }
> > +
> > +     return 0;
> > +}
> > +
> > +struct codetag_type *
> > +codetag_register_type(const struct codetag_type_desc *desc)
> > +{
> > +     struct codetag_type *cttype;
> > +     int err;
> > +
> > +     BUG_ON(desc->tag_size <=3D 0);
> > +
> > +     cttype =3D kzalloc(sizeof(*cttype), GFP_KERNEL);
> > +     if (unlikely(!cttype))
> > +             return ERR_PTR(-ENOMEM);
> > +
> > +     cttype->desc =3D *desc;
> > +     idr_init(&cttype->mod_idr);
> > +     init_rwsem(&cttype->mod_lock);
> > +
> > +     err =3D codetag_module_init(cttype, NULL);
> > +     if (unlikely(err)) {
> > +             kfree(cttype);
> > +             return ERR_PTR(err);
> > +     }
> > +
> > +     mutex_lock(&codetag_lock);
> > +     list_add_tail(&cttype->link, &codetag_types);
> > +     mutex_unlock(&codetag_lock);
> > +
> > +     return cttype;
> > +}
> > --
> > 2.43.0.687.g38aa6559b0-goog
> >
>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFpKKqCtU2EJM28fbYRYUbBLR9XuDONmS21zeTc2Z6nxw%40mail.gmail.=
com.
