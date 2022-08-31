Return-Path: <kasan-dev+bncBC7OD3FKWUERB6UGX2MAMGQEJVSW3HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B015A8238
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 17:51:23 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id b19-20020a9d6b93000000b00637113961absf7704289otq.5
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 08:51:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661961082; cv=pass;
        d=google.com; s=arc-20160816;
        b=GsXvfp8AM4K/y9iPbWx1axf4RaSkPcFZkidq366IWSznbWbHutQPy8g3adGhpThhgc
         pffxlPtnLg8zrF/Y4YimLa7A/PVDn3V2hG8mTQQTERkrj4bR7Evdt1ZwClBu1pEF8UPP
         c+gTdZi9EHZ/NnLm+X0ZBSrIctpBdO5cr1C1PDZQ70Lbx5rZiMfMlvwK9dOxStp411oZ
         zlraNLolF8R5zknFJQ1rGAIYdQ+b+lXisx3RofeGaGPpp6bPVLy1LbDw8F0adfSlfSeX
         7mSbb/7uEokZpEWWsfZZXooRsDfEjs40PHLkCdEwmF7bx9VpME5XL8XH6hSyh4eZ9IM5
         h1og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bQXVSCZQypozjq8qiTXT5Ba8la1EEgbvDKe5kHhrV7c=;
        b=cWqxtgxTaDtckxf5KwjAYeLvdA1xnvqJYcpH6J62yNFIJ3dLW3ZqWKa5N+EITMxpCA
         Z4WxoM5TH/W97SctZpMnWKp0+ZBQf9eiJg2+di2xqXbFlENyLhOOPjTk9wgiitxOp2XL
         4JAbaqj+QHRLr44mt3vj6VH7f8OLG14d+RtTSWK5Nkwg+iVRYl/zUdytfjH2Q0xln+KI
         Yf7h3HEF5UY8emA3gWUvWKr2WEjhg+StC5woV4sX+4BpZGvTVXOWZVd5YuRp3Zsv6Qbi
         zzfdKdOKKgbW6TXeEHRaRJhYOvd5yWF5M6Y5sGyE33GxJcS3OkBZnqQwNY7HexQkVcAi
         lPyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Gmi2UWcv;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=bQXVSCZQypozjq8qiTXT5Ba8la1EEgbvDKe5kHhrV7c=;
        b=CfG7w2IK2uQUjshk5ZgbGRZDvnt0Mw7+5GzMw5rSodLjYrJz09luNOyfLlwbJcR9Vm
         SMs1kIchgFdfzHjfGPxsYgNC0ybTS76tMDqmFEvlEXJh0bkZdYbuYDT/XJiWxhHcAfUe
         v9wGcPyxVhn/cTaNScShToyQa9vmSIZMS7jV34BSD5Fs3CTlgcNTLn+NVSZQn9eCLDMw
         +R4mYVAkJpGJVDtHdqVrGxmwqypoRqSCMiFdUswT2HQr83n9zcCWx/F3MMF56cJmseSM
         ZXMKku5G5In0B4hQs0onXU3XAClij1brgI8YQhd9RFR4suUJFLcEM4k0a9pBL0lzP3NK
         XcsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=bQXVSCZQypozjq8qiTXT5Ba8la1EEgbvDKe5kHhrV7c=;
        b=Ju7Oohc4JlAhHbG3IZpXDKOfZbvTpuz+flTvpIMZIGENM8s8GhTOMr0CaeZO4Q7TJi
         vc00A3NhJ8fjjtUbCm16k3qdc0NT/WcJqAZuASOi7dKLG7icGPJ+MtAs0E8V+WzRPL5N
         E9piR/P9DKNju6LXnOR8owkHnCPH1VcPZ7StZQwYjBdgVcg6L9Sc1wMchmSYmFTVt5ZJ
         U4go/0jf0nTUppiP9JL4+p59E8Traf7OsUQkrGgqzt7mn+799LceypFvqi9GDnD2czdR
         MyNnmrEykCLBXVtJytHrephjF1ZtIhDN2Bw/olSxHC8Fb/s6NEJO6rwbH3Vy47/w+41Y
         XRrQ==
X-Gm-Message-State: ACgBeo1vXTBP1RvsUGquE7OlpwISJ/1pbkf5jyCUzqCgAVZA23IWTIqe
	PrscPc4JpVOPIvyCUNU34j8=
X-Google-Smtp-Source: AA6agR4u3KhrZ0njK7WHmbeQbGPlNeJ9JVmB3zuxmQkD9qQDpD8Fjj33cD1TBuThOOyvCw/ngMsilw==
X-Received: by 2002:a05:6870:2197:b0:11c:f898:c995 with SMTP id l23-20020a056870219700b0011cf898c995mr1770074oae.216.1661961082261;
        Wed, 31 Aug 2022 08:51:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:770d:b0:11e:47d1:a33a with SMTP id
 dw13-20020a056870770d00b0011e47d1a33als443802oab.11.-pod-prod-gmail; Wed, 31
 Aug 2022 08:51:21 -0700 (PDT)
X-Received: by 2002:a05:6870:a78e:b0:10d:9e12:ba09 with SMTP id x14-20020a056870a78e00b0010d9e12ba09mr1770268oao.288.1661961081845;
        Wed, 31 Aug 2022 08:51:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661961081; cv=none;
        d=google.com; s=arc-20160816;
        b=fcVbyqo+22HymUlMZanNE1J+51xOxEu8KrZvYLmemW5Jgbu1nf5Gm9PHFW1SUl/4KN
         1z5Vhp9yg1qLuFQhsZhDZg9RtkDWVJbxpsBwMg9J8xnqRMQRkg9IwpAQCzRpeP5HOO3i
         xMkhXXrsXmjjcNYyaRjO1J4T2ryk6o7dB9fq3FO4pwyUkYcB7pBIEVIcgUVgJOaMCtAQ
         CAfBR8zMUDbAYKCrHb1qKHtky7hd0lwK8znylrxj0vb/+K08GWnowyR2Urlt+YGiE3xb
         IB2MqF9m9T1rE2yvzoekc3LiR/tU5p5IbgHdGKzXErroHEin+QTEgF0gKTmeq6mB5crf
         6cgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3PvMR/XycqORFlizT6CxByuKDuIxggxJlBTQLJTuWPk=;
        b=GQGUkWzdPL3VIGm9Ng0qIZctxOLvwYDQPMSV0GWPMPmH/noo8rCShSGddCsmg0fc/s
         yHCBlBhGRlC2wkgybA7i+Zv+rwN+rg+Elknbhgo+23LjCsEvC1oMKZt7Qq7g5wW5bWzv
         /qy5cLCcIb/C8WLWGHvXfiYU3uhMRkFe6rZ1qS9lPmO4NODe44DPmVvAb2oXOt57qaKB
         EOrUsxFfNPLtTnB0jgmhsYOApQNvcW9KMWlnGDTAk3VzX6OUqSqkKNIVR17LF65SZ3O0
         DrwL25W3uQw+owUH3S4EIhqMgicK18r4XrOcGZEo7888bNfrG/195Id5d2luuYFTk2aV
         nj7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Gmi2UWcv;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id u18-20020a056870f29200b0011ca4383bd6si1617948oap.4.2022.08.31.08.51.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 08:51:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-33dc345ad78so311411547b3.3
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 08:51:21 -0700 (PDT)
X-Received: by 2002:a0d:cd02:0:b0:341:a401:4630 with SMTP id
 p2-20020a0dcd02000000b00341a4014630mr4588576ywd.293.1661961081082; Wed, 31
 Aug 2022 08:51:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-23-surenb@google.com>
 <CACT4Y+ZX3U1=cAPXPhoOy6xrngSCfSmyFagXK-9fWtWWODfsew@mail.gmail.com>
In-Reply-To: <CACT4Y+ZX3U1=cAPXPhoOy6xrngSCfSmyFagXK-9fWtWWODfsew@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 08:51:10 -0700
Message-ID: <CAJuCfpEQJe7HiNXhv+fH3auvr_-M6VpxhgWTj9q6e5GLkd+8Uw@mail.gmail.com>
Subject: Re: [RFC PATCH 22/30] Code tagging based fault injection
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Mel Gorman <mgorman@suse.de>, 
	Davidlohr Bueso <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, David Vernet <void@manifault.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com, 
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira <bristot@redhat.com>, 
	Valentin Schneider <vschneid@redhat.com>, Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Gmi2UWcv;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132
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

On Wed, Aug 31, 2022 at 3:37 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, 30 Aug 2022 at 23:50, Suren Baghdasaryan <surenb@google.com> wrote:
> >
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > This adds a new fault injection capability, based on code tagging.
> >
> > To use, simply insert somewhere in your code
> >
> >   dynamic_fault("fault_class_name")
> >
> > and check whether it returns true - if so, inject the error.
> > For example
> >
> >   if (dynamic_fault("init"))
> >       return -EINVAL;
>
> Hi Suren,
>
> If this is going to be used by mainline kernel, it would be good to
> integrate this with fail_nth systematic fault injection:
> https://elixir.bootlin.com/linux/latest/source/lib/fault-inject.c#L109
>
> Otherwise these dynamic sites won't be tested by testing systems doing
> systematic fault injection testing.

Hi Dmitry,
Thanks for the information! Will look into it and try to integrate.
Suren.

>
>
> > There's no need to define faults elsewhere, as with
> > include/linux/fault-injection.h. Faults show up in debugfs, under
> > /sys/kernel/debug/dynamic_faults, and can be selected based on
> > file/module/function/line number/class, and enabled permanently, or in
> > oneshot mode, or with a specified frequency.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > ---
> >  include/asm-generic/codetag.lds.h |   3 +-
> >  include/linux/dynamic_fault.h     |  79 +++++++
> >  include/linux/slab.h              |   3 +-
> >  lib/Kconfig.debug                 |   6 +
> >  lib/Makefile                      |   2 +
> >  lib/dynamic_fault.c               | 372 ++++++++++++++++++++++++++++++
> >  6 files changed, 463 insertions(+), 2 deletions(-)
> >  create mode 100644 include/linux/dynamic_fault.h
> >  create mode 100644 lib/dynamic_fault.c
> >
> > diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
> > index 64f536b80380..16fbf74edc3d 100644
> > --- a/include/asm-generic/codetag.lds.h
> > +++ b/include/asm-generic/codetag.lds.h
> > @@ -9,6 +9,7 @@
> >         __stop_##_name = .;
> >
> >  #define CODETAG_SECTIONS()             \
> > -       SECTION_WITH_BOUNDARIES(alloc_tags)
> > +       SECTION_WITH_BOUNDARIES(alloc_tags)             \
> > +       SECTION_WITH_BOUNDARIES(dynamic_fault_tags)
> >
> >  #endif /* __ASM_GENERIC_CODETAG_LDS_H */
> > diff --git a/include/linux/dynamic_fault.h b/include/linux/dynamic_fault.h
> > new file mode 100644
> > index 000000000000..526a33209e94
> > --- /dev/null
> > +++ b/include/linux/dynamic_fault.h
> > @@ -0,0 +1,79 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +#ifndef _LINUX_DYNAMIC_FAULT_H
> > +#define _LINUX_DYNAMIC_FAULT_H
> > +
> > +/*
> > + * Dynamic/code tagging fault injection:
> > + *
> > + * Originally based on the dynamic debug trick of putting types in a special elf
> > + * section, then rewritten using code tagging:
> > + *
> > + * To use, simply insert a call to dynamic_fault("fault_class"), which will
> > + * return true if an error should be injected.
> > + *
> > + * Fault injection sites may be listed and enabled via debugfs, under
> > + * /sys/kernel/debug/dynamic_faults.
> > + */
> > +
> > +#ifdef CONFIG_CODETAG_FAULT_INJECTION
> > +
> > +#include <linux/codetag.h>
> > +#include <linux/jump_label.h>
> > +
> > +#define DFAULT_STATES()                \
> > +       x(disabled)             \
> > +       x(enabled)              \
> > +       x(oneshot)
> > +
> > +enum dfault_enabled {
> > +#define x(n)   DFAULT_##n,
> > +       DFAULT_STATES()
> > +#undef x
> > +};
> > +
> > +union dfault_state {
> > +       struct {
> > +               unsigned int            enabled:2;
> > +               unsigned int            count:30;
> > +       };
> > +
> > +       struct {
> > +               unsigned int            v;
> > +       };
> > +};
> > +
> > +struct dfault {
> > +       struct codetag          tag;
> > +       const char              *class;
> > +       unsigned int            frequency;
> > +       union dfault_state      state;
> > +       struct static_key_false enabled;
> > +};
> > +
> > +bool __dynamic_fault_enabled(struct dfault *df);
> > +
> > +#define dynamic_fault(_class)                          \
> > +({                                                     \
> > +       static struct dfault                            \
> > +       __used                                          \
> > +       __section("dynamic_fault_tags")                 \
> > +       __aligned(8) df = {                             \
> > +               .tag    = CODE_TAG_INIT,                \
> > +               .class  = _class,                       \
> > +               .enabled = STATIC_KEY_FALSE_INIT,       \
> > +       };                                              \
> > +                                                       \
> > +       static_key_false(&df.enabled.key) &&            \
> > +               __dynamic_fault_enabled(&df);           \
> > +})
> > +
> > +#else
> > +
> > +#define dynamic_fault(_class)  false
> > +
> > +#endif /* CODETAG_FAULT_INJECTION */
> > +
> > +#define memory_fault()         dynamic_fault("memory")
> > +
> > +#endif /* _LINUX_DYNAMIC_FAULT_H */
> > diff --git a/include/linux/slab.h b/include/linux/slab.h
> > index 89273be35743..4be5a93ed15a 100644
> > --- a/include/linux/slab.h
> > +++ b/include/linux/slab.h
> > @@ -17,6 +17,7 @@
> >  #include <linux/types.h>
> >  #include <linux/workqueue.h>
> >  #include <linux/percpu-refcount.h>
> > +#include <linux/dynamic_fault.h>
> >
> >
> >  /*
> > @@ -468,7 +469,7 @@ static inline void slab_tag_dec(const void *ptr) {}
> >
> >  #define krealloc_hooks(_p, _do_alloc)                                  \
> >  ({                                                                     \
> > -       void *_res = _do_alloc;                                         \
> > +       void *_res = !memory_fault() ? _do_alloc : NULL;                \
> >         slab_tag_add(_p, _res);                                         \
> >         _res;                                                           \
> >  })
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 2790848464f1..b7d03afbc808 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -1982,6 +1982,12 @@ config FAULT_INJECTION_STACKTRACE_FILTER
> >         help
> >           Provide stacktrace filter for fault-injection capabilities
> >
> > +config CODETAG_FAULT_INJECTION
> > +       bool "Code tagging based fault injection"
> > +       select CODE_TAGGING
> > +       help
> > +         Dynamic fault injection based on code tagging
> > +
> >  config ARCH_HAS_KCOV
> >         bool
> >         help
> > diff --git a/lib/Makefile b/lib/Makefile
> > index 99f732156673..489ea000c528 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -231,6 +231,8 @@ obj-$(CONFIG_CODE_TAGGING) += codetag.o
> >  obj-$(CONFIG_ALLOC_TAGGING) += alloc_tag.o
> >  obj-$(CONFIG_PAGE_ALLOC_TAGGING) += pgalloc_tag.o
> >
> > +obj-$(CONFIG_CODETAG_FAULT_INJECTION) += dynamic_fault.o
> > +
> >  lib-$(CONFIG_GENERIC_BUG) += bug.o
> >
> >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
> > diff --git a/lib/dynamic_fault.c b/lib/dynamic_fault.c
> > new file mode 100644
> > index 000000000000..4c9cd18686be
> > --- /dev/null
> > +++ b/lib/dynamic_fault.c
> > @@ -0,0 +1,372 @@
> > +// SPDX-License-Identifier: GPL-2.0-only
> > +
> > +#include <linux/ctype.h>
> > +#include <linux/debugfs.h>
> > +#include <linux/dynamic_fault.h>
> > +#include <linux/kernel.h>
> > +#include <linux/module.h>
> > +#include <linux/seq_buf.h>
> > +
> > +static struct codetag_type *cttype;
> > +
> > +bool __dynamic_fault_enabled(struct dfault *df)
> > +{
> > +       union dfault_state old, new;
> > +       unsigned int v = df->state.v;
> > +       bool ret;
> > +
> > +       do {
> > +               old.v = new.v = v;
> > +
> > +               if (new.enabled == DFAULT_disabled)
> > +                       return false;
> > +
> > +               ret = df->frequency
> > +                       ? ++new.count >= df->frequency
> > +                       : true;
> > +               if (ret)
> > +                       new.count = 0;
> > +               if (ret && new.enabled == DFAULT_oneshot)
> > +                       new.enabled = DFAULT_disabled;
> > +       } while ((v = cmpxchg(&df->state.v, old.v, new.v)) != old.v);
> > +
> > +       if (ret)
> > +               pr_debug("returned true for %s:%u", df->tag.filename, df->tag.lineno);
> > +
> > +       return ret;
> > +}
> > +EXPORT_SYMBOL(__dynamic_fault_enabled);
> > +
> > +static const char * const dfault_state_strs[] = {
> > +#define x(n)   #n,
> > +       DFAULT_STATES()
> > +#undef x
> > +       NULL
> > +};
> > +
> > +static void dynamic_fault_to_text(struct seq_buf *out, struct dfault *df)
> > +{
> > +       codetag_to_text(out, &df->tag);
> > +       seq_buf_printf(out, "class:%s %s \"", df->class,
> > +                      dfault_state_strs[df->state.enabled]);
> > +}
> > +
> > +struct dfault_query {
> > +       struct codetag_query q;
> > +
> > +       bool            set_enabled:1;
> > +       unsigned int    enabled:2;
> > +
> > +       bool            set_frequency:1;
> > +       unsigned int    frequency;
> > +};
> > +
> > +/*
> > + * Search the tables for _dfault's which match the given
> > + * `query' and apply the `flags' and `mask' to them.  Tells
> > + * the user which dfault's were changed, or whether none
> > + * were matched.
> > + */
> > +static int dfault_change(struct dfault_query *query)
> > +{
> > +       struct codetag_iterator ct_iter;
> > +       struct codetag *ct;
> > +       unsigned int nfound = 0;
> > +
> > +       codetag_lock_module_list(cttype, true);
> > +       codetag_init_iter(&ct_iter, cttype);
> > +
> > +       while ((ct = codetag_next_ct(&ct_iter))) {
> > +               struct dfault *df = container_of(ct, struct dfault, tag);
> > +
> > +               if (!codetag_matches_query(&query->q, ct, ct_iter.cmod, df->class))
> > +                       continue;
> > +
> > +               if (query->set_enabled &&
> > +                   query->enabled != df->state.enabled) {
> > +                       if (query->enabled != DFAULT_disabled)
> > +                               static_key_slow_inc(&df->enabled.key);
> > +                       else if (df->state.enabled != DFAULT_disabled)
> > +                               static_key_slow_dec(&df->enabled.key);
> > +
> > +                       df->state.enabled = query->enabled;
> > +               }
> > +
> > +               if (query->set_frequency)
> > +                       df->frequency = query->frequency;
> > +
> > +               pr_debug("changed %s:%d [%s]%s #%d %s",
> > +                        df->tag.filename, df->tag.lineno, df->tag.modname,
> > +                        df->tag.function, query->q.cur_index,
> > +                        dfault_state_strs[df->state.enabled]);
> > +
> > +               nfound++;
> > +       }
> > +
> > +       pr_debug("dfault: %u matches", nfound);
> > +
> > +       codetag_lock_module_list(cttype, false);
> > +
> > +       return nfound ? 0 : -ENOENT;
> > +}
> > +
> > +#define DFAULT_TOKENS()                \
> > +       x(disable,      0)      \
> > +       x(enable,       0)      \
> > +       x(oneshot,      0)      \
> > +       x(frequency,    1)
> > +
> > +enum dfault_token {
> > +#define x(name, nr_args)       TOK_##name,
> > +       DFAULT_TOKENS()
> > +#undef x
> > +};
> > +
> > +static const char * const dfault_token_strs[] = {
> > +#define x(name, nr_args)       #name,
> > +       DFAULT_TOKENS()
> > +#undef x
> > +       NULL
> > +};
> > +
> > +static unsigned int dfault_token_nr_args[] = {
> > +#define x(name, nr_args)       nr_args,
> > +       DFAULT_TOKENS()
> > +#undef x
> > +};
> > +
> > +static enum dfault_token str_to_token(const char *word, unsigned int nr_words)
> > +{
> > +       int tok = match_string(dfault_token_strs, ARRAY_SIZE(dfault_token_strs), word);
> > +
> > +       if (tok < 0) {
> > +               pr_debug("unknown keyword \"%s\"", word);
> > +               return tok;
> > +       }
> > +
> > +       if (nr_words < dfault_token_nr_args[tok]) {
> > +               pr_debug("insufficient arguments to \"%s\"", word);
> > +               return -EINVAL;
> > +       }
> > +
> > +       return tok;
> > +}
> > +
> > +static int dfault_parse_command(struct dfault_query *query,
> > +                               enum dfault_token tok,
> > +                               char *words[], size_t nr_words)
> > +{
> > +       unsigned int i = 0;
> > +       int ret;
> > +
> > +       switch (tok) {
> > +       case TOK_disable:
> > +               query->set_enabled = true;
> > +               query->enabled = DFAULT_disabled;
> > +               break;
> > +       case TOK_enable:
> > +               query->set_enabled = true;
> > +               query->enabled = DFAULT_enabled;
> > +               break;
> > +       case TOK_oneshot:
> > +               query->set_enabled = true;
> > +               query->enabled = DFAULT_oneshot;
> > +               break;
> > +       case TOK_frequency:
> > +               query->set_frequency = 1;
> > +               ret = kstrtouint(words[i++], 10, &query->frequency);
> > +               if (ret)
> > +                       return ret;
> > +
> > +               if (!query->set_enabled) {
> > +                       query->set_enabled = 1;
> > +                       query->enabled = DFAULT_enabled;
> > +               }
> > +               break;
> > +       }
> > +
> > +       return i;
> > +}
> > +
> > +static int dynamic_fault_store(char *buf)
> > +{
> > +       struct dfault_query query = { NULL };
> > +#define MAXWORDS 9
> > +       char *tok, *words[MAXWORDS];
> > +       int ret, nr_words, i = 0;
> > +
> > +       buf = codetag_query_parse(&query.q, buf);
> > +       if (IS_ERR(buf))
> > +               return PTR_ERR(buf);
> > +
> > +       while ((tok = strsep_no_empty(&buf, " \t\r\n"))) {
> > +               if (nr_words == ARRAY_SIZE(words))
> > +                       return -EINVAL; /* ran out of words[] before bytes */
> > +               words[nr_words++] = tok;
> > +       }
> > +
> > +       while (i < nr_words) {
> > +               const char *tok_str = words[i++];
> > +               enum dfault_token tok = str_to_token(tok_str, nr_words - i);
> > +
> > +               if (tok < 0)
> > +                       return tok;
> > +
> > +               ret = dfault_parse_command(&query, tok, words + i, nr_words - i);
> > +               if (ret < 0)
> > +                       return ret;
> > +
> > +               i += ret;
> > +               BUG_ON(i > nr_words);
> > +       }
> > +
> > +       pr_debug("q->function=\"%s\" q->filename=\"%s\" "
> > +                "q->module=\"%s\" q->line=%u-%u\n q->index=%u-%u",
> > +                query.q.function, query.q.filename, query.q.module,
> > +                query.q.first_line, query.q.last_line,
> > +                query.q.first_index, query.q.last_index);
> > +
> > +       ret = dfault_change(&query);
> > +       if (ret < 0)
> > +               return ret;
> > +
> > +       return 0;
> > +}
> > +
> > +struct dfault_iter {
> > +       struct codetag_iterator ct_iter;
> > +
> > +       struct seq_buf          buf;
> > +       char                    rawbuf[4096];
> > +};
> > +
> > +static int dfault_open(struct inode *inode, struct file *file)
> > +{
> > +       struct dfault_iter *iter;
> > +
> > +       iter = kzalloc(sizeof(*iter), GFP_KERNEL);
> > +       if (!iter)
> > +               return -ENOMEM;
> > +
> > +       codetag_lock_module_list(cttype, true);
> > +       codetag_init_iter(&iter->ct_iter, cttype);
> > +       codetag_lock_module_list(cttype, false);
> > +
> > +       file->private_data = iter;
> > +       seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
> > +       return 0;
> > +}
> > +
> > +static int dfault_release(struct inode *inode, struct file *file)
> > +{
> > +       struct dfault_iter *iter = file->private_data;
> > +
> > +       kfree(iter);
> > +       return 0;
> > +}
> > +
> > +struct user_buf {
> > +       char __user             *buf;   /* destination user buffer */
> > +       size_t                  size;   /* size of requested read */
> > +       ssize_t                 ret;    /* bytes read so far */
> > +};
> > +
> > +static int flush_ubuf(struct user_buf *dst, struct seq_buf *src)
> > +{
> > +       if (src->len) {
> > +               size_t bytes = min_t(size_t, src->len, dst->size);
> > +               int err = copy_to_user(dst->buf, src->buffer, bytes);
> > +
> > +               if (err)
> > +                       return err;
> > +
> > +               dst->ret        += bytes;
> > +               dst->buf        += bytes;
> > +               dst->size       -= bytes;
> > +               src->len        -= bytes;
> > +               memmove(src->buffer, src->buffer + bytes, src->len);
> > +       }
> > +
> > +       return 0;
> > +}
> > +
> > +static ssize_t dfault_read(struct file *file, char __user *ubuf,
> > +                          size_t size, loff_t *ppos)
> > +{
> > +       struct dfault_iter *iter = file->private_data;
> > +       struct user_buf buf = { .buf = ubuf, .size = size };
> > +       struct codetag *ct;
> > +       struct dfault *df;
> > +       int err;
> > +
> > +       codetag_lock_module_list(iter->ct_iter.cttype, true);
> > +       while (1) {
> > +               err = flush_ubuf(&buf, &iter->buf);
> > +               if (err || !buf.size)
> > +                       break;
> > +
> > +               ct = codetag_next_ct(&iter->ct_iter);
> > +               if (!ct)
> > +                       break;
> > +
> > +               df = container_of(ct, struct dfault, tag);
> > +               dynamic_fault_to_text(&iter->buf, df);
> > +               seq_buf_putc(&iter->buf, '\n');
> > +       }
> > +       codetag_lock_module_list(iter->ct_iter.cttype, false);
> > +
> > +       return err ?: buf.ret;
> > +}
> > +
> > +/*
> > + * File_ops->write method for <debugfs>/dynamic_fault/conrol.  Gathers the
> > + * command text from userspace, parses and executes it.
> > + */
> > +static ssize_t dfault_write(struct file *file, const char __user *ubuf,
> > +                           size_t len, loff_t *offp)
> > +{
> > +       char tmpbuf[256];
> > +
> > +       if (len == 0)
> > +               return 0;
> > +       /* we don't check *offp -- multiple writes() are allowed */
> > +       if (len > sizeof(tmpbuf)-1)
> > +               return -E2BIG;
> > +       if (copy_from_user(tmpbuf, ubuf, len))
> > +               return -EFAULT;
> > +       tmpbuf[len] = '\0';
> > +       pr_debug("read %zu bytes from userspace", len);
> > +
> > +       dynamic_fault_store(tmpbuf);
> > +
> > +       *offp += len;
> > +       return len;
> > +}
> > +
> > +static const struct file_operations dfault_ops = {
> > +       .owner  = THIS_MODULE,
> > +       .open   = dfault_open,
> > +       .release = dfault_release,
> > +       .read   = dfault_read,
> > +       .write  = dfault_write
> > +};
> > +
> > +static int __init dynamic_fault_init(void)
> > +{
> > +       const struct codetag_type_desc desc = {
> > +               .section = "dynamic_fault_tags",
> > +               .tag_size = sizeof(struct dfault),
> > +       };
> > +       struct dentry *debugfs_file;
> > +
> > +       cttype = codetag_register_type(&desc);
> > +       if (IS_ERR_OR_NULL(cttype))
> > +               return PTR_ERR(cttype);
> > +
> > +       debugfs_file = debugfs_create_file("dynamic_faults", 0666, NULL, NULL, &dfault_ops);
> > +       if (IS_ERR(debugfs_file))
> > +               return PTR_ERR(debugfs_file);
> > +
> > +       return 0;
> > +}
> > +module_init(dynamic_fault_init);
> > --
> > 2.37.2.672.g94769d06f0-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpEQJe7HiNXhv%2BfH3auvr_-M6VpxhgWTj9q6e5GLkd%2B8Uw%40mail.gmail.com.
