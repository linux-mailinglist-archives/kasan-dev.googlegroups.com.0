Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEMHXSIQMGQEBEOWSJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C9F94D7DEE
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 09:57:54 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id l138-20020a628890000000b004f7cb47178csf1310116pfd.12
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 01:57:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647248273; cv=pass;
        d=google.com; s=arc-20160816;
        b=gli4m2BZnCqVuTPO+dn2VRu/N8iFjPbtFRWPjPtkFyzIJBWjMRN2fcZPK413ehajP2
         T0dLVBEZQgdwKw8b54Q3jwSmQfM+NMoelmBaCB+lClT4ll1smBNzN0Agf47Pdo6+XhLN
         vvXl3cSKpLpf4uBAQhn0TnQe9jZQb5o5CInafXxx5NJfWXXzPeVp2C2auxVKuNq1xgCA
         NN0EyJ8IzcL2LZqQ/AnaMBgueSfkRzWBxqJg5eAexX4ScAbAzD4TtlGQyUfSSWq94rg7
         3FXgNCs1cw9B/UoAWDfd7zvyy3/Too7f2xoPRifhGOX3xEnF31DnQnClYtVKG7FIZ1ap
         Lylg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=F/Lh/zW/cQAZtDMcIu0U6VJcX2QJNPdPsqMm6yitX8g=;
        b=kx8psjYTpJaqsrlxqzXMxhoepNuGvoTsC4eqwBhy/gO03RfKx+6Tj7LlEzAzH2UydU
         K8mTLKDh6hLbJJnYHvmr+WN7OLgxKv2t+qParjZ1jRLxXliYw3ByDji+RpjUp/KJ/Deb
         i9PgnCw/44tuWIuIKBivUj/GfqDB4TAWUM4hjjVapU78y0Zs2mDqcew0zGMegUvR8AEX
         xkDTBTf6ODEVUNOLqCYLN69w1V9MkzInB6js8c6a5y1n9DbiOFfYyQG20sFbOreVFerx
         e1sPO51VhPS4rT8sIZo9A1n7kNL21cCYutbcrF6+zhs//0xcuakB943yDiIlJwIIL7pL
         U7WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dq218i3q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F/Lh/zW/cQAZtDMcIu0U6VJcX2QJNPdPsqMm6yitX8g=;
        b=hDkBjrEdabogNow/GgHQLo8vG5JmwEkcya5uCNbHVPYR/9PursHtM2AyfYFdBg2IV3
         1bAgpSUP13YWceLdqaHjJcIHnMivy+960QfrZNnfL619NkUgY5N+OLnpvXF9nrq6iIQ+
         SgCjmOQ/fwAhA+ATyDlJhNZGiU16lsIRq3Xwwv1TspOVoAFR2sihG4cuc9yKgnpDDUXb
         XjI2ws6ily/rkMBypd5VokccLTaN+c2tc/GKcolDx9KduDBhGWTiTCcKZNYo6bhOWl6+
         aNtb/UUbnsnKoAVxhMu4hG2NdRny6YiHnZzc55SsYTLIjwwJLGNFSLoCj516PAKAGFJ+
         7KYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F/Lh/zW/cQAZtDMcIu0U6VJcX2QJNPdPsqMm6yitX8g=;
        b=3vYekPKLiQrdxNiRKWgS2ZG84YGJEAQIRH/NCy6H0Uy35tv1iz2JWFE1AVMC3XMyOb
         YuAOR2Q5gin7U/YgFKWaifUkh5iKmrBUvh/RNfscRMdh2LcJS5pyNcNy9RQ7qzOIT0rr
         x6eewTIoOOUOEdoATjINhI7zCStMDYGnAdCHNiKcrfbCyr6qmLnYWIs9QU77gDdX1On9
         i3/2h8Veb8O6m9INkD1K9Rhc2n9hMtrL6vnMsg2tf50DmcnlSvwJYPG2tAUw0DuVUAM8
         7r9RvWkkSTKxSUaTcS5WyWBe6fMWOoJHNa7NyvsTp2XuPoSjTrMC2kJYWAEFl27UmeGB
         rL9Q==
X-Gm-Message-State: AOAM532WZ1L7nHU7cvciSn4f0kkhdonzt4exZPA5fZWTwtPWTQu7IuOw
	JIu37bXnEHtUw8N+hNF+BiQ=
X-Google-Smtp-Source: ABdhPJwP7u6p297MYQCh6UkxIiWKxh6Ps3MRmeUMWtpOn1qo+ftL8Dp2KX0oa+UPc1HnX0GDwZfa5A==
X-Received: by 2002:a17:90b:4f4b:b0:1bf:bd24:263f with SMTP id pj11-20020a17090b4f4b00b001bfbd24263fmr24177067pjb.228.1647248273147;
        Mon, 14 Mar 2022 01:57:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8c0e:b0:1bf:1a38:d505 with SMTP id
 a14-20020a17090a8c0e00b001bf1a38d505ls6232205pjo.3.gmail; Mon, 14 Mar 2022
 01:57:52 -0700 (PDT)
X-Received: by 2002:a17:903:32c3:b0:151:f021:74c7 with SMTP id i3-20020a17090332c300b00151f02174c7mr22048947plr.48.1647248272462;
        Mon, 14 Mar 2022 01:57:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647248272; cv=none;
        d=google.com; s=arc-20160816;
        b=E37Gh6kdp/2m1O1h0GhjwFBjvGNSVSti2cMFLhp3h9f9oGQVIydo6q4UoWYE9PqNtG
         ZxWOgsvrej8O9DzLMOZqrs1aAYIsTh+A6YB2bWhfLhEGj0nFOBrNiKbUKZc4h55xVbkZ
         GqtQz5w8gno0yia0AIC/Cyrh6SCOhnL6MIlxJZ9L0OkNmw/J4QRULr0Y1eQFNZEqUGGE
         /ggyWopjCTQOxrC/+8+asmODo6Bcd2eBaYAJEjj2Opvuw9AhM4oAXylTgXm+EVKg3xIb
         SxQ1FY81T4mmOe6iiUU2M1fR1B29Zz4oYXcXJXEuXDXVso5DZdko6tr+w4HML6vWdjFL
         iMcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dnStb81zNfCbHNpdfKDavCPptqLqSaSsDRJFANgLx8A=;
        b=TX3NfkkNDVznriH0rjgquzcWNG7zm+FCNWVJDli2pu34iJvqX4XkURxWEe2eNoKOZi
         m12YMCaS1zRxMG0JIEjlqOO7NNWMqcWhzMUyaXlSd2GgIg0YMAWUyAXFR/SQ9zzMCUVH
         NQO5lh2rJ6mVJjhqNG/9FEYmSCS5RRNd2h2LxGr7kZt6n5XnuwmgwFK5+h8ZV6hnrm25
         h1haDSjop/7W/A9ogqrhiAIRqasifnXS8Ow7XfyURdsB++BrKTyPBhC4qWvJamMVBcu7
         4Z8tLX2ZF1WdBhnd2sOF+WALE5MhUVuRkjyLWybUtf2/7zrt4vrsNwtX9/jsPUZE3xbj
         GCGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dq218i3q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id o64-20020a17090a0a4600b001bf0a82f880si810365pjo.2.2022.03.14.01.57.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Mar 2022 01:57:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id g1so29342686ybe.4
        for <kasan-dev@googlegroups.com>; Mon, 14 Mar 2022 01:57:52 -0700 (PDT)
X-Received: by 2002:a25:6994:0:b0:629:1e05:b110 with SMTP id
 e142-20020a256994000000b006291e05b110mr17250131ybc.425.1647248271489; Mon, 14
 Mar 2022 01:57:51 -0700 (PDT)
MIME-Version: 1.0
References: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
 <CA+fCnZe-zj8Xqi5ACz0FjRX92b5KnnP=qKCjEck0=mAjV0nohA@mail.gmail.com>
In-Reply-To: <CA+fCnZe-zj8Xqi5ACz0FjRX92b5KnnP=qKCjEck0=mAjV0nohA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Mar 2022 09:57:15 +0100
Message-ID: <CANpmjNN-UPGOwkYWiOWX5DeSBWnYcobWb+M1ZyWMuSbzJQcFsg@mail.gmail.com>
Subject: Re: [PATCH] kasan, scs: collect stack traces from shadow stack
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Florian Mayer <fmayer@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dq218i3q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, 14 Mar 2022 at 00:44, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Sat, Mar 12, 2022 at 9:14 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Currently, KASAN always uses the normal stack trace collection routines,
> > which rely on the unwinder, when saving alloc and free stack traces.
> >
> > Instead of invoking the unwinder, collect the stack trace by copying
> > frames from the Shadow Call Stack whenever it is enabled. This reduces
> > boot time by 30% for all KASAN modes when Shadow Call Stack is enabled.
> >
> > To avoid potentially leaking PAC pointer tags, strip them when saving
> > the stack trace.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > ---
> >
> > Things to consider:
> >
> > We could integrate shadow stack trace collection into kernel/stacktrace.c
> > as e.g. stack_trace_save_shadow(). However, using stack_trace_consume_fn
> > leads to invoking a callback on each saved from, which is undesirable.
> > The plain copy loop is faster.
> >
> > We could add a command line flag to switch between stack trace collection
> > modes. I noticed that Shadow Call Stack might be missing certain frames
> > in stacks originating from a fault that happens in the middle of a
> > function. I am not sure if this case is important to handle though.
> >
> > Looking forward to thoughts and comments.
> >
> > Thanks!
> >
> > ---
> >  mm/kasan/common.c | 36 +++++++++++++++++++++++++++++++++++-
> >  1 file changed, 35 insertions(+), 1 deletion(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index d9079ec11f31..65a0723370c7 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -9,6 +9,7 @@
> >   *        Andrey Konovalov <andreyknvl@gmail.com>
> >   */
> >
> > +#include <linux/bits.h>
> >  #include <linux/export.h>
> >  #include <linux/init.h>
> >  #include <linux/kasan.h>
> > @@ -21,6 +22,7 @@
> >  #include <linux/printk.h>
> >  #include <linux/sched.h>
> >  #include <linux/sched/task_stack.h>
> > +#include <linux/scs.h>
> >  #include <linux/slab.h>
> >  #include <linux/stacktrace.h>
> >  #include <linux/string.h>
> > @@ -30,12 +32,44 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > +#ifdef CONFIG_SHADOW_CALL_STACK
> > +
> > +#ifdef CONFIG_ARM64_PTR_AUTH
> > +#define PAC_TAG_RESET(x) (x | GENMASK(63, CONFIG_ARM64_VA_BITS))
> > +#else
> > +#define PAC_TAG_RESET(x) (x)
> > +#endif
> > +
> > +static unsigned int save_shadow_stack(unsigned long *entries,
> > +                                     unsigned int nr_entries)
> > +{
> > +       unsigned long *scs_sp = task_scs_sp(current);
> > +       unsigned long *scs_base = task_scs(current);
> > +       unsigned long *frame;
> > +       unsigned int i = 0;
> > +
> > +       for (frame = scs_sp - 1; frame >= scs_base; frame--) {
> > +               entries[i++] = PAC_TAG_RESET(*frame);
> > +               if (i >= nr_entries)
> > +                       break;
> > +       }
> > +
> > +       return i;
> > +}
> > +#else /* CONFIG_SHADOW_CALL_STACK */
> > +static inline unsigned int save_shadow_stack(unsigned long *entries,
> > +                                       unsigned int nr_entries) { return 0; }
> > +#endif /* CONFIG_SHADOW_CALL_STACK */
> > +
> >  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
> >  {
> >         unsigned long entries[KASAN_STACK_DEPTH];
> >         unsigned int nr_entries;
> >
> > -       nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> > +       if (IS_ENABLED(CONFIG_SHADOW_CALL_STACK))
> > +               nr_entries = save_shadow_stack(entries, ARRAY_SIZE(entries));
> > +       else
> > +               nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> >         return __stack_depot_save(entries, nr_entries, flags, can_alloc);
>
> Another option here is to instruct stack depot to get the stack from
> the Shadow Call Stack. This would avoid copying the frames twice.

Yes, I think a stack_depot_save_shadow() would be appropriate if it
saves a copy.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN-UPGOwkYWiOWX5DeSBWnYcobWb%2BM1ZyWMuSbzJQcFsg%40mail.gmail.com.
