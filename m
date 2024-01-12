Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZPOQOWQMGQEIN3P65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B6B7982BC54
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jan 2024 09:25:10 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-680b48a8189sf115331796d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jan 2024 00:25:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705047909; cv=pass;
        d=google.com; s=arc-20160816;
        b=wzGFI6OtCPM//ZPtIYkTxuoq5ewheNbpnnf7hJqrKQNU7arj+MNBL0I0KAedKIxyor
         puSm7C9W2wZ2k/6dFLxQXQm3Mck86TMIOEWL4nRZsADP3zdt7vzvorKxpMak8CN6NE5R
         ZuEXTWKCSgrKI3uNTGhQQUbGMZwW3+DT0mySr/CW8yJ6vT+GyvOwTZ7q5fvZmdTZ8g/F
         x/Upf6u7BXKa3xB+5t/FvO8t3PZLoJWHViEH3lpKqg3gami70MWlEuLXmyixDwsbx4Mk
         uQ+OjfO8GZZPnusU5WmBOun9twfgtdA89XDvvp/zfSCtnpJ+9EP/oBS+Y0DvSJ6afjyK
         pHHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k5CtEw/a/L1+7PJgVVeo+z8EXVDh3cGHfY+VVfa9qFk=;
        fh=j6tCIeSP61/EBd1FLHa5+OGsbFDbjOBEDTSkFizD/J0=;
        b=xWAMSPbJ4scIYNPK5oJ+j7tsVlP8GlwjlrYx98u/tm1MG9oRCQaHgWf9IZ8yozi/9M
         29/FQY3KtsKtMwD3jFx4Bx/OCS7U+Gy7WcZ8NPv4ku8/GSJvtaqMng298knjl1/iihNy
         3fnW5YLulJBYpGtHWaUB3/nAFUhLNtzEJdTvqnm/MYnBKjR9qRziF/h5YVGZDDg3QV3L
         NnnYf61z6ca4B2U7xdHOpkCCDlX8hcmERu7IcnCJup05BkhEsTXjMmvIHK/4otcwBU6y
         71TZteFHFrUOlEuKeY2sqY/idvSCUC9SCnwr6rhic6mhNNJCJMkt0Q58ZPbv4pTQbUZp
         /pzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rxG+hUJz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705047909; x=1705652709; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k5CtEw/a/L1+7PJgVVeo+z8EXVDh3cGHfY+VVfa9qFk=;
        b=uj7xpeK1iF0aTjP+Qao+hYvd+h6WnqC7Vz/afqZ99YLM615a85n8q5eILjgShp+ocD
         C3rgLw4eYQ4vKYrMa1F3qJv9mfdXTPgfix9soJGe+0b1arlJV1WK/cM6UuBHotF26IfQ
         DG0tnyFIngbOD2+qq1YVWYguyyExAnbVIHDLDvVA4z8v2j9sRf7h/0JKIN/g0COjdT5r
         hkyRUCEuzGGTKM9xQgC4dMguTqT+hEu0P2duqtyzMUNYiu11nlN1xIVhyyNfEMhm7VmB
         5D8QO+rCk5pufwOf8ki2sSkjzI1rWskH72Mk9AS6AuzG9rZXJ4nJGSa7NvdXriuf++PS
         vuHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705047909; x=1705652709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=k5CtEw/a/L1+7PJgVVeo+z8EXVDh3cGHfY+VVfa9qFk=;
        b=TiUAyCVL5amRrq093nBAg0TBZBuUJz5HkHXv1pw7qX0F7xMG0+gHbCg42FF2ZhQ4yw
         DE8rgWAqu13Qdv5PInxWAdnddgXjpNivbW28OPmF7RjT3P2hp0dP68mZi1Fc+wZ04RG6
         8ZnqEvl369ajP4e17KzvNuo4qhQbBE6tjbm9nahhTiP49e59mwD6NvVkUz7b1QzFflfW
         HxMHHm8CM8JHguhA4kFJqfONc7rNhkUXZ7BEdnR0iT+aL9tB6ObuVh0t+qECHxbMNIAC
         v2RG3oV8Vxu890QKkxzQ04A7QtW735rjf0PB07FQ0V8nOB+kIAul9sINy0JxJEwgsY4L
         /ang==
X-Gm-Message-State: AOJu0YzTeWFrzK6N2a/DujvjFWaE2MZAwA838O7wU6nRKpKjeNE590MH
	Q9mbUejKFWzUl+OP7jquIec=
X-Google-Smtp-Source: AGHT+IGutWw3F2+jhsG5M3lLMJ6Ybt2b/vvw0qpX3bBWN6lZesBltX/gZAqHRxIPTd8/mSrwagoblQ==
X-Received: by 2002:a05:6214:3011:b0:680:f9b1:8457 with SMTP id ke17-20020a056214301100b00680f9b18457mr538411qvb.58.1705047909525;
        Fri, 12 Jan 2024 00:25:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:574b:0:b0:680:c838:d067 with SMTP id q11-20020ad4574b000000b00680c838d067ls1456712qvx.0.-pod-prod-02-us;
 Fri, 12 Jan 2024 00:25:08 -0800 (PST)
X-Received: by 2002:a05:6214:5901:b0:67f:457c:21b2 with SMTP id qo1-20020a056214590100b0067f457c21b2mr756685qvb.45.1705047908701;
        Fri, 12 Jan 2024 00:25:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705047908; cv=none;
        d=google.com; s=arc-20160816;
        b=zr1hOyax/kgJBwoPwpENqQBIfPybjMxA75PXfbRuNfhGfQsZm1L6RYy41ZidMmKmQX
         5fOLX5++D7nO1BXu9lYsYs9vqmzS6Ve+caBTIgEad/geRvi+aKXA5tqlH3rn+Q5sAOT8
         8E3r5eOHqfDdfcqtgAahxEwaDU9lOGJELHSGnRmFfgzFySS0oscXW03jgxf+3ANdGe7V
         UMvM3TamxSAgm7k69yerDejBx7g0XbexEY0z8hKR85RkdqoESBp3YUVrEC/Eb6JH9QwM
         iE+l8MFLW4S24BJm7mHj8zpCs7OSnk1rSihU2UZXV2EIH8/SD7YbiewOz3w7Eqq+AtPM
         7O1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gCCY2JLDqYranqLbAyh8urj43fEFYVd1fpB6EByYouA=;
        fh=j6tCIeSP61/EBd1FLHa5+OGsbFDbjOBEDTSkFizD/J0=;
        b=vSFbSB6rfakDoBOHf+btiqZtCcqfEmbb5TPEz54hj3SzpmlcPQHhS3XuD22vM/Dt98
         T+HKGskIUfmYzk/aw6g+XnEf+aJoeQ7+PvMTw2DTcA57izbQcuU9tnD4ulGXeFvG5F2D
         oOYUo/cWSDLYyMpiEUZ8q0p3birJtCw3E8/sEhvLXfYL3SfIhMrDVGLtA4vnJinP7VPt
         4X+TajHaVKLTxf+aySdnhgs9h1D6bOvHxobROsNETAYdWhpsA7M49DIFs3breroQQ28d
         omiMHe/fDZZSoAwaCgjkElZDmf1RpR0ymUrRkDmKy9JKuCisQzCBIeoNwkHDiVuaTZ+G
         06lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rxG+hUJz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe35.google.com (mail-vs1-xe35.google.com. [2607:f8b0:4864:20::e35])
        by gmr-mx.google.com with ESMTPS id k3-20020a0cfa43000000b0067fb9da9819si200735qvo.1.2024.01.12.00.25.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Jan 2024 00:25:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e35 as permitted sender) client-ip=2607:f8b0:4864:20::e35;
Received: by mail-vs1-xe35.google.com with SMTP id ada2fe7eead31-4670adbd76aso1517648137.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Jan 2024 00:25:08 -0800 (PST)
X-Received: by 2002:a05:6102:38d3:b0:467:1ffb:d6a1 with SMTP id
 k19-20020a05610238d300b004671ffbd6a1mr1234685vst.26.1705047908159; Fri, 12
 Jan 2024 00:25:08 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
 <ZZUlgs69iTTlG8Lh@localhost.localdomain> <87sf34lrn3.fsf@linux.intel.com>
 <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
 <ZZ_gssjTCyoWjjhP@tassilo> <ZaA8oQG-stLAVTbM@elver.google.com> <CA+fCnZeS=OrqSK4QVUVdS6PwzGrpg8CBj8i2Uq=VMgMcNg1FYw@mail.gmail.com>
In-Reply-To: <CA+fCnZeS=OrqSK4QVUVdS6PwzGrpg8CBj8i2Uq=VMgMcNg1FYw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Jan 2024 09:24:32 +0100
Message-ID: <CANpmjNOoidtyeQ76274SWtTYR4zZPdr1DnxhLaagHGXcKwPOhA@mail.gmail.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andi Kleen <ak@linux.intel.com>, Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rxG+hUJz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e35 as
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

On Fri, 12 Jan 2024 at 03:38, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Thu, Jan 11, 2024 at 8:08=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > On Thu, Jan 11, 2024 at 04:36AM -0800, Andi Kleen wrote:
> > > > stackdepot is severely limited in what kernel facilities it may use
> > > > due to being used by such low level facilities as the allocator
> > > > itself.
> > >
> > > RCU can be done quite low level too (e.g. there is NMI safe RCU)
> >
> > How about the below? This should get us back the performance of the old
> > lock-less version. Although it's using rculist, we don't actually need
> > to synchronize via RCU.
> >
> > Thanks,
> > -- Marco
> >
> > ------ >8 ------
> >
> > From: Marco Elver <elver@google.com>
> > Date: Tue, 9 Jan 2024 10:21:56 +0100
> > Subject: [PATCH] stackdepot: make fast paths lock-less again
> >
> > stack_depot_put() unconditionally takes the pool_rwlock as a writer.
> > This is unnecessary if the stack record is not going to be freed.
> > Furthermore, reader-writer locks have inherent cache contention, which
> > does not scale well on machines with large CPU counts.
> >
> > Instead, rework the synchronization story of stack depot to again avoid
> > taking any locks in the fast paths. This is done by relying on RCU
> > primitives to give us lock-less list traversal. See code comments for
> > more details.
> >
> > Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces=
")
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  lib/stackdepot.c | 222 ++++++++++++++++++++++++++++-------------------
> >  1 file changed, 133 insertions(+), 89 deletions(-)
> >
> > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > index a0be5d05c7f0..9eaf46f8abc4 100644
> > --- a/lib/stackdepot.c
> > +++ b/lib/stackdepot.c
> > @@ -19,10 +19,13 @@
> >  #include <linux/kernel.h>
> >  #include <linux/kmsan.h>
> >  #include <linux/list.h>
> > +#include <linux/llist.h>
> >  #include <linux/mm.h>
> >  #include <linux/mutex.h>
> >  #include <linux/percpu.h>
> >  #include <linux/printk.h>
> > +#include <linux/rculist.h>
> > +#include <linux/rcupdate.h>
> >  #include <linux/refcount.h>
> >  #include <linux/slab.h>
> >  #include <linux/spinlock.h>
> > @@ -67,7 +70,8 @@ union handle_parts {
> >  };
> >
> >  struct stack_record {
> > -       struct list_head list;          /* Links in hash table or freel=
ist */
> > +       struct list_head hash_list;     /* Links in the hash table */
> > +       struct llist_node free_list;    /* Links in the freelist */
> >         u32 hash;                       /* Hash in hash table */
> >         u32 size;                       /* Number of stored frames */
> >         union handle_parts handle;
> > @@ -104,7 +108,7 @@ static void *new_pool;
> >  /* Number of pools in stack_pools. */
> >  static int pools_num;
> >  /* Freelist of stack records within stack_pools. */
> > -static LIST_HEAD(free_stacks);
> > +static LLIST_HEAD(free_stacks);
> >  /*
> >   * Stack depot tries to keep an extra pool allocated even before it ru=
ns out
> >   * of space in the currently used pool. This flag marks whether this e=
xtra pool
> > @@ -112,8 +116,8 @@ static LIST_HEAD(free_stacks);
> >   * yet allocated or if the limit on the number of pools is reached.
> >   */
> >  static bool new_pool_required =3D true;
> > -/* Lock that protects the variables above. */
> > -static DEFINE_RWLOCK(pool_rwlock);
> > +/* The lock must be held when performing pool or free list modificatio=
ns. */
> > +static DEFINE_RAW_SPINLOCK(pool_lock);
> >
> >  static int __init disable_stack_depot(char *str)
> >  {
> > @@ -263,9 +267,7 @@ static void depot_init_pool(void *pool)
> >  {
> >         int offset;
> >
> > -       lockdep_assert_held_write(&pool_rwlock);
> > -
> > -       WARN_ON(!list_empty(&free_stacks));
> > +       lockdep_assert_held(&pool_lock);
> >
> >         /* Initialize handles and link stack records into the freelist.=
 */
> >         for (offset =3D 0; offset <=3D DEPOT_POOL_SIZE - DEPOT_STACK_RE=
CORD_SIZE;
> > @@ -276,18 +278,25 @@ static void depot_init_pool(void *pool)
> >                 stack->handle.offset =3D offset >> DEPOT_STACK_ALIGN;
> >                 stack->handle.extra =3D 0;
> >
> > -               list_add(&stack->list, &free_stacks);
> > +               llist_add(&stack->free_list, &free_stacks);
> > +               INIT_LIST_HEAD(&stack->hash_list);
> >         }
> >
> >         /* Save reference to the pool to be used by depot_fetch_stack()=
. */
> >         stack_pools[pools_num] =3D pool;
> > -       pools_num++;
> > +
> > +       /*
> > +        * Release of pool pointer assignment above. Pairs with the
> > +        * smp_load_acquire() in depot_fetch_stack().
> > +        */
> > +       smp_store_release(&pools_num, pools_num + 1);
> > +       ASSERT_EXCLUSIVE_WRITER(pools_num);
> >  }
> >
> >  /* Keeps the preallocated memory to be used for a new stack depot pool=
. */
> >  static void depot_keep_new_pool(void **prealloc)
> >  {
> > -       lockdep_assert_held_write(&pool_rwlock);
> > +       lockdep_assert_held(&pool_lock);
> >
> >         /*
> >          * If a new pool is already saved or the maximum number of
> > @@ -310,16 +319,16 @@ static void depot_keep_new_pool(void **prealloc)
> >          * number of pools is reached. In either case, take note that
> >          * keeping another pool is not required.
> >          */
> > -       new_pool_required =3D false;
> > +       WRITE_ONCE(new_pool_required, false);
> >  }
> >
> >  /* Updates references to the current and the next stack depot pools. *=
/
> >  static bool depot_update_pools(void **prealloc)
> >  {
> > -       lockdep_assert_held_write(&pool_rwlock);
> > +       lockdep_assert_held(&pool_lock);
> >
> >         /* Check if we still have objects in the freelist. */
> > -       if (!list_empty(&free_stacks))
> > +       if (!llist_empty(&free_stacks))
> >                 goto out_keep_prealloc;
> >
> >         /* Check if we have a new pool saved and use it. */
> > @@ -329,7 +338,7 @@ static bool depot_update_pools(void **prealloc)
> >
> >                 /* Take note that we might need a new new_pool. */
> >                 if (pools_num < DEPOT_MAX_POOLS)
> > -                       new_pool_required =3D true;
> > +                       WRITE_ONCE(new_pool_required, true);
> >
> >                 /* Try keeping the preallocated memory for new_pool. */
> >                 goto out_keep_prealloc;
> > @@ -362,20 +371,19 @@ static struct stack_record *
> >  depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **p=
realloc)
> >  {
> >         struct stack_record *stack;
> > +       struct llist_node *free;
> >
> > -       lockdep_assert_held_write(&pool_rwlock);
> > +       lockdep_assert_held(&pool_lock);
> >
> >         /* Update current and new pools if required and possible. */
> >         if (!depot_update_pools(prealloc))
> >                 return NULL;
> >
> >         /* Check if we have a stack record to save the stack trace. */
> > -       if (list_empty(&free_stacks))
> > +       free =3D llist_del_first(&free_stacks);
> > +       if (!free)
> >                 return NULL;
> > -
> > -       /* Get and unlink the first entry from the freelist. */
> > -       stack =3D list_first_entry(&free_stacks, struct stack_record, l=
ist);
> > -       list_del(&stack->list);
> > +       stack =3D llist_entry(free, struct stack_record, free_list);
> >
> >         /* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES=
. */
> >         if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
> > @@ -385,7 +393,6 @@ depot_alloc_stack(unsigned long *entries, int size,=
 u32 hash, void **prealloc)
> >         stack->hash =3D hash;
> >         stack->size =3D size;
> >         /* stack->handle is already filled in by depot_init_pool(). */
> > -       refcount_set(&stack->count, 1);
> >         memcpy(stack->entries, entries, flex_array_size(stack, entries,=
 size));
> >
> >         /*
> > @@ -394,21 +401,30 @@ depot_alloc_stack(unsigned long *entries, int siz=
e, u32 hash, void **prealloc)
> >          */
> >         kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
> >
> > +       /*
> > +        * Release saving of the stack trace. Pairs with smp_mb() in
> > +        * depot_fetch_stack().
> > +        */
> > +       smp_mb__before_atomic();
> > +       refcount_set(&stack->count, 1);
> > +
> >         return stack;
> >  }
> >
> >  static struct stack_record *depot_fetch_stack(depot_stack_handle_t han=
dle)
> >  {
> > +       /* Acquire the pool pointer written in depot_init_pool(). */
> > +       const int pools_num_cached =3D smp_load_acquire(&pools_num);
> >         union handle_parts parts =3D { .handle =3D handle };
> >         void *pool;
> >         size_t offset =3D parts.offset << DEPOT_STACK_ALIGN;
> >         struct stack_record *stack;
> >
> > -       lockdep_assert_held(&pool_rwlock);
> > +       lockdep_assert_not_held(&pool_lock);
> >
> > -       if (parts.pool_index > pools_num) {
> > +       if (parts.pool_index > pools_num_cached) {
> >                 WARN(1, "pool index %d out of bounds (%d) for stack id =
%08x\n",
> > -                    parts.pool_index, pools_num, handle);
> > +                    parts.pool_index, pools_num_cached, handle);
> >                 return NULL;
> >         }
> >
> > @@ -417,15 +433,35 @@ static struct stack_record *depot_fetch_stack(dep=
ot_stack_handle_t handle)
> >                 return NULL;
> >
> >         stack =3D pool + offset;
> > +
> > +       /*
> > +        * Acquire the stack trace. Pairs with smp_mb() in depot_alloc_=
stack().
> > +        *
> > +        * This does not protect against a stack_depot_put() freeing th=
e record
> > +        * and having it subsequently being reused. Callers are respons=
ible to
> > +        * avoid using stack depot handles after passing to stack_depot=
_put().
> > +        */
> > +       if (!refcount_read(&stack->count))
> > +               return NULL;
>
> Can this happen? It seems that depot_fetch_stack should only be called
> for handles that were returned from stack_depot_save_flags before all
> puts and thus the the refcount should > 0. Or is this a safeguard
> against improper API usage?
>
> > +       smp_mb__after_atomic();
> > +
> >         return stack;
> >  }
> >
> >  /* Links stack into the freelist. */
> >  static void depot_free_stack(struct stack_record *stack)
> >  {
> > -       lockdep_assert_held_write(&pool_rwlock);
> > +       unsigned long flags;
> > +
> > +       lockdep_assert_not_held(&pool_lock);
> > +
> > +       raw_spin_lock_irqsave(&pool_lock, flags);
> > +       printk_deferred_enter();
> > +       list_del_rcu(&stack->hash_list);
> > +       printk_deferred_exit();
> > +       raw_spin_unlock_irqrestore(&pool_lock, flags);
> >
> > -       list_add(&stack->list, &free_stacks);
> > +       llist_add(&stack->free_list, &free_stacks);
>
> This llist_add is outside of the lock just because we can (i.e.
> llist_add can run concurrently with the other free_stacks operations,
> which are all under the lock), right? This slightly contradicts the
> comment above the free_stacks definition.

Yes, llist can be used without locks.

> If we put this under the lock and use normal list instead of llist, I
> think we can then combine the hash_list with the free_list like before
> to save up on some space for stack_record. Would that make sense?

No, the RCU protected list can only be deleted, but not immediately
moved elsewhere. I.e. doing list_del_rcu() and list_add() immediately
will break list_for_each_entry_rcu() list traversal because list_add()
would modify the entry's next pointer which list traversal can still
potentially observe.

This actually made me realize that even doing list_del_rcu() and
list_add_rcu() later under the lock is dubious: it's possible that
find_stack() observes an entry that is being deleted, stalls, and that
entry is re-added so another list and then have a data race on reading
the next pointer of the old/new entry (which list_add_rcu() assigns
with plain C writes). While the documentation says that list_del_rcu()
and list_add_rcu() can be used concurrently with
list_for_each_entry_rcu(), 2 successive list_del_rcu() and
list_add_rcu() have to normally be separated by an RCU grace period.

I was trying to not have to use synchronize_rcu() or call_rcu()
(because we can't from stack depot), but perhaps there is no way
around it. What we can do is use get_state_synchronize_rcu(), but that
requires adding yet another field to stack_record. Another option
would be to have validation to figure out that the entry moved between
lists, but that's also hard to do.

> >  }
> >
> >  /* Calculates the hash for a stack. */
> > @@ -453,22 +489,55 @@ int stackdepot_memcmp(const unsigned long *u1, co=
nst unsigned long *u2,
> >
> >  /* Finds a stack in a bucket of the hash table. */
> >  static inline struct stack_record *find_stack(struct list_head *bucket=
,
> > -                                            unsigned long *entries, in=
t size,
> > -                                            u32 hash)
> > +                                             unsigned long *entries, i=
nt size,
> > +                                             u32 hash, depot_flags_t f=
lags)
> >  {
> > -       struct list_head *pos;
> > -       struct stack_record *found;
> > +       struct stack_record *stack, *ret =3D NULL;
> >
> > -       lockdep_assert_held(&pool_rwlock);
> > +       /*
> > +        * Due to being used from low-level code paths such as the allo=
cators,
> > +        * NMI, or even RCU itself, stackdepot cannot rely on primitive=
s that
> > +        * would sleep (such as synchronize_rcu()) or end up recursivel=
y call
> > +        * into stack depot again (such as call_rcu()).
> > +        *
> > +        * Instead, lock-less readers only rely on RCU primitives for c=
orrect
> > +        * memory ordering, but do not use RCU-based synchronization ot=
herwise.
> > +        * Instead, we perform 3-pass validation below to ensure that t=
he stack
> > +        * record we accessed is actually valid. If we fail to obtain a=
 valid
> > +        * stack record here, the slow-path in stack_depot_save_flags()=
 will
> > +        * retry to avoid inserting duplicates.
> > +        *
> > +        * If STACK_DEPOT_FLAG_GET is not used, it is undefined behavio=
ur to
> > +        * call stack_depot_put() later - i.e. in the non-refcounted ca=
se, we do
> > +        * not have to worry that the entry will be recycled.
> > +        */
> > +
> > +       list_for_each_entry_rcu(stack, bucket, hash_list) {
>
> So we don't need rcu_read_lock here, because we don't rely on call_rcu
> etc., right?

That was the idea, but see my answer above. I will have a rethink how
to solve the list_del_rcu() with successive list_add_rcu() problem.

> > +               /* 1. Check if this entry could potentially match. */
> > +               if (data_race(stack->hash !=3D hash || stack->size !=3D=
 size))
> > +                       continue;
> > +
> > +               /*
> > +                * 2. Increase refcount if not zero. If this is success=
ful, we
> > +                *    know that this stack record is valid and will not=
 be freed by
> > +                *    stack_depot_put().
> > +                */
> > +               if ((flags & STACK_DEPOT_FLAG_GET) && unlikely(!refcoun=
t_inc_not_zero(&stack->count)))
> > +                       continue;
> > +
> > +               /* 3. Do full validation of the record. */
> > +               if (likely(stack->hash =3D=3D hash && stack->size =3D=
=3D size &&
> > +                          !stackdepot_memcmp(entries, stack->entries, =
size))) {
> > +                       ret =3D stack;
> > +                       break;
> > +               }
> >
> > -       list_for_each(pos, bucket) {
> > -               found =3D list_entry(pos, struct stack_record, list);
> > -               if (found->hash =3D=3D hash &&
> > -                   found->size =3D=3D size &&
> > -                   !stackdepot_memcmp(entries, found->entries, size))
> > -                       return found;
> > +               /* Undo refcount - could have raced with stack_depot_pu=
t(). */
> > +               if ((flags & STACK_DEPOT_FLAG_GET) && unlikely(refcount=
_dec_and_test(&stack->count)))
> > +                       depot_free_stack(stack);
> >         }
> > -       return NULL;
> > +
> > +       return ret;
> >  }
> >
> >  depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
> > @@ -482,7 +551,6 @@ depot_stack_handle_t stack_depot_save_flags(unsigne=
d long *entries,
> >         struct page *page =3D NULL;
> >         void *prealloc =3D NULL;
> >         bool can_alloc =3D depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
> > -       bool need_alloc =3D false;
> >         unsigned long flags;
> >         u32 hash;
> >
> > @@ -505,31 +573,16 @@ depot_stack_handle_t stack_depot_save_flags(unsig=
ned long *entries,
> >         hash =3D hash_stack(entries, nr_entries);
> >         bucket =3D &stack_table[hash & stack_hash_mask];
> >
> > -       read_lock_irqsave(&pool_rwlock, flags);
> > -       printk_deferred_enter();
> > -
> > -       /* Fast path: look the stack trace up without full locking. */
> > -       found =3D find_stack(bucket, entries, nr_entries, hash);
> > -       if (found) {
> > -               if (depot_flags & STACK_DEPOT_FLAG_GET)
> > -                       refcount_inc(&found->count);
> > -               printk_deferred_exit();
> > -               read_unlock_irqrestore(&pool_rwlock, flags);
> > +       /* Fast path: look the stack trace up without locking. */
> > +       found =3D find_stack(bucket, entries, nr_entries, hash, depot_f=
lags);
> > +       if (found)
> >                 goto exit;
> > -       }
> > -
> > -       /* Take note if another stack pool needs to be allocated. */
> > -       if (new_pool_required)
> > -               need_alloc =3D true;
> > -
> > -       printk_deferred_exit();
> > -       read_unlock_irqrestore(&pool_rwlock, flags);
> >
> >         /*
> >          * Allocate memory for a new pool if required now:
> >          * we won't be able to do that under the lock.
> >          */
> > -       if (unlikely(can_alloc && need_alloc)) {
> > +       if (unlikely(can_alloc && READ_ONCE(new_pool_required))) {
> >                 /*
> >                  * Zero out zone modifiers, as we don't have specific z=
one
> >                  * requirements. Keep the flags related to allocation i=
n atomic
> > @@ -543,31 +596,33 @@ depot_stack_handle_t stack_depot_save_flags(unsig=
ned long *entries,
> >                         prealloc =3D page_address(page);
> >         }
> >
> > -       write_lock_irqsave(&pool_rwlock, flags);
> > +       raw_spin_lock_irqsave(&pool_lock, flags);
> >         printk_deferred_enter();
> >
> > -       found =3D find_stack(bucket, entries, nr_entries, hash);
> > +       /* Try to find again, to avoid concurrently inserting duplicate=
s. */
> > +       found =3D find_stack(bucket, entries, nr_entries, hash, depot_f=
lags);
> >         if (!found) {
> >                 struct stack_record *new =3D
> >                         depot_alloc_stack(entries, nr_entries, hash, &p=
realloc);
> >
> >                 if (new) {
> > -                       list_add(&new->list, bucket);
> > +                       /*
> > +                        * This releases the stack record into the buck=
et and
> > +                        * makes it visible to readers in find_stack().
> > +                        */
> > +                       list_add_rcu(&new->hash_list, bucket);
> >                         found =3D new;
> >                 }
> > -       } else {
> > -               if (depot_flags & STACK_DEPOT_FLAG_GET)
> > -                       refcount_inc(&found->count);
> > +       } else if (prealloc) {
> >                 /*
> >                  * Stack depot already contains this stack trace, but l=
et's
> >                  * keep the preallocated memory for future.
> >                  */
> > -               if (prealloc)
> > -                       depot_keep_new_pool(&prealloc);
> > +               depot_keep_new_pool(&prealloc);
> >         }
> >
> >         printk_deferred_exit();
> > -       write_unlock_irqrestore(&pool_rwlock, flags);
> > +       raw_spin_unlock_irqrestore(&pool_lock, flags);
> >  exit:
> >         if (prealloc) {
> >                 /* Stack depot didn't use this memory, free it. */
> > @@ -592,7 +647,6 @@ unsigned int stack_depot_fetch(depot_stack_handle_t=
 handle,
> >                                unsigned long **entries)
> >  {
> >         struct stack_record *stack;
> > -       unsigned long flags;
> >
> >         *entries =3D NULL;
> >         /*
> > @@ -604,13 +658,12 @@ unsigned int stack_depot_fetch(depot_stack_handle=
_t handle,
> >         if (!handle || stack_depot_disabled)
> >                 return 0;
> >
> > -       read_lock_irqsave(&pool_rwlock, flags);
> > -       printk_deferred_enter();
> > -
> >         stack =3D depot_fetch_stack(handle);
> > -
> > -       printk_deferred_exit();
> > -       read_unlock_irqrestore(&pool_rwlock, flags);
> > +       /*
> > +        * Should never be NULL, otherwise this is a use-after-put.
> > +        */
> > +       if (WARN_ON(!stack))
> > +               return 0;
> >
> >         *entries =3D stack->entries;
> >         return stack->size;
> > @@ -620,29 +673,20 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
> >  void stack_depot_put(depot_stack_handle_t handle)
> >  {
> >         struct stack_record *stack;
> > -       unsigned long flags;
> >
> >         if (!handle || stack_depot_disabled)
> >                 return;
> >
> > -       write_lock_irqsave(&pool_rwlock, flags);
> > -       printk_deferred_enter();
> > -
> >         stack =3D depot_fetch_stack(handle);
> > +       /*
> > +        * Should always be able to find the stack record, otherwise th=
is is an
> > +        * unbalanced put attempt.
> > +        */
> >         if (WARN_ON(!stack))
> > -               goto out;
> > -
> > -       if (refcount_dec_and_test(&stack->count)) {
> > -               /* Unlink stack from the hash table. */
> > -               list_del(&stack->list);
> > +               return;
> >
> > -               /* Free stack. */
> > +       if (refcount_dec_and_test(&stack->count))
> >                 depot_free_stack(stack);
> > -       }
> > -
> > -out:
> > -       printk_deferred_exit();
> > -       write_unlock_irqrestore(&pool_rwlock, flags);
> >  }
> >  EXPORT_SYMBOL_GPL(stack_depot_put);
> >
> > --
> > 2.43.0.275.g3460e3d667-goog
> >
>
> Looks good to me from the functional perspective (modulo the
> clarification comments I left above), but it would be great to get a
> review from someone with a better understanding of the low-level
> synchronization primitives.

Yes - and I'll have to rework this to use get_state_synchronize_rcu()
after all. When it's ready for proper review I'll send an RFC patch.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOoidtyeQ76274SWtTYR4zZPdr1DnxhLaagHGXcKwPOhA%40mail.gmail.=
com.
