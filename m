Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTHTRCLQMGQEUVIFVPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 82F90583970
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Jul 2022 09:25:01 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id p13-20020ad45f4d000000b0044399a9bb4csf765197qvg.15
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Jul 2022 00:25:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658993100; cv=pass;
        d=google.com; s=arc-20160816;
        b=rUq2dMrbkxJy2X8lgfUNjoTa6aGkGAmfo/qOlBOu75rRkHmodgSeblyd1OtZ/FIESC
         Hyk5rF4/VMvcp1zvRicfns+2G6aTJi7PvYpI6QaB0dtnpqPAJ2TmoKQHocFSY0DLpkwp
         QWpUh5I5ed4wG4IYtlv8WvOiSr2efmH0K3XTfL+ZItshCarqGFJOgTee1IvGE4i65C8v
         xVfQXDpvHQoYLi+zuytxMx3255GrX73CTT+8/QlI8aGkyOJGY/9dXRFcm+kKUS5YGHOB
         2SugdYWDDLRkk6PVQAONLSSqrKONoi1xvqxD9nnz7aMpS6qPhGZJeQfj9EX5db5iUSPq
         LN0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=b9Sjuplc1wLoT2DPnX74mxshR3Or+HUQBZlcjdnml0A=;
        b=yGrXV7yZ9MTLrQGwsORbAV7fhNxDnBZOxOBTjc9lFr1H1XB+JQf1hqEDI5N5sG2lFd
         qspMi3ngrpByTLXNtcfepAq4JtMfQtJofFV7tOa/fsMUWGm39GHNYytTrActhJ2OMeP2
         PEpobFQBYEJo9kT/Rhy7asEyEBzUVzONh8tlhgAV7YGfDKj0/1AcKEajjSGM9XP602XA
         /xCQ35IsiCQGmcoPifedF6mdkWubnXB/7gMKnzOJb6ii09hNlxNTuWloh0zAxH3kQ9Wv
         egii1ZWvBCbrCG3n2IguUQBtnuGNiQ49gPxCQoq6KWMHUG2sOUEV7a9lKUezsMCjS6MZ
         4bFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="VewyJ/sV";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b9Sjuplc1wLoT2DPnX74mxshR3Or+HUQBZlcjdnml0A=;
        b=WCvAFzL3CRnNapfgbLMxadxUp1okm+IVj7bJVF+0+11DGoAK+/sQHiDOJ5/OPfvrmr
         YysXJJO0TtOdSqdEGsf8nnPCmxgEZHDO5QQnROm4Gh9W3uua7WuezNINRVx2JkuLwxXH
         mchKYU/1X38wW+1CXxMJhKD0sFXhukOx753D++sn1lp3Air3M/+DI44IKSNPNl0cuMCD
         fXA4a4znreUDw9BXze+LQcCx/uGzDefSgXCtA5GBbX7PbcnzqDLCAUJb8npssaPcJxIn
         AyQkxVpNHiiyPyKwbohBn7pS3EEyOIndtIho+6ld4BRf6W/ev36kZL/bXKZbWruVy13b
         4WLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b9Sjuplc1wLoT2DPnX74mxshR3Or+HUQBZlcjdnml0A=;
        b=cOEWrL3gydcSHqnR6ABXrpwEvbHXBzLGNyADOPv9o+ckpIsIgy270CuLyBAZW92+pA
         oG+ctTFkFF7v92f2ssn2p/dYU2pAjxY2BrnA9KCwrkItPNZzsYNG7k+5eQYDqk9vwz/4
         0vG6LvvqXQVLHH3esEMrWSxN8CMd3UfdE4yTR1NrpP6m0hBwjxJfyLV1fHMeQ0Kc4LJK
         xMcJh3GW/asVXfFb5OMAYKhy+r30t/0adohOFyIfo2E9bIqPhWFLXhH8BeDOvwr2HSHt
         g0JxBVYvZJ5IWVDxq+NZJX8EtjA3VhxxkbsQJ0x7HqYERFYpf8r98doUNgpUEsEmAT4I
         O1mg==
X-Gm-Message-State: AJIora8pgybrU/h4VLmHOJofHW5ZXpzRk96taqdKiF9h/mB9VZ3O7uCG
	SyfWOuWxU3Lg3FWF+cd/XPE=
X-Google-Smtp-Source: AGRyM1u5RbK4206cGDDKf0xzH5wmv7ZblF5X5cJ+Mlw5JKYQY98X38h3fCkBVEWm5FxXU+Md6FDcxg==
X-Received: by 2002:a05:622a:1186:b0:31e:eb85:ad62 with SMTP id m6-20020a05622a118600b0031eeb85ad62mr21186760qtk.424.1658993100236;
        Thu, 28 Jul 2022 00:25:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1473:b0:6b5:db60:854f with SMTP id
 j19-20020a05620a147300b006b5db60854fls768058qkl.6.-pod-prod-gmail; Thu, 28
 Jul 2022 00:24:59 -0700 (PDT)
X-Received: by 2002:a05:620a:c16:b0:6b6:c7c:67c9 with SMTP id l22-20020a05620a0c1600b006b60c7c67c9mr19889996qki.656.1658993099643;
        Thu, 28 Jul 2022 00:24:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658993099; cv=none;
        d=google.com; s=arc-20160816;
        b=YYJ5pDU6ynFukVlxbBn0fdtf4NDDJEHgGWLKwP0us2rmG354V6VaoJsoyS2g0Jw82E
         szqVczHpJZP3RdWEg55BB4CnzmutzD15ij+SvqzsY6KerkgGLqsfpJ/8+1eq94/a8YWl
         jd01YgirMfPFcdKc9SxEPK+ybz5wxO2roZHiH2Fwh/+FuFZ1KAYD0Umx6PTiAxGxBAbR
         jJfVqMq5Fc8UKma9qDsinS1vIAHri6yf5diRzZ3cSKtxE2X5GsxXGY9mK8/rZRuJ4boU
         gJtYgHWBSwLPkoAsT3nj998+21VFlzafKt1cpBJBwHaDGOefpabWowM5XOAj+RwpdiEC
         kH9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oqbTPnu/pF8QmgHbRP8i1nrgyN4MT+vnZXxtlSHsiqQ=;
        b=k9xDzJnvSajmTxpQaEXhtkcLjlu80mCPLlEHTBWhSokqceGH/rOK5uUtjpPEKaHGyE
         mVQLjb8Na2F7oAY9Inj7l/cRg9jr5aQoHwpICpv/v5XwstLYg9cVauPpB258YEucph94
         QOnA/izJe7vq1142MjbG5Mpax1fhHzOfSJTJ1LL1Htb6rX1RBqenawsW17PQ0LlcK85j
         yU3I4pC5hedx7vLMqFQWJAkF8tsSck/bI773MPOCDTP9xYWOLyVgurVDTOa5Y2KwsFRP
         RBtwi0FhYoG7RNHWDqwx6fCD+v8k9qXYiGgfiCkJti6VwwAbT0wOIhc1ae1M3L6YpfOq
         K8cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="VewyJ/sV";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id s5-20020ac85ec5000000b0031ecf06e367si5897qtx.1.2022.07.28.00.24.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Jul 2022 00:24:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id o15so1914618yba.10
        for <kasan-dev@googlegroups.com>; Thu, 28 Jul 2022 00:24:59 -0700 (PDT)
X-Received: by 2002:a25:ad16:0:b0:671:75d9:6aad with SMTP id
 y22-20020a25ad16000000b0067175d96aadmr7997719ybi.143.1658993099072; Thu, 28
 Jul 2022 00:24:59 -0700 (PDT)
MIME-Version: 1.0
References: <20220727234241.1423357-1-imran.f.khan@oracle.com>
In-Reply-To: <20220727234241.1423357-1-imran.f.khan@oracle.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Jul 2022 09:24:22 +0200
Message-ID: <CANpmjNNmD9z7oRqSaP72m90kWL7jYH+cxNAZEGpJP8oLrDV-vw@mail.gmail.com>
Subject: Re: [RFC PATCH] mm/kfence: Introduce kernel parameter for selective
 usage of kfence.
To: Imran Khan <imran.f.khan@oracle.com>
Cc: glider@google.com, dvyukov@google.com, cl@linux.com, penberg@kernel.org, 
	rientjes@google.com, iamjoonsoo.kim@lge.com, akpm@linux-foundation.org, 
	vbabka@suse.cz, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, corbet@lwn.net, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="VewyJ/sV";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as
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

On Thu, 28 Jul 2022 at 01:43, Imran Khan <imran.f.khan@oracle.com> wrote:
>
> By default kfence allocation can happen for any slub object, whose size

s/slub object/slab object/

> is up to PAGE_SIZE, as long as that allocation is the first allocation
> after expiration of kfence sample interval. But in certain debugging
> scenarios we may be interested in debugging corruptions involving
> some specific slub objects like dentry or ext4_* etc. In such cases
> limiting kfence for allocations involving only specific slub objects
> will increase the probablity of catching the issue since kfence pool
> will not be consumed by other slub objects.

Have you seen this happen? The "skip already covered allocations"
feature should take care of most of these issues filling up the pool.
Have you tried adjusting kfence.skip_covered_thresh?

Or put another way: with your patch, have you been able to debug an
issue you haven't before? Typically this is not how KFENCE is meant to
be used if you know there's an issue; at that point your best bet is
to build a KASAN kernel and boot that. Of course that may not always
be possible, but there are other knobs you can tweak
(kfence.sample_interval, kfence.skip_covered_thresh).

Your patch only makes sense in a "manual debugging" scenario, and not
quite what KFENCE was designed for (deployment at scale).

> This patch introduces a kernel parameter slub_kfence that can be used
> to specify a comma separated list of slabs for which kfence allocations
> will happen. Also introduce a sysfs parameter that can be used to re-enable
> kfence for all slabs.
>
> Signed-off-by: Imran Khan <imran.f.khan@oracle.com>
> ---
>
> I am also working on getting kfence enabled for specific slabs using
> /sys/kernel/slab/<slab_name>/kfence interface but in the meanwhile
> I am sharing this RFC patch to get some early feedback. Especially
> if this feature makes sense or if there is any better/existing way to
> achieve similar end results.

Do you need the slab restriction from boot? Because if not, I'd much
rather prefer the /sys/kernel/slab/<slab>/.. option; in that case,
it'd also be easier to flip the slab flag to SLAB_SKIP_KFENCE, and
none of the "kfence_global_alloc_enabled" code is needed.

Then if you want to only enable KFENCE for a few select slab caches,
from user space you just write 1 to all
/sys/kernel/slab/<slab>/skip_kfence, and leave them 0 where you want
KFENCE to do allocations.

>  .../admin-guide/kernel-parameters.txt         |  5 ++
>  include/linux/kfence.h                        |  1 +
>  include/linux/slab.h                          |  6 ++
>  mm/kfence/core.c                              | 86 +++++++++++++++++++
>  mm/slub.c                                     | 47 ++++++++++
>  5 files changed, 145 insertions(+)
>
> diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
> index 98e5cb91faab..d66f555df7ba 100644
> --- a/Documentation/admin-guide/kernel-parameters.txt
> +++ b/Documentation/admin-guide/kernel-parameters.txt
> @@ -5553,6 +5553,11 @@
>                         last alloc / free. For more information see
>                         Documentation/mm/slub.rst.
>
> +       slub_kfence[=slabs][,slabs]]...]        [MM, SLUB]
> +                       Specifies the slabs for which kfence debug mechanism
> +                       can be used. For more information about kfence see
> +                       Documentation/dev-tools/kfence.rst.
> +
>         slub_max_order= [MM, SLUB]
>                         Determines the maximum allowed order for slabs.
>                         A high setting may cause OOMs due to memory
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a4b680..140fc4fe87e1 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -125,6 +125,7 @@ static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp
>  #endif
>         if (likely(atomic_read(&kfence_allocation_gate)))
>                 return NULL;
> +

Why this whitespace change?

>         return __kfence_alloc(s, size, flags);
>  }
>
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 0fefdf528e0d..b0def74d9fa1 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -119,6 +119,12 @@
>   */
>  #define SLAB_NO_USER_FLAGS     ((slab_flags_t __force)0x10000000U)
>
> +#ifdef CONFIG_KFENCE
> +#define SLAB_KFENCE            ((slab_flags_t __force)0x20000000U)
> +#else
> +#define SLAB_KFENCE            0
> +#endif

Consider flipping this around and making this SLAB_SKIP_KFENCE, which
would be more intuitive.

>  /* The following flags affect the page allocator grouping pages by mobility */
>  /* Objects are reclaimable */
>  #define SLAB_RECLAIM_ACCOUNT   ((slab_flags_t __force)0x00020000U)
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index c252081b11df..017ea87b495b 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -132,6 +132,8 @@ DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
>  /* Gates the allocation, ensuring only one succeeds in a given period. */
>  atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
>
> +/* Determines if kfence allocation happens only for selected slabs. */
> +atomic_t kfence_global_alloc = ATOMIC_INIT(1);

This does not need to be atomic (kfence_allocation_gate is atomic
because it needs to increment), just use normal
READ_ONCE()/WRITE_ONCE() on an ordinary bool. But I'd also prefer if
we don't need any of this if you go with the SLAB_SKIP_KFENCE version.

>  /*
>   * A Counting Bloom filter of allocation coverage: limits currently covered
>   * allocations of the same source filling up the pool.
> @@ -1003,6 +1005,14 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>                 return NULL;
>         }
>
> +       /*
> +        * Skip allocation if kfence has been enable for selected slabs
> +        * and this slab is not one of the selected slabs.
> +        */
> +       if (unlikely(!atomic_read(&kfence_global_alloc)
> +                   && !(s->flags & SLAB_KFENCE)))
> +               return NULL;
> +
>         if (atomic_inc_return(&kfence_allocation_gate) > 1)
>                 return NULL;
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
> @@ -1156,3 +1166,79 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
>
>         return kfence_unprotect(addr); /* Unprotect and let access proceed. */
>  }
> +
> +#ifdef CONFIG_SYSFS
> +static ssize_t kfence_global_alloc_enabled_show(struct kobject *kobj,
> +                                         struct kobj_attribute *attr, char *buf)
> +{
> +       return sysfs_emit(buf, "%d\n", atomic_read(&kfence_global_alloc));
> +}

Why do you want to make this a sysfs param? Have a look at the top of
the file where we add parameters via module_param(). These can be
written at runtime as well as specified as a kernel command line
param.

> +static ssize_t kfence_global_alloc_enabled_store(struct kobject *kobj,
> +                                          struct kobj_attribute *attr,
> +                                          const char *buf, size_t count)
> +{
> +       struct kmem_cache *s;
> +       ssize_t ret;
> +       int val;
> +
> +       ret = kstrtoint(buf, 10, &val);
> +       if (ret)
> +               return ret;
> +
> +       if (val != 1)
> +               return -EINVAL;
> +
> +       atomic_set(&kfence_global_alloc, val);
> +
> +       /*
> +        * If kfence is re-enabled for all slabs from sysfs, disable
> +        * slab specific usage of kfence.
> +        */
> +       mutex_lock(&slab_mutex);
> +       list_for_each_entry(s, &slab_caches, list)
> +               if (s->flags & SLAB_KFENCE)
> +                       s->flags &= ~SLAB_KFENCE;
> +       mutex_unlock(&slab_mutex);
> +
> +       return count;
> +}
> +
> +static struct kobj_attribute kfence_global_alloc_enabled_attr =
> +       __ATTR(kfence_global_alloc_enabled,
> +              0644,
> +              kfence_global_alloc_enabled_show,
> +              kfence_global_alloc_enabled_store);
> +
> +static struct attribute *kfence_attrs[] = {
> +       &kfence_global_alloc_enabled_attr.attr,
> +       NULL,
> +};
> +
> +static const struct attribute_group kfence_attr_group = {
> +       .attrs = kfence_attrs,
> +};
> +
> +static int __init kfence_init_sysfs(void)
> +{
> +       int err;
> +       struct kobject *kfence_kobj;
> +
> +       kfence_kobj = kobject_create_and_add("kfence", mm_kobj);
> +       if (!kfence_kobj) {
> +               pr_err("failed to create kfence_global_alloc_enabled kobject\n");
> +               return -ENOMEM;
> +       }
> +       err = sysfs_create_group(kfence_kobj, &kfence_attr_group);
> +       if (err) {
> +               pr_err("failed to register numa group\n");

numa group?

> +               goto delete_obj;
> +       }
> +       return 0;
> +
> +delete_obj:
> +       kobject_put(kfence_kobj);
> +       return err;
> +}
> +subsys_initcall(kfence_init_sysfs);
> +#endif /* CONFIG_SYSFS */
> diff --git a/mm/slub.c b/mm/slub.c
> index 862dbd9af4f5..7ee67ba5097c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -645,6 +645,7 @@ static slab_flags_t slub_debug;
>  #endif
>
>  static char *slub_debug_string;
> +static char *slub_kfence_list;
>  static int disable_higher_order_debug;
>
>  /*
> @@ -1589,6 +1590,27 @@ static int __init setup_slub_debug(char *str)
>
>  __setup("slub_debug", setup_slub_debug);
>
> +#ifdef CONFIG_KFENCE
> +extern atomic_t kfence_global_alloc;
> +
> +static int __init setup_slub_kfence(char *str)
> +{
> +       if (*str++ != '=' || !*str)
> +               return 1;
> +
> +       slub_kfence_list = str;
> +
> +       /*
> +        * Disable global kfence usage if specific slabs
> +        * were specified in bootargs.
> +        */
> +       atomic_set(&kfence_global_alloc, 0);
> +
> +       return 1;
> +}
> +__setup("slub_kfence", setup_slub_kfence);
> +#endif
> +
>  /*
>   * kmem_cache_flags - apply debugging options to the cache
>   * @object_size:       the size of an object without meta data
> @@ -1653,6 +1675,31 @@ slab_flags_t kmem_cache_flags(unsigned int object_size,
>                 }
>         }
>
> +       /* Check if kfence has been enabled for this slab */
> +       iter = slub_kfence_list;
> +
> +       while (iter && *iter) {
> +               char *end, *glob;
> +               size_t cmplen;
> +
> +               end = strchrnul(iter, ',');
> +
> +               glob = strnchr(iter, end - iter, '*');
> +
> +               if (glob)
> +                       cmplen = glob - iter;
> +               else
> +                       cmplen = end - iter;
> +
> +               if (!strncmp(iter, name, cmplen))
> +                       flags |= SLAB_KFENCE;
> +
> +               if (!*end)
> +                       break;
> +
> +               iter = end + 1;
> +       }
> +
>         return flags | slub_debug_local;
>  }
>  #else /* !CONFIG_SLUB_DEBUG */
> --
> 2.30.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNmD9z7oRqSaP72m90kWL7jYH%2BcxNAZEGpJP8oLrDV-vw%40mail.gmail.com.
