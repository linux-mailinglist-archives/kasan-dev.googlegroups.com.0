Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFMR7FAMGQE2RCPAOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E3DE5CCB59D
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 11:24:13 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-88a43d4cd2bsf5565676d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 02:24:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766053452; cv=pass;
        d=google.com; s=arc-20240605;
        b=a+AibDxnE5G7IIlGnOVvLOQsMcI+2jtsfK4cGTb+jUSFBXVlqdRy7qHmCHx9F3Grx7
         WWhz4ljy0ZCDdFMWWE0TxtDY0mQjwO4gj77O4mMD47/8VATKMFYILCwPC67fM6wDLRUc
         +B3q87A0nQrjWImtxWd5q5NmoHjCPE7QaRIo05HL+vek2xjmNPhwafdm7BlwCZOYrKEk
         la/AO4qo3vHWI6wl2SeACutvY6ep1q8nOa6IxOz4sryWOVpWb2AtukedYrtPPniCaaiV
         q0bvhWQt7jDL9ZOkQRqV70DxJW3KTwDIcHYgWVfLlzaUIVUPN/sAl82HRFFJViUBYdpq
         EoiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=btASJgqZ2Wpxxq0QcfoACZb6bublPtSG4LMF2YgCK9k=;
        fh=j/6/FuTfrqsK5mjxCgZuPoN9RKJMUYqf4cFLVay2S6Y=;
        b=T5rD6kvMHA2VKm4g67uzjUmrTSdBkEv8wFgMqkLx0LNJCEkHlhtObSS8+qVwUkj9Bq
         A6135dHWIaOdemGCxDmqS/vSjEmbnswB+XQ1IYayBGSh9Mkc6EyeYMYj387QKXvhSM6C
         OE6kznPhe9MwkrRliNrNdI8ZI0rUa6r01sb/pwZC8PDdQwdoZJ5fXy6nBnpB4IhqmDwQ
         uTR4t+AeNBTwP/+pCk77lM+Ky+5Hklwwt6vskh3Km8lOdJGIlKJe0+iLXB8QwGktEE8J
         DF4oyAxxSjX6dGhwIWPhqT/VkYo0gyWMabH5bCkptaubJhCkCT0mwHyAF1elKy9VQbR7
         ISwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eYeDsl6z;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766053452; x=1766658252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=btASJgqZ2Wpxxq0QcfoACZb6bublPtSG4LMF2YgCK9k=;
        b=wKSGjjAd80aw5xQBhSDsO/vW8tssDjSbH/BJIpXoCWqOBPefQXsX8mIPa+moQnD2GY
         05D4Q3YaZ3kiX7QH2aZPk8Cy0C3HaKa6mGceO96BE3sA8TbXjL2BWghqAoyKHoQzI4ua
         7IS0rOUDAqZ6elO7n4w5r5JDBkoVH/ImPUp4KHmtd94wXXX1fpmX/Q7NYlpk4nfROKU0
         mhUe5+VgBuKhybQreF9H4plfhwcmyS17cUh6LVrWN2OBEn25/LwAHhsQFAWVSNG3RMMV
         V80/7/IfxzDSm+44jFJfnlSgkO4QyKxieYXh/Eq3fFYm/NemIz+B1TUNuBxok01CrgbS
         IJAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766053452; x=1766658252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=btASJgqZ2Wpxxq0QcfoACZb6bublPtSG4LMF2YgCK9k=;
        b=Hhgx36joj+YS4KhuXQPpZdwzYUvT6ZQmJbZs4Xbg/f94NU8Zbug55RVFhOUKlGPpVw
         QXZDg4Gm8urV30qce45wmTUOepjeg7zldjwePBnGDohTwCJxUxFUO9N2Dd0Tu/uuYuB8
         15puj4uN2O7JwbXMW9gmuRq6dT6ZFFjLqjS7f6EJDr3Ae6aVJw7wCZ8voe04H6Dr30qQ
         1EWvk9LYgqIfiRjJbVxHjwtFsegNL6iXSbQ8CDyLZ/ptO5TRuwZQz0QecJW+UqlCEBOQ
         ZvKMn9g6vacCzrA5YnDZYNn1RfyaSyCS4NGXyJRe3t+XA0/b6sH5Ck/H0yI3JzcLQFdz
         XtIA==
X-Forwarded-Encrypted: i=2; AJvYcCVvNzet2Rz3ZcWFMGJ0PYk5OnguRBTlH+42POYPTVq169fxEFxK5qr4TWpcS09RfXque60XCw==@lfdr.de
X-Gm-Message-State: AOJu0Yxu+9Km9QJvbl/4pWsvDr1pr7O1p71coeYx7ZrYSVvqS9UZZGt3
	ZljI5pFeE+j/p0eOUAgZAb+gBOKxfOl/9b2zlsYUM5qWxIuRBgqEzdeQ
X-Google-Smtp-Source: AGHT+IFADH6mN3Hewlt3cUU1hvtruOG7a6w0R1XT7cDbcPXxtq/gS+VUzPP8tfb3V5D3bT61MDTiZQ==
X-Received: by 2002:a05:6214:5285:b0:880:4c73:9e3b with SMTP id 6a1803df08f44-8887e42cd54mr296649856d6.15.1766053452498;
        Thu, 18 Dec 2025 02:24:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaGQq5SZTY0Z0w2c8vG7qPsJNQaE8y/iJ8KURUuyFZQgA=="
Received: by 2002:a05:6214:3005:b0:888:3ab3:a46f with SMTP id
 6a1803df08f44-8887c7fa6adls95602746d6.0.-pod-prod-08-us; Thu, 18 Dec 2025
 02:24:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWidz71sbZYAf/75oYjcFy18x4/ViWUAiqvDQd0YWvMfNGsfPEZR03Wdl6WzK+KvEhHaJ/XvD+dJhI=@googlegroups.com
X-Received: by 2002:a67:e703:0:b0:5b1:15:1986 with SMTP id ada2fe7eead31-5e82768b167mr5929938137.15.1766053451111;
        Thu, 18 Dec 2025 02:24:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766053451; cv=none;
        d=google.com; s=arc-20240605;
        b=jxTPajNDWM7rLfTP1nS0lgEH/OmUkYvxbvogT2JLi4Lo95g9tM0uJXwn/DffN1Ttkv
         Qi2sdeBGWGdnTm7+hkQ9sSdWIB/kxUJ2valsNMEs6MI1cHvB/yzJeL9z8PyBS0QykLDg
         afNi+ihqaiSk176R1vtQu5FIJQ6U3rQ2clYVM+lzLNm/Tk9AA/gUwGl9xg1ShyCgoLP9
         B+ySEHXFHjiSqY0GFNqjJ8w32xLQp1AjpeExKFKwjGhrsv0Yqnm3Nkt/B1LyJt/bU9hm
         3AdmwbB5YnLcHSfFGnzILvrs9szh+InFuBQ+7Fz6goVXDFAowFarpdWxw13L1LVpPL7C
         /aVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WslnZ1panE0zhxGDe3aCJhXLiwIja75afp2ehy4KLwk=;
        fh=BppgxwSb8oyQP2YJzBxbq/W2KPGnwXUCnNO/S9zDLO8=;
        b=NeKYRO33UElW3KN8//lQwpDOaJ5X8BxERZqkByZjkJE19AO13t+o8/uRoFpOGExUpC
         8Ou/Ev2RIz9uGRLZi5+ZHjIOcJx1weTnKrJ0fU1+0N6ke4vnejtTBi3mYbWoKM03Ajiv
         qgfGIEFin5RFF1JMTsUu+yVCQelb2Tls7Bn4cX5FXuJDqE/998D4y4eWsUpTY6tkmtEM
         vIXbK6ZG1wFBROkGpQQqvSwTaZWH8ICGOAFUlApNJU7HHlwHy7Vz4Ypnkve1fDQY+EUP
         XFB9KspgAHLe2WHQDTGN1QuHrI1z4fO9UZfFfKJKYvJe3N3D3KeIR+0u9iamqiq9ktWe
         mV+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eYeDsl6z;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-94331058528si83802241.0.2025.12.18.02.24.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Dec 2025 02:24:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7bb710d1d1dso853262b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Dec 2025 02:24:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUAj+ti6umM9t8t63+RKYr8Ou5XYKEMaM98/yITrKYYOILOp6Omn5dmiMZvuLuuNC15zT18KWNXfJ0=@googlegroups.com
X-Gm-Gg: AY/fxX573kAnJ+2ZfQZlja9Vr19TbVjdcM59qw4qZ5tgs3zQBOj3rX18PXTFlzq30H9
	7M6ZmuXRFKCmCQ1f4ePRRs1fgQbursyOr3bRsUjEAu0r685Hlxw5WZKutq/WAhsIobsApqmVxxH
	gv48s2sTgzX3yfw+KMpbfCmAJMfVpI+z4J/fyEYJVbb/J4FaL5Q98D1vpzGimWPPA8h+d5ueIOK
	F5cg+qHRANIf3KGRkTc/6ITRgkfay/XZ4D9a+ZMXXRc7FDes9AgEWRj2xxMubEiBYqA7kMvpOEe
	MdR4qTkbSdyY//50IOPE0rnpCvW+/A6LAzpr6g==
X-Received: by 2002:a05:7022:f503:b0:119:e56b:c75b with SMTP id
 a92af1059eb24-11f34c2625amr13304701c88.32.1766053449983; Thu, 18 Dec 2025
 02:24:09 -0800 (PST)
MIME-Version: 1.0
References: <20251218063916.1433615-1-yuanlinyu@honor.com> <20251218063916.1433615-3-yuanlinyu@honor.com>
 <aUPB18Xeh1BhF9GS@elver.google.com> <7334df3287534327a3e4a09c5c8d9432@honor.com>
In-Reply-To: <7334df3287534327a3e4a09c5c8d9432@honor.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Dec 2025 11:23:33 +0100
X-Gm-Features: AQt7F2ri_watnVgJFp6cbP7eAfmz1Mi-buK4oLrIxtfdr5TG5N1pjsoHb_vA5KU
Message-ID: <CANpmjNMmiXjifpc9LdCVi5jzzKU3sgb0iJn7P7TMFMNqDH7TbA@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kfence: allow change number of object by early parameter
To: yuanlinyu <yuanlinyu@honor.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Huacai Chen <chenhuacai@kernel.org>, 
	WANG Xuerui <kernel@xen0n.name>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"loongarch@lists.linux.dev" <loongarch@lists.linux.dev>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eYeDsl6z;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as
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

On Thu, 18 Dec 2025 at 11:18, yuanlinyu <yuanlinyu@honor.com> wrote:
>
> > From: Marco Elver <elver@google.com>
> > Sent: Thursday, December 18, 2025 4:57 PM
> > To: yuanlinyu <yuanlinyu@honor.com>
> > Cc: Alexander Potapenko <glider@google.com>; Dmitry Vyukov
> > <dvyukov@google.com>; Andrew Morton <akpm@linux-foundation.org>;
> > Huacai Chen <chenhuacai@kernel.org>; WANG Xuerui <kernel@xen0n.name>;
> > kasan-dev@googlegroups.com; linux-mm@kvack.org; loongarch@lists.linux.dev;
> > linux-kernel@vger.kernel.org
> > Subject: Re: [PATCH v2 2/2] kfence: allow change number of object by early
> > parameter
> >
> > On Thu, Dec 18, 2025 at 02:39PM +0800, yuan linyu wrote:
> > > when want to change the kfence pool size, currently it is not easy and
> > > need to compile kernel.
> > >
> > > Add an early boot parameter kfence.num_objects to allow change kfence
> > > objects number and allow increate total pool to provide high failure
> > > rate.
> > >
> > > Signed-off-by: yuan linyu <yuanlinyu@honor.com>
> > > ---
> > >  include/linux/kfence.h  |   5 +-
> > >  mm/kfence/core.c        | 122
> > +++++++++++++++++++++++++++++-----------
> > >  mm/kfence/kfence.h      |   4 +-
> > >  mm/kfence/kfence_test.c |   2 +-
> > >  4 files changed, 96 insertions(+), 37 deletions(-)
> > >
> > > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> > > index 0ad1ddbb8b99..920bcd5649fa 100644
> > > --- a/include/linux/kfence.h
> > > +++ b/include/linux/kfence.h
> > > @@ -24,7 +24,10 @@ extern unsigned long kfence_sample_interval;
> > >   * address to metadata indices; effectively, the very first page serves as an
> > >   * extended guard page, but otherwise has no special purpose.
> > >   */
> > > -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 *
> > PAGE_SIZE)
> > > +extern unsigned int __kfence_pool_size;
> > > +#define KFENCE_POOL_SIZE (__kfence_pool_size)
> > > +extern unsigned int __kfence_num_objects;
> > > +#define KFENCE_NUM_OBJECTS (__kfence_num_objects)
> > >  extern char *__kfence_pool;
> > >
> >
> > You have ignored the comment below in this file:
> >
> >       /**
> >        * is_kfence_address() - check if an address belongs to KFENCE pool
> >        * @addr: address to check
> >        *
> >       [...]
> >        * Note: This function may be used in fast-paths, and is performance
> > critical.
> >        * Future changes should take this into account; for instance, we want to
> > avoid
> >    >>  * introducing another load and therefore need to keep
> > KFENCE_POOL_SIZE a
> >    >>  * constant (until immediate patching support is added to the kernel).
> >        */
> >       static __always_inline bool is_kfence_address(const void *addr)
> >       {
> >               /*
> >                * The __kfence_pool != NULL check is required to deal with the case
> >                * where __kfence_pool == NULL && addr < KFENCE_POOL_SIZE.
> > Keep it in
> >                * the slow-path after the range-check!
> >                */
> >               return unlikely((unsigned long)((char *)addr - __kfence_pool) <
> > KFENCE_POOL_SIZE && __kfence_pool);
> >       }
>
> Do you mean performance critical by access global data ?
> It already access __kfence_pool global data.
> Add one more global data acceptable here ?
>
> Other place may access global data indeed ?

is_kfence_address() is used in the slub fast path, and another load is
one more instruction in the fast path. We have avoided this thus far
for this reason.

> I don't know if all linux release like ubuntu enable kfence or not.
> I only know it turn on default on android device.

This is irrelevant.

> > While I think the change itself would be useful to have eventually, a
> > better design might be needed. It's unclear to me what the perf impact
>
> Could you share the better design idea ?

Hot-patchable constants, similar to static branches/jump labels. This
had been discussed in the past (can't find the link now), but it's not
trivial to implement unfortunately.

> > is these days (a lot has changed since that comment was written). Could
> > you run some benchmarks to analyze if the fast path is affected by the
> > additional load (please do this for whichever arch you care about, but
> > also arm64 and x86)?
> >
> > If performance is affected, all this could be guarded behind another
> > Kconfig option, but it's not great either.
>
> what kind of option ?
> It already have kconfig option to define the number of objects, here just provide
> a parameter for the same option which user can change.

An option that would enable/disable the command-line changeable number
of objects, i.e one version that avoids the load in the fast path and
one version that enables all the bits that you added here. But I'd
rather avoid this if possible.

As such, please do benchmark and analyze the generated code in the
allocator fast path (you should see a load to the new global you
added). llvm-mca [1] might help you with analysis.

[1] https://llvm.org/docs/CommandGuide/llvm-mca.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMmiXjifpc9LdCVi5jzzKU3sgb0iJn7P7TMFMNqDH7TbA%40mail.gmail.com.
