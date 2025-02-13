Return-Path: <kasan-dev+bncBDW2JDUY5AORBGM7WW6QMGQERLT6FOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 760ADA334F2
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 02:49:14 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-38dc88ed7casf202802f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 17:49:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739411354; cv=pass;
        d=google.com; s=arc-20240605;
        b=XtydTN2JS7eadz1taygt7qunKa9w/20yWp9kcsfaS754v712orsuO+B9hNiBVsMUek
         8I75QU/67nYGZ6nK7Jp/iqDSazXYYTP2UM+sIR643FL5smxZ3wBN9DisK6U7lH9Y0/j5
         DHf2YNUy2zFd2GU9FYsq9dwCZs+Xaa2jQbhaoz8q0j6W7SyaDixsP7U7tVx5vwPTbHhx
         PA09oJLxZbNIP03z422CrsVIfcco7oRsvfBb4cuiYW3XP/0U4V6loSnK2P6C0u9WPPVQ
         vX93phAJf6kmGgU8EiqVctwHA5ETD/KGH0r8U90/QGBjUj4x+7tvWDVqOUBqTaT8yjB3
         Ig6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=7fbg6zdLj/eD2YzXna/Viwqg2aaoUeaGbtYMByFTmJE=;
        fh=moPPIR3VSQcKhN7jhcP+4c2KB7DTCAZcoO1gXMTA93Y=;
        b=a/fhI3mr1HC+Bz7+h4ZgDFLVckZY9sYZGah1P6nFvpUBFyDmTu1erTv7hqF+z61zum
         XCuh7C0BsnjOsxGUJcrtRX6N+Xtvo+swHe/ZDF9bMWAb2hzazH9JLWlCuyfAOsg2oPn9
         99TgzlCSLV48gzbcwL/JOP7MbSWRCRL+ZEmSS1FIp4qAwyEfilPqKTaSnez3Qc3bNQ7E
         9qR0gtYYL3cQMxhM1p1RWLSP/ezm02KFM6V0Dskzqbd/EAyz0AbdbWSkmt1/zRHrowVF
         u/kT1DjbbUEU3+UtRY44yuPYXyFADHDUKTSd65+VK0dno06DRpRVDI9aTZf0A+h9ZECs
         3leA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="LWoo5Nt/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739411354; x=1740016154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7fbg6zdLj/eD2YzXna/Viwqg2aaoUeaGbtYMByFTmJE=;
        b=PQCrxqX/bD7chY7+hk9BoN/poAtPp/Xwnbg4bYHdtkuX7bXfGEjbpEAUuLO+y42hq2
         foT6qjJNk6lSGzqKxh/KQsRZR+CxOffWpxKBeYTJIzneI3c0FYXiRpJjCBI4DMX33cub
         U/q6/Wgq3z/RJ7rgXfz3TayxCp9ECzxvE8ReRwbhCHAhUTbrMJHlQ0bgo7pxkQpVY9Du
         vfqKoTq0rM3eH/UAK9HKTNTndO1blQSENgBXLsB4PwMCcu//7yBbulf5wvwm23Enrsya
         Zi+toG1CELlEluDzrr4YpeSTJkXwTvaTOvK/hOSnfMVs70EB1Z4rP/s9XHS3G3S57pVm
         DVxQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739411354; x=1740016154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7fbg6zdLj/eD2YzXna/Viwqg2aaoUeaGbtYMByFTmJE=;
        b=GQe5LVN/Ren4N1SSMMIRfgMQlzaA3r2B09a5H2LA10KRI0Jlis+Z2nwMDNhlwrN8cG
         tV05blQWEsRKmn2EkfeJZLwT8WeNnpNyCMnzoXuGa7bPFZz1U5PRm462SmDLRLopq3y+
         6DvhNfdwsyn5CM16VlHDwpYSlz22v6dHtlv3L/CxKDi/1S7vX3HKI3y/9t9lAub9QeSL
         J1OXfh6QI2f+urA/qbIgfw54DwJtUji/PefJX06/6paD56nSSsQkpESgrg4NRt8n2N5h
         kYELc9o5LsOmAtvGtXuPaIGTeU6OoWW8Au+Iazi9iyvCh/jUEnvjR6F87qqIKLOqaTef
         pCWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739411354; x=1740016154;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7fbg6zdLj/eD2YzXna/Viwqg2aaoUeaGbtYMByFTmJE=;
        b=biwd4i21ULWto4x5s357A5C01Jz8ZaZ/8LoRTO8vxtKSYf4B9p69MVMHOkoz9ZMLpo
         qxAMm4YcXd8asZEm0hqpVtYrbaXNSyh73O0zzZzB+AbuUOJaUf/KFROoEPDzucB0WvRd
         HHSB+soSiqn/eOtMk5c8qbA8QgdCYfMVvPlC3od4GPlJ6BD0pc+Tl41A8rrLksHCdWdF
         6m8fd53+TGe0pcRgjHIj5xDi2+d4R+ZdzLvNjycIUmjEXrNlPIiMd4ZQNMESrp2yND8F
         GLadmP+w/z6BxQEB4H3jsqvx9L4+03icAR5eqlg2A+iFvNzkUj9qgKHfyLF50mXP0TEj
         Syuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUl5qpM0J1832aeXlcCcrI5frZnrPp84xplPZLhdq+uKSfqsofTwU67KdgYQ7XmDcMgqNtVqg==@lfdr.de
X-Gm-Message-State: AOJu0Yw2ls+Nl1LgnzBzMfJ6aqERh/fZSru+w4ezcjU/HBAr7lXk6ZgU
	HBXoDoDZ2e9pXRIfI0t9Ldiw3JBOJk8w4eBI4couBA4SsQUIgKva
X-Google-Smtp-Source: AGHT+IGBNxxq1xaq4vMs/+L/fJ+SlmPbf6ERaCkPDrBgs/U20FupRNiFQnWmjJ+lcDiGG6v7dtO1fg==
X-Received: by 2002:a05:6000:186d:b0:38d:da11:df3c with SMTP id ffacd0b85a97d-38dea2e9ed7mr4741761f8f.48.1739411353534;
        Wed, 12 Feb 2025 17:49:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHMgUesjELbRkhCVl7ur2Z+iQeX1oQlTlm2O1DOzNwF9A==
Received: by 2002:a05:6000:4024:b0:38f:2234:229c with SMTP id
 ffacd0b85a97d-38f24685f3als143053f8f.1.-pod-prod-07-eu; Wed, 12 Feb 2025
 17:49:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVPdmOdZ4VZvx7Jkg+qjtNd8C30pxD8u9wxFBDjDIWYU8tRQxU5rnIqAzMS/Kvt8q0z5F/rMtmrHEc=@googlegroups.com
X-Received: by 2002:a05:600c:35ce:b0:436:ed38:5c7f with SMTP id 5b1f17b1804b1-43958176904mr58253455e9.12.1739411351127;
        Wed, 12 Feb 2025 17:49:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739411351; cv=none;
        d=google.com; s=arc-20240605;
        b=c3AC99uRHSYAnpvqlS4nl3dodpTK08yj6DNDWgzt3XE0N54OdTO2+kwLAe4KJ67opl
         W1CTAiwEgRG82T8UcX0vbZcJRnIn0ttGr7s/gupDq82Uk07g6yshMbMazkrSQeAH986n
         ws0wVKcQwqjR2XX9cBbCWsyi0tdDNmz0AZkrD0sOVzm73BXLqfCD8PiBsD9JoVDDcN08
         MKe9dohBddEdDotNvLLqSiVAp1UOvlZVKFztjShfDH62FyT2mzXuKNqNCOAvxxqUkzKz
         aOB9rxfn+8Kmgp/RAl+nZ9LyzFwEt1W8g7Uuh4MhgRGXWpwxI1Ieg7Er8xkJk4fBzfGE
         /aXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/wY4wXs5+HLRneqjqUBolpxhGqLVUYvpAwoIF6j/MLQ=;
        fh=hNJ4M81AgpfZ7gChtRw/QqHih4JRz+L1mIzZX/+SJvE=;
        b=TVm6Vdcec0beIT7Bm3YaBcs5/XN/q8j7Naczttr/TSnSWeuXap0t02ooP9jcJgRaAm
         DfOEnENhVIjptUGqxnrnI9gCa5KibxGpiBytvxZvCOEoDNBFAlAjPm427gmuMu7chbi0
         CroHMmY8fP8eLJ26827xH40QuCjdASkD9HGwrjeCMIlVJ3zQdfL4Yomu4/u9TORE8CQM
         MxPRcPpnRRl5E+qW7Mbszom7cGC7lxU5RYLkqE9iagloHqgFg7JnnQTer3kwBxmrBAyk
         TjRHiBBpbHKhcaiW/zMwMqZLdHA3pCV6SreJc6Pp7kLKq/6xaapUisLhYD2hfmVj9g2D
         k+qg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="LWoo5Nt/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4394dc49feasi2569105e9.0.2025.02.12.17.49.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 17:49:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-43948021a45so3492085e9.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 17:49:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWAVHbib7wLttrSdHXE3eep7J3QYLbhuE8htVVLZRZX4dvWuUqCdf60vqLbsOIiEfYFF9tzvLr5+VU=@googlegroups.com
X-Gm-Gg: ASbGnctIA4PKIIGV0bnUS7W58DCeXbFKpdZQEEH85VQ25i+wvTBEnKkBbkqbXsljjWq
	rUaqrzemGk/77/F9Yr/0rjzGw9tjRWDnIbDHlGKUa0GeaI4YJ/G0g9PykOaxbq/dPhV5AJLeeoD
	s=
X-Received: by 2002:a05:600c:1d9b:b0:439:60ef:ce94 with SMTP id
 5b1f17b1804b1-43960efd0ffmr6349015e9.21.1739411350285; Wed, 12 Feb 2025
 17:49:10 -0800 (PST)
MIME-Version: 1.0
References: <20250212162151.1599059-1-longman@redhat.com>
In-Reply-To: <20250212162151.1599059-1-longman@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 13 Feb 2025 02:48:59 +0100
X-Gm-Features: AWEUYZlva8wcqIGZAMNqHBqIKxnv5SeuKq11Lnse6U1bm1Vg8g3HRUGtElXJDM4
Message-ID: <CA+fCnZdbW1Y8gsMhMtKxYZz3W6+CeovOVsi+DZbWsFTE2VNPbA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Don't call find_vm_area() in RT kernel
To: Waiman Long <longman@redhat.com>, Peter Zijlstra <peterz@infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Clark Williams <clrkwllms@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	Nico Pache <npache@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="LWoo5Nt/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Feb 12, 2025 at 5:22=E2=80=AFPM Waiman Long <longman@redhat.com> wr=
ote:
>
> The following bug report appeared with a test run in a RT debug kernel.
>
> [ 3359.353842] BUG: sleeping function called from invalid context at kern=
el/locking/spinlock_rt.c:48
> [ 3359.353848] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 140=
605, name: kunit_try_catch
> [ 3359.353853] preempt_count: 1, expected: 0
>   :
> [ 3359.353933] Call trace:
>   :
> [ 3359.353955]  rt_spin_lock+0x70/0x140
> [ 3359.353959]  find_vmap_area+0x84/0x168
> [ 3359.353963]  find_vm_area+0x1c/0x50
> [ 3359.353966]  print_address_description.constprop.0+0x2a0/0x320
> [ 3359.353972]  print_report+0x108/0x1f8
> [ 3359.353976]  kasan_report+0x90/0xc8
> [ 3359.353980]  __asan_load1+0x60/0x70
>
> Commit e30a0361b851 ("kasan: make report_lock a raw spinlock")
> changes report_lock to a raw_spinlock_t to avoid a similar RT problem.
> The print_address_description() function is called with report_lock
> acquired and interrupt disabled.  However, the find_vm_area() function
> still needs to acquire a spinlock_t which becomes a sleeping lock in
> the RT kernel. IOW, we can't call find_vm_area() in a RT kernel and
> changing report_lock to a raw_spinlock_t is not enough to completely
> solve this RT kernel problem.
>
> Fix this bug report by skipping the find_vm_area() call in this case
> and just print out the address as is.
>
> For !RT kernel, follow the example set in commit 0cce06ba859a
> ("debugobjects,locking: Annotate debug_object_fill_pool() wait type
> violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
> inside raw_spinlock_t warning.

Would it be possible to get lockdep to allow taking spinlock_t inside
raw_spinlock_t instead of annotating the callers for the !RT case? Or
is this a rare thing for this to be allowed on !RT?

>
> Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
> Signed-off-by: Waiman Long <longman@redhat.com>
> ---
>  mm/kasan/report.c | 47 ++++++++++++++++++++++++++++++++++-------------
>  1 file changed, 34 insertions(+), 13 deletions(-)
>
>  [v2] Encapsulate the change into a new
>       kasan_print_vmalloc_info_ret_page() helper
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 3fe77a360f1c..9580ac3f3203 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -370,6 +370,38 @@ static inline bool init_task_stack_addr(const void *=
addr)
>                         sizeof(init_thread_union.stack));
>  }
>
> +/*
> + * RT kernel cannot call find_vm_area() in atomic context. For !RT kerne=
l,
> + * prevent spinlock_t inside raw_spinlock_t warning by raising wait-type
> + * to WAIT_SLEEP.
> + *
> + * Return: page pointer or NULL
> + */
> +static inline struct page *kasan_print_vmalloc_info_ret_page(void *addr)

No need for the kasan_ prefix: this is a static function. (Also the
_ret_* suffix is something I've never seen before in the kernel
context, but I don't mind it.)

> +{
> +       if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
> +               static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEE=
P);
> +               struct page *page =3D NULL;
> +               struct vm_struct *va;
> +
> +               lock_map_acquire_try(&vmalloc_map);
> +               va =3D find_vm_area(addr);
> +               if (va) {
> +                       pr_err("The buggy address belongs to the virtual =
mapping at\n"
> +                              " [%px, %px) created by:\n"
> +                              " %pS\n",
> +                              va->addr, va->addr + va->size, va->caller)=
;
> +                       pr_err("\n");
> +
> +                       page =3D vmalloc_to_page(addr);
> +               }
> +               lock_map_release(&vmalloc_map);
> +               return page;
> +       }
> +       pr_err("The buggy address %px belongs to a vmalloc virtual mappin=
g\n", addr);
> +       return NULL;
> +}
> +
>  static void print_address_description(void *addr, u8 tag,
>                                       struct kasan_report_info *info)
>  {
> @@ -398,19 +430,8 @@ static void print_address_description(void *addr, u8=
 tag,
>                 pr_err("\n");
>         }
>
> -       if (is_vmalloc_addr(addr)) {
> -               struct vm_struct *va =3D find_vm_area(addr);
> -
> -               if (va) {
> -                       pr_err("The buggy address belongs to the virtual =
mapping at\n"
> -                              " [%px, %px) created by:\n"
> -                              " %pS\n",
> -                              va->addr, va->addr + va->size, va->caller)=
;
> -                       pr_err("\n");
> -
> -                       page =3D vmalloc_to_page(addr);
> -               }
> -       }
> +       if (is_vmalloc_addr(addr))
> +               page =3D kasan_print_vmalloc_info_ret_page(addr);
>
>         if (page) {
>                 pr_err("The buggy address belongs to the physical page:\n=
");
> --
> 2.48.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdbW1Y8gsMhMtKxYZz3W6%2BCeovOVsi%2BDZbWsFTE2VNPbA%40mail.gmail.com.
