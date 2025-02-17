Return-Path: <kasan-dev+bncBDW2JDUY5AORBTGHZW6QMGQEGDW7CAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E8E2A3891E
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 17:29:02 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-ab77e03f2c0sf491730966b.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 08:29:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739809742; cv=pass;
        d=google.com; s=arc-20240605;
        b=FFPX+0D8ABNQCfPbmhKntAybvOzZiAvgA4pV/nVj1G/TLF61MxPMU+UxtasXbzcMoV
         HhebwwFcnWvL3uXZJDGAaBgznGOL/IagrSy9/7cPfAPYL0IcYAJaZdBjWa9N58obwL1W
         IdfX4od+zGYW2c1/eWwA3li8M6HNAqrea8DHJDr8geF+7rxiJACbqdBv/vi9Dqi/aq0N
         pMB0qxxNIOvi/16w/2G4lMl9Zh2ZshXu9kjGQxik7anStzn0+zRsaZdPL8qsP/ZC2PAW
         wrvJACOHeBU0AukENliZlAgK7Epu5glKpUDEirG/uvhL9xpxUk3OjOeuCrIr9G+HQUbi
         yyVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/w6j+5U1argEFdQl6rqUOkwRYJ3ioJSNjFpqSaFn4qs=;
        fh=xWp05MDIyvSdmZQ612w7dSlGd2tqig4gAQJahWBw9ec=;
        b=Mj987VG/3G/gI0BKg/+tcFRCa9ASvn4xZTyBaYJezHO+DhWD8JGxhpfPs052ULhwRo
         Bzrh2NHdBpKdaiSSmACgn2uniCqkH+edQLItWzKhjMAnBv39Xd48vwWK5FxjoKP3ypRk
         Qyfn8LF6uSeGWw+VNM3UzXkW6oLfqWAi2FpOgfqgsOWCJ+mPFK7cZ5MDay7NPrxzGsoc
         a8t0lcTWn3djM7Sn0gRTQZRebT3lQ8n6rsP/AJCwk3IPjS6u8BZzNEGL9dL9f0W7E8+g
         gPBg8YvknoI+FCoLmn333Kuc3BhtAEkmVzfAog+pzFusAXMicqX5Zj3rlX9BUUIipui4
         vpBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mr+mku5T;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739809741; x=1740414541; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/w6j+5U1argEFdQl6rqUOkwRYJ3ioJSNjFpqSaFn4qs=;
        b=p3lRtFJ+rTHSSSO3N5CJqcUH+SR263GFYGheL+0Rh+CtIIfrmHGDLS4RdLXd+e7wRu
         zxR6rvBYvrAd1vl8NTRKeoUWnOODYAKJVf/uV8TjhA0BbAP+VluoT/LnI2Cpip9epFDU
         XkiiaX8wjQl9h8aMf59EYvCez3KPPKvnJ4jScdxVFiGNJs0Ds4UilRZWDyCIvkvFspzD
         quC80aWYWIB540GDWxUrRbZfw/GtNiTNBSl64/JokmgFz7upLrZQBhwQlt/e3BKFzEFF
         Rjp2kxWRnhdmHTP/FKSjWioR4iOWWfF1Ep2jfDmt1H4ipMZZIqgru/5axOWX6fZEydxS
         xK1w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739809742; x=1740414542; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/w6j+5U1argEFdQl6rqUOkwRYJ3ioJSNjFpqSaFn4qs=;
        b=NDk/m5xfyMUFQXm3NAOhsFgtL8OB0Af9MrQX3lbgxWOQVf3IWhzz7+PonzrImGsAkD
         6Us53jywU8W3gp7+cWGKByfGWR+2DaCi7D88FikdUzrJBJB+eVX1VQzkhvxy5Lw2xVEU
         Dq/ZY6NIqLHfbTaRTTHL8wrhn3cf+HXXuiT3rWASYK8oVgvnqmvJfTzA9eravposcby/
         JHM7l2DV73BSAdtN/Xh/7y26D3OE1ZlgROwEz1ABLKbsWH50eQ0jJNRCNNPuELc3uTGz
         JCdiG0cQ9bFRLVU77B9ffRD30ZJB/g2tQtGPfEGAv1/aIDGz8YhtE3jG0o6XitE1+S6C
         cX7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739809742; x=1740414542;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/w6j+5U1argEFdQl6rqUOkwRYJ3ioJSNjFpqSaFn4qs=;
        b=l/dbjMBTV3pOV40HMhDk4/JXzqtG8qmBrQcuOqeZdntNhARd56qekobjQOggBFpfl6
         Jji/CBhZLdc9rX2A2Jcgtbk76RecDMHt5vnV9oAiGDML+Sy5QliP9jWkVD3tYPzVygEx
         1HNpcc3SQC7qbuSOkwfn2WcPPbt6OBA94hljcpD1ZeqtSt7HD/bPGp2ZVjRQBmriVCr1
         VbEy7SGIeOCELNL8Tt1ojZ931PT95idZFyWI7V5H81s5nLeNWFHOYMgkiwmkhagRYmQH
         VsSIz03m3kE/yWR2RqgRSHmu6AbuZ9mtlthz4SP1Fzt8FQnZXn0ieIZhxdNe+t7fhKot
         FwlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUC8u5EEl0KyMz/AHte4p34CEQEUBKjsbtxvhdT6s+gkGHnQNjfY5kukNet2pLF+PbsikUDPA==@lfdr.de
X-Gm-Message-State: AOJu0YwzEDrZKV450K7j8ALwkQN0JeIk9iOQv+EF3j2166auT/t3lelj
	Wj9KMy2GtvY0C8GeJaAy8Y+Pl6zOSM6mOxBkJEG5hJ1eZ8kgidC8
X-Google-Smtp-Source: AGHT+IGAGfY8lrMMb86ld/9za+fi/3Su8F8aAg/1RQFXFQYsLU2VNAunPjCnE1qkYFdMSuAAzZwdCg==
X-Received: by 2002:a05:6402:1ecd:b0:5df:6de2:1e38 with SMTP id 4fb4d7f45d1cf-5e03607e9b2mr11153677a12.17.1739809741036;
        Mon, 17 Feb 2025 08:29:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVENfiSrhSAnxTebZl10l3YyXkIvN3A/ZT5+ohc1oM1Tig==
Received: by 2002:a50:d6d5:0:b0:5da:aad:6265 with SMTP id 4fb4d7f45d1cf-5dec9952321ls180029a12.2.-pod-prod-02-eu;
 Mon, 17 Feb 2025 08:28:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxpglCGfFu0RPLV2EzM4CZSj5ZX3RQYV9g41GnSfMwmCEWnh81tQclOkrJkcUpdfHErWPAjR8U2DM=@googlegroups.com
X-Received: by 2002:a05:6402:42d2:b0:5e0:2996:72ff with SMTP id 4fb4d7f45d1cf-5e0360bdf15mr10281501a12.19.1739809738716;
        Mon, 17 Feb 2025 08:28:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739809738; cv=none;
        d=google.com; s=arc-20240605;
        b=L1DDLvxgxND9erPBUiV9aPTDkRY9kIclILny/HelQAbV/t/nS03AIPAnyQJIWKdio7
         EpbThcTteKnYK7EEFzJcZwLlpmRdjWeaYFdoRixxaU3iKcDHujAwhTMzbLIliwPa6POU
         AXUhbSSV+7PTnkigyJG8tnWS1qBGI2nnJF85m8+BDUnp+xGwgKxIIw80CMohRvOyYio/
         TO3TcY4WaTxGCfMOFndd+CbtROKYgYaXmymj1HUCocKCPrftiezRSd0fMpwfAAJ/yMCI
         IQE0pYmuHCiO7COIgbpsARzCitdyFd4bid/IkwPYZq9oVlB9BUENxV0yN1pFHjLJQGTd
         dgkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=yz5eSSbGmek/6y/tsCBF0vwN+yx7lRsH/SSKw++UQXI=;
        fh=vLSIY/HfP9wIH4WhXciMM2QF90maV7Ud1cfXEsJSyPg=;
        b=OGpNvdbM8v6x4ptOvZ+rB6wIkVLWfqPaQQPSKub1n4UFtSoiYOpuDiVP0uI+Ej++vT
         ReST419WfimN3JYqfJ9HSpSnQBV/+WV7DL6Bj6HmJxP8Ql0+u4onj7n6HaKidWGykTE9
         lbDuBrG6jSs8XQx1AIaZS8rqspcYhPwZpIsjnr87a2Nf1p7p4DPsm5AYj2WVSzlOUbsg
         XVFes/JHMUTScP7QQMOJFRuB8+uZPQrXWUos2JgA/rqdYK/m3msPO5oyw3VptALthl4N
         kGvS2iG9XEb9T/drZKQNhr1IPyx3s9vSh2Va5S9jV2aphwoxlBzjeczy4PH66VKHV8nk
         NL2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mr+mku5T;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dece240ef5si162920a12.4.2025.02.17.08.28.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 08:28:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-438a3216fc2so47577285e9.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 08:28:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX8Gg9QgedO+MCebipIAt+V91qj8Xx6SseG4I1lk38+6wyjERtm5EDxcIKclKVORvYZZZfqSrdDCus=@googlegroups.com
X-Gm-Gg: ASbGnct2mlJPCxGd4hfJ/DdJ6kIWAkFD9w2kZHmK6UcXa4P/eFHJ1PJ4V50n0R5UA2Q
	bSzrT6SzVo4ISR90CdH2WJDeNltoTR0p4HbpIQ8FOEl5bhlJtbduxfJ3i5pdj8Y+ZOlreYUNJkq
	Q=
X-Received: by 2002:adf:ec03:0:b0:38a:88ac:f115 with SMTP id
 ffacd0b85a97d-38f340676b0mr8083238f8f.34.1739809737912; Mon, 17 Feb 2025
 08:28:57 -0800 (PST)
MIME-Version: 1.0
References: <20250217042108.185932-1-longman@redhat.com>
In-Reply-To: <20250217042108.185932-1-longman@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 17 Feb 2025 17:28:46 +0100
X-Gm-Features: AWEUYZkOCsf3Lwl5kZxqhWvK51MQBU8TFE8a7QrsCXHmnwBN1EdOJpdIiaaxzBA
Message-ID: <CA+fCnZcaLBUUEEUNr8uZqW1dJ8fsHcOGCy3mJttfFDKq=A_9OQ@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: Don't call find_vm_area() in RT kernel
To: Waiman Long <longman@redhat.com>
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
 header.i=@gmail.com header.s=20230601 header.b=Mr+mku5T;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b
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

On Mon, Feb 17, 2025 at 5:21=E2=80=AFAM Waiman Long <longman@redhat.com> wr=
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
>
> Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
> Signed-off-by: Waiman Long <longman@redhat.com>
> ---
>  mm/kasan/report.c | 43 ++++++++++++++++++++++++++++++-------------
>  1 file changed, 30 insertions(+), 13 deletions(-)
>
>  [v3] Rename helper to print_vmalloc_info_set_page.
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 3fe77a360f1c..7c8c2e173aa4 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -370,6 +370,34 @@ static inline bool init_task_stack_addr(const void *=
addr)
>                         sizeof(init_thread_union.stack));
>  }
>
> +/*
> + * RT kernel cannot call find_vm_area() in atomic context. For !RT kerne=
l,
> + * prevent spinlock_t inside raw_spinlock_t warning by raising wait-type
> + * to WAIT_SLEEP.

Quoting your response from the other thread:

> Lockdep currently issues warnings for taking spinlock_t inside
> raw_spinlock_t because it is not allowed in RT. Test coverage of RT
> kernels is likely less than !RT kernel and so less bug of this kind will
> be caught. By making !RT doing the same check, we increase coverage.
> However, we do allow override in the !RT case, but it has to be done on
> a case-by-case basis.

Got it.

So let's put this exactly this explanation in the comment, otherwise
it's unclear why we need something special for the !RT case.

> + */
> +static inline void print_vmalloc_info_set_page(void *addr, struct page *=
*ppage)
> +{
> +       if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
> +               static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEE=
P);
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
> +                       *ppage =3D vmalloc_to_page(addr);

Looking at the code again, I actually like the Andrey Ryabinin's
suggestion from the v1 thread: add a separate function that contains
an annotated call of find_vm_area(). And keep vmalloc_to_page()
outside of it, just as done in the upstream version now.

> +               }
> +               lock_map_release(&vmalloc_map);
> +               return;
> +       }
> +       pr_err("The buggy address %px belongs to a vmalloc virtual mappin=
g\n", addr);
> +}
> +
>  static void print_address_description(void *addr, u8 tag,
>                                       struct kasan_report_info *info)
>  {
> @@ -398,19 +426,8 @@ static void print_address_description(void *addr, u8=
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
> +               print_vmalloc_info_set_page(addr, &page);
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
A%2BfCnZcaLBUUEEUNr8uZqW1dJ8fsHcOGCy3mJttfFDKq%3DA_9OQ%40mail.gmail.com.
