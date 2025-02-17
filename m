Return-Path: <kasan-dev+bncBDW2JDUY5AORBRP5Z26QMGQEHZVIM4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 656C2A38F55
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 23:57:11 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-3091da22365sf17608041fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 14:57:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739833030; cv=pass;
        d=google.com; s=arc-20240605;
        b=eNT4p1B0784UoTG5MNm1M1o42oaqCJZ2yaBiuQLPAlX7eDNL9fngPqc1HJ9wSOrTzH
         y4jVHi4p6BO9BRJ+XsEnMDtPJeD/R2C/E3AR6mAo6mjR+xGN1PmZaU6fkSoI2DKJDE0I
         VcntAi4JSFO4E7bMozTzGYqGDn2cyriroYJosRiQYOK3quofEBbVdiegIQDluMjOVGyu
         PEnps4uEOUbF/UbWdJ3NjWk1KemPjsXo3C+F4UYEr3lXBFReEPUaW+QJTGP6ogR8Xc0m
         fHIrC37QfdtRrj5O+5aEITg0RPyQrq5Cdu49LW6mHoJhNbcOV/BBZOPrJ5MJpbR4iTZT
         /QSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=DypL8mQl5OnWIFkOsvvTTUKeUSOqfA6eRaSLBaPhGYQ=;
        fh=PMeN2BBbkzVnSvZLaGM9Udnht0VCg6X4JbcVbSiGV8s=;
        b=ONEVGjBZ63uxFthEJdY6hHT/rVCySNHhf9C71k0EdSEkpk69eD0D6R3Sh+nptRpjrG
         Rw+10vb/0SvnFQNkgxxJHdyKFrT8kPH1XseKfnrrN+DsjByFUPSPvmnk1PA98Mt1++oW
         cA6RHoFvmufpwtjAIrVgg3KnpUwugdfOl1mpbIGhil67TnXqjMouca99nFMO+/qmXXLY
         rDQZTNOnC9uJbua0PFwYCTcqq529IizD7xAwzlQ/ZmwhbGHaAFsMZceX1Py+7/sHRIAE
         5S6tEiIKSB4D8ZPx8Cu8sk1zu/sgmezUQLMZ8KaSKHqOKusMq2KI2bRdKfURJv5q2N+E
         pjag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W65o5UDx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739833030; x=1740437830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DypL8mQl5OnWIFkOsvvTTUKeUSOqfA6eRaSLBaPhGYQ=;
        b=roHa89QGTL3Pg9iqQZB8cZ6uwyNrQM7obex3TqhFcuELSJa+Bq3IEdEDps9Rhjinqj
         VQ5N4exOMhZWDRXKk8xm/zl8BP/tBbu1ASo1pVOSyOJ9JdYCOI/eu55sZiYUc57sKSIH
         5l0uEFb/c9xKlE2Qt5mC7t+4fW7Jc1fgX2dTweP1cZZQKhhFASpFy+ZZ9w7hC6tDXArX
         kYOAd/87mj44ztE0qt1KbEZaAbXScUFqZelogV9eyRzqfIV6dukrvkHFTu2zjeNJjskv
         WYNNCFHTQmxhyEHAj5JuBAxmHVPNeKZ2mCyUrw9nishy3SNHORpA2kcXzvLqXqOGhjDe
         kxcg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739833030; x=1740437830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DypL8mQl5OnWIFkOsvvTTUKeUSOqfA6eRaSLBaPhGYQ=;
        b=TVE2El5suNMhjaltS8oAlM0oNHdKseGv6eu9rGECzvYi2dTwgOcE1Iua9hZkYjbSrk
         u9R+WEG98TDQAhkcD67KibvPWLqNl/484oyeGjrWOKV+v9Ggog1I4rM67usPUv6xOmJh
         VJpqm+fRaZQMDd47ncLBCxKjBuGzrc+Pcyu8ZnRY/GB5o/v6wL+eDfvxgq23CdkfJlqN
         KT37OuuXwcItvDAjSlHdBAXcg4SASgTd1uV/Sl3mEc4UYWbIPoEKrSc7mVamj9P5pH6B
         T/l6HBZB9/OF7NYjPITFPYmP3rB+A+AEIJR+8/n9W8judLfAMLqbuysw2DVu02TI6sQa
         KS1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739833030; x=1740437830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DypL8mQl5OnWIFkOsvvTTUKeUSOqfA6eRaSLBaPhGYQ=;
        b=UJ4Gw2MM8A33nj30tuibFEWB43KyeZl7z1S1uLIYbbbGyrXfd1oWCk8IsXmJrgZ5aM
         F3n67pJFhL3J+xRE6bZ4gGstOKOTgREjtGTCV1LJIv7NgzWtIJkZylSYsfOHXNBhl1+v
         vgsHaeczVTrBgYQrm+S/wO6xLc0kF5DB+F7nJKOU/Gm4BC+IBPH054+O+3+3DlVeF/Wu
         TytBjGqI89HTvOelL8M/F/n0PwspWVzQEA+suCrkcq3gEZLx1uePWVvJMLrKSy7OIFuj
         9NmO/AWTNv+fDOaHtHZ2pOaLmXi7gksCWn0JQkZpSMFWBoWTns5vN2N2a1z+tM/srpBN
         BQkw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUr3tt3tJ7YFj38NEfEJrgBTRXZwRnOGUP5K3z4uS3wbO/DFThMhpFaMDNjaJDMaUhG+rDbQA==@lfdr.de
X-Gm-Message-State: AOJu0YyseG2TXF2cbuSOqatpwtn18ETzw0LjE0KKPI2yTF2E42UWc8aL
	j3Op1qKrI+4CdjYYS8n70BU2Xn7vgSH/SiWF2FO0BYcE0gZZ7PbJ
X-Google-Smtp-Source: AGHT+IFPO+X+R/lBSAo658xr4LnSFo7Xrw6ZQWCBEMhMHDkagEywNZ32VdT1ZjT2oAA0YSjjmqNrJA==
X-Received: by 2002:a2e:9905:0:b0:308:f01f:181f with SMTP id 38308e7fff4ca-30927aff022mr28272321fa.31.1739833029917;
        Mon, 17 Feb 2025 14:57:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEkbGQaZDq2pXk9hloVdnFU97i5l1yvGrhO43lYJ1vxwg==
Received: by 2002:a05:651c:2221:b0:30a:2c11:1251 with SMTP id
 38308e7fff4ca-30a2c1114c1ls2193711fa.0.-pod-prod-01-eu; Mon, 17 Feb 2025
 14:57:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUfkuyZRgGqJbQIg6GRohrbQwDiMC6KizQOkzNoddCfkWiie1V/tlVl69cZwRUzAnP6LwYWI2JqFP4=@googlegroups.com
X-Received: by 2002:a05:6512:eaa:b0:540:1a40:ab0d with SMTP id 2adb3069b0e04-5452fe65367mr3964404e87.28.1739833027389;
        Mon, 17 Feb 2025 14:57:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739833027; cv=none;
        d=google.com; s=arc-20240605;
        b=VLPZlCMaYV39rVExHqQsKqdgeozsf8tgI1g7kLqbTx77C7xbFdYDxvemaMni5JKCrn
         WmhuDF8AJIhqHVxzgXF9X0dB4gYqQpX3Bs+/VKMLqAKaG5z8svGtPiDoTyhKiKxDmdt9
         ectF0nK6ac3Fa19ZfiOcpB0U3ADWEr1gFNdir9XmZRRCB102lYte6vd24pNH/+adNArl
         zpIXLBpTDMV45uzW5mq1INmwTYsU/860EciFPDlVb7VdyhvDsZkSDULbe7EhEXgOh6D3
         WO1IdCUwKlqbTFdrgzbfVMFC6T+YGOEGl87nGdZ8ORsRDA77eM35C5RAK7yLEnSC+8jw
         Re7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=l0Pzx9XFyMoQwaq/j01KSTY/+B12ar50FlSTQ8at2Kc=;
        fh=9Ol8JPh9haSDwyqnCKgmB2i6rSeTrjW6hpsShFFkvIQ=;
        b=TCZ3NSIwVcFgitu53yghp6EtDp2Dxld3M7bX7iIKDeShCV1XOBlDESIRwPDSF6iiUn
         t6aNyKER2Hl1azDPbawDCgiByWph1MfSStznCVXPnqpk1lknfrRlCnXK2BGGnEysvV3a
         f8jrS+uO78uT9Ujp0yrogyS0uy5D4e1NuzaatQIWW/a/GnXqOP9NYhznAzaozn+0mqKS
         TQivUUZmBAUNF1w8AxzMR3qr7MdIxJmtRg5DcBg7PL7LmirT+CuM8+mqPOAFQjBpADk2
         97uvvgVAd8cMq/h6NZgBGHNfCpX5EQSIVtQ/0+vsGIK5uoFh1BoSiri0d5TCOF/jMSAy
         VLew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W65o5UDx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3092ace042bsi1470801fa.0.2025.02.17.14.57.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 14:57:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-38f325dd90eso1731662f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 14:57:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUkUgSbIdHM6a0Y8ApInQDy02BYDJMcJiewEf4aemZQ/pSFPf98BGK1TA7Dv+k89rWrs7zprakEwgM=@googlegroups.com
X-Gm-Gg: ASbGnctDu3Aavb9DBCQXFomZzz4RLLYFIuQ5nbGZbWt1vlaSMeRV2d6rgj0HxCyMN/d
	N/ZhDOMh465SBKCsBP4mTl0SA7Yauta9Zg1M129Uix4LpWvWUYMkHcP9Zn0Z7mNZVWuEkPhnOQH
	I=
X-Received: by 2002:a5d:468d:0:b0:38f:2b34:5004 with SMTP id
 ffacd0b85a97d-38f33f4e2aamr9008909f8f.38.1739833026353; Mon, 17 Feb 2025
 14:57:06 -0800 (PST)
MIME-Version: 1.0
References: <20250217204402.60533-1-longman@redhat.com>
In-Reply-To: <20250217204402.60533-1-longman@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 17 Feb 2025 23:56:55 +0100
X-Gm-Features: AWEUYZmSmtSFKImfOr51DZheaPH7tbwA6sqeu5erz96SBLmh7o8z1iWhPYcqCvY
Message-ID: <CA+fCnZf3JbTUErHm_AG7r-dMD_6BmMctPAOaFAJQNH4k2Ev+dQ@mail.gmail.com>
Subject: Re: [PATCH v4] kasan: Don't call find_vm_area() in a PREEMPT_RT kernel
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
 header.i=@gmail.com header.s=20230601 header.b=W65o5UDx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Mon, Feb 17, 2025 at 9:44=E2=80=AFPM Waiman Long <longman@redhat.com> wr=
ote:
>
> The following bug report was found when running a PREEMPT_RT debug kernel=
.
>
>  BUG: sleeping function called from invalid context at kernel/locking/spi=
nlock_rt.c:48
>  in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 140605, name: kun=
it_try_catch
>  preempt_count: 1, expected: 0
>
>  Call trace:
>   rt_spin_lock+0x70/0x140
>   find_vmap_area+0x84/0x168
>   find_vm_area+0x1c/0x50
>   print_address_description.constprop.0+0x2a0/0x320
>   print_report+0x108/0x1f8
>   kasan_report+0x90/0xc8
>
> Since commit e30a0361b851 ("kasan: make report_lock a raw spinlock"),
> report_lock was changed to raw_spinlock_t to fix another similar
> PREEMPT_RT problem. That alone isn't enough to cover other corner cases.
>
> print_address_description() is always invoked under the
> report_lock. The context under this lock is always atomic even on
> PREEMPT_RT. find_vm_area() acquires vmap_node::busy.lock which is a
> spinlock_t, becoming a sleeping lock on PREEMPT_RT and must not be
> acquired in atomic context.
>
> Don't invoke find_vm_area() on PREEMPT_RT and just print the address.
> Non-PREEMPT_RT builds remain unchanged. Add a DEFINE_WAIT_OVERRIDE_MAP()
> macro to tell lockdep that this lock nesting is allowed because the
> PREEMPT_RT part (which is invalid) has been taken care of. This macro
> was first introduced in commit 0cce06ba859a ("debugobjects,locking:
> Annotate debug_object_fill_pool() wait type violation").
>
> Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Waiman Long <longman@redhat.com>
> ---
>  mm/kasan/report.c | 34 +++++++++++++++++++++++++++++++++-
>  1 file changed, 33 insertions(+), 1 deletion(-)
>
>  [v4] Use Andrey's suggestion of a kasan_find_vm_area() helper and
>  update comment and commit log as suggested by Andrey and Sebastian.
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 3fe77a360f1c..8357e1a33699 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -370,6 +370,36 @@ static inline bool init_task_stack_addr(const void *=
addr)
>                         sizeof(init_thread_union.stack));
>  }
>
> +/*
> + * This function is invoked with report_lock (a raw_spinlock) held. A
> + * PREEMPT_RT kernel cannot call find_vm_area() as it will acquire a sle=
eping
> + * rt_spinlock.
> + *
> + * For !RT kernel, the PROVE_RAW_LOCK_NESTING config option will print a
> + * lockdep warning for this raw_spinlock -> spinlock dependency. This co=
nfig
> + * option is enabled by default to ensure better test coverage to expose=
 this
> + * kind of RT kernel problem. This lockdep splat, however, can be suppre=
ssed
> + * by using DEFINE_WAIT_OVERRIDE_MAP() if it serves a useful purpose and=
 the
> + * invalid PREEMPT_RT case has been taken care of.
> + */
> +static inline struct vm_struct *kasan_find_vm_area(void *addr)
> +{
> +       static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
> +       struct vm_struct *va;
> +
> +       if (IS_ENABLED(CONFIG_PREEMPT_RT))
> +               return NULL;
> +
> +       /*
> +        * Suppress lockdep warning and fetch vmalloc area of the
> +        * offending address.
> +        */
> +       lock_map_acquire_try(&vmalloc_map);
> +       va =3D find_vm_area(addr);
> +       lock_map_release(&vmalloc_map);
> +       return va;
> +}
> +
>  static void print_address_description(void *addr, u8 tag,
>                                       struct kasan_report_info *info)
>  {
> @@ -399,7 +429,7 @@ static void print_address_description(void *addr, u8 =
tag,
>         }
>
>         if (is_vmalloc_addr(addr)) {
> -               struct vm_struct *va =3D find_vm_area(addr);
> +               struct vm_struct *va =3D kasan_find_vm_area(addr);
>
>                 if (va) {
>                         pr_err("The buggy address belongs to the virtual =
mapping at\n"
> @@ -409,6 +439,8 @@ static void print_address_description(void *addr, u8 =
tag,
>                         pr_err("\n");
>
>                         page =3D vmalloc_to_page(addr);
> +               } else {
> +                       pr_err("The buggy address %px belongs to a vmallo=
c virtual mapping\n", addr);
>                 }
>         }
>
> --
> 2.48.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf3JbTUErHm_AG7r-dMD_6BmMctPAOaFAJQNH4k2Ev%2BdQ%40mail.gmail.com.
