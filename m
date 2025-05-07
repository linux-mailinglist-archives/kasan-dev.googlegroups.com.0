Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4M53AAMGQEGDQMC5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E730AAE620
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:10:50 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-85e7e0413c2sf607479139f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:10:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746634247; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ad75ctR6cb8Hw8bEMd2Mown7zfDdeeFK9PYjYCeWpuPz6fUDX6KWxT6fllO7MgYkE7
         BGypJYNEBpoeOUp9buxoEu09WG8wR54+QWZPOpBo2aa69me2rXfJOquTdVjswHTkEZwL
         sXAubWsTgWkhD/enPkX+rL9uFec+71DD7SFGliYvs25yd8QqBhVR+sLtaPiEsOSJ39dW
         I0MwN+kS33uVpNuTvMS7b0b/+wjZtGRXN2OUioHAjvgjUofAthWzGs268jHZgWiJo4HP
         FsNm2kULc0kXevKgpVPTih2bDoPR45yxuUHHMFxzdV9asc8dBr4U+xNQB5DqsR8IRGnm
         Mk7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Nj4xzCPkixZWX4TshC26i70L0v8l4S+PPdiOwe9zyIU=;
        fh=v/1rxhE+lq2dIO/51DVPPr7xHJFEYLhXHhokY4n9krk=;
        b=HBHg+n20xeWW9zpZ/zqigRMSmRA3hy1XYOguq5jJftaVSNbxHoGUpLMA1hhhuvOxSS
         V6EfdFCemmNt3bzftRqK96zAU/zIJHbjKzxL6shid4hUMqCVOuCMuZ/M/vM+CvHZYQ3p
         sxVGMb1HXcNmhSjL/d3khHbgnX/lII1sHKI6KH2JFJaZ/cRXOZUfqGnztl7Naahi8X6s
         anYYiJIEV3BpiTnHmOCFRVJ1VspxxAzqrr0OgBkk+1RPofcWnkKotDKYicxYaZYXuyom
         O5Jr3JpPy2ZcZZSjuLw+an7nntN80e6y/skjw+61wz7653mVl1ZkM+SxOvI+tqHGZtzc
         sWXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cqVk9tHW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746634247; x=1747239047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nj4xzCPkixZWX4TshC26i70L0v8l4S+PPdiOwe9zyIU=;
        b=nxL86Uy5XnI9x0DirJctvJx8bn+naMiNjynxxz4BWF7uCNZQKeEekmohJpqeUOAlpQ
         haq4J0+1+b9co8S/n/WvVFeYxO/In/3Swt5pPB2T61np4uugNRIJqKz4eakQz2xL7dcV
         81geqhRxzkuyHRYzd8dhtzTvGijHjK/Rk9y/MdG34kRDF+tZ97yPDuyJ7JbJSqEW1ch1
         /u01ylC6VJ1I9lsszyps82GdTvTfYY2NQqy26qFO+OX6hBYokOPJ7El6fufyMVmDjUIV
         6ffnlusidsX3QMYE7Adbie4T/NjO+xC3mBiIYggUvRSMnkTSfqhBFxJZNfT7RKhTwl/u
         Wxqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746634247; x=1747239047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Nj4xzCPkixZWX4TshC26i70L0v8l4S+PPdiOwe9zyIU=;
        b=TP2vYc3VsYRsyl8bxjgBw662meefK7Jddo7U3wg/X2PNMVq2HplPPYMbDHDRaSfcUC
         p6kULuF3NpqwyOExvfbv/gdccIG8p5lrNcTHXz5HeXwcxHn+iTlE3CHYDT0I9xMqWPvJ
         OwLHUU6oUInqnUQeZ4+Rm6qJUfRJ4nD7kk33ynMLipCKXTfJRcxPYFFOxeHN5smF30pX
         XOP5UfeBYnxVvhf0F4M8H8FjDxB0zVXB3RRzjg9pvogNfn/Qhhve3AKNdRdFUrthRG2R
         TslZfubCgd+DDpA1LBNl+90Jn6G2kYEpXPSNBxKYm2kYBpXpw5SnNp/w0p8CUgcVjqar
         QnhA==
X-Forwarded-Encrypted: i=2; AJvYcCUfYvtKVzHX5YyoXjO7CXqLU7JqBptHZaokkknrs/uNINBq9r3NoxNj+IsptOwLvu6ZaVev/w==@lfdr.de
X-Gm-Message-State: AOJu0YzxAvTHbdio24zp2UhCMIKvVjmd+gXNzcg0G/F290dzrd+3KO4B
	4zd2EMSh3tIXdzU1jHMRYY5Y8qKJXYPZwUhzMkGxmXHSPufIxvR4
X-Google-Smtp-Source: AGHT+IHeAj12OkqBFEyktinuqDOk8ng34PT73wCbOcrCynTp5Q+6WpG3+oWKbsdex+Gx1m1qUHmozA==
X-Received: by 2002:a05:6e02:1fc8:b0:3d8:1d7c:e180 with SMTP id e9e14a558f8ab-3da7855c101mr1597775ab.6.1746634247416;
        Wed, 07 May 2025 09:10:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHhiN3nVuP4cb11Pb4sZeY5acyrruu1zz0t2btpqUTlCw==
Received: by 2002:a05:6e02:1208:b0:3d1:9c39:8f7e with SMTP id
 e9e14a558f8ab-3da7855283els240435ab.2.-pod-prod-07-us; Wed, 07 May 2025
 09:10:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXfjYlf3AJXIfNQB6+tRC/bRlzlX4kbBNYJh60M1pFzgJi6FRafV3HBk6mwTpIWOvrHYcCA7Flmz60=@googlegroups.com
X-Received: by 2002:a05:6e02:1fc8:b0:3d8:1d7c:e180 with SMTP id e9e14a558f8ab-3da7855c101mr1596175ab.6.1746634246268;
        Wed, 07 May 2025 09:10:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746634246; cv=none;
        d=google.com; s=arc-20240605;
        b=TdQYMbFEF4OnyQ2CTYcJ5Gu2S+ehaOF+ThKrL0u3hdZM+ecSWluhmRXDU/uA6B004z
         srIuNYLMntFxi1EfE1yS6fjkXVSi1A8J6yblf/r9durV5AtJzblm5/ecBBEkWjpM4Wu7
         dTWM/1aeXpfSMcKNH0HCKQGXcayeP433M+npbnD4BtqZa2Eat8jVcjdwvxFUd+DRFrlc
         DjYTI2gJX5c/oJe60AJuRvIBaRoAnfNVI+za4k0mjN49jEcH4QTTBkakCEI8sjLC1r3X
         w1dayieEyQNyP6taOakCHYFD7WDx1crkNb22qoLhkOqrwlZYsFHmmTiYaQM6HqQe4vWD
         VxiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tzZXY4+kZQl5HFpe8i6WC+loNaLSCDjR3rOfrJMJkeg=;
        fh=9WKtAb5sWMP0m9Ot411+EyuyzLK0NYpusw0nLrUyQfQ=;
        b=O4w75Hyb+V2janlVbQgrxjv43MKR9TK6fZl2Jc7fGsl6GDtkGgDS+BtHUaNclGPEnc
         a2MoFJnveQMvO5U8Z30cCmjNa9EKbq1FqolhSV7UNhefurlR7FV66c0T8ZmnikalPwst
         01w3Yvq7IrNJUbRGB+aRHGJka1DIRONc1cmDywLntUPGRmD8vIwHZNf1hm92eyprSd2r
         UrBIORdkeI+t8D1qIAv8qKQGueLKScSErSdrxo0BB6SeabqL71SjnmnsPihCTu1O+Kjz
         Lcc2CqLGJ4ZuXKn5E+pxCE+1J0H24jFv0/lSUb0xzbUF1O9GkdkiIjezY6h689JE3EvP
         RfQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cqVk9tHW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d975f408c2si5855ab.3.2025.05.07.09.10.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:10:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-af579e46b5dso4893989a12.3
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:10:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWmw2B0Kn6ToRv+THMYtuphLK2FgQIYDJMGq7iApw4egmiQGg2nMy2rwV81EeH0DzOM9flAO+UwgC8=@googlegroups.com
X-Gm-Gg: ASbGncvUQWJjqDVULRmlRpgCGMqPHXKe2nAyTte5480IoOxjbP72gWhWkXfJkglOlSF
	JkUjXEwweLHM8meL4zHjB9IGEUnKwsPeV9YU9PVt3epjBCoPUcDDZMfMjqbJd7pyQRxNRXBcQFD
	jS2if9iybm35RrYE/V/xPCGHiS64/Whzr0DAj0ezUULHpfUmJZ1kZv1Rfzehd3QZ4G
X-Received: by 2002:a17:90a:8a0e:b0:2fe:b937:2a51 with SMTP id
 98e67ed59e1d1-30aac28b737mr5683271a91.33.1746634245268; Wed, 07 May 2025
 09:10:45 -0700 (PDT)
MIME-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com> <20250507160012.3311104-5-glider@google.com>
In-Reply-To: <20250507160012.3311104-5-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 May 2025 18:10:08 +0200
X-Gm-Features: ATxdqUHpnwYmhy45jfBUre0B7_p2RU_rQE72-Bu393Mv_C7ux1bSvhFcJF5Eo88
Message-ID: <CANpmjNPpbSxWdaw=N_-gnweok9XtaJ-Pqcg15Z=Kko9sUffwhQ@mail.gmail.com>
Subject: Re: [PATCH 5/5] kmsan: rework kmsan_in_runtime() handling in kmsan_report()
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, bvanassche@acm.org, kent.overstreet@linux.dev, 
	iii@linux.ibm.com, akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cqVk9tHW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::534 as
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

On Wed, 7 May 2025 at 18:00, Alexander Potapenko <glider@google.com> wrote:
>
> kmsan_report() calls used to require entering/leaving the runtime around
> them. To simplify the things, drop this requirement and move calls to
> kmsan_enter_runtime()/kmsan_leave_runtime() into kmsan_report().
>
> Cc: Marco Elver <elver@google.com>
> Cc: Bart Van Assche <bvanassche@acm.org>
> Cc: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/core.c            | 8 --------
>  mm/kmsan/instrumentation.c | 4 ----
>  mm/kmsan/report.c          | 6 +++---
>  3 files changed, 3 insertions(+), 15 deletions(-)
>
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index a97dc90fa6a93..1ea711786c522 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -274,11 +274,9 @@ void kmsan_internal_check_memory(void *addr, size_t size,
>                          * bytes before, report them.
>                          */
>                         if (cur_origin) {
> -                               kmsan_enter_runtime();
>                                 kmsan_report(cur_origin, addr, size,
>                                              cur_off_start, pos - 1, user_addr,
>                                              reason);
> -                               kmsan_leave_runtime();
>                         }
>                         cur_origin = 0;
>                         cur_off_start = -1;
> @@ -292,11 +290,9 @@ void kmsan_internal_check_memory(void *addr, size_t size,
>                                  * poisoned bytes before, report them.
>                                  */
>                                 if (cur_origin) {
> -                                       kmsan_enter_runtime();
>                                         kmsan_report(cur_origin, addr, size,
>                                                      cur_off_start, pos + i - 1,
>                                                      user_addr, reason);
> -                                       kmsan_leave_runtime();
>                                 }
>                                 cur_origin = 0;
>                                 cur_off_start = -1;
> @@ -312,11 +308,9 @@ void kmsan_internal_check_memory(void *addr, size_t size,
>                          */
>                         if (cur_origin != new_origin) {
>                                 if (cur_origin) {
> -                                       kmsan_enter_runtime();
>                                         kmsan_report(cur_origin, addr, size,
>                                                      cur_off_start, pos + i - 1,
>                                                      user_addr, reason);
> -                                       kmsan_leave_runtime();
>                                 }
>                                 cur_origin = new_origin;
>                                 cur_off_start = pos + i;
> @@ -326,10 +320,8 @@ void kmsan_internal_check_memory(void *addr, size_t size,
>         }
>         KMSAN_WARN_ON(pos != size);
>         if (cur_origin) {
> -               kmsan_enter_runtime();
>                 kmsan_report(cur_origin, addr, size, cur_off_start, pos - 1,
>                              user_addr, reason);
> -               kmsan_leave_runtime();
>         }
>  }
>
> diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
> index 02a405e55d6ca..69f0a57a401c4 100644
> --- a/mm/kmsan/instrumentation.c
> +++ b/mm/kmsan/instrumentation.c
> @@ -312,13 +312,9 @@ EXPORT_SYMBOL(__msan_unpoison_alloca);
>  void __msan_warning(u32 origin);
>  void __msan_warning(u32 origin)
>  {
> -       if (!kmsan_enabled || kmsan_in_runtime())
> -               return;
> -       kmsan_enter_runtime();
>         kmsan_report(origin, /*address*/ NULL, /*size*/ 0,
>                      /*off_first*/ 0, /*off_last*/ 0, /*user_addr*/ NULL,
>                      REASON_ANY);
> -       kmsan_leave_runtime();
>  }
>  EXPORT_SYMBOL(__msan_warning);
>
> diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
> index 94a3303fb65e0..d6853ce089541 100644
> --- a/mm/kmsan/report.c
> +++ b/mm/kmsan/report.c
> @@ -157,14 +157,14 @@ void kmsan_report(depot_stack_handle_t origin, void *address, int size,
>         unsigned long ua_flags;
>         bool is_uaf;
>
> -       if (!kmsan_enabled)
> +       if (!kmsan_enabled || kmsan_in_runtime())
>                 return;
>         if (current->kmsan_ctx.depth)
>                 return;
>         if (!origin)
>                 return;
>
> -       kmsan_disable_current();
> +       kmsan_enter_runtime();
>         ua_flags = user_access_save();
>         raw_spin_lock(&kmsan_report_lock);
>         pr_err("=====================================================\n");
> @@ -217,5 +217,5 @@ void kmsan_report(depot_stack_handle_t origin, void *address, int size,
>         if (panic_on_kmsan)
>                 panic("kmsan.panic set ...\n");
>         user_access_restore(ua_flags);
> -       kmsan_enable_current();
> +       kmsan_leave_runtime();
>  }
> --
> 2.49.0.967.g6a0df3ecc3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPpbSxWdaw%3DN_-gnweok9XtaJ-Pqcg15Z%3DKko9sUffwhQ%40mail.gmail.com.
