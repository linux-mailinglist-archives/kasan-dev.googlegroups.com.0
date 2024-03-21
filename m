Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHWQ6CXQMGQEQV7ZFEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id A30F5885915
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 13:29:19 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7cbf1d5d35bsf97796739f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 05:29:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711024158; cv=pass;
        d=google.com; s=arc-20160816;
        b=LD4OizjO8j0Kg4D142HHl5re5AioTNn0rvZVLuyqSQSvXrzaLa3+2KEhDKUaFGCaJd
         XS05KQiucNZqQqxOMJhpJk6k22epmWpV+AmtYvz4WmWVjK0Ue86Cbv2Yd8yOJe+xs2CE
         95M5ScbG4hDD2HRMW8QKokHuA2QCjj+vGio3T6Gkp/HBy8XyGyoqQnIwvTQnkiLNkfRV
         ZIivzuZ+kOWJcTsMCZzcZvlbZ0KPU2gF+GnXQV8nU0qtnIaudcJdVOleOmzyPSxvXBm2
         FOID5GKZ16raxahd8qYaRkpiNI14eDaCbcJQzqKmIU0y59aR9ct3xxNOOCLu3IbFP4lB
         Vp0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uHsEXTiX8x5dAt7+NMeUVP4eQW3j53nW3I6X89Yizu8=;
        fh=JXxw8x3gvz3ofCub1Qo8x4qqV6EJYYflL2Smk2IQLnM=;
        b=sld1mMw7A4zMLS1iK4XECxApJ33dMgYsq0boH3DiGHhZDqD0Bf4J4/bRwnlwLSV5Cn
         osaMDAqTqabkIh5nSUUsXoAoIoNCHawIUSW4ozUBvy1pcZoqBTv4RdjBEO+wfubJsc/A
         BkZZi9gxuDZ/0byrmIqpSSlHP5+q0pBzcilyQWIT1bYh+/MyG74X2pxJCse9c/D4310Q
         hHrVeKOnc4w3s5WaUFpGfRN+3HsjQM92lRo1Asd+VZ/yd0OM5CADE923M18h3BaJspBk
         NbxT9ThRQkqBRHf1qBh0PAtKRhftePpULUTyuyCezgm/QtiJiwGM0uYka7j5i5VZLIWp
         czvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ra19Vf58;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711024158; x=1711628958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uHsEXTiX8x5dAt7+NMeUVP4eQW3j53nW3I6X89Yizu8=;
        b=svWJFPh17c6dkeS8yylOMZbNT7Rpiugh26rctu8cTjNvrHJVyEjolCtwrLXBdfDRAM
         LghIYzGn78cfW4Fo0Tn0MWkRbtyYGDcBO+7kVhNb89SeHQx0Hb0RHH1QHjgPaAMAtYIg
         pMr/TnVIhHpBMCWwDaH56QVD4tO1tNPs4j+OdF4sjCyrVcM77Nb9PFWiu1TWnpKR9W1j
         N2FkjqlOueATRR8IrGoZaa3tZje1y4QbKL0+xZnsjY+cYk7XdKhG73m7PjOjdvk/VL2g
         cQvUy3xL3g5o3ajcl+LUyy7gjZ6u3TUrKhSGOdEJiuZIDPUwBVL9h78t1YhdVpLsL5+r
         cvsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711024158; x=1711628958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uHsEXTiX8x5dAt7+NMeUVP4eQW3j53nW3I6X89Yizu8=;
        b=w2cDgv9BPOnblmKvKudVJH4nqwv8AN0ntPDfeDEOr6DTnkGsIkqyLf6oBvklO5quAW
         NktiIQedRbkCw6RikqI5+nATQbbHjkCiN98RbFiY4M0kUQ6RAgZpnPZac+MC9GaCY24H
         8/M3AHuCzR0UTFghBPcRfN03pYOQrBWQP3MaXvOyaj7JTUq1FHsKM/fqwyUkyDUxAHIx
         ChdEHO39j+b5E0FhHqCmmLAyYI4WYEfEGded90p2Bal3HhDHlYLsLKD3y6UP7nnAOlXk
         Yvs6jchvcWE/Eg+eMt5VcQ7qs1bgr6Th72CHFkuOPQQvf7S/Z6dY0USsODOfzWzo+BUP
         nrNA==
X-Forwarded-Encrypted: i=2; AJvYcCUPVDyYrchj+J6Am3Hgpjnx6PSGe/pADOP54xEuOzHScsMsuizWBvyZwbhrUM/px5PnvtOXcXoGOQZQJjfgB3QN96480mwtwg==
X-Gm-Message-State: AOJu0YzzRnOe8VdtVmYEaWZyWQaNgrf6jg2hAwsJw6Xqv+wYkWILAFC1
	UHlfEYMFsruWbAMa7HJit+edoU2nn1Pg2IjBxqD8YGnTDdxGm8Fr
X-Google-Smtp-Source: AGHT+IFvgqT9ZVVMu/4ODQCecN7E/fpCqP1JcCupqUs98NYDcuY3UToT0axOGOqSsonIVuzUgEFXMw==
X-Received: by 2002:a92:c74e:0:b0:365:bff:adfa with SMTP id y14-20020a92c74e000000b003650bffadfamr23896040ilp.17.1711024158355;
        Thu, 21 Mar 2024 05:29:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a61:b0:366:c09b:649b with SMTP id
 w1-20020a056e021a6100b00366c09b649bls575278ilv.1.-pod-prod-02-us; Thu, 21 Mar
 2024 05:29:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnBvBPv+mw3LhyQ4IotGIC296gQ/b+1N9X868Ils5g0/xAkFM5yNW6JpGK70hwFewnmoA9Xnm2zge5ePdKtwXs4z3foNfXReiarw==
X-Received: by 2002:a05:6602:4a:b0:7cf:1c5c:681e with SMTP id z10-20020a056602004a00b007cf1c5c681emr4652236ioz.17.1711024157416;
        Thu, 21 Mar 2024 05:29:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711024157; cv=none;
        d=google.com; s=arc-20160816;
        b=aWcqpUl2FS8TQDiYkU58LMTND7zBQkzy4CX+q0x3k14ETS/ynQCHS/EIhgFpbMDSHf
         t+Sd5yoU1fCZFWHK47GDnhf4gOsg37SbjQjoZOE9NYHCA6tRPZrRSGA0rrTqE4Nacv08
         Q63rcRNPd3SePbzVZfDHqOWM+YXJRjaCLnvd3XKJmfAjd8tEoWnw5jynMwH8drwfRbLf
         DH3+QTUa8COfLwmUqep1HKVVNJFjoJKOIGhyda1FLS0H4D0Fm+rmKsRFkYZaMPoT08PR
         AyGaMmpDOWPuNjU1PnXFymovwgrs3wrRoOXztP1Q7/T3KiaurREwWYI+nBLaJhTFr2se
         xm/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7kkkaXKbTgy3PIzx4XPScnI5vGtNWw818zYmBGpfIzA=;
        fh=VKOE+ffVocqNCb28zig402etF0sLfsiSCth3lFw30hg=;
        b=BD70Ut6cv6xQnoc7+hprpR03guJyV3CsEBAEyglw8+DBNLw4fJ55kD2jGPjAPrQgJB
         pKksT++8Y8Ea8gBuMFKZxatLeB8AP9xKu5tbEnUqPKT+Aw1ICEimuQeIjseegOrx32U9
         c745V/efG34t9AwCEAAH+BpQpdUaAG1+kwNOr4fNsOhEo4bvtftK/l7AG0pAo7y32Nu8
         gd0ZkuAZRSooMiczTK97GTbbOUuib43vB8BZjkFPlp/MXDncAf3rxDBigXe/zDVesDod
         rHz7iZ8YsnNromE/q/RdIeKE8rdwAn6YyvUIl5mjxv6UOHDc02jsnvzK5TNL6WZN/BIc
         NG+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ra19Vf58;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id n4-20020a02cc04000000b00476de528316si1531039jap.1.2024.03.21.05.29.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 05:29:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id 71dfb90a1353d-4d42d18c683so337751e0c.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 05:29:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXN7lrqmJkuELA9b2FgpkllzgZn0odvra/Ka1YnoSyyuTzYO3CN6uq45YSa9Mwobl6BkhPuEkZ9tSsP8uhlF+iWhwTQF0qzalXlQA==
X-Received: by 2002:a05:6122:3626:b0:4d4:3621:b245 with SMTP id
 du6-20020a056122362600b004d43621b245mr12680826vkb.16.1711024156532; Thu, 21
 Mar 2024 05:29:16 -0700 (PDT)
MIME-Version: 1.0
References: <20240320101851.2589698-1-glider@google.com> <20240320101851.2589698-2-glider@google.com>
In-Reply-To: <20240320101851.2589698-2-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Mar 2024 13:28:40 +0100
Message-ID: <CANpmjNPA9h_OgizevqkiEkGS34nSPnQrqWF0FMazwVfjR3w0uQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] instrumented.h: add instrument_memcpy_before, instrument_memcpy_after
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ra19Vf58;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as
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

On Wed, 20 Mar 2024 at 11:19, Alexander Potapenko <glider@google.com> wrote:
>
> Bug detection tools based on compiler instrumentation may miss memory
> accesses in custom memcpy implementations (such as copy_mc_to_kernel).
> Provide instrumentation hooks that tell KASAN, KCSAN, and KMSAN about
> such accesses.
>
> Link: https://lore.kernel.org/all/3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp/
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
> Cc: Linus Torvalds <torvalds@linux-foundation.org>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  v2: fix a copypasto in a comment spotted by Linus
> ---
>  include/linux/instrumented.h | 35 +++++++++++++++++++++++++++++++++++
>  1 file changed, 35 insertions(+)
>
> diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> index 1b608e00290aa..711a1f0d1a735 100644
> --- a/include/linux/instrumented.h
> +++ b/include/linux/instrumented.h
> @@ -147,6 +147,41 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
>         kmsan_unpoison_memory(to, n - left);
>  }
>
> +/**
> + * instrument_memcpy_before - add instrumentation before non-instrumented memcpy
> + * @to: destination address
> + * @from: source address
> + * @n: number of bytes to copy
> + *
> + * Instrument memory accesses that happen in custom memcpy implementations. The
> + * instrumentation should be inserted before the memcpy call.
> + */
> +static __always_inline void instrument_memcpy_before(void *to, const void *from,
> +                                                    unsigned long n)
> +{
> +       kasan_check_write(to, n);
> +       kasan_check_read(from, n);
> +       kcsan_check_write(to, n);
> +       kcsan_check_read(from, n);
> +}
> +
> +/**
> + * instrument_memcpy_after - add instrumentation after non-instrumented memcpy
> + * @to: destination address
> + * @from: source address
> + * @n: number of bytes to copy
> + * @left: number of bytes not copied (if known)
> + *
> + * Instrument memory accesses that happen in custom memcpy implementations. The
> + * instrumentation should be inserted after the memcpy call.
> + */
> +static __always_inline void instrument_memcpy_after(void *to, const void *from,
> +                                                   unsigned long n,
> +                                                   unsigned long left)
> +{
> +       kmsan_memmove(to, from, n - left);
> +}
> +
>  /**
>   * instrument_get_user() - add instrumentation to get_user()-like macros
>   * @to: destination variable, may not be address-taken
> --
> 2.44.0.291.gc1ea87d7ee-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPA9h_OgizevqkiEkGS34nSPnQrqWF0FMazwVfjR3w0uQ%40mail.gmail.com.
