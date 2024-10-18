Return-Path: <kasan-dev+bncBDW2JDUY5AORB4W6Y24AMGQENALSODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id E51FE9A31BC
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 02:44:35 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2fb50351d18sf11920581fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 17:44:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729212275; cv=pass;
        d=google.com; s=arc-20240605;
        b=hDOp3m/5pCvyJo3ccje5caH70kbZ2tkkBQaTE4fh2TixVhPctwj53FNNhr8COUfRsi
         o6b/Ry6s6/AOGcy+jPaXO++EFmQ6bc4S76ptk+HNHBIal+x1BjBsMOsP8sRaBOeaBBR4
         UYXDGBKtvyoU051dche5I6Tg/HmVLnxMLoI8gCxR2dPxhcmiyIfmFVEC4FlnsPRJ46tQ
         JAtCcJEfEpqyNqVreGl95SEc+4FDhV6hkh5REM4GLG2+NbXYTtl21RBKw/9NfLFRRK3d
         winhxDdWbpWsxk8P3d+OjpsiMuhWOxQdb146ZkrHRa6DDYKVw1qyoIZGcoqlbxuH5r2I
         O96A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+hPu/7aD3xodWYdPK5ukbhb69BsTJU0apT+Pmudc2yc=;
        fh=lN3Av+CkRGBrVq+c6m/0pxUZdHpRoisNGgn6cWrceW0=;
        b=X8e2GoW+gUeL6RXq7MJGvfdCeXpWkb/a6Sg0km//SuuPGMA7ANMehkvaKpBWEVt0Iv
         1H91y0CIk8nrPGE9OfsL3BS1HZ9GDmg2SpemalsJN89GISnV6iGAEscQFn5eFe5/Ea+a
         gjvhBrvh8Nfe3ZApLs1gm+syeXbhphvWazHvm5Aog1jyhnqhPXlFSL0gzrZx+TrsPwyA
         2toaGlnne9keSq3D6J9ZfBXTVnx+lAjgBRWBjnAXOE2w880f92CC9bkI195pyQnjhLRJ
         vDkAkcomT7xhgt17IYo3MFqJC9TjHRP3jH3ok66F3cHpqNONylNWsrUDrYJEEy5LDKd0
         rwkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cQrZnRxD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729212275; x=1729817075; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+hPu/7aD3xodWYdPK5ukbhb69BsTJU0apT+Pmudc2yc=;
        b=wn3jKYq7J4QumcFq0iV4CWgQqYfgUX1Ro/f68+5Nf909Cgkwq3O8hJMCr4HTkRyMlO
         ySJZSMhPosGS+q2IZXQA/iUp6grF8uWKOV1ZabgPMxK5yoILyyFD90jKpI1SoxB1TFnI
         KsszZ/XiSeQqghRzY8gbiEo9M8Mmfe9TKdWu9Ue0LruEOJFbJzI4z3gc1x4Qzr2UgnsY
         TAPJ2D59QN9mOeHcOwiW+UkrOVnjKBOHRwVvm7IVwk/KybnjXtAxtk5viruwKLMW224H
         925atkKHJmU5CkAJBV0zC4BaMxQiKKx0jWUbjrY87Bs/uBAysjaw7qoWh7FpJWy1UoQ8
         o3YA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729212275; x=1729817075; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+hPu/7aD3xodWYdPK5ukbhb69BsTJU0apT+Pmudc2yc=;
        b=ZG89xPbwwOAz5HVPX7hI8/VNqCAzcCzhCk4RpI5Y3lcn3PNgtyOVcRZSUWenN5nUfC
         Hv0zrWyzTpO/XN1eG7gNKz3+StVi+PXIS2LydHRbRqivsoQskChMmfolHwF+tZWoxl7+
         uT/i1XXXSB401t7d+0Kl4PmUxBSG+AKhVhXk4HoRkfVj4WpOsQXA+s+nN1qQgkQUF2xH
         5ooDg1Uy0/2L89isN8biRFAu09nqENkkuUMnOLxiPLl0BxFigVPwef048S4r86Tp7Egp
         W3UB3IEgo2rJHgwnWfM7hUTLKl1QU5MeMe/pFb5WeK3HCx3o76zeI8ypPg65fKVT9ke7
         lcCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729212275; x=1729817075;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+hPu/7aD3xodWYdPK5ukbhb69BsTJU0apT+Pmudc2yc=;
        b=CBlWTallYrz7tr+kPo/gIFrgXvApAQZoxznFdhx/xmJKs8UrRigOqAeyWEw+t87eMx
         MuyVy3TfTb7raucjsduLYhdhVyi9TJG3hknW5BRF8naSCNXKMjlyBJ2LPJVYtULvTyGa
         5M6tIz+3amRtKTlq07BSQoOM9Ft9UGe1EU8GpCdSZ30dyx8RWl0wwMx0oBzElZQFeHDo
         2QdtPyjjufkwsJ7EmEXa9Ibgl3K9O464oRKoNXHmzV6+nDCcKAm/KQ0qnSy4hJBnK+0P
         Ok1D04dW67/4a1ghb+mRcgaF5c1M/W2YUMNNLd3Ld3x6iTNrPdZ036ggJUlu11B+5EJR
         8e+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzB4hBzzLqlqCOmMxyj+B99F1fc2S2UBFO8Sa9tKm5GnsApqZeMWSpQ6xsEPHVum3H6YDS0w==@lfdr.de
X-Gm-Message-State: AOJu0Yxxtt0nk8eKmSdjJ/TF9L4gy4vvAhFtcC3P6VJISvBiJW5qpct9
	V59h0D35L+DC7aD4bnsdXqvEgFeDF+QWOUevTyg6egYDeKn17T+G
X-Google-Smtp-Source: AGHT+IHJkfZufcjjaHTjHwSttSGBEDoFKrBr04tlnf3OCtZ7gxPcdn5l8v1oFsbbVu2ZqUTSXs7g/A==
X-Received: by 2002:a2e:bc29:0:b0:2fa:d723:efba with SMTP id 38308e7fff4ca-2fb82e9096fmr2147781fa.8.1729212274656;
        Thu, 17 Oct 2024 17:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2205:0:b0:2fb:4ec0:e150 with SMTP id 38308e7fff4ca-2fb6d55342cls1944041fa.0.-pod-prod-06-eu;
 Thu, 17 Oct 2024 17:44:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAAzEkZcRnnpmToW+cYhMZHHkJ9SLi80yTKhsPClR0KHdHUKuzA9Mejvb1/8KDLuT4pY6ZkRTfymc=@googlegroups.com
X-Received: by 2002:a2e:71a:0:b0:2fa:f5f1:2539 with SMTP id 38308e7fff4ca-2fb82eafb5fmr1352031fa.24.1729212272315;
        Thu, 17 Oct 2024 17:44:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729212272; cv=none;
        d=google.com; s=arc-20240605;
        b=LV55dA/nZp4tQboUmGVOQyYHPtWzIG0+q0VYLYOhPkaZh8pmX3DBSOI1SvoNtGPhno
         nel6tBYhVFQ5myiEXJDxfiGM/vYYSXvbH1YC9CkKXakpsRPMygnLY0QRJZaOqbYxd/1M
         YtywGwc5DA/X6xwmqSyJgagvoHmaiGUE9+ajHxDWIH85Z1yVigOMw21GStr4E+7QN9f/
         RlmW2u/lHGAiCnlS6fvUyX5U0JaIeCyFxUFQ/4VWO3F/cABbka8unR913aRFBAYBuID1
         NGwjT6i4zT2Vok8iXXCKyvlJHJ31cK7+QEFEcqLkNrenVjUXWIhHMm4nw2m6zwZz8lgW
         edjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DAvkFrdc7zAxYyluwBsnI5D7V9ZNzBP/jZq5jYVwZ9E=;
        fh=rL2H2tMxs5vej+5ocomSsegNR6goZTVWPrUVkJLW/io=;
        b=HP9EZpZQsmhg2yZs0BfaAf+vIyVhH0jn39YQVPfjdJ+mdjKu5pk1AJUlNRwVrqzQVG
         B1GVi/fzcBpkpp196ZxQ81dOICuLftN0ihD+KOrdcRd7+nKe/ofxMK88Yp4pHQ4pd1yZ
         jU21K0o0BJxvTpiit9NWUnD/9gYNwqgTDWD2Re06cCFseO8b5PIhsIHkRzAYvryKbqmH
         QskCbIaH2VUkWZZ9bDA4DxOkPYkY7UkUdIHUuKCEWfSdpVZuShiPyDKwQv869wW+FS3d
         4Z2XxEB2Uo0losr9P+MOcVhEt0WGxFU97Hs1wGadhtcx2xcFjcfv1nZ8L6iJoO342M1h
         7Arg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cQrZnRxD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb80a0acb8si97481fa.5.2024.10.17.17.44.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2024 17:44:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4315baec69eso11000575e9.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2024 17:44:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVEC3oOGPG8FE2uKo8JUtzsWmtha+8/H7x4NHlqTmfRTsOIAK9tsbcRJf0pfxQvrZA8/Uks4KKHvNs=@googlegroups.com
X-Received: by 2002:a5d:4903:0:b0:37d:4eeb:7375 with SMTP id
 ffacd0b85a97d-37ea2164baemr367751f8f.16.1729212271270; Thu, 17 Oct 2024
 17:44:31 -0700 (PDT)
MIME-Version: 1.0
References: <20241017214251.170602-1-niharchaithanya@gmail.com>
In-Reply-To: <20241017214251.170602-1-niharchaithanya@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 18 Oct 2024 02:44:20 +0200
Message-ID: <CA+fCnZfT80jDpQ5Dh-4w+eGQGoJQYd-F6h=_qNP4aw81TUMOCw@mail.gmail.com>
Subject: Re: [PATCH] kasan:report: filter out kasan related stack entries
To: Nihar Chaithanya <niharchaithanya@gmail.com>, Marco Elver <elver@google.com>, dvyukov@google.com, 
	Aleksandr Nogikh <nogikh@google.com>
Cc: ryabinin.a.a@gmail.com, skhan@linuxfoundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cQrZnRxD;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e
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

On Thu, Oct 17, 2024 at 11:46=E2=80=AFPM Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> The reports of KASAN include KASAN related stack frames which are not
> the point of interest in the stack-trace. KCSAN report filters out such
> internal frames providing relevant stack trace. Currently, KASAN reports
> are generated by dump_stack_lvl() which prints the entire stack.
>
> Add functionality to KASAN reports to save the stack entries and filter
> out the kasan related stack frames in place of dump_stack_lvl().
>
> Within this new functionality:
>         - A function save_stack_lvl_kasan() in place of dump_stack_lvl() =
is
>           created which contains functionality for saving, filtering and =
printing
>           the stack-trace.
>         - The stack-trace is saved to an array using stack_trace_save() s=
imilar to
>           KCSAN reporting which is useful for filtering the stack-trace,
>         - The sanitize_stack_entries() function is included to get the nu=
mber of
>           entries to be skipped for filtering similar to KCSAN reporting,
>         - The dump_stack_print_info() which prints generic debug info is =
included
>           from __dump_stack(),
>         - And the function print_stack_trace() to print the stack-trace u=
sing the
>           array containing stack entries as well as the number of entries=
 to be
>           skipped or filtered out is included.
>
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=3D215756

Great start!

One part that is missing is also filtering out KASAN frames in stack
traces printed from print_track(). Right now it call
stack_depot_print() to print the stack trace. I think the way to
approach this would be to use stack_depot_fetch(), memcpy the frames
to a local buffer, and then reuse the stack trace printing code you
added.

I've also left some comments below.

Please address these points first and send v2. Then, I'll test the
patch and see if there's more things to be done.

On a related note, I wonder if losing the additional annotations about
which part of the stack trace belongs with context (task, irq, etc)
printed by dump_stack() would be a problem. But worst case, we can
hide stack frame filtering under a CONFIG option.

> ---
>  mm/kasan/report.c | 92 +++++++++++++++++++++++++++++++++++++++++++++--
>  1 file changed, 90 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b48c768acc84..c180cd8b32ae 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -39,6 +39,7 @@ static unsigned long kasan_flags;
>
>  #define KASAN_BIT_REPORTED     0
>  #define KASAN_BIT_MULTI_SHOT   1
> +#define NUM_STACK_ENTRIES 64

If we keep this as 64, we can reuse KASAN_STACK_DEPTH.

However, I wonder if 64 frames is enough. Marco, Alexander, Dmitry,
IIRC you did some measurements on the length of stack traces in the
kernel: would 64 frames be good enough for KASAN reports? Was this
ever a problem for KCSAN?

>
>  enum kasan_arg_fault {
>         KASAN_ARG_FAULT_DEFAULT,
> @@ -369,12 +370,99 @@ static inline bool init_task_stack_addr(const void =
*addr)
>                         sizeof(init_thread_union.stack));
>  }
>
> +/* Helper to skip KASAN-related functions in stack-trace. */
> +static int get_stack_skipnr(const unsigned long stack_entries[], int num=
_entries)
> +{
> +       char buf[64];
> +       int len, skip;
> +
> +       for (skip =3D 0; skip < num_entries; ++skip) {
> +               len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_=
entries[skip]);
> +
> +               /* Never show  kasan_* functions. */
> +               if (strnstr(buf, "kasan_", len) =3D=3D buf)
> +                       continue;
> +               /*
> +                * No match for runtime functions -- @skip entries to ski=
p to
> +                * get to first frame of interest.
> +                */
> +               break;
> +       }
> +
> +       return skip;
> +}
> +

Please also copy the comment for this function, it's useful for
understanding what's going on.

> +static int
> +replace_stack_entry(unsigned long stack_entries[], int num_entries, unsi=
gned long ip,
> +                   unsigned long *replaced)
> +{
> +       unsigned long symbolsize, offset;
> +       unsigned long target_func;
> +       int skip;
> +
> +       if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
> +               target_func =3D ip - offset;
> +       else
> +               goto fallback;
> +
> +       for (skip =3D 0; skip < num_entries; ++skip) {
> +               unsigned long func =3D stack_entries[skip];
> +
> +               if (!kallsyms_lookup_size_offset(func, &symbolsize, &offs=
et))
> +                       goto fallback;
> +               func -=3D offset;
> +
> +               if (func =3D=3D target_func) {
> +                       *replaced =3D stack_entries[skip];
> +                       stack_entries[skip] =3D ip;
> +                       return skip;
> +               }
> +       }
> +
> +fallback:
> +       /* Should not happen; the resulting stack trace is likely mislead=
ing. */
> +       WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void *)=
ip);
> +       return get_stack_skipnr(stack_entries, num_entries);
> +}

Hm, There's some code duplication here between KCSAN and KASAN.
Although, the function above is the only part dully duplicated, so I
don't know whether it makes sense to try to factor it out into a
common file.

Marco, WDYT?

> +
> +static void
> +print_stack_trace(unsigned long stack_entries[], int num_entries, unsign=
ed long reordered_to)
> +{
> +       stack_trace_print(stack_entries, num_entries, 0);
> +       if (reordered_to)
> +               pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordere=
d_to);

This reordered_to is a KCSAN-specific part, KASAN doesn't need it.
Thus, this helper function is excessive, let's remove it.

> +}
> +
> +static int
> +sanitize_stack_entries(unsigned long stack_entries[], int num_entries, u=
nsigned long ip,
> +                      unsigned long *replaced)
> +{
> +       return ip ? replace_stack_entry(stack_entries, num_entries, ip, r=
eplaced) :
> +                         get_stack_skipnr(stack_entries, num_entries);
> +}
> +
> +static void save_stack_lvl_kasan(const char *log_lvl, struct kasan_repor=
t_info *info)

And this one we can then call print_stack_trace().

> +{
> +       unsigned long reordered_to =3D 0;
> +       unsigned long stack_entries[NUM_STACK_ENTRIES] =3D {0};
> +       int num_stack_entries =3D stack_trace_save(stack_entries, NUM_STA=
CK_ENTRIES, 1);
> +       int skipnr =3D sanitize_stack_entries(stack_entries,
> +                                num_stack_entries, info->ip, &reordered_=
to);
> +
> +       dump_stack_print_info(log_lvl);

No need to pass the log level down the call chain, just pass KERN_ERR
directly to dump_stack_print_info().

> +       pr_err("\n");

dump_stack() doesn't add a new line here, let's also drop it to keep
the report style as before.

> +
> +       print_stack_trace(stack_entries + skipnr, num_stack_entries - ski=
pnr,
> +                                        reordered_to);
> +       pr_err("\n");
> +}
> +
>  static void print_address_description(void *addr, u8 tag,
>                                       struct kasan_report_info *info)
>  {
>         struct page *page =3D addr_to_page(addr);
>
> -       dump_stack_lvl(KERN_ERR);
> +       save_stack_lvl_kasan(KERN_ERR, info);
>         pr_err("\n");
>
>         if (info->cache && info->object) {
> @@ -488,7 +576,7 @@ static void print_report(struct kasan_report_info *in=
fo)
>                 print_address_description(addr, tag, info);
>                 print_memory_metadata(info->first_bad_addr);
>         } else {
> -               dump_stack_lvl(KERN_ERR);
> +               save_stack_lvl_kasan(KERN_ERR, info);

Ah, looks like we have duplicated dump_stack_lvl() call. Let's move it
(or rather print_stack_trace() in this patch) before the if
(addr_has_metadata(addr)) check and the drop it from
print_address_description().

>         }
>  }

>
> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfT80jDpQ5Dh-4w%2BeGQGoJQYd-F6h%3D_qNP4aw81TUMOCw%40mail.=
gmail.com.
