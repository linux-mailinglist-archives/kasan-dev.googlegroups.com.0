Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYMW4TZAKGQESQT6HCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 97FF517376A
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 13:45:22 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id d26sf714846uak.13
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 04:45:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582893921; cv=pass;
        d=google.com; s=arc-20160816;
        b=nf2UlUGsmM86ZF0m4ycrWfuiV4YojAuIZ+JXxtUWZa293gnchtEEgbX80AhZ2qlLdT
         X0Mk9FXzlaFA/1R96De7sWcbNPLQRzGS0DJOCitM0ZxAW0nJJfTpvGnqTot9S2US/bIr
         qjGhtB+mKQtTyfOjR9SKcyi3iiYtUEK3rtsKgEPBiMWgAicMlTdBY4Ez0mWLPc+hB0BH
         RyxXIJvfquMrC5uAaRhp8pOl/7L2AX2aSROk2mwew6NRQAgde7vbeXqTBDJ9PYv6TkBf
         LfcLNsdkPfO/Yf75vEX1ieUfPnK7Ie5oeaL40apUvk3yOsIu6VLKdVkNJSf9X3oZuHca
         EI+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kYc9gPn5EK5CrIfgtgAL1UZjeuFIKPBRQyBnF92i3EI=;
        b=eUE9LD5546UInRn0J46mi7frD96qiUqjE2tL/RI+JMzfD6RB3L4rIm8WJA3fPP7kVD
         Lqy25bg/qlPIaVr1N0/9khNGTRnynQFiVCYdAGBvxrZ0rrtVudEpRzjOh95lxPgVFrEr
         ZuXfMDyhEavL+W/NGTy3rqSVrLNPp5ga1MVbmcrotSZXsqM60jaxtPaIZR9qCpu+pHtT
         Fn+8ze+ZhqLNs9edwhSOZKjEo7/uQB1V8W9KGlZRyTb3t81Y+flm3GeeZwClZr84Bo4D
         Mkkgc1xC0n6lAthQx/ZTWKxJc8V0tljfmqfs4fTBFzd8BmBLw7gI98O4rIpAzgBcgEAp
         9JVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=prezLH9X;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kYc9gPn5EK5CrIfgtgAL1UZjeuFIKPBRQyBnF92i3EI=;
        b=EdGvvLErrgRqgyjRb8PG+JeC0yXqiXLSi5U9h2cbZQ6/39ysdnKDA5N6RchJxOMXL0
         3lJsAyV5YL13WpvZP22as+Zi3bR8xyZyOipbjKBZNagrF7gZz9PP36DpAPo0BcMbZ44j
         DaSUGUDL+5/X4EVPi4hi+pqaf1aUMM4LppoHwejGjLBLXDkQiib63e9uvxrY+qh/0XwX
         AqrXfOuQv+NhBENockuZ/8pfixj+qf7AuyRyJjdAAoED3Wd0zk7K2uAVFsxeZg2nxFC/
         2EiLgVW7WkFYrkJR+A28oABVXs/OHfnnNOSHx3vcpHVPGryjuKG/8HPqW+QDulioJyGZ
         m/XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kYc9gPn5EK5CrIfgtgAL1UZjeuFIKPBRQyBnF92i3EI=;
        b=kqazpb5kXPtg4/7RzO0KL4BAVpHQVyX8YfUNLOoE9wvAQVr2GtYRJMDbKB06YXDuEr
         bL3X/w9TH+ikaW2gCYz2g0W47ap55lacL4o2fwmKNfigYr3UIHjT0VjP0Lkcds4NTyqh
         FGAJoPtpNYw7xvmn3xHAUjnBrK14AdjG627jcUEh6rKLwqWpbchFXCZ1DjcRw50ExDPo
         GinotU/nlmx2pDyKCVsBf1HBqztHnneDOlpMzTGbdK0IfL7o6TPGolpyMAaL2pJutp39
         icHcn9/uEzhmKIPqXpDyIzcUfQKKbJ68YvGFJnCQp4Cet61VFScrqOq8JOLiGuL6wfpX
         0otw==
X-Gm-Message-State: ANhLgQ3bvuV17dTfzveMd1ZprFMzGUn37jlDNGZcBDVjvQV7DS0Ndcv9
	0Q4DBrbp3EOC5hfi0Aa9keI=
X-Google-Smtp-Source: ADFU+vuWRLR7uNRiYi4AmdCZQ3HjPgpZhscwMfEwtKd5txMlxbtL46gG5k7oFVEXMPbKO9cZubzwHA==
X-Received: by 2002:a67:c30d:: with SMTP id r13mr1450407vsj.12.1582893921410;
        Fri, 28 Feb 2020 04:45:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:27c5:: with SMTP id n188ls344067vsn.8.gmail; Fri, 28 Feb
 2020 04:45:21 -0800 (PST)
X-Received: by 2002:a67:eecb:: with SMTP id o11mr2472251vsp.227.1582893921018;
        Fri, 28 Feb 2020 04:45:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582893921; cv=none;
        d=google.com; s=arc-20160816;
        b=RhMWgks1ZRYHsvEHOcAAZgjIcAL2aYyBpuVSIb+oEEQ8AUwNs+rijsGIFEjneoaVIb
         Q22aIlcMXA47+bGLnXyC1USwpNKPaIWSJalkai+9r44XGzT65rADSVLY+++ZyRDD09SA
         eGk7Gc8Ubka6oST5Ue64K6ZDDjKqRnk6LvACIGGFE7M2o/3Z+X3pLVwguk+ehMecTpYu
         8RjJqXL16OVBXut3X845goWh+jM0yykvw5WKLdnL9OyJV0PnbhK2lyTQP1xKrCmZOClg
         1jGmkdQkaEhns3eTOwsQpJe43jhaQVSG5hrrazkveSuY3emZaUOcK3JXBl905+1Fw3Zh
         Nchg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8/UqvYVXzGtEHBHG3XZtTd7eLo2Dd8AJKY596FBc5Ug=;
        b=RuYceBK+NnoEKXPTgSjAIZR9Dz2+814iUNlJwn2wwJPeaW23vx6VL8URtg4iMIqqWI
         5jzfYv/RDIfURFZJTHj/qpqw4fv64CT3mTVx8yQpVhCmd5rZRP352sMqhJLXj3+UrVCf
         VYwRlSpfxMTUBtA1RmywzkEwrYrK5vZqpPduckbTCfpBe+K9CBo6TvY+xDEputVUwUv5
         6ekQSXpkS2Eivw2iUlfKu5vGu2j7Tc1LyzvwpHl6y+PUXJdRQtWKwKPiK80s+KGzn3CH
         chJSxomdguMGeWGBE+qNGbsJvn6TFJudqD0SSxNfYC8LPOTLq2cjikO+0ciuVo+Mf9Ic
         aFAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=prezLH9X;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id 9si211048uau.0.2020.02.28.04.45.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 04:45:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id e9so1262610pjr.4
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 04:45:20 -0800 (PST)
X-Received: by 2002:a17:902:8492:: with SMTP id c18mr4058531plo.147.1582893919646;
 Fri, 28 Feb 2020 04:45:19 -0800 (PST)
MIME-Version: 1.0
References: <20200227193516.32566-1-keescook@chromium.org> <20200227193516.32566-7-keescook@chromium.org>
In-Reply-To: <20200227193516.32566-7-keescook@chromium.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 13:45:08 +0100
Message-ID: <CAAeHK+xhFJxUeY4BN52Rd6Q_DH582VhQ2pbZZcrDYrnaUHQufQ@mail.gmail.com>
Subject: Re: [PATCH v5 6/6] ubsan: Include bug type in report header
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Alexander Potapenko <glider@google.com>, Dan Carpenter <dan.carpenter@oracle.com>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Arnd Bergmann <arnd@arndb.de>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kernel-hardening@lists.openwall.com, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=prezLH9X;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Feb 27, 2020 at 8:35 PM Kees Cook <keescook@chromium.org> wrote:
>
> When syzbot tries to figure out how to deduplicate bug reports, it
> prefers seeing a hint about a specific bug type (we can do better than
> just "UBSAN"). This lifts the handler reason into the UBSAN report line
> that includes the file path that tripped a check. Unfortunately, UBSAN
> does not provide function names.
>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://lore.kernel.org/lkml/CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  lib/ubsan.c | 36 +++++++++++++++---------------------
>  1 file changed, 15 insertions(+), 21 deletions(-)
>
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index 429663eef6a7..f8c0ccf35f29 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -45,13 +45,6 @@ static bool was_reported(struct source_location *location)
>         return test_and_set_bit(REPORTED_BIT, &location->reported);
>  }
>
> -static void print_source_location(const char *prefix,
> -                               struct source_location *loc)
> -{
> -       pr_err("%s %s:%d:%d\n", prefix, loc->file_name,
> -               loc->line & LINE_MASK, loc->column & COLUMN_MASK);
> -}
> -
>  static bool suppress_report(struct source_location *loc)
>  {
>         return current->in_ubsan || was_reported(loc);
> @@ -140,13 +133,14 @@ static void val_to_string(char *str, size_t size, struct type_descriptor *type,
>         }
>  }
>
> -static void ubsan_prologue(struct source_location *location)
> +static void ubsan_prologue(struct source_location *loc, const char *reason)
>  {
>         current->in_ubsan++;
>
>         pr_err("========================================"
>                 "========================================\n");
> -       print_source_location("UBSAN: Undefined behaviour in", location);
> +       pr_err("UBSAN: %s in %s:%d:%d\n", reason, loc->file_name,
> +               loc->line & LINE_MASK, loc->column & COLUMN_MASK);
>  }
>
>  static void ubsan_epilogue(void)
> @@ -180,12 +174,12 @@ static void handle_overflow(struct overflow_data *data, void *lhs,
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, type_is_signed(type) ?
> +                       "signed-integer-overflow" :
> +                       "unsigned-integer-overflow");
>
>         val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
>         val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
> -       pr_err("%s integer overflow:\n",
> -               type_is_signed(type) ? "signed" : "unsigned");
>         pr_err("%s %c %s cannot be represented in type %s\n",
>                 lhs_val_str,
>                 op,
> @@ -225,7 +219,7 @@ void __ubsan_handle_negate_overflow(struct overflow_data *data,
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "negation-overflow");
>
>         val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);
>
> @@ -245,7 +239,7 @@ void __ubsan_handle_divrem_overflow(struct overflow_data *data,
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "division-overflow");
>
>         val_to_string(rhs_val_str, sizeof(rhs_val_str), data->type, rhs);
>
> @@ -264,7 +258,7 @@ static void handle_null_ptr_deref(struct type_mismatch_data_common *data)
>         if (suppress_report(data->location))
>                 return;
>
> -       ubsan_prologue(data->location);
> +       ubsan_prologue(data->location, "null-ptr-deref");
>
>         pr_err("%s null pointer of type %s\n",
>                 type_check_kinds[data->type_check_kind],
> @@ -279,7 +273,7 @@ static void handle_misaligned_access(struct type_mismatch_data_common *data,
>         if (suppress_report(data->location))
>                 return;
>
> -       ubsan_prologue(data->location);
> +       ubsan_prologue(data->location, "misaligned-access");
>
>         pr_err("%s misaligned address %p for type %s\n",
>                 type_check_kinds[data->type_check_kind],
> @@ -295,7 +289,7 @@ static void handle_object_size_mismatch(struct type_mismatch_data_common *data,
>         if (suppress_report(data->location))
>                 return;
>
> -       ubsan_prologue(data->location);
> +       ubsan_prologue(data->location, "object-size-mismatch");
>         pr_err("%s address %p with insufficient space\n",
>                 type_check_kinds[data->type_check_kind],
>                 (void *) ptr);
> @@ -354,7 +348,7 @@ void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data, void *index)
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "array-index-out-of-bounds");
>
>         val_to_string(index_str, sizeof(index_str), data->index_type, index);
>         pr_err("index %s is out of range for type %s\n", index_str,
> @@ -375,7 +369,7 @@ void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *data,
>         if (suppress_report(&data->location))
>                 goto out;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "shift-out-of-bounds");
>
>         val_to_string(rhs_str, sizeof(rhs_str), rhs_type, rhs);
>         val_to_string(lhs_str, sizeof(lhs_str), lhs_type, lhs);
> @@ -407,7 +401,7 @@ EXPORT_SYMBOL(__ubsan_handle_shift_out_of_bounds);
>
>  void __ubsan_handle_builtin_unreachable(struct unreachable_data *data)
>  {
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "unreachable");
>         pr_err("calling __builtin_unreachable()\n");
>         ubsan_epilogue();
>         panic("can't return from __builtin_unreachable()");
> @@ -422,7 +416,7 @@ void __ubsan_handle_load_invalid_value(struct invalid_value_data *data,
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "invalid-load");
>
>         val_to_string(val_str, sizeof(val_str), data->type, val);
>
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227193516.32566-7-keescook%40chromium.org.

Acked-by: Andrey Konovalov <andreyknvl@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxhFJxUeY4BN52Rd6Q_DH582VhQ2pbZZcrDYrnaUHQufQ%40mail.gmail.com.
