Return-Path: <kasan-dev+bncBCMIZB7QWENRBV4KXLBQMGQEV2WRUWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id DA82DAFED06
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jul 2025 17:06:02 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-450df53d461sf44617805e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 08:06:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752073562; cv=pass;
        d=google.com; s=arc-20240605;
        b=O0vo0/TCXmk2Qfm6958MfejHKBRjrnI/YEk4nvayR4U9BQDDR4RPk0w88zFgm9+Udn
         6yTktRGRu+GkIhwwKfv6IZ5P3GZgXWT3hYfQqPpkLEvp4Py35KcumgRQTjvXARa1+Enl
         lzayCkWBNzkQyoteRjAzLbHY7UAElDLpvS4lZpD90O1X3oQbDWDOYM0qFLf6YJUBM9Er
         srcrKLH3v5NhsW6WiUIoOHDBCy58aHKXNXMeMbJ8J2ExHw465sI9RE0exSejK1vhfHcQ
         Rx0YyupIDWwTuLGF75h+A1IPNb3a23ZDsOQXkvmXMv2hCMD7h1dJTUJLrRHStsxP7Y3U
         Jvpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Hp8FumWoa9u3krvaMACBqLwT+tpQVg6WZFU0mbxkHYo=;
        fh=cNq+q5KpPMIXQCg1dhBM4nrAzxX0J2OIeAiL0C25TXU=;
        b=SfBspXABr0pDELx4aL0gw47MtvywMWiBipPwafG75F++FngoqzMAZ+mij4nY699rfq
         bMtjj3U64onFLvu56WE9v8RI38ht5ynf+2wLXHcIkfIQHWR5V0JVx0/oRiGVsUWmAHxt
         dVQD9B+w4qKt9yBieck8Ecli6Kxp/PgLLMYtB8k7w0uvKcYQlJw0r0BIt44LOgAzlC1f
         h2lNhqydDrjHlTnUod50f9J0KuSXCVauy8oCnbsmhbGgq5EGdwoyx24s2T6iMo26i3CZ
         pXyUMIJQk6wE5EFmumkrRLyK+nbxMLDbetz9V9hywptJtY7xyTeKjRH9pvfZb2Pn+BVw
         kEyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B5s0PTLk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752073562; x=1752678362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Hp8FumWoa9u3krvaMACBqLwT+tpQVg6WZFU0mbxkHYo=;
        b=MMvX4v0ECmCuXos7dEIRuqDDnEEFA1WH99MIDtapRyjKQ4UY7gb/O787hsdMj/r9NB
         /mWR1sDw/WOXPnKh678XqF3q/auF2SxBqiBTJPNYet9N9YHVuiCOTo1z3CDw+MJGb4f4
         RUEINIuKrs/8Hs8rh/tuqEBtWKZYffR3pW1Kz1+awcAmqdBRtCvwsGmWdbIbNSS/XIrm
         NtVaf1krnyU/eZLYzEZxR0gyN5MjtU7W2lUyRwYK79BLgbT7N76llTqWPxR9tcWHcBt2
         BiIaj4zmfADRT4dEbYRoH2cwinVTBy6WAABBkKILz3Bp/lGpSLElLZbM9tKjOj9brweb
         0ozA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752073562; x=1752678362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hp8FumWoa9u3krvaMACBqLwT+tpQVg6WZFU0mbxkHYo=;
        b=W8YEg0baRVzesNHvw2j0/iFVKBFveddD8aph7JXXZPGg6mCV1Vaw+q03GxGwB/axWp
         /Yzb+HZA8WMIQd5zVXQa5XYpuAS3ToxrUolbvrfdj1Z2OHo+L23dtiCkA9veo5O7UnjL
         /HElSeQg44PTZnCOlLY39LMI6Z4dnerS7HRxiLuzPbNfuK8BoiIj+lm8j4bznIIpIlvH
         De+aie1Isl8fxzLNW0b4rRWYWdFTm68XkrW5OFTKa7rMY4eyQLeVJnmfO4IyhrYWrtXm
         gETtJpNDVK4T5PGvqL4f0TpjQjEMmVNICHmdhRjpMKNXClpsikwt6q2tChMkmbEAqlTQ
         +vKA==
X-Forwarded-Encrypted: i=2; AJvYcCWkKxjlIcmJoPMTGoQZ9HW4UJhc5d8rX8nHGCBsoRgf3C9GU9ZWP7VW8dVAL85JnYNKkGDW3Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw6CAQD6JSoSOM/29LtiqRnFCMxZ1EroOuHvfW+qjNYEUiG3Abo
	J5iiCUty/lzE7LtEBrxE5Syew/yvHp0bwqEEEnJ0yWvRtrOZn3ysH94+
X-Google-Smtp-Source: AGHT+IGBQToNlF7k497k3vNSTWAxFJlnLzNd5ABF5fACBL9u0q/8Os2M9RNA53wgUkP13gzuMSShPQ==
X-Received: by 2002:a05:600c:6989:b0:450:d3c6:84d8 with SMTP id 5b1f17b1804b1-454d52fb1e7mr31529595e9.14.1752073559955;
        Wed, 09 Jul 2025 08:05:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZci1zZbp46QXbfcO8Xnz6qxZB2ZsaG3RptWbnrlF3rnyQ==
Received: by 2002:a05:600c:608e:b0:43c:fb0f:d9ae with SMTP id
 5b1f17b1804b1-454db45a8d4ls195185e9.0.-pod-prod-05-eu; Wed, 09 Jul 2025
 08:05:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIExsz1c5iCo6RWGiXwEP/cYmvRc7dUt/+LKFWx8zndIEZ7gcBoVQF4ikgiGHNcCy6xfIBnNUqMYI=@googlegroups.com
X-Received: by 2002:a05:600c:3ba6:b0:43c:fa52:7d2d with SMTP id 5b1f17b1804b1-454d535caaamr24507675e9.20.1752073556435;
        Wed, 09 Jul 2025 08:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752073556; cv=none;
        d=google.com; s=arc-20240605;
        b=Nbg5PY064XXd9KWhLG1YjyfNa25kADR/CaT9Kt8wRYeRZOBhv7w9sS1Rv6SUm/U6rn
         r1lJwyYromUDCFk/MLtfh4NpkeK4COXFt2s4scJRWc++EjlQxuyiB/GX7kE5Of7FwvJP
         4iln/Gs8qavRKmFzxRpkGbx1MsGyYT/+uQHsSndBXka16X26TUZKA7haNv7WtZS8F7kv
         7kf0XTZH5hgipw6B7Krz179KMFtbtpIU443DyJby0mgOfv2UqxK1QPtI1liguS5st5hE
         n847rEa8HKsxMbO/tgFGOh3wkhC8yx6+lfJdMaSMLFnfzGS7jWu3ZsxvVu9S74dj32V7
         0xfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X3EFJZWHFKRnvYs24gJy3y+hySRApe+N9eZ4FMpwih8=;
        fh=9sjPqOq1hTG0HC0YAcuJJ5zZZ9UzeEKjDqQzqV+fq1w=;
        b=kpwCpaLLkfM1ut8z+b79vSYT0edw/ufro8ela7Ctt8DV9wdFvtdsrR9o1fqSr2ziRO
         /f+jDF9Y3nVGJnOEz4vRXWBr6eSBN32ERO2faCyeVMeDqF8bemGn0wl9S3AzMmdepeZ/
         s+JyThAF+AWJIZKSD4QgQOtN4wa/RQwPs4zGdeobNtW0RkDKcIm1l7FOl4+JalefTBvX
         xFOO/d2Bw0WmqeRTrqZjmhbLeyi6xdeOiBTWsLBN5NN1qtlwcx7Gy84nj+CuGxF2X1Ev
         qn0j5yuxTp2I08JC+qQAZM0ECpK2UmhADYN0TBGMkNBDDKEVNZFHbrqPkS9JskN6DX4H
         I+UQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B5s0PTLk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-454d508d947si529105e9.2.2025.07.09.08.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jul 2025 08:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-32b31afa781so47910831fa.3
        for <kasan-dev@googlegroups.com>; Wed, 09 Jul 2025 08:05:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX1EBZ14kIH4x0NRCfqRd3XIGcbOa3v98h40Oo1xy6KcUrdnTyAp6P5SZlC8AyFQbwbp61JVsvNpxc=@googlegroups.com
X-Gm-Gg: ASbGnct+b02Hv+fy1215eGtqZwdr/WzGazuhyhB5R60toIHwa8QKb6ZdjzoW3bGC+4N
	POOeLbXeorTmD0hOLvY07T+FZxmLokzqxqMz/nGwXj4GX2RvVZp2JVOud8ulSltIXmnph28QxdB
	9EWGNGTQKCI8vtzaetV4kc+KXbYkn0vwFfL6nwQu1ft4+KK322wk//fi5zp0Ro+8NVv5loSLAOC
	eMf
X-Received: by 2002:a05:651c:304c:b0:32b:a9a4:cd3b with SMTP id
 38308e7fff4ca-32f500208b3mr296861fa.1.1752073555389; Wed, 09 Jul 2025
 08:05:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-8-glider@google.com>
In-Reply-To: <20250626134158.3385080-8-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Jul 2025 17:05:44 +0200
X-Gm-Features: Ac12FXzeQAhmBo1BEER1qVGdHBxq8SPxRNE1VAHT5W_fT8Mz44wAcz5cFMNrv3E
Message-ID: <CACT4Y+Za7vRTQ6M6kKs-+4N4+D6q05OKf422LZCMBBy-k4Cqqw@mail.gmail.com>
Subject: Re: [PATCH v2 07/11] kcov: add trace and trace_size to struct kcov_state
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=B5s0PTLk;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> wrote:
>
> Keep kcov_state.area as the pointer to the memory buffer used by
> kcov and shared with the userspace. Store the pointer to the trace
> (part of the buffer holding sequential events) separately, as we will
> be splitting that buffer in multiple parts.
> No functional changes so far.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
>
> ---
> Change-Id: I50b5589ef0e0b6726aa0579334093c648f76790a
>
> v2:
>  - Address comments by Dmitry Vyukov:
>    - tweak commit description
>  - Address comments by Marco Elver:
>    - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
>  - Update code to match the new description of struct kcov_state
> ---
>  include/linux/kcov_types.h |  9 ++++++-
>  kernel/kcov.c              | 54 ++++++++++++++++++++++----------------
>  2 files changed, 39 insertions(+), 24 deletions(-)
>
> diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
> index 53b25b6f0addd..233e7a682654b 100644
> --- a/include/linux/kcov_types.h
> +++ b/include/linux/kcov_types.h
> @@ -7,9 +7,16 @@
>  struct kcov_state {
>         /* Size of the area (in long's). */
>         unsigned int size;
> +       /*
> +        * Pointer to user-provided memory used by kcov. This memory may

s/kcov/KCOV/ for consistency

> +        * contain multiple buffers.
> +        */
> +       void *area;
>
> +       /* Size of the trace (in long's). */
> +       unsigned int trace_size;
>         /* Buffer for coverage collection, shared with the userspace. */
> -       void *area;
> +       unsigned long *trace;
>
>         /*
>          * KCOV sequence number: incremented each time kcov is reenabled, used
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 8e98ca8d52743..038261145cf93 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -195,11 +195,11 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
>         return ip;
>  }
>
> -static notrace void kcov_append_to_buffer(unsigned long *area, int size,
> +static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
>                                           unsigned long ip)
>  {
>         /* The first 64-bit word is the number of subsequent PCs. */
> -       unsigned long pos = READ_ONCE(area[0]) + 1;
> +       unsigned long pos = READ_ONCE(trace[0]) + 1;
>
>         if (likely(pos < size)) {
>                 /*
> @@ -209,9 +209,9 @@ static notrace void kcov_append_to_buffer(unsigned long *area, int size,
>                  * overitten by the recursive __sanitizer_cov_trace_pc().
>                  * Update pos before writing pc to avoid such interleaving.
>                  */
> -               WRITE_ONCE(area[0], pos);
> +               WRITE_ONCE(trace[0], pos);
>                 barrier();
> -               area[pos] = ip;
> +               trace[pos] = ip;
>         }
>  }
>
> @@ -225,8 +225,8 @@ void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
>                 return;
>
> -       kcov_append_to_buffer(current->kcov_state.area,
> -                             current->kcov_state.size,
> +       kcov_append_to_buffer(current->kcov_state.trace,
> +                             current->kcov_state.trace_size,
>                               canonicalize_ip(_RET_IP_));
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
> @@ -242,8 +242,8 @@ void notrace __sanitizer_cov_trace_pc(void)
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
>                 return;
>
> -       kcov_append_to_buffer(current->kcov_state.area,
> -                             current->kcov_state.size,
> +       kcov_append_to_buffer(current->kcov_state.trace,
> +                             current->kcov_state.trace_size,
>                               canonicalize_ip(_RET_IP_));
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> @@ -252,9 +252,9 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
>  static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>  {
> -       struct task_struct *t;
> -       u64 *area;
>         u64 count, start_index, end_pos, max_pos;
> +       struct task_struct *t;
> +       u64 *trace;
>
>         t = current;
>         if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
> @@ -266,22 +266,22 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>          * We write all comparison arguments and types as u64.
>          * The buffer was allocated for t->kcov_state.size unsigned longs.
>          */
> -       area = (u64 *)t->kcov_state.area;
> +       trace = (u64 *)t->kcov_state.trace;
>         max_pos = t->kcov_state.size * sizeof(unsigned long);
>
> -       count = READ_ONCE(area[0]);
> +       count = READ_ONCE(trace[0]);
>
>         /* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
>         start_index = 1 + count * KCOV_WORDS_PER_CMP;
>         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
>         if (likely(end_pos <= max_pos)) {
>                 /* See comment in kcov_append_to_buffer(). */
> -               WRITE_ONCE(area[0], count + 1);
> +               WRITE_ONCE(trace[0], count + 1);
>                 barrier();
> -               area[start_index] = type;
> -               area[start_index + 1] = arg1;
> -               area[start_index + 2] = arg2;
> -               area[start_index + 3] = ip;
> +               trace[start_index] = type;
> +               trace[start_index + 1] = arg1;
> +               trace[start_index + 2] = arg2;
> +               trace[start_index + 3] = ip;
>         }
>  }
>
> @@ -382,11 +382,13 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
>
>  static void kcov_stop(struct task_struct *t)
>  {
> +       int saved_sequence = t->kcov_state.sequence;
> +
>         WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
>         barrier();
>         t->kcov = NULL;
> -       t->kcov_state.size = 0;
> -       t->kcov_state.area = NULL;
> +       t->kcov_state = (typeof(t->kcov_state)){ 0 };

In a previous patch you used the following syntax, let's stick to one
of these forms:

data->saved_state = (struct kcov_state){};


> +       t->kcov_state.sequence = saved_sequence;
>  }
>
>  static void kcov_task_reset(struct task_struct *t)
> @@ -736,6 +738,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>                 }
>                 kcov->state.area = area;
>                 kcov->state.size = size;
> +               kcov->state.trace = area;
> +               kcov->state.trace_size = size;
>                 kcov->mode = KCOV_MODE_INIT;
>                 spin_unlock_irqrestore(&kcov->lock, flags);
>                 return 0;
> @@ -928,10 +932,12 @@ void kcov_remote_start(u64 handle)
>                 local_lock_irqsave(&kcov_percpu_data.lock, flags);
>         }
>
> -       /* Reset coverage size. */
> -       *(u64 *)area = 0;
>         state.area = area;
>         state.size = size;
> +       state.trace = area;
> +       state.trace_size = size;
> +       /* Reset coverage size. */
> +       state.trace[0] = 0;
>
>         if (in_serving_softirq()) {
>                 kcov_remote_softirq_start(t);
> @@ -1004,8 +1010,8 @@ void kcov_remote_stop(void)
>         struct task_struct *t = current;
>         struct kcov *kcov;
>         unsigned int mode;
> -       void *area;
> -       unsigned int size;
> +       void *area, *trace;
> +       unsigned int size, trace_size;
>         int sequence;
>         unsigned long flags;
>
> @@ -1037,6 +1043,8 @@ void kcov_remote_stop(void)
>         kcov = t->kcov;
>         area = t->kcov_state.area;
>         size = t->kcov_state.size;
> +       trace = t->kcov_state.trace;
> +       trace_size = t->kcov_state.trace_size;
>         sequence = t->kcov_state.sequence;
>
>         kcov_stop(t);
> --
> 2.50.0.727.gbf7dc18ff4-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZa7vRTQ6M6kKs-%2B4N4%2BD6q05OKf422LZCMBBy-k4Cqqw%40mail.gmail.com.
