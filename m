Return-Path: <kasan-dev+bncBDW2JDUY5AORBK4P7WBAMGQEYWA7WEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 62F2A34B7D1
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Mar 2021 15:56:43 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id v13sf5908239wrs.21
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Mar 2021 07:56:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616857003; cv=pass;
        d=google.com; s=arc-20160816;
        b=jJ9B04ovzTfQucEBN6PhSjPK32GzosJaGvveX7T1B3fE2gEaDNdpm8e1Ru++T5aX/x
         IaPwy5pvxc8UwueCGB9ulk/EwOABQSMsquu7DpvcffERo23S+SkRjpXpirVV8hiKKlZh
         HoBsPKKNzXtOdhI2Oij60DUUss5NdnanZa0o0sQZF2e2cWP97PbXSFUfua7q6l14nZLk
         ajiRxW4kvilLe2qKuHvlqpbJfZTY7E0igIqDnkdZRXSX4CmBeuo7pvY60K1kQQwEgvNh
         1JnaC/W8lhjXf19Ellx7+YQwbAEkuHMvKXdsp3jl8Ho2ibiPzfpS3yL7VddC3ka9LlYZ
         PYTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ImNLOBQo9v+yLppJYy319Ot6J7IqTEmSX5SebS1ifFo=;
        b=0xQu+MejVy+SD1haivPtulKhTSveBf3q1NzhBvHeHXa/seLMNfzDtJw1rhMullMaXs
         2LwF/X5Gl155i9U4oorDlF0yF7ufay7HPSPSUetaZ5RsmKruR4VfBkqwZqj1NMluZIPE
         l0YEPqJJ8m9kHMB6iConu9YHfJOktgt1QMli++Pe6DNsjDlR5I3hJXbOiPrwPtf2eEjy
         TYhkyP7m0U3x+xdoz8aCEe9P6h0EaFwtCggVEGsZdp5kSEs+8wPoG6PtnOn90GKT+ux/
         LdBfKQ07purPZ6nzlEwCKdp0vFbbTdEJznBn/PC+L2cyuVcZDtfXh/LDwSbP68rvScnQ
         igCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=daUZHZ3f;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ImNLOBQo9v+yLppJYy319Ot6J7IqTEmSX5SebS1ifFo=;
        b=kJ4G7IaUURZ3og905QbQJ/1StOK81yL3CrgkhjnkjuRI3clr4J7gFj1XIKomHj63Yk
         WS2XGMy6ugwz4UNJNo1Rp16v3lg+6B9kJFlvsBEA6ME1nKs+3HL8i6TYm8Zx+u3eA8Ay
         6Ie5yjOdN5pT86LhRScy3C/p/ZIa98lOkKZgWYneIPJ+SrBUmfavccvuFgpi894jxP+C
         T1TkXcl4EZfZ7Wxrlebmd43Wsqm5S15FMuznV7dMwCY0F8JFhxtRRBEHCYfu+CzSsxiD
         fcNobDJ82KmXK2b0kHUBnvJCVvaSWJEl2kf1jQcyz0ev8ePQs9LBEBdH9+UuFdPXH5L6
         69+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ImNLOBQo9v+yLppJYy319Ot6J7IqTEmSX5SebS1ifFo=;
        b=Kf1pNNAkSJ3uofgdCr+866asHbNd9WHTeECRoS7vHzaB6UP4/rBZdcEcul25qbG8es
         dINFIlS9Nwx6DDc2DXrtgZG1lQdApu/tw6NOZ0xem482nLYJJ4hNL011q/hiOs3pNUyK
         OXepCvlT3zpj/AndL3GeeUXt+T6dQ1iUJI0ONEBSKblxn+V12KKXLBld8BowTAz8lPqS
         ISnnUGWqgViaf0PdzLmjpoEvUOxWz4J/VEJThtICSV3ruP56TVTTvaPsaN4bwkXqayPA
         kA0y1XzdPdBiZESN/94bFLUuS88DppBSMv732MHSW318j6UDAf8ym4PAezB/oXSnYQBD
         DOAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ImNLOBQo9v+yLppJYy319Ot6J7IqTEmSX5SebS1ifFo=;
        b=ifIdpc0sYKgwJlzmKYHtBIv7egurLYuTEdYUQBw5o8fIrhMf5KR1WKMUaSsZI4pb5Y
         Bw+lRAfdQ/fIpe8GUimyQCrKIJXfGAIiWuuhZ3towdy9U2UOGATM2rM/6Cg7vuJpf6jK
         gWgY229DItOA7rZGTVfEQsWIdKD/Zc310MoPGtKhWGF8yn2O9aGm2hdBWfvbghoTmV8G
         Gp035uY3xd5sCFp71D/QIi4zoLxAYZ53u5NwlNzowHEFSnvISTWq8iH12mjBF4ZROLgG
         C/cOffpBJXKtb+LTjQgMivO1iX/1BI3Y/lvQ09Gko6lmIZO40rUzfo/2KseDb3n7GXNH
         juGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530B2FAcupSHiguNTXWQoligGVTDXMvs11VhdUpXPgYXo9fiQ//z
	LrR8LiQY179L67itiiTGbtQ=
X-Google-Smtp-Source: ABdhPJwch0PZcGS00/mxSYkdhT6d+F5/Lj8iG5mYCle4SvCME8JcoFG4wY9hMmls6KzcqJF/Sn5Dng==
X-Received: by 2002:a05:600c:19cf:: with SMTP id u15mr17324122wmq.7.1616857003168;
        Sat, 27 Mar 2021 07:56:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c763:: with SMTP id x3ls5689132wmk.1.canary-gmail; Sat,
 27 Mar 2021 07:56:42 -0700 (PDT)
X-Received: by 2002:a05:600c:21ca:: with SMTP id x10mr17896308wmj.48.1616857002395;
        Sat, 27 Mar 2021 07:56:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616857002; cv=none;
        d=google.com; s=arc-20160816;
        b=uZIdJP4zj02R7N1jxs1gzGpAHTkq0u0ZjrK2gTasKVf6WAY4qgb/nsJcj0Yeh/ErAS
         32pB+zEEMfsMevFDkUpr7YPzo3shZJww/TLOMlK7ZheYkBWNRzBTaNdCgydFQyeF19RU
         xiHrWyKOKb/HvgUe99O7FI8NTDi3ydfkcIVh1vw+FyfTtHitRnTvHRU35aZ9e7pWDwiv
         mDETbVUv8SJvXKC16OPRN2a0uoRbHvudnw4Ez1BDXs4cxDkGexVchxvlkc67DgTkjUfe
         ifBhxgzIfqmgI3EeUlrJt4Lg2jsSoOBeiCMdgOhikk/xVkAmb7lnnOxTwZZ13jB04HNB
         SffA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9XfERiSuS0jgzL6XtH0j5Zkdj6GdS3lhay8hKtzIIvw=;
        b=h5raSOrItW5Tfoe9i0er/BqdgQTl/OCbZdDf7ek+ynEB3pbgomFp1WPUBdKmFZrnGa
         5x1ZYdpMBvRl3Zl/iAdebJUOtbmsHDBBlnp517IAJ+nYANmkz7FXOkuJPB3N6Eh8dUv/
         dlJRQuKaApmihcoOdUSZts3eJtlSv/1rXjI5UWmWXcQakhrcGLCyHqFoP8/1C/b0PzPd
         pvW5SRYM19+C3JH5V/tJVoWsRroHm8+D7wNNMJ2wB64SCQ4ekeVyyxkv1ieWBoWDOYlP
         OL1pvqGcjQA/1EWjQY88uKBZFKeocwDK8tMznLv9dqm/5YngDBTAbch1MyPlM3vR2PPK
         DDrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=daUZHZ3f;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id b5si526511wmc.2.2021.03.27.07.56.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 27 Mar 2021 07:56:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id hq27so12741892ejc.9
        for <kasan-dev@googlegroups.com>; Sat, 27 Mar 2021 07:56:42 -0700 (PDT)
X-Received: by 2002:a17:906:1fd6:: with SMTP id e22mr21088169ejt.481.1616857002134;
 Sat, 27 Mar 2021 07:56:42 -0700 (PDT)
MIME-Version: 1.0
References: <20210326205135.6098-1-info@alexander-lochmann.de>
In-Reply-To: <20210326205135.6098-1-info@alexander-lochmann.de>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 27 Mar 2021 15:56:31 +0100
Message-ID: <CA+fCnZcTi=QLGC_LCdhs+fMrxkqX66kXEuM5ewOmjVjifKzUrw@mail.gmail.com>
Subject: Re: [PATCHv3] Introduced new tracing mode KCOV_MODE_UNIQUE.
To: Alexander Lochmann <info@alexander-lochmann.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Randy Dunlap <rdunlap@infradead.org>, 
	Andrew Klychkov <andrew.a.klychkov@gmail.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Jakub Kicinski <kuba@kernel.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Wei Yongjun <weiyongjun1@huawei.com>, Maciej Grochowski <maciej.grochowski@pm.me>, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=daUZHZ3f;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Mar 26, 2021 at 9:52 PM Alexander Lochmann
<info@alexander-lochmann.de> wrote:
>

Hi Alexander,

> It simply stores the executed PCs.
> The execution order is discarded.
> Each bit in the shared buffer represents every fourth
> byte of the text segment.
> Since a call instruction on every supported
> architecture is at least four bytes, it is safe
> to just store every fourth byte of the text segment.

What about jumps?

[...]

> -#define KCOV_IN_CTXSW  (1 << 30)
> +#define KCOV_IN_CTXSW  (1 << 31)

This change needs to be mentioned and explained in the changelog.

> -static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
> +static __always_inline notrace bool check_kcov_mode(enum kcov_mode needed_mode,
> +                                                   struct task_struct *t,
> +                                                   unsigned int *mode)
>  {
> -       unsigned int mode;
> -
>         /*
>          * We are interested in code coverage as a function of a syscall inputs,
>          * so we ignore code executed in interrupts, unless we are in a remote
> @@ -162,7 +163,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>          */
>         if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
>                 return false;
> -       mode = READ_ONCE(t->kcov_mode);
> +       *mode = READ_ONCE(t->kcov_mode);
>         /*
>          * There is some code that runs in interrupts but for which
>          * in_interrupt() returns false (e.g. preempt_schedule_irq()).
> @@ -171,7 +172,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>          * kcov_start().
>          */
>         barrier();
> -       return mode == needed_mode;
> +       return ((int)(*mode & (KCOV_IN_CTXSW | needed_mode))) > 0;

This change needs to be mentioned and explained in the changelog.

[...]

>  static notrace unsigned long canonicalize_ip(unsigned long ip)
> @@ -191,18 +192,27 @@ void notrace __sanitizer_cov_trace_pc(void)
>         struct task_struct *t;
>         unsigned long *area;
>         unsigned long ip = canonicalize_ip(_RET_IP_);
> -       unsigned long pos;
> +       unsigned long pos, idx;
> +       unsigned int mode;
>
>         t = current;
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t, &mode))
>                 return;
>
>         area = t->kcov_area;
> -       /* The first 64-bit word is the number of subsequent PCs. */
> -       pos = READ_ONCE(area[0]) + 1;
> -       if (likely(pos < t->kcov_size)) {
> -               area[pos] = ip;
> -               WRITE_ONCE(area[0], pos);
> +       if (likely(mode == KCOV_MODE_TRACE_PC)) {
> +               /* The first 64-bit word is the number of subsequent PCs. */
> +               pos = READ_ONCE(area[0]) + 1;
> +               if (likely(pos < t->kcov_size)) {
> +                       area[pos] = ip;
> +                       WRITE_ONCE(area[0], pos);
> +               }
> +       } else {
> +               idx = (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
> +               pos = idx % BITS_PER_LONG;
> +               idx /= BITS_PER_LONG;
> +               if (likely(idx < t->kcov_size))
> +                       WRITE_ONCE(area[idx], READ_ONCE(area[idx]) | 1L << pos);

This is confusing: for KCOV_MODE_TRACE_PC, pos is used to index area,
and for else, idx is used to index area. You should swap idx and pos.

[...]

> @@ -213,9 +223,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         struct task_struct *t;
>         u64 *area;
>         u64 count, start_index, end_pos, max_pos;
> +       unsigned int mode;
>
>         t = current;
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
> +       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t, &mode))
>                 return;

mode isn't used here, right? No need for it then.

> @@ -562,12 +576,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>  {
>         struct task_struct *t;
>         unsigned long size, unused;
> -       int mode, i;
> +       int mode, i, text_size, ret = 0;
>         struct kcov_remote_arg *remote_arg;
>         struct kcov_remote *remote;
>         unsigned long flags;
>
>         switch (cmd) {
> +       case KCOV_INIT_UNIQUE:
> +               fallthrough;
>         case KCOV_INIT_TRACE:
>                 /*
>                  * Enable kcov in trace mode and setup buffer size.
> @@ -581,11 +597,42 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                  * that must not overflow.
>                  */
>                 size = arg;
> -               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> -                       return -EINVAL;
> -               kcov->size = size;
> -               kcov->mode = KCOV_MODE_INIT;
> -               return 0;
> +               if (cmd == KCOV_INIT_UNIQUE) {

Let's put this code under KCOV_INIT_UNIQUE in the switch. This
internal if only saves duplicating two lines of code, which isn't
worth it.

> +                       if (size != 0)
> +                               return -EINVAL;
> +                       text_size = (canonicalize_ip((unsigned long)&_etext)
> +                                    - canonicalize_ip((unsigned long)&_stext));
> +                       /**
> +                        * A call instr is at least four bytes on every supported architecture.
> +                        * Hence, just every fourth instruction can potentially be a call.
> +                        */
> +                       text_size = roundup(text_size, 4);
> +                       text_size /= 4;
> +                       /*
> +                        * Round up size of text segment to multiple of BITS_PER_LONG.
> +                        * Otherwise, we cannot track
> +                        * the last (text_size % BITS_PER_LONG) addresses.
> +                        */
> +                       text_size = roundup(text_size, BITS_PER_LONG);
> +                       /* Get the amount of bytes needed */
> +                       text_size = text_size / 8;
> +                       /* mmap() requires size to be a multiple of PAGE_SIZE */
> +                       text_size = roundup(text_size, PAGE_SIZE);
> +                       /* Get the cover size (= amount of bytes stored) */
> +                       ret = text_size;
> +                       kcov->size = text_size / sizeof(unsigned long);
> +                       kcov_debug("text size = 0x%lx, roundup = 0x%x, kcov->size = 0x%x\n",
> +                                       ((unsigned long)&_etext) - ((unsigned long)&_stext),
> +                                       text_size,
> +                                       kcov->size);
> +                       kcov->mode = KCOV_MODE_INIT_UNIQUE;
> +               } else {
> +                       if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> +                               return -EINVAL;
> +                       kcov->size = size;
> +                       kcov->mode = KCOV_MODE_INIT_TRACE;
> +               }
> +               return ret;

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcTi%3DQLGC_LCdhs%2BfMrxkqX66kXEuM5ewOmjVjifKzUrw%40mail.gmail.com.
