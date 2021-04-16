Return-Path: <kasan-dev+bncBCMIZB7QWENRBBM44WBQMGQEWNVVTHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AE8E361BA9
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 10:42:46 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id n13sf5345146ybp.14
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 01:42:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618562565; cv=pass;
        d=google.com; s=arc-20160816;
        b=dF8GALBhzlnRwfCrAXYdz17eJVkxD2qCY/NqU6Y2W6sux+QdXfbzq3wY0WZs29XWHv
         8zCoSP89czewrWDJhaFxJ5eZ+2y7Yo28Eb28fZ6WexySe7pZ4hN0J9epY0rMvPI9icpI
         rMCbbf4xrv1rOwg/HGWM5qmtHZNveI3OsbFZ9Fz8ckCUE5gOgFasCzr/1ojrH9oHWJkB
         aB8pauKFboIF/lR1aMYe7/PQCQJ1XXT1LIbPO2+CA5kQLS7KUKXbiTY5rlc6EL8clCWC
         syzA5QGWAkDhb9ihc8tVoxH90FlOPL9xUHKF9t7mcBum72U1lwy1T5p2DF5jC179BHMX
         geSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R03O0MpwqhOOgV0610rplhihESjlqyZ137t38wkTFgg=;
        b=f5ks9t3NQeHnfwoXBo7m8bUnYQFUdt/Zq/wMNZnVAmrYqqCmag19nR4Wi7rfFoQkrJ
         igoTn7bFtHBwx99Leo1alDszqMomhspr0Gu8x/q/eW7i9cFXBBb3TE6N8Bu4UpvUb3NZ
         TfPZ5CgwVAWb82YUIufJT/92p+OLNnfhkuF2fFSgrp13aTSoIDTn1Xc9ds7Ffg3sTZaX
         T9dhE97TrM63iUomgHgQbdOPZOACWCaiyt8jtO0qItA+6SmpU+TqhDhTu2CI8kqoKj7I
         NCJcVzZ21Leb+6Ylb/9SaSN3QZraamHCyUoxqjpgrhT7u0oLOnz2+y3zPoUCYDyyZb02
         8Kaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VAqp67df;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R03O0MpwqhOOgV0610rplhihESjlqyZ137t38wkTFgg=;
        b=ftjgOKpD110UFm0v4UJ4waBA7PZdZ+xrGr4rD5VE7yetW6MMwBL16x67wJTxi8o8zQ
         xcWo6uqHdmPaTEaiIeCbwuLIh3F3/dfX1OxjqnqlOpVSXcV50Dms3Aj1d7pZNBHntAvI
         9BSRatfVi5MitGPYSr8A49/sY4qInWnWeNSH+AzKvGoUQVU5epMxHYuJWVo7UId85frj
         0F/eu6c/5GcjnUksJzH2Ezll65wCBFhWFkPAYrFOCvHKuV2fQ3trPelxJEE84Et7p/lw
         L4gSx1/sLtykYyL4xgOdHxR2ytYp9Be7yreHjEWkNxA2H29uUCKPBRcu3As1+q3555Wo
         J5vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R03O0MpwqhOOgV0610rplhihESjlqyZ137t38wkTFgg=;
        b=kMUMIUzYkLRRSZYLgXrrm/k63SxU4wge38+jINRS8iq6+Wgb/xusG370yvZi6nZdML
         M8yj8Y2sZ0aBSfvxHdXBpEtdqwo2YGmnlz3Do2X//Pedfy0qAC47shDeyc5R63NdD7uC
         PNiLsltL7vYa5USf76B3VXy6mGPDmF7HQc0WI/HKOzxQgyy5B/3CVDbwaKnhNq3Xuob/
         bjfZcbTHAulUHuGblbJx8hIhT48XDKvH9RmQjiYRAhBxEtpFgJ0cFrTmQxJEET0aGTB8
         OCrQKcg2pYL0Wj5G9fpD1hqAtBYz/IwB82wc0EokSjDf6G3H43Y4esWAqxfICRIVhq4b
         PRTg==
X-Gm-Message-State: AOAM530rwjBYbqQCQxl5b/WM1htQVQQ/rWErPRdsh7BXqxkuH1GH1Jxc
	wc8eLacPsJLp3vpGNd/7yuE=
X-Google-Smtp-Source: ABdhPJw3LpGDEOlCD8JLVWQNwvy1NOkXSB55aTJ8zpr0YobsHChd9dHdEYcIsDoRR/VJRNmq5Vu8Hg==
X-Received: by 2002:a5b:5c7:: with SMTP id w7mr10439427ybp.164.1618562565303;
        Fri, 16 Apr 2021 01:42:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:1342:: with SMTP id 63ls4018747ybt.8.gmail; Fri, 16 Apr
 2021 01:42:44 -0700 (PDT)
X-Received: by 2002:a25:10c5:: with SMTP id 188mr10145262ybq.38.1618562564850;
        Fri, 16 Apr 2021 01:42:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618562564; cv=none;
        d=google.com; s=arc-20160816;
        b=atZk6yeDCfiOsZfLuuH00MKfoBJ/YBo6UwFjaNKqWQ//1EKGkhPWxjsK3BCMrkDg3s
         Io87tEri2QEeIAeY0nX9s/aMEVQz01FyUR10bNjxfbUV97qisZa7xBgvNPztyJW4WTDl
         vwjkBjxgGSKT+m37AmNhgfKugg8bqwF+V+z450lV+js8xd47/1qB1FECjwYn8Z6sGa5J
         T/ho569Ea4iHlQvn7OJ087lk5fF0CrDmVcSvHnxj2YSgXHUdMtpCf+chzSstW28FFQLC
         WV5Ez7Cun2aIt5j+Xi0b6gFi4Bvs/UcQbMC6KkWTOp7bsvFWPC55lbYLWdmfN/guhq6F
         2ZpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DNspso6eu8FyK0S12pp5SaJi4n/DElqZlTW5QhLtIS8=;
        b=XHY/m1ilW95ovmdrGBHjXizJUikZdza7OFOxEY1TFVY7RDNSYKKjO6qiNICf5H4dZC
         qCd2V1xIl7mBlP6wqr+GmWfxinoeXWK1IuifBtDFqHgGuvmK/KVzSGoKISxdujPoq6f+
         ljptGTMCb02o7wMLZk3YNZ+2HJRCFAh4GliBXh9eOLHFkvelpwOO11G/dFIrldAQ+j2C
         9uG8i8BYZl46Jxp122Jcpk0iZ4S2vdfLqu5zh/3V1T4MA0YpB13zYZRNfl6MGtvSmdF+
         9eJ5mhyk51Bsl+JsD4KlWP3fv+YoiOXjMuih5eGvJPp+MqDt7gr7xjiZIpjuoG1v44SM
         RWmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VAqp67df;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id i1si445010ybe.2.2021.04.16.01.42.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Apr 2021 01:42:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id x11so28030964qkp.11
        for <kasan-dev@googlegroups.com>; Fri, 16 Apr 2021 01:42:44 -0700 (PDT)
X-Received: by 2002:a37:a9c1:: with SMTP id s184mr537104qke.231.1618562564151;
 Fri, 16 Apr 2021 01:42:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210326205135.6098-1-info@alexander-lochmann.de> <CA+fCnZcTi=QLGC_LCdhs+fMrxkqX66kXEuM5ewOmjVjifKzUrw@mail.gmail.com>
In-Reply-To: <CA+fCnZcTi=QLGC_LCdhs+fMrxkqX66kXEuM5ewOmjVjifKzUrw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Apr 2021 10:42:32 +0200
Message-ID: <CACT4Y+Y_PfAhjV26xYf8wcEv0MYygC14c_92hBN8gqOACK7Oow@mail.gmail.com>
Subject: Re: [PATCHv3] Introduced new tracing mode KCOV_MODE_UNIQUE.
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Lochmann <info@alexander-lochmann.de>, Andrey Konovalov <andreyknvl@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Randy Dunlap <rdunlap@infradead.org>, 
	Andrew Klychkov <andrew.a.klychkov@gmail.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Jakub Kicinski <kuba@kernel.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Wei Yongjun <weiyongjun1@huawei.com>, Maciej Grochowski <maciej.grochowski@pm.me>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VAqp67df;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Sat, Mar 27, 2021 at 3:56 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Fri, Mar 26, 2021 at 9:52 PM Alexander Lochmann
> <info@alexander-lochmann.de> wrote:
> >
>
> Hi Alexander,
>
> > It simply stores the executed PCs.
> > The execution order is discarded.
> > Each bit in the shared buffer represents every fourth
> > byte of the text segment.
> > Since a call instruction on every supported
> > architecture is at least four bytes, it is safe
> > to just store every fourth byte of the text segment.
>
> What about jumps?

KCOV adds call __sanitizer_cov_trace_pc per coverage point. So besides
the instructions in the original code, we also always have this call.


> [...]
>
> > -#define KCOV_IN_CTXSW  (1 << 30)
> > +#define KCOV_IN_CTXSW  (1 << 31)
>
> This change needs to be mentioned and explained in the changelog.
>
> > -static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
> > +static __always_inline notrace bool check_kcov_mode(enum kcov_mode needed_mode,
> > +                                                   struct task_struct *t,
> > +                                                   unsigned int *mode)
> >  {
> > -       unsigned int mode;
> > -
> >         /*
> >          * We are interested in code coverage as a function of a syscall inputs,
> >          * so we ignore code executed in interrupts, unless we are in a remote
> > @@ -162,7 +163,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
> >          */
> >         if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
> >                 return false;
> > -       mode = READ_ONCE(t->kcov_mode);
> > +       *mode = READ_ONCE(t->kcov_mode);
> >         /*
> >          * There is some code that runs in interrupts but for which
> >          * in_interrupt() returns false (e.g. preempt_schedule_irq()).
> > @@ -171,7 +172,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
> >          * kcov_start().
> >          */
> >         barrier();
> > -       return mode == needed_mode;
> > +       return ((int)(*mode & (KCOV_IN_CTXSW | needed_mode))) > 0;
>
> This change needs to be mentioned and explained in the changelog.
>
> [...]
>
> >  static notrace unsigned long canonicalize_ip(unsigned long ip)
> > @@ -191,18 +192,27 @@ void notrace __sanitizer_cov_trace_pc(void)
> >         struct task_struct *t;
> >         unsigned long *area;
> >         unsigned long ip = canonicalize_ip(_RET_IP_);
> > -       unsigned long pos;
> > +       unsigned long pos, idx;
> > +       unsigned int mode;
> >
> >         t = current;
> > -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t, &mode))
> >                 return;
> >
> >         area = t->kcov_area;
> > -       /* The first 64-bit word is the number of subsequent PCs. */
> > -       pos = READ_ONCE(area[0]) + 1;
> > -       if (likely(pos < t->kcov_size)) {
> > -               area[pos] = ip;
> > -               WRITE_ONCE(area[0], pos);
> > +       if (likely(mode == KCOV_MODE_TRACE_PC)) {
> > +               /* The first 64-bit word is the number of subsequent PCs. */
> > +               pos = READ_ONCE(area[0]) + 1;
> > +               if (likely(pos < t->kcov_size)) {
> > +                       area[pos] = ip;
> > +                       WRITE_ONCE(area[0], pos);
> > +               }
> > +       } else {
> > +               idx = (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
> > +               pos = idx % BITS_PER_LONG;
> > +               idx /= BITS_PER_LONG;
> > +               if (likely(idx < t->kcov_size))
> > +                       WRITE_ONCE(area[idx], READ_ONCE(area[idx]) | 1L << pos);
>
> This is confusing: for KCOV_MODE_TRACE_PC, pos is used to index area,
> and for else, idx is used to index area. You should swap idx and pos.
>
> [...]
>
> > @@ -213,9 +223,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >         struct task_struct *t;
> >         u64 *area;
> >         u64 count, start_index, end_pos, max_pos;
> > +       unsigned int mode;
> >
> >         t = current;
> > -       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
> > +       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t, &mode))
> >                 return;
>
> mode isn't used here, right? No need for it then.
>
> > @@ -562,12 +576,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
> >  {
> >         struct task_struct *t;
> >         unsigned long size, unused;
> > -       int mode, i;
> > +       int mode, i, text_size, ret = 0;
> >         struct kcov_remote_arg *remote_arg;
> >         struct kcov_remote *remote;
> >         unsigned long flags;
> >
> >         switch (cmd) {
> > +       case KCOV_INIT_UNIQUE:
> > +               fallthrough;
> >         case KCOV_INIT_TRACE:
> >                 /*
> >                  * Enable kcov in trace mode and setup buffer size.
> > @@ -581,11 +597,42 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
> >                  * that must not overflow.
> >                  */
> >                 size = arg;
> > -               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> > -                       return -EINVAL;
> > -               kcov->size = size;
> > -               kcov->mode = KCOV_MODE_INIT;
> > -               return 0;
> > +               if (cmd == KCOV_INIT_UNIQUE) {
>
> Let's put this code under KCOV_INIT_UNIQUE in the switch. This
> internal if only saves duplicating two lines of code, which isn't
> worth it.
>
> > +                       if (size != 0)
> > +                               return -EINVAL;
> > +                       text_size = (canonicalize_ip((unsigned long)&_etext)
> > +                                    - canonicalize_ip((unsigned long)&_stext));
> > +                       /**
> > +                        * A call instr is at least four bytes on every supported architecture.
> > +                        * Hence, just every fourth instruction can potentially be a call.
> > +                        */
> > +                       text_size = roundup(text_size, 4);
> > +                       text_size /= 4;
> > +                       /*
> > +                        * Round up size of text segment to multiple of BITS_PER_LONG.
> > +                        * Otherwise, we cannot track
> > +                        * the last (text_size % BITS_PER_LONG) addresses.
> > +                        */
> > +                       text_size = roundup(text_size, BITS_PER_LONG);
> > +                       /* Get the amount of bytes needed */
> > +                       text_size = text_size / 8;
> > +                       /* mmap() requires size to be a multiple of PAGE_SIZE */
> > +                       text_size = roundup(text_size, PAGE_SIZE);
> > +                       /* Get the cover size (= amount of bytes stored) */
> > +                       ret = text_size;
> > +                       kcov->size = text_size / sizeof(unsigned long);
> > +                       kcov_debug("text size = 0x%lx, roundup = 0x%x, kcov->size = 0x%x\n",
> > +                                       ((unsigned long)&_etext) - ((unsigned long)&_stext),
> > +                                       text_size,
> > +                                       kcov->size);
> > +                       kcov->mode = KCOV_MODE_INIT_UNIQUE;
> > +               } else {
> > +                       if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> > +                               return -EINVAL;
> > +                       kcov->size = size;
> > +                       kcov->mode = KCOV_MODE_INIT_TRACE;
> > +               }
> > +               return ret;
>
> Thanks!
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcTi%3DQLGC_LCdhs%2BfMrxkqX66kXEuM5ewOmjVjifKzUrw%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY_PfAhjV26xYf8wcEv0MYygC14c_92hBN8gqOACK7Oow%40mail.gmail.com.
