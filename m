Return-Path: <kasan-dev+bncBCMIZB7QWENRBGXKSKPQMGQEP2JVQUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 21D0A690291
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 09:55:55 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id t20-20020adfba54000000b002be0eb97f4fsf229713wrg.8
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 00:55:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675932954; cv=pass;
        d=google.com; s=arc-20160816;
        b=U8Bq5AH3nIGqzWOsbgmaywThYHJR5tDP0PDPtl2h9mPdUZOZIMHvYg8JLhA1eBsOEb
         Yx5Gdj61PISFsWKWtCfv/TD7quiXfx8Fm3nY79nkYgAkpt0zS0WqgU6JF3w4M77MzysM
         9nWszvPevnefhWgIzOiRh90gNYpBpygNw9RPE7PXUUtk2RojoTfw01nxEE/sPx+6Zqsa
         iMDEQyLISSvUaq06RL59c0590es6r4XWDdM8rQshCcL9YoGa6WovKjKk13b/6rBVmyZn
         QbOklhjShNphh/jhF5jaPlXNvna/U4xpf4N2K5ksHwipjZ3txDGdXjRxsyGXwurvqTus
         bFbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=s2n5B0lskMn6TjONDLyl9S/cAwctVpQt7yH92M7vzF4=;
        b=dYM6NgMuJ1Xtzdnj2mDHznZUlh2/a0qY43S38XHxCiQG0ImCJkreJJhVbXnbZFrkTF
         iA+YewkGtSNpGSBTxPemtQ3LJv3SvooCzgVaaUh2VZIXVLxxGCDtTqvtCzGzO42NaxQ5
         xwXRFwF1d9oxilHYWLoO32jSV01AXdZcRevIV8/hn88jGAmOMkQQJIV7F8JZeL3VYYfz
         Dnt+q/RFiIeabi9Ojw4Gpl9C6wPEfgvl5DbQI8du9L7xze7cDqOgvKtnVwe0sAot6U8e
         7wvo4pBXUJ6vcLxS9zgTkV14YWheFlLXEneV6nV6hyFeDxFQ/LJFW7NIwbH/oHIeCoUz
         p+sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EwK6fYrk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s2n5B0lskMn6TjONDLyl9S/cAwctVpQt7yH92M7vzF4=;
        b=gMtpsfu7w8ugpYyR9tZpvSwWk06v6VK8qdPcUWws9A3U/p9nmqnGxCF78L/2bKpawz
         +CTnweUtd2LHJmd27ylMOOgtaWo6X6XEI6KgffhDPJMHBa7CQfbWezXBVF2ZvKf3Wkb/
         jYgEpkxFjOtVUBys30e4NLtDWCmScWSQNwuAGT+ZfYL/Su1J8Q6x+NdpR9CGY0MxB3vz
         duY5G5TStqVI4e8UW3j8AFtMrRIASn1DtVayi4ujuf1hmo2msz5NUSQvT4pMMOcmcnMS
         6lUCWnQoS89jDKUPR5ZdZnGDV+vrFpReFxpn8ioDjJ3iRM45d/3hIo2wRoAveqw01WwV
         NlIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=s2n5B0lskMn6TjONDLyl9S/cAwctVpQt7yH92M7vzF4=;
        b=ILGMMaB/9RFOwcJuWYTnUhoM8Wh54ec+Bo7UmK744twxXMmYoQ/ewRDR3MfYHMvqM5
         q0CpRXCLRlkCYOkVYOL5cVkys5ZsawKdMxenT9MKMGpqotMJn34748M9rPaUJkg+z0WH
         Q+6Ht/AUYAOrOA0dfcK1TJ5LbkdhzYi1zwz7rkM0JeVzyso5c9MaVzpk00L8q0QjiXzB
         YjajG+C2uynNp3KQ+m1JH1+U5AKUf7Vic7avT3XTg1baSf/VfqUTR2loMSg+H0yeZ4LU
         oFi4LZLLqBZs/CS4AcU6KTfL904QxTXAm1se40xf+MXJ3vZPxqApD/1K70/2b4Oy7hDE
         rogQ==
X-Gm-Message-State: AO0yUKVPRQpKQFjyq05xJ/t67h6CyLbgmKnBX2pBiYNl+QMRabdDImUd
	7/FIgArsUJN1r7X5QOsAtJY=
X-Google-Smtp-Source: AK7set8f6NPaaHHF2gLd47u4cFr2BuP9I8+4y6G0EuuboReurwXFOilc0fipaOxQOJxhgIS69UUAlQ==
X-Received: by 2002:a7b:c004:0:b0:3d2:3e2a:d377 with SMTP id c4-20020a7bc004000000b003d23e2ad377mr483194wmb.118.1675932954565;
        Thu, 09 Feb 2023 00:55:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34c4:b0:3dc:5300:3d83 with SMTP id
 d4-20020a05600c34c400b003dc53003d83ls627176wmq.0.-pod-control-gmail; Thu, 09
 Feb 2023 00:55:53 -0800 (PST)
X-Received: by 2002:a05:600c:a697:b0:3e0:1ab:cf2a with SMTP id ip23-20020a05600ca69700b003e001abcf2amr9053267wmb.39.1675932953337;
        Thu, 09 Feb 2023 00:55:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675932953; cv=none;
        d=google.com; s=arc-20160816;
        b=h3G1kA/MaMIhsoPYKJimY0gVM8SsOxGQntbOgwOcWnV0mWzFk4jBgLhxog1S5xhzwx
         xwDY4NYkJVPFrnx6C2OSp06Zfi8r8vrE98sGedBZR1BsVykQ2ql1RIQj6S2p7oq8GWP9
         /kdKwXQroOvEgUzLIxCd79nusDIQccqFpCDMNfDhiStWtkgUrC+DH6PVLzXj+MJnf8H4
         0kaDk9xzSbAF7GrS/dnnQzOKD5DSh/JRrRlrQiydz3Vy3gxf3K+11GaMev7ufRW/Q6Ti
         n2hH7DK21qq1ijJwCvovcvfQRLT0VrZLtos4DY0ojs01+evhUDnOG8eqZ++qsPzaOUNk
         LMxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j/nTYGgZ1XHRzJPT8H8qfStrWDflyDZ6TSwRAnls8wY=;
        b=FKCQDQ00QAkbW1R0o6Pq6ybq+OMEYHygsD1aTFUlEmm6gFKY9WS3bF1VJKSFYJsb/8
         cDo95fLMENRvqBHoHgeRMJfM0x6Okjf1P/gsVoPDFytaF3ApOVTF/UZ+DNPLbenAp7bs
         69eW7QeKGPh2pAdLZL0ffDIlxX5zeNiz3D1CXt9MZwRY8uoj5EJJ8m5+XZP9h129THxL
         5Xq0JFULc9rwD4GLGIealM56AiKdKQlsGK1my+xNwQUg9O8cMA6XeAZFwtUtEqYxd2H2
         mX07/2pbwTaDOojB+Vy10NY/Kob8lJFV/ugFywhpRq2jXs4fTelCZK/ZOAmRlLl79tby
         btZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EwK6fYrk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id bg10-20020a05600c3c8a00b003db0d2c3d6esi245579wmb.0.2023.02.09.00.55.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 00:55:53 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id h4so1280300lja.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 00:55:53 -0800 (PST)
X-Received: by 2002:a05:651c:2cb:b0:28b:7bae:65de with SMTP id
 f11-20020a05651c02cb00b0028b7bae65demr1615983ljo.124.1675932952903; Thu, 09
 Feb 2023 00:55:52 -0800 (PST)
MIME-Version: 1.0
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
In-Reply-To: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Feb 2023 09:55:39 +0100
Message-ID: <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
To: Weizhao Ouyang <ouyangweizhao@zeku.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Weizhao Ouyang <o451686892@gmail.com>, 
	Shuai Yuan <yuanshuai@zeku.com>, Peng Ren <renlipeng@zeku.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EwK6fYrk;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
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

On Thu, 9 Feb 2023 at 04:27, Weizhao Ouyang <ouyangweizhao@zeku.com> wrote:
>
> From: Weizhao Ouyang <o451686892@gmail.com>
>
> From: Shuai Yuan <yuanshuai@zeku.com>
>
> Calling start_report() again between start_report() and end_report()
> will result in a race issue for the report_lock. In extreme cases this
> problem arose in Kunit tests in the hardware tag-based Kasan mode.
>
> For example, when an invalid memory release problem is found,
> kasan_report_invalid_free() will print error log, but if an MTE exception
> is raised during the output log, the kasan_report() is called, resulting
> in a deadlock problem. The kasan_depth not protect it in hardware
> tag-based Kasan mode.

I think checking report_suppressed() would be cleaner and simpler than
ignoring all trylock failures. If trylock fails, it does not mean that
the current thread is holding it. We of course could do a custom lock
which stores current->tid in the lock word, but it looks effectively
equivalent to checking report_suppressed().



> Signed-off-by: Shuai Yuan <yuanshuai@zeku.com>
> Reviewed-by: Weizhao Ouyang <ouyangweizhao@zeku.com>
> Reviewed-by: Peng Ren <renlipeng@zeku.com>
> ---
> Changes in v2:
> -- remove redundant log
>
>  mm/kasan/report.c | 25 ++++++++++++++++++++-----
>  1 file changed, 20 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 22598b20c7b7..aa39aa8b1855 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -166,7 +166,7 @@ static inline void fail_non_kasan_kunit_test(void) { }
>
>  static DEFINE_SPINLOCK(report_lock);
>
> -static void start_report(unsigned long *flags, bool sync)
> +static bool start_report(unsigned long *flags, bool sync)
>  {
>         fail_non_kasan_kunit_test();
>         /* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
> @@ -175,8 +175,13 @@ static void start_report(unsigned long *flags, bool sync)
>         lockdep_off();
>         /* Make sure we don't end up in loop. */
>         kasan_disable_current();
> -       spin_lock_irqsave(&report_lock, *flags);
> +       if (!spin_trylock_irqsave(&report_lock, *flags)) {
> +               lockdep_on();
> +               kasan_enable_current();
> +               return false;
> +       }
>         pr_err("==================================================================\n");
> +       return true;
>  }
>
>  static void end_report(unsigned long *flags, void *addr)
> @@ -468,7 +473,10 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>         if (unlikely(!report_enabled()))
>                 return;
>
> -       start_report(&flags, true);
> +       if (!start_report(&flags, true)) {
> +               pr_err("%s: report ignore\n", __func__);
> +               return;
> +       }
>
>         memset(&info, 0, sizeof(info));
>         info.type = type;
> @@ -503,7 +511,11 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>                 goto out;
>         }
>
> -       start_report(&irq_flags, true);
> +       if (!start_report(&irq_flags, true)) {
> +               ret = false;
> +               pr_err("%s: report ignore\n", __func__);
> +               goto out;
> +       }
>
>         memset(&info, 0, sizeof(info));
>         info.type = KASAN_REPORT_ACCESS;
> @@ -536,7 +548,10 @@ void kasan_report_async(void)
>         if (unlikely(!report_enabled()))
>                 return;
>
> -       start_report(&flags, false);
> +       if (!start_report(&flags, false)) {
> +               pr_err("%s: report ignore\n", __func__);
> +               return;
> +       }
>         pr_err("BUG: KASAN: invalid-access\n");
>         pr_err("Asynchronous fault: no details available\n");
>         pr_err("\n");
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230209031159.2337445-1-ouyangweizhao%40zeku.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS%2BdXrA%40mail.gmail.com.
