Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3V6SKKAMGQEGXS4HHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 302A852B330
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 09:25:36 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id r206-20020a2576d7000000b0064d82e5b692sf1155192ybc.11
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 00:25:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652858735; cv=pass;
        d=google.com; s=arc-20160816;
        b=gousVrjur8m3BUGulfXlhZA1XshJbxmNN8pKSARKd+/Hi60+u1zuZWaxkMR4FS8+F1
         eWznnBd08ZJjPfcszE6pxpM6ZKB+v7ngxjnBwznhlFRg7k9GsRMqg8I7YcnwryLGUOQV
         bEHQbh6K5kVhr6pPBOHqvPYYrn2zYl9JFEVcz+F+m01Wov7VksD2q9JIwkrS4dQRbNpr
         WJGFnpgMK/cO1FvbLPpSDOVQ4pu6W+GOwKGsHtoWBZVs2TFE5sqWHKwov0Zjd3knuHYM
         7NA6kLQRCqQFMyAQIob1HjzHxNmLjoYhPtJFRp3o2HuA61JGLt+q1/C/hZjCVy2cmcPt
         v6oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=J/unwTaDs9LSVCG58cCVKYf45tyahJKUt875pl84+Ds=;
        b=i9ehq4tZiFxJAy/tCr930ErZl9gfjh8Do4pYDINS/f3AMQ/Y37OFr67UI08RucHC9f
         ssaB09HmjMG8C85Jl/YGK0CzaGqloFV78rnCPpfOk0AbJWYmGAIHzIEh6we3eDQIPHoG
         kiMGXCx/SSL2kas4VJ1+cZhWq1kmyc8OUNhO5PpXv4ZUOf5sgCPzCD2y1J5J44XZXkKk
         znI5oNLMyixBJr7n7UddqPKL/+ruyRUnnKjtLVrG64hLWsbz85nocMz76UzxQXT5Iqow
         OY0fgHhVrryVT/dHrPbVaejTFBli+HybnwNRc3OP/uzcvCVUrfxhBjA7SuiEMXmVjJfr
         fbgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eVrGmjEL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J/unwTaDs9LSVCG58cCVKYf45tyahJKUt875pl84+Ds=;
        b=lltdonnm92ZcWwAQ+JDfi7rfE87C6mCtsiYS2AgP7is3mu6JAwmhKorexIHi76Xg+/
         nLluX2ebJjilOupdpoCUM/k/z2m0i8r8pRvlxWHLmL1CesK+P4hx1ieSAJiwTAXhQ7FY
         nHf3OTlma4qsCowUtz6ku5XkpofwqTZOyDrJU/X0+pWB13dRSl/z8lYBHRtHA3YpdkK0
         DserURLCKxMRqis7XupaGqoa3GCaSeO35jvH3oFkptCJ1INbV1h2lv5vwVGbzG0hsGuz
         dd/ShWuCQYT0ECUybiUVlyuABr9em149eUn7SNopcx8l6oKS5+lu9olhfRYKJ4hqsDBF
         xUnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J/unwTaDs9LSVCG58cCVKYf45tyahJKUt875pl84+Ds=;
        b=hS6ohTKPluAwSmpU0BtNs0sk5eFI/09DEArnja+wizyi8SUAah6NGWmFnXB5DXL4jp
         lxQuMht7vuFyOlc9SNL+NJFIQOJ8WA0cLTCevk8Exi20tyYRasw51vDO5Sv/lTQGHIHm
         CVBiWKYGsNuHcgN0nlwmD/iX1fuEeEKJkYOx7CgfQ/jj/brEGDycajt6gJLvCWhVvoE0
         1+iXcFg8HpRN3k8nSsqtK6l6sFsiImyGLLjnHV6almm87fgkPDt8xfMI00E7wiVJyKMq
         SZbqsMfI9KL1iILd/rLBXDrcge//5Le/98Umlnc8ETuh/YL95cvHWcCku4XdThWYmMMn
         pyeA==
X-Gm-Message-State: AOAM533JMJax+oCWkQOzBkTy7YA2NEHOWZH9zkm8vb+oatpzd89Y/X3J
	tLkVt7+atyeNq0GocHJFIhg=
X-Google-Smtp-Source: ABdhPJwvlGk1bMgwGmRQHMPaDjlDzqNfD9Qiqvd7Txlj2Vbm73Ygb+UijLPRFz4gjykhqPvg+5kUyA==
X-Received: by 2002:a25:ab05:0:b0:64d:bc6d:b06d with SMTP id u5-20020a25ab05000000b0064dbc6db06dmr11742252ybi.76.1652858735074;
        Wed, 18 May 2022 00:25:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4409:0:b0:64d:efa3:4f55 with SMTP id r9-20020a254409000000b0064defa34f55ls3166080yba.9.gmail;
 Wed, 18 May 2022 00:25:34 -0700 (PDT)
X-Received: by 2002:a25:2483:0:b0:64e:2389:424b with SMTP id k125-20020a252483000000b0064e2389424bmr1823907ybk.521.1652858734395;
        Wed, 18 May 2022 00:25:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652858734; cv=none;
        d=google.com; s=arc-20160816;
        b=UW2HiBVoG6bftvH0OETth2rOjK2icmcN036DwqzsQpxSRmc9a4cYSUWK+CnXvjPEwE
         bQC+Rlo5FafKfa8l4oXGQIGidT9ogS0KJRGh8mBrwSsl2wQclvW+K+ABYwrIMAx9D3U1
         qXxo3XeoK4x7PkOpuwhY7ygL5nRc/XX1kAe3OOlA6wkTvL+2JtqazYTgSNqH4A3ThrmE
         1cMTVi0keB42cPz2bAh2nnPay+2NZydkEKsfj9PyJjV6DLpvCMHSgDPx1typaekWhqAZ
         tYiVb99CPlYmChxja/QMwBsnaXGcaKXVFVYUeoicIrF7GD/wGly2MBH3O5utFGmTaxWf
         3D/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2qE8WnR47trg0BtZ98Z7WOsDD1VTZmk3mutfVHzqGE8=;
        b=UB9+1A7LasmdMAZORWSmACDMe+Xtqg7G/5Tyv5qKxZQr4fOhflcpFwxFF7oay1v2Qq
         1HPHeVsdXO3vl5AZ1rBTwzX4oVe9xeFZyenJKI1iDZfbrEFtJfIjl/AGHN0Oqmeq+YXx
         xzV/B2ls0V7lSfGjxOx/OXLy8I8AsaGmAm0mJyCLFAZbFS4Ubf3dNneQwHIXMiTv/5VH
         2awy6nyFGcyQXmUm862kE12yrL4sGcTRKxgQdfHJK8X7v7t8VKatjz4U4/lhe3cvhzum
         2iGRcN47UeIKuOxIHJ2XOuGL/4o3bLlzyL7NhsKdzm5ewhCNBSYxMsGX2Ne0jt+95L6m
         8RmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eVrGmjEL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id i12-20020a056902128c00b00634581eb904si81176ybu.2.2022.05.18.00.25.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 00:25:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id o80so2250197ybg.1
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 00:25:34 -0700 (PDT)
X-Received: by 2002:a5b:691:0:b0:64d:ab44:f12e with SMTP id
 j17-20020a5b0691000000b0064dab44f12emr13404828ybq.533.1652858733954; Wed, 18
 May 2022 00:25:33 -0700 (PDT)
MIME-Version: 1.0
References: <20220518010319.4161482-1-liu.yun@linux.dev>
In-Reply-To: <20220518010319.4161482-1-liu.yun@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 May 2022 09:24:57 +0200
Message-ID: <CANpmjNMSnvKVYOwof1WSxVX+qRsKUK3QPjPuWk5KdNjwMkEfPQ@mail.gmail.com>
Subject: Re: [PATCH v3] mm/kfence: print disabling or re-enabling message
To: Jackie Liu <liu.yun@linux.dev>
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eVrGmjEL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Wed, 18 May 2022 at 03:03, Jackie Liu <liu.yun@linux.dev> wrote:
>
> From: Jackie Liu <liuyun01@kylinos.cn>
>
> By printing information, we can friendly prompt the status change
> information of kfence by dmesg and record by syslog.
>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>
> ---
>  v1->v2:
>    fixup by Marco Elver <elver@google.com>
>  v2->v3:
>    write kfence_enabled=false only true before
>
>  mm/kfence/core.c | 10 ++++++++--
>  1 file changed, 8 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 11a954763be9..41840b8d9cb3 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -67,8 +67,13 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
>         if (ret < 0)
>                 return ret;
>
> -       if (!num) /* Using 0 to indicate KFENCE is disabled. */
> -               WRITE_ONCE(kfence_enabled, false);
> +       /* Using 0 to indicate KFENCE is disabled. */
> +       if (!num) {
> +               if (READ_ONCE(kfence_enabled)) {

Now you could just write

  if (!num && READ_ONCE(kfence_enabled)) {
    ....

> +                       pr_info("disabled\n");
> +                       WRITE_ONCE(kfence_enabled, false);
> +               }
> +       }
>
>         *((unsigned long *)kp->arg) = num;
>
> @@ -874,6 +879,7 @@ static int kfence_enable_late(void)
>
>         WRITE_ONCE(kfence_enabled, true);
>         queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> +       pr_info("re-enabled\n");
>         return 0;
>  }
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMSnvKVYOwof1WSxVX%2BqRsKUK3QPjPuWk5KdNjwMkEfPQ%40mail.gmail.com.
