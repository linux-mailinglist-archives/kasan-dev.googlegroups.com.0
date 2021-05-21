Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYNQT2CQMGQEICILYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 03BD538C59E
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 13:24:19 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id pf14-20020a17090b1d8eb029015c31e36747sf5848170pjb.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 04:24:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621596257; cv=pass;
        d=google.com; s=arc-20160816;
        b=xXzHAR9eQe1La57GH0/lvhk6GR8av7JGhA/SBJm+3rLFKc+1v4Op+x68Lxzq+Lv0n8
         KCy1WpYVWSCgMeIRE0CjoluKfIA/ijMZhlFvggbAYHx7C+LP0j0vQjQaaLoJSPophyeE
         /zzcWC/qiidVZheEsD8jmi5K1RWRl+aIRSa8VhYnXKNmmj02InpPY3yYurNxCv6Mq61A
         TnNOtFGeaewYn6EiWAZxZvM5hR2bCBA9SH24nU6CvN/w/efYfZHK7xLRfgKFTqOqDwgO
         hQuyuifnA1LAACDbRktppixYgmYnsuXtGj3vsGFPxZe2mFiaAbPaCobO3aCQuPxPuvqh
         5Pfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fJL5idd4jChjIX32e//59IMetHT26inVjdHz2HrNLKA=;
        b=StJiOS0dSVnKZzaZI0QJgOdOg857fSS0kbfD1p0LIxVd5AH21iiDTytkgcJcNf/O7v
         Dc9JQV1cbPq0ZHwWypN2Z6SFaWvPg5sAyWYY0sA5Gfpk9iaYghlJakHtkMVQVwvV3aln
         4uhHHxARi4Qrl7HI+CGJYD68lNzmvwh4jbIZZoLtR4tVjfFem8HZ/2K2WEa+MSg+/Cg4
         mUf8KHsm514XWCgic0Rox5qttofGOodWDPsLJE8rU9itfes6pd5SXhwXtxGJQySiNHt4
         GhkoJWI3SxULbkolCtqrOMaofSkpKKr8wmdB1hRhxZDPpp19UfKdDzkfGaB/NrxNbLMa
         2RPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CH9kJ8AD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fJL5idd4jChjIX32e//59IMetHT26inVjdHz2HrNLKA=;
        b=fdYUpFBK/lhy/IbbG7ecPtHn+eA+BW2oqksq0fkAn/maXkJNdp066vvNC4zx+rWzcl
         d/hqTPp0wiXxbx5kQKvehEFJ8cZHiz+sLJNr0vIFN5L0w1qDtPnRMdajagKZ5QavnXNL
         GUqJDsiy/tv2GZxveR03F6Lw1ytIdbDUmhLFGaAZW7Sonc0vUk8LU3s0J4hpRHKANDAo
         MwmSzG66SGyHnBoBc8k5HYE2SceyJ7mUNZLw0n5CLZgJSE1WcCDIEt//Tmv6Zs3pJIVy
         aKmlhUlLajflvthYhQ1+cjS0q9SV2QQ6auimNrnmv9Dpngx2tFnhJFy9QZ8kF726ihlQ
         Z4mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fJL5idd4jChjIX32e//59IMetHT26inVjdHz2HrNLKA=;
        b=lwwXl6413+EzHdarmA+4MOOLY4bW6qoIJphqnXEZ5Lo7t/kyG3WKHu/R4jv/s8PD43
         th3uRCrIsqID3RNcCNXbut9A1scxne1bG2uj2YsLM9Ny5oCaUIfy7l85ThrQQvSlINU6
         FtcpTpisuwJ/kFCtAQuWAp5ulIw0FsEbxHXnFBi/E029NyESonXlKS5vYHdFm2U0FJdi
         YddpfKq5h3T7N7zykadQdhv4Bp23+5XdrTKZC7cWJLbPinJzGajPNFtlfGydUVq5b5Nh
         eSqOh8j0AbFkOvv9s0/Ma6mZk2XwV8vykO8aszj9voWfxpBtq3brPPorFichpskv6i2o
         1Rpw==
X-Gm-Message-State: AOAM5306qOfyUcBdBgrk+EDZ3OxI7gf50cd5Vxv1heGOwhU2Y2ddUOOv
	4dGNBUpkqj56U+PyPLch7J4=
X-Google-Smtp-Source: ABdhPJxNSDQGZVdsJLVHLWpZrXcsnlkKiKGtILqGZ1p6WNSa1cLXp3Qy0Q4XD5l5VFsZqhLpq9PJLw==
X-Received: by 2002:a17:902:a40e:b029:e9:7253:8198 with SMTP id p14-20020a170902a40eb02900e972538198mr11621903plq.82.1621596257718;
        Fri, 21 May 2021 04:24:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:314b:: with SMTP id x72ls2936290pgx.0.gmail; Fri, 21 May
 2021 04:24:17 -0700 (PDT)
X-Received: by 2002:a63:652:: with SMTP id 79mr9608236pgg.293.1621596257188;
        Fri, 21 May 2021 04:24:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621596257; cv=none;
        d=google.com; s=arc-20160816;
        b=JhIHYFGEiI2Y+G/cnpIO1J+rLtFxf2QhaReR6d9utRnA86AtQxzTEd/i2a6L2hLpN4
         051awV5AoZPs6AFngbayejtxmbtBKSu2MDrEaQzQXphoF7awyf1G9PFFqOwe9mYapRiO
         BthdSfQC6bpt6AZ8qYD8CEFCUJ+6UyhNao/TCgP/y1rwLh2wUCjZZQ05ul/nM2OchsAC
         Bmd0QFuJEHXRSWeMiQL6kkjGi3n3v3+YOhwaak4Il8NhMJc/dcjkOMLntkPY+nnQHM0M
         OvSVpUNg0RCovrTFJ93Ub1Ky78Arq1GEwcHmFczD/jOIqB6hgEL4/2sbEAN88B6g/Hrk
         sq5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UkWBXwz4jU1wfeZPH0TcLgdabL7pumSujVwmqN5JMTI=;
        b=nq1GtvmpiOMzwdEJ9gx5IlhEPDX5lZfsLSPB3PzA06RmkvR8ITFTVzpzeGtdmmGjnr
         IFkZ110SITsGRPt3scH/oLMw6uC372P7LR3W2EirWuENMS0hMuLGuT1kzk80DRDkq0o/
         XLfx83j2Fg7+/pVQBRPp1qKWjNq2eDMbZtMqG4IhkwWHUYXUrQrVY4pc75QxrVUZNrNp
         0Z/aha9QZbebTTxKaootPOHHHAsjAsJzQdkuwVqXyJs1Qeyv1yUyK0XM9CWOmFT/qdlo
         Pa37mRbopgl7suv/IrTEx9nNC4sQLw8R9uaczABwrC/2Gco4vKH4gQi75K6NaLesN722
         mdAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CH9kJ8AD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id p50si673392pfw.4.2021.05.21.04.24.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 May 2021 04:24:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id v8so19339837qkv.1
        for <kasan-dev@googlegroups.com>; Fri, 21 May 2021 04:24:17 -0700 (PDT)
X-Received: by 2002:a37:b643:: with SMTP id g64mr11995439qkf.6.1621596256143;
 Fri, 21 May 2021 04:24:16 -0700 (PDT)
MIME-Version: 1.0
References: <20210521111630.472579-1-elver@google.com>
In-Reply-To: <20210521111630.472579-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 May 2021 13:23:39 +0200
Message-ID: <CAG_fn=UshTFy23PvM7_4ZVtdMCmfFTB47=LxEgkzgF0rHHK3-g@mail.gmail.com>
Subject: Re: [PATCH] kfence: unconditionally use unbound work queue
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Hillf Danton <hdanton@sina.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CH9kJ8AD;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, May 21, 2021 at 1:16 PM Marco Elver <elver@google.com> wrote:
>
> Unconditionally use unbound work queue, and not just if
> wq_power_efficient is true. Because if the system is idle, KFENCE may
> wait, and by being run on the unbound work queue, we permit the
> scheduler to make better scheduling decisions and not require pinning
> KFENCE to the same CPU upon waking up.
>
> Fixes: 36f0b35d0894 ("kfence: use power-efficient work queue to run delay=
ed work")
> Reported-by: Hillf Danton <hdanton@sina.com>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kfence/core.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4d21ac44d5d3..d7666ace9d2e 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -636,7 +636,7 @@ static void toggle_allocation_gate(struct work_struct=
 *work)
>         /* Disable static key and reset timer. */
>         static_branch_disable(&kfence_allocation_key);
>  #endif
> -       queue_delayed_work(system_power_efficient_wq, &kfence_timer,
> +       queue_delayed_work(system_unbound_wq, &kfence_timer,
>                            msecs_to_jiffies(kfence_sample_interval));
>  }
>  static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
> @@ -666,7 +666,7 @@ void __init kfence_init(void)
>         }
>
>         WRITE_ONCE(kfence_enabled, true);
> -       queue_delayed_work(system_power_efficient_wq, &kfence_timer, 0);
> +       queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
>         pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%=
p\n", KFENCE_POOL_SIZE,
>                 CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
>                 (void *)(__kfence_pool + KFENCE_POOL_SIZE));
> --
> 2.31.1.818.g46aad6cb9e-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUshTFy23PvM7_4ZVtdMCmfFTB47%3DLxEgkzgF0rHHK3-g%40mail.gm=
ail.com.
