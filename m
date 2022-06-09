Return-Path: <kasan-dev+bncBCMIZB7QWENRBYV2Q6KQMGQEB7GJFDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id E1C94544AD5
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:45:39 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id g7-20020a056402424700b0042dee9d11d0sf16814585edb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:45:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654775139; cv=pass;
        d=google.com; s=arc-20160816;
        b=YPN1ZbG83dyBnkkbQFnUqrbWfJcJ/p6WQQS+NeON6e1cjPf9W1Qx72RoPBVDc7Nrup
         c0auJq5aOgMWNHDIk9BP12HH8sAUZDqdNAbs5W7/QcRgiS5gZ14BgWPqg5yN0kbDleEF
         F+tEee3qBgoBHNTyzBRA7DZNMRwcNxbzkM5xmAtnm76FiZcmlEFnh/9hXIpN8H8wkZcg
         GrvTsieB6viJbvaZBOkkU0wZgxZM1es8Mza97NyE8qYwA0muwHW6CcGC2UAnOup/13fe
         9jgnqZ1nGMe7+RM94syFxAT+N69HocWu1JrePHYB/1E/0/hgmodPPL6HUQjQBRm0ph9k
         +CcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=t1El0aTRS8X+1nfe8DdxMCkPrY0KjdUFN0T/FAyrbOU=;
        b=D/y/YrExcDbpeJD79uaI9febbxfEidr5Zil9DTJIz2lX8Rf6Y9JJqneSJ539zn89+p
         oswx7w9C9M+R8xvjrchI8jV9qZIV6BVd/FWiZnLaQM3xlbF+YqYuV2CUV8+sUnE4d6+X
         zpXC6gvRdnD9DlmiOy4JqpDYCwNFbWUoQmwnvn3q2r6ny+WgvJ2r8UO0Ig7oKkQf1DO1
         8fecTKjPF07eSB87mJVT//veLI1b2mQoQLIw3LlHuKq2C2jJKmZXPVyPhwcTBOr5YkRa
         SfxmjCCvPbK0y2kyy7PypWYGHwRrsI88kDM1K+pw+OnE9e0vOHusx5HAK6Hb3XOl87ZW
         j4Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wn59IozK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t1El0aTRS8X+1nfe8DdxMCkPrY0KjdUFN0T/FAyrbOU=;
        b=RWtQnklPqeokU3y6b8PdrrZ0acEYvS6iAtrd6GfA/IXJpmFUkbBJF73G534hthnmq1
         OmJIQ+2ogDyLGFYXydpfhLjsuuLuoC6K2GqnEAPRSYY6E4M6gpSBcE8vdrk+abh9IJGh
         dtIAZiFTeRhOfBJ2aHC66I7lRrDb/nm0r+Mu0xS9Lj9sZdxnXK1gvpNRSrBec6or6wfP
         Rs2I9TfC1sivR8fth1x86LAANoJcLfzbvMYwpOi2vSHSkAxnGAU2OLOtbom/+n5zpvgF
         TthhX+76U4Xx/8SPglUltk1WV0CFaG85/NO3O3atD33bmsO2Fi7DR6nkZwIFun/wW8VO
         a3Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t1El0aTRS8X+1nfe8DdxMCkPrY0KjdUFN0T/FAyrbOU=;
        b=SXmMVh7uZNLnyeHDRXpLQgXz2MTwrK14Z4uFKOU8hTcBG2sg3qKzSbq3htQnS0YMyD
         Lrasp3CJtPuLudrBa772iauGypTARtn+XxIP8gXbyE+OhXpEsSs6jZTMvRou4r9iSvrK
         j2WRKmMpQpri9LT0nlxp1xJQ4BO2mkaaEdnBHydYE95YIRH4C7gUlKELbDNsc2uqO/Km
         y/tlmS9/k2Gw97+8SU6bBG8ZIKej9NV8kshniEZfDQ6SVc8SAGpayLf6rsuN8P/1KXLI
         F64qQew3HPjFOC4G8ezWD8mqrA35WSP2eKUWOgdfbby0OdSXjiFPX81ugBCRavq/yTcs
         6xYA==
X-Gm-Message-State: AOAM533pX6VgCp1J+bWWuXuw7IQnAlb/qCAfXXaFg4+d3lecmEDxBwyQ
	5Z79zVHxlsFgQ1o6G6DJxf8=
X-Google-Smtp-Source: ABdhPJw2N9MJKIbxUujsocVP9N8umpTrPSdFNU7Xwv2iHvErMqjBPBD3WrTgV6hY9uZ5306b8hBDtw==
X-Received: by 2002:a05:6402:2405:b0:431:6ef1:e2a with SMTP id t5-20020a056402240500b004316ef10e2amr20893902eda.26.1654775139015;
        Thu, 09 Jun 2022 04:45:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:97c4:b0:711:d2c2:9fa4 with SMTP id
 js4-20020a17090797c400b00711d2c29fa4ls754392ejc.9.gmail; Thu, 09 Jun 2022
 04:45:38 -0700 (PDT)
X-Received: by 2002:a17:906:7309:b0:6f5:ea1:afa with SMTP id di9-20020a170906730900b006f50ea10afamr34947088ejc.170.1654775137869;
        Thu, 09 Jun 2022 04:45:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654775137; cv=none;
        d=google.com; s=arc-20160816;
        b=SmW0toEmxtjXs+VQJ2sjBrB+eQhsm46AHUvUW8iyV1bEtBKaiMQ3K0llcOK23jfp/u
         twm6ZFObaCd8OdbpZb+hJRofsOwYwGQ9FqSVQ4XpgyRLxvAg0ygxW46xTTLLNETVtwtT
         5ZPBS5ho9uvFWX1MKa9JDUDw5LzFSlIamP8Y3f+FM2XDRiQStpD1K4QXWqmjoazNMLa4
         K2r7sN/N+BtXHB2AN2qoL563vYUEIJbyTGccTwoixh8bLoWpxzdJAiI9PeUBI3hZTEIq
         PV/i7RWbQmnJAryk6xCLbONTKjhQKRUwgt4PRRs2p+8oHVEcsu+pqM5OlE0hOFKAMZ8c
         RQUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SgEKCxAtx5GHqR+44FfrWhhi7CpRDkMPbE0Ct/xZup4=;
        b=SfgPONm159+PrI3fSkgdizzd6xpGiojGmJJBvONHF5x/NBD/gjaBhRrCadXCWQd3mc
         FNwhxe5+IdABn8BU7zG7pWy4zesF0ygWR/SGwA3SheOZ/vPXbWnKazZ69srXTYUqO+WG
         tI9DtlrdLqmu20UlvkmZ8DVv+GhLNz0KMjo0chOdrrzzh8NDozS/PyrhP43XhVgsxjlG
         JULwyPo1N/dcTaxdE7Kq0bIrOsGmOnOOR1UDGRw6L8lCabmc3+0LNj0cW4L2gf9xdadM
         wp4fdBRFzY0HQfmLkTPgSjLuVW3GyzxELa/vpEUCVP2oJvLkZ4MUiwTvRxbyQ0nKtNMn
         EIYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wn59IozK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id m7-20020aa7d347000000b0042dd1db7093si197234edr.5.2022.06.09.04.45.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:45:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id q1so25846606ljb.5
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:45:37 -0700 (PDT)
X-Received: by 2002:a2e:b0fc:0:b0:255:6f92:f9d4 with SMTP id
 h28-20020a2eb0fc000000b002556f92f9d4mr21861715ljl.92.1654775137344; Thu, 09
 Jun 2022 04:45:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-3-elver@google.com>
In-Reply-To: <20220609113046.780504-3-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 13:45:25 +0200
Message-ID: <CACT4Y+ZM3yYYeOGBNEA8+FzjjfMcR-TiENjmCB8Dq-KSPvOWyg@mail.gmail.com>
Subject: Re: [PATCH 2/8] perf/hw_breakpoint: Mark data __ro_after_init
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Wn59IozK;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231
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

On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
>
> Mark read-only data after initialization as __ro_after_init.
>
> While we are here, turn 'constraints_initialized' into a bool.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/events/hw_breakpoint.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 25c94c6e918d..1f718745d569 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -47,7 +47,7 @@ struct bp_cpuinfo {
>  };
>
>  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
> -static int nr_slots[TYPE_MAX];
> +static int nr_slots[TYPE_MAX] __ro_after_init;
>
>  static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
>  {
> @@ -63,7 +63,7 @@ static const struct rhashtable_params task_bps_ht_params = {
>         .automatic_shrinking = true,
>  };
>
> -static int constraints_initialized;
> +static bool constraints_initialized __ro_after_init;
>
>  /* Gather the number of total pinned and un-pinned bp in a cpuset */
>  struct bp_busy_slots {
> @@ -711,7 +711,7 @@ int __init init_hw_breakpoint(void)
>         if (ret)
>                 goto err;
>
> -       constraints_initialized = 1;
> +       constraints_initialized = true;
>
>         perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
>
> --
> 2.36.1.255.ge46751e96f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZM3yYYeOGBNEA8%2BFzjjfMcR-TiENjmCB8Dq-KSPvOWyg%40mail.gmail.com.
