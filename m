Return-Path: <kasan-dev+bncBDPPFIEASMFBBIN74CLAMGQE72QEFBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E44FE57B99F
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:30:41 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id k27-20020a05600c1c9b00b003a2fee19a80sf1416885wms.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:30:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331041; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bxm7XqK253Orl5wlZBcSyzluL7d/dXzoOPRdmkuvC5lVOnTEBW5cseeq0pCyfH4bTb
         AGY7sNBxl1xs/oPLiJsw4l4zWoGi3YyYAshrzGwHP0yuppUk6apB9/S6V0aqjYS8kbw9
         107zlgHDDpc0iL18LEXfZfjnAU9thqFWfqVQGCECXPrUvBAA3R2cnVujx2d2gq+U2HiW
         rcAa+ACnahI13Q+DOGiH2wJoBgNSACvYFrWxcgAi+pHF8HHiCJOJl+3rXCcDa+8owE/l
         VTZSJ1qDeN9Cqp1zkorm2AwD2NF0eyeTvpS/7so4RUPyS5BWqcCIklEztwrYldkcIUjW
         p3YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QF059cma8cbRsKFQcmLIuJQYVU37s7MRc0TfZIlHsmg=;
        b=qKC2nRSpWNn/JXMMNtWyEdb9DW0fU7Rk1wcoKeSfNFsu0Q4cj2dHS9N2c1VRaMbdwe
         Cqv2VY1L44ngGg2/t5Iz+Xs5c0Q2KSQxJQ4ucBAYhXzVTT995mC293pkE2xZisWXNH4M
         aplj1vmuIh7AAd1MIFCHys2oZ8YK1TW2sJ7MjQUUwlQQEDe879hnA/Loye6jAeLdZsEr
         ECNTWfGU1fQhwQlgyKdZ0ekNhvkKIdE5H1MqVUb6Zf9PBqjpZFrPCm10Vcn0MaThNP4B
         YEwzrHEVFLMrw+g6rSgasHRCh3OqZW+mA5Yhrf1+3ZrOT6WuLeBTT6QT/pjUouyqngVn
         yMAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZgSdDrcT;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QF059cma8cbRsKFQcmLIuJQYVU37s7MRc0TfZIlHsmg=;
        b=s0rIU7JTi+bd++7e5fO7Vz5/MzfUAQS0W2soo66KJu50hBe09xMYHG70sQ6ZGXzn/w
         jBLjBNfh0Tsi6flhn6OAtuKQsa2xBWJEiBHIEdqPXPIunjoPSBlMrJJM+AaofvoR79QC
         4tmR9u8tTieSYYeEcJDd1EcnOvZv0CqGvm3WJZV0tjgNzFrN8s4Bnx5p9G2EwlaoXT9f
         naTZVG8M44QDlNmS8G0KXsWvTsq4FfJjRNly4aoTeSmehMLsn11vzjgr1ovwgmVUoymI
         5fDyiXK08ggRvAdVTnyZn50yk8s2CXZJjG2k7loJi4T6udg0T537fHM2HWZtsje9Ftj4
         rmCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QF059cma8cbRsKFQcmLIuJQYVU37s7MRc0TfZIlHsmg=;
        b=Cn/uDYtsG2dLj7Tm4SOjoaqmNBsfga54KDrgv6riTO76BhI+zXD+L6BdNgDdD9QeO8
         RZCWjmS4PZvSJdyUF5wz5M9a3T1lvH2c9ubxXjf8rkjOAoLlst3IoUsAjQuEfzlzLeLL
         hXoy84xJAgA9OJUEg0kqU+UCkJLneWzdpG0uEHzWIyffIW7e+l3p02VYbWOB46VpdHij
         nbpU84cI90E+Cwe49kt0daSxdqC+jYg1PbewJrsVrK8HyQai80acUzKNB73XM0e2ka3E
         hh3Hv1TJsglUE7Vn1TeqDDNiglPAuGf4lRPhbilj+NHGeKwCbS96WO5tA3jOPKdnDK44
         vnQw==
X-Gm-Message-State: AJIora8DaIX8vyRHvKW2OKYIf4Csndox1oFbizdaA0DIviAc6onSS1nT
	phamL8bMcxm9KCDhxlX1H2o=
X-Google-Smtp-Source: AGRyM1tG5rDCFcU7betrA4OT8q9AAr9ZLG5ld2OI8Nh8K4pZkJLEEfcP42Gd35Xqfh7MSxf3KvQPog==
X-Received: by 2002:a5d:64ed:0:b0:21d:af70:3515 with SMTP id g13-20020a5d64ed000000b0021daf703515mr29845811wri.101.1658331041393;
        Wed, 20 Jul 2022 08:30:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:22a:b0:21d:a0b5:24ab with SMTP id
 l10-20020a056000022a00b0021da0b524abls118983wrz.1.-pod-prod-gmail; Wed, 20
 Jul 2022 08:30:40 -0700 (PDT)
X-Received: by 2002:a5d:6483:0:b0:21d:99c5:cb6e with SMTP id o3-20020a5d6483000000b0021d99c5cb6emr31503508wri.592.1658331040478;
        Wed, 20 Jul 2022 08:30:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331040; cv=none;
        d=google.com; s=arc-20160816;
        b=oYEOOmq9SPh1UU8apSUTvzUk4DfrsG2ONHigAOynCx9eWE4w53/7Nw+nq2cFGRrG9m
         QydJuVIN/gzt74/ovOLACtTUOjIFIpEcCPerhQ+TAODHgfdtEuA33M+AXEw8LqoDuGkE
         1XIdKEPVqAnROMXurSCeLTdHM13tyH0Jr4VB2WUH0WN+ckHq3f/TUK4beLmU2wKVL44f
         y7skURiZTIu0G45wiv1w1FrqGbM51p67a94AhGIKhmp4cTrOfoi2vqqVPY+KjtMI1fhx
         RdRKWn3u1EYWAl7RZvE1yTVQ8EeSicShxXLYzgqK55S3AInol810kVbNFgk7wQdSixdu
         vSFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cbQQtxk91yWYRZraNSUPdpEN5EtZ/LYwfMBL5CTtBFk=;
        b=QqThihab7C4tomcDPvxJXlGpQQXhYTi8aF/RUnFzb0xOjZGH0oh5fRjG/modjvJXjB
         XC3WzNpGaa5c8+FTB0bdR6NKx4MRpuVNQXUZFLjHXhVUFQ4L9ldCVH0KSm5e6yTd5Kjf
         dBrVcEJzN3okUjyRSEekopq+aGf2q3SmI7YYV51YeJqUDe7SzTvh/biB//TYFnbmZ42D
         KIfYJSTS/Xho28+Wy0nZRRuUtSVz1+PVCrEoGQuoEwURb9lsMHGPnlnW5q0MynNhU+Ag
         ljaYkF5f4hMdFjbCB4cU/ULK3BWpp3CiLy4feUB6X3KmCE9tKTouo1H4eymNPkf5QgMd
         D37Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZgSdDrcT;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id ay24-20020a05600c1e1800b003a31dd38c4esi113859wmb.2.2022.07.20.08.30.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:30:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id f24-20020a1cc918000000b003a30178c022so1580311wmb.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:30:40 -0700 (PDT)
X-Received: by 2002:a05:600c:19d2:b0:3a3:2cdb:cc02 with SMTP id
 u18-20020a05600c19d200b003a32cdbcc02mr1916330wmq.182.1658331040002; Wed, 20
 Jul 2022 08:30:40 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-6-elver@google.com>
In-Reply-To: <20220704150514.48816-6-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:30:26 -0700
Message-ID: <CAP-5=fUySGaL32RQH5AuXjRCuBe8E6Nacarg8z1nkS38RkzZHg@mail.gmail.com>
Subject: Re: [PATCH v3 05/14] perf/hw_breakpoint: Mark data __ro_after_init
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZgSdDrcT;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32a
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Jul 4, 2022 at 8:06 AM Marco Elver <elver@google.com> wrote:
>
> Mark read-only data after initialization as __ro_after_init.
>
> While we are here, turn 'constraints_initialized' into a bool.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
>  kernel/events/hw_breakpoint.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 6d09edc80d19..7df46b276452 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -46,7 +46,7 @@ struct bp_cpuinfo {
>  };
>
>  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
> -static int nr_slots[TYPE_MAX];
> +static int nr_slots[TYPE_MAX] __ro_after_init;
>
>  static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
>  {
> @@ -62,7 +62,7 @@ static const struct rhashtable_params task_bps_ht_params = {
>         .automatic_shrinking = true,
>  };
>
> -static int constraints_initialized;
> +static bool constraints_initialized __ro_after_init;
>
>  /* Gather the number of total pinned and un-pinned bp in a cpuset */
>  struct bp_busy_slots {
> @@ -739,7 +739,7 @@ int __init init_hw_breakpoint(void)
>         if (ret)
>                 goto err;
>
> -       constraints_initialized = 1;
> +       constraints_initialized = true;
>
>         perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
>
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfUySGaL32RQH5AuXjRCuBe8E6Nacarg8z1nkS38RkzZHg%40mail.gmail.com.
