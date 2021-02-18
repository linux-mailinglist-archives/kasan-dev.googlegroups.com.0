Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5XOXKAQMGQEI4HYOBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3109431EEEF
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 19:52:40 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id f3sf1588471plg.21
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 10:52:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613674358; cv=pass;
        d=google.com; s=arc-20160816;
        b=zw+n9FjN0x796v9XZn8GV+LUHs24aMlmNi4VnEVFWuB1u0wcB0WzC/tesbVfI8KnEM
         iy3N1ZQsp0+jdl4nesQ4A6Y2Krng1fis2bwm1ImQI0eIkjTOzqCxfYi03JuOKqxEb+Na
         rJgtUFZwdleMHw5c4HCfndLkmpmP6YnwVjhfEQS288oavMeE0hLLJfRPrwhhvS0Ouu07
         GKblpHw+80O9cs99ZBk8iw0hZc5n2eMjHtFRsI9f0A4VwJ+rIxengiiu1Mha5Ogz+o32
         GVrFL93JSOH5lYn74R0M9JWLo06sTVoxxLejMAr9Pr4ywnHJmJstrZMAcgdyi9ONG/tn
         I3Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1APmndMoRltvC7RFwNMwZmknHmLkaBAwTEvki4L2KX8=;
        b=okM1f8IgiRVLSn1MVx9/pmvlL8aYzPsehTq5HAB79GHLn0MNZOjfna6z4ZVD5Z9LLv
         KjrGykWhBuCS0nKQsfIYbvqkUk5eHLReBcqJxTGo7arC9Yx10f9RY1LCjYCH+9eNR1e/
         BPuX5RLL2rkZkIni17lURIwx93FOQjqvx8tBT1zP64s0DXeR949fEPFi8471rHKhRpXj
         7QlUuUeISfa/UB+iWobh3Ct1sXwNAxH+q7wZh9yozX/UoBnT1ej2ymWry1xJ3FMEtkeh
         8xJJmJ8ACv3m073Fk51nCFaU2cktj3cGjbtWUpmCE56+NYI7R1bP2IEIYYPVXq681Mvj
         bbmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nH4c5dgF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1APmndMoRltvC7RFwNMwZmknHmLkaBAwTEvki4L2KX8=;
        b=EnmAp79tA6AMyR9tytgzBRXe/O9pBxMsoVmj7w8riZPsy985Un0vjKlTYjNuRc+ayY
         Vy7w7BQ2yeKlk1XwfaOKSiPlyTsiB2GcZSVQJdwSJpJ0iEbXRBAinCTpNiBmSnsiTqZK
         Tol9kzyEHj8G2QcuItP1pUjcg3CYymCSn2UaZ6dqdQcLnfHH944dEEOH7tR/cYDH3IWQ
         kH1PVUVxQKfrvIb7OKTJfBpGOat6U11qVMjpWTApRPb/A/tSvE76V6yXmX0MW0RsRfdO
         jDL5ZTPnh/7fSzPExesPLobQIkt71rbJxKh1tHuQtxsy2x59Kyx8eF3X0ogyKVkR6Ifd
         Wfgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1APmndMoRltvC7RFwNMwZmknHmLkaBAwTEvki4L2KX8=;
        b=Pa4PkDBXYc4zHVxhMq9tLVA33WnFolkd7JPrb2IT8VDXLiJWDF21xcTY7Hdro3h4w1
         DywTNTsdjLEZXKWwH04J1MkZiJO3w+p9Ng+XLvd2h5KSY/cHRmIU1nKDAP1Z/fHaMFJB
         96MYxq/zrzQ5H+aRHdASb3ULjWf0BXSL25ZBUxO+/H3h3qmBNJldDMV2mL9ENi30nH/a
         Iotq8XaevZMRP9Cl0KnVo4VXEzn3OyLt6Dxfaf1Cq2WUDB2cgUj974Yayeb4/MXgdVwO
         oSRzD97AdR+sO7QNG8V4RR4c+eQ7mCWDohNVoelIjWkyRnzbNdjBgshda41Sxck/VJzg
         lplw==
X-Gm-Message-State: AOAM532bVIJn3ozT90qdIs9IaiQBVWk4zyvtYnbp1d+wrCuBxjFZPefN
	i0TVHQqDbKFDR6R+bGRlEPA=
X-Google-Smtp-Source: ABdhPJxzcbLjTG4AQmoHl94+CdEsY9wmSTxR0ZsBv2T46Z8pmfy3ys4Td47LWWY4R4KpfRNY6Pe7CQ==
X-Received: by 2002:a17:90b:94a:: with SMTP id dw10mr5200615pjb.90.1613674358559;
        Thu, 18 Feb 2021 10:52:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f190:: with SMTP id bv16ls1297653pjb.1.gmail; Thu,
 18 Feb 2021 10:52:38 -0800 (PST)
X-Received: by 2002:a17:90a:bb18:: with SMTP id u24mr5338663pjr.67.1613674357960;
        Thu, 18 Feb 2021 10:52:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613674357; cv=none;
        d=google.com; s=arc-20160816;
        b=CAa/alaXyrLTzmHcGsDuq5GXcziDxBDBwu9ippVxGp65kVuW4Jq124JCr/ytVM/BJx
         trM0iHLgYZkbTCxURugIibapRmKizs7yyYE1LS43y9utsU4zhh6IlwzfcXxsXul/1h6u
         l61HURuG0TMJQsFttoTGC2AwI4y1mX5HsRxG+GOS8qphO3ygi1EOT3hms9deBUzp8fQ0
         Okg5r9sT+m7sKvtzzbDonBK9hEc5GNVhrYTbOCHXaYHFDUMLJqcThrnbkfBxEgf6RjXY
         uzwghPFSTl+63iJuwVSvW/DWAgOrzocXDVa+XCcXKAJA3/s7zdVqV3GIthBFIMpjVv2n
         r0Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7G3JVW2KBRmJBfDlGzhqslH0TpNnVSsRPoclsWcVzgU=;
        b=svC+RMPrI49F85Sp1eadMOM6Ks94YxblWGP/AM4GGfVJlf5l/HNLAhRJonv98PGhV8
         +xpBpymhNhfr9CSUJCE9K8aocE5UU/NhG6vI+RKQzikB4UTzAa4bpc3wktk0q2tMRIEs
         /lFT9oghf1g4kFa3vy/xbyWr6SRVU2KaNcsHu6B1P76m+gsHST54NjHOVC8XxuLMxZy4
         sD7BGcd08JQlqY3DW8wCv50DshtFtu4GZsgSZ+O6R0KQ2OMNEht74mm7SrdizTZvwPit
         scoo+W9h6z0RI5PwGXulm+r4UHlkRtgc5u4M2ds2z58LirJnuGKA2NMSqt9FYoJoPqWD
         1e7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nH4c5dgF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id g22si330929pfu.6.2021.02.18.10.52.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Feb 2021 10:52:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id l18so2079424pji.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 10:52:37 -0800 (PST)
X-Received: by 2002:a17:90b:3756:: with SMTP id ne22mr5109449pjb.41.1613674357497;
 Thu, 18 Feb 2021 10:52:37 -0800 (PST)
MIME-Version: 1.0
References: <20210218173124.iy5iyqv3a4oia4vv@linutronix.de>
In-Reply-To: <20210218173124.iy5iyqv3a4oia4vv@linutronix.de>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Feb 2021 19:52:26 +0100
Message-ID: <CAAeHK+x92X_NZt7MXw1a_=23tLqKyiuOesGHo_Y=aqdZZqdzEQ@mail.gmail.com>
Subject: Re: [PATCH] kcov: Remove kcov include from sched.h and move it to its users.
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, "David S. Miller" <davem@davemloft.net>, 
	Jakub Kicinski <kuba@kernel.org>, Johannes Berg <johannes@sipsolutions.net>, 
	netdev <netdev@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nH4c5dgF;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030
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

On Thu, Feb 18, 2021 at 6:31 PM Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> The recent addition of in_serving_softirq() to kconv.h results in
> compile failure on PREEMPT_RT because it requires
> task_struct::softirq_disable_cnt. This is not available if kconv.h is
> included from sched.h.
>
> It is not needed to include kconv.h from sched.h. All but the net/ user
> already include the kconv header file.
>
> Move the include of the kconv.h header from sched.h it its users.
> Additionally include sched.h from kconv.h to ensure that everything
> task_struct related is available.
>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> ---
>  include/linux/kcov.h  | 1 +
>  include/linux/sched.h | 1 -
>  net/core/skbuff.c     | 1 +
>  net/mac80211/iface.c  | 1 +
>  net/mac80211/rx.c     | 1 +
>  5 files changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 4e3037dc12048..55dc338f6bcdd 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -2,6 +2,7 @@
>  #ifndef _LINUX_KCOV_H
>  #define _LINUX_KCOV_H
>
> +#include <linux/sched.h>
>  #include <uapi/linux/kcov.h>
>
>  struct task_struct;
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 7337630326751..183e9d90841cb 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -14,7 +14,6 @@
>  #include <linux/pid.h>
>  #include <linux/sem.h>
>  #include <linux/shm.h>
> -#include <linux/kcov.h>
>  #include <linux/mutex.h>
>  #include <linux/plist.h>
>  #include <linux/hrtimer.h>
> diff --git a/net/core/skbuff.c b/net/core/skbuff.c
> index 785daff48030d..e64d0a2e21c31 100644
> --- a/net/core/skbuff.c
> +++ b/net/core/skbuff.c
> @@ -60,6 +60,7 @@
>  #include <linux/prefetch.h>
>  #include <linux/if_vlan.h>
>  #include <linux/mpls.h>
> +#include <linux/kcov.h>
>
>  #include <net/protocol.h>
>  #include <net/dst.h>
> diff --git a/net/mac80211/iface.c b/net/mac80211/iface.c
> index b31417f40bd56..39943c33abbfa 100644
> --- a/net/mac80211/iface.c
> +++ b/net/mac80211/iface.c
> @@ -15,6 +15,7 @@
>  #include <linux/if_arp.h>
>  #include <linux/netdevice.h>
>  #include <linux/rtnetlink.h>
> +#include <linux/kcov.h>
>  #include <net/mac80211.h>
>  #include <net/ieee80211_radiotap.h>
>  #include "ieee80211_i.h"
> diff --git a/net/mac80211/rx.c b/net/mac80211/rx.c
> index 972895e9f22dc..3527b17f235a8 100644
> --- a/net/mac80211/rx.c
> +++ b/net/mac80211/rx.c
> @@ -17,6 +17,7 @@
>  #include <linux/etherdevice.h>
>  #include <linux/rcupdate.h>
>  #include <linux/export.h>
> +#include <linux/kcov.h>
>  #include <linux/bitops.h>
>  #include <net/mac80211.h>
>  #include <net/ieee80211_radiotap.h>
> --
> 2.30.0

Acked-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx92X_NZt7MXw1a_%3D23tLqKyiuOesGHo_Y%3DaqdZZqdzEQ%40mail.gmail.com.
