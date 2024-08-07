Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH46ZW2QMGQEQFLCINQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id A4B1E94A5D5
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:40:33 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1fb44af00edsf3563425ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:40:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723027231; cv=pass;
        d=google.com; s=arc-20240605;
        b=K/lMU4xVzds7GEukQwrzAvekdqALiI1fczkk7vrGvgGR0pWqxpNciAN5hoDc/a9EJK
         BOyY2NHNAkCuTGLWr3Up0Rm5zBkAvDGtq7GrdH4XG8WJnymYpnzfuVuIsKb08KicUhH/
         65vRrVof7GPoVevS6NtGqO6SgB7m/vOkKXWELm7BpHpVK1MtoeeVvuNsdgKYO9A4Y2zK
         KwdPFE3DDDBg4rHYovLse7sacYqF+DHIg721OY1nuxfvKzFytpX0Z45Yd5GolpiOnmrh
         +6RWu9l498t+2ySuxXT4z1b17NeLVqW2+RJjDbR7ubIU0zJslse5m3xZ0EdEjtPwYomf
         gHbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5iN+gogMbasH5Jv1tIIbOfD/YDCxY0vnjgDgDZUmaAY=;
        fh=psd9p3DTfRlEbjDDyn4FUJuOLgoqu/0wwWKLwzQJ+u8=;
        b=geVxNCqxyJm621hn5L77VqULp5Oks5iVCWlK9f1fhKs7hieBtB3NlCspfmNeu9pho1
         hU4LsSRfeZYSGZVKvKp4YWrm2GQdy2fuBy4OOPS0Ou0rqtSV9LWQDPg6XVdqh34pKu1R
         6ExEsjV9P/Nc9LM9vj8PiVuwiJyjHWnghoqS5AwZkLqlKXc++4yTpDnrefjhD+pNGHSg
         K/y2F4IrtMLQbZgtvf38CVywgyUMpOmOlVvAmxR+gU22S0LI48h6avCChkNzeBYWTdO3
         LTQXuPQHamfWt+G6VekIZd1xHXTduS+MjTE4+qXjXaUXHr2rbjvrQ3rpQUIsbSF0ICfh
         kEfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QNBdjq3B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723027231; x=1723632031; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5iN+gogMbasH5Jv1tIIbOfD/YDCxY0vnjgDgDZUmaAY=;
        b=c1IcK8PlPwAuhWEyuCq44d93n3jKSqzP55g7T7Y3xcgndzrGJ+HynZLRh/q4LXcT4P
         YgyQCElzmD7pV5W9mW2n4C7J9Zp763j1eR5IVUeOq+Q5+cGaR52Cu9czg7E7RTUxJ/j3
         MhVnSfYIH0PIBTvPCzrFV+HTuZiazUCed2lK0HknsSx8Z87zVlvZWPCJ2JjTyrx/U+ov
         bSyjOUk7Tp49mWsaiAzLYIXaL3+sr4NihV/iLZN84RMoPHgB5N06g6AuO6yrFflMZmio
         5SNrmjW3Gg+4docwXN8GxLnPm9KOIJw9n9q8oy6tyUF54JM6pj3GffctJ/KG6sTmnFlA
         K4HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723027231; x=1723632031;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5iN+gogMbasH5Jv1tIIbOfD/YDCxY0vnjgDgDZUmaAY=;
        b=DzyA4zbctIoD7zNk11T3zMkvN7s56cKVNlyDPS5EJPk2DG93e5/9dYAIDADA7v2p7H
         q+mW9gbHpi/CWwWEF/QVxUN1k0wm6+COkckkuHWWPejjpUNnDDC0e2eOuoJ5BJw4DVeg
         DKDJibd8UVOI5JdQXeQZg28LWuN/eCnzYzWCJ2orvAZUIXpLd3/heUTQ50/9qHN8xx+J
         LTWO+jysdHen18MeUPrY8FDOLCFlequOyfdmEPsyF2TRBt08MuwiieqjBhuwodmrIuoY
         F47Qzx9A+JRd4uI8a+fcsD15SjiK6vFy8riWkBqzzYaozMnvnBdcrFL/QkUYQGSX5/ea
         di/A==
X-Forwarded-Encrypted: i=2; AJvYcCXnuj8V3Oax0cbkVeq1gsoj3atwprgbZ3Q3uCcEd4/ZQQN1bKKsff19EVYgc86rRB+mLI7sQfotmxrwCvQPLt2HrHZMDvK3Ew==
X-Gm-Message-State: AOJu0YwPaQ/klSyaL5ThNfl8CdJIqtikEXzHvn4UM4Yq4qq/dG4EQSAJ
	GVUlkmb+4GoGtHR3ZJBpT7mWRdq3aRLKPz8qdqCjX/HactVEYPpz
X-Google-Smtp-Source: AGHT+IEdLtO4+J5j1CXwThsfE8+58Ri+RzUL+eTwxhR50EbD+2AeKjhVHmE+pTwiRhGR1azU/HdYGw==
X-Received: by 2002:a17:902:d2c5:b0:1fb:19fb:a1f0 with SMTP id d9443c01a7336-200836ce4d3mr2780735ad.4.1723027231359;
        Wed, 07 Aug 2024 03:40:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e9cc:b0:1fb:299e:94a5 with SMTP id
 d9443c01a7336-1ff6874d9acls40015155ad.1.-pod-prod-08-us; Wed, 07 Aug 2024
 03:40:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0Fdcg+m1+7RLdA4FdbbaCD9HWOTkQKvCHNq8DdEs/Smvfc42bRv8hRQvK2liYYqLOyQy9kWJS5eAGC7Te59osD6cEbGD89ZnQAg==
X-Received: by 2002:a17:902:ea0e:b0:1f9:fb48:7cf9 with SMTP id d9443c01a7336-1ff574cf7cemr220810265ad.63.1723027230074;
        Wed, 07 Aug 2024 03:40:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723027230; cv=none;
        d=google.com; s=arc-20160816;
        b=zosXagXLJmB1Btxz8AdR+aq49LXEhmXDt/01Jhnbfn4HHoU+r2f8hnXsnmlBp6J8zf
         f4TFy/bB5X4kEU2J7FFnHzh8cKbiZyqIrpbB4fvtG1WsTwl3AAW8M844PxeWDrKza7xk
         X9vbt5JF0mX8KOt4+UAhFPsn1gHjFAD8X8mhBMbIwag0JaPtLPsyL2uIp+u/l6cTBYya
         4oeRnCKCDNFhpSha0Vj8Y7fbLBwkr+dvq3YctKwrPGQkb0IU/k3QrOCCgSUjQylIujG1
         DjTixffPhYwax8x4exnuei4NwtHth+fmp7vwNl+4YJWfmgTmD2W0gN9pm66Ggj5ecXNh
         l3BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5jMeE7K9O2DS7pnDAgDvtLDpZJCQRKll4W9o5RnUXec=;
        fh=L4Icx8R1scs6YIpXahatzwexLgtICvVXgXVK8RFfHU4=;
        b=LeHO2AAtLh76D82rAlwK2kWxZGDvag3L925Af4UEtE61LsvlalmDVu62fqT/rvKEVl
         2IAKDTux7hatgVS1fYKVCC5yeZSWOtqgvQxQqCI535qdQxRu8aS3Bfu3/FBXg8OFZr3X
         f8mTK00OiHIH1xKYySD5WxM+DVeimR+muItZZo7GKsLcInRLEZecmk4VISwt51XGYvIP
         5ZXCAFzfLOAFUy+dPm53uiWFnFmzWdwXwqmBRJjUSgq/mJIPKc/a5m7xUq22Bnak2deX
         /i1GtkPbpna9Pum6IAWdqqW/WeDHNnFroAFcs8d1ZLScMi2YRKEAVXa9E1d/iDUQgfGC
         pUtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QNBdjq3B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x92d.google.com (mail-ua1-x92d.google.com. [2607:f8b0:4864:20::92d])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1ff59043483si3824225ad.8.2024.08.07.03.40.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Aug 2024 03:40:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) client-ip=2607:f8b0:4864:20::92d;
Received: by mail-ua1-x92d.google.com with SMTP id a1e0cc1a2514c-83172682ab3so520105241.2
        for <kasan-dev@googlegroups.com>; Wed, 07 Aug 2024 03:40:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWtFGKDw9xB/XO9jyRPf+PO/xuTyzrP1kQNBi0wddsoyZpN9L8nTstFofX6d57NIHaM/vLfezhYLZ+Ys4FJK4EYpG4QHWByCqrf0A==
X-Received: by 2002:a05:6102:6d1:b0:48f:95cd:e601 with SMTP id
 ada2fe7eead31-4945bf055e0mr16144512137.25.1723027228674; Wed, 07 Aug 2024
 03:40:28 -0700 (PDT)
MIME-Version: 1.0
References: <20240807025627.37419-1-qiwu.chen@transsion.com>
In-Reply-To: <20240807025627.37419-1-qiwu.chen@transsion.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Aug 2024 12:39:50 +0200
Message-ID: <CANpmjNMvdkn8Zw4SQy1n2e+HHvpg33fC9xmYkFD9fi6THNj_tQ@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: print the elapsed time for allocated/freed track
To: "qiwu.chen" <qiwuchen55@gmail.com>, Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, "qiwu.chen" <qiwu.chen@transsion.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QNBdjq3B;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 7 Aug 2024 at 04:56, qiwu.chen <qiwuchen55@gmail.com> wrote:
>
> Print the elapsed time for the allocated or freed track,
> which can be useful in some debugging scenarios.
>
> Signed-off-by: qiwu.chen <qiwu.chen@transsion.com>

Reviewed-by: Marco Elver <elver@google.com>

Thanks for the changes! I think this is more generally useful and much
simpler than v1.

> ---
>  mm/kfence/report.c | 8 ++++++--
>  1 file changed, 6 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index c509aed326ce..73a6fe42845a 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -16,6 +16,7 @@
>  #include <linux/sprintf.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
> +#include <linux/sched/clock.h>
>  #include <trace/events/error_report.h>
>
>  #include <asm/kfence.h>
> @@ -108,11 +109,14 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
>         const struct kfence_track *track = show_alloc ? &meta->alloc_track : &meta->free_track;
>         u64 ts_sec = track->ts_nsec;
>         unsigned long rem_nsec = do_div(ts_sec, NSEC_PER_SEC);
> +       u64 interval_nsec = local_clock() - meta->alloc_track.ts_nsec;
> +       unsigned long rem_interval_nsec = do_div(interval_nsec, NSEC_PER_SEC);
>
>         /* Timestamp matches printk timestamp format. */
> -       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> +       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago):\n",
>                        show_alloc ? "allocated" : "freed", track->pid,
> -                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
> +                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
> +                      (unsigned long)interval_nsec, rem_interval_nsec / 1000);
>
>         if (track->num_stack_entries) {
>                 /* Skip allocation/free internals stack. */
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807025627.37419-1-qiwu.chen%40transsion.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMvdkn8Zw4SQy1n2e%2BHHvpg33fC9xmYkFD9fi6THNj_tQ%40mail.gmail.com.
