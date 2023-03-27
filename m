Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCXRQWQQMGQE5JGZQGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C1DE16CA20F
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Mar 2023 13:05:47 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id i14-20020a2e864e000000b00298ab0c9877sf1690532ljj.19
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Mar 2023 04:05:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679915147; cv=pass;
        d=google.com; s=arc-20160816;
        b=nENENe12whJEnI61PSAPGK1nJRUAKja7tfb9qvvmM/SYJ1Jm0XRNQ9sUzRNIqmLTHY
         a2JnK3PCbqAyGb1GMRtX86tP8fzLmmnt0tJYZbjlNKnSI8LnM6M12gzuqWh2zpB0Evlx
         MwLGSw3BAaXM/JU4fVZtqWh66kJPOMbINioRv7JNx8/omcclDY83yIP1GzJSVUAHTh4D
         jJhByA5mmzRf2med8GHdcy+UCKJFK0SxDNzqte+i35GMO7Neiq3q9HIIlXJNOnzJN2dI
         bQAcu/l15ndNj++1fDzF8b6bIC7K0df4I6LrZ2mFBzUC6yux0fFDU/TjhdGo2jasL/Df
         bhfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qQzmntoz01/Kee0JYZZXC/6EHPJ8VtIzZHqgvL3n4vg=;
        b=yyWuKfBFiO8C/9T1b5qHUnVlTpMjQVGBni543ezlNxOdeGOoEJa1+RGYsYIaG6cJTl
         fkkh11eU0kSrjTRv3Lz6K7WkxYAwGW0cWIvlGPQicZ7TFVDJJr3jDiAIjMAi0KtIFmcQ
         1psaDmjGdWaqFv4PRMxAV13xzT+gIWPaWggIKnkYVTwlbeC0WQVmlKCsbKEQzcCc/6rf
         z0lHBBLbLaivTw/Ns5p2IyNtgHvdj41AewCezP4YlT2xmtpQwXyS9nBYj+TrfBBvTuTO
         TknlapFTbYk5+/kWusnC5O9k7ekFs2mBcLhF1CJvNQMgpVNkOcAyyLkNGtLBI90uT+Sn
         55IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="b/cIc4Mb";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679915147;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qQzmntoz01/Kee0JYZZXC/6EHPJ8VtIzZHqgvL3n4vg=;
        b=Cbd/VRcuX+JgPTNr3td4XCrTLPL/s26BD7rIloVTmlFM+QsTU1w9r3SxB/6NRhtAfE
         aJH5+oNakAre+pv5mOW+Oa9WM5y7NKwX18izXogfakibsRxFMGEkEDE8gt4rXtlIa2zU
         HcDAx+s7SsOFRhiuJIvXOcvSWkC4u2U1V5XWeVoz8e2YgmtcPUhlHk4OKq2chTlvHt/E
         Ow3dV/fSYXM8zaQ7NIZLqfvyXiRj0h7Y8qEu/V3n564rnJbHijVpKXxDq8Vcf2xFkwgs
         ujrv5TRUZMGZJmgB74by2mEE3HvXyarkssvSIfbZwPCr2ISRt0LFNcjpWTB+AI5dHQth
         1MrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679915147;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qQzmntoz01/Kee0JYZZXC/6EHPJ8VtIzZHqgvL3n4vg=;
        b=Qx25hKQUoqJ78osSjaBDhFzMNHQoUS/y/3BKiimeG99rpwfecxuVVcuWOI24SC1rlV
         Ut77JPPhgKBZAVDuABo0XuDFVhVLfeN/O5Zr+HJy+LrZdKQw+GGtbzRjhOB0GBJJcoyn
         s3vENdvRpNaUc/PrK6ls6tAJLXPdwBIiBtcRKwhMhl3v9l1eUdSnJeHDAAzwJEF4rXGP
         qNlmwtAddk18geP2tghS6hvyk91yj9OANu5O6l3RFAA1R2dnKcpD48UpvB2LMTRryo7A
         G7iGK/MR9/BywAh2A2L6m+apBWOdzPYZ4EuNlXxLZCxd01x3vDKXsG7bJPNlM2yihP6W
         Yxpw==
X-Gm-Message-State: AO0yUKWb69Vrc9GjkC7RwkL8mEWly/HowXID0Op6tG02vaabwkTe6bXU
	lb1zJXxR5m5ayCh+T5E0F0Q=
X-Google-Smtp-Source: AK7set+6wYFZSpvbdnF461tbXvo/JtRdOdgX7VKf5PJKa4PV3aWuCX4brf0b6l51OsEt88zqrNCSuA==
X-Received: by 2002:a05:651c:2122:b0:298:b378:961f with SMTP id a34-20020a05651c212200b00298b378961fmr8273648ljq.0.1679915146792;
        Mon, 27 Mar 2023 04:05:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:220a:b0:4e8:c8b4:347a with SMTP id
 h10-20020a056512220a00b004e8c8b4347als1056472lfu.1.-pod-prod-gmail; Mon, 27
 Mar 2023 04:05:45 -0700 (PDT)
X-Received: by 2002:ac2:518d:0:b0:4a4:68b9:66f3 with SMTP id u13-20020ac2518d000000b004a468b966f3mr3264520lfi.62.1679915145306;
        Mon, 27 Mar 2023 04:05:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679915145; cv=none;
        d=google.com; s=arc-20160816;
        b=iShooH3gtij19kanbJqumROpSbQcwKNtPCcanptTivWzldhBIJ9BD9D73HBYVs6hmV
         kVbXnbR2FCH9/8tqwiRse02Zp7hb5fGMRQyZ32jH3l/IYPIOZfdeIBRPHWRy1kiHEMk0
         g7+9pDjE285LaNOPLWm2PIRbZUsi4UZbUzaYEq1HQpAwmmrd5FSdOeT81y6StHog4KNX
         8X5B4GPqM624gfZlECFesfjtpH2UQvBzOXMDwIHfiHH3aQ/jdFYSq7OewMu2247vowvg
         gSsEHG6vC4VLbm2V7eD63TTiZ34rihfYk2Ec5IdiWCnfKA9bUwFEYBVw34NYTfv4jxPl
         9FHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ehsWNKlF0rOfJEhYzl+s3Qt/MT/o/tgkdKM9etceMxA=;
        b=tPp7hPg6BCb0shFzzL1w92RGWFEn90eELnFEj6t1DgjuA8jXbeLP0KBYBQna3vtBdV
         qFtc+6DmLZ4sk1/NSQQb9ZiPEgh1OsSl3XK6TQ1TEorg/mk2vZqkWIP6QEIHoQq26h7W
         KB0BczeyoGbHgeSxxb+ruX0YlWghwxc+qiIOqvDakD+59rD7VgNwT6/CuyFyX4Tfj4gS
         ntZaqGjpu9mYgCE1kKxjja46QTz2f0AEZ7NKZdvhav659lu90c0BqgI5Ev5IEDnsv0Lk
         iAEI0frwr8gh//qiElx9zniElJrk6H465GoSvaiXcWZTB/0GGoXVgyY51N+wU/tZO/g9
         90wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="b/cIc4Mb";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id f3-20020a05651232c300b004e83ea1c56csi1359129lfg.9.2023.03.27.04.05.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Mar 2023 04:05:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id u11-20020a05600c19cb00b003edcc414997so4974964wmq.3
        for <kasan-dev@googlegroups.com>; Mon, 27 Mar 2023 04:05:45 -0700 (PDT)
X-Received: by 2002:a7b:c3c7:0:b0:3ed:fddf:b771 with SMTP id
 t7-20020a7bc3c7000000b003edfddfb771mr8982017wmj.12.1679915144600; Mon, 27 Mar
 2023 04:05:44 -0700 (PDT)
MIME-Version: 1.0
References: <20230327034149.942-1-thunder.leizhen@huawei.com>
In-Reply-To: <20230327034149.942-1-thunder.leizhen@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 27 Mar 2023 13:05:07 +0200
Message-ID: <CAG_fn=VeP9HbpwEY3wYCrb7cMaLbX7-VFxPdM9zN1dSQ09A8Mw@mail.gmail.com>
Subject: Re: [PATCH] kmsan: fix a stale comment in kmsan_save_stack_with_flags()
To: Zhen Lei <thunder.leizhen@huawei.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="b/cIc4Mb";       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::334 as
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

On Mon, Mar 27, 2023 at 5:45=E2=80=AFAM Zhen Lei <thunder.leizhen@huawei.co=
m> wrote:
>
> After commit 446ec83805dd ("mm/page_alloc: use might_alloc()") and
> commit 84172f4bb752 ("mm/page_alloc: combine __alloc_pages and
> __alloc_pages_nodemask"), the comment is no longer accurate.
> Flag '__GFP_DIRECT_RECLAIM' is clear enough on its own, so remove the
> comment rather than update it.
>
> Signed-off-by: Zhen Lei <thunder.leizhen@huawei.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

>
>         nr_entries =3D stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
>
> -       /* Don't sleep (see might_sleep_if() in __alloc_pages_nodemask())=
. */
> +       /* Don't sleep. */

Thanks for spotting this!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVeP9HbpwEY3wYCrb7cMaLbX7-VFxPdM9zN1dSQ09A8Mw%40mail.gmai=
l.com.
