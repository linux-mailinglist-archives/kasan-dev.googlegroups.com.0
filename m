Return-Path: <kasan-dev+bncBDX4HWEMTEBRBREY2GAAMGQECSIBGQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE87B308BFA
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 18:56:21 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id x21sf3753500plb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 09:56:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611942980; cv=pass;
        d=google.com; s=arc-20160816;
        b=zyLDcVGlIdQdcitLsjRTKxz9/XlnjoTbQMmkrINLVunYpz39+OU//qrDE6jv0NdoVR
         LcMB0eGgaiqyg4EKc0vUSoOCGo+5jLHYo3JkI6WwB36xLXFw50HaLyaVuM0hiAQamTnM
         ZltLN0Wwiwf09s9/iQhm5nKk87gw49zfVewjbwJSnxy2DvlpGDHcP+Ql6ROnq7riHIGR
         qREvjbOiszXHoIzdngM9qJhlwjyAUmvPU/35TZN15eCcGxsbVzObuDWBIQiHvfUJ54x1
         S0X1nKToFjVa/apstUWPq5NgfxX5MXjaYWmhFxDMdnYZw+HggnoIa4yVGyrQ+qew8Kn4
         IPrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oDUpdixKHSqQ65Beh/STCxR/m5Z8ZE1VwoLMWAhBs0I=;
        b=fScBBcfcDuWALivD3sMJ0yhvH8ABcPnofTWEvjhrTYUcc/rvmoLJklZa3/ksC3N+W2
         EtaB7vJ8+clXPtZG8xHUthDCh0Q7LpGgHz3fqeybWEevCnEbzBCCgYAAlaTRu/yfM33g
         Xc0FgBKgKLb47ZQuD6CIW7SaE8NAozj8JkN0Iw8+AvCE8Bj4cz8nFdto05nMIVnUhKgG
         XF/jJ0GVD8yJijVzlfjUEVt+nXHYvvDM+D6c4eiwGEMoBZNy9ZSXwwcqGKNBH8x826h4
         CAqK2YL6tuBydThWOMs+urr4MacUikXTZPHzlGmHDPxKS8iDeIpbWWzjjiqr1UgxR/qp
         Gryw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Xa+k/wr9";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oDUpdixKHSqQ65Beh/STCxR/m5Z8ZE1VwoLMWAhBs0I=;
        b=n5Omf3nmcDSdIpS+3YHPFaCArUiZPVNuIlx+x4Xf9f02eUWTWZcDNq5DEZtPwHWgE7
         w797bizH4F/RbYkpRhw8pLVbyOHZbqqBLPoT5Nach51aymSVlhN+aQ/yHJNv8kEQeOxz
         uHABEnopwdJJtrrgagltx6yUNt9Z51bx7y4MykYuUd7WYGB5K5Nby/WYa0JOugAGTmUD
         NHbzgeMHZ0IF+q4uLGVVTiG5hYkR+p5r1wUBvmbzzEq2MnyjWYNcSWz5Vimr0sBZ5tFD
         d7vvLfLcTCgDlx+tU5B+S3ah7gfRWl8VpM3ZQkj/I4Wug4TY5e4mr4G2oHyd7OW4upBV
         R9Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oDUpdixKHSqQ65Beh/STCxR/m5Z8ZE1VwoLMWAhBs0I=;
        b=HzyG6dWE8IkFoydtX9d2SHAxvQu/oQ60iCWTOv18yjbxf6ZJKi6g3bGXjqUrmWnw3M
         o9VgOfC86WyU4TwJejkoNy/armChYepMnG721/1HPdK0IKYsk2zKubttMRGjh32BgQto
         Eh5VeMoehSF+PmumSndgZji7gBxd12G1G4mxERn2VB7U6iZXY4j68axqVtJnVsLjr57m
         iHcaCdyoPDxUJ0BR+M1GNVMBw+/YoNW6LU03/FaJOvS7OLwH86c/0UYSntptI8L5NglU
         2uEtnXY60OAPfeynglb4VL9poLfgmCbXarUG5y/DZLBJZXfghaYOgiaYKzk6mRhFIcRP
         4eVg==
X-Gm-Message-State: AOAM532Hz84ktt9xMta+NX5oveSLLxZd70dgyGlAL3CbHsrCYgsHBVJp
	HSspjAxlTB/iDprLwwUD0O0=
X-Google-Smtp-Source: ABdhPJwpPjtZva3xfCHxQkVF4+uMWmCYbUZMXt8H0liSxJzzXsSHH7d3hW0pvHJf8zq29TbLyT6F/w==
X-Received: by 2002:a17:902:edcb:b029:df:cce5:1105 with SMTP id q11-20020a170902edcbb02900dfcce51105mr5425375plk.2.1611942980630;
        Fri, 29 Jan 2021 09:56:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9f87:: with SMTP id g7ls4684164plq.5.gmail; Fri, 29
 Jan 2021 09:56:20 -0800 (PST)
X-Received: by 2002:a17:90b:f08:: with SMTP id br8mr5500367pjb.134.1611942980047;
        Fri, 29 Jan 2021 09:56:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611942980; cv=none;
        d=google.com; s=arc-20160816;
        b=cC6+SiJ4bt+/DYDWdsP2+hMbZUjCG/daXVxuGxiH3Vr+YDxUai2E+LV8jilggf/9az
         9kVZwHZKg9k0ceA5uzRIz16iFbnwmfb+KrynLUGNTysMRZ2KvND0ZSsQRtRlV4Zc+nGt
         DKFkA9OvD7CrcDQgHXrQ6CcwIOCzjLqb8Y/J3+0Weki5+osGTI2FQKa2Xb0OdyBEnnUS
         HIAz2GiqT6Bq9h6rbe15iwYFidJ2E7msx3V0jywh7uLdnJ96o/78xGNI5kHu3yvoA+1X
         V8Up5K+cd04jCrxZRTnb2B1yKpXX5dh2ydl7kVYPQOOBfHdOwHDAu6/f1T/v8xdv4pcr
         rXkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KY25Xh6DIR9IRYESFVzdYe8dpCzTrFCAYLNdKXuQz8E=;
        b=mHNbrF6XUwtShK/zFJDtgBmdJBw3PB5T/oVB+G/KZvcTtIW1Gs5Hps0o7Q0FJdMNgM
         /NMhGf+AK9Rcu1oZ5HwXLR5zATEK2knsOmkmVruoi2Ixo39ogwAdUUucqXAxmmVFXq3E
         QYpCwM3H46i8EAkHBiGjB6BsQlu9M9N0sgaxJ4hycZy9yx84dTBYBFXMlM7MXaPb+5DY
         Tkblf/l/Z3xm8hThOdyLVASGQ4VIuDPH49NV6tMbsvmVmI/Xr1kt93BCbA7Ho10dcTFi
         n7liNkTJhvvHX9BLkEr3o5vuL+XG5ciIZL1DocB/EpF415cguzVzfu4grZIfmVB8uhNN
         TiWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Xa+k/wr9";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 13si588164pgf.0.2021.01.29.09.56.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Jan 2021 09:56:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id w18so6685595pfu.9
        for <kasan-dev@googlegroups.com>; Fri, 29 Jan 2021 09:56:20 -0800 (PST)
X-Received: by 2002:a05:6a00:1:b029:1c1:2d5f:dc16 with SMTP id
 h1-20020a056a000001b02901c12d5fdc16mr5321304pfk.55.1611942979560; Fri, 29 Jan
 2021 09:56:19 -0800 (PST)
MIME-Version: 1.0
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <20210126134603.49759-4-vincenzo.frascino@arm.com> <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
 <77de8e48-6f68-bf27-0bed-02e49b69a12d@arm.com>
In-Reply-To: <77de8e48-6f68-bf27-0bed-02e49b69a12d@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Jan 2021 18:56:07 +0100
Message-ID: <CAAeHK+xMWXpfLs6HuKN73e0p61nm+QrZO1-oXphJpjZprKQVKg@mail.gmail.com>
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Xa+k/wr9";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430
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

On Fri, Jan 29, 2021 at 6:44 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
>
>
> On 1/29/21 5:40 PM, Andrey Konovalov wrote:
> > On Tue, Jan 26, 2021 at 2:46 PM Vincenzo Frascino
> > <vincenzo.frascino@arm.com> wrote:
> >>
> >> KASAN provides an asynchronous mode of execution.
> >>
> >> Add reporting functionality for this mode.
> >>
> >> Cc: Dmitry Vyukov <dvyukov@google.com>
> >> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> >> Cc: Alexander Potapenko <glider@google.com>
> >> Cc: Andrey Konovalov <andreyknvl@google.com>
> >> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> >> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >> ---
> >>  include/linux/kasan.h |  6 ++++++
> >>  mm/kasan/report.c     | 13 +++++++++++++
> >>  2 files changed, 19 insertions(+)
> >>
> >> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> >> index bb862d1f0e15..b6c502dad54d 100644
> >> --- a/include/linux/kasan.h
> >> +++ b/include/linux/kasan.h
> >> @@ -360,6 +360,12 @@ static inline void *kasan_reset_tag(const void *addr)
> >>
> >>  #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
> >>
> >> +#ifdef CONFIG_KASAN_HW_TAGS
> >> +
> >> +void kasan_report_async(void);
> >> +
> >> +#endif /* CONFIG_KASAN_HW_TAGS */
> >> +
> >>  #ifdef CONFIG_KASAN_SW_TAGS
> >>  void __init kasan_init_sw_tags(void);
> >>  #else
> >> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> >> index 87b271206163..69bad9c01aed 100644
> >> --- a/mm/kasan/report.c
> >> +++ b/mm/kasan/report.c
> >> @@ -360,6 +360,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
> >>         end_report(&flags, (unsigned long)object);
> >>  }
> >>
> >> +#ifdef CONFIG_KASAN_HW_TAGS
> >> +void kasan_report_async(void)
> >> +{
> >> +       unsigned long flags;
> >> +
> >> +       start_report(&flags);
> >> +       pr_err("BUG: KASAN: invalid-access\n");
> >> +       pr_err("Asynchronous mode enabled: no access details available\n");

Could you also add an empty line here before the stack trace while at it?

> >> +       dump_stack();
> >> +       end_report(&flags);
> >
> > This conflicts with "kasan: use error_report_end tracepoint" that's in mm.
> >
> > I suggest to call end_report(&flags, 0) here and check addr !=0 in
> > end_report() before calling trace_error_report_end().
> >
>
> I just noticed and about to post a rebased version with end_report(&flags, 0).
>
>
> >> +}
> >> +#endif /* CONFIG_KASAN_HW_TAGS */
> >> +
> >>  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >>                                 unsigned long ip)
> >>  {
> >> --
> >> 2.30.0
> >>
>
> --
> Regards,
> Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxMWXpfLs6HuKN73e0p61nm%2BQrZO1-oXphJpjZprKQVKg%40mail.gmail.com.
