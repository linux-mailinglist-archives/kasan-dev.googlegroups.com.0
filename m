Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMOSUOWQMGQEEUDWFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 448F383155A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 10:02:43 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-598d67da1c2sf5145612eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 01:02:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705568562; cv=pass;
        d=google.com; s=arc-20160816;
        b=SyxWK028N+Q3ehhzOww7YOMOaJ2HQOjub8v7oyjlQr/rDdi0Y/508B7lZpCCXjQdcY
         oTI+s8JZLvs5QASELT3VeK8dOdJLcAply5aHlv78ChpVgnhoe1J4/r9QRKECh/GyVY6b
         dhsFwa18nSTyJbM98JoR5mZJRvXcN9jAyGIayFnWUNBoBQ1SB4Dn0ht0Ov8UyiXCGA/L
         CfpxssPa/8vKp5YvWngWWt+6UzsewaXf4nrMSqvBWKSrzC6Ves3nWK2PZMPLSYoVveBw
         vAAe2/Xz8dUw3ItFkwMqskLVpDehsPLl36ZNKeuGuoz0KxzCssBcfdtsqUlG4Oc5jA3B
         SnBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2CGOHNf5FNHSfAXMlbancanWRJSh0m8zc0pBV808kSo=;
        fh=mdrFOu/t4oI9VraqFSNvYd/kAt0kblfUIy3mhguPOs0=;
        b=WRN59FBPZH3b2QgQW2heuNuWNmnqRwZHrjYyCvUMwhnPZ2EszdQITy/SceecXc1quI
         Z2OKEKIS5/nHhdn8slwmoYX/SHuttgbk/wraPjC5KtGRDC+MDLi0ZMexBPLMjkC8z3Gl
         DC7rwsYfmJyhY4SzmphEjes29E7pWcc4opKbBc4eRXEzoIy+q8Hju2IS9A88gbIeLf/b
         U7qwBPnGnKItjJxeZaTrI/y6VjwF0GD8P/Gfdp3bRpfJa0SDAulmundReCXnphApVeBy
         YGlA93uDYH/0suz5l8Erp1cYZGazIwAjXUDlBnQZg2GgWSJf0/0GuPJwFDoDT+AhPZ9J
         vDTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KtNC6qSF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705568562; x=1706173362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2CGOHNf5FNHSfAXMlbancanWRJSh0m8zc0pBV808kSo=;
        b=YD5Gj0iqs/lgP/4t2RkI1cQnztLq08YVAuR1d8qZTTlY2XUlFzK769TDCHngUv6UD3
         F0PiQkfAaGl/J/fvDBLXlfB0BNkpXKqw/ISQcm5n9JvA5NAWvEV96BSY7WtDCfBWYDJZ
         //+ldBNh+cQKeWmxmVh+Ob014XeZ0GJYRyr+0IeXYDYhPKo9nG29byCtHKWTPaidA0pQ
         AxhzfFWUcdPBtN46ne54OlKYw5aGveM9mCnkHc1tka8LtbXotfL2PMPZrJz83N9DdYpm
         4s1WtlZKb9vaISrpCTM630xeDf3y9KwIBeRTriXp7roLqbvHsqlqtD0AbeffpUeh2nec
         Uf2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705568562; x=1706173362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2CGOHNf5FNHSfAXMlbancanWRJSh0m8zc0pBV808kSo=;
        b=jmw8TbQPi39UxBuj5dINcr76uaPx8NmhSalsAMtkcfl+TSxjnFYy7W+kIM9nF2YBzz
         35s4hPPDQK/1Z4AJXqAonYVcsQ5y5Olgwg5uLQPJiNVQzyE+UlPAhN5fYEio7TqauiN4
         x330tofz9MTtZrH83Q/wFdlZ2KbAg27pnTDPCGhOqL8qA5Gj6IZrp8WmuJEj1BWe0EGy
         Y27udn5iSrx6l7eydsXY02Gvr2/0jJoOX+WWSxNvOhxAGJOmeXJkw/gpuzbHb74shwYI
         L9x7Bjf1vdR2lHMt385MOpCjVqz4V9GDLuYQ/pXGbJV8ixG9hH8TK3F84rVtKu2K+Ne9
         Kbew==
X-Gm-Message-State: AOJu0Yw1lb5lDFoMBEWM9e65Tnit3BOmWGL/fa/FjrT6MgYF41I9Z1eV
	Nn5el4mUiSeFYmy7iXKyRIrqJYE4SF7QX4Hkpw9hSjJypDE0Ii0x
X-Google-Smtp-Source: AGHT+IFDlFo0GjkmhctGsFejDdFhe8HI8fA+4M1mr296MKngTTN1VzY46qJgLSWmcOO32xKBDzr4og==
X-Received: by 2002:a4a:b647:0:b0:599:103e:6cfa with SMTP id f7-20020a4ab647000000b00599103e6cfamr388563ooo.13.1705568561833;
        Thu, 18 Jan 2024 01:02:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:af02:0:b0:599:25d8:29ad with SMTP id w2-20020a4aaf02000000b0059925d829adls1914839oon.1.-pod-prod-02-us;
 Thu, 18 Jan 2024 01:02:41 -0800 (PST)
X-Received: by 2002:a05:6830:719d:b0:6dd:ef90:9336 with SMTP id el29-20020a056830719d00b006ddef909336mr580068otb.6.1705568560799;
        Thu, 18 Jan 2024 01:02:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705568560; cv=none;
        d=google.com; s=arc-20160816;
        b=gTsWreiS9hMn83fAHoO5b94tAgmwZTiabrf2YXU4nYO4f1B37zJc6ofvgSejw9E6U/
         WHnXx6V/E5lsU6r0zsQSIiUGFVH2JGzcfa6wERxmDU9EbSSMW63BESjXcWnQo+gwZwlC
         Mxo8ua0owHWzanNcLYVrPVBwbQPRic+6l+hjQvL3F2uaCgw2PishDatL0TOgoErFTRg7
         MgrJR1euf3DAOYCLMFUtghZ7NIQ9YbMRUDOlsyuFj/9cazJwkyvrFp+SnTK+JhL9+UZI
         mqHPyh6dJ+4Ntyx2yl70q5QuYPyKsnXKWrLsNOITOnnFzbsHjJQ8wV6Bo9wovtoA124j
         8piA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dZx8jkcSyxiY1OJQQRVdDwc9jw/KxeIOYkFsA2FOdyk=;
        fh=mdrFOu/t4oI9VraqFSNvYd/kAt0kblfUIy3mhguPOs0=;
        b=DmffG/rLXCyXwpk/IG+Ev8rARzGwhRbriQ6m4ZAx3nDO8srrWUHf0Voheju71gdEkJ
         XjUmVFr1JSpW/VGhmAtfEcqKBW/wWAG6hjiKSXxLkpu/LVZe58VwobsQTOU4TY5VzSFZ
         vlKp9W5h/VX7uOPHA1tQcTyxubV3F+LnKTcP87LchDPkEbWSP6rfBIp/anJkeZvGGWH5
         t3X9A9B601O2h9k9SCT7SLWcGNZN7gGeFb5mc91wCaG2f0slHPxaNJ176KopNfKf9IBA
         JhUW6CrGuQ/PnvKQWpCE0mHOfANt9tZ/RfBy3WlLXuLCSEZ1kSsH+NmnDkoN7XsQcP6e
         3lDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KtNC6qSF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id dm7-20020a0568303b8700b006dbb6f37f29si92728otb.2.2024.01.18.01.02.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 01:02:40 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-6818f3cf006so1619176d6.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 01:02:40 -0800 (PST)
X-Received: by 2002:ad4:4ee1:0:b0:681:86fe:6fc with SMTP id
 dv1-20020ad44ee1000000b0068186fe06fcmr477337qvb.116.1705568560115; Thu, 18
 Jan 2024 01:02:40 -0800 (PST)
MIME-Version: 1.0
References: <1697202267-23600-1-git-send-email-quic_charante@quicinc.com>
 <20240115184430.2710652-1-glider@google.com> <CANpmjNMP802yN0i6puHHKX5E1PZ_6_h1x9nkGHCXZ4DVabxy7A@mail.gmail.com>
 <Zagn_T44RU94dZa7@elver.google.com>
In-Reply-To: <Zagn_T44RU94dZa7@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Jan 2024 10:01:58 +0100
Message-ID: <CAG_fn=XcMBWLCZKNY+hiP9HxT9vr0bXDEaHmOcr9-jVro5yAxw@mail.gmail.com>
Subject: Re: [PATCH] mm/sparsemem: fix race in accessing memory_section->usage
To: Marco Elver <elver@google.com>
Cc: quic_charante@quicinc.com, akpm@linux-foundation.org, 
	aneesh.kumar@linux.ibm.com, dan.j.williams@intel.com, david@redhat.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mgorman@techsingularity.net, 
	osalvador@suse.de, vbabka@suse.cz, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Nicholas Miehlbradt <nicholas@linux.ibm.com>, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KtNC6qSF;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as
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

>
> Hrm, rcu_read_unlock_sched_notrace() can still call
> __preempt_schedule_notrace(), which is again instrumented by KMSAN.
>
> This patch gets me a working kernel:
>
> diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
> index 4ed33b127821..2d62df462d88 100644
> --- a/include/linux/mmzone.h
> +++ b/include/linux/mmzone.h
> @@ -2000,6 +2000,7 @@ static inline int pfn_valid(unsigned long pfn)
>  {
>         struct mem_section *ms;
>         int ret;
> +       unsigned long flags;
>
>         /*
>          * Ensure the upper PAGE_SHIFT bits are clear in the
> @@ -2013,9 +2014,9 @@ static inline int pfn_valid(unsigned long pfn)
>         if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
>                 return 0;
>         ms = __pfn_to_section(pfn);
> -       rcu_read_lock();
> +       local_irq_save(flags);
>         if (!valid_section(ms)) {
> -               rcu_read_unlock();
> +               local_irq_restore(flags);
>                 return 0;
>         }
>         /*
> @@ -2023,7 +2024,7 @@ static inline int pfn_valid(unsigned long pfn)
>          * the entire section-sized span.
>          */
>         ret = early_section(ms) || pfn_section_valid(ms, pfn);
> -       rcu_read_unlock();
> +       local_irq_restore(flags);
>
>         return ret;
>  }
>
> Disabling interrupts is a little heavy handed - it also assumes the
> current RCU implementation. There is
> preempt_enable_no_resched_notrace(), but that might be worse because it
> breaks scheduling guarantees.
>
> That being said, whatever we do here should be wrapped in some
> rcu_read_lock/unlock_<newvariant>() helper.

We could as well redefine rcu_read_lock/unlock in mm/kmsan/shadow.c
(or the x86-specific KMSAN header, depending on whether people are
seeing the problem on s390 and Power) with some header magic.
But that's probably more fragile than adding a helper.

>
> Is there an existing helper we can use? If not, we need a variant that
> can be used from extremely constrained contexts that can't even call
> into the scheduler. And if we want pfn_valid() to switch to it, it also
> should be fast.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXcMBWLCZKNY%2BhiP9HxT9vr0bXDEaHmOcr9-jVro5yAxw%40mail.gmail.com.
