Return-Path: <kasan-dev+bncBCMIZB7QWENRBHG5ULCAMGQEXFTOG4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id AD470B14CF2
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:21:02 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-32b4ef4055fsf41268781fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 04:21:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753788061; cv=pass;
        d=google.com; s=arc-20240605;
        b=bV7icCuCRmmnjsUcWT3Vvdl9c/O7/DrENAgM24Jdw154hWqeFob9f+687e0MwWKe0l
         iKMx3gs+mwn9BpHYVgUdAFCBK/h3ctBl21aMEnvm8ljz/05C1BW9XOwG+l1TBErXcko+
         6ShlFtk9kAHHlpA+80JMjnjcYg7kkBwKwz/8eLA0Be0YrGV+dzAVMB9BRuLi3O42WX3E
         np9ID3WlWbqt+cFbb/dhnIDtqMfrs3IF1vW79ID2fDRdPyanCEpx9OgPV7ny//snrVyp
         HGngKNu3bVvavAFOWFcEi+QVn6Klu/sOavxHyDYB+Cu9mOdHOvC+hpoRLyGP3UVvKCpc
         vHpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j0xJnjIFq1wus4en7fQRd5lwn6nfoYvh9Db8vB8UQ34=;
        fh=Ls3swhq9k+MiC26NYGMwvMtPbZlWETIKQ/ANISmjYFQ=;
        b=dIQNw5LoGUdnuFb6YRGFTmzG9SjP/TJeXVlUieAHl+V53pcU8lCJ+dtF1nQrDZoHFT
         AXSMmoniFLMrnI+5AioLr6523lOFFjUEZHjYG/6/L2PYi4tl/SAhgGS3V0sZ2+wLU6fU
         mKACWATQAFYEyZlknripb+MKjXYKoi+5DEAtfoDYAVr7Wwqbnt6H/lF4pS+1OB7oUQbm
         fN7D3FEzwoAwQEQVyKrbx4rBQ9mNDJlNiDt0+gwlc/Vz5pMvQdsC7/mRXbQEpym1K4dS
         8rZdfpZvpZc8dATsGcv+wEZf7MywSY+wUbMvbOs2yPQdSa+kl7iv0g3GF+CP8FPzL46e
         fK2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ORKqUwY6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753788061; x=1754392861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j0xJnjIFq1wus4en7fQRd5lwn6nfoYvh9Db8vB8UQ34=;
        b=qWi4H4EU6wWA/DaCHSt1QpbOhbvaUNkHq8j7FkZ9qtboPPKks073/98dXcjJeycuxV
         f3429AEoL3M+po6QwhEF1VjCnGJF3h3Jhi6cdb0e4Jt6EqnXvej7A99MQWr6jCrcKKiP
         lxj0DenDTQ8kDXNxAS5hgyyh2FvPAZX8G7srBFTxbLWd6g/a4D2haNlo+/kc72n4JVXC
         Jh3x+HOPzs7nZE24m3Srgdj6ZpKlPCxjRHyoWPdxVzkvAgqmLWdL/joz4yELOF3bnBCw
         sSB4O1VSEOxMdaQus7NkhSLlj/yY6gdc7GfWuP1H+VNsQD3JTvNM1zJ6eBAv1OQRL0Mh
         p3vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753788061; x=1754392861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j0xJnjIFq1wus4en7fQRd5lwn6nfoYvh9Db8vB8UQ34=;
        b=uiRw8js7S8df77eG7Lqywze+zYkgFUR7gs1nxueLZaYJaUg2i5xSjTWGcLk73yYHFh
         mMwXmCIfdefRJ3q5Wq+vi7nthxv/nX+qiM/Gxp/dvpajh6WMdoaR6JnjZ0wxbwScj4dm
         AyJMZLGL7Y7SJUyTaDnF9yFXIrn/OUZSMTUf3Y6nGy/5ELe+b50Mm5ysPxFULyTeWiH4
         DnoM4msKhQSMIRN5I9y6ERbF47M5ftlaDD8vf8tPwADiyX7WQ8SKS7Q9wYV9tlSq9YIS
         H2YNsw7ZPxxSbZ5lqiQh7oRigOPY6QK3j8AMaORMg3sZeVVybemPOocQ3K4kEyy7wWsP
         UUfw==
X-Forwarded-Encrypted: i=2; AJvYcCWdxfKXRJF5jL+iyYAvQ03eDfxEmysJqKuTLs6jVwzKTBC0xSM5NrBEH6eDHRRBYnLlGBAi6w==@lfdr.de
X-Gm-Message-State: AOJu0YyY23Yfp/1gDksJXykeE2cHuw8aCf1kYQoDP3qZ1S14S36qaj7t
	PPEQcvq8J3EQCMVgDeFVFI3tHaaG5WKw4TbBc74/Kq8LvmEGHbnQXDU6
X-Google-Smtp-Source: AGHT+IF11LJz/oGk+ZUJjncpPakR9OMh5cjitD3tpr7dsqPvTtK16eLkC99qjOor2eOFLmmwwvV58A==
X-Received: by 2002:a05:651c:4104:20b0:32b:8989:eb72 with SMTP id 38308e7fff4ca-331ee78e3efmr32222181fa.40.1753788060848;
        Tue, 29 Jul 2025 04:21:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe4aj0A5L6ApTVgqGKsbaL6XNWw2dWZi+dQMaPTh38q0w==
Received: by 2002:a2e:a9a5:0:b0:32a:6991:c382 with SMTP id 38308e7fff4ca-331ddac2fa3ls14974321fa.2.-pod-prod-07-eu;
 Tue, 29 Jul 2025 04:20:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLNpLcaoFd305uAmZdslOf5CZ5BY5I4yIZAXHzNQPfR9BHIrjka1SsIqVBFLYChRxSpwowkuPc4ds=@googlegroups.com
X-Received: by 2002:a2e:a178:0:b0:32b:8045:7264 with SMTP id 38308e7fff4ca-331ee652140mr35870181fa.12.1753788057965;
        Tue, 29 Jul 2025 04:20:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753788057; cv=none;
        d=google.com; s=arc-20240605;
        b=kAAhEEXDFtMsG+bi5z8kJX6ao4xRe9Gan+xqME0tl7WXW1tRT67x50nlVFK2V0X9mo
         SCM10eJa70SE+ZRGhwybDHAreaDU2qvquFLx4YqEgmliaOLLVlrZqYSPqbj4vWWojSG8
         pxPbHiWF33HQhyhEbUjk/l9hN67ojlycT25/jGyC74GgqmhEehOMDXnAw8G54PDMrJYT
         ZLdHXUJuIJP8RhSYQEUm7l9KqjcvM6/6jtV1dnNcUcuH6PbDQqrce6vZrA5DIZAGVKmf
         GFwQy4onVSev/4GHhvQ0HhRVmm37Kn+RY3ZWIuKoFPOqfl6CCU+fY4qXFuO2mUMeJ5yQ
         U3PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aZGvUusdBUkFEqwrfYta8x6X6B0/cd+kHoZtenZK+Qg=;
        fh=zYFfGSHfVzp8z0bUp8QqIXGnCwx3qpPUPPNClQkiO4c=;
        b=Sm9wuGaKV9kjZZ9Xn07fRKjJ/XXBbmESkC4gr0nyfZy2PQzT1cceoa+dhNMwQq3wXT
         sGB4lDSwenURYRUhtk6xk2WyDZZkhOUlRqn4tG/roaCLq5q/NlJ1G2Lcdjj9oYQUzfbY
         qCk+NJ7L5sQbLRYBfOukcGXlauGXAqtRPeeJwC2yqw0STrSvsbWN687/YjFUrZpT9JhS
         XJ5dxgJ7ZQmGHoPAx1MHjmOMw6u47pqvpdUcgCKKxNXTkSGRmLPI5u0ni6WaR0G+9+At
         oAWvY93m/a4a7+gto2wb045efkYaoVzfZfWbNMGaytHbSwGrBKnPZH0YHWWZH/fznjJF
         BWDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ORKqUwY6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-331f4225c22si414941fa.8.2025.07.29.04.20.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 04:20:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id 38308e7fff4ca-3321de5c9d3so2198591fa.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 04:20:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrM6X9LYXA8E1rlH78h7zB4PQwifRNFNhh+YXlvzNDupTXCMoeufXg/HCp2epecAfJOl7TMv4ikVI=@googlegroups.com
X-Gm-Gg: ASbGncvmWR2kU3JHZSSrQLeKj7P97F8NdSADHpoLSq+6JpLAM6cLy2CLrdqgHBZKW4q
	1cdhAe88frXBdrUlG3xtcA+drBVdPo83bpTGM8t8xWnEEOTnXqNqUHmHNgriuc+stu/Nwc5y9J7
	2hvLRGHW4EXE63p7ly71XctJXofOv6kZ5FbSv+WDKGKKQISaAb2eJri88P0esstiTnUGTIxKQ6t
	UtGDoJWZZmKwfB8ruPafPwx5KHu8DhcXxnW43wZL8Bv75X8
X-Received: by 2002:a05:651c:1107:20b0:32c:bf84:eb05 with SMTP id
 38308e7fff4ca-331ee755392mr36538281fa.33.1753788057365; Tue, 29 Jul 2025
 04:20:57 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-11-glider@google.com>
In-Reply-To: <20250728152548.3969143-11-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 13:20:46 +0200
X-Gm-Features: Ac12FXxyIb_E3t0l8qtZ2HSqsI1hLPZphi9ZLVEqgdYyys_290qbB_DEIwuF4CY
Message-ID: <CACT4Y+YjtGOnkex3fc8Ugcqx-qYtjty45jgdD3AurFYv4Xq9hw@mail.gmail.com>
Subject: Re: [PATCH v3 10/10] kcov: use enum kcov_mode in kcov_mode_enabled()
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ORKqUwY6;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> wrote:
>
> Replace the remaining declarations of `unsigned int mode` with
> `enum kcov_mode mode`. No functional change.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> Change-Id: I739b293c1f689cc99ef4adbe38bdac5813802efe
> ---
>  kernel/kcov.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 82ed4c6150c54..6b7c21280fcd5 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -949,7 +949,7 @@ static const struct file_operations kcov_fops = {
>   * collecting coverage and copies all collected coverage into the kcov area.
>   */
>
> -static inline bool kcov_mode_enabled(unsigned int mode)
> +static inline bool kcov_mode_enabled(enum kcov_mode mode)
>  {
>         return (mode & ~KCOV_IN_CTXSW) != KCOV_MODE_DISABLED;
>  }
> @@ -957,7 +957,7 @@ static inline bool kcov_mode_enabled(unsigned int mode)
>  static void kcov_remote_softirq_start(struct task_struct *t)
>  {
>         struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
> -       unsigned int mode;
> +       enum kcov_mode mode;
>
>         mode = READ_ONCE(t->kcov_mode);
>         barrier();
> @@ -1134,7 +1134,7 @@ void kcov_remote_stop(void)
>  {
>         struct task_struct *t = current;
>         struct kcov *kcov;
> -       unsigned int mode;
> +       enum kcov_mode mode;
>         void *area;
>         unsigned int size;
>         int sequence;
> --
> 2.50.1.470.g6ba607880d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYjtGOnkex3fc8Ugcqx-qYtjty45jgdD3AurFYv4Xq9hw%40mail.gmail.com.
