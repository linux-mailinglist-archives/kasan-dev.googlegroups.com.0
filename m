Return-Path: <kasan-dev+bncBCMIZB7QWENRB3VAUS4AMGQEUT3YWDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 1700699A2F8
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 13:48:00 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2fad27f65bfsf15941361fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 04:48:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728647279; cv=pass;
        d=google.com; s=arc-20240605;
        b=ELFd/YsemZw0bT5/nJqtHKYFDB2h32t9mD/RjCHwKBrgjcGkMjBQ2eOZn3JIL+MlvV
         yKGG2Ns4HXaexYL7mKnNM5pK+KL1ZSPVoGXYk7WcjSSVXkUbXHz82lTzbkv7vLFhEY1H
         48XIJX5MIr9Wfh+Yaeqnqjb8L7niINtQDiwV6wBka1hKRIYAqv7+/LVifRPYJ1TsEtn/
         AcC/JhvcRZfJmAsfcodu/9MmyzpGfFc0sYGjQ3WUM6/YR4loO/+2W7rNs+miTv0j/u+F
         zir7zP/ml8+3u6i8gMjTa0lwbm15d9VLeWKbJ4ClVL8a0KYJ58w5/WzGxXTERMGMe9ow
         V6Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HTG1Pw+oJeoquTpE1kAlVuNIoYhCw9u9fCOnywetz4g=;
        fh=LFsVGH9lQOnv/XGoZRTcPrk/GwtDuJO7/v01SXgcqdA=;
        b=T7GybmILTv4VFDj0UGBJJ0BLk2s7Iurvkpz7NpcNX+jri88t6v2Xm0HYtqlR6LYjIN
         ttJdaP3wvU3emOrKBzqezVBhDtJTlraD+SYGcoHBYWwDh6apX7azxnMro0hqCvT0014k
         MYL9LUXb5Hl1dytmMPnJgBli1o4hHZ8LvUcjd4m2hxbUY3ckdV+6NB1YzwZO5pZ/eGDv
         jiE8TOsZHV2uwv5QFMRUHolMqyxDen0BmA741ZecztCzE0jxOj29g7GQ8PwTHt3c2oPs
         rvd3+TZWKwBG7iDS6qJJxp9EkZMdXo9G3voghrZ8bgSyN+r9PCLRm4Npm7d1t6qWFH26
         BorQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=W96SiD1S;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728647279; x=1729252079; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HTG1Pw+oJeoquTpE1kAlVuNIoYhCw9u9fCOnywetz4g=;
        b=KAdv886W7lD0/K6iTnLcwy6viTcKZwGe+x29/HJ33oEqR2kWaSh56YQ1swEGkLXnoO
         MFdrKwqSs1/iopEo4xCzgIUhPCFz0e9zAnZhEghUQsgtmvgVMYdC6m1XqbtlQRl2Mamy
         fkWvhyhl9MOqAll+SO6hHGM/yi9iu1qG/nFSNGAKgZxk3lIBFvyf7t7BW3xZSPPOHAJ6
         yo9ojAlbkCjR2lPsKMFdcKcIy6yRSr5Oqi7Owi5Pn7koX74YnzJtJqUjxpoQOf9TYGWJ
         YyfKwPqK4Qw5Rmf3sq5qsNbr5nBmNAYeaA10H0jhszyVPk1wwcAdJDcjJkJzIlegv2M7
         xCfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728647279; x=1729252079;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HTG1Pw+oJeoquTpE1kAlVuNIoYhCw9u9fCOnywetz4g=;
        b=l5Ppt0aXegJ5Z0nrOZoIq4yWDDzJOVy1vw6e+QvWb4396/dGFWSaLdS2R7FvPQSwkz
         DDyQgIbOJyCf3F4T8F0KI+td2NAaFcPv35pjbByFLHiff+WMfPenQ+kW1lakonzvSUYj
         mgakClpVvTmF9Wp9tJQqD1wIkwmcawRO2bvSWwNdLR2shszEHmYBAFIa+OcefGa8ayBi
         C/0r1EJ+gC97GzHyggq9FnkZvcGJOK3M+YEII0OS9lksDsbuFDplppwCkCYZ+K7Ttbuz
         YMiUSuJiQlbkBwGXzqAcrrsChhXxemhi8FSDzsYA9DFwfszGa4VImkxJsNtYTl+Ghk66
         ZlrQ==
X-Forwarded-Encrypted: i=2; AJvYcCWSdoI8GUx7iTbVFcZUF+qFVh9wXJONHNV3WKKnTuoev/vNrFME3ork2yj1MtSwVzwRDcNTiA==@lfdr.de
X-Gm-Message-State: AOJu0Yy1W5bnFLZChdgTMbop6Wt7tsj8GCq3REKzOhAMrcjf4o1WC/mV
	3D7lBIU1Q9A7x7RqiN126HGBH+kCV+wZgExaWR6V68/TGoNcmRh7
X-Google-Smtp-Source: AGHT+IHd1Y4yqOUH9T0NbLhDoYKgzanHZRAbD/6204W3G2LQZDWPDzpqBrJty4bZUIfuKgoe5CjFtQ==
X-Received: by 2002:a05:651c:221b:b0:2ef:2cdb:5053 with SMTP id 38308e7fff4ca-2fb329b5496mr9618571fa.37.1728647278505;
        Fri, 11 Oct 2024 04:47:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f11:0:b0:2fa:c1d3:edd8 with SMTP id 38308e7fff4ca-2fb21262d8bls6590431fa.2.-pod-prod-01-eu;
 Fri, 11 Oct 2024 04:47:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVkTjIMRUr7UhdatdGD8xCNk8lw0GNYfte2h6f/xePdP3nqcVhYxez+S3x7cbNqMBNNWs6pQhCFyo=@googlegroups.com
X-Received: by 2002:a2e:80a:0:b0:2f7:7ea4:2a1e with SMTP id 38308e7fff4ca-2fb327b5608mr9500961fa.28.1728647276504;
        Fri, 11 Oct 2024 04:47:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728647276; cv=none;
        d=google.com; s=arc-20240605;
        b=kbwUhibZVqDen8t4JEXWxsmWoLXoc4YoWvPeD9QbEmVG0EnncDIK2LPsSypSgXQTgR
         padRgojHJ56D2i9/c23m9dlkImccSXl5KlpuXHeYOpMghzJGcUWMXEHCAcOrDMhwXnx7
         hPgXmgTtVKMZScc2RdFZgyzh8LTBGr4m/Rv884gcJzoNezi+5e74UVGk7ukW7nOc2BvX
         AdY7CVZSRHV+/xvDg13RjOIG7cZgk3hbIvWaQA6cWyc7468vm9B9MdqCtK2vQBE0XTSt
         y2caE1DpVKq6v1jMbp+0Ro3bCwKIHFZDSefjnGUcJu1BzIEPZqdZxwWnPaBAFEaHY+z+
         5/hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vqfE0b2kghW+la5PW6I2qXSzxR7wAN9/SBpobg5HUto=;
        fh=5Px4wcj5wytTqgBv5WDnAWYA3bTOO8U2cCzS3FOWxP4=;
        b=gnKNAd5ut5+y+cQX/dzcoCmjmxWrhBS0WMItgW+nO+/vT184LJo3E013MdKTmXaDDT
         EaWkCc0DV6yF8Zr3VzmpBDeuco07HbllP5RLzmP+RZfePBvD6xHNqj4ELK738GPGRHvj
         nnKvm7Ldg8M1RXDgq9mcTIvMfE6px/dhEBMkOR4+EM542HuE0NnAdTqN5t91A8RrljtZ
         RXGUbtojTWILkVOjoHiVf2BL8hagWNApJno418MWgr2ubpZn/3kgoNtuKDASUaE9oJoj
         fNAx3Y9XveiYgHcyHgqSF3KJ9kQ3OtTp2OGpIIB9AreZTgA+KWABRqAlbjK7kBlxet2k
         Ek3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=W96SiD1S;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb24706405si580311fa.4.2024.10.11.04.47.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Oct 2024 04:47:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id 38308e7fff4ca-2fac47f0b1aso19768041fa.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 04:47:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXocv2Uz0BVFJfjt+btnvgBM5YqH2fUZm2Dhx/Iw7VPxZOLRF6V2t3+g6r+H1eTjCU/aXZz1ueB3VM=@googlegroups.com
X-Received: by 2002:a2e:131a:0:b0:2fa:d84a:bd83 with SMTP id
 38308e7fff4ca-2fb32770fbamr9707871fa.24.1728647275817; Fri, 11 Oct 2024
 04:47:55 -0700 (PDT)
MIME-Version: 1.0
References: <20241011114537.35664-1-niharchaithanya@gmail.com>
In-Reply-To: <20241011114537.35664-1-niharchaithanya@gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Oct 2024 13:47:41 +0200
Message-ID: <CACT4Y+a=c3qOb3eW-CWbdjignJg0WYvZcPhP63RRekF0sHqVDg@mail.gmail.com>
Subject: Re: [PATCH v3] mm:kasan: fix sparse warnings: Should it be static?
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: ryabinin.a.a@gmail.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, skhan@linuxfoundation.org, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=W96SiD1S;       spf=pass
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

On Fri, 11 Oct 2024 at 13:46, Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> Yes, when making the global variables kasan_ptr_result and
> kasan_int_result as static volatile, the warnings are removed and
> the variable and assignments are retained, but when just static is
> used I understand that it might be optimized.
>
> Add a fix making the global varaibles - static volatile, removing the
> warnings:
> mm/kasan/kasan_test.c:36:6: warning: symbol 'kasan_ptr_result' was not declared. Should it be static?
> mm/kasan/kasan_test.c:37:5: warning: symbol 'kasan_int_result' was not declared. Should it be static?
>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202312261010.o0lRiI9b-lkp@intel.com/
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v1 -> v2: Used the aproach of making global variables static to resolve the
> warnings instead of local declarations.
>
> v2 -> v3: Making the global variables static volatile to resolve the
> warnings.
>
> Link to v1: https://lore.kernel.org/all/20241011033604.266084-1-niharchaithanya@gmail.com/
> Link to v2: https://lore.kernel.org/all/20241011095259.17345-1-niharchaithanya@gmail.com/
>
>  mm/kasan/kasan_test_c.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..7884b46a1e71 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -45,8 +45,8 @@ static struct {
>   * Some tests use these global variables to store return values from function
>   * calls that could otherwise be eliminated by the compiler as dead code.
>   */
> -void *kasan_ptr_result;
> -int kasan_int_result;
> +static volatile void *kasan_ptr_result;
> +static volatile int kasan_int_result;
>
>  /* Probe for console output: obtains test_status lines of interest. */
>  static void probe_console(void *ignore, const char *buf, size_t len)
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011114537.35664-1-niharchaithanya%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba%3Dc3qOb3eW-CWbdjignJg0WYvZcPhP63RRekF0sHqVDg%40mail.gmail.com.
