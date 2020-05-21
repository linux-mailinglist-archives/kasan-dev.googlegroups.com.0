Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBGHZTP3AKGQEZNFIK6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 2888F1DD9F8
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 00:11:38 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id k23sf4037288oiw.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590099097; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZSvsJhlgJKwmIvj39c2t+tADpKjDpKJK0aVTJJlFM/DPwbi5pllZxWEnVJrEMRvZ9N
         2kUc2PvUWFRbAA0I7SEnequSlBHV5nY0lg6rixAHrYPa4/TR2CKSHGZXfHlajHznXBlB
         +y9WAAb5baG63rFrvCsq/6zhM1YuVjHkgRxpwspE75cJy3ZGaGdDyOB21YvNIF6kfUjo
         b1Kmb5rjA6+slnvjHISBLh4JSmhibcaZBODHJjVwHUCBYsClpJqgCHlqLz58VcCeqwfB
         +NGJG0GnFZGKqz1m+FNiSRRABjE+U6U0bYARf78fjy9mQ4xKccAoIapBFbz/5BT/IWE7
         /UcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yTXiW7AxIUiyXEQ64cl19RCGWCsRZZBLbhk6MqPkjys=;
        b=tKVPY63k75s9g300mc7AHtl0MMIvXG3ma1q234e1GxRRoWpb5wCB1KtohJC9djKvlS
         DuF4hciT1N9HW9GlswXFjNf99ruw2aXtbkD/Yk9f0g3I/HKWdP1SlMXVuAJpAq7jynPs
         f4brdqTR5GU7lhyvjvdtV7vBgcl1cdcOyi77Ot7IT0F2Ywrl6Ecr+Pca8fBNaUwRv/AN
         fSqj302zQFNwGR5l1qln35UlNpQ6m84EbDPMKciP277fIIciai8BfxuoaKqLyNAo+EKQ
         jh+yzZ/gSjFDg/349Iy/ca7IF+Zz5OiBj/FLa78c9/XaVSLQ0QRjEmaDs+q9uO2Pf+VA
         wfKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hfbS9LZx;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yTXiW7AxIUiyXEQ64cl19RCGWCsRZZBLbhk6MqPkjys=;
        b=TpTx8kPiN7M6NqKyDLi6FWtrXum6QR1Wr9hhES0laiv0sZz6NXdUQEOc2nyRylBuvN
         W0AgNc5bYcmwxl16tHD1l2XxCrKlwJL7ar8zDAidckKJs37AwPZytwKgtpgfBme1o5oc
         Kx5wSXfUittC7rMlQEhmpvicg8iaMbk0mRTsZq7IyMn+YGrlFWLttVvpDGW4g9bfmMtj
         88K3kf2up3CmQ1uXFGET5ctA7dtiW0DDh+ovHFuDpHRy/D1hqm1/Q857hsn33c6nS28S
         ajM/InZ7N0OlftVvfPSwLDwIFHKweKOoxtYLCWe+fHu66syg3cnEmuxQAvmCR2gpAJth
         o2Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yTXiW7AxIUiyXEQ64cl19RCGWCsRZZBLbhk6MqPkjys=;
        b=VWv7nsuKAvY1B3v+9Wylxqq2maw54QoBLLqJ6o32T7JZDAg6cPWhpwk6eNwFBUaWgq
         7bkHiWj5GHDvN7UF4LPoEIzEzOAU7tUN7N16uVYaCu9HNpvxCxd46VAU14EMV8utBCk+
         aizrAJeg1ZMZcIyeakJ0XbqmYUGh2Ev6pd8k6mtdyM4dWTvH/Y8wkcl358pajkC7eXFY
         qjySjuiBh3bXCe+INZ0sT8tjAaECmkL0vY4ku1SeHe2M1Qhlhx4W1XPSwpe42rsHUkuX
         GODcfh9l4VzEZu1xERBLUr4pkfrhcz+t7qmi+fvlyBm8NkmYwI29E9lAvH+yhyVaaN5F
         TxeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jBAz7Ht360JfiPGz/zzgVKQr6k1veLEwt86x7/gKGo9qOj+SG
	vnQkfMWzFGxeqFKWyXFhkbg=
X-Google-Smtp-Source: ABdhPJztjfrfgOAk3p/Rgj8DVxBOIAnUy06wR2ewl1LL+both/5ZlLlMcbVDTX5K3iAJqCx+yD34ew==
X-Received: by 2002:aca:72ca:: with SMTP id p193mr607763oic.34.1590099096799;
        Thu, 21 May 2020 15:11:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:731a:: with SMTP id e26ls738266otk.3.gmail; Thu, 21 May
 2020 15:11:36 -0700 (PDT)
X-Received: by 2002:a05:6830:e:: with SMTP id c14mr7510286otp.300.1590099096228;
        Thu, 21 May 2020 15:11:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590099096; cv=none;
        d=google.com; s=arc-20160816;
        b=Qsg3K970gfdL0992enCXdA9XI5uiTyJuFHtF+ZA/EIZuw1g4U+xslNJq7RqcJPn0gx
         WNyYrdNe+DYnqX4sNkJxcKDf19dY0ni9n4UdrPbYhkLGlA8gbmjhlO2JN/0IigtE6zjT
         GGfyISZt8S0B1W13ia0XRuAVmxxdg6heVrus/9a42PrMojUNtgeiN6IEbcsfM88mSqYY
         sbxJnUdLPxGQHAkfSIfilchnMBjupXXKyT4+XJRYhMIpSKcGIcqyV9AmEIWBkUTCVzo9
         mGJGSwgyzxxvGa4LS0XWa9xLiXQG7wSQeSzoB9LDpaazJe94lCr9jiK8jZqAvtlsZ7x2
         ck4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kocdT4g9nbRMGVt+gTfNYp2kFlQFGidtfQ3ppE7WaVg=;
        b=INM5F3HlDlEwpq/k6JyGOYioVsEQ71/RM0m8oi9kOs12qmEIZ/jZJ3fReg36awxQoa
         riSS5vASmBM57zdb1P4SFK4y1FfqzTos4LalepKjvey/9gO1Kw1OdDkmzxSYqJhYcXP8
         myglO00ID2E/HA+M6dhBUKIjqIOxTUaAxO/W7Akah3GnH0Y3ZeeqY90zzIA85ikx3Zec
         dIr3MZBi7mpwO08KGQGvokUWbK3syaWkKHipZ9oIU/J4ay//EKuKAciJXr0hxX6LacWg
         2sfTWmc1ild9kULCVIwjTKUDvDjubbuNG3lkPemYS+FaT2AicL4eDW6hRksWOm3bgnXS
         06wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hfbS9LZx;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id u15si618965otq.2.2020.05.21.15.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 15:11:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id fb16so3853993qvb.5
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 15:11:36 -0700 (PDT)
X-Received: by 2002:ad4:4145:: with SMTP id z5mr884054qvp.29.1590099095680;
        Thu, 21 May 2020 15:11:35 -0700 (PDT)
Received: from ovpn-112-192.phx2.redhat.com (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id o18sm6452090qtb.7.2020.05.21.15.11.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 May 2020 15:11:35 -0700 (PDT)
Date: Thu, 21 May 2020 18:11:33 -0400
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	aryabinin@virtuozzo.com, akpm@linux-foundation.org,
	linux-mm@kvack.org, kernel test robot <rong.a.chen@intel.com>
Subject: Re: [PATCH] kasan: Disable branch tracing for core runtime
Message-ID: <20200521221133.GD6367@ovpn-112-192.phx2.redhat.com>
References: <20200519182459.87166-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200519182459.87166-1-elver@google.com>
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=hfbS9LZx;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f44 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Tue, May 19, 2020 at 08:24:59PM +0200, 'Marco Elver' via kasan-dev wrote:
> During early boot, while KASAN is not yet initialized, it is possible to
> enter reporting code-path and end up in kasan_report(). While
> uninitialized, the branch there prevents generating any reports,
> however, under certain circumstances when branches are being traced
> (TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
> reboots without warning.
> 
> To prevent similar issues in future, we should disable branch tracing
> for the core runtime.
> 
> Link: https://lore.kernel.org/lkml/20200517011732.GE24705@shao2-debian/
> Reported-by: kernel test robot <rong.a.chen@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/kasan/Makefile  | 16 ++++++++--------
>  mm/kasan/generic.c |  1 -
>  2 files changed, 8 insertions(+), 9 deletions(-)
> 
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 434d503a6525..de3121848ddf 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -15,14 +15,14 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
>  
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
>  # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
> -CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)

mm/kasan/tags.c:15:9: warning: 'DISABLE_BRANCH_PROFILING' macro redefined [-Wmacro-redefined]
#define DISABLE_BRANCH_PROFILING
        ^
<command line>:6:9: note: previous definition is here
#define DISABLE_BRANCH_PROFILING 1
        ^

This?

diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 25b7734e7013..8a959fdd30e3 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -12,7 +12,6 @@
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-#define DISABLE_BRANCH_PROFILING
 
 #include <linux/export.h>
 #include <linux/interrupt.h>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521221133.GD6367%40ovpn-112-192.phx2.redhat.com.
