Return-Path: <kasan-dev+bncBC5ZR244WYFRBE5M22ZQMGQEJB4SN5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 209439128C8
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 17:02:45 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2c79f32200asf2320499a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 08:02:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718982163; cv=pass;
        d=google.com; s=arc-20160816;
        b=dRhkT5592mFIhFLlruft/ondqLjDYX9+MnAQcYFadKVtGQ4TLfzZm8B0sn3TWHtHSP
         KPeedzZAnLyi/OxfWVFRGebRjktqHHOzMT0H/hUXCjYR0Isz6QHnRpNU67yVT7qwnbcc
         EkFU4SETFLyMidoGTv7zxTLLz3PQpN3UBv95M1/q2LIP5xHB8HuM4vl3SZ3O86jKyxC1
         ipW80k7Wdc2SV45Tp9Ig21TqV4NF4LXC+pfxu54wT2Cb//dBafU5QoXNLdSBLDWXoisp
         iNo0LrSc4uVJXGCuEsv7kk41jBx3OYEzRjSpvgD1nE2XqZs8sohk2qLqQeQ7ym08xmGx
         o7dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DB099Riflc1zQtcpq4KjAXpRp8TcFOGIJ2hzhxpbWkc=;
        fh=JpfuZmXAxd8JcuoYp16vENQEyixBkiiepmdXaNIRzz4=;
        b=OO1D7dkQ4kzpHiCGgHJzp5xAAFGbhlnVMNpr7U3AgUT1JsAIwxQ5T+we3QW8SpTbs8
         soTTeC76bV+/4m1CTWh37YYVwEm8MpK28MeCpZhW9P91MYrftR4aZ8A/oAPf6Q4Sbvjb
         4UXWUjqm0VxuwPELzzeoOXQvKLWR/qvBpPu2G/RdT40sAkeFzYSj45/oI+jyY65QJrNw
         065uP5V1IUHvYQrycw79GJprEjE/A8AjrctS84PTmvy34Q2UZ1qP3stpzvFVKRzZvZ6k
         1uUiXm55M0AYxe++17mqq6b6w5SApGB2Yw3OiQ9yPqwgTG+OcJjALQzr4F52b+NlA/9M
         1t4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GZK1x7Cf;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718982163; x=1719586963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DB099Riflc1zQtcpq4KjAXpRp8TcFOGIJ2hzhxpbWkc=;
        b=WjxcqklKeYulTrTMB4CYtTayBlPG3vwmB7OAagZUaapMDh/ZiE52jeyEhxZcuyAutq
         utJAPgraxme2AtbgqcXcmCG/jmIRnQqk8eisE5ev7Tv57BcAl1Txf6qb0nQ7achih+lO
         /zNMTgQ5eDf6KNFQwHgnnrdmYdtse0d/nPLUS2Z5wMtSe/rb9j6pZCAAJxZrUe8qHAnR
         NRXDpHMROHB2ahBUwXsSKaLe9a5ogY7eCb6oJktxjT5wKEsbpLortMYt0yAqCKmi7Kgj
         HiZi+nW5pvBkxAC29/xN+5GDKXcH9eMyPtFiR0er3aEMZ8NC/B1iBSd2KY/p+OJER2yR
         LGHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718982163; x=1719586963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DB099Riflc1zQtcpq4KjAXpRp8TcFOGIJ2hzhxpbWkc=;
        b=w58AdNP+tYXc8lvopXHk3gjHQoBbNOqUch3qVRO2RiaS9eE7LF4Iarrud7FluU1/9e
         VbeFrD06Ct/PHJyrdMVUESro/cyGtyurXKWq+X3JbMuJbLcBWO/WuYuwjDCvx2n/G2AI
         Eo+o73Mdug2jdZQ7MHEXfg1zxhPjbFK+4suRO2vHHYfjQQy1q3V8TiEyZ/HrQU0HoLtc
         CuI2xKNn2aWtFkWCQHYiCDQDgBSLD4TsD3ig6tN0wFe2mMnNurWPbhC0z+s5kLcdcTSJ
         W4qrc67E9e1UdeKF8xaV1BY6hhEQXJK/6NE3Nc3unt4R0/OatYMXDX8wTmeDE2oXOrNA
         qs/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjLozv4r2X+Dx7EuC+3i1Vus7w5o/ILH80yTR2DO3EfFMOHkQUsbkadtasC9zNTrYi0ky2jNPnRX3iqihff/8+4qgKuyD3ZA==
X-Gm-Message-State: AOJu0Yytch5RkZzbhPlTtfI1ntfXK5/RFoPAZr2AMc+NodXlgPfiOYd0
	39a8enrWtRL++aacb8IFNSQoWCFGamJuR7DAu56o8jROf41Tl1PX
X-Google-Smtp-Source: AGHT+IGremDEYgiiUGQ8kpJXDTINlL8GcxSbHF415v0IpWwaVpdjY2mNXbI+N2ZKPqJWgm18EgygPQ==
X-Received: by 2002:a17:90a:fe06:b0:2c4:eab5:1973 with SMTP id 98e67ed59e1d1-2c7b57f505amr8250749a91.7.1718982163338;
        Fri, 21 Jun 2024 08:02:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:194a:b0:2c8:1a7f:5bc3 with SMTP id
 98e67ed59e1d1-2c81a7f5cafls541941a91.1.-pod-prod-06-us; Fri, 21 Jun 2024
 08:02:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2Gwmq/qv/KVzHs0ddRc4Q5LplGVuZn1oxlPR6Tj/BRdE7AprFP2LHwXWc5Yz3Z4nP+piTt1YtLgUdAhs0zSbLrH2Vo2aQxXqmzA==
X-Received: by 2002:a17:90a:12c1:b0:2c8:880:776b with SMTP id 98e67ed59e1d1-2c8088078b1mr4160927a91.23.1718982160388;
        Fri, 21 Jun 2024 08:02:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718982160; cv=none;
        d=google.com; s=arc-20160816;
        b=mh3jvPmugjAmQT0IH7whVoavUG50k67cR/gbVhEykY0g0BZ2dyDZYCPplEmW8lvk9x
         Qkx3dPG5UsyIR6y5rDTefZBlGvP40OCbuK0iMs7+Oe0v/QVNutNtWFqaVghG1NGBuLm5
         EPfe4jMD4KVwMDmJl0GtMQr1JSrkUmYZVd129v+cKngppP4fM4qRz4xNNNT+stDWTxqs
         JzKMqfBeFVdkqrMgAsguqhp1oQG+Y+0c0qjdsKIu7BsopWw7latJZdOFue2w4TNMDz8U
         FwV+8FGncqXdJyev24S8micqhchtoqCgPkxglBTlsNxl8LY7ZKJPKl2sRlW9fQ5lrimu
         Mlyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jGtCNFiKVlOh2Lzw5lkNo8DBBMAZUtebvZnR2+XF38w=;
        fh=Rd0eMmseSGMPh9TTSECG001hqBGCl4V7ITo+N5A6yGE=;
        b=X6tVlyM5mMNUzVwxHANF/aabyKNm+ZKwpNTv8lqgmM/YT+WLpWT7igpzKjY+F3dA4W
         31zetn95iBxhWEjZbjzPLOUctVmMg6e9gSBqc+aBbZ0cU+vL+XCxehRvWdMoZbHWoABD
         Jn/q2ZGH9tit/czzCPesK9M/e4sMyytyLwVviRBQwaU/xoVat76AiWBl+rk0XiGn4RNp
         2RDk6czWyZrbmRJlju+6pUhOLVHqLJI6v51pciJxpHqM8/Jk36bBsia6klmvzqeNLEBx
         Yaj+BJPkDzFBmzmAmjU6QKq1HyxeBkwR0kB9Giji40gWM0gDr3vZi9xRAsepcaYgKspD
         OWBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GZK1x7Cf;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c70ac0dd5bsi566750a91.0.2024.06.21.08.02.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Jun 2024 08:02:40 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: q3kdAB9aQmGtgB1Wt7wv2Q==
X-CSE-MsgGUID: mq6neISBSmGsaSEVQSKv8Q==
X-IronPort-AV: E=McAfee;i="6700,10204,11110"; a="26705686"
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="26705686"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 08:02:30 -0700
X-CSE-ConnectionGUID: pHiuskksQ9SWgl8c9a5F+w==
X-CSE-MsgGUID: ncj+Et7DRFmffSWXyVPxCw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="42585370"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmviesa008.fm.intel.com with ESMTP; 21 Jun 2024 08:02:28 -0700
Received: by black.fi.intel.com (Postfix, from userid 1000)
	id B91E01D6; Fri, 21 Jun 2024 18:02:26 +0300 (EEST)
Date: Fri, 21 Jun 2024 18:02:26 +0300
From: "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com, 
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/3] lib/Kconfig.debug: disable LOCK_DEBUGGING_SUPPORT
 under KMSAN
Message-ID: <meity7zml7rsrf6lhlj6a33chvye7uipztqjbhgvqwx3sbyzoi@gh47yptppwu6>
References: <20240621094901.1360454-1-glider@google.com>
 <20240621094901.1360454-2-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240621094901.1360454-2-glider@google.com>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=GZK1x7Cf;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=kirill.shutemov@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Jun 21, 2024 at 11:49:00AM +0200, Alexander Potapenko wrote:
> At least on x86 KMSAN is seriously slown down by lockdep, as every
> pfn_valid() call (which is done on every instrumented memory access
> in the kernel) performs several lockdep checks, all of which, in turn,
> perform additional memory accesses and call KMSAN instrumentation.
> 
> Right now lockdep overflows the stack under KMSAN, but even if we use
> reentrancy counters to avoid the recursion on the KMSAN side, the slowdown
> from lockdep remains big enough for the kernel to become unusable.
> 
> Reported-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
> Closes: https://github.com/google/kmsan/issues/94
> Link: https://groups.google.com/g/kasan-dev/c/ZBiGzZL36-I/m/WtNuKqP9EQAJ
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  lib/Kconfig.debug | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 59b6765d86b8f..036905cf1dbe9 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -1339,7 +1339,7 @@ menu "Lock Debugging (spinlocks, mutexes, etc...)"
>  
>  config LOCK_DEBUGGING_SUPPORT
>  	bool
> -	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT
> +	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT && !KMSAN

Nit: no need to pile everything in one line. Add "depends on !KMSAN" on a
separate line.

Otherwise, looks sane.

Reviewed-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/meity7zml7rsrf6lhlj6a33chvye7uipztqjbhgvqwx3sbyzoi%40gh47yptppwu6.
