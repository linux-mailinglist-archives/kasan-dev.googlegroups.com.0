Return-Path: <kasan-dev+bncBCT4XGV33UIBBR6SV66QMGQEXRXY4NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id AFDC3A31A5E
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 01:20:25 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2fa38f90e4dsf12842156a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 16:20:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739319624; cv=pass;
        d=google.com; s=arc-20240605;
        b=X74qOsJFWNn6zP/zyWr44Ib5MzmGduYjTrJDIRdW+/yi44203iJvyv3hN+LNunP9dT
         nTxQXXnvMBl1lV+AzIIZHf12WlmPCjvsM9lDs4a6aqCG+VBmCwUwoE177f3DAyKul//r
         fBXpWrLMBiE8iVQxCejRdqIZgzNQ4/bIQObzSmBtsQl+mOAPWBjq4vgxavTlaZaQUwtv
         fb2tiYMZ/8ZlTazNTkaPHTk1IkxunjCXP1Ty0uGW5vlh5QDWl9gUMBTWixhBcPy7NIaE
         NUaBw5qmI09CMwMCQxl/Y10Lnl0wRzaEAIDuS2TrLHGd4oo5MrhNeZYwyKT2W2KYQglE
         GBhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=G/RaJxIPvZ0r205rrPPf0A3p/GHQp+HJ4rJ2OUino4A=;
        fh=9/fcQHkXYoTqGLSQF8ZntFWjvOgguqgPD2a3FOh7Hvk=;
        b=elOMku5if5y6s5Lo5crckR9I1T+3eOtBHrYQXlr4oQaXWnOpBqKvGhnpkjpX//F8q0
         09/ngRT7K4zpowjMZdG7eGN0WMnlpt5KuwSFwH7+BvVM4e5G6uRWPBO1KiD/0J4f4gtj
         T/q9hkmlXj2jiF0SGSk9uifcl4DWbxMFX0bymT6bVeGdY9pwzFsRID4koGfUUSz07X2I
         H+FCXVHCip2YrKne+4nylk+qW8WMjSoFoulVWlx+v3UM/n9qfgqalUdIPXx0xFHAfmC3
         H1nmFwhMWgaQ1FfcRAqkcwsCesRSXJACeo7bFXJwXICwGZ0tsOmTQ9FVMUR1rrY8X3Wu
         an7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=18yKYkzu;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739319624; x=1739924424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G/RaJxIPvZ0r205rrPPf0A3p/GHQp+HJ4rJ2OUino4A=;
        b=xphnrhyQAK83P0PPwbvRS3yJUplv4yTgAK14M6OGLxT2l8Rbi1KhrguhX4Dp/nISy+
         aJYnLyuQ2xDUs8gcCu8Bz0kVR2nEIXxxTpyRHGKoSlw8qabGmsOH5F+NVkq97W7UcUbr
         ZgqKua4R7c7zMVf54ajNZYe7kyK4ohQFN2jkgzGoFmNmET2fRSA9A4cHLTzbwtyMe50X
         AP0EU7uDWl2fQJCVws56VeXcX3FUMlxoRfW2b+JAlaAoVSVMSz8YGHN8DN/jTnFAQvsg
         LESMYSWRI5jLBwhWxV0T1r3b8uqYx9/ptE2688uqOM8WG+GX2EWhDw2zuphaNSH8N+Ue
         YnoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739319624; x=1739924424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G/RaJxIPvZ0r205rrPPf0A3p/GHQp+HJ4rJ2OUino4A=;
        b=VdReGnlBHlij7uIlyOd5gSKtqEGjp/glTg+QEa+hUptapY/YQc8yS1eBDEr5K2F486
         yrctXKr2+d0i2qzGe0vcl/U0i94UK/VO/S1DLjM+sJo0y1ArGslUZ0Hvi03ompIShYSb
         GZ6KAEokun4eTZyj5t8usSSgVGS+RPm+InrpFynUJyO2+4YlKFb4R17BoJ+9tIrraZDT
         n4UtOWyxR6Tfun6QEYqHsnKGahmP0C2k/j8/tNlSOMpWz/1i43yLSKgAVCWO8DGm0Fhi
         qY4HYvHGa5pN4VM5TegNewxiGuqmhhGb/hrHadWdxIODGPZPs6iJX8AMxYj7cDTMIsdh
         Ekdw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVpMXxDbJ6+t36uY6J0FTzBQjmawal1IRY19ijRN3Z5V4BqUTL0i7mAJ8GzEy1cGKFoFue1sQ==@lfdr.de
X-Gm-Message-State: AOJu0YzlWS49hFXhr1xCDWVNh4Ol7pHJu1NLo/uSN+ZYNbWLdkmpHSSR
	7iDZZ89sevm8S2lGRduEm8BOWCDTUTgD0cBgc77TvoTN7+P6k7NJ
X-Google-Smtp-Source: AGHT+IFsTXL/sk1ZB8now9oI9hjnMzwdpWumTQmHwAgqTfVePn9AvpqBP6DPQaCKkN/EnJw5IYLlGA==
X-Received: by 2002:a17:90b:50c4:b0:2ee:ab29:1482 with SMTP id 98e67ed59e1d1-2fbf5c0f645mr1967415a91.16.1739319624113;
        Tue, 11 Feb 2025 16:20:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3503:b0:2e7:8a36:a9b7 with SMTP id
 98e67ed59e1d1-2fa228f2df1ls1161368a91.1.-pod-prod-03-us; Tue, 11 Feb 2025
 16:20:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVmegoq4gma2pljUQU0gQIkPdfFa71zoSiFdVd5DbVM4ZX+gu9lA5Ss8KYOGgInHc8WkW3XbVhszbs=@googlegroups.com
X-Received: by 2002:a17:90b:2e4f:b0:2ee:5bc9:75c3 with SMTP id 98e67ed59e1d1-2fbf5bb1cdcmr1711483a91.5.1739319621792;
        Tue, 11 Feb 2025 16:20:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739319621; cv=none;
        d=google.com; s=arc-20240605;
        b=lpNFXd0IbQuM28rQFVLTDtaOUwyAPX0HhIpZ9i1T5BPmRSD6YAcgHCKYM/K+U/w6hb
         nGjFvpa4zv48n+u5tf2SI1qiifr5+EL2TV9V8mOoV1A/ODMz52EBgcKpcHxof2LvHvbh
         0gkgkKLCP5dz9t4ytfTvsMbu9EuU1FazDHWGDqy1CV1eXb89ns3LIzxlK/xeUEwy0HyM
         TPSi0bYLCCYavOiBGCXbsOPmcsadkzrhRDtc9AQoorkkCnAxtJqJynEDk4hdM86HkcjK
         adVKafjckBOXqgyPyMSz95YVgeyHU4M3CWDiu6InUntbEZoDsR2XZoKZ9Mw1Am73s0LR
         w0FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tPZ1uG/ODu38Hxnlb3UJ9M5uW8tyg/wddV9PIuBuE1s=;
        fh=+Gql9DutV222yaCC9EicIsQY4xgtU05gGJLX4Or5wOE=;
        b=DfQIxi6Ofq7tnV2/dK8h9RqmEziY4aC0RWE8U/clXzu2p+hgVrSWgDWA4yeXey2Ds9
         bywgu8TwR1q2De+XT4erCE9i6YVjBRFq5qEI1Q4MkCfc1tS8mwslYqgIWAlOA0oiphvj
         e0SastA3BVopC+bLfZj2hHI2mIR9rCwn9MenBagI3ZBAUrK3Sy/3QpT8So82Qb26gwlw
         ODqIgTkwwht8oW1uMR+AkJBjpOmHau0i0sJQgmmF0yRFR0tDEra38j0PAxkuvIwLJeu/
         nuVPiOtiY6Rn0hVWAHeo+t8YJKaysixATCnmgfd/vWEoWy3vN1mBUxWl7K8DDTfvJEes
         Av3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=18yKYkzu;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2faa4b0e10dsi332396a91.0.2025.02.11.16.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2025 16:20:21 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7D4775C0183;
	Wed, 12 Feb 2025 00:19:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 548A4C4CEDD;
	Wed, 12 Feb 2025 00:20:20 +0000 (UTC)
Date: Tue, 11 Feb 2025 16:20:19 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Waiman Long <llong@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Clark Williams
 <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, Nico Pache
 <npache@redhat.com>
Subject: Re: [PATCH] kasan: Don't call find_vm_area() in RT kernel
Message-Id: <20250211162019.c2ce0583060cedbd5db199e5@linux-foundation.org>
In-Reply-To: <6b6c1245-f6ee-4af7-b463-e8b6da60c661@redhat.com>
References: <20250211160750.1301353-1-longman@redhat.com>
	<20250211145730.5ff45281943b5b044208372c@linux-foundation.org>
	<6b6c1245-f6ee-4af7-b463-e8b6da60c661@redhat.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=18yKYkzu;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 11 Feb 2025 19:16:34 -0500 Waiman Long <llong@redhat.com> wrote:

> > Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> > Cc: <stable@vger.kernel.org>
> >
> > but c056a364e954 is 3 years old and I don't think we care about -rt in
> > such old kernels.  Thoughts?
> 
> The KASAN report_lock was changed to a raw_spinlock_t in v6.13 kernel 
> with commit e30a0361b851 ("kasan: make report_lock a raw spinlock") to 
> fix a similar RT problem. The report_lock is acquired before calling 
> print_address_description(). Before commit e30a0361b851, this 
> find_vm_area() is a secondary issue. We may consider commit e30a0361b851 
> isn't complete and this is a fix for that.

Great, thanks, updated...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250211162019.c2ce0583060cedbd5db199e5%40linux-foundation.org.
