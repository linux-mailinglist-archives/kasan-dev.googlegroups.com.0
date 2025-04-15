Return-Path: <kasan-dev+bncBCVLV266TMPBBOFN7K7QMGQEZON3WYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id E4C5DA8A559
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 19:26:18 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-43cf446681csf38221625e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 10:26:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744737978; cv=pass;
        d=google.com; s=arc-20240605;
        b=PCv1Hf+ZMxVrPyHA+0mOvwVcf87NdlCmpaQqLwmstQR6HWOce+BwVdgM8PaRAy0PIm
         custXewu52t3htz+l9qSeFwJnDAWxI5OKu3Lcj1yk6tqqDf9bz5po7NUGOKkFC9BZSQn
         owup9iXG4mSgRmarbOMYfGuIsRxj1zPOmDgCuerAE5p071/uVgqOqSWiwH3kJy3mmuER
         fnbBn/YB2m6a7vvDAWuFTJMtEX7Y5oQZrTrGm+/wnaFh1xX62Zv7WmmBeZW+6y5RoudX
         X9euCe/yCt56AcrfuqZQluUTIlPtNpHEo+JQupgqQg8QFsXdN61AkGPElZCUEX1PFaa7
         8/hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=r3AAh3/oqoI6cRae5glFsKNwcKS2YzSih22AxzefF3s=;
        fh=FG6Yxqoaq9RizQi/c1Fzmmc8XdEb7q4gwV8XNOHQDg4=;
        b=fHi7izoqvb1ZH9soZNWezc5ja8Uy0K/VkqhIoABxU1BXuLmJ+XPO4Todg86+zSSv3k
         jQev96YbiEhqjqkkIcqEtrAnE8tvjn2LSWTi+JyClSdYCqQ3N5klpAXk6IZodMHIBCtP
         SuFYAZ3fMJcCCAix+MK03ZESnQQxbOZCNXpJYUH5GBzgvtK6yVTMgQWupgEcYQnxkkVc
         f2kQhremfmy96fltCE6noS71xq0sCPxh6oZgNy99k3JPWrCuZKb2s6EB03T/iI+GjrsT
         9yxsNdW8M+BN8mzDsw2CYbKBOUrM/CtTkX7aG1qmOv/GOzunyF263rQYA2bcFa2h4cR6
         U2yQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gABXRHWt;
       spf=pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=smostafa@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744737978; x=1745342778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=r3AAh3/oqoI6cRae5glFsKNwcKS2YzSih22AxzefF3s=;
        b=tGE8AKMoHssWiHpHTHp/QrBj7Nf1nddu0vo6zX+8TkzuRCI6/v3YNlscIMsiSqklmj
         XUwiXJ8S55zd31BIVHhkQVSdukaCtcFEzbNGwGnVsvAGhnVrTfAMqZKQo6tPnvqj8MU4
         eXaC3w3cv8Nzc6iOVevISYrXhNu/0cARudgQHsNggcH3mo55OrllamOTHxGU0kSsPN/a
         PHkU8yaYclyahFe0tJnRKZAewJHqs1SACTR+ZYr5DFXBpgIKSFs4R7zVVGCbjSl0ta5z
         3XWJFOgX+8lWS7z8PXtBMeHPMBq+tptZJ4MbGvPXdo5E8GkqEIHRS1g2WAwSbjBNqEuh
         Lw+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744737978; x=1745342778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r3AAh3/oqoI6cRae5glFsKNwcKS2YzSih22AxzefF3s=;
        b=CP2/Cnoh+VzulmG44wBLomhzyheufbWumOfoD+RYauGb/UrVWJiHmOoIIWnWc5GYZg
         vj6rhDTlv75T2W5oNF1QNZvEbL+KDOwybPZ0k8qdGnLspbHPsE240R8tbnW/ZIH1As6/
         Ez/HiOuL7D+aKOh5hgtcSGcOkvbd0BvKikeq0udyBFKJMmATlZuu8u8Qhxabkkw465R4
         yd8dv3lFcoo0NqtR+7WDMqCVDdtGl/DXoz4cQoPjse2rv1jdxSuoRG5/VwQvlyhGa8zo
         wj9nrZmVQHaEfmIwasnHmcpmvRiOoUybEQdjZ3Hk9cSZe/zdhNZEFBWrcnneeXrCWV0K
         zGRg==
X-Forwarded-Encrypted: i=2; AJvYcCXC1FSLHlT5O7sd/uhkbqnYuTK/2DbnIRpwh2ETMPmnJFkJPfFtC8yW59FzuXqXz/CIyQXqaw==@lfdr.de
X-Gm-Message-State: AOJu0Yz8ZGXHLJFtUsJYrEE4DiNIz59fFpg1iLVNAZnYV0eqJGLckM0s
	Idsgly5xxbXuJ/zQe//wzyYnrG+9pLfMmUrg4TVO7AhTyjdgANjp
X-Google-Smtp-Source: AGHT+IGis9CNtcW0qUU3cc3HW47JW3O8bkQOVDYGCsMv8KRuD07L7dLwqCeBTHBOTgJ6Pin/4b5FkQ==
X-Received: by 2002:a05:6000:2586:b0:39a:ca40:7bfb with SMTP id ffacd0b85a97d-39ee276a1b6mr262653f8f.54.1744737977468;
        Tue, 15 Apr 2025 10:26:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIUnyJaFDN9VbzBRzWynn4z2be7xETU8vakfqugoddX4Q==
Received: by 2002:a05:600c:1f95:b0:43c:f19c:87b2 with SMTP id
 5b1f17b1804b1-43f2c26723als23467575e9.0.-pod-prod-08-eu; Tue, 15 Apr 2025
 10:26:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/oFBNZJ65+/ZfbK/+Sozp+ze32QZtKJbl+n0NlajUVgkpdGTHY1zqUM9kIsxoKa+R7oom7KHNkdk=@googlegroups.com
X-Received: by 2002:a05:600c:3591:b0:43d:54a:221c with SMTP id 5b1f17b1804b1-43f3a959e43mr161411575e9.18.1744737974615;
        Tue, 15 Apr 2025 10:26:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744737974; cv=none;
        d=google.com; s=arc-20240605;
        b=J660xdA0p8vfXGSk/YRMD7zNkvp+KFINtEVNJ6VP+gWkWazXVLr/oS4pYbe5J25mdv
         Ne79sgXIMu0EpstFwsC1FQwaQyIXBE1ieUbUbNl26T0BYXcZ0xNH2ZxrYgxE2vuv6QlV
         PjRxlYIDyrUQyePcWxuA3fYaMp9aVtq9tRKOlOr/W0kRVdBHuJu6/UIpSTiLbxIuWS5Z
         2MNb2OLpqUloTfcI2ilatDL9WjGmDp3NHrKDTL2JERRVCNJ+HRTeXRnOVWF1UgX/tpRI
         qCQhTZz/z0pghlwxbd9vQDntTR5a0O4qfRGC10+4yLnViurJQ/gBF57XlVQ6SYREDAcQ
         4whA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KWFMXVeKRJ+DP9uGC7jJBQmmeqwjnwUxPXQH0Ux5Ukw=;
        fh=IXPHqMf4C7VGX4V48R20kTxtNyhnbpHEM8auwrsgQvY=;
        b=VN4gX/Oni3T762l0imwMN4wuokkXiWJHldaq2GEFr1OhMU/Jxh42WXQqYME9NiTN+u
         HSCtOXufRwRzbp2FQF9RzN4eTzux4JCeZwbrpWnO6inDpBs12tt8T+8uFz8g4NNPwQAH
         Oea6CVdRS8m+RA0C56eZGAQgyCTsLaQBPJ2UKNbvl4Gc4r2xCUGzuE0QoLNNRw4ncPDL
         pW8q/WxHicZ9J5MisCbUS0WSLW2E7V6HOrjft3A40olw4lAmkrmYRdX1khO59BxL9+CI
         41DcqnG1G17uIpkQtdbcdx3ZFHjy5mFmwF/HeHebJt9Qfy0iy4ZxL0yQg9VR8RAf9mif
         OIKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gABXRHWt;
       spf=pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=smostafa@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-44051139dcbsi1270975e9.1.2025.04.15.10.26.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Apr 2025 10:26:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-43cfe808908so6325e9.0
        for <kasan-dev@googlegroups.com>; Tue, 15 Apr 2025 10:26:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVNUL49xDVYKThJQEl+R3tWj0fosv6R0wmetao+fZBZGBgQUZ0lFRHxYZPyxBuEzWTCBkZCcBH13bY=@googlegroups.com
X-Gm-Gg: ASbGncvRsT1PM4zeAVk/36/73oGaruVLqHKp8dfO1gzWvsGs6fOF6qngBgCwOT8QYUj
	DgzEBZc5KhvThWde7turGO3BeKX/0W07D6XnPaZJ/VE4wazLPGP7Qq72lTWf+pTksk9aTSuCJ8G
	UqJZR7w9OyritU0MiU+nG0vbzY7xaA72Yg/zCOWIv0wVaR1gRNRh+XMyS9zIV0iuDXKcVqUU62N
	4aKFL2AVZlCHzQx35Eyq8sPxgU9jCPdI5c/XVfJ+KqrGvM9okt9j3OTX+qWBi9EO/Fvr9RqC7ec
	/zsis7XuJK9PKckhs434WakNys9pTbEbYWhjobLljG0jO11RxhwAMpXjOn8QEfxCV9eLyLTBqWd
	2AQw=
X-Received: by 2002:a05:600c:4f14:b0:439:961d:fc7d with SMTP id 5b1f17b1804b1-43ffe57b0b7mr1742785e9.6.1744737973575;
        Tue, 15 Apr 2025 10:26:13 -0700 (PDT)
Received: from google.com (202.88.205.35.bc.googleusercontent.com. [35.205.88.202])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-43f2075fc78sm219997655e9.27.2025.04.15.10.26.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Apr 2025 10:26:13 -0700 (PDT)
Date: Tue, 15 Apr 2025 17:26:08 +0000
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com
Subject: Re: [PATCH] lib/test_ubsan.c: Fix panic from test_ubsan_out_of_bounds
Message-ID: <Z_6WsC9f0mby1nV7@google.com>
References: <20250414213648.2660150-1-smostafa@google.com>
 <20250414170414.74f1c4e3542b1f10c8b24d90@linux-foundation.org>
 <Z_4dXk0RlyXYuzYt@google.com>
 <202504151006.19150DFE@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202504151006.19150DFE@keescook>
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gABXRHWt;       spf=pass
 (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::332
 as permitted sender) smtp.mailfrom=smostafa@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

On Tue, Apr 15, 2025 at 10:09:00AM -0700, Kees Cook wrote:
> On Tue, Apr 15, 2025 at 08:48:30AM +0000, Mostafa Saleh wrote:
> > On Mon, Apr 14, 2025 at 05:04:14PM -0700, Andrew Morton wrote:
> > > On Mon, 14 Apr 2025 21:36:48 +0000 Mostafa Saleh <smostafa@google.com> wrote:
> > > 
> > > > Running lib_ubsan.ko on arm64 (without CONFIG_UBSAN_TRAP) panics the
> > > > kernel
> > > > 
> > > > [   31.616546] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: test_ubsan_out_of_bounds+0x158/0x158 [test_ubsan]
> > > > [   31.646817] CPU: 3 UID: 0 PID: 179 Comm: insmod Not tainted 6.15.0-rc2 #1 PREEMPT
> > > > [   31.648153] Hardware name: linux,dummy-virt (DT)
> > > > [   31.648970] Call trace:
> > > > [   31.649345]  show_stack+0x18/0x24 (C)
> > > > [   31.650960]  dump_stack_lvl+0x40/0x84
> > > > [   31.651559]  dump_stack+0x18/0x24
> > > > [   31.652264]  panic+0x138/0x3b4
> > > > [   31.652812]  __ktime_get_real_seconds+0x0/0x10
> > > > [   31.653540]  test_ubsan_load_invalid_value+0x0/0xa8 [test_ubsan]
> > > > [   31.654388]  init_module+0x24/0xff4 [test_ubsan]
> > > > [   31.655077]  do_one_initcall+0xd4/0x280
> > > > [   31.655680]  do_init_module+0x58/0x2b4
> > > > 
> > > > That happens because the test corrupts other data in the stack:
> > > > 400:   d5384108        mrs     x8, sp_el0
> > > > 404:   f9426d08        ldr     x8, [x8, #1240]
> > > > 408:   f85f83a9        ldur    x9, [x29, #-8]
> > > > 40c:   eb09011f        cmp     x8, x9
> > > > 410:   54000301        b.ne    470 <test_ubsan_out_of_bounds+0x154>  // b.any
> > > > 
> > > > As there is no guarantee the compiler will order the local variables
> > > > as declared in the module:
> > > 
> > > argh.
> > > 
> > > > 	volatile char above[4] = { }; /* Protect surrounding memory. */
> > > > 	volatile int arr[4];
> > > > 	volatile char below[4] = { }; /* Protect surrounding memory. */
> > > > 
> > > > So, instead of writing out-of-bound, we can read out-of-bound which
> > > > still triggers UBSAN but doesn't corrupt the stack.
> > > 
> > > Would it be better to put the above three items into a struct, so we
> > > specify the layout?
> > 
> > Yes, that also should work, but I ran into a panic because of another
> > problem, where the padding before and after the arr is 4 bytes, but
> > the index is "5", which is 8 bytes out of bound.
> > As we can only use 4/-1 as out of bounds.
> > That should also work:
> > 
> > diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
> > index 8772e5edaa4f..4533e9cb52e6 100644
> > --- a/lib/test_ubsan.c
> > +++ b/lib/test_ubsan.c
> > @@ -77,18 +77,18 @@ static void test_ubsan_shift_out_of_bounds(void)
> >  
> >  static void test_ubsan_out_of_bounds(void)
> >  {
> > -	volatile int i = 4, j = 5, k = -1;
> > -	volatile char above[4] = { }; /* Protect surrounding memory. */
> > -	volatile int arr[4];
> > -	volatile char below[4] = { }; /* Protect surrounding memory. */
> > -
> > -	above[0] = below[0];
> > +	volatile int i = 4, j = 4, k = -1;
> > +	struct {
> > +		volatile char above[4]; /* Protect surrounding memory. */
> > +		volatile int arr[4];
> > +		volatile char below[4]; /* Protect surrounding memory. */
> > +	} data;
> 
> Instead of all the volatiles, I recommend using:
> 
> 	OPTIMIZER_HIDE_VAR(i);
> 	OPTIMIZER_HIDE_VAR(j);
> 	OPTIMIZER_HIDE_VAR(k);
> 	OPTIMIZER_HIDE_VAR(data);
> 

I can do that in v2, although the rest of the test still
uses volatile, I can convert them in a separate patch if
it's worth it.

Also, OPTIMIZER_HIDE_VAR(), doesn't seem to work for structs
or arrays. Instead of using it per elements, I guess READ/WRITE_ONCE
might be more suitable for that.

> >  	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "above");
> > -	arr[j] = i;
> > +	data.arr[j] = i;
> >  
> >  	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "below");
> > -	arr[k] = i;
> > +	data.arr[k] = i;
> >  }
> >  
> >  enum ubsan_test_enum {
> > 
> > ---
> > 
> > I can send v2 with this approach if it's better.
> 
> Yes please, the struct is the right solution to keep the memory
> contiguous.

Will do.

Thanks,
Mostafa


> 
> -- 
> Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z_6WsC9f0mby1nV7%40google.com.
