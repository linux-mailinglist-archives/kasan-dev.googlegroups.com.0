Return-Path: <kasan-dev+bncBDCPL7WX3MKBBMNF7K7QMGQEVABXEIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CC3D9A8A503
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 19:09:06 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3d43d3338d7sf73177925ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 10:09:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744736945; cv=pass;
        d=google.com; s=arc-20240605;
        b=WXM/R9Vp9ZlkJm1Nu3t2UUQelmK3kdPqycCzhYJIJQ1JtuqRT7qNIyiXk+WHAMu7DY
         0aYY8Bdu4FBz5OuPsDt6zZdLZEJ4o+Ope7UDDdd+JNlo4eX1Augy3wsfGSbzoLvorI9J
         EyqYa4SG2FPJsZwmWBhNyxrEkCYraD7aYnePLjyru8MqBE5nh+VM7q/KgM54pc3839/x
         zteAq8qIbguflB5+ieMn5OkFp5QrOM72MMXTDTq2Sy30KzhXrFHZeIB+ta/f6VGIW+P/
         Hc1/kIbGCVHe9jCaPu1tUzKI0BZpBrZU72wm0SuiTDZWqiXNLpYHgvaj+pho/WlZbIsz
         eN2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OfmweZAb1i2xfQ/C/VzQihfq/B4O4dlfWsH71b3v+yA=;
        fh=BOBmgvj+ePQ6iE3jFcTDqIgKxDiUS83zTUMRueyZ0BU=;
        b=ClA4fplVPDuShmJJA5tHuXlCGr7zSU90GA7t+pGm/TlboHkwqwqtjAzALyBQTWYi0Z
         pkMT1aoLNBqq+eYCg/XbtNSW/LhxTAGoOm85bghjmyhtQ2Z3wvlWmHyLzMlvp0Oz5fwn
         0xHFSvVOrkPmF4xeSq8dwXgohNP69Zpq2rDYfB+BXX9ndC0TsO8S/D6akuzO5JkxFRIy
         ce2wOVzrmEY3M3Oxm/wQj0i9lF4nO9hxe/tsFgc7ynHjo4ISTY8nsfe8a7uNIPLjXRxP
         +DYKSW0Z1xoLaAsmBNm2VTStBDQSLqTucuxZn6vasFkKYak708jTpf82zrvB066cbeZO
         1VLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=awiPhOyH;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744736945; x=1745341745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OfmweZAb1i2xfQ/C/VzQihfq/B4O4dlfWsH71b3v+yA=;
        b=TYSYuPgA8UvGHrX3zJDAQlizrwK4URDUmiBj/QkWhhN+MUav2qdR4Yd6L7nlA7jjDI
         VCxsric3YdpD2njOMxM09uS3ft90bUDPFmRjbnNfa/hkfJ0Ja0VuyClx9eB8oQwYNaLW
         iCTWt2vftgtonjfYUJLHV4+/egQqpcFpxdEl4BxQu6Kbjx6FfvGbf2/exLJN9W7cAEPc
         2QlFTs1snE9NAFixVU2x9nYrYz90/xxzngBDsEJzxKxwSylx4HMfVXzC7DOHWjPJcE3w
         Ua54A/UaSfdQ/+8iUgCNBan8e03OLJOIREtzLOXn29VsQYmN3akktsFircfDq9d4ZnNB
         3D0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744736945; x=1745341745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OfmweZAb1i2xfQ/C/VzQihfq/B4O4dlfWsH71b3v+yA=;
        b=CjM99xM0s1l+gaOb3a71/W7aCGgq5V/iw9lBYUXV/DQ4qIBhZUXIkuvY3/sDc4Fdh+
         nY/MbFh/KN6w8jUY75rDBZO0il4/aZw4SDmZs4+oKlbB38esjG4iKGl2YKbEtJwIU4eo
         XLmL6aw/RcZyM18jd+QHKar5QdPqqEpT3AYpiJSR7g0XUkzLZnyJ8N8uLWcMXO7DywY/
         xmLOHLoa7M9k7ojrqMxEWKztprkjISbHX/iusc5bgXKXc7ylfbbhyfzzZGfbYvHeTxss
         MdUXIKoxEKehR1/Aza2GInFp5cfI/pCKGbQw4yqHrWjKku8GaxcEzn5niutSBSLGJ5s0
         6clg==
X-Forwarded-Encrypted: i=2; AJvYcCXeDxaytwdGLwRxV/IdbAnrwbI8Hz2k56ds9FqvfSBKzwSx0b6uuSbNDBfj/Q2WuUbsOQjurA==@lfdr.de
X-Gm-Message-State: AOJu0YxXnGjq6WruYyxc0BCu6h9LsvjbS0dfkjmHZfhuBLgPh2+BXLSG
	RLYioDu5bgz4Enj3d0aQHNzeDzgNWCg1sKMLCBuoc9LcTsnM/t3R
X-Google-Smtp-Source: AGHT+IHvFpTldHVa9TseyKeXT86YuIa/shNkDHllagACMh5PGRseB95acYuGabmNEP0Qol4GFPINDg==
X-Received: by 2002:a05:6e02:19c9:b0:3d3:fdb8:1796 with SMTP id e9e14a558f8ab-3d8124e1b06mr1031525ab.2.1744736945307;
        Tue, 15 Apr 2025 10:09:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIfuvXIud0wSXXfc9AKtdASU5Pwp9pufnhdROnbCHD3Tg==
Received: by 2002:a05:6e02:3288:b0:3d4:4545:9ce1 with SMTP id
 e9e14a558f8ab-3d7e3d2577bls323125ab.2.-pod-prod-05-us; Tue, 15 Apr 2025
 10:09:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9HZis3y9XCNi08sQHbav2crHejfjmlfYdeA/FQmYZ8KTd7ZTzBFcFezoqRa/tzvp1Nlrpel8OL/E=@googlegroups.com
X-Received: by 2002:a05:6602:3889:b0:85b:577b:37da with SMTP id ca18e2360f4ac-861bfc7b555mr8681439f.9.1744736944463;
        Tue, 15 Apr 2025 10:09:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744736944; cv=none;
        d=google.com; s=arc-20240605;
        b=N/XBw6StHuOyd/BMEwq4o4DcZuF88IQecEomqFQiX3wbjVaXsMs+nENkJKJtpb/2f5
         NWGaDxar0tGfntGz56N7q5vsD+RC5VN4EZrrvgEizm9QNbDXjCzm7ddaQqCuYRr/HICy
         rf3NzLp8Yp6KlfIr9WkklvSwfLrcG2g2ym49adbWnHRRk+gP2UM3/o0KGB9NzUpp6A7p
         +IkgsxD71sPLftRYJBGlKN0XBC/edj7bwBCCnG9M8lexbMIX9dGpPs0XTc5C9rhC+Yb3
         yXeokn1WPHneJNWHtkCUob67jK4G8HYZUsHqeTUxFQZYjC3mizidfddIofdUKdex9zdp
         j+jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Ffb5G+g7Jy+WaT1QLvAy6b3W+h6N8+WbMSYH10fKNO4=;
        fh=jYPj8I2gsTyoPewetHNMd+hlISvf0lRKqqFPJrp+lSU=;
        b=f4kIncwgF7PetSPZKnwHzaia3rs5Leg62WsHbxqfHpgT2hClaJx20FgJbJsRj3Qr3o
         Cw0RkLzhE/oLr/2B2wO5xmTI7vsuG7gbJCX8CGkEIpx3av2YM0MFH/wbG0RpXA5Kwg1y
         vfHjFFbe0bFZDYZh8/Kv8ERgUL/aget7HduGyosIJxA53oHxSmS8z9EkbJiBdUIOFPeM
         ic3om62+hh+WHv2peXgLwC+aNDufiRJazqFdLnBKk0TJt2Et9gspj4jHSnwx0IfFm3qT
         Cu/sVlH/KEnJP+xPHvF8NGtXp3RMPD1Dl+mPR1H2KtE1ooLVUn5+QsNoj6lYNUHFCUVw
         /mNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=awiPhOyH;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f67c9ccaf4si119467173.0.2025.04.15.10.09.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Apr 2025 10:09:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 81761A4A4E9;
	Tue, 15 Apr 2025 17:03:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 89079C4CEE9;
	Tue, 15 Apr 2025 17:09:03 +0000 (UTC)
Date: Tue, 15 Apr 2025 10:09:00 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mostafa Saleh <smostafa@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com
Subject: Re: [PATCH] lib/test_ubsan.c: Fix panic from test_ubsan_out_of_bounds
Message-ID: <202504151006.19150DFE@keescook>
References: <20250414213648.2660150-1-smostafa@google.com>
 <20250414170414.74f1c4e3542b1f10c8b24d90@linux-foundation.org>
 <Z_4dXk0RlyXYuzYt@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Z_4dXk0RlyXYuzYt@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=awiPhOyH;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Tue, Apr 15, 2025 at 08:48:30AM +0000, Mostafa Saleh wrote:
> On Mon, Apr 14, 2025 at 05:04:14PM -0700, Andrew Morton wrote:
> > On Mon, 14 Apr 2025 21:36:48 +0000 Mostafa Saleh <smostafa@google.com> wrote:
> > 
> > > Running lib_ubsan.ko on arm64 (without CONFIG_UBSAN_TRAP) panics the
> > > kernel
> > > 
> > > [   31.616546] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: test_ubsan_out_of_bounds+0x158/0x158 [test_ubsan]
> > > [   31.646817] CPU: 3 UID: 0 PID: 179 Comm: insmod Not tainted 6.15.0-rc2 #1 PREEMPT
> > > [   31.648153] Hardware name: linux,dummy-virt (DT)
> > > [   31.648970] Call trace:
> > > [   31.649345]  show_stack+0x18/0x24 (C)
> > > [   31.650960]  dump_stack_lvl+0x40/0x84
> > > [   31.651559]  dump_stack+0x18/0x24
> > > [   31.652264]  panic+0x138/0x3b4
> > > [   31.652812]  __ktime_get_real_seconds+0x0/0x10
> > > [   31.653540]  test_ubsan_load_invalid_value+0x0/0xa8 [test_ubsan]
> > > [   31.654388]  init_module+0x24/0xff4 [test_ubsan]
> > > [   31.655077]  do_one_initcall+0xd4/0x280
> > > [   31.655680]  do_init_module+0x58/0x2b4
> > > 
> > > That happens because the test corrupts other data in the stack:
> > > 400:   d5384108        mrs     x8, sp_el0
> > > 404:   f9426d08        ldr     x8, [x8, #1240]
> > > 408:   f85f83a9        ldur    x9, [x29, #-8]
> > > 40c:   eb09011f        cmp     x8, x9
> > > 410:   54000301        b.ne    470 <test_ubsan_out_of_bounds+0x154>  // b.any
> > > 
> > > As there is no guarantee the compiler will order the local variables
> > > as declared in the module:
> > 
> > argh.
> > 
> > > 	volatile char above[4] = { }; /* Protect surrounding memory. */
> > > 	volatile int arr[4];
> > > 	volatile char below[4] = { }; /* Protect surrounding memory. */
> > > 
> > > So, instead of writing out-of-bound, we can read out-of-bound which
> > > still triggers UBSAN but doesn't corrupt the stack.
> > 
> > Would it be better to put the above three items into a struct, so we
> > specify the layout?
> 
> Yes, that also should work, but I ran into a panic because of another
> problem, where the padding before and after the arr is 4 bytes, but
> the index is "5", which is 8 bytes out of bound.
> As we can only use 4/-1 as out of bounds.
> That should also work:
> 
> diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
> index 8772e5edaa4f..4533e9cb52e6 100644
> --- a/lib/test_ubsan.c
> +++ b/lib/test_ubsan.c
> @@ -77,18 +77,18 @@ static void test_ubsan_shift_out_of_bounds(void)
>  
>  static void test_ubsan_out_of_bounds(void)
>  {
> -	volatile int i = 4, j = 5, k = -1;
> -	volatile char above[4] = { }; /* Protect surrounding memory. */
> -	volatile int arr[4];
> -	volatile char below[4] = { }; /* Protect surrounding memory. */
> -
> -	above[0] = below[0];
> +	volatile int i = 4, j = 4, k = -1;
> +	struct {
> +		volatile char above[4]; /* Protect surrounding memory. */
> +		volatile int arr[4];
> +		volatile char below[4]; /* Protect surrounding memory. */
> +	} data;

Instead of all the volatiles, I recommend using:

	OPTIMIZER_HIDE_VAR(i);
	OPTIMIZER_HIDE_VAR(j);
	OPTIMIZER_HIDE_VAR(k);
	OPTIMIZER_HIDE_VAR(data);

>  	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "above");
> -	arr[j] = i;
> +	data.arr[j] = i;
>  
>  	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "below");
> -	arr[k] = i;
> +	data.arr[k] = i;
>  }
>  
>  enum ubsan_test_enum {
> 
> ---
> 
> I can send v2 with this approach if it's better.

Yes please, the struct is the right solution to keep the memory
contiguous.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504151006.19150DFE%40keescook.
