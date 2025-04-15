Return-Path: <kasan-dev+bncBCVLV266TMPBBZN27C7QMGQE6YG6AGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4480EA89714
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 10:48:40 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-43e9b0fd00csf26326205e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 01:48:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744706919; cv=pass;
        d=google.com; s=arc-20240605;
        b=ESnEBwPjAsElAczsZCfB15XPRmlARgJCd4enR3Vn3u9ejEZWxXDr560ojp/v3jfCHk
         P5hetxvZLZpmFQXbQJLkqAy6eb/YhMf4MwLOPwXniJGXwJI5fe1dE6FJQatrrHECRVXX
         bPSvfcZUo12SGPwnsb1+NWL2IX7+5vQsZXNVIAnxt+93San4tfG8SQC02ECJrQxdC89U
         jQQ2ih+2XRGXILcxnIzTgf45ckimKLW+YWyvegSGXqXccANpa+zw97ZSVph2Z1EPr76U
         FvbPf+EdeKCW2glNsKYGR6SfOl7tJqHE4/zc09z6qsx3ojHOEPaVPYhMbJ3tthvqduDd
         9OsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=CQbPfWsLRKX2YmbxclyLg1i78PYLI6lz++B8XdZRPEA=;
        fh=HKL7wdo5IX/F/q1eBYMp4dl7ti3RX7PPcPyKzJ2iI00=;
        b=NfZP8PHEmBiHIFwh4SEQefyirW6rP5Je7aHvSlloRiGxg49/stWlwFxf/L1PEVPfB6
         k8dDLknmEygj/UntgOIzdHtGT5Vf/GLJq5cSZIZwkYZ+8a2a1zybEuNAYm+PmnX/QNA3
         pAzDksZRRxBOEHVIxnKXSvLqRZkGHGwCYFPRBJBhkCLrOCOmIUs7VZkKYu3WPlJcrebt
         PuY6Lj9HbAbwQtnu4zPWgRNiZm7emCRz4TgNWOtMEIG5tAs1g0Bjef6NKqYYebZjF+ET
         xB73AuthduItm6/KJ4nIJhQSODqW6mraWZ/2sAa64o8CBWaVZNWnzWGmTUfiuKQAI/TS
         xQuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EyemoXgc;
       spf=pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=smostafa@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744706919; x=1745311719; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=CQbPfWsLRKX2YmbxclyLg1i78PYLI6lz++B8XdZRPEA=;
        b=nWnDjFqbn7XUljyZ3GlRadwCi95EoweT8naqts0Cymb8SXjUV3vhlF1SDfzjEEM5ms
         yeVjttl0mFlGXlUDJn9kJ9XTRDEA9x/LorwXQb5kPkPznZPoA9JA+l72aQFmDUi0wnk5
         PtIa6q8n9h9tX0SJ7hqoFI4g9QdD6iDIPZyg1QcJj7tNpzvniHEaRSoMS+YVJYrpY4hk
         bfJQ3477/xB0BZKuqhg6kH0OF2zVt9D4dCemORx213Z9T2p42D8vOx62ocPBikwnm3Ip
         POZ/+yTPmgsPSFFiB9ii6SnwWKG5cgDbmT14voxOo4wZfa6l3kmqcTyqKByJG59nQ27C
         Pr0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744706919; x=1745311719;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CQbPfWsLRKX2YmbxclyLg1i78PYLI6lz++B8XdZRPEA=;
        b=QgLiGW0XYStCVAZZREDqvHFOtN7h40SzNYS672POJxni9BeSt1Xo1t1B/U169vcJ8w
         KectBWL20RiRgkoaBRpUxkPrXmvtNEIUZbT/S7BqccVEk7deTAb3Zha/dgK+LQK59ECE
         a+kabPh/unO+0f0ulapt2qT9HD5Z/NsNfhNu9sMvW2z4CRH/b+BYsxKjO2MNaujNyOBi
         CENyP3SNcw8APbDHXMmJxgIU+fwAbeiZ/cdhlVFPgBC3ZYz83snpx6DDmsFmiinXFkrL
         zTQdS6Ho5UPhozX40szX1kxiHBM560W30QtHARAM5uSTsbkaryzSXe8oAdF94M/oiiy6
         7fug==
X-Forwarded-Encrypted: i=2; AJvYcCX1oNfMyPQglWXMHDoiH+i4CFTER+FqspCIbvbnbTvwqL6g1H4/eepYnXNqdi7++hYuRNxEoQ==@lfdr.de
X-Gm-Message-State: AOJu0YxTsK+kq34gmmh++q0l6HlGmfCqQbz+3PTNt6P0BGbrpkuwaBHN
	+NgTHwkVBCqWmiN6haHY2h/o5uDkzvVe1S8yyRa4QiVhKIJynSxw
X-Google-Smtp-Source: AGHT+IE9F2nkExx9ZPulSV7GMrzxGMdkMvcFxGXRHby55FaAq+XvmM3zBRz5AOh4WfCzQE7xKtgZwQ==
X-Received: by 2002:a05:600c:35ce:b0:43b:4829:8067 with SMTP id 5b1f17b1804b1-43f9988a8ccmr20600775e9.6.1744706918180;
        Tue, 15 Apr 2025 01:48:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAITXIvYo1F0E/nCfGM9AqIqxFL8cT1e//ZU4OjIsp/g+w==
Received: by 2002:a05:6000:2282:b0:390:d6ab:6c26 with SMTP id
 ffacd0b85a97d-39d8df195ddls2105110f8f.0.-pod-prod-00-eu; Tue, 15 Apr 2025
 01:48:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxzAJbGiNk8jF4psDE2xdsBfnQo1UL/07sa+mfXTaMCzNC3rdVNkYiPDC69/aRHqe8E3T8XQQppAU=@googlegroups.com
X-Received: by 2002:a05:6000:22c1:b0:391:952:c74a with SMTP id ffacd0b85a97d-39edc3056f2mr1929013f8f.8.1744706915597;
        Tue, 15 Apr 2025 01:48:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744706915; cv=none;
        d=google.com; s=arc-20240605;
        b=iL/QIHoayQDOUc+qeDNH45bw1IW/06KlvEtEY5EEsNmsD5iQeO2iiTJcZsSDbQ80Bn
         CHcktfTjL+K57QBeDHJ80biBZpOvt3y3SLvZZelJ6CqdS8/aSVwgtnAmik4AdYI9+fNd
         Q4YjyQWBry6rCOJ2HNg3XYoj4qvEYQtzmfO2NwnzFVWCmRqoaaadvv3LNOrbq8zBNYmq
         4/WyTdS12nfmo6B5xwzaVfk7ibmp3SJn04tfFCMExomcofvQeDZ835/wh9irGZJpSD5U
         09DkM3fSA6pHzHPzlCz5NSQ5c12jRhct3QR1UtWEaVdiuxgChkpkf7JuzaQe616+C6qJ
         9R0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=P2dLV0t9lDObm6obO+scd0gk1JmVp4YwTv7aMmXR6dQ=;
        fh=3KaxLiwzjHOf+f+vGTPnhFhycmTBV3gjLetVQ4dD1Xo=;
        b=UV/kh5roqmbyFAowo/b3NNhy8pcwp4/2xftJb7tq9YPAFOxmA6WHWg3xxgG665jSzh
         QLSn3NRS3yrkwqupGXUwXO98U/Vgt9HWTP6n5eH82sGeNADogLPmIqNlOfQH0Y6x5URf
         cN1QynjTuBVeELvnpEq64BHB2AuMLgFRdazjssWeCGAyFxmNe/SZ/jh8Ev5uFhGM0JfL
         YHKqhDyWipdib9pVLnd954GuYJ29HhAAbxfXiHl5Snr8aTSD93gZkfav4q/qGmJb7Xwf
         WgbvplQBFN3/6iNNjRHJ5uYbO/rsvNZ/alPOxL+iMhzAQj/hwU9e3cyQnEni+PfR4GQc
         Kd8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EyemoXgc;
       spf=pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=smostafa@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-44051139dcbsi489275e9.1.2025.04.15.01.48.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Apr 2025 01:48:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-43ef83a6bfaso34425e9.1
        for <kasan-dev@googlegroups.com>; Tue, 15 Apr 2025 01:48:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVHELLcd1+VsjRwkZXMs+Riv2mlZ56XKQHKrhSt/1B+OLWIQjr9oIn6s26dSKfcmLvBu3qN2UJT2oM=@googlegroups.com
X-Gm-Gg: ASbGncsfWTxffKZZGoMqe7QDfDvzHjMMtkGLhi7OZepxoWkksIiMnkkS8kL/CZEcKKc
	tTG8gn1aOfNiQVJB2hmXVQ5a6se5sCMTNYtlNVDrfoewxb1DWEu8QsQPb6lm1Jq9LUtESuslzvg
	b18BlY9V3UPVHSgfTSqsdMAJVCI7rYSxzvlcYExSdkxrgpZNCTigCyXhiwKJ0kTR3nCsHTBcXJ9
	YNBQgCZ/Wuysl9V04ANdjf9v+iC6ro7D20KHxqKOLJLIKvG+uzPprikDCFJZzcQ21SAuqlQVAU9
	p7kTHPpDimbIGNhxYNFtFCXcpu2B9rqXgVfOn7QmHdbK7szvHJ/ZwaIti+0U8wKYEZ0J8LdwPgj
	pVrI=
X-Received: by 2002:a05:600c:4247:b0:43d:169e:4d75 with SMTP id 5b1f17b1804b1-44039657a6bmr408175e9.1.1744706914774;
        Tue, 15 Apr 2025 01:48:34 -0700 (PDT)
Received: from google.com (202.88.205.35.bc.googleusercontent.com. [35.205.88.202])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-39eaf43cb43sm13614636f8f.65.2025.04.15.01.48.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Apr 2025 01:48:34 -0700 (PDT)
Date: Tue, 15 Apr 2025 08:48:30 +0000
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, kees@kernel.org, elver@google.com,
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com
Subject: Re: [PATCH] lib/test_ubsan.c: Fix panic from test_ubsan_out_of_bounds
Message-ID: <Z_4dXk0RlyXYuzYt@google.com>
References: <20250414213648.2660150-1-smostafa@google.com>
 <20250414170414.74f1c4e3542b1f10c8b24d90@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250414170414.74f1c4e3542b1f10c8b24d90@linux-foundation.org>
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EyemoXgc;       spf=pass
 (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::334
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

On Mon, Apr 14, 2025 at 05:04:14PM -0700, Andrew Morton wrote:
> On Mon, 14 Apr 2025 21:36:48 +0000 Mostafa Saleh <smostafa@google.com> wrote:
> 
> > Running lib_ubsan.ko on arm64 (without CONFIG_UBSAN_TRAP) panics the
> > kernel
> > 
> > [   31.616546] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: test_ubsan_out_of_bounds+0x158/0x158 [test_ubsan]
> > [   31.646817] CPU: 3 UID: 0 PID: 179 Comm: insmod Not tainted 6.15.0-rc2 #1 PREEMPT
> > [   31.648153] Hardware name: linux,dummy-virt (DT)
> > [   31.648970] Call trace:
> > [   31.649345]  show_stack+0x18/0x24 (C)
> > [   31.650960]  dump_stack_lvl+0x40/0x84
> > [   31.651559]  dump_stack+0x18/0x24
> > [   31.652264]  panic+0x138/0x3b4
> > [   31.652812]  __ktime_get_real_seconds+0x0/0x10
> > [   31.653540]  test_ubsan_load_invalid_value+0x0/0xa8 [test_ubsan]
> > [   31.654388]  init_module+0x24/0xff4 [test_ubsan]
> > [   31.655077]  do_one_initcall+0xd4/0x280
> > [   31.655680]  do_init_module+0x58/0x2b4
> > 
> > That happens because the test corrupts other data in the stack:
> > 400:   d5384108        mrs     x8, sp_el0
> > 404:   f9426d08        ldr     x8, [x8, #1240]
> > 408:   f85f83a9        ldur    x9, [x29, #-8]
> > 40c:   eb09011f        cmp     x8, x9
> > 410:   54000301        b.ne    470 <test_ubsan_out_of_bounds+0x154>  // b.any
> > 
> > As there is no guarantee the compiler will order the local variables
> > as declared in the module:
> 
> argh.
> 
> > 	volatile char above[4] = { }; /* Protect surrounding memory. */
> > 	volatile int arr[4];
> > 	volatile char below[4] = { }; /* Protect surrounding memory. */
> > 
> > So, instead of writing out-of-bound, we can read out-of-bound which
> > still triggers UBSAN but doesn't corrupt the stack.
> 
> Would it be better to put the above three items into a struct, so we
> specify the layout?

Yes, that also should work, but I ran into a panic because of another
problem, where the padding before and after the arr is 4 bytes, but
the index is "5", which is 8 bytes out of bound.
As we can only use 4/-1 as out of bounds.
That should also work:

diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 8772e5edaa4f..4533e9cb52e6 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -77,18 +77,18 @@ static void test_ubsan_shift_out_of_bounds(void)
 
 static void test_ubsan_out_of_bounds(void)
 {
-	volatile int i = 4, j = 5, k = -1;
-	volatile char above[4] = { }; /* Protect surrounding memory. */
-	volatile int arr[4];
-	volatile char below[4] = { }; /* Protect surrounding memory. */
-
-	above[0] = below[0];
+	volatile int i = 4, j = 4, k = -1;
+	struct {
+		volatile char above[4]; /* Protect surrounding memory. */
+		volatile int arr[4];
+		volatile char below[4]; /* Protect surrounding memory. */
+	} data;
 
 	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "above");
-	arr[j] = i;
+	data.arr[j] = i;
 
 	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "below");
-	arr[k] = i;
+	data.arr[k] = i;
 }
 
 enum ubsan_test_enum {

---

I can send v2 with this approach if it's better.

Thanks,
Mostafa

> 
> > --- a/lib/test_ubsan.c
> > +++ b/lib/test_ubsan.c
> > @@ -77,18 +77,15 @@ static void test_ubsan_shift_out_of_bounds(void)
> >  
> >  static void test_ubsan_out_of_bounds(void)
> >  {
> > -	volatile int i = 4, j = 5, k = -1;
> > -	volatile char above[4] = { }; /* Protect surrounding memory. */
> > +	volatile int j = 5, k = -1;
> > +	volatile int scratch[4] = { };
> >  	volatile int arr[4];
> > -	volatile char below[4] = { }; /* Protect surrounding memory. */
> > -
> > -	above[0] = below[0];
> >  
> >  	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "above");
> > -	arr[j] = i;
> > +	scratch[1] = arr[j];
> >  
> >  	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "below");
> > -	arr[k] = i;
> > +	scratch[2] = arr[k];
> >  }
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z_4dXk0RlyXYuzYt%40google.com.
