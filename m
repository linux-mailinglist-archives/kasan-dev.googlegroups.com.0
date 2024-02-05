Return-Path: <kasan-dev+bncBDV37XP3XYDRBZUMQSXAMGQEGUGQX4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6891E849F20
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 17:01:50 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5997417c351sf5268095eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 08:01:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707148909; cv=pass;
        d=google.com; s=arc-20160816;
        b=RXhW3hlb5Bnx2cybw66q8IvhOhhCtk8Gfv6IlcK94ZZrIXHDv47vXBC3ZmBmdtvzSt
         ehDHQJa/SQHapoNDhZlYVC9aeJSeWj3DajVvMZDCzcEh31PQKTtXXhMmi1Aju+G2ehGc
         YaOR2Z9kkNd0JKRRCHnxtn7T4QEhCu/cHs3H7p6gvlEjU/QNpTyUVdplpyT6p+byId/F
         QmcXAbsww6NbtjCBJg4ab0FYtF4/vI4TTzZQz6jMRPpVyrTtvehWFIrczHdPQhhcgY1v
         uJEOV+Cwx+IuT8lg2D28kfsYBFY9Wpm8lBkefjeV8n08QLYzgEBxR38L6djlKMr8XPXw
         13Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wf11/BJcK+CZazRzTX1YsZ4YMhYXDOB2huTdRCHiZGk=;
        fh=wN0K+CEJ7WUvhZ5/i3PLE5r8tIHssSKcXKIKbLNr6UU=;
        b=GmBUFPEsjNWMAYkhgBZW91qzWq7/9viSs9HhnWsjsjm9hnwv972Qa8GecoZfgjZt04
         179GmaAsAEdTxM4KOCz6qkcNVnwExWBHe0p8+lKMFLbTXdIbbPBfYkN8sdHqjIy0g4pk
         mp2IMcyA5QHpuF1iXmfoD7d4uY828jrC6jFuWRF3JUzycnoEW3LVMfCYWnKOZsFoprZs
         8KIte1gPUGmTaUnnv0o0y0qIXdbgIuPdyk5iiFlRFX81SsA0YWQ9Ek/WiEX/UcoFD/84
         5v9T7KBMuEQI/YezHLON/Fo5kpY+dUCQ/BMMMayeHc9SuTxQsc+A1oTdO1UAXGBeIIpj
         18hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707148909; x=1707753709; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wf11/BJcK+CZazRzTX1YsZ4YMhYXDOB2huTdRCHiZGk=;
        b=H1iN3pxRM8YQQiYvuGuTWHLQWFh/5me3kIo4AYLQHE1IvPU02r9CAff/QRZZMSb+Bt
         VqbJqDJwoI4bIhz2IdFVFdSmpsB2/QE2AsRZTOf+L9djqMNTG5WYXQiuzj2HqCxVdM4F
         DMgLy2Egbi6UuzOg0QxzqYavQMN4YbNqZaCL1pJbmvfEwPukOajskgrXOJfW4jQzyT4E
         qArKhG0mZeo2egMgi6jYFivBctwrGNQwNCtycP/KTdFuISNHt5uc9cyYrX0r1000yPO8
         3VoXVRE3GDVAoe71DAtOOnAIwOSGBVQqNlDuRnTAl83rpeBvFz3cP75Vc/KNG8/upG4T
         LmZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707148909; x=1707753709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wf11/BJcK+CZazRzTX1YsZ4YMhYXDOB2huTdRCHiZGk=;
        b=LE25hzJ0s57kbIoLEscggy4ABrv9bJj0SVt8udG3VC8juQUeZShV+0XmmDkd7QELbF
         3KTKvY9GUwa5WkFaBHuD4l3dALaD95NuO4nu8C4hUwcdyoi1tSro65BFfpLiO/Mf0OMb
         EmLiMvde7DiBtss7T5D14ri3iyvvRQnQu61bv6w5SG0FPKKPArjlgaKUScu6UgR6iCNR
         RJ5gVHKhTsZdK34Yqlt7nJpXW+imDd7vw0AwyDDgV11iICf+88CPdV7U6hj9aEt4yXmU
         3qBDvdNwE/gQL8w0WgSUrA78E9ZgMHAro87PUmCFa97xjISfDBgFrEU/fzSOeq3fpLtq
         q3Aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz85PLL4zi/hh4JU70QFPsNxVJPZHBtjX9P7LIG5yVgbh2WsIGA
	p8/7PmRRmIS1xSzga9rpb+/mV20l0h8n9a8pUkmSHM1MHPgUf8uy0Pc=
X-Google-Smtp-Source: AGHT+IFt2rcNJnJkNMzeDmBTDgkZA0D669SdVS6S5yGWeE620Sni6o9N5hPS0AM+SR/+hykkm9tr8Q==
X-Received: by 2002:a4a:2416:0:b0:59a:6461:cc85 with SMTP id m22-20020a4a2416000000b0059a6461cc85mr127931oof.3.1707148902472;
        Mon, 05 Feb 2024 08:01:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:55d2:0:b0:598:db3f:b1ae with SMTP id e201-20020a4a55d2000000b00598db3fb1aels1545802oob.0.-pod-prod-04-us;
 Mon, 05 Feb 2024 08:01:40 -0800 (PST)
X-Received: by 2002:a05:6830:1b65:b0:6e1:786:87d with SMTP id d5-20020a0568301b6500b006e10786087dmr29646ote.8.1707148900159;
        Mon, 05 Feb 2024 08:01:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707148900; cv=none;
        d=google.com; s=arc-20160816;
        b=huw/Ci4pZ2h47Qr/Vdd0GK96HVXl+3PN+FvhMDIzVc4nSHDpX2xyqg99aT/d8jJ7gt
         7/SjlUnUPTR7LNc8xgmh/cl6K6FPuOr+bqs91NoclKVi1j9Buwha7Q8MKhUk1b8aelo/
         SwRhVArV0jzGieGOshprWmFAj2RpkFzuO9/7O8gpACn011KB43q3t98GIGyxygXQkNhh
         y9E8jYmfABN7MWnViy6xozeWArESJ2cTf1cvnJcopHnTqUXvNxZmhW/BQm3G26oL+Jp9
         UFqpY7/UX6k/wZ/TlIOoMiZehPuXThCsVkameMzlLUy8ElTKwpDoJpjURd5uSv3wzMuR
         oLcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=9PmwAXZzlI/3tKHIRlCPcUPoUA3xllDT3/1Q0y+jEXI=;
        fh=wN0K+CEJ7WUvhZ5/i3PLE5r8tIHssSKcXKIKbLNr6UU=;
        b=VBbkavBl7LdVpRj2R3/7/AwpSDtNrFhFwQq1vy4SZXdNiL8/2q7woRpTMkbMSRj+ku
         TZJ5psPhlxd5jbpLdazzDIIId+BLkDM1YGsU/+krAmtpO0tzKhdS16JzIHdEYUIVbHOO
         qdThLDhOLDKXpgmF055qcHgxT6MKji7AxT63gq/E+97HFZv1gyhft3iMfDB8FP61sc0H
         +ew8VeE/2P0ImXWZ/3QMv1xPKKf7ulCQhNwZtoWgcvc5IMBHakTED4o+Efd/+U2/AzgN
         UrKhJFfKfu1LiDwW3gqqIUUY+Mnq1Q4Y8ZYSxrxDjo9aITGxJ7HwcfGcjCdX75H7OzY4
         M91Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
X-Forwarded-Encrypted: i=0; AJvYcCVekke9ptmblYmkP+vaoU54p5cX73IyYZkVP6sTWMaeRhNfiNyj+ESfMLd7I68aqzoDIiG50ds+OeEPgq9h/diFIkP9PgJY8o6udw==
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i20-20020a056830451400b006e13fae7870si16979otv.3.2024.02.05.08.01.38
        for <kasan-dev@googlegroups.com>;
        Mon, 05 Feb 2024 08:01:38 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CFE801FB;
	Mon,  5 Feb 2024 08:02:20 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.66.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 777FE3F5A1;
	Mon,  5 Feb 2024 08:01:36 -0800 (PST)
Date: Mon, 5 Feb 2024 16:01:30 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: "Paul Heidekr\"uger" <paul.heidekrueger@tum.de>
Cc: elver@google.com, akpm@linux-foundation.org, andreyknvl@gmail.com,
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
Subject: Re: [PATCH] kasan: add atomic tests
Message-ID: <ZcEGWm30LsslEpMH@FVFF77S0Q05N>
References: <CANpmjNP033FCJUb_nzTMJZnvXQj8esFBv_tg5-rtNtVUsGLB_A@mail.gmail.com>
 <20240202113259.3045705-1-paul.heidekrueger@tum.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240202113259.3045705-1-paul.heidekrueger@tum.de>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Feb 02, 2024 at 11:32:59AM +0000, Paul Heidekr"uger wrote:
> Test that KASan can detect some unsafe atomic accesses.
> 
> As discussed in the linked thread below, these tests attempt to cover
> the most common uses of atomics and, therefore, aren't exhaustive.
> 
> CC: Marco Elver <elver@google.com>
> CC: Andrey Konovalov <andreyknvl@gmail.com>
> Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueger@tum.de/T/#u
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=214055
> Signed-off-by: Paul Heidekr"uger <paul.heidekrueger@tum.de>
> ---
> Changes PATCH RFC v2 -> PATCH v1:
> * Remove casts to void*
> * Remove i_safe variable
> * Add atomic_long_* test cases
> * Carry over comment from kasan_bitops_tags()
> 
> Changes PATCH RFC v1 -> PATCH RFC v2:
> * Adjust size of allocations to make kasan_atomics() work with all KASan modes
> * Remove comments and move tests closer to the bitops tests
> * For functions taking two addresses as an input, test each address in a separate function call.
> * Rename variables for clarity
> * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_store_release()
> 
>  mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 79 insertions(+)
> 
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 8281eb42464b..4ef2280c322c 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test)
>  	kfree(bits);
>  }
>  
> +static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
> +{
> +	int *i_unsafe = (int *)unsafe;

Minor nit: you don't need the cast here either.

Regardless:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, safe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
> +}
> +
> +static void kasan_atomics(struct kunit *test)
> +{
> +	void *a1, *a2;
> +
> +	/*
> +	 * Just as with kasan_bitops_tags(), we allocate 48 bytes of memory such
> +	 * that the following 16 bytes will make up the redzone.
> +	 */
> +	a1 = kzalloc(48, GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +	a2 = kzalloc(sizeof(int), GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +
> +	/* Use atomics to access the redzone. */
> +	kasan_atomics_helper(test, a1 + 48, a2);
> +
> +	kfree(a1);
> +	kfree(a2);
> +}
> +
>  static void kmalloc_double_kzfree(struct kunit *test)
>  {
>  	char *ptr;
> @@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kasan_strings),
>  	KUNIT_CASE(kasan_bitops_generic),
>  	KUNIT_CASE(kasan_bitops_tags),
> +	KUNIT_CASE(kasan_atomics),
>  	KUNIT_CASE(kmalloc_double_kzfree),
>  	KUNIT_CASE(rcu_uaf),
>  	KUNIT_CASE(workqueue_uaf),
> -- 
> 2.40.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZcEGWm30LsslEpMH%40FVFF77S0Q05N.
