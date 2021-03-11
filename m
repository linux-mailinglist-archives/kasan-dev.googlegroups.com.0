Return-Path: <kasan-dev+bncBDDL3KWR4EBRBK4KVGBAMGQEKL3ZQ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C99933794C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 17:28:29 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id 127sf26070762ybc.19
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 08:28:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615480108; cv=pass;
        d=google.com; s=arc-20160816;
        b=CAwY8e7CXS8GBoEQHG4AArZfWl2RqD2WW/kpvBWiOLGeRAwt4IAB9rVYdC9m0Bjb7R
         BwA+uHuVT8VtrwQXjrZ4fgSM4AOWNlSAd2A+L8mXitjpn1RivjGDaxZi1odindLgWke0
         srOyTd3ocqHbLhzm3Z3fa0WYsDqJ57UIj9dm+5fbHqyAIK3KgLG8nUJTaBj2eWq+Smb0
         ZpeiVqV/XhdGAxNykvGp4sYNJNIIN5vTjd+a9Wl4n7d+vrj36xETdY0Q9YtJSWNkRfk2
         9fg3VrhhNqPI5M5zjdgOimLsTwv6vqQDH46RrhyJgp825/919RzYCwVqg37vtu0yUWGG
         30LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=78HvGNkt8nVSdYR9ZOalj396z/Uji1pnF/wNwueNPdI=;
        b=uMClTX5z9g3iH+mYULdHcCM287SUpAIot34JhHwZItMjufyTikNhlklbw5LzTcGsGU
         bcqY/EIcxxANtUmJD9U1r5TRaAJy7oCWJ4xSCcNoeh1uASRq7l7E6JyTg4C17n/T37Ul
         cZSL7W2CaCDpPkkNGLc98jQg36/aejpwVec3Cjq3dnma/QKanDeYy7lHqJVly6Eb6+kU
         9JeVMDk/Z5q9wRWv6UJDZlWl9Nwybu2UWPqnAK6zWm3oc9SgJDPbt496kC5k+KyW4xqb
         q3GmVhR4zhh3yPCwMZVO5aVjvEn/MSrpT+uVAR1yrUNzX00bCcDz8kQGT0woXlk2e36o
         xD7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=78HvGNkt8nVSdYR9ZOalj396z/Uji1pnF/wNwueNPdI=;
        b=BemLGnCFwi6b9Kxicydun5PBF6P7jQniyng8tmaVO2SoXj0bfyd/XrlmpdyslZY7Xb
         JaVhQN1AJijhBuzsftotq4NLkWzBj5q+uL9k0y9JLVZxo5y8naEVx5kQflQmn3N2BITk
         7uCJo6L3RmY9APdZR9K+vIQAPl/766UCW/K2k+837eS7guUM3z1oijrOoAis2HHM+fq7
         JxMSej7piQe0c/29HRvUgKvDL9tB2buwInniGsRMzXGxWbEIcDfzdLe4oj8DD4bB3IqN
         g1KdpVxvDLinZ1iijp1iJ+qBDFmrBVi7gTog+I7JF1GRDjdtwom3CIph8Bt/NV8ikGqf
         yz1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=78HvGNkt8nVSdYR9ZOalj396z/Uji1pnF/wNwueNPdI=;
        b=HoYAPaL+WkEKAzoxYByUw7wHyDKdLRWX9qJX+JNDzdB65xxIbepwqMaGnzvnXpJuqX
         Lu3rIEgqk8Za33rZd6NIL0XTK2jcOQpYqU9J42QIw6BRqA7bueclvenCoUwyyq2SM7FG
         or7Z7OA4IckTIM3MvxWhVM/bKjcpiT68DWt7auvwiWQcxxDd7NVO/gaBu1+OtxMQt8ZJ
         LlsIrygPD0pSej/fowosISSYwNGUP0z5kStgu5KX2zt35HxoIraygTAi9Ok5l5PQ9nRp
         hxPsfxwsLEP7WH4vZpKstUtPYQHNBVikYIVYBowKkEngd2F7CzUQZF9WtK+vD6SCBOaN
         kZ3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qqJckw6yhk1noaFRDcPiSbmh/uysTDeKbackHyGWmjniYZ1NM
	jCSew9GocmsbvCfy1JrJfd0=
X-Google-Smtp-Source: ABdhPJxrgK+5zxN6DSrTGmj95u9XkoyyBZS8/G0VKTVK3s2V/un1J2wSm8TQgso94m68bSgwZyZg/w==
X-Received: by 2002:a05:6902:701:: with SMTP id k1mr12254095ybt.342.1615480107987;
        Thu, 11 Mar 2021 08:28:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bc4c:: with SMTP id d12ls2925473ybk.0.gmail; Thu, 11 Mar
 2021 08:28:27 -0800 (PST)
X-Received: by 2002:a25:3802:: with SMTP id f2mr12721053yba.48.1615480107542;
        Thu, 11 Mar 2021 08:28:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615480107; cv=none;
        d=google.com; s=arc-20160816;
        b=UmZbVQSkSQMWwbhlOL9tgpfeof3SVtrdbzEvzOA1jaTreDti+VJ3PtdZUhy8ec+ITT
         cwe5H/LDsb8GRM8qXnRRLjDSnbltBPd7AEKAI7ClUuiox7boQNLOfREuH9L5dwtP3VFu
         dUIZVnMKJYQhb+9DfOJHeYtb8GA+trljc3dD6WGG+JSoYOLMrZWQbHWy+AY1Mm/zWD5P
         JVvLczkaxi4D+A9EPosEmrO7n3Ge69mezeeobMm7rJPCfJKkLWVEx1tZw/uXBh6glQC5
         tPI2SaIwTvd//jZn8h+HdXhlmdz0EewolvXxrC/Y+PU5eOSvY+ZeSGhZy26BvJBuL4xQ
         y/yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=5iNJ/kvQ/CSqofP3aEMAPTJ/NlECEduQYL42tjr/MuU=;
        b=XDBdhZHwjDfLbr4pZZ1C05l8OwIvuFlpeZrm81174kCdbxSjfCaQ0sWsAJje0A3vSo
         aZTPJPoBhjzaBvmv2gbMCyxkr+r9FVdsdE7Fn5KVDT/Zv3p9uapXyBK54M2Mx0+2q6/q
         yFlqmWXcy7k2eEUnmfS2clctdb9gi88RxUKh2G/BIs2i+oaYkmkKU1x8J+2Hoi8jWknq
         WHIExIAbDmJX7UIciW523ENMfoLjCOHrU4COVsEFxEjqRoB75mrRl6V2ZsMDHJ1JLCmT
         tXF8bUZUIeWVKX/pPZ7byFZasXs5tyFxxQOPS2kFmtgX0qFna94nBxfA5NHK1JoKKwkv
         tsFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x7si238412ybm.0.2021.03.11.08.28.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Mar 2021 08:28:27 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B875A64F9A;
	Thu, 11 Mar 2021 16:28:23 +0000 (UTC)
Date: Thu, 11 Mar 2021 16:28:21 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v14 8/8] kselftest/arm64: Verify that TCO is enabled in
 load_unaligned_zeropad()
Message-ID: <20210311162820.GE30821@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
 <20210308161434.33424-9-vincenzo.frascino@arm.com>
 <20210311132509.GB30821@arm.com>
 <bd403b9f-bb38-a456-b176-b6fefccb711f@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bd403b9f-bb38-a456-b176-b6fefccb711f@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Mar 11, 2021 at 03:00:26PM +0000, Vincenzo Frascino wrote:
> On 3/11/21 1:25 PM, Catalin Marinas wrote:
> > On Mon, Mar 08, 2021 at 04:14:34PM +0000, Vincenzo Frascino wrote:
> >> load_unaligned_zeropad() and __get/put_kernel_nofault() functions can
> >> read passed some buffer limits which may include some MTE granule with a
> >> different tag.
> >>
> >> When MTE async mode is enable, the load operation crosses the boundaries
> >> and the next granule has a different tag the PE sets the TFSR_EL1.TF1
> >> bit as if an asynchronous tag fault is happened:
> >>
> >>  ==================================================================
> >>  BUG: KASAN: invalid-access
> >>  Asynchronous mode enabled: no access details available
> >>
> >>  CPU: 0 PID: 1 Comm: init Not tainted 5.12.0-rc1-ge1045c86620d-dirty #8
> >>  Hardware name: FVP Base RevC (DT)
> >>  Call trace:
> >>    dump_backtrace+0x0/0x1c0
> >>    show_stack+0x18/0x24
> >>    dump_stack+0xcc/0x14c
> >>    kasan_report_async+0x54/0x70
> >>    mte_check_tfsr_el1+0x48/0x4c
> >>    exit_to_user_mode+0x18/0x38
> >>    finish_ret_to_user+0x4/0x15c
> >>  ==================================================================
> >>
> >> Verify that Tag Check Override (TCO) is enabled in these functions before
> >> the load and disable it afterwards to prevent this to happen.
> >>
> >> Note: The issue has been observed only with an MTE enabled userspace.
> > 
> > The above bug is all about kernel buffers. While userspace can trigger
> > the relevant code paths, it should not matter whether the user has MTE
> > enabled or not. Can you please confirm that you can still triggered the
> > fault with kernel-mode MTE but non-MTE user-space? If not, we may have a
> > bug somewhere as the two are unrelated: load_unaligned_zeropad() only
> > acts on kernel buffers and are subject to the kernel MTE tag check fault
> > mode.
> 
> I retried and you are right, it does not matter if it is a MTE or non-MTE
> user-space. The issue seems to be that this test does not trigger the problem
> all the times which probably lead me to the wrong conclusions.

Keep the test around for some quick checks before you get the kasan
test support.

> > I don't think we should have a user-space selftest for this. The bug is
> > not about a user-kernel interface, so an in-kernel test is more
> > appropriate. Could we instead add this to the kasan tests and calling
> > load_unaligned_zeropad() and other functions directly?
> 
> I agree with you we should abandon this strategy of triggering the issue due to
> my comment above. I will investigate the option of having a kasan test and try
> to come up with one that calls the relevant functions directly. I would prefer
> though, since the rest of the series is almost ready, to post it in a future
> series. What do you think?

That's fine by me.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210311162820.GE30821%40arm.com.
