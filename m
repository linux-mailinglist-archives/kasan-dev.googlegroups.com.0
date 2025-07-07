Return-Path: <kasan-dev+bncBDTMJ55N44FBBG7CV7BQMGQEWBUPMSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 17A95AFB85D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 18:09:01 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3a4eeed54c2sf1971835f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 09:09:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751904540; cv=pass;
        d=google.com; s=arc-20240605;
        b=efcwNxL+cN/9i81dnwqJ7deHxMSk8V2IMBilp+Ps4ktId3E/iWjRBRmVII/0WC7PgL
         IV9avcwD6KmAxBUp+9sIEdkYvQ4ODptlPzDByo4BhR8HLfaUx91R5hEhdmTzNComoEpi
         iNwJQ2B3Uxydk8K/oNI2hf058JtnSpSZ++bCLNRiYKQ0oZ0HPdYt4gFXpJhPwIB7FXxV
         q0nmcvy2IKoETEOeV9F+Uk8rnyHMfCs0sLXgT2b0i+zYnB3m5f4Iew3N7OVK3/9Fcp3H
         E3jGRYJwjWaKZ1x+XQw1BqCfan9IXVlIG78RhTuLZROvhuWFA8pvgGjcxPQJBCiRsMxc
         m0NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uuaecaF2f0IZjyXY6Ci6mvUVbWixnn76HTn4Eiywr60=;
        fh=AOjtQxjRqGj2Y2+8NvOgOORH7HD7EfhqT0k4VAQFGmQ=;
        b=Ynm5wcRj+tHraJ+3gmYT/Ec0+Esh4KgyyH429nBIXfdl/E3EvapQXzlsvxiVlaIrFG
         0uUVnwVyid/L6JsJZEs+2n2PuYy2X1xjTO/J8xSgS8prs2djwAawxU6rdK3kuWr7WQNb
         wxLKwPbrv+tCgrcYrvmiAngUy5N6db1uGJbqa+A+/ZHh5i+lhLXj3DOSy5Yaecwzv4Av
         EdCSB/41iItih48w0EWJlb0OQGc4I+yX0q2iH1m5kV+jrEdf9fn+Mi3h39eKcaw/LdpQ
         Vs5Z1R6dvxMhEj6+Or7kapGIant1sDnddmF09B7us9eLa0ao9kzGpv9MpK+Xu3a8x/T7
         +nqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.51 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751904540; x=1752509340; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uuaecaF2f0IZjyXY6Ci6mvUVbWixnn76HTn4Eiywr60=;
        b=sNdS2p73oswZ5ksNymnH61BZIWglbfIbdln2ZA17+X4BABn8a5nwWGeJHaBbpBreBq
         BsTy2fySidUl6nqDMg+bseZYBbpSco2YzzJw3hSF7f4Tl+gUzu+/bUDpEsGT6MIcNxZR
         O4kd/k/prMFQavP8k/y+1GFoa8FIe7ioxog5HarK3A1f4wsAGNUc5z3T8ZeHND+6he8s
         fCp3dOMs0U/iojSpbvtbVQssWGKmuywqbBYTFowutVLzzS24dTGjF12byLIudjnErJg7
         ATX6V3l/fs/3nZYSPGRdM0ZypDyDbRsKbHcQ7XJPeyADBegA99UCtB2IFNQXSvIKNI+l
         M2gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751904540; x=1752509340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uuaecaF2f0IZjyXY6Ci6mvUVbWixnn76HTn4Eiywr60=;
        b=u8E7eeUdbCidWlizugZryX5nHVtIHOHNKWlDCmcTI4GQfRRYfrhIgPb9g1UBGsWG0/
         /FS4fAoZdbW4ESUD+y2+7Wwold46jU+AhYoB/IjhipyWVehj7Jx98jplQUu/4OGvEHcB
         4sAEKje/dLzWqQXPWcGOLyK+j0sJpxjhpPJLhpZmzi6FfhHceCh5z4TW18FSvYfxgBFZ
         dIO1gvqlhlaWgf251FCt0aKfJ4fQk/kPxZe38bG5/+c8SGYBvjux1slXFRs4SC64lx+S
         DqvoKfaDW5BBKG9Fegjagje+HuF3ATMdHhylw2f7PBxTidnZxZvYmLwrmSRfjz9YFhv4
         Wj2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWNN4i4Ix8P22mqv2mEchrAwwP7cZwDoEvGFodO7jSa7aDnw8xG+Hzu8+gm7Ky/bit0kExug==@lfdr.de
X-Gm-Message-State: AOJu0Yxr8FqxUpAwXpZtpWOcQxu4bk/gpq/wYbZDM0pPqfismLW9bjPp
	S/DFTfczLkSetWt1TFO1f5b/o+41OIS8zw7EPR/N0IDWDJvRsepxQgcr
X-Google-Smtp-Source: AGHT+IFuLLnWgxMmotudGoMUd0kwJFcWynzBoN8fPGKC+4BqdoF+Me8/90qUSzmrBGo0TDQBTTLhtA==
X-Received: by 2002:a05:6000:3ce:b0:3a4:d31e:4af3 with SMTP id ffacd0b85a97d-3b49660bfefmr9248293f8f.37.1751904540161;
        Mon, 07 Jul 2025 09:09:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdr4VjK6on0uCBWmnV1IY4FN8t030UJy1i5jEqAeAWfAQ==
Received: by 2002:a05:6000:420d:b0:3a3:673b:52cc with SMTP id
 ffacd0b85a97d-3b497441047ls1698373f8f.0.-pod-prod-05-eu; Mon, 07 Jul 2025
 09:08:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX31d9K75yu9VMnVdzGvKevuqVbp8mAzdMvrw92GiTrrE7MnKaHsQXq7dq+jC26ADOwoulPcV7240I=@googlegroups.com
X-Received: by 2002:a05:6000:18ab:b0:3a4:eb7a:2cda with SMTP id ffacd0b85a97d-3b49660bfbdmr11120923f8f.30.1751904537067;
        Mon, 07 Jul 2025 09:08:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751904537; cv=none;
        d=google.com; s=arc-20240605;
        b=akEN0GhLBNEAWEO7KTXPFtMsbhPgiQ9k2OwW9ofcsmFCxaH029mOuViGTq3a2WmREk
         8rqHivM5FFwKLU8PPjh9L4mjaQliPvOcDkmzKg2LgZ8rm8KtM5oG1Kadyz/yB0DVdyWF
         fX+eojFsneiGTj89bmLrwjQGG75ZeEoSof6S32RiAWyHw3ZGwSH43XjLtJ/jsgIU33aL
         wDL2/scFCtZb5pJyVFXmhqBRc5krPtPggPFiQb/Ndf2HHJQIiOtwLeJSp2xdNEG0sIjF
         cKbzmhsJEdT+3c56sBZbHb9l57wXEB92na9wscoXqtWDmomq2msnhUEnJ7m1xjsX40XQ
         YsGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ukbvHzZfhwx6533qERNgaNRmfc+1+i0ljL79gEDoL88=;
        fh=4P9jk2lICBzBGND6gQscmQgm2sQ0Nk3Q/2dSEUA5ZnU=;
        b=a55nG01CmJc3p+Or7/vZrt/zNRkqCz8DYBZ4kn8au41Xf64lbFlCEukEq+NQ0iYYq1
         joSGuRUyyrgFpETkgZ9p9l/i/tRk4zKkirQgvtTN5yichm+oLlNuCahz9yWca94N75fo
         ML5ZEiP/VVncjcFnWCsrcnp7v3cr+Tvt/aevQ8OcdKu1RrQrH9GRQNtRwHxqm409F/yd
         9vjLoZJlGq2pjn8xOymZwyd6/wvicwafPjD3Rzm6CBdMcGl11oMd968+KahJOhhRn7Nz
         s/uMEDFLS3zSH/mifzWxFSD+sNHf7QuR6NLYo02mgVOJnR+drBShJqSDcfhS3afnpdPH
         czmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.51 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f51.google.com (mail-ej1-f51.google.com. [209.85.218.51])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-454c57a7553si747795e9.2.2025.07.07.09.08.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 09:08:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.51 as permitted sender) client-ip=209.85.218.51;
Received: by mail-ej1-f51.google.com with SMTP id a640c23a62f3a-acb5ec407b1so553185166b.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 09:08:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZaLCgeF3GlC9KEDCTSLslyDhOgqDOZ0G6+quPPqhKqLs5mRTzr82jLHlmquvqryGB6I9KCStLO+U=@googlegroups.com
X-Gm-Gg: ASbGncslnkczQPVlvDtgVycXvCtEIcqwAFBkbXEjyNyGi9dHKHLb6woYVyY4pwcw67W
	mQh5rD8Kx37Ec0dWOQY2PlxxhsTuq/y7AdsN54SPxxlWjwKrEvWOARrDuVlGRiYZbR8aQFXj9Kk
	J/pLx2LJqfD9yPniSzr/+uKvK/KxK0t1ZXkrhUFldjKV1cW/OnbAiqIJKKLhhVMtMDoQ5BXt7SZ
	M3SNj+7ReGv5ivWUX9BdONp+1gEOfRbm1GMmphU1oYY8j+mYgR2rnjwGaXrbdqs5YpW9HCIyIc8
	AtGfKilYrfO1tkpeMJM7P0q+AljRovnrz4rZzDKKEW5xbN5Z7j8CDg==
X-Received: by 2002:a17:906:2412:b0:ae0:bdc2:9957 with SMTP id a640c23a62f3a-ae3fbdea236mr1001311166b.61.1751904536006;
        Mon, 07 Jul 2025 09:08:56 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff:70::])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae3f6abfadbsm729371066b.80.2025.07.07.09.08.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 09:08:55 -0700 (PDT)
Date: Mon, 7 Jul 2025 09:08:49 -0700
From: Breno Leitao <leitao@debian.org>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Will Deacon <will@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>, usamaarif642@gmail.com,
	rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime
 stack
Message-ID: <aGvxEYDP8pVlalaz@gmail.com>
References: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
 <aGaxZHLnDQc_kSur@arm.com>
 <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
 <aGfK2N6po39zyVIp@gmail.com>
 <aGfYL8eXjTA9puQr@willie-the-truck>
 <aGfZwTCNO_10Ceng@J2N7QTR9R3>
 <aGsYkFnHEkn0dBsW@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aGsYkFnHEkn0dBsW@arm.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.51 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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


On Sun, Jul 06, 2025 at 07:45:04PM -0500, Catalin Marinas wrote:
> On Fri, Jul 04, 2025 at 02:40:17PM +0100, Mark Rutland wrote:
> > On Fri, Jul 04, 2025 at 02:33:35PM +0100, Will Deacon wrote:
> > > I would actually like to select VMAP_STACK unconditionally for arm64.
> > > Historically, we were held back waiting for all the various KASAN modes
> > > to support vmalloc properly, but I _think_ that's fixed now...
> > > 
> > > The VMAP_STACK dependency is:
> > > 
> > > 	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
> > > 
> > > and in arm64 we have:
> > > 
> > > 	select KASAN_VMALLOC if KASAN
> > > 
> > > so it should be fine to select it afaict.
> > > 
> > > Any reason not to do that?
> > 
> > Not that I am aware of.
> > 
> > I'm also in favour of unconditionally selecting VMAP_STACK.
> 
> So am I.

Thanks. I've played a bit with it, and did some mechanical work, and
send a v1.

https://lore.kernel.org/all/20250707-arm64_vmap-v1-0-8de98ca0f91c@debian.org/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGvxEYDP8pVlalaz%40gmail.com.
