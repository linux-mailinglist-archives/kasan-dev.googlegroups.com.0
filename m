Return-Path: <kasan-dev+bncBDCPL7WX3MKBBNWZ722QMGQEUTRBJKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id D9C9195519C
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2024 21:47:03 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-270235bceffsf942478fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2024 12:47:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723837622; cv=pass;
        d=google.com; s=arc-20160816;
        b=RtsHMfqzpNmw0RI3s8ORzT/mbPiqitDmJ2D0dqz8at5m6Lz4jqXtsCAl6jCE85iwdp
         3CLouj4GCr4dg2Ot8+X49gY5cYGmwzslCuXqbEmDBHjV/f3ZoEgac6Q3b6kjTAEUDfz6
         zD0qTni4bdC9FybyDMJwaxGAQ/iauyZ9T6OhZ6x/hwItzNwwZpX/QbgMGVEkNbix5Wrc
         E7oZb5yAhWudJvVpvFOQRClliL+SdW3YEfyamTEcPfC3lzxcGjd9LecPOkqVo/t6ZIvG
         Z8ChhxFqczFBFsz7sOIG6nozHY9EuFvxcF5tPAQ+rKiq1cdnFgXwDZTfifW5SGH2vp4O
         xETw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bmpNCF9u0qJRhploi/YbNWLyBzfouAQJcJMZsk0+tbY=;
        fh=x8/QmA2pYiOtUklwYpkYwk/fzZUHIZkk03FymE6J/mg=;
        b=kIRwOUjwEACUBMVVL6w6EU0Gr1hDxr3MH5KcZiqXCuR/Me545b91ALVaaCdXBqjApA
         VMnb0x1k27PIIN+g+xRjhO25Ksq2XPv+0XarRzgrzhY7FsK3IHFtHJ17juRgJR5aT2PZ
         oFzLsusSt+FZ+idFHCw2G28CuxtVdMm9ZPUXY1gkKr+/ezn4vJ+YMTVZlT+bZH2hXEx6
         rvMk+XRoEqsemjrULtydMMSzG7gXFaBZPAS5hMdd9MGxLEawCNwvyltCRulL/Y/jGJ+H
         7D8iFoM9vjz8wyDIfSz2/mgYCQmGae/1aoWzCQ2TTYILIIoqwJiK0pgh/nReXjk9btnZ
         +Pyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Sv+EH4aM;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723837622; x=1724442422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bmpNCF9u0qJRhploi/YbNWLyBzfouAQJcJMZsk0+tbY=;
        b=rUIzuIXJhOfhGnPzdpS/Oaow++hot9UVPms85bavUc5/ZidPT5gSnPhJWv8eBbCk8z
         mAw0EKQxycLl1W37LlI4nXQuYG05MH097gTWMkFABP2U5uk0r8k2ef4TH9IJgn18Nu1x
         MWxfaDq8/6id8L7frvKansCkUe8Pjoh7Fd9ZfstFhVsalPNPOP52Cn7020WB5HxH3oen
         SDM0OFidChbpn9s9YVSoF9HZx6aEYuGnr7u/EOpnEpH7x49i4xINsMWvFx49qHNtmYf5
         emhaKf4shglrglHRtOQtF/Xfc0kDaJxXkWLjdOkZLvbRwhD0cEjIYuLg07PdnFydDPdp
         +X1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723837622; x=1724442422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bmpNCF9u0qJRhploi/YbNWLyBzfouAQJcJMZsk0+tbY=;
        b=pKHKCjebc9FE09XlXX6PNZqdwQ5CNF1RGasX9JkmH4YwHnUmgPmcLgP1qjC6AkO1/i
         5hElnHudMrrSY3Mhtv7AWdNzZwYpp3SD3o4yEp7/dLLZDhJtb22fKPDLdrWS4X80mfs0
         ajhTs6ciXurWTUVA773EDF01aDKbDFNaUrDhhuXncZkuEdWkK8e8Uiq7S0pbiaCvC6cb
         l90c2lSuks9Y2/SwUfwptFPp/XmtZ/0IWJXwLLdLAmU4MqoaXCPUhF0TxJ6n4Jiu3dDc
         gV5SxPDerhlk5+0n/VSupJyDGMwImQ8w0erpdw1bxXybe5l0vjtU7zoQK4RFx5TKVkCh
         y5zQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX3PXJsA5XGhhIojxBWO68/hlmiLA/H/w1caDkVmq3S+33YyXnGvwRdeZnLcaXL/xC66qy6+JYDQYo76ih8jijdibKex4wp+Q==
X-Gm-Message-State: AOJu0YzyXSQOSwZFMgrAWPhFfJzcxgjlTnbhU2U4O5vtpmnBdlMO8QAM
	OdOGm1kF0ShFJ9r6NCgk4vdJh59/B9JT9AyhTuqxL0c8zv3anUv4
X-Google-Smtp-Source: AGHT+IHZ975uPN2/FuAVrdbo/ukyXrcS4cULY+CMwGsAHx59HZ1hs8a3q7MNz6KR4wJFBGMkuRSQQQ==
X-Received: by 2002:a05:6871:3a07:b0:261:10b7:8c48 with SMTP id 586e51a60fabf-2701c3deecemr4651627fac.27.1723837622420;
        Fri, 16 Aug 2024 12:47:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:d043:b0:25c:b2c1:8569 with SMTP id
 586e51a60fabf-26fff3c6788ls2775667fac.1.-pod-prod-04-us; Fri, 16 Aug 2024
 12:47:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRVY9BKsKXzzbEENXDYarAPoJYmSAFs7jchLmgsnn0rSODIJSIVFAUCpSDCd+5I0ghfBKe4yR6Y03uNcMlcSAIxtR6WNKJkas6IA==
X-Received: by 2002:a05:6808:1454:b0:3db:3320:beba with SMTP id 5614622812f47-3dd3aceacf3mr4576980b6e.12.1723837621451;
        Fri, 16 Aug 2024 12:47:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723837621; cv=none;
        d=google.com; s=arc-20160816;
        b=IMJq9OH8/nzfuAOUA6ro4Y5oeTo91VrskBrUtHL2tV32uJfLhWU2m79iBAfY8z0d6z
         lEHFYmOz8+tpX8rmKTKEMaNZho9usdmlF4PEAujmitWrT/Jt+H9sA5VBA9kPplsHCM44
         s3HbiIc6yljlau+YG+Ws9XQf8wm2LvJXgU+QTVSsk0xsJ0fOMwR04V7PR6v9lGi22SYH
         7XbTG7/eXa/E6/ftoQ+0Gg2zgJsmVVw6oOLU/RVVXuYv9wng0J2hPbrPsQAh9J0ox2D1
         yJyI3ukJ+JEksX2Gryf9MnpSGBcSIyXk8TPvuaDZXnZwa8kFtbat2rnRHywqEaUT7HXc
         rD3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gL+xYRbW/YXsCNB49ljAke7oI2pj2Jr+l+W6Ga40FZo=;
        fh=ti8ooBhbbOCO/jhtzXvOIPeYGT8AtpMcGP7UrgoejNU=;
        b=sMwkl1sevwNolAo6vipx/DeO3un/AabID/7Vt/OHv9WuvE31FxVRr5zhBp8qCP9GdR
         zmTiGR4CZXqJ8FUFMXftV2Jq6IB2KA+PWLxxlb3z9e+j2uSD3iCqpx98nYl7fgLnk6A3
         AQyic6lThKHaBxwf6YcqEGfDw+jf3AvBTyNBjT4rimYvkFbY4XtcLUPJnN3m4YDT6qNi
         T+RZTdGeEGWGZ1JjPQO8X4Tevu3o3TSzkUKNWCWg+ScG78EvvrhsprgrsxDpe868osBf
         KwXoUtYvgqU3FkEKFtaBYFZsI+guGUffYoQxXqJtUylj925WD9O8aJFbeP9lnomm1ndq
         ZYAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Sv+EH4aM;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3dd33d3d011si200928b6e.2.2024.08.16.12.47.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Aug 2024 12:47:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2282162209;
	Fri, 16 Aug 2024 19:47:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C9411C32782;
	Fri, 16 Aug 2024 19:47:00 +0000 (UTC)
Date: Fri, 16 Aug 2024 12:47:00 -0700
From: Kees Cook <kees@kernel.org>
To: Jens Axboe <axboe@kernel.dk>
Cc: Breno Leitao <leitao@debian.org>, Justin Stitt <justinstitt@google.com>,
	elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	asml.silence@gmail.com, netdev@vger.kernel.org
Subject: Re: UBSAN: annotation to skip sanitization in variable that will wrap
Message-ID: <202408151400.614790C62@keescook>
References: <Zrzk8hilADAj+QTg@gmail.com>
 <CAFhGd8oowe7TwS88SU1ETJ1qvBP++MOL1iz3GrqNs+CDUhKbzg@mail.gmail.com>
 <Zr5B4Du+GTUVTFV9@gmail.com>
 <1019eec3-3b1c-42b4-9649-65f58284bfec@kernel.dk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1019eec3-3b1c-42b4-9649-65f58284bfec@kernel.dk>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Sv+EH4aM;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Aug 15, 2024 at 12:40:12PM -0600, Jens Axboe wrote:
> On 8/15/24 11:58 AM, Breno Leitao wrote:
> >> 1) There exists some new-ish macros in overflow.h that perform
> >> wrapping arithmetic without triggering sanitizer splats -- check out
> >> the wrapping_* suite of macros.
> > 
> > do they work for atomic? I suppose we also need to have them added to
> > this_cpu_add(), this_cpu_sub() helpers.
> 
> I don't think so, it's the bias added specifically to the atomic_long_t
> that's the issue with the percpu refs.

Yeah, the future annotations will be variable attributes, so it should
be much nicer to apply.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202408151400.614790C62%40keescook.
