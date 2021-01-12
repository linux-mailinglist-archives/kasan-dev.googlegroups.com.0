Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQVD7D7QKGQE5VOOPRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id A7CDE2F3BC4
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 22:16:51 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id h75sf6129ybg.18
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 13:16:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610486210; cv=pass;
        d=google.com; s=arc-20160816;
        b=mAEq+FuVckeTVuC8rfeGGXl0X0TREN7HDcbTYvXbxG/Wlg2UueNH4rvHKH8HclTPXV
         ykjhmFrK4ZvtleqZOHcckzrAZbXsAMUugD3p0LUxI0BqWptnU0GA665aBE/cq20BN9VM
         yODwrCN15hveil2j30bpldVxejX9kpeboVpyJ6hpNoGAA4dBjG0PCtmj6FMRPvCxzxH9
         i6K43xfBBYy+Q42bYYZw7XkrFWu2slGpUv55RC5OVswlI7BijaV9LEN3/iJHkkHna5bM
         uBouOYqacmxmyQ4jlDH1X4dawbHC5uxLrpitmVR1AfkCzko5zbtWKlDTG0c1rQi8b9R5
         CmqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=T4Uiga7nVOIixnrUbe2K+DZTPwKe8G0Zk3akqPYRLOE=;
        b=RsvXYCux3e7L5kdm2eIuomiesmNZeZJwgFhoDqRmvQKutwhgk+LrHK8z4hqNRqNu9M
         giA3kWhjOI0IanTN/J7u0hRcOtqsro36Q9Gi7/sf+BZVb4681Op7ST+xO+uEsCOQn3dd
         e1cpbED1LKvfaltdJvoD4sgrJvnPM2Fc9GZpBPXtHFsO+IfsrZqv6QNCYFkhzTRzFlLh
         JgO2p9SyWZ2z1y9Ei506GDC5rWcefklHzAhxFZLTdTITJRBLAGgCqSIlN/RYeEnr7B4M
         biGnOQNXb4xwZNcQYJ7b1/sZ2VTlSlRKlBXcW8UGjtAt7Fh9ihopanPjc32Kf4P6UjbK
         ytaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tte5vz34;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T4Uiga7nVOIixnrUbe2K+DZTPwKe8G0Zk3akqPYRLOE=;
        b=KIC9bkibQ2znziqayWe605NCB2NGCLw4P2TLxo3ezZOG6jPD48ZPrMm+HsMXF6/16a
         tvgvJMRN8TbsfONuLkzMcxWyYyqDZYY+/a7IhUX65IcrnbDrD1z0/C2eOnZgnZ6kUnJ7
         7YrEB0Z/Lw6/MFe0HOkHs4lGZR9oua7MNCx73+nIhcFWtRUrGF/1PdVf41iuuQbbFiRQ
         6msOULRKtAOBUBiM4r7VqG1bNN9d4/pJbXjsWqPOeLK97ULJ/VEpB8nhv57PG730kavH
         I2Tpan6DY7cgq0PIdkgTdsl4R8SVxJ2iCguKXz0V60AaatikfTxLjdy9OkWVjdYUh700
         9aWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T4Uiga7nVOIixnrUbe2K+DZTPwKe8G0Zk3akqPYRLOE=;
        b=iEf7dWaM7HwrM4oyPRA62O2d3CSP3qtn+ZWrgBbnad2HceQuBTqPNZzf6SEVbBJxZu
         iLMxTbiPnWdbThJqP9izR7897eh5x0kmZR1zEuj+bf/XBvjiblzb4AAtY03C45uHDZ+g
         Hl7BN76hmGA61MUF0GPA1TRZuBVyvr+zXFBiPNOtDX827xarpFFXoD9KpNJMCCEupuHM
         TiwUv6NOqlpyRevLJ76AUJTB3Y2MIhiG41L/73srmCthsYtkt0TbOAisTOKov7TLFMm3
         k2endrRScPPr+YcsbGaOlenq8PqKuQTj8JJnt8wK7ab8dkU6HQzQT9DAAZngyysbEyPq
         jOTA==
X-Gm-Message-State: AOAM533TxJ5+Dn7mEYPw7xiukOUs41LyPtODAaH+Wb0yoVTUHwpadE5j
	TR/h9gdF9qU5h7meqMcbY88=
X-Google-Smtp-Source: ABdhPJyAnMQIHgk+r4Yxo9wAYyJZMrPkDhjCptS9hPGCAYEDlmoZgVRsC3gkmM3OduScZJSHPOVgmw==
X-Received: by 2002:a25:db91:: with SMTP id g139mr2116611ybf.48.1610486210702;
        Tue, 12 Jan 2021 13:16:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:23d1:: with SMTP id j200ls2148495ybj.11.gmail; Tue, 12
 Jan 2021 13:16:50 -0800 (PST)
X-Received: by 2002:a25:cec1:: with SMTP id x184mr2145405ybe.101.1610486210154;
        Tue, 12 Jan 2021 13:16:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610486210; cv=none;
        d=google.com; s=arc-20160816;
        b=lDuOU757STiv8KYeW9cGuHPwXSzBaDz6RyoB1okWqJoJPbzXMtrI6cHsUXOFqUapoL
         /KNDPjPOj3JLmRZ8ZchDptrBJ4J+o8/VDEWd8lauY0NLepuVZqNukiu4/JGR4nIdeawI
         lc6m/mbUisx92cYkaK4PlFYhU/GY1VyOPjbPQKOjEZc56xLs9CZF7P+YuLWIY6Wpl74z
         bOl3Y/9zNwHirF1DfFfqlIRr8fgsl2oV56b0MWjvFtpgTe3tUAaPSbUwvauTLPdy1eCZ
         qVZDRUY+GnHTtBD+SYH31Ez9IlwQA8Mmw3y8/FiO3bf/D4b6sES8JLPL9EKyuJTv3nrz
         Y4lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1LiS/Ah7gWBCj+VqG26e57TUr+FTn3EftEs4Z008F6g=;
        b=L305blXvDfOzhpb3QQpXi8xifnegpo126feEpnzr6MpUIb++3B4OWQQfx5Ge0o9rdb
         QIwTCRSRq0c4ix7TUfA4ZiXU57B4Mnp1CDLwZN3mrBwYZPNWLEHjXpJz36pnebknksTt
         mryCvzjzd9EEtBjpCaBe6M6x/4NBMsgkuS55AQO3g/EZ5vIy7H1rXWgGymFuLLGaICAb
         BVHz49fKOWoQqHfamX6imy85tV/LyzSL7rTLlsofIoriru7HqN58f82HzjmxbJ9ldp3X
         7pLKkRTw0dfKFWdDxMF+ND9zw23ZGcwQVSeiter0QtYZXItukfr9/4DPEGpSuJ9i8u0Y
         Xstg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tte5vz34;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id e10si1496ybp.4.2021.01.12.13.16.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 13:16:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id cq1so2231240pjb.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 13:16:50 -0800 (PST)
X-Received: by 2002:a17:90b:1087:: with SMTP id gj7mr1070271pjb.41.1610486209574;
 Tue, 12 Jan 2021 13:16:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <a83aa371e2ef96e79cbdefceebaa960a34957a79.1609871239.git.andreyknvl@google.com>
 <X/2zBibnd/zCBFa/@elver.google.com>
In-Reply-To: <X/2zBibnd/zCBFa/@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 22:16:38 +0100
Message-ID: <CAAeHK+y0nmeDEWG8ZMX9KmE3-MhWCtrssDJi5oHG2PFNtrDK_g@mail.gmail.com>
Subject: Re: [PATCH 10/11] kasan: fix bug detection via ksize for HW_TAGS mode
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Tte5vz34;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 12, 2021 at 3:32 PM Marco Elver <elver@google.com> wrote:
>
> > +/*
> > + * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
> > + * the hardware tag-based mode that doesn't rely on compiler instrumentation.
> > + */
>
> We have too many check-functions, and the name needs to be more precise.
> Intuitively, I would have thought this should have access-type, i.e.
> read or write, effectively mirroring a normal access.
>
> Would kasan_check_byte_read() be better (and just not have a 'write'
> variant because we do not need it)? This would restore ksize() closest
> to what it was before (assuming reporting behaviour is fixed, too).

> >  void kasan_poison(const void *address, size_t size, u8 value);
> >  void kasan_unpoison(const void *address, size_t size);
> > -bool kasan_check_invalid_free(void *addr);
> > +bool kasan_check(const void *addr);
>
> Definitely prefer shorted names, but we're in the unfortunate situation
> of having numerous kasan_check-functions, so we probably need to be more
> precise.
>
> kasan_check() makes me think this also does reporting, but it does not
> (it seems to only check the metadata for validity).
>
> The internal function could therefore be kasan_check_allocated() (it's
> now the inverse of kasan_check_invalid_free()).

Re: kasan_check_byte():

I think the _read suffix is only making the name longer. ksize() isn't
checking that the memory is readable (or writable), it's checking that
it's addressable. At least that's the intention of the annotation, so
it makes sense to name it correspondingly despite the implementation.

Having all kasan_check_*() functions both checking and reporting makes
sense, so let's keep the kasan_check_ prefix.

What isn't obvious from the name is that this function is present for
every kasan mode. Maybe kasan_check_byte_always()? Although it also
seems too long.

But I'm OK with keeping kasan_check_byte().

Re kasan_check():

Here we can use Andrew's suggestion about the name being related to
what the function returns. And also drop the kasan_check_ prefix as
this function only does the checking.

Let's use kasan_byte_accessible() instead of kasan_check().

> > +bool __kasan_check_byte(const void *address, unsigned long ip)
> > +{
> > +     if (!kasan_check(address)) {
> > +             kasan_report_invalid_free((void *)address, ip);
>
> This is strange: why does it report an invalid free? Should this be a
> use-after-free? I think this could just call kasan_report(....) for 1
> byte, and we'd get the right report.

Will fix in v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By0nmeDEWG8ZMX9KmE3-MhWCtrssDJi5oHG2PFNtrDK_g%40mail.gmail.com.
