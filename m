Return-Path: <kasan-dev+bncBCM2HQW3QYHRBFP4535QKGQEPSABPOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 54CE0284371
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 02:45:10 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id ml20sf4773337ejb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 17:45:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601945110; cv=pass;
        d=google.com; s=arc-20160816;
        b=zzI8sozPywg46brv8xC1aShisd1mRuVSAbSUyAorbNOoWN0BAMoH3at1sdRFTBBWSC
         k9xG06FoC7l1XbN43EKAwDVCtjTq4LlETVKB7IjX71ayKUEXKQ47rUxw3IVG8hATmxZh
         V1sRQKYpLcI71Xrl4rtq9gXK1c0HYFsYn9OUtP0GrBIGfEdk2mC8Q+zBh75Munyo5pu7
         MgYv1/ZOYWUpaRu4M5Ar7N+HK6R9UJ5CMRoe0eWKyo7Fz1ZOz9TCv/6AHsH9MPx9EtwZ
         SMVU6FlHqa3qo5LgayA7R2uRzQyol2xlm6JqBSIKdnLYlbGT9yJELYPBEbg70RaNFx1i
         Erqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZfFzAVbK4hOUGMTOTOAlRZMwT87LoNeXq89Thk/OZvk=;
        b=CZoR4gLmrXPpZb7fwwOdqeMJ8PTvEtdsC5T9TsEd6+urHjRkn34Xufc4D1JubIl6hI
         A9EhqkvLIUMYXONnhpWEEM+0OFR3gHRylI7ZBnRNvopMqpcmSQfo91JZv3rtUN+xUREu
         /m/+qXvEk0l1UNg4CH/tVIfbMTmJumeATDwGWfdzktQxtRizuVL1p+wfY0VtjYsB0ts4
         GRHJneuFcia8KM19wdDsAvHeZSnlCfmER+HnT2y7k1mCAS7wS0vF9M3y9m6zX00hf7Xt
         HMrHNK5kgkKh6K/kEJqWmMVcFZJqLsl4XMM5/jMY8ecYAvhFJjd2tapuEsb4ugv0PtTF
         SJCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Onk4Nn05;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZfFzAVbK4hOUGMTOTOAlRZMwT87LoNeXq89Thk/OZvk=;
        b=Qy44LFeFa5zbjb0IneIR1RK2iFFGnJXbzo5xOF8rtUcHPoG6Jk9yViQxs2TV+LbBZn
         3Ah85A9ydc9VWloADRd6PfGm+gJ50MTxdVDW6aXSBSXi5WweGZzEK3VvQwsJQTGmehyh
         OuOXGJfexrpqfb1mtjY7pzaNiFMjxms26UgM6ddHd/PPduu+q5pwU1r5CK9gIaNxJ3rz
         Rkn8VJ4/3CQh6a7LRwYdTo9WhVKDeqN268P1dXZOcqDAUDD+mzB81GT6qEVeza2zqezC
         lEGYXFJqOq/PzvVcJZ7+0myV5M/tgHmugn4W48rU0Kr0Pk2vDR1sfKxoF/o7qC+BBX1L
         yFYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZfFzAVbK4hOUGMTOTOAlRZMwT87LoNeXq89Thk/OZvk=;
        b=oX/Ytjkaz0eWTnzzZu6+x+ZHcFrVwooFMaxRVaKlc/yvzBEg3LFA/4oY6FCUI+TmOy
         q5CN6kztLcMB4CWMve+Jcv5wBLF3dRv5lmxYjh6BYrt+CDivzQCw7tCaMQn+MojOQmCZ
         QCPmbFIR2C5D5xV6xe2U23E8t9RWgdo2BKG0H76ZU7uoDwExwRt0OPfKrEvNxpVIkOgw
         f9f3InJyfnfXyb+v/zm8HuoU+aXoJVhpQ7i45GrvseMxzPXKe+CVU56h3Run92mx25zi
         243dQwXjo4Hu6QkQgA81oQcGWhhZ1pCGs9fjCB1IykaXOf5Zlaf+1PyLg8sVtJnDmHJ5
         UsXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532trH8iY3leLk4QATfqcRARSykUYh2UZ/xmBAAmgKKl/piAGD+t
	rHTvQcY5hkDKlTsA0YX8VJk=
X-Google-Smtp-Source: ABdhPJydFWAfNnipbdkTNdx9MgRsaNCJr0zk5y3K+NmMrGssLgkqomSLb+aHVgOcVt/JJT7Gz463uw==
X-Received: by 2002:a17:906:783:: with SMTP id l3mr2509032ejc.253.1601945110037;
        Mon, 05 Oct 2020 17:45:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d3c:: with SMTP id dh28ls7261394edb.0.gmail; Mon,
 05 Oct 2020 17:45:09 -0700 (PDT)
X-Received: by 2002:a50:b063:: with SMTP id i90mr2589184edd.187.1601945109209;
        Mon, 05 Oct 2020 17:45:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601945109; cv=none;
        d=google.com; s=arc-20160816;
        b=xgEkTNYCfVOWmi3fPZ7z6o4eIJlFOVK0u/posqvAtBQW6JYxElun9cnOhNEqQ3XSZe
         W8wwd2DkWKAj07JB+S2yutyuu0QCDBeYOt1a/Mu4f5hnE61AmC8CfRTChRLs34rugM4V
         kpVf7W/QWICXcrNJd2+AxS+6WC9izC/CdynByx35UUAf/jYESseKUTCFvwa0e0gXcEhK
         r86WECsEUlv4WYohyLpEgdckms0VblG/t9iJSyhpoKeDpWaqnYUMJmGmNqgaB9ucDSV/
         gmzGRRhAy5taNrSTTTKovKwE/gS/v+uELCt48gNb+VTa6EIc1IhxfuWh1jWAA9D/2IRT
         Jh2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=d7VSZPo044cxIxYzl44q0fNIFgW7c06/GV69ntJURIg=;
        b=s51492U/4jwvMRSIAIKaioUKZw2ROJ8vVNIS7x5ZxFkcHzv97eKQSn0VkXA0u/zZpp
         +JLbWqN3rMDRp0CJg1KYmcf3fvg2gUnCaw2/lQrR915JnucL2mtAwnnwC4UZdPfNgpSn
         qIUlwTJoQhW+v2SJyBLqlr/WMK9kVUrhgIzKfYRBosUr5IvWuEnwWqykmaVrl8F4MTaF
         tXkVy352Z0/SjRtE4ymiNmY5SWws7BZUiSaAZNm/kolprCd3m2JqMSSmemEnSryPkn41
         mp6OJpU2TCbC0zIA/0oGq64dUjNeeL0a0De/xw8KlO8wRRup763N+lhrBMVMFaX42jbW
         u78A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Onk4Nn05;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v18si47643edx.4.2020.10.05.17.45.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Oct 2020 17:45:09 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kPb5S-00007d-KE; Tue, 06 Oct 2020 00:44:14 +0000
Date: Tue, 6 Oct 2020 01:44:14 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Jann Horn <jannh@google.com>
Cc: Alexander Popov <alex.popov@linux.com>,
	Kees Cook <keescook@chromium.org>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>,
	Kernel Hardening <kernel-hardening@lists.openwall.com>,
	kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting
 use-after-free
Message-ID: <20201006004414.GP20115@casper.infradead.org>
References: <20200929183513.380760-1-alex.popov@linux.com>
 <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
 <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Onk4Nn05;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Tue, Oct 06, 2020 at 12:56:33AM +0200, Jann Horn wrote:
> It seems to me like, if you want to make UAF exploitation harder at
> the heap allocator layer, you could do somewhat more effective things
> with a probably much smaller performance budget. Things like
> preventing the reallocation of virtual kernel addresses with different
> types, such that an attacker can only replace a UAF object with
> another object of the same type. (That is not an idea I like very much
> either, but I would like it more than this proposal.) (E.g. some
> browsers implement things along those lines, I believe.)

The slab allocator already has that functionality.  We call it
TYPESAFE_BY_RCU, but if forcing that on by default would enhance security
by a measurable amount, it wouldn't be a terribly hard sell ...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201006004414.GP20115%40casper.infradead.org.
