Return-Path: <kasan-dev+bncBDV37XP3XYDRBKFI47UQKGQEI3XOUBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9940A7538F
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 18:09:13 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id k25sf5169208lfj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 09:09:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564070953; cv=pass;
        d=google.com; s=arc-20160816;
        b=IiNCU+3kOPNbl1QbOmTgMFcy6KT8+hZfFGkoUCo66HkSB/bQ4h9tY3JKMszldcBcDi
         0oCgSZ9K14w4sbl54FM1yAt13mO0F9mcz2pN2o0ug1npycjMG8bgy5ulB33oYoiK4E5g
         ZDxxNSLLEPCKlaSIYCAiZOrioWFWHtK9HMEvMZRQlAwsKHez5grbkcHdoUXmL7fwilSP
         yveyxRCac7rWRWNZ4c4X4yvhpms93daWXA9Sck0O9AMn55SdUtm4A71bfQfXe23FrYIj
         th6tZVQ/QqnY4sNHWReO66HjeYbykD2KcTtvyCzOZWeEORmXckg+pG/69lNJDhdjbrCv
         h+Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=5yHx4cBYnDwLpF+Ok+anSdgl/jx5p5+OkJJDicKjW+0=;
        b=Nv3geE/6EStszx3gHxmjKlw+++ehGWs+W9CUQt2PVPIKlAIQyPNGv4xFttWxUj1jR9
         Ej6Pwlb7wIG/jFfAtxfE3/X2ixtWFnsMuwH1ObOFwjI8ET2qx/f6BQQj8vRjB0N9jHzg
         fYhojcqBfZEiBdQkeMiL0amqukVv+lwHGEXVMI5RyTAqA2nL1gveIR0zac5C7kptTwWP
         zNLyit5AgNGVPZZjEw/urSLFqK+5rWSV+pEILmwU5OXrKHdguuYFDZCcU6//dKhi/KE2
         8BGVe022/Cn0EbI/YbIZFR3GkyN3WQCw8g6Mkz0BIxhq9L88L8/I7kXIJoTCMl7dxJUc
         MIqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5yHx4cBYnDwLpF+Ok+anSdgl/jx5p5+OkJJDicKjW+0=;
        b=MUwgD0yk14t11T9xm5C77LsyLyOWXzbN5nPAD/u/asvaOEbGr4L91BORWrhB3YbfDh
         qutAxxijPcplbG3xR23rLgxrB6oIx+aV6rh9crzqZVDWUwwpd0OEn+JuGZ5j5Ov5dJ4r
         COioFqeXyo0hdyS5GfQkb2wQ5C7pkzzSqrIq6It/3ysrrfWK0m4T55D1O62acsTkdiX0
         kW8T1Ew8J1g11bjPLBGWS4x5Rv4vuEY00BkgGzuMXGIJVs7EjdMI5EjTn7mazoTuGxA5
         cJkR1C2FwLDUjzMAv5fVrgXyw329mfzDc2JmscIOyed2lm4ZfRLR5T3jTl9iBItuaHgv
         J/QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5yHx4cBYnDwLpF+Ok+anSdgl/jx5p5+OkJJDicKjW+0=;
        b=MkO70pFJRyXb8hZHWXQW57Gm7kEsdsrC1eKYtqGCDAVQWaXyC9jIvDkWPdAxTX8v7Q
         p1rSiPg0Yiw+e9r0vaUqytNAKnth5sWqMZnKMlYDEuMV5aKGu3lyVztNYbzOm5+qow0w
         Aio1LnAzfzy8OxZyD38safhJWh0jluK9FWjaXfxM91WDEaSCu8GvHCYrYBvKaSRczqSZ
         F6EKahajC6qQulOU6KZT6KRTKWfTZitB5je8+5ylN3Sh0Y+32dO3qpBA0Mgg8ZtSJnVC
         WmsKRFj4eGZQAKfi1XPiq4uoTrWQtvzvxWJ0LyI31f61ZHcc9VEXaOenp9M4FhAWqaLP
         zohg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWBJjq34cQeryr0bVrqou2gPB6IDXKt8WbxGj8yOaDuhw0QJcfD
	ult1LT+2WcZpnbQT9oBcfao=
X-Google-Smtp-Source: APXvYqzX+Zknj4xWBft/fytlRCylf9iAz+xPBzes+I79BBNlp1ucr1oX3eeNjkTM7EwaXAJQkzwc2w==
X-Received: by 2002:ac2:518d:: with SMTP id u13mr6976977lfi.40.1564070953219;
        Thu, 25 Jul 2019 09:09:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:5b91:: with SMTP id m17ls5781485lje.10.gmail; Thu, 25
 Jul 2019 09:09:12 -0700 (PDT)
X-Received: by 2002:a2e:8741:: with SMTP id q1mr46115635ljj.144.1564070952427;
        Thu, 25 Jul 2019 09:09:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564070952; cv=none;
        d=google.com; s=arc-20160816;
        b=ckMiuHIR/Z0qaa6ccaG2CupSoSIiAmLW2IqyoLVOINwOrI7BsOW6eOJ311ioOkemX6
         S0mz69Nkm0wyP3sKzkplaHhTXLxGvydyDvJ5BSyv8BbzicX5DjLlSzMyP21wYFq9Oish
         udzWvjEyHhp0oH0eQiPDi5lzyh7owiRUdBamD0DKRNUccouB8Mo6xmfVJytmlRwaoSXt
         JqkViSUKGUJLOXgDiW67ugeVwN1I8ClOG3CyXPY1KsW4ia9q0yIxlqrqyJeay0N0OMDE
         CSr0tHw3cdolF2kQo65PfhISBRGShXvHQLHGLq/fsUrEJyi18jueGHpoaMzpt5Uzbw9b
         s1ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=PE5C2v0RqFx9Vaz90TU2SD4wxEoAkBRjqxHlhXXugeI=;
        b=rQdZ/C4Br4WcGIBNqtQ+c2HpJlZ/FSy7fcmKPCJaTQJ2wdEf5q8+WGqYWrxI2ptHzb
         yaOHmDkvAVj6gltUHXKjR3U+9QiALQJ6hJESbPgH/Au5spOF49EYojbomOSxuRopnBfo
         0XD5P4DsD4g5HRu5X2nWpcOH0bKxRrQ7sKFJDr8uyGpfxMD2bwlysSeo0ATuPLWiRdEl
         1jwmQLa8jAkmZakfPRaYzGLQihvg575SU19M9fQOD+8y3BufySP1kQtoRYY7xgDWFVpy
         LEP7APIOKIYBbsNSWVqqSrsUiHFAyqIEnTeREHl/CbhsWLunyRKg/X9mJcA6dzPfaMUY
         LDow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v29si2494072lfq.2.2019.07.25.09.09.11
        for <kasan-dev@googlegroups.com>;
        Thu, 25 Jul 2019 09:09:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 20645174E;
	Thu, 25 Jul 2019 09:09:10 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4BCDE3F71A;
	Thu, 25 Jul 2019 09:09:08 -0700 (PDT)
Date: Thu, 25 Jul 2019 17:08:59 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] kernel/fork: Add support for stack-end guard page
Message-ID: <20190725160859.GA22830@lakrids.cambridge.arm.com>
References: <20190719132818.40258-1-elver@google.com>
 <20190723164115.GB56959@lakrids.cambridge.arm.com>
 <CACT4Y+Y47_030eX-JiE1hFCyP5RiuTCSLZNKpTjuHwA5jQJ3+w@mail.gmail.com>
 <20190724112101.GB2624@lakrids.cambridge.arm.com>
 <CACT4Y+Zai+4VwNXS_a417M2m0DbtNhjTVdYga178ZDkvNnP4CQ@mail.gmail.com>
 <20190725101458.GC14347@lakrids.cambridge.arm.com>
 <87r26egn8t.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87r26egn8t.fsf@dja-thinkpad.axtens.net>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Jul 26, 2019 at 01:14:26AM +1000, Daniel Axtens wrote:
> Mark Rutland <mark.rutland@arm.com> writes:
> > On Thu, Jul 25, 2019 at 09:53:08AM +0200, Dmitry Vyukov wrote:
> >> FTR, Daniel just mailed:
> >> 
> >> [PATCH 0/3] kasan: support backing vmalloc space with real shadow memory
> >> https://groups.google.com/forum/#!topic/kasan-dev/YuwLGJYPB4I
> >> Which presumably will supersede this.
> >
> > Neat!
> >
> > I'll try to follow that, (and thanks for the Cc there), but I'm not on
> > any of the lists it went to. IMO it would be nice if subsequent versions
> > would be Cc'd to LKML, if that's possible. :)
> 
> Will do - apologies for the oversight.

Nothing to apologize for, and thanks in advance!

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725160859.GA22830%40lakrids.cambridge.arm.com.
