Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLGJ3L3AKGQEPNJVQKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 013D71EC271
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 21:12:46 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id a15sf4168694oop.7
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 12:12:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591125165; cv=pass;
        d=google.com; s=arc-20160816;
        b=z3URfxfNZcy2GCOU8UzX2/1STbRFALKTKR7fkKbZ9zwXJa8LpTsvbXu5buL1kgXkUg
         grQi4dkhj5+9diGzlNn6u7BYEKaJuQykot2Ob8/GcVr39SP27HhJOlCpWkpK8BCphn//
         NYRnxfyQFAv34NSQyWjkEjdJkxyemvkjK/hAgdHFgNWL9DoVp6e8PYpRy8XtaYE59UH9
         itCZzOUKIcLzpXoCK0GX4poyHx3Ymc8hlFq/1R8CbR4C4U81cWs3QPVVby8MGV+wHnlh
         qcErtWkQVNKQg3Js5ozRJCvrBCcbHktURoyovaAPmgbqytnoZpC4bPCB8RBJPBoWuOtZ
         OZ2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VkZ4Jg+A5tLZLCeoYQeZ367VtLscKkCUUkFAiRNJ6i4=;
        b=AeYlwj9SShaC2UXQbnVxK/ew1Wu+DXIRiWLgUxlj1eBz4TmSq5m1Ncd1i7oM1gmMAH
         QWqHCOfYeVTMjvr7sYsrTSroCc2f6h9gq+759ZadcTq50ChbzUXPCgdxhdda3hTO9A5q
         at2gzoI46rNoAPmJ0PZcSgWvuenLKuYWYXWSxaiTQEXaHuyUiGZh6+fsuC+ZgNLizT/M
         Jb2EXzocSxlW88R3A6WyYGwKLzu8nccCmJ1t+G5Gm+No5sJ2FScyaTaqOQ6PcC4EjTsl
         G6o/QDJpTWbJmwz0BNiL8Hf3IFOABaWPtVy8mCCsx5vKN3Vfq5ci45Z70FsYCxRkCM+d
         IAyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aF3rgGsV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VkZ4Jg+A5tLZLCeoYQeZ367VtLscKkCUUkFAiRNJ6i4=;
        b=kkS/wMwnuPVA0vtbDuHCDrL07zLMva5WtjnoPFSE+oHRd4j38msWuVNpMFZROHrLqd
         vv2eKm4sep+YgYNtFWVCwtezziywbKFr8D3EvZI0z0rpZC5gk+w2cBUcUW2Yo8AEBJB7
         XVs6CnlBdzT1knO5oojA7K5NvHe/ogObvIDzjSjYHQ3f8Wc6CUL6zsJir0nUqTQ4vScK
         mwzMZJ4O/edP1pNi7+7BXakt5ehHKyEusXRxHTiUE598gDdeshvIoktAST8wbe6IzyYS
         YYhEL6Qb/7tYjhzyUS6TY6yIB6HZdnoTxhqHRWcrhTbptv9jOeRxKlckbEkH9X914RPD
         sUsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VkZ4Jg+A5tLZLCeoYQeZ367VtLscKkCUUkFAiRNJ6i4=;
        b=SfXFKVhRqTcc6/61L/pw9edyyk4nkNnE9crc4bQPpofbq5JTp4i75aLLhlrnE4IuxJ
         BBUzkMKLZV+LDgyXsufm8+G8/i/nW+G/KTcqF/A0zDMKmlWXxKo6XNMEekH6rUWWkQS0
         AxIZ1NW1Dl69TlzagVfmsyKMG1zCJkjMaRV1WoJRGhVCAjHYQ/cVnmhtHFyGE7qSF4dU
         EqubqHr7zVO+CVNZPgmhaUeWth3RbGUi0aFDeqY41AZopcKWek+i4Uqi1zCTqc2NPowW
         cD7RhcIwfF9lsgUf/R2wUYQBTBdWQ6WoC6MJ5M+hDRi9vuff91J9mX2HNvV19Sf7S3Ny
         lsOA==
X-Gm-Message-State: AOAM533AFevC2fPIrL9gwJpMb3kEF5uKKePBj/sNkIqWQwyd79sKX6XH
	AMFBauDOKf9uIeWYY54Wo/A=
X-Google-Smtp-Source: ABdhPJxwp1cIiU1mMJWYum9XZP0N8v9JJQSJu3n3WtYPW1AsvavG4arLqaMV0d+y0JaDrhFwDdVaQQ==
X-Received: by 2002:a05:6830:17c7:: with SMTP id p7mr626284ota.22.1591125164870;
        Tue, 02 Jun 2020 12:12:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7d0d:: with SMTP id v13ls2047014otn.3.gmail; Tue, 02 Jun
 2020 12:12:44 -0700 (PDT)
X-Received: by 2002:a9d:6a44:: with SMTP id h4mr541742otn.287.1591125164542;
        Tue, 02 Jun 2020 12:12:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591125164; cv=none;
        d=google.com; s=arc-20160816;
        b=kjrcXfCH/tWsEBNu5BCkUUSa60SrK2+sk+ZpguIt5pW7Ut9M0TPibeTosljU7VPfBn
         d6lXO68C5O5wf+muZXuoudowQBU6TZH3Y04qqlz/jDNCGYzcXz+KBhbgCAnZOLZCsNlc
         gfNj8enHW/Tj55F8I2qc+idXSLF/NcY9TXIx+Hr0+EGcm4mNwzbHGpxpWBSmT+WtF6gg
         eQNVH/ihXH7QrXjcEqct9IFz7Jx7dfRfj67AcjrKATbZtHKWCbmcGwatE0quMDJz+ZCv
         y2aTDNhu+mL2wbXeMGS9PSl5MiDYzunfy8S9xlidIsJcxE72PgiZFgMfn61chN6Xkir4
         RaKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dT5kVRE874bAh/32tBP4Sh3AXgtH1D6NYtRpFWupE3o=;
        b=gnyzSgqW/yE1pb/Y6j2QXAt9nruWgAyoSZSchX2fP1jbQ8iJIZecIXK9ljbWC5pkVt
         JgqXPYz+tyW6TfeQAsj6xjHijOIrGacIURV2lVah2s9Z8Ze/lLFAgobgbVHpM35Ro3QD
         lRWNsUCU1r5L0EGNZTVmVp6js++vzCKklPwxHkzovQwtTRJaCWRSAZ1rphmHHFf+6XZ7
         NxtrLBGSscU551PpLmo4ZVdhD7Sl7HtRgyOt2W/uYTUUDsG8hJquK2OakHAOSrQoxXVw
         FeNFdRccZM4soeWh8BFsB7kyVYZQUYKepiD/wxOcQDZ20O8dmNPAR7D8AhE/chAAOY8S
         GiDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aF3rgGsV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id u15si356073oth.5.2020.06.02.12.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 12:12:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id x22so1245711pfn.3
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 12:12:44 -0700 (PDT)
X-Received: by 2002:a63:724a:: with SMTP id c10mr25112669pgn.130.1591125163555;
 Tue, 02 Jun 2020 12:12:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <CAAeHK+wh-T4aGDeQM5Z9tTgZM+Y4xkOavjT7QuR+FHQkY-CHuw@mail.gmail.com>
 <CANpmjNPi2AD5jECNf6NBUuFk0+j+0-RA6ceFCOPPvw5PtoQu2g@mail.gmail.com>
In-Reply-To: <CANpmjNPi2AD5jECNf6NBUuFk0+j+0-RA6ceFCOPPvw5PtoQu2g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 21:12:32 +0200
Message-ID: <CAAeHK+y2kfX32TbzcosCLSmr6sMB2BvEfKF8B1_4PrxgjKeLdg@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aF3rgGsV;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434
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

On Tue, Jun 2, 2020 at 9:07 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 2 Jun 2020 at 20:53, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > On Tue, Jun 2, 2020 at 8:44 PM Marco Elver <elver@google.com> wrote:
> > >
> > > Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> > > have a compiler that does not fail builds due to no_sanitize functions.
> > > This does not yet mean they work as intended, but for automated
> > > build-tests, this is the minimum requirement.
> > >
> > > For example, we require that __always_inline functions used from
> > > no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> > > fails to build entirely, therefore we make the minimum version GCC 8.
> >
> > Could you also update KASAN docs to mention this requirement? As a
> > separate patch or in v2, up to you.
>
> I can do a v2 tomorrow. But all this is once again tangled up with
> KCSAN, so I was hoping to keep changes minimal. ;-)

OK, we can do a separate patch after all this is merged.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By2kfX32TbzcosCLSmr6sMB2BvEfKF8B1_4PrxgjKeLdg%40mail.gmail.com.
