Return-Path: <kasan-dev+bncBDAOJ6534YNBB3PO6W3QMGQEGU7O6XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8251C98E10A
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2024 18:40:14 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-37ccbace251sf3333f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2024 09:40:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727887214; cv=pass;
        d=google.com; s=arc-20240605;
        b=CRE5nkhlYsqhCo7rbN8UUBPUtrCYqbPWcqj33RPJBlQw8cxKW0FC/skjte30DBGSdx
         GMkx1etx3VdlszrdzMgS73ys09PB4Gi9lBLIEKCX+WWL5oPDCgoQR8J66o98BVBJa1U8
         VQL5KpO54NoY+tibu65WtWNjuc+26CAhYh0zTIgczd5wCHidQjdcyxyFNTrlrKvEsFrt
         bAzpd6G0z9MVWTnVWlAPuew5fOOfHjgpnzYQe7bgXyq9n1ZiSldJDyCLSYjzaamF5D8O
         /kKQjN73cUbCnGnTnUUTjvrpHAi1avajj7KdB2E4XXAGKLtkvgpLMf2Kal1Q7P6nG6LH
         oyUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=RI699hK4a+gRXU3xoAzkvzoYRu5GiYqNPC+Nw395YpI=;
        fh=yzlQ8R2YmYa2OzNuBzFvO9OGmzaPAO/VtpSRB1W4ynI=;
        b=cVygTnt8F3z2tMae2tPPyhWhsoap33p2FFqhtVdw2QZfsuq9xX2qQOQiWvk9fTs/GR
         6ctnM3c63NeRmCbrW5ro/z3dngsP3uKRN1JBxwE29kbj0U2LzZSov0F4+P7C8zzzNVzE
         a48C4YHgLFuEWkU2ljQYubv1IGQfRZMmxGEjayjIHsSHiFyS2j4v1twRcN3HnkrXm5Us
         wdeh/c6Atq6FS4GMyqUcr370l/sB6/Osal9mRGFsjr/sh95VrS6a05oLZN0m4tKkGfvt
         jBIS28hNu7V0b/PqqEydNC3NnyQU2cqFxHBCG40eO3BjzPDUU86dKKP7jVHvZMIDMOjV
         bB8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="eWCTaK4/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727887214; x=1728492014; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RI699hK4a+gRXU3xoAzkvzoYRu5GiYqNPC+Nw395YpI=;
        b=algtxwZ3kuYRrvVU6rLnVOcqJJcIz2QXkcHZQ7H2Zqy68SgyU9QtF154UGJSGvStvk
         pyJ3vjpTvadwXv8kHvCx68RoCydfG77TY3v4y4bzbgXU5BnMDaU1Gx8f47ElBjjulLS9
         6gsrSSv8BH01rZzk9OPCmpmwZSzgO+O5UIyIUcrkj4Hh/wppfUnBvNRlgsmLxcCFirwl
         bBw09Kqv8tumqNnyU70my3dchTQjdwzbBlx2wJJBMhboRsmcXhs/dRkEudFYb5rjjNJy
         nd/nnj3X0em4kdaebP7q/9qkqB28hSA6Tjx6hBdyQLD9CA5m60xIcwd8gaauoAPwCg4e
         dt+g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727887214; x=1728492014; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RI699hK4a+gRXU3xoAzkvzoYRu5GiYqNPC+Nw395YpI=;
        b=kG78bazmzcJUp9lmSgKMPVrqiCBQ0FxdmAvLSlbqFdovgSNAdFcagZkY+aWTMMPUCd
         zDwX50a5OWE1CkDkyLKT+Aov5dbrtt329N3N5zCqdYDv6dTD3drgQ8l5z5aZgQS1U7Or
         clBmfNvHIalSKgkZ8iY2K8t1z3EV0bXmSh5S01exFHu7tynqMzK0N4lhx/WLtcWmKIbj
         71Xc+ZtTdRIRVgfXRzZpTn4qYfiC6y6vqHjtZIxUf7T+w49j7MSuSiYrA4JOoAmrqfYA
         4fobV6WOMyZaxgQR0A2eQe4td1HUX6468HFbCyaTr+8V6sjD5kla5h9LCX2G+Iu3UFMQ
         OZYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727887214; x=1728492014;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RI699hK4a+gRXU3xoAzkvzoYRu5GiYqNPC+Nw395YpI=;
        b=YHRXztEfc3F7xEykRiKvKIUDJi/4QuXhpCluT5kZFEuaNSUTTn9JbnwmXplAfUjssf
         PF90SYx/tUKlRz7GbSbuhuSzuJ5z7gZgQ9RyVFVVS9YqDkgVkLIoJ/1gbjXCyHz3FTU5
         bDv5eoAJhYfP0ma+DYZzWxB8hjMI30lnvdm8z96GwSTM+t0fHU98A3LbizWSXhdTCuwB
         azECdVTSV323pU6tPcczsFOcQ9qwhanyREwx4Lt3/w9a4sJYHefKvY0YLEVpbkG8Q9h5
         /hEe63Hmk+tKNIzFq8vukf2Aw86p7LTjJj5RUMWRpZnFdhLse57BJpo5e8Z7cqxd2cfp
         FKEQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+Dv7IW/wTJmIh2Z0xnQKqmkDcVuzqzLWdOt4jSDCRpHJj+zr1RCFtXDqN1gJ/jP+5dfk7Ew==@lfdr.de
X-Gm-Message-State: AOJu0YzM1GvSQnPWTEM/T1LwqMO1GvWnKhhdxa9SrpOKbV1WEB5PJyWx
	kFErjFHK6nlGSdnTqZTiF3rndaxJE1dSCAbCMxPLsJzhPp3UPWBf
X-Google-Smtp-Source: AGHT+IGEb8YLovAdP2UoVa5da/UbPOdbpPE19AKi2g4lQMiOHVHSwB/Ip00LxH+LTqVo+od5sKiHYw==
X-Received: by 2002:a5d:410a:0:b0:374:cea0:7d3d with SMTP id ffacd0b85a97d-37cfba19c03mr2811092f8f.53.1727887213252;
        Wed, 02 Oct 2024 09:40:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:44d0:0:b0:37c:ca21:c700 with SMTP id ffacd0b85a97d-37d04c65452ls11343f8f.1.-pod-prod-07-eu;
 Wed, 02 Oct 2024 09:40:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMNSed/OvcpFQa5wipGxNgZgiXNwHW2FvBn5ACpAfCkNem4DVyOsnMHaghv0AJbq8MlHjajj6TAPA=@googlegroups.com
X-Received: by 2002:a5d:6783:0:b0:37c:c5b6:ec11 with SMTP id ffacd0b85a97d-37cfba0a5dbmr2766383f8f.39.1727887211353;
        Wed, 02 Oct 2024 09:40:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727887211; cv=none;
        d=google.com; s=arc-20240605;
        b=lWLTI37gmLO3qZaV85mcINUhw+za+nTX9lekE+tkOSEQkuh3mK1eZkW1GiLgI1pPGq
         W1PMlA+vYRuGQaeJE9Gp4mtP0+7FUK5eW4UYIxIg0lt0yO9AepuHB6v86MKX31F1bPly
         VNy061//38/yfdlDh04CXP8aCGzLZdpQuYAvsxzr0SXR1Xe3CfpGg75Tlk43wGfymsXG
         Kor+Ay+xOIvGY384SgunIm+X8RxYZxOxd6OabPhn2/1Merpoj0P7L4pe+wFNsMeyBQNC
         WZ3g/yAIxX0dRlGWVpPR30ssMeCidmcxZXnGhhNEVmcISOMICWGt6Sw37MvbDiwItraV
         ROXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=atucTbQvnUu3RiHgioj3nleKoWYLpTdzHHtrixvOPdM=;
        fh=7CdpMgg9bgqFbCA/KI2Rck3xHrDLtllvjjbEDJTGn9Q=;
        b=SlfG0916QV4Vyyb3j2EQJl+0NF5lq8VrezMnNoLS3XmCrmmGvy9/qmFQ3ARS6vEekl
         C10ygGxw3r8tutRxQyVWMoRMRmZGXqROjiF/aX9wAI6XH7oZBvWgpOpGM5W1K3KcWT2m
         seFul3j4zlW2PmuFm7UEomfg/Je5Xk03XxyPak0d5DeeqcNT5AmGCcPjzUP6DfhNMuqJ
         /jDf5pSj4Fpgbaqb1Rfy9i/WDeXJPZQyAKuIDKt/dRdcknmrgUF+BArxO4mrq6SjrR0y
         mUrxI2yQwGhdAnOLXo7t8/lPmbeK/yyQAUaLAAQzULRV2jzeAmC57R9bg0X3CusZmJZI
         HZmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="eWCTaK4/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37cfcfe85a3si36730f8f.2.2024.10.02.09.40.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2024 09:40:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-5c5bca6603aso8294578a12.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2024 09:40:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUGfGGmWBmIhz4vH1o2fArLhJTRbquxFv/0ucP6f9iatUtw9eye0Scm6cXlYcvJFYl5javtDNlfE6A=@googlegroups.com
X-Received: by 2002:a05:6402:3486:b0:5c8:bb09:b413 with SMTP id
 4fb4d7f45d1cf-5c8bb09b89cmr1699747a12.0.1727887210576; Wed, 02 Oct 2024
 09:40:10 -0700 (PDT)
MIME-Version: 1.0
References: <20240927151438.2143936-1-snovitoll@gmail.com> <CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com>
In-Reply-To: <CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 2 Oct 2024 21:39:57 +0500
Message-ID: <CACzwLxhjvJ5WmgB-yxZt3x5YQss9dLhL7KoHra0T-E2jm=vEAQ@mail.gmail.com>
Subject: Re: [PATCH] mm: instrument copy_from/to_kernel_nofault
To: Marco Elver <elver@google.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="eWCTaK4/";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::534
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 2, 2024 at 9:00=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> On Fri, 27 Sept 2024 at 17:14, Sabyrzhan Tasbolatov <snovitoll@gmail.com>=
 wrote:
> >
> > Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault()
> > with instrument_memcpy_before() for KASAN, KCSAN checks and
> > instrument_memcpy_after() for KMSAN.
>
> There's a fundamental problem with instrumenting
> copy_from_kernel_nofault() - it's meant to be a non-faulting helper,
> i.e. if it attempts to read arbitrary kernel addresses, that's not a
> problem because it won't fault and BUG. These may be used in places
> that probe random memory, and KASAN may say that some memory is
> invalid and generate a report - but in reality that's not a problem.
>
> In the Bugzilla bug, Andrey wrote:
>
> > KASAN should check both arguments of copy_from/to_kernel_nofault() for =
accessibility when both are fault-safe.
>
> I don't see this patch doing it, or at least it's not explained. By
> looking at the code, I see that it does the instrument_memcpy_before()
> right after pagefault_disable(), which tells me that KASAN or other
> tools will complain if a page is not faulted in. These helpers are
> meant to be usable like that - despite their inherent unsafety,
> there's little that I see that KASAN can help with.

Hello, thanks for the comment!
instrument_memcpy_before() has been replaced with
instrument_read() and instrument_write() in
commit 9e3f2b1ecdd4("mm, kasan: proper instrument _kernel_nofault"),
and there are KASAN, KCSAN checks.

> What _might_ be useful, is detecting copying faulted-in but
> uninitialized memory to user space. So I think the only
> instrumentation we want to retain is KMSAN instrumentation for the
> copy_from_kernel_nofault() helper, and only if no fault was
> encountered.
>
> Instrumenting copy_to_kernel_nofault() may be helpful to catch memory
> corruptions, but only if faulted-in memory was accessed.

If we need to have KMSAN only instrumentation for
copy_from_user_nofault(), then AFAIU, in mm/kasan/kasan_test.c
copy_from_to_kernel_nofault_oob() should have only
copy_to_kernel_nofault() OOB kunit test to trigger KASAN.
And copy_from_user_nofault() kunit test can be placed in mm/kmsan/kmsan_tes=
t.c.

I wonder if instrument_get_user macro is OK for src ptr in
copy_from_kernel_nofault().

If this is true understanding, then there is no need to add
kasan_disable_current(),
kasan_enable_current() for kernel helpers functions that use
copy_from_kernel_nofault().

>
>
> > Tested on x86_64 and arm64 with CONFIG_KASAN_SW_TAGS.
> > On arm64 with CONFIG_KASAN_HW_TAGS, kunit test currently fails.
> > Need more clarification on it - currently, disabled in kunit test.
> >
> > Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> >  mm/kasan/kasan_test.c | 31 +++++++++++++++++++++++++++++++
> >  mm/maccess.c          |  8 ++++++--
> >  2 files changed, 37 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> > index 567d33b49..329d81518 100644
> > --- a/mm/kasan/kasan_test.c
> > +++ b/mm/kasan/kasan_test.c
> > @@ -1944,6 +1944,36 @@ static void match_all_mem_tag(struct kunit *test=
)
> >         kfree(ptr);
> >  }
> >
> > +static void copy_from_to_kernel_nofault_oob(struct kunit *test)
> > +{
> > +       char *ptr;
> > +       char buf[128];
> > +       size_t size =3D sizeof(buf);
> > +
> > +       /* Not detecting fails currently with HW_TAGS */
> > +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
> > +
> > +       ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +       OPTIMIZER_HIDE_VAR(ptr);
> > +
> > +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
> > +               /* Check that the returned pointer is tagged. */
> > +               KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_M=
IN);
> > +               KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_K=
ERNEL);
> > +       }
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL(test,
> > +               copy_from_kernel_nofault(&buf[0], ptr, size));
> > +       KUNIT_EXPECT_KASAN_FAIL(test,
> > +               copy_from_kernel_nofault(ptr, &buf[0], size));
> > +       KUNIT_EXPECT_KASAN_FAIL(test,
> > +               copy_to_kernel_nofault(&buf[0], ptr, size));
> > +       KUNIT_EXPECT_KASAN_FAIL(test,
> > +               copy_to_kernel_nofault(ptr, &buf[0], size));
> > +       kfree(ptr);
> > +}
> > +
> >  static struct kunit_case kasan_kunit_test_cases[] =3D {
> >         KUNIT_CASE(kmalloc_oob_right),
> >         KUNIT_CASE(kmalloc_oob_left),
> > @@ -2017,6 +2047,7 @@ static struct kunit_case kasan_kunit_test_cases[]=
 =3D {
> >         KUNIT_CASE(match_all_not_assigned),
> >         KUNIT_CASE(match_all_ptr_tag),
> >         KUNIT_CASE(match_all_mem_tag),
> > +       KUNIT_CASE(copy_from_to_kernel_nofault_oob),
> >         {}
> >  };
> >
> > diff --git a/mm/maccess.c b/mm/maccess.c
> > index 518a25667..2c4251df4 100644
> > --- a/mm/maccess.c
> > +++ b/mm/maccess.c
> > @@ -15,7 +15,7 @@ bool __weak copy_from_kernel_nofault_allowed(const vo=
id *unsafe_src,
> >
> >  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label) =
 \
> >         while (len >=3D sizeof(type)) {                                =
   \
> > -               __get_kernel_nofault(dst, src, type, err_label);       =
         \
> > +               __get_kernel_nofault(dst, src, type, err_label);       =
 \
> >                 dst +=3D sizeof(type);                                 =
   \
> >                 src +=3D sizeof(type);                                 =
   \
> >                 len -=3D sizeof(type);                                 =
   \
> > @@ -32,6 +32,7 @@ long copy_from_kernel_nofault(void *dst, const void *=
src, size_t size)
> >                 return -ERANGE;
> >
> >         pagefault_disable();
> > +       instrument_memcpy_before(dst, src, size);
> >         if (!(align & 7))
> >                 copy_from_kernel_nofault_loop(dst, src, size, u64, Efau=
lt);
> >         if (!(align & 3))
> > @@ -39,6 +40,7 @@ long copy_from_kernel_nofault(void *dst, const void *=
src, size_t size)
> >         if (!(align & 1))
> >                 copy_from_kernel_nofault_loop(dst, src, size, u16, Efau=
lt);
> >         copy_from_kernel_nofault_loop(dst, src, size, u8, Efault);
> > +       instrument_memcpy_after(dst, src, size, 0);
> >         pagefault_enable();
> >         return 0;
> >  Efault:
> > @@ -49,7 +51,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
> >
> >  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)   =
 \
> >         while (len >=3D sizeof(type)) {                                =
   \
> > -               __put_kernel_nofault(dst, src, type, err_label);       =
         \
> > +               __put_kernel_nofault(dst, src, type, err_label);       =
 \
> >                 dst +=3D sizeof(type);                                 =
   \
> >                 src +=3D sizeof(type);                                 =
   \
> >                 len -=3D sizeof(type);                                 =
   \
> > @@ -63,6 +65,7 @@ long copy_to_kernel_nofault(void *dst, const void *sr=
c, size_t size)
> >                 align =3D (unsigned long)dst | (unsigned long)src;
> >
> >         pagefault_disable();
> > +       instrument_memcpy_before(dst, src, size);
> >         if (!(align & 7))
> >                 copy_to_kernel_nofault_loop(dst, src, size, u64, Efault=
);
> >         if (!(align & 3))
> > @@ -70,6 +73,7 @@ long copy_to_kernel_nofault(void *dst, const void *sr=
c, size_t size)
> >         if (!(align & 1))
> >                 copy_to_kernel_nofault_loop(dst, src, size, u16, Efault=
);
> >         copy_to_kernel_nofault_loop(dst, src, size, u8, Efault);
> > +       instrument_memcpy_after(dst, src, size, 0);
> >         pagefault_enable();
> >         return 0;
> >  Efault:
> > --
> > 2.34.1
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/20240927151438.2143936-1-snovitoll%40gmail.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxhjvJ5WmgB-yxZt3x5YQss9dLhL7KoHra0T-E2jm%3DvEAQ%40mail.gmai=
l.com.
