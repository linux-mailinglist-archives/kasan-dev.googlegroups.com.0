Return-Path: <kasan-dev+bncBDW2JDUY5AORBFOW2SIAMGQENHD6SOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 70FC64C0141
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 19:27:34 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id k23-20020a05620a139700b0062cda5c6cecsf546229qki.6
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 10:27:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645554453; cv=pass;
        d=google.com; s=arc-20160816;
        b=GeRibAWHD2gQKvwsrWZ1giMLvrUvm8KLQ1nmqMmWaLanG51+mykcgbVXNdd5yHWrNj
         qS29Sc+55beXxfErgMXDIs9HsiRLhFubxrcyeccMgQLKKeZx9J4JIRZNCX/HE8471BqP
         uDQHOBUmtfv/dkFEJLMcyoYAvEV73wkLGk8qNsOscLm6uCDHh2kweiMLpf8Eew7nYEds
         F9thDX0tfuqGcr1OLEUpbucQX7vFwIF6/h0hOsr43nIP18vuPBKdXJYxGqwXan9VtpuP
         m+KrsURhkli16CI9wBuv0H8B4mjlg9uE4sp/hMEMiHNfXstIMA/CFKmLYKS5o8ru1yFD
         zXrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=VJ/V2wJeDSN2mSoc9h1VYsPK9cKaNto3Fp9triBqKgA=;
        b=iGDISQPvmzu30IDyAFay9ffhvnsjTmX1b01BZmQH9CEfXYrEIKiMqfqG6UF/5Uujrf
         iPbfxCeyotJv3L32QZEJDOdm38ia4nuNhr3k+h34aaw185PTjcwZFHQx6x7Hb8x8Iw1d
         jHUt88xC4A2ELCUxDGoZkC+F5GOotAMYpZN/Ki1jZRSxsjSLf3RvXUBRmpyO6K8kIPI+
         lLbif8rp4jpkms+8ktcIi8xmS2vvF/ZrU2Q9l+CgvTuX3dBY5lmfEGt8//4PELBU9rW0
         C/5eowkhAdmibuff7IuQlyZEvEdCHn28hUvDH7u1QsC085dHgvSGd/Xi/nD2o2DyT3Ve
         85yQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=X1llFE4v;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJ/V2wJeDSN2mSoc9h1VYsPK9cKaNto3Fp9triBqKgA=;
        b=n08GZbQGA68tLyEHVNZTKPR9wxj9Dr650dT+tAhPhsAVyTApG95pzKyO3h/G+BFFMX
         f7gnku6/dAXl6kkkLlzskIgAF6knR09Di6bvVevpY3bdDG9NcCzWOH1WH0q6wBKk744A
         wzjRNMdMfRU5A8ONA+uuH2d3Qm1lnTNbxHtVa3eEFFaKp51JNcF80ktrc625QjRJGqrA
         8svlVYhD6b+a8bSXyjENTVn1inMmiINK3Wf9ERcrfNi9lL6ZKDPd+QdCxz3PrA79CE+R
         hiwCGH7aVnBfFnWT3e87PMRIg8fJnkeZQsOU7+3FI7C1Jc0SjdmJmCL5J1aKHS1TA1UT
         0p1g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJ/V2wJeDSN2mSoc9h1VYsPK9cKaNto3Fp9triBqKgA=;
        b=MUkefnsqc1N2/wjOACwfMHoiMJhEFxFP+feNN4x9zCWouMGhgQcHNOgGeUkX4WrmNt
         /1yy3kxSxP2V235qgOdYHQk8z5KdZ7d1TmRDjfpA7hL7+NqNnkkkgm2uxo0ogL9D8cX6
         eZmikWJ+7gktq7/Ao0quS375O/ff/kXmeSrsA/lUeDWFMbARVqRCoTmsqaVtNz7CUoav
         W2JYgwvabkAmj1ZftOUS8t8XnErirX7MXO3ozBgBaC7jNrazpm13FiXDxkG1wE6pZKQO
         RHTOzXFlvoIAjRHRxcyORPQ3wx5YWao1Y8XoJNRQ5l39fpzWuBA8SyQEcAL47xV11O+r
         at/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJ/V2wJeDSN2mSoc9h1VYsPK9cKaNto3Fp9triBqKgA=;
        b=Fq/aBulu6/MiRVlvBj5/vKZRVd6aK/V8JW8OYXjCXfW6Yzp8hvvEfO3bdSn/GeLBqL
         +ckvN9gWiJr02oGy2a0OVm96N6NmoDuua600rjDwZw/EKCx7lwB81SQj1+H/v6YsZtBE
         CWobEoMwOxs9TKQZpu0QPPxOlTi0v45SHq20W2UtdZ7danlf5rfuV0cqsxNPXbMqOPIY
         s99VhXRxXcCahDGdygwMQcn4g3/J5LJdZr8mDmhVfe7XC2Ow5sN1CpkyXVBLCOqHsWbR
         iQqbkSzdH9NAL90Ocnou+7fEuba84o9I3CmslxDSsCiNYDwWRHu3ZZABexk3rnOr6Yvt
         nLSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530uLvPcAFVJYE0LWD0qkP+XQ6mH3jJFNxEaEAhfvhFM8Rt+ZEH/
	jZIzg/37JVEpdQssgGImApw=
X-Google-Smtp-Source: ABdhPJx0vYOoAHoBUT/i4gosGAbtSRgPQIu78xVmFdcTbdOIOJav6ovpl7RsVwZtreovEFzr9WZIVA==
X-Received: by 2002:ac8:5713:0:b0:2de:4e16:5b25 with SMTP id 19-20020ac85713000000b002de4e165b25mr3591604qtw.682.1645554453273;
        Tue, 22 Feb 2022 10:27:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:6:b0:2dd:d674:2067 with SMTP id x6-20020a05622a000600b002ddd6742067ls7385091qtw.2.gmail;
 Tue, 22 Feb 2022 10:27:32 -0800 (PST)
X-Received: by 2002:ac8:5cd2:0:b0:2de:6f28:58c0 with SMTP id s18-20020ac85cd2000000b002de6f2858c0mr2042651qta.311.1645554452839;
        Tue, 22 Feb 2022 10:27:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645554452; cv=none;
        d=google.com; s=arc-20160816;
        b=meqoRGxzvCoASM5SzAM6xtO1LwBtnysMndj2AXQl8tael/FM61IiHGfcov2zMSNhNz
         mMaU8sRbX4Wbc2NAaSADuycbuZxA6UJ9sVvCkeEy6JoDOQ5eap80JLDwics4Kc4TMigI
         xyIHXsrGgZD7KXbGjrze+CA1WJDUbXpy1U7aNGv/66Q3r0OP9bcuHXJUu1d776rNOmi7
         wUWdDZaWvnsdlUPgYx3H/Yon9LOpALWxOlW5LEek0XfYwdo+dY+/UG+HuwEsCBJtYadQ
         5FyFsbv5aJieygj9MdyKy6fruiQ65ETtAoil8cIDSOTnNtxGH2yqZjkZwaFcGtrTjmRl
         J8uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oObgooNlIOOo2XH59U0uuMMQ0kQeglBbkBAVHE8QeMY=;
        b=mfAcTkoHqioTCdphv2GJ1/+E9TGt2fzZCMrzu6vQMMbLXONc1/vx9C1bzhf5wkVGXt
         H4XI0ejshaORc7Yw/kjzJJZx2Q6KPraSwIa8E0gEm8T77aTUR+R/O6JILxwdiMOLm/bp
         4YOB2TZRX7jN70bvajRN5pImS3n1xhr/q8sv5mKGHORyccR17SzOlYYjfPfzWowaRAkG
         gUnDMw7E3xmWa+DTdkY6n8+LTFUKotmpmAcXfnix9B80iQJ1x9JDcMRvr9rNfVGfMsUd
         SPvucF6JfmuFH7EV8kjgI+E9BLFzmAXyS3jqcn49nlpLBmvzlN0oZju5RvoqomH2PUit
         hMGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=X1llFE4v;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id f33si27768qtb.2.2022.02.22.10.27.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Feb 2022 10:27:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id e79so21273245iof.13
        for <kasan-dev@googlegroups.com>; Tue, 22 Feb 2022 10:27:32 -0800 (PST)
X-Received: by 2002:a05:6638:10b:b0:314:ef3d:bfe4 with SMTP id
 x11-20020a056638010b00b00314ef3dbfe4mr6978543jao.218.1645554452615; Tue, 22
 Feb 2022 10:27:32 -0800 (PST)
MIME-Version: 1.0
References: <2d44632c4067be35491b58b147a4d1329fdfcf16.1645549750.git.andreyknvl@google.com>
 <CANpmjNOnr=B_o83BJ6b1S6FKWe+p2vR58H8CHtGPNPnu6-cQZg@mail.gmail.com>
 <CA+fCnZf2jE1N8j9iQRtOnQsTP=2CQOGYqREbzypPQa-=UXjhDA@mail.gmail.com> <CANpmjNN3-qX_brk9PTW0MkF0H=-DeM+n_ccge_QQ07oKBPx74w@mail.gmail.com>
In-Reply-To: <CANpmjNN3-qX_brk9PTW0MkF0H=-DeM+n_ccge_QQ07oKBPx74w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 22 Feb 2022 19:27:21 +0100
Message-ID: <CA+fCnZfy=c3haZqqmeBo6P1Fmt5s7dqt1jVfk=MEAJpCwuaR3A@mail.gmail.com>
Subject: Re: [PATCH mm] another fix for "kasan: improve vmalloc tests"
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=X1llFE4v;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Feb 22, 2022 at 7:11 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 22 Feb 2022 at 19:08, Andrey Konovalov <andreyknvl@gmail.com> wrote:
> >
> > On Tue, Feb 22, 2022 at 6:50 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Tue, 22 Feb 2022 at 18:10, <andrey.konovalov@linux.dev> wrote:
> > > >
> > > > From: Andrey Konovalov <andreyknvl@google.com>
> > > >
> > > > set_memory_rw/ro() are not exported to be used in modules and thus
> > > > cannot be used in KUnit-compatible KASAN tests.
> > > >
> > > > Drop the checks that rely on these functions.
> > > >
> > > > Reported-by: kernel test robot <lkp@intel.com>
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > ---
> > > >  lib/test_kasan.c | 6 ------
> > > >  1 file changed, 6 deletions(-)
> > > >
> > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > index ef99d81fe8b3..448194bbc41d 100644
> > > > --- a/lib/test_kasan.c
> > > > +++ b/lib/test_kasan.c
> > > > @@ -1083,12 +1083,6 @@ static void vmalloc_helpers_tags(struct kunit *test)
> > > >         KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
> > > >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
> > > >
> > > > -       /* Make sure vmalloc'ed memory permissions can be changed. */
> > > > -       rv = set_memory_ro((unsigned long)ptr, 1);
> > > > -       KUNIT_ASSERT_GE(test, rv, 0);
> > > > -       rv = set_memory_rw((unsigned long)ptr, 1);
> > > > -       KUNIT_ASSERT_GE(test, rv, 0);
> > >
> > > You can still test it by checking 'ifdef MODULE'. You could add a
> > > separate test which is skipped if MODULE is defined. Does that work?
> >
> > Yes, putting it under ifdef will work. I thought that having a
> > discrepancy between built-in and module tests is weird, but I see the
> > kprobes tests doing this, so maybe it's not such a bad idea. Will do
> > in v2.
>
> Additionally you could have the test skip with kunit_skip(), so it's
> at least visible. The code itself has to be #ifdef'd I guess because
> set_memory_*() aren't even declared ifdef MODULE (I think?).

I sent v2 with the simplest approach without an additional test. I
hope that's OK with you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfy%3Dc3haZqqmeBo6P1Fmt5s7dqt1jVfk%3DMEAJpCwuaR3A%40mail.gmail.com.
