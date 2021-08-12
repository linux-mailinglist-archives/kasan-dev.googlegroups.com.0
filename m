Return-Path: <kasan-dev+bncBDW2JDUY5AORBQFU2SEAMGQE5DMPO4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 780C13EA4F4
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 14:55:29 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id f11-20020a05651c160bb0290192ede80275sf1946781ljq.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 05:55:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628772929; cv=pass;
        d=google.com; s=arc-20160816;
        b=RJzpYFP1lCNFHQkF8l5kZk9F0hmB2D9mgCFfuJzyG5+LpoFTJjL+Iee0eljxYgiD4N
         q6DIwmiUkii2N2nxHrUD7o9j2rUbIs7nnQE4/AncJfpysZNEjKApXDsYLjUBxObDbRBn
         IYv6OmXqRR5Byr1XZCYW4/bA+0Y6gr660sneT9Ud4qYWyYw35CJ9frOs9UUe+QVtgqOm
         23ymMlqUEK49N3Oo8yBnyeBCK1AnAo7uvFv00ch31SejPi0E8624n0UmW91oO8Hit+Vw
         xc+ulgqJZ4ifp3HkAy7TI1H4aNwxb+bL7EtwglUWjI/C1z5Ev/Q4iy2PYjEvOZpaX3ai
         O86A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=R0VbwStW/LOivM/MktuPJT4Bdm0HK1F/VcsC1F4HHxQ=;
        b=j8j2mfCcc3uYsfGqEkLn9+b/paD/XaaaGRhGJlwv/KtK8FW1YWHC3oxAX92kWHIsJh
         aZf66wsN483aMp03wZbzLcQH8N3a3rwZ746csDD+fq1aHoFCNXfEEfLQmcmN98/CRiMz
         JWx4BbCmPtaTXlbvPyUxJxBdwjUbPXeyxVZt9p6VHm7RZAuqaEX938WHY4DtiKqVvUU0
         3FoWHDv1/uE3RqJhaNV1D1gWoHsSYwk4tVWcOXQ0GJZzXTYvcLP29wvJidQIZDfDK4qL
         UmKNTEFj8Ko56up2+PauNSpf1gXc6rGCzRzp1gJWEYMNbE+yobFOXLs3cOZhNEGphDin
         sydg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VX3lXUnc;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0VbwStW/LOivM/MktuPJT4Bdm0HK1F/VcsC1F4HHxQ=;
        b=PqiQdxoQ8UL7x1UMoz7BJaVt81B61bjh5616S+OW4iZh11VZa+PSo0c5NSYriyXItc
         X+XWKPyiFPRoZnkA3isRSYB+zXKzArla0nV8mlgpLzssgLHmSfh6wfkk75wWhqJWk6eo
         olaBeimx6z/taJvZJMT65MNuwddCarmSyHq7ORxlwNEqonJRDZDe1h0aG2TyO7Tt4RXg
         a0WIlWGlbVc5CABdo330Y6k+XZZbjEdmDofxgbpWvz0fz3lwY7RoRhyROLjPXb3pV37C
         Ed5G18yp5Zz3F+Iy2ALgWijKe8ibFlXbUsvxQiIAlNg26wqC+Sp+GDnyl3VnVAg5xgN5
         vxSQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0VbwStW/LOivM/MktuPJT4Bdm0HK1F/VcsC1F4HHxQ=;
        b=rWUHJCYAXYSawh9v40EOPcjEh3SSgoZxAB+Tpg2y2efcC/0fOU3DNMcBWRfNE90sSC
         IigyFzmkK2CZijPFFxs445EY3fcZ8znsJDQwUFq3dJGeT0Pq6i+ftr6oo8TTZGDMnmzG
         faf6DHYiqZ49uxHO+9dX9b6xns45T82SsCA/94BHgjjtFMlD2HfJ/LfgiVROu4beAzrg
         NWhVmqR7gT1kvWQnaUg2wzS0VfdVxKfTHIxHWp5iI4FN09q52mvDxF06qVuRZKq6Oy01
         LdFBBgoyZgcspT2u/nJRM9cTO9qiZr7CWYQHr4KgV+JQ/bRsWqzf1ZZBJCukvimSVzte
         0Log==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0VbwStW/LOivM/MktuPJT4Bdm0HK1F/VcsC1F4HHxQ=;
        b=JL9x/4JDABFZ63Ta+RHrSNFnqd/ke98LW4KXxsZ3alIYezZWkEOfalLDVB2UaJOgV7
         9gKrf9ZtfWqkI0OMR6cgtVfU9qPxPVEHe+VIKb0ZqguL1PbkXlKg5yhCZleeKIg6Luco
         f8LQ5/KinE8z2w0x3FsHqwyS+oPTTW2EBQmnIyOEkBI0dZvyDB7yJxSbLHSFHOS7dZcP
         tfO4zZIqhOLAcryYyVaieX1QjKzly6Yro+v97eWUb1ODT1mfxkOGF7WIbhcrOtVDK7Ux
         ikFglmc0yL53v+JM83Nlj5HV0z4HnhjiL/LRL9151HMXc3u+j78mJbqv4Sy2Fg5BeQnt
         Tdsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531f+QSwWXHzMYxDJro7Xndm4YtmnnSpryKOypxRw+j5cPCpRVvJ
	LcJ8BkCKAE5oyAeju08meO4=
X-Google-Smtp-Source: ABdhPJx6gfygO+Pqr94PVODRx9I35gqostIhLCZsfku501PZGHgBplqMh1zeAcD2up4ftiJAqxbCkg==
X-Received: by 2002:a2e:580c:: with SMTP id m12mr2862056ljb.316.1628772929024;
        Thu, 12 Aug 2021 05:55:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5395:: with SMTP id g21ls427096lfh.1.gmail; Thu, 12 Aug
 2021 05:55:28 -0700 (PDT)
X-Received: by 2002:ac2:55b4:: with SMTP id y20mr2402086lfg.33.1628772928045;
        Thu, 12 Aug 2021 05:55:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628772928; cv=none;
        d=google.com; s=arc-20160816;
        b=fmwc6J6jkpKtTKsskZ8+i+KrnpUIBx1tIjf3EuO8HaYvlxPerrWLZFjFco5NWlAG0j
         2qzp+Gl/UadQPrIo6+1qAC9I4jzHwSm6WRzcsjdyuwJWRyUGHtSwKdqWPUiwUlvIlCKW
         J+SjWeJr3gTuIcByImGAAxOYDoM8It7Ry5eNUyxA7P6/WcJuw4hyek0bvpOAvVUq8Ywx
         EW2tqQhP/Qlei7hHZ+W13SXfiW5lOI/D8YueOgwhuIIkJD6sAeDVgWR1yawbQH9NSlnC
         ht743TktaGD0Ay2FgCXgZs4lMLODXHgCyAd9q6OTchdvQkxhtRBGv5oBle+z/yJDrCXS
         HX9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hetAWS8vJTkbvJ1Yuh2ecULwYt0HQ0q3zS2e3QmOOk0=;
        b=SOUCHRqUKnBsq9JZuUC06oA08fMf3CMBArDdSrXLGRJKDG2q0p/Wzi0+IgpQ4NCaD/
         GlMAhA5PR9k5r/H1EKnCi00FYUbh+yxGQRTnQgS1Z+i/kt++bD6uwE8J3JMdSw+QDQbj
         g02xsqYHuz0x4rE+nsiyHfYAICTImKUFPf8/qJ6fF1/g6bsLkwEeFYrLp0Uxjmb7OXmZ
         Gl0C4hdi+2zgOExjc8KzGazjJzdvozAph1ISr7ikiPAVSdfLRXyMQmmfK9WvCTbtUotw
         nPZR9anI/G7g0U4/gKnUlegQrFtkZeHccV3Yp8ZqnywrIWBKuYEk2E7T7ewlGw5+jlsi
         DLLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VX3lXUnc;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id k40si126131lfv.0.2021.08.12.05.55.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 05:55:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id gs8so11310409ejc.13
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 05:55:28 -0700 (PDT)
X-Received: by 2002:a17:906:d147:: with SMTP id br7mr3613564ejb.126.1628772927836;
 Thu, 12 Aug 2021 05:55:27 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <e9e2f7180f96e2496f0249ac81887376c6171e8f.1628709663.git.andreyknvl@gmail.com>
 <CANpmjNPGsD_nZbcDNVTeL-b9W7X+2_AhzNAiSLdtxuvfyNFMEA@mail.gmail.com>
In-Reply-To: <CANpmjNPGsD_nZbcDNVTeL-b9W7X+2_AhzNAiSLdtxuvfyNFMEA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 12 Aug 2021 14:55:16 +0200
Message-ID: <CA+fCnZcoPO8+43bNakv4_vaA=kQJmBkvUF=hDoE4iTGhjcnv6g@mail.gmail.com>
Subject: Re: [PATCH 3/8] kasan: test: avoid corrupting memory via memset
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=VX3lXUnc;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::635
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

On Thu, Aug 12, 2021 at 10:57 AM Marco Elver <elver@google.com> wrote:
>
> On Wed, 11 Aug 2021 at 21:21, <andrey.konovalov@linux.dev> wrote:
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > kmalloc_oob_memset_*() tests do writes past the allocated objects.
> > As the result, they corrupt memory, which might lead to crashes with the
> > HW_TAGS mode, as it neither uses quarantine nor redzones.
> >
> > Adjust the tests to only write memory within the aligned kmalloc objects.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> > ---
> >  lib/test_kasan.c | 22 +++++++++++-----------
> >  1 file changed, 11 insertions(+), 11 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index c82a82eb5393..fd00cd35e82c 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -431,61 +431,61 @@ static void kmalloc_uaf_16(struct kunit *test)
> >  static void kmalloc_oob_memset_2(struct kunit *test)
> >  {
> >         char *ptr;
> > -       size_t size = 8;
> > +       size_t size = 128 - KASAN_GRANULE_SIZE;
> >
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 7 + OOB_TAG_OFF, 0, 2));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 2));
>
> I think one important aspect of these tests in generic mode is that
> the written range touches both valid and invalid memory. I think that
> was meant to test any explicit instrumentation isn't just looking at
> the starting address, but at the whole range.

Good point!

> It seems that with these changes that is no longer tested. Could we
> somehow make it still test that?

Yes, will do in v2.

Thanks, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcoPO8%2B43bNakv4_vaA%3DkQJmBkvUF%3DhDoE4iTGhjcnv6g%40mail.gmail.com.
