Return-Path: <kasan-dev+bncBCMIZB7QWENRBAOWXGYAMGQESAPQJVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CAFFB89838C
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 10:55:31 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-515c91a7ffdsf516453e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 01:55:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712220931; cv=pass;
        d=google.com; s=arc-20160816;
        b=nkM2ezwOsKxvXSsA4ItjmWEcL7tIkeYQkW/B/aQFQ7Dg8N70fCitVxaqNdbx9tWLSR
         XSG4i3mwgwpMy1/dJvI0bbQTDwR71rRH0PDTrPMrydDlz+//+8efNotHiPDe3WFYOAVr
         hfsVlnn6joQwlW0jWoQytN1fIYHsXGLp+O3z5vBiw8yU6ySPAMgZeoiYp0TtbQpgu0W+
         Pa6nYUztgyDJ/BDSGVnb/T8Lc/k8ZSylljbKr7xZtEXrn3Jhl/xE8htMonlzIymQ+Sfl
         TjsjcPX+1FcmtHa5S5hpE6kQozNbEWwxpwweiemb9CAjyYA9V4m4aBNctZQPWcuPkXOQ
         ZUGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IVQb9GIRNU2QvmnuQ4G49P1BueebUQr6YbQ4ddozlKA=;
        fh=/kqXgH3GsejQ7LVlEoJTzRJ39WFHY80bVjb3ui24MoM=;
        b=K3Q7bE5AH6fhBaEzj3i4ZZaNczNDsfyM1q2b1BvboA5L0YM2lybH7eZWn4tYb/gvWo
         z3zPDUhCkHehcJojI2wIr218yRULNEEr+u3zWa1wakv6uwXtItW9BU+iqOpq44ZmKT1W
         J9L/jgZWFPC7BctMY1sL9ZhVl0foH3e4eYVGGcCsokAlM2ivVa+gm55OzjypeTW8Kkeo
         Je9JPzTBNGo9ySXMEPqhOaUqF06990RuZf5IAX8xWfwrmqpEFDJhbNMxoJsWb3FGDs5j
         sUfClAQL749NI/oRm0Tqd8CTHJZzC+4InZQTdRgj191Men1/3oa5AGi93939rxQ4NGY1
         lxUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mQen+zDg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712220931; x=1712825731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IVQb9GIRNU2QvmnuQ4G49P1BueebUQr6YbQ4ddozlKA=;
        b=LUzhFMQDYbgCzBSmVusMc6m/bVSVExJElTa6Dn7mNo5OapUiY7Ej0XpqCPiOxPoI32
         iI+wpVuHeIJXR6NUeYox2/wd7Wcyl/q2i8evn+eCby7ryxDFaRkrDdAbv+/Ii3o6fBE3
         fIf9w1d2UUG2ckcHTUteOahgow2TnvE56jjXCert/Zp068Q5a159GLfcbgmwcoXRIM7B
         3Awp2H1ILBIo3LeiRKmPIN6nKp3BrUPnAulSZXUVR9KGxIiaJZkJRdU9V+2wP1QE+uNm
         2NXiVgBzwpHf2ig8VzaxS1tmazdPj0Z3PEyfPFA15ELGTV2RZ9byamtdIXVRd/7qhhgM
         xr0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712220931; x=1712825731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IVQb9GIRNU2QvmnuQ4G49P1BueebUQr6YbQ4ddozlKA=;
        b=DAHq20LmxDXf21c0lJLsGChD6YRIGvYfTzx96UEXpWNZmz68PKDrpplG/4W8fUbWIj
         oBwUe9n1VsRm9jpn/RokpsAcsPveGPv83YBMMqfFb4CeHYNiNOOnh172ZbGyLu2KYPG9
         18T7L1a0SqaQEvVlutQMF0ivmvuxyYzn+pZba/fdFj0Zlp22wD8pdGIW5rDUHintPRHT
         /K6vg7zITsE9Oqj/lFq4PRAx8oJlmxb6yEU5DPVndGGuLlHAYwPKMIuBsuPQSqTb8UzQ
         iXfRVlx6PrvHL3FAnK6piOyfWSmQC9121DOUluRjABvzamfP2IpxfuVU4EiIee2HauYY
         ChEw==
X-Forwarded-Encrypted: i=2; AJvYcCVFWAZElG7NkZGfYDyY9QXfPoxrllt77Kd7xeVfQ2lLgsIuSsmGhqzpfj3kmtvDJA/aJybpvZEgwRhFH9uRzptIU7D887GvHg==
X-Gm-Message-State: AOJu0Ywu628zj/sP5foERe3M4wKrc9T5SpW4HgCkDRvOicaLywmRejej
	nyc39wD1gz2iZ485jdVTnOSTUQWOv1HkvalH7uBtnwlU1Ynq2bjb
X-Google-Smtp-Source: AGHT+IEpEvpLLgxV8PUfmrSuw3T86ymLqEK4W8hDyxJQ18HnTYWEg8BFdEJC6MH/EzwpIVEcx35AsQ==
X-Received: by 2002:ac2:5ec6:0:b0:516:d0c2:3ff9 with SMTP id d6-20020ac25ec6000000b00516d0c23ff9mr186800lfq.67.1712220930305;
        Thu, 04 Apr 2024 01:55:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:615:b0:516:be4a:286c with SMTP id
 b21-20020a056512061500b00516be4a286cls108478lfe.1.-pod-prod-05-eu; Thu, 04
 Apr 2024 01:55:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5veuDehQNRxEO6wvoktUWJEhPLONPqFxZY7t5f4wDy6gSXGKpj3iLi5HzeVmu725B7Z72ZChrR351hjmUEuwoNfHNQCV5uDlRUw==
X-Received: by 2002:ac2:4c39:0:b0:515:c141:2a32 with SMTP id u25-20020ac24c39000000b00515c1412a32mr1657830lfq.35.1712220927665;
        Thu, 04 Apr 2024 01:55:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712220927; cv=none;
        d=google.com; s=arc-20160816;
        b=N1VJPi8HWJG/kgi7hFP4XxCZG/rYSdUo/ut/3mKOfu15R6QzaktyXowFE4unEvO+aD
         5NooU/yF41MH+6x07TLTTzRcFnW0mFSeDvsqh5BjhPXkuhpl5rLL9tG7iKn+G4kv8tHC
         Xx42x0fLyxyCrXL/KOqNEfhK9S0udJu9A58CwjNOWOcGxcYFpNV4qVX9kTPqyOd9R7en
         40IWYMpFLsos5du9ycWkOWEhLOcouZeQMKAOBqHLMcobWeMEdNVgM0l/Oz+5dhP8sx2s
         ThLg65u7guupv8wZlHDMYq5KOVhaCcHLyy4VBEL8jr8jPooWSdnhvxcqe2Zx6jRlqf+f
         FYuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t3+/tCR4hiyQCc/kSu8Ua48ZwM/P/iLQrVfSfzYNWog=;
        fh=xwG+lsh3/5U+xdm4Kmy60baNNn0J0s+Jr/dz5YPB9rw=;
        b=iRBLpje49lTjJV2y5QKICQg2CJqse3aeVVhtumRllVbdQzyYg3DaVe5WmDBTRZhT3Z
         TD/tAB1aWaAmLWnffXUXIgRUNq9T5icWSw59LZg+u4uLjQVPOk30zYI+dzScxBKjPFnr
         jXbSmdizL9pJarGuE1CkARrCVfaBi17wpWMlndZD/RoZN7KLyze0KcFeRDdsORSiwbxa
         338MbklcFFvaGSHyoCkc0Ewc7lHKybsUtgBI6jbBc7BQ8lf87ZhZEOrfhkSTpQVMPD8U
         Gc7t7LGlF2D9Sadk5kfYLj3OFVp1MwtM2+BFynJeL+9mmBSQ4PfPOCOIBe0s/F3V9wnz
         qvUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mQen+zDg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id r22-20020ac24d16000000b00515cb72e437si506440lfi.6.2024.04.04.01.55.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Apr 2024 01:55:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id 2adb3069b0e04-516d0dc0cf7so127e87.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Apr 2024 01:55:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNjk3Qa8EhvQyP148+oqJVePLaXP+7LHcQVNdCgCon2v78sOUbsw4vkSLQ/hk7WueFXi3qWC1jQ8uEYZBzK5s0EdkOpORaSUyPYw==
X-Received: by 2002:a19:4342:0:b0:515:b9de:e444 with SMTP id
 m2-20020a194342000000b00515b9dee444mr25478lfj.6.1712220927041; Thu, 04 Apr
 2024 01:55:27 -0700 (PDT)
MIME-Version: 1.0
References: <20230316123028.2890338-1-elver@google.com> <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx> <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
 <874jcid3f6.ffs@tglx> <20240403150343.GC31764@redhat.com> <87sf02bgez.ffs@tglx>
In-Reply-To: <87sf02bgez.ffs@tglx>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Apr 2024 10:55:13 +0200
Message-ID: <CACT4Y+a-kdkAjmACJuDzrhmUPmv9uMpYOg6LLVviMQn=+9JRgA@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Oleg Nesterov <oleg@redhat.com>, John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	Edward Liaw <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mQen+zDg;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, 3 Apr 2024 at 17:43, Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Wed, Apr 03 2024 at 17:03, Oleg Nesterov wrote:
> > On 04/03, Thomas Gleixner wrote:
> >> The test if fragile as hell as there is absolutely no guarantee that the
> >> signal target distribution is as expected. The expectation is based on a
> >> statistical assumption which does not really hold.
> >
> > Agreed. I too never liked this test-case.
> >
> > I forgot everything about this patch and test-case, I can't really read
> > your patch right now (sorry), so I am sure I missed something, but
> >
> >>  static void *distribution_thread(void *arg)
> >>  {
> >> -    while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
> >> -    return NULL;
> >> +    while (__atomic_load_n(&remain, __ATOMIC_RELAXED) && !done) {
> >> +            if (got_signal)
> >> +                    usleep(10);
> >> +    }
> >> +
> >> +    return (void *)got_signal;
> >>  }
> >
> > Why distribution_thread() can't simply exit if got_signal != 0 ?
> >
> > See https://lore.kernel.org/all/20230128195641.GA14906@redhat.com/
>
> Indeed. It's too obvious :)

This test models the intended use-case that was the motivation for the change:
We want to sample execution of a running multi-threaded program, it
has multiple active threads (that don't exit), since all threads are
running and consuming CPU, they all should get a signal eventually.

If threads will exit once they get a signal, then the test will pass
even if signal delivery is biased towards a single running thread all
the time (the previous kernel impl).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba-kdkAjmACJuDzrhmUPmv9uMpYOg6LLVviMQn%3D%2B9JRgA%40mail.gmail.com.
