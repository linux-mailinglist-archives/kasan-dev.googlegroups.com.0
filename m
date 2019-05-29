Return-Path: <kasan-dev+bncBC7OBJGL2MHBB35JXHTQKGQEHTBSKXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id E3A982D959
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 11:46:23 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id w6sf646152qto.18
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 02:46:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559123183; cv=pass;
        d=google.com; s=arc-20160816;
        b=GUQr9DlRuWzM+E0iZRrgmOwHxuAKee6su9DtRnqgi5SmjBRlNb7940MUGuSPSLUELz
         aABkdcOuttyxeJj6vBmfYFTWAutTd5e7wiHgMEVEH+C5YkG/Th2LFyegX96N67VPpP2x
         35bgA27tOKZjy8gbDGIzpS8tqg6u+IRB/E8G581MnEy6I0JtVqtvC5Axe5+WlAPW/LQa
         gIy12YE6TCjlcsL/tsQiEYXxCDElf49xiTsFP7iKoAHOT+s+NfQrHjWmlPsRufbjDzYx
         c7eMSVjT5voib//2oXXkr8lojBi8VUNw7DPuoX0+IG9JgEJl4RmZPbPzphtDaMu9/Wt/
         TvmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0acPoMRJsnPDUa1UZJUMDmQayhM/O9z8iJsr5fUguGk=;
        b=dHNvoxeyOPQfUi3ruyEb2OQ7MFr0raJl9wpWVyaiC6j0Zko2kmfnTrr+elb/mI+McC
         bVUyv+trkIpNA6aYnCYe41w6zIDJZVKUi9epmtg+h3ifJQUDQI/7ZjkOdOB36XreCXCb
         KgKg6ocMwuMQDht1u0EtWBezcJm6hnrYaViuqgPbwotvelekutsIpfSHHh0FDslOAHWL
         gT15grgbNw4B6NyUfGvRxHH90hNXU0ziSXYk6wbpufW9ofkDsTDSGh1GLJwTt9tIL14b
         4bPso8+Grr8Gzte367l/EeEvyrSGrdPWoJJSBb3bDEjXITXU+LQI6RUKvWNC/EmR1nfZ
         O4lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WQaepMq9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0acPoMRJsnPDUa1UZJUMDmQayhM/O9z8iJsr5fUguGk=;
        b=HxKa7W3+fSdz9IbSFrCTYuABPcI066hW8eTirjZz5lXFpJE4TAjB/O7rKFG/HF7DjK
         Y8mBx4gXVssrzXM2wB3CSpcY60m+U4M72sR8cZZTc38mdD1F0DtQK4cRQIKwKoigmlXY
         ODiSrqIt2qS2thewVurBFrUR6hyrKO33fgP5YriqHIF6ysWMg1pSB/WqGkx0irMRmW6S
         YbkbNJGT34dwshLgfpFyYCejzn+gKO4HHNx7EVtJ9id0izLAG9JufTSVljpqqstwYtBu
         k8Sv/9pqBTo+Eq730ilkgAXrBEoyE50WSJfmSWJt1SN1beQBwBiuALQ0cABnwpee6SkE
         K3CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0acPoMRJsnPDUa1UZJUMDmQayhM/O9z8iJsr5fUguGk=;
        b=kk7Bdz2MEjvu2mWetB8M2YxyexVd+fsEEi6XWtihZHjH9hPUD7lSB1E3iuTpcA9hqc
         80PwzcxUtnNvO9MOGklBi5rLJpD7xugTzY57VCTMh3zzbhdBjoBe0Gq8sw9KrmfvJgbN
         nGVtI6WkG5RtUmHAhGHe3wkrkhMri4Se9Qo1l+eJSy/OUu6SD2HVHqNRQw+DVKlBsGdi
         ErzZ1pDOfN2f8jZCOe5kFm+zoiSN4xz5ZMss2TTHIBIhQ4pDRlAEUzTFdNd4lcyjDIe7
         5dBpIVjT52UnaJMimFNf1e76SVaXoyUdTVGiiitTQfu+XZhypFFbSxm3w1fw69zKZnVD
         +DDA==
X-Gm-Message-State: APjAAAWiJBEUS6GWTuYslYGQWRob+eWR3rCa9CbztLbYkUq9rYAH4U8+
	+JOZDyTOa3mQxd3P1t+Nldo=
X-Google-Smtp-Source: APXvYqxI3pQNER7dwmhnQwV1iJku9bNg2McSSiuXC9prPCzs04WqXR9aOpx5FAIJLZATGrcrMilxxw==
X-Received: by 2002:a37:a91:: with SMTP id 139mr7871850qkk.301.1559123183046;
        Wed, 29 May 2019 02:46:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d0c3:: with SMTP id b3ls322788qvh.14.gmail; Wed, 29 May
 2019 02:46:22 -0700 (PDT)
X-Received: by 2002:a0c:9bae:: with SMTP id o46mr41615695qve.196.1559123182814;
        Wed, 29 May 2019 02:46:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559123182; cv=none;
        d=google.com; s=arc-20160816;
        b=0P3RWMasW0x+51CN4Pbf5V9DBOCVDDQn9G6NWMJoKkeULAkWgKVEiIVIxVS3L4YE1r
         BPLY6sNIKpEU91XuqEOnSvjzQmbktCPcp/t+odUPvALFu8eN8XHik2gfMM/01u6Wf92X
         EjhP0ycv88CKhV4S3T9cYT2dYA618+2JJs3HOHuErdDUqM5I8/rr6K9gC4tQtIGe7TKo
         XXz3w/52h4QOssfN1fySzX1AtfqV81Z+NtZ2xET1Ua53M/XifyS7o5y/uyDq7MpTtmeM
         J6o0pN2V8OqzCV0AqsLkfPDbpASrovp9zbIZqzgk23D8aAXwPEV2o+Y2wwDmZUrUma+i
         9SBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GAjjxbCt4+5cgrjM01YSZfWgmJp/G0TutPxW6NVwEDU=;
        b=tc/WRbXC7w3x/HhMmGLOnbc+sNYAv5EtmxZDK+V95NxwdYpNyFBHJquZXDV90SqmCp
         wYjR42ZNoN7aU+JgHPnaeD58s/DAnTIgb7Ca7A0MujxH079VNM7YJEPvNXhBpbxVimbS
         2Wb80YrmAPOC9uF+hDYg3WEYt2LvjQtJE5WxdXe8FMzNEvYhRElx4gtyEzwUmhmMCnoz
         ZoFXGt1WpSGCavTSCYEQpLdkXh8ysyox4z98SeuovR0JlbDSZ6DF7ywIkhI+gup5y8qd
         KzyJWJzlpZ1I0FZu5heRYxVGqsU2SxTQnuhHovoKZb9e7IY+PlonYuNr70hLbL7vGEeG
         jqNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WQaepMq9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id w79si712633qka.3.2019.05.29.02.46.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 02:46:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id s19so1380095otq.5
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 02:46:22 -0700 (PDT)
X-Received: by 2002:a9d:62cd:: with SMTP id z13mr2621053otk.251.1559123182136;
 Wed, 29 May 2019 02:46:22 -0700 (PDT)
MIME-Version: 1.0
References: <20190528163258.260144-1-elver@google.com> <20190528163258.260144-2-elver@google.com>
 <20190528171942.GV2623@hirez.programming.kicks-ass.net> <CACT4Y+ZK5i0r0GSZUOBGGOE0bzumNor1d89W8fvphF6EDqKqHg@mail.gmail.com>
In-Reply-To: <CACT4Y+ZK5i0r0GSZUOBGGOE0bzumNor1d89W8fvphF6EDqKqHg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 11:46:10 +0200
Message-ID: <CANpmjNP7nNO36p03_1fksx1O2-MNevHzF7revUwQ3b7+RR0y+w@mail.gmail.com>
Subject: Re: [PATCH 2/3] tools/objtool: add kasan_check_* to uaccess whitelist
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WQaepMq9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 29 May 2019 at 10:55, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, May 28, 2019 at 7:19 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Tue, May 28, 2019 at 06:32:57PM +0200, Marco Elver wrote:
> > > This is a pre-requisite for enabling bitops instrumentation. Some bitops
> > > may safely be used with instrumentation in uaccess regions.
> > >
> > > For example, on x86, `test_bit` is used to test a CPU-feature in a
> > > uaccess region:   arch/x86/ia32/ia32_signal.c:361
> >
> > That one can easily be moved out of the uaccess region. Any else?
>
> Marco, try to update config with "make allyesconfig" and then build
> the kernel without this change.
>

Done. The only instance of the uaccess warning is still in
arch/x86/ia32/ia32_signal.c.

Change the patch to move this access instead? Let me know what you prefer.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP7nNO36p03_1fksx1O2-MNevHzF7revUwQ3b7%2BRR0y%2Bw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
