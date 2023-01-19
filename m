Return-Path: <kasan-dev+bncBCOIBWPB64CBBVOLU2PAMGQEAQAES4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9458067436A
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 21:19:34 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id k20-20020a05600c1c9400b003db2e916b3asf117948wms.6
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 12:19:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674159574; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jw0DV3zhWIUZMSqPMx1I/CNsS3SzStwlJg291Nl5mDisN2dDm/CnoP8O8gSBxy7wsF
         AGDat+3gcg5or/rl38Dn6JyNustxKLzJHuxigQ+LUgcmnlGts6TNEXvZpTbofyB4x9iY
         /oWMVbqqQrUdz5y8JN/7cjOmrdhOIn24P7jJAQ3pg3grySyaHGKu/EOYq3jhpk9B0BW8
         fIDPPJTfLqoWS1WmlWsg/+5IZ3KM1AD1I9dGiN6xn1l7v3aHeM5TZStW4tJAlhRKV9e5
         5cX8ri2qLk7DzqP3Wi1uSVLTwIis4JypkMQds/iUMC76XPMVgGeKKRj6jEXZRN9Y+kJd
         GPOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dthWjKgRRXA7QtS3prle4paXMb79HPqfAg4pDVv4KfM=;
        b=Vl+n3FQwRyx0a8mZYxjIZ0zhxKfIXeJmJ8+Ch1ghc+PGCDsyzC2dUKSKYHWtfGv0QR
         J9m6NDmGQQ23Gcfmm5qQQ5MZayiqVFjtDsOLBiiliANhoiSbu+nUnj8LfxDDJ+8shY1W
         VSNu9xOlWErWN2d39c74wiGAjjl/Ghr6rcAredrGN5uHrLK0/2AgULF5oplPQWRvi7Au
         Kkm1Ommos0vUdEleJDlBZN1zA22ZOecV2V6m7FassuS6S2B968KcGuJV3Dios3txA3b1
         5+eLkAaPMXCT5i+82mi2YV/Taqui8Gj61mCLj0zhVIEjY19cKxjF9VWiSFuguBIb8n+Y
         zGUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Njq65P8q;
       spf=pass (google.com: domain of sethjenkins@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=sethjenkins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dthWjKgRRXA7QtS3prle4paXMb79HPqfAg4pDVv4KfM=;
        b=KwNo6Tuymq4otZaWHnb2gF5qVt3s4CCq/9VUlSMl2mS5ZcDDPd23XCZb/Emm6fjmuk
         rYX/L2lsa1WY2QG2ZFQCG+9mYN4GH5iw3I5bLCmee8v1jPT6KBuDLTWK7fuVBFRO88hl
         Sr51kNA0yMfIq+YkDzTgIMlaGnYNuxKuc6OT3eELkYoOU2Yjau8sAX7OeKrvp7rBcyuH
         fTqJKO2BXahn2ZEdBSjhs8/MzmUQn/LPHV2Ffuwig+NiLwhteVs6RlOhV2NpyFQnkRAS
         PoXKgDDMBEEQDevulsOEB6/2l5FbhjXZptAUhZJSOvn1dkeFPiCVBnFYTpw1mxUJl4EU
         fCYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dthWjKgRRXA7QtS3prle4paXMb79HPqfAg4pDVv4KfM=;
        b=CvJZtuUJBWD/kOMcJfuESqpN6FaiGm5RhEVw1iY/AcXN5oQpMqcl0hOr7z4pwaJK/Y
         SBXsQBegmw3NjVyhB7cmwDi1/cfggXIBYEmw1tPy0j3gmCHbigg8qO02YjvX4LtuwOob
         S1B8pRlSXjP46DPdMzuJSj72N7aWoHbSnDCl9KLbL+0aMTuVqq74kYGPQCvDWaIPXxOq
         kAEOyZwZu23Y8wUPYMUC6kN1KeDwwhoODYlN38KSavWJZ0k9PQH8AjEkSOesyO8Wjb3m
         AsM72cJceTDGkfPxYHxr+3myMZtH3WnXAlX+A5sznfFrvy8TitbNtEz3Y/RPq6VKFzc3
         ONNA==
X-Gm-Message-State: AFqh2kpJadCTJI9SejHtgRQPkHg3Y+1H22KlUSsbYRECzcBx7Y8vCsFR
	e4BoCqja3K2uUbzK7AoG+lQ=
X-Google-Smtp-Source: AMrXdXv6Knw/qOM3OD2acLPZZerBwl5MhBnw/phVPiWm4FH88IgKZRGbkWd/Y2EjCxKBmZSy3+lnNQ==
X-Received: by 2002:a5d:464e:0:b0:22a:f91f:674a with SMTP id j14-20020a5d464e000000b0022af91f674amr687612wrs.214.1674159573861;
        Thu, 19 Jan 2023 12:19:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbd3:0:b0:3d9:bb72:6814 with SMTP id n19-20020a7bcbd3000000b003d9bb726814ls1444920wmi.3.-pod-control-gmail;
 Thu, 19 Jan 2023 12:19:33 -0800 (PST)
X-Received: by 2002:a05:600c:33a8:b0:3d9:ed3b:5b3e with SMTP id o40-20020a05600c33a800b003d9ed3b5b3emr11118006wmp.19.1674159572893;
        Thu, 19 Jan 2023 12:19:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674159572; cv=none;
        d=google.com; s=arc-20160816;
        b=nZqGHeWA21gBXm1SlRJqLEBp5tdEjPIlTLW9HdUnKhAONmMvPzHtNSikO5LajiabeX
         INRo8iMg1LJLIrAzLmhmtuz01AziT43eTdOptNXRaS6+hoFGNasQQoYfdUaVeIyl5xiW
         q26NFo2K16LXnS5VQKpNkcRwt9VazaDalBtEY+mOxtL9zlbbZMCWjliIZmIFy1ozjckB
         fqoTUYeVbZ1xzOvdD+qrct8dGpQnSxE5LAH1vBOWaHJgux4TwMRhb+IcMAI2mf7N5PJ7
         QSLyt8lldH7lSgnxCiYP6RotfggGgkHiaT0qIQ1/kPaUfRaVNEVQJ5vzZmWX2666MB5c
         C6+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DwALFcrEiKMJKQDtzjjSGBC+/S37AZnAdeZoHTjv71c=;
        b=tTvo9YzO8g9QCED4dWIk/rOkaeLXgs5Utg6ZBbLRDyUtUUWdPWKnz3/t+nB/iXL+HC
         uLtkZC33HeVeMpStDFHXsifPgC2Pp9zFuoGWE+uNkT+/hNw9X9PD6OOxk71GxF7039td
         OOSlp8Y/l0TqXFVM48AG7irV4UrZK7m3uEw4EpK7aqz2quaXHzbWdw1PBlu3ZgZixKF7
         o422unSkimo4viMvPf+rZspyVXIS42RLCJwet4nQ6V7tP+BkosDzadl5pS5CR5Qylt4R
         Z0J9akV07em/ppGUuOQANCWyPxVXHDsc7cjxLcTjJb5D+sCzQ05YMbi9Hgq3BNNHktmG
         bsPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Njq65P8q;
       spf=pass (google.com: domain of sethjenkins@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=sethjenkins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id o10-20020a1c750a000000b003d9ae6cfd2esi10279wmc.2.2023.01.19.12.19.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Jan 2023 12:19:32 -0800 (PST)
Received-SPF: pass (google.com: domain of sethjenkins@google.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id v10so4330530edi.8
        for <kasan-dev@googlegroups.com>; Thu, 19 Jan 2023 12:19:32 -0800 (PST)
X-Received: by 2002:a05:6402:221a:b0:49d:836e:21f9 with SMTP id
 cq26-20020a056402221a00b0049d836e21f9mr1588134edb.36.1674159572334; Thu, 19
 Jan 2023 12:19:32 -0800 (PST)
MIME-Version: 1.0
References: <20221117234328.594699-2-keescook@chromium.org> <20230119201023.4003-1-sj@kernel.org>
In-Reply-To: <20230119201023.4003-1-sj@kernel.org>
From: "'Seth Jenkins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 Jan 2023 15:19:21 -0500
Message-ID: <CALxfFW76Ey=QNu--Vp59u2wukr6dzvOE25PkOHVw0b13YoCSiA@mail.gmail.com>
Subject: Re: [PATCH v3 2/6] exit: Put an upper limit on how often we can oops
To: SeongJae Park <sj@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>, 
	Luis Chamberlain <mcgrof@kernel.org>, Greg KH <gregkh@linuxfoundation.org>, 
	Linus Torvalds <torvalds@linuxfoundation.org>, Andy Lutomirski <luto@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, tangmeng <tangmeng@uniontech.com>, 
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>, Tiezhu Yang <yangtiezhu@loongson.cn>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	David Gow <davidgow@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Jonathan Corbet <corbet@lwn.net>, Baolin Wang <baolin.wang@linux.alibaba.com>, 
	"Jason A. Donenfeld" <Jason@zx2c4.com>, Eric Biggers <ebiggers@google.com>, Huang Ying <ying.huang@intel.com>, 
	Anton Vorontsov <anton@enomsg.org>, Mauro Carvalho Chehab <mchehab+huawei@kernel.org>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-doc@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sethjenkins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Njq65P8q;       spf=pass
 (google.com: domain of sethjenkins@google.com designates 2a00:1450:4864:20::52f
 as permitted sender) smtp.mailfrom=sethjenkins@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Seth Jenkins <sethjenkins@google.com>
Reply-To: Seth Jenkins <sethjenkins@google.com>
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

> Do you have a plan to backport this into upstream LTS kernels?

As I understand, the answer is "hopefully yes" with the big
presumption that all stakeholders are on board for the change. There
is *definitely* a plan to *submit* backports to the stable trees, but
ofc it will require some approvals.


On Thu, Jan 19, 2023 at 3:10 PM SeongJae Park <sj@kernel.org> wrote:
>
> Hello,
>
> On Thu, 17 Nov 2022 15:43:22 -0800 Kees Cook <keescook@chromium.org> wrote:
>
> > From: Jann Horn <jannh@google.com>
> >
> > Many Linux systems are configured to not panic on oops; but allowing an
> > attacker to oops the system **really** often can make even bugs that look
> > completely unexploitable exploitable (like NULL dereferences and such) if
> > each crash elevates a refcount by one or a lock is taken in read mode, and
> > this causes a counter to eventually overflow.
> >
> > The most interesting counters for this are 32 bits wide (like open-coded
> > refcounts that don't use refcount_t). (The ldsem reader count on 32-bit
> > platforms is just 16 bits, but probably nobody cares about 32-bit platforms
> > that much nowadays.)
> >
> > So let's panic the system if the kernel is constantly oopsing.
> >
> > The speed of oopsing 2^32 times probably depends on several factors, like
> > how long the stack trace is and which unwinder you're using; an empirically
> > important one is whether your console is showing a graphical environment or
> > a text console that oopses will be printed to.
> > In a quick single-threaded benchmark, it looks like oopsing in a vfork()
> > child with a very short stack trace only takes ~510 microseconds per run
> > when a graphical console is active; but switching to a text console that
> > oopses are printed to slows it down around 87x, to ~45 milliseconds per
> > run.
> > (Adding more threads makes this faster, but the actual oops printing
> > happens under &die_lock on x86, so you can maybe speed this up by a factor
> > of around 2 and then any further improvement gets eaten up by lock
> > contention.)
> >
> > It looks like it would take around 8-12 days to overflow a 32-bit counter
> > with repeated oopsing on a multi-core X86 system running a graphical
> > environment; both me (in an X86 VM) and Seth (with a distro kernel on
> > normal hardware in a standard configuration) got numbers in that ballpark.
> >
> > 12 days aren't *that* short on a desktop system, and you'd likely need much
> > longer on a typical server system (assuming that people don't run graphical
> > desktop environments on their servers), and this is a *very* noisy and
> > violent approach to exploiting the kernel; and it also seems to take orders
> > of magnitude longer on some machines, probably because stuff like EFI
> > pstore will slow it down a ton if that's active.
>
> I found a blog article[1] recommending LTS kernels to backport this as below.
>
>     While this patch is already upstream, it is important that distributed
>     kernels also inherit this oops limit and backport it to LTS releases if we
>     want to avoid treating such null-dereference bugs as full-fledged security
>     issues in the future.
>
> Do you have a plan to backport this into upstream LTS kernels?
>
> [1] https://googleprojectzero.blogspot.com/2023/01/exploiting-null-dereferences-in-linux.html
>
>
> Thanks,
> SJ
>
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
> > Link: https://lore.kernel.org/r/20221107201317.324457-1-jannh@google.com
> > Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
> > Signed-off-by: Kees Cook <keescook@chromium.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALxfFW76Ey%3DQNu--Vp59u2wukr6dzvOE25PkOHVw0b13YoCSiA%40mail.gmail.com.
