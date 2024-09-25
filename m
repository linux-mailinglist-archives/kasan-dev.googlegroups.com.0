Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBGER2C3QMGQE5DEXXJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id AC3D3985CE4
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 14:56:58 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-42cb830ea86sf46852665e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 05:56:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727269017; cv=pass;
        d=google.com; s=arc-20240605;
        b=gFdkWu1231gfV5Sak00OymFk0/ecQLXz5CzqxZd+5atvDFJXle3zDrPoxDgNTryfRG
         hRsQnOyWyZgGx4MOD4H2fJ9pk80yGSKsvcBVwafjcAAQZGXzq4rxqlYE02xM/bwdMbcR
         q4ROyzWPoEILr0j2Fy3addhS5L+Nvy4oGPMo3f2Vi6BZZgRsC2EEb2RiwCOoLrxxSAWn
         3sP1Zm5BqOgvO5aSFQ0pFih5h1PMNnA40Bhv1tpAL9sNuRnY0nqhBLrL/k/tJDd8JVD/
         YZJanJIFmyayKPTH7e8ZVu37pJLvZLY2tcXFTWwadTHCOHs1/Dk+mmk5zef8qaBpefv2
         N+LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=D/jY3mHWPXU2EFH8PAE1mi7eNDiGvImS41D9MK6jts4=;
        fh=9SKgL1Xfz66DwT4G8lT7fq3v4lh2t2g5iZj6Rulp00w=;
        b=BZ5B7lSQMtGLuEVJ3UQXaigB0qxhE/f6s9DgIc+R7oe0p8d1PP9PX4ajUy5Z5MhBA9
         nS4Df1F0OP+IxNgpmnA3BcDgrxqTWIND9Bsw1AhzVrmZqXMgX4Jv7ZsFGHTDQcb7TbnM
         l5ph/wyGNtw5qqVyTUo5V964w9Fb4fEhpVM0ZZyzW+lvdIEgFHlVLmK5ZB+t9BNp57+A
         xBx1fRFd1/OcvS8N+6U2n8/g0dSLd3HdUjYhNBcER2taGx8qHGnc+0aJY9QeOycxzzUm
         enL0XGHT0Y9P15AHQ2wXzvp8A+uzfN5XPOA/jb9/FWeegFcwhWrOnoA1u6cyQW/5KB7u
         fgcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gIqQhZu5;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727269017; x=1727873817; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=D/jY3mHWPXU2EFH8PAE1mi7eNDiGvImS41D9MK6jts4=;
        b=C6adVA4QyO+4VoMjOTpVnR9DYTN1otPz21L9tPt0wVzEmkb05EidcvtUj0g7om5Prb
         iH+xtzG9aDQNrDstXd4qc9wjSOMJxyJjsKcqLCfcMVgfKHUyWOp3g6KZDtDYTDLfXB0f
         rRofm/atjVshc7MLLKJLSBXoyCmBT70Lc+EGbPQ7Vy6g3GIg4t6nP3vvzZDuAHY6duAl
         7XxwLiPxi9EP2vbGQQdm/q3Vpw9kfD6q2snwnTJmP/kLMmNvX2JtFzOPGqvZBHkQrOeF
         RUZ9UdXn9ghDRb/ZpXW4VBKJC78RpMeMoLGTN9rDtjZK7MbDDR09IjP9OlmmJwavtSFx
         Cezw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727269017; x=1727873817; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=D/jY3mHWPXU2EFH8PAE1mi7eNDiGvImS41D9MK6jts4=;
        b=W3IB5VD/2sT0o9k61B8eCJRNA5eTNZCt6P6/r8WRZleyXf3Oe2m1y7xVTGp4jSHVS+
         hItMcO04hZKApTgwsG6a0Tyh2agxteojn4UR/dNOMz5N5yQgyxW3ManpGkG9G1pXmd+A
         QyyCTWX1pM5YW6y2NrNxmk2yNt4ORc1HtsOGXPW7O9eenmPkATvX3VwZgfdqdLUbFOgS
         4kvkmKZX1dzW35QZL06BG/zDsJoaTVZNlTtp+bhmPINtY/3SbcPmf+FHfsgc7jTjrHBO
         ufSFIA0nfbGU0Nny6Y0H9BLOENetxw5m459l6Lr9seDJzJcwXekG/pLq23hA7+HpUDVZ
         DHJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727269017; x=1727873817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=D/jY3mHWPXU2EFH8PAE1mi7eNDiGvImS41D9MK6jts4=;
        b=uLL732ZOYJ/HjDmGapM4hiElXsQ03zY6EHtIFyPb4wsjIT49afvE389FXbnQA3zui5
         u8O8uYHVyjyIo0PZ3qt3DxiwRGcxDpMg+oDW49BipW9xZQ8WgDiP4pBqddj8Z/Lt074m
         HZtJhCWFXMxPDnCaRaqadrTVNOH7srDrVqhJuwW9OhFs+nFyLJXnnQ1k0byq4po2Ys6o
         8XotVyXfy5naoIMGJ9qNeMYsmHan23AmMe7M9FRnOAEEE/s6zatWKuqVV9mxxrT5dPYz
         rTlkAUrcOWUoayt80wtFJmVDSp0SLKVmnudFtkJRuMOha6G4YnkE1u3PngAOYCe7KggS
         G7CA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUL3K+x1YitbMfrBEY4jMOQSQ/kFWj0utGTVNS+RXW+X3ZeMQYGtzFhuxNikzdEgY8KTYG8lQ==@lfdr.de
X-Gm-Message-State: AOJu0YzxlTbl1kJTvv/Ydu+WL54WY3oOdMw+0jGz4xgSn/YtnuVGWk5z
	S10AQRsqvFzCxqyJ+q8RvNC6iWcGv5g7Ku5bqU8UWzUSQ7qSMvoX
X-Google-Smtp-Source: AGHT+IHcGiOxpjdZ3V+BD0cwdjH2GCD+nIP/cx1ELmmG1XWTcvKcbP0vSHgllptD7uV78BMslD4NNw==
X-Received: by 2002:a05:600c:4751:b0:42c:be90:fa2f with SMTP id 5b1f17b1804b1-42e96144d26mr16982485e9.25.1727269016858;
        Wed, 25 Sep 2024 05:56:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c95:b0:42c:bb08:9fa6 with SMTP id
 5b1f17b1804b1-42e74554fe8ls24943875e9.0.-pod-prod-03-eu; Wed, 25 Sep 2024
 05:56:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVytnkg534EQ+9VJ9+0NmFlEh+bPv5N6dsRaoWWMb2BvMFfovlYHcytJ6JBs8Q2rSJQETB/DHeMkds=@googlegroups.com
X-Received: by 2002:a5d:5e0b:0:b0:37c:c9fc:1824 with SMTP id ffacd0b85a97d-37cc9fc19a7mr720142f8f.8.1727269014552;
        Wed, 25 Sep 2024 05:56:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727269014; cv=none;
        d=google.com; s=arc-20240605;
        b=GvoauZpABMavIBRv+gsDJauCLMcWM+t/QynG0mJ2XtBXTUTZiWIYgfF+Bq9pUW3Rkh
         V+If2AsSZjqpAsoLVDjTzg9PDkAw2stVrMpRM68YyDp+QlAxg4TH76ND2nPDAJIUSRz9
         krSeI2Y8Vpw95XNU5/WTeCJyxCqnDAWHNVQR1U5Ff8h5EkU7oAtjJk9QdPxB4djFyRyK
         idjlVbUQW7LRJWKWq4KyydttHYNEI8PiPZR8avZj5gzyH3K0a8DT596KNRGKsS3Davdb
         9iKUhBvk3w1dLABuGmL5slZgpNv1ucFLXeSkLAERdIH9ra+3D32T3XAanVaDjpkI+gge
         c1RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3fxAT9AVfLIeN6rjTVrSeohwxgf70dKlprguYeTQ+CE=;
        fh=oHf0M7JPvIbH1YLen716HCIQVMkSW/v3RKwaYoCRqTE=;
        b=hFRbH6e/IFk0EIYAf85jRLmnZHl9c+oPoqwQ16fVi3FrFxGwmrXmVa1KZasefkzVij
         QT5H8U8nL7YrB39UkrUJryhU1RlPoMiMbC0IlUqBEfnvz+zVNLqsrqtX6cfUVPCWPTFs
         4DmLYEh9s+ojgFi9WlkzN8bwjgwz8KKqnrB9EM0QlxpfDnjVickFdpQzJaBwWGAGU5gI
         rwsyVKAC/sLaRHKNpUnS/woXrr/XEYsbrKfePLMLTZ72aW1jbht99Yjt/uWziKWjiy58
         k7rSeM2XYw1gSsZiar2tqa36qhSSeK5wIdfDhFBB1nPae93A2mn13GT/ASWaZS6EB+H5
         VJ6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gIqQhZu5;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e90cd16easi1721055e9.1.2024.09.25.05.56.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2024 05:56:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-2f763e9e759so76137001fa.3;
        Wed, 25 Sep 2024 05:56:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrJgvwYjlevsWDs83EqhnEvJz7LwZvUSeer7XUazhoZG0ZYxL1kDwXtV/dYGNCq3nx8U3avGtdD1Y=@googlegroups.com, AJvYcCWj18C3szrDn0aZd/SJTzFH4dUeIJnygwMNA7bT8+tlpXp+MIg5CSXxGUlkPGPViEU3baaaV0pI1gdC@googlegroups.com
X-Received: by 2002:a05:6512:4019:b0:52c:86d7:fa62 with SMTP id
 2adb3069b0e04-53877538cc6mr1823486e87.23.1727269013251; Wed, 25 Sep 2024
 05:56:53 -0700 (PDT)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
 <6fcb1252-7990-4f0d-8027-5e83f0fb9409@roeck-us.net> <07d5a214-a6c2-4444-8122-0a7b1cdd711f@suse.cz>
 <73f9e6d7-f5c0-4cdc-a9c4-dde3e2fb057c@roeck-us.net> <474b0519-b354-4370-84ac-411fd3d6d14b@suse.cz>
 <CAB=+i9SQHqVrfUbuSgsKbD07k37MUsPcU7NMSYgwXhLL+UhF2w@mail.gmail.com> <fcaaf6b9-f284-4983-a8e3-e282dd95fc16@roeck-us.net>
In-Reply-To: <fcaaf6b9-f284-4983-a8e3-e282dd95fc16@roeck-us.net>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Wed, 25 Sep 2024 21:56:40 +0900
Message-ID: <CAB=+i9Ty5kUUR1P_ahSfReJAOfhQc_dOdQ=9LBZJ4-=1kEOVXg@mail.gmail.com>
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and test_leak_destroy()
To: Guenter Roeck <linux@roeck-us.net>
Cc: Vlastimil Babka <vbabka@suse.cz>, KUnit Development <kunit-dev@googlegroups.com>, 
	Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	rcu@vger.kernel.org, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gIqQhZu5;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::231
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Sun, Sep 22, 2024 at 11:13=E2=80=AFPM Guenter Roeck <linux@roeck-us.net>=
 wrote:
>
> On 9/21/24 23:16, Hyeonggon Yoo wrote:
> > On Sun, Sep 22, 2024 at 6:25=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> On 9/21/24 23:08, Guenter Roeck wrote:
> >>> On 9/21/24 13:40, Vlastimil Babka wrote:
> >>>> +CC kunit folks
> >>>>
> >>>> On 9/20/24 15:35, Guenter Roeck wrote:
> >>>>> Hi,
> >>>>
> >>>> Hi,
> >>>>
> >>>>> On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
> >>>>>> Add a test that will create cache, allocate one object, kfree_rcu(=
) it
> >>>>>> and attempt to destroy it. As long as the usage of kvfree_rcu_barr=
ier()
> >>>>>> in kmem_cache_destroy() works correctly, there should be no warnin=
gs in
> >>>>>> dmesg and the test should pass.
> >>>>>>
> >>>>>> Additionally add a test_leak_destroy() test that leaks an object o=
n
> >>>>>> purpose and verifies that kmem_cache_destroy() catches it.
> >>>>>>
> >>>>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >>>>>
> >>>>> This test case, when run, triggers a warning traceback.
> >>>>>
> >>>>> kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still has objects=
 when called from test_leak_destroy+0x70/0x11c
> >>>>> WARNING: CPU: 0 PID: 715 at mm/slab_common.c:511 kmem_cache_destroy=
+0x1dc/0x1e4
> >>>>
> >>>> Yes that should be suppressed like the other slub_kunit tests do. I =
have
> >>>> assumed it's not that urgent because for example the KASAN kunit tes=
ts all
> >>>> produce tons of warnings and thus assumed it's in some way acceptabl=
e for
> >>>> kunit tests to do.
> >>>>
> >>>
> >>> I have all tests which generate warning backtraces disabled. Trying t=
o identify
> >>> which warnings are noise and which warnings are on purpose doesn't sc=
ale,
> >>> so it is all or nothing for me. I tried earlier to introduce a patch =
series
> >>> which would enable selective backtrace suppression, but that died the=
 death
> >>> of architecture maintainers not caring and people demanding it to be =
perfect
> >>> (meaning it only addressed WARNING: backtraces and not BUG: backtrace=
s,
> >>> and apparently that wasn't good enough).
> >>
> >> Ah, didn't know, too bad.
> >>
> >>> If the backtrace is intentional (and I think you are saying that it i=
s),
> >>> I'll simply disable the test. That may be a bit counter-productive, b=
ut
> >>> there is really no alternative for me.
> >>
> >> It's intentional in the sense that the test intentionally triggers a
> >> condition that normally produces a warning. Many if the slub kunit tes=
t do
> >> that, but are able to suppress printing the warning when it happens in=
 the
> >> kunit context. I forgot to do that for the new test initially as the w=
arning
> >> there happens from a different path that those that already have the k=
unit
> >> suppression, but we'll implement that suppression there too ASAP.
> >
> > We might also need to address the concern of the commit
> > 7302e91f39a ("mm/slab_common: use WARN() if cache still has objects on
> > destroy"),
> > the concern that some users prefer WARN() over pr_err() to catch
> > errors on testing systems
> > which relies on WARN() format, and to respect panic_on_warn.
> >
> > So we might need to call WARN() instead of pr_err() if there are errors=
 in
> > slub error handling code in general, except when running kunit tests?
> >
>
> If people _want_ to see WARNING backtraces generated on purpose, so be it=
.
> For me it means that _real_ WARNING backtraces disappear in the noise.
> Manually maintaining a list of expected warning backtraces is too mainten=
ance
> expensive for me, so I simply disable all kunit tests which generate
> backtraces on purpose. That is just me, though. Other testbeds may have
> more resources available and may be perfectly happy with the associated
> maintenance cost.
>
> In this specific case, I now have disabled slub kunit tests, and, as
> mentioned before, from my perspective there is no need to change the
> code just to accommodate my needs. I'll do the same with all other new
> unit tests which generate backtraces in the future, without bothering
> anyone.
>
> Sorry for the noise.

I don't think this was a noise :) IMO some people want to see WARNING
during testing to catch errors,
but not for the slub_kunit test case. I think a proper approach here
would be suppressing
warnings while running slub_kunit test cases, but print WARNING when
it is not running slub_kunit test cases.

That would require some work changing the slub error reporting logic
to print WARNING on certain errors.
Any opinions, Vlastimil?

Thanks,
Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9Ty5kUUR1P_ahSfReJAOfhQc_dOdQ%3D9LBZJ4-%3D1kEOVXg%40mai=
l.gmail.com.
