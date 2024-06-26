Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5VF56ZQMGQEZP6UOSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D2BB917B10
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 10:36:08 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-37629710ab1sf183115ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 01:36:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719390967; cv=pass;
        d=google.com; s=arc-20160816;
        b=r7iA7wI9BE9vDlSajUorex1dHt6rnP6Uixo07xnKy/pGMyaZI+KqFDu6tyU1IrRvJa
         uLXK+DFAluXR0Xie1TFsYWcaecMBbFg8UYXCEL+f2KJ1L5CKen6gBXntL3iRzniWZBWS
         6iuFsRBgv324hQSKWwfFJSjiceznVNCvyV9FhsDmhXuRr1GfQpB7pvM6iubTQhIp3ALO
         FV2rFRG6p4pevCQL3NEoPLv32Qsh+ipA/grN1gawMM0/AC9puyXBH+1LGSU3wexcDM4M
         IsLgNT/yTzfwkMSPkvExBrNeeI5tp3SzGH9dN2x/AOvcXegSc+YeMNZEkOaRIe0mBMG5
         U1Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2PaqfskZsSux52jOMpWqNjhla19ZGJsqJkwgpX0bnzQ=;
        fh=JNFhqQGPxaBzP34x/Z1KwEs5loYrQkButOo0u/wFVc4=;
        b=eYqdWhQ6heN3m4rUmyIT6ur4xBISTTmPM1/NwU9aVuqxPwggMfxrKz/urfz1Q2fkJt
         VPbU9PjodI0x9XhCoPWJjS5ydUprRc0w+cATBrgttNwkPQLZLffhZhwviNhv4EEhYCS0
         whlTgzHitckQi/8ihsVhm6V4wluCO+pZImURfpTOEknM+m1TGR+AYavkAdkgtXTgamCk
         18umTB1liUlmCUEidS62GYtUz1/R0kMa5zJDLXoOvbNEaRju8IZsf+ySeChHlYPU/cQN
         XAY1JK5xC9eJq6bMQHWB6fc1vB1jGguNcusIyAjj6Lhz3GMxliYcSYLOb8Pe3tuluUNJ
         Gnbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="sKW/DyFF";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719390967; x=1719995767; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2PaqfskZsSux52jOMpWqNjhla19ZGJsqJkwgpX0bnzQ=;
        b=HeToo3YPvOU23CmyOMsWb+yyfVilcbpyqGiJrRrt0Ls4DkmsGPbwanKYlBPgN84Pj5
         jsykVdAOHJzn6Nv/TYbqykd2zd3q2907DF9agXLdy+fYVPOqO8ELcmDkDkuWmmnU3PNP
         HgGYbDPMNT1TIN884rHiCv7UepIrrR4EkfyDHNqLH+H2Py+1JZjgQfPQ184YSpjmXPtq
         sMyjvrp/e/u0KGXTRu347A0CH+Sqg1o+PLTT8EbH1yc2D7OThPladXTsnMS3qe0Av46a
         qaFfecOIeItC2ZDeKoaYmbIOG++cUxsKRJKFBXnYj4kMsMS+2KMBNU65tQjs2fB/rdDa
         a93Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719390967; x=1719995767;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2PaqfskZsSux52jOMpWqNjhla19ZGJsqJkwgpX0bnzQ=;
        b=WymxR/VoWBBg0sVuxirbi8jaHh5q0fIk1Aakr/E2Y5BFdGU+EgMTm2GJcyVscBq8cS
         zfelaZBwQ385xTv7550ZNq0vYHjgAF96a9scTANzEz+yveH6pEnD2oLyERxRECIbeMHi
         ib80QJD4YhtGAn8PwRkIaWrN4B7aVr7NdgVe9dfezTTK2kS5pMNygHqj74ZfrbdIkpC2
         x26Q+NHFYyvouQQm1IzWcn+gLXYuqTnBTf3Dn9ajEoYA6aFTRdyQh2Iq6Vb2NA3QkPQA
         TmjuVSTDWHaPIyQxHylsh8dMsy+bWktlLb4dpULR75PHHgb4eF2ZqHC7gJs4PDI2h53k
         6lNw==
X-Forwarded-Encrypted: i=2; AJvYcCUBuPh7IGoaNbU9bVzIAhgytURy/79/IHwQj85vg4hgAXGb4Ryfll+wDZgJgnxC1vNG6rvNnG4/jhU8w6UottwZ1tvwYcSL1A==
X-Gm-Message-State: AOJu0Yz6WADaaJWZ7+rC/zTikNla+yDduh1uOSgfwSISSahRFA1NV7HD
	v5AzX8kY+4zDbL6VAK4vNyDGoiu9sGMQy02zSl6vp9ZWQaFbKCwx
X-Google-Smtp-Source: AGHT+IE9K4A8ilOV1bmN4cjggUxjvFu1zSulvaj/93yBFOZoKI/R2n7J9IzEfO4cpQTwdMSdG3B2Vg==
X-Received: by 2002:a05:6e02:1d0a:b0:375:9e2b:a832 with SMTP id e9e14a558f8ab-3782713580dmr2073575ab.21.1719390966804;
        Wed, 26 Jun 2024 01:36:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12c4:b0:375:b30c:ffd with SMTP id
 e9e14a558f8ab-37626b2a46els51280815ab.2.-pod-prod-06-us; Wed, 26 Jun 2024
 01:36:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWH9QR2oXw+LhVnrDr8lJJSMFtxeX9TIcZNu5cBWuWsUz4vNixZeENaO+5eazitB7cYLlxpeKj6R+xPlrN+KlZgT28x3WxNluEJfg==
X-Received: by 2002:a05:6e02:214c:b0:375:deb0:4c4f with SMTP id e9e14a558f8ab-3763f6c37damr131273015ab.31.1719390965858;
        Wed, 26 Jun 2024 01:36:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719390965; cv=none;
        d=google.com; s=arc-20160816;
        b=y+6AMMC0SYkOW3uiJVjVmCYTMu9+reGjCfqWI+F6XfZFlPuMXk4Iwi3bE1tI9e3g8E
         A2HdMQyZVT7OmdrcUfMg1O07uxYJC0/AJ+16w1zklsIPyFyLJnHiEvj2z3HVfzut869x
         OuxqCplJTc5PkuJWjEnWPY4HvBpMGkKkKJsP4VWpTLIvXJK5ZA9lW/HxcYHFEw6R2phg
         JuAGq/I0j8xwNiqXCmNRzLXi9LGEk8ZMrBDdKe8oC/kzVvULdbuOFtU1Lvi9KIE4ECr1
         CKn2PSHGikojowjFs2zrMnDoPbDNpGZoXrCGf+fbqDz/pQgcQRB5V6ibjAnNwHb5OGR/
         94rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=F6fPnNtBvpnTerhI3bBMQd3FP8HRZAvOd3Sy7HCVoG8=;
        fh=P+NodiMiKxfPG254ERwJqsv5PZHIRkq8NAkAiPXDUZA=;
        b=M6upZ64XtSiHYT6BDEYmE/3eLcwnM1GRIDWAzo9gH7qOC9nzri5zV9DMqalKP2UqVH
         zbH20hWiLZNkueFqMDx+Iokgv+IHN7nRF3BJ6FAAB5Fe15DHS7ibyaIyAOOxwIEffl7r
         pH/XvCd2UMR2u2A4yivU7y0pHsK08iWZlv1YMdd4vJ5tK24imBXQlrRBWmJOMd8pP6if
         qwwhk2V+J3UFIXI28p0etLBDZjrTs2HFFvEZ/aZXlQ6P6fywuyl5Ob3rUJ2A8i/7k2c3
         2W6AbzOApGyrqzZ+hiw1n/4fnTq1Fe5bDLmBFEWPoHEMq90GqeOonhOyGz/7gpWmsyAH
         QUJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="sKW/DyFF";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-376323ab163si4143965ab.4.2024.06.26.01.36.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Jun 2024 01:36:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id af79cd13be357-79c06169e9cso103191085a.3
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2024 01:36:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWWvBmM7AEMt00Z8jKsXwLJHsMTTF/XwZ1oykKTcBD8SvzlnzJlg4GQyd6HAKpVOHT0Uvjte+PrnwOkNiLSMMk7LfJTsIYiFH2+aQ==
X-Received: by 2002:a05:6214:29e1:b0:6b4:7910:2b60 with SMTP id
 6a1803df08f44-6b5409a5064mr122854286d6.6.1719390965051; Wed, 26 Jun 2024
 01:36:05 -0700 (PDT)
MIME-Version: 1.0
References: <20240621094901.1360454-1-glider@google.com> <20240621094901.1360454-2-glider@google.com>
 <5a38bded-9723-4811-83b5-14e2312ee75d@intel.com> <ZnsRq7RNLMnZsr6S@boqun-archlinux>
 <3748b5db-6f92-41f8-a86d-ed0e73221028@paulmck-laptop> <Znscgx8ssMlYUF5R@boqun-archlinux>
In-Reply-To: <Znscgx8ssMlYUF5R@boqun-archlinux>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Jun 2024 10:35:25 +0200
Message-ID: <CAG_fn=U699fy+zQtEE2wiTD2meyYe+DWrvk7PV_=T1xW+Md+pw@mail.gmail.com>
Subject: Re: [PATCH 2/3] lib/Kconfig.debug: disable LOCK_DEBUGGING_SUPPORT
 under KMSAN
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dave Hansen <dave.hansen@intel.com>, elver@google.com, 
	dvyukov@google.com, dave.hansen@linux.intel.com, peterz@infradead.org, 
	akpm@linux-foundation.org, x86@kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="sKW/DyFF";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jun 25, 2024 at 9:38=E2=80=AFPM Boqun Feng <boqun.feng@gmail.com> w=
rote:
>
> On Tue, Jun 25, 2024 at 12:06:52PM -0700, Paul E. McKenney wrote:
> > On Tue, Jun 25, 2024 at 11:51:23AM -0700, Boqun Feng wrote:
> > > On Fri, Jun 21, 2024 at 09:23:25AM -0700, Dave Hansen wrote:
> > > > On 6/21/24 02:49, Alexander Potapenko wrote:
> > > > >  config LOCK_DEBUGGING_SUPPORT
> > > > >         bool
> > > > > -       depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT &=
& LOCKDEP_SUPPORT
> > > > > +       depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT &=
& LOCKDEP_SUPPORT && !KMSAN
> > > > >         default y
> > > >
> > > > This kinda stinks.  Practically, it'll mean that anyone turning on =
KMSAN
> > > > will accidentally turn off lockdep.  That's really nasty, especiall=
y for
> > > > folks who are turning on debug options left and right to track down
> > > > nasty bugs.
> > > >
> > > > I'd *MUCH* rather hide KMSAN:
> > > >
> > > > config KMSAN
> > > >         bool "KMSAN: detector of uninitialized values use"
> > > >         depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> > > >         depends on DEBUG_KERNEL && !KASAN && !KCSAN
> > > >         depends on !PREEMPT_RT
> > > > + depends on !LOCKDEP
> > > >
> > > > Because, frankly, lockdep is way more important than KMSAN.
> > > >
> > > > But ideally, we'd allow them to coexist somehow.  Have we even disc=
ussed
> > > > the problem with the lockdep folks?  For instance, I'd much rather =
have
> > > > a relaxed lockdep with no checking in pfn_valid() than no lockdep a=
t all.
> > >
> > > The only locks used in pfn_valid() are rcu_read_lock_sched(), right? =
If
> > > so, could you try (don't tell Paul ;-)) replace rcu_read_lock_sched()
> > > with preempt_disable() and rcu_read_unlock_sched() with
> > > preempt_enable()? That would avoid calling into lockdep. If that work=
s
> > > for KMSAN, we can either have a special rcu_read_lock_sched() or call
> > > lockdep_recursion_inc() in instrumented pfn_valid() to disable lockde=
p
> > > temporarily.
> > >
> > > [Cc Paul]
> >
> > Don't tell me what?  ;-)
> >
>
> Turn out that telling you is a good idea ;-)
>
> > An alternative is to use rcu_read_lock_sched_notrace() and
> > rcu_read_unlock_sched_notrace().  If you really want to use
>
> Yes, I think this is better than what I proposed.

Thanks for your comments!
Yes, that's what I was actually looking into after Dave's answer on
the other thread
(https://groups.google.com/g/kasan-dev/c/ZBiGzZL36-I/m/WtNuKqP9EQAJ)
I'll still need to rework the code calling virt_to_page() to avoid
deadlocks from there though.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU699fy%2BzQtEE2wiTD2meyYe%2BDWrvk7PV_%3DT1xW%2BMd%2Bpw%4=
0mail.gmail.com.
