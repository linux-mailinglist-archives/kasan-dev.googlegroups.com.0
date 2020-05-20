Return-Path: <kasan-dev+bncBDYJPJO25UGBBN5XSX3AKGQEHPP5GEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 179AA1DB97E
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 18:32:57 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id t5sf1635620vkk.11
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 09:32:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589992376; cv=pass;
        d=google.com; s=arc-20160816;
        b=CGMy/amWtZ/SUCkAlRAzbeQvndJCF7mI8XS9/sRw+CPJIsJGgODCPWv23HKj0I+ok5
         QA07skIhJDz42Cu3WWyboparqFykwwHO1p9YVP2oG9N2pCMZ/OP+/GZsALa0qnBDODkM
         t47Mye9ko/oYBwes2z7tXi5Vwo7P0X719CgpYZudznSIyO/Vs6S/cizzDMNjphT1CFFp
         wr/1R1L/xI3KNrsLH5EdX+HPTtrNDbB/Ldv+6e8tNC4eX2I3NHrYgqx477RIiD0vNCBe
         YMlfyTCbrs5lMKkbRBttgh1ekgMMKIae5utNv5r7irHKT9RIHEU4jCpKKQ991i6wGOuf
         Q0Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5th6EqMPI8BseJUGBJmLZvaHUJ3Gdt8nWYREGrIxCg4=;
        b=MmUBfZRJZ0EmIr2XOjeyvlFNqSfsc916C8ma1NuZzGLTDw9DGyKlvgRKR8jlslzruF
         4IfsgmijUStM8cuke3QbHX4ohXjPdNvsYIlpIJBt2OLAGUMA6SvbuUOizaa2trOoKihr
         kKDFLc0TQNSaOBFU6knYE2Vkog1Jguo1u8KMjN+j+/zPt+J7zMkIoz/F3DCxU4ufg8AE
         N0/j+H1UlayvK/nAFEj/FHP0ZOmLzwgAPQtDBpr8SGTq74zw9eNk4nZ+IyTNAykZmiwn
         M2cdmZW67kBfOqGB7r/gS5vy4HMCte0p1lkSTQJffDb/3evfsrPJocgynrdoL6waaBYz
         d73w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Lop/y0Dk";
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5th6EqMPI8BseJUGBJmLZvaHUJ3Gdt8nWYREGrIxCg4=;
        b=qhChHPF7H6dWDSgdP5tR+lnM2p0Jz9NWR4VA2wRbhUVSrBnBYK5b50EhNTXRVwuRFN
         XhlqPebqwElhm4QxfopqXkYpAQ9AEJ4JBoysJbUshz5CqWNsYMvV7ZzlmFQj51MYpus7
         3D7ASjbg0QMnqKJtgt9i6kiNcdFK33GXlx59jokWrvwIxLsJEkMtANteZmSFyJ6jNRle
         EHSvd6KMWX4i9YwC8LazaNH4ok71vnqGNNftdV18Q2DatXgqpgFP8Ma+8yccUV7vPxSU
         5YkWFhGoeMpa/9TNurQjca6U15zECIe3VxQlURbxiwLyekugGr2vc3Hyl7PxRPeSBbeO
         1w3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5th6EqMPI8BseJUGBJmLZvaHUJ3Gdt8nWYREGrIxCg4=;
        b=NSDpT+UXqeLsh0+hBfR4Hx83DH9NpSMQt0cCpKcddqzTnDNMEawV813l/DkJU9BxdI
         O1ubE3RmwGDyFZhRW/Ns8r9OOPAKw1JyLBbkIPA8dkDijf3bwh10VUqthACwZULYPTIn
         hkR1dADcTE2RdT5LGE3MQIa0JKD3fSkeyvAeePVMtTj64zQmW8bdJHdFmmzNiWHm0ETc
         jVYwYnF82oDfPIZ1Hn5vEWgDnEKcPVOFj5p4xKNoSCFLflPTowfAoTKIXSPMCnXe7BIj
         Z2hbMMtUdccmNx8vNtvBcNQMJnBVWlyCzV0dJzWC3BgTIflzJHEeTd0RFl/U7XlgxWTF
         oBfQ==
X-Gm-Message-State: AOAM531FYTtxxYOKdt5knFUEKBguoCJIu3ig9rDsosW5XcKX0mUPiUL5
	H+TTo4OoCSkNU+nNMkkzYBs=
X-Google-Smtp-Source: ABdhPJzvb+tmxXHOaifa+k4lQiSfL/XqTiHlj+5HQmDwbDYqL5b1vocFha74DXCrTyLRCcfc1rvX7w==
X-Received: by 2002:a67:310e:: with SMTP id x14mr3956212vsx.237.1589992375873;
        Wed, 20 May 2020 09:32:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:418:: with SMTP id d24ls256057vsq.7.gmail; Wed, 20
 May 2020 09:32:55 -0700 (PDT)
X-Received: by 2002:a05:6102:21a9:: with SMTP id i9mr2567251vsb.9.1589992375543;
        Wed, 20 May 2020 09:32:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589992375; cv=none;
        d=google.com; s=arc-20160816;
        b=Y2bvwVrOjRqrKO/AAXw5JbsBnBZnZqDcNjn2kPNl5DatC/16t1MOjxYQEpmgpl/Cl3
         nQzptxZcqgJVWYxAYhHE3ExuIkTk82XWlybk1OyRfcLLvApRFyeAgVYoXeuNJ5b6yIAP
         UA8RqRuL3iAqikTwsiI3fK6XmsreZFnlhhtLRlnF3T2637we70IKJg9TEVJuzchcCP/E
         s5YnaA0zlJbs7c3veRm9qMU0t05h2xYZ2PNdMP3rOLIfGfZtVx+zPqAo+qHjidJwVrBk
         +OoHi917IyCqunGP0VKdiY0egMTuIlivOshA9mMUe32UDYqyr5wsVNI48PybVzKWO1+e
         eFAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yx+SO7MaZlAD9vie5x6QfkffO8b6beNlaHDdml9CWsM=;
        b=RodksU9CTurMRo2o5sJH1PCehbK3qwgs7qeMDWYhaD5Dvq47GTqybP+gDr81VUJJWp
         +YXNPZorCtE1GK46L1vwE7p0yF+gRs2wpOwHg1z6vdlg/x5B5A6VJRtHKjpMFLSGHvHn
         jCfS4yYoNJdZf+G+m5ighgDvZ0yI9hXPdCgwori92Fl2EYFcOyITXvNmwP0mKKqWrtxT
         GmzGYZmJwiih8PPTAaEb6bAtye5/89byCV8emnytgHjp3h3X33Ro0GTyxLyvc1o8As2t
         t53/djR5ELN1+GFeVAmgtiUtfbd49R1DlY1A1z6VGeoFUbuCRQKV8LWutihkS5cAbrKM
         c2BQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Lop/y0Dk";
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id q123si216245vkb.3.2020.05.20.09.32.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 May 2020 09:32:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id x2so1806110pfx.7
        for <kasan-dev@googlegroups.com>; Wed, 20 May 2020 09:32:55 -0700 (PDT)
X-Received: by 2002:aa7:8084:: with SMTP id v4mr5089195pff.39.1589992374419;
 Wed, 20 May 2020 09:32:54 -0700 (PDT)
MIME-Version: 1.0
References: <20200517011732.GE24705@shao2-debian> <20200517034739.GO2869@paulmck-ThinkPad-P72>
 <CANpmjNNj37=mgrZpzX7joAwnYk-GsuiE8oOm13r48FYAK0gSQw@mail.gmail.com>
 <CANpmjNMx0+=Cac=WvHuzKb2zJvgNVvVxjo_W1wYWztywxDKeCQ@mail.gmail.com>
 <CANpmjNPcOHAE5d=gaD327HqxTBegf75qeN_pjoszahdk6_i5=Q@mail.gmail.com>
 <CAKwvOd=Gi2z_NjRfpTigCCcV5kUWU7Bm7h1eHLeQ6DZCmrsR8w@mail.gmail.com>
 <20200518180513.GA114619@google.com> <CANpmjNMTRO0TxxTQxFt8EaRLggcPXKLJL2+G2WFL+vakgd2OUg@mail.gmail.com>
 <CANpmjNO0kDVW4uaLcOF95L3FKc8WjawJqXKQtYbCad+W2r=75g@mail.gmail.com> <CANpmjNOeXmD5E3O50Z3MjkiuCYaYOPyi+1rq=GZvEKwBvLR0Ug@mail.gmail.com>
In-Reply-To: <CANpmjNOeXmD5E3O50Z3MjkiuCYaYOPyi+1rq=GZvEKwBvLR0Ug@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 May 2020 09:32:43 -0700
Message-ID: <CAKwvOd=ga4cjJCQASVH=Vwjkk5_Qh7b_TtoTSBBoLiMENL8hOQ@mail.gmail.com>
Subject: Re: [rcu] 2f08469563: BUG:kernel_reboot-without-warning_in_boot_stage
To: Marco Elver <elver@google.com>
Cc: george.burgess.iv@gmail.com, Kan Liang <kan.liang@linux.intel.com>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel test robot <rong.a.chen@intel.com>, Peter Zijlstra <peterz@infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, LKP <lkp@lists.01.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Lop/y0Dk";       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Tue, May 19, 2020 at 11:32 AM Marco Elver <elver@google.com> wrote:
>
> This fixes the problem:
> https://lkml.kernel.org/r/20200519182459.87166-1-elver@google.com
>
> I suppose there are several things that happened that caused the above
> bisected changes to trigger this. Hard to say how exactly the above
> bisected changes caused this to manifest, because during early boot
> (while uninitialized) KASAN may just randomly enter kasan_report()
> before the branch (annotated with likely(), which is caught by the
> branch tracer) prevents it from actually generating a report. However,
> if it goes branch tracer -> KASAN -> branch tracers -> KASAN ..., then
> we crash. If I had to guess some combination of different code gen,
> different stack and/or data usage. So all the above bisected changes
> (AFAIK) were red herrings. :-)

Thanks for chasing to resolution.  Consider using a variable to store
a list of flags, as that code (before your patch) invokes the compiler
multiple times to answer the same question.
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3Dga4cjJCQASVH%3DVwjkk5_Qh7b_TtoTSBBoLiMENL8hOQ%40mail.gmail.com.
