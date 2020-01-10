Return-Path: <kasan-dev+bncBCCMH5WKTMGRBP7P4DYAKGQEVRX4D7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D72D13690C
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 09:37:20 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id f22sf252875lfh.4
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 00:37:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578645439; cv=pass;
        d=google.com; s=arc-20160816;
        b=fqQgV6dlO0mjjDEW9KruXj+Mjt5EKBSwQ7GlWLK/Am2OgjbukTbZTgEH2zJjnAiSKx
         3D/lafWZn0mAWyitycqtvRbSnRBe3HcsYDJfJ3fIHcN+RXgmyz89X966OA3q4zHY4YP7
         j8FTxwfsQSNHKcJgrDv/bNTX8ham4C5vrEcur9CmHM4IN/qQ+1eTQgTMB2sSIqx6XyzW
         rIyLWERiOsmh3LOlKN3VMqAJtgwyCVPP3SWW/+rdf4ySeD++4VruReQ6bcIIhgDUR3B0
         aqjQU5zY4mIpLPH4woh36GQxNtAcWQO4EWeU6c/Ea8sOIG8ym+wU+hNDAuh70+FIFX4N
         DyiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tBzGHcPRmJhZDKSW7FdEzqQyVgUYgFhbwe3R1YglPnI=;
        b=Hur0hL62V1d2I+SyriYgiecZTxFuvSRMqxeNEY2o9/SIq3bWFHpotqlrcGfsY8V3EH
         C0G6S5ha63UgaSvGLYY800WLezmYVLIDwGSBnfE7q46VXOEiYU5tKXy/neYFPEXBeTb7
         zOj/EPZfh2OK+V3UFJNiot+TvqRndb0SnKqT5XMmmjiW/iMiHP9kZgamik6Y5c2+Rjt9
         gqc7oH0B1XeYe4UfQIXfG0H3mjXWEeeib82OCDzCGbwSaRlGZgeMrO2kImF/UJttSLZ3
         FY+GoAhAx8xVlTvNQGOK5HCf5ASNlcjEP7U7X2B87Ff+rZN6jHlD43rdYhgU0v91+U9j
         Pqsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bJ2dpBuS;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tBzGHcPRmJhZDKSW7FdEzqQyVgUYgFhbwe3R1YglPnI=;
        b=DHxd4dL9bYUhr0draOQ2qVmC54WbVF31KBSdOV93h6WpIL/H27qbc+DgSIDDba6vgI
         nMaWokx96Z78Ak2OxMtqF6KEfqYjDjGpRdGs7Ph/tPV8gd8JcLH0iH38q/nKPxJuiDvj
         LLeEr6KeE3FkR+vwZQKnN9aCkiB/qAs/md1yqZxXCR+4tqy6nAIvQd3VAhJKeqzpyo2t
         tqxS2+Vl+FpZ/ZCsZVP8kausvVAN0TqRTepvoWlDDAbkFKpS9u7HgsoCArp1i4RqZCyt
         iWK1XKiJYPyRaonlYiLEI6RR80UYAFXkXBqhWh9Nz/64NnZ8OelTfBhRljD+aC3gFlrq
         2qWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tBzGHcPRmJhZDKSW7FdEzqQyVgUYgFhbwe3R1YglPnI=;
        b=sEAi1vJQnE6d3lVfax4QcS6qsIrM/tefFnc8BtafEeGtwaH4c7LnqG9R2BHOtQIubm
         EXMwslVwHqcvaXmws1jkfH5SJMCZFwvPMNwxzIHDBihB9ecPcySZ5Wr7mC3L5aLPuXKc
         srqOUNExoyoqbozEGLJ6qXbJp+oV/2L7u4qg4J/WuxMlHS8Lm8dKgkuuLQDbiyrJuZZQ
         s+k2IFpFtSo8i447HRyTXFMxYC/rlRq27Vxfv0ijVxHvY3cxT3rf9cb55g4VlTUYYASB
         DG0toGW3NNlZPY12QxNBjOi3yr+xFrrscLrs9YAYBsRmYY+P2Nh4T+3aBy3nvSSzdbbZ
         EiTQ==
X-Gm-Message-State: APjAAAVNHXk7Y3nYybBfOwRkUf66vk104+g7ht/52/OzLOVK2V6kRIWN
	TcOxO1yJW5vbcWRl6m5ghVk=
X-Google-Smtp-Source: APXvYqyMavv3/EkmD6tXJAvSZDxMtWaZB4h5TAYa/vxlxAB2JcEU8GBqCQyNDwhiLjPEwPiYA83seA==
X-Received: by 2002:a2e:9596:: with SMTP id w22mr1765667ljh.21.1578645439707;
        Fri, 10 Jan 2020 00:37:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9709:: with SMTP id r9ls612449lji.14.gmail; Fri, 10 Jan
 2020 00:37:19 -0800 (PST)
X-Received: by 2002:a05:651c:1b0:: with SMTP id c16mr1821828ljn.236.1578645439210;
        Fri, 10 Jan 2020 00:37:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578645439; cv=none;
        d=google.com; s=arc-20160816;
        b=T8t36889Ha7qJED6yf1O38F4cI5IFMMTwIAAITfe+cDZ5Eko47/RLmulKGllq61ntn
         +ZKbki64+8aQLBONgkOkh+f7FPdLQYVfE6J6jS4Y20xZzsr7vgH11nIE9vmrMkma22OT
         +KyKR3zE2UAkVpqInR4CR1CTn878qAiqWdGznutymCRfAOT9qRkU4AH5v3+V4n7rL8ju
         CKphouPTJsogtAaR2yTLi6Hk4hQ4MbED0TZope4dvMIlcMXvb32/yN5Ycut3BXCT2tlM
         8od356IrdFz/LittNo7/04qea/5TMH81iOSFQ9qiBPRE52LRzjVFp3DfHsSnOfcwMAD5
         iPMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=om0mw7hfO7KryyMGfpDve61XxX/EYx11Q6dBG1khPIU=;
        b=vwuUWkSWJvOf5BIxAvkTIuJbXQrJlqM8hMHdMFh0WiTJJByvosdVaDsmZZxi9zRhct
         UYVIJXrfiLPSRby+3ItixbX1zpMS81VxM5IGe/Ou9BEkNVWDVz5M15PUxihnM7eWLuIe
         Hk3SERjVBizGtIFMkXltfAQGWghrEjI2ifvp1QmizU7xhmagnekfIOdhSxh07oNYi4YN
         rK8hc/qHaFg/yqUnNvMUy7ovG/hPjEqBZmSsKlL2Z+pg0U3T+LnyRGHPNcxF8Yth6v6W
         W7Vp3AFkCNmSl/t8Bl6r02FeMWLc5rmCH1zfGZgWW/ojL+Shh5ksZ6wzy99J4xvTmNJg
         SeHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bJ2dpBuS;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id 68si73045lfi.3.2020.01.10.00.37.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2020 00:37:19 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id c9so924586wrw.8
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2020 00:37:19 -0800 (PST)
X-Received: by 2002:adf:ef03:: with SMTP id e3mr2216681wro.216.1578645438209;
 Fri, 10 Jan 2020 00:37:18 -0800 (PST)
MIME-Version: 1.0
References: <00000000000036decf0598c8762e@google.com> <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
 <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
 <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com> <87a787ekd0.fsf@dja-thinkpad.axtens.net>
 <87h81zax74.fsf@dja-thinkpad.axtens.net> <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
 <0b60c93e-a967-ecac-07e7-67aea1a0208e@I-love.SAKURA.ne.jp>
 <6d009462-74d9-96e9-ab3f-396842a58011@schaufler-ca.com> <CACT4Y+bURugCpLm5TG37-7voFEeEoXo_Gb=3sy75_RELZotXHw@mail.gmail.com>
 <CACT4Y+avizeUd=nY2w1B_LbEC1cP5prBfpnANYaxhgS_fcL6ag@mail.gmail.com>
 <CACT4Y+Z3GCncV3G1=36NmDRX_XOZsdoRJ3UshZoornbSRSN28w@mail.gmail.com>
 <CACT4Y+ZyVi=ow+VXA9PaWEVE8qKj8_AKzeFsNdsmiSR9iL3FOw@mail.gmail.com>
 <CACT4Y+axj5M4p=mZkFb1MyBw0MK1c6nWb-fKQcYSnYB8n1Cb8Q@mail.gmail.com>
 <CAG_fn=XddhnhqwFfzavcNJSYVprapH560okDL+mYmJ4OWGxWLA@mail.gmail.com>
 <CAKwvOdmYM+sfn3pNOxZm51K40MjyniEmBvwQJVxshq=FMaW_=Q@mail.gmail.com>
 <CACT4Y+apeR4GJdS3SwNZLAuGeojj0jKvc-s5jA=VBECnRFmunQ@mail.gmail.com> <CAKwvOdkh8CV0pgqqHXknv8+gE2ovoKEV_m+qiEmWutmLnra3=g@mail.gmail.com>
In-Reply-To: <CAKwvOdkh8CV0pgqqHXknv8+gE2ovoKEV_m+qiEmWutmLnra3=g@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jan 2020 09:37:06 +0100
Message-ID: <CAG_fn=UU0fuws59L8Bp8DEVhH+X6xRaanwuRrzy-HNdrVpqJmg@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in sys_kill
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Casey Schaufler <casey@schaufler-ca.com>, 
	Daniel Axtens <dja@axtens.net>, clang-built-linux <clang-built-linux@googlegroups.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bJ2dpBuS;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as
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

On Thu, Jan 9, 2020 at 6:39 PM 'Nick Desaulniers' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Thu, Jan 9, 2020 at 9:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Jan 9, 2020 at 6:17 PM Nick Desaulniers <ndesaulniers@google.co=
m> wrote:
> > > I disabled loop unrolling and loop unswitching in LLVM when the loop
> > > contained asm goto in:
> > > https://github.com/llvm/llvm-project/commit/c4f245b40aad7e8627b37a8bf=
1bdcdbcd541e665
> > > I have a fix for loop unrolling in:
> > > https://reviews.llvm.org/D64101
> > > that I should dust off. I haven't looked into loop unswitching yet.
> >
> > c4f245b40aad7e8627b37a8bf1bdcdbcd541e665 is in the range between the
> > broken compiler and the newer compiler that seems to work, so I would
> > assume that that commit fixes this.
> > We will get the final stamp from syzbot hopefully by tomorrow.
>
> How often do you refresh the build of Clang in syzbot? Is it manual? I
> understand the tradeoffs of living on the tip of the spear, but
> c4f245b40aad7e8627b37a8bf1bdcdbcd541e665 is 6 months old.  So upstream
> LLVM could be regressing more often, and you wouldn't notice for 1/2 a
> year or more. :-/
KMSAN used to be the only user of Clang on syzbot, so I didn't bother too o=
ften.
Now that there are other users, we'll need a better strategy.
Clang revisions I've been picking previously came from Chromium's
Clang distributions. This is nice, because Chromium folks usually pick
a revision that has been extensively tested at Google already, plus
they make sure Chromium tests also pass.
They don't roll the compiler often, however (typically once a month or
two, but this time there were holidays, plus some nasty breakages).
> --
> Thanks,
> ~Nick Desaulniers
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/CAKwvOdkh8CV0pgqqHXknv8%2BgE2ovoKEV_m%2BqiEmWutmLnra3%3Dg%40mai=
l.gmail.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUU0fuws59L8Bp8DEVhH%2BX6xRaanwuRrzy-HNdrVpqJmg%40mail.gm=
ail.com.
