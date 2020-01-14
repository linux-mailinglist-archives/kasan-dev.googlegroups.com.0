Return-Path: <kasan-dev+bncBCMIZB7QWENRBSVJ63YAKGQEEWT5K7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 845C413A5B4
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 11:15:40 +0100 (CET)
Received: by mail-yw1-xc3d.google.com with SMTP id r75sf15630090ywg.19
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 02:15:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578996939; cv=pass;
        d=google.com; s=arc-20160816;
        b=GEwtF0OcYVJc0R0TVC4HpHNXU5T7KVuuGP7QxAhIcGm7NjBU00AgSnS/GsS3N77G+b
         TCN9IRLkd61XaG1st6ejdY8V9pvW1diANwapXnpbAcXLEvUt+xbAYq2NVyK6OPEV2lGw
         DXWJmM+hEy/BPbz1Ii1xRwmSZcEEWdXc+xdxyJACv7UpaDCooufmpdCuPwdzr9kNjbrs
         v4EK4yycs+VNDRD4yioluyIXpwL+2AukiIdwuMMxMZcJzekWb3JLoquW+4GoHWvZlKYg
         8rslWxxJwBaHStwXVH5ncyqEP2BpufcIy8K+ceAygUFdZKcro+UN8RXLtCq7TR4jFVpc
         figA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DebVyXtKm0LZGvWANyRiLQvj8/OefLlWSIDlCGxuKPc=;
        b=Od0rFcoC6pPTFsxKo4mGI95bDSY9tXovFZ+MaIFTggWrlZGdKqOmw1jgdfY/fOsdFo
         WJpYPQsQ2tF5vaimTDKJTEWUpwIcSq8OxuDwq0wNGOHS4/5XjXPQ7hA5Hgj4NCNAvPZY
         VPWq4fr6OD0X+5Qx1v9InU+t10Rw4naABZvHE5sCMr3cK6oIoRcadj8AD3aRuowMHoh0
         FKHQXPTGqCVmACUYprI6tjZsodU78qAhoJdjTEAsK4b89Q1nHgxFq0I+jE3BWGTBaB1Z
         EyAoE8YgpyXv2Hwx9AeWUzo60Ggfz8bm6LTsUFzSf8ym0bMZ1jn3pQI6Kh1IOBXdnf2M
         f9Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JrWid8wp;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DebVyXtKm0LZGvWANyRiLQvj8/OefLlWSIDlCGxuKPc=;
        b=DkCzkCQa8Gq13hQXTMndJfeZj1e0ziqAX2fhPzpQhjdgPuINJSldkRGXQiS4xdmbn6
         sO9z2u09rAy+BM8MFEafL2qjcZrNUd30f5v8EJ6XQLV3I4EzlZKp74usgohAwO9SSJhq
         tWGxyg3Knjpg/1/6mhK1b/lauNpBvLX2zvWd3N5rASzRYf/FFuy4p5W3Fc5EXeIspycz
         LM4DEx0pPs3y0/msATDhDxZDh5Qa4lpI9UA8W3Ps2AuDGKaLwsEaKFQmPrV3gW8yLML8
         6fjV+EYds2A8oNFDI/ortzI7B1d63iqmTCMpzodjJly1dnxD5pWHt8dHOyeKV/Bl6+Yb
         XCIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DebVyXtKm0LZGvWANyRiLQvj8/OefLlWSIDlCGxuKPc=;
        b=mzul/UDD7KRnO3lRJHUQ/57gzoq6dszx+xy2ARHbrLry65vufNqZzH/eLlboGGnI73
         1RF30brVPqUTiVrjfMchYarxLz05BbaJx3CCmOLOjMRkTdEBNyf+CY8I+tX38Bhmjtkl
         tQOrpDyXF2iCmExTBi39JNxuTT0JZ+qTYwq/+fUxtMtXS2W1ERs3sqSO9iQm815orDxb
         EmrgetAlfjFsFIeM3J/2311JmTEl3MkBcuXyNCgsGYOw+dSDuvI1SqcsaFROnEcNqCNL
         OeTXJhVMrZG78Ov3etVNTixiYmfqIdstHeiyaS8kD4BnBSHQ/j+wl71+Gy91A/xYW0iU
         +nbg==
X-Gm-Message-State: APjAAAWvwRgMY1KpO8zMg9ao9UhvEPVrKVUAvHvaYBfMW/H9egpQk/+8
	NIhukvPzj/RDszCnmNm++xI=
X-Google-Smtp-Source: APXvYqw/e0mez4vU4GdZLKKipuj0ij0QMZl4leX5jr6xI7YTogfrKJgOOgfhmCmx4vusz1uvZkH9yA==
X-Received: by 2002:a25:cf95:: with SMTP id f143mr15515823ybg.333.1578996939083;
        Tue, 14 Jan 2020 02:15:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:dd82:: with SMTP id g124ls2353619ywe.13.gmail; Tue, 14
 Jan 2020 02:15:38 -0800 (PST)
X-Received: by 2002:a81:83c5:: with SMTP id t188mr16964784ywf.178.1578996938634;
        Tue, 14 Jan 2020 02:15:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578996938; cv=none;
        d=google.com; s=arc-20160816;
        b=RzrMLtuC/5iHwk07Af475LQqVatsjVo5UXqOc6jzpC8+0nAqMujo693g7qYiUoUpy5
         3kql370YbX6TpjrNESGKj2BuytE3vAQ+5i6QXvASEIrMQopLMCJrriS6K6v6SZQ1ayXa
         ENncpCnO+QYn/f3UQrQ+JBmKTC/ySDSwiyA03LCPyBOzDigKdffx0CQ8xTRDUggv3HNP
         AALUhwdbzBD7Shpv8mo47Iv/uwnOOPyNIeZy2IVqDMqg99GqxyUIAsO/mQUO4gVMTC4P
         ktxdfPLAboOHSweZZ0eF69U/pA5Dd6gpe8xUHOmZeLzbK2VJFG8px7oL+batlbeHXVAp
         6mSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vAww8IXRbacm5VnYWGSAdMWNYd81EOzINN0pZmP3twY=;
        b=TLav2puE//MIpyjVz8RswELVP3qBmc6FocZfN+yIqAq9aX/B80+AjbCJ/uH0LI3JpH
         xq4X1K3CHIRSlbUIfjblwMwUD9TgdQLz+OIpHEFU35dcpAlMofWwSCz7TJ7E2zOaDBJM
         2kgGGIYGXoFrIEgWHrsN8PhBnY+iKFKaqvjbCpI3eTXyqAoG8sdVS/XsxRWpTagPRGRe
         2TRPHRp4gzLNdKCiysTEIRvqY4hj3jRG7iS2ThBYY2Rbao3SCK0uVQRWqPE/UvdIExQ9
         HfnacWjvgsIC+KjnSCw8UfX/v2H0vUP+3xDzNla1KYctH2L7KmxOxp1AB+cPyI5bIuv2
         hP8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JrWid8wp;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id p15si468193ybl.5.2020.01.14.02.15.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 02:15:38 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id c16so11548303qko.6
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 02:15:38 -0800 (PST)
X-Received: by 2002:a05:620a:1136:: with SMTP id p22mr21161287qkk.8.1578996938005;
 Tue, 14 Jan 2020 02:15:38 -0800 (PST)
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
 <CACT4Y+apeR4GJdS3SwNZLAuGeojj0jKvc-s5jA=VBECnRFmunQ@mail.gmail.com>
 <CAKwvOdkh8CV0pgqqHXknv8+gE2ovoKEV_m+qiEmWutmLnra3=g@mail.gmail.com> <CAG_fn=UU0fuws59L8Bp8DEVhH+X6xRaanwuRrzy-HNdrVpqJmg@mail.gmail.com>
In-Reply-To: <CAG_fn=UU0fuws59L8Bp8DEVhH+X6xRaanwuRrzy-HNdrVpqJmg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Jan 2020 11:15:26 +0100
Message-ID: <CACT4Y+ZWvnEVEDQe6c-4WRhdKkS0W=DHcWXe0etONnjjysR2pA@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in sys_kill
To: Alexander Potapenko <glider@google.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>, Casey Schaufler <casey@schaufler-ca.com>, 
	Daniel Axtens <dja@axtens.net>, clang-built-linux <clang-built-linux@googlegroups.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JrWid8wp;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

The clang instances are back to life (incl smack).

#syz invalid

On Fri, Jan 10, 2020 at 9:37 AM 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Thu, Jan 9, 2020 at 6:39 PM 'Nick Desaulniers' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > On Thu, Jan 9, 2020 at 9:23 AM Dmitry Vyukov <dvyukov@google.com> wrote=
:
> > >
> > > On Thu, Jan 9, 2020 at 6:17 PM Nick Desaulniers <ndesaulniers@google.=
com> wrote:
> > > > I disabled loop unrolling and loop unswitching in LLVM when the loo=
p
> > > > contained asm goto in:
> > > > https://github.com/llvm/llvm-project/commit/c4f245b40aad7e8627b37a8=
bf1bdcdbcd541e665
> > > > I have a fix for loop unrolling in:
> > > > https://reviews.llvm.org/D64101
> > > > that I should dust off. I haven't looked into loop unswitching yet.
> > >
> > > c4f245b40aad7e8627b37a8bf1bdcdbcd541e665 is in the range between the
> > > broken compiler and the newer compiler that seems to work, so I would
> > > assume that that commit fixes this.
> > > We will get the final stamp from syzbot hopefully by tomorrow.
> >
> > How often do you refresh the build of Clang in syzbot? Is it manual? I
> > understand the tradeoffs of living on the tip of the spear, but
> > c4f245b40aad7e8627b37a8bf1bdcdbcd541e665 is 6 months old.  So upstream
> > LLVM could be regressing more often, and you wouldn't notice for 1/2 a
> > year or more. :-/
> KMSAN used to be the only user of Clang on syzbot, so I didn't bother too=
 often.
> Now that there are other users, we'll need a better strategy.
> Clang revisions I've been picking previously came from Chromium's
> Clang distributions. This is nice, because Chromium folks usually pick
> a revision that has been extensively tested at Google already, plus
> they make sure Chromium tests also pass.
> They don't roll the compiler often, however (typically once a month or
> two, but this time there were holidays, plus some nasty breakages).
> > --
> > Thanks,
> > ~Nick Desaulniers
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/CAKwvOdkh8CV0pgqqHXknv8%2BgE2ovoKEV_m%2BqiEmWutmLnra3%3Dg%40m=
ail.gmail.com.
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/CAG_fn%3DUU0fuws59L8Bp8DEVhH%2BX6xRaanwuRrzy-HNdrVpqJmg%40mail.=
gmail.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZWvnEVEDQe6c-4WRhdKkS0W%3DDHcWXe0etONnjjysR2pA%40mail.gm=
ail.com.
