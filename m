Return-Path: <kasan-dev+bncBDYJPJO25UGBBOGK3XYAKGQEUTQWECY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id BBF0C135F76
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 18:39:05 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id h87sf5096432ild.11
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 09:39:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578591544; cv=pass;
        d=google.com; s=arc-20160816;
        b=WmZ/eCscjKzeXJ4BNba+YJTL0nUJz8C+VdUCQ3jUQ/yhejsIrQFxCTHxyfozGbtqPc
         MJUx4Row8TVLqU9LHbMuLYRVw9oCLMoCbZHfuvSxZdr2rSEsUq45iaMS8dCVQUbO4cJW
         2G61SyTUcqPudZF9XMJoRazOGSuGfC6hxftEa1tAJAU85JlyoWvJIXEQqWQYTzaXU7Xa
         LSJ5SSgkvdey9JMYAX8YOhzioTs6exCw32rHMbzoWNv95IqAqAEx2+4YJ7WU1nduA0in
         sUcHr/QeGRKIhVLaEfEMrNvDTjwXDlER9baCa2PuLtKvXDyjKFORJfgTw/t6PHyG/6HE
         Gbyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jSyZ1u2J7JWrBuT/Lqai9l5NOF6KUNPt60de1WL3LvY=;
        b=AYra9WOPDsm5roWqa10+x7w1Zqt4W9Oj1LHiPIjeBTTPuQ9np1/pw9MYXUrHu/hoFB
         FNuXBm+OiDDCpwKEyYSccwZ7PRpXczivGP8P4SiLnnuQFaNsR7ySwFM5+rYd9RcZQGH7
         tAqVrmphb2JEaHba/y6KCJXcu4XlHtSB/f2IjAErCnRTY9+KqqUFx+cDUlmk/lh4xB7W
         kogHO+QMWxB+HflyRqZITtpgo9BOjAKoC5bfIoqMt0dA53X7E1BJ5J5r1fXxzdKQVD++
         HfJJSyxRUM8Oy8eL7hAfpPSDsf1BsROg7K5gYAkjPHt9fBPpP901TvHbJiihZzx893lG
         PSVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O2I2NOfW;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jSyZ1u2J7JWrBuT/Lqai9l5NOF6KUNPt60de1WL3LvY=;
        b=ANEtlxvKabB4MDKoXbZeQrEGVAaTHIt4bDHJoBDDoIrko8SMMWaBVPHIOW3pcSUZt+
         m1UcOqH3AO/2G5z6hyqmdqs5t1o1F6GnR88AJYIQShjT+R4Jk0A13kA9wHM5CaNsPZGR
         CQl7P6r/wUaw9BexGVOBbzol39qOztqrxFJspd19h6zpL0clz2n+i6pf+ZNMNHFOriCI
         vnIjMk0H5ObTHGf0WMsko7bavQ4dW2I2GJMuZLiyL32zK769ObUH6WmZKvP2XHct6GAg
         wCvVaVcJjUwzb5MADqytglWnCobOM+6DdfbXu7O3QLwdW29s0LwrR9ywTL63g4J5L5e4
         c/zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jSyZ1u2J7JWrBuT/Lqai9l5NOF6KUNPt60de1WL3LvY=;
        b=GMC+M+pcXstEVg6RqJQwrENPYiZHqK4Hs3YWVIstjFlUpZGoCJRPB3+PrE/GNonfAy
         4TQkFuwcKJXXu9lTuaXDggZyIpvOlTw5g+svLj81abNB7gDrrxnb0MKpzPkCNg1xV/Ki
         x7dETcdyqVFhi2XRBTIKSR2FXQqgC5D8tG+lZQirh6uiAx2KZXG/axzoOCjCADlX7pgS
         uA0vCYk0TTvDBAfpHJtIFCXxpKVsPwqTG4KbJmzj3Vv3In+NsUcKikZ/K91KUXTUssnk
         49bjviHMifkY33ujnefdkbIrb8ppHRJz3KVCjSN8GvmObkZ4/dU+FjORk6N/0me3p1gh
         kffQ==
X-Gm-Message-State: APjAAAW2dpeFTG9tEw0LHz8eB2qlfDJAtnFMuwsWJtiSLruQAI74qGI5
	vW/b8j17sW06gdjzVEkpTUE=
X-Google-Smtp-Source: APXvYqyV+Z/IOydEX070XY9oOLua6AS1pcXq7QEBomP+GrJ7/+K2arMfDvWnJlrUsEl/4iY11iRbEw==
X-Received: by 2002:a92:280e:: with SMTP id l14mr9716404ilf.251.1578591544636;
        Thu, 09 Jan 2020 09:39:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:5f17:: with SMTP id t23ls430640iob.10.gmail; Thu, 09 Jan
 2020 09:39:04 -0800 (PST)
X-Received: by 2002:a5e:a713:: with SMTP id b19mr8360003iod.91.1578591544209;
        Thu, 09 Jan 2020 09:39:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578591544; cv=none;
        d=google.com; s=arc-20160816;
        b=0Q93yoKjrrbqgwWgI9KNHLWM/vNQ6hx/OxcfjILMZU499tnrhd7dQq9YIIoOerTt5i
         WbaFiQk5KMWn6WRHlEPWodzyv862Mky8wJrGSQUN3eSVeB794MRzZXlnGDmG9GCjHtca
         PYd8x8+dRQiwrwBz+ilJg9WMVLGspX/3UMc/84j3p/xtSO7JXqcozGQm2+VOKTTQtkPs
         1uaVf4oRn/S/ZZCi9mWY0Le1PdKhz99BQ+t8n/42BqLhB5/L6GijI18LLeyha0Cm1r8F
         x8iV7r5uqHb86ZX6HSP+B1vJqaZIuZcQKwR+QvzqtIuaqsQ8z1zlrL3vIa7H+5WPAfvG
         W+1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MSJaP50tcbssCy+wUHSI0wzNq4LNnMEZ5ONXZaI5D4I=;
        b=f+g0U/hVqJeLfO+D1vghAnC/v7J7neJptUwZdJkhoU7Z6G32waEuymaj1FxTbjhABh
         avgUm6Y82GX5BqJoXkaqPn1J8JI9dDMwneoTzllhwP5DOqk7XRygRsqpQVZ5Ys9pC/2u
         qEEzkzj/eLr7StxKbg3N6d0WfdPNQ/bDADN6UR/UTvyWL2PlKA+lxibk+HPBXJ0cV18+
         jlO0VT6PW4VTJ9IOzZqTa1cyA+PeBvHENEsZ/TLiYxP7RGIIxOFJjqBR0Y1LYpGJqh2c
         74wocCdMBMUhXiCd1UW+96DvCCXNIlknICjkSUCWqR1UNfurOgSl4DNOATH2asG/5vFV
         kzsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O2I2NOfW;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id f85si12789ilg.2.2020.01.09.09.39.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 09:39:04 -0800 (PST)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id q8so3690724pfh.7
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 09:39:04 -0800 (PST)
X-Received: by 2002:a62:e215:: with SMTP id a21mr12577184pfi.3.1578591543402;
 Thu, 09 Jan 2020 09:39:03 -0800 (PST)
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
 <CAKwvOdmYM+sfn3pNOxZm51K40MjyniEmBvwQJVxshq=FMaW_=Q@mail.gmail.com> <CACT4Y+apeR4GJdS3SwNZLAuGeojj0jKvc-s5jA=VBECnRFmunQ@mail.gmail.com>
In-Reply-To: <CACT4Y+apeR4GJdS3SwNZLAuGeojj0jKvc-s5jA=VBECnRFmunQ@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jan 2020 09:38:52 -0800
Message-ID: <CAKwvOdkh8CV0pgqqHXknv8+gE2ovoKEV_m+qiEmWutmLnra3=g@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in sys_kill
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>, Casey Schaufler <casey@schaufler-ca.com>, 
	Daniel Axtens <dja@axtens.net>, clang-built-linux <clang-built-linux@googlegroups.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=O2I2NOfW;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::430
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

On Thu, Jan 9, 2020 at 9:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Jan 9, 2020 at 6:17 PM Nick Desaulniers <ndesaulniers@google.com> wrote:
> > I disabled loop unrolling and loop unswitching in LLVM when the loop
> > contained asm goto in:
> > https://github.com/llvm/llvm-project/commit/c4f245b40aad7e8627b37a8bf1bdcdbcd541e665
> > I have a fix for loop unrolling in:
> > https://reviews.llvm.org/D64101
> > that I should dust off. I haven't looked into loop unswitching yet.
>
> c4f245b40aad7e8627b37a8bf1bdcdbcd541e665 is in the range between the
> broken compiler and the newer compiler that seems to work, so I would
> assume that that commit fixes this.
> We will get the final stamp from syzbot hopefully by tomorrow.

How often do you refresh the build of Clang in syzbot? Is it manual? I
understand the tradeoffs of living on the tip of the spear, but
c4f245b40aad7e8627b37a8bf1bdcdbcd541e665 is 6 months old.  So upstream
LLVM could be regressing more often, and you wouldn't notice for 1/2 a
year or more. :-/

-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdkh8CV0pgqqHXknv8%2BgE2ovoKEV_m%2BqiEmWutmLnra3%3Dg%40mail.gmail.com.
