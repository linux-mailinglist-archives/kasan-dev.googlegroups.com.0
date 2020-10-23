Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBMP5ZP6AKGQESQXXOWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 70CC7297319
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 18:02:58 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id i6sf737718wrx.11
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 09:02:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603468978; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nifv3+8aAJuGIYowJnraWzlJ4h5ArZeb6UZO5K0RsVtbrlyy0r8yXTFKzeuc+wodbP
         g13j8pRlwzxnjGnP3hgYvqr4BjLWfNrHp3fBNeQ5pxI452zuQVBzRmpNO3X1wOsjyPE1
         ZydRwglJd0yFXoj0erfW+O4GJlxyOvXAgB8ib5+QK1x5Osf9b1do0qGF+6UJDCSI4ev2
         5AFBZOyqs3uz1WcFvgGJHOmSDJFAcjAF7+ODpFSUipBwT0o0EJf5NozZnkisVMWYwykT
         NywvdQcIXNQWD5YuZlfMb524CBUdNUbklWWM5cIrIHpmoEPRcUA6EvaFBkOa4cCqXILf
         ItBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=RSapjPFTYDoLJXvqzz26+My6GytmPexsJ1Z183cT+Gk=;
        b=qiEuDMEydNYTv3WH/+67WwH1Xa3GVcV6aDHeOOs0ojOGxj9dxaB/ao8FZy1FWBRRDz
         A6CYTwoXesKR+yecK3Dba9ftFCQbSZwev7TsU6pqDRMQa8SmPFBjmmXg+ihYjdIgdWLm
         wmaTsBWl/fpfbKO8LqSt4DqtUU/pMlquFOsZoXFQXh0ZPaxkcCE7cFnPreOdABLcfjGZ
         moFmaIrPUQBVAXNVL9EVmn2T0tA1hELzb1e5/LZBZGBhocfF0jmB4z6HV0O8H/hT2HbY
         GZkSG3jr3BCtEyxbOp5FBMCo646jz5wB8pE6iMMKbGbbtyeHTy0+RoelO1Dj914tfAQ8
         UL2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=GD436E2U;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::643 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RSapjPFTYDoLJXvqzz26+My6GytmPexsJ1Z183cT+Gk=;
        b=MF/c6QP+u5r12KziaF3CH13J+1iylAQNI8I1qLXQvejiwtlNdq0Z+iYEONQkwzgtUA
         D3/7wotHRL+MDFq8RQIfw8w1/3aIPvWq/fdFRyHibOU/jVyE+8sGaCS/IGXAXeETSMYY
         lZ7z6LknyWRYgX8Wi0COElCrJkD8jVriwp7ClAh+2hzcaKGNakqB3Xb6tttaIuIWtWAv
         lslG6n1Kn7epQRUwo5+qhv+LQJANY0Cui62brZzUX1lAnmlWBljboFF+iOtT/7V9qoQJ
         guBocgDeI3C008kX/FbYksEBKyN0FCAm+UaUferndMfhkKwtUg4xBSfBNNBduA5Zb0Bi
         9C5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RSapjPFTYDoLJXvqzz26+My6GytmPexsJ1Z183cT+Gk=;
        b=YwX4IcYkOM9HyfsWjU3fVcZxcElhRtrW5IVJCp0peTuOCAfmRp6O7LomV90revw0Xf
         vfqHS1TmJd95OEgICa4rv1bwAOncBBPNrVrHkSjhCc31CNGefR+vhwbUSlGU3KPGUvmA
         ShWVsvuQtqCVFXq0v8MRteBs35ndsSOffQ4XVUcbJlCKoMRDxBvnru/rqvGqejI9Kb85
         gYMCYyemrw73KMSDn5H1JHaYuww4Ft/lekVcLiN19hBgHZHOfnzaWALV2+pPSDBXSypM
         dWj2LFcNJ1np7DEx9b7JD4GnvkbTfWDzWtEJRuthJS5ZdpaX7NDIhsa5fLmZu/8/i2AP
         i4fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kcBMtKGGKPUxH8vC9XGLDhPBlvk7CVrE1vm6rQLhHXOWBakvd
	Mk9EoHfc6sVzGwpngA2saaU=
X-Google-Smtp-Source: ABdhPJzVdWPb0WFoNnARRzGwDN4Imit0YruxaBRTOmwLxngV7twYbP43qkVaoQtSFCL/k6s1oWnprw==
X-Received: by 2002:a1c:cc:: with SMTP id 195mr3216897wma.52.1603468978128;
        Fri, 23 Oct 2020 09:02:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4ac3:: with SMTP id y3ls2744629wrs.2.gmail; Fri, 23 Oct
 2020 09:02:57 -0700 (PDT)
X-Received: by 2002:adf:a345:: with SMTP id d5mr3614588wrb.55.1603468977138;
        Fri, 23 Oct 2020 09:02:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603468977; cv=none;
        d=google.com; s=arc-20160816;
        b=UaB6vqVsrFeyjwAXphcCSzecprKZpWztnM3lQf3Aci6R+ctcrpTy+ECEFgYi4DOuMR
         3Y4yPhPMEbyDM1FRzq1EJh3+GUVasBlI/VCJs8bIjkkxwvQ3aXmUZTl1B+CiwwrCUbpZ
         xU/zL+LNKKpaE+JmlaozbUx+MKrpbBmZYVJrAJtDR2wX7aTcC61etrrDm0YcBMmBwaC3
         0N2ctOmNRXLEmyRf50+0FI0Mn27pzNL16ObBWxteXPK5/JhkZs36C72SJQktgA60hgkv
         zso8I/zPLK2yU4Kjd7NlraE40bPSPIkPYopxCDF7V0SbP0wYu6/xTJfewTlX43iYmU4V
         drYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CVCIDlW+4rSCxQwC/0UuCHmyl6vLpGQY3YbrIv0lS7k=;
        b=LQM/X2WR6UknjouHWInAPvpXte1MfnUCEz67OZfTMFrXsbYDIU1V1DDHU6MAOGy61B
         H+oEcohAdtbwkHRDBgZxxkWUT2amm6clpTGX6GnueTH6ptJePMERiipe47wkNqeKTnzS
         qCxFAfzzvJu5LfyWF4wjnM2cCBLucfBZrXqaUI7atdXBU24qvoxWHtDpoJ496XBmCofs
         TLtWJxx3O7+HbQup3h061aFuhoNCJKPKrLI2qYOALPzK+wQpWET6/Ppmm1lJYi2Je5g8
         ZwWZhQFfs73YN7srJeAlaYCJaXH8wgu072/0VNrA7ZsJgWmP4pnsI0+FrkhjKZF5VeUN
         ncgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=GD436E2U;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::643 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ej1-x643.google.com (mail-ej1-x643.google.com. [2a00:1450:4864:20::643])
        by gmr-mx.google.com with ESMTPS id w6si101622wmk.2.2020.10.23.09.02.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 09:02:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::643 as permitted sender) client-ip=2a00:1450:4864:20::643;
Received: by mail-ej1-x643.google.com with SMTP id k3so3071635ejj.10
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 09:02:57 -0700 (PDT)
X-Received: by 2002:a17:906:3092:: with SMTP id 18mr2618731ejv.43.1603468976517;
        Fri, 23 Oct 2020 09:02:56 -0700 (PDT)
Received: from mail-wr1-f46.google.com (mail-wr1-f46.google.com. [209.85.221.46])
        by smtp.gmail.com with ESMTPSA id oz18sm1061572ejb.55.2020.10.23.09.02.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 09:02:56 -0700 (PDT)
Received: by mail-wr1-f46.google.com with SMTP id h5so2491030wrv.7
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 09:02:56 -0700 (PDT)
X-Received: by 2002:a2e:8815:: with SMTP id x21mr1227378ljh.312.1603468500894;
 Fri, 23 Oct 2020 08:55:00 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
 <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
 <20201023050214.GG23681@linux.intel.com> <356811ab-cb08-7685-ca01-fe58b5654953@rasmusvillemoes.dk>
In-Reply-To: <356811ab-cb08-7685-ca01-fe58b5654953@rasmusvillemoes.dk>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Fri, 23 Oct 2020 08:54:44 -0700
X-Gmail-Original-Message-ID: <CAHk-=whFb3wk0ff8jb3BCyoNvNJ1TSZxoYRKaAoW=Y43iQFNkw@mail.gmail.com>
Message-ID: <CAHk-=whFb3wk0ff8jb3BCyoNvNJ1TSZxoYRKaAoW=Y43iQFNkw@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Sean Christopherson <sean.j.christopherson@intel.com>, 
	=?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	"Matthew Wilcox (Oracle)" <willy@infradead.org>, zenglg.jy@cn.fujitsu.com, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=GD436E2U;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::643 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Fri, Oct 23, 2020 at 12:14 AM Rasmus Villemoes
<linux@rasmusvillemoes.dk> wrote:
>
> That's certainly garbage. Now, I don't know if it's a sufficient fix (or
> could break something else), but the obvious first step of rearranging
> so that the ptr argument is evaluated before the assignment to __val_pu

Ack. We could do that.

I'm more inclined to just bite the bullet and go back to the ugly
conditional on the size that I had hoped to avoid, but if that turns
out too ugly, mind signing off on your patch and I'll have that as a
fallback?

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhFb3wk0ff8jb3BCyoNvNJ1TSZxoYRKaAoW%3DY43iQFNkw%40mail.gmail.com.
