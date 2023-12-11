Return-Path: <kasan-dev+bncBDW2JDUY5AORBVEX3WVQMGQEFINUNVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id D74B380D473
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 18:50:14 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5be09b7d01fsf2412922a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 09:50:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702317013; cv=pass;
        d=google.com; s=arc-20160816;
        b=xnDkuQ348ph50v11bK33p6bZ9CH04p9dsPSE2OtLq/JZH1eQTGFul+51XQPoLoI6E8
         dcoZlcUd/DC0z+FW7PP9Z5Ot7b+6KezCvmcMryZlvYSYVdxetpMpEtF5HcQFEaDep9xQ
         t6LP3/dMsqE6uK4DU8kJGsGiRPPPFm1abPXU1M7ovtBxS/WyW4v2XAY4jsdd+k4TcNFL
         fbbzw4Z799GHkKgF480hEAvt04gUf3/2T7BP2JeQt+pxqPT6vYzHzlsk4V1XdjvShPKh
         pzy6hn5oyUcvRi9wXBW/wSKhZPfRjKtoFd/lQfenJcy7Z6qqGO4msz1agHLgf0U0fpFB
         fj1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=dHpNi4MfYU8hCOCuHnbFX+He/PBp1WWLdDlM9otGniQ=;
        fh=i0W2A2eq0+ABFU0kQIx38SXH4G0GLVPJSKpmgwl4lCY=;
        b=UwxM3zqmK6PEC3mDlIFxzHfbT53M57aIcwBCbBn8gCDIcHPSd0it7RXhIEPgQ/XuMJ
         OA7OHqt6tiazbCrqvbcP0FGP40y/oFl9BWPvFZUZb59IirUi1pSBBqEZecjZXz4JuftS
         mBci/ozOenucYApOVitXhcwlQ3JnE/2ESkKm+DrFRnSk1uoMJtItNrkM99gek7FifEI8
         JkGkR+GT6IBhS8Gg6q3kR0FbEU5WutErM+FG4QA8RtV+NsQrmZEVmEOYTW68h+4d8J0u
         9X4R4z0B0WeLHepkhowfWAkeLAoJYaNoyDJmnRs0lgRmN8q/UTkgY4rBQP1SW+/gc6wP
         ghrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fkZOFYL4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702317013; x=1702921813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dHpNi4MfYU8hCOCuHnbFX+He/PBp1WWLdDlM9otGniQ=;
        b=S3h0vMPjt0Sv49M7+7V1sRvqy/zuYoxKzeK9DLZgkWFs5kQW7Ik9Y3BStRLuOquwQ+
         OwPz+cewC8woJ+dBOd+qK5gt0uSh0gnt34vI/ounyx/nRd1Zf+Pkg6dl+ZsPhjqvBEiN
         Vp/KQWIJ+oaqSuqteyoS4lq8KvSHVhEcdfqXXc6y0jH9pQwSTO44RxskW9hU9DXn/1k0
         9BjY17x3ssY18QP8MmI883ieK5ltGRX8awmhw7rcP/8bdLvDXcMokxfeZ9nQupHWfXWh
         poHXUUSKd7sc1LcJxwhIZ+7QqbslprB82GNK1tN0/qLv4l62c17jI50bfHf+EzVfgKbu
         GwNA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702317013; x=1702921813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dHpNi4MfYU8hCOCuHnbFX+He/PBp1WWLdDlM9otGniQ=;
        b=jZJuAmXBM47YQkAkW1pYsBdX24YqbIvac5vjK1NQz0uU7f6z6bcPbjEZM9+rOjNJHM
         ltIomA2jS+C2quw5B43CyIhTz0l7ovKQmlMiGrqzv8qlurIg3IKr/hnKiM3l+ErGit0Z
         R35hD1udnBZSsv4fTuGV6z0+sdTq4JY+WBe74Su7uCszjlozaMpJ/3Fdq70ou8rvuxUQ
         +Eek2e+G4OLXCEpQCge9tvpYzc6h9P0A/mme6G9U6Dhw9eE59Pclrjo4ApRO0qA/ksdv
         y8GPbjwTpI7wGiKHTwQ+RAhmbVSB+3bk3vNDQx/jnAnv9IUeFLpTlyq6XFwfoqI1eJyK
         GYEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702317013; x=1702921813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dHpNi4MfYU8hCOCuHnbFX+He/PBp1WWLdDlM9otGniQ=;
        b=UaMbzH4oF1niRq2OAi7szzYRkytyAC2gkwo1ridloSh/H3/DfUF8BLVjn15KialzG3
         h5iLCtDX7N0JCybIPbUMKKUEVoR9N+K6Y3QsjnmvnUrLGDfUdQ3XvcNF3207HopwAYZJ
         e3YASJ/xVDGe56l4Ro1EmfLYscjdug+7fBWQsSX0VrxhyStKEURTtY4tlunlRxdyXRpF
         PE94YSH0onOKhA+vXn/p2SDLeUVnclEBNnvh1483qgT+PxwJ4O6QZ2S7CtlHDRJOOC1C
         lsej5iuXvjy+/kzo2yYS1EifLebjMSIGA4gEyXbYdVi7qIELzcmqnGUW4WymIQAFIuP8
         GWDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzWt6CPa+eDUrav+Ys+FXGij7Zqm6G/W16sWCVV/iYYc9BoMYBW
	GHqj/VUdcEQKQclJB7EU3S8=
X-Google-Smtp-Source: AGHT+IEcZgA3JvohRwdOufk6Zaz+MUON8YBmCyAW+ywjbcytfWqR/mSthyAvLtZYIhz98SbawtOArA==
X-Received: by 2002:a17:903:247:b0:1d0:c888:d129 with SMTP id j7-20020a170903024700b001d0c888d129mr2610215plh.103.1702317012929;
        Mon, 11 Dec 2023 09:50:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce86:b0:1cf:89e9:f23 with SMTP id
 f6-20020a170902ce8600b001cf89e90f23ls853651plg.0.-pod-prod-01-us; Mon, 11 Dec
 2023 09:50:12 -0800 (PST)
X-Received: by 2002:a17:902:c1c6:b0:1d0:acf9:f45b with SMTP id c6-20020a170902c1c600b001d0acf9f45bmr2139812plc.135.1702317011829;
        Mon, 11 Dec 2023 09:50:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702317011; cv=none;
        d=google.com; s=arc-20160816;
        b=LX4JmZNtfm+sD2q2sB27Itn6nZSdMIHKzl79F6T4EGUyrFVtdZk55dlWK3VKXYOlCm
         0yCARJgK+G8DFNhNebVnTmXz9Ek8hOClOS0pbE3PZArMra1O+BGmsngAiddL8Og6A9y7
         ubTc6YCU/dOpZ717xAWOjldyHupUh3K5Rl+Nos3M48A0NvnSG+7F8M/1ygIfEc1+8+5s
         x1S0/ves20C8eR8IlkEK9wm7hIzd+WHAtxfZcUg/e+xAvZZvRrIUgQ93uomctTR9VkOX
         xbNhLwfYS2+V3czdjAyfQVrupGFksmTszTil1RnX/DMdnFMsS6TAVumuZVJz5Q2NOAP0
         BWOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tiLi/yokcTOlHvcoLGIsa/eRQZmbR3afyB1eNuF7ev0=;
        fh=i0W2A2eq0+ABFU0kQIx38SXH4G0GLVPJSKpmgwl4lCY=;
        b=Zb6VYAWDH1/oXgTDmrFR+SWf9+YsvfpkVPpjtzEnYox8spdo0gBEpaRxFpTvzDuW5C
         I6EWTARydNVeY/AgRD+FK7X25T/AQi6ulb/HEYyPrH/Wo6i5rDX6YZ4TPYgAwBa4mKep
         i6foQu/LgE/O/0ecW1qstaXY3e1PRkQiohyn0hWLftgmQlW/JV5+i72H98b6ibJBUlyw
         u61i1MQBvNT9H1VkgoHPe6Jx6oFY9qKviq+FqhHAYpy/oGcav2+LnfMOZdvAWs/FsCTG
         f2UDVsRUj1VbVFCJbzJVOGkRqojtliQCLKbqVgWUjp2eDOI6UKFySXJ8PfH0s9QAIzya
         Zutg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fkZOFYL4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 17-20020a170902c21100b001d045f1d86asi524680pll.9.2023.12.11.09.50.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 09:50:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-5c6ce4dffb5so2465611a12.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 09:50:11 -0800 (PST)
X-Received: by 2002:a17:90a:454f:b0:286:d42d:e7e with SMTP id
 r15-20020a17090a454f00b00286d42d0e7emr2099722pjm.3.1702317011374; Mon, 11 Dec
 2023 09:50:11 -0800 (PST)
MIME-Version: 1.0
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
 <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
 <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
 <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
 <20230215143306.2d563215@rorschach.local.home> <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home> <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
In-Reply-To: <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 11 Dec 2023 18:50:00 +0100
Message-ID: <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: Steven Rostedt <rostedt@goodmis.org>, Peter Collingbourne <pcc@google.com>, Marco Elver <elver@google.com>, 
	andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, linux-trace-kernel@vger.kernel.org, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fkZOFYL4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Dec 11, 2023 at 5:37=E2=80=AFPM Paul Heidekr=C3=BCger
<paul.heidekrueger@tum.de> wrote:
>
> Hi all!
>
> On 05.05.2023 09:58, Steven Rostedt wrote:
> > On Mon, 1 May 2023 15:02:37 -0700
> > Peter Collingbourne <pcc@google.com> wrote:
> >
> > > > > "ftrace" is really for just the function tracing, but CONFIG_FTRA=
CE
> > > > > really should just be for the function tracing infrastructure, an=
d
> > > > > perhaps not even include trace events :-/ But at the time it was
> > > > > created, it was for all the "tracers" (this was added before trac=
e
> > > > > events).
> > > >
> > > > It would be great to see this cleaned up. I found this aspect of ho=
w
> > > > tracing works rather confusing.
> > > >
> > > > So do you think it makes sense for the KASAN tests to "select TRACI=
NG"
> > > > for now if the code depends on the trace event infrastructure?
> > >
> > > Any thoughts? It looks like someone else got tripped up by this:
> > > https://reviews.llvm.org/D144057
> >
> > Yeah, it really does need to get cleaned up, but unfortunately it's not
> > going to be a trivial change. We need to make sure it's done in a way t=
hat
> > an old .config still keeps the same things enabled with the new config
> > settings. That takes some trickery in the dependency.
> >
> > I'll add this to my todo list, hopefully it doesn't fall into the abyss
> > portion of that list :-p
> >
> > -- Steve
>
> Just adding to Peter's concern re: CONFIG_KASAN_KUNIT_TEST's dependency o=
n
> CONFIG_TRACEPOINTS.
>
> I'm having no luck running the KASan KUnit tests on arm64 with the follow=
ing
> .kunitconfig on v6.6.0:
>
>         CONFIG_KUNIT=3Dy
>         CONFIG_KUNIT_ALL_TESTS=3Dn
>         CONFIG_DEBUG_KERNEL=3Dy
>         CONFIG_KASAN=3Dy
>         CINFIG_KASAN_GENERIC=3Dy
>         CONFIG_KASAN_KUNIT_TEST=3Dy
>
> CONFIG_TRACEPOINTS, which CONFIG_KASAN_TEST relies on since the patch thi=
s
> thread is based on, isn't defined for arm64, AFAICT.
>
> If I comment out the dependency on CONFIG_TRACEPOINTS, the tests appear t=
o run,
> but KUnit isn't picking up the KASan output.
>
> If I revert the patch, the above .kunitconfig appears to work fine on arm=
64 and
> the tests pass.
>
> The above .kunitconfig works as intended on X86, no changes necessary.
>
> Am I missing something?

Hi Paul,

I've been successfully running KASAN tests with CONFIG_TRACEPOINTS
enabled on arm64 since this patch landed.

What happens when you try running the tests with .kunitconfig? Does
CONFIG_TRACEPOINTS or CONFIG_KASAN_KUNIT_TEST get disabled during
kernel building? Or tests just don't get executed?

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZebmy-fZdNonrgLofepTPL5hU6P8R37%3D%3DsygTLBSRoa%2Bw%40mai=
l.gmail.com.
