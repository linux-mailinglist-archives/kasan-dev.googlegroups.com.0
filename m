Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZOR4CVQMGQECTIRGYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BF1E80E7C6
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 10:33:27 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-6d9dff164bdsf7066452a34.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 01:33:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702373606; cv=pass;
        d=google.com; s=arc-20160816;
        b=BloDW+MZEDITEkoVidRNERhi/lTFj+W6402uMNYWYlZ4vARQFeWxNq/QYva97YTLrd
         sLAE//DVRJjR79X2kYgS6Mpm9huiIss336Dg0b4I5oNI1tTr65jifkBckTIdRdq2QHYx
         X43/U4ol6Lsmjr9vHGUDIsIw+vANPNyvyWBDI2QtG26yVnTH3EuaGpJZqiZJ4d+bhqND
         BOB64bXGAgCMPbUGQVNuJJXGMjTptDfRVbVOhWzw2rMoJD6Yq/5OMOPdMaWATL6jjo9V
         ZTTzvAh9cB/5FPuVo58aOiG0qkggRFtUh06OUybK7wiSfJeKIsc4bWWBdFMcBPIWacvr
         knyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wLKJY8Oy1jSrX0tRc8Ndb5sVFnDL9sJpudo3Fxp2GI0=;
        fh=GsT3hAat2TqRvpMYR9O/XV5pBI0aUTywK8FkNd4Ngjw=;
        b=wgaBKxamTk+WDKCsILiu2Wz6AEXCEzm0p/MeCd/V/Ho9k+nLVc2JCuHBvBlM+2re/q
         IV9CvzYyrTuZF4FyJfH6nzC8bwm7fBgSs5qATkoFwA2HdBQQxwwHhyCvTasxmxIVscn8
         g57nEVkyx9V4eXklP5YXMS0UbrElxe7OjprsNFxkolTPY0iibeoUCSy4FqO6XoZUDWgh
         d+jqQI0finHZwz3Y/XNJoba9//knzl9XDvw7J1vuKbbHembIMXXk3F2hzfl0O9cbkiiI
         SreWSD6iosYbB62bau/FcPkgWpAcr2EdZJEVKUHHyT0rPQUOndQnij3wORAVLIpqzd2D
         amOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jHP2WNJm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702373606; x=1702978406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wLKJY8Oy1jSrX0tRc8Ndb5sVFnDL9sJpudo3Fxp2GI0=;
        b=Zl1rahdZVipOXi8QZ74zoYjC9YpX29wsBD7FnkceHcVk4b3GNiIBX6XOHLpZRi8dcO
         hk8uI57pvQH1/7Gs7Djw14O8ScA+LXA3+drT553skEUnKGZwEPSWayp+qYbgqFh5xq56
         RNJaM4UxW5j06nxgiol0RKGFwiiwNV03UvkVW1yL8TKI6ThwHk/F3HkzKeO98kpk1NBC
         GHVadcZJFNib+PjNv1XL01Xmx3tP4QnQYnlbFYcsB0IV8UGhJN0PpayKtBHD54oRA7Lr
         0kOFjzlj160pQQUs/NI+rW+6oMyKFpq9pKHbvBd48P+m04eV92Ka18KyiFSuisVmt2rk
         Akbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702373606; x=1702978406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wLKJY8Oy1jSrX0tRc8Ndb5sVFnDL9sJpudo3Fxp2GI0=;
        b=a0nbTXeKkK6Z/qYfmf5GChkzA7a6wm7XIoSgWKqAOuOy2Vsu+uzcBMzr/rn1ZQDTNP
         THMEJFWlXu/qoguTsCRWYCVg7jVwGV0hV/AG3q7mz/8hx+zLZA10JPx5BmTyCJC0kXqG
         HMWo93GBSyorxKpaxEs3/n2YGIJ6nJPHVnfv6vsrWcdhmr6Wo/23Pko5fFKqDHB0W03N
         1T+LvgFDVHuW2WtO/hQu4kK/u0r+HedFViy95E7//3RaF2UxWOAUJrbODljNRU1lqMxV
         EUku9rW6EGPzUPg78TcngsH3P2cea2z9pRRSs9j6dPKOob/0u0vdHgB2vnHWxps8AMkM
         7yfw==
X-Gm-Message-State: AOJu0YzhswJ1WrI0XoTvhMi9GOewXIDXjLUA4I5+tfeHiMp2Dw6KYouR
	B7BrYrbstgAmtnB+kfdhsV4=
X-Google-Smtp-Source: AGHT+IHkXNPtWyXS1kA6L67Dm//hbiEAjJL5CtX3xGHzy6QIG7sadA8xJGTmZwF8BhQNgz64pO0Rtw==
X-Received: by 2002:a05:6870:70a4:b0:1fa:f2a4:f3fa with SMTP id v36-20020a05687070a400b001faf2a4f3famr7114566oae.12.1702373605800;
        Tue, 12 Dec 2023 01:33:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4f18:b0:1fa:fcb4:2776 with SMTP id
 zu24-20020a0568714f1800b001fafcb42776ls1696905oab.0.-pod-prod-07-us; Tue, 12
 Dec 2023 01:33:25 -0800 (PST)
X-Received: by 2002:a05:6871:5c6:b0:1fb:75b:2fd0 with SMTP id v6-20020a05687105c600b001fb075b2fd0mr7246843oan.103.1702373604718;
        Tue, 12 Dec 2023 01:33:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702373604; cv=none;
        d=google.com; s=arc-20160816;
        b=Zwodv+MjtTME/QNOpJTRtJ2dppv0Afe66L3GitLCe7EQcpP4HV+Ego4pKhpS81EIAQ
         WB/5MBy3kI9WXSxrmUBSAvcYz3YlQSHO1Q7ZZbcTN2mNoI51pZU2XuOxku/myf931SKX
         REWyoRJQDr6TdCVMdPOrLNSxyFvIddNTgYOJHK74k9x9+QBTgGISh4sDQUoVE4wwDSfO
         TDJUMiySpjn/6tzvoApH1f8LBIkQYYSAZroxTUtZkV0hFVLsWMp/TMRsFFBC/W8cwgqW
         geUC2WzvIwQUaJEYJcrEQCZ7OPY+USxms+UavtMAOMDp5JKNP+AUAXBd0GYXyTJPJTuM
         31kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gsXSrEFfFqnsLGyUGm1rzVcPU2A/TTzMQTc9kn2e+Kg=;
        fh=GsT3hAat2TqRvpMYR9O/XV5pBI0aUTywK8FkNd4Ngjw=;
        b=drL/ohtlokejFyxflOgpPvRIjkhzPfn5YiSJefRRTtJrPVqM3+fLqfiq6JYSKV3Bag
         ZKzjEtbvFZsctidfwsE7ZJbeH77JfekvkKszflOA0JpNfn2B0CnbkBHk50dmUY13Ztn6
         GM9u/NRNMe/3h8WFXYl+UEpUOa9HGj9WUj7/rsPpTG5hJDq4gQvkNnbnz5tZh1DdVCo2
         fWRpsQS70FrG5xcOs8bs2x8atso63eELDYQaZJWnseMIOH+AMYAao/PDcO4FuWem7ugE
         NnMxysxMUpd/dgYgWKxlszmWzisD1THYD6qmaRsUZoxexOftn2yCU24wJFUvs8G+x6qK
         S3ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jHP2WNJm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2b.google.com (mail-vs1-xe2b.google.com. [2607:f8b0:4864:20::e2b])
        by gmr-mx.google.com with ESMTPS id m19-20020a056870195300b001fb34066b5asi833115oak.2.2023.12.12.01.33.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Dec 2023 01:33:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) client-ip=2607:f8b0:4864:20::e2b;
Received: by mail-vs1-xe2b.google.com with SMTP id ada2fe7eead31-4649c501c1fso1637480137.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Dec 2023 01:33:24 -0800 (PST)
X-Received: by 2002:a05:6102:e13:b0:464:6008:72cf with SMTP id
 o19-20020a0561020e1300b00464600872cfmr4421711vst.20.1702373603951; Tue, 12
 Dec 2023 01:33:23 -0800 (PST)
MIME-Version: 1.0
References: <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home> <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
 <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
 <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
 <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
 <CANpmjNMw3N09x06Q+0mFCEeTKfUsDdXwXM2hdgAQ+wwbZGpB9w@mail.gmail.com>
 <rbcdbilhh67fvjdgnstu25v4jnfeesthoxstnzzglynbngu5bk@5ozwgzaulbsx>
 <CA+fCnZf5kxWUWCzK8EKgUuq_E2rYv5aw=SqZMDb93+=7vSUp+w@mail.gmail.com> <rgndtm3sawyzdh76oofoqp22jyqdb25sd4326k2heevjmxum7f@wfgwvdf4iuyi>
In-Reply-To: <rgndtm3sawyzdh76oofoqp22jyqdb25sd4326k2heevjmxum7f@wfgwvdf4iuyi>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Dec 2023 10:32:45 +0100
Message-ID: <CANpmjNN5Q+byA3sWv1uB_R=QYQxKg5YsLKayqv7WNWokkL5H4Q@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Collingbourne <pcc@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	linux-trace-kernel@vger.kernel.org, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jHP2WNJm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as
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

On Tue, 12 Dec 2023 at 10:19, Paul Heidekr=C3=BCger <paul.heidekrueger@tum.=
de> wrote:
>
> On 12.12.2023 00:37, Andrey Konovalov wrote:
> > On Tue, Dec 12, 2023 at 12:35=E2=80=AFAM Paul Heidekr=C3=BCger
> > <paul.heidekrueger@tum.de> wrote:
> > >
> > > Using CONFIG_FTRACE=3Dy instead of CONFIG_TRACEPOINTS=3Dy produces th=
e same error
> > > for me.
> > >
> > > So
> > >
> > >         CONFIG_KUNIT=3Dy
> > >         CONFIG_KUNIT_ALL_TESTS=3Dn
> > >         CONFIG_FTRACE=3Dy
> > >         CONFIG_KASAN=3Dy
> > >         CONFIG_KASAN_GENERIC=3Dy
> > >         CONFIG_KASAN_KUNIT_TEST=3Dy
> > >
> > > produces
> > >
> > >         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=
=3Dmm/kasan/.kunitconfig --arch=3Darm64
> > >         Configuring KUnit Kernel ...
> > >         Regenerating .config ...
> > >         Populating config with:
> > >         $ make ARCH=3Darm64 O=3D.kunit olddefconfig CC=3Dclang
> > >         ERROR:root:Not all Kconfig options selected in kunitconfig we=
re in the generated .config.
> > >         This is probably due to unsatisfied dependencies.
> > >         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy
> > >
> > > By that error message, CONFIG_FTRACE appears to be present in the gen=
erated
> > > config, but CONFIG_KASAN_KUNIT_TEST still isn't. Presumably,
> > > CONFIG_KASAN_KUNIT_TEST is missing because of an unsatisfied dependen=
cy, which
> > > must be CONFIG_TRACEPOINTS, unless I'm missing something ...
> > >
> > > If I just generate an arm64 defconfig and select CONFIG_FTRACE=3Dy,
> > > CONFIG_TRACEPOINTS=3Dy shows up in my .config. So, maybe this is kuni=
t.py-related
> > > then?
> > >
> > > Andrey, you said that the tests have been working for you; are you ru=
nning them
> > > with kunit.py?
> >
> > No, I just run the kernel built with a config file that I put together
> > based on defconfig.
>
> Ah. I believe I've figured it out.
>
> When I add CONFIG_STACK_TRACER=3Dy in addition to CONFIG_FTRACE=3Dy, it w=
orks.

CONFIG_FTRACE should be enough - maybe also check x86 vs. arm64 to debug mo=
re.

> CONFIG_STACK_TRACER selects CONFIG_FUNCTION_TRACER, CONFIG_FUNCTION_TRACE=
R
> selects CONFIG_GENERIC_TRACER, CONFIG_GENERIC_TRACER selects CONFIG_TRACI=
NG, and
> CONFIG_TRACING selects CONFIG_TRACEPOINTS.
>
> CONFIG_BLK_DEV_IO_TRACE=3Dy also works instead of CONFIG_STACK_TRACER=3Dy=
, as it
> directly selects CONFIG_TRACEPOINTS.
>
> CONFIG_FTRACE=3Dy on its own does not appear suffice for kunit.py on arm6=
4.

When you build manually with just CONFIG_FTRACE, is CONFIG_TRACEPOINTS enab=
led?

> I believe the reason my .kunitconfig as well as the existing
> mm/kfence/.kunitconfig work on X86 is because CONFIG_TRACEPOINTS=3Dy is p=
resent in
> an X86 defconfig.
>
> Does this make sense?
>
> Would you welcome a patch addressing this for the existing
> mm/kfence/.kunitconfig?
>
> I would also like to submit a patch for an mm/kasan/.kunitconfig. Do you =
think
> that would be helpful too?
>
> FWICT, kernel/kcsan/.kunitconfig might also be affected since
> CONFIG_KCSAN_KUNIT_TEST also depends on CONFIG_TRACEPOITNS, but I would h=
ave to
> test that. That could be a third patch.

I'd support figuring out the minimal config (CONFIG_FTRACE or
something else?) that satisfies the TRACEPOINTS dependency. I always
thought CONFIG_FTRACE ought to be the one config option, but maybe
something changed.

Also maybe one of the tracing maintainers can help untangle what's
going on here.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNN5Q%2BbyA3sWv1uB_R%3DQYQxKg5YsLKayqv7WNWokkL5H4Q%40mail.gm=
ail.com.
