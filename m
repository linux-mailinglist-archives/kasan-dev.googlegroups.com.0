Return-Path: <kasan-dev+bncBDW2JDUY5AORBRPM3WVQMGQEI2U3BNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A1B380DC09
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 21:51:18 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-679ff96b259sf68406706d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 12:51:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702327877; cv=pass;
        d=google.com; s=arc-20160816;
        b=bFLHUtCbxu+e9AqlD65mNWujXhnJB2ZHNyAKVQOq/4VSRGaIwj5hx1+lN6DuN4TlRp
         p9BU2u62XYvz4ZROc+bCi9gdCERexoO4Asyyj7Bkuigbv9i3FaUsvCfYvKzvogAbx+By
         AwdjuorXg29kODLm+GUHDyRGHwoE6PmjrFkMfJqW/hP+vvhdcqvoezOO/5TNvYXHxdg0
         IPr5L999xzXOIBMVIHgb2WfZTCV8/Lm2nOueiNXCSVJgddV2gVb6/xi6ZNknhAR6DBkk
         tG78L07e1bPIX9lwockvyfPhqeqhPL9Jfx1bPAu8QwyN748G4V0Mt5bGk9JXnIkOYMFh
         xLOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=JTVs44E6D9l/3lSpCBaDAal5B13AasEMYrNVnQXmdws=;
        fh=i0W2A2eq0+ABFU0kQIx38SXH4G0GLVPJSKpmgwl4lCY=;
        b=csZK9jGblEcJjD0oa4lBO/C1ywGMOm+2Lh8boETWy70ArgR+7U3ZlTtUM4b4N+sQ9m
         q3ewDR66eAHNGfUtmzVsKZn1zC6i2MEfwjzs2yzW/exUfSacVjiIyZaZs84rDp0G0iE4
         3sSX8mK3QlNV1gAqUVuECQbVY6hQXxRCp1YPcpat6Dh9iR/Yehf92aaHfwgogELCaYWs
         2zZ7SP1zjdP099I2vl4hF/cpTgZ8WCHd0/xSXZsXxnlUbIlYgfOBVYpJbGtPBPm1pGSw
         qhQ8Vm2eyxUiRcIdorPTbqmRC2Xyujtc/xdczbwLFhj0ajntustzXheSmENs91ZRh9FP
         X5ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=A0K0CxE4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702327877; x=1702932677; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JTVs44E6D9l/3lSpCBaDAal5B13AasEMYrNVnQXmdws=;
        b=Jtm1OVjkqLkEuKvbkiv9kBAidDCgazRtg1H2gp3gKY9YoeyYNIyGUxt4iIJ02oUzfp
         gCHRHaj7DbhX4Q5WRhdCHB4pBvrIjxHkAoWpKjfaHeCJAJi2kx5oI+6smjSYkjvz8JlA
         4e8N2CWs63+LKQBI0B781e4CaeyHU/eoCc5bDghSTyNmj/ERzVQUpnOSeJ+N7cMDfsrQ
         KkEEWRpNtqknExjXJslzM3rGFWonlxA7CwpQA6yt9dn17102XWwOQMmtUdU4NoaahpYO
         8fdZ+hgwIhwKVHH3+HTYbfyAiW3PUeIJuqGpw9Q1hy/y1o9G3mnXt0Wyi8iF0T6Eiuo9
         uxPw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702327877; x=1702932677; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JTVs44E6D9l/3lSpCBaDAal5B13AasEMYrNVnQXmdws=;
        b=Vbb0dLdem7vGBWfC/l0Z94HWRfuepib91xlDaqmbmahP2DGuDOGB/NRQuVnYYqBbID
         SvMRXp5zv502/2So5iYqIQjHV2zhCdGxQLeVf/zTUQHLPaqx3VnysYnqPXUC88pSz72R
         JMtX0zH8QncEfysWGXYoYJ5f9EamHryf2OOXQ+fB7h0OxioxBk8X3SQtsy03+TBlLAiK
         5qcDAOCh3Tqmn+ts2WCfXvQTv/oKJn8RMA4cEfqvG42TUdGp/48z58CQbuZLBGOvtIpK
         EoDQ4rbWyj/I3Dp887K9x4C6Y+McxG/Hx1+TTfIQREPamSdfna6kiLLsO0vDGyLKhsr1
         f0pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702327877; x=1702932677;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JTVs44E6D9l/3lSpCBaDAal5B13AasEMYrNVnQXmdws=;
        b=SSPfCn127yE6/mCCwMxDJcWZKOny8gt7FYFuSNt/Pzlgy6Wrimu8pCAsCYw2b7Dlgu
         Yxs+oKk0NS/9QpQfK/e//z5GsmIXpgaAbRZa3y128xfB6jUerc8lNNOmPCGcFi2Chza/
         0c3a6y1t4C/a/zE4SeGRCSHkCemyUwNET6tB676krAUHpRiEM1QxDQaVabu3KYVTOws3
         pttyJBgs7yfftwbWDfsY+gvZbl9O3e6LA96jvHnDCZUe3ILG+cY+28XNhvH0xdlStr/D
         rGAttFn0z8Unig43pqIgVZ2tC3fC3T3Snf4HAjUWimmSi7mQcU5AQ5GGMTfQdtibHhpK
         KD+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyVv7ME4CxhyzhwNWN31xid6FCkfn6qPMpUjOOLza/k+abC3YaU
	bYyHwnXAWZOlBiiHpYjKTX0=
X-Google-Smtp-Source: AGHT+IGkOb8v2JO7eFy06xfU9bIiezFFGOX+9qPHaHDe7wT97qf7a0AOCHrrEAYbVddvFbv+NmO0tw==
X-Received: by 2002:a0c:ee45:0:b0:67a:a61e:f1fa with SMTP id m5-20020a0cee45000000b0067aa61ef1famr5645861qvs.52.1702327877295;
        Mon, 11 Dec 2023 12:51:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:945:b0:67a:a8c7:4f24 with SMTP id
 dn5-20020a056214094500b0067aa8c74f24ls1157394qvb.2.-pod-prod-02-us; Mon, 11
 Dec 2023 12:51:16 -0800 (PST)
X-Received: by 2002:a05:6214:2426:b0:67a:cb7a:11bd with SMTP id gy6-20020a056214242600b0067acb7a11bdmr7988904qvb.118.1702327876573;
        Mon, 11 Dec 2023 12:51:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702327876; cv=none;
        d=google.com; s=arc-20160816;
        b=pcqlQbi15azmfRsH3BzTYi0wGeMnmz4IpVLeDSltRsqqMJxDjLtQNvplZ+5fIvEhWS
         bf1hYTfruLNckDC7V4/WJAdhm3u3Se4dhVzAZtPNFLOm6HVFylcw8mqYZI4uDeX0j7Mg
         iBUKinZazOBiPEV5lofuFilNU3BmRIZefPouqJa3foEGiKcP1NjZsklrBv2hrmdeKY6W
         1sN9Tx6DHlmgK2vfdA31o5Ag5G0NjhClDq1nITwJnIPSN6Ud5N9YLWBA7Gbs+6Tobjom
         +zvFsGUjU991ZL4XtlBenNtSZzeE5fkbGbog6251OHsezrPeRPrL/9dfK2crq1lP8m52
         dmZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OckqF+ycLHzYHFxbjXbvIz3Ml946FujF+AQK5q5s1sM=;
        fh=i0W2A2eq0+ABFU0kQIx38SXH4G0GLVPJSKpmgwl4lCY=;
        b=VB3PD9K1B79zowWaYxBpyr1ZsMMYsWp69Na7fqzulDVnO/PB5Gx5paA8NEdcrTGFm1
         3vi531lF2U1ai8JrMXoSlfBzZnml4hNx0YOkKEUW/SAvuyhBlmfHhQkTAwuV3JDUKT55
         C+0OnPN0q07xNYiTXWQIi1r4G9dSu2iOkSphCjHQBamsTtkDpD0KvbDZ4rdqM5VZjO2O
         E5zP9YvubKAv14DHhpgsQ8gHTOCs0blYNnqTu0HHecyJCZU7rD3BT9coigxuEbWUdCgX
         i9Knqgk54b9VOkICND0LZ7ybPk9RGkRLrvldBwBQ4iSOeiSVitgdlerktFuGpvTN1jpS
         LJyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=A0K0CxE4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id v18-20020a0ced52000000b0067ab24a47a9si756773qvq.2.2023.12.11.12.51.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 12:51:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-1d30141d108so8396145ad.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 12:51:16 -0800 (PST)
X-Received: by 2002:a17:90a:34c1:b0:286:6cc0:b918 with SMTP id
 m1-20020a17090a34c100b002866cc0b918mr2228620pjf.79.1702327875595; Mon, 11 Dec
 2023 12:51:15 -0800 (PST)
MIME-Version: 1.0
References: <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
 <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
 <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
 <20230215143306.2d563215@rorschach.local.home> <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home> <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com> <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
In-Reply-To: <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 11 Dec 2023 21:51:04 +0100
Message-ID: <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=A0K0CxE4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e
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

On Mon, Dec 11, 2023 at 7:59=E2=80=AFPM Paul Heidekr=C3=BCger
<paul.heidekrueger@tum.de> wrote:
>
> > Hi Paul,
> >
> > I've been successfully running KASAN tests with CONFIG_TRACEPOINTS
> > enabled on arm64 since this patch landed.
>
> Interesting ...
>
> > What happens when you try running the tests with .kunitconfig? Does
> > CONFIG_TRACEPOINTS or CONFIG_KASAN_KUNIT_TEST get disabled during
> > kernel building?
>
> Yes, exactly, that's what's happening.
>
> Here's the output kunit.py is giving me. I replaced CONFIG_DEBUG_KERNEL w=
ith
> CONFIG_TRACEPOINTS in my .kunitconfig. Otherwise, it's identical with the=
 one I
> posted above.
>
>         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=3Dmm=
/kasan/.kunitconfig --arch=3Darm64
>         Configuring KUnit Kernel ...
>         Regenerating .config ...
>         Populating config with:
>         $ make ARCH=3Darm64 O=3D.kunit olddefconfig
>         ERROR:root:Not all Kconfig options selected in kunitconfig were i=
n the generated .config.
>         This is probably due to unsatisfied dependencies.
>         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy, CONFIG_TRACEPOINTS=3Dy
>
> Does CONFIG_TRACEPOINTS have some dependency I'm not seeing? I couldn't f=
ind a
> reason why it would get disabled, but I could definitely be wrong.

Does your .kunitconfig include CONFIG_TRACEPOINTS=3Dy? I don't see it in
the listing that you sent earlier.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q%40mail.gmai=
l.com.
