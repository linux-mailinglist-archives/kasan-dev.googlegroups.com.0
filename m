Return-Path: <kasan-dev+bncBDW2JDUY5AORBR5232VQMGQEBK6TNYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id E45B280DF91
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 00:37:44 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-425920ae636sf446071cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 15:37:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702337864; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z4nJTK+hfmdpHRvaUk2rIdIvu8FDSyh5JR5HJPhCwaGHJd05bOtWn0S04J95brjVMi
         gLbMgKXxVA5ZqXcC08IUbz3/NK5NFfJ0xrkFPuksc4DPVwTw6+frCWc362gDYs5e+2IW
         Oor2EBLBIbAt2vSaJSs/Sbe45p/9tM02/6qkRpqCUTUQ2jZrXZK5/cXXWJT0+PsiEOaM
         qchpFUlViaiyvZgQfzhZKiNweyYE9qlEj+B8V4la92T49FaLLdq+zveHPPrvsYE60Gkp
         SQgnI3O8xtTRZubJS+cdSMHZRHzbQzHWaZl7x9VAcC0DZzd6KzMcHAiV39tp1rS9VpOT
         uVYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=BRR0PciBtrANM0ozADFhhAouQq+iua+xrAp+3933ALQ=;
        fh=G8LpRUEj/CNC/tdUqJhJQ8TvkwdRKX07kT9vfjglBjM=;
        b=oOWei0N12Wb846ZYRtmtdhWQ/4npSOQ0a7c1GCQoY+kkodW5wwMkGKtphc2tKuhGUW
         MbvPUcfgFEcecWcNk7drsLXxqncKQe6qhYkn/LWCB6iCUepEsIW9bdG6JV+guhK+B9kL
         QTu2UCTLzI9o6iqLZfCL3GIqXhuL6HONSRNJZ3QZHVlKSTKAX7JztoXb6dKSDA0yodKl
         nC16DMSo+DNrg3Ze0CtYGLm4+PccHWOO8ySiBd9uo+Mij6ObU6iacBEmc2yMPIyzIBWw
         tZdgjmPXQU5TAMLe42GAY5N2UCpjFOshTiMwK14KVIHrKSgjERzK1MZDHGMUx/6dPlMp
         2v9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="NwmPb/Y+";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702337864; x=1702942664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BRR0PciBtrANM0ozADFhhAouQq+iua+xrAp+3933ALQ=;
        b=W145avaXKqek64YUBVVoP+oRE0y1jfTyaVd+76JHtX9q8E/nqbZIsTQkhMx13Na93y
         yCQPS/Z79Pk9A1Onsrv1J8SuaRAKcI969BmHF5iz10dwVlVudxRW0KXvwmMqaN+s4R2b
         1MY7TE9PTbic0cTj2QlYM9HYG7Xqi2X1/y9bv5yk8u0P6Cm64kyxuOW0DtPl9kR7WTEv
         6ZFSNIggXld2Mncyk7H3brx+lAM/K+d7F1/FKyiIdKDd9sx3MpUQ3qU434aK4a53W/5s
         YPot7kDqEAy6PgAjU1TCrgvKeNH2jieJnnebzbDkebSEq+45B/TwDdC6Y8onbNGhpBZF
         fULg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702337864; x=1702942664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BRR0PciBtrANM0ozADFhhAouQq+iua+xrAp+3933ALQ=;
        b=C6Mhup7NEyovYzrk9sH8DsT5rDosyEuNKaD6IXIWloXueniVSreEPNnMfXHl/T1dcV
         t0pvch9xPmZyq7FwbgY9MhR+yjJUsgT7U3rRdlPkxmUE/uG8i/e/Q+F7fUWDokeafuAH
         ccWzhzLRS+Wcyt1Fb9eeMWGG/3tqvuCSjcBuuEz86dvtyZR2nfRNISk5kpBLwa6vxo4N
         i7zM2MHC9+zRULo3VzZhDAMgMIfbszDgH9IdtjPIcxICxRjqudHtUGjHUaWNhA+l4y+d
         nhF0JcJkmAbuJLmQCE86u2U6vs+1XDPB/whPsNIxDYoitw7J7m4wIiM0JgfqDKfhIW6i
         ND5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702337864; x=1702942664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BRR0PciBtrANM0ozADFhhAouQq+iua+xrAp+3933ALQ=;
        b=uPWKEUTeCs5H81TCqPa0Km1SBFLrXSsKcAR773/IyiO50WYh9ZQKzRVJJXzgrzIPUU
         BK9KZSoA15ztCYkOZmM9wFQEwSH6TiHSZe9pkLglutO8rjnI0Fs4ifE+UB97zYLNhip1
         7Lxq619KUqOzOHK+4P3ve8hecYkjyhE2wqPRNZaDsZUfgoJh6gc8MKl4JkUeIG/JzoAM
         w3ooTEdbaqLUOgMVTpN1/8gqiBdGuKRkRiQtwC4H1uHP73fVR7Su/qRPFRwKi1Ur1zxg
         trtGfNei/VSEG5IIliVccHDCkiHIt8d4SymbIpJ7E1EXyk+KBqn9sleWyxmwP6GzYQQH
         5O6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz580WskwOhKNTY5vOi3LVV++ncUUIV/65AgKNc6up86ELJUuYx
	mswfYbG8QxWatfVNcBAlOPw=
X-Google-Smtp-Source: AGHT+IH1wRWQxIBePlenR2TM8b/3PYHLZ4FyD1oBWssvrp4GDkc/mbxL2gldwnKc4FcF8hNQ1KULLw==
X-Received: by 2002:ac8:5dc7:0:b0:425:93ce:83c7 with SMTP id e7-20020ac85dc7000000b0042593ce83c7mr842108qtx.3.1702337863786;
        Mon, 11 Dec 2023 15:37:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:a06:b0:67a:3dd6:779e with SMTP id
 dw6-20020a0562140a0600b0067a3dd6779els681188qvb.2.-pod-prod-09-us; Mon, 11
 Dec 2023 15:37:43 -0800 (PST)
X-Received: by 2002:a1f:7808:0:b0:4b2:d392:1915 with SMTP id t8-20020a1f7808000000b004b2d3921915mr3774642vkc.21.1702337863172;
        Mon, 11 Dec 2023 15:37:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702337863; cv=none;
        d=google.com; s=arc-20160816;
        b=OKCVNuGuctVGbMrzcT/jdqBAGXjofalAKRWMd/RtcxLquXkLVEpGY4bezlvfck0EwW
         SHgM7ikuOXzV3rJfLEO2SLiPpTmfZup/1mEabSPPUc3ZjiCSzS77DbbBdycCE6hlZsv7
         Ng7pAlrEcVc65YTCZ1mtjaYgdceaf6l0noGcaluagMI/Ab76EF0WQjQxUVaCJz/9ttqa
         kWdnqTSvRioSi+EBY/2WbfRfYy5aPqZRP2Id4aa8EO0uYOp6wzln+ryHEbf4wtt9btUA
         oMF1k6sHIidpKj5eoLcpazLKLxrKSZu0Zq87CpRpWZ/t0FwxK15JqqdDeudZmoDDK+Ve
         BysA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=t86WZt4ENI/hv5N6g/BMDwtkCseB1St9FbZ8iMLj7J0=;
        fh=G8LpRUEj/CNC/tdUqJhJQ8TvkwdRKX07kT9vfjglBjM=;
        b=N+LCODgzdSy/g/4gy1abCOtGPBJ+Mz3ow0dfZ0treyswLzyP1twwO/uHLQHjAkUgWu
         HkIcL6hJxJj1d0wk7nItUS/TpPGuXO8mWkekJy0roqrAoQMesriJicZnbhxqY+HkcU8E
         mTV4ChJXGBuwSRGB6DZsDJt7Y10tkXw25STsLcnZ2rnLESuzVRNdtPeRRFUhapEy4l6F
         2+JrM4L9Z8wrajJjgGRrx3Qhp/ezfX3MWNuuWZJRe5irwRbYOiu9SgXpd0dAkHJsZdWM
         pFE2HpRHz++M0pkh/TWND95/79mPYExLk3bjJeEzMGRLJ5DLbLQtwxKlgYmzuCgbNjV6
         sykw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="NwmPb/Y+";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id bq6-20020a056122230600b004abd0f58a5esi1048630vkb.2.2023.12.11.15.37.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 15:37:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id 46e09a7af769-6d9f8578932so2518924a34.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 15:37:43 -0800 (PST)
X-Received: by 2002:a05:6358:c304:b0:170:3f9f:b367 with SMTP id
 fk4-20020a056358c30400b001703f9fb367mr4811270rwb.26.1702337862479; Mon, 11
 Dec 2023 15:37:42 -0800 (PST)
MIME-Version: 1.0
References: <20230215143306.2d563215@rorschach.local.home> <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home> <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
 <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
 <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
 <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
 <CANpmjNMw3N09x06Q+0mFCEeTKfUsDdXwXM2hdgAQ+wwbZGpB9w@mail.gmail.com> <rbcdbilhh67fvjdgnstu25v4jnfeesthoxstnzzglynbngu5bk@5ozwgzaulbsx>
In-Reply-To: <rbcdbilhh67fvjdgnstu25v4jnfeesthoxstnzzglynbngu5bk@5ozwgzaulbsx>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Dec 2023 00:37:31 +0100
Message-ID: <CA+fCnZf5kxWUWCzK8EKgUuq_E2rYv5aw=SqZMDb93+=7vSUp+w@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: Marco Elver <elver@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Collingbourne <pcc@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	linux-trace-kernel@vger.kernel.org, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="NwmPb/Y+";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::32a
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

On Tue, Dec 12, 2023 at 12:35=E2=80=AFAM Paul Heidekr=C3=BCger
<paul.heidekrueger@tum.de> wrote:
>
> Using CONFIG_FTRACE=3Dy instead of CONFIG_TRACEPOINTS=3Dy produces the sa=
me error
> for me.
>
> So
>
>         CONFIG_KUNIT=3Dy
>         CONFIG_KUNIT_ALL_TESTS=3Dn
>         CONFIG_FTRACE=3Dy
>         CONFIG_KASAN=3Dy
>         CONFIG_KASAN_GENERIC=3Dy
>         CONFIG_KASAN_KUNIT_TEST=3Dy
>
> produces
>
>         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=3Dmm=
/kasan/.kunitconfig --arch=3Darm64
>         Configuring KUnit Kernel ...
>         Regenerating .config ...
>         Populating config with:
>         $ make ARCH=3Darm64 O=3D.kunit olddefconfig CC=3Dclang
>         ERROR:root:Not all Kconfig options selected in kunitconfig were i=
n the generated .config.
>         This is probably due to unsatisfied dependencies.
>         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy
>
> By that error message, CONFIG_FTRACE appears to be present in the generat=
ed
> config, but CONFIG_KASAN_KUNIT_TEST still isn't. Presumably,
> CONFIG_KASAN_KUNIT_TEST is missing because of an unsatisfied dependency, =
which
> must be CONFIG_TRACEPOINTS, unless I'm missing something ...
>
> If I just generate an arm64 defconfig and select CONFIG_FTRACE=3Dy,
> CONFIG_TRACEPOINTS=3Dy shows up in my .config. So, maybe this is kunit.py=
-related
> then?
>
> Andrey, you said that the tests have been working for you; are you runnin=
g them
> with kunit.py?

No, I just run the kernel built with a config file that I put together
based on defconfig.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf5kxWUWCzK8EKgUuq_E2rYv5aw%3DSqZMDb93%2B%3D7vSUp%2Bw%40m=
ail.gmail.com.
