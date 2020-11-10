Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMXTVL6QKGQETBJY3ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F7282ADB1E
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 17:02:59 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id e202sf2398871vke.7
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 08:02:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605024178; cv=pass;
        d=google.com; s=arc-20160816;
        b=FrMnzvA+CpDW8UXXOMbTZmgoQobbwPd0yUs1KxJSmO0bLZUeh9Y/Kwcn4MStwIAxhW
         rT/FY//ResD3F2+RC9c6YMC9G+wOigdk4vDEkMCae+7gtcTLQR6UjhngXw9cBOKUG1xm
         /jGrUHusvVRyNY0J3MbuXUHKAo4MJ1/Tt92vYJ2ZRC/VF382FDU5DvnrIQVC4QbRbbRb
         IZa7zVHo0IC8Oy9jUlKSWRs5BeN0RVnV/Aal+L884z6DwLkExN8yPLyvFsCK4Sr3rMlk
         JSX/L2FSYREScnVOy1g66jEm5yq5O06cvpe047guaErXucBfhvnMaftKvC/GrMwgfF7L
         7U8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nGRogW/BEZ9zlsnqUllCM053YZ/onaSCWjvbF3VhV08=;
        b=A93+wdgzrTJQsx/viFlpPIBETjl4Iixn2VMO9CJWXU9hTHX+tuK4rM7tRPJAFUhBlH
         YXa0PXe0YEF1It18lPc21+jFDrci1dd2IVohExp397QcSOav/fEc4cLjRW8q9jP5n7V1
         3oS9dTOSTFtIHt6wrx3RSyC/5GJa3vxcurgY3Y93yhaBTQYdunOObu2TnJQZ7bIyyNv1
         Nd0hDWU0hyqfiMTgiPYcolBtxBD3do2k0ZQZLwc6pdjfivpJfly8baXC0nCuPE0pFKam
         9AdTZjmpEKo+8Epm/CzIEvvC3JC1vnVU0WU4Y8cJue1znzjw1aguUVnA1E7iYCXOAudu
         +N/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R7ctCrsB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nGRogW/BEZ9zlsnqUllCM053YZ/onaSCWjvbF3VhV08=;
        b=TOdYt47gBhwB6KhCIvQkynadIKObiUzQvzhrxLsTRLREUokHV9mMuFRuwZgwcZS0EO
         IJX/Ug8xjZxET2073jaRE0wxXAHYLxHI+QFDLoYa4aSh6gVt0DMgmOde41IqpZZ8USa0
         AMGbkRm5BGrC80RaZXkoIeZ1pgGvlITx8GneGdgGlMv4q5uBMcgGINOd2F+nzOM7nKDV
         AmQhZviMd0fPSyjEFeoKJbwaqY68EjDSAG8imx09WM0uOypY1Rt1O25C3DF0tJEMtEAy
         hDz8Vr7waSbruEdtj0sR6i0Tp9F9jFhljNgjMcU9aSSXlBPtlzYQH775mQuRClz5ypOv
         TVmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nGRogW/BEZ9zlsnqUllCM053YZ/onaSCWjvbF3VhV08=;
        b=ScAMpv/yBxSHdNd/Y6lOxoGjooX9AW0JpiS2MMbtRASD0vHjJv5KXLexX+3slKUfdh
         FusDVJ38E3r9l+WeUGFGVVWmHf/NLrY5r2xBZgUqaw3QK3HF+MnONNPlu7yD01adCeYH
         zvNqwFr178NZ8E4bdifJp0j4xFS8fp1L/H7cnsGTQBxv8BjyEbNdLaYe+oIl0RPASkeP
         HGi7A4d9YlR4vZvrwqVNo79BbTpKNr/wH4boXFJvHxDowut5eW24eqyxMTmtdVgkHo+I
         82jwPqtro13Mm5MkFMtQ16vcCHuYZsKqRZeknMJG1mC8yOPWs0zGc+GIjX1EVd4dHDg+
         6DcA==
X-Gm-Message-State: AOAM532RqKXAqY/FuJT+OhIxhRkicZQn4sCx7s9xlnYeg/IFyeb+JO+t
	sSX1JvZyBnrVVhqRUAZ8BqA=
X-Google-Smtp-Source: ABdhPJzj3jTsbj44sDgbe09VT+scVT6Ka47KVV6MBBXkG3vC+UeFz2knVU/5XkxtwlshBGSYIA0viQ==
X-Received: by 2002:a1f:3655:: with SMTP id d82mr11023011vka.22.1605024178680;
        Tue, 10 Nov 2020 08:02:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3137:: with SMTP id f23ls1502922vsh.10.gmail; Tue,
 10 Nov 2020 08:02:57 -0800 (PST)
X-Received: by 2002:a67:ea8c:: with SMTP id f12mr8109775vso.20.1605024177637;
        Tue, 10 Nov 2020 08:02:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605024177; cv=none;
        d=google.com; s=arc-20160816;
        b=qxOq5C+dzGxFFhEpFQ5QZ/VsH8KfTRiuamZmrl7t8HCcK8LsBAc8JVJRyaGFJVqKiE
         K/m9Ta7YbXfRXQME98DIYPeYrdJToqOZCyfN4FYbVzGXDQvUwM+8VKlffPde2BIMvMR3
         8QLDVIMDlrpTXL9z+/SP5VSpkpgsEStj0m5mu7ONl+/qlpKawvMDmnHuYEz0nadPXzTR
         zMNdzG8LZHO/ma+ONz5yQ+jzEdOLudRQOjk3iXHgRqqfe6NEzYFUapW8lv6A9l4LWhOe
         Y0UQb6nPLFCAolm9tuBGmyya55suHJWPdlKjd1U8eLzx342JOOgz9hroDFM/SHRtd0Pv
         JxxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3LzNReHV53OMBNVDp85xYqJELJ0TTV1pGSCz6PvcmXA=;
        b=sMXlonEVbItVJG5e+DvxT9jfHwJqDbgzsIgss/i4bC8HiaKVjYsgCaN0PyhE9Xg4l7
         h458BPuuACW8/5Sh4FUpQCPmSFEXBfLU8PlZM8Ilmw+3xi3ksEFn9+wpw5CMPKqIp7RK
         coYayug4agaNkGd+aJNPiK+hpNom+8x/ViDT4OMSpOQu+QB8QfQA4yTQ5w6Qla+d/rFo
         QX//Em8tD0lApB2ifFGx+WIPpGoX5OW1mCMYoDSxUITc1BbcEJ+RgfJiNAqsWfM9nFj1
         ufZ9zgk6HUo5qC9Tw5Q01IJH09l1v2u3FUZYi0i52GOSaO4JHfa6ZB6gcfKqRSeoOi7X
         eVGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R7ctCrsB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id c124si386794vkb.4.2020.11.10.08.02.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 08:02:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id j7so14872913oie.12
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 08:02:57 -0800 (PST)
X-Received: by 2002:aca:6206:: with SMTP id w6mr3338073oib.121.1605024176875;
 Tue, 10 Nov 2020 08:02:56 -0800 (PST)
MIME-Version: 1.0
References: <DM5PR02MB32115A1568F018C726BAB62982E90@DM5PR02MB3211.namprd02.prod.outlook.com>
In-Reply-To: <DM5PR02MB32115A1568F018C726BAB62982E90@DM5PR02MB3211.namprd02.prod.outlook.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Nov 2020 17:02:45 +0100
Message-ID: <CANpmjNMS_stvBiTFw4CR3oSgg9W_Pxinn8omkYX24TOETybFdA@mail.gmail.com>
Subject: Re: Questions about providing generic wrappers of KASAN and KCSAN
To: "Chen, Yueqi" <yxc431@psu.edu>
Cc: "mingo@kernel.org" <mingo@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=R7ctCrsB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

[+Cc kasan-dev]

On Tue, 10 Nov 2020 at 04:14, Chen, Yueqi <yxc431@psu.edu> wrote:
>
> Hi Marco and Ingo,
>
> Hope this email finds you well.
>
> My name is Yueqi Chen, a Ph.D. student from Pennsylvania State University.
> I am writing to ask questions regarding the commit https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?id=36e4d4dd4fc4f1d99e7966a460a2b12ce438abc2
>
> As described, this commit unifies KASAN and KCSAN instrumentation, and probably in the future, KMSAN is also included.

That instrumentation is only for explicit instrumentation. For those
it's quite easy to combine as the type of accesses can be generalized,
but when it comes to the instrumentation that the compilers insert
things look *very* different.

> I wonder do you have any plans to re-design the three sanitizers into one sanitizer.

No, we do not.

> By re-design, I mean brand-new shadow memory, brand-new instrumentation, and etc.
> Do you think this re-design is helpful in terms of reducing uncertainty, facilitating reproduction, and so on?

Each sanitizer works very differently, and e.g. KCSAN relies on
soft-watchpoints (and not shadow memory!). The latest KASAN
(AddressSanitizer) compiler instrumentation normally uses inline
instrumentation for performance, and not function-based hooks unlike
KCSAN.

While theoretically possible, the complexity and performance would
both suffer immensely. Some past discussion:
https://lkml.kernel.org/r/CANpmjNPiKg++=QHUjD87dqiBU1pHHfZmGLAh1gOZ+4JKAQ4SAQ@mail.gmail.com

Getting things like this to work in kernel space is much harder, and
before you look at the kernel, try to think if what you'd want works
in user space. There I think any real-world benefits are also
diminished by complexity and resulting poor performance.

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMS_stvBiTFw4CR3oSgg9W_Pxinn8omkYX24TOETybFdA%40mail.gmail.com.
