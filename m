Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3XTY77AKGQEYXGRUZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id DB0572D5847
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 11:35:27 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id e68sf3382364pfe.4
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 02:35:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607596526; cv=pass;
        d=google.com; s=arc-20160816;
        b=JPeHa2pd2hHaBMS80EUQ69NvicKd0vG0Uj4l5Zfc0lpnc5R3MMtYIhQ78Wu9tqb84+
         qsaz1nKN8KDqwgU4WARvG/4c+dZKNEZ1VNK5LJ4mx2Ui5oPbR0eqRVz2MCzK57Rh3tpL
         Jj/MPVrT2H0qkQfn+1fxs3/+LLMkjtGDG/NK0dV+2PhqaTnLTmR4SQ5YSO7JnCAIns46
         9cGxRExE5KHtKlgzO8LA6YCpbxtQBx/3iYLtgDgp6MDmndnlbw3ZCPG/BKkdIdcvcWmz
         2a2rQgz5w3c4VQdX2VnYBQCYF9wo7CbSxifRYSMCPqmwbjcZhOc7fNO/Emg2QhBAMsun
         5J4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NbgZPNYaf/u5vy9Zxue7drM/hVW2bkc5XGjMGeX+XcE=;
        b=A82tATTb8HFZww6xpo3+NNIQu0nDKNqgHLlNgeyNLvQxEJFcQiFH16yxiCGqxDMYi6
         F6BemeoOOOjONBBQNO7EqPOVPG3EKFdexg0LFTgm7mB3px8hy4e2CLgMUNLazYFu5aWm
         mFHfpLVOs5xPSHNeOECIFNZvZWEcrD92q3lnyx0XSgHkPdzc5IzPHoprFQ5FzGqjoV3F
         ujsayYpl8+S72lzzHmCEB41vPA2lpf/BrTmFzZBs0c7+1RoFnyUPgEf1yKBrZgxWx1zy
         5n9gJoEx7gZI3lG2GsYVI82agWPs/1J2+n3Ot73zJzbFwnJmBUOryPddCz43Cq6dTMCm
         b1Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uDiLP1wY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NbgZPNYaf/u5vy9Zxue7drM/hVW2bkc5XGjMGeX+XcE=;
        b=E/jABD6QY6Osb2UEHLUBw6xREyetEKIPAOKOfGQplR6ijNtNO7goUT7Zd0fhC0knv2
         vzOEtvDQhiZUQcgCYge/yYcAfPm5M2MBwQ/5pRsH23klpQtlvV2NHK3dJ1Tdfb/u+5no
         Bh4qBRcumqcSMqYIpmQHqCbbRuf2TEItNGYzhL1QTxuxIOWMSd71MYl/GAyMormtUhf/
         5qz+MlPYihpdA3Q1xvLuM22CLHnRADJygfH3OxRGsLTBR86jqEnG9DcR4VFPtErO+wgr
         Xz1JG7d79odum1iqjrSLeWXAEBDaQfjJKlApJpV+yu2OQ1l3CKg3MTWiVmvkHkmRttRx
         nanw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NbgZPNYaf/u5vy9Zxue7drM/hVW2bkc5XGjMGeX+XcE=;
        b=qRLuwK/4623tCmQDu8uOaLj6oGqADxodYUeJRxpZKxVou7XGNoZA3e3ipm6InchI5a
         PBvZdl8Cu3o6eQC/YQXfnjD4PuUW5hldBld2B/qz2SXztDrIe756Dlo9/6p5HoLTA/87
         Eo5desk3a5lGwo0QHUj7U7ye9PK+mGnXa8aXb3tOT09Yt0zNCZ/WDEE+kxF1TcBQzkyR
         jcLeltieQu7QLNbRSBNE5H4RRw5EjQy9NFnxd1WVgDhPxm+appUO94rBKiZJuM9DHftF
         BzZBCGUa9gALs1S8asDlqNnhWBmPX2245e8XdX6bVBEHcXXKNc+1iQ8kTcmXH4HcMdJO
         OcUA==
X-Gm-Message-State: AOAM532Cp0g+hr4r4Ycq5B1o+g6hHbhdynuk7taP952vi/5Gzpshm0Uj
	TcXxbN8FmDwVJ8l62wuEEBc=
X-Google-Smtp-Source: ABdhPJz/ohhED8G4AeltCBXHbk7AJUIcJgwY06+W4UF7w/b+aUQlhfR43YHpabA9ap3rK8/FatzUAQ==
X-Received: by 2002:aa7:96d8:0:b029:19e:bc79:cf7 with SMTP id h24-20020aa796d80000b029019ebc790cf7mr2661530pfq.22.1607596526159;
        Thu, 10 Dec 2020 02:35:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9155:: with SMTP id 21ls1850362pfi.3.gmail; Thu, 10 Dec
 2020 02:35:25 -0800 (PST)
X-Received: by 2002:a62:8185:0:b029:19d:fe39:cfd7 with SMTP id t127-20020a6281850000b029019dfe39cfd7mr5941620pfd.79.1607596525474;
        Thu, 10 Dec 2020 02:35:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607596525; cv=none;
        d=google.com; s=arc-20160816;
        b=KfuOVXnD6mRf2Mfzn4UuON7Ba2nTqJfN99/EpngbSRieAiBV9tfC+ykBVaF+0RHeuI
         0HO+j+8y1d5q8banz+P07fskcsSV6HA3Gvp600jjoCz4TjpN8/9ZUVHxmBwpiC30/Qtr
         49MBH6n2WH5NcTnW3vspD26YUJx/bAR15fv6YvgNCWtxif/7hBWR0pkoAXS8Y277mJhm
         9BVYtNGUEOFDJhzRZlSbbPa0tdJVJTxWE2PP2okOAswqWS4uMEImIyEgzsLkyMDvPpC1
         sjp0eQWZrEC8YFCwlZ9m9fcg0GJUDarEgR7RD/nO9sxsUimHYPSyW3MD7R+kk0FM+FX0
         R40g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0RukmWBs4EfbLw0LKaTCMp0B3EXWkv2oBBxKfL580zU=;
        b=q+zB8g/Xe8l+JsRL7YYqeNjG6Y41TDK4h2yxZfIvjfYy8aGOr4U/COCJ06xQ9fH8mc
         yq/lVTqLzwzrX4a+TX7mGbiTUl7kXUg/gA4t+uYuOUUlaWvwcF0KxMLjPKabXvSodu7n
         ZMEuObzryN9xUTnO5AQHX4uxOPa7b/Dc/RnUARL1A6i4ZwLFcagyKzY87PTfU5Hr0EHz
         38qalubBqz/odJAg2uV7ivUWZQfRuDgmOk9L6GnPlJrbHUmaDj8xUmlFBUBxbKfTW9hU
         49ovi3aviA6GGuvxZt/Z7kQA33QfuCEI5+nGet61Wm8MjUMlrE+rUCiYfLj3ekITUhT1
         y48w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uDiLP1wY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id il4si245081pjb.0.2020.12.10.02.35.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Dec 2020 02:35:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id j12so4396114ota.7
        for <kasan-dev@googlegroups.com>; Thu, 10 Dec 2020 02:35:25 -0800 (PST)
X-Received: by 2002:a9d:6199:: with SMTP id g25mr5221108otk.17.1607596524684;
 Thu, 10 Dec 2020 02:35:24 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com> <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
 <CANpmjNOUHdANKQ6EZEzgbVg0+jqWgBEAuoLQxpzQJkstv6fxBg@mail.gmail.com>
In-Reply-To: <CANpmjNOUHdANKQ6EZEzgbVg0+jqWgBEAuoLQxpzQJkstv6fxBg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Dec 2020 11:35:11 +0100
Message-ID: <CANpmjNOdJZUm1apuEHZz_KYJTEoRU6FVxMwZUrMar021hTd5Cg@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Joe Perches <joe@perches.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uDiLP1wY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Fri, 4 Dec 2020 at 11:21, Marco Elver <elver@google.com> wrote:
> On Tue, 1 Dec 2020 at 21:00, Nick Desaulniers <ndesaulniers@google.com> wrote:
> > On Tue, Dec 1, 2020 at 7:21 AM Marco Elver <elver@google.com> wrote:
> > > The C11 _Static_assert() keyword may be used at module scope, and we
> > > need to teach genksyms about it to not abort with an error. We currently
> > > have a growing number of static_assert() (but also direct usage of
> > > _Static_assert()) users at module scope:
> > >
> > >         git grep -E '^_Static_assert\(|^static_assert\(' | grep -v '^tools' | wc -l
> > >         135
> > >
> > > More recently, when enabling CONFIG_MODVERSIONS with CONFIG_KCSAN, we
> > > observe a number of warnings:
> > >
> > >         WARNING: modpost: EXPORT symbol "<..all kcsan symbols..>" [vmlinux] [...]
> > >
> > > When running a preprocessed source through 'genksyms -w' a number of
> > > syntax errors point at usage of static_assert()s. In the case of
> > > kernel/kcsan/encoding.h, new static_assert()s had been introduced which
> > > used expressions that appear to cause genksyms to not even be able to
> > > recover from the syntax error gracefully (as it appears was the case
> > > previously).
> > >
> > > Therefore, make genksyms ignore all _Static_assert() and the contained
> > > expression. With the fix, usage of _Static_assert() no longer cause
> > > "syntax error" all over the kernel, and the above modpost warnings for
> > > KCSAN are gone, too.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Ah, genksyms...if only there were a library that we could use to parse
> > C code...:P
> > Acked-by: Nick Desaulniers <ndesaulniers@google.com>
>
> Which tree would this go into?
>
> It'd be good if this problem could be fixed for 5.11.

[+Cc everyone returned by 'get_maintainers.pl scripts/genksyms']

It looks like there's no clear MAINTAINER for this. :-/
It'd still be good to fix this for 5.11.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOdJZUm1apuEHZz_KYJTEoRU6FVxMwZUrMar021hTd5Cg%40mail.gmail.com.
