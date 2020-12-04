Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIE3VD7AKGQEJ5GLK2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 574652CEC10
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 11:21:22 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id d4sf163159ybs.20
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 02:21:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607077281; cv=pass;
        d=google.com; s=arc-20160816;
        b=zpcbmgTZgKKea1t2BKGJeMxaTa9KuhY4Q/2pmYVRwaRuifu62J9EWc6VSlrtQmhFIL
         waQ9Lx2dUWTXwgPE7YbCWCnZ2YaOclDWekQAm93OD5w/foAa9y/hP37oZtTronBG1//X
         tDVCQ+WVd0uFS1ifarYmOx/mWLnqyS93ZYobysasdUaSpHxVOrZpiRQvZWuTzqmhWuQJ
         oZJ8jiBnlZMzRmxWQnmQrUVUlDQ5EDnw8HzVrwQqTASyj2yUdUGqnISu9tvaqmbZE85/
         R+ZtAq74WZeYlR4HezuEVjb+tOvbYr98E74Yr8Bcz5kaOmeL/JnT+S+u7A1dWzqGN+xO
         UDlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dBoWDTcyJX9resBuPzJDj3/Hyp/fRgEZpisxwG2Z3lM=;
        b=JJpHb7OvJSieHu8KP+GchbLDLQNL7Dc+WPXCzZ1/Qmdc/Dsy3s1A7KJlx0MNReaLHz
         V8uPaEWRt87r74VrryHADa+YOg7WZMG9Hi72ONCwf4mmr+uKEXuf+N41La/UEE9fwR2v
         LT3WzXHqJ8LR2bVcHIaFI54FralcjUyliIr6YbhO/QQfxLEdx1D1ZVC+IejDabknRxLm
         nFeEzuwrVsFckqwr7Wyh+ma3tojrIkugQvkvToZABvQM9Lafyv6QwRQKxI28YPRvbDUa
         FdJmhGKASFNLWaYst4e6ha6Z6lz31Bi/gy9JRQYcgQ3QwGOI5iuzEl6vPFwoyzFNXQ5+
         RBeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zz6qtvLU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dBoWDTcyJX9resBuPzJDj3/Hyp/fRgEZpisxwG2Z3lM=;
        b=Wkekv33kXOUiNBrUc7T7gStqlmA2XwTJ6QLAsmvN38PVN0ywdQ9oJGcqkJA/2/wMpI
         NNyG+OXBmHWSBABPTE7ItJxlz7YrCJ7h8Z05fPeOUllNCOGjxM6LmCBC2baSgCTM5eAt
         4xHUaVYBqd0fma5jO9aHdsBGUngntnTLrAGISw5RvBGn5WzwMULFsVE455zWQgjYd3m3
         7XrrfE6vgsmmXIObnLrViJjn/vqcvwpIMOlYDYiBQsLMt4bcSDFZ+tyhoTqyL03A7SYd
         aF7DQzvaf7cSQGFqZ3uzqXNDB/ApbrIEEaDLrTfDeM66AjBFwo+3f0LfTHdk/dvNK9sU
         eTUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dBoWDTcyJX9resBuPzJDj3/Hyp/fRgEZpisxwG2Z3lM=;
        b=e+XOchEu4e9ZEfLy+3Yq9H2Y0c1ipxfZPxtpwBS5I4wdCqWpXpU+eZkJSabCN9ABuz
         +FRnV13kXvTdqB3X4iWaKvMjafMV2VFloveoxipta6X/0Z7Vv2bm33IC8tk27B65437O
         amLzAaS8k+BG/T/o+SqqZLdAk2zetyuQOO0R66iM2xPXQ0f9v4exto6fN5c47fVweJwt
         oc9HHfgI0BoA9aapdQNRYNb60eNZrELoMFpJIKvRkYAbUd4QGRaSyObs8c6y+9RMzZf+
         3GRg0WtC8AwTtYoj92ckP8ZR7o3fuVwfDYUIF+tBWDnbJsf+xgy7dH2ZC2jD3q5xX7Ca
         QazA==
X-Gm-Message-State: AOAM53309opahuAEd4hZN7zSVsQ951WiWX++4KxniOqYxZvdom//nF/Z
	lefhhd1QuaJ8aMNfm+RMX84=
X-Google-Smtp-Source: ABdhPJykwgGcZB/nWY0EPcDCddX3kiVxrvn7GdcxXA1+F7jUxLl+bTuZED7aFa9MG4bJN4hWjt87Ag==
X-Received: by 2002:a25:397:: with SMTP id 145mr4491102ybd.6.1607077280247;
        Fri, 04 Dec 2020 02:21:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:19c3:: with SMTP id 186ls4157778ybz.7.gmail; Fri, 04 Dec
 2020 02:21:19 -0800 (PST)
X-Received: by 2002:a25:738d:: with SMTP id o135mr4443755ybc.349.1607077279769;
        Fri, 04 Dec 2020 02:21:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607077279; cv=none;
        d=google.com; s=arc-20160816;
        b=eq3vuMGbvcqEkVRlF/qYKIbgYjPHz/qkopXtTP5PfL5jGNRV0rMBoh60roUrRWHqib
         hRG29ULH/cddeR6CrJMiMcG3iv9Jj4M3ZOFbO4KMBfb2m7v8e2apxZSJc9xuTqpscAv8
         6DstgjfhyzdOLZu8QLpMAz/m7wfbcruMz4Pt+Ur6DZkar7/dQL3+EVmlfEonkTEKqxEL
         ZlI7JDwdwMk1XjbE7ZuzBpiqrZzZ9BfEn3Zr5GQYFxhhZXCbEhguYCdYDAu2RbAzYbjA
         yM7xwRH93e/Fj/XbmrMF4yMakye/7LXyP59GNIzMVK0W4s78/WxKinwVYU41hcMAz16q
         gSdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kk+jgYQurGhXb5v13hLoLvf1FnCh+AW+lm+ijO2Uveg=;
        b=yioMHncaoS7ZIjjOfo1omBZepNShUwWpGsnpi3z/PfaWChKWzJyvvzdoGR89iBQALB
         IQzrJDIb2JYIdGmCVEqgKtPH1HNyuRrJrawaasCNd0S04vMmUIwgysBmuAQC0XTPK2hB
         /L83HKXrDjXLyOvwQ4nz+C0dm1CVQapBIHOV5nAxUMcm600/taEfOCfgTHhCpnUewzLk
         vuT2ZVUaJNMyXBnNaIdBKh0pIxZTueFCLVDwThPjtsN5ljrOtR+h+FqBXbanelpTGAf3
         zQYAv5MPQvT1Uqpv5tkYQujkYoa8DfEM8kTVt+jSOFM5D2PBSZaJmPfQUA+kyi2s0YT2
         AxtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zz6qtvLU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id v16si68092ybk.3.2020.12.04.02.21.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 02:21:19 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id t9so5629214oic.2
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 02:21:19 -0800 (PST)
X-Received: by 2002:aca:448b:: with SMTP id r133mr660309oia.121.1607077279178;
 Fri, 04 Dec 2020 02:21:19 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com> <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
In-Reply-To: <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Dec 2020 11:21:07 +0100
Message-ID: <CANpmjNOUHdANKQ6EZEzgbVg0+jqWgBEAuoLQxpzQJkstv6fxBg@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Joe Perches <joe@perches.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zz6qtvLU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Tue, 1 Dec 2020 at 21:00, Nick Desaulniers <ndesaulniers@google.com> wrote:
> On Tue, Dec 1, 2020 at 7:21 AM Marco Elver <elver@google.com> wrote:
> > The C11 _Static_assert() keyword may be used at module scope, and we
> > need to teach genksyms about it to not abort with an error. We currently
> > have a growing number of static_assert() (but also direct usage of
> > _Static_assert()) users at module scope:
> >
> >         git grep -E '^_Static_assert\(|^static_assert\(' | grep -v '^tools' | wc -l
> >         135
> >
> > More recently, when enabling CONFIG_MODVERSIONS with CONFIG_KCSAN, we
> > observe a number of warnings:
> >
> >         WARNING: modpost: EXPORT symbol "<..all kcsan symbols..>" [vmlinux] [...]
> >
> > When running a preprocessed source through 'genksyms -w' a number of
> > syntax errors point at usage of static_assert()s. In the case of
> > kernel/kcsan/encoding.h, new static_assert()s had been introduced which
> > used expressions that appear to cause genksyms to not even be able to
> > recover from the syntax error gracefully (as it appears was the case
> > previously).
> >
> > Therefore, make genksyms ignore all _Static_assert() and the contained
> > expression. With the fix, usage of _Static_assert() no longer cause
> > "syntax error" all over the kernel, and the above modpost warnings for
> > KCSAN are gone, too.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Ah, genksyms...if only there were a library that we could use to parse
> C code...:P
> Acked-by: Nick Desaulniers <ndesaulniers@google.com>

Which tree would this go into?

It'd be good if this problem could be fixed for 5.11.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOUHdANKQ6EZEzgbVg0%2BjqWgBEAuoLQxpzQJkstv6fxBg%40mail.gmail.com.
