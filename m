Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOXOSKXAMGQELL3V3TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A6CF84DF7C
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Feb 2024 12:13:00 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-dc6ba5fdf1asf2123962276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Feb 2024 03:13:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707390779; cv=pass;
        d=google.com; s=arc-20160816;
        b=WtltM3WSfO8v9Es2QctAKJUdyxSWXQdPZ+9lwNrCJ1gHsCjbiYgzKu4KZ/uu44dL4V
         3WLnqz6HIo0Zt0XCMYPLTohsJ+Q/xv8tUED7ZQ5Krp6SE5oSUxg3jlmLw5gotKT/JIEw
         ZOefmUfwPIlrKKX7nVcZf5fT0xa2UDCiKoJljL2Ysbke4YrUwEbCqJqd1x2vwfNWLQ7V
         x4rmYJLVjPqGNOlGqPt1ss/zJnfoQ+rJkZ2ewtZEE6b9KMQQ25GqLmO55wGnWEvjsh2R
         mawrHRpXPyCMrL584c68dosZdfO08lL3Y59lpontT6sul6/HghKn136xcnQQnQtIAO+Y
         zuMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k7s5ibUeVnYLq6BNIA/qh1wW7fEPFV435ncb4L918JY=;
        fh=4L7AbOgoyCfIbbm8sRLOQ0oWRDEzJjOsyeoB+IRnP/s=;
        b=N6fKSpCCZHJ5skAHsGACKdf8brHEh+YdTuGhmXG53PKiHybBejbgFoah3BObTwLrxH
         6H77Vm1S4BWm0uuNP3Odaru2/uk6RIT29K5UFuDli5PPhSKVXyUx33gQw9fI2+WSfR8o
         cETqAgTmpCyVoUyzagRrhISvOuXxUkOIHK+0sw+tXpO0Qjhv/hnPbpaw3M2755hDJRAJ
         cQuhMB+w4C9CB3gKbHcInKqUMphwyn2xPWF4KqhUrac2j0gGTj8HCxoPlPs4fRuMiL+6
         5uWd949wkgR+QSUalQ5HStR+vo8LeDkeGnu8pD3YY9/sADYuCNv81S+20xiJFQQ+h3LQ
         MWfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p2UNDtBp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707390779; x=1707995579; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k7s5ibUeVnYLq6BNIA/qh1wW7fEPFV435ncb4L918JY=;
        b=FbynbhJ4eoBR/NkW8xYK7pZNpdOBu5VPUx0t/T4dt5JtC9B/Lut/sTkyd9PQF84xqo
         URrPfL5Rq4Pe6oi8/cccOwb/gDGhL7j8C5Iwze/r/9grKcMrFwe+LABtkLVyZftPXoYA
         fo+wXnhZdqJnLgX+uto7B2WmZflVQhazayKH/X4DRSUod7vx83+KtNltrCJrTppdC2WT
         khP8WmI4U3Cb67oe9gJlAzzF+MLk09/iop45ej+Qf/jIdAL1SssLdcy1f0JCR7DN3qES
         cAuA9jTz9GMLRBIEev19rKWpQlM8JemCAoTkNCvJYjvLpF3sywHEgN9obfdsnwK8+Aav
         YJ0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707390779; x=1707995579;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k7s5ibUeVnYLq6BNIA/qh1wW7fEPFV435ncb4L918JY=;
        b=A6dkY5i83wPRk4cirufoQPnJdIcW9LBPAZVs5HyQzkaUDQSOxzqeexebM6lY2IFsaE
         6/3BPYuHdXPN9JXeFm1FaRU85r8sIh7MbWHrfmK4WbAMbZJ/7Eq1vK72vGmdVSQYLQ8h
         rhIq9MfPjb3Kwg92i5QdiSXAcyhXBGyuegeWSi3QOwfKBo8GmT8dWTCfboLCvghJjGep
         LEuZUTQv0xfQGQ0B0FICCQ/ilTdxS0tlQL6CTDeWoznoRiqP7W1AzJ2BVlzqPSaWJ5VC
         f9vZIFkbtu8Pv/3CjfXx1rqTwgIe6wLemrl3Xtkl+T3TLb2d3N2eAQ1D2t+kngrFMLBo
         tLOw==
X-Gm-Message-State: AOJu0Yy8sTNF+/wi7ka766ZxqYoIjdH+kMEGlRqxXaRvJxBVRawL1pe3
	zDI79S1FxhOE5PriE89GFifRXdD7R/yqpqW0BMQiyVPBqoxvsZZ3
X-Google-Smtp-Source: AGHT+IGjK8tdX2MxiEeIQWCCDzgK6udURR0Hybi/x/lLLrvTdjt6ztnZ9S1pgaLgGL+Wil8stSaEnw==
X-Received: by 2002:a25:9111:0:b0:dc6:d457:ac92 with SMTP id v17-20020a259111000000b00dc6d457ac92mr7705973ybl.31.1707390778296;
        Thu, 08 Feb 2024 03:12:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ab09:0:b0:dc7:4417:ec4e with SMTP id u9-20020a25ab09000000b00dc74417ec4els511012ybi.1.-pod-prod-04-us;
 Thu, 08 Feb 2024 03:12:57 -0800 (PST)
X-Received: by 2002:a81:4ec7:0:b0:604:a32c:9998 with SMTP id c190-20020a814ec7000000b00604a32c9998mr2190450ywb.22.1707390777437;
        Thu, 08 Feb 2024 03:12:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707390777; cv=none;
        d=google.com; s=arc-20160816;
        b=RrBgATINGducJoxdVopVBAKQn6SkNYWsEmUXjVi/nou6vQ0O5lLLTwKntyg/TeeM2q
         AqQ12TjBlaqfvWlL4mf41k0nZWP3BLl15giQIGwHZzTDTqhJ5WyWOp8jxMY9EE+MK6pC
         rAnPWwdDFGJlItxEfICmP37igW4oXzS21FVQLBOfX+Nn3v8rcEnNimh7HaZSMD5VWSkm
         LP6JskOI8SYF1nP8e3J0dpPqWSULB3Uj5GGlJn1xRNG+a8V8pX3IgS6MQNYpUz3I2YGd
         FGckXFos7q/5HrWunnVjZ/GRFsHyQRef9bbyA5erOmTFt+oGAW1JOq+qxOTcKq5BQ1TL
         mThA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VJsSscqQ4m0MN/FGyPVyx9oMz+6/oNg/GzMN0pvUUbw=;
        fh=4L7AbOgoyCfIbbm8sRLOQ0oWRDEzJjOsyeoB+IRnP/s=;
        b=wnq95DX2FDkBp1+ukyxrbYI7bOK7XbU4/uIkGDYLBCZNxechBmx6AzfTABudq3fzNU
         8TOgnB4YwZf99z3I23QuePZCFG+Rjh3SVVfZo+PT9pCXs4z98C1ri5JSZM2Mbi9W+0et
         0dB9CT0NN4TGyxN2O3TBLFs3+PJ3NeLJN0doLbSe9M85wI/fLh9HDTWxp9HUe3y2WQnQ
         E7fbU4ZP/9gipJDIHL44GPQpeoTjW7nnueuF9Tyxo3mWJWDKX7cyvoYoMcQlvQAHIeMt
         hyV8sQAmBnP3JGJuOrN9KSI1hpBIYQVhS4uYYCz/ZCNRbkHzuU7zzs/LZEMY9jGVKrpP
         JvYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p2UNDtBp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCULw6GPO1ILq5owup6UA+qvd2vTUAwJQ75KBx6UxCZ9e/pPYcfjFnzXWWZxMf62lBkaJR8seXyd6+PmG/dekmecGDOyurZyUi1Qgw==
Received: from mail-vk1-xa2a.google.com (mail-vk1-xa2a.google.com. [2607:f8b0:4864:20::a2a])
        by gmr-mx.google.com with ESMTPS id w20-20020a0dd414000000b006040f84d90bsi371204ywd.4.2024.02.08.03.12.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Feb 2024 03:12:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) client-ip=2607:f8b0:4864:20::a2a;
Received: by mail-vk1-xa2a.google.com with SMTP id 71dfb90a1353d-4affeacaff9so589067e0c.3
        for <kasan-dev@googlegroups.com>; Thu, 08 Feb 2024 03:12:57 -0800 (PST)
X-Received: by 2002:a05:6122:1807:b0:4c0:292d:193c with SMTP id
 ay7-20020a056122180700b004c0292d193cmr5712620vkb.12.1707390776764; Thu, 08
 Feb 2024 03:12:56 -0800 (PST)
MIME-Version: 1.0
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local> <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
 <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local> <20240207153327.22b5c848@kernel.org>
 <CANpmjNOgimQMV8Os-3qcTcZkDe4i1Mu9SEFfTfsoZxCchqke5A@mail.gmail.com> <20240208105517.GAZcSzFTgsIdH574r4@fat_crate.local>
In-Reply-To: <20240208105517.GAZcSzFTgsIdH574r4@fat_crate.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 Feb 2024 12:12:19 +0100
Message-ID: <CANpmjNPgiRmo1qCz-DczSnC-YaTzpax-xCqbQPUvuSd7G4-GpA@mail.gmail.com>
Subject: Re: KFENCE: included in x86 defconfig?
To: Borislav Petkov <bp@alien8.de>
Cc: Jakub Kicinski <kuba@kernel.org>, Matthieu Baerts <matttbe@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Netdev <netdev@vger.kernel.org>, linux-hardening@vger.kernel.org, 
	Kees Cook <keescook@chromium.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p2UNDtBp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as
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

On Thu, 8 Feb 2024 at 11:55, Borislav Petkov <bp@alien8.de> wrote:
>
> On Thu, Feb 08, 2024 at 08:47:37AM +0100, Marco Elver wrote:
> > That's a good question, and I don't have the answer to that - maybe we
> > need to ask Linus then.
>
> Right, before that, lemme put my user hat on.
>
> > We could argue that to improve memory safety of the Linux kernel more
> > rapidly, enablement of KFENCE by default (on the "big" architectures
> > like x86) might actually be a net benefit at ~zero performance
> > overhead and the cost of 2 MiB of RAM (default config).
>
> What about its benefit?
>
> I haven't seen a bug fix saying "found by KFENCE" or so but that doesn't
> mean a whole lot.

git log --grep 'BUG: KFENCE: '

There are more I'm aware of - also plenty I know of in downstream
kernels (https://arxiv.org/pdf/2311.09394.pdf - Section 5.7).

> The more important question is would I, as a user, have a way of
> reporting such issues, would those issues be taken seriously and so on.

This is a problem shared by all other diagnostic and error reports the
kernel produces.

> We have a whole manual about it:
>
> Documentation/admin-guide/reporting-issues.rst
>
> maybe the kfence splat would have a pointer to that? Perhaps...
>
> Personally, I don't mind running it if it really is a ~zero overhead
> KASAN replacement. Maybe as a preliminary step we should enable it on
> devs machines who know how to report such things.

It's not a KASAN replacement, since it's sampling based. From the
Documentation: "KFENCE is designed to be enabled in production
kernels, and has near zero performance overhead. Compared to KASAN,
KFENCE trades performance for precision. The main motivation behind
KFENCE's design, is that with enough total uptime KFENCE will detect
bugs in code paths not typically exercised by non-production test
workloads. One way to quickly achieve a large enough total uptime is
when the tool is deployed across a large fleet of machines."

Enabling it in as many kernels as possible will help towards the
"deployed across a large fleet of machines".  That being said, KFENCE
is already deployed across O(millions) of devices where the reporting
story is also taken care of. Enabling it in even more systems where
the reporting story is not as clear may or may not be helpful - it'd
be an experiment.

> /me goes and enables it in a guest...
>
> [    0.074294] kfence: initialized - using 2097152 bytes for 255 objects at 0xffff88807d600000-0xffff88807d800000
>
> Guest looks ok to me, no reports.
>
> What now? :-)

No reports are good. Doesn't mean absence of bugs though. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPgiRmo1qCz-DczSnC-YaTzpax-xCqbQPUvuSd7G4-GpA%40mail.gmail.com.
