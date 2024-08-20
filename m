Return-Path: <kasan-dev+bncBDW2JDUY5AORBUFESO3AMGQEZCLJN6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EC0B958D53
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 19:28:49 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-428207daff2sf46468875e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 10:28:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724174929; cv=pass;
        d=google.com; s=arc-20160816;
        b=fdR+ypEt+uDv8ECoSZqmorRPOTe30WcctedmAz6joSLG0vyc53KHNi395owecpeIFm
         z4w21EPiW/y+Mv9JsM8gNlu7yizTdRI61E/hCM9nG22UYBNHSJD0lEWaoxIdGn1YWKH/
         aESS1kNUN75Vj71Sl4WS6pxzQz81JaKCeg7QVXonhp1StKlU8a4SJRhsUGRQSe7zKj6x
         64KQHd2DhRsZeaGB9NF3Lhs1/XqaX6LdFHN31TyjIsEw9YRsTJcwOpDfHeiZtmjSyuif
         HxYbc8hreOGZ0Z3Iegb4s42kzTFmDjAOhHlopvQugBBpi7V1tc03rB5oEUTQY6jf6470
         q2eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=VRCCodiGIAHnopmWIK/Xs0ppu/x+o2nf5+Wr8qZrtkk=;
        fh=ndu3DnDG+qI977xBkc8WXTRgWMgRVOA/WOdDFbSHUAE=;
        b=Hq4uVJF+KX/DwCVU7U5Ay3LGYUahJvPfAM5KDNjWcji1TVuvGEZ5fQHyCDQ9pOlJNo
         0PgiN1jgbTmlKA8IHeB6UR+L2zI6j6ppnuCCO6N8AouPf/1HJKNHPKaf5Zbdst9gySIw
         tKrnXaRlOXCMKzfCw5BwraMQjGqP6Ph/67M5dswxQe//oN8qsDWI+VMT8nCaSUan8u2O
         y5Roz+/AaWvhB/f6TZ20pP5zmJn78x8YrVeYqBK+cM1fTVRE35tTHrOZyrY+lzm6VkR0
         Wavm9hYV+KC1cXC+5am5SrhzOaCkYG4p5TZE6rA+QEYiSirJvqLPM8T8yJBxovtuGoVO
         Tw1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UENLM6yP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724174929; x=1724779729; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VRCCodiGIAHnopmWIK/Xs0ppu/x+o2nf5+Wr8qZrtkk=;
        b=pVOpOpOTwWM6itndGkgSewlvjSKTCD7HgOj8ozN8tHagOBlT/MxByLL3RQe9zw3aNs
         AlFdiH7wISJIu86mbq6D35tLFneDDSUVmS6QMVi/2p8TKuuA2DU1OUSW118UIluCEw7r
         3+zbqHRtWdyqDWFN1BH5JjEV/L8Owq6TVA221RTEn2HjEnZ6sP2FxVlnSCFFxNN39OgN
         j2I7fOr8m2d1IY6tqtsbyBCHPDj0u+eWwgZT2Bij9GF/UN9PnpSTeVxqLkylGxdHk+jv
         KaOXM9j5Nu6izrjGAdfq1pn5op5zFdep1TrhP2UWFiGQqbrqbxisEVBv9munoIm9JTX8
         2HkQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724174929; x=1724779729; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VRCCodiGIAHnopmWIK/Xs0ppu/x+o2nf5+Wr8qZrtkk=;
        b=QQ17PWmwyTKrsbxNI1lInYfZFZ6GGSVnGVoilm+9T2dIwIbJtaRJ5GJYzPekn4gm+t
         4Q8EtE/9I5u4F82RUi/ZCvLUJ58H8T+nAjRr6Z2YKa0/w6k+CW4mkEjG8Jui4SIW/FSN
         ZDeIgciHD7xwryujg7z+9dTu+XJXxI1jco0z/Ju/h4lwYDrb7x62xlahHDoxoHslls8D
         U71mHZ8Pmz4u8Ky37mu2/pNk22dijIJ+00wcYr+EadN9Zd9+oFodRpglq3YdW4WaqsSh
         UevDmdCQEmTUav8ixJYvhZuJKpQnpNqGTsI2bbVdJ4sxu/JzoyHNj3c+94CbS+psAZD7
         lSFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724174929; x=1724779729;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VRCCodiGIAHnopmWIK/Xs0ppu/x+o2nf5+Wr8qZrtkk=;
        b=N5KSa7Gnv40CpzkCAVUyIvFVU5NzAG0lcP+0fhSBDhqVtmujQSCOdQScMhlAoIv2x3
         aCpBAeruFWWriLb14mLDTpOuAxZOhPS4UOKl2k+Aj2LNUdGeu0SsQJMq9URHkZrOkg07
         OcmZHgjW22vTH5LvwthRpPh2mgslbwkyfO5Q21CCuOqL2MJ0Op3TsVJDPbQF3OGFJTeW
         zFndd0eL9kEHooI1kSA9ZRtetUD1uF1h03A/1sCB+PrQmRciKbdOGQtYCUh7zCAZWLIs
         I7Yy3ccyq/m8Te+w9yUA3LGujXeWg6rF/inIgtvKncBMqvLje6xLRpG8NiFanyKnrDzo
         Ynkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXGHHYfOO4efNmVDHSqfEnhdIZNmy1x/deKiRlZGb/GukWppwHqaAy7b3HqmG/uyq//3L4Z4J1QRS3gEV/Qle8cYXzUYC9mdg==
X-Gm-Message-State: AOJu0Yw03oPKHog/BfBGGxqCtzeQYFtVF5JbX/SB1osXvnNSGg/F/z5U
	BJDmdpOCkqqMq1x7PDy9TY39D/CtoRIhfzs9umFP1r+SQwA+HBD5
X-Google-Smtp-Source: AGHT+IF2U9/ACz5WedyuByaT28L5RuPFVSzwu4+50WvthrQAHCmwKv4w4oesxd/t6FA7wt1Ft3LBhA==
X-Received: by 2002:adf:f4cd:0:b0:362:8ec2:53d6 with SMTP id ffacd0b85a97d-371946bf053mr8246474f8f.61.1724174928303;
        Tue, 20 Aug 2024 10:28:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a52:0:b0:367:99fa:1fcb with SMTP id ffacd0b85a97d-371868edf2els1280203f8f.0.-pod-prod-04-eu;
 Tue, 20 Aug 2024 10:28:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXv7G0h7xJFpD+YhK+ifHLnJ03wsLWp4SHRlQR1mCoxhugBy8bfewj9bQuo0q5Kr9rAD1EelD0l7Ff/svlKgqXCNqcLPGuXKDGLVg==
X-Received: by 2002:adf:a314:0:b0:371:9121:5643 with SMTP id ffacd0b85a97d-37194314ba6mr11181428f8f.12.1724174926343;
        Tue, 20 Aug 2024 10:28:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724174926; cv=none;
        d=google.com; s=arc-20240605;
        b=SxMinu/e4EIss0/N1SlXGTqUIXkXSrX9EK1eJ/Mpb65v8/J2GZxK9oR3fvwnvf3Xel
         rVINGRjYq3V6JMgIDYoOOZ+PMNKhDjkMqD6Z2WKoHQ3R1fYPdCEctqHZAcoxVwBjUQ/T
         gQ6W8Gq94Q4XC1apQxlgX5RzkqksMKnjlletefrl2H26/L4l1+iMQ8VxuO7aoZCki5Ts
         P178KH++j8RBJYBzTSJUA//1pThGCoHboiPsx/tyyfshoKIt6S3iEDV2EpY14VoHlEu6
         II4Elu+mYRAEnQrnBk5ZY1SbjHbt4gEXrc690KOqXEAsGBCy5RAKRvpdouYApiLUc5He
         tJUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QEDqYF9tb9faubrQz3i+oeJSL+hsxPawYdSfJmGCtpI=;
        fh=qJhwYSgFvBrAqtDOo+FNAvhKg5NdLumtUF5CgTMXjcg=;
        b=JqCB7GYKk9DocLn5Jp4tW8LE57e8a9KtBGQAfep25fYgbLFYs/TVPgF/0fI9voYC/q
         K3mNl/rQEHWhTBnAupNvwm+WwTmV0eFsWrevQceRccpuPQWmXt+b4RW7eyliRKguJLHs
         HYiAAk9BUocM/0UvHZbBYK4p1ySmlbCJoZAkyUaNpNa4Qj84/7bQCeb0Jz+H9eUuYCtm
         v6H5XWIRVdrJC0ROgtmLMoKwzDeOn96EhwJmp+R/J/dnNjMsVbN5h73ThTdG2Oqu/+sg
         qS7S6p+pSE4e20R5Sy6fCItnEC60Wf9ZL1EY2PpPG9VCCG7XfHH9/crW6LZ5LRRHV13R
         DeEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UENLM6yP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42abbab1de4si473425e9.0.2024.08.20.10.28.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 10:28:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-429e29933aaso44790905e9.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 10:28:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXjKLAU5yh+H3PVemoCQRnnJOP8PrkCqb1SBqN3Uex94t/5MJqefWuKR9PosRPquKaUKUcTX89mkN7NUmjYRx0yRhNvkAfm7nwUCw==
X-Received: by 2002:a05:600c:1da0:b0:426:5b21:97fa with SMTP id
 5b1f17b1804b1-42abd2449edmr616875e9.29.1724174925358; Tue, 20 Aug 2024
 10:28:45 -0700 (PDT)
MIME-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com> <CANiq72=jxS-LtTMPdtFCmO0T2ajNZO+XLywqeevE4FyNhtyNBA@mail.gmail.com>
In-Reply-To: <CANiq72=jxS-LtTMPdtFCmO0T2ajNZO+XLywqeevE4FyNhtyNBA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Aug 2024 19:28:34 +0200
Message-ID: <CA+fCnZfbHUJZOWBksYC8N30OWxXG8bJ=-pzkwEcHA4Jpc-b7FA@mail.gmail.com>
Subject: Re: [PATCH v3 0/4] Rust KASAN Support
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Matthew Maurer <mmaurer@google.com>, dvyukov@google.com, ojeda@kernel.org, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, aliceryhl@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UENLM6yP;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 20, 2024 at 4:20=E2=80=AFPM Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:
>
> On Mon, Aug 19, 2024 at 11:35=E2=80=AFPM Matthew Maurer <mmaurer@google.c=
om> wrote:
> >
> > This patch series requires the target.json array support patch [1] as
> > the x86_64 target.json file currently produced does not mark itself as =
KASAN
> > capable, and is rebased on top of the KASAN Makefile rewrite [2].
> >
> > Differences from v2 [3]:
> > 1. Rebased on top of the maintainer's cleanup of the Makefile.
>
> Andrey/KASAN: whenever you are happy with this series, assuming it
> happens for this cycle, do you have a preference/constraint where to
> land this through? I am asking since we will likely need the
> target.json patch for another series that may land this cycle too
> (Rust KCFI). I asked Masahiro as well what he preferred to do, e.g. if
> he wants to take everything (KCFI, KASAN, SCS) through Kbuild, that is
> great too.

No preferences, feel free to take this through any tree. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfbHUJZOWBksYC8N30OWxXG8bJ%3D-pzkwEcHA4Jpc-b7FA%40mail.gm=
ail.com.
