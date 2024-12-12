Return-Path: <kasan-dev+bncBCCMH5WKTMGRBH7L5K5AMGQEBTD2PMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CB6539EE3B1
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2024 11:06:27 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e3c7d56aa74sf527965276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2024 02:06:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733997984; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z6XERXMhswGbnUD4cuabG3E//E+wpP3bH6WguyU6QzPiZ/+EyrKB1UB/rSpC+ZHTu8
         oTwMt2cKYOShA0DsX2HoJsEosB00/9t+qLJxO8RcyOXKlJ+I01Np+hwfE0QAqzaQarpq
         zW/Piucdlo9xTtQx2QBvGL1g7oFw1JgmzFD2O7iPhL4RW3SJXZEa1A/3WkVe6DvfN/lX
         hKjnWaaicXYRLChvW9MlOH0zv5qr4+Qhoi3l9P0PhXL1HqKT8BRzhqXq+BRLAnddUOOc
         JDSowefDP+HNP3WXpbR8H8ssqyjxB9w5Rwc2NT0OTPMAat2OA24KXblpEwFPjXlhRIwA
         7TYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QKbFI4KcIlSbt1dcO+ZzmNxmh42ZCqyP3UlGpZF2w7s=;
        fh=emq44UEXb4y9bO+XKhTjbhp0fnfBg0tvFJTi417fjHQ=;
        b=JGifIaw5y6Lyjti/9ACTXmrdNhwoDfjlVi/tjFjPA4XW+4DRT2YnheBtKkZBjz8JrU
         iI4OrihDxlOohpK535+ZMCe6KCge3VC7hMCDpGeD5lIy+Ct9R7HJ8Zlk0DI5SV0H7IhH
         wHjqtxm9JrwrHys51HjZmejJhm4zOrlZF4enXXEnoisrLXtX1GN0V7LGgjwG77ysfC46
         mRyTw0E4Skxnxx2MNpTn/ctDlEIN9Jb9CYEGaTFnmWNdID6RVyZM2Zv4dHyKMUFGSPNQ
         GPZEo7pwhxCZ4+2WWA+W6n7p2Y25EofGAqHddsVvL8q8eAgGsixH9UtsNQMY+3bhdAVz
         3rJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Se0/r0Tc";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733997984; x=1734602784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QKbFI4KcIlSbt1dcO+ZzmNxmh42ZCqyP3UlGpZF2w7s=;
        b=IfEHivsSEN8XGDKbH756UkH+JCYYk9MR0EawZAfpsFK0bPYHSZFKDGovcA5vuB4sb/
         Gbwc/+n86i8EE544tYD6pZilTbfvoD33WyCYWMpHwrQH1ICbw75hrPQ1EAU/UBJlUzI7
         9H3+AO1hV/ziB0AI2GyABDA0/1ANEPnTIicqa71DMA49V4ynbfEgtpJbxmIzoXxfxC22
         vVwK51e40HzkiUV12JGl4J0HZ+poveKAA8jnQdiHAaUtuQu2+oLjbMhpAOaX2oagifjw
         iWeEka6qVjx0IVw7Yf14XK1408N8ICHj1ZFG6RgXGHUFjumnAHHGTCioI44rl2Poq5qt
         gubw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733997984; x=1734602784;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QKbFI4KcIlSbt1dcO+ZzmNxmh42ZCqyP3UlGpZF2w7s=;
        b=i+BW4FajsrlAiQwijKyLA7/FyjEQ/wwpUuqWNSs6ne2SpTxsHmqMq5F+iNOco7Ugcz
         Tgpq/6Eb4xNU+o4hWd+Fj3G6VyYePCV0yC/2Z/lMVJDZuVn64OtL36i/l7whfOhvn+gq
         SKVayIFSKA954/YxKJkJIGqDZlVmb+I9URiDQuo8gQSS4UpiaRzF6RW2vuecjABERJB2
         BmVK4/4X9SXDGUaEQp6TpSr4QmQh3PXG5vtkbhUR1ITmAJT2HSnvWqbCKjah8fRp45bR
         iCa2f4v135hjvrN4V/AIbeoxt66dg9dN020AYZkBmFbQGefT6VUByV2tj1l0U3kFL247
         1PIQ==
X-Forwarded-Encrypted: i=2; AJvYcCX9zH4QOToJsQ5tafM1tMEHFUK97M4DsROhfvKh5BYx49NBB74OxEfuqtUF6orNFNkmN+E2BA==@lfdr.de
X-Gm-Message-State: AOJu0Yx4XNaflbEctS3wRePBrFRHnJyNxnBMtPalxvi+OhFczUE+zKl3
	oMdy/mNytCdHw79dtD88O24a6KDI/zzGSXBqw+Ilnz/vOdqhtjja
X-Google-Smtp-Source: AGHT+IGn3I5GaPXWmnmHscaxwxDExeGEHTGybjgtxTyK4MxE3pdKyAABTnIPgq2X2E1IKTYdCAm19A==
X-Received: by 2002:a05:6902:1b0d:b0:e39:8462:8bc1 with SMTP id 3f1490d57ef6-e3da26b90b7mr1899765276.51.1733997983610;
        Thu, 12 Dec 2024 02:06:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:abcb:0:b0:e35:df28:2ec9 with SMTP id 3f1490d57ef6-e3d70e5394fls234761276.2.-pod-prod-06-us;
 Thu, 12 Dec 2024 02:06:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUQ86rwP5dKo3hCqFILp7YFiwKDQYAR3IleiDudoeenaupvDjkIvTUIVoTWmJzsypWMkz/ZbSOMiWA=@googlegroups.com
X-Received: by 2002:a05:690c:886:b0:6ef:800c:6394 with SMTP id 00721157ae682-6f19e50e402mr26099487b3.37.1733997982810;
        Thu, 12 Dec 2024 02:06:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733997982; cv=none;
        d=google.com; s=arc-20240605;
        b=YDnVtTa5IllOrsD0NgY3xPN98+Ss05xgzypKKiga+wSus2yVL6iGyS7NBDpmEplO6k
         aOwELkWnIFTNWtyhxPcqmAdw5pYwSN+C/SAY2FWTpyq/3Qohl/58dGYzHsEMXGwvz7Dg
         b3gQQGBMOIVGxve9yGBxfMS9fCK6GMsDWE8yg5ceEKnUTmDgE9W9fyetP+2zxPgjc5OO
         rorLdj3WDXagn35GfeTVZaLmFS6KZaRmGBThZzp2xvT6lCWk+798aEPnaSCcgpc44Cw4
         EogyrCZEYx7FOGjNTbQdL1EgLzzHZGYNWJa8tTthqED8sHGhdaWqnMX6WPhDQdA9SIJF
         XiYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Of1BFeg2KON1xNm3jFNunekzp1UDOQsJoCnNxyLjjW4=;
        fh=KkYXUW01xRnRXl3rVVeHJIDpwxYGHRsyPmym9QvUbYQ=;
        b=F27APi8WYz5AYc6TUmRPGtiVjkZJ9AjOi5ff4SqPZ7YlSC3moXr3cNH5cwn7uCuHYj
         o+31HK1AdAOa0VXrC8ZKvSB1maKbXHIrnWjJv5FNqp8j3YFbcHAbxQqwW29znpIYTb6P
         ur8vI69mx/wmCuqRlxAzSeowsgqO2CAkqb/8GWMX6muR/V83FjNUpJcHObHt59FSM9DZ
         seQU5OZSNGsL162j9pkVkK6VLnzYNv0o+T+LUF3Zn7FOehposzbKT/fMwZuhxZgWQmv6
         08BXmB/nyrtSPxhALfP3rDpvzhoQLlnniN1PRs+Q1PzYsGPHes+UYLPT/pvt9xT3kZvv
         VvEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Se0/r0Tc";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6f14ce46cddsi1739627b3.2.2024.12.12.02.06.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2024 02:06:22 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-6d8fa32d3d6so5392176d6.2
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2024 02:06:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVmul922yqvdbu+Wm8/XKYbSJhjPG4ay4ruP8afTYvJgMjRTAmBaBvnveeKpMEq0zm53WVqSIHG3VU=@googlegroups.com
X-Gm-Gg: ASbGncthVOOmueoe9dgeQt5zY/qh9m7fWYUYstXJqvYXZDuCDNNkN2YM/f0xxGGgvjY
	HYAeqerQtHStidBQqUHLcD+6ghSoN2rgnMdbp9BUpsQvLKWVClF4cjRNxk/uSO6UodZQ=
X-Received: by 2002:a05:6214:21a6:b0:6d8:99cf:d2e3 with SMTP id
 6a1803df08f44-6dae3913ff2mr41578706d6.22.1733997982309; Thu, 12 Dec 2024
 02:06:22 -0800 (PST)
MIME-Version: 1.0
References: <20241108113455.2924361-1-elver@google.com>
In-Reply-To: <20241108113455.2924361-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Dec 2024 11:05:45 +0100
Message-ID: <CAG_fn=VyvPfJnPcXOOAeFqNakKKYzjuUdDqW5Z4rVQMgQA=AGw@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] tracing: Add task_prctl_unknown tracepoint
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Kees Cook <keescook@chromium.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>, 
	linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Se0/r0Tc";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Nov 8, 2024 at 12:35=E2=80=AFPM 'Marco Elver' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> prctl() is a complex syscall which multiplexes its functionality based
> on a large set of PR_* options. Currently we count 64 such options. The
> return value of unknown options is -EINVAL, and doesn't distinguish from
> known options that were passed invalid args that also return -EINVAL.
>
> To understand if programs are attempting to use prctl() options not yet
> available on the running kernel, provide the task_prctl_unknown
> tracepoint.
>
> Note, this tracepoint is in an unlikely cold path, and would therefore
> be suitable for continuous monitoring (e.g. via perf_event_open).
>
> While the above is likely the simplest usecase, additionally this
> tracepoint can help unlock some testing scenarios (where probing
> sys_enter or sys_exit causes undesirable performance overheads):
>
>   a. unprivileged triggering of a test module: test modules may register =
a
>      probe to be called back on task_prctl_unknown, and pick a very large
>      unknown prctl() option upon which they perform a test function for a=
n
>      unprivileged user;
>
>   b. unprivileged triggering of an eBPF program function: similar
>      as idea (a).
>
> Example trace_pipe output:
>
>   test-380     [001] .....    78.142904: task_prctl_unknown: option=3D123=
4 arg2=3D101 arg3=3D102 arg4=3D103 arg5=3D104

For what it's worth:

> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVyvPfJnPcXOOAeFqNakKKYzjuUdDqW5Z4rVQMgQA%3DAGw%40mail.gmail.com.
