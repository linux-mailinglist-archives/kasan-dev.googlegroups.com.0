Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKMDTD7AKGQEYGWIOBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 38FF92C99B7
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 09:41:15 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id g2sf829785ilb.23
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 00:41:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606812074; cv=pass;
        d=google.com; s=arc-20160816;
        b=kZgX4b69SCeu2YEf2HI+rpBuifpMm1ly201Im2Cq82QL4Yxu8UGaSszC0WU8s6/D0v
         +UD3vKusoJ8elQu4yus51kzQNYBkY3jM7JO4D6TgbZyZFTwsBtUeT4nOrHRfexsfstJn
         q39n4CtFzWdxGMQUWORSf8WSw8FrPy1Z7lmHhjSxE1GKanSiL5NVM+8/qhpZ/s6CQhN5
         5v3mn56ahtjG+tPXLd7fr4yRKOn9TiqQ4zurBv+jf1UlIiK45uMOEtlYWMO1XttKUllo
         Fo6gWZEp8McHr/jeaqEYVpUocCiWo8zt1hc/f3r0Nttxk4Xg3z8vf73xvreLPjTIQ5gU
         4R2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lTAbdLtnKk7tIH6q1+vlFw4cxDB1I4qEAx2gbNmBl7s=;
        b=0NATayIR/4h7jiPk458+8Xs6cBM49ModiABBjkWUa4VwXiHec/hZdgv6fbp+KYpcdz
         fg5WpIoXcRPDvonVTWYkzH1B3ugeTCMYBYCjHh1sM/iaf0/aP2j8evr+SeqMGGgMP4dq
         gHQ/i+AJDxI617rHoPu/u60FWSOne/PbIJL4BCSVdWJX8XVIIFaJ454AQGXS4U77F1i7
         y2YY0xUNtVBZ5EYiURpsPsl9AdEZxevTdVH0ZlTDqI8OTCHxlKiMxL6L/lV8az7zyZTd
         NtEU31UJ/4oBm0b6WDVsHftmTJDHXJAG0zNlcHPrkYNWio5q/xootJqgU4jD4RQi9Dmk
         Wkeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ENWN14cw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lTAbdLtnKk7tIH6q1+vlFw4cxDB1I4qEAx2gbNmBl7s=;
        b=QgXkn1PH9xd3dNhWEJZgQUJsDYcJ2v874TdQ3+BXAtzK1MpMeJKExJ9GUN1N6eduRJ
         /eAQbfNyhs4VsJvvYy40N2ATlfH5Pd6Dy5roSzGmxulu5bI/4iB1B7sMx79J7fH+2ypW
         KJZCyazi8EEHLEllLiV8j9Y0TdBXiFMWnQAPbvxScb+Gq1ipnXhUWnI3DlCHlCoFNNqI
         Uf7v/pBguYcSm8/JIwk6z9lfWwoy5n/igiwCWRPpzgGCBN17P8tuG5Uy8M6B9pYEFVvo
         WaiF4wUPjUKd9ELzP/I35IDC+NwXXLEIz4XYiXKr//9i2nvV0iZltosTunhahYOfo9W5
         ENrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lTAbdLtnKk7tIH6q1+vlFw4cxDB1I4qEAx2gbNmBl7s=;
        b=YuJb4T4YiwEn4FN2OdYivBXb1PNGco+SEKSTS0kOW2RjSpGI4+ODNyseJn+CVxlpqS
         iJPoiELUN2ZfANF+DvONcEiBKEp2KWZIILyE9DOcp70p4OlR0Hd/8h/dvCyPiGW/f037
         /JwtCJTgPBFn2Y57IE/0Df9M/YlgLMxI145RJ4gxJeOteWGPfjxo0xvn+9EPxiWD+W7a
         3ZyRq1skYqV3BtNymXp8tvWRFR4gzEvnTdpOaP5uoHlLzU87fYlkX2vztWGUhB+eVCqA
         n10NHz20+e0ubU2HhNKbdGReWXunQWVaqfNzLPzEOCe74szcdClhVUycagjno4VLGyHu
         IZLQ==
X-Gm-Message-State: AOAM531E0WI8nxAE1hFBfTWJc+xq+OG7BJ9pWk9EtCtu9S9CU+zfMKWQ
	280KQvesWsRDoFnQEy6kgeY=
X-Google-Smtp-Source: ABdhPJzcb4IhPN5liM2FVdHWCYYZDGvPHyztnaKwWhN1Xf+tPk7uO38o02DJSssQDVH6YPiWhrbMsw==
X-Received: by 2002:a5d:85c7:: with SMTP id e7mr1539285ios.162.1606812074089;
        Tue, 01 Dec 2020 00:41:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a41:: with SMTP id 62ls153746jaw.1.gmail; Tue, 01 Dec
 2020 00:41:13 -0800 (PST)
X-Received: by 2002:a05:6638:603:: with SMTP id g3mr1717711jar.128.1606812073719;
        Tue, 01 Dec 2020 00:41:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606812073; cv=none;
        d=google.com; s=arc-20160816;
        b=lXtEAjEiGUPO14sqVpLVz5NcGUfRvQcIj75tuIhZCLBvv89LB7KUnDnG/doiiNkgpc
         CIAmwEuWt1kq+wkdQcGuUlQuPEc0aE9P9BAbXzfoLA1KuDCm16B9PHUg5Xo4VSqtx/gw
         dCV25zEQvzJVDe68/jgmQKAlaqnrtugTfpvLfOa991PFRZ9tqXjP7dr1CvyCKe9u5iOE
         /gCqpHjTcGoWaaaPChbti4Rqx2kicRb+N6VTV/T6V7ngioK3Z2V4v681M3N0oGMdGevn
         eKcWiMbHwvNCLdTuCpBMYDcPjeGgmQGTIfG7f/Jc102ajdLAZ5bW7V37g9FIbeKH8m/b
         elvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/ImR5mFtg9wXtOK4HaxnOpZ6Mas0agGqVuxRp77OqsA=;
        b=UIx7Bw2CUZA46MpS8tbHSq76Sc3eeTl3oyr/7+jK51kOc47RO6mU1yIR8dTkY6ASbW
         MCppY4ajBmlpEUjErWuoBwuAusNtoVH1meWub1FnUaVAPoRuBJEf6bhc3R7KOTXDeb46
         CVnbDy4W6+A9u6wiTxIQcGFz5zVnV7puzWaG8NaJ4VplxpCk1V+FRBt0415a221zd9de
         4aT96EjL9M08pYu2zllDCazqf3yldVyOeW8iMXVRVPPblogMWQvJRWCuUIm9AFZH+Blu
         2sr0hnSUXJ5F+A74T53gRQHBqAlCQOJqn2FOPpPrZ5g2809N+9k9ntUoLgDWXEQhaefd
         T8qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ENWN14cw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id a2si78693ild.4.2020.12.01.00.41.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 00:41:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id x15so925309otp.4
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 00:41:13 -0800 (PST)
X-Received: by 2002:a9d:7d92:: with SMTP id j18mr1142495otn.17.1606812073263;
 Tue, 01 Dec 2020 00:41:13 -0800 (PST)
MIME-Version: 1.0
References: <20201124110210.495616-1-elver@google.com>
In-Reply-To: <20201124110210.495616-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Dec 2020 09:41:01 +0100
Message-ID: <CANpmjNNKgKAxHVdxC9LWpwrxRREU7JdMTeDiCU7hzMG=Oh9QcA@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kcsan: Rewrite kcsan_prandom_u32_max() without prandom_u32_state()
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ENWN14cw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

Hi Paul,

On Tue, 24 Nov 2020 at 12:02, Marco Elver <elver@google.com> wrote:
> Rewrite kcsan_prandom_u32_max() to not depend on code that might be
> instrumented, removing any dependency on lib/random32.c. The rewrite
> implements a simple linear congruential generator, that is sufficient
> for our purposes (for udelay() and skip_watch counter randomness).
>
[...]

It's been about 7 days -- feel free to pick up this series (unless
there are new comments).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNKgKAxHVdxC9LWpwrxRREU7JdMTeDiCU7hzMG%3DOh9QcA%40mail.gmail.com.
