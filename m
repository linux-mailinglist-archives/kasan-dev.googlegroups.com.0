Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6W3QPFQMGQE5RFISHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BEADD0928B
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 13:01:07 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-7c75663feaesf7976876a34.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 04:01:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767960060; cv=pass;
        d=google.com; s=arc-20240605;
        b=ScOa3+P1EWpfO3g8kS9wiHHrKJI15Bz3k6zsKGGA2J4fy5PhyVD+zp/FLHIyPmCmOR
         JKmqi7ClBoQgHiw2EWUWDEn0RiDWbaF4PSoj/wb6WyElmdT+W3hRHUjsfhOYKL5NQ/xx
         v/xIXoopnasPEZTIWnXp4cBy7lHuKsHktVy9t3UIn7855E6e0TM7QnA7pYL+NOLLhxA/
         Fgy0dukVEnohTR4JccW+hbXaclD4orpAX+jkeQTA9Gevbx9Dti3tdRJNa3MLRkp3uqUT
         85avErIBhna6itZSEMkwyetRZU6zAdhsFnARPB2T83s2SkUKb9Rh/9hPtdvNUOqBKakT
         mpDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d4ewFRaymQAp1bFkgtW432bvsupxADecn9qyRvgXXFM=;
        fh=6a8dK7OMjTdeZceh57IDajmy1YAUZghLrhT6dxlQRjE=;
        b=CELCNUdGa6X2xMtaYpcn6VRbBGXZ4DHEMrgUJYR6+q2NpBCB7KaqUiajBqqB16wzDZ
         58P8Kcx265UdIX/2Tclv6eW8ZUsZT/kM99XyHf5UbKPzQOC/Z129oEwc96H53KxMRH5J
         sIJTmREWcHe5Ism2V3TWEHJhAXGNy/q59aid2kajMW3zDmGX+nyu1UBmmlX167D7xZPk
         Q5Ni7Y2HwO+tuqmaJs0e5Swjeg6ihu4QBWrpGMcDSUNTVffFhlAVWkSdsFPd9E7ZADbc
         OFR1KNJX7RsRoi3PNYG5iwq8PrH0VsXPzkMT7LnS4a4+4eW7qCz0Ik0/MYRZUSvPMTim
         GgtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="pgM/vbI2";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767960060; x=1768564860; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d4ewFRaymQAp1bFkgtW432bvsupxADecn9qyRvgXXFM=;
        b=nVlgLvKGr4reUgAUDlt+5VcxuHdfXZn/O8fbLJRXJ8RtEnc6orteQI6npQzjXsvh97
         u7lCewdTnCcMSvL7BAgu4F0uhbEFCjs9uOSEfHtomUrmqxhUKIXynMkmmLP4hc5ByJSH
         6/Ya+1l+rf3qixkmMRhuArCYpTFq5j+qF2/Zg3CBGpkdDF1w2ucyIi/vR17PhqrtIf5g
         aNp2CtsyZxsn/cySqsKO0mt3eAWDPMJgo+weoKn6nHBF2gplG2LZQ2Xbnfvb2qWa/U+c
         DJsfHMuxcF5wSARhgTk6jkeVrsNTqBXfTqlR1jDBzdIQD+T4oLfbO9gBqkwyItSpHbzp
         KEIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767960060; x=1768564860;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d4ewFRaymQAp1bFkgtW432bvsupxADecn9qyRvgXXFM=;
        b=Qvaa9rBMN13Arw32F4V8aGbmgYy5B+w9NicZxDJ0D4fu32+pCtpirI3FYg3mTTyFGp
         JjONK6puMgmOiXtGpn8XXIHA/T1RSDFYgvFCdC78urIbrYuBFArBi5suslbcHMaouKZD
         VanCWZ+nCWToZf1LYfdf50bhsQ/ydyUaHC+EksgG4dLuLc9WTJk8YfSLadvPOiZNFE2n
         g9X9nUNmNGcoAL130NFuNTYnwZdgaSdK9IVkxL/5yL7FsXv40lP4DyExsgRrnMX9NGYp
         u8mV6KB0vBso7iez7kZbDivW0LqtHn4F1VvOnOFxm7EmwfH9crZzZM4Bjr/31alVnYaX
         GAXg==
X-Forwarded-Encrypted: i=2; AJvYcCX5BFAKLDIJ2ZPDRvyiECatFnoy2/nRJYe1gW2clAuJnTffCAAau8d4JYN9+Sy6CW3WgyQ8pQ==@lfdr.de
X-Gm-Message-State: AOJu0YyzwLwQKuRpT20Cbi8Vg7gMG3AKFUpOhE87lm6LMzExnCeI3llH
	QUIJh9IIK6j7Vf1G0q6Thx+Y2LkbxkW+YT67DlLBppez1XAMFe8th1H9
X-Google-Smtp-Source: AGHT+IGMFZw8ZVzou/Y2YjjVR53doAM9G6L8DEjndiPq+dzJtGbqV1I9ac/aAznok6KpzCOXtHtW4w==
X-Received: by 2002:a05:6820:62a:b0:65f:6bcd:e32 with SMTP id 006d021491bc7-65f6bcd126emr402488eaf.58.1767960059004;
        Fri, 09 Jan 2026 04:00:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWblwspKJ/OKFaJ+mCQwI1eKELCjbGpgPwFhaTomRgJOFA=="
Received: by 2002:a05:6820:6ad3:b0:656:cea8:d380 with SMTP id
 006d021491bc7-65f472d1131ls1446202eaf.0.-pod-prod-02-us; Fri, 09 Jan 2026
 04:00:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUIONffIvV8eroUGXxsWRIT5CjfXwZk7DNmauMBkpKYHOI7JuUOH9dgmg0+AGZx8Wxv2Eefj1QOvU4=@googlegroups.com
X-Received: by 2002:a05:6830:1cc2:b0:7c7:8280:9207 with SMTP id 46e09a7af769-7ce50c106a8mr6893561a34.37.1767960057747;
        Fri, 09 Jan 2026 04:00:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767960057; cv=none;
        d=google.com; s=arc-20240605;
        b=Zem9YZKTltGPU//SiUTWTgT+FOGzTFhF4vSXrVMgvH50u7DBeEFELowim9IWj0Vgn/
         geIbNo8PrFbi/csRxz8d3cQdLBqUf/upzK1wklvs4p72VcEAykp7eqtZkF91NDUNZrF7
         asQePG8TzM0c8Q7b8Giqjwrvwun+SsLxOg6KCDhD31iRdndy7L8E1ISc4wXQ02+UTSye
         oUuZNcCjzeTex21bumG26vfz8BWKD4nfAgPPVcXXnZzLkKzGwtfMEbbOZtsGxAdva0v6
         FI76qYpe0DvwZnZg3SObee1kBDlQOe9/0TNJeWHueQ0a/pDoq3Ysss+ayFjQbEIyCpSN
         WIIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8T/N0YjJdMPLkCw5fXXL5pxg8eGLGcQ3fujG7tmwcHw=;
        fh=HAQMMmJrMkpg5j25I+o0TN0lVgmU6CAuF1ela/q0ZJQ=;
        b=gAhy8eIH7OVh9Pes6CBnjr6MTLBRlmLPT0L28qTLjKVZLQR/l4eqRiL1xGHzU0WTyE
         Zj1Yzpb47eKNElJp5cjCV5qQypz6rmiAyhuR5u/+DDLYUQndOCQUKiEuR1kPZCs1LQZt
         uwp8YA+PjhbrfOZXW4Po8X4GNG4c7YSoNTxLGUQTE5JSEiZJbLtQWKcruSRQGcRPniyn
         3eAGB3PLaOm7OWHSQXA3YI9Rld9elIhPD8RgAiK5daSKuxj8YXpCRDZrZmkprcZyFkpH
         isQAL3lKvIO0eZ27KJiytbzWwxHAggKgNHrKzx4FVeipx8Yg7KmNQs8obAXrMuitPFlp
         OZyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="pgM/vbI2";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1230.google.com (mail-dl1-x1230.google.com. [2607:f8b0:4864:20::1230])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7ce48164d23si495586a34.2.2026.01.09.04.00.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Jan 2026 04:00:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) client-ip=2607:f8b0:4864:20::1230;
Received: by mail-dl1-x1230.google.com with SMTP id a92af1059eb24-11f42e97340so346837c88.0
        for <kasan-dev@googlegroups.com>; Fri, 09 Jan 2026 04:00:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWvtI79MF2L2YDHBBQSNZA2Nns3Bldq/I08zgUAzPM4UL5DPkxzUNH+6qPYXwynMMTbOJbqojzqSkg=@googlegroups.com
X-Gm-Gg: AY/fxX7DN8FgonScgKgxK10m3mxPLHcsRijxxnf8IkheXHFJYS6jik93xXx6QV9Lj7C
	kfQpws5zPuwnf5aa7USHTKlrZ7e4X2lmvMmgK6Uwg9fwRGbAVzJu/a7/KcwHu6X4t9r8fEFtU4l
	/wkkgdymNMYIyUkfbyGvErRNa4v70lRzvXAa9G/gVrINw71ARkmJfxTM8429XF0/RLE5ct98R/6
	1VmGzMaRku6aZBE/+FwcZjqGblq+gbRY2HlWTrE1lrAoMlmrzIPtlce6cJl1a2mWhIs+8j21aP6
	TPF4xaIS5AmAy4RlTWQpKbHRjMU=
X-Received: by 2002:a05:7022:4199:b0:11b:ca88:c4f7 with SMTP id
 a92af1059eb24-121f8b67cc0mr8303949c88.40.1767960054556; Fri, 09 Jan 2026
 04:00:54 -0800 (PST)
MIME-Version: 1.0
References: <20251231-rwonce-v1-0-702a10b85278@google.com> <20251231151216.23446b64.gary@garyguo.net>
 <aVXFk0L-FegoVJpC@google.com> <OFUIwAYmy6idQxDq-A3A_s2zDlhfKE9JmkSgcK40K8okU1OE_noL1rN6nUZD03AX6ixo4Xgfhi5C4XLl5RJlfA==@protonmail.internalid>
 <aVXKP8vQ6uAxtazT@tardis-2.local> <87fr8ij4le.fsf@t14s.mail-host-address-is-not-set>
 <aV0JkZdrZn97-d7d@tardis-2.local> <20260106145622.GB3707837@noisy.programming.kicks-ass.net>
 <7fa2c07e-acf9-4f9a-b056-4d4254ea61e5@paulmck-laptop> <CANpmjNPdnuCNTfo=q5VPxAfdvpeAt8DhesQu0jy+9ZpH3DcUnQ@mail.gmail.com>
 <b0f3b2a6-e69c-4718-9f05-607b8c02d745@paulmck-laptop>
In-Reply-To: <b0f3b2a6-e69c-4718-9f05-607b8c02d745@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 Jan 2026 13:00:00 +0100
X-Gm-Features: AQt7F2pBr33IaeEZzEbVtkwEGkq72MjCI-S9aarJ4oQjqFT6bTaIuZHUMWVHI0k
Message-ID: <CANpmjNNSCNm+A=nKdeSDAkcgiKXMEdcQUeMb4PZxWoP2t-z=3A@mail.gmail.com>
Subject: Re: [PATCH 0/5] Add READ_ONCE and WRITE_ONCE to Rust
To: paulmck@kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Andreas Hindborg <a.hindborg@kernel.org>, Alice Ryhl <aliceryhl@google.com>, 
	Gary Guo <gary@garyguo.net>, Will Deacon <will@kernel.org>, 
	Richard Henderson <richard.henderson@linaro.org>, Matt Turner <mattst88@gmail.com>, 
	Magnus Lindholm <linmag7@gmail.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Miguel Ojeda <ojeda@kernel.org>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <lossin@kernel.org>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	FUJITA Tomonori <fujita.tomonori@gmail.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Lyude Paul <lyude@redhat.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Anna-Maria Behnsen <anna-maria@linutronix.de>, John Stultz <jstultz@google.com>, 
	Stephen Boyd <sboyd@kernel.org>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-alpha@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="pgM/vbI2";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 9 Jan 2026 at 03:09, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Tue, Jan 06, 2026 at 08:28:41PM +0100, Marco Elver wrote:
> > On Tue, 6 Jan 2026 at 19:18, 'Paul E. McKenney' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > > On Tue, Jan 06, 2026 at 03:56:22PM +0100, Peter Zijlstra wrote:
> > > > On Tue, Jan 06, 2026 at 09:09:37PM +0800, Boqun Feng wrote:
> > > >
> > > > > Some C code believes a plain write to a properly aligned location is
> > > > > atomic (see KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, and no, this doesn't mean
> > > > > it's recommended to assume such), and I guess that's the case for
> > > > > hrtimer, if it's not much a trouble you can replace the plain write with
> > > > > WRITE_ONCE() on C side ;-)
> > > >
> > > > GCC used to provide this guarantee, some of the older code was written
> > > > on that. GCC no longer provides that guarantee (there are known cases
> > > > where it breaks and all that) and newer code should not rely on this.
> > > >
> > > > All such places *SHOULD* be updated to use READ_ONCE/WRITE_ONCE.
> > >
> > > Agreed!
> > >
> > > In that vein, any objections to the patch shown below?
> >
> > I'd be in favor, as that's what we did in the very initial version of
> > KCSAN (we started strict and then loosened things up).
> >
> > However, the fallout will be even more perceived "noise", despite
> > being legitimate data races. These config knobs were added after much
> > discussion in 2019/2020, somewhere around this discussion (I think
> > that's the one that spawned KCSAN_REPORT_VALUE_CHANGE_ONLY, can't find
> > the source for KCSAN_ASSUME_PLAIN_WRITES_ATOMIC):
> > https://lore.kernel.org/all/CAHk-=wgu-QXU83ai4XBnh7JJUo2NBW41XhLWf=7wrydR4=ZP0g@mail.gmail.com/
>
> Fair point!
>
> > While the situation has gotten better since 2020, we still have latent
> > data races that need some thought (given papering over things blindly
> > with *ONCE is not right either). My recommendation these days is to
> > just set CONFIG_KCSAN_STRICT=y for those who care (although I'd wish
> > everyone cared the same amount :-)).
> >
> > Should you feel the below change is appropriate for 2026, feel free to
> > carry it (consider this my Ack).
> >
> > However, I wasn't thinking of tightening the screws until the current
> > set of known data races has gotten to a manageable amount (say below
> > 50)
> > https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce
> > Then again, on syzbot the config can remain unchanged.
>
> Is there an easy way to map from a report to the SHA-1 that the
> corresponding test ran against?  Probably me being blind, but I am not
> seeing it.  Though I do very much like the symbolic names in those
> stack traces!

When viewing a report page, at the bottom in the "Crashes" table it's
in the "Commit" column.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNSCNm%2BA%3DnKdeSDAkcgiKXMEdcQUeMb4PZxWoP2t-z%3D3A%40mail.gmail.com.
