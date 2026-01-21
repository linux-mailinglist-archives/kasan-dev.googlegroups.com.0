Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLEGYPFQMGQEIYVVJCI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eDedAy/DcGkNZwAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBLEGYPFQMGQEIYVVJCI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 13:14:39 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 777E45698A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 13:14:38 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-50143b67424sf173530041cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 04:14:38 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768997677; cv=pass;
        d=google.com; s=arc-20240605;
        b=fAWQAtlc0LH/KZ0ZJXqWN5Q2L0g76L753tHGIgOAysnrkhDGWRqSJpFX6v0WoS8vmZ
         14nh5hfjgJU0SMTSJiozpkMW86AiEzlba/AIS5ihc/EfbBRQ3Kzr4XmDgXj5MBCSkbES
         8rqEMvQVrKkoFxlJ6ce33SVBbKPmop4Hrx9W6CfjYYAUU72pial3JkPkhKS6i2sRSZLc
         XDdXpw4Yz2XD/V0hG9TEaKqar9cnbPlEgOo0ZnSn0NtgNZA0rpx9xy9qcJvNTMKgJkmz
         mVDWaSzlTG0/5w06w0a2FCSQ7cWCnaMW9kbOU8igwlZltPoZEMSKVjxDQuWhgvq8D4W2
         KO0A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zmF9ueOQz87AWF0COQR/x3d0M6xcV6tQST/jus+g1Fg=;
        fh=GatIwZWx9GGbKYeHVhZiCBWMo184pEisKFhEJTwU8OY=;
        b=ew+bu4yc4GLy0n6DP+nJsNUJQyQGEdJ/5nt17vfAqqPObuZW+hx6fdZMHxY+8Wb56D
         L16NwNXeAnPensP5urvll5Wc76Q2n/v3wOYKcSHNMXLM9Tk1mPfAq5yKWP3o6/behrON
         OcLQwKGwByRiAX1ARuJonziBWtpiL9lM76t+HTCDy9modsUKeVlUQ2aOjY1CTni5c6Bc
         MirvNjPHUxbEKvsDQbWx1kXcPIZGajknDQBMHVGOMGCbTnNlCB4cGZLjfagI5Ivrh0iB
         P9yVpuxRK3EB/vjpuZo+EpSePtr+6DBv9jRqVnk2XzR1vJ6UCs7YU3nVaqOgQtvgG3rt
         h/7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Zg5M718R;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768997677; x=1769602477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zmF9ueOQz87AWF0COQR/x3d0M6xcV6tQST/jus+g1Fg=;
        b=Rc03WP91G+w/5c1zyuQwP6TWCsVJ7WvdD/rX0y+PBWbpIlaBke+L2fmzYU35RSTC2c
         EyyIVuoEpd4iZTvGyH80cNdP6nDU7Ic69yt6rvQhVfBv2IMavtDvYsFD3J0HruCo/mme
         vcQaQrHQt27mFu7N5YXhdM/sXO1c5xWb6iNboiQqL4CIqMoWujyCR6bXT65C1YJrV0Ra
         v1AOfUabplP/zJfA/txI1RrR0z5oFa7omooqxNWCvVYJk0YZjsXcfrKYSBmQCzQv58py
         jnifRO2z5g/A53J1mzsBamQsNuBrlTV1CJpzvj2WHokNlAazU1NRYG5HzgJq2IT6BVVi
         eOzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768997677; x=1769602477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zmF9ueOQz87AWF0COQR/x3d0M6xcV6tQST/jus+g1Fg=;
        b=eejrCBCLPVV/yqVBjU5GDIdBGDojKakLRYjuf2hnylztim173qQsUczXIfLesK/EGR
         ZBF7JBYIEFi+unt2M8pzYqUwkCbdsTeRAXxCMN2uth0YUMf8obBqFJBV2Xyd4gcWOZNa
         N5ngACJCrK62kH5Mu7m3k72nuAGuKDbq4J0+LqFWIO5dgmohEOKTtODJt6gDI1654u98
         3RFC65lQfrI/ENNR0gvk6VsZxZ01H/wl8lASJWA0tgBQMENdtJKuT6AHMKKFA5G7x/T/
         xzAnxqixOKqAdIzF/mzrjk0xOSdalPeR3cTQUTDBIqVoBQXkFJavPEP59aIGCNs91am4
         LHSg==
X-Forwarded-Encrypted: i=3; AJvYcCWrsCBIVboChH2G5QeeU36oU/iWrPNHqXYq4/fcfdEjKGcbz3w2gO1MksivVFATUqFLd9WcFg==@lfdr.de
X-Gm-Message-State: AOJu0Yx0RjcC5KY7ChsxHlqBaQYIYZgam3qSFT3PMuc/o83GYFFzUu/Q
	gYoa7eLBXew6d1dkOTsvdyw3G+ROCJubkwPsNWcUBeKfwGeKI57hON8z
X-Received: by 2002:a05:622a:592:b0:4f1:ab28:d9f6 with SMTP id d75a77b69052e-502d84d491emr58432991cf.26.1768997676992;
        Wed, 21 Jan 2026 04:14:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GuUOgaWkVbLM7cvCSy0W23UuKAkCgH2H7myxUA3FOdrA=="
Received: by 2002:a05:622a:91:b0:4ec:f039:2eda with SMTP id
 d75a77b69052e-50214a17de4ls119556781cf.2.-pod-prod-09-us; Wed, 21 Jan 2026
 04:14:36 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUvFZsiKeRDh733nrjLiPRenD/ZajmvBAxKfbykjrFiR68w9GuQoBB2EISNru9VNDStDfkexgTYq8s=@googlegroups.com
X-Received: by 2002:a05:622a:3cf:b0:501:145f:dbf4 with SMTP id d75a77b69052e-502d8580bd6mr65680721cf.64.1768997676096;
        Wed, 21 Jan 2026 04:14:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768997676; cv=pass;
        d=google.com; s=arc-20240605;
        b=TL5CAquxp8qh0/B5fLoEUvp0K0gqyb3tYWdV1wzDHRjVX94E0SxRwbm8iOWIVc+Vjz
         3op7I98YuJeWQNbArnyVqAiG9FYoDOj5KpeOHEX3aSxhiwNTQelq0HQdt3hbKDZQdoNG
         2kZZcb/160EqarYNK+xt8sUU+QivS5o0K8ri0/T+bPggZZuj2PAPSwIHowTMGr68pC6c
         fae/hh0pX80gbxDj0FI9yjZjJTwEzdlmNdkfnib5rqn/Sfvew0K1Cqg+MXzVYmrD7fDg
         K973Q89y1wfj0LOLkivshzfdR0n3s9s54tLFXojftvqGI1O0ngktPz4f/AMZhZRIUfLD
         J/vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QT5JLW9eYEpsOmAOwnp2GUulzcXGfwSdxy/nr0y3+KI=;
        fh=SiyvjVrZRBo5QykahYcDz1Q8OtsIqRg7wTJnCV5+Gdk=;
        b=NuqrsOzmgsy9QBqAuckEQOCbhfgiEF9Pkfrvdm3Bu/LytY5acpt7ht6+N9vZmlv/kd
         S5fEwBlJZzy90WjmSROuL7EB5V6wCRLdYw7tSbxrIVmD/SvoHujJN6K1l5EOrPVhKKST
         cZ5EEC6hqC36Ce9C61izROFyzJFUZY4osxZDOTN23WLV+y0HFhDgEIaJlqmKiai2t7NA
         +D9rdSCRL9KQOuU+uOv5TkN7KXLh2kyI4TIZSLg7ULfIEcNA8HRQqQDFdX8LpQe0Sz4/
         Gv07kluiedvWH4X/hzszWX5WPIDuEir12I5rLGJZox2zTBImqWoZjglx/O9G7Cyh/7IJ
         uoqA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Zg5M718R;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dy1-x1329.google.com (mail-dy1-x1329.google.com. [2607:f8b0:4864:20::1329])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a1ea3beasi4583111cf.8.2026.01.21.04.14.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 04:14:36 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1329 as permitted sender) client-ip=2607:f8b0:4864:20::1329;
Received: by mail-dy1-x1329.google.com with SMTP id 5a478bee46e88-2b71515d8adso517710eec.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 04:14:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768997675; cv=none;
        d=google.com; s=arc-20240605;
        b=UShSkZFkbm7bC3K5PkmsRY0jcibiCKcqSYnFD1H1YEaPy3r0vHnXPYGqPEgnavILLZ
         NGvu2Up8rHqNsFwobD1A5Jt8NXxukq/s0TNocCnBRe00KuvwQugmgEOBUyJ3gLG073Zp
         hq10xP4LIEspeea+i42Dq5hTlCAOgQiZ5vMDnpjp+TbKmlf54zsRkic2GBnha1VSKJn0
         ImHnRmpSHI0pnDS52F834y6isOgDs+OWOiV8pk/nwnr+KepHfDT2hD8U8/dI1Tt/WElm
         eaiy73MFadS3p6e9kous/ApGcoev4GtBf6Jv00fZxrivkjVuSzIJntx7COizdGjf+4d+
         /YKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QT5JLW9eYEpsOmAOwnp2GUulzcXGfwSdxy/nr0y3+KI=;
        fh=SiyvjVrZRBo5QykahYcDz1Q8OtsIqRg7wTJnCV5+Gdk=;
        b=dIwVLlnLGyYAkP2xgZQ8qjVtRbIoclOrXi1h5cd7SuU23UDCFP9ijwxAN7BVcNoS9Y
         3gYYb9vlyASUkMq5XIunO015CAZrdP4kJt+gjRReJjRrzBZoEL970xBOvbM+dk7pslZ5
         xeHS4z0AnooYyIc+Ke4wO4LTA9RjVy2HWkerIGCL1qNzNEM6STmmPE2VzuLXOyRFDHW0
         fGmQ4dbN7Anodt5NnE28nKIlZ4zOCDAODlkwVQVcstP2WGjQrfCjiMKtm6QpfmXLhfJH
         Xb5H7cbopDA8XOO5y40eISVw+zw5hUUPn5HgU7ICUn8tYP/vDrseAhR96uMXTXIfxDAP
         yx2g==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXFB51ooUwqQkkdihM/5N2za/7Y97Fr+hda6lG82znXQ5vJpVXZVn5S/ojXoNif/12YUCK9ej3rcyQ=@googlegroups.com
X-Gm-Gg: AZuq6aKuM0DNQUfFwj2zKxLSGobDBRVIrTrcNSAgjDg8KZT7rTrkUYm6eu811jQ4/vj
	fvM7t8MO1r0JnT7myWmsiGU5bGqM8DjRRlfybfYhChctywFsdvvh81U7XfPqsmgSLoPhK4phRsy
	2hr7QLvrhE8JDtfKjIieXTcaXerTavdOSDHHc+CKklGIipmZKFVKN+E8viUhUXOT8WdZx35S9+U
	tGQfls7+3+K72oDA+OymsjomjorZQs0c+gwMr/Jxg7KVcwTlL0lFd/RCdwzkdrqbvnc0Ng6hgg4
	ExVV25OPIQ1cKU35+UNA4E1d7A==
X-Received: by 2002:a05:7300:ad06:b0:2ab:ca55:89b1 with SMTP id
 5a478bee46e88-2b6fd7bdf89mr2710322eec.40.1768997674493; Wed, 21 Jan 2026
 04:14:34 -0800 (PST)
MIME-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com> <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
 <CANpmjNN=ug+TqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A@mail.gmail.com> <aW_rHVoiMm4ev0e8@tardis-2.local>
In-Reply-To: <aW_rHVoiMm4ev0e8@tardis-2.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 13:13:57 +0100
X-Gm-Features: AZwV_QiNdZftFkEU8_aSSpgL9dCXraNCslVH2OipOEvIiJlDSmBop19Ul7_z1dM
Message-ID: <CANpmjNNpb7FE8usAhyZXxrVSTL8J00M4QyPUhKLmPNKfzqg=Ww@mail.gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers over
 raw pointers
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	Miguel Ojeda <ojeda@kernel.org>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <lossin@kernel.org>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, Elle Rhumsaa <elle@weathered-steel.dev>, 
	"Paul E. McKenney" <paulmck@kernel.org>, FUJITA Tomonori <fujita.tomonori@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Zg5M718R;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBLEGYPFQMGQEIYVVJCI];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[19];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	HAS_REPLYTO(0.00)[elver@google.com];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[garyguo.net,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,google.com,umich.edu,weathered-steel.dev,gmail.com];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 777E45698A
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, 20 Jan 2026 at 23:29, Boqun Feng <boqun.feng@gmail.com> wrote:
[..]
> > > > READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
> > > > like memory_order_consume than it is memory_order_relaxed. This has, to
> > > > the best of my knowledge, not changed; otherwise lots of kernel code
> > > > would be broken.
>
> Our C's atomic_long_read() is the same, that is it's like
> memory_order_consume instead memory_order_relaxed.

I see; so it's Rust's Atomic::load(Relaxed) -> atomic_read() ->
READ_ONCE (for most architectures).

> > > On the Rust-side documentation we mentioned that `Relaxed` always preserve
> > > dependency ordering, so yes, it is closer to `consume` in the C11 model.
> >
> > Alright, I missed this.
> > Is this actually enforced, or like the C side's use of "volatile",
> > relies on luck?
> >
>
> I wouldn't call it luck ;-) but we rely on the same thing that C has:
> implementing by using READ_ONCE().

It's the age-old problem of wanting dependently-ordered atomics, but
no compiler actually providing that. Implementing that via "volatile"
is unsound, and always has been. But that's nothing new.

[...]
> > > I think this is a longstanding debate on whether we should actually depend on
> > > dependency ordering or just upgrade everything needs it to acquire. But this
> > > isn't really specific to Rust, and whatever is decided is global to the full
> > > LKMM.
> >
> > Indeed, but the implementation on the C vs. Rust side differ
> > substantially, so assuming it'll work on the Rust side just because
> > "volatile" works more or less on the C side is a leap I wouldn't want
> > to take in my codebase.
> >
>
> Which part of the implementation is different between C and Rust? We
> implement all Relaxed atomics in Rust the same way as C: using C's
> READ_ONCE() and WRITE_ONCE().

I should clarify: Even if the source of the load is "volatile"
(through atomic_read() FFI) and carries through to Rust code, the
compilers, despite sharing LLVM as the code generator, are different
enough that making the assumption just because it works on the C side,
it'll also work on the Rust side, appears to be a stretch for me. Gary
claimed that Rust is more conservative -- in the absence of any
guarantees, being able to quantify the problem would be nice though.

[..]
> > However, given "Relaxed" for the Rust side is already defined to
> > "carry dependencies" then in isolation my original comment is moot and
> > does not apply to this particular patch. At face value the promised
> > semantics are ok, but the implementation (just like "volatile" for C)
> > probably are not. But that appears to be beyond this patch, so feel
>
> Implementation-wise, READ_ONCE() is used the same as C for
> atomic_read(), so Rust and C are on the same boat.

That's fair enough.

Longer term, I understand the need for claiming "it's all fine", but
IMHO none of this is fine until compilers (both for C and Rust)
promise the semantics that the LKMM wants. Nothing new per-se, the
only new thing here that makes me anxious is that we do not understand
the real impact of this lack of guarantee on Linux Rust code (the C
side remains unclear, too, but has a lot more flight miles). Perhaps
the work originally investigating broken dependency ordering in Clang,
could be used to do a study on Rust in the kernel, too.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNpb7FE8usAhyZXxrVSTL8J00M4QyPUhKLmPNKfzqg%3DWw%40mail.gmail.com.
