Return-Path: <kasan-dev+bncBDRZHGH43YJRBO5GQ3BQMGQEKSKAU6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C8AFAED01C
	for <lists+kasan-dev@lfdr.de>; Sun, 29 Jun 2025 21:25:50 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e72ecef490dsf5042828276.0
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Jun 2025 12:25:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751225148; cv=pass;
        d=google.com; s=arc-20240605;
        b=IXp3k56jQ5ygXO7yeo9J05+HM2NLjB0UQRq379LFtH2dGAalxFYKSARV4Lvmlo7bym
         +PdzFfb2fhCJWVTvP4Ch5zK8qW8g+sXHFFCbU1YlcVfa0Z0SzGvf/XO9JegnEjNc/wXX
         B9vU/uz07Lb7PqB52ZMFhEH04iDJ/PEiQnuOqfwlw/Unt791GMRvm0i3tyxcKVv7yyQH
         tNKMb0lQwul9UpsA2E2qITuoyrel3lY/h9HTWOaMpNCO3mhMLJY0foEDs62gHCXR+qkb
         rAowaTa8kzESPSZocZnd4wZN+XMhKlxfJrER/oUiwH/XmhNVxEJzJ+YuRrT9SmusjlmE
         Fjow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=F5Yz4i2nYGHcxXXDxYuKkEOYa/Llo4ukedBCCS/hwOU=;
        fh=NV577S/7BGJL8pRIwjI7txr4YXXFPW2rczKMZGOx8vs=;
        b=DRdnCP0Lrq7O1vzZ2jrYe1gKvK5WCBuF+DnEdDUxjiicfQPc+kitKaigNND+BwrAus
         D8ldu3fbvNASf4QM+ObsgiDcAJluS1ik4ifhBwKAxfy3+DuQ+n4YIF15PNwP7UkLQ+md
         SH7udL8qO9EqAz0paEh9vYwFM7yI9+CQa3kPUrOqAfggPP8g7aZGrSwQKUnCkJJg8aLq
         cjtoU4KK1XqcN/7PwoKRwXx4wh3g0Hwu8DNK38qk+AzSOJzz7MuWz350xBG8dbpua95S
         lkHLCQguyzOWsBX4STq00Qvt7Kz72Y/3iRoZ9jUmMnSygC4HFVwO+Es6AwjhTh863GTM
         APAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aFqvbUG+;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751225148; x=1751829948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=F5Yz4i2nYGHcxXXDxYuKkEOYa/Llo4ukedBCCS/hwOU=;
        b=sR+a18khs2vOaQM8KCEoi+T8nkTlw2gmJUP93q8mQxO+V2CCf9Pb0on3RHihcvBScn
         TCng02f76C2Jxz94fewx/vswlx+UJcfTLcPcsmZyWcp8hVOUBSHDyPU30N/hZnanFSA4
         hKZbsibMD49/b9RsWbqDPT1YFb6bDHwy9PVuqMHflRya5aWcEQ3Qzs9/PkBfkipJcQcq
         UOziQ7DKOJv/iaF9bpMQ9vZ9EUWqbGWe58tZyLKsKFPSGDVxiUgFEtI5B4JZSYV9t2jQ
         HLwhq0WZh1uLiMTxbgredX1fOalVyYiYJNE4Q2HeZ+LgaAcxwna+Ph3hMBxvLxYl3MJn
         98Fw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751225148; x=1751829948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=F5Yz4i2nYGHcxXXDxYuKkEOYa/Llo4ukedBCCS/hwOU=;
        b=ZmQuxBHS+EmAjqk74T6H+BcqKL6B+i2AtiIuilTNVjFZIkOuSyFlnoIUAwFsqPVfc8
         X3x+4GoSab7SyaSQjRXKAzd27ZyJ72je8YIV/ys9fJSfYv56rzOQMZcVeDOuL6sYTIvA
         TIDiddkQsOeTx7ozd4A1PKBM6EaA6gG68KtzQNJV4sxhTcpg/OJDhSkU5NjP6CoT06D+
         zhBRWRCcaQzX7XAGnHRhY9SwHx4GEXd9aXxjNwLrNhpHUHBhjvRcdN5cSlrEfJ5vGxy2
         JAMZSEnKwHRW6DQHcfJ5jsmITKs8gU9w8nulUkAv09CaApgWTFJX2ivUpYp8P6pHPilX
         oLwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751225148; x=1751829948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=F5Yz4i2nYGHcxXXDxYuKkEOYa/Llo4ukedBCCS/hwOU=;
        b=NGO39c0U7YLINXNPt5pZqsvDcpTQ17tEUsyrtGg76aBf1K4wih4F/SO1oBNU2rHB/D
         r+9hCuVzpWaBke82pk6iSLA/JEL1kqfGqjCcNlGGLz1rOJFRE83ZrYciXYzNL4Pfwvw2
         Fe7/1ITxe6VGN8HDGGf5eRPfBw8i8nCKSovucx2lijewcOC0kV5yOrUrE8aQ4JqpUfQH
         aZS99C2rtip593qc+luBIbM3dgwpCsZYc6B52pkfc9hMKtMCt/fihKjQujGMJAS6m0ET
         OwVDoUk142VvtmJtW2jYEYpVYwPEzTZWtXoLZfSnC7rFFrh2sd5gxxeRDOviYViGO9cE
         VEMQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZjBOdFYtMX6jVs+JyepXii9MclPh+rG3/kCGbGoGN47uOCURZc1+vC2lGRyeplXHhCZ6cQg==@lfdr.de
X-Gm-Message-State: AOJu0Yw3OhtNCWrbvRg6z9O1bhZ2L5Wt/7OgMfcTfWIErRP6rCWUwsh6
	w7vIgsv5K0MY2/uhBGAM4BMjNweai64a4O09t0IKIv6wc5lOb3mIOmq6
X-Google-Smtp-Source: AGHT+IHkmkApSIWVKCR5espRkMWoIKrNqnLYSBe0J2N+RCBvsV9lT2P8lA+ikpS5Oq/PnTPskL7JRw==
X-Received: by 2002:a05:6902:230d:b0:e81:cab6:6db5 with SMTP id 3f1490d57ef6-e87a7ad1bf8mr11484587276.8.1751225148431;
        Sun, 29 Jun 2025 12:25:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZebNXIhR+EFl+yZz9TtbBS0WoKG2St23WK8+2/d97yLkw==
Received: by 2002:a25:d081:0:b0:e87:adad:c527 with SMTP id 3f1490d57ef6-e87adadc65als1964569276.1.-pod-prod-04-us;
 Sun, 29 Jun 2025 12:25:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyqU5PtR9y/iWdk4d98s5Pqnr0aH0PQL4ulTT1+M+uLIXEAgUSDnToVMuEV4bTIlPQXVEoFCYoLG4=@googlegroups.com
X-Received: by 2002:a05:6902:20c1:b0:e85:1e91:562c with SMTP id 3f1490d57ef6-e87a7ae8fa6mr14352747276.14.1751225147178;
        Sun, 29 Jun 2025 12:25:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751225147; cv=none;
        d=google.com; s=arc-20240605;
        b=X3RgNxKCra7YlEfPGSIHhZ1odGL14jfXx1iQ5A43HFkhtugVZWBtXgV2Lnx6lpNm6u
         RESn0kzRXe9ISy18yS6aQP6paZUMajqAd5FpzI6K7L/wtGMmMtdRiPwux53XJhNevZ8r
         TyvBJTEhfqOyyMT9e4DIzv/GEwffsUsb6a20X39ArIwFsBHvb9OkESAmevfuI1CcocaQ
         rFSAqxDkbFhbnb+CA1Uo3EYVgodpekWHMzfzRm936eH8VDBiHZOra9U5jjgpaCYdYaE1
         T2fDAQlLuOnkdJeULDmr8hOIHsJ5yZotEPt098EczDi0AtM0O9otTR0WYSVSC0pPZdmB
         xOQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=y20xUJwqc+Vl97NT8HBTLKHOwEwVH/qR2d88daEIqMI=;
        fh=o7CbVF83yai8j2hr6hbnuEUACu4R9EV0PNnppDF61n4=;
        b=Cv0ZeZIQVJp0+nf0OesS11/Q+3BWcUUYcnL/Is5DpVO7fNr3LoAJ+JVgb5j8rb/9ly
         yv8ymbVXlT2k/8WyML5siGKEjv6vHaayolZ1YpEHldzTWmg1LvqxZFE/x7EpU2TeTcf2
         bTAaJbnRpwtL3mfohYzYcnov+zTuYBl1m3EIvkkCOVujlvynLROTaryRSvOOfly+eZgd
         7NMzKlwJiy1tBfoTms6Go2D6fRCPd6LprZhHTEeUa3ytXyu/3ZsqSBPBv5naka7kNNhe
         U1yF1XAKXD8Jh6uj4741GR6IP4WVhwmRYa7XHXTk5QvGcTbj9KMvArCJ3DDxYxQ1Ni8Q
         m85w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aFqvbUG+;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e87a6c2a3d0si351054276.4.2025.06.29.12.25.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 29 Jun 2025 12:25:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-313067339e9so627332a91.2
        for <kasan-dev@googlegroups.com>; Sun, 29 Jun 2025 12:25:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUY/KVgNQXf5WykZi5dF/Iap+w3op5h31E4mGNsdFVVnero0ZLNvonxSK5RYZZbPElqMxk3rZCXTVs=@googlegroups.com
X-Gm-Gg: ASbGncs2UCuky4Z0WXzLOEr7uWr0I+0n4BLNEiyPXFLyTgRHgV0poB0AYIYC9TBp7F6
	eArVfAFc+Ay5zOu5y7o2pLjKamFIbTlKoSVVARYWSii3QPF5QiC4gstIu1Jxc0mWcoUGlIUeHTJ
	R1IEzl1aG3O/raFBAo7md/VxUTBbXSB7CgQwIAOnTlaHQ=
X-Received: by 2002:a17:90b:1d88:b0:313:2f9a:13c0 with SMTP id
 98e67ed59e1d1-318ec333f66mr3768349a91.1.1751225146187; Sun, 29 Jun 2025
 12:25:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-3-glider@google.com>
 <20250627080248.GQ1613200@noisy.programming.kicks-ass.net> <CAG_fn=XCEHppY3Fn+x_JagxTjHYyi6C=qt-xgGmHq7xENVy4Jw@mail.gmail.com>
In-Reply-To: <CAG_fn=XCEHppY3Fn+x_JagxTjHYyi6C=qt-xgGmHq7xENVy4Jw@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Sun, 29 Jun 2025 21:25:34 +0200
X-Gm-Features: Ac12FXxmpz3C8AlbbdlYHddP4CtTveSZCQxyhvgXre6C579OA7sLk_AQ2GhDFsY
Message-ID: <CANiq72mEMS+fmR+J2WkzhDeOMR3c88TRdEEhP12r-WD3dHW7=w@mail.gmail.com>
Subject: Re: [PATCH v2 02/11] kcov: apply clang-format to kcov code
To: Alexander Potapenko <glider@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Miguel Ojeda <ojeda@kernel.org>, quic_jiangenj@quicinc.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aFqvbUG+;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Fri, Jun 27, 2025 at 2:50=E2=80=AFPM Alexander Potapenko <glider@google.=
com> wrote:
>
> Random fact that I didn't know before: 1788 out of 35503 kernel .c
> files are already formatted according to the clang-format style.
> (I expected the number to be much lower)

Nice :)

> I think we can fix this by setting AllowShortFunctionsOnASingleLine:
> Empty, SplitEmptyFunction: false in .clang-format
>
> Miguel, do you think this is a reasonable change?

I have a few changes in the backlog for clang-format that I hope to
get to soon -- the usual constraints are that the options are
supported in all LLVMs we support (there are some options that I have
to take a look into that weren't available back when we added the
config), and to try to match the style of as much as the kernel as
possible (i.e. since different files in the kernel do different
things).

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72mEMS%2BfmR%2BJ2WkzhDeOMR3c88TRdEEhP12r-WD3dHW7%3Dw%40mail.gmail.com.
