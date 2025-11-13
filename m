Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFWX27EAMGQEAM75PRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2654CC57F34
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 15:30:49 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-7b2238eef61sf165283b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 06:30:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763044247; cv=pass;
        d=google.com; s=arc-20240605;
        b=XoRdSNA66mdm71SyRFXF753dL/qEeDdRz8qgmCoKML+kJ0+/4L4i9g0UxzXUUjWXrE
         56ydHFSjQ3erY1Fpg1gQgDHKaTV80hrks4uIYsFE6OfV/5FKnmJKkPZugBgykP8YUDTz
         QKY4ZTtgoUdyOyF8zeFVkleoHCu/kGdDz+jAx0awdHP6lseZEaxCSsC0S5huXpcwX5nM
         s/2y3GYki8Rmu4SPBNTCcKfJAH42MucE3c2KWO+9ewP6a9qOEhtcm9y7rUKioRCapkcu
         ahGcRwHWN7fzm4z9I31+OHHdnBArqiEoLb4HtIQS6lcIupfWn+6o9NqfQ//66Ozeel9d
         UyVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4l/WBIepzRBZn0YixAdBmO6t1yeEat3YXfcqddnw4Gw=;
        fh=0sknnZfutHcBD+EdA0s8SLdPld180n3XiMIpFP35Utc=;
        b=Xot+tUUcio9aHIKpvEzb5HalhNCEHLsWYsPxoDcbDMPYXHYNh5gmQ2PCRDKkjkwlNt
         H6N6EIJvzeujsxyFxOR5o+q5MOyWzuin68XUt1sN0AVN6XXIWRhgN1o2VPHQW+6Mi+Lm
         U9/vattG6oPQ5ZIw4300MEx1KauCGmklCjuAdonr4mci2UPUtUJUdpV/3kP3ZIb5ZKir
         2WNsgTbci4BLnDdATLhRLqPPzCkii0BCnVbJnt0MkSVCDrkI7S+ystqTCCFzl1s6z18D
         smSbe0sPQKg4WKSSj4NEdobclD814niPjoVazjdbZA+V2T6iOVVUshGFR7VO4qpsnhQk
         bGlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T9vamlF9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763044247; x=1763649047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4l/WBIepzRBZn0YixAdBmO6t1yeEat3YXfcqddnw4Gw=;
        b=r7fgwzH3dV2gkiNILSqQ0BHiR580qSk1ssS2OKh1zwUZofglYCMco9FzwrY72FTZBs
         cA68umVI6PYs6MKXrDpEnbgYh6Jm2rQXVqed3vW8Rm8AKOH14BDuFVtH/di0zowIA/Tx
         4+7cPi0xF9AZbfZy/2PHuuP0+Kj6bGj048kjeGCGQEIAZSu7SbcPanPBOpnhp5+jWMQk
         sUHXdP55zEPC+8bK6YT8JsTJKXnWmr4e8G5bxgrC7stS5TX1b7zL/zRZAK6MN8gxP2Hw
         eB7E2oqvEAVCxHUBgqlON11UtmwHP1fy64xUYef+z0/HnnR1Lqs6mKxrEXNn4m0TKOnF
         RKLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763044247; x=1763649047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4l/WBIepzRBZn0YixAdBmO6t1yeEat3YXfcqddnw4Gw=;
        b=k/GBh2d4TxLcv8n6dfJT9NVDlZD0vsx+vang5Xezs3N0atDocjBpdY/xPaE8G2upjY
         5TKiDd9+CJ6jp2P+bKLnjxPFpCjGbfotYcNqAtrCRijuIMfc+UQHeIYyuY4Ofl/ttLCN
         vpeRYrXWzk+7I+w1WDfcqmXr/h4iyAdu4xhwWrL1omIOLuZmkNhHNGPFijHYhv8TrdD/
         RjqRYjIhg1kNolkMsfMnfk7SyX5B79lE7CvUGIbhHXT5NkkAJ7j7zpmHLWcHiGrDRV2E
         PhTqfKekC/cnBakssaQQfMw6Sx5VVYDjids4gPbyQKu++DmkYhS4SvQtG2tsgFw9Mt81
         45OA==
X-Forwarded-Encrypted: i=2; AJvYcCWLcGiJR1M6jV2D1km0juc6zfhW99csCrGxTJP/M8kcjnu/DDzaJPBNcnQYuA0zr1zh0KJRTw==@lfdr.de
X-Gm-Message-State: AOJu0YztBgfzPAiuK9BOZDhnjgo5Of2uNYORjpHV/a77ElA9l3Jkw/KN
	M7CRK6IWHglcQ18zE3vNZaxTKHD0MycbkcoXXfdSVaTeHZOovOzFid3g
X-Google-Smtp-Source: AGHT+IHa23YpTsDxqn+2R3vpAq9jKtX4j0SdPACr08uC8//e87jTHD5LFQ2AJBv/M5Tkshvs9e8Ryw==
X-Received: by 2002:a05:6a00:84c2:b0:7b8:2599:801f with SMTP id d2e1a72fcca58-7b825a8c80dmr2462954b3a.7.1763044247130;
        Thu, 13 Nov 2025 06:30:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bTXheBPDq7UzgHuiMVJsJxeuJSR8zIiIAUSMUxprwnfg=="
Received: by 2002:a05:6a00:2f8c:b0:7b1:41b8:c173 with SMTP id
 d2e1a72fcca58-7b8d54bfb6fls753933b3a.0.-pod-prod-05-us; Thu, 13 Nov 2025
 06:30:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV1ih1660LJnlUG+M9aTseYT/jVV9oTt9plcQ8g1GG0dKOQtLrvRb9fxokAULSvVwyVmNMViY6DPL8=@googlegroups.com
X-Received: by 2002:a05:6a00:1ac7:b0:7ad:f6e8:d013 with SMTP id d2e1a72fcca58-7b7a57a4533mr9508214b3a.32.1763044245319;
        Thu, 13 Nov 2025 06:30:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763044245; cv=none;
        d=google.com; s=arc-20240605;
        b=ZCQscM81FETjnCghHg4qsPZOlroelZqXY1XZAS7KPZ7w8972s1q5Bn6doUKBOkzF78
         1h/IflJoxvEo4mIk8iz+HLXc53Vxe9z0XK1hr+XUc32tx/1j8b7yxh0DsnQJxT0UJ8Ne
         MG+p+CHipnaLsoKd/wudTTcsYx0RDPLaTeY2hCSBYEcHQV2GnV92xTYgFLNE3wRG9mR5
         DFGYW2umQYN/vyYEZECk+B3d1VkNTHeNqbLJHamAdTcJavVhOQZISBkKc814ADF7hMHW
         tG67HyxRbcuj3K1vFHL79J2s5PKP8oqajU+9a1QKkkioDYqC/Mj/vfny+4GJ7DYksIEz
         TQgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MBXryWsSo8WBJYsfFQQsezl+bvHfvcNsNG0PI/C7tiU=;
        fh=fGYKVP/Q8HfahG7PxKIlhQ1js86Z4qAA50RRAlrtZUo=;
        b=EK56MIb2PpdEDYt/2UnYI6OgUv5GpPMDziwGXGVYjSt/dHthHnlvFpboobU03xgJsD
         wvL7ItCClBX/ymohNZLfFgcOpqJvjlUK2gUxBaU/AtNWCRora8/kqMfmYfvZBaCP0qek
         f6pslbBtu622wOgRo5kOtQbT9IcFE4Bc2iA1/OLOR6dkzMaXKyxXr2UlaNADRBfnZ5o3
         zO9VFlNCeCrt6YfePsnPs031rzBH+WNtlsriH6PvuSn0RnGtsR4FKvLDSdtyCQnX2z4w
         wYpmcmeB2HJnlv0INePXEPRyfCSNoeCGYUfFdS+c41NxVFMBbezBSPQyYgxTrwvO6TIU
         OZGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T9vamlF9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b927a1daa3si95924b3a.7.2025.11.13.06.30.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Nov 2025 06:30:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-782e93932ffso720813b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 13 Nov 2025 06:30:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXE9B9WbheeGavpkDTpJtp+RSSIRyALCXxvHqyoyH/zjR9NY7xKB87/cHZ3gPmQaXguB5JGd8UfQ9U=@googlegroups.com
X-Gm-Gg: ASbGncvbjMJTIz2oQBVz8SH1/f/kQPFhddgLjhQuCSz5TgO6bVX0xTigmy3RwkxlTLZ
	RA5HWSBT/Uo6sh2Z6WKkmOafjfwTSNkd/irjx0CaYzlj34GLmt+SUGrmNfglEXfKZXBIzJz279C
	gxHiUVpduug/Xqu4Mk7YbKJImEE/MaVtQ/TIwohNSPTQUWXI/V/assRj7wFldmiSFaThe0U8n0w
	i8Do/hileCcmizqV3JeQKS7a5vyZ68QJhAKlEU81BnsfCySlrweVlUlUNNhQC3XXFOQyyiikn5t
	1Y5max1sHDkZannk7eSAjF0=
X-Received: by 2002:a17:903:fa7:b0:294:f6b4:9a42 with SMTP id
 d9443c01a7336-2984ed2b5edmr67173465ad.9.1763044244630; Thu, 13 Nov 2025
 06:30:44 -0800 (PST)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com> <CAHk-=wgd-Wcp0GpYaQnU7S9ci+FvFmaNw1gm75mzf0ZWdNLxvw@mail.gmail.com>
 <aMx4-B_WAtX2aiKx@elver.google.com> <CAHk-=wgQO7c0zc8_VwaVSzG3fEVFFcjWzVBKM4jYjv8UiD2dkg@mail.gmail.com>
 <aM0eAk12fWsr9ZnV@elver.google.com>
In-Reply-To: <aM0eAk12fWsr9ZnV@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Nov 2025 15:30:08 +0100
X-Gm-Features: AWmQ_bmFh2aVYHZwkaHdVYkb7IeD9B_c5E9TrUEhRxSr8kO14B_rxSCEK8GKI2o
Message-ID: <CANpmjNNoKiFEW2VfGM7rdak7O8__U3S+Esub9yM=9Tq=02d_ag@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=T9vamlF9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42a as
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

On Fri, 19 Sept 2025 at 11:10, Marco Elver <elver@google.com> wrote:
[..]
> I went with "context guard" to refer to the objects themselves, as that
> doesn't look too odd. It does match the concept of "guard" in
> <linux/cleanup.h>.
>
> See second attempt below.
[..]

I finally got around baking this into a renamed series, that now calls
it "Context Analysis" - here's a preview:
https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=ctx-analysis/dev

As for when we should give this v4 another try: I'm 50/50 on sending
this now vs. waiting for final Clang 22 to be released (~March 2026).

Preferences?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNoKiFEW2VfGM7rdak7O8__U3S%2BEsub9yM%3D9Tq%3D02d_ag%40mail.gmail.com.
