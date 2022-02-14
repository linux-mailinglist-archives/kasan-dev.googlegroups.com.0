Return-Path: <kasan-dev+bncBCF5XGNWYQBRBCOUVKIAMGQE3SZ7VNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id A0BCB4B5A72
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 20:14:18 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id m3-20020a056e02158300b002b6e3d1f97csf11912205ilu.19
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 11:14:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644866057; cv=pass;
        d=google.com; s=arc-20160816;
        b=za04pmyEEmU8TYRhr1H79BCRolWB2HCvbDNpwSUDw7daqXY/h35Hlx1AAqq7JkSPRg
         JkHj9YrT9Fp0MY5ztBisa/iTqMyLZMzuOnZxxM5c8gPKFjNcBd6WwcNRxs9plfgJcmUI
         LkajHkGFxHRgcIFHvG3O3k+Vx3EUIUs1dJGIfPuVq+zXXd9/aVLbR2oL9fYolPkjG99S
         gAwMTb8aVRVG0clvYhfcAdLL+8OnoOZ4TdRacPCkEL0VS7ddV+axgy0PkRaTrjIsVl78
         eOiKyK88aD/Xg1M006qFNWCGC6YIq9oNVSvuo/oY++4+2NJ3DqCOy24w0CcqU6lSk5AH
         RNDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vhYEBpS4QStWmWJ90SwIvu4bbUaqgCp4lv4SQ1Exdus=;
        b=JN9/RORzysD6uG/iZ3FO82bqgkvXFs70FemBa7VPwbY+gejV+4oJ1LikRjQmE5HOir
         qAOhx9SuIqOsR0Y5kDlQEdCCTwwKhp3umIPCvflebSdjVVi9zqKsKQL/ECe/i2L1Q8Bu
         gQ2QF/RFeX2vzR8N/oNAksrYdc4MCS7a7MuEVia1l6tlJmu+ntYfhy2B2RudtPwUDy1n
         lLibaAxUIz2fBSyziExXuvNZdOxGvL/SnHOWsU/SkpZ9mMAhJcy19IwifCPPRbTg8Tow
         3C5lR7ttKMD5vEDbxYKjomVF4Vdhz9U1//MCPGf+xccSHhliaq0kanxom6lMusZlK+Iw
         1wdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="DLytup8/";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vhYEBpS4QStWmWJ90SwIvu4bbUaqgCp4lv4SQ1Exdus=;
        b=lE85IjIq8jNprzCynTttIIpOkRXjoStgEKUn/Ruu0suU5MbFeKxPFK90oKLqp7rUeX
         2OBJ19WkbhNPIi+KOtAN93Evh/d5pEZ3xde8MEGdyLaqI9O0YyR/F352lck8KqAK8tia
         eo9IamOBrLCwUoJK9vPMq6wGtiZIQCwm+8QFi3RuehRhj0yGjv3tocSnZHpL5ui2Gr1d
         cg6crIZLsdIRrsSQDvRpO6TMGsmB5Oq362LUgI/aU+IHnaAM+WO8gq5FR+c3uZ6BsoXT
         /fVV9kzdJcfPycAhAi+N6zd5RPZxSfPVp5BQenhnosIGIeYZSbeN/oKwHutBBLi62E2/
         QHPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vhYEBpS4QStWmWJ90SwIvu4bbUaqgCp4lv4SQ1Exdus=;
        b=gPNHmP87qihzb+8CJ5yhhUrT3ubxs8J66RwJGURQseYZQ4KUWDi+vkqSSZFbNHmIs3
         ZUhG69TY2vKTqSjTqeRL8m3fq0zvbtDiQFj0nccPw5FeR6YT/QZ3rn3IF8AWsqI/mJVF
         paK8v7BQWjYOsZrTBA9UFD65CMrH17FhXrL2BPyeyVl30PDtf7kP23eCTU2I5Z0XmVmS
         YFCf1xTmrJpQN36s6vHDOLv5Y8op7hgNBzppOvxdOM+fUARnY+ru78BKmdInDHzXiySV
         u3EnBt/ETh/B6FqfJ4bKsIzOVgj6Jh1u4jOJzpTHwX3cUpVWqmU60xtkf1yS0deslUq7
         1fXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rx6H7byc6wGAUGZsdnZPw++fV0BqZUMDDybpyFcOeVd7l9qDr
	sP/8pubEovSSV6PHzwnCCzw=
X-Google-Smtp-Source: ABdhPJy4Z0Gr9T0FfDNEtgqIfjziAgusrjoLxpyvoz/MDCn2DZDRtq5/8F8/uVoV4yf0FPni+Vm7Uw==
X-Received: by 2002:a05:6602:1605:: with SMTP id x5mr197713iow.14.1644866057454;
        Mon, 14 Feb 2022 11:14:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:160d:: with SMTP id x13ls100970iow.0.gmail; Mon, 14
 Feb 2022 11:14:16 -0800 (PST)
X-Received: by 2002:a6b:d80c:: with SMTP id y12mr170705iob.31.1644866056219;
        Mon, 14 Feb 2022 11:14:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644866056; cv=none;
        d=google.com; s=arc-20160816;
        b=nd1ALfU6IgRPgCJd3RCn1WhyVINFFOEpgre5+rvtiP2ZjjetlcbmgKVOg8Jt/SjXfM
         AD0kV5AbhqxG5FA0Zx6AjXkwAu6/VJS398SAmSvsY1Ity8krA3m03LvxkbckAsA7zv9P
         nnuy+KsZzzFHbqln2KZgOoyD12LR31dHIfGBi9AaqEUwWD0pRsBZ9HE+eFOHAyh+ajIU
         G2/03cmXi6jluRJ47M1sn49umdWocLrG708ZVGEfeTtmakbQGBimboQ/g+a6v0fuI4oL
         h+inm463NWoHeWgjXy34tsgoi/N18ZTM8oEGcBpkWDu7v9g5Dl/gSYBWDWUCXhG6l/G9
         9v0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7CzXZHBrjrvvHPuFEDIUoa2XYSCdiIOC+ZXymIl1Gq0=;
        b=Jmvf+Gz8E9lrW1S34fO0a//WFJjS4HjjlF0PdqJ25Lk90kr1ySzAXh3zpKySW1IArq
         WPCfzVoLsVKiQ1rwRSlWLs1LycAEArYjPEeDSQW5X2zhOc4pqb0Tbat5tKGGddujDmFv
         J5W2SPKh6ObJfFpd7PRjKQW9pKI/rcDzrOkZUUJZLwB3rAoFIy+ra2+2yyOkqEFUH6k+
         RXs9+bNAnR/jP2rf1Riv0HTUYQXmWQGqGQDog94ympql1MWVXeY9NGIe9Sv3PvYTv32X
         jzn+IKhKYvwBwIx8NBsefMt7hEX+MzoscpkuHXUT8TlFmw26Jec/Css3egUfXwRMQCpm
         O4pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="DLytup8/";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id h18si4525117iow.2.2022.02.14.11.14.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Feb 2022 11:14:16 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id c10so5300012pfv.8
        for <kasan-dev@googlegroups.com>; Mon, 14 Feb 2022 11:14:16 -0800 (PST)
X-Received: by 2002:a65:584d:: with SMTP id s13mr389414pgr.369.1644866055556;
        Mon, 14 Feb 2022 11:14:15 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id oa10sm12985799pjb.54.2022.02.14.11.14.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Feb 2022 11:14:15 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Cc: Kees Cook <keescook@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	kasan-dev@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	linux-kernel@vger.kernel.org,
	Elena Reshetova <elena.reshetova@intel.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	llvm@lists.linux.dev
Subject: Re: [PATCH v2 1/2] stack: Introduce CONFIG_RANDOMIZE_KSTACK_OFFSET
Date: Mon, 14 Feb 2022 11:14:03 -0800
Message-Id: <164486603894.3748820.17377347049312013591.b4-ty@chromium.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20220131090521.1947110-1-elver@google.com>
References: <20220131090521.1947110-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="DLytup8/";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, 31 Jan 2022 10:05:20 +0100, Marco Elver wrote:
> The randomize_kstack_offset feature is unconditionally compiled in when
> the architecture supports it.
> 
> To add constraints on compiler versions, we require a dedicated Kconfig
> variable. Therefore, introduce RANDOMIZE_KSTACK_OFFSET.
> 
> Furthermore, this option is now also configurable by EXPERT kernels:
> while the feature is supposed to have zero performance overhead when
> disabled, due to its use of static branches, there are few cases where
> giving a distribution the option to disable the feature entirely makes
> sense. For example, in very resource constrained environments, which
> would never enable the feature to begin with, in which case the
> additional kernel code size increase would be redundant.
> 
> [...]

Applied to for-next/hardening, thanks!

[1/2] stack: Introduce CONFIG_RANDOMIZE_KSTACK_OFFSET
      https://git.kernel.org/kees/c/8cb37a5974a4
[2/2] stack: Constrain and fix stack offset randomization with Clang builds
      https://git.kernel.org/kees/c/efa90c11f62e

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/164486603894.3748820.17377347049312013591.b4-ty%40chromium.org.
