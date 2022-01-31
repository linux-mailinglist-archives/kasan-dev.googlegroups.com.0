Return-Path: <kasan-dev+bncBCF5XGNWYQBRBVNC4GHQMGQEVDFPJ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 096584A5135
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 22:15:03 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id l10-20020a056e020dca00b002badca9390esf8505260ilj.9
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 13:15:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643663701; cv=pass;
        d=google.com; s=arc-20160816;
        b=d6ytKr6ZbshCLq3FgxQlQqtJ8V9Y0/gcfMNjBIKKB+qGYKJ2m1DWimdb6bnBJi2S0R
         G/A8tF9IzU9ijxqe3UGld2p1tMKKl2y2hz1hUblTRjcSCOl5IHkD+lTy2BNNkm1v+sI1
         2pcAop3lJHhi5ZE/o12Grrt02p2XkvbdGloaMZ5DuRCppvbcvfPzEVdge7Ab578LuFuy
         Qr5ioXEMfhn4ZanevX2Yi9xfkNzvGITLSiqMQrrd6dvEB/l7YifnSlELuoUXY3yiXd3O
         3cQw+07R4QWWGwmApUz6IKjCY7rFa/PTirHpsLYvGjuz9YxJ6GJJth9OfDGkLJXZiRNH
         WUbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=99rLuHeTX/s8fi6KSOZvZWBsvQc+cgWT5M5nkR2ZPqg=;
        b=MXOxyucrb++lIk3pvuFl8jx5++ojtgCaV4p+xQS3obJpxqWuvTNchIMBdaN2mmFmW+
         lENiZtYGaf6BVZA5aQ0h15tEtE9Iu/ra9t/LpjvsdV/0LTHzSbp0Jchz0iq8CJOU2G24
         e9jx9LLYFgLh8xjLLq6n2PtXv8DuxXcr/MbUxj/+lbgDlSqlFhmA2FGGtkVYMbzNwHHK
         kt/eUTTJptWnJUaJLVVznmqG4DIAMbvTQper18rS6QU2bP4RNGfLQpx2E8ysd13hLx40
         fmpIJWCxdmhjTAUV9OWb0bwsRYhMcyi1R1Cdm30/1WUpqlXgyUXmy3FEY6vTBaGq+Cjq
         jxng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Xn0LtiOP;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=99rLuHeTX/s8fi6KSOZvZWBsvQc+cgWT5M5nkR2ZPqg=;
        b=rd3NwYLqHbEtff3mkBxt8ex8T7pSTbcZqulqD2T4lxKmGpkX1nIecJ+U1zqkr45ppr
         QD64E3lrDPBim3cbrGAPLQcNabozYSFKY2RAebgwKCCQQ2dEnoIc3sf0HMpF753Kk4uE
         U0pRvLe1wQGMaGOu/WIiEWTffgZmq9oZ9kuBc4S/Vb6akNwhh0whlX0ureqZrBYQJ7l9
         E8LdY+q3DSrG6YizTQjii2FH6VdQ+wnkIjhYzb03jlF9iZ/vVKtHMAgIv2rnVKju/VLq
         GLIf2JY/UNS56RT5bfQ7cvd2okpXr4FgNiHjdj+n2qbIJ5BEkLfG9WeC+1WhIWEgjuro
         KE3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=99rLuHeTX/s8fi6KSOZvZWBsvQc+cgWT5M5nkR2ZPqg=;
        b=d54mA8M1tqBMZCWyMPWoUyGI+pR3hw2h7clRApSkvddOxyEQ+hb5R38X1mCYh0gfEQ
         0CDJ+qkpMXXsMQ2JCK+OsJTd+tMer8PUFAVJ2F7SHrTHmgKkvv2LcwPqrJVqpcMqjR02
         LW1m23oteV65m2/sYiqc5dL9EMX3TSSyuzh+AdJPmuru50DFr3FjjT2u0uW5DQ3/paWV
         S7FVe94ZDH07T5V9J+M12dYOL5SQPeXR5xUFWyJl9qcrp3qHD4uCYuTsVFywnbgmUFLM
         XHE0dwE2PS0Kss+kNMaYRHJMfdlVnOdy4MnOozOYQe/qWgT66c6Dq9+HcVgD+UUzZ2yt
         h6eQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532REmLCfJlOw5Wgm1S6Y0c8k+1B4o4jJNR/iWCIntXWPZGNKldl
	Ol+cmOJUlWTuZuSLin9RlgA=
X-Google-Smtp-Source: ABdhPJyXN/mW4isQYSlL66CxO+Sv/O00TjQ+fk8kUNpT/uQ/GtGgKhXTV0CLvo/2S0jWwH39FQ4Jow==
X-Received: by 2002:a05:6e02:1ca4:: with SMTP id x4mr12925830ill.262.1643663701777;
        Mon, 31 Jan 2022 13:15:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1490:: with SMTP id a16ls2346584iow.7.gmail; Mon,
 31 Jan 2022 13:15:00 -0800 (PST)
X-Received: by 2002:a05:6602:1513:: with SMTP id g19mr12216218iow.30.1643663699957;
        Mon, 31 Jan 2022 13:14:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643663699; cv=none;
        d=google.com; s=arc-20160816;
        b=fqZdzl4FI6Eu4o/G1VFQqg4kMC5zsYo8B4LeAfGjXb3YOVOmJKOMMc6M+DXRCqbFbJ
         84QlA1d6ul75KDzHDkgI8y1OexGnHCGn5Cmj/sMCkHxGvtjauWO6ZCk9wzef7aWGoRlB
         alqp1hecwWC2qbJjBH3Wsj5OodKFJW6+mxOndKPkJmgG19TVUKywpcUOxHHLe2/+/zC9
         TXcs1joaOOE5/w4T6ywxtUNZoAcAlHLG6OgCJ0j5Q1gleLmn5JgfpQmI0PDsuEPUMN2H
         Jscy9IG5cTY1P8lRLFlB4PAoEK5ACo4BPooaPOOxwqCJlc+UhwetRdYWrTlFaj7tJ71V
         8UGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PomGqS/ojw0AtqU3Fb7HbY+FvnyoZQSU3mF25QVJV7c=;
        b=dGJaqo8yqiy/vbfkZn89xQK7x+zi27LItv4AFy2nWmE04qYXypEEy/QuMbNNmaFMwZ
         KfC07yt+DW+zvmT/cXi9sBM8A1oIjPWx4mY2ETuIxS1lKU6yixc57KigQeVfUzU9XUzT
         u/Jn61MYHvFS28SoIpkKCKeGxZF97noUDNcUIH30vg0LCt+wuC3YvoLEa3HWDUMU8cik
         4hexvjdValmhyaHtYpA28StcM97o6qYxoaI3EUxYNnH1y17b6nKoe04OApJ0SHMxAJk/
         xEiOF4InRRTjlbcW5gLjrKKpd26c67SFs89NhWUPtx1VpTUH9ch8gsTKW3BZvsogKV6g
         6S3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Xn0LtiOP;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id m17si2337996jav.6.2022.01.31.13.14.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 13:14:59 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id i30so13959944pfk.8
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 13:14:59 -0800 (PST)
X-Received: by 2002:a62:e40f:: with SMTP id r15mr22514435pfh.24.1643663699526;
        Mon, 31 Jan 2022 13:14:59 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id a1sm29349483pgm.83.2022.01.31.13.14.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 Jan 2022 13:14:59 -0800 (PST)
Date: Mon, 31 Jan 2022 13:14:58 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 1/2] stack: Introduce CONFIG_RANDOMIZE_KSTACK_OFFSET
Message-ID: <202201311314.2978E80C05@keescook>
References: <20220131090521.1947110-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220131090521.1947110-1-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Xn0LtiOP;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::435
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

On Mon, Jan 31, 2022 at 10:05:20AM +0100, Marco Elver wrote:
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
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202201311314.2978E80C05%40keescook.
