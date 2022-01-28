Return-Path: <kasan-dev+bncBCF5XGNWYQBRBO652CHQMGQECZCPF4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5325B49FFCF
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 18:58:20 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id hu4-20020a056214234400b0041ad4e40960sf6757491qvb.13
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 09:58:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643392699; cv=pass;
        d=google.com; s=arc-20160816;
        b=f7Fydbz7mSC4P407UNv6DFjs2QWPKkMXf1kGf9KHE76ZR/z3f9VYt2tlCC7y8sX6m5
         pNeGTSy7ZBUgNYelDRN6H3ytaStCfymEgzpg1l+w1OwZ1me0PqGj70TIy2OOC8Ydhias
         hAFFmK9KpZIkelIv9SRW8+73lKzupuTv05LcVaZe+X+8vH4+ip8ZAfzDltzMMzTla83f
         MyFmQfP5SjIegLWeUA6TgoQwGK3N6gOBgUw09HzQwOWkzEXURYfCwiBB2p6K54y7ZlqM
         Nu5gW/iXH17tyOWuP1A9y9fz07URBomJMFTYZ7bPGsmdwyS6lrRvt1u4OOqHv5/gZrqQ
         4wpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OexmwyalQAskCboI+Y1IDGhgRhHV4esq+RrBaibNS9A=;
        b=NrRONmNw9bgQfUJ3xWuxZKZK2PqB2oviV/OmEeSU3XrpJ059sydLssHcAwRJAi5MD+
         RSZTTmgr0/U0VFQaq2Yx0uQt7NvWVymsz6Y68IZZH+aQtKQCYYCvCEbEBPjqS6tpbNJ8
         x5nyPm28GDVoWKsHr47os+5/xPC1inI8tyi3YL5oYca+cma//5TXh2gSNAAtwQBzSO/i
         7dBnS3aIpsfk5jOaQKHD5AWbFQWvc+CNeNqcXYFRXAXpqdT6oe59LKBnCx8yIJeHvTuG
         bKRmPSYHhz3byxxumhaf/FiG8gSPeIiaNjAFstvVT3I1280fzkTPv59Loao3nkn4zvmM
         qIhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=J7fuSAhE;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OexmwyalQAskCboI+Y1IDGhgRhHV4esq+RrBaibNS9A=;
        b=TpRt58garyLz20aPfI5hawQZYl33on6E/h5LpO8OZ7EMtHst+fJQAW78Dvg/6KxdMi
         TBupSsmhb0upHOBqzeTW3CZ2+KHdBvh7btc/erqZW/4ZSoHORac/Rf+NC3qkI3yEYg1k
         o0Tuyleukls31RbHC3MNG8Hepze48gp1/QFjTCujS7n2Mp54dXUPAEkAFd+95J6hcnm1
         sMGxXEdW036CfMtIP/kQIUtLPI9D3m3GsxNzK+z23SClUHXRSSYrO5wV2EZuet3DCz1f
         +0CnflVTTOMvx/MQO/oxN2MrjwNLS0/rRxr9Ogawr+n8gzQJcYZZ2Edx13nbRzFWCkMn
         A4Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OexmwyalQAskCboI+Y1IDGhgRhHV4esq+RrBaibNS9A=;
        b=rsZoN15GduiB1WBwgJFw2EmtkZaYFR8r/dQ8uOiy1+xkEohIliUIq/OEf2UAxh+LLC
         O7IxsDD6F7xF5/7u2tj2whC4i0F6Xm2UF7MgMysQtL/lc9zHmf9kPP+PGJRy5qSnK630
         BWeC4YDO5Q+kkyvWlXSjUUIksd0uebGApJs+vBOF00fqhbU3sxFaY+YJNx3FJKsUh/k7
         ySE4GBgQJOHvltPsrJN58OXGQ7zLMCEl14w4ZZktNIf7TocNFDT+Cd1hX148BU7nGMVA
         V+EHbYxHGq60Sw6FMcb5IlfomMZqRynXpcvD4PPUYvzJaOqFsYcpLMJ9y5tCR2cEgLg3
         sxUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ZPlQyzWGBCZr0HrT3D4higne+xHWK8GdxTLOFVGn6+ht0VWES
	aKDWQ6Ae/c1Wahe/J3PtURI=
X-Google-Smtp-Source: ABdhPJyz8k5aOJrw6scdv+/vjJel/nSo95jXxqXFaVMgU7RWulcLCuwp1RjwCMyc2EWeL0DIDzBaXw==
X-Received: by 2002:a05:620a:d51:: with SMTP id o17mr6263574qkl.633.1643392699114;
        Fri, 28 Jan 2022 09:58:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5057:: with SMTP id h23ls5028026qtm.1.gmail; Fri, 28 Jan
 2022 09:58:18 -0800 (PST)
X-Received: by 2002:ac8:5e49:: with SMTP id i9mr7024866qtx.576.1643392698661;
        Fri, 28 Jan 2022 09:58:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643392698; cv=none;
        d=google.com; s=arc-20160816;
        b=PFueJtuzhxIO6WPoBIhOoGoJGN5fVOiQe5wu9/Ex0HIt3SsOPKEw0TytL5Zf2YJ55V
         zwjl0s2I+MCSTCRKpfyRmWVg5aIKwFGSJbRyH8B421+ciyPB54KBA/NiFpAaWUUZRNqU
         CSDxrtKa3/F08emEsAH9H+R0/hYTmrE3lmTvJurNiNGAtoC8nwAt+yRx08Ub8C4FEzDP
         Ow7fq/PY9jtZYI8e8gqSH8KH6rbB5Y9LHx3UyojVrxspoRSyYMZbTiDk8iq5sLsVZldp
         mowXkR0ZHXTG8uNcbghU2qZwSOLCtjEQ/9xm1ZucMj25gNJNVeifiIZ20hyBrRhDnrjT
         r2XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qMBeUtTGoBAaUmn8ulylEeU3TILxfDlpE26BBKiNnGY=;
        b=Ie4nzpD97FeYx/baG+Hx4mc9fgyRaFB4GtPvAI1WMQPG+3jxb5Gmb65+P8Mk3jgOsI
         X2t8Iz9Hap2SdphpEHsb571YRaSa32/CSZUswnaiRglyx7t1GKsFLdvp+bRWyPLJQM12
         r0IJf23D4WKltDzo1UCO65X2sDBs2r38+5p6yTA+K8zrKwH3wGLVcM/wNzIBn2abaSGb
         jyr4GdqKR9N7tS9Ocg2HenT1+VpZWeDkqD76/NAc8hTcos4PNzwbpMAm076ARPZQFY0Z
         cdl/FugjbWDL6qj4SnoGKm2GC3ocxqEwXSHSQZaatnMwzZtWow6DbyxdoySiMcn7jPKL
         kFzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=J7fuSAhE;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id y65si271684qke.3.2022.01.28.09.58.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 09:58:18 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id h14so6801401plf.1
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 09:58:18 -0800 (PST)
X-Received: by 2002:a17:902:bf0a:: with SMTP id bi10mr9948941plb.164.1643392698276;
        Fri, 28 Jan 2022 09:58:18 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id p17sm5893755pfo.11.2022.01.28.09.58.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jan 2022 09:58:18 -0800 (PST)
Date: Fri, 28 Jan 2022 09:58:17 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, linux-mm@kvack.org,
	Arnd Bergmann <arnd@arndb.de>, linux-kbuild@vger.kernel.org
Subject: Re: [PATCH] Revert "ubsan, kcsan: Don't combine sanitizer with kcov
 on clang"
Message-ID: <202201280957.562D6AC@keescook>
References: <20220128105631.509772-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220128105631.509772-1-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=J7fuSAhE;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634
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

On Fri, Jan 28, 2022 at 11:56:31AM +0100, Marco Elver wrote:
> This reverts commit ea91a1d45d19469001a4955583187b0d75915759.
> 
> Since df05c0e9496c ("Documentation: Raise the minimum supported version
> of LLVM to 11.0.0") the minimum Clang version is now 11.0, which fixed
> the UBSAN/KCSAN vs. KCOV incompatibilities.
> 
> Link: https://bugs.llvm.org/show_bug.cgi?id=45831
> Link: https://lkml.kernel.org/r/YaodyZzu0MTCJcvO@elver.google.com
> Signed-off-by: Marco Elver <elver@google.com>

Yup, good to get rid of it.

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202201280957.562D6AC%40keescook.
