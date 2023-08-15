Return-Path: <kasan-dev+bncBCT4XGV33UIBBKO556TAMGQE2WQF7CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0973577D51D
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 23:31:24 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-6871080795csf7411774b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 14:31:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692135082; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZtIm0VxIlV5GyG9W7mHFJ1UoMdbfOjIK02l9/YJVOkwUP6afEKR+98HnWt7V305OQp
         goisHSs0kJXtBY3aDLrKnEwxFlO1KIjxrmIVKoxYGLrTgyu6I0AqxRtE4AUQpl/k39ua
         EQN5P4eos1IuDN7LzPP/47uED0/m0lRwaxEjqQn/FmBLha3k/pkGkvbMZkttUU0lwx/r
         Y+XpC569dk07HLYn0ego968ueDjNvB+Y1FoI5uh30t//zR066Mk44RBuf0lYItngtcJN
         TSAKkSajTBgZ4aHuetU3LJfrw1sFQKc/bjIhug56DxMSR6xetHpPRJGmSGfP4t043gSX
         kHDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=TQtF6/A1UuLTTMkOTeEwz9xG6K4vlKqH2tQQW2yqwzA=;
        fh=PPGf9bsLPzzPBafbS//EiFSohmWhCJTIpDiaSqXvQhg=;
        b=bO4bk27iAn/TIAF6SKr1P+xUhioxIVkSA+YXVNAeg/5zrMrmtNAfs8QLRET2gOAJpW
         nKCoiFPupdCAXQvU2D6wsdlu8JiemTYKiqJK7m0CSjdYQKPIwI557iU2/afI0qeuoMfV
         rPBh2Qh6I7sAweN4zeNp4/ErUmtMbS/HivR+y9CkOm1hyHAzwejYdfjGlpCct5Iy6cp1
         yRsHeXm4tzvb13crbnsxgCxtIjM9tK2p35TkQtVLw64TOydteLoE8jOtfid/Z4oZr9OE
         Ofmzeryc6T4Pxb8BxFwPZP3Hpoxkqw5nY7uT1vS/oWhtiRZbhHmmS2AZcEamzvtgrIOm
         kDcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=YyXw8OtB;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692135082; x=1692739882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TQtF6/A1UuLTTMkOTeEwz9xG6K4vlKqH2tQQW2yqwzA=;
        b=h0Q50+FhDPzUSdgiexf0pxncWVRDDwc7oHKU6oU82EG//6wuSqqdcVDHVcLF+BCwuL
         9SfLNIBx94bwP24UdkE2/4DRBeN+bVGQVp5WLMUQ5bvAS/Z745VwUtpqElfJNA7cDlWN
         yP77uipgJRAvmc+m3DrPScjuYWEuht4QfrlOpkaXd9n+YlAmZeExeelfO9QyyWJ0VLM1
         Cgf2L4K1EipLw5ng3VZwjRPhrQC7fdfCxm8+lMImEHI/WIsxd86+wPZAxtI8W75JvmNk
         /Mpp3fUbo79H0hjS3wBAJdwTFV0m+P/DT1vesdKfcCggM/79+6qCgW4T+T2+xlBJdU5L
         VQtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692135082; x=1692739882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TQtF6/A1UuLTTMkOTeEwz9xG6K4vlKqH2tQQW2yqwzA=;
        b=OGHxBoOEvtVqkN6yzSIuGlLHWlLMVVAhyeA7afApQ9VIWZO308hP3HYclK650X7HH+
         mZOFdn5pOFb45CMqwK24nLOhh8qHwXg0mT8pDIulSF9sSlAq2Cxf69HPks+DXkQyN/+k
         XM+lbieyx+Bxg3D1Nkn9jU2cLcHbt8v7PLnGks19VEIYJZlkXzOWFi2AkAymYki24OQ/
         CYLRW+XbfLU7WUzUHv/V3xCpqhyHZuYv9LYktTpgj3AZ6XPcGx9TPkwGZ8r+0QuYRCtZ
         WwsohKlcSXOOIYe0Ok1pZQtoam8jO09mk23qyDI7ieQLUtdXj5/Nlc/pLZPgrbEpDkct
         GFZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzTvOxNRuR0G+ygz28sxgPpGa9MxJdzTwhDD3x2g1XKbj0wr0wH
	gio+fhpfarT/DUg8CrU1NN0=
X-Google-Smtp-Source: AGHT+IFMDii6bmFT9jw4aFqI0hanCUkCAjhiO/aZfLxKayFJbZpbNvmzjHdPsXR8N4UK3/lr+LXMcw==
X-Received: by 2002:a05:6a00:189c:b0:687:9909:3c78 with SMTP id x28-20020a056a00189c00b0068799093c78mr254202pfh.0.1692135082079;
        Tue, 15 Aug 2023 14:31:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8ec8:0:b0:687:c1eb:cd25 with SMTP id b8-20020aa78ec8000000b00687c1ebcd25ls5442813pfr.0.-pod-prod-00-us;
 Tue, 15 Aug 2023 14:31:21 -0700 (PDT)
X-Received: by 2002:a05:6a20:9143:b0:132:d09f:1716 with SMTP id x3-20020a056a20914300b00132d09f1716mr224127pzc.2.1692135081028;
        Tue, 15 Aug 2023 14:31:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692135081; cv=none;
        d=google.com; s=arc-20160816;
        b=DlQYD+WU0U5VeFN4S+CG8Y8DwpqoO9vaqtp7UxuqEELLfxBTDDj5hNBagZjp1CX2n7
         X82IEFFSBHxBaJgyWGCtcHLM16oprPeWiAzMuRW4F0IdNgMZwOsRmtlbEu9RG9uk6yPO
         uoyPI+7NGxYqBVGygm5+RJFKAEJ7hGiUffzIN/bvJ5Pmub/0X0aBNbBELY1B/gD9yICr
         5StQx/PpMXxKfJTSimqjzoGv0HtNB98vvCGzNMJgkZ2BbNJEpUkfQCpVOcNgWTtDtJvN
         BaKnN727rSIToaqi+ivP7YzdelnoXfn8PTOKdFQvSOdzupGPazSPvx+hFBcFzHoI8oRz
         ZcZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=44nqP2+rxiy7+ftu8/29+SQO1/KKAl9lLgkE77FHuY4=;
        fh=PPGf9bsLPzzPBafbS//EiFSohmWhCJTIpDiaSqXvQhg=;
        b=TjRuTWe63EADpqt8/2x8n4jgYBW6wDl6CiCkptMOGg9vl4CBS1SJKeJNVUt1GLvnzS
         pwAk/2Yi6oxPLp8/blRtNIfC2VJBwt3zdNzlea3HnLi/UGrbu33Ysyi4LR1c+EFT5fD3
         lxdYzjDAZV3farHWkbyDCgHNSrLwBrG5VM/9ipx4AHl5R4WnMO4UDVs2hM3g24EefiXF
         EtzRQd2bBywWDm2bexI62SL+N4Ge+zz+Q7qqRdsfRrML9cooNbNueO2UddDG/7Zi8yVh
         4Mwchbp21zW7tXxOwClLjAwxnS5J8WbdxB2U7BjPeyFoEtwxSgKQg4VVDAeO8MPVSAci
         w9Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=YyXw8OtB;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id cq9-20020a056a00330900b00681f56016b9si830179pfb.4.2023.08.15.14.31.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Aug 2023 14:31:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5D6C761EAD;
	Tue, 15 Aug 2023 21:31:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 86368C433C7;
	Tue, 15 Aug 2023 21:31:18 +0000 (UTC)
Date: Tue, 15 Aug 2023 14:31:16 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Guenter Roeck <linux@roeck-us.net>,
 Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>,
 Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>, Oliver
 Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, Suzuki K
 Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Arnd Bergmann <arnd@arndb.de>, Greg Kroah-Hartman
 <gregkh@linuxfoundation.org>, Paul Moore <paul@paul-moore.com>, James
 Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, Nathan
 Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>,
 Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen
 <samitolvanen@google.com>, linux-arm-kernel@lists.infradead.org,
 kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-security-module@vger.kernel.org, llvm@lists.linux.dev, Dmitry Vyukov
 <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 kasan-dev@googlegroups.com, linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v4 1/4] compiler_types: Introduce the Clang
 __preserve_most function attribute
Message-Id: <20230815143116.17baaae9b91e1f1708c928a8@linux-foundation.org>
In-Reply-To: <202308141620.E16B93279@keescook>
References: <20230811151847.1594958-1-elver@google.com>
	<202308141620.E16B93279@keescook>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=YyXw8OtB;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 14 Aug 2023 16:21:43 -0700 Kees Cook <keescook@chromium.org> wrote:

> Should this go via -mm, the hardening tree, or something else? I'm happy
> to carry it if no one else wants it?

Please do so.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230815143116.17baaae9b91e1f1708c928a8%40linux-foundation.org.
