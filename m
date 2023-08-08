Return-Path: <kasan-dev+bncBDUL3A5FYIHBBW6TZCTAMGQEKBQWKLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 334EC7739EE
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 13:41:17 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2b9bf493456sf56351501fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 04:41:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691494876; cv=pass;
        d=google.com; s=arc-20160816;
        b=FXPkLWAQPA5ff3BxEqrz6smqsTo1Ln9X3sigsAHJXRrs/u8PhMKw/pV0nL76DIWAPu
         SInmmXkv9zA0Nx4TuEXC7RSb8rwhmxJA6/iUeThKgyUNWYd7lP2HEpvx5tzFCGT3Stb4
         2SCRd40m68KdIpA5NcwyhsK6NxO/tNPW/nWvL5ulEST9cKZ+1h1dK54y07akKcxybJ5f
         xEA65AxetK6/t2ddPXhSkz/1dNQRbJnvNmG+3t47W6kI8CUCEzh7uxLiRAtyUqLlIIDP
         +uoaK0Rz6tjQTBffgmR/wP+9aZEFgJpFJ1CGcQVTmfffRU+Rv3SVT2/FZshPL8GOqqFK
         dcfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=odPx+5wdzB2so1r7RYRRgmIRtN4TDx3Ds/yx7rhYF8E=;
        fh=shlGGbApy7qGdDHB+lq6z5bM4NEXnY9gUBYcpu2vW9U=;
        b=GP1Vmu4ilE5I3qQkOkpWxDci8pAg39k7QovAfiFXdNJF9ibuM7cFPVojt9PWqVmYhA
         F8xraPLJBITjDzxvzzDRLCA0qVVkpHor0kU/TXR6uJ6dfCuoal/r+I/OwKOVaXA/2gV/
         SfMIMHrA9w3IlGwQOG6V+Jmg74aO6sE7lkdcMWayak5YeVv+nxzDL89XrJzIFl4kLW10
         RmvENj21uzfBjul0JpWcOPNE36UlcIAedPSQt1JACNf4eofC0fgenP5tLDkr3CWfKXS5
         LigHfOqicHfyAOBvkBW0ebYqSHDOnTC3yvdbiahuiLKql4cHCnUbfQf3ifuUBm2vgRKB
         FS9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BDiB5vuk;
       spf=pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691494876; x=1692099676;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=odPx+5wdzB2so1r7RYRRgmIRtN4TDx3Ds/yx7rhYF8E=;
        b=oTrHOO5VX0N9h3/fJPw7saP+XhJVMDgY3nnc+C6Qv9YoVQg2mPKZYvMpdp+LR2mUcx
         iBYU+iSEfFKHTTRjtkMRrgrDG6mAEdALrLD6/m65pJRjHAKTVbEZ8UCsAuJvGDCm4+DE
         UGNtMekDsIPy3G947IAPyJyiDEARyOgqhFjDVAxkYxLuPyjggwxaHcjaffzDGvdHR//6
         +NRP8ed/mEq/kbF01iVldCeC2X1Z8UfWlmqHr4jXpQY2RQrFa9kriVyeDA61aE4uQUSZ
         ArVFG/iQlZPqhKwwMGfa00KeNvVTsOqBobBlq3VtxxNM5ELcYa4zwqK9LPiGdVGxJSxw
         K93Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691494876; x=1692099676;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=odPx+5wdzB2so1r7RYRRgmIRtN4TDx3Ds/yx7rhYF8E=;
        b=JhpeJwmM6Fsae9NPPgByCt1NqeY4SFpf4+aSQ8/MvVmQg1OMaGHtHlVPGKmERrGOpk
         ldfqReYCViWATZKDCNdoAuK+qnFUMaNS3AKZHD4935YhElSqiAkhkKe7q8u+zqeUeed6
         lsMI6zrc5j97I5NTOwRmcQUh8ckrKXbtES6mnhXQZRb4Qh/ZXkHO6XPV4w3swmTxhzwS
         uY8ZdCJ2b4TfLeYCACecS2ZAhw/Spec+a6VTDwroKaOooRCq9d7TYq/l1bn5p+SORE9i
         yTpRTZxg0/h5j1OCXR5D5KqhVnV5DSln2XuSvQZE8CkDCKPsbea26fw3r130mP3t+Ens
         HJnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YziZhGORiX+cun/tOWOmBeuTBh5AkArvJjoexUq7dXDcw+Af8gz
	/eqAi56OqWEHiwrs9xJbjrM=
X-Google-Smtp-Source: AGHT+IGmYjYzgepZIwzE6aDaCvithTmRFWPUDnXA7YKBhTO5qIWjX6swXOxUc3rSs0AnMlcJWiJLPQ==
X-Received: by 2002:a2e:968a:0:b0:2b9:cce1:712d with SMTP id q10-20020a2e968a000000b002b9cce1712dmr8619360lji.41.1691494875606;
        Tue, 08 Aug 2023 04:41:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1b:0:b0:2b5:8027:4784 with SMTP id b27-20020a2ebc1b000000b002b580274784ls25434ljf.2.-pod-prod-07-eu;
 Tue, 08 Aug 2023 04:41:13 -0700 (PDT)
X-Received: by 2002:a05:6512:348d:b0:4fb:76f7:fde9 with SMTP id v13-20020a056512348d00b004fb76f7fde9mr7783040lfr.30.1691494873642;
        Tue, 08 Aug 2023 04:41:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691494873; cv=none;
        d=google.com; s=arc-20160816;
        b=oBN4vojRuE7BABdUjJQNmaPvf5AGhBWXfQtB9KVzEa/mP5a0qejD9MhVF7GiygB+1z
         jkbQx7WYgFXdUDBgEpUrBe5zoxaZp12Pe3+4nI3WV6imCG7nfDY7yIUDoReO68Yqccl0
         Zmld07I9VqBjCp9bgwxtZNzOPhDnbnQP61O4N/Snv3SA2SDdW7mmNC5lWdjE/ZksL2K3
         CuKnYw12aj98qESsFZGqGrTgkm6C23OJD7R02SahXrAbXDDO1KFupbaYOpSJjWhCELdS
         xACPAUmTcEIKr3qrIg3Rf0ip7cNZanNeyjkAGGczHOiiwarpmiYMVxKgtV2TWLGElpMt
         LDUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=LpOwTgxUQueKTTwOJlS9a4DMbQJlgeLRkDEjrIokCAc=;
        fh=shlGGbApy7qGdDHB+lq6z5bM4NEXnY9gUBYcpu2vW9U=;
        b=S7IvyWmG8dRXLSguJp0pPoPdsEP07DGUy3GCPUR+0Y1f7sdFRr1O1zyLwNmYKttBiH
         NUDIZs9asLVSXOu9J9eQ9kppLMenr5ZQE0v+3ohcVbXwW6Pfyo/SWLN4+RrUotWsWQz+
         uhMKc5woLKB5EJ8rqYuTPx0CXtYV3SU6u/Xzs1exkvUvPhwm4BBRO67/BPZPDwuBswUY
         B5ueWi52YEd3L1V0HxK/vv8vGoLJv1j9i5WpLnbJ5eIfujEwdRRt6UPUH2y/HP8hbOOT
         irBTfCbxFy+SHR55nh6OljrmO3eFEP3u7quIHD+lTkZB9ohwJfYDZaxRO0MkvATmu9kp
         VZlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BDiB5vuk;
       spf=pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id v21-20020ac258f5000000b004fe3478235csi668239lfo.7.2023.08.08.04.41.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Aug 2023 04:41:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (66.187.233.73 [66.187.233.73]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-678-x_BVl-L4N6OBZSXsqfsgqg-1; Tue, 08 Aug 2023 07:41:11 -0400
X-MC-Unique: x_BVl-L4N6OBZSXsqfsgqg-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.rdu2.redhat.com [10.11.54.3])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id CFA37381AE42;
	Tue,  8 Aug 2023 11:41:09 +0000 (UTC)
Received: from oldenburg.str.redhat.com (unknown [10.2.16.12])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 462E41121314;
	Tue,  8 Aug 2023 11:41:06 +0000 (UTC)
From: Florian Weimer <fweimer@redhat.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>,  Andrew Morton
 <akpm@linux-foundation.org>,  Kees Cook <keescook@chromium.org>,  Guenter
 Roeck <linux@roeck-us.net>,  Mark Rutland <mark.rutland@arm.com>,  Steven
 Rostedt <rostedt@goodmis.org>,  Marc Zyngier <maz@kernel.org>,  Oliver
 Upton <oliver.upton@linux.dev>,  James Morse <james.morse@arm.com>,
  Suzuki K Poulose <suzuki.poulose@arm.com>,  Zenghui Yu
 <yuzenghui@huawei.com>,  Catalin Marinas <catalin.marinas@arm.com>,  Will
 Deacon <will@kernel.org>,  Nathan Chancellor <nathan@kernel.org>,  Nick
 Desaulniers <ndesaulniers@google.com>,  Tom Rix <trix@redhat.com>,  Miguel
 Ojeda <ojeda@kernel.org>,  linux-arm-kernel@lists.infradead.org,
  kvmarm@lists.linux.dev,  linux-kernel@vger.kernel.org,
  llvm@lists.linux.dev,  Dmitry Vyukov <dvyukov@google.com>,  Alexander
 Potapenko <glider@google.com>,  kasan-dev@googlegroups.com,
  linux-toolchains@vger.kernel.org,  Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
References: <20230804090621.400-1-elver@google.com>
	<87il9rgjvw.fsf@oldenburg.str.redhat.com>
	<20230808105705.GB212435@hirez.programming.kicks-ass.net>
Date: Tue, 08 Aug 2023 13:41:05 +0200
In-Reply-To: <20230808105705.GB212435@hirez.programming.kicks-ass.net> (Peter
	Zijlstra's message of "Tue, 8 Aug 2023 12:57:05 +0200")
Message-ID: <87pm3xhicu.fsf@oldenburg.str.redhat.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/28.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.3
X-Original-Sender: fweimer@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BDiB5vuk;
       spf=pass (google.com: domain of fweimer@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

* Peter Zijlstra:

> Now, the problem with __preserve_most is that it makes it really easy to
> deviate from this pattern, you can trivially write a function that is
> not a trivial wrapper and then does not show up on unwind. This might
> indeed be a problem.

Backtrace generation shouldn't be impacted by a compiler implementation
of __preserve_most__.  If unwinding implies restoring register contents,
the question becomes whether the unwinder can be taught to do this
natively.  For .eh_frame/PT_GNU_EH_FRAME-based unwinders and
__preserve_most__, I think that's true because they already support
custom ABIs (and GCC uses them for local functions).  In other cases, if
the unwinder does not support the extra registers, then it might still
be possible to compensate for that via code generation (e.g., setjmp
won't be __preserve_most__, so the compiler would have to preserve
register contents by other means, also accounting for the returns-twice
nature, likewise for exception handling landing pads).

But __preserve_all__ is a completely different beast.  I *think* it is
possible to do this with helpers (state size, state save, state restore)
and strategically placed restores after returns-twice functions and the
like, but people disagree.  This has come up before in the context of
the s390x vector ABI and the desire to add new callee-saved registers.
We just couldn't make that work at the time.  On the other hand,
__preserve_all__ goes into the other direction (opt-in of extra saves),
so it may be conceptually easier.

Thanks,
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87pm3xhicu.fsf%40oldenburg.str.redhat.com.
