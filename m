Return-Path: <kasan-dev+bncBDUL3A5FYIHBBX5QYOTAMGQEEDTCEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C96F37722DF
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 13:41:20 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-348c2705818sf4744245ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 04:41:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691408479; cv=pass;
        d=google.com; s=arc-20160816;
        b=LKNZMyVVcaxmUovouSPUw8BxmBTSGv9TFG0ZTJXYAjcgI8xCFJIU9xLYMwTQvx5V1n
         obnyndYEaPIU+QeLHxlYebFZ8lRksUeNEsUKX78b6vlHXK4pr5Vpuksr8Vh3y4XQay9T
         xTd2uQLy1wxkA1F67BTncVc9FShjmgJ9Wbt2KKOtcn9kKJ0Pt0DzTVnWD0kUR5rywWVt
         zNf30VUDKJoe1DFSum5wbw4x8mFnsXot/6kRFYbbVgTFdYfbChSKnkPOUgUfzDpDHgd7
         2004HSR//N/5W4eACZA7XBG7lC8MJX2KyrZsbDOJiV3MWePjaPsTkyZa7X4Hd71/l+/4
         t01g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:sender:dkim-signature;
        bh=vkYKtnvV+yQ/RAvlZriFcwUQW6cxSAX4uQpy9gyZpEs=;
        fh=DNJA6HcCJhJZCmWWxaPFAvM+QLbC/Wv2H42SXIZ53pc=;
        b=tP/J8h5DfY6LIXu2JLvtiTA5BEE2LM4sSD7w6N7vcG7wPfxgsiNkHXgl8yWDRFQsGP
         AUUDWRvOUdNHrDv3kDEE6YPlEAIMdxcuALpfI0jI7s7Qsbq16eZ0q6CJ/kuCB0eahVtO
         CZzDh6AYjQ33tanBJlXRKXFq6BdXy5ezvTK/jq4lUxDZ3PktNlDZksheF/qnOQXjFCh7
         Cc4dmb+B1QlUVHDXue5Yk9HYfOWRuiGOVsoQtuXvmpn4KqtaFJqaVFMSgDUTTowPIEOX
         zwywmfdM3uu8mVtyNbTLtO77dJQY2vV1aRaF1uDRh1mdG6ijEvizTXw/RMdhAsmEOXHi
         CMnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=G+kX1ODj;
       spf=pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691408479; x=1692013279;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:user-agent
         :message-id:in-reply-to:date:references:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vkYKtnvV+yQ/RAvlZriFcwUQW6cxSAX4uQpy9gyZpEs=;
        b=awWav/loWaLRYvv4YsB1hKY+F19bNZyDQFJcLIuS4TnpAakmN9L9v/DfpnUdxcdtUZ
         LNOKm5yxSsh6WLAiPyFkAck2GWiyh1leYU/UCzBGznA4N9YaJ+xoVtFR5NobzaeZqm4X
         +CqKFSWwgaSeYQ4vVpJYPeezdXcWogCdnKbpEPB7403DtQjWHVin7noHdfVS7virQ6Om
         7QzRU9HDDnArjWr/Eyc9Gp4RU3V1392B9oblWrpxKN0doXaAG7E2/1zy5/zJ+3aKacHl
         5VcgdXKHJZDqe1EzDpwLgiK1JB3bAieVGUTb+Mq8izZQuuX8OqjCJ0Nk46cWgTWjF17j
         E+vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691408479; x=1692013279;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vkYKtnvV+yQ/RAvlZriFcwUQW6cxSAX4uQpy9gyZpEs=;
        b=hNmBGOQ8EUqnrSme2TCKpN3rLyugPUiSaEj4Rk1AMkEKmqDAaCAloSh7XyLupxQ7XO
         Z90q7E4G3Y2Ly4dJ6w7qOcXpaMTIk0H5u4HJ6YBjhk/TVX27IIS1okFeCCc0SREA7wGU
         Ewh6eKzhXMYl4w4GEHtmNFzHBBfM4xgdpPqwNAE4nsfUI9Jkdp3dOw434l+MM6URE6p6
         24lG/LI4CROs68FdwG7OXPbYpK16OppkVk70/uW7hMPkuksIsMQ2lEAarly/KOJYqNd2
         ZuuMMriuNLE3AlacUY+xjlha/rmes+180zVpPeZVaVr30wyNm6skgP4WEmLrr2a5FYs3
         Lv7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyqfZuYBkysS9CluEB+0CpKp/5a0QrL1gz8rwxxWtv1vUYfsB82
	ewWxPzA0RIe5qzkHaw2R040=
X-Google-Smtp-Source: AGHT+IF7x/Fybg6GG+LJqlDGuvLq4421NAoVWrdAc0zUkYYZ8udyB1N9IsNcLDkc2dveykWsRRMirg==
X-Received: by 2002:a05:6e02:1a67:b0:349:3c79:e634 with SMTP id w7-20020a056e021a6700b003493c79e634mr401109ilv.17.1691408479388;
        Mon, 07 Aug 2023 04:41:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:520e:0:b0:342:2a4b:458e with SMTP id g14-20020a92520e000000b003422a4b458els317557ilb.0.-pod-prod-01-us;
 Mon, 07 Aug 2023 04:41:18 -0700 (PDT)
X-Received: by 2002:a6b:ed11:0:b0:786:f352:e3d4 with SMTP id n17-20020a6bed11000000b00786f352e3d4mr11723017iog.7.1691408478494;
        Mon, 07 Aug 2023 04:41:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691408478; cv=none;
        d=google.com; s=arc-20160816;
        b=aOiFIncKNUhOAZ9oh4gcG8E68c0o5csDhZAueAIf5/LAa7zcxPEydKXuYKTfPEDWSw
         KT+EJk3xz/xkgYHa4JmahrLWRIbiOQuS3NymRgQW++AxhKpqV/zHLxf25q6oG0ZMlWcX
         wANLGSa+911zrJ1EVRq0ibszHRNdI9FO0P354JO8HWKP/IW3pHVA3HQ4YIBd1K1q9Ok1
         8Vzq3jn7S0vfR8K7aVHQc2AKKx7qBrKpshCClEtXjvwRvusXXdf9pWjntRX3LY75UR8t
         KXLyL9IBzruO71b+DU7sRAImQPm1nOzC/WRvJc/jcjWRiMOhD3l0oJQvl49wy4HzopGP
         G0UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:dkim-signature;
        bh=WmODk+CdskyMtYG8TdUz/Cv201lmsUcEqfPEQkGIYLY=;
        fh=DNJA6HcCJhJZCmWWxaPFAvM+QLbC/Wv2H42SXIZ53pc=;
        b=ttSuZlLt8pDrME1KmyuPulThD5h5RHEcnsHErkE5hT/CR+Y0CmyWdTgTb8pTvbu3r5
         uUaYufGRs5po0KBqXRj3hqRHPHfJ8mdagD0Hr/UiOl/3YssXgJtuEc9DWdNMkBeJTB6Y
         lL47gokyKddF6mOl9gyqUTtdoNBwQKRSjm8POQ5/ouDMoIsm44pSnJ1nDp09+5CysxXm
         oKYa2Ar758ImnN8S5ZRdC/w20Evf1vGs/FViHvuuvWwKeufX+W+MOMEYWQbpmTgJlCmm
         wIbOd9mELWh9YRTRbt0EmuXMlXTBbrbtbmOVmO4gXiu7pXLDT/yAqQMFOYYS0q2Rbz92
         vp+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=G+kX1ODj;
       spf=pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id bw6-20020a056602398600b0078360746879si582600iob.0.2023.08.07.04.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 04:41:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (66.187.233.73 [66.187.233.73]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-74-2LnRN-WnO9Klk1-rMuLD1w-1; Mon, 07 Aug 2023 07:41:14 -0400
X-MC-Unique: 2LnRN-WnO9Klk1-rMuLD1w-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.rdu2.redhat.com [10.11.54.7])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id F38281C0690C;
	Mon,  7 Aug 2023 11:41:12 +0000 (UTC)
Received: from oldenburg.str.redhat.com (unknown [10.2.16.12])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 72335140E962;
	Mon,  7 Aug 2023 11:41:08 +0000 (UTC)
From: Florian Weimer <fweimer@redhat.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,  Kees Cook
 <keescook@chromium.org>,  Guenter Roeck <linux@roeck-us.net>,  Peter
 Zijlstra <peterz@infradead.org>,  Mark Rutland <mark.rutland@arm.com>,
  Steven Rostedt <rostedt@goodmis.org>,  Marc Zyngier <maz@kernel.org>,
  Oliver Upton <oliver.upton@linux.dev>,  James Morse
 <james.morse@arm.com>,  Suzuki K Poulose <suzuki.poulose@arm.com>,
  Zenghui Yu <yuzenghui@huawei.com>,  Catalin Marinas
 <catalin.marinas@arm.com>,  Will Deacon <will@kernel.org>,  Nathan
 Chancellor <nathan@kernel.org>,  Nick Desaulniers
 <ndesaulniers@google.com>,  Tom Rix <trix@redhat.com>,  Miguel Ojeda
 <ojeda@kernel.org>,  linux-arm-kernel@lists.infradead.org,
  kvmarm@lists.linux.dev,  linux-kernel@vger.kernel.org,
  llvm@lists.linux.dev,  Dmitry Vyukov <dvyukov@google.com>,  Alexander
 Potapenko <glider@google.com>,  kasan-dev@googlegroups.com,
  linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
References: <20230804090621.400-1-elver@google.com>
Date: Mon, 07 Aug 2023 13:41:07 +0200
In-Reply-To: <20230804090621.400-1-elver@google.com> (Marco Elver's message of
	"Fri, 4 Aug 2023 11:02:56 +0200")
Message-ID: <87il9rgjvw.fsf@oldenburg.str.redhat.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/28.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.7
X-Original-Sender: fweimer@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=G+kX1ODj;
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

* Marco Elver:

> [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> convention of a function. The preserve_most calling convention attempts
> to make the code in the caller as unintrusive as possible. This
> convention behaves identically to the C calling convention on how
> arguments and return values are passed, but it uses a different set of
> caller/callee-saved registers. This alleviates the burden of saving and
> recovering a large register set before and after the call in the
> caller."
>
> [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most

You dropped the interesting part:

| If the arguments are passed in callee-saved registers, then they will
| be preserved by the callee across the call. This doesn=E2=80=99t apply fo=
r
| values returned in callee-saved registers.
|=20
|  =C2=B7  On X86-64 the callee preserves all general purpose registers, ex=
cept
|     for R11. R11 can be used as a scratch register. Floating-point
|     registers (XMMs/YMMs) are not preserved and need to be saved by the
|     caller.
|    =20
|  =C2=B7  On AArch64 the callee preserve all general purpose registers, ex=
cept
|     X0-X8 and X16-X18.

Ideally, this would be documented in the respective psABI supplement.
I filled in some gaps and filed:

  Document the ABI for __preserve_most__ function calls
  <https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/45>

Doesn't this change impact the kernel module ABI?

I would really expect a check here

> +#if __has_attribute(__preserve_most__)
> +# define __preserve_most notrace __attribute__((__preserve_most__))
> +#else
> +# define __preserve_most
> +#endif

that this is not a compilation for a module.  Otherwise modules built
with a compiler with __preserve_most__ attribute support are
incompatible with kernels built with a compiler without that attribute.

Thanks,
Florian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87il9rgjvw.fsf%40oldenburg.str.redhat.com.
