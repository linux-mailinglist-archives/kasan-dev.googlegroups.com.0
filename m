Return-Path: <kasan-dev+bncBCLM76FUZ4IBBOVY6S2QMGQE2OBJO7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EAE3952470
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 23:06:04 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-39b3e12769esf2997785ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 14:06:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723669563; cv=pass;
        d=google.com; s=arc-20160816;
        b=IQQGIRKqJ0Q83TgSOQcNSd/NBLnGro9JBuM/2lCmAbGbYWBVRFolOkmXlCnqXt9wO1
         qRulRtjVLqBKYH5wBRvvJ901nmHBclscYRjxsjtgxHmkhrD8RTnf4Ask3FU0ucA1qpOR
         mA/wRDy8UkXZtrqd1rpxt2r0UMGz/n0M9IP/jsc+P+2cBV9CwrtJWTBlrDNEqpoZJafk
         myhMqRpUWuAsn4n793voT/NHdNFZD2sSnXOPC1Z+M+ow8JxPzSuwryS8xsZsrCXw3Kvd
         Zdvh9um3l+J4BT3ggwcgGLzNToBNUjk5BqMYvg/OOfAUHxz7WrGza0Qv19Qz9kXmhLSo
         RXzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NDGsdDlnOacYZEZNOezfdUhSXYe3SlbWSVEIaD42VpA=;
        fh=wPZJAagMw+r2Zw6Og/9zdxjtm1rzcZqeC/KKHdf/D5U=;
        b=C+N9RKZqWHzksvcVKhB4cHm8KQApJyd/Ov02jnpJFj7yahDTuXzKIVZFtdPsdaszuP
         POksYmTRn5ESse1UfsiHZ3Ap+jfBMns6MW9qtYbHaNr8vX7zu/ZxQJLes3t/mCpCKGn3
         Sby/S2iGeo14LAx9oegSjv163M/V3lqDckXF36llftxaYyNyQyki2GLmsOuHAfKljerz
         I+KbyXgz8hcWmKh9ey8eelPXoAJOYfNpfKz9mKyCSVYTNbVTd/vIqTfR9YhLmz+pY3NW
         ZPjsJdE7rCRcHKDNKDdJUvw5nbnfDk7JLe2HyKAa0D/24xnrNP23Cro30jVzKF/ldElW
         VEag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=032YVWE0;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::92b as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723669563; x=1724274363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NDGsdDlnOacYZEZNOezfdUhSXYe3SlbWSVEIaD42VpA=;
        b=YMOhEwXyzPw5SJljKgETknqLhkA8yP4pIPFO9fv4lmC4KaVwQzzqbYj9IXe9B8PYW7
         K4H8w2FyKCZ0oFA79pnTg0howgMVwbPFHuZ3bs9mj5CyTXNTzhbNroeVVCofW+QRGZDi
         Fh/+uF7AOC3Br1Y2gMVc35B3PDgI14onLNtlPlKbFBGT8rqK9Hfwwcfa/6CT0yRGeIAt
         bSDxH6QBac2gbyYDMTq7/BXggkD8Xry76gGCk4HjmIwRvEC6/RZ1KKZg5nutY8XeKPTj
         XraqiX94KaLZq3TwqbwvfOgZbOKplHF9nKBDyL0EZ0+kes/PdZ8e5Qzin7n29vRUMIm3
         Qpsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723669563; x=1724274363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NDGsdDlnOacYZEZNOezfdUhSXYe3SlbWSVEIaD42VpA=;
        b=cwRtytGapbcD+PuinV9WxTisXYB48hKOsqHeCB97J3jAb/0gHhZeQofTsZpRcxh2Z+
         jor2udL8F2ik7BkJ0ZaXbGzpDiCgAuQJOpBSYwmS676B4v9ay6bl0DaBF+1gKDz1suJZ
         X7nMOtzXgVTJJXISj6gLnRxFsQ54Z/A/VBvjmZsyHvxWPuIbuA9gtEX+tFone0PYk10K
         NjsCUKDCun0ZNVp+7EGPjb0Afm2lUHNAHGaxSByc+3FGDwfIDDvuIzUFuArd1CYm6fos
         rkjBCebc/0cGdOiVDO0QiLyxdOemaYtZVSXLSKOJgZ+7rsVTNab48IVNrB/+cMrTFeeW
         Yzog==
X-Forwarded-Encrypted: i=2; AJvYcCUv1MzivzSETBokpW7tPtkcIHtMKsaYISKKQRrnV8dVlBrKzzowxSK2aUbsdKwl4gqQv13zuqz5OGBWRHDmL5iR6DZoFtfKqA==
X-Gm-Message-State: AOJu0YwczIK1asHvhHKMz/+q1tlnFpusgAA4ylBdeTFqRZ/rhLpLAUAf
	etBxHBwvA9GamkNY/uEHO/oNz8+jg9C+GK1hyC5IUxJcGvNcJlQj
X-Google-Smtp-Source: AGHT+IF01uKdIRuO1bnra6efuPU8TBVsNcK31+F3vNMsYiuy687ZBGd8NfgdEArUH+AFEsOsgNtu9A==
X-Received: by 2002:a05:6e02:17c7:b0:399:ed4:6e9e with SMTP id e9e14a558f8ab-39d124bfdf8mr54059085ab.17.1723669562969;
        Wed, 14 Aug 2024 14:06:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2186:b0:375:b30c:ffd with SMTP id
 e9e14a558f8ab-39d1bc97bd7ls1915415ab.2.-pod-prod-06-us; Wed, 14 Aug 2024
 14:06:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXAeAz+AkzMBoF7LLaCX6c5W0qEita2NKj10JafTBYynh8dpAVjx8uYJC4oDaAiJ0FOtt9h5ES8YaoGSsKyBgd7yoW6agOlIDMs0A==
X-Received: by 2002:a05:6602:27cb:b0:807:f0fb:1192 with SMTP id ca18e2360f4ac-824dacd5afbmr612745639f.1.1723669562208;
        Wed, 14 Aug 2024 14:06:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723669562; cv=none;
        d=google.com; s=arc-20160816;
        b=aEqO9VpOxqHOgsPLvfCY+Zxl/7ZN3u6AGT5NNHJq2qxwdwLhU8iHX16l9zkFdZUs7f
         Ca1IewlxAWus8QBA9ZiZy1RYF5ELZo3fzb4aCMF66ym9yvwe0b8iceqpWHw4VryrxTMB
         CXlTyFJOnTEdkfWoVCKpCYuO/nELDWexagI0IzfJEsGP00rroGd+IUYvVVlY5CmILGo1
         TKzqZGawbRZCiyiIPX9H+bKMZaKtUtid64Ib1eGvdLsIy4yyNWsjc4Uo38TlScMJpwsp
         ePr2aCN1Nfa8UIxzqtdW3SNmO5wjOYJ57SPtMYD0RSmcRos+nm0bi2/idUm6GF66fNsR
         LD3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pZKLox5eS3QRtbNUFn2cEECTACt7m3r5KD0Nhy6dpnY=;
        fh=UKWkPjsTBL5c3Kwleyg+l1kGk2SlwXXd+Dy7qWhDIKg=;
        b=je3/wYlX42Ze8cYHPf889nhv3144L1JF6EqEilXljyvSUv2gTPuUrHJarSrvIpvWUy
         S7x2tz7jzSw4cAsKiQ6LoVrpJ0MH+Gi3rFBYX38Wi2bHhxcuASlatIg6KwGHDVSU0OFi
         mXJU1n9VW60xuE4ZG7kTbsL3i8zmUkDUDYFt8fEhW6UZxlJJDs3La2/HSngD6eqSqREk
         HlDcnOK/qAew/vMNPhRD80zX8N3jjI4iUTSojVqOZ8gTFJE+PSafopep+sFVoRpQhfmY
         NvwDkSZZcpue9ntHvVgVghtvv0dl2OElRqzA2nEoAVSo9Qdg6M1unPIfXPtEYyaJaUtC
         c8Zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=032YVWE0;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::92b as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x92b.google.com (mail-ua1-x92b.google.com. [2607:f8b0:4864:20::92b])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-82267273b3asi41506739f.2.2024.08.14.14.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 14:06:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::92b as permitted sender) client-ip=2607:f8b0:4864:20::92b;
Received: by mail-ua1-x92b.google.com with SMTP id a1e0cc1a2514c-842ef41238fso96336241.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 14:06:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWblH8R1f4ctebIMatWRzqVBpfR5MMGELZe7MqjNC98ktWK2zb3/hkhvgflFE2NdX2A/rWmjbEkAk3OqSRfwqWsOObAB1fzlHg2NQ==
X-Received: by 2002:a05:6102:6d2:b0:48f:461c:ab86 with SMTP id
 ada2fe7eead31-49759928e16mr5099648137.12.1723669561306; Wed, 14 Aug 2024
 14:06:01 -0700 (PDT)
MIME-Version: 1.0
References: <Zrzk8hilADAj+QTg@gmail.com>
In-Reply-To: <Zrzk8hilADAj+QTg@gmail.com>
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Aug 2024 14:05:49 -0700
Message-ID: <CAFhGd8oowe7TwS88SU1ETJ1qvBP++MOL1iz3GrqNs+CDUhKbzg@mail.gmail.com>
Subject: Re: UBSAN: annotation to skip sanitization in variable that will wrap
To: Breno Leitao <leitao@debian.org>
Cc: kees@kernel.org, elver@google.com, andreyknvl@gmail.com, 
	ryabinin.a.a@gmail.com, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, axboe@kernel.dk, asml.silence@gmail.com, 
	netdev@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=032YVWE0;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::92b
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Justin Stitt <justinstitt@google.com>
Reply-To: Justin Stitt <justinstitt@google.com>
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

Hi,

On Wed, Aug 14, 2024 at 10:10=E2=80=AFAM Breno Leitao <leitao@debian.org> w=
rote:
>
> Hello,
>
> I am seeing some signed-integer-overflow in percpu reference counters.

it is brave of you to enable this sanitizer :>)

>
>         UBSAN: signed-integer-overflow in ./arch/arm64/include/asm/atomic=
_lse.h:204:1
>         -9223372036854775808 - 1 cannot be represented in type 's64' (aka=
 'long long')
>         Call trace:
>
>          handle_overflow
>          __ubsan_handle_sub_overflow
>          percpu_ref_put_many
>          css_put
>          cgroup_sk_free
>          __sk_destruct
>          __sk_free
>          sk_free
>          unix_release_sock
>          unix_release
>          sock_close
>
> This overflow is probably happening in percpu_ref->percpu_ref_data->count=
.
>
> Looking at the code documentation, it seems that overflows are fine in
> per-cpu values. The lib/percpu-refcount.c code comment says:
>
>  * Note that the counter on a particular cpu can (and will) wrap - this
>  * is fine, when we go to shutdown the percpu counters will all sum to
>  * the correct value
>
> Is there a way to annotate the code to tell UBSAN that this overflow is
> expected and it shouldn't be reported?

Great question.

1) There exists some new-ish macros in overflow.h that perform
wrapping arithmetic without triggering sanitizer splats -- check out
the wrapping_* suite of macros.

2) I have a Clang attribute in the works [1] that would enable you to
annotate expressions or types that are expected to wrap and will
therefore silence arithmetic overflow/truncation sanitizers. If you
think this could help make the kernel better then I'd appreciate a +1
on that PR so it can get some more review from compiler people! Kees
and I have some other Clang features in the works that will allow for
better mitigation strategies for intended overflow in the kernel.

3) Kees can probably chime in with some other methods of getting the
sanitizer to shush -- we've been doing some work together in this
space. Also check out [2]

>
> Thanks
> --breno
>
>

[1]: https://github.com/llvm/llvm-project/pull/86618
[2]: https://lwn.net/Articles/979747/ (Arithmetic overflow mitigation
in the kernel; Jul 1 2024)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAFhGd8oowe7TwS88SU1ETJ1qvBP%2B%2BMOL1iz3GrqNs%2BCDUhKbzg%40mail.=
gmail.com.
