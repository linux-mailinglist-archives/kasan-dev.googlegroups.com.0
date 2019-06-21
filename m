Return-Path: <kasan-dev+bncBDYNJBOFRECBBBFZWPUAKGQE2WN2FIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id A83514E937
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 15:32:53 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id 18sf7542724qkl.13
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 06:32:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561123972; cv=pass;
        d=google.com; s=arc-20160816;
        b=sYQPNQphY2FiV7QlgVwYOGs0U2trO90s72PjBRRgSP+/z9385fGXajSZpiazvkU6KO
         TNW1XFgeNq2GEmMPUHYkbPuvWWWwAMnlRrqtLBVSzUGnHDWxC6SkNCnBKsfXTV3RNe7V
         189qBOqbLFM+bUeZE/WH11GA9w9dIy8lL6MDL4QV1Y0ioUan+qF5zBa1CiLojU3+2Bt1
         7Em7/4RZOcc3XmQ4g8f8PnII7fO0Gl0k6iDnvOGd7Pl4/grKqNg4IINq6beEq+RtrG3w
         jaPTMLDV7Ffl3FpDHDa8r/Rtx7ma6MfCdlQy8u3/oduwz6PGNlNDjmeI87zgaSjKnydF
         JJ9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=aEugmqYqEM/0rYWEZ2krRfJhWIcp3NZQRNRI2oL5z2Q=;
        b=bZxy+ONgrcguPqKO/QdstQq9l640TE0KRYjb3GHXD+WjeJWrh7hS8pKuuxs2oGJVcJ
         W5o9wwpHbTP3AFL6Seh2bWBcN0ITFr1ZzIwDLh6E6JSRmHy/vb70bNryJIBWELbDLisZ
         m/I+/gRpOKe/b0Ye0WcJAaoPu4XH2dZ0nZQVdJo2gKwmWx735rqoR5AYfF6B0VAc0uZ/
         hHF7XFZo0S5zGN59uAAY+GwLQR4hnqtEKtjU43Pq7PeaYOPQ9yPdeyabA9SyvzPABsT1
         DtB3RBDF0GnaFJV9Xn6w6YcGel4pT7m9TT4WZc7HE7a4S7ZX/Ip56ePo2lGDf5jQEeyl
         GWjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=G3vi2AAO;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aEugmqYqEM/0rYWEZ2krRfJhWIcp3NZQRNRI2oL5z2Q=;
        b=Fspk2VJfguP25BeYAJBfH/4uOBKOlfW9wfTOt7B1e0nZfCLIfubEl5+zCmzAnyoeFT
         xx5NZYzXkwB4zc8K5lZo5AprRctbCPXssyZJlcQeTfo4JpVjGA1LownNOJ9oCKFYnGWq
         yBkDEiTLYlnePTRJhR96K4f7JlNdHPIyU7IPFJ9xrLt8kFLeP37eH+cbuf5OAtxYcZyD
         B9y3D5DFkUpnVswjFsaWEJuHFMSfYR00n01nuFjDfsJoGsHp6gkuYEnrgj3by0GJW+02
         1Xb7TiKnNm6z54AC5q+nWMBEia9gZjjImKwdnXeiSBO8niRuzyG79KpUjbiwu9+hEt/U
         o6Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aEugmqYqEM/0rYWEZ2krRfJhWIcp3NZQRNRI2oL5z2Q=;
        b=fpSVahfeoonGJC5wB8uCNQPgmYqJ3Sdw6LN1WMeGJrZ/dVGjs+1RcBsKlTjxfULMJ5
         bnee/mBbdLoetSUJuSRb8XaMkAwT/9y3c/YcyJJfP5Gx3fEIY6guJ59MW7E1h3Y0Ic2u
         7uYIWGwEbB+9ezFOK3dBl3qdGamdyNlEnsqApQWc21AJAy3OA15OhFTEOBI3uWoeWcHf
         9z99AZRPIqmawcR5+SBkT6UXPydRZtE6JrlOHl9MKNpES+9ZT7GS+7agX1+GGCPVcqqN
         GaJ/CD6gDz+4pSBDXklTNLMSSLIlrB+Qtq8wOPs65XkCca9clj84h8w1Qb/DLMYajiQw
         2QxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX58w2fu+dErwCYO4Xn+bDaBQcRlh+z/v5NqCFLueU7nQvknA5b
	V5E6uTNXu57DipuMW6auzLk=
X-Google-Smtp-Source: APXvYqyr0CcYUl2WBO4e5ZeqixjnSw/7aTj3+hEZ4iov/KKKvNH+IKla7cowYYlcrS2qAWeWNm2aLQ==
X-Received: by 2002:ac8:2f90:: with SMTP id l16mr102169432qta.12.1561123972379;
        Fri, 21 Jun 2019 06:32:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7541:: with SMTP id b1ls590207qtr.10.gmail; Fri, 21 Jun
 2019 06:32:52 -0700 (PDT)
X-Received: by 2002:ac8:2f07:: with SMTP id j7mr105616537qta.359.1561123972146;
        Fri, 21 Jun 2019 06:32:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561123972; cv=none;
        d=google.com; s=arc-20160816;
        b=yBj24MA+PIsmWQzNzcDDEuZOhTWGRiWgt7/lYA5oi5hQvS2mhitnxmZZRXspEbfZcj
         Q2WADKj9RKgwPV3MbBuOYkv8sKvveiFdFAh+ee+9mQwnQM3LBMe4ZgCb5JD0HGO9ixDY
         ChYEWnc7kxBd/xzCWUynFbK5+F0BmE7ZkMrp78fozanrmmvm83dQzci29IPreedn8IHE
         ZlgSIEm3GoAzbu093oyWwg32w7qX5o9tudAuoS6YEn45/jKNAvzlUwNQC81vkPU9LLn0
         u4oH3Ys9tN8DLHAcI4aEmksAieL+OmjX+LIR4jorEOJCJLVm/M4gaut8TkVt9QqXPaYV
         M8FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZOu+sVSXpOqICESmggSM2r4CPCyuPx9bs4vYuIKuU68=;
        b=J28iTpmlbSgPnC0/MaDlUIFcUMTn7qHOQxpIyAZlSk24G1Ikjmd/CbZOqAWsCzVkac
         y0T1C2KrOuOkxBSXqhaZXhLhZ/Mk3qgdyXJgnYH7qSV6Ldq52DmMhhD1Q5GR8QL25HbH
         qIthVE/mw+gAuNeAsAOqdkUqV5lZL4hecjV8nuHK38189cLUdnCyHbbgINIeEJP0JP2e
         /2o2jfeVCeoi7s+cTBnxUZQahQuOYlJt/tC0Y7YZRTF70iHIjLVwijnD7n5u0Mvb7bnc
         xLWRiAH3Uj/sGtlumDxo09FZvRlhsG9O0wiBIKYYOtIxSk05kE4eFZtib20/npIvYKqn
         6XUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=G3vi2AAO;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id c39si137337qta.5.2019.06.21.06.32.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2019 06:32:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id n5so702937ioc.7
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2019 06:32:52 -0700 (PDT)
X-Received: by 2002:a02:1a86:: with SMTP id 128mr8265567jai.95.1561123971509;
 Fri, 21 Jun 2019 06:32:51 -0700 (PDT)
MIME-Version: 1.0
References: <20190618094731.3677294-1-arnd@arndb.de> <201906201034.9E44D8A2A8@keescook>
 <CAK8P3a2uFcaGMSHRdg4NECHJwgAyhtMuYDv3U=z2UdBSL5U0Lw@mail.gmail.com>
In-Reply-To: <CAK8P3a2uFcaGMSHRdg4NECHJwgAyhtMuYDv3U=z2UdBSL5U0Lw@mail.gmail.com>
From: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Date: Fri, 21 Jun 2019 15:32:40 +0200
Message-ID: <CAKv+Gu-A_OWUQ_neUAprmQOotPA=LoUGQHvFkZ2tqQAg=us1jA@mail.gmail.com>
Subject: Re: [PATCH] structleak: disable BYREF_ALL in combination with KASAN_STACK
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <keescook@chromium.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Popov <alex.popov@linux.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, 
	LSM List <linux-security-module@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ard.biesheuvel@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=G3vi2AAO;       spf=pass
 (google.com: domain of ard.biesheuvel@linaro.org designates
 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, 21 Jun 2019 at 11:44, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Thu, Jun 20, 2019 at 7:36 PM Kees Cook <keescook@chromium.org> wrote:
> >
> > On Tue, Jun 18, 2019 at 11:47:13AM +0200, Arnd Bergmann wrote:
> > > The combination of KASAN_STACK and GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
> > > leads to much larger kernel stack usage, as seen from the warnings
> > > about functions that now exceed the 2048 byte limit:
> >
> > Is the preference that this go into v5.2 (there's not much time left),
> > or should this be v5.3? (You didn't mark it as Cc: stable?)
>
> Having it in 5.2 would be great. I had not done much build testing in the last
> months, so I didn't actually realize that your patch was merged a while ago
> rather than only in linux-next.
>
> BTW, I have now run into a small number of files that are still affected
> by a stack overflow warning from STRUCTLEAK_BYREF_ALL. I'm trying
> to come up with patches for those as well, we can probably do it in a way
> that also improves the affected drivers. I'll put you on Cc when I
> find another one.
>

There is something fundamentally wrong here, though. BYREF_ALL only
initializes variables that have their address taken, which does not
explain why the size of the stack frame should increase (since in
order to have an address in the first place, the variable must already
have a stack slot assigned)

So I suspect that BYREF_ALL is defeating some optimizations where.
e.g., the call involving the address of the variable is optimized
away, but the the initialization remains, thus forcing the variable to
be allocated in the stack frame even though the initializer is the
only thing that references it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu-A_OWUQ_neUAprmQOotPA%3DLoUGQHvFkZ2tqQAg%3Dus1jA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
