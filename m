Return-Path: <kasan-dev+bncBDUL3A5FYIHBBCOOYOTAMGQERQBO6PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A5A2C77246A
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 14:43:54 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-349156848f7sf38038015ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 05:43:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691412233; cv=pass;
        d=google.com; s=arc-20160816;
        b=XgFodqp9mhChK7i+4iHDgBWxRZjkN6NcyarfCM4VPqRDWowC29rPJh/zvQqFdRqKLc
         VrVZl1RAlQsbkFTkN7OafOf0+o2LA5wlNhEbbsMCujH+z/Gm32XRUhpl5rrlyUAjGOrW
         t7boV5DXeojBpzZ5h8sjI9vPEiiazJyGuFEBhrovlzGrfxQPxxAUtPBYvGoZEUwrZDXy
         W7lXrqspZU3nqMydepYy5bF3NSFRPJxDAK/v0me3QfZTgrtZobA+u9L9q03eFiJPSQ/H
         pOkN0C5rcHKkv+QUi90212z92hSDZfydD/tUl7ZEWWtZ6KH17um9/8O9DglwKDVEdIvg
         /rgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:sender:dkim-signature;
        bh=8wn/2HPCL9HUYe0NWoAQD1NOlXSrMs/uhCoLeYs4nhc=;
        fh=KutyjcbQvQAObT73hZ9+Mk/TI79Vc0CV6w2Xk+1Erfc=;
        b=i9jzDXqbqx2SwaW2bbWyPyUv0CjDuVQnz9d16PcnPkz8r5Kx/bSYaLsIS3euM6VERv
         kmqNVKNWUvxH+wrgiVtBJO45NrhoorAUiyEyxpWmNJEKjRsC7s/rNObhpy1Wkgo4e4UH
         nxoB0VogaUhahgsRn2/L8qRyz6hxmXVjh7/WCcO4l2cxHSh3RXvANkj7Gb18aAmG1B/3
         /Tc9an7Pr6QEw5IjfJ+jJrcvsUSA0TDPGOs7cSb7sax9ijd5HtAmhXAV0MGILnTAmi+3
         /Xs36Hjt97eIBGblbIWg73wAFqyXhB2aYd9JHz+CdV4dG/cYS7c8nMTolVfwvZNg+5V7
         KsQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LSz023+I;
       spf=pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691412233; x=1692017033;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:user-agent
         :message-id:in-reply-to:date:references:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8wn/2HPCL9HUYe0NWoAQD1NOlXSrMs/uhCoLeYs4nhc=;
        b=Y89d7I4vtAwMnYyhZ1qQmkP6rMue8orIchtg6l5Vys8Y+SmONxSEO4gsg4/IXlAKcR
         +lDnEzZAzUlspQb704wzBi+MsFIz6p8W6x5HgKU9tVWGr/6O0MfH/fdVd0KDP58Y32Q0
         V+1jb0R1uvKHcZVIrEtRqwa+OvWmki6rPgQ6IhV4yfC+fB8piKC0VWOQno6v0bXO0dCW
         u140tRz3hpVIjt/K7XKAIkWpNatbxRkg53xshQtqH2wQrZf6hV7uYYVMKNVxPeI8Wt0W
         qPFw4LcyxG3gEU2KNdNzDP+lgxXADYgvdX2v6sUKONMcmqzGZ1GPVtNeqEBq9Zz7Gwlf
         edMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691412233; x=1692017033;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8wn/2HPCL9HUYe0NWoAQD1NOlXSrMs/uhCoLeYs4nhc=;
        b=GpootqG2EP0D2p2PRvwhoP0sI4IKeRfInXUl+UZWeEH8G0g52U22qofMXR/8H6CKPw
         Kk5T7Sye9iE4sBW3o8DuGZi3FYY6uhRTrfPFWn0t0LK1rjqfmqiMU8elj+UMhXJheym9
         9QA4QtMooFmrw2IknFLgn/WtlOOHMCMjq4HAt9kniX6xJc6GLcUmB6JnVnSzY0nf0t+h
         tg3AMhjIiNoC2t3nJsK8bAH0nFEu8O3ULEQ+RBj513VipHJmAvlD09K6Ak61Ea3Yhsh8
         F3YQCe1KqaDjMVtWHW7p8dL2W5wmFlfPfe0X/3v4sm8cRqnzJZQF+TceIpHKfNoG35Ke
         jlGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy6Zu+oNyTWl7o8rfEPq1NHI/CnOarlCW5IsPyKFuxacJIFYMmx
	vYeNWLo1a8B+gi019s/e92w=
X-Google-Smtp-Source: AGHT+IGrMlp3FRkn21dBWzvOr58VOpCS2TZ3BNZP/hTVra3CUo0Ia19BuFcyK8g/16s/uL/CDmpauA==
X-Received: by 2002:a92:c546:0:b0:349:5050:df44 with SMTP id a6-20020a92c546000000b003495050df44mr7611582ilj.5.1691412233434;
        Mon, 07 Aug 2023 05:43:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:6d10:0:b0:348:81bd:2f88 with SMTP id i16-20020a926d10000000b0034881bd2f88ls1399391ilc.1.-pod-prod-00-us;
 Mon, 07 Aug 2023 05:43:52 -0700 (PDT)
X-Received: by 2002:a6b:f003:0:b0:790:b44f:b9ee with SMTP id w3-20020a6bf003000000b00790b44fb9eemr7143925ioc.10.1691412232766;
        Mon, 07 Aug 2023 05:43:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691412232; cv=none;
        d=google.com; s=arc-20160816;
        b=YaSVWKK5VsmcHP8YL2L+OQ1YteUHzkyQgrEdLv4kpnuJiScjowWhhR5TUYlrdUEFab
         utgKW3jBHXL2P+IIiuqUXWDKizYMsjDRJBahXI+hYYvGaMstk5oY919rq2YoRtBmhzPq
         X071rdbZaBJPmP3v4QXcG0kpN2dWlX8NIeafZvyxDv+P2iumqbJh8tSKR5udhVTpjgU4
         grFIneCi/+0voovGIJ3YLu2JOoFKT8SvuUEM1ndQImD8azXBQSvMU/DiFE7AECp0JdSZ
         nAaqcFFD/agQ8TD++rVMChyI8p5aDz/xJxB9ColcSL89L71g+CiO1ICYhS8yWsU29b7r
         xzDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:dkim-signature;
        bh=pgN6ITNOX4XAghEqnE7rc109x2dPHO2XXLtjfGMGEBw=;
        fh=KutyjcbQvQAObT73hZ9+Mk/TI79Vc0CV6w2Xk+1Erfc=;
        b=K3YgVwkweDvnX08Bo1rKcXD4CGohbCSkMWunWHMczho2Jhso24JfBE/YVxCQXbyZwe
         XZh9DeIDxO1GOci3GkUnMAuy3nGwCA5Ius7k8JIihemdl3hJOmYyF9agwxfqZjL+9KAx
         o56+RKedwalUO+tPvmLIv28Er7rj5H/3zTxhp7C5OBkteoFA2NMLIKWpFpBf+U5DjtnG
         D3N6kIIA+wKkpF+kSM3/rOIC6ftuDnTaDgIMl3DjtPAvSC1LQCpnNYNLWpEw2SZ3CXOu
         DsXlO4Dp/l4irJwtYsK+LJCDR1gL25tGuLuGgTPs9Vj/AH5/Qi7vrsA4n9q5p/2Q2E12
         JVbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LSz023+I;
       spf=pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id bc10-20020a056602360a00b00786deceee7esi592234iob.3.2023.08.07.05.43.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 05:43:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (66.187.233.73 [66.187.233.73]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-558-VkhQ3GWqNk66vZeVUGT2Qw-1; Mon, 07 Aug 2023 08:43:49 -0400
X-MC-Unique: VkhQ3GWqNk66vZeVUGT2Qw-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id BD5F6381AE49;
	Mon,  7 Aug 2023 12:43:43 +0000 (UTC)
Received: from oldenburg.str.redhat.com (unknown [10.2.16.12])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 6342E40C2076;
	Mon,  7 Aug 2023 12:43:40 +0000 (UTC)
From: Florian Weimer <fweimer@redhat.com>
To: Jakub Jelinek <jakub@redhat.com>
Cc: Marco Elver <elver@google.com>,  Andrew Morton
 <akpm@linux-foundation.org>,  Kees Cook <keescook@chromium.org>,  Guenter
 Roeck <linux@roeck-us.net>,  Peter Zijlstra <peterz@infradead.org>,  Mark
 Rutland <mark.rutland@arm.com>,  Steven Rostedt <rostedt@goodmis.org>,
  Marc Zyngier <maz@kernel.org>,  Oliver Upton <oliver.upton@linux.dev>,
  James Morse <james.morse@arm.com>,  Suzuki K Poulose
 <suzuki.poulose@arm.com>,  Zenghui Yu <yuzenghui@huawei.com>,  Catalin
 Marinas <catalin.marinas@arm.com>,  Will Deacon <will@kernel.org>,  Nathan
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
	<87il9rgjvw.fsf@oldenburg.str.redhat.com>
	<CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com>
	<ZNDlrRrUS2AWTCiw@tucnak>
Date: Mon, 07 Aug 2023 14:43:39 +0200
In-Reply-To: <ZNDlrRrUS2AWTCiw@tucnak> (Jakub Jelinek's message of "Mon, 7 Aug
	2023 14:38:05 +0200")
Message-ID: <87h6pbf2f8.fsf@oldenburg.str.redhat.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/28.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.1
X-Original-Sender: fweimer@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=LSz023+I;
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

* Jakub Jelinek:

> On Mon, Aug 07, 2023 at 02:24:26PM +0200, Marco Elver wrote:
>> > | If the arguments are passed in callee-saved registers, then they wil=
l
>> > | be preserved by the callee across the call. This doesn=E2=80=99t app=
ly for
>> > | values returned in callee-saved registers.
>> > |
>> > |  =C2=B7  On X86-64 the callee preserves all general purpose register=
s, except
>> > |     for R11. R11 can be used as a scratch register. Floating-point
>> > |     registers (XMMs/YMMs) are not preserved and need to be saved by =
the
>> > |     caller.
>> > |
>> > |  =C2=B7  On AArch64 the callee preserve all general purpose register=
s, except
>> > |     X0-X8 and X16-X18.
>> >
>> > Ideally, this would be documented in the respective psABI supplement.
>> > I filled in some gaps and filed:
>> >
>> >   Document the ABI for __preserve_most__ function calls
>> >   <https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/45>
>>=20
>> Good idea. I had already created
>> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D110899, and we need
>> better spec to proceed for GCC anyway.
>
> "Registers used for passing arguments
> are preserved by the called function, but registers used for
> returning results are not."
>
> You mean just GPRs or also vector SSE or MMX registers?

I think this is pretty clear for x86-64:

| Floating-point registers (XMMs/YMMs) are not preserved and need to be
| saved by the caller.

The issue is more with future GPR extensions like APX.

Thanks,
Florian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87h6pbf2f8.fsf%40oldenburg.str.redhat.com.
