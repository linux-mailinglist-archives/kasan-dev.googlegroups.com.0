Return-Path: <kasan-dev+bncBCVJB37EUYFBB6OYYOTAMGQED3U3XYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C5117724FC
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 15:07:07 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2683548c37csf2833280a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 06:07:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691413625; cv=pass;
        d=google.com; s=arc-20160816;
        b=sHXkouvAeZEP8V21gx32HBK9lJyK9N+OTj4a7azUjVljiV+9FJpoKbk1i8EiYB1GSW
         XDLbkDHGp8YZRLhUofViFbjRvuk/WfYqBsRRuShWirJqUJwbWknePiqznze+tc5/+D8h
         ngT1Og3W1HKsVQKl2NNOc9bndozvgvUyeQNotkjvV700vjSxo9f20puS+bx0FJIVuuK+
         OwFqjA8es5GpCONe1JahRHVTBZNWg6isJmF9cx+tNlWP+GUFIa91dx4wSV5R5krc22a6
         nYthKGpIlakkuwFnh/4lwOtYRDz03UycvfS3UfxvFyYEEW9IiUqvnWLl65b1rkwsyk0t
         vmeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lusu3UL7nlYnO9iNQkDJ4WygPigFDVaP3N5CQvoJSqU=;
        fh=Cg8SSnAE9P3rfimTSdXVyIc4Kl2SLD5VfZz8WaJIllQ=;
        b=FhvObaIgCQDTENrjaQRVQzzznjO4+/TbJaYbmuDrWQymB4fCIGQgdh6W1COwL5duiR
         RlIiM4UFb78W34UoxTrhl2Tteqob4Z2pNN+SJtHGv6ggnR/Y14rRsx5YSNczc5XtLHRF
         PRPot/JDG+TnxdJyMYn9qL5+kyiyy+9/M4G7NnGB6w3E5/gHDq0vSBALUkCthe44VD7m
         Lj2VZmP8cxTU4e5d0NvzV3Os2y31z+Yzue4AfltE1PIjraPPWz109wSefi/YBqltdGYj
         fsnxJ/b6eAPkaipYOD7+v9xYO38QZ675PX7i7S32iewg3NnIB2cvTFvEFTF3mdCbe/79
         ycPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GCOw82kP;
       spf=pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691413625; x=1692018425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lusu3UL7nlYnO9iNQkDJ4WygPigFDVaP3N5CQvoJSqU=;
        b=S64JTuWfBMbB6PU9D0VexHkTMALJRoSPCfZo/RKUipFc9wmOh119RFYDsd6RGhU/Yx
         hWv6SkfWRZDpmOmy91UjK5+MVuaoUC+4uY6hR81hnpe8xyVLdRVeaZykQLPxwSfLPJ8d
         H88RsmlwnVGBOiINnJC7sqchtRsqMDmgQfnZb7ddtFy84eGXo1lG1QuinxcblNe/upVR
         wSKF37VFZdYy34nX834z0H0YZZDhL4wZoB383V2gOP/0LnSIL20hzW0EuVtNA9w3p+Fj
         fvmgSUn9ZfsYdPtmICQnMi4FJMyFrpWFj6LEtvWU9U5oQ1/WS9ryS6dMyubbrAvp/wAG
         R7BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691413625; x=1692018425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lusu3UL7nlYnO9iNQkDJ4WygPigFDVaP3N5CQvoJSqU=;
        b=SisnPTFqLPSomC3Yxjt+zM9p1YDEC1uvXvt3fCo8NOz5z+rv+8lDIjWfpAVbZNcZJx
         8VI6sJ3d/cSRmyBYKj5fOOEkPpu0cGIm4crVAGMnAuYihP5fF9wQgklYxZU/k1w+F0Gi
         uBVMsWOqP2BsQtAKcVDvySihPbgUKZ8gGnlm6RDd9bYK99CNA2hMe+HSgt2F5PMzGTK3
         aCYCPrxR5A4VCAW/X30HUBmAm/CDaNIeuncV1dQhKqGH8YN+qRhXKYxD4jeufNRyvtQN
         8ZwYEHw8EzcHTHLSmyD54/xNvbfeItEfFsPoIxPE+n38RSNPvoT2yePw9camzQYbDJKD
         2nog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywh+WYmYv8/23yZAL28AyK87tQoHsL2QYTRqhH/X+AXieQlOnNc
	4D4VN+kk/sw0AWj1aMHnEK0=
X-Google-Smtp-Source: AGHT+IE1ypqVGXT7GNezH+autCOa3NPwMRwchWaT9Lewn7MnSdhXg6S3J0h2Nb4Y4HV07Jy4yMsDDQ==
X-Received: by 2002:a17:90a:8990:b0:268:2930:ca49 with SMTP id v16-20020a17090a899000b002682930ca49mr7730627pjn.44.1691413625196;
        Mon, 07 Aug 2023 06:07:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:190d:b0:268:18dc:c7de with SMTP id
 mp13-20020a17090b190d00b0026818dcc7dels1746149pjb.0.-pod-prod-01-us; Mon, 07
 Aug 2023 06:07:04 -0700 (PDT)
X-Received: by 2002:a17:90a:70f:b0:268:2c60:9969 with SMTP id l15-20020a17090a070f00b002682c609969mr8249062pjl.47.1691413623851;
        Mon, 07 Aug 2023 06:07:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691413623; cv=none;
        d=google.com; s=arc-20160816;
        b=eIdAHteZWpgJiuZ7wm7ByPNg01YUIBXcr24YBWlaYGmZGAvl8lP2H1DMuSrIYntAfB
         ttKKbLp72ua0Sav0k+Hqf3N6Zf+lQGMRFOovSV5IulIyFvNRmkAsee774qbE+x71swat
         pb6dvOyGQ9W5/sJLjNybAEyk3mvYt+LBBFFuE+V2toRwIuUD1zwxTLwWTY7ggzRsUMvA
         72uomd6d4ADfc2/2hvSDjNkGXVBqQWOZOXSPMHyKyve7ItDyIeFYTZ4dhx+I3r4GKyV6
         /1UIdNSDUdcXCYisEIa3eUs6xkuxq5rDs4nGqhp3hbwInzKDGTw7ezUR8HqRZSEFuPlj
         l8Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=wTw5UGHZz4e2SdP2OePYtf5FEiTOr08NgMVHrTIjIdY=;
        fh=Cg8SSnAE9P3rfimTSdXVyIc4Kl2SLD5VfZz8WaJIllQ=;
        b=1D6BAvCgsLaKZjv/oyV6qf8fgKi1M+hTwdSji2SOw0RoFPdSXnzgv/vJciiQQ+EbIs
         ZCEWuqateC86GRlgh5g2awKGm71hei3KxagiiDuoSL6BBP6mBXZ5pDKWONQd5YGwHfkz
         Wh622i2G8glG9MyE0+6M7ASOLuc3OL1dQiaezstif8ELSYNd1oOuCK7YtzHfC+RhG5zy
         GQHKhN2janVPizACB/v2gXvHOETE+rqOW3+YTl9Z6wjLdGYmYfyQS1Z67rZeuA7hazOU
         eCnJudEqOsxGdYjGukfVmDfuPSd42XekT1uiicDjs27n393HB/6g4taytYEchX95++8I
         VyAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GCOw82kP;
       spf=pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id sf16-20020a17090b51d000b00269342a194bsi286815pjb.1.2023.08.07.06.07.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 06:07:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (66.187.233.73 [66.187.233.73]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-684-8FRjDLUHNAWmNwU-04hwKw-1; Mon, 07 Aug 2023 09:07:01 -0400
X-MC-Unique: 8FRjDLUHNAWmNwU-04hwKw-1
Received: from smtp.corp.redhat.com (int-mx04.intmail.prod.int.rdu2.redhat.com [10.11.54.4])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 6B69B3C108CB;
	Mon,  7 Aug 2023 13:07:00 +0000 (UTC)
Received: from tucnak.zalov.cz (unknown [10.45.224.18])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 1A81C2026D4B;
	Mon,  7 Aug 2023 13:06:59 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.17.1/8.17.1) with ESMTPS id 377D6th33645769
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Mon, 7 Aug 2023 15:06:55 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.17.1/8.17.1/Submit) id 377D6pvb3645768;
	Mon, 7 Aug 2023 15:06:51 +0200
Date: Mon, 7 Aug 2023 15:06:51 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Florian Weimer <fweimer@redhat.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>,
        Kees Cook <keescook@chromium.org>, Guenter Roeck <linux@roeck-us.net>,
        Peter Zijlstra <peterz@infradead.org>,
        Mark Rutland <mark.rutland@arm.com>,
        Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>,
        Oliver Upton <oliver.upton@linux.dev>,
        James Morse <james.morse@arm.com>,
        Suzuki K Poulose <suzuki.poulose@arm.com>,
        Zenghui Yu <yuzenghui@huawei.com>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>,
        Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org,
        kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org,
        llvm@lists.linux.dev, Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
        linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
Message-ID: <ZNDsa3AyR6EvIDeq@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20230804090621.400-1-elver@google.com>
 <87il9rgjvw.fsf@oldenburg.str.redhat.com>
 <CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com>
 <ZNDlrRrUS2AWTCiw@tucnak>
 <87h6pbf2f8.fsf@oldenburg.str.redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <87h6pbf2f8.fsf@oldenburg.str.redhat.com>
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.4
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GCOw82kP;
       spf=pass (google.com: domain of jakub@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
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

On Mon, Aug 07, 2023 at 02:43:39PM +0200, Florian Weimer wrote:
> > On Mon, Aug 07, 2023 at 02:24:26PM +0200, Marco Elver wrote:
> >> > | If the arguments are passed in callee-saved registers, then they w=
ill
> >> > | be preserved by the callee across the call. This doesn=E2=80=99t a=
pply for
> >> > | values returned in callee-saved registers.
> >> > |
> >> > |  =C2=B7  On X86-64 the callee preserves all general purpose regist=
ers, except
> >> > |     for R11. R11 can be used as a scratch register. Floating-point
> >> > |     registers (XMMs/YMMs) are not preserved and need to be saved b=
y the
> >> > |     caller.
> >> > |
> >> > |  =C2=B7  On AArch64 the callee preserve all general purpose regist=
ers, except
> >> > |     X0-X8 and X16-X18.
> >> >
> >> > Ideally, this would be documented in the respective psABI supplement=
.
> >> > I filled in some gaps and filed:
> >> >
> >> >   Document the ABI for __preserve_most__ function calls
> >> >   <https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/45>
> >>=20
> >> Good idea. I had already created
> >> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D110899, and we need
> >> better spec to proceed for GCC anyway.
> >
> > "Registers used for passing arguments
> > are preserved by the called function, but registers used for
> > returning results are not."
> >
> > You mean just GPRs or also vector SSE or MMX registers?
>=20
> I think this is pretty clear for x86-64:
>=20
> | Floating-point registers (XMMs/YMMs) are not preserved and need to be
> | saved by the caller.

The above wording conflicts with that, so it should be clarified.

	Jakub

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZNDsa3AyR6EvIDeq%40tucnak.
