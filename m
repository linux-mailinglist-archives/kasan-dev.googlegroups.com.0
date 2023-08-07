Return-Path: <kasan-dev+bncBCVJB37EUYFBBPWLYOTAMGQEE5MRTCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 99241772456
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 14:38:24 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-68790b952bbsf2479041b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 05:38:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691411903; cv=pass;
        d=google.com; s=arc-20160816;
        b=oKQGodxdUaAbD5k3pwEvUecw2pUWnQuv4ZCSJBsmawftXkOTuXVnZXKQMB2SZIHgva
         ZTPL3H7yAkWp3GGTojVmgpSxgJBY5q5m/EVYNagmGST3pEHIYFg7YNlrSfj2iyGmCnYJ
         FYlVTy68Nuqnm1nhv9dHTHML9AtCj6ErxBGe4afvL8enK2m8u3xAMuEbkCFEq428mUtV
         in4kjuElyuiot5bX4wMujTN0Zm5mqG39ChS46OMocdQFY85F3g4nHL5PiXmlDupmVb2p
         yq5P2Xl17xb+C4iWZ9PHmJYusEkbW83s7VAO/ItHEBhPksp4cUHFoSD3N+d6Jsm7fZE9
         dR5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Jrz0yn+9E+5CTaYYPwLqfitZi/Qd1cf5GaacRiMoZ1Q=;
        fh=EnRYQXx2UDmhKHq7TfNYTxUTET/dp0zrxu9EmAhtS/M=;
        b=d3rA6JGcveWCp23sDNnKnO2aS5pEwpCtWpKeYT9rD/SshUiey1eeB/NoAwEHbvp28D
         Hp4sTMldCgvgGO0ZQJ1CkjyUp2PEs4juM90WP2GPMBs4cIDmQf0h7U2PyvPrm/YA/U/x
         68Ce9+VUMl7kXzfVcMICqqavjAAgsdSacFBbCA6BaxM3uPT4Fi+CYhSWtAJhextRvOBm
         75nDJ+8B6bAuR+USms1fsaDvn/DWGqJrDK6aMcK2ed641bbuZVaXPhuxWutasXxB1fYZ
         j80RDtg0GRFqAnGdQDOEUq/1kspTfLlzoOx0mMnr6D6CaKDkaL/UF2ysHQo/JTobiD1e
         budg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bugNhNCs;
       spf=pass (google.com: domain of jakub@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691411903; x=1692016703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Jrz0yn+9E+5CTaYYPwLqfitZi/Qd1cf5GaacRiMoZ1Q=;
        b=q2bx62C/gS5Fu0MKM5Al9eHVGlvAq0MiMv8THgiLkLkIEPZqjKfSu9dzjMUsWVRPxP
         NdO1xGuuSJ0ZecoLuvppFrOENcqJ2H7OsvKNLGmF3dXFJj3SnZX/IlWXcErKzDowCuMz
         3pDeJYhvSNrXoJknS4lEKFMvwQxZi13sw0RwvWyrIKNmvfjKQgzTKKApf5MjsX6K3EJe
         OzKrpzBjVx3aJtF90swsOVyH6k/4kyF42dRpq4FczHsHaj1pp8cjjzX1fXAA5TRygmH6
         5dpY3r2czltsxduhbKiCVB/d/LpEOFnCo+8qKpZBuw9Zz3socLXhtj3+0Z7KM9OIxgIl
         8YEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691411903; x=1692016703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Jrz0yn+9E+5CTaYYPwLqfitZi/Qd1cf5GaacRiMoZ1Q=;
        b=gcqNJcfI71R3g6olvUou9d0okMJ6+zrN9+fXb57YAzjxHRC6S0ZwPVFdMlX6qXwGO+
         PJ/N6QpWEqVACPPwfFe7pHGoVQSmkIxJh5fuw2ytUUjSyVpKTP+bZb6evs6iPJ0PxMWY
         EQ+0fplzsmlsYf5Cd5OY/htxahR4wSJE2GQUySSya7IW8XrE+GMilTVFE4MgIeJAhPbQ
         NB1X76lKDtmdiGqFZoAb4hzaFBqQOsvTt2F/fnzyuoTkB6yA/EZpo+JIs4PZuzybEkEc
         EKw1d1TuH3uMi8RTL2aK/cq0yXeVQW0MuKjI/UVyFSpxR7RiHzA/ypkfvuuJSzqtun1J
         qFRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy4Nq+WQOGxNJyZ6EfT/yPb+JBXfMoWq3iseFoAhSJ/GwRRsqhK
	NBjwdaTp6CTSGGo2kDWyc4k=
X-Google-Smtp-Source: AGHT+IE+GGnsSbjoSm28ULVTsX9GoL2FxUniCFE05NArvxqMzKT/jhEp0CVn2Amtg8ckbjI35Frrvw==
X-Received: by 2002:a05:6a00:1306:b0:668:73f5:dce0 with SMTP id j6-20020a056a00130600b0066873f5dce0mr7952845pfu.29.1691411902695;
        Mon, 07 Aug 2023 05:38:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8f31:0:b0:668:7511:1552 with SMTP id y17-20020aa78f31000000b0066875111552ls1643292pfr.1.-pod-prod-09-us;
 Mon, 07 Aug 2023 05:38:21 -0700 (PDT)
X-Received: by 2002:a05:6a20:4413:b0:134:9b83:9888 with SMTP id ce19-20020a056a20441300b001349b839888mr9313080pzb.0.1691411901407;
        Mon, 07 Aug 2023 05:38:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691411901; cv=none;
        d=google.com; s=arc-20160816;
        b=CHfK5ox/KQBKHYYb3225YTBw9ZwGkfq9sAErwel3fewJyE8DKG79kTbatne20cK59k
         4y1nxpCAeW55rzeBK48Knj6SjTgHO9jFJ+PlxAsgh1HD3Uj7pZ8ryoJy2Xl3RJFjtjlA
         Qv8zjD+m3lml58YeiFghOA+endoLicRoC1QImz9gpNCH5nvFNfzHptvt7A3v/nZvgdiE
         sjrH9lfQR/Jol1vQ7j79PVhFIxuOQASl1s6fvqZ5XsEdvkz6GZXgcBBm694Utzuqy7+a
         PKYguN8UmM/wz+O1MzBEiWKLwkNpH5arPMdDAn1AVhaQnIVWM12k5UAM+Uk37hOkdbJw
         s0FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ePFRnq6E9cmG1Qs9e3n4TY2fhHkanWOkJ/7w8uarlKU=;
        fh=EnRYQXx2UDmhKHq7TfNYTxUTET/dp0zrxu9EmAhtS/M=;
        b=HDk25WJyhge2tzEQtgj7q9sQLGp69cFlsNEH0bKRQHfdGe9sMqib5t+wKBfxLlDAk1
         7Pwi9gkOKyqd3aXKnrJFT+Si7hjkqx6gPUUixcEOcfX4+0WBL/5Zd3Tm1MfaBs9eOn1K
         kfCCHHFIDfwtlKXrwJ3ok66EhTHyxoIrO9J5FGLdDAlwK5/8SrvoNPGf+IetKvaX7VJ1
         og/OaqJ3rcjuzxZAqIEz47gDeV7eTLh4/cO0C3wx4E8geJ5nT9IOw8EHDjTgiJDtLYOx
         6LG//lUwjBKSZWvgIFfI3CCqwNEiH3X6imS432ukaNyM2EUYX/d9RF/l6omXX8e/ctz0
         Xe9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bugNhNCs;
       spf=pass (google.com: domain of jakub@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id g3-20020a170902e38300b001bb2c4018a6si406514ple.2.2023.08.07.05.38.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 05:38:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-637-wZWr1zJaMSiPiVo_gSlCsg-1; Mon, 07 Aug 2023 08:38:16 -0400
X-MC-Unique: wZWr1zJaMSiPiVo_gSlCsg-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.rdu2.redhat.com [10.11.54.3])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 6FED585CBF9;
	Mon,  7 Aug 2023 12:38:15 +0000 (UTC)
Received: from tucnak.zalov.cz (unknown [10.45.224.18])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 1DFFC1121314;
	Mon,  7 Aug 2023 12:38:14 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.17.1/8.17.1) with ESMTPS id 377Cc9Gu3645380
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Mon, 7 Aug 2023 14:38:09 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.17.1/8.17.1/Submit) id 377Cc5lu3645379;
	Mon, 7 Aug 2023 14:38:05 +0200
Date: Mon, 7 Aug 2023 14:38:05 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: Florian Weimer <fweimer@redhat.com>,
        Andrew Morton <akpm@linux-foundation.org>,
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
Message-ID: <ZNDlrRrUS2AWTCiw@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20230804090621.400-1-elver@google.com>
 <87il9rgjvw.fsf@oldenburg.str.redhat.com>
 <CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.3
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bugNhNCs;
       spf=pass (google.com: domain of jakub@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
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

On Mon, Aug 07, 2023 at 02:24:26PM +0200, Marco Elver wrote:
> > | If the arguments are passed in callee-saved registers, then they will
> > | be preserved by the callee across the call. This doesn=E2=80=99t appl=
y for
> > | values returned in callee-saved registers.
> > |
> > |  =C2=B7  On X86-64 the callee preserves all general purpose registers=
, except
> > |     for R11. R11 can be used as a scratch register. Floating-point
> > |     registers (XMMs/YMMs) are not preserved and need to be saved by t=
he
> > |     caller.
> > |
> > |  =C2=B7  On AArch64 the callee preserve all general purpose registers=
, except
> > |     X0-X8 and X16-X18.
> >
> > Ideally, this would be documented in the respective psABI supplement.
> > I filled in some gaps and filed:
> >
> >   Document the ABI for __preserve_most__ function calls
> >   <https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/45>
>=20
> Good idea. I had already created
> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D110899, and we need
> better spec to proceed for GCC anyway.

"Registers used for passing arguments
are preserved by the called function, but registers used for
returning results are not."

You mean just GPRs or also vector SSE or MMX registers?  Because if some
of those are to be preserved by callee, there is an issue that they need
to be e.g. handled during unwinding, with all the consequences.  It is hard
to impossible to guess what size needs to be saved/restored, both normally
or during unwinding.  As caller could be say -mavx512f and expect
preservation of all 512 bits and callee -msse2 or -mavx{,2},
or caller -mavx{,2} and expect preservation of all 256 bits and callee -mss=
e2 etc.
MSABI "solves" that by making just the low 128 bits preserved and upper bit=
s
clobbered.

	Jakub

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZNDlrRrUS2AWTCiw%40tucnak.
