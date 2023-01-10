Return-Path: <kasan-dev+bncBCT4XGV33UIBBPWZ6KOQMGQEWSDY5DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AB1EB66360F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 01:09:35 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id a24-20020ac25e78000000b004b5b7587537sf3718707lfr.18
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Jan 2023 16:09:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673309375; cv=pass;
        d=google.com; s=arc-20160816;
        b=bIyR4Y+Y2Bo2yHrplU7f9qrasYVi1yrYlL+LhZA1CCYRZUzbjVryOtRjuXm53gItpL
         Fv+YfzlwsxJzcqr9pAh0n8RxhzfxNpmcYoPa4IUZAJNvKTqTYFXj0lbiZ15cBcgmJJc3
         sSztv7l1OSoefhJxDB7acpUu2W1q9IDCgUXY0UR7lkZbIUjHPbzltAF3Po535YlfT/X4
         Yvd24UfgpaUt9GHXXHAgSJmTjQCrpMchSSRf/BFO90KQDDydkvVUUglfe75aiizrQJ6t
         dWy0VDApL2Se7sDTZFfNjrBCGE92lXU2CO/RMVxynWTZyestxhejvr79kbxYwkRkv1Gb
         LCUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=GrSEKQBfWLdBtJZ5FwSajc+wkPX+xe+8ExRTiosGwNM=;
        b=evmawHWTSZkxeX7zxCTzD+5O/NVR0YrVyRzyPEiT1LR8yZO5Gkar3kGcSU19mIFX45
         jft2vrQ2GXMyB4y41qNxLWtXQh6hBPiqMYcO8vM+3jJiv4upjff/krD6bIm9F956EBtA
         oA8xPrux9iVU1SMclLWr68vQJ6gL6NIWN0jP4t0ZLY4zQZc96rK0pEvzAHXjjk+gB+wf
         TvtvS+46VvKjuBCq6QCfuovmmpxn+oXk0x1kujTzpY81yX/VbeA3t7Az6YX557nx0+mL
         MOqZjJfx+rzIdmFNFI9udfjF380JS22Z8CcmdEXcPvgEFSXmai3dgozCbAAekKzNEemX
         Gv+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=VaHnQYT6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GrSEKQBfWLdBtJZ5FwSajc+wkPX+xe+8ExRTiosGwNM=;
        b=jV3IWZefj8jNeeTkEd1jsBanN6OrhQtOtTrKTPR71X7mqveICTrGXyx5I3VNxoM6bK
         ABTPBTPZCltNxOvJf0K5j3KL3tMdIJoQeIltug2nnvi/tZVH8Pkt+oo8zi37Tyq1o+Mq
         4Np8PF2ahEFVZZdjCe8B7SUTHq6z8H/hqpgS/YmQ4kEzRSzLcExKdQhxci79xqIUiIml
         uwEewu27DiyGdUlDy1Cm0y+jWqT9TjKmDn388cTU55eM0QPD4tTqPqZr3lvsCAgdqZUr
         Ct2ywwwqAb7Y65P9TaCwcpgeuhf6SjDko4osD2VVFRwYHU0C1FlMl7GOEWcOKNHzBBxX
         6J9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=GrSEKQBfWLdBtJZ5FwSajc+wkPX+xe+8ExRTiosGwNM=;
        b=zZlkt7PeILryYQW/DbDX/LEaHwuvGfgrZAC9kmhHWmlWG1Rur0OoTtDx18kmIVxjEK
         X0Ofc85Xk8EL/9428ZnCg1j0cC4xgSOtC4PgQSCwDLNcm/weFFUt5Wqm+pHF+1nYf2D8
         hc8dRyeYPbvL2gNxQa3J5m6x3vC8bMcfw4GiKLEJHOGzMkQMBoxgz/10bfTLgw/70bo/
         7fPUm3TASgiilWztVl1WwcqYwJZhNZxXbWWQF+NfNXpv3veOCARrtTjIIWB6a3qJXJGO
         li36ISaomGOPhgxyQdUfelyh/mNRnAAjNQBjVI1FTonFJss7AeM7OfsxRi9+51bAnwxS
         2JOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqb5oRs2wK2ZfqSXRPg8ZYYz8510zqZsVOLBh/cJEDg63DyaaoW
	I0wt1cfSl2VKEI7mXh2XupY=
X-Google-Smtp-Source: AMrXdXt/imoOXKou345HhZGrWoA2q6vrcj1D/LklHxnMAZjSf5otLloTV8LLJTJ/znlUccIgSR9C7A==
X-Received: by 2002:a05:6512:10ce:b0:4b5:9840:9c78 with SMTP id k14-20020a05651210ce00b004b598409c78mr3473095lfg.444.1673309374741;
        Mon, 09 Jan 2023 16:09:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58f3:0:b0:49a:b814:856d with SMTP id v19-20020ac258f3000000b0049ab814856dls1724199lfo.1.-pod-prod-gmail;
 Mon, 09 Jan 2023 16:09:33 -0800 (PST)
X-Received: by 2002:a05:6512:32d5:b0:4cc:73ff:579a with SMTP id f21-20020a05651232d500b004cc73ff579amr2968083lfg.38.1673309373136;
        Mon, 09 Jan 2023 16:09:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673309373; cv=none;
        d=google.com; s=arc-20160816;
        b=vA8ro1Sq7AKc0w9rCEP2WJr62/VtEaJsJ7fmSxY6L/hZbLM7mvExdy+HIomvqJnmi4
         VaxG5bi3Zk7ZVPYIr/F2OL7ECUVZ3uEELV939dMK/Sx46/P8NmV3QPLNoGk0jYjTeGO7
         vBcRzMlAx2EC3hAqxuiQAML/8CLg7xh1gEWzGF6AW7qWulRVHJRTBD+k2uTad9HNh6vu
         Bj0uAt/HBIu8IKG/H8fBnOoezM7u0GxkDDIZsD2TnEgSmQoRreu+6kYk1O9WXlwqrgqd
         1WhnMvORDIE140PKRos+Yp3tf7oQl0jk821LujdqB+CTHShrq+KTVL1shABKecwmT5kH
         o4DA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RuNPQHoZNIkbcEAHvs3amaLbPgJ8oEj2LUwxvAsuP9o=;
        b=OrNLIAy5SIs5+ePDOYE/9Ocp2NZ3Yo8EOLpkmMhI2fgfMEoXLZnf1w8++624FPuOoe
         dBti2imjjhuZ6doOMGs2i10mwouCXvhstbuskkCw7HBfY/bSM5JLPQZZqZ/kuWAEhDRs
         /28F42rARzYHJFaj1Uh9+DfQmD+eoBkYTsrXBoLIUe/3et0sBSq2VypiIwGjge/ehQzQ
         NpWu0e2C7WTiUtJCKqhHWbwUc8DbLHN/mlc7CAM4ZCSu5sFF+E7/vecWP1201LTW7Hc1
         PYxE9zyJQexyTlaIJypAKrgSO7OgB491q4OcT7TriDDXfJMAss3CkBraqDrnXU51eTni
         /nkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=VaHnQYT6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bj36-20020a2eaaa4000000b002810d5101ffsi376843ljb.2.2023.01.09.16.09.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Jan 2023 16:09:33 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 743FEB81094;
	Tue, 10 Jan 2023 00:09:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ACE57C433EF;
	Tue, 10 Jan 2023 00:09:30 +0000 (UTC)
Date: Mon, 9 Jan 2023 16:09:29 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: nanook@eskimo.com
Cc: bugzilla-daemon@kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
Subject: Re: [Bug 216905] New: Kernel won't compile with KASAN
Message-Id: <20230109160929.1ecacff5fb8ca2b1ae25141f@linux-foundation.org>
In-Reply-To: <bug-216905-27@https.bugzilla.kernel.org/>
References: <bug-216905-27@https.bugzilla.kernel.org/>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=VaHnQYT6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

(switched to email.  Please respond via emailed reply-to-all, not via the
bugzilla web interface).

On Mon, 09 Jan 2023 23:42:40 +0000 bugzilla-daemon@kernel.org wrote:

> https://bugzilla.kernel.org/show_bug.cgi?id=3D216905
>=20
>             Bug ID: 216905
>            Summary: Kernel won't compile with KASAN
>            Product: Memory Management
>            Version: 2.5
>     Kernel Version: 6.1.4
>           Hardware: All
>                 OS: Linux
>               Tree: Mainline
>             Status: NEW
>           Severity: normal
>           Priority: P1
>          Component: Other
>           Assignee: akpm@linux-foundation.org
>           Reporter: nanook@eskimo.com
>         Regression: No
>=20
> Created attachment 303563
>   --> https://bugzilla.kernel.org/attachment.cgi?id=3D303563&action=3Dedi=
t
> These are errors when trying to compile KASAN inline
>=20
> Using GCC 12.2, can not compile a kernel with KASAN enabled, either inlin=
e or
> outline.
> The hardware is an i7-6700k based home brew machine, Asus motherboard.
> running Ubuntu 22.10 32GB of RAM but using gcc 12.2 rather than the Ubunt=
u
> compiler.

crypto/ecc.c: In function =E2=80=98ecc_point_mult_shamir=E2=80=99:
crypto/ecc.c:1414:1: warning: the frame size of 1168 bytes is larger than 1=
024 bytes [-Wframe-larger-than=3D]
 1414 | }
      | ^
lib/crypto/curve25519-hacl64.c: In function =E2=80=98ladder_cmult.constprop=
=E2=80=99:
lib/crypto/curve25519-hacl64.c:601:1: warning: the frame size of 1376 bytes=
 is larger than 1024 bytes [-Wframe-larger-than=3D]
  601 | }
      | ^
lib/zstd/common/entropy_common.c: In function =E2=80=98HUF_readStats=E2=80=
=99:
lib/zstd/common/entropy_common.c:258:1: warning: the frame size of 1088 byt=
es is larger than 1024 bytes [-Wframe-larger-than=3D]
  258 | }
      | ^

(etcetera)

Increasing CONFIG_FRAME_WARN should fix this.  Try 2048.

Perhaps KASAN could increase it somehow to prevent others from tripping
over this.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230109160929.1ecacff5fb8ca2b1ae25141f%40linux-foundation.org.
