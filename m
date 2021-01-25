Return-Path: <kasan-dev+bncBCT4XGV33UIBBEUUXWAAMGQEMS2YFUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 86838302F4F
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 23:45:39 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id b20sf471891pjh.8
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 14:45:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611614738; cv=pass;
        d=google.com; s=arc-20160816;
        b=fPKbc/Fsbq/N3vocSzXdq1qExG+zvLu/NZHCLf9wKbpQGpMuseIc1lvVMlbHUnReqw
         Mhtj5yeO0o0wNOmucdh2wtapqwYhx08CfweOx39SiMUwRueroljtESVCocmYBNrle9Uj
         377LKr8FD6xr2vuU5A/VVvinKdnVWLAcAp0f689AnPmz4pUUfVt5OOnjTsWs/fCJDtAb
         uGSIwNP8Puw0/kXq5VoLtv5yxFG586xk6pPZRAHGpq9DuwaJreFbW/TAK7UIRm43SQQJ
         j4BzCkGHwEhkifC3nDJjTjVdOIelu/xsMfBUkYmLDXFylz67C+1um4+7u5OpMVEbRBlU
         XAsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=J5fAuJ6KhR03x1IyoexssxTteJ2i3/u+RmMC7E13X0s=;
        b=z8I5W7ysMQNacepSCkvEaOHAZlfgdZNtLMteHk39UgyhIY1z3SNBJtyST7IcP6NeW5
         nJU6Cw6d2fo6p7tzoe6+0H5jZc09vscelh0nsQQVU0ViyPZHRdgEU8I9eG6wJ5z0agIS
         xXle3tyH79o3v8qNqL7YYqmlsLm3kDvD077fCltzUNQHDKy4narb+lp4wP8wjMd+clgl
         7DmYxCVOyLjaFZSKPcxm0isjAk8YPttL/gXYY+9WtABNrtWxQ7Ux8eW2OphJn/y1W6r2
         JFLwX/hF8G1iQYMo0b9ZWicQNcGvMrRgdVn69bbQcS8YPwFDgCVthFA3TQt/+ay3oRVM
         tUUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=WJx98ur0;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J5fAuJ6KhR03x1IyoexssxTteJ2i3/u+RmMC7E13X0s=;
        b=mBG1ovJ9XqPYt3WIL0rin7jnPf/zzfpmTyeyIDqqpbbzr46prrKZAzdWRVYgNW9Ykb
         VY2oihqD0n3bRHS6FabsV+BVDtTfSdOLAL2X7AgpD5FTTH/DvZi42qaRo0P8yjJDyRag
         hQxszA8kluTZXjB3e1WEHxZirpJhTfuoM5ymrTN6YFeRX2JQoJDUmC0giCP9BW7vN1tH
         pcT3v2n1y1o+kniMG0FxM3JMjf2cYuje0f7OqnmpYoVNjeUHbjlaiV+4ItzDDnx5lQts
         gwAaAXX0/gGqfKUnvx1TSLJEwWJ9GH0yPB8s7NqyRX9xIBpkrbQ/YGqHhekjy0nPKSXw
         7HeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J5fAuJ6KhR03x1IyoexssxTteJ2i3/u+RmMC7E13X0s=;
        b=uh1mkQ0/Ucya6LqbWOR624qNLypIJrLj0CJIOqWxb0vhXZKNtyrwCuMFCJB1kgegST
         6qqKFSo45ghaNKtao1/rDMKQYHim39/MHG/ThXWe+Y/3h41RTR2MfsnXJFPdPjYelZQL
         +juPMVcAhZPDWzPpS47uevSSCAKcyP5I6OsqiA9YttHmKdh79GIXlOWiL5by008SK1EB
         IfazNKVtes2QocJLchihJ6NxMR7q1ojlFie8DcwicUvsabHoXRNoiYBJQhx4F74tBdz1
         uVUX1bGDE3lRUuMN9c3OirzAiPhBKBrXE1rRy+x6j1KW1VkrQbvYduaAoUyK+J/IqDRW
         b37Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532KcomGzfZS9vhJjlmB0IZlfwE4kXVw+yN9XL122JaivdWB4h/x
	9NyWLbV43dySDkaXORZy0CA=
X-Google-Smtp-Source: ABdhPJxeVOMe6WPSQLa99eTrkwiz6U3kSTBAE74UEbDjcaUTFoYvL8AWd1eJI53n45sC6FdTjgIvGQ==
X-Received: by 2002:a63:34d:: with SMTP id 74mr2660222pgd.388.1611614738288;
        Mon, 25 Jan 2021 14:45:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9309:: with SMTP id 9ls5249593pfj.0.gmail; Mon, 25 Jan
 2021 14:45:37 -0800 (PST)
X-Received: by 2002:aa7:80ca:0:b029:1c1:b636:ecc2 with SMTP id a10-20020aa780ca0000b02901c1b636ecc2mr2539126pfn.20.1611614737700;
        Mon, 25 Jan 2021 14:45:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611614737; cv=none;
        d=google.com; s=arc-20160816;
        b=R6gTkIfsjR9DizYVoJlvqa4YTe50Ak9vpA355Cf+tzIf4Kh/14wRKifqeaYxG5OSXb
         ltQktojT/svnYyTEWiIcrh6HhnaaWfeEoGBqko0QzwXAYTn/j6FHV47pOswCPaysBfl5
         wEuGWc8t+mX6hnbfxQ3Jbzisi3w3oaq28pZDrpGQMqYnWFZk03HAe/iXIv0qBuMeQNa/
         n7HvvVHlw1AgyN1VJX537ZjGy6QHZpxfZYwCnfJ7zE/CzKywbAI8JnR8YyCcnJCGb4rU
         3UYWPyxJc/DpZFrtcVpaBgVEQ58XQKU152KwsVILH1RxedbQcG/Y52+a/a8m6ddK7Fov
         IkBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dGbdIqt2CWXQblr7ptN63u8WPXbmTGjT8RbSYzvYITk=;
        b=Ov0lPNqT2GGNNV8MF43gPWuJkh9cL7PVqKzykWWGTd2eRZ9GZqh+sO+BkZUvHocdY0
         rEAGm8bPKdgTkxXShsvFk2LEFZ9oJo1GuHl5m3JlsBd9GeAHwBIKEQQqrStRB2Mzf7wo
         TOG50gcy1R23ckVURO+3srRR1v+UxKDj2icn4oF3Ti1xChgwB45/SnvBWh1jzSfhu9w6
         m+ILpBGdyK53BGET1rJK6El16bIBszzOCk06GxcjsidGl3Db/ul6wcH4U8bKSQg0xxbr
         trd2rB+2CgW5VZJnw5s8Rze6gq7bZRONGRtsxoo0U9m/yut/20zc0+Ai7WUF6SOP6jhD
         GP6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=WJx98ur0;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 13si874293pgf.0.2021.01.25.14.45.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Jan 2021 14:45:37 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C8ECF221E7;
	Mon, 25 Jan 2021 22:45:36 +0000 (UTC)
Date: Mon, 25 Jan 2021 14:45:36 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Anders Roxell <anders.roxell@linaro.org>, glider@google.com,
 dvyukov@google.com, catalin.marinas@arm.com, will@kernel.org,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, rppt@kernel.org, david@redhat.com
Subject: Re: [PATCH] kfence: fix implicit function declaration
Message-Id: <20210125144536.4544d9fca3b4cda8a6e42517@linux-foundation.org>
In-Reply-To: <X8otwahnmGQGLpge@elver.google.com>
References: <20201204121804.1532849-1-anders.roxell@linaro.org>
	<X8otwahnmGQGLpge@elver.google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=WJx98ur0;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 4 Dec 2020 13:38:25 +0100 Marco Elver <elver@google.com> wrote:

> On Fri, Dec 04, 2020 at 01:18PM +0100, Anders Roxell wrote:
> > When building kfence the following error shows up:
> >=20
> > In file included from mm/kfence/report.c:13:
> > arch/arm64/include/asm/kfence.h: In function =E2=80=98kfence_protect_pa=
ge=E2=80=99:
> > arch/arm64/include/asm/kfence.h:12:2: error: implicit declaration of fu=
nction =E2=80=98set_memory_valid=E2=80=99 [-Werror=3Dimplicit-function-decl=
aration]
> >    12 |  set_memory_valid(addr, 1, !protect);
> >       |  ^~~~~~~~~~~~~~~~
> >=20
> > Use the correct include both
> > f2b7c491916d ("set_memory: allow querying whether set_direct_map_*() is=
 actually enabled")
> > and 4c4c75881536 ("arm64, kfence: enable KFENCE for ARM64") went in the
>=20
> Note that -mm does not have stable commit hashes.
>=20
> > same day via different trees.
> >=20
> > Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
> > ---
>=20
> Ack, we need this patch somewhere but we should probably fix the patch
> that does the move, otherwise we'll have a build-broken kernel still.
>=20
> > I got this build error in todays next-20201204.
> > Andrew, since both patches are in your -mm tree, I think this can be
> > folded into 4c4c75881536 ("arm64, kfence: enable KFENCE for ARM64")
>=20
> I don't think that's the right way around. This would result in a
> build-broken commit point as well.
>=20
> Looking at current -next, I see that "set_memory: allow querying whether
> set_direct_map_*() is actually enabled" is after "arm64, kfence: enable
> KFENCE for ARM64".
>=20
> I think the patch that introduces set_memory.h for arm64 simply needs to
> squash in this patch (assuming the order is retained as-is in -mm).
>=20

OK, I requeued this patch as
set_memory-allow-querying-whether-set_direct_map_-is-actually-enabled-fix.p=
atch, part of Mike's secretmem patch series.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210125144536.4544d9fca3b4cda8a6e42517%40linux-foundation.org.
