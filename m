Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBFW6Y3EQMGQE3SEDR3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3972ACA45C8
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:56:09 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-345896654e8sf288855a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:56:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764863767; cv=pass;
        d=google.com; s=arc-20240605;
        b=cWBo9IOdA+s1OuVnAMCw0io4yjktmE0YJoDWgB9vOq/uLTlresuJDS+tWJvRltaQ6P
         SPwjq183ylbr3H11nNhmNlRexILU4QIURCp8JqGbsZMsC9NHSbqHz9j/TVdqxn5QH35l
         ImB4z68G5+OStCGlgjk+agX6Nr1JWDRGggWwFfCiuI08o1om/AHCw5VlRUWS0vUWBKNV
         TMqM8diB709JLohBdVkMGQKzasQPX0en/ELeR6EPBUpEi3MDVR3FX/hE9cMZk9SnficI
         h2QO15tSQ0y2yOg/W96EsRFDdxTFCE0/JLyrBVT5s+Op40zlExybriyFob1T5/74iJ+/
         +9Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=WBvhKilX4oBT0RhAZ4u8yT1S/4FJYc4QflgjWNkyXqw=;
        fh=H0vO3nSkDtmFG6XgjcAwrvEVf9Ng16EowL/8xT5sEog=;
        b=JtTFZW1C88WH6dkrElF9EZt2AAXKv4FmW/j0yzCN4wpnxM1dpWdNc/goViA7trXyYI
         erHi8daGdCFCYLjHCv0YNZISlykQYCJkjAs0Szvr2oKy6oGS5Uky37czA9npenopsGrN
         7fLTjttw7pBadf7rDw38Q5Sv1rm3ylpdrr3pNGfJ3/oupEgP+u/Mphnmx26UveMR9Krn
         Sf4o/UUeGU9KPNUiraoeBEDtPx+9ivclMd3ql88416xcEXxu8kmeEzyPHRyfvcSDBIqS
         bQtzyHq7g+IPMiOMSg/qoH7HIb9uhUSH9BTpTRecGAaBftuvfIw7xgIbKeMEWwQQ6TAd
         Gakw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=JGa2TWiu;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764863767; x=1765468567; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WBvhKilX4oBT0RhAZ4u8yT1S/4FJYc4QflgjWNkyXqw=;
        b=JD5reIEClq7hI/7tUEULDZYlV62ntY1n1OtdbJSd4LIm58wk57aikHFgOMiSS0furP
         DeCIj72+B6md3v7xpFSx9tTM93Kx2Db7b38kAAS124QuvIkz0QONTdS9KNmZjNsCPdvh
         Iyl+ZOlW2CWhKE3lxij5BF0iweFjp/8dJUzQU29uAJI0ROABg+YIznMgv8lisTPxIsAN
         0xgzcurTgNBabn71SGtEJnJvE7DfcVWogXqPCU4ePnfHAhWb9jcwwURGKRZzmEX7HBi7
         kjxlXiIzZXCabkfxmpRQ+VCupltPvVUHsALxPTjMJYkf3IzCSgAn7bk79UIGCVc/cFn4
         /eYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764863767; x=1765468567;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WBvhKilX4oBT0RhAZ4u8yT1S/4FJYc4QflgjWNkyXqw=;
        b=o2BppJdabxmnxcdJDiZ1Ebz6g88uikMshU6iySDW9lmKQa/96Bi1XsrsjUMP0DQST1
         D9Teukmx4VllDbvjyx92psAB8KgHfJT5EmW5mchuw8+ZT1CZFGAEcXcAF9Ip+vb6Aw4E
         p9hhCi+KE25kQ5nc0IlxvQ4yPnB87I/+L/JjZTtPqM2DQ4LWf7NR/E8zLX5f+HktNOWE
         16K62UvoTiRSzjUe+bDxkZdZrbyfNLZiZIihGQPI3RY0MR+sv4zY2aBXF8VAsN9Ug7p/
         7e1TNeO5RF2KgTSus3VUXR+mYMvS4vsyarX0+ePlOnEPRut1Q5VgOXerkzr3bEuFn+IE
         RcCQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGiL6V0WN6FcOwqFThf8hfYb98cOepL72jJCcW7TtwSlnH2KWoKRApFuplTcQIxRmbWaWonA==@lfdr.de
X-Gm-Message-State: AOJu0YxALE3FIOgTu4D+7BuCQXpGnnnuPLghlZy20zRmezlcXo925bIH
	GaHdDwDnLvma4HTzm50sX3RZY7f9rOFwxQyJK22fIwAK2Nm04oPqB1a8
X-Google-Smtp-Source: AGHT+IF/VHHmkgamCgNsL4oOFEBo+giCHCVXiEpMVFmkFl9CmKeSJeSQrtX0lTVCazIiY6+SNsBQKA==
X-Received: by 2002:a17:90b:4c50:b0:340:b8f2:250c with SMTP id 98e67ed59e1d1-3492104897dmr3363596a91.1.1764863767327;
        Thu, 04 Dec 2025 07:56:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Yu+4xnnm6TASWR9125XmUEwCY4eJx1S5p9o2F4jRKDYQ=="
Received: by 2002:a17:90a:dd92:b0:340:be7f:c37c with SMTP id
 98e67ed59e1d1-3494da362e8ls908954a91.1.-pod-prod-08-us; Thu, 04 Dec 2025
 07:56:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUD1Z9yRXYz8cqaZEQ+aIs7Bs//DAKz56xJQMC20s/TELJYBSHLo5d5cJEOA7T1wqzulQc4Ed9e9z0=@googlegroups.com
X-Received: by 2002:a17:90b:388a:b0:339:ec9c:b275 with SMTP id 98e67ed59e1d1-34947b601d0mr3752285a91.6.1764863765649;
        Thu, 04 Dec 2025 07:56:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764863765; cv=none;
        d=google.com; s=arc-20240605;
        b=Sf3qNt0Z62sOul+wW/bzd/zBRQMKR4NlYKJ6nJzPczYWAMZvx/V75cb3KmtyOZlmoZ
         kLB8J90TDi3boj6bg0OwYWGuoUOO8IfeRczzPJ3OKeDLJijV1oM8jiS5PqKEbhalPYNg
         DBjwSnqn0j/kfO5DbPFTGiN1+KZIYOzziWuyPgXv678TI2/y51TQ13msEUt2WDGv1e8a
         ei210JeTao5SwWQv3jU+5V7crc4dCZqwaVReL7e29YUK+dco9L0eqM2VS9pj/6WReDbY
         AmKinuqpO/ZYj44CFhigkhMdcxU5o6yk7OdJUGNGfNaVcNP+QJKVujHSu6z3VAJG+kyT
         h1ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Mq0SWl9iyU3yIW6aBSVSxHhPulPqk2disOphQYpPRDg=;
        fh=tQB7WLspYTzSsZtWFRHhHkKlas+A/V4tG4ak97qe0Mc=;
        b=AR7OnUsgXSUtoL5QIR4HISN7dnbUtZ96SL60C6dNOKqQoOLlqiMUIpbSWo79Bf6jp6
         l5Pn1A+OCrG9W2dw8FDjgtPjLdXKEwFxXhSYjgHgnPinckihceWaiinyibgXBiUT1cql
         y0p6GxJ0petRAxKQW5eMar2lBqRIY3b9dDCNZKE0LknMNP4EGAMUjEfAglTugu5qS9Kx
         69Ho/WcGMCQPM2LJcsWNMEfQq3vWZDgIgFLdkHQdp806EsEr7FFxOVx1kdAV4AacobDJ
         yDQ6ljQDGNmlGzpfuntpuI5xIz4Wz61U3zLDKU4dOkmP+rmmpr16llxDpD6J+WFeIAUQ
         Gl2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=JGa2TWiu;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-349129ba8a2si54251a91.1.2025.12.04.07.56.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 07:56:05 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 200E6440C5;
	Thu,  4 Dec 2025 15:56:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6C05FC4CEFB;
	Thu,  4 Dec 2025 15:56:04 +0000 (UTC)
Date: Thu, 4 Dec 2025 16:56:01 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: Andy Shevchenko <andy.shevchenko@gmail.com>,
	Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com,
	andreyknvl@gmail.com, andy@kernel.org, brauner@kernel.org,
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com,
	dhowells@redhat.com, dvyukov@google.com,
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
	jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	shuah@kernel.org, sj@kernel.org, tarasmadan@google.com
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
Message-ID: <2025120431-squishier-cold-8cde@gregkh>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-10-ethan.w.s.graham@gmail.com>
 <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
 <CANpmjNMQDs8egBfCMH_Nx7gdfxP+N40Lf6eD=-25afeTcbRS+Q@mail.gmail.com>
 <CAHp75VfsD5Yj1_JcXS5gxnN3XpLjuA7nKTZMmMHB_q-qD2E8SA@mail.gmail.com>
 <CANpmjNOKBw9qN4zwLzCsOkZUBegzU0eRTBmbt1z3WFvXOP+6ew@mail.gmail.com>
 <CANpmjNNqCe5TxPriN-=OnS0nqGEYd-ChcZe6HQxwG4LZMuOwdA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNNqCe5TxPriN-=OnS0nqGEYd-ChcZe6HQxwG4LZMuOwdA@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=JGa2TWiu;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 172.234.252.31
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Thu, Dec 04, 2025 at 04:42:37PM +0100, Marco Elver wrote:
> On Thu, 4 Dec 2025 at 16:35, Marco Elver <elver@google.com> wrote:
> > On Thu, 4 Dec 2025 at 16:34, Andy Shevchenko <andy.shevchenko@gmail.com=
> wrote:
> > >
> > > On Thu, Dec 4, 2025 at 5:33=E2=80=AFPM Marco Elver <elver@google.com>=
 wrote:
> > > > On Thu, 4 Dec 2025 at 16:26, Andy Shevchenko <andy.shevchenko@gmail=
.com> wrote:
> > >
> > > [..]
> > >
> > > > > > Signed-off-by: Ethan Graham <ethangraham@google.com>
> > > > > > Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
> > > > >
> > > > > I believe one of two SoBs is enough.
> > > >
> > > > Per my interpretation of
> > > > https://docs.kernel.org/process/submitting-patches.html#developer-s=
-certificate-of-origin-1-1
> > > > it's required where the affiliation/identity of the author has
> > > > changed; it's as if another developer picked up the series and
> > > > continues improving it.
> > >
> > > Since the original address does not exist, the Originally-by: or free
> > > text in the commit message / cover letter should be enough.
> >
> > The original copyright still applies, and the SOB captures that.
>=20
> +Cc Greg - who might be able to shed a light on tricky cases like this.
>=20
> tldr; Ethan left Google, but continues to develop series in personal
> capacity. Question about double-SOB requirement above.

It's the same natural person, so only 1 is needed.

thanks,

greg k-h

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
025120431-squishier-cold-8cde%40gregkh.
