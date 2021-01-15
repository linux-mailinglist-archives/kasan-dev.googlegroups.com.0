Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHWHRCAAMGQE2H5BWIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1367D2F894D
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 00:22:07 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id h15sf4895597vka.10
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 15:22:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610752926; cv=pass;
        d=google.com; s=arc-20160816;
        b=bEzwaG+zrd155Bwqub6ulDVfY+PHCSwjijCMYeQYtwQgjywN15w1YKWleaZhTV8OBt
         jGIRbFPGkUeulZTFoVQCDHtkF7sJwUgViZOvfznJg9Mw0eCP/FK81qBKvuN8a2I4xFTS
         RO5yhgAD+IEBOcnn2fHPz5wde7GJSXJMs95UnPJGrvgAY1J2Pr67EzjOiKd7XnRXsAoX
         Gdb1M5v+MjPEyK15S5C19BT+iuW1vPTqO9/BEBBGgPKrBuTkdtVW9SMlBUlD55Ehh2ev
         mSYnmJgm4ZJlP3XNa5gOfu+qyN7O/KnaoLUZt2eO8pENqJRQk+eOipjwA+DgCEU8nyWi
         qAoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VL/S9Rex/83fAm4NMbJ4u3PQEISPnv/r+Q1z7zeaZ44=;
        b=tZGMKjrfNqU/CgRng7ilmepGcH6rsLk3AWCPEpwCLcc4zJHUSR9hOb9uqaWEr9V+Lj
         oGdA+7Z4R878eXiHJFABXQiblREyNXTgwh9QkUYVTtkmPGXlj7k+dAgrWbQc6eT9fEY9
         Knc/SZQRo3wUWyP4fBBd38mSaGeZW6BCrz3ytSsaY7xewdwdALIufXDEJQ7AV5xJPwy1
         wJqgN14j3veZFZs3mGv/vIId2xewmUOkyM2Y93WZKsaXrHQTCBgwD0CLgwMDy/lVwz1I
         z+2FEY/Hb1mc7Nd0crhDtVp0McLogXBpN23e5VEuq/Me5kG50stb1+Y/uoFWut02S7/y
         ELDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=heRLg2nu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VL/S9Rex/83fAm4NMbJ4u3PQEISPnv/r+Q1z7zeaZ44=;
        b=bKt1Iw6qhBhmRGmEZ/tLVuN6tIQnVKXpVQpjEoPdA0vQ8kTKet80tdb8nimd9nsIal
         Daarv/CGY/MA6OBAlm3OMU7ut4VJQAFc/imLGbVWllmvR57HfhYL2wIbFB/3KnNPwlMb
         rxYmFkDEI/of91IOaZIXRsBwJYaooZjXgZvQG+xJ/5FE9mnEaEjQdLuqmlso8gFxZQ8B
         SW6OSV0SXMNkDeRjWtW/TDTE3ETNdaDgxK3JfBr81toaTicN6tUJRJ0uPWzhoNomEOv/
         rXkZLDu5FYQ/oHnC4iwp4lG8uullWsxE6RJ398pkNen0ZjhetnoDQUiLb4sR1ZTnKOlA
         CgDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VL/S9Rex/83fAm4NMbJ4u3PQEISPnv/r+Q1z7zeaZ44=;
        b=ku4zV7l5MZY4Hq4hStivmYZiGhhG+929YX/7Y4txHb/HwV7aWI99r9hKFh8QDwA7+S
         CsTPmTGAZJk17ga2BjiRIGs7USVeY9Ap9OgbYkWQ9cJEZ7Y+7ZEbK8pgGc3HPegVfV5/
         PSAziCVTdP5bsic57+G3PIVko1cp/RIJEEapxWgIAUD/4IsJ3t8eujLuSPJBJjNQ9c7p
         dflbouPYyMAEpYk1CcRNYH36BqlskLkSej4Iq60lOmy0BEM4QcRj6YO0xdg4kAO9vwLl
         /mf9+KDlGwW8FAiLp2YCz0Lx/yzvpktRQWtCJEJT1RgT4gcEWQvxhc09bBMTbht/JUNs
         R6XA==
X-Gm-Message-State: AOAM532FyjM7cwVA5afqtaRJO8IlodPEcNdFq7j9Ss3AmQrf+UK+/mLA
	TPnyVSc0qxKOixfYgZdd35A=
X-Google-Smtp-Source: ABdhPJw5ADSYSJMwsQJ807h6svQALE7Kdmi291RYf90BzGPsVWJgsdGEzv3sckm0rHq2gG2jks+XJw==
X-Received: by 2002:a67:6908:: with SMTP id e8mr11628660vsc.35.1610752926115;
        Fri, 15 Jan 2021 15:22:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e287:: with SMTP id g7ls1492605vsf.5.gmail; Fri, 15 Jan
 2021 15:22:05 -0800 (PST)
X-Received: by 2002:a67:e90d:: with SMTP id c13mr12883673vso.0.1610752925574;
        Fri, 15 Jan 2021 15:22:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610752925; cv=none;
        d=google.com; s=arc-20160816;
        b=VdFiT+s8sTQ1t0X6yBy4IxUcCjzu+MCTqrqTUUdAAktFlez4VkOdrW/o6UFFX/3l5c
         ehbxJzpF3gwUnpL45/dtdCOmt4EroOEHozaWBD2i7axxMAG4ke6HNpzmUP0LbLVbqbLS
         d5vC8EVumXFhkDKK7UT5E46eQPTRi8aFj5DIzN87cgu/1zYDEFhrezX50J3X29dwlQ8h
         pZyFjUTakCuehcY9Ly749tAvG17QMwtHV8RzgWmirNDkHwXx/u5JoPBzh2pMsB8L+F6G
         T3u6Afd8b+cAiShtj3c5mgWxc54AvQ+9y78/tZrMT957Hs98o9zGB1XDJ7BfScY9Topn
         pLmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zvpNSvkn/fPLpmBXk1T0j4u5eWw0h0OZrt7MVAhdTdg=;
        b=cqK1M/kuGDtxhrJ1z7Cd2XYH1/EDXQE3YQk2nA6tvq0g6bv2gev1fLKloYeZmZytg4
         3Gc+kSWGIR0KROg7NjVqRYV8O9Ax6VZo4TnNxvFrIUuTbvc/Gi43ha5paA12Ju1xdn0H
         yXZq27EhM6w7dgVqgx6SOcJk1GTSc4DcUaCnHGjnT+1bs7fgRc7luovlOeSP0AkyIly5
         WDGkn/uh3LvUCGoIP9qJSJbaVQ02fQzdWQjDgxGn7kZIkA7885DljRMUAl5LYBJpXfqI
         HFCIKR19x8S3eJMw+ftbMxEYQVTKuLzcxoWmsILi+TDxR+/KZ4CO0MZaUifV69oOyfOy
         XUIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=heRLg2nu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id h123si665962vkg.0.2021.01.15.15.22.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 15:22:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id 9so11314571oiq.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 15:22:05 -0800 (PST)
X-Received: by 2002:aca:58d6:: with SMTP id m205mr7136601oib.121.1610752924862;
 Fri, 15 Jan 2021 15:22:04 -0800 (PST)
MIME-Version: 1.0
References: <20210115170953.3035153-1-elver@google.com> <20210115215817.GN2743@paulmck-ThinkPad-P72>
In-Reply-To: <20210115215817.GN2743@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 16 Jan 2021 00:21:53 +0100
Message-ID: <CANpmjNM9++GSuSHH+Lyfi23kW8v0aXLX+YbD20UX8k5jAAaSnA@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Add missing license and copyright headers
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=heRLg2nu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 15 Jan 2021 at 22:58, Paul E. McKenney <paulmck@kernel.org> wrote:

> This one seemed straightforward and I heard no objections to the previous
> two-patch series, so I queued them for the v5.13 merge window, thank you!
>
> If any of them need adjustment, please send me the updated patch and
> tell me which one it replaces.  Something about -rcu being in heavy
> experimental mode at the moment.  ;-)

Thank you!

I would have given the go-ahead for the other series next week Monday,
but I think that's a holiday anyway. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM9%2B%2BGSuSHH%2BLyfi23kW8v0aXLX%2BYbD20UX8k5jAAaSnA%40mail.gmail.com.
