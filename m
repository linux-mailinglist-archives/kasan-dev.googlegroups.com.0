Return-Path: <kasan-dev+bncBCMIZB7QWENRBDH6UOEAMGQEKD6RCMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 077BE3DE87B
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Aug 2021 10:32:16 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id j22-20020a17090a7e96b0290175fc969950sf2303374pjl.4
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Aug 2021 01:32:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627979533; cv=pass;
        d=google.com; s=arc-20160816;
        b=ggAnzqE6Cyqa2Tphq/qTU7cojKhPEm/Mi9Ip9FmrF51pY8aEtsYyBUM89Te4LHUf/a
         yvDJ1jcXbaZdkmHZGuI1WF7PYY6mneYWoY8A8BHcMEquuFi3NQfm/r11dgWCjJpxZvm7
         yPYCnUOfY78uf87emxZugqbgJTy0zct10WCnLF6mzyor8GFoaqPFU5AIiGEWfxSscF8G
         tfG7tIsJa33wCRdSAkyjyY3P35iA7ptxRcMAiQNwN/iyielYEH48YdA4O1e5aj4tNnyk
         6gLYAFKnPHOHiESJlCaknu9id68o+rSsHciQCHNJsGPAGBXEnnqqh5Zjh6lEWr15fybO
         mEeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Crsd07xSUL50ZPxRMfuTOJ651y60mwpH5zu2ppEklzY=;
        b=HiuCUEY7FaMhZhamw9l8+ghIInvOGw9Hxh8rGarj1dAxgHPjS0/nY6RQsa+SSae9TM
         DmoWpq8X0STZDQqnnsv60Lcxtn47UJ9LaaDRU35Hp34KlO1H0elkJVRa0PGpgDoFHvbX
         WBFmCABJ+cXQptzCnKnmqs42/0g/HToCpPjKu9a7blJUK24MDna6VsflHszGLOduDN5J
         fMmfXepIUVf02naFhMVnb2P5mUR854N26tpw1FphTuXUwMs5tgwDMh95946hacnqZEoR
         nRsphwsAOf/simrt6TAXlL9h/70NmoNcmou8SGr9EfZ44ZdLFc+c1VtucJH0inDMSKYA
         hAUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bP+UZ7Dc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Crsd07xSUL50ZPxRMfuTOJ651y60mwpH5zu2ppEklzY=;
        b=fh+KFoMEUyKV7jVzLe3OQf0rZMzAChPHnVMvIRnoeeqHjr443gOUL15fu26o9vD6UV
         a3FLkw6BEctoXCRLA0SKoKOEzLqUqIBD8sCaLBGJuOszBTajvIJuffHjVjNLLJy6f7F5
         Y/9haL7qWeG+wuOlTeCrPycM2pvR2xP41x2US9xuHnVa1XTRZAlSRoXaC2TBSEZPmpsu
         e5pAwZ389AMhsHYpl7dqaj3CisZesRJH/hsxWvgflP+Hyc0pQkE2cp89s+cwwSJIw1vN
         apIDPFY9Yoft6sJJVbdr0gDho93Mu0GCZEQ+mrzEEtf/yBDYLnu6Y2gP1QElwefutvY+
         bUvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Crsd07xSUL50ZPxRMfuTOJ651y60mwpH5zu2ppEklzY=;
        b=RcKdBZbcNaLNSffpDiiP7/2dswly6ak/iJj79w/NBhYd4X6+U3m2z9m0DBu/E03y5d
         xyBTvnp3jmmiUxddko5VxLg4poVpan0nmuKxZnwj68SvvUENcW9JJgi46eRl+QzVRDxx
         euIBhi0XlLpgBJWODU8mDFgnizdEp65wKZqzU8/shnus9d4zCFz/6ra7tkHsuiCHq29Q
         aEF0xtO0ykCTVuFB6PFLscVyR300V2Uo9fA7grPZxstB4cwo+wWgOLk4/DSA7HCb7qp8
         EM6BEvccZdi/9RnsMBDY8I5IiC5LbNul13POJS5GboP+VLHLXo0KnJh3vGJyRw8OlmD+
         /0Dg==
X-Gm-Message-State: AOAM5300Q+c53DMh1pLT74I02D3DbUOzeXa7Hv/lSV5uSFNb9vJ/7suS
	x+QDStZONkro/t2ERpuSKyM=
X-Google-Smtp-Source: ABdhPJzg2ezx2U252hoAN23Zhe3zVHHvsUScC2t8jiXQE/ajj89zZyMFoicERQ9hl2HU6LAgrdW07A==
X-Received: by 2002:a05:6a00:ac8:b029:320:a6bb:880d with SMTP id c8-20020a056a000ac8b0290320a6bb880dmr21344434pfl.41.1627979532485;
        Tue, 03 Aug 2021 01:32:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8f:: with SMTP id m15ls6714091pls.3.gmail; Tue, 03
 Aug 2021 01:32:12 -0700 (PDT)
X-Received: by 2002:a17:90b:4b10:: with SMTP id lx16mr21736871pjb.53.1627979531896;
        Tue, 03 Aug 2021 01:32:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627979531; cv=none;
        d=google.com; s=arc-20160816;
        b=AvcdjX+whV0Nq74Mg9ZnvN8HsprIFy+8WEM081V07pjXwKbOImwEU9TiNnX3WjApCP
         93emrpSJXKp7XrxUkYzCjbrl9a2WDp4/SDJ6WQtmIBcxxdhGD41tEEb2zmbUfVZTzWkN
         RheYtHSfsgNO3O71r9hlLFKPg5at+IG1tLoXrzh5UyUHim0E+b+hpXV1UXvaxbni70TY
         jhjYtrXPme4cbZRbg2fd3MTAuzuw5Fm58m0FSOVMdzTmWVETby1NurCaViTpLLjWnT68
         RfGneUPIFEBADz3gSO3/HEf5cTFDEJ0fzoEdZWbD5JQ/OOUg47O6sNG+8qbB4vkvmP3x
         ByrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HYEhFfE/MgNjcUJSNA/EikiumZN3elnlgDSgoG8S+pQ=;
        b=DEDDXgBhQE/Xl/rmXtFX/V6CfVYe/le5gximancmnqWvIVHnpmG6Hkws64FJKTnI5t
         lDfGh3qs5+ZFEeoE/+Kq/t0+pLwxD2pn0unFHGmnUd2sxKLk8v1dTrJEOMJNfAM7S5ai
         OzkMR3Ru6uOfXGUMphs3hzJNUBnrTaR/X8avbiwJsXALjkhkqRT/vrGXFezojMuC3Y/+
         jEsAyEvFRHGu7aRNSfnApXgwBSKKb6f7M4UD/Ec14qVZMk+eV0SBCEI9hF27nqoRa8Ey
         FPI4+ljJmCBtTI9lJVsgo/tbEhANEr4zv4+A62LX+RSEfKRlMmNCCQytmFJ1f70Vite6
         pU+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bP+UZ7Dc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id 136si827348pfz.2.2021.08.03.01.32.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Aug 2021 01:32:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id f22so19162681qke.10
        for <kasan-dev@googlegroups.com>; Tue, 03 Aug 2021 01:32:11 -0700 (PDT)
X-Received: by 2002:a05:620a:13f8:: with SMTP id h24mr19221798qkl.350.1627979530958;
 Tue, 03 Aug 2021 01:32:10 -0700 (PDT)
MIME-Version: 1.0
References: <bWmJIaBTNCVY08GLY-AFFzLkFRIWs1NxOLdMGyWgELKsksOzGEb6Q0-wWCYHrLMJmqM7rxNIRA5mebViNUXT8czz4KAgyGhmXCoKmtE_yqw=@protonmail.com>
In-Reply-To: <bWmJIaBTNCVY08GLY-AFFzLkFRIWs1NxOLdMGyWgELKsksOzGEb6Q0-wWCYHrLMJmqM7rxNIRA5mebViNUXT8czz4KAgyGhmXCoKmtE_yqw=@protonmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Aug 2021 10:31:59 +0200
Message-ID: <CACT4Y+YJCJLbJdP7r0EdbMfqxCqYgMA3zFg98wpPAHJE8QzZEg@mail.gmail.com>
Subject: Re: Enabling KASAN On Select Files
To: Mike <nerdturtle2@protonmail.com>
Cc: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bP+UZ7Dc;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 2 Aug 2021 at 22:33, 'Mike' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Hi,
>
> I see in the documentation it states:
> """
> To disable instrumentation for specific files or directories, add a line similar to the following to the respective kernel Makefile:
>
> For a single file (e.g. main.o):
> KASAN_SANITIZE_main.o := n
>
> For all files in one directory:
> KASAN_SANITIZE := n
> """
>
> My questions are:
> - How can I make KASAN disabled by default and just turn it on for specific items?

Hi Mike,

There is no existing support for this (use cases are unclear). You
would need to modify Makefiles to not add -fsanitize=kernel-address by
default and then some way to enable it only in specific Makefiles.

> - If I add the "KASAN_SANITIZE := n" flag to say drivers/Makefile will it disable KASAN for every driver in the kernel or do I have to add it to every specific Makefile for a driver? (eg driver/superimportantdriver/Makefile
> - Does the "KASAN_SANITIZE := n" recurse down into/take affect on every files and subdirectory in that folder?

I don't think it's recursive, but I don't remember exactly. Should be
easy to check by disassembling object files it subdirectories.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYJCJLbJdP7r0EdbMfqxCqYgMA3zFg98wpPAHJE8QzZEg%40mail.gmail.com.
