Return-Path: <kasan-dev+bncBCSJ7B6JQALRB74IUP5QKGQEPUJP7CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 89E7A2729CC
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 17:19:28 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id e21sf10181230iod.5
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 08:19:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600701567; cv=pass;
        d=google.com; s=arc-20160816;
        b=L7SPwnKCTUQ+bQhF+rNH2rfPZsgeT87/lwaYUkbS2KnK21TWsUVElAShHDpTIgQBMC
         +RsvxohGekLH/KpU6oIdkmUQf6kOCKD4P1otZJ1lvjf5sC5VZrIys6hsw9MfPLqf6dK3
         jhsYKqU90y+qAKewflGIiVLdv8dBBR5RbCAJPq58zAy3Aa7wfDtFzbocFJBI5jgNfvwZ
         rsX5HIDhxU9lpyN+yOk8aFEp8PZqWNi1/rgiiwvwTnV7lqp/2ZOYWO7lZ6w0yFUL53EV
         Ml5MU3Nb9zQ89sb8bkneZSMnzziaZSNp8nXhNVnf7hRaYEDWRp+Pku7pN40tMpVN4eb4
         qzow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3+ZrP/+P78w8l5DX1WTcLhsl/NI6tk/BG0I145C/T+A=;
        b=jMXwWjxQDdnfx01m25lbTRpWkRm5Mk1Bqe3TiZs42r6s22555h7xyhqrrauo37G4Wn
         fljAHlWYCoWYHjtAj3v0sFqkE8sCcdQxFAFKUj6lAMQ5FNMHMlCoFcVwLres72rIIs7P
         tHkEIYXN5FnpewTGovvIQP06I/E+krRbPHBN6LJHTuJzgQBV6iR3vKHC71diG6zUAXc+
         gK/aeOzt+GhZmRAXxCJVPlLmSRWb+SjOpQFnYuM3tBVXGRrZHl2eU31Cvs/yNYY9KQZa
         6VNrBQUgTg71h0ZGxzyVn/XpENmSfZjUuiXjIkgNBopj7jr4hpyEHel5whrwVOknJqnc
         0qtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IOBjkXZU;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3+ZrP/+P78w8l5DX1WTcLhsl/NI6tk/BG0I145C/T+A=;
        b=LN2JJDsapMuPLk9jOGmMwbkiDcsB2e46HRbuReacFTZNApD+bw5iOXr9i07RTKDB5F
         dfNTl+I5eJgZwLAJYR8EI30WVMja1B3hG32dNXA4s+vr3MPMato0A5QAZeHak/DSLVKB
         N9A3LsASdCmfG2nzjQgphlTacyohbDzmaN+7rX5UEVE44x3N8YgMlstR4DXy+G9A/rGP
         xMNWq7xFvVvkL19oKsdTS2MFvz9KYRAAu+QoREOEdEZG0KCLFr5MlPLirC4BngWzTTeJ
         m2E/2PKVOLC35D5epbw8LGgWJ8PV+6wLMyRsLdvbeXd3hfqK/QSwaz/z6xW3uq6pEMYc
         +fEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3+ZrP/+P78w8l5DX1WTcLhsl/NI6tk/BG0I145C/T+A=;
        b=N1jU89a16UIQUnfGb1kLoNy8eXM+R6KE0JlCnTUwDIuG6wkZ304KspL4wuwGjik8BJ
         KBDtx4mx/5kOhhqvaBS8a/R+RlXBLnzNtU+5jXePa8vnOlRUaz8Hxej2OGxMWn5BRdBu
         JQVydu6Dsot+XSFWD+kDcOkvTKnmpwcbOVXnX3bHt2VEdRkqHS/5OJrgv9ETVsMEjvNM
         V64Gt0xL/QQ5Sc/ecv0rHq+P3Cj1tqKJfpQ71c7MWfLh9OEzTvD70NFliVH8APasQp5U
         Fws3st85Yxxux3JKNn6ebkreViBhX8KVCzCuDipMj580r0JyU8mdDdU0sPNlkrO/m6Je
         281g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533nhtONsrmd3UnrIcmp0WxAfCxbVr31y6UnDMo5oLKowl1FBBAs
	xVP1Paf0+fIKtDmbbB5rX24=
X-Google-Smtp-Source: ABdhPJxR6ScZp+wUZ8w0zHLe0pmHCWoSL++SdzuV/Utft8cXx0Usc2KI7KV6zf4w8NqeLYIL4e++NA==
X-Received: by 2002:a05:6e02:60d:: with SMTP id t13mr371355ils.196.1600701567211;
        Mon, 21 Sep 2020 08:19:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:770f:: with SMTP id s15ls3183912ilc.11.gmail; Mon, 21
 Sep 2020 08:19:26 -0700 (PDT)
X-Received: by 2002:a92:b68c:: with SMTP id m12mr356346ill.71.1600701566856;
        Mon, 21 Sep 2020 08:19:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600701566; cv=none;
        d=google.com; s=arc-20160816;
        b=N36qDfLZmCGHDBUgevtSJmKeQl4MRv0mCgRKPVNtUle3S40a05G/vAUG8V45aK4qed
         K1ObVOUbjTw4lvOryqezOzjmAvstewmJslZ+CwL7hCmzWgmtixCtjo2APzv09J5/xM5I
         DEReKvNWnQAobG5M+e1h+bSaSNGNrDYQBATTeZfWD5y4+0raozulutXP/qYo6LN7HfH/
         KAIqR2LthY7a+S4BtQLD1L7olpBoi5Uy2dT1VddfwWbgZoNE79UF3PTlZ8r1iKUvlbav
         doPuaEfZtDiqARMFdXp7FEZf/+RnMkb/xpa3gfulXi/aISRDLZoMs5HHwrZEr/LsHAtB
         3DFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=78VYwFftorgadheBNYzJKmL144uRfgx6TOEZIwj+BGo=;
        b=Pfwa+4X7Uyi/UPQxBt5cpLnkynx3aG7o6L5bUHTG48wRsXaEU6A2Je5t3DskFGVnBA
         nhhENQ934TNDQBODo2oj7ByJq4zmFeEVmoymfmffxywvUWq97Xx85Di3pRWMJAFc1ye6
         U+/yc1udIl1eMpWWT/Iysd8NtKxe1vcWfjHPxHguwCjeWsjHJULy12tjYt5erCtxCxdi
         Tc44b0HW9/mgXqSYPN40S66eXQ2jpp3Yv7YHEzKNqlH6kD9aP5jGt865u/JLSAhFm4ue
         ekF8PnITWLzKCd//ofOcl1PUh9uLMnHCC3TuuCBuaW4bseP7TCrpGuTU78YlrMx5Lg1t
         XVcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IOBjkXZU;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id y1si985036ilj.2.2020.09.21.08.19.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Sep 2020 08:19:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-535-gNN5vVhCM7KoxqTm9vt0JQ-1; Mon, 21 Sep 2020 11:19:18 -0400
X-MC-Unique: gNN5vVhCM7KoxqTm9vt0JQ-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 567BE801AE2;
	Mon, 21 Sep 2020 15:19:16 +0000 (UTC)
Received: from treble (ovpn-119-131.rdu2.redhat.com [10.10.119.131])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id ECE9655778;
	Mon, 21 Sep 2020 15:19:14 +0000 (UTC)
Date: Mon, 21 Sep 2020 10:19:13 -0500
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Ilie Halip <ilie.halip@gmail.com>
Cc: linux-kernel@vger.kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	Rong Chen <rong.a.chen@intel.com>, Marco Elver <elver@google.com>,
	Philip Li <philip.li@intel.com>, Borislav Petkov <bp@alien8.de>,
	kasan-dev@googlegroups.com, x86@kernel.org,
	clang-built-linux@googlegroups.com,
	kbuild test robot <lkp@intel.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Nathan Chancellor <natechancellor@gmail.com>
Subject: Re: [PATCH v2] objtool: ignore unreachable trap after call to
 noreturn functions
Message-ID: <20200921151913.rrfbqfnrhfmb26w4@treble>
References: <20200918154840.h3xbspb5jq7zw755@treble>
 <20200919064118.1899325-1-ilie.halip@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200919064118.1899325-1-ilie.halip@gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IOBjkXZU;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
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

On Sat, Sep 19, 2020 at 09:41:18AM +0300, Ilie Halip wrote:
> With CONFIG_UBSAN_TRAP enabled, the compiler may insert a trap instruction
> after a call to a noreturn function. In this case, objtool warns that the
> ud2 instruction is unreachable.
> 
> This is a behavior seen with clang, from the oldest version capable of
> building the mainline x64_64 kernel (9.0), to the latest experimental
> version (12.0).
> 
> objtool silences similar warnings (trap after dead end instructions), so
> so expand that check to include dead end functions.
> 
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Rong Chen <rong.a.chen@intel.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Philip Li <philip.li@intel.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: kasan-dev@googlegroups.com
> Cc: x86@kernel.org
> Cc: clang-built-linux@googlegroups.com
> BugLink: https://github.com/ClangBuiltLinux/linux/issues/1148
> Link: https://lore.kernel.org/lkml/CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com
> Suggested-by: Nick Desaulniers <ndesaulniers@google.com>
> Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
> Tested-by: Nick Desaulniers <ndesaulniers@google.com>
> Reported-by: kbuild test robot <lkp@intel.com>
> Signed-off-by: Ilie Halip <ilie.halip@gmail.com>
> ---
> 
> Changed in v2:
>  - added a mention that this is a clang issue across all versions
>  - added Nick's Reviewed-by, Tested-by
>  - added Reported-by

Thanks.  Queued.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921151913.rrfbqfnrhfmb26w4%40treble.
