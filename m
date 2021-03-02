Return-Path: <kasan-dev+bncBDV37XP3XYDRBE667CAQMGQEZPXUP2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CA96329E46
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 13:27:00 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id p1sf1411486pgi.16
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 04:27:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614688019; cv=pass;
        d=google.com; s=arc-20160816;
        b=V6oZXZRrMlkQBRcO2vgZt8glPZ4PEX/g6Fy+CDK8Imnw5kb8VEEwsOzrE1Dj1VJE0g
         V+oLIz7+n+S0rnXp7CSyOkVrMprau8TPHgHBhQcyzZggQvND/6O/H99gquo7b9s0FblF
         M4PuolJcxfX3Rby333meGb/2VaLQ5dermNZewFjyH+EfRFM/rqa55nlOMAGadOQtG7gF
         GEOd6sL8fmkn7qhYfm4D2mtzJqXZwpLjdPXIRclJQY/670eJNjvJvttSsxXPPF76SS9K
         K5nYjdIJrzH9ZzfKlbgGP89cZoN42rhd/9fcIwRYbv1ZkSdQZbRrr+wglJCNKRIx6Q5I
         eZqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FFQt87m3TgdfoZ169jfpam9oAu9DoRprGWrTdHXC7YY=;
        b=NUq4tWNB7DpMAMND6rfYkMwYWS8jsGxVplIbDgtGQ+hiedFDOb3QOmvrWcpLluhxCG
         oj9kKY5+MDD+rrB+dbf/AVxCnZCycm8ytF19VmEHLEJEheYFIJIBvpGqD2Z8T/QDCrI+
         58FlL3UgLX/ERAzDBl+b4e7iUx6Yiqpy87ziPNo8vR78ITygjeTCpO3bYIy3kcLytLj5
         AiMcJIR948+sa4EUe4JsAMeK84zJZ3pVgCZOK+V0qXZyjBB58K6ZsECJEB1XW9im2kBK
         jvEqoSz/W5oz32+D6d2jvYaUHa44qQLKNMs3z5+YZ5lj945aGJWqaOpFtLz2K8EWgcke
         Pf5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FFQt87m3TgdfoZ169jfpam9oAu9DoRprGWrTdHXC7YY=;
        b=LuDmEaWPkgFjVnBkrhR/JFBJuTVgxTuadaxlhVY3u762HX4UFVs6xtOtrug170Hcr+
         48QTuOODXO109UcMAH6RBGNav3tA777yCKeLXXAIZXHlppPr4QmNBXhbM6u6dUDZayAr
         CcDMqNe7bgAhSSajoXtNa/ExMPeMfVul44DMl0SDQOeLfRWUeTxXcmGyi319+EuoAIzC
         yu2YHGWjpr9cda/0iSLMHrumTLIHBtk/1xKMtrb8McIKGZ/q3Vslln+B6nIZoRY7Mqmt
         ZKOn9gMFLADIZdKT7vmGCMbwjJDAVyLbLw0TUzHlgEAo+IpEaGFcmzrBtiXMYuCgUC+l
         rhCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FFQt87m3TgdfoZ169jfpam9oAu9DoRprGWrTdHXC7YY=;
        b=qOk2KC0aYqvhR6B6pGkFyK2KDGy8h26O4V+vbUhssItdLpvijvFsvAZ4NKMejm3QBZ
         6oKOQ1SMXkF52mTNuVXfVvJ9eE9fE+3amB8+5VnAm3fnSteOYdL8M3naau2tIEuDirVe
         DLE0bpU3WfOUXZ1QY6aVsnqVlIvR0AUyubwIXkJn+N4Flztrrth0Aslo3TGMHoetwFwv
         5BKdGEu+awhGd8VOTvEPeDzRiLt4j8QqLJyc6IStUi/AcAj99lfxf3EU08SO8CgSYpl1
         Ws3u+JavFh+zaeRMomoBPDhWLmFDSjZnJbuHxgwARdEp7m41IoBpcNj14sQXIozlBvKs
         uGxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kEhaeQY49Qbh50/yngLjEh0BF6ROm0oF097OM4tYQ+Q5qlXNe
	HG2+I9T9ApRcGFmuNeiRCco=
X-Google-Smtp-Source: ABdhPJwDSi+G4oB6hGIrNNMGyfo4S0PPUtmp4KQ7OsA/5CxuBgx/SdLzhwdpzLAwV2f1y4QkAFK78A==
X-Received: by 2002:aa7:8b59:0:b029:1e9:8229:c100 with SMTP id i25-20020aa78b590000b02901e98229c100mr3172588pfd.19.1614688019401;
        Tue, 02 Mar 2021 04:26:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1704:: with SMTP id h4ls8322528pfc.2.gmail; Tue, 02
 Mar 2021 04:26:58 -0800 (PST)
X-Received: by 2002:a63:fa02:: with SMTP id y2mr17725946pgh.412.1614688018835;
        Tue, 02 Mar 2021 04:26:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614688018; cv=none;
        d=google.com; s=arc-20160816;
        b=fStwA4lXAahfzFv12AInKlxsHXROf+DrMH1PpR0PDMXnMKh7vsiRNEOsU6uWH5U4Eo
         +Ur6AQYTMynDzf61ACKj6dlQf2zyO3uL9+P9f+Ndrk75AzFI5yMIHOAi2FCSg0UTty7Y
         qqV1i6WVEBxzUFEU/Mk2/8mzpr16gixq33QaMw33gmahJ76RUrhknq/CZD7OhFGseKMZ
         Mk+ByRDAokse/3k4S32fanJ3gU1CxzDYwFJZofloNSuj5Qnt4228IV4KNtw8TEgb/vim
         UGQu8ag2n/IKzQ3fuA4DfW+hDhlgVZsiJUdp+zotLert8lsjIh3UnQjp895jDogaA4I+
         dDbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=3e1UXkJlJ1BT+lEX/Ho2o3Swwg8VpNuk8hJLdSn2vjE=;
        b=GsnqkWB++yKBpryIFmspwdltk6c3a9xugeMGm+JjavXjgGitlpe9AnuXkU+t7n4ths
         Fblv02ex2ucJ6CW350ql9DZQycE/TOfQhf5nXfq4aUq7bXIpFZqI+6XBTEiheCeN4dRs
         i3MTsaoPw0n8LrdCwuqxR9Gf4CNDNCM7oiDI08wV78i0v/+++9pWj71pLbPllIJ2s8Gl
         +XDbFmQxW9fd7xRbqHVZBKZH4Hd1t5JLGXMSjhNThnazUDw6piZzSDjmT2/RQkgQW/CK
         P/VmtuxmihdqxU6LXrl73B1tK+gXXMXc6JAsiDuB6OR3LMO9rpVzn6gosL2hr/WdDvz2
         SuUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e130si1041880pfh.3.2021.03.02.04.26.58
        for <kasan-dev@googlegroups.com>;
        Tue, 02 Mar 2021 04:26:58 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 091F41396;
	Tue,  2 Mar 2021 04:26:58 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.50.217])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E4A803F766;
	Tue,  2 Mar 2021 04:26:55 -0800 (PST)
Date: Tue, 2 Mar 2021 12:26:53 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Daniel Kiss <daniel.kiss@arm.com>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20210302122653.GC1589@C02TD0UTHF1T.local>
References: <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local>
 <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local>
 <20200727175854.GC68855@C02TD0UTHF1T.local>
 <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
 <000601d6909d$85b40100$911c0300$@codeaurora.org>
 <20200923114739.GA74273@C02TD0UTHF1T.local>
 <CANpmjNNk8MHXNsHdyWqcO1VxREv+LP0sxid9LZOy+2Pk8i9h+w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNk8MHXNsHdyWqcO1VxREv+LP0sxid9LZOy+2Pk8i9h+w@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

[Adding Nick and Daniel]

On Mon, Mar 01, 2021 at 02:09:43PM +0100, Marco Elver wrote:
> It's 2021, and I'd like to check if we have all the pieces in place
> for KCSAN support on arm64. While it might not be terribly urgent
> right now, I think we have all the blockers resolved.
> 
> On Wed, 23 Sept 2020 at 13:47, Mark Rutland <mark.rutland@arm.com> wrote:
> [...]
> > The main issues are:
> >
> > * Current builds of clang miscompile generated functions when BTI is
> >   enabled, leading to build-time warnings (and potentially runtime
> >   issues). I was hoping this was going to be fixed soon (and was
> >   originally going to wait for the clang 11 release), but this seems to
> >   be a larger structural issue with LLVM that we will have to workaround
> >   for the timebeing.
> >
> >   This needs some Makefile/Kconfig work to forbid the combination of BTI
> >   with any feature relying on compiler-generated functions, until clang
> >   handles this correctly.
> 
> I think https://reviews.llvm.org/D85649 fixed the BTI issue with
> Clang. Or was there something else missing?

I just had a go with the clang+llvm 11.0.1 binary release, and it looks
like there's still some brokenness. Building v5.12-rc1 with defconfig +
CONFIG_KCSAN I get a stream of warnings of the form:

| warning: some functions compiled with BTI and some compiled without BTI
| warning: not setting BTI in feature flags

I took a look at arch/arm64/kernel/setup.o with objdump, and while
almost all functions begin with a PACIASP (which can act like a BTI),
there's a generated constructor function with neither a BTI nor a
PACIASP:

| 000000000000010c <tsan.module_ctor>:
|  10c:   14000000        b       0 <__tsan_init>

... IIUC this is a case that D85649 intended to fix, but missed? I
assume that D85649 is part of 11.0.1?

The resulting kernel does link, but won't boot (due to the Linux
structural issues I mentioned previously).

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210302122653.GC1589%40C02TD0UTHF1T.local.
