Return-Path: <kasan-dev+bncBAABBEER472AKGQECZ6KADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id AF05C1AE0E0
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 17:17:39 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id a11sf2035649otc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 08:17:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587136656; cv=pass;
        d=google.com; s=arc-20160816;
        b=FuY7k6o6l/dpk+RUdnwGaE1hSk8blvH19r/yAGZjuemuZ27Kujs49JUCn0HAJkKoYm
         9hY8Ot3Rp4GLCKdh4xJHr1oshtn4uFEJqXFe1GlKZGpPeJLll2QR/W1355h2DJGShFkk
         OsD5Um9HrcsjojESI3HK8IhUjPDkEPUZPcsKde/MAuwFJlIOFcSVJr1yrQSBzkbesMCC
         vJMJjuBFZG/6w2rlSCYtMyd6LseDFs/dRjtuVGA5HzfMoJ5HLi6xUVkngvy8c6SuyKZ2
         ec8ljB0JbYsUK29vgrX13H+zgD2pUGe7FuEqyJ34mcgaWPvA7RNYtnsrFzNlPtUTp4s7
         8M/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=6VdxHo6z12bXm0PA1POMuRpV2HV1Vg2uLtw/O9NKqgY=;
        b=dd31htyxQXYOTsxQieyyujIz9Ad58vol/Tblr1plnpHrypB8vsWYKJPpdzK3Atp53Q
         fjAjOrXS4qIkGPb66rXk8We2bv5VqH7ji8QW9c8wA8gxWramgPtJ8eRdZuWQiX/prU6W
         Ewq0++Y2kqHuOlQN1w1tSPazaSEd9IL4CMAGq/PfqSWzp/aWozLKrC/VbkJHt/7XvqPD
         b9DBWQVzdslFGTiejuHgZYJEveeVXJqHnDCJAbVyLY08fXLiWPbawnfGI9u4g5HmAL8V
         QGuoftdeP7cQvH8bBcnBRUX8ngUC809I5iZNo327k00a7nW6zX5tW6i8T/1meBUv74Ax
         4KFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=dYtXIG1+;
       spf=pass (google.com: domain of srs0=4ge1=6b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4GE1=6B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6VdxHo6z12bXm0PA1POMuRpV2HV1Vg2uLtw/O9NKqgY=;
        b=evkuoPdegk4nuouklrTjh+royJj5LdRWS5NTYHXhbfmGaEPQMhajzH6iIeODckykMq
         16Lg9hA14iluQ65tl7epXmVRqIktYPOYOVWAJA0sqzIXXW5locvDIrjlWxGof56AzFtu
         BMD/uy8sDnd9OKCXryJ+vgXzkQY5dYCh58EXc1Q0YbvQVg2BKEke3UDpjb0LWGSSo5wG
         0sI+XCYQUkJ80aiFZ2vrRIpFXgQ4CstQk224hRzAh5jXmtXR2NcL9HuDpdWrnkBX4NHe
         H28wTovpLXq3SBY7/2yelCi9XbBg8iY19P873v+bzlpIlmrJQxOc/AIXpGCCh8lNzHxI
         SLGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6VdxHo6z12bXm0PA1POMuRpV2HV1Vg2uLtw/O9NKqgY=;
        b=VaJ6P/UwahGI2goVsly2ME4joM3BPQaMULXLuEZPJjuKUvyeNCne93aubfapkswyhi
         778fkd0iEz6K7Q2dT2G5QmfUwZd8uJ/DGljgIc7IPTiqlE0jbl801XSvKOzoGfKJ92KL
         82zipGpREw60S0Lb3Ye9X0wWAbJEur1DTOJ8NPCyg78fCbhtqqHmbIeM+htnQDdXtv/5
         rLFG994zlTzB5K8lg2YILHiOmgLJGS6tHO0Z/39Qoxmn7iCwsqtaXAtcCb/aea96LfiG
         dJzoXMOWlzceB2d8IxrOiKhcmKO259O0wPRNLbfKT2536/Rur0dYamoHWKFWZaieDb5h
         /+LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZl2Zb0VsoY7OkO8iDM3cquE0f9BjyBA3zR3OjH8+Um2PiAdfGe
	Fep7XDAsKWFNGa03tYZMgDI=
X-Google-Smtp-Source: APiQypKGirc8WXM2b1sqMxN7jVrJEYUJNzrCKybLuyeMPo5HWRXxmePwgYcmTxSj140R2sX+SKOwXg==
X-Received: by 2002:a9d:58c:: with SMTP id 12mr3057728otd.156.1587136656059;
        Fri, 17 Apr 2020 08:17:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7312:: with SMTP id e18ls509139otk.4.gmail; Fri, 17 Apr
 2020 08:17:35 -0700 (PDT)
X-Received: by 2002:a9d:77c7:: with SMTP id w7mr3061519otl.318.1587136655741;
        Fri, 17 Apr 2020 08:17:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587136655; cv=none;
        d=google.com; s=arc-20160816;
        b=Fx/sD5SjTv1P5W7ODUT3efogf9WbpGsYhKSEgOX9a3fo9U22dNsmoNIKJ3eXBNXozm
         IIPBf1ZKJM04Fxh2QPv1PhDu3Yda+lYkZbDfTw0eQimlr5klynJIhs0FsYVBQBsD/n6X
         wWBrqa1dLPYCp5b2ykWnn/yF8Tl7In8OO4pgQ9nkwAnGuXlaf8XvKznZSRjqal8fUjRO
         7QZTwa9gfDomEShe7w8ZpsOw2Eb2BK4uRiYamufT6EQa0DveVV2reiXYKjNIgAw1MnjO
         R7CUTKaO4f9Ebrij9du52DAikHArg4RNbeBVO0YbFxxN4t57ZSk5rflY941W4vcACO1a
         MmLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=yZmc+Gn+gTykKgUTsRKpMN1RsNTk7o/3nNOmw945ZCs=;
        b=1KCmDH6u7FWNCKOxQ3Lij4EhIiO6hsBc/VYER11TcXW1Spo4gRpV1V9NG/XLSlTnSY
         0js30GrwURRjItQwFgBnyOR8+JUyletgRAHB55dGF3hfY7G8nc2E7N6OlGX6jAIGgSdf
         8DljgpWaP0XILVsj3sWofbYE5OeR8GzR+lFSLUj2RZXvLsN13OEPB9Rb6KT3NY2NZ+xK
         BpT6YKtKusBW/Xst64+3sW+uenORmn29AtJLQrLaUVNanSVQE19SeZu5CgptxNMOODCJ
         ry/IfTJe9gqRqjmqJwNDJ7G7xwTc0jTr+4+QMNzGclpRNm9pXLhCpQrPby2Dh8kb0Wu2
         Zjqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=dYtXIG1+;
       spf=pass (google.com: domain of srs0=4ge1=6b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4GE1=6B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v1si1708537oia.0.2020.04.17.08.17.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Apr 2020 08:17:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=4ge1=6b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id DF4BF20936;
	Fri, 17 Apr 2020 15:17:34 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id B63573523234; Fri, 17 Apr 2020 08:17:34 -0700 (PDT)
Date: Fri, 17 Apr 2020 08:17:34 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Elver Marco <elver@google.com>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	kasan-dev <kasan-dev@googlegroups.com>, kvm@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>,
	Paolo Bonzini <pbonzini@redhat.com>
Subject: Re: [PATCH -next] kvm/svm: disable KCSAN for svm_vcpu_run()
Message-ID: <20200417151734.GJ17661@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200415153709.1559-1-cai@lca.pw>
 <f02ca9b9-f0a6-dfb5-1ca0-32a12d4f56fb@redhat.com>
 <1F15D565-D34D-41F5-B1C5-B9A04626EE97@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1F15D565-D34D-41F5-B1C5-B9A04626EE97@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=dYtXIG1+;       spf=pass
 (google.com: domain of srs0=4ge1=6b=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4GE1=6B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Apr 17, 2020 at 09:21:59AM -0400, Qian Cai wrote:
> 
> 
> > On Apr 15, 2020, at 11:57 AM, Paolo Bonzini <pbonzini@redhat.com> wrote:
> > 
> > On 15/04/20 17:37, Qian Cai wrote:
> >> For some reasons, running a simple qemu-kvm command with KCSAN will
> >> reset AMD hosts. It turns out svm_vcpu_run() could not be instrumented.
> >> Disable it for now.
> >> 
> >> # /usr/libexec/qemu-kvm -name ubuntu-18.04-server-cloudimg -cpu host
> >> 	-smp 2 -m 2G -hda ubuntu-18.04-server-cloudimg.qcow2
> >> 
> >> === console output ===
> >> Kernel 5.6.0-next-20200408+ on an x86_64
> >> 
> >> hp-dl385g10-05 login:
> >> 
> >> <...host reset...>
> >> 
> >> HPE ProLiant System BIOS A40 v1.20 (03/09/2018)
> >> (C) Copyright 1982-2018 Hewlett Packard Enterprise Development LP
> >> Early system initialization, please wait...
> >> 
> >> Signed-off-by: Qian Cai <cai@lca.pw>
> >> ---
> >> arch/x86/kvm/svm/svm.c | 2 +-
> >> 1 file changed, 1 insertion(+), 1 deletion(-)
> >> 
> >> diff --git a/arch/x86/kvm/svm/svm.c b/arch/x86/kvm/svm/svm.c
> >> index 2be5bbae3a40..1fdb300e9337 100644
> >> --- a/arch/x86/kvm/svm/svm.c
> >> +++ b/arch/x86/kvm/svm/svm.c
> >> @@ -3278,7 +3278,7 @@ static void svm_cancel_injection(struct kvm_vcpu *vcpu)
> >> 
> >> bool __svm_vcpu_run(unsigned long vmcb_pa, unsigned long *regs);
> >> 
> >> -static void svm_vcpu_run(struct kvm_vcpu *vcpu)
> >> +static __no_kcsan void svm_vcpu_run(struct kvm_vcpu *vcpu)
> >> {
> >> 	struct vcpu_svm *svm = to_svm(vcpu);
> >> 
> >> 
> > 
> > I suppose you tested the patch to move cli/sti into the .S file.  Anyway:
> > 
> > Acked-by: Paolo Bonzini <pbonzini@redhat.com>
> 
> Paul, can you pick this up along with other KCSAN fixes?

Queued and pushed, thank you both!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200417151734.GJ17661%40paulmck-ThinkPad-P72.
