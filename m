Return-Path: <kasan-dev+bncBCSJ7B6JQALRBGNPSP5QKGQEU3CBWEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DCE3B270156
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:51:54 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id w32sf4039753qvw.8
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:51:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600444313; cv=pass;
        d=google.com; s=arc-20160816;
        b=e3J8/2iXtU+CH2A1kwvm9MM1aM3ndLDJO+py3/8zlO5UZb+ULg5JFKDHLAmVDDX3S4
         785rPISM9qRr/Z7P8M1fI034k6kuryLyF4dlYBXzj5tjniNXYT9oVh8u2eIQgkGjX230
         /Gf/ITCN/PiPuGb8l7q9ce7meU1Op7OKmJR5ua79Gs2mT8Rr8gtlRRBYd3jLCCQsXZnK
         VbJO8XpDA4mw57URK8AqJwbc10riNpBN2p+bFjDBPFnJqn88xiNdXM2dU/pVEn/H4lvC
         czSvB36ZGiTOhI0LFAUm8nanbegni5njTNg7u3Rn2mZOOj8VId+rtYoMzoz1EvIqbJmx
         qZdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FqPXb0NkTuV/7BB1n4caf5xl0bed8c9ErXMOQr4J0Kg=;
        b=LJGTVjcnD3elG60A7ozYEqgZlzzUm0mNJc7QHk3Cszfxo4LTMRsasRQGwvYshDl7eh
         ufFCmuPwLQREbDgds7hyxBZmq90OMb3uYbSEiUh7a1s/i4TDeyqEd2RG1d22+oSG/Hhp
         hQwahAVdBz00fXSA1VLAvdPB95u3gKHsA1kKJ+JNs1A5CbqbfS0CpwHU4U9q0gyHnhIg
         yOa2AkdUhWL3z7Bok9rlcfFHT26DpthMlyV/A3shj+2Ut1iJklrSKpbQ5QEhBizxBt3q
         psdepFNr7MrAY9XABnUMTyQW5GBvCYBwMpv7omswSUd9VF0DJ80+4mRedi7lLLVpb14Z
         s75A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Xap2UwzO;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FqPXb0NkTuV/7BB1n4caf5xl0bed8c9ErXMOQr4J0Kg=;
        b=b2ZCDz53k4ZA6cPRdEp/6cuDvdjnIwk2kDrDROQb1jrvmxt2xioji2LA0yZ8qo5Nv4
         29gAGnlEzOJopTIcy5fn8ENVdkBREs9C9nIaJ4P4ZrM7r8gcd6RZKE6Psp7XFiMj12tu
         WmbW/j65cS9kBRHpVOqaYe3kSuaRGGH5tbTbGRYsr8UEt6YcsTfUMPYOyBzrzv/lAS/Q
         iVh8SqBXHvLi3PVew4J3PVAFMAPZnThTny9GW45X2T+OEl45GOD6JynybC3ugH3sfiRB
         uh5wZgOYU30pQqtPCsTjqIpwUq1wwYpEk5FJTvSFpPsggzNU/pP/GG6FWzCy0g+zZNky
         Pfig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FqPXb0NkTuV/7BB1n4caf5xl0bed8c9ErXMOQr4J0Kg=;
        b=EKW3ZOV2+71+Gnbg36vHFlE7iFOf82/MThBXmMPHST42cYtvbK/k2NKwRYEdqf5bUG
         Eoe19m/esrz1HAwkD+ZB0Z3Z4UEWm5IiAXAxziJOGACKTeKr17QG3NUIjgLZiTKbTFEv
         VxLhF68du0BeWT+uaSE2qc+V42q0kChofps4QGA+Lh3ZnU+fXSS45x/54pWKAeU3SO61
         N3PZreFiuhgULYj9E7IQQck90gYioZ3NAXsoVZxew7IeJaFJnziW/pcxkh/DBAgQiIvH
         ZPmhjXLPF/zqBBQsJ4E2t5p3uMT7U0deTEDV0OO5auJbQ5QcUuYuB8GVws/u7jPjlLLG
         6MzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530XQllt29UDvgKlZ9MhQPbcyhdtq8ciDMcaU2FRAfoC8LwoJ8d7
	+mUHVNelZyvoMD09F1LfmQA=
X-Google-Smtp-Source: ABdhPJw7/eJoazrBxYMl9kycaBdLJyvE8O/x93uUAvTR+5QAh5yT9DaM3di9IbRxzyiKAp82sLWafQ==
X-Received: by 2002:a37:4cc9:: with SMTP id z192mr7332361qka.364.1600444313164;
        Fri, 18 Sep 2020 08:51:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b987:: with SMTP id j129ls3047189qkf.5.gmail; Fri, 18
 Sep 2020 08:51:52 -0700 (PDT)
X-Received: by 2002:a37:a64a:: with SMTP id p71mr34796611qke.389.1600444312701;
        Fri, 18 Sep 2020 08:51:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600444312; cv=none;
        d=google.com; s=arc-20160816;
        b=UxGlx5rbMsQI2NQPMH4RizRBTGEVODljIKj45YvfgUFAehbGUAXs+3TcFe5L5QZcgg
         3lkBLRL9WSxgPHiO+o2ECtu5bK0EVVRv1Kn4im5S9REhBK7Z3cSfvukONX6Yxs82dHfF
         r2/UpySlXJ6vB8icf0Tw7ARYyLG8dsipJ+V/23Hod8CPmu7tWXyPQkbHVrH5lYOtAntr
         necax0pYc9xxxj24jjlhgFfXOGOHRqGUIch6TyDvNuCNgzmB45Nqz3shdxz2g5qwJJXN
         cQrm8rTnRARXm1m7T6MkW+kzEZGcYzrRzCNU/oStSBm3Ao6EoQ9AJ+AbOKK2F8lJXc4Y
         0O8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wN2Lonk3fGag+MhygRATrzJGxu02WDrFo0smM6EKPM0=;
        b=FhUc3ediW/oZi3f1xKaPzRg8yo/iCRJNRrVgqcb5BeY3hXyU66XFeiWLKgwR+/QfBM
         HA9KWbv2r7cbWGUtRG2itX/9GINNBwVGRJiwL5FAgib1a95ONMbBXEy6glaZtEEamtBt
         5mtOM50yVOO2rvk/+zB5Y6zwi0gs640r61Azu6JWvhyUKqotAlwhuYRdaNdzNd1FyAB/
         Cw9CxUyaK5KY5CBOmG03eoUIq+g4L0NWgQUaz6HWzIHRTiIT0oP+FnBEIZxYmJ+O/Xx/
         AhHeeELlwyj8ugnUhBnIwCdHzAt0Qp9/sY/LHmaS9c22EnL1ueGDDAQz9sYi/kc7/OCR
         Wv9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Xap2UwzO;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id a2si198264qkl.4.2020.09.18.08.51.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:51:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-324-WN-K92OLM3CSA5U4WeuAyw-1; Fri, 18 Sep 2020 11:51:48 -0400
X-MC-Unique: WN-K92OLM3CSA5U4WeuAyw-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 810D7188C12D;
	Fri, 18 Sep 2020 15:51:46 +0000 (UTC)
Received: from treble (ovpn-116-15.rdu2.redhat.com [10.10.116.15])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id E0B5555771;
	Fri, 18 Sep 2020 15:51:44 +0000 (UTC)
Date: Fri, 18 Sep 2020 10:51:43 -0500
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Ilie Halip <ilie.halip@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Rong Chen <rong.a.chen@intel.com>, Marco Elver <elver@google.com>,
	Philip Li <philip.li@intel.com>, Borislav Petkov <bp@alien8.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"maintainer:X86 ARCHITECTURE (32-BIT AND 64-BIT)" <x86@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Nathan Chancellor <natechancellor@gmail.com>
Subject: Re: [PATCH] objtool: ignore unreachable trap after call to noreturn
 functions
Message-ID: <20200918154840.h3xbspb5jq7zw755@treble>
References: <20200917084905.1647262-1-ilie.halip@gmail.com>
 <20200917221620.n4vavakienaqvqvi@treble>
 <CAHFW8PTFsmc7ykbrbdOYM6s-y1fpiV=7ee49BXaHjOkCMhBzhQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHFW8PTFsmc7ykbrbdOYM6s-y1fpiV=7ee49BXaHjOkCMhBzhQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Xap2UwzO;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
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

On Fri, Sep 18, 2020 at 08:35:40AM +0300, Ilie Halip wrote:
> > The patch looks good to me.  Which versions of Clang do the trap after
> > noreturn call?  It would be good to have that in the commit message.
> 
> I omitted this because it happens with all versions of clang that are
> supported for building the kernel. clang-9 is the oldest version that
> could build the mainline x86_64 kernel right now, and it has the same
> behavior.

Ok.  It should at least mention that this is a Clang-specific thing,
since GCC's version of UBSAN_TRAP doesn't do it.

> Should I send a v2 with this info?

Yes, please.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918154840.h3xbspb5jq7zw755%40treble.
