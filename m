Return-Path: <kasan-dev+bncBCSJ7B6JQALRBCVP6GAAMGQELPN4ORA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 27B0F30FE04
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 21:22:35 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id a26sf3978250iot.14
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 12:22:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612470154; cv=pass;
        d=google.com; s=arc-20160816;
        b=RT+gIUNSUnh449yFpGjT6erlE99PVsJJska1yYQ3rPCJBe+H52qqvJpZ5rDBTTfJqq
         3z9Imi5zylhJ31NZsiXGi1ftaPOWTAy8SpDIAnZU6TPrHzUS0a526WoWsmVhjfdZk+BO
         DS6b6Tf1dk42XGo/f0XlqtiBJTLq5hSmE3fmTHM8vpeP0vBg2Bg37w7+f2eS6EXbmzP7
         NGaqY3bBcCUc7PWH6BmkEyXUecX7QnTK7NmmxS34Ng06Y6GOUJV9TZEz08EXwAoWdstK
         51S16SYReU1wUF3mRygSSYpeBvLK2edmiTwmqaR3xcwlgJr7jfXwZHRRB002QeeTcQZH
         vBsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3cINYJW/d7PRFiwCoR5G24/lkbrHcXhn4sK+9pV9U50=;
        b=0cCNAhTnuXBedngUVJ+z9iMm+NeYDqh9ICWKp/lusOdp1+gchtARj+zMfNlgIsk+8F
         8rNqN5C3pQU3kHGaJSjdYysQ7diAQw90BDM7zjhHz/EQ+5uqIAB7+FAS6VBuDKt84HbJ
         ksp4qIccEXLWm24Y0+CJCu2gmpwoV9hBTLM9feAlUSECesc7mF3GgERWu8jFtpVJv3Yw
         OIYUrLFrRRV8ZfoEKP/IoLI2o4RvXTCZHFlUxLGdEjMyTKlgVSmh3Aittk+copzBbRcD
         FJ1GBZt6r4OzNnWZsBy2gNjxiRAKpCzGvyX8Pf7KKGcF4Vsr8s7GeCp3aNaycvzmaA6x
         IcIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fuPEFOTF;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3cINYJW/d7PRFiwCoR5G24/lkbrHcXhn4sK+9pV9U50=;
        b=JbrawoTvS/+9I0t3SivYox0iRDLYOiPIN7qlccCZurdEP9eNt61VNN7PNkKLmniL5i
         HpBiRmzgNT1k4Z0FhCTGjdYr2jRyvU0nT4WXNklbffwI2sI2Yhh9nfuSKxm9vsJGZKBK
         SNRI9Pl+WMT0gTyjURxw1RRl4h7evg4Isp1BzyUCfSQzp02beZmeFLDa0banF3O91QLj
         tys2MjVZCJCZmo6iuvzodMxLSas+BSqfLailZBp28M8F8pvHvviH8clXy/SWNnyWJWRw
         e2zagIiJ2W+mycoKq8fcMUjz72HxIiqwSEu2e1kO+F8bP6SCsSt5UuhRpzEuL5/U9PoO
         5PXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3cINYJW/d7PRFiwCoR5G24/lkbrHcXhn4sK+9pV9U50=;
        b=FmlN7auGlnbxjCfCQ27X3WIQ14+Wqr6cdegvalOJ66/aZ7TYORgyEBHwYEUs112bDX
         XQKyo7D2rFATmRUaYHhaiar21E1sdvil8F3ZJtKKcDK4O923jNBABgViHi2i10Y0IPEX
         nGUVxeoPF7iFYcvGtf3Wqf79vEC99hkzZDns8EkvE74qSyxkiwUEVoMIwVbCXLu4OE+u
         jfgKtkk6nGaMNtWfoSuN4ZbOTw8EWU36rVgSAhHCJsIxID+o22NYQeD2I7dz2oyDg/EN
         T2OmvMjp6IKH6JLSXQ1SbkcblB1n1Y+FLDkt30FRFvuQdvuNjh8sNnTSRnfBmA0T07BA
         5Ouw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fifQD/V/gCKS2ljWA7iiRbQxnI9f1jRrFqC+mYtc/O1DlG/Dt
	adKyFmt6LHpzZzg+LpzTW4s=
X-Google-Smtp-Source: ABdhPJyvGgGjgHTcNOv4kP09FfiVAkC4lUKn5+osxPmsWLM/9ra1DUI16TnjRieAGlXz8FAzxjanfQ==
X-Received: by 2002:a02:cdce:: with SMTP id m14mr1253576jap.85.1612470154113;
        Thu, 04 Feb 2021 12:22:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:8216:: with SMTP id l22ls1116008iom.9.gmail; Thu, 04 Feb
 2021 12:22:33 -0800 (PST)
X-Received: by 2002:a6b:3fd7:: with SMTP id m206mr967543ioa.120.1612470153670;
        Thu, 04 Feb 2021 12:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612470153; cv=none;
        d=google.com; s=arc-20160816;
        b=C70FRFjdIoCBQpqStuwr4ZiJ5f15pDCbi4Q4YKsxo7cl0+r+Cqr7eZcDmyfx/XMwXA
         V5Ky+jf4F92Pbwhr9grlXVErjdyjiIeZyeROPGzzcfmHzkGo+Jw2d6vZm2Q6GQPpg3rV
         Wb9ohwefKwnqgq0kxqxj0eYaDCjp69xUSXX9pPZW1YZGwjm2+Yfn1HHSEw7BKCB5f+El
         pGB227KFAZ+riQkhjNaruPO6k3NNXrWuSWlmmrAXAhf4A5t9GbmSOxzvpKFUkyCloZHW
         Cpg0vvwhkpYYx45W8HjhoOezU92jZr0IiVoOJ2h03RFB3ezQ/24pMyqpdX84jvL6hJOJ
         rotA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ob/Q0z75fUha7sOp70sKDWv4y9mB1atawq7qE94MTs8=;
        b=EzigWOlIlmn3KMK5DAvwH3PXr27DxFzNfy4GXTpA31lSGq5gXLY/dcx99BsrLqbEE3
         TjmnDAiiSLUgCPOi1JqqDNAt8U+NWLFq15HqLqtrDpO/E55i2EYGa5PPfJYYajgCBT6t
         qYxq949HRVn5m9F0Xy2rlriNRVJA08MlnOhHYkMp54VoTNOQM+olJrpkcWBPR1C8AYmP
         rtsfnTEd1W3+t/b/WiEhjwjLEYAkML0FyTzTdzxP9bvuTIlBXVxAFOFg3FE6oZYZU4ST
         L3p51Fz6I5T7nZCDBUjTGK0GAmbrWSwC0GJRMfpyfw8rWHFo3LLW8r5xQUxjqi4MkqVC
         qrqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fuPEFOTF;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id s10si238225ild.2.2021.02.04.12.22.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Feb 2021 12:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-428-A7ohRb1EOQ2tcgOjpeJI5w-1; Thu, 04 Feb 2021 15:22:31 -0500
X-MC-Unique: A7ohRb1EOQ2tcgOjpeJI5w-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.phx2.redhat.com [10.5.11.11])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 0E1A18030B5;
	Thu,  4 Feb 2021 20:22:27 +0000 (UTC)
Received: from treble (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 2A7DB722D9;
	Thu,  4 Feb 2021 20:22:14 +0000 (UTC)
Date: Thu, 4 Feb 2021 14:22:10 -0600
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Ivan Babrou <ivan@cloudflare.com>
Cc: kernel-team <kernel-team@cloudflare.com>,
	Ignat Korchagin <ignat@cloudflare.com>,
	Hailong liu <liu.hailong6@zte.com.cn>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Miroslav Benes <mbenes@suse.cz>,
	Julien Thierry <jthierry@redhat.com>,
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel <linux-kernel@vger.kernel.org>,
	Alasdair Kergon <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>,
	dm-devel@redhat.com,
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>,
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>,
	"Joel Fernandes (Google)" <joel@joelfernandes.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Linux Kernel Network Developers <netdev@vger.kernel.org>,
	bpf@vger.kernel.org, Alexey Kardashevskiy <aik@ozlabs.ru>
Subject: Re: BUG: KASAN: stack-out-of-bounds in
 unwind_next_frame+0x1df5/0x2650
Message-ID: <20210204202210.4awpfn2ckdv7h5cf@treble>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
 <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
 <20210203190518.nlwghesq75enas6n@treble>
 <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
 <20210203232735.nw73kugja56jp4ls@treble>
 <CABWYdi1zd51Jb35taWeGC-dR9SChq-4ixvyKms3KOKgV0idfPg@mail.gmail.com>
 <20210204001700.ry6dpqvavcswyvy7@treble>
 <CABWYdi2GsFW9ExXAQ55tvr+K86eY15T1XFoZDDBro9hJK5Gpqg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABWYdi2GsFW9ExXAQ55tvr+K86eY15T1XFoZDDBro9hJK5Gpqg@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.11
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fuPEFOTF;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
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

On Thu, Feb 04, 2021 at 11:51:44AM -0800, Ivan Babrou wrote:
> >  .macro FUNC_SAVE
> >          #the number of pushes must equal STACK_OFFSET
> > +       push    %rbp
> > +       mov     %rsp, %rbp
> >          push    %r12
> >          push    %r13
> >          push    %r14
> > @@ -271,12 +273,14 @@ VARIABLE_OFFSET = 16*8
> >  .endm
> >
> >  .macro FUNC_RESTORE
> > +        add     $VARIABLE_OFFSET, %rsp
> >          mov     %r14, %rsp
> >
> >          pop     %r15
> >          pop     %r14
> >          pop     %r13
> >          pop     %r12
> > +       pop     %rbp
> >  .endm
> >
> >  # Encryption of a single block
> >
> 
> This patch seems to fix the following warning:
> 
> [  147.995699][    C0] WARNING: stack going in the wrong direction? at
> glue_xts_req_128bit+0x21f/0x6f0 [glue_helper]
> 
> Or at least I cannot see it anymore when combined with your other
> patch, not sure if it did the trick by itself.
> 
> This sounds like a good reason to send them both.

Ok, that's what I expected.

The other patch fixed the unwinder failure mode to be the above
(harmless) unwinder warning, instead of a disruptive KASAN failure.

This patch fixes the specific underlying crypto unwinding metadata
issue.

I'll definitely be sending both fixes.  The improved failure mode patch
will come first because it's more urgent and lower risk.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204202210.4awpfn2ckdv7h5cf%40treble.
