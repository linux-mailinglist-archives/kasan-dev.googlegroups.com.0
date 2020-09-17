Return-Path: <kasan-dev+bncBCSJ7B6JQALRBZW2R35QKGQE7TZ4SJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 240E526E3FB
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 20:39:36 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id j8sf2433145iof.13
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 11:39:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600367975; cv=pass;
        d=google.com; s=arc-20160816;
        b=LWv5/j71srb/k+PORwTBAt6VkbuFwgQ6B0v0vgsGINqcufBZm5Yp6Z9Kdgkdk5Z1n7
         YIzUo7X39F4RoGavPz2+AH26JSfwiazdlv/PoYV8vXHj0xZ+4aS8lOe1pEonnt8VQUea
         TGIXt5h0icpAXk1dAjdOoJlJ3U5H7+p7aPhH9A03JVWrE5HP4YORUT5SHd4V8p6ZBfon
         WB23D5JTXknlyRhncAMV3ceJvdu6p7/1b8AYUgEUcPjsvWcEE47+jWU/biEnP5hgJs/6
         bDtW33zm5Wdr1/iBokofv2sYCOXInsQYBnm6QtE5QksQuL7VYBEKbDtRBTny3F+oMiMr
         +MIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=k32CcZaRsZktwbSk7M+iZUX0mp9kGTqefOBrWvksspc=;
        b=Gr7/1mc2mCDylIbRY0W0WOG+8a5Ea4Z/UiMurKOMll9LKSQRRGkNrbcICflre4MIZO
         e+WxwQsKJWF5AxbjGNBQ/n/UKdE+HdjhgNev3dgVkv9pkyOIq97YChENdW83ZJrRAla3
         FLlrsMG20QGfsrFbyCEwDNq6bTUDsSIVDzi9Ai1qILjH3GUPgd+cS+6CuhBUGx0lN9vT
         WMNucEH8TMJ/cST288Qs+uvA4YDmGKlM6MXzvobmcGH6OcL/9fNV81helxFY8JKderTz
         /b1zgBfuZaCx19ylU6HGgHfth1uYg2vtICN9wY6PMxqvNgESVQmq5e6xXEWcxJ0r/fHR
         r7xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MxgcqBmf;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k32CcZaRsZktwbSk7M+iZUX0mp9kGTqefOBrWvksspc=;
        b=Cs5hW2FpJnGoJH1Hz3KPD4u86linLX8P2SEa+HqbMPoj36FfEYYg1eJvGVbWkhcsEk
         u4e8nzQpxe9zR0rowr2ajYMi25bgBhDZq+lxwSjzIzO0HDcpZ1XwtqVpebgMDBg98b1Q
         Fbu/qBRMCIMCM0XXOAIQxs7oQltnlth4vIJQX85fnm0WXoeF2CzMjzvUQg+rKDAdjgqx
         w5ZopYh58zU7/GKh1Zl3JFKXwgN9lqR820fjLw7hR1xC4x0/N+4K3GjcfjefdfsBrWQX
         +tUFwgKYxBC5fXXipeqPZhF9gTp0OnFwQIcWu4i9a2CjSYeEEJJvWWg+dBSI7790ybQq
         NaMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=k32CcZaRsZktwbSk7M+iZUX0mp9kGTqefOBrWvksspc=;
        b=m7Wu9e11+NM7ciaSK2Wj6xZ+pQpWc8Tfx4zC91NBaNsqcZNJUK8PFokeCa60HoWgZ4
         w/U3w6BpmARxeUBv5VNR7pdTtWYfVAuQp16uSzRqWZ8Uv1T8qoWHlsCoL2EB15n/Jmmf
         XlJzX0nGfsiinl3uXxUM+G+N+/mzZyL4+YyuixheVHtfRcOUyStfwkB6P6B0ZWvBmdVl
         V7XHV4qGsLjWuG88Whs///GGcdBwNhwEQtHqoc5VqhKVYPPdbQeumjObXiNiNKsBVf9k
         4tN7oN1zkB+E8Ct644HjfZ5z0HWYodnTVP7iqwgIijDD2eeI9kme/ROYnRlj8Fs3tAMU
         3dIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KSym3ME6qp24YhiyauT1qBHhOylC+HjDQh8EJiXcrJ6KfN60t
	fTER1NUxzBtLtaXvAfdRu9g=
X-Google-Smtp-Source: ABdhPJxUnLurm8GAFjL1aGkjLymsDQ/HHrqeDoKKnrAKxFDkm3xwR4+IgJKKXKxRqMVrqqy6J4E2UA==
X-Received: by 2002:a02:cb99:: with SMTP id u25mr26338264jap.99.1600367974521;
        Thu, 17 Sep 2020 11:39:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:12d0:: with SMTP id v16ls391934jas.8.gmail; Thu, 17
 Sep 2020 11:39:34 -0700 (PDT)
X-Received: by 2002:a05:6638:168c:: with SMTP id f12mr27514426jat.16.1600367974153;
        Thu, 17 Sep 2020 11:39:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600367974; cv=none;
        d=google.com; s=arc-20160816;
        b=JVEFsAifKe5m1P+bkP77vNS2/NNuWHbJohZ7EbAzNo58dNcb7VxSWreVxgDCxN8OXv
         wLHmHS+bNycizE2ck1TF91e2pqVLJ6/YcoBZ5O0Siswh+vtxfIo4gW3Acyv2qwNbdwCA
         Mn+MEGXQvS62NCAr4WZl+sovLHOuNTIOmufOLsWHnBoFCRKdiJudvCWz9RbNDUhkW5w8
         jBwlrESTcp/+NgQ9DMJLtWGlRDAtosiYAbW+0lcLpVFmdvzGowZlWvMhaOz/F8pGDq0B
         SEeWkDlO2SBZuepLaVFnecgR4MsEL2YRWCX86msgH+DDS6vzPjrtFUfp0MogPW26H4zD
         2EQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=s8/ARKLQp0M0HyDLCLKuWSzwoxVAsS/APQ6NuiD3MNU=;
        b=fbsIVDoGkqU0hdiylNSj78Ub/9wJumCeEROG+Wa5uKYRMUzknOD8/BGznTvpNXuVs/
         KErkArVhnipfdbFOdr7ZRwa8g14pOyQPbbF4Oe6002WXBDFHcRYcefxJ2a06zmeEPyOy
         JfBpt82TBIh6SJU5iMEQh1zN+phAGddalJPqlh3dV7CzVu6n+qsquHryLMSm8AKNLZlG
         JRbhofth8MS1q4saHxk7GiAtuNxZ1ZvzRd+UdeWyHQ1YN+Vw+k0WgfUwIClp1BYEkuuC
         BOmTLdFtcbO4IQHzE14FubmKAZvRKQcY0TxzgfPTwxV2WpnQRcg3p32URk+koY4YUF9W
         aY5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MxgcqBmf;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id a13si49671ios.2.2020.09.17.11.39.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 11:39:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-329-I6O1PZQ6O7yXfGqmLvj70w-1; Thu, 17 Sep 2020 14:39:29 -0400
X-MC-Unique: I6O1PZQ6O7yXfGqmLvj70w-1
Received: from smtp.corp.redhat.com (int-mx08.intmail.prod.int.phx2.redhat.com [10.5.11.23])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 1CC6D10A7AE1;
	Thu, 17 Sep 2020 18:39:27 +0000 (UTC)
Received: from treble (ovpn-112-136.rdu2.redhat.com [10.10.112.136])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id E159819D6C;
	Thu, 17 Sep 2020 18:39:24 +0000 (UTC)
Date: Thu, 17 Sep 2020 13:39:23 -0500
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Borislav Petkov <bp@alien8.de>, Rong Chen <rong.a.chen@intel.com>,
	kernel test robot <lkp@intel.com>,
	"Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Daniel Kiss <daniel.kiss@arm.com>, momchil.velikov@arm.com
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING
 e6eb15c9ba3165698488ae5c34920eea20eaa38e
Message-ID: <20200917183923.b5b2btxt26u73fgx@treble>
References: <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian>
 <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble>
 <20200915172152.GR14436@zn.tnic>
 <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
 <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
 <20200916083032.GL2674@hirez.programming.kicks-ass.net>
 <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
 <CAKwvOd=T3w1eqwBkpa8_dJjbOLMTTDshfevT3EuQD4aNn4e_ZQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKwvOd=T3w1eqwBkpa8_dJjbOLMTTDshfevT3EuQD4aNn4e_ZQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.23
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MxgcqBmf;
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

On Wed, Sep 16, 2020 at 11:22:02AM -0700, Nick Desaulniers wrote:
> I looked into this a bit, and IIRC, the issue was that compiler
> generated functions aren't very good about keeping track of whether
> they should or should not emit framepointer setup/teardown
> prolog/epilogs.  In LLVM's IR, -fno-omit-frame-pointer gets attached
> to every function as a function level attribute.
> https://godbolt.org/z/fcn9c6 ("frame-pointer"="all").
> 
> There were some recent LLVM patches for BTI (arm64) that made some BTI
> related command line flags module level attributes, which I thought
> was interesting; I was wondering last night if -fno-omit-frame-pointer
> and maybe even the level of stack protector should be?  I guess LTO
> would complicate things; not sure it would be good to merge modules
> with different attributes; I'm not sure how that's handled today in
> LLVM.
> 
> Basically, when the compiler is synthesizing a new function
> definition, it should check whether a frame pointer should be emitted
> or not.  We could do that today by maybe scanning all other function
> definitions for the presence of "frame-pointer"="all" fn attr,
> breaking early if we find one, and emitting the frame pointer setup in
> that case.  Though I guess it's "frame-pointer"="none" otherwise, so
> maybe checking any other fn def would be fine; I don't see any C fn
> attr's that allow you to keep frame pointers or not.  What's tricky is
> that the front end flag was resolved much earlier than where this code
> gets generated, so it would need to look for traces that the flag ever
> existed, which sounds brittle on paper to me.

For code generated by the kernel at runtime, our current (x86) policy is
"always use frame pointers for non-leaf functions".

A lot of this compiler talk is over my head, but if *non-leaf* generated
functions are rare enough then it might be worth considering to just
always use frame pointers for them.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917183923.b5b2btxt26u73fgx%40treble.
