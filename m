Return-Path: <kasan-dev+bncBCSJ7B6JQALRBFH25SAAMGQEISGLUFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id A761D30E866
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 01:17:25 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id i2sf912061plt.14
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 16:17:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612397844; cv=pass;
        d=google.com; s=arc-20160816;
        b=DLzdpudt0YUvqDoLrMX0/mGPfdP/1eTM1q2IhY8wH/UFvIbXp8ULj/k6mci2JNExs/
         T50aKmt15OeRIqy/eAYmF1+8Lh3kzgaJtQ1n6k0oNMEZWfK0kGaI06qaYRvzGJV/vt+s
         20+5MzNBqM7XLHAMYE4QevwiZFTm+62s/N+7LrhcHIoTwI1XpPzk2CsQhmYD7vbheGPF
         CzU9AuWavZqKF9ulG63IL75YhNg1PgaGJEIvlBT+UjnWHqj3zV+uaoagpOGyPIQ6zqW4
         AhMI0JMDDXLlFWwdqvGSgk/NEZqOxgTNOt6pUVx+tv6DNdGx7XU5WGnYY2H99Lj6tV3J
         ZHrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=A+CbdDItu0B8SBCvXs666jnVQGvAGjXtXqBEPiDsOPE=;
        b=wXrLlf+9xIF5oCMo+y+dME2NpjdxYfqjzBHaY346QcPFqi5z6ztDAF3c31Ol/ecf0H
         +/ZSuFYnYFauYrvoJrqqKrHrlRL4BmLRH4EeTIP9flkRJIQQV01x8/HbAOLoOMdinRzE
         rSwOTeBSTqh8ZI/C/5g+XOYyB7DP2EZ/sK0NVQhkvRoh18ajsI8Mi9xXMZdYDN5klHl+
         5UxisjsNAia47criVZVCqgz+POZ+Mc0xPkIxtapauU4mp3GhJVYy+UFUNpysfT0O7MH/
         9uYtOy+LTGeAzm0c9Y44pOSerhS5ty7SSb0N2CgDh8GRxjrMVQu9yERcyKU+T4BbzP5B
         RRug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AUozw4f4;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=A+CbdDItu0B8SBCvXs666jnVQGvAGjXtXqBEPiDsOPE=;
        b=hMTMvKJ35+DktYoAaj/bdNPOCzYCsVgQEwF0SU2jKBhyg7Pl2F4h4kEXl8X23XDsHH
         YqftPtc/Kkf5xNsbdBZhuko4WKeHTO0HAM46cghQnrrglXEdaFd2R1aObI88VhaXWqfK
         3juUEsigQgTpJXvGkWrGJZ3Z4SXeoJj4Zfjwg1FHxRuLW8Z+ROaZH+KIyZy8V5iuR38z
         lgMxPmHAQt1XqJJAXMU1eTED9mr9ep9oOgaEDWBUjsAjnQWEnn01cAVMXYk3FsCHAg+9
         7Mhl81z9ebA0ZktxVUvAQyS2yS9ALS0YiTcD+kNgNG6pZbwWlfGWaMn8QBUnkoYuXIyr
         I8jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=A+CbdDItu0B8SBCvXs666jnVQGvAGjXtXqBEPiDsOPE=;
        b=pDoGbfVkK3Vc2U4MukMJAtvcOfxE0Zgxyu6eg2EUJgeZn7ZUEpKztVdw0tVhpik+wC
         Ay17SeSPpwovwUMjKz2T0PFJn6aEK72PliSuMO6WD40mV0ho6livfwpi3xYbCL+wxR63
         8LKSv/5Dz0liL3iqXbenxyMuYz2nf5sukMRddOj3EXQjBWATo6UW14JmwuRiByLBb3BP
         uUZWmH1cjZslmSkyEs2ATe6B04ck/61zJLL/7NyfbYeNMEjZ161JzoDzkmzPc2YVT4XN
         aharZ703RKXQRIdKT64YGkraHTRv5DhI7GOaiuIacJawVVPZKYl47Rh/ZSnLCxGwJwCm
         TD/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cwjDYwf5XuFKlCobNVjX+W5D8szj03uoySBE6KaqtB8Ql7LOq
	BLH+j1C5bD3v1XMBa9cBKsk=
X-Google-Smtp-Source: ABdhPJz2jQnOsdiYPz90bRvIHwuKZEvLGG/HaV9KgAu0qGmLE/uZ+oRnlI2v5XJ0/NfVV8o/s728eg==
X-Received: by 2002:a63:cb01:: with SMTP id p1mr6228411pgg.406.1612397844343;
        Wed, 03 Feb 2021 16:17:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f683:: with SMTP id l3ls1753381plg.4.gmail; Wed, 03
 Feb 2021 16:17:23 -0800 (PST)
X-Received: by 2002:a17:902:be16:b029:df:bf44:9c5f with SMTP id r22-20020a170902be16b02900dfbf449c5fmr5335226pls.22.1612397843699;
        Wed, 03 Feb 2021 16:17:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612397843; cv=none;
        d=google.com; s=arc-20160816;
        b=dXCRI7GbJvkYKxuCjRHFqJxA5CIgQRCJLIKE4+ySn5qWawHXDxpImxXYcg4IdkVZai
         dURhufEP+1kZeYGOhacUtsdJhWbu44/tDZf+kY5mynoiG95yrIpXoErXn7UHiM9UQ9wA
         58tbs16KyiV2TwhRAjB/GILZRvCGubB+J6YaqdsWaRdbbQY9lNcS9PCLBfwYaS12tWKy
         iKwU2/LsOjcKAor2TbctdFK9ua+7qJ22oa7Mdw6J4Hv/ccp25fViO3pPXZQ6aKSBqu1Y
         BG32044jRXTab/5vQAEkzkYp2UUI01YXTy9fvZFh9Jo2zbsf2/6hehRNxmZJ6SJ61V/6
         qqxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aH1rhNhUTj2RKUZJRdsnzrFvXxO/fmeN1LzVYQPVogc=;
        b=JL1xYZGE7FbRX+8AQn2EFsE9X6T5/X/74t6rmBGGiNvayATBvZNeng4zcpOEG0qz04
         wFu4Bc+/LGnCG/94tetBVxkh+XTvj5Yn8gmfTpNzM2/uTpS6K9G/OPpctWjK9FB+/g7x
         /1mPN0/9sTwAioYpDzGu+G8UofCyXqEzsul1uSpwY/ignkhNycelyDUX7U5n2Jt3aCFW
         nYexrHTWDKysmIHCpiwHfGea9i4qIJhoEbk2L7hBpPrl+xEfGvpe76XnL8pqGBrWaKle
         rs4Bi9xUh0bVqh4sAnEKADBgJhfHXpFdxrLaAfaAxQ0p+BZz/KWloqZCKHVhqfhGJ0Qx
         3fhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AUozw4f4;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id f11si153351plo.4.2021.02.03.16.17.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 16:17:23 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-468-0rp0hcNIPm-QpktHhG4f4g-1; Wed, 03 Feb 2021 19:17:20 -0500
X-MC-Unique: 0rp0hcNIPm-QpktHhG4f4g-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 7884A1934110;
	Thu,  4 Feb 2021 00:17:16 +0000 (UTC)
Received: from treble (ovpn-113-81.rdu2.redhat.com [10.10.113.81])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 911A2100AE4D;
	Thu,  4 Feb 2021 00:17:03 +0000 (UTC)
Date: Wed, 3 Feb 2021 18:17:00 -0600
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Ivan Babrou <ivan@cloudflare.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	kernel-team <kernel-team@cloudflare.com>,
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
Message-ID: <20210204001700.ry6dpqvavcswyvy7@treble>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
 <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
 <20210203190518.nlwghesq75enas6n@treble>
 <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
 <20210203232735.nw73kugja56jp4ls@treble>
 <CABWYdi1zd51Jb35taWeGC-dR9SChq-4ixvyKms3KOKgV0idfPg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABWYdi1zd51Jb35taWeGC-dR9SChq-4ixvyKms3KOKgV0idfPg@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=AUozw4f4;
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

On Wed, Feb 03, 2021 at 03:30:35PM -0800, Ivan Babrou wrote:
> > > > Can you recreate with this patch, and add "unwind_debug" to the cmdline?
> > > > It will spit out a bunch of stack data.
> > >
> > > Here's the three I'm building:
> > >
> > > * https://github.com/bobrik/linux/tree/ivan/static-call-5.9
> > >
> > > It contains:
> > >
> > > * v5.9 tag as the base
> > > * static_call-2020-10-12 tag
> > > * dm-crypt patches to reproduce the issue with KASAN
> > > * x86/unwind: Add 'unwind_debug' cmdline option
> > > * tracepoint: Fix race between tracing and removing tracepoint
> > >
> > > The very same issue can be reproduced on 5.10.11 with no patches,
> > > but I'm going with 5.9, since it boils down to static call changes.
> > >
> > > Here's the decoded stack from the kernel with unwind debug enabled:
> > >
> > > * https://gist.github.com/bobrik/ed052ac0ae44c880f3170299ad4af56b
> > >
> > > See my first email for the exact commands that trigger this.
> >
> > Thanks.  Do you happen to have the original dmesg, before running it
> > through the post-processing script?
> 
> Yes, here it is:
> 
> * https://gist.github.com/bobrik/8c13e6a02555fb21cadabb74cdd6f9ab

It appears the unwinder is getting lost in crypto code.  No idea what
this has to do with static calls though.  Or maybe you're seeing
multiple issues.

Does this fix it?


diff --git a/arch/x86/crypto/Makefile b/arch/x86/crypto/Makefile
index a31de0c6ccde..36c55341137c 100644
--- a/arch/x86/crypto/Makefile
+++ b/arch/x86/crypto/Makefile
@@ -2,7 +2,14 @@
 #
 # x86 crypto algorithms
 
-OBJECT_FILES_NON_STANDARD := y
+OBJECT_FILES_NON_STANDARD_sha256-avx2-asm.o		:= y
+OBJECT_FILES_NON_STANDARD_sha512-ssse3-asm.o		:= y
+OBJECT_FILES_NON_STANDARD_sha512-avx-asm.o		:= y
+OBJECT_FILES_NON_STANDARD_sha512-avx2-asm.o		:= y
+OBJECT_FILES_NON_STANDARD_crc32c-pcl-intel-asm_64.o	:= y
+OBJECT_FILES_NON_STANDARD_camellia-aesni-avx2-asm_64.o	:= y
+OBJECT_FILES_NON_STANDARD_sha1_avx2_x86_64_asm.o	:= y
+OBJECT_FILES_NON_STANDARD_sha1_ni_asm.o			:= y
 
 obj-$(CONFIG_CRYPTO_GLUE_HELPER_X86) += glue_helper.o
 
diff --git a/arch/x86/crypto/aesni-intel_avx-x86_64.S b/arch/x86/crypto/aesni-intel_avx-x86_64.S
index 5fee47956f3b..59c36b88954f 100644
--- a/arch/x86/crypto/aesni-intel_avx-x86_64.S
+++ b/arch/x86/crypto/aesni-intel_avx-x86_64.S
@@ -237,8 +237,8 @@ define_reg j %j
 .noaltmacro
 .endm
 
-# need to push 4 registers into stack to maintain
-STACK_OFFSET = 8*4
+# need to push 5 registers into stack to maintain
+STACK_OFFSET = 8*5
 
 TMP1 =   16*0    # Temporary storage for AAD
 TMP2 =   16*1    # Temporary storage for AES State 2 (State 1 is stored in an XMM register)
@@ -257,6 +257,8 @@ VARIABLE_OFFSET = 16*8
 
 .macro FUNC_SAVE
         #the number of pushes must equal STACK_OFFSET
+	push	%rbp
+	mov	%rsp, %rbp
         push    %r12
         push    %r13
         push    %r14
@@ -271,12 +273,14 @@ VARIABLE_OFFSET = 16*8
 .endm
 
 .macro FUNC_RESTORE
+        add     $VARIABLE_OFFSET, %rsp
         mov     %r14, %rsp
 
         pop     %r15
         pop     %r14
         pop     %r13
         pop     %r12
+	pop	%rbp
 .endm
 
 # Encryption of a single block

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204001700.ry6dpqvavcswyvy7%40treble.
