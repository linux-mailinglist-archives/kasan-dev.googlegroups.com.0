Return-Path: <kasan-dev+bncBD62HEF5UYIBBXNA6GAAMGQEYL54SVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id C458530FD45
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 20:51:57 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id n15sf3131666ljg.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 11:51:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612468317; cv=pass;
        d=google.com; s=arc-20160816;
        b=N1zY8XsGihfHfCJsXqnbED2R7JFGvH+rheAaMqos4cfHWrjJN6s/J5nfxsTpfcskxJ
         eTrnZXmvPdrbDroiVySz7BCOGC8UZNgDeaQfoeufXwKRBIj36BSWTFFChI9y0W3nEEAp
         6TfPREi1ZjgzX0q487W6KaEjdTGy+i8OcBtzNemWqJSFJcvSeUmlqVMJ+QyZgWUTfpqu
         6b02HnNGjgrmdQO8I80E7CrFLjMlRZV+olS/hvwgtfz9JzGeBQRJUmYdi4KGwqnEgNIP
         h7M/5PSjFITeJtU/Y51++/PPWMKCYLVIddRKxOfqFLblxQVVeEbeb9xuuYyPvkHY0HkG
         TosQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7ry9eBAENGNKjLfdnmUig7/xT1atgZsTD3QhyCQuuSc=;
        b=wqdrEuGFjsuD7b3CWWFZMdD+WjkC6P26AbhNbHcGDmSvGaAebusdLoB+q+PeMQLEAp
         V61uxu0QpgF06o7wuAkAEA74kYbCTe/Ch89t9n4kl/7fbBQXfwicd/+9uE73UIzeWWSC
         uheC3QXeTFxQQMzzTGoxtsgjhKsnbk8OpgKAM2rU2SQeQTKoX3k24K1/ZO7yycy5rWr6
         XCQ5Gu0SQEqdCNWWUOkNNasP+QSPSV2kqK1gyVVE7GVELJdegJa+XrskwYfny9iBCjWS
         XyHhtTAs5m+j8EhO9c2aY9OzkOju9AotVyO4JbWEAfWsGcEsYpmgN/iFXuqjV0N/FYQX
         oD1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=ABi2tO0t;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ry9eBAENGNKjLfdnmUig7/xT1atgZsTD3QhyCQuuSc=;
        b=XJ3Vy73y4uiXG62unqIljEZLzcXMHqQbkQW9h5JKtiTXK3L2LrPiVYlXgC2ytvMrgd
         zsbZnaYc5933unffhrsyMmt9GaZkvlyalA8MoWRS0DOC9usjikgB9Ky2gnczhkk2o2nr
         ijwsETtEamjFJHgSxU1vcUo4ZrXVignyBz5Dpk0ZqXPkGYaoAj2w2tPoMh6JMuyqH/e2
         sPuUUutkxtjGrXMcj/YfvEIZJlyps8zGFT9/N/UtzqfSdJ/dKx5yRsLfJVcolp097QF7
         AWvqQJWO+ln6gMMrNpXb62t7AE38Ct88VZwKSYjHTrs/aVnvvv3Xnw/Jnd8BxMecTZkN
         zHpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ry9eBAENGNKjLfdnmUig7/xT1atgZsTD3QhyCQuuSc=;
        b=XTxgQyeX59Q6O6Pq9lwoVZg5z6UNJ6owQqejzqQG6rLWcAL5XX8/Jy67e/IMJDZcHQ
         kxhfGK8SiKa8uajBaDhvEc7XUFR6UcPfU5qla5oG4Q1/ItCgEFxbT/uOzJChispeT3zT
         c5aZ5z4yKeomEqfOifZ1aipbSAseMBHm5gY8hYDNzrJ2dwtvWO2JNVj7Oz4Db47eq+FP
         vthTYw5TmhUsQp4LZgoBrJXt+h13oSlWYHgS1Hp5jVVtX2DTAJOmxWDaowQcvCta8El/
         tofBatF2i0sreWr+ugKoZEcnTwz4j1pHPtXRbTCHHY3hr9oOzkVbEPEIyIdd9vJuhoJZ
         UVYQ==
X-Gm-Message-State: AOAM532et88pZPfVLTTVRoJdUnE8OXtUm1HC41aVKsrRXWECk43n5oQl
	IhcGYWLlmoK/IwVpoapUsq0=
X-Google-Smtp-Source: ABdhPJy++vWBNv3WYi/m7c98DJhog56XsIFMbV1ciHUliP92ns8Pt6D4JRlHv7EKFnXdw4dCDj1gqw==
X-Received: by 2002:a05:6512:a90:: with SMTP id m16mr485069lfu.577.1612468317306;
        Thu, 04 Feb 2021 11:51:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8745:: with SMTP id q5ls1249902ljj.6.gmail; Thu, 04 Feb
 2021 11:51:56 -0800 (PST)
X-Received: by 2002:a2e:980a:: with SMTP id a10mr576270ljj.280.1612468316347;
        Thu, 04 Feb 2021 11:51:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612468316; cv=none;
        d=google.com; s=arc-20160816;
        b=fCsvUO7+tStrmseAcwAVMdDoIgj+ueAzJei7IibGwcLeJvyHYOOodC07BHeqw547zU
         bCJ5yyLYNHd9pToPk+LcIdtCYdX8d2ax1dbHNOwtVcc60puikn5AhFqJSfK+jnXbaHbR
         c1ExR7e6NAXIwbuckyBGE5zF17Vww/bIV35t2tn5pUUXdaan+iqHJX9GenmPzMTQT1hB
         RUCbmlLxdeHs8q9Ap0wis35hrH6m+nsXtM35RXJnyTHQWMvOrASXTHEtJFUK2te2nw9f
         Xh2GnHUakXlCG32DthemlNinypLEel3jvmHMEh35Wodfvcx6neTq9zsK6T8oh+Vm+k7+
         ZWiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FToFoRW57QEfMw0vp233PBaMzzSywEYZZwEWphiSDG8=;
        b=or01SXO2pP3CvRStlWjx47exFLjowyYtkd/NxYO9eNd85bqaBoeWO8bcBrZk+Nhhyy
         0sfuLbfUXt8pnpnUWsgrCmgCNRe/7c9BFJJIEEYzJC/WtnMgrHN6KVnt1WqeweRUA405
         pmrh32HEc3+ks9h0Ojbbna4QPLP+RnYLmg14MxiVATWDyF4vE8WfcqNmHquRvubn7JXx
         V2mgOy9qwGQTSewKs+x9/IjPNvLiwGlTYr9d4j1re+osWZn6vRpCd695RSuWtezF8Jm4
         QtyazNdttLrQVzflksQwbqE/xvgyA/O2BvxcwkF6nHkZh096dbuQBvAfs9nZjmLuIEad
         s1Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=ABi2tO0t;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id g28si318723lfh.12.2021.02.04.11.51.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 11:51:56 -0800 (PST)
Received-SPF: pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id b2so6439293lfq.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 11:51:56 -0800 (PST)
X-Received: by 2002:a05:6512:3904:: with SMTP id a4mr526525lfu.340.1612468315961;
 Thu, 04 Feb 2021 11:51:55 -0800 (PST)
MIME-Version: 1.0
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net> <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
 <20210203190518.nlwghesq75enas6n@treble> <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
 <20210203232735.nw73kugja56jp4ls@treble> <CABWYdi1zd51Jb35taWeGC-dR9SChq-4ixvyKms3KOKgV0idfPg@mail.gmail.com>
 <20210204001700.ry6dpqvavcswyvy7@treble>
In-Reply-To: <20210204001700.ry6dpqvavcswyvy7@treble>
From: "'Ivan Babrou' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Feb 2021 11:51:44 -0800
Message-ID: <CABWYdi2GsFW9ExXAQ55tvr+K86eY15T1XFoZDDBro9hJK5Gpqg@mail.gmail.com>
Subject: Re: BUG: KASAN: stack-out-of-bounds in unwind_next_frame+0x1df5/0x2650
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: kernel-team <kernel-team@cloudflare.com>, Ignat Korchagin <ignat@cloudflare.com>, 
	Hailong liu <liu.hailong6@zte.com.cn>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Miroslav Benes <mbenes@suse.cz>, Julien Thierry <jthierry@redhat.com>, 
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel <linux-kernel@vger.kernel.org>, Alasdair Kergon <agk@redhat.com>, 
	Mike Snitzer <snitzer@redhat.com>, dm-devel@redhat.com, 
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>, Alexei Starovoitov <ast@kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>, 
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>, John Fastabend <john.fastabend@gmail.com>, 
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>, 
	"Joel Fernandes (Google)" <joel@joelfernandes.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Linux Kernel Network Developers <netdev@vger.kernel.org>, bpf@vger.kernel.org, 
	Alexey Kardashevskiy <aik@ozlabs.ru>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ivan@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google header.b=ABi2tO0t;       spf=pass
 (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::135
 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
X-Original-From: Ivan Babrou <ivan@cloudflare.com>
Reply-To: Ivan Babrou <ivan@cloudflare.com>
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

On Wed, Feb 3, 2021 at 4:17 PM Josh Poimboeuf <jpoimboe@redhat.com> wrote:
>
> On Wed, Feb 03, 2021 at 03:30:35PM -0800, Ivan Babrou wrote:
> > > > > Can you recreate with this patch, and add "unwind_debug" to the cmdline?
> > > > > It will spit out a bunch of stack data.
> > > >
> > > > Here's the three I'm building:
> > > >
> > > > * https://github.com/bobrik/linux/tree/ivan/static-call-5.9
> > > >
> > > > It contains:
> > > >
> > > > * v5.9 tag as the base
> > > > * static_call-2020-10-12 tag
> > > > * dm-crypt patches to reproduce the issue with KASAN
> > > > * x86/unwind: Add 'unwind_debug' cmdline option
> > > > * tracepoint: Fix race between tracing and removing tracepoint
> > > >
> > > > The very same issue can be reproduced on 5.10.11 with no patches,
> > > > but I'm going with 5.9, since it boils down to static call changes.
> > > >
> > > > Here's the decoded stack from the kernel with unwind debug enabled:
> > > >
> > > > * https://gist.github.com/bobrik/ed052ac0ae44c880f3170299ad4af56b
> > > >
> > > > See my first email for the exact commands that trigger this.
> > >
> > > Thanks.  Do you happen to have the original dmesg, before running it
> > > through the post-processing script?
> >
> > Yes, here it is:
> >
> > * https://gist.github.com/bobrik/8c13e6a02555fb21cadabb74cdd6f9ab
>
> It appears the unwinder is getting lost in crypto code.  No idea what
> this has to do with static calls though.  Or maybe you're seeing
> multiple issues.
>
> Does this fix it?
>
>
> diff --git a/arch/x86/crypto/Makefile b/arch/x86/crypto/Makefile
> index a31de0c6ccde..36c55341137c 100644
> --- a/arch/x86/crypto/Makefile
> +++ b/arch/x86/crypto/Makefile
> @@ -2,7 +2,14 @@
>  #
>  # x86 crypto algorithms
>
> -OBJECT_FILES_NON_STANDARD := y
> +OBJECT_FILES_NON_STANDARD_sha256-avx2-asm.o            := y
> +OBJECT_FILES_NON_STANDARD_sha512-ssse3-asm.o           := y
> +OBJECT_FILES_NON_STANDARD_sha512-avx-asm.o             := y
> +OBJECT_FILES_NON_STANDARD_sha512-avx2-asm.o            := y
> +OBJECT_FILES_NON_STANDARD_crc32c-pcl-intel-asm_64.o    := y
> +OBJECT_FILES_NON_STANDARD_camellia-aesni-avx2-asm_64.o := y
> +OBJECT_FILES_NON_STANDARD_sha1_avx2_x86_64_asm.o       := y
> +OBJECT_FILES_NON_STANDARD_sha1_ni_asm.o                        := y
>
>  obj-$(CONFIG_CRYPTO_GLUE_HELPER_X86) += glue_helper.o
>
> diff --git a/arch/x86/crypto/aesni-intel_avx-x86_64.S b/arch/x86/crypto/aesni-intel_avx-x86_64.S
> index 5fee47956f3b..59c36b88954f 100644
> --- a/arch/x86/crypto/aesni-intel_avx-x86_64.S
> +++ b/arch/x86/crypto/aesni-intel_avx-x86_64.S
> @@ -237,8 +237,8 @@ define_reg j %j
>  .noaltmacro
>  .endm
>
> -# need to push 4 registers into stack to maintain
> -STACK_OFFSET = 8*4
> +# need to push 5 registers into stack to maintain
> +STACK_OFFSET = 8*5
>
>  TMP1 =   16*0    # Temporary storage for AAD
>  TMP2 =   16*1    # Temporary storage for AES State 2 (State 1 is stored in an XMM register)
> @@ -257,6 +257,8 @@ VARIABLE_OFFSET = 16*8
>
>  .macro FUNC_SAVE
>          #the number of pushes must equal STACK_OFFSET
> +       push    %rbp
> +       mov     %rsp, %rbp
>          push    %r12
>          push    %r13
>          push    %r14
> @@ -271,12 +273,14 @@ VARIABLE_OFFSET = 16*8
>  .endm
>
>  .macro FUNC_RESTORE
> +        add     $VARIABLE_OFFSET, %rsp
>          mov     %r14, %rsp
>
>          pop     %r15
>          pop     %r14
>          pop     %r13
>          pop     %r12
> +       pop     %rbp
>  .endm
>
>  # Encryption of a single block
>

This patch seems to fix the following warning:

[  147.995699][    C0] WARNING: stack going in the wrong direction? at
glue_xts_req_128bit+0x21f/0x6f0 [glue_helper]

Or at least I cannot see it anymore when combined with your other
patch, not sure if it did the trick by itself.

This sounds like a good reason to send them both.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABWYdi2GsFW9ExXAQ55tvr%2BK86eY15T1XFoZDDBro9hJK5Gpqg%40mail.gmail.com.
