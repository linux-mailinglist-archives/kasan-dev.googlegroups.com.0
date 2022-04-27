Return-Path: <kasan-dev+bncBDAMN6NI5EERB2ULUWJQMGQEWPT2CVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 429F0511860
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 15:32:27 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id c12-20020a2ebf0c000000b0024af8f2794bsf755278ljr.12
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 06:32:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651066346; cv=pass;
        d=google.com; s=arc-20160816;
        b=dysUWvj8PgFBRnctqt+dBoeeyhOhOXvNCQvRcxLGmnMMIFi8qRk+9l0nUl9Ue4RnXh
         onJR75DVFlSShNI7rZZr7h70iMXqTRw5k8uA7+j76MmjABYtxRG2KkBCg9rtFZZSJlWQ
         KcmuPh5yaMxf/KTczTuxd+55i1bJHiSjKi9h6rq2ZTylcgl7v2XLU3Xky9hS9160wi+Y
         Bwcc/wxhsw25/ISJaxL0csunZZmz0SIgfXDifk6fPZ90DgCsSb9P6ieRdTezmTJwZlKo
         B43ns3+f6A91A2YUnQ3lzgGVsTyyqHWvB5bi9hsjF57WMUCbOAbreLGhRAh4SSNbmHzk
         YOcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=nt1SbXD0N9mBMinFu/G8XTI9ssnIQ8kZc2TdN+HVe8U=;
        b=KFhFgr8qernrorFJqrW8KeCZKOXjj0ViQx/74nOc78fMS7MDZ4Y1y4jevIWpWDNrrb
         R1Pgw30jvUEdeCHajZO8WQ1wxVcTqw/OiDFAxwPGk3G0Hw1E5QrBF8q/qu3+1qpubw0c
         U04mkLjALD8xL8SSpFXbkammroOS7D7o205HBUWU2wHg0Wt7Tf1WXweLiG81haP7cIH5
         ScfWbgRrGKJYwJKbchrAf1XJ59fJwI0K70lla/IyXUa1OEJukia1/rlat7AsKo08rTAr
         DZZ+0EHpiGZA7wVrtufgjovx4EsugcsvzdZH2ZK6PBDRyW3wwWgPqmnj0rwxxAXC+L7U
         tZ1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ohn+hC64;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nt1SbXD0N9mBMinFu/G8XTI9ssnIQ8kZc2TdN+HVe8U=;
        b=FifyqydYDXn+j8juqIjadDVD06FRsSDb2cXgE5WFFGj2inPGspoTAaGTPc1qJbyIZn
         g13aCGF4Qebn+KzJt2/jbua9/L44L5bYkxd33zbCJOINN07vbw9IxyAXro9bHhow9nHv
         l6YNTYZxGCjSO2p7qHSy2wFWO3gIUXghxRCks1Y6p4XJz0wNo/mUx3a5aWPFqqaDl09p
         l/J2LaVrFAP91qrY/KdIC/uenuVW5gmbMnEdFibAix8Lt2fcOTv2xfS26LCNOngJC8w/
         9jsl5pvYouDhL2e3HIU6V+wpyHlt45joFu+6BNS7Ai36xaWuw15xSPZGy8t1BCK+H+07
         PHQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nt1SbXD0N9mBMinFu/G8XTI9ssnIQ8kZc2TdN+HVe8U=;
        b=mdK4Evx8hg/CvDBTNia/QWlU9iH2WJO+q8yqQqP3OmCzbREtmosIG57S6SDirJbMPT
         LaTM4iR19Mcorz/bcpAYtKEjsR9SJ2/Eg1qmC9SPq0+tFIjSLlXWgU0f0oJVL3LcchnY
         /Jn9sLHRouIhMXjj9B8mal02zhPy3RDvjEcuqpMlbFeCKzGv2BRmW0N6vCliCorcWvh9
         ys3zDmfF297y6GIajHl+C/pu2XxaVSSxvWVdMYiv5fG/IvpPgWjNMBNjACbFa/yHGGZI
         qV1F04GY+U7T7Nhv30xlfTr2tAFhaO1eKScXvhNpOhJkwFpT1DRV1HEicUaa2BUzfHQT
         rFBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533by1gdIJGFdtvCILRypfabskSdMfqJUisn21fYRQ3lYm1E6La7
	xlTl6emRMsRw42gs2CHOQrI=
X-Google-Smtp-Source: ABdhPJxCpxIL+cagIxcXoMbPDN7n0eLikrlOWwJIGMta5zD/ND+Z8Hl94NN6A3I1jaHM+ficKRDCaw==
X-Received: by 2002:a2e:9483:0:b0:24f:efb:779a with SMTP id c3-20020a2e9483000000b0024f0efb779amr10963915ljh.499.1651066346671;
        Wed, 27 Apr 2022 06:32:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:892:b0:249:a5b7:d97e with SMTP id
 d18-20020a05651c089200b00249a5b7d97els2743775ljq.10.gmail; Wed, 27 Apr 2022
 06:32:25 -0700 (PDT)
X-Received: by 2002:ac2:5921:0:b0:471:fabe:ad90 with SMTP id v1-20020ac25921000000b00471fabead90mr14988065lfi.496.1651066345520;
        Wed, 27 Apr 2022 06:32:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651066345; cv=none;
        d=google.com; s=arc-20160816;
        b=EZktXW0CpTHBXcZzbp9PCbBVWo5Pzi9CI5CP/9Q1r8MmsKHMMZddOyof9mBjUMOpHV
         tKCHRPu63YOqcFyiQV6s5/CcATXtxFmGkRF8+8lP1CYtByskJuLiC7BytH5r5K5/w49k
         AbaI5c0cTRWuQV9b1OTgw+muSA4rq0n/MOtpDfNaSxggP6lq9rp0n5oYXaTOPMWihl6d
         FexBqMd/nUDNzE1k0u/1KQv1L0twqqhF+k6vQI9ujds4XQwvnyNDZFojifK5MGJhmJ1t
         I5j9rqqiuYTA4piISucGJgtK+7+ZMzEjNXAmWICIfSwY5NCtZk66RC4J7knW4sFYqOia
         Pqpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=X7MGqKhcR2rK4bHhpyakvKk80PXfTvRpOEHw1CHocKs=;
        b=qB+iF7JjNQTAIItWxkR/pnPHVGpuLV5VIUzD8/edCwgdPu2XfXCAg82NCwIuKkkKkd
         9reXsJDZ6IVMKlbT8yNt28M+zl31o0IWopzIPgH8gfgfm8m5ckT0kIzk7Lu6DitQnZ5Z
         An4XNbFCXKwmx9a3drqNaUYeAl6cGj44/qyas1SKSnXTIw/ZQ1wL64b0KwVEAg73x25W
         FSDntv+GlEswa0GnBJHOh8Pwmt63hYpK1bhgMzeh7HR7NfkzJJTuG/jAj5+spw+fyAeu
         ZLyrROFeAP15ytNMIGcRUuzZ7u33nYHoEXKuU4wFDwnCR35ds7VYaKQufXgOh4NQ37Bo
         LZig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ohn+hC64;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id h21-20020a2e3a15000000b0024f0dcb32f8si68417lja.5.2022.04.27.06.32.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Apr 2022 06:32:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Alexander Potapenko <glider@google.com>, glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton
 <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>,
 Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav
 Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik
 <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
In-Reply-To: <20220426164315.625149-29-glider@google.com>
References: <20220426164315.625149-1-glider@google.com>
 <20220426164315.625149-29-glider@google.com>
Date: Wed, 27 Apr 2022 15:32:23 +0200
Message-ID: <87a6c6y7mg.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=ohn+hC64;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Tue, Apr 26 2022 at 18:42, Alexander Potapenko wrote:

Can you please use 'entry:' as prefix. Slapping kmsan in front of
everything does not really make sense.

> Replace instrumentation_begin()	with instrumentation_begin_with_regs()
> to let KMSAN handle the non-instrumented code and unpoison pt_regs
> passed from the instrumented part.

That should be:

     from the non-instrumented part
or
     passed to the instrumented part

right?

> --- a/kernel/entry/common.c
> +++ b/kernel/entry/common.c
> @@ -23,7 +23,7 @@ static __always_inline void __enter_from_user_mode(struct pt_regs *regs)
>  	CT_WARN_ON(ct_state() != CONTEXT_USER);
>  	user_exit_irqoff();
>  
> -	instrumentation_begin();
> +	instrumentation_begin_with_regs(regs);

I can see what you are trying to do, but this will end up doing the same
thing over and over. Let's just look at a syscall.

__visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)
{
        ...
	nr = syscall_enter_from_user_mode(regs, nr)

  		__enter_from_user_mode(regs)
              		.....
			instrumentation_begin_with_regs(regs);
			....

                instrumentation_begin_with_regs(regs);
                ....                     

	instrumentation_begin_with_regs(regs);

	if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr != -1) {
		/* Invalid system call, but still a system call. */
		regs->ax = __x64_sys_ni_syscall(regs);
	}

	instrumentation_end();

        syscall_exit_to_user_mode(regs);
		instrumentation_begin_with_regs(regs);
  		__syscall_exit_to_user_mode_work(regs);
  	instrumentation_end();
  	__exit_to_user_mode();

That means you memset state four times and unpoison regs four times. I'm
not sure whether that's desired.

instrumentation_begin()/end() are not really suitable IMO. They were
added to allow objtool to validate that nothing escapes into
instrumentable code unless annotated accordingly.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87a6c6y7mg.ffs%40tglx.
