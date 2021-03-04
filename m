Return-Path: <kasan-dev+bncBCR5PSMFZYORBYEMQOBAMGQEJHKAZWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B22332D1E2
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 12:37:06 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id g16sf10330080pfr.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 03:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614857824; cv=pass;
        d=google.com; s=arc-20160816;
        b=BRy7xIW8NjOIvDYShWjSpJqH7larGdQC+pEFi6X5cZugpD7m6VylcWphM8oAoEZRjG
         jh5ExsAWy8Z7g078/lypF8zo6onx4yQIGmJwcUInWXiyApHEfappGJ63i0El7ObhoLeT
         3dH8Z0FT0doMbtYqNbqSuX/Wk9p9PenDYlg1rC/a3KDXOfywXFNBXkcScPTh7+cBtbH0
         Kyoqt2CjJJCfnTx6v6SpwlxLkOYsDGg/TYGojdzvoUiGhTSkAhCgbndAvBqt2UDozYl/
         qjMmAaDSyunaz9c/O8+tT1ng0Qd59dCfKoBmaNk9jfjNfhEm3uxaGOKMg2gfDAp4/XMy
         +p/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=QMXv+vpc/BUrzxJIJS4w7aZ0OmKmqj2CSaYXhQdQ1/c=;
        b=nPuFfGdO3njS1Gt5+ugFkpXU5KkyslslTYfumwqBVchD7ycIpAxPG1JXAt5sl9ZOv2
         QdEs4MBWXPppGnwBiTpzv50tq5AIhd3yk11JhFNw1g4MPiiXuQLYkFsV0+7k+olK4Tfl
         CmaseAno+iwU8RWOoDgLXm1Iw3IP3+52YpBqsamY2ZtMFAdfy5jCOAxt1K21U7nrM2ph
         O0BXl+OJ6fb7QauNaAf57MCDeh+++J25nRkUoZno4aLYjy9/cW6soTQsubJuvvLDF54E
         R/Kw8dNKk1V4MGE5tvIm23nwUOcZr85+RmxpFi3wqa3fAv6DxeUfFSuG1TloMwb+j2i5
         vZjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=h+SU9xNx;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QMXv+vpc/BUrzxJIJS4w7aZ0OmKmqj2CSaYXhQdQ1/c=;
        b=VcOKB4GHiTeb28aA2k8oPD2+M1FSVAZBA0OriqJcD3NEkLLkfkCyqjAf/PeiiCxm3U
         4bUU3NUiIUPQ2cpseuQ9mm8N+GS4wNLXcentMIQdAGDfwrFEeEYErgkPbYO9dSKRKoAH
         Jg5J6E8kQ5VpdXn2mOLxn4dy7rPurLljeR70qxt8w2ulmV1HJtd7ySbQkm1iiSI+LtP2
         N9DSGvuXjvGthz1iCc5KNLU9c9Hso1e6FVzs6TNB4m43mhsfjvOfau/cLQxxvNOYTiez
         tRyIwxS0l91HnRDZuOjqtwjtuXJwpM7Ha1oUDxPjpBep7Keq7ljnWY/FZlYbcJy3Uw2P
         NqZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QMXv+vpc/BUrzxJIJS4w7aZ0OmKmqj2CSaYXhQdQ1/c=;
        b=G5ect66137Yx7b4hwBCARW2TUCiGa+geXCxIXyLbSN9Dsr02BEnoEULVIQKYy5bU98
         4Q4V7Wzm/W/7P3tDwg84IBDAqLthytdCMRYG1X9pKQ0Sd7doa5uOKlAlBtDsVCuZV+CE
         /5MoldvMlUbHKMB1C73Qz7ySmIssr6WQdLeKb1lm/TTCdNocEUYx2XDYzCw04n/P/J7b
         UJWEHH/fi2rk1KBg+kH9aUZkP9lU4YX/1khOSb/X0nPRd42MH3YaHaiw4iCCUuVdzzjG
         BvTv/xYpUkK72EwZCALb+OUWAyhBxSu2QN5rRjgNLmgKo11J+3XG3JpeRIWsRsdNDxO+
         N/TA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EBUyMWpCQ3h0I/gi3frmzkVCmCtCHYVHHyOwPl8b/Rrkhqb2U
	s5a9PpQSfsRpp2fSmCv7VtM=
X-Google-Smtp-Source: ABdhPJzLBrJ5QW8sckLcJqO0sFddxc3wEzqX71jsj1EC6YGJiVCO3kYU76mjrHbB6xcDIJ9XKc2VYw==
X-Received: by 2002:a63:368b:: with SMTP id d133mr3444130pga.88.1614857824627;
        Thu, 04 Mar 2021 03:37:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:63c2:: with SMTP id x185ls2297933pfb.7.gmail; Thu, 04
 Mar 2021 03:37:04 -0800 (PST)
X-Received: by 2002:a65:524b:: with SMTP id q11mr3260736pgp.207.1614857824093;
        Thu, 04 Mar 2021 03:37:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614857824; cv=none;
        d=google.com; s=arc-20160816;
        b=HDdGn5nFV/9927Xe9rAwMxCToxDZwWsM9nlI3qgT1x5TYYVPuTXXtI+b5tg7kYFaoC
         3/OG0LWQ6TLyp7PYXh01BAkwZQiLQWpDn9lXTunLyCfNaTf/K/VhNVFM0lgfXWk5IFnv
         uHjUSBdXLqtt5V+gyAQ2+6kMP8n1pyYzTW8hmuHYx3uUepg3n9UIG2Oxd+DDMhHV9Sep
         Syvt/eU9xHtvRqEDRAh4lskIXdEj6/ySUV9DCYEY4x+KmGrqUGXGrkBe78yl6kkNMQA1
         3K+cN+jzS7pxxKEmV9fmHnj8FNcVtz50oF3vhUyGMjbRIaZI0V/VK2g1N6HXxJxvJOCW
         akwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=xB2NH2RDnNFxOP2JfengPRlNHO42YuHU5/2Vw/S7pOg=;
        b=Ff6/C5pTXOS1NR6BTfyLpQTdHF04UwwkZsmjrxPk0/1FXHqnuxZQh38pZgEDUiS0Ex
         yVoOvEmtjpWWVOsCYDSOSb2PEuDMwzsaDiXS6KD+icpeyQgADYE/q6mlSITPmTqEUat6
         AAgXnoB6bB+wheLVBb6/b+NJ9QgRH4FzKpQdACZGQNOE/fp0viavSavy1jtMiijtXV4Q
         qsgJYxjXPZBls6Ec+IG+O7bFOkQOKdBsB32h/LuwTBLOCRxp5W//sBHAhbEbQjaY6Ia2
         N+Bbh0Aca+2BOoNH0E+h1vHqjyBRx5qfXlU7qtwN/TM0r5qwXzrgBQO0VcQcdQ9T8LWH
         z6IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=h+SU9xNx;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id j11si2051531pgm.4.2021.03.04.03.37.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Mar 2021 03:37:03 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4Drpjz4ZPsz9s1l;
	Thu,  4 Mar 2021 22:36:55 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, Benjamin Herrenschmidt
 <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>,
 elver@google.com, rostedt@goodmis.org
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, Segher Boessenkool
 <segher@kernel.crashing.org>
Subject: Re: [PATCH v2] powerpc: Fix save_stack_trace_regs() to have running
 function as first entry
In-Reply-To: <20dad21f9446938697573e6642db583bdb874656.1614792440.git.christophe.leroy@csgroup.eu>
References: <20dad21f9446938697573e6642db583bdb874656.1614792440.git.christophe.leroy@csgroup.eu>
Date: Thu, 04 Mar 2021 22:36:49 +1100
Message-ID: <878s73rvzi.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=h+SU9xNx;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted
 sender) smtp.mailfrom=mpe@ellerman.id.au
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:
> It seems like other architectures, namely x86 and arm64
> at least, include the running function as top entry when saving
> stack trace with save_stack_trace_regs().

Also riscv AFAICS.

> Functionnalities like KFENCE expect it.
>
> Do the same on powerpc, it allows KFENCE to properly identify the faulting
> function as depicted below. Before the patch KFENCE was identifying
> finish_task_switch.isra as the faulting function.

Thanks, I think this is the right approach. There's kfence but also
several other users from what I can see with a quick grep.

...
>
> Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Fixes: 35de3b1aa168 ("powerpc: Implement save_stack_trace_regs() to enable kprobe stack tracing")
> Cc: stable@vger.kernel.org

I'm not sure about the Cc to stable. I think we are fixing the behaviour
to match the (implied) intent of the API, but that doesn't mean we won't
break something by accident. I'll think about it :)

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878s73rvzi.fsf%40mpe.ellerman.id.au.
