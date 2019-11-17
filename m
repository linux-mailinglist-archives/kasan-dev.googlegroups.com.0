Return-Path: <kasan-dev+bncBCW677UNRICRBWNGYPXAKGQEWKMWO3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 50FBFFF793
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Nov 2019 05:58:03 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id e13sf11306442pff.17
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Nov 2019 20:58:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573966681; cv=pass;
        d=google.com; s=arc-20160816;
        b=xa+DaMG2qwbOmVfQd6zDkNsvbm7uw9pCvs4jnCqwQROEqfgU71Yp/T8SlXgIclJtTR
         aFZEeyAt41gw24dkX7NqDo4sjj7HciYkn7MIvncqf6pRyQSh4jzgJZcLopix5IatU0d/
         +FPlKl7op+8mH2WltALYj3xBHN53Cgac6QKtdTlb2XfFCGeko2AmGWlpnLf29rkeLuOB
         HraicN/CcMhoxKKxTVZvWaZE5wtzWd/gmXuPs1iGe746gEVJYc6WddKWsR9Hxgeu6UkN
         kS94lwmB/4le1biTGPDyRcz8ZYUEv1SBmVoFWvtZUzHWOzYJE4P0o2+I2rKOAo+uz680
         ibVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7oCELSej7gNWSJe92PbbYqF/+RkgAAAcpQa7iE+T3i4=;
        b=pCowDNRVU+PyRdFRhTQ5b+2KtsSAT2PgsXXahiQumBH8c7pL1ALfj5Qsmd1HOga0IZ
         lb3Cdd7WV1GwDifJMhJO2ygnRRqAbXFHW5cNNgkVYPtP37KcJqqfD4cbJwdCECrs+4dl
         UTJkPc5Eru62IkupN4jEdMXvRoV6Svx18TAETI/Exg4ZKrUaNoY45Xg1AKHV4QeON89S
         nv0aNqql15Bx8KJym6ltvM4M9jcbqnXwIH7mGrY+WDsvipvnLJm5DzH+tFyXQ0XMdgdw
         DYLpeJCay7S4DiJa4yK0zdpUwtqC6R7xlFNC4FVDkRpNJOYX4jBsqVyOTCoFWH4P9VOH
         Y2fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="a/3JWGzt";
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7oCELSej7gNWSJe92PbbYqF/+RkgAAAcpQa7iE+T3i4=;
        b=ilGaaPNIGIVF7BfJCt4q1GThlYQqF4DhfSUnJ0HVP1/mOjRa31uK7PEa4z5t6Xzxbm
         7iW8ERTxnw/WVFh5f4tCRSyDor2UpD4rEiH+lghCH4fuek7kMLSwfcuUP+qBW/YPh/s2
         Gfpco1ls/8qC+ydyr+YaXoU3lBBJUQYgCN7DGBIx951sRJ10tXssQADZvK8S8AxLzR/4
         puHYa5KNFFFCNkMSMqs9w44Eu4qlbLFKTNPNxAIdxojqmk80u0hgqmjPJxSTgfKe/9kf
         1nr3Lz/k3k9cVnvf7cSjp4pL6kriZ+Rb++QsruDSTbJ0xzkVfd/LsxaYz1RRYK4WyB8T
         XDyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7oCELSej7gNWSJe92PbbYqF/+RkgAAAcpQa7iE+T3i4=;
        b=Jon7w9y6mKDsSNVRd59M0l2N0NC8UFbB5hx4R9GHVVq/IDsg+aTIhMJWq+233xr24/
         75aLBYrshl8hz59vRcvPGS/qIqeNB9BlNUPlrtA3CGCz9sfKIQJK+ErU/gZH9RZ0UCcq
         aa3Z/klYyI5H7Ms7f+RVMnH/4WZNqCiZgEKj7JBWBnPr7RbH4XDELsfyl5XPbUHAzMj2
         gsSXRBjsljOlb1C+Dv0K+jIKkTVgt75+a81cgVXu4RLMu0SYpss3a+GoL0MtalOjL9Qe
         +hckYkjnnXC6jTjf6ssOlfVkftJeGOjFnOALQgYbuBqsonCBBrOMlAzrXFAJfZ7MrR7X
         O+4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWc/aAwGX5TtZ2e6eL0GpaueVgrebPrx4Ed7QayHwizK/Wxr3Rm
	91HbAmc483MRD/5Zlja0tno=
X-Google-Smtp-Source: APXvYqyPx4wMRIpdt14bWEmQv26n9uJK5Xmpaa1fzvLTG+P3Y3GV4WCa1PrUcYeIVmT78rCM+QhQnw==
X-Received: by 2002:a17:90a:6d27:: with SMTP id z36mr31202098pjj.38.1573966681358;
        Sat, 16 Nov 2019 20:58:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:a10:: with SMTP id 16ls1441757pgk.1.gmail; Sat, 16 Nov
 2019 20:58:00 -0800 (PST)
X-Received: by 2002:a62:8490:: with SMTP id k138mr27233688pfd.186.1573966680960;
        Sat, 16 Nov 2019 20:58:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573966680; cv=none;
        d=google.com; s=arc-20160816;
        b=DGHMPO9lTIwMQxdh9EYftCTicBKvyxUahc3KOifeUQat2flPyBFX+WqMBPnpzclrLP
         Scy+Ct8AE/Vki6yfDH5iu0aRQt8lzVg5fjj3SvEyxRQzDNsemN1bfPSGRFuN5SUJwMN7
         hWlL8diRWTS5j2hCJaG6Dz/EUqK2tB7w9dGChY0Wty4q8JVryngi7DCvyDouuqFRvXYA
         wHHxwH+pRitE1VpibWcSrECmQGeZeqaCnVi9SjEcKEOZX8AlEycO2j5qEJ3SMqbLLWR2
         5GLHGK5IIOVvuTpsK1OS1s6Ac3kNV0qoE6apwy0jrmnYDSKHeaZntZ/mYa1Rnav6ewVm
         pQcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=jEgcbLffHvInuudf1yxHrJupAep1eByuwcjffM5aOvc=;
        b=wdsEXVZyZxCjPUf4oMVCN2RHkbwrAiJM9t2NdBw7Ov2sveuY1gNk3OVQmilJ6QY9su
         gbHwnsIxYfGzZn0pCQbIDtOgF/07yu8x8HfZiL4ePZzaRRApozSr0I1oFcSpLCPXpV8d
         neRkr904nHdBU6C+I8nykeSdHubSKzJwaVF7gSpdyUYU7bZqvE2zY9+uHRglNisbNJkR
         l1OoGUA5APS/trqfU+xTYdlFiMiZ6iISmgmYhaVi5PqIH1XtrSbQmA5ChekTzLhn8F9v
         LQdHhuTDyNdD6WN3eVKUYkYKl3wwLm/FgEC+4iG1JVf0vcYIa4fSqQMfEizIWvO4oR7V
         SUPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="a/3JWGzt";
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id w63si501505pfc.1.2019.11.16.20.58.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Nov 2019 20:58:00 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id k32so2208055pgl.2
        for <kasan-dev@googlegroups.com>; Sat, 16 Nov 2019 20:58:00 -0800 (PST)
X-Received: by 2002:a63:1f08:: with SMTP id f8mr8309321pgf.145.1573966680566;
        Sat, 16 Nov 2019 20:58:00 -0800 (PST)
Received: from localhost ([2600:1011:b043:4c6e:3bc6:3ed3:dc27:5ef3])
        by smtp.gmail.com with ESMTPSA id j20sm15436653pff.182.2019.11.16.20.57.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 16 Nov 2019 20:58:00 -0800 (PST)
Date: Sat, 16 Nov 2019 20:57:55 -0800 (PST)
From: Paul Walmsley <paul.walmsley@sifive.com>
X-X-Sender: paulw@viisi.sifive.com
To: dvyukov@google.com, glider@google.com, aryabinin@virtuozzo.com
cc: Nick Hu <nickhu@andestech.com>, corbet@lwn.net, palmer@sifive.com, 
    aou@eecs.berkeley.edu, tglx@linutronix.de, gregkh@linuxfoundation.org, 
    alankao@andestech.com, Anup.Patel@wdc.com, atish.patra@wdc.com, 
    kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
    linux-kernel@vger.kernel.org, linux-riscv@lists.infradead.org, 
    linux-mm@kvack.org, green.hu@gmail.com
Subject: Re: [PATCH v4 1/3] kasan: No KASAN's memmove check if archs don't
 have it.
In-Reply-To: <20191028024101.26655-2-nickhu@andestech.com>
Message-ID: <alpine.DEB.2.21.9999.1911162055490.21209@viisi.sifive.com>
References: <20191028024101.26655-1-nickhu@andestech.com> <20191028024101.26655-2-nickhu@andestech.com>
User-Agent: Alpine 2.21.9999 (DEB 301 2018-08-15)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: paul.walmsley@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b="a/3JWGzt";       spf=pass
 (google.com: domain of paul.walmsley@sifive.com designates
 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
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

Hello Andrey, Alexander, Dmitry,

On Mon, 28 Oct 2019, Nick Hu wrote:

> If archs don't have memmove then the C implementation from lib/string.c is used,
> and then it's instrumented by compiler. So there is no need to add KASAN's
> memmove to manual checks.
> 
> Signed-off-by: Nick Hu <nickhu@andestech.com>

If you're happy with this revision of this patch, could you please ack it 
so we can merge it as part of the RISC-V KASAN patch set? 

Or if you'd prefer to take this patch yourself, please let me know.


- Paul

> ---
>  mm/kasan/common.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..897f9520bab3 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
>  	return __memset(addr, c, len);
>  }
>  
> +#ifdef __HAVE_ARCH_MEMMOVE
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> @@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
>  
>  	return __memmove(dest, src, len);
>  }
> +#endif
>  
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
> -- 
> 2.17.0
> 
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
> 


- Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.9999.1911162055490.21209%40viisi.sifive.com.
