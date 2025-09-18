Return-Path: <kasan-dev+bncBD4NDKWHQYDRBN6AWHDAMGQEKGX6F3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EEF18B86B80
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 21:40:48 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-7916b05b94bsf30047626d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 12:40:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758224440; cv=pass;
        d=google.com; s=arc-20240605;
        b=WuVdrWqCYvCEq6NjjWIpctGXAMNNb2GmA7B7Pqsz4EGwvBCoPuULBw09wL/HqWDfWf
         RDpY8OrOJhE3whWbkWNqf9+r0iwN/6U12/PCVFN0E/NL3dNDAH1w4YIspJiA/dFxSPLl
         Jd6K6W2ppQ2vMYxHJme6Wt+pgmKwqgEoNed3q2O52YL+DBcPUOg+9DiOJ6k9bfEq0DyJ
         YLGcDE0wm/2weELzi2QUi0vLq0pvvowQYticFisnP1l9SOjaQizXZ1NFRmYUOgVt5dj5
         9/3bBOt5J8iBXi/JGFgkSbmUXSG+N2FhRRc2feOSDh2/MLUKKlfCosqZWQkb6z8qnPRP
         M/cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=kSvdSYqWWG/ucWlRrXQ+MJ25JGGi03W1yt2P3BnXsPU=;
        fh=a7yHQUAyjJwxsE4Zzv4b9Bgvy+M9jwuCYiU/nXwTsiQ=;
        b=RM0X4hq1WpoCL9vX2gOhTjmZSlwipz7yCY5/IxK66V95PICOuTS/o7kNNLcCF+L0AE
         Y18JPpjUg8Vjjho07AoL6epIm4oF/bYVsh54bYtc9/z8APO6uieyKNN7WUoeZtyxpo7H
         dY5kJAgIc8iC9XD60tFsqjazEHlsoaFLbt/t+CHxgYlom2RXUPTig0xzas37QnoQV6/W
         HunCjU/cVZmMIg9CmFeKz5Slvtkwa0YLJwj3hbL3PdYpWs5K0emIcT/yh/rwb1zOS38z
         Y0Q8enaGEI2b/Y54ne65vQcRkaAoqGiw4hkxZUa+QFYC+Edgz5AiswJok9Lb9+s1D3YN
         UV5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qkCy5zq7;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758224440; x=1758829240; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=kSvdSYqWWG/ucWlRrXQ+MJ25JGGi03W1yt2P3BnXsPU=;
        b=Lfd12JbNNxVenOT/qdonJ6XhIQK/1wuA0EEuYyRys1+LCezN0RFRJBiiJ6lO3N8vN0
         1fbZgbDoXS0IFaP9/bLwNRh+jOyyWTimOf2DP4QyJC7mXzoTAuM6l7ZgG80Sq98pyMhw
         PJqDMuEi6rHNLdVs1Jo7uRIjFD371NzhlpRCKcXfnYkJugw/6/L9RECDK2gtPvxAvBsD
         0Fpfqf5EYX+zbc8PLfxhA+CSs11OSNDw2TwJvWWur3POSGnj2d7To/l3AP1vd/fPYvwH
         R94s/1PjIZeXqHsSXSAX1hRaaeS+Lz2232ile1TlOSGLjuBR6jB5fPyFWlaXec0/M1mk
         9n0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758224440; x=1758829240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kSvdSYqWWG/ucWlRrXQ+MJ25JGGi03W1yt2P3BnXsPU=;
        b=gEcdbyX69R/tvVYQX7mUkUj1SOJmLhPW0bI7HunivgGMfavWlZ7h8K4dMRgFuRGo1r
         FneOFN9iS2CGnYJg195knOP9SvzyLP4Gbuiudqbt8sXV62YNa5e2Wjib4z052qtc9jbc
         PzpPYE84f9CfrjywyKKjKtsKoEvqZm5NeBPVcLRDqLJ4xWoJXRgu8xBqo5nVTJpKxkqx
         tyeviRVd9OKG9xz+zSPdqLKAwcEg2yAj/0xIz3aGu9+mXnS9Z364+3dIL3+Gu59xBnzm
         Le3QGJLFVmFAmdkpbfzyN0P2uFDQ4afgHDfNMOV2Nn8cminkPHMGaM6haeRwyeSZ8QKl
         bogg==
X-Forwarded-Encrypted: i=2; AJvYcCUqErtSSNihpXA+l0/3P42W6xv7wNAa7nEv2jsFPB5Ik/jIChC+vOIMMRk/MgWJUj8y12rojQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx9HvwlKAMzAdRk+rqSVE7WnfJy1IB0aGTHy8rsqBoXYPzxYTA/
	lQaEncBKgGBXk1e6ZdqybZHv2Lu0zQzaovgyPQ5WpDOPiMNXiqWqb12Z
X-Google-Smtp-Source: AGHT+IGsayjh9xj4yCSk5Gs/iZVLFhYGg4xh5ERQJGCKyAbafi+4mzrWbKRphTS6MOgGZxl93CH6YA==
X-Received: by 2002:a05:6214:509e:b0:78f:5265:4923 with SMTP id 6a1803df08f44-7991312bce2mr8456286d6.16.1758224440088;
        Thu, 18 Sep 2025 12:40:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd59zKOiyUAZfIKnTctFg3k01o+kQFTsfmZQYn7knHgLiQ==
Received: by 2002:ad4:5d6c:0:b0:70d:ac70:48d7 with SMTP id 6a1803df08f44-7934bac202cls17390316d6.1.-pod-prod-06-us;
 Thu, 18 Sep 2025 12:40:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+vJkF16TpoZuiPr3n+PjyJC5FZqFexpxvWuDFdCPiFZIcZZrLLJFD5GnDa6DrVkDCc+9HtsP6/Hk=@googlegroups.com
X-Received: by 2002:a05:6122:1819:b0:544:cb0f:a659 with SMTP id 71dfb90a1353d-54a8380efcdmr376696e0c.6.1758224439157;
        Thu, 18 Sep 2025 12:40:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758224439; cv=none;
        d=google.com; s=arc-20240605;
        b=Q+OkN2kXE79U/PiXRZqygN1bjhKJkqNbcCnIEPHExqlUjevcIq3E/fUl3TSk/BjmPJ
         nVzR7+cbyJRXzoX+mpUfbugLuL+/4IQ2OTf/wsqIYnAKIw2A2JMgEq4UggcDAmvR6TJf
         Q1EeEWl/d2lM4cCOpuKvlzmRlF18iRMK5u3PLWW0WVWuvEre+oBljE0KzGb8JnGtO/70
         1dyBq0xZd1pB56Zm55+1Nsxf+AupGIkUzvQhlsRuPCfs7K+PILvDK2yk510GMJbBl1qC
         PXTX95f25txHCNCWxVNEROmR50ZvVLm4y/Dy3cKBh0+ZPmiNaydg78nXdRbzrw05hHR4
         J7+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2vIbbwP7GCvPvb7hRRchVESVHm5MRSjl/DOR9gQmNqY=;
        fh=EZQyiKzrwShLjgJBhvT4NkPajKdgpWMgXK79y+fD56s=;
        b=XN7E9epGjKcju5hdvD3Tbsq7IAmhgjjy98oOXFol8V+vaBlsnKd2quD0DwWor5dg6U
         Du+mnWg5wq3oR28NRQEollp4TnRN3mtnT1w48W+DlxLZhIoKoT5XjkUPvQuoXBlIIIy3
         dPSp7/KEnBMSkERi2t3UjkwSJZPHcreodmPOp9WFcMkowLFaZ86dVp2dLzXQh31O55Kb
         zRG6Wz81HnFtgXzv/YvBOYSeLBIB7DI6oEq/s7uziw838wRw/DKKt/EleUnU6V8DilXT
         9jOY27/3GrEeYawg6fa6tieLefGfU58X/JFkFU5r4fVD0uaxFp1ECbVj0ezwV8cE7D3S
         9JiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qkCy5zq7;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54a77256326si94112e0c.1.2025.09.18.12.40.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Sep 2025 12:40:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id EF1BA434D3;
	Thu, 18 Sep 2025 19:40:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 08B1EC4CEE7;
	Thu, 18 Sep 2025 19:40:28 +0000 (UTC)
Date: Thu, 18 Sep 2025 12:40:26 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
Message-ID: <20250918194026.GA3379805@ax162>
References: <20250918140451.1289454-1-elver@google.com>
 <20250918141511.GA30263@lst.de>
 <20250918174555.GA3366400@ax162>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250918174555.GA3366400@ax162>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qkCy5zq7;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

On Thu, Sep 18, 2025 at 10:45:55AM -0700, Nathan Chancellor wrote:
> On Thu, Sep 18, 2025 at 04:15:11PM +0200, Christoph Hellwig wrote:
> > On Thu, Sep 18, 2025 at 03:59:11PM +0200, Marco Elver wrote:
> > > A Clang version that supports `-Wthread-safety-pointer` and the new
> > > alias-analysis of capability pointers is required (from this version
> > > onwards):
> > > 
> > > 	https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e610c351a3227f36c92a4 [3]
> > 
> > There's no chance to make say x86 pre-built binaries for that available?
> 
> I can use my existing kernel.org LLVM [1] build infrastructure to
> generate prebuilt x86 binaries. Just give me a bit to build and upload
> them. You may not be the only developer or maintainer who may want to
> play with this.

This should include Marco's change, let me know if there are any issues.

https://kernel.org/pub/tools/llvm/files/prerelease/llvm-22.0.0-e19fa930ca838715028c00c234874d1db4f93154-20250918-184558-x86_64.tar.xz

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918194026.GA3379805%40ax162.
