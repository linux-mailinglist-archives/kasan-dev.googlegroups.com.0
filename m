Return-Path: <kasan-dev+bncBCW2HNMCXUPRB2NL6XZAKGQEB4LZW4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 9625F17633C
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 19:52:25 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id t14sf95995wrs.12
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 10:52:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583175145; cv=pass;
        d=google.com; s=arc-20160816;
        b=QvjuiTBUA5wnLaLpNzYcAm6gBo8B7NxublXRVFtgm84ZMwy+/scZSEEyggyjo3onNA
         dxmO/j6Q/KQCJ+BrhwZ8rKUS9k92Ce5XHnV3ng8N/iJMeNitHxfWHZeblxauRnYSKI0T
         /L6miNpvdXNQtdjgXbo4IuYNwZYEogIPxoDHXCfZUi/uTtriQnLLQdjNT4Uw72QhyDNe
         tVJVcIgpISHryI2NUnslZoMpKxyU8vUWxvkT0nmHCmxXwQ/11qZF1+OaZFqngsbe0hs7
         hrj/NKhq+e+5XzinUPToAjB7NSBSUkcukQp1h+4qED4Twn1fqNEyNWUFk6QkrzbOL42r
         3BaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=VzAp4RK7WV7i9noBipZ0VwFxfYaaefYkckVNtoD6GvU=;
        b=EHxrRnoKwf0xAMMEJHnsu0fHhw3PoRKcjKtZUG8ktXTzcibzeXsbuNE8AOVVp7tZQ4
         7FbGk2K3qqOhHp/Vh/vIFjA/4fT/tluofbxEX3u7Hd4nnc9S0L8J7ORp6aAznPyBcEAg
         bJKTYfHFif14ScGjCE91I1ADlh41ZvSV07axVQ/Y6+XhpIdFajMSJa06v91yotOvlbOQ
         Q4IzyRhQvu/vuMmcuTbiHDlNtICDrAAyvL5alfSdi19kZlXwJCzDlEWdVxyt8mtDozQs
         cNaligjabM1qqjV30ZywHfqftbkw82wH8PiiOhXTXiwNTKXsUpBH4hhjJnjUdlIEOR3R
         xYfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=AMAtFQWc;
       spf=pass (google.com: domain of parri.andrea@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=parri.andrea@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VzAp4RK7WV7i9noBipZ0VwFxfYaaefYkckVNtoD6GvU=;
        b=aacWwt2zWw5+cfhnJ1Cq7ILTM8PI++Wv2Ho+j40lLCmDZN8G9n6tHvPp7l17vcAdVH
         faSKJK1KOCrgm4vrballxnHlCzWAVX0uDY0Ei1HJXVzhz+DUIS+9aA7IoCaCmVM6RXzE
         G9KzBW1mIFU6fVAgdUix/pi3eJ54UfjXI+fUvwFcO0jM6eCA/osYndThN8nMw56N33QE
         x+tfzz+bDrLpoRE+eUno/Je+goBj5SMec+An23v3rDDoYsyptj/GxtrrG0a8jT1+wHkY
         TzLZw3d0px70O5k8J4pO5Ti+IKXSd33z4aIZ/ouXcFXxpSgXi521jW8KH0+3aTjBiWFR
         Cmyw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VzAp4RK7WV7i9noBipZ0VwFxfYaaefYkckVNtoD6GvU=;
        b=adMA7Dgn62eNGp9n/sRZ4EwBgOFf6C8YkUULUf9T4umZAuCRtPLHAODPjbQpgbJmXs
         VqM8dLgVO/1MwDFGhywVmXktGbiW8A/BaZqxxkMA07NHZAxxXibTBqT4kigu9CSLipv/
         dbUeXyRaq1Fm1/K9D2We7hFqPdOhRKjSJ/N8VO5FWTzgx8kaLyPX2uBUkdwHs34wJDTL
         0fFdTzxIuVWPtyblrDljOa3e9HxeWWjRCOgMPJvlr0RL3Vra/7Z2J+PGJ/eoxGkl2LgD
         ArPlezCEnNuzDCs1L9fybtmULFfEGYpxocGRBxV6JpD0PmHZJzICMKLAzeJcFhGupkOd
         403w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VzAp4RK7WV7i9noBipZ0VwFxfYaaefYkckVNtoD6GvU=;
        b=doJ55Lo8kIXjbR2U5eGDo8SJzhdAk62Bp7GyXXdcwfYqEnKuuW4uH1aGgQ+DcSYj3U
         fkkUGJX9aPeo3v/aTZlIU/CW+5ZtudXT2GFahRS0DfgyrABnmAXtnBPJcmCp4PV4jGNm
         DHzzawsd1j/Ap03gYN5Yp6ycZqv+2h3HO30n22Nlc0OBxg3Q4SCbXi8bmygjlO7dKwCs
         FLL3XJHteCPPwTzlyCSM+LKQfO2ZV4Ihhwgiaqt6oP5c3lewjdw6ZPKyktkj4fA4Vqum
         FUwyyJEBQRZgQglJ/JSBRJnNqHhBpyInIYV3r169XqUrnefLIqWXPRIFdOAVpHg+d1mK
         tMtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2Xh67ICYjNcriuaJqA5fYSDkH3GLiCXPSq9LDGkfLizXks/cUh
	0bv1udDDNQvarlBQQ13Z8pI=
X-Google-Smtp-Source: ADFU+vsmLNM93y5mDSaCQpKWA0kKhsYaKS7SoxCqFEchDLq+qTQD4WS1x/p435rycPTd4mDaHzNf6A==
X-Received: by 2002:a05:600c:2154:: with SMTP id v20mr367052wml.175.1583175145270;
        Mon, 02 Mar 2020 10:52:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e745:: with SMTP id c5ls67108wrn.4.gmail; Mon, 02 Mar
 2020 10:52:24 -0800 (PST)
X-Received: by 2002:adf:ff84:: with SMTP id j4mr941170wrr.426.1583175144550;
        Mon, 02 Mar 2020 10:52:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583175144; cv=none;
        d=google.com; s=arc-20160816;
        b=xWwk2dTJ3STlh24mLyAWx4ibSDs3RVjccbH0PJSbsWREpIe8Gnq0nOdZC46VTVIv9e
         Xv+8ygKyoRU43NhY9UFwak4SQnNWwc6/TvMKHQRVHLF46VkTKXH/WL9urw6WFsjpvVrC
         vgAl2jlhAVK52JWIIfgRzl03oQeyYeol61thfBYf+qZfGLMdcnXDGwt79KqlT0PUCEIX
         Ra2W0Cb1co/qMRu4PCismbzGqg84ZydIuThVJOWCbwn5uZR15C+Txo5rx2cu0qooL7Um
         BO8BHTyjbJsPe/0RtAXMtgyT08f/ELR8MNAWsjaNhlQuajrCTSFZoeoK0R+NgU+K+8vO
         S3dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=N+92nMqwyvyqnvBWahI9x0clg05C+2OnWX3BXzruqvI=;
        b=ZGmt7JoRR/bizruHnhr9DbHNvjrZkjKsgSrZDQ19N1bwKT56XGn0Eko91IGkkKBdSc
         FT3bmw6Q04YluK0ZUAe5ZMAlBdtZ9QBJQLbd3EKLwt5B4VsdVblAzrWW2QeXhQdj2CTb
         BERbtNERonoxbqEFPYofOoXscMcfCodT07wjP495+o1KuEo6COUJb4W9XF2Qg39UK+Vi
         tGsOp/eQEv5Pt9NnX36NNq3Se1gHySk1MyMj5PRuK4cptfmYUJFJ/spukfz8BD+UQh+s
         VrIoOq0NHyokwu9hNaJA4yEznvYpJgYCglMvLz5jE1HyNpvYiqlGVp+4y8Op69nqfUSI
         Kf6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=AMAtFQWc;
       spf=pass (google.com: domain of parri.andrea@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=parri.andrea@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id o194si16977wme.2.2020.03.02.10.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 10:52:24 -0800 (PST)
Received-SPF: pass (google.com: domain of parri.andrea@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id a132so206253wme.1
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 10:52:24 -0800 (PST)
X-Received: by 2002:a1c:e108:: with SMTP id y8mr220600wmg.147.1583175143890;
        Mon, 02 Mar 2020 10:52:23 -0800 (PST)
Received: from andrea (ip-213-220-200-127.net.upcbroadband.cz. [213.220.200.127])
        by smtp.gmail.com with ESMTPSA id t187sm474548wmt.25.2020.03.02.10.52.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2020 10:52:22 -0800 (PST)
Date: Mon, 2 Mar 2020 19:52:16 +0100
From: Andrea Parri <parri.andrea@gmail.com>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	stern@rowland.harvard.edu, will@kernel.org, peterz@infradead.org,
	boqun.feng@gmail.com, npiggin@gmail.com, dhowells@redhat.com,
	j.alglave@ucl.ac.uk, luc.maranget@inria.fr, paulmck@kernel.org,
	akiyks@gmail.com, dlustig@nvidia.com, joel@joelfernandes.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH v3] tools/memory-model/Documentation: Fix "conflict"
 definition
Message-ID: <20200302185216.GA5320@andrea>
References: <20200302172101.157917-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200302172101.157917-1-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: parri.andrea@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=AMAtFQWc;       spf=pass
 (google.com: domain of parri.andrea@gmail.com designates 2a00:1450:4864:20::342
 as permitted sender) smtp.mailfrom=parri.andrea@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Mar 02, 2020 at 06:21:01PM +0100, Marco Elver wrote:
> The definition of "conflict" should not include the type of access nor
> whether the accesses are concurrent or not, which this patch addresses.
> The definition of "data race" remains unchanged.
> 
> The definition of "conflict" as we know it and is cited by various
> papers on memory consistency models appeared in [1]: "Two accesses to
> the same variable conflict if at least one is a write; two operations
> conflict if they execute conflicting accesses."
> 
> The LKMM as well as the C11 memory model are adaptations of
> data-race-free, which are based on the work in [2]. Necessarily, we need
> both conflicting data operations (plain) and synchronization operations
> (marked). For example, C11's definition is based on [3], which defines a
> "data race" as: "Two memory operations conflict if they access the same
> memory location, and at least one of them is a store, atomic store, or
> atomic read-modify-write operation. In a sequentially consistent
> execution, two memory operations from different threads form a type 1
> data race if they conflict, at least one of them is a data operation,
> and they are adjacent in <T (i.e., they may be executed concurrently)."
> 
> [1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
>     Programs that Share Memory", 1988.
> 	URL: http://snir.cs.illinois.edu/listed/J21.pdf
> 
> [2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
>     Multiprocessors", 1993.
> 	URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf
> 
> [3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
>     Model", 2008.
> 	URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Co-developed-by: Alan Stern <stern@rowland.harvard.edu>
> Signed-off-by: Alan Stern <stern@rowland.harvard.edu>

LGTM:

Acked-by: Andrea Parri <parri.andrea@gmail.com>

Thank you both,

  Andrea


> ---
> v3:
> * Apply Alan's suggestion.
> * s/two race candidates/race candidates/
> 
> v2: http://lkml.kernel.org/r/20200302141819.40270-1-elver@google.com
> * Apply Alan's suggested version.
>   - Move "from different CPUs (or threads)" from "conflict" to "data
>     race" definition. Update "race candidate" accordingly.
> * Add citations to commit message.
> 
> v1: http://lkml.kernel.org/r/20200228164621.87523-1-elver@google.com
> ---
>  .../Documentation/explanation.txt             | 83 ++++++++++---------
>  1 file changed, 45 insertions(+), 38 deletions(-)
> 
> diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
> index e91a2eb19592a..993f800659c6a 100644
> --- a/tools/memory-model/Documentation/explanation.txt
> +++ b/tools/memory-model/Documentation/explanation.txt
> @@ -1987,28 +1987,36 @@ outcome undefined.
>  
>  In technical terms, the compiler is allowed to assume that when the
>  program executes, there will not be any data races.  A "data race"
> -occurs when two conflicting memory accesses execute concurrently;
> -two memory accesses "conflict" if:
> +occurs when there are two memory accesses such that:
>  
> -	they access the same location,
> +1.	they access the same location,
>  
> -	they occur on different CPUs (or in different threads on the
> -	same CPU),
> +2.	at least one of them is a store,
>  
> -	at least one of them is a plain access,
> +3.	at least one of them is plain,
>  
> -	and at least one of them is a store.
> +4.	they occur on different CPUs (or in different threads on the
> +	same CPU), and
>  
> -The LKMM tries to determine whether a program contains two conflicting
> -accesses which may execute concurrently; if it does then the LKMM says
> -there is a potential data race and makes no predictions about the
> -program's outcome.
> +5.	they execute concurrently.
>  
> -Determining whether two accesses conflict is easy; you can see that
> -all the concepts involved in the definition above are already part of
> -the memory model.  The hard part is telling whether they may execute
> -concurrently.  The LKMM takes a conservative attitude, assuming that
> -accesses may be concurrent unless it can prove they cannot.
> +In the literature, two accesses are said to "conflict" if they satisfy
> +1 and 2 above.  We'll go a little farther and say that two accesses
> +are "race candidates" if they satisfy 1 - 4.  Thus, whether or not two
> +race candidates actually do race in a given execution depends on
> +whether they are concurrent.
> +
> +The LKMM tries to determine whether a program contains race candidates
> +which may execute concurrently; if it does then the LKMM says there is
> +a potential data race and makes no predictions about the program's
> +outcome.
> +
> +Determining whether two accesses are race candidates is easy; you can
> +see that all the concepts involved in the definition above are already
> +part of the memory model.  The hard part is telling whether they may
> +execute concurrently.  The LKMM takes a conservative attitude,
> +assuming that accesses may be concurrent unless it can prove they
> +are not.
>  
>  If two memory accesses aren't concurrent then one must execute before
>  the other.  Therefore the LKMM decides two accesses aren't concurrent
> @@ -2171,8 +2179,8 @@ again, now using plain accesses for buf:
>  	}
>  
>  This program does not contain a data race.  Although the U and V
> -accesses conflict, the LKMM can prove they are not concurrent as
> -follows:
> +accesses are race candidates, the LKMM can prove they are not
> +concurrent as follows:
>  
>  	The smp_wmb() fence in P0 is both a compiler barrier and a
>  	cumul-fence.  It guarantees that no matter what hash of
> @@ -2326,12 +2334,11 @@ could now perform the load of x before the load of ptr (there might be
>  a control dependency but no address dependency at the machine level).
>  
>  Finally, it turns out there is a situation in which a plain write does
> -not need to be w-post-bounded: when it is separated from the
> -conflicting access by a fence.  At first glance this may seem
> -impossible.  After all, to be conflicting the second access has to be
> -on a different CPU from the first, and fences don't link events on
> -different CPUs.  Well, normal fences don't -- but rcu-fence can!
> -Here's an example:
> +not need to be w-post-bounded: when it is separated from the other
> +race-candidate access by a fence.  At first glance this may seem
> +impossible.  After all, to be race candidates the two accesses must
> +be on different CPUs, and fences don't link events on different CPUs.
> +Well, normal fences don't -- but rcu-fence can!  Here's an example:
>  
>  	int x, y;
>  
> @@ -2367,7 +2374,7 @@ concurrent and there is no race, even though P1's plain store to y
>  isn't w-post-bounded by any marked accesses.
>  
>  Putting all this material together yields the following picture.  For
> -two conflicting stores W and W', where W ->co W', the LKMM says the
> +race-candidate stores W and W', where W ->co W', the LKMM says the
>  stores don't race if W can be linked to W' by a
>  
>  	w-post-bounded ; vis ; w-pre-bounded
> @@ -2380,8 +2387,8 @@ sequence, and if W' is plain then they also have to be linked by a
>  
>  	w-post-bounded ; vis ; r-pre-bounded
>  
> -sequence.  For a conflicting load R and store W, the LKMM says the two
> -accesses don't race if R can be linked to W by an
> +sequence.  For race-candidate load R and store W, the LKMM says the
> +two accesses don't race if R can be linked to W by an
>  
>  	r-post-bounded ; xb* ; w-pre-bounded
>  
> @@ -2413,20 +2420,20 @@ is, the rules governing the memory subsystem's choice of a store to
>  satisfy a load request and its determination of where a store will
>  fall in the coherence order):
>  
> -	If R and W conflict and it is possible to link R to W by one
> -	of the xb* sequences listed above, then W ->rfe R is not
> -	allowed (i.e., a load cannot read from a store that it
> +	If R and W are race candidates and it is possible to link R to
> +	W by one of the xb* sequences listed above, then W ->rfe R is
> +	not allowed (i.e., a load cannot read from a store that it
>  	executes before, even if one or both is plain).
>  
> -	If W and R conflict and it is possible to link W to R by one
> -	of the vis sequences listed above, then R ->fre W is not
> -	allowed (i.e., if a store is visible to a load then the load
> -	must read from that store or one coherence-after it).
> +	If W and R are race candidates and it is possible to link W to
> +	R by one of the vis sequences listed above, then R ->fre W is
> +	not allowed (i.e., if a store is visible to a load then the
> +	load must read from that store or one coherence-after it).
>  
> -	If W and W' conflict and it is possible to link W to W' by one
> -	of the vis sequences listed above, then W' ->co W is not
> -	allowed (i.e., if one store is visible to a second then the
> -	second must come after the first in the coherence order).
> +	If W and W' are race candidates and it is possible to link W
> +	to W' by one of the vis sequences listed above, then W' ->co W
> +	is not allowed (i.e., if one store is visible to a second then
> +	the second must come after the first in the coherence order).
>  
>  This is the extent to which the LKMM deals with plain accesses.
>  Perhaps it could say more (for example, plain accesses might
> -- 
> 2.25.0.265.gbab2e86ba0-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200302185216.GA5320%40andrea.
