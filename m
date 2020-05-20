Return-Path: <kasan-dev+bncBCG6FGHT7ALRBBHCST3AKGQEP22UCNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D31061DB506
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 15:30:44 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id c22sf607084lji.19
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 06:30:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589981444; cv=pass;
        d=google.com; s=arc-20160816;
        b=GoPmxH7yOFHf9xRLPOH5xhgYRK3HDVYm4ff2GIm3NSIUc8iTu8RICm8qaM0R7K3Zor
         +CRjb7n4877/lOvvrSaDctwO0ozFo061M8vhc/YTsOBOw/N/QFPwosrMi4fBclhlSLLG
         G18ZvErv9reZSiuSUWhEWvK+MTsrO8hOKaxf2y60k/Ykhrpm8Ihr3gRi2gjQrMoy9P3x
         o6Fo5UHGreMq0m3ar33AQSnqlC0ZbeF+CMTqc8zaBvjmPj6u5+DKz7EVk/WtjgHPqJA2
         R9QpragTkIAM6NbfNdlgzuFZ9k9CGoWZktvZMmO3M3hmDaNVZuLxlltGBE4gkMXcEmUD
         JPJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=P5kp16c51bjyvqK/CsdqsyFALC1J2Lw3EWrcLwJxma0=;
        b=VueoJhniaiYHtRG7aZZx6kqtlU9izcS0OgNAC5dwJ6wn/YyuAAbooXXmlXbN4y/tJR
         PVU1ga2xmcvgAVGGucXc9yYBkcZImKTvCUxnDPlWL0Nv7kOY/gaDoRG9esKEewDap/cg
         xqNiGEFntzeF1CNaVa2kmVWqh3B/i0jgTL2QaBdMfxWho3Ef7ykwLd3QdUwOflyorTWN
         4i5sTHJ4Ly0KazkYTVU+S4I1Cx2cOKdDAwzltgm7liOoczNPH4i1uWfteNekEFdq9bbW
         2vlcqgXAAaTJAqntootPtsF6De5NflhGOesuz2/mqYCQkh74Au5PUxHH7xFYGjGSi5/7
         /DQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=P5kp16c51bjyvqK/CsdqsyFALC1J2Lw3EWrcLwJxma0=;
        b=hqANdn53CgBzTXt90ym9Iyu/BNGDiCrMre9DtWkHChMbEhMgSnhN6p2SeFxyYkZGJr
         0V5aAFYxfma8dSC3O2M7U4uW7mJ6fSzTQOPjSi7bVOElVceKwi4uzf1aeg4Pg4PHMRdy
         2hnVAQLltWDvA9zaCN2uZhLl4JSOjelZ3Ot5RvWL8HepCkQavRqXju+Mq994aexM+sxU
         qxdxSWz+LqVDil2O0RHUfBD7OfY3gB4FrKxPcYNDvTUoDZ9IfomsZNr0BD6vtQi92Ji3
         TrPWkn2vpq4A3oQDIRxKMpdD+8Q6SvMtCEYU01Q3zhjiED853PQmfi5QwCJf48usJCTE
         PqkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=P5kp16c51bjyvqK/CsdqsyFALC1J2Lw3EWrcLwJxma0=;
        b=RqG5gLsqOw6gwQB8s0s1tzBhUfgz0kT8vmhPLXhnFzbloCdcLHrJoXd585fkWTqMGt
         ATOK1Rq292p1TbgPTay7Beh+A3TOTqi76kkdU2ui/KIubBs2/R0eS4veZ0j/kKTGDrK1
         YtOSSTvDGZGhBvN6Z6c316IzMp2FLkE0FKFtdB5Kux1Yc+Khi6IicCW1BIEoRH1wX+Mc
         kzi4kmqH1JsvLIU2hNj0ZazHV2rsF44uD1t7zHEJo1pyOzsZP/Z4/GpicrT0Gfq7j8A6
         qVs2V2p7r/W6X344Uh0KIiizSOrgpWiPQzIyJR2VkoPRCGA/CSSZn333cHDopjnsfhjE
         wc4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dH9swoGm+NgXAdyPFbnpqhqMAgER75OAy4cPV+kSkUBJFlen1
	33qjLtMJDmTixS1YCz9+jbI=
X-Google-Smtp-Source: ABdhPJzyLTk6fSgSdcKxRV3mahI4NXJfpW57hdDBQVze05Je3Z3LTn9ZQ3PmWyZ/wcNMT/KJnSpteA==
X-Received: by 2002:a05:651c:3c6:: with SMTP id f6mr2735962ljp.138.1589981444168;
        Wed, 20 May 2020 06:30:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9194:: with SMTP id f20ls631462ljg.10.gmail; Wed, 20 May
 2020 06:30:43 -0700 (PDT)
X-Received: by 2002:a05:651c:1199:: with SMTP id w25mr2722130ljo.69.1589981443492;
        Wed, 20 May 2020 06:30:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589981443; cv=none;
        d=google.com; s=arc-20160816;
        b=RDtOJENYhcO0uCYOREnS1b0eIROc3O2MR/bO1RMQh0ErznGFy+eCieNN2PstY4d/VS
         8Vfcfa9+/16BspnlO+ttCLCEmwe+i3MIT0ri+X0d9qUAjw5X0hxIKvy14lBrUd2IlQc1
         82GHKMn/W3ZwTG9shZEaYoWZhIeR+xay/8Y39gX69bkZoaULGgfA5Z35rsMh0CeTceTu
         QXPDIpn0vncKjPvJhcQstdRylnpGg1aQBu8msSt1ZLjp6pojXV0jZ8CTMoI2BZKDnxyx
         a3bXbFj8ZzpPX2i0SGyLq11HaciPMN1NTav8vubSzMfU1ncbcBxU/e/SH1mY76VUmuPX
         loUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=y/sZqZaTdSTJRgZYfpnN2Q6Sgk+pWJIg/L6vKkhlQB4=;
        b=dRbHoxm/7hThAlRyaxwQXVrw8pfxgsfYMJX7JZMBDUYEvf/9AUBr6zSUTBCw2D+tyw
         /b2k04pz3iGRt2mFidd2IqMBwCKq+cofP0HyHnqS2mUq1FrBXH1E+zlC7jSvf5IPtJwc
         tOKkMjSjdjjhuF1d5jGtkou2Nj9dXa569vRIe6p1JYdkBxmTABJwCCV/EyyL29M+CVH5
         jxereAcR2mx5ryo9isK6PsALudP1FW/pBgNuxqd2BUwmE2CmvcNpeYwLjI6WIxx5078P
         y6JSsNytWa6yinWyA1Ekl+9Bnv3za9dN0Zb7hg1dBubG9xNiFCFmCt938mNM+sLZVIcV
         GXiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id e7si142686ljo.2.2020.05.20.06.30.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 May 2020 06:30:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 000E9AC7B;
	Wed, 20 May 2020 13:30:44 +0000 (UTC)
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: Marco Elver <elver@google.com>, gcc-patches@gcc.gnu.org, jakub@redhat.com
Cc: kasan-dev@googlegroups.com
References: <20200423154250.10973-1-elver@google.com>
From: =?UTF-8?Q?Martin_Li=c5=a1ka?= <mliska@suse.cz>
Message-ID: <0e79d50f-163d-0878-709b-4d5ab06ff8eb@suse.cz>
Date: Wed, 20 May 2020 15:30:41 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
In-Reply-To: <20200423154250.10973-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: mliska@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=mliska@suse.cz
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

On 4/23/20 5:42 PM, Marco Elver via Gcc-patches wrote:

Hello.

Not being a maintainer of libsanitizer but I can provide a feedback:

> Add support to optionally emit different instrumentation for accesses to
> volatile variables. While the default TSAN runtime likely will never
> require this feature, other runtimes for different environments that
> have subtly different memory models or assumptions may require
> distinguishing volatiles.
> 
> One such environment are OS kernels, where volatile is still used in
> various places for various reasons, and often declare volatile to be
> "safe enough" even in multi-threaded contexts. One such example is the
> Linux kernel, which implements various synchronization primitives using
> volatile (READ_ONCE(), WRITE_ONCE()). Here the Kernel Concurrency
> Sanitizer (KCSAN) [1], is a runtime that uses TSAN instrumentation but
> otherwise implements a very different approach to race detection from
> TSAN.
> 
> While in the Linux kernel it is generally discouraged to use volatiles
> explicitly, the topic will likely come up again, and we will eventually
> need to distinguish volatile accesses [2]. The other use-case is
> ignoring data races on specially marked variables in the kernel, for
> example bit-flags (here we may hide 'volatile' behind a different name
> such as 'no_data_race').

Do you have a follow up patch that will introduce such an attribute? Does clang
already have the attribute?

> 
> [1] https://github.com/google/ktsan/wiki/KCSAN
> [2] https://lkml.kernel.org/r/CANpmjNOfXNE-Zh3MNP=-gmnhvKbsfUfTtWkyg_=VqTxS4nnptQ@mail.gmail.com
> 
> 2020-04-23  Marco Elver  <elver@google.com>
> 
> gcc/
> 	* params.opt: Define --param=tsan-distinguish-volatile=[0,1].
> 	* sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
> 	builtin for volatile instrumentation of reads/writes.
> 	(BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
> 	* tsan.c (get_memory_access_decl): Argument if access is
> 	volatile. If param tsan-distinguish-volatile is non-zero, and
> 	access if volatile, return volatile instrumentation decl.
> 	(instrument_expr): Check if access is volatile.
> 
> gcc/testsuite/
> 	* c-c++-common/tsan/volatile.c: New test.
> ---
>   gcc/ChangeLog                              | 19 +++++++
>   gcc/params.opt                             |  4 ++
>   gcc/sanitizer.def                          | 21 ++++++++
>   gcc/testsuite/ChangeLog                    |  4 ++
>   gcc/testsuite/c-c++-common/tsan/volatile.c | 62 ++++++++++++++++++++++
>   gcc/tsan.c                                 | 53 ++++++++++++------
>   6 files changed, 146 insertions(+), 17 deletions(-)
>   create mode 100644 gcc/testsuite/c-c++-common/tsan/volatile.c
> 
> diff --git a/gcc/ChangeLog b/gcc/ChangeLog
> index 5f299e463db..aa2bb98ae05 100644
> --- a/gcc/ChangeLog
> +++ b/gcc/ChangeLog
> @@ -1,3 +1,22 @@
> +2020-04-23  Marco Elver  <elver@google.com>
> +
> +	* params.opt: Define --param=tsan-distinguish-volatile=[0,1].
> +	* sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
> +	builtin for volatile instrumentation of reads/writes.
> +	(BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
> +	(BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
> +	(BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
> +	(BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
> +	(BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
> +	(BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
> +	(BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
> +	(BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
> +	(BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
> +	* tsan.c (get_memory_access_decl): Argument if access is
> +	volatile. If param tsan-distinguish-volatile is non-zero, and
> +	access if volatile, return volatile instrumentation decl.
> +	(instrument_expr): Check if access is volatile.
> +
>   2020-04-23  Srinath Parvathaneni  <srinath.parvathaneni@arm.com>
>   
>   	* config/arm/arm_mve.h (__arm_vbicq_n_u16): Modify function parameter's
> diff --git a/gcc/params.opt b/gcc/params.opt
> index 4aec480798b..9b564bb046c 100644
> --- a/gcc/params.opt
> +++ b/gcc/params.opt
> @@ -908,6 +908,10 @@ Stop reverse growth if the reverse probability of best edge is less than this th
>   Common Joined UInteger Var(param_tree_reassoc_width) Param Optimization
>   Set the maximum number of instructions executed in parallel in reassociated tree.  If 0, use the target dependent heuristic.
>   
> +-param=tsan-distinguish-volatile=
> +Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRange(0, 1) Param
> +Emit special instrumentation for accesses to volatiles.

You want to add 'Optimization' keyword as the parameter can be different
per-TU (in LTO mode).

> +
>   -param=uninit-control-dep-attempts=
>   Common Joined UInteger Var(param_uninit_control_dep_attempts) Init(1000) IntegerRange(1, 65536) Param Optimization
>   Maximum number of nested calls to search for control dependencies during uninitialized variable analysis.
> diff --git a/gcc/sanitizer.def b/gcc/sanitizer.def
> index 11eb6467eba..a32715ddb92 100644
> --- a/gcc/sanitizer.def
> +++ b/gcc/sanitizer.def
> @@ -214,6 +214,27 @@ DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_READ_RANGE, "__tsan_read_range",
>   DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_WRITE_RANGE, "__tsan_write_range",
>   		      BT_FN_VOID_PTR_PTRMODE, ATTR_NOTHROW_LEAF_LIST)
>   
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ1, "__tsan_volatile_read1",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ2, "__tsan_volatile_read2",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ4, "__tsan_volatile_read4",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ8, "__tsan_volatile_read8",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ16, "__tsan_volatile_read16",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE1, "__tsan_volatile_write1",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE2, "__tsan_volatile_write2",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE4, "__tsan_volatile_write4",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE8, "__tsan_volatile_write8",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile_write16",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +
>   DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_ATOMIC8_LOAD,
>   		      "__tsan_atomic8_load",
>   		      BT_FN_I1_CONST_VPTR_INT, ATTR_NOTHROW_LEAF_LIST)
> diff --git a/gcc/testsuite/ChangeLog b/gcc/testsuite/ChangeLog
> index 245c1512c76..f1d3e236b86 100644
> --- a/gcc/testsuite/ChangeLog
> +++ b/gcc/testsuite/ChangeLog
> @@ -1,3 +1,7 @@
> +2020-04-23  Marco Elver  <elver@google.com>
> +
> +	* c-c++-common/tsan/volatile.c: New test.
> +
>   2020-04-23  Jakub Jelinek  <jakub@redhat.com>
>   
>   	PR target/94707
> diff --git a/gcc/testsuite/c-c++-common/tsan/volatile.c b/gcc/testsuite/c-c++-common/tsan/volatile.c
> new file mode 100644
> index 00000000000..d51d1e3ce8d
> --- /dev/null
> +++ b/gcc/testsuite/c-c++-common/tsan/volatile.c

Can you please add a run-time test-case that will check gd-output for TSAN
error messages?

> @@ -0,0 +1,62 @@
> +/* { dg-additional-options "--param=tsan-distinguish-volatile=1" } */
> +
> +#include <assert.h>
> +#include <stdint.h>
> +#include <stdio.h>
> +
> +int32_t Global4;
> +volatile int32_t VolatileGlobal4;
> +volatile int64_t VolatileGlobal8;
> +
> +static int nvolatile_reads;
> +static int nvolatile_writes;
> +
> +#ifdef __cplusplus
> +extern "C" {
> +#endif
> +
> +__attribute__((no_sanitize_thread))
> +void __tsan_volatile_read4(void *addr) {
> +  assert(addr == &VolatileGlobal4);
> +  nvolatile_reads++;
> +}
> +__attribute__((no_sanitize_thread))
> +void __tsan_volatile_write4(void *addr) {
> +  assert(addr == &VolatileGlobal4);
> +  nvolatile_writes++;
> +}
> +__attribute__((no_sanitize_thread))
> +void __tsan_volatile_read8(void *addr) {
> +  assert(addr == &VolatileGlobal8);
> +  nvolatile_reads++;
> +}
> +__attribute__((no_sanitize_thread))
> +void __tsan_volatile_write8(void *addr) {
> +  assert(addr == &VolatileGlobal8);
> +  nvolatile_writes++;
> +}
> +
> +#ifdef __cplusplus
> +}
> +#endif
> +
> +__attribute__((no_sanitize_thread))
> +static void check() {
> +  assert(nvolatile_reads == 4);
> +  assert(nvolatile_writes == 4);
> +}
> +
> +int main() {
> +  Global4 = 1;
> +
> +  VolatileGlobal4 = 1;
> +  Global4 = VolatileGlobal4;
> +  VolatileGlobal4 = 1 + VolatileGlobal4;
> +
> +  VolatileGlobal8 = 1;
> +  Global4 = (int32_t)VolatileGlobal8;
> +  VolatileGlobal8 = 1 + VolatileGlobal8;
> +
> +  check();
> +  return 0;
> +}
> diff --git a/gcc/tsan.c b/gcc/tsan.c
> index 8d22a776377..04e92559584 100644
> --- a/gcc/tsan.c
> +++ b/gcc/tsan.c
> @@ -52,25 +52,41 @@ along with GCC; see the file COPYING3.  If not see
>      void __tsan_read/writeX (void *addr);  */
>   
>   static tree
> -get_memory_access_decl (bool is_write, unsigned size)
> +get_memory_access_decl (bool is_write, unsigned size, bool volatilep)
>   {
>     enum built_in_function fcode;
>   
> -  if (size <= 1)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE1
> -		     : BUILT_IN_TSAN_READ1;
> -  else if (size <= 3)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE2
> -		     : BUILT_IN_TSAN_READ2;
> -  else if (size <= 7)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE4
> -		     : BUILT_IN_TSAN_READ4;
> -  else if (size <= 15)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE8
> -		     : BUILT_IN_TSAN_READ8;
> +  if (param_tsan_distinguish_volatile && volatilep)
> +    {
> +      if (size <= 1)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE1
> +            : BUILT_IN_TSAN_VOLATILE_READ1;
> +      else if (size <= 3)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE2
> +            : BUILT_IN_TSAN_VOLATILE_READ2;
> +      else if (size <= 7)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE4
> +            : BUILT_IN_TSAN_VOLATILE_READ4;
> +      else if (size <= 15)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE8
> +            : BUILT_IN_TSAN_VOLATILE_READ8;
> +      else
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE16
> +            : BUILT_IN_TSAN_VOLATILE_READ16;
> +    }
>     else
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE16
> -		     : BUILT_IN_TSAN_READ16;
> +    {
> +      if (size <= 1)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE1 : BUILT_IN_TSAN_READ1;
> +      else if (size <= 3)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE2 : BUILT_IN_TSAN_READ2;
> +      else if (size <= 7)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE4 : BUILT_IN_TSAN_READ4;
> +      else if (size <= 15)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE8 : BUILT_IN_TSAN_READ8;
> +      else
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE16 : BUILT_IN_TSAN_READ16;
> +    }
>   
>     return builtin_decl_implicit (fcode);
>   }
> @@ -204,8 +220,11 @@ instrument_expr (gimple_stmt_iterator gsi, tree expr, bool is_write)
>         g = gimple_build_call (builtin_decl, 2, expr_ptr, size_int (size));
>       }
>     else if (rhs == NULL)
> -    g = gimple_build_call (get_memory_access_decl (is_write, size),
> -			   1, expr_ptr);
> +    {
> +      builtin_decl = get_memory_access_decl (is_write, size,
> +                                             TREE_THIS_VOLATILE(expr));
> +      g = gimple_build_call (builtin_decl, 1, expr_ptr);
> +    }
>     else
>       {
>         builtin_decl = builtin_decl_implicit (BUILT_IN_TSAN_VPTR_UPDATE);
> 

And please check coding style, 8 spares are not expanded with a tab.

Martin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e79d50f-163d-0878-709b-4d5ab06ff8eb%40suse.cz.
