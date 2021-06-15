Return-Path: <kasan-dev+bncBCTJ7DM3WQOBBUNNUSDAMGQETOVLCGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EA1E3A8AAA
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 23:08:34 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 76-20020a190c4f0000b02902e8d879d2f2sf107232lfm.19
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 14:08:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623791313; cv=pass;
        d=google.com; s=arc-20160816;
        b=sqXGa5KSjuqFHRh19F/fZ0TNhWhmlPCW6U2TZzi6lE75z77VC/lSrBQcHA0bWQRwDY
         5RH1IhASvi2QicNeSh4sqKNPtI8Rjqo38QjieqGrlWyTkmlwbox5JNXFnPiHaK9O0m9h
         XIXTeHcWyRTjbiqtVUIn7pOy+A6aF18fLBJpE6ITTIct/LKIDE0ixcjG6F6GcWuQUbkX
         W4gWBSh2JNgT4WIeF+Klp8BRKEujYDvo0K7m1FJzj2ZBm9OXy0KHRchf00OA47MdTczL
         RGidesSSH6np4n+h0M1a075BNitKLV2+DROJvdXq/xrbqQLcw+nIU13xMLkjbX3cDr4c
         YC9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=jmDKARBlMCf/d1LD9oXVcDZEFLqABd6SeuJYYskHcnU=;
        b=U6a1BObyiDzq16lojNM4OspAFw7/A62KWTTiGqlP3kPYErkidd8d3A+vT8+L0m9E6t
         5h51iuWAfJu61Zc6ZZKiPXuAFO6ACypVzAndgF5rtyXQjDAutzYQ5ERx4/aSIQYqZDet
         YbMRKI7XT4JVc6dGHdG8gZ9SztElDktRW3Qi8SYLzOp/29bkeiwHAYViE/3lYN7MIzhs
         mgBtnLzn7vGA4J6d+Ev16eohi00iiosNxlIwNeMH/b3zgniWHdGzgPflcUq3ILQt592I
         u2j9eRmBkhsT/RlVzzKtEGOo8hE0AkfPddYrnBma8okrEN16flhO6KK6C+nGpcM8uTT/
         whWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jmDKARBlMCf/d1LD9oXVcDZEFLqABd6SeuJYYskHcnU=;
        b=jPZVZiAK5KqsaUm3kPlidkI9FcJ94Vmfmr8h2jqlcSg6qkHt5OjLqah7AMojs0Digj
         9CQi0jgmZjZ3Fv+zbmZMN7Jgp22wHpVC7cOpIurqkc2ItzoOIzPa/50CvqMpV9DBt6JU
         f/aqQGHjDmtRQdl4HQKpugGDp1LVqjNopfpi+yWQW3f/0HBQ+igYZFrHuDIvwpgweqBT
         r3C5YZAZVyFKD5sYJNY89cQ7ln839QUUg+12nvK5GwupTZGdI7KvWVL/y+PfDQ0f5gLZ
         /lStxHR7hMS2opZp9HYklqFAyoIwbH6zkYSMJsidks6zfNnqaZoLfO4UPdtikH9m7m3d
         PZjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jmDKARBlMCf/d1LD9oXVcDZEFLqABd6SeuJYYskHcnU=;
        b=cFt2r92DOFyYgJ8b07B9bKa4Q8dc1Vs3FuINoC4pf8c5VD0PZg0q2g+YiyAMoonaxQ
         JAGmDeT2Z8nA/u84GyWvqS2zjCGyQlbHYLknltnNkoV0zsZJrENyqkNlkOEmMYVaZxUx
         Rqv0YEqbImkSLxkfVoZiPrt0J/NHUlzcZwkIR9tACPnTo3oNFTcCoebeQXj4jLHHdyzI
         /rglYAufj9YBe4LnyazlmMD4PgXtdcsS0n6ZhSyrxcbl9osQjEfZAibd6rQ25kubvQeQ
         xDPpZKiGavTSwBIfO8Y5OPeSR0F0kutdqx720yHz3e3dQ28XdcF2MIaGPycKz7sR3gxe
         8ubw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334Ms6I3NJNmZLBh81ZZECAT5Q5e49x4aCBpr/CGr5/UCW1j+0n
	a4tVYXQoDDbMMQH8EDISY8o=
X-Google-Smtp-Source: ABdhPJwdUqJm/8Caz6PoIJb23cOM2T+1sq3m4DkI/xirGtahXckAKAH0iYtcjZQnxpvj07EmdSoo4Q==
X-Received: by 2002:ac2:4c2c:: with SMTP id u12mr904880lfq.209.1623791313749;
        Tue, 15 Jun 2021 14:08:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e50:: with SMTP id g16ls37261ljk.6.gmail; Tue, 15 Jun
 2021 14:08:32 -0700 (PDT)
X-Received: by 2002:a2e:8590:: with SMTP id b16mr1398974lji.342.1623791312616;
        Tue, 15 Jun 2021 14:08:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623791312; cv=none;
        d=google.com; s=arc-20160816;
        b=ZDKnzVQ8yRvdlMV25S228j5z4aDPK/k7LdBwOZMzXBUrrK6lmy9/ypIdD9D2Y7t+iS
         fq1v/lFribxj0Hdi+mKH0bnxLT+eNbm5dKTJyPqhKMaTtYvJzKV6GVyqULz5Ku1Y9iFr
         9YsQpBgUJ7evn2ymdOqVxkr97prYuhwmdNqT8wcUFq4BBroxKYGRHY480fGwrxYvxhVC
         nBvCpdDN/DYW8l+ttGyy4Q7oeuuDE1ktXhi+GAlSSt+X11+8Fx5zjxF7lS5ufJjHFNCF
         npHcRWYzWrkk+VMvGK2Cye+jo/7902TKXJwPWm9HzxIXeZepX5kccRMRPOekJzK2vQc9
         bfkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=xcUQq6kY0EaFg9vgo4O40iAPqg3rLd7W0goI4tZ7Juw=;
        b=c0Y6TNHQzqeTMXpcHG13Guozl4cLEF2u+Qc5VWsDI4GS33o8U6CghYkrPd0CITTQMU
         yzZsIfS+sKKaBUphj+XcJRkbchZOGpfUNPAQbcu7sakzCiz6PxdX9DjSPFZemsDeqUlh
         N1D5x4FkdemUb3TujHVkmt1m0KpgQg6ywKyn+HzAkP/LVRKTW1+y1iR/K+sAxUhd0Tbe
         ohmALN4aMMpU3VyS0fiK5dbyBQ5B4ztWA2aUDMVNm3HTxvIJyAbTCQcSLJeAfPTRtwqI
         lPnaxrv30KGCJGO9zD2IV/nsTsl0JSo6MTMYSwz3znmWKVfD9b4VXUj+bupzmOeaVvii
         Tn9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
Received: from www62.your-server.de (www62.your-server.de. [213.133.104.62])
        by gmr-mx.google.com with ESMTPS id w3si4513ljg.8.2021.06.15.14.08.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jun 2021 14:08:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) client-ip=213.133.104.62;
Received: from sslproxy03.your-server.de ([88.198.220.132])
	by www62.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92.3)
	(envelope-from <daniel@iogearbox.net>)
	id 1ltGIF-0004xO-Nz; Tue, 15 Jun 2021 23:08:19 +0200
Received: from [85.7.101.30] (helo=linux-3.home)
	by sslproxy03.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <daniel@iogearbox.net>)
	id 1ltGIF-000CCY-9W; Tue, 15 Jun 2021 23:08:19 +0200
Subject: Re: [PATCH v5] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
To: Eric Biggers <ebiggers@kernel.org>, Edward Cree <ecree.xilinx@gmail.com>
Cc: Kurt Manucredo <fuzzybritches0@gmail.com>,
 syzbot+bed360704c521841c85d@syzkaller.appspotmail.com,
 keescook@chromium.org, yhs@fb.com, dvyukov@google.com, andrii@kernel.org,
 ast@kernel.org, bpf@vger.kernel.org, davem@davemloft.net, hawk@kernel.org,
 john.fastabend@gmail.com, kafai@fb.com, kpsingh@kernel.org, kuba@kernel.org,
 linux-kernel@vger.kernel.org, netdev@vger.kernel.org, songliubraving@fb.com,
 syzkaller-bugs@googlegroups.com, nathan@kernel.org, ndesaulniers@google.com,
 clang-built-linux@googlegroups.com, kernel-hardening@lists.openwall.com,
 kasan-dev@googlegroups.com
References: <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
 <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
 <202106091119.84A88B6FE7@keescook>
 <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
 <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
 <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com> <202106101002.DF8C7EF@keescook>
 <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
 <85536-177443-curtm@phaethon>
 <bac16d8d-c174-bdc4-91bd-bfa62b410190@gmail.com> <YMkAbNQiIBbhD7+P@gmail.com>
From: Daniel Borkmann <daniel@iogearbox.net>
Message-ID: <dbcfb2d3-0054-3ee6-6e76-5bd78023a4f2@iogearbox.net>
Date: Tue, 15 Jun 2021 23:08:18 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <YMkAbNQiIBbhD7+P@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Authenticated-Sender: daniel@iogearbox.net
X-Virus-Scanned: Clear (ClamAV 0.103.2/26202/Tue Jun 15 13:21:24 2021)
X-Original-Sender: daniel@iogearbox.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as
 permitted sender) smtp.mailfrom=daniel@iogearbox.net
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

On 6/15/21 9:33 PM, Eric Biggers wrote:
> On Tue, Jun 15, 2021 at 07:51:07PM +0100, Edward Cree wrote:
>>
>> As I understand it, the UBSAN report is coming from the eBPF interpreter,
>>   which is the *slow path* and indeed on many production systems is
>>   compiled out for hardening reasons (CONFIG_BPF_JIT_ALWAYS_ON).
>> Perhaps a better approach to the fix would be to change the interpreter
>>   to compute "DST = DST << (SRC & 63);" (and similar for other shifts and
>>   bitnesses), thus matching the behaviour of most chips' shift opcodes.
>> This would shut up UBSAN, without affecting JIT code generation.
> 
> Yes, I suggested that last week
> (https://lkml.kernel.org/netdev/YMJvbGEz0xu9JU9D@gmail.com).  The AND will even
> get optimized out when compiling for most CPUs.

Did you check if the generated interpreter code for e.g. x86 is the same
before/after with that?

How does UBSAN detect this in general? I would assume generated code for
interpreter wrt DST = DST << SRC would not really change as otherwise all
valid cases would be broken as well, given compiler has not really room
to optimize or make any assumptions here, in other words, it's only
propagating potential quirks under such cases from underlying arch.

Thanks,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dbcfb2d3-0054-3ee6-6e76-5bd78023a4f2%40iogearbox.net.
