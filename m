Return-Path: <kasan-dev+bncBDOY5FWKT4KRBBWN7GRAMGQEY22TABY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 64A5C700CBE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 18:17:13 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-645538f6101sf34563241b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 09:17:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683908231; cv=pass;
        d=google.com; s=arc-20160816;
        b=NsR8/GSRZDQ2d/4oQukR2UwPcnd3Sumasqb2UZf1Zfc2y3OPItw3EVlV7585cWT5Uo
         g0C7mOQD6fe2nV8+EUKj25gp8tNnXytHthIarhcWPNR50iKeN0uCZ9GfXp6myCjHp8d+
         AaO9fh4MbTUB+E0l93RSaoZ6enEUnc4kZdHNwgw85cwoh5kr7hnVK7m/VbNf9mB+xkV5
         pD7KsSbjYi3b8fdrrXTWxbgDanj7bvIN75Ck3YIFNAkJlvMuzx8HZov3hwJoJKFSuShQ
         vWSumgl4XDemibpxmQOuCVJolDYtkqMOWAplMI3y08uGD/DDeOuNQwGTLRCfw3eUdGL7
         GOdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BFf3rnBOSuXhwOEwYfYm8lRcM6VsWfkXnYunWBwArW0=;
        b=GUhOS74Spvo2g5QzgYRMwtSx5DXhzL5eh54ou6gtivFYPz/FNemsA/m3aTYh8ZvjU0
         5ALNpGeNFZebF+sBqHNNAV7qlQ85802LIJCmRcmp7bVqYhqDUuF3zyAy0LXvQpxlqiwt
         KD5RIAkV8Ex/uJtUTaveTKOy8m70nTMbj+IFReBfY5VTUKi+T+03hTtMTjp5P9JLYZJ/
         PQEpDUeuSJ/94DLtd5a1/9jnuAEGmrv7HzvZI4G0lz3k2ugEfMntT0gOpigow/1kXdvX
         zyXaUQo3n16Pq0ZP8Bh2iKpAl8CuIJSBknpOY9Q4RKKHVjrvI6J40wZLcqsQwT+8x++I
         5XaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YtE3ivUR;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683908231; x=1686500231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BFf3rnBOSuXhwOEwYfYm8lRcM6VsWfkXnYunWBwArW0=;
        b=WieVkLZnAc7mGmH3aYtirMBAAfefEHXWNr5DbQmg/3vfavy1hTKH/VodNyjCPetIIe
         sfWCOT8Qufgu2DZto2LsijRHG/Thi27wq/DEgb9GQRSLy/rbd3WGKISrLVP0xLNrqkwn
         BA43ZNzXPJ/VYHa0hgDYCG7GWtJM8OiM3rMgZPoYMrYCfnr7YPwg6rK40qvq3LkuwiXe
         bbTx0jMMO8bMTpkZR1zrUuEihj/rknUYdasjeNIgLXVwY8lqagS/2aS46t6hfupxP/Su
         CwufPp1um7Hs27fPe8Czw4sGPhLoSv7hmeuGT4lcqSlPtt+73WVz1NG9BrLp6Ts+2uI6
         mnhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683908231; x=1686500231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BFf3rnBOSuXhwOEwYfYm8lRcM6VsWfkXnYunWBwArW0=;
        b=lTL2xFIwPDlYolMKw9oqZ2y7KLrwewOu+3LvzQYEYuPRMQkjB/xkZf5qYDdhf4YKXk
         ZH8B+OyeBS64rlCi6uU8PPe4bOwCHYr/vVB9y05+1LBIhByVWBmGUG7iTonKYptQAcky
         yAyMUeacSTdHSmuavEthceafMS0uyUFiHvF8E4HW4C5xizQKadSYg8utDMQerbSRmCh9
         O2YvjAURUAmLJqQIOtAIzNNdX1yi6nXibBMAEfgPEcYyFzy0GdSPg/l6kUgh2cFPHyaH
         SUOiS584QbwgRSLZHGVCRPG6bgOnW7xwcs27QXDlDddPKjuGSw71nymhLVlFqkoKfTpA
         AnCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyBu2fCj8llAUa/ojhfwWMx17Kd1hD/w9u9EFF1HmSSppFQNsCq
	htyKkfuyDUIeqnlFiUDy28I=
X-Google-Smtp-Source: ACHHUZ63ZBBO516jEQAUTA0GR7B38WD8q86BgtWTpUdQz4Rh4/tGHCNcs+MTRJZ1dtRpYVm2Wyhz6Q==
X-Received: by 2002:a17:902:d489:b0:1a8:1f4:2d50 with SMTP id c9-20020a170902d48900b001a801f42d50mr9546211plg.4.1683908231073;
        Fri, 12 May 2023 09:17:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5c8:b0:1a5:1ada:5c00 with SMTP id
 u8-20020a170902e5c800b001a51ada5c00ls1709063plf.0.-pod-prod-02-us; Fri, 12
 May 2023 09:17:10 -0700 (PDT)
X-Received: by 2002:a17:903:1110:b0:1a9:bc13:7e20 with SMTP id n16-20020a170903111000b001a9bc137e20mr30732203plh.44.1683908230169;
        Fri, 12 May 2023 09:17:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683908230; cv=none;
        d=google.com; s=arc-20160816;
        b=rK1/XOFc9U9X3RvrHQSqVznWFFDykDcOoEwjt2qyjFUCPt9fwqr+jFaWvf1coJ4ewe
         V2UUpVmN0IXiBCyv7clkuHK89nahUa+rUXbE6Cs/29V3sPjbinAdGYHmohH2QWFsA5MH
         Sb3vdOqum9BN31L7uBVAvBvCZMq1CM8e97JoGjHdFjmdCQkkjx7dK6ftzjUnP6xATsUu
         WOe4ZnN49JaIjN1sqoSGuKwjow0GwyHzsO54a8pVWM4BK9OeyF4Uiem4fdTKLdyqeA7u
         NNtmgNQhj6Qk1stFxe/jxkb8dPklWriWniiU0COZibHO1AppoP9JhvzLOkyt0jrIQ0N8
         Pjcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Cb8gfCtT31tl0Hd05HJ61jy3YwTBles2tWwg6XzjYyc=;
        b=WjJNDsM9+StlKJJN6U86EklI2RnJsCz4AGbWzuwa6UMXi2mhYLxcY7u1t79402YwFF
         Vcr7CpwbrVasjC10plim81q6k0nV7pyWN6ez17jZIrbuRmC0rv/FAM+Ga7hurvltdfZT
         XVwe8+5aicpRIg65spqulFFioGfC7Uhr3RbK2HlDVw0MnR4JeWQDZcqQ7dY5C/tQbCZu
         d12IKcCoexHahxcaINpmz4DaJudeavin8DfhIk78EWgx4vqCzVhyIGyMZqxRBrzajvt8
         ZAyQ/CUNt5vBtlj0r2MK/FtDM1rFNPLYnI3AYqROVgdq1+aCeQw4g9vVrziLrwfotCQi
         FrwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YtE3ivUR;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id u4-20020a17090341c400b001ab29e16b30si438431ple.10.2023.05.12.09.17.10
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 May 2023 09:17:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 96B53614ED;
	Fri, 12 May 2023 16:17:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A1018C433EF;
	Fri, 12 May 2023 16:17:08 +0000 (UTC)
Date: Fri, 12 May 2023 09:17:07 -0700
From: Mike Rapoport <rppt@kernel.org>
To: Chuck Lever III <chuck.lever@oracle.com>
Cc: Dan Carpenter <dan.carpenter@linaro.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	open list <linux-kernel@vger.kernel.org>,
	linux-mm <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>,
	"lkft-triage@lists.linaro.org" <lkft-triage@lists.linaro.org>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: next: WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744
 __alloc_pages+0x2e8/0x3a0
Message-ID: <20230512161707.GH4135@kernel.org>
References: <CA+G9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC=wQ@mail.gmail.com>
 <6c7a89ba-1253-41e0-82d0-74a67a2e414e@kili.mountain>
 <DC7CFF65-F4A2-4481-AA5C-0FA986BE48B7@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <DC7CFF65-F4A2-4481-AA5C-0FA986BE48B7@oracle.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YtE3ivUR;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, May 12, 2023 at 01:56:30PM +0000, Chuck Lever III wrote:
> 
> 
> > On May 12, 2023, at 6:32 AM, Dan Carpenter <dan.carpenter@linaro.org> wrote:
> > 
> > I'm pretty sure Chuck Lever did this intentionally, but he's not on the
> > CC list.  Let's add him.
> > 
> > regards,
> > dan carpenter
> > 
> > On Fri, May 12, 2023 at 06:15:04PM +0530, Naresh Kamboju wrote:
> >> Following kernel warning has been noticed on qemu-arm64 while running kunit
> >> tests while booting Linux 6.4.0-rc1-next-20230512 and It was started from
> >> 6.3.0-rc7-next-20230420.
> >> 
> >> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> >> 
> >> This is always reproducible on qemu-arm64, qemu-arm, qemu-x86 and qemu-i386.
> >> Is this expected warning as a part of kunit tests ?
> 
> Dan's correct, this Kunit test is supposed to check the
> behavior of the API when a too-large privsize is specified.
> 
> I'm not sure how to make this work without the superfluous
> warning. Would adding GFP_NOWARN to the allocation help?

Yes, it should. 
 
> >> Crash log:
> >> -----------
> >> 
> >> [  663.530868]     KTAP version 1
> >> [  663.531545]     # Subtest: Handshake API tests
> >> [  663.533521]     1..11
> >> [  663.534424]         KTAP version 1
> >> [  663.535406]         # Subtest: req_alloc API fuzzing
> >> [  663.542460]         ok 1 handshake_req_alloc NULL proto
> >> [  663.550345]         ok 2 handshake_req_alloc CLASS_NONE
> >> [  663.558041]         ok 3 handshake_req_alloc CLASS_MAX
> >> [  663.565790]         ok 4 handshake_req_alloc no callbacks
> >> [  663.573882]         ok 5 handshake_req_alloc no done callback
> >> [  663.580284] ------------[ cut here ]------------
> >> [  663.582129] WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744
> >> __alloc_pages+0x2e8/0x3a0
> >> [  663.585675] Modules linked in:
> >> [  663.587808] CPU: 0 PID: 1200 Comm: kunit_try_catch Tainted: G
> >>          N 6.4.0-rc1-next-20230512 #1
> >> [  663.589817] Hardware name: linux,dummy-virt (DT)
> >> [  663.591426] pstate: 22400005 (nzCv daif +PAN -UAO +TCO -DIT -SSBS BTYPE=--)
> >> [  663.592978] pc : __alloc_pages+0x2e8/0x3a0
> >> [  663.594236] lr : __kmalloc_large_node+0xbc/0x160
> >> [  663.595548] sp : ffff80000a317bc0
> >> [  663.596577] x29: ffff80000a317bc0 x28: 0000000000000000 x27: 0000000000000000
> >> [  663.598863] x26: ffff0000c8925b20 x25: 0000000000000000 x24: 0000000000000015
> >> [  663.601098] x23: 0000000000040dc0 x22: ffffbf424e7420c8 x21: ffffbf424e7420c8
> >> [  663.603100] x20: 1ffff00001462f88 x19: 0000000000040dc0 x18: 0000000078b4155a
> >> [  663.605582] x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
> >> [  663.607328] x14: 0000000000000000 x13: 6461657268745f68 x12: ffff60001913bc5a
> >> [  663.609355] x11: 1fffe0001913bc59 x10: ffff60001913bc59 x9 : 1fffe0001913bc59
> >> [  663.611004] x8 : 0000000041b58ab3 x7 : ffff700001462f88 x6 : dfff800000000000
> >> [  663.613556] x5 : 00000000f1f1f1f1 x4 : 00000000f2f2f200 x3 : 0000000000000000
> >> [  663.615364] x2 : 0000000000000000 x1 : 0000000000000001 x0 : ffffbf42516818e2
> >> [  663.617753] Call trace:
> >> [  663.618486]  __alloc_pages+0x2e8/0x3a0
> >> [  663.619613]  __kmalloc_large_node+0xbc/0x160
> >> [  663.621454]  __kmalloc+0x84/0x94
> >> [  663.622551]  handshake_req_alloc+0x74/0xe8
> >> [  663.623801]  handshake_req_alloc_case+0xa0/0x170
> >> [  663.625467]  kunit_try_run_case+0x7c/0x100
> >> [  663.626592]  kunit_generic_run_threadfn_adapter+0x30/0x4c
> >> [  663.628998]  kthread+0x1d4/0x1e4
> >> [  663.629715]  ret_from_fork+0x10/0x20
> >> [  663.631094] ---[ end trace 0000000000000000 ]---
> >> [  663.643101]         ok 6 handshake_req_alloc excessive privsize
> >> [  663.649446]         ok 7 handshake_req_alloc all good
> >> [  663.651032]     # req_alloc API fuzzing: pass:7 fail:0 skip:0 total:7
> >> [  663.653941]     ok 1 req_alloc API fuzzing
> >> [  663.665951]     ok 2 req_submit NULL req arg
> >> [  663.674278]     ok 3 req_submit NULL sock arg
> >> [  663.682968]     ok 4 req_submit NULL sock->file
> >> [  663.694323]     ok 5 req_lookup works
> >> [  663.703604]     ok 6 req_submit max pending
> >> [  663.714655]     ok 7 req_submit multiple
> >> [  663.725174]     ok 8 req_cancel before accept
> >> [  663.733780]     ok 9 req_cancel after accept
> >> [  663.742528]     ok 10 req_cancel after done
> >> [  663.750637]     ok 11 req_destroy works
> >> [  663.751884] # Handshake API tests: pass:11 fail:0 skip:0 total:11
> >> [  663.753579] # Totals: pass:17 fail:0 skip:0 total:17
> >> 
> >> links:
> >> ------
> >> 
> >> - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/test/check-kernel-exception/log
> >> - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/tests/
> >> - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230420/testrun/16385677/suite/log-parser-boot/test/check-kernel-warning-ac79d2ca0f443d407d9749244f1738c9a2b123c609820f82d9e8907c756f5340/log
> >> - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/test/check-kernel-warning-ac79d2ca0f443d407d9749244f1738c9a2b123c609820f82d9e8907c756f5340/history/
> >> 
> >> 
> >> --
> >> Linaro LKFT
> >> https://lkft.linaro.org
> 
> --
> Chuck Lever
> 
> 
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512161707.GH4135%40kernel.org.
