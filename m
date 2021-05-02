Return-Path: <kasan-dev+bncBCALX3WVYQORBEG6XOCAMGQEVRQYRKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 70166370E77
	for <lists+kasan-dev@lfdr.de>; Sun,  2 May 2021 20:27:30 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 11-20020a17090a194bb0290155426bcf44sf3339667pjh.4
        for <lists+kasan-dev@lfdr.de>; Sun, 02 May 2021 11:27:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619980049; cv=pass;
        d=google.com; s=arc-20160816;
        b=hFQcUzo7vX80B1NNFa0IbiHS1VV04pVq519COOaeOiBqZjjHOCE7P56xZgQ0yKbaee
         gL+C4NeSkv7PblctJQ8jccfVaK/q7jf8eD6mV1Dq4oHzEWm1BKv7AkOHt5j13RZvYLSD
         nkoshhwlBGju+EQJAvwdfcXdQXKfsK8Gy32FmDuAr71xc0kLyOQza6VvC1cuzV0GRlS8
         kyVgld+j2+l8P8ajlwp7UbSsCEKMPbR+qaAnGVDhZtaouy6lRked3FEgsQghU843O5Fb
         2PtSDcJbapU82VE7e0sE3x+gWH+BJHT9I2YP6d0npjkMao99MoswJ4UA8iZllJErX3gO
         VWkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=0JXiEVYAeTCnvhdgWhkU7Gd/8yqdvxxE7+9ffAlBEQU=;
        b=0ZjSWSJTBZ1Xwr4E29CNv2vA2Lx3dHTYOr3Q+CbCMB9MZVB/XQAkh2H/4YIk7ynyaf
         MFXHRXCRh+6NEIXwNoJh+06UL1IUKhESl4LIugv42txGb3OjdIbkOJTgpzy2ULYvq+6V
         ZX+ratOAsDSaSwvnlXWI6Z7UKmt6WWutMAr/x31sn7Gf+ZoNgxnVhOsGVPvuDk/IJeAT
         BHRN5XivklE/HrmLz+MN1G0ABvDk79jJEoAdKtRlkmxhFUcXbwssx5lOOnuuOeniAfjs
         f6Cz44IYTSd4qo3hl5nvxgDtjQE2mXodct9sBatgdYLuZ8xhc9jSgNqP+/1Rfl5zuwvA
         p32Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0JXiEVYAeTCnvhdgWhkU7Gd/8yqdvxxE7+9ffAlBEQU=;
        b=FeGrEcnIFCyCL0Ldfc1kyt9Vsgq4eqqUKNSH+6MbkHm9o5vlnHWspDGLdO9WX/Pt0U
         NRYzqy45Ls3qxDCljcCrQOnkrhA8Dd/Ob6sr/4IUCgPm4e4N14GYTTU00avvJ5QGyms0
         xOKGAo8bcXI6vDuMnNDlS2WlBWnGZHNPEO2x+kQrCn1RAEprb5igHnT+4Ed6CoM2buzW
         i4U5+VDEfqoypwuk+d38YYLDMkyVFBsuBrn6/EdWy2LmJVF1FBrF5tu1iF02nudi98/4
         wK5jhE2S6zSbg+5esLmrbtV7w7bpeLQWXZzOYO0fDEJfE1hTgJKsIYs7lopJHMDbziTL
         ZE6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0JXiEVYAeTCnvhdgWhkU7Gd/8yqdvxxE7+9ffAlBEQU=;
        b=P5O3fjXwaVycfsSc7pRB3fp55S2nDaTEIdqejDiqQxeDXJizhUZX2hpuFld5oqm1t2
         j2XjCesxwPgulox1Y/Gr7bOeiXRKcqNan8LwyDzfXXioW1rUvDOn5Bo8k9FUdLZUIfL5
         wRvzDTC00DSgwyMMC6Ihji1ZM7p6bFE39kWBQ/66/2rvFslDlXsE0aol35sdH3sTTe12
         U37WEq/cKquyE/4tlDz50cNdTlCRg6RRKHNvV4z9A5WiQ1fcJ/a8CwLQk4gbEQ30C+j4
         Hz26V7EhihcQDYpawPAjv+jMYVGTW70is3DtBsjJTbKfO6RGknDfKtwizsWRp31L2S2D
         tHjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JGfDq3386B7OCYMJZb2wJ1k+jG1lco+IXmVHLdA22rFQs+OlN
	KQ2RDiVOhAtuiBx1ON5jl2c=
X-Google-Smtp-Source: ABdhPJxosDwyk8kL1iI7l+nPQB6dhXSuuDP6dvCCjzZBL57GeQFMTvSD1xmGJrHsILfYmCqPejTc5Q==
X-Received: by 2002:a63:5160:: with SMTP id r32mr7432736pgl.83.1619980048108;
        Sun, 02 May 2021 11:27:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b710:: with SMTP id d16ls6518975pls.3.gmail; Sun, 02
 May 2021 11:27:27 -0700 (PDT)
X-Received: by 2002:a17:90a:8b18:: with SMTP id y24mr16805642pjn.215.1619980047584;
        Sun, 02 May 2021 11:27:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619980047; cv=none;
        d=google.com; s=arc-20160816;
        b=pAZJTuzur6XbADq7KmU4NdhWzoCDqRkMpfbfRWRAq90ARWdbdBlVJ6nFyta9wKkab2
         Wlv26Ymh44h638grxCqk4LrxYFYul+ppZUSFia/9O4LOkV+8NqayZqwGjkzb/ZixeM82
         YXjGK3IpuArWWzo3uvBExxA0TGOzM6R6TwccAe1HNwMgt0EuuWjDZXjuvuo1Bg9fxZIr
         KVWf9K1RPuzzTL3365TcjjDBR7iroIJtGBvPuGyuE7L9vwb/LIoLC9DEDZyvmSLyGtsF
         KTUSzkhSUKIIGnH9XbB63FZN+cT13r0qhmnE75YEsqmoZw9G6SzLBTZ0n8lNNHieUJqi
         yiNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=1AKTeZzqbDFUGxYviuzsOPuHohoaIIxN+/lbdZwTyOo=;
        b=caiTFqtbIQkB+frIpQdiXh9MBhNkyYTLMTtIGu0bsGW/FKbatd9T3Re+o8bXyaJEI5
         vVS20jns3kDZdS73bF6eUroyg4g6nHsAwIiSY+1hkJKgJDkcmptQ3QpFY9tQhviVGVQs
         Imxfp6hUnxX6BlkLkYs0AtIHgJrkQpz9SaXIG7Y/10J3VGtffIrA5BVuWzbace1k6ufl
         0+kzqkK2Sy2z6euWlSVt5cZgkerxuF+b0MsxSTETiT5dnj4jqT+wU3RhX0ZMMt3oSg8y
         AZVaV0Nm/LTjD0VMGFbIaw37dK2W5tM5dht/vghmdO737m2/sVC+NulvX4NZ9GEZ4TNq
         TxOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id z28si974063pgk.2.2021.05.02.11.27.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 02 May 2021 11:27:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldGoQ-00FXga-HS; Sun, 02 May 2021 12:27:26 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldGoP-00BO9w-MT; Sun, 02 May 2021 12:27:26 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m1tunns7yf.fsf_-_@fess.ebiederm.org>
	<CANpmjNOZj-jRfFH365znJGqDAwdXL4Z2QBuHOtdvN_uNJ8WBSA@mail.gmail.com>
Date: Sun, 02 May 2021 13:27:21 -0500
In-Reply-To: <CANpmjNOZj-jRfFH365znJGqDAwdXL4Z2QBuHOtdvN_uNJ8WBSA@mail.gmail.com>
	(Marco Elver's message of "Sat, 1 May 2021 12:31:10 +0200")
Message-ID: <m1czu9ng8m.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1ldGoP-00BO9w-MT;;;mid=<m1czu9ng8m.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+I6HZ0cD4XvYQ+uzlALtJgYoOqGyYDPxk=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,XMNoVowels,
	XMSubLong autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4920]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 325 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 4.4 (1.3%), b_tie_ro: 3.0 (0.9%), parse: 1.06
	(0.3%), extract_message_metadata: 11 (3.3%), get_uri_detail_list: 1.98
	(0.6%), tests_pri_-1000: 11 (3.4%), tests_pri_-950: 1.02 (0.3%),
	tests_pri_-900: 0.83 (0.3%), tests_pri_-90: 52 (16.0%), check_bayes:
	51 (15.6%), b_tokenize: 6 (1.8%), b_tok_get_all: 7 (2.2%),
	b_comp_prob: 1.90 (0.6%), b_tok_touch_all: 33 (10.1%), b_finish: 0.72
	(0.2%), tests_pri_0: 232 (71.3%), check_dkim_signature: 0.37 (0.1%),
	check_dkim_adsp: 2.3 (0.7%), poll_dns_idle: 0.94 (0.3%), tests_pri_10:
	2.7 (0.8%), tests_pri_500: 7 (2.2%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH 1/3] siginfo: Move si_trapno inside the union inside _si_fault
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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

Marco Elver <elver@google.com> writes:

> On Sat, 1 May 2021 at 00:50, Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> It turns out that linux uses si_trapno very sparingly, and as such it
>> can be considered extra information for a very narrow selection of
>> signals, rather than information that is present with every fault
>> reported in siginfo.
>>
>> As such move si_trapno inside the union inside of _si_fault.  This
>> results in no change in placement, and makes it eaiser to extend
>> _si_fault in the future as this reduces the number of special cases.
>> In particular with si_trapno included in the union it is no longer a
>> concern that the union must be pointer alligned on most architectures
>> because the union followes immediately after si_addr which is a
>> pointer.
>>
>
> Maybe add "Link:
> https://lkml.kernel.org/r/CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com"
>
>> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
>
> Acked-by: Marco Elver <elver@google.com>
>
> By no longer guarding it with __ARCH_SI_TRAPNO we run the risk that it
> will be used by something else at some point. Is that intentional?

The motivation was letting the code be tested on other architectures.

But once si_trapno falls inside the union instead of being present for
every signal reporting a fault it doesn't really matter.

I think it would be poor taste but harmless to use si_trapno, mostly
because defining a new entry in the union could be more specific and
well defined.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1czu9ng8m.fsf%40fess.ebiederm.org.
