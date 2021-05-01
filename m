Return-Path: <kasan-dev+bncBCALX3WVYQORB4XBWWCAMGQEBTQRMVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4406F3707A9
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 17:17:08 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id x7-20020a056e021ca7b029016344dffb7bsf1142775ill.2
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 08:17:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619882227; cv=pass;
        d=google.com; s=arc-20160816;
        b=gXWlzBR0c8Ck6zgu4UF2wD1br1IwzKvs61H4nuHO8bsb1KK5Mte/+EB1cxN1oc8Zfu
         X3fMk8BOKe7cvufwSmFJq3Y4jKOppV29p5eqzkZeCE5Ry6GDmbYXuzC7NYvTz7WmY4NJ
         YPuK7lq8Fz2EtPZ895QLsa1UMysFdTuU5OiBAJZD8q/QmzU6ai2/YOnbIQOl/OHMkVz2
         pqBolJXLDye8e2Qwv5qUZDGXyoofZa6Z/mhMOxW5gQCbjtguuK5OMgRIQHBRCEppWr9P
         INVh4EdHXyLFbvXQHsmDEv79GjUqqx4gRa0EfYfRHyQ1WcpZxdv4NVSIg29CIEyCCOb+
         6v6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=nbyK+tIKkxYfeNDFbYuv5hINXoI2/SVpxF2tyEkMi+4=;
        b=b9DFmXvDpb5+CXuAnBu9rU0lTIEsG0yWr/IyPAKxuJy3VYP+Waugjf7xav/68Ks4iK
         Gd03rSHOKKsUtZc5WItekNnUNOzfgnb4AYUCP3sjjDK7iQe0vc/lNuj3uNv2C1NKpxzO
         OR7P+IkMwA+Av6IYEOdNUhnEhJLRI36DhEPLLj7+FdJB0w/VG1m2bGpcrs3Fo7qTXq4/
         JorKSWmLs4RtkzyVPnQc3Efzz+duF3+sv9ZjZQRwEYZhlP+W2SSUOjMQu65k9WKL3iAw
         99pgItmdMk73sOfCky/h0SsjtjetOMRyC4QwuEngoyEqcIJg30pA2ye1Gb5q5HzGXXdB
         5rGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nbyK+tIKkxYfeNDFbYuv5hINXoI2/SVpxF2tyEkMi+4=;
        b=Pg50VW+w+GdtPHiVUTTdQdS1SDibiHVPjED8I9rgxF0seHitER99mVOXy6FuUq/ezs
         +mIwnb2H0QZIdbpU84O4CbrY+/FAF6Y/WVVHaaLcGxBuoiiG1dqfwD9HTCF4q4Asjbns
         KwEVEKPoyp3Cz2/7okawRbD4GthhQ/qSwgaO0kwNNCrZykHqtHrNAvi1kltooTha0nBw
         meOzKqB7JvKBbCFp49Ybl7zuS0qjrOQgD2w7vmOfQnQLzpPY0UvP+WaD6DKvjPpvnOo7
         cPnJb7NhpsK0L+n2fxyEALbXqUqeYUWP9eSwDf9L0q2T19+yS86rFK/4GeCKNxvYzZVZ
         zX7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nbyK+tIKkxYfeNDFbYuv5hINXoI2/SVpxF2tyEkMi+4=;
        b=CR+5nqaqdHgyWFJFVv8tUgVx8GUxU8hUNx3lMWM5enW43jQSz5iXRj6vVwGydgG1PM
         JORaA1mzhiIRW/UIIwjmRP/qppIXLcrPTsmiZEN/Fr4lM6dc1CbKwd1GoBpRJpQs/EuR
         jluZwO1OkIbrfLbpGkuUnP60sqGnmUQtfO4eT6ujXhW+jE4go95KVlYIirVV1gvKpoTn
         jnMRfrz6pRkEaFuS9dUa7PqrbNpqBZFJ/5d2Nb7ak9QTVSfMx576bDXGVOQt5jkShivh
         3hWNJGoOm8BZW2/7LRdksBdT+aJz7stYK08lHJpBZpNPfJtIBIIzAfT1ARnRzt+bU8qT
         Mdqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XQrONYFwFhYk4llaHILbYdN3HPku6iLI5wEd4V+rZ5XtxFOQo
	3Osib3lhn3o44smsCkZFyRI=
X-Google-Smtp-Source: ABdhPJw+ordJ0m525/Oo4QGQBKLy31Gq5K6OiEA7fk5kCv0SK9RrNi6M8q5f8M1N+JlBA06Cx4KWpw==
X-Received: by 2002:a6b:7014:: with SMTP id l20mr7753169ioc.96.1619882226929;
        Sat, 01 May 2021 08:17:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2b93:: with SMTP id r19ls584685iov.2.gmail; Sat, 01
 May 2021 08:17:06 -0700 (PDT)
X-Received: by 2002:a5d:9682:: with SMTP id m2mr8276657ion.20.1619882226501;
        Sat, 01 May 2021 08:17:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619882226; cv=none;
        d=google.com; s=arc-20160816;
        b=CiDvPL+0NckGdNJC00iR4AGNzQ50bcBaWBv1Mu6/RvSqMuGsiSJuqIDLqlkjGgdCbA
         T0oQWhN97tdNx2KY9gtj2vQayOl0fTJgTH9gk7+2yRdhSgS2xW6wiJgZNsGko/1cmX87
         nsc6c2kN0SVh+zev+jXaqjyb/cq3ZqT87zTH3G/cuFlCvrU/vv7nRQ+37SuA55h2a6Lz
         l2vwNVyIPcgPpwLP9uaVUgyyOYpkum3SXvYmR+AE3hbf6ftqUmajofv307vtRxqGu+Zk
         K5Jk4CW2BGb0phkg1adxV2aIJrgQICzyAGDbWE94yCqzniulyLDFiojTL6LJQeBl2352
         J2ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=ulofuXNzpQMHJ9gUUypPuJDoXucbhjj2b/PHrn841Ik=;
        b=USdyyUZu9xbwmAQIQaBu6YdDx6n+TXZ+DxLAuswdQBsnH1Tqxt2kqZVzxHEzf963w3
         y3ECG/wik0I8r6Pl4SlI//Avzl7TkKMzVpUrObUzESrxhtDkVSdZftKxz7PgBGj+quwQ
         KxBHVBSPU7soNXM8LHE+/BXKH4bU7FiplbzONLiqdAKEA9DJqdH40vQ6SPPx3al9XhgI
         J+fxswCWAkwRhLf5R9layg4djaef0labzlBki77Tejitrf5PeIWRrEenC98DT3XegU3m
         rXxQXEpTCfbXozzZMVEfmPyPgJRCSWB9y7Dj5TDmx9h3k4x93lT6+6lzUanJCxzKsg8M
         +Jiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id o3si960519ilt.5.2021.05.01.08.17.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 01 May 2021 08:17:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcrMc-00DX9j-SQ; Sat, 01 May 2021 09:17:03 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcrMb-008qNO-TS; Sat, 01 May 2021 09:17:02 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m1r1irpc5v.fsf@fess.ebiederm.org>
	<CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
Date: Sat, 01 May 2021 10:16:58 -0500
In-Reply-To: <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
	(Marco Elver's message of "Sat, 1 May 2021 02:37:22 +0200")
Message-ID: <m1czuapjpx.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lcrMb-008qNO-TS;;;mid=<m1czuapjpx.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18DzHMcLYDrGj+W7oEcRW3RY5bEckDfeoo=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa08.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.2 required=8.0 tests=ALL_TRUSTED,BAYES_05,
	DCC_CHECK_NEGATIVE,TR_Symld_Words,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,T_XMDrugObfuBody_08,XMNoVowels,XMSubLong
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.5 BAYES_05 BODY: Bayes spam probability is 1 to 5%
	*      [score: 0.0454]
	*  0.7 XMSubLong Long Subject
	*  1.5 TR_Symld_Words too many words that have symbols inside
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa08 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
X-Spam-DCC: XMission; sa08 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 401 ms - load_scoreonly_sql: 0.11 (0.0%),
	signal_user_changed: 13 (3.3%), b_tie_ro: 11 (2.8%), parse: 0.95
	(0.2%), extract_message_metadata: 11 (2.7%), get_uri_detail_list: 1.29
	(0.3%), tests_pri_-1000: 14 (3.4%), tests_pri_-950: 1.57 (0.4%),
	tests_pri_-900: 1.23 (0.3%), tests_pri_-90: 102 (25.3%), check_bayes:
	99 (24.8%), b_tokenize: 7 (1.7%), b_tok_get_all: 8 (2.1%),
	b_comp_prob: 2.3 (0.6%), b_tok_touch_all: 77 (19.1%), b_finish: 1.49
	(0.4%), tests_pri_0: 240 (59.7%), check_dkim_signature: 0.70 (0.2%),
	check_dkim_adsp: 3.0 (0.8%), poll_dns_idle: 0.90 (0.2%), tests_pri_10:
	4.0 (1.0%), tests_pri_500: 11 (2.8%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [RFC][PATCH 0/3] signal: Move si_trapno into the _si_fault union
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
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

> On Sat, 1 May 2021 at 01:48, Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> Well with 7 patches instead of 3 that was a little more than I thought
>> I was going to send.
>>
>> However that does demonstrate what I am thinking, and I think most of
>> the changes are reasonable at this point.
>>
>> I am very curious how synchronous this all is, because if this code
>> is truly synchronous updating signalfd to handle this class of signal
>> doesn't really make sense.
>>
>> If the code is not synchronous using force_sig is questionable.
>>
>> Eric W. Biederman (7):
>>       siginfo: Move si_trapno inside the union inside _si_fault
>>       signal: Implement SIL_FAULT_TRAPNO
>>       signal: Use dedicated helpers to send signals with si_trapno set
>>       signal: Remove __ARCH_SI_TRAPNO
>>       signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
>>       signal: Factor force_sig_perf out of perf_sigtrap
>>       signal: Deliver all of the perf_data in si_perf
>
> Thank you for doing this so quickly -- it looks much cleaner. I'll
> have a more detailed look next week and also run some tests myself.
>
> At a first glance, you've broken our tests in
> tools/testing/selftests/perf_events/ -- needs a
> s/si_perf/si_perf.data/, s/si_errno/si_perf.type/

Yeah.  I figured I did, but I couldn't figure out where the tests were
and I didn't have a lot of time.  I just wanted to get this out so we
can do as much as reasonable before the ABI starts being actively used
by userspace and we can't change it.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1czuapjpx.fsf%40fess.ebiederm.org.
