Return-Path: <kasan-dev+bncBCALX3WVYQORBNGKS72AKGQE3UGO4RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2246119C1DE
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 15:14:30 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id a69sf2930260oib.11
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 06:14:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585833269; cv=pass;
        d=google.com; s=arc-20160816;
        b=GjdzS804lI+H+LgK5gl6YldwWaYT2nZZkWpAPnK4CJ58dMDxXuAfoI4us/J7YbQn3c
         ic9wZyh80BNYtm9VcBlEiNBAJSq0pOVyiGDDhwbSE7HnAG7CcB8qE7UGlosA3bQNsky4
         IFE2H150jGrW3+/pz5e/Cd7fLP9u+W8kzYD0qmQ0b/UzqgI6fdRgrr2Ou7ti2Y4JI7lW
         O1KiYiRJUUDD1Aj+KBFiVZhvnOgfw9lUlopPbTDU+pAAo04mZxmbsM4r9qqe0sjMVcfw
         8vPYmnw6bMcTFHNEF50dVtDotyU+9qNMAoCJb0/ikChGCaHLDVPN3a7oViMi0dQeTjoC
         /EAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=HpcfkSDxCBlyaAZDZoER/TBNXE6vJ/g3mlSBVK5sFGU=;
        b=blDi7VxmRmVI2chhkcJxPDeCO1tWFMcQmtGq7ro/Z/Qjvi/F7RLTN71XPzb7ed0/VD
         3eF4tmor1w5ojoflkfwgN+LtndjBARylToHVe9oI3h0MppdpP9iEq09Dhp4WlHnzQRFJ
         EnftgcZ1OJDyWkFyRZgpWcXq3pcuUd8bDjELf4Zj8iVUK2JIRm8ek1n5q4mzp5aJ72hn
         9e4Smt045DNEDvVk6ws1gfwCpMfdJAmDvFATWnX2wvqXLPmRXgPmZ4Z61ETLwU/cm+eA
         Pv8G9G7f0XvQ83+ylgml4rEcW6n+Ys+EHUd8KdBKxbhZnS5A4litrMRn9P6ZQjGtOzUf
         MtLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HpcfkSDxCBlyaAZDZoER/TBNXE6vJ/g3mlSBVK5sFGU=;
        b=EQz2SLx3Bke8soZD8AEdA15tkENc8L3xLaYR6W+Tg6KY0fBqCaCr8C9XO9irNOEJ2K
         C7UOTsbqgiARJCUpLBH1XJ+eCgiUCPq73/9ufGbgdabOaV0RPvCgUofkEdn+rcV4Tcng
         6Ke7RVZCZbP75KAXUL2iYdJv2fIUPg1eV3T8zWq5qLIqH4GioCk8PMRG7DTxezKMt1FT
         je9/FlAoQqK3V2TxqS1yyPGoZDg+C+eRQ9ACFiLnDBSPO801C4o+31Ta7SrOkT2vc4u1
         3AnxO5sLmqixH9FM354UkX34scF4qPjkRTt2CXBREux4d6RAf8G9GwOn8Jfnwn58FJ12
         mvQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HpcfkSDxCBlyaAZDZoER/TBNXE6vJ/g3mlSBVK5sFGU=;
        b=F8ELuORlQ1MloMpLwX977397Qyb1c600BL8RSHtKKLxGy2k4BnGHeVjS0OkQIXESTD
         6eH39qgfS+si7QPYJ67WJzxeaLTEgcRc1iiHO74Y/rXvQ4zKcx3CYvdfFLqoIJa1fVMs
         e3Reft+T+Qtamshs7nA+Vfm+WYyurMCwU1la2IrHnqjdC0w+mySFpRGfi7f4SX0AfLya
         5ZqGftiLP7qFdmDMOghBumpFRNZdSm/BztEq75XTo1l1NohMGGo8xp6BgGp1jCuHz9u6
         f6o6bM1ZSgzEqyhl9IugARwUijGKhY56fHv+44DbpdjkWp7o8FSurbCilC6vX3WBr0rv
         FaCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubjIXiTrNH/VrqtS/+Z+/B1ocu4Yym8npCFlDPm6JuFmtL2NP3R
	Yu3UOwhCF3HywBLJKvzGmxM=
X-Google-Smtp-Source: APiQypJqDZTRTvH7769A5OFmtJbUw5R0L83IG5XIIkcPIn76htBmgxLYLXKbbh0dQ1s7oMNrYJ3GzQ==
X-Received: by 2002:aca:c54d:: with SMTP id v74mr2100927oif.50.1585833268961;
        Thu, 02 Apr 2020 06:14:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cd45:: with SMTP id d66ls1421741oig.7.gmail; Thu, 02 Apr
 2020 06:14:28 -0700 (PDT)
X-Received: by 2002:aca:5210:: with SMTP id g16mr2218455oib.174.1585833268610;
        Thu, 02 Apr 2020 06:14:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585833268; cv=none;
        d=google.com; s=arc-20160816;
        b=rzQEsVFpUCG80AkLH7Df6R5MwmVNlD7vDycF0QY/jSuOzsHdhiiCmq7oaFiod0I2wB
         XcHg1iirnWZNsLUMIpI4uqYM6IBrLSAfxFHaGk3uQGHrWOnMs2JZMdiEBPU/xyxEqwig
         YlfSNbtljVRNjiKHZ8q0t/pl7G7S1vbyk93j90pQcFBAMyvAwUpWpUxFFl69oTHKySqI
         eFVJibX1kqOFuzsqWtx2DMEpDshDJATHerzQFoR61RHadfq+1t13tuMjkGn10/Sxk7w9
         qUsQfrpDAZAjg4dYQkQ//kBKXQ8KS7ylfP726Qd+v27C6nyPU1LmJfkBSAEHoRsQAmyW
         GD3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=pW6TyTOFJJzuW3a+I6XSfZsC50rdmInkrJ26R06xR3w=;
        b=Kcm+bdmPcxBWazCSzuL8sptDkrEXJJ0A42nJ+BvK2gYcE6SCs20AL5nAjGCE2Wu284
         j6Z4pyQW4fiHHv2SaP/YiIBSl893sj8u2y7Q9GJbZIzuvAOcEtF4E1aI6hJHRCS4ZlX7
         ypJ8yu4gK6rY6Aj54FJd6wFlcJKuX/fiP5x0+vJSOB8Kn8uj+iR+Eo/9d3vVuAzV7SaL
         6C6jHiCE89x7g3GqcS8T2SF053BVGt6YJJjCRfwfigngf2Gcd8YzkqqmMYvK6d+o95yl
         /eY9nLtsSa6Yr8AcOE6GuDLRZq3uB7UIo8QYsArWGT+vDmavC6KUqrrUQCLimicX09A2
         Z6Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id o10si260700oic.1.2020.04.02.06.14.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 02 Apr 2020 06:14:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.90_1)
	(envelope-from <ebiederm@xmission.com>)
	id 1jJzfp-00075I-T0; Thu, 02 Apr 2020 07:14:21 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=x220.xmission.com)
	by in02.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1jJzfj-00021V-6R; Thu, 02 Apr 2020 07:14:21 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Jann Horn <jannh@google.com>,  Alan Stern <stern@rowland.harvard.edu>,  Andrea Parri <parri.andrea@gmail.com>,  Will Deacon <will@kernel.org>,  Peter Zijlstra <peterz@infradead.org>,  Boqun Feng <boqun.feng@gmail.com>,  Nicholas Piggin <npiggin@gmail.com>,  David Howells <dhowells@redhat.com>,  Jade Alglave <j.alglave@ucl.ac.uk>,  Luc Maranget <luc.maranget@inria.fr>,  "Paul E. McKenney" <paulmck@kernel.org>,  Akira Yokosawa <akiyks@gmail.com>,  Daniel Lustig <dlustig@nvidia.com>,  Adam Zabrocki <pi3@pi3.com.pl>,  kernel list <linux-kernel@vger.kernel.org>,  Kernel Hardening <kernel-hardening@lists.openwall.com>,  Oleg Nesterov <oleg@redhat.com>,  Andy Lutomirski <luto@amacapital.net>,  Bernd Edlinger <bernd.edlinger@hotmail.de>,  Kees Cook <keescook@chromium.org>,  Andrew Morton <akpm@linux-foundation.org>,  stable <stable@vger.kernel.org>,  Marco Elver <elver@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  kasan-dev <kasan-dev@googlegroups.com>
References: <20200324215049.GA3710@pi3.com.pl> <202003291528.730A329@keescook>
	<87zhbvlyq7.fsf_-_@x220.int.ebiederm.org>
	<CAG48ez3nYr7dj340Rk5-QbzhsFq0JTKPf2MvVJ1-oi1Zug1ftQ@mail.gmail.com>
	<CAHk-=wjz0LEi68oGJSQzZ--3JTFF+dX2yDaXDRKUpYxtBB=Zfw@mail.gmail.com>
	<CAHk-=wgM3qZeChs_1yFt8p8ye1pOaM_cX57BZ_0+qdEPcAiaCQ@mail.gmail.com>
	<CAG48ez1f82re_V=DzQuRHpy7wOWs1iixrah4GYYxngF1v-moZw@mail.gmail.com>
	<CAHk-=whks0iE1f=Ka0_vo2PYg774P7FA8Y30YrOdUBGRH-ch9A@mail.gmail.com>
Date: Thu, 02 Apr 2020 08:11:31 -0500
In-Reply-To: <CAHk-=whks0iE1f=Ka0_vo2PYg774P7FA8Y30YrOdUBGRH-ch9A@mail.gmail.com>
	(Linus Torvalds's message of "Wed, 1 Apr 2020 19:05:59 -0700")
Message-ID: <877dyym3r0.fsf@x220.int.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1jJzfj-00021V-6R;;;mid=<877dyym3r0.fsf@x220.int.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/aAgD/0VF7hya1cN9dZdOTpz/w8uomdK0=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa01.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,NO_DNS_FOR_FROM,T_TM2_M_HEADER_IN_MSG
	autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4987]
	*  0.0 NO_DNS_FOR_FROM DNS: Envelope sender has no MX or A DNS records
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa01 1397; Body=1 Fuz1=1 Fuz2=1]
X-Spam-DCC: XMission; sa01 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Linus Torvalds <torvalds@linux-foundation.org>
X-Spam-Relay-Country: 
X-Spam-Timing: total 6259 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 4.6 (0.1%), b_tie_ro: 3.2 (0.1%), parse: 1.03
	(0.0%), extract_message_metadata: 11 (0.2%), get_uri_detail_list: 0.70
	(0.0%), tests_pri_-1000: 4.0 (0.1%), tests_pri_-950: 1.01 (0.0%),
	tests_pri_-900: 0.88 (0.0%), tests_pri_-90: 83 (1.3%), check_bayes: 82
	(1.3%), b_tokenize: 5 (0.1%), b_tok_get_all: 6 (0.1%), b_comp_prob:
	1.59 (0.0%), b_tok_touch_all: 66 (1.0%), b_finish: 0.79 (0.0%),
	tests_pri_0: 6143 (98.1%), check_dkim_signature: 0.51 (0.0%),
	check_dkim_adsp: 5997 (95.8%), poll_dns_idle: 5993 (95.7%),
	tests_pri_10: 1.70 (0.0%), tests_pri_500: 6 (0.1%), rewrite_mail: 0.00
	(0.0%)
Subject: Re: [PATCH] signal: Extend exec_id to 64bits
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as
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

Linus Torvalds <torvalds@linux-foundation.org> writes:

> tasklist_lock is aboue the hottest lock there is in all of the kernel.

Do you know code paths you see tasklist_lock being hot?

I am looking at some of the exec/signal/ptrace code paths because they
get subtle corner case wrong like a threaded exec deadlocking when
straced.

If the performance problems are in the same neighbourhood I might be
able to fix those problems while I am in the code.

Eric



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877dyym3r0.fsf%40x220.int.ebiederm.org.
