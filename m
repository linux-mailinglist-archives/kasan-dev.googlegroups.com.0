Return-Path: <kasan-dev+bncBDAOBFVI5MIBBBHOWOGAMGQEQSHZ6AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1127344D569
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 11:57:09 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id q17-20020adfcd91000000b0017bcb12ad4fsf946583wrj.12
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 02:57:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636628228; cv=pass;
        d=google.com; s=arc-20160816;
        b=fEKnmF9BF8Hn4KF1m1qSpd5PTDDhifH4ufDpkmza7kHZ2xz6OQMuFTi5mY1i7vMI83
         13/LCYAQw5ishqmaKxavocqOO0sNkOk4qmOrUDF2pcGzZDf+z9Vbhg7EkOfqqIwR9YxP
         KwnGwQlPN6SQDLfZn6DC+bSyyGJylEmq4kaopgtliTLAaTF8WmlT4Lx54A4h7ct8l+h7
         E/CiYZIGez4itbNqHs+wM2lHShpyA5Zm0j05S+bjKTg9/TP2l6f+c2XMIEvSu3wolfSY
         7gG18DPG9jVbZbEet4kY1kAtIuN8W+UwICbzPBg4pjUB1vy5zvY4+p3XURJsRhgSBXW2
         Njmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=eYdpcJXxc90BMlXr3WRIwPwmpLihivTt5VooC3i+LfY=;
        b=BOqLwvqt75NT7f/D37RrdD7UO3N0igiqpoBu4jzhUX0x+a7jeFHD5Ehu1DClcCHvqT
         2LJnf6FxyjX6WvzhAONY+d7aX1hmL5Dx9eHaEchUusMW1daVcbTfDZxkYB5Xp0n+4Hev
         3BCROYVcWA1o3GImYhR5Zg1JH8DCX2RUaUk844EBS5fFNpGhooG1XaEeBBIHHk11FsTa
         4a6q30j5QnkYNJI5V16MwOIwoLTts+NHCM834ICOmj6SD/Zix+sQYpVrWKYMYAIGz213
         pHeqSfdrg2kQYHSPabQXwI+XgAR5NCT8p9J17fgB1PaK+WiDk1ESRRKHwmOZUf4X4J9E
         fBBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eYdpcJXxc90BMlXr3WRIwPwmpLihivTt5VooC3i+LfY=;
        b=WpZGcGqdtin5oibNJ6kapQzbTZ3rAHbgHc16Q0iuytWlW8f6jvleGAsiB3Ct13/+qa
         npJjkgdnxkYHMsueJqkN+kHZDAlk8DjjIEupOzjLI+dyZBMAFFrhYXSzubCTjY/6VjbI
         z2E8Vmnz8xueiI33WokrU1sMaae3iT2GWgSLHIoqdl2hoZo4MFcElYybExkMVpHAGsoJ
         +0E7Uhr6rLDCW41sSQk6k9gTj30bl1Ik0QU6kvZFVCIiMmvFlmPvNDHG+ybsRao8fjBI
         9BjluNV3Nm8CabuBOB2avp4qZXzf2RcQg8f+ebfRwugDi/T+dp55NMFo8Outwn2YdCIY
         XTUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eYdpcJXxc90BMlXr3WRIwPwmpLihivTt5VooC3i+LfY=;
        b=u4Uhu+CG6laCWd8BK4veFmuRErPYhUhU7XU9n5dPzyViQsnD1GqFb/HAheXuGuDqLZ
         huWtaXqxrcUJcaRjTk26jfUpa75GAkyFsAdjU4JHVSJ+OOkpoIl8p74EjvRgLrXnYgy2
         CmJU67x0IJ3gmvrVDgp20Gtob2ULsftETUYNPJRI+oGG9SepA4Fp/W/8Su6A394NQkSD
         M9kP8iCpjy2X+Zej+L8k7o2ZcQrJvG5Yk46WCKVjigfA2kvKiOXvLQapS2Fm7jxgML3j
         9p3v7gEmw8goGOb0562F5GBBaXfYXu0k4QC5lQlM4dRcuLGzyrTpyPLcOS1ZsQHu20eO
         cdDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324Qmsiof93p7rMDBCvDYhUZ0r24qH+LgHjD7e3TF6/+5HSTpyL
	Osgn+3AX0McmfRHT7DLmFEM=
X-Google-Smtp-Source: ABdhPJwS91PFk6xG18nJTwgrtz3qaWmO174mckub0TdHixeVhoTn9Sg9kHm/qOKG4ldkGQoP80Kwvw==
X-Received: by 2002:a1c:a70c:: with SMTP id q12mr7479662wme.105.1636628228813;
        Thu, 11 Nov 2021 02:57:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls4704741wmb.3.canary-gmail; Thu,
 11 Nov 2021 02:57:08 -0800 (PST)
X-Received: by 2002:a05:600c:501f:: with SMTP id n31mr3676448wmr.101.1636628227978;
        Thu, 11 Nov 2021 02:57:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636628227; cv=none;
        d=google.com; s=arc-20160816;
        b=tVMSXj0IGCeUDS9pC7YOrwwpTxa6yoPQ+CyVMhRcWKrd8tdv/z0IlabbFVD1GLSAAJ
         USmauuMb0QcE7MoVptbz+OONJFtKyT30w0+rB+f8IeJwnIRdACNmUbciLsS22k+j6fzP
         VCXRnoTuZQjYDSa1Bz7Klbv7wEfIM5v9oYZTZ0lhosO8ZGxUxYmIAwnWEp3CQRxwiWAj
         OKj6WIO7PEQgTLpQV8UnbnALODeF+3cxqIuj3xcnLyaOiSJUfq2qm/l5W/a/Mu5r3BOq
         Un4qwtcHpsEE9Q3//GzT1LHIkgrO7jglWMWQ0A8VTB6TCbJdkE+2Zk+3B6sgu9M2K4XY
         dDMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from;
        bh=UyrVtJj/KIYK6aXDCjjIkoicCKKkzok9XBBspWDaUtc=;
        b=UtjIwYSm/mWRTYiliVPU0SyuJX2YUUE+UmJJYa8X7obzAIGhJz08VcwiNzyT3TF+BZ
         RXncu7EhDl7UcVhVd23siLQymUGZop+cafPEopnX/oc2mh/37Ku2/RZORt7/6YyLo6Zt
         JAHhEsP6HtjKOAaRFJmvZdCVQtjbs3ISqJeLHD4bN+YV1b/WBa6GyCo+ApnnRiZYcFXl
         x1scQ1NWr3anjE6krsS9Anz8q7Zt8qaI3IiQuzlThLttf8G53+AgDIZmKHEWACv2PGv+
         HHpDotFaNZfnMzepjJjMlssJaYhFrphZmbUqmFUm5n1wP9BIiyZtusbJo8ZB8E0+MDZy
         PoCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w2si145978wrg.5.2021.11.11.02.57.07
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Nov 2021 02:57:07 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 41DEDD6E;
	Thu, 11 Nov 2021 02:57:07 -0800 (PST)
Received: from e113632-lin (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 292E93F70D;
	Thu, 11 Nov 2021 02:57:05 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>, Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>, Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v2 4/5] kscan: Use preemption model accessors
In-Reply-To: <YYzeOQNFmuieCk3T@elver.google.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com> <20211110202448.4054153-5-valentin.schneider@arm.com> <YYzeOQNFmuieCk3T@elver.google.com>
Date: Thu, 11 Nov 2021 10:57:02 +0000
Message-ID: <871r3nrmdd.mognet@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 11/11/21 10:11, Marco Elver wrote:
> Subject s/kscan/kcsan/
>

Woops...

> On Wed, Nov 10, 2021 at 08:24PM +0000, Valentin Schneider wrote:
>> Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
>> preemption model of the live kernel. Use the newly-introduced accessors
>> instead.
>>
>> Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> Though it currently doesn't compile as a module due to missing
> EXPORT_SYMBOL of is_preempt*().
>
>> ---
>>  kernel/kcsan/kcsan_test.c | 4 ++--
>>  1 file changed, 2 insertions(+), 2 deletions(-)
>>
>> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
>> index dc55fd5a36fc..14d811eb9a21 100644
>> --- a/kernel/kcsan/kcsan_test.c
>> +++ b/kernel/kcsan/kcsan_test.c
>> @@ -1005,13 +1005,13 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
>>      else
>>              nthreads *= 2;
>>
>> -	if (!IS_ENABLED(CONFIG_PREEMPT) || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
>> +	if (!is_preempt_full() || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
>>              /*
>>               * Without any preemption, keep 2 CPUs free for other tasks, one
>>               * of which is the main test case function checking for
>>               * completion or failure.
>>               */
>> -		const long min_unused_cpus = IS_ENABLED(CONFIG_PREEMPT_NONE) ? 2 : 0;
>> +		const long min_unused_cpus = is_preempt_none() ? 2 : 0;
>>              const long min_required_cpus = 2 + min_unused_cpus;
>>
>>              if (num_online_cpus() < min_required_cpus) {
>> --
>> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871r3nrmdd.mognet%40arm.com.
